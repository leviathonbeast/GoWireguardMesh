package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"gowireguard/internal/proto"
)

// ctFlow is one connection-tracking entry in platform-neutral form.
// Src is the flow initiator; counters are cumulative.
type ctFlow struct {
	protocol         uint8
	src, dst         netip.Addr
	srcPort, dstPort uint16

	txBytes, txPackets uint64 // initiator -> responder
	rxBytes, rxPackets uint64 // responder -> initiator
}

// flowDumper abstracts the platform flow source (conntrack on Linux;
// none on Windows). A nil dumper disables flow telemetry.
type flowDumper interface {
	Dump() ([]ctFlow, error)
	Close() error
}

// linkCounters is a snapshot of one peer's kernel transfer counters.
type linkCounters struct {
	rx, tx int64
}

// flowKey identifies a conntrack flow by its original-direction tuple.
type flowKey struct {
	protocol uint8
	src      netip.Addr
	srcPort  uint16
	dst      netip.Addr
	dstPort  uint16
}

// flowCounters is a snapshot of a flow's cumulative conntrack counters.
type flowCounters struct {
	txBytes, rxBytes     uint64
	txPackets, rxPackets uint64
}

type directProbe struct {
	started       time.Time
	candidates    []*net.UDPAddr
	index         int
	relayEndpoint *net.UDPAddr
}

// telemetryReporter periodically collects WireGuard link counters and
// conntrack flow data, converts them to deltas, and ships them to the
// control plane. Deltas survive failed reports: pending data is only
// cleared after the server accepts it.
type telemetryReporter struct {
	wg        *wgctrl.Client
	client    *http.Client
	serverURL string
	authToken string
	iface     string
	selfAddr  string
	selfAddr6 string
	network   netip.Prefix
	network6  netip.Prefix
	interval  time.Duration

	ct flowDumper // nil when the platform has no flow source

	prevLink map[wgtypes.Key]linkCounters
	prevFlow map[flowKey]flowCounters

	pendingCounters map[wgtypes.Key]*proto.PeerCounter
	pendingFlows    map[flowKey]*proto.FlowRecord

	// Relay fallback state.
	relayTransport relayTransport
	firstSeen      map[wgtypes.Key]time.Time
	relayed        map[wgtypes.Key]bool
	relayedAt      map[wgtypes.Key]time.Time
	relayEndpoints map[wgtypes.Key]*net.UDPAddr
	directProbes   map[wgtypes.Key]directProbe
	wsProxies      map[wgtypes.Key]*wsRelayProxy
	relayBroken    bool // control plane said no relay; stop asking
}

// relayTransport selects how the agent tunnels to a relayed peer.
type relayTransport int

const (
	// relayWebSocket rides the control plane's own port (443), so it
	// needs no extra firewall holes and traverses UDP-blocking
	// networks — the NetBird-parity default.
	relayWebSocket relayTransport = iota
	// relayUDP is the raw UDP forwarder: faster, but needs the relay's
	// port range reachable.
	relayUDP
)

func newTelemetryReporter(
	wg *wgctrl.Client,
	serverURL, authToken, serverCA, iface string,
	selfAddr, selfAddr6 string,
	network netip.Prefix,
	network6 netip.Prefix,
	interval time.Duration,
	transport relayTransport,
) (*telemetryReporter, error) {
	client, err := newHTTPClient(serverCA)
	if err != nil {
		return nil, err
	}

	t := &telemetryReporter{
		wg:              wg,
		client:          client,
		serverURL:       serverURL,
		authToken:       authToken,
		iface:           iface,
		selfAddr:        selfAddr,
		selfAddr6:       selfAddr6,
		network:         network,
		network6:        network6,
		interval:        interval,
		relayTransport:  transport,
		prevLink:        make(map[wgtypes.Key]linkCounters),
		prevFlow:        make(map[flowKey]flowCounters),
		pendingCounters: make(map[wgtypes.Key]*proto.PeerCounter),
		pendingFlows:    make(map[flowKey]*proto.FlowRecord),
		firstSeen:       make(map[wgtypes.Key]time.Time),
		relayed:         make(map[wgtypes.Key]bool),
		relayedAt:       make(map[wgtypes.Key]time.Time),
		relayEndpoints:  make(map[wgtypes.Key]*net.UDPAddr),
		directProbes:    make(map[wgtypes.Key]directProbe),
		wsProxies:       make(map[wgtypes.Key]*wsRelayProxy),
	}

	dumper, err := newFlowDumper()
	if err != nil {
		fmt.Fprintf(os.Stderr, "telemetry: %v; flow logs disabled\n", err)
		return t, nil
	}

	t.ct = dumper

	return t, nil
}

// run collects and reports until stop is closed. Runs one final
// report attempt on shutdown so short-lived sessions still show up.
func (t *telemetryReporter) run(stop <-chan struct{}) {
	ticker := time.NewTicker(t.interval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			t.collect()
			t.send()

			for _, p := range t.wsProxies {
				p.close()
			}

			if t.ct != nil {
				t.ct.Close()
			}

			return
		case <-ticker.C:
			t.collect()
			t.send()
			t.checkHandshakes()
		}
	}
}

func (t *telemetryReporter) collect() {
	t.collectLinkCounters()
	t.collectFlows()
}

func (t *telemetryReporter) collectLinkCounters() {
	device, err := t.wg.Device(t.iface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "telemetry: read device: %v\n", err)
		return
	}

	for _, peer := range device.Peers {
		cur := linkCounters{rx: peer.ReceiveBytes, tx: peer.TransmitBytes}
		prev := t.prevLink[peer.PublicKey]

		// Kernel counters reset when the interface is recreated; a
		// drop below the previous snapshot means "count from zero".
		deltaRx := cur.rx - prev.rx
		deltaTx := cur.tx - prev.tx

		if deltaRx < 0 {
			deltaRx = cur.rx
		}

		if deltaTx < 0 {
			deltaTx = cur.tx
		}

		t.prevLink[peer.PublicKey] = cur

		var handshake string
		if !peer.LastHandshakeTime.IsZero() {
			handshake = peer.LastHandshakeTime.UTC().Format(time.RFC3339)
		}

		if deltaRx == 0 && deltaTx == 0 && handshake == "" {
			continue
		}

		pending, ok := t.pendingCounters[peer.PublicKey]
		if !ok {
			pending = &proto.PeerCounter{PeerPublicKey: peer.PublicKey.String()}
			t.pendingCounters[peer.PublicKey] = pending
		}

		pending.RxBytes += deltaRx
		pending.TxBytes += deltaTx

		if handshake != "" {
			pending.LastHandshakeAt = handshake
		}
	}
}

func (t *telemetryReporter) collectFlows() {
	if t.ct == nil {
		return
	}

	flows, err := t.ct.Dump()
	if err != nil {
		fmt.Fprintf(os.Stderr, "telemetry: flow dump: %v\n", err)
		return
	}

	seen := make(map[flowKey]bool, len(flows))

	for _, f := range flows {
		// Overlay traffic only: everything else on the box is none of
		// the mesh's business.
		if !t.overlayContains(f.src) && !t.overlayContains(f.dst) {
			continue
		}

		key := flowKey{
			protocol: f.protocol,
			src:      f.src,
			srcPort:  f.srcPort,
			dst:      f.dst,
			dstPort:  f.dstPort,
		}

		cur := flowCounters{
			txBytes:   f.txBytes,
			txPackets: f.txPackets,
			rxBytes:   f.rxBytes,
			rxPackets: f.rxPackets,
		}

		seen[key] = true

		prev, known := t.prevFlow[key]
		t.prevFlow[key] = cur

		delta := flowCounters{
			txBytes:   counterDelta(cur.txBytes, prev.txBytes, known),
			txPackets: counterDelta(cur.txPackets, prev.txPackets, known),
			rxBytes:   counterDelta(cur.rxBytes, prev.rxBytes, known),
			rxPackets: counterDelta(cur.rxPackets, prev.rxPackets, known),
		}

		if delta.txBytes == 0 && delta.rxBytes == 0 && delta.txPackets == 0 && delta.rxPackets == 0 {
			continue
		}

		pending, ok := t.pendingFlows[key]
		if !ok {
			pending = &proto.FlowRecord{
				Protocol: int(key.protocol),
				SrcIP:    key.src.String(),
				SrcPort:  int(key.srcPort),
				DstIP:    key.dst.String(),
				DstPort:  int(key.dstPort),
			}
			t.pendingFlows[key] = pending
		}

		pending.TxBytes += int64(delta.txBytes)
		pending.TxPackets += int64(delta.txPackets)
		pending.RxBytes += int64(delta.rxBytes)
		pending.RxPackets += int64(delta.rxPackets)
	}

	// Flows gone from conntrack won't report again; drop their
	// snapshots so a restarted flow with the same tuple counts fresh.
	for key := range t.prevFlow {
		if !seen[key] {
			delete(t.prevFlow, key)
		}
	}
}

func (t *telemetryReporter) overlayContains(addr netip.Addr) bool {
	return t.network.Contains(addr) || (t.network6.IsValid() && t.network6.Contains(addr))
}

// counterDelta handles both new flows (count everything) and conntrack
// entries that were recycled for the same tuple (counter went down).
func counterDelta(cur, prev uint64, known bool) uint64 {
	if !known || cur < prev {
		return cur
	}

	return cur - prev
}

func (t *telemetryReporter) send() {
	if len(t.pendingCounters) == 0 && len(t.pendingFlows) == 0 {
		// Still send: an empty report is the liveness heartbeat that
		// keeps last_seen_at fresh on the server.
		t.post(&proto.ReportRequest{PathStates: t.currentPathStates()})
		return
	}

	report := &proto.ReportRequest{
		Counters:   make([]proto.PeerCounter, 0, len(t.pendingCounters)),
		Flows:      make([]proto.FlowRecord, 0, len(t.pendingFlows)),
		PathStates: t.currentPathStates(),
	}

	for _, c := range t.pendingCounters {
		report.Counters = append(report.Counters, *c)
	}

	for _, f := range t.pendingFlows {
		report.Flows = append(report.Flows, *f)
	}

	if t.post(report) {
		t.pendingCounters = make(map[wgtypes.Key]*proto.PeerCounter)
		t.pendingFlows = make(map[flowKey]*proto.FlowRecord)
	}
}

func (t *telemetryReporter) currentPathStates() []proto.PeerPathState {
	device, err := t.wg.Device(t.iface)
	if err != nil {
		return nil
	}

	out := make([]proto.PeerPathState, 0, len(device.Peers))
	for _, peer := range device.Peers {
		endpoint := ""
		if peer.Endpoint != nil {
			endpoint = peer.Endpoint.String()
		}

		out = append(out, proto.PeerPathState{
			PeerPublicKey: peer.PublicKey.String(),
			State:         t.pathState(peer.PublicKey),
			Endpoint:      endpoint,
		})
	}

	return out
}

func (t *telemetryReporter) pathState(peer wgtypes.Key) string {
	if _, ok := t.directProbes[peer]; ok {
		return "probing-direct"
	}
	if t.relayed[peer] {
		if t.relayTransport == relayUDP {
			return "udp-relay"
		}
		return "ws-relay"
	}
	return "direct"
}

func endpointCandidatesFromProto(p proto.PeerConfigResponse, fallback *net.UDPAddr) []*net.UDPAddr {
	out := make([]*net.UDPAddr, 0, len(p.EndpointCandidates)+1)
	seen := map[string]bool{}

	for _, c := range p.EndpointCandidates {
		udp, err := net.ResolveUDPAddr("udp", c.Endpoint)
		if err != nil || seen[udp.String()] {
			continue
		}
		seen[udp.String()] = true
		out = append(out, udp)
	}

	if fallback != nil && !seen[fallback.String()] {
		out = append(out, fallback)
	}

	return out
}

// post sends one report and applies the config-sync payload from the
// response; false means keep the pending data for retry.
func (t *telemetryReporter) post(report *proto.ReportRequest) bool {
	body, err := json.Marshal(report)
	if err != nil {
		fmt.Fprintf(os.Stderr, "telemetry: encode report: %v\n", err)
		return false
	}

	req, err := http.NewRequest(http.MethodPost, t.serverURL+"/report", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "telemetry: build report request: %v\n", err)
		return false
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+t.authToken)

	resp, err := t.client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "telemetry: send report: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		fmt.Fprintf(os.Stderr, "telemetry: report rejected: %s\n", resp.Status)

		return false
	}

	var sync proto.ReportResponse

	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&sync); err != nil {
		fmt.Fprintf(os.Stderr, "telemetry: decode sync payload: %v\n", err)
		return true // report was accepted; only the sync failed
	}

	t.applySync(sync)

	return true
}

// applySync reconciles this agent's own interface address and then the
// peer list. The self-address path lets the control plane re-IP the
// mesh and have running agents adopt their new address without a
// process restart.
func (t *telemetryReporter) applySync(sync proto.ReportResponse) {
	if err := t.applySelfAssignment(sync); err != nil {
		fmt.Fprintf(os.Stderr, "telemetry: %v\n", err)
		return
	}

	desired := make([]wgtypes.PeerConfig, 0, len(sync.Peers))

	for _, e := range sync.Peers {
		cfg, err := peerConfigFromProto(e)
		if err != nil {
			fmt.Fprintf(os.Stderr, "telemetry: bad peer in sync payload: %v\n", err)
			return // don't apply a partial view
		}

		t.maybeRetryDirect(cfg.PublicKey, endpointCandidatesFromProto(e, cfg.Endpoint))

		desired = append(desired, cfg)
	}

	if err := syncPeers(t.wg, t.iface, desired); err != nil {
		fmt.Fprintf(os.Stderr, "telemetry: %v\n", err)
	}
}

func (t *telemetryReporter) applySelfAssignment(sync proto.ReportResponse) error {
	if sync.AssignedIP == "" || sync.NetworkCIDR == "" {
		return nil
	}

	network, err := netip.ParsePrefix(sync.NetworkCIDR)
	if err != nil {
		return fmt.Errorf("parse synced network CIDR %q: %w", sync.NetworkCIDR, err)
	}

	nextAddr, err := overlayAddress(sync.AssignedIP, network)
	if err != nil {
		return err
	}

	var (
		network6  netip.Prefix
		nextAddr6 string
	)
	if sync.NetworkCIDR6 != "" {
		network6, err = netip.ParsePrefix(sync.NetworkCIDR6)
		if err != nil {
			return fmt.Errorf("parse synced IPv6 network CIDR %q: %w", sync.NetworkCIDR6, err)
		}
		if sync.AssignedIP6 != "" {
			nextAddr6, err = overlayAddress(sync.AssignedIP6, network6)
			if err != nil {
				return err
			}
		}
	}

	if nextAddr != t.selfAddr {
		if err := replaceIPAddress(t.iface, t.selfAddr, nextAddr); err != nil {
			return err
		}
		fmt.Printf("[agent] adopted new overlay address %s\n", nextAddr)
		t.selfAddr = nextAddr
	}

	if nextAddr6 != t.selfAddr6 {
		if err := replaceIPAddress(t.iface, t.selfAddr6, nextAddr6); err != nil {
			return err
		}
		if nextAddr6 != "" {
			fmt.Printf("[agent] adopted new IPv6 overlay address %s\n", nextAddr6)
		}
		t.selfAddr6 = nextAddr6
	}

	t.network = network
	t.network6 = network6

	return nil
}
