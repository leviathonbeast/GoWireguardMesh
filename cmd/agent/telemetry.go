package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"gowireguard/internal/proto"

	"github.com/gorilla/websocket"
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
	interval      time.Duration
	deadline      time.Time
	epoch         int
}

// telemetryReporter periodically collects WireGuard link counters and
// conntrack flow data, converts them to deltas, and ships them to the
// control plane. Deltas survive failed reports: pending data is only
// cleared after the server accepts it.
type telemetryReporter struct {
	wg         wgBackend
	client     *http.Client
	wsDialer   *websocket.Dialer
	serverURL  string
	authToken  string
	iface      string
	selfAddr   string
	selfAddr6  string
	network    netip.Prefix
	network6   netip.Prefix
	lastDNS    string
	dnsApplied bool
	dnsWarned  bool
	interval   time.Duration
	syncMu     sync.Mutex

	ct        flowDumper   // nil when the platform has no flow source
	proxyTail *proxyTailer // nil unless --traefik-access-log is set

	prevLink map[wgtypes.Key]linkCounters
	prevFlow map[flowKey]flowCounters

	pendingCounters map[wgtypes.Key]*proto.PeerCounter
	pendingFlows    map[flowKey]*proto.FlowRecord

	// Relay fallback state.
	relayTransport relayTransport
	firstSeen      map[wgtypes.Key]time.Time
	lastInbound    map[wgtypes.Key]time.Time // last tick a peer's rx grew (keepalives count)
	relayed        map[wgtypes.Key]bool
	relayedAt      map[wgtypes.Key]time.Time
	relayEndpoints map[wgtypes.Key]*net.UDPAddr
	directProbes   map[wgtypes.Key]directProbe
	lastPunchEpoch map[wgtypes.Key]int
	directFailures map[wgtypes.Key]int    // consecutive failed direct-retry probes; backs off the uncoordinated retry
	lastCandidates map[wgtypes.Key]string // digest of last candidate set; a change re-arms a prompt retry
	wsProxies      map[wgtypes.Key]*wsRelayProxy
	relayBroken    bool // control plane said no relay; stop asking
	directProbeOff bool // keep relay stable after fallback; useful for service sidecars
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
	wg wgBackend,
	serverURL, authToken, serverCA, iface string,
	selfAddr, selfAddr6 string,
	network netip.Prefix,
	network6 netip.Prefix,
	interval time.Duration,
	transport relayTransport,
	enableDirectProbe bool,
) (*telemetryReporter, error) {
	client, err := newHTTPClient(serverCA)
	if err != nil {
		return nil, err
	}
	wsDialer, err := newWebSocketDialer(serverCA)
	if err != nil {
		return nil, err
	}

	t := &telemetryReporter{
		wg:              wg,
		client:          client,
		wsDialer:        wsDialer,
		serverURL:       serverURL,
		authToken:       authToken,
		iface:           iface,
		selfAddr:        selfAddr,
		selfAddr6:       selfAddr6,
		network:         network,
		network6:        network6,
		interval:        interval,
		relayTransport:  transport,
		directProbeOff:  !enableDirectProbe,
		prevLink:        make(map[wgtypes.Key]linkCounters),
		prevFlow:        make(map[flowKey]flowCounters),
		pendingCounters: make(map[wgtypes.Key]*proto.PeerCounter),
		pendingFlows:    make(map[flowKey]*proto.FlowRecord),
		firstSeen:       make(map[wgtypes.Key]time.Time),
		lastInbound:     make(map[wgtypes.Key]time.Time),
		relayed:         make(map[wgtypes.Key]bool),
		relayedAt:       make(map[wgtypes.Key]time.Time),
		relayEndpoints:  make(map[wgtypes.Key]*net.UDPAddr),
		directProbes:    make(map[wgtypes.Key]directProbe),
		lastPunchEpoch:  make(map[wgtypes.Key]int),
		directFailures:  make(map[wgtypes.Key]int),
		lastCandidates:  make(map[wgtypes.Key]string),
		wsProxies:       make(map[wgtypes.Key]*wsRelayProxy),
	}

	dumper, err := newFlowDumper(iface, parseSelfAddr(selfAddr), parseSelfAddr(selfAddr6))
	if err != nil {
		slog.Warn("flow logs disabled", "error", err)
		return t, nil
	}

	t.ct = dumper

	return t, nil
}

// parseSelfAddr parses an overlay self-address (a bare IP or a CIDR) for the
// capture flow classifier; returns the zero Addr when empty or unparseable.
func parseSelfAddr(s string) netip.Addr {
	if s == "" {
		return netip.Addr{}
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap()
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr().Unmap()
	}

	return netip.Addr{}
}

// run collects and reports until stop is closed. Runs one final
// report attempt on shutdown so short-lived sessions still show up.
func (t *telemetryReporter) run(stop <-chan struct{}) {
	ticker := time.NewTicker(t.interval)
	defer ticker.Stop()

	signalDone := make(chan struct{})
	go func() {
		defer close(signalDone)
		t.runSignal(stop)
	}()

	for {
		select {
		case <-stop:
			<-signalDone
			t.syncOnce(false)

			for _, p := range t.wsProxies {
				p.close()
			}

			if t.ct != nil {
				t.ct.Close()
			}

			if t.proxyTail != nil {
				t.proxyTail.Close()
			}

			return
		case <-ticker.C:
			t.syncOnce(true)
		}
	}
}

func (t *telemetryReporter) syncOnce(checkPaths bool) {
	t.syncMu.Lock()
	defer t.syncMu.Unlock()

	t.collect()
	t.send()
	if checkPaths {
		t.checkHandshakes()
	}
}

func (t *telemetryReporter) collect() {
	t.collectLinkCounters()
	t.collectFlows()
}

func (t *telemetryReporter) collectLinkCounters() {
	device, err := t.wg.Device()
	if err != nil {
		slog.Debug("telemetry read device failed", "error", err)
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

		if deltaRx > 0 {
			t.lastInbound[peer.PublicKey] = time.Now()
		}

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
		slog.Debug("telemetry flow dump failed", "error", err)
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

		// Aggregate by service: fold every connection to the same
		// server:port into one record, oriented client -> server, so a
		// storm of short connections with fresh ephemeral ports (e.g. a
		// reverse proxy health-checking backends) collapses to a single
		// row. tx/rx swap when the orientation flips, since ctFlow always
		// keeps tx = src->dst and rx = dst->src.
		client, server, serverPort, flipped := orientFlow(f.src, f.srcPort, f.dst, f.dstPort)
		aggKey := flowKey{protocol: f.protocol, src: client, dst: server, dstPort: serverPort}

		txB, txP := delta.txBytes, delta.txPackets
		rxB, rxP := delta.rxBytes, delta.rxPackets
		if flipped {
			txB, rxB = rxB, txB
			txP, rxP = rxP, txP
		}

		pending, ok := t.pendingFlows[aggKey]
		if !ok {
			pending = &proto.FlowRecord{
				Protocol: int(aggKey.protocol),
				SrcIP:    client.String(),
				DstIP:    server.String(),
				DstPort:  int(serverPort),
			}
			t.pendingFlows[aggKey] = pending
		}

		pending.TxBytes += int64(txB)
		pending.TxPackets += int64(txP)
		pending.RxBytes += int64(rxB)
		pending.RxPackets += int64(rxP)
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

// ephemeralMin is the start of Linux's default ephemeral port range
// (ip_local_port_range). Ports at or above it are treated as the client
// side of a flow when orienting client -> server.
const ephemeralMin = 32768

// orientFlow puts the client (ephemeral port) as src and the server
// (stable listening port) as dst, so both peers describe a connection the
// same way and connections that differ only in the client's port fold
// together. It reports whether that swapped the original src/dst, so the
// caller can swap tx/rx to match. When neither or both ports look
// ephemeral, the lower port is taken as the server.
func orientFlow(src netip.Addr, srcPort uint16, dst netip.Addr, dstPort uint16) (client, server netip.Addr, serverPort uint16, flipped bool) {
	srcEph := srcPort >= ephemeralMin
	dstEph := dstPort >= ephemeralMin

	switch {
	case srcEph && !dstEph:
		return src, dst, dstPort, false
	case dstEph && !srcEph:
		return dst, src, srcPort, true
	default:
		if dstPort <= srcPort {
			return src, dst, dstPort, false
		}
		return dst, src, srcPort, true
	}
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
	var proxyEvents []proto.ProxyEvent
	if t.proxyTail != nil {
		proxyEvents = t.proxyTail.drain(proxyDrainPerTick)
	}

	if len(t.pendingCounters) == 0 && len(t.pendingFlows) == 0 && len(proxyEvents) == 0 {
		// Still send: an empty report is the liveness heartbeat that
		// keeps last_seen_at fresh on the server.
		t.post(&proto.ReportRequest{PathStates: t.currentPathStates()})
		return
	}

	report := &proto.ReportRequest{
		Counters:    make([]proto.PeerCounter, 0, len(t.pendingCounters)),
		Flows:       make([]proto.FlowRecord, 0, len(t.pendingFlows)),
		PathStates:  t.currentPathStates(),
		ProxyEvents: proxyEvents,
	}

	for _, c := range t.pendingCounters {
		report.Counters = append(report.Counters, *c)
	}

	for _, f := range t.pendingFlows {
		report.Flows = append(report.Flows, *f)
	}

	// Proxy events are a best-effort log: if the report fails they are
	// dropped (not re-queued), while counters/flows survive as deltas.
	if t.post(report) {
		t.pendingCounters = make(map[wgtypes.Key]*proto.PeerCounter)
		t.pendingFlows = make(map[flowKey]*proto.FlowRecord)
	}
}

func (t *telemetryReporter) currentPathStates() []proto.PeerPathState {
	device, err := t.wg.Device()
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
		slog.Error("encode report failed", "error", err)
		return false
	}

	req, err := http.NewRequest(http.MethodPost, t.serverURL+"/report", bytes.NewReader(body))
	if err != nil {
		slog.Error("build report request failed", "error", err)
		return false
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+t.authToken)

	resp, err := t.client.Do(req)
	if err != nil {
		slog.Warn("send report failed", "error", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		slog.Warn("report rejected", "status", resp.Status)

		return false
	}

	var sync proto.ReportResponse

	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&sync); err != nil {
		slog.Warn("decode sync payload failed", "error", err)
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
		slog.Warn("telemetry sync failed", "error", err)
		return
	}
	if err := t.applyDNS(sync.DNS); err != nil {
		slog.Warn("dns sync failed", "error", err)
	}

	desired := make([]wgtypes.PeerConfig, 0, len(sync.Peers))

	for _, e := range sync.Peers {
		cfg, err := peerConfigFromProto(e)
		if err != nil {
			slog.Warn("bad peer in sync payload", "error", err)
			return // don't apply a partial view
		}

		t.maybeRetryDirect(cfg.PublicKey, endpointCandidatesFromProto(e, cfg.Endpoint), e.PunchEpoch)

		desired = append(desired, cfg)
	}

	if err := syncPeers(t.wg, desired); err != nil {
		slog.Warn("telemetry sync failed", "error", err)
	}

	if err := applyOverlayACL(t.iface, sync.ACL); err != nil {
		slog.Warn("overlay acl sync failed", "error", err)
	}
}

func (t *telemetryReporter) applyDNS(cfg proto.DNSConfig) error {
	if !cfg.Enabled && !t.dnsApplied {
		return nil
	}

	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	digest := string(raw)
	if digest == t.lastDNS {
		return nil
	}

	if err := applyDNSConfig(t.iface, cfg); err != nil {
		if errors.Is(err, errDNSUnsupported) {
			t.lastDNS = digest
			t.dnsApplied = false
			if !t.dnsWarned {
				slog.Warn("dns sync unsupported; configure DNS manually or install systemd-resolved", "error", err)
				t.dnsWarned = true
			}
			return nil
		}
		return err
	}

	t.lastDNS = digest
	t.dnsApplied = cfg.Enabled
	if cfg.Enabled {
		slog.Info("applied dns settings", "nameservers", cfg.Nameservers, "search_domains", cfg.SearchDomains)
	} else {
		slog.Info("cleared dns settings")
	}

	return nil
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
