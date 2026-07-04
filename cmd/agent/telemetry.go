package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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
	network   netip.Prefix
	interval  time.Duration

	ct flowDumper // nil when the platform has no flow source

	prevLink map[wgtypes.Key]linkCounters
	prevFlow map[flowKey]flowCounters

	pendingCounters map[wgtypes.Key]*proto.PeerCounter
	pendingFlows    map[flowKey]*proto.FlowRecord

	// Relay fallback state.
	firstSeen   map[wgtypes.Key]time.Time
	relayed     map[wgtypes.Key]bool
	relayBroken bool // control plane said no relay; stop asking
}

func newTelemetryReporter(
	wg *wgctrl.Client,
	serverURL, authToken, serverCA, iface string,
	network netip.Prefix,
	interval time.Duration,
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
		network:         network,
		interval:        interval,
		prevLink:        make(map[wgtypes.Key]linkCounters),
		prevFlow:        make(map[flowKey]flowCounters),
		pendingCounters: make(map[wgtypes.Key]*proto.PeerCounter),
		pendingFlows:    make(map[flowKey]*proto.FlowRecord),
		firstSeen:       make(map[wgtypes.Key]time.Time),
		relayed:         make(map[wgtypes.Key]bool),
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
		if !t.network.Contains(f.src) && !t.network.Contains(f.dst) {
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
		t.post(&proto.ReportRequest{})
		return
	}

	report := &proto.ReportRequest{
		Counters: make([]proto.PeerCounter, 0, len(t.pendingCounters)),
		Flows:    make([]proto.FlowRecord, 0, len(t.pendingFlows)),
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

	t.applySync(sync.Peers)

	return true
}

// applySync converts the server's peer list and reconciles the device.
func (t *telemetryReporter) applySync(entries []proto.PeerConfigResponse) {
	desired := make([]wgtypes.PeerConfig, 0, len(entries))

	for _, e := range entries {
		cfg, err := peerConfigFromProto(e)
		if err != nil {
			fmt.Fprintf(os.Stderr, "telemetry: bad peer in sync payload: %v\n", err)
			return // don't apply a partial view
		}

		desired = append(desired, cfg)
	}

	if err := syncPeers(t.wg, t.iface, desired); err != nil {
		fmt.Fprintf(os.Stderr, "telemetry: %v\n", err)
	}
}
