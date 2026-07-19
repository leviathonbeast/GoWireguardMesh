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
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
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
	confirmedAt   time.Time // first direct handshake; waits for later inbound proof
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
	wg               wgBackend
	client           *http.Client
	wsDialer         *websocket.Dialer
	serverURL        string
	serverCA         string
	authToken        string
	iface            string
	selfAddr         string
	selfAddr6        string
	network          netip.Prefix
	network6         netip.Prefix
	lastDNS          string
	dnsApplied       bool
	dnsWarned        bool
	interval         time.Duration
	gatewayNATCIDRs  string
	gatewayForwardOn bool // routed-mobile FORWARD accept currently installed
	syncMu           sync.Mutex

	ct        flowDumper   // nil when the platform has no flow source
	proxyTail *proxyTailer // nil unless --traefik-access-log is set

	// NAT-traversal material shipped with every report. listenPort and
	// stunFallback are set once by the runner; the rest is refreshed by
	// maybeNATCheck (async, so guarded by syncMu like the relay state).
	listenPort      int
	stunFallback    string      // --stun-server value; used until mesh STUN is known
	stunServers     []string    // mesh STUN endpoints adopted from sync responses
	publicEndpoint  string      // last known public ip:port of the WG socket
	publicEndpoint6 string      // last known reflexive v6 endpoint, "" if none
	endpointPinned  bool        // --advertise-endpoint: never overwrite publicEndpoint
	stun6Server     string      // v6-capable STUN for the periodic v6 refresh; "" disables
	noIPv6          bool        // --no-ipv6-endpoints: never advertise v6 direct
	natType         string      // "easy", "hard", or "" unknown
	portMapper      *portMapper // nil when --port-mapping=false or no router mapping
	natTick         int         // report ticks since start, for the re-check cadence
	natBusy         atomic.Bool // one NAT check in flight at a time

	prevLink map[wgtypes.Key]linkCounters
	prevFlow map[flowKey]flowCounters

	pendingCounters map[wgtypes.Key]*proto.PeerCounter
	pendingFlows    map[flowKey]*proto.FlowRecord

	// Relay fallback state.
	relayTransport  relayTransport
	firstSeen       map[wgtypes.Key]time.Time
	lastInbound     map[wgtypes.Key]time.Time // last tick a peer's rx grew (keepalives count)
	relayed         map[wgtypes.Key]bool
	relayedAt       map[wgtypes.Key]time.Time
	relayEndpoints  map[wgtypes.Key]*net.UDPAddr
	directProbes    map[wgtypes.Key]directProbe
	lastPunchEpoch  map[wgtypes.Key]int
	directFailures  map[wgtypes.Key]int    // consecutive failed direct-retry probes; backs off the uncoordinated retry
	lastCandidates  map[wgtypes.Key]string // digest of last candidate set; a change re-arms a prompt retry
	wsProxies       map[wgtypes.Key]*wsRelayProxy
	quicProxies     map[wgtypes.Key]*quicRelayProxy
	pathKinds       map[wgtypes.Key]string
	quicUnavailable map[wgtypes.Key]bool
	hostnames       map[wgtypes.Key]string // control-plane names from sync, for readable logs
	advertiseV6     bool                   // gather global-v6 host candidates (only when we manage the firewall)
	// Flap damping: a promote that doesn't hold is a flap, and repeated
	// flaps earn an escalating hold-down during which no direct probe —
	// coordinated or not — may run. Bounds direct<->relay churn on
	// marginal paths that can handshake but not stay up.
	directSince    map[wgtypes.Key]time.Time // when the current direct stint began (via promoteDirect)
	directFlaps    map[wgtypes.Key]int       // consecutive short-lived direct stints
	holdDownUntil  map[wgtypes.Key]time.Time // no relay->direct probing before this
	relayBroken    bool                      // control plane said no relay; stop asking
	directProbeOff bool                      // keep relay stable after fallback; useful for service sidecars
}

// relayTransport selects how the agent tunnels to a relayed peer.
type relayTransport int

const (
	relayAuto relayTransport = iota
	// relayWebSocket rides the control plane's own port (443), so it
	// needs no extra firewall holes and traverses UDP-blocking
	// networks — the NetBird-parity default.
	relayWebSocket
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
	gatewayNATCIDRs string,
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
		serverCA:        serverCA,
		iface:           iface,
		selfAddr:        selfAddr,
		selfAddr6:       selfAddr6,
		network:         network,
		network6:        network6,
		interval:        interval,
		gatewayNATCIDRs: gatewayNATCIDRs,
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
		quicProxies:     make(map[wgtypes.Key]*quicRelayProxy),
		pathKinds:       make(map[wgtypes.Key]string),
		quicUnavailable: make(map[wgtypes.Key]bool),
		hostnames:       make(map[wgtypes.Key]string),
		directSince:     make(map[wgtypes.Key]time.Time),
		directFlaps:     make(map[wgtypes.Key]int),
		holdDownUntil:   make(map[wgtypes.Key]time.Time),
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

	// The GUI refreshes peer state faster than the report interval; a
	// publish is one device read and no-ops entirely in console and
	// service runs (hub disabled). The same tick drives direct-probe
	// candidate rotation: probe dwells (8s coordinated, 20s normal) are
	// far shorter than the report interval, so checking them only on
	// report ticks would quantize every dwell up to ~30s.
	statusTicker := time.NewTicker(5 * time.Second)
	defer statusTicker.Stop()

	t.publishPeers()

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
			for _, p := range t.quicProxies {
				p.close()
			}

			if t.portMapper != nil {
				t.portMapper.close() // removes the router mapping
			}

			if t.ct != nil {
				t.ct.Close()
			}

			if t.proxyTail != nil {
				t.proxyTail.Close()
			}

			// Remove the routed-mobile FORWARD accept if we installed it.
			if err := applyGatewayRoutes(t.iface, nil, &t.gatewayForwardOn); err != nil {
				slog.Warn("gateway route teardown failed", "error", err)
			}

			return
		case <-ticker.C:
			t.maybeNATCheck()
			t.syncOnce(true)
			t.publishPeers()
		case <-statusTicker.C:
			t.checkProbes()
			t.publishPeers()
		}
	}
}

// publishPeers pushes the current peer set (path state + counters) to
// the GUI status hub. It takes syncMu because pathState reads the
// relay/probe maps that syncOnce mutates.
func (t *telemetryReporter) publishPeers() {
	if !statusPub.enabled() {
		return
	}

	device, err := t.wg.Device()
	if err != nil {
		return
	}

	t.syncMu.Lock()

	peers := make([]peerStatus, 0, len(device.Peers))
	for _, peer := range device.Peers {
		endpoint := ""
		if peer.Endpoint != nil {
			endpoint = peer.Endpoint.String()
		}

		allowed := make([]string, 0, len(peer.AllowedIPs))
		for _, ipnet := range peer.AllowedIPs {
			if ones, bits := ipnet.Mask.Size(); ones == bits {
				allowed = append(allowed, ipnet.IP.String())
				continue
			}
			allowed = append(allowed, ipnet.String())
		}

		peers = append(peers, peerStatus{
			PublicKey:     peer.PublicKey.String(),
			AllowedIPs:    allowed,
			Endpoint:      endpoint,
			PathState:     t.pathState(peer.PublicKey),
			LastHandshake: peer.LastHandshakeTime,
			RxBytes:       peer.ReceiveBytes,
			TxBytes:       peer.TransmitBytes,
		})
	}

	selfAddr, selfAddr6 := t.selfAddr, t.selfAddr6

	t.syncMu.Unlock()

	sort.Slice(peers, func(i, j int) bool { return peers[i].PublicKey < peers[j].PublicKey })

	statusPub.update(func(s *agentStatus) {
		s.Peers = peers
		// Live self-IP adoption can change the overlay address after
		// startup; the reporter holds the current one.
		s.OverlayAddr = selfAddr
		s.OverlayAddr6 = selfAddr6
	})
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

// natCheckEvery is how many report ticks pass between NAT re-checks
// (2 minutes at the default 30s interval). The check is two UDP round
// trips; the cadence is about how fast a changed public IP (ISP
// reconnect, router reboot) propagates into this peer's candidates.
const natCheckEvery = 4

// maybeNATCheck refreshes the public endpoint and NAT classification in
// the background. The kernel owns the WireGuard port, so this measures
// from a throwaway socket: the mapped IP tells us when the public IP
// changed, and querying the mesh STUN port pair classifies the NAT's
// mapping behavior (see checkNAT).
func (t *telemetryReporter) maybeNATCheck() {
	// A pinned endpoint makes both outputs moot: the advertised address
	// never changes, and the pin asserts reachability ("static") better
	// than measuring the outbound path's NAT ever could.
	if t.endpointPinned {
		return
	}

	t.natTick++
	if (t.natTick-1)%natCheckEvery != 0 {
		return
	}

	if !t.natBusy.CompareAndSwap(false, true) {
		return
	}

	t.syncMu.Lock()
	servers := t.stunServers
	t.syncMu.Unlock()

	if len(servers) == 0 && t.stunFallback != "" {
		servers = []string{t.stunFallback}
	}
	if len(servers) == 0 || t.listenPort == 0 {
		t.natBusy.Store(false)
		return
	}

	go func() {
		defer t.natBusy.Store(false)

		mapped, natType, err := checkNAT(servers)
		if err != nil {
			slog.Debug("nat check failed", "error", err)
			return
		}

		t.syncMu.Lock()
		defer t.syncMu.Unlock()

		if natType != "" && natType != t.natType {
			t.natType = natType
			slog.Info("nat classified", "type", natType)
		}

		// Refresh the reflexive v6 endpoint on the same cadence, before
		// the v4 early-return below so it runs even when the v4 IP is
		// unchanged.
		t.refreshV6Endpoint()

		mappedIP := mapped.Addr().String()
		curHost := ""
		if h, _, err := net.SplitHostPort(t.publicEndpoint); err == nil {
			curHost = h
		}

		if curHost == mappedIP {
			return
		}

		// The public IP moved (or startup STUN never succeeded). The
		// mapped PORT belongs to the throwaway socket, so advertise
		// newIP:listenPort — port-preserving NATs are the common case,
		// and the relay-observed candidate corrects the rest.
		t.publicEndpoint = net.JoinHostPort(mappedIP, strconv.Itoa(t.listenPort))
		fmt.Printf("[agent] public endpoint changed, now advertising %s\n", t.publicEndpoint)
	}()
}

// selfCandidates assembles the agent-gathered candidate list shipped
// with each report: interface addresses plus any router port mapping.
// Runs under syncMu (reads network prefixes and the mapper handle).
func (t *telemetryReporter) selfCandidates() []proto.AgentCandidate {
	if t.listenPort == 0 {
		return nil
	}

	out := gatherLocalCandidates(t.listenPort, t.advertiseV6, t.network, t.network6)

	if t.portMapper != nil {
		if ep := t.portMapper.external(); ep != "" {
			out = append(out, proto.AgentCandidate{Endpoint: ep, Type: "upnp"})
		}
	}

	// The reflexive v6 endpoint (refreshed by maybeNATCheck) is a
	// reachability-proven direct path — kept as its own candidate so a
	// v6 address that stops answering STUN drops out on the next check.
	if t.publicEndpoint6 != "" {
		out = append(out, proto.AgentCandidate{Endpoint: t.publicEndpoint6, Type: "stun6"})
	}

	// An operator-pinned endpoint (--advertise-endpoint) also rides
	// publicEndpoint, but the server cannot tell it apart from a STUN
	// guess there — and a STUN guess ranks below UPnP and v6 candidates.
	// The typed candidate lets the server rank the one endpoint the
	// operator has guaranteed above the discovered maybes.
	if t.endpointPinned && t.publicEndpoint != "" {
		out = append(out, proto.AgentCandidate{Endpoint: t.publicEndpoint, Type: "pinned"})
	}

	return out
}

// refreshV6Endpoint re-probes the reflexive v6 endpoint from a throwaway
// socket and updates publicEndpoint6. The kernel owns the WG port, so
// (like the v4 NAT check) this uses an ephemeral socket: v6 is not NATed
// in practice, so the reflected IP paired with the WG listen port is the
// endpoint peers dial. A failure clears it — a v6 path that stopped
// working must stop being advertised. Best-effort; runs under syncMu.
func (t *telemetryReporter) refreshV6Endpoint() {
	if t.noIPv6 || t.endpointPinned || t.stun6Server == "" {
		return
	}

	mapped, err := stunReflexive6(t.stun6Server)
	if err != nil {
		if t.publicEndpoint6 != "" {
			slog.Debug("v6 endpoint no longer reachable; withdrawing", "error", err)
			t.publicEndpoint6 = ""
		}
		return
	}

	ep6 := net.JoinHostPort(mapped.Addr().String(), strconv.Itoa(t.listenPort))
	if ep6 != t.publicEndpoint6 {
		t.publicEndpoint6 = ep6
		fmt.Printf("[agent] v6 direct endpoint now advertising %s\n", ep6)
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
		t.post(&proto.ReportRequest{
			PublicEndpoint: t.publicEndpoint,
			Candidates:     t.selfCandidates(),
			NATType:        t.natType,
			PathStates:     t.currentPathStates(),
		})
		return
	}

	report := &proto.ReportRequest{
		PublicEndpoint: t.publicEndpoint,
		Candidates:     t.selfCandidates(),
		NATType:        t.natType,
		Counters:       make([]proto.PeerCounter, 0, len(t.pendingCounters)),
		Flows:          make([]proto.FlowRecord, 0, len(t.pendingFlows)),
		PathStates:     t.currentPathStates(),
		ProxyEvents:    proxyEvents,
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
		if kind := t.pathKinds[peer]; kind != "" {
			return kind
		}
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
	// Mesh STUN endpoints beat the public fallback for the periodic NAT
	// checks; sticky once learned (a response without them means the
	// server build predates the field, not that STUN went away).
	if len(sync.STUNServers) > 0 {
		t.stunServers = sync.STUNServers
	}

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

		if e.Hostname != "" {
			t.hostnames[cfg.PublicKey] = e.Hostname
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
	if err := refreshGatewayNAT(t.iface, t.gatewayNATCIDRs); err != nil {
		slog.Warn("gateway NAT refresh failed", "error", err)
	}
	if err := applyGatewayRoutes(t.iface, sync.GatewayRoutes, &t.gatewayForwardOn); err != nil {
		slog.Warn("gateway route forwarding failed", "error", err)
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
				slog.Warn("dns sync not applied; configure DNS manually", "error", err)
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
