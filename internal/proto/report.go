package proto

// ReportRequest is sent periodically by agents to the control plane.
// It is authenticated by the enrollment auth token, never a setup key.
type ReportRequest struct {
	// PublicEndpoint is the agent's STUN-discovered public ip:port,
	// "" when discovery failed or was disabled. Refreshed by the
	// agent's periodic endpoint re-check, so a NAT rebind or ISP
	// reconnect propagates without an agent restart.
	PublicEndpoint string `json:"public_endpoint,omitempty"`

	// Candidates are the agent's current self-gathered endpoint
	// candidates (host addresses, router port mappings). A non-empty
	// list replaces the stored one; empty means "no update".
	Candidates []AgentCandidate `json:"candidates,omitempty"`

	// NATType is the agent's classification of its NAT's mapping
	// behavior: "easy" (endpoint-independent — hole-punchable),
	// "hard" (endpoint-dependent/symmetric), or "" (unknown). The
	// control plane skips coordinating punches for hard<->hard pairs.
	NATType string `json:"nat_type,omitempty"`

	// Counters carries per-remote-peer WireGuard transfer deltas since
	// the previous successful report.
	Counters []PeerCounter `json:"counters,omitempty"`

	// Flows carries overlay flow deltas observed via conntrack since
	// the previous successful report.
	Flows []FlowRecord `json:"flows,omitempty"`

	// PathStates carries the agent's current path choice for each
	// configured remote peer: direct, quic-relay, ws-relay, udp-relay,
	// or probing-direct.
	PathStates []PeerPathState `json:"path_states,omitempty"`

	// ProxyEvents carries reverse-proxy access-log entries the agent
	// tailed from the node's reverse proxy (e.g. Traefik) since the
	// previous report. Bounded per report.
	ProxyEvents []ProxyEvent `json:"proxy_events,omitempty"`
}

// ReportResponse doubles as the config-sync channel: every accepted
// report returns the current peer list, so membership and endpoint
// changes propagate within one report interval without restarts.
type ReportResponse struct {
	AssignedIP   string               `json:"assigned_ip,omitempty"`
	AssignedIP6  string               `json:"assigned_ip6,omitempty"`
	NetworkCIDR  string               `json:"network_cidr,omitempty"`
	NetworkCIDR6 string               `json:"network_cidr6,omitempty"`
	DNS          DNSConfig            `json:"dns,omitempty"`
	Peers        []PeerConfigResponse `json:"peers"`
	ACL          *ACLPolicy           `json:"acl,omitempty"`

	// GatewayRoutes lists the overlay CIDRs this agent is the routing
	// gateway for (a routed mobile peer's /32 and /128). Non-empty ⇒
	// the agent enables forwarding without NAT for its overlay iface.
	GatewayRoutes []string `json:"gateway_routes,omitempty"`

	// STUNServers mirrors EnrollResponse.STUNServers so a running
	// agent adopts mesh STUN endpoints without re-enrolling.
	STUNServers []string `json:"stun_servers,omitempty"`
}

// PeerCounter is the reporting agent's view of one WireGuard link.
// Byte values are deltas, not cumulative kernel counters, so the
// server can accumulate across agent restarts (which reset kernel
// counters when the interface is recreated).
type PeerCounter struct {
	PeerPublicKey   string `json:"peer_public_key"`
	RxBytes         int64  `json:"rx_bytes"`
	TxBytes         int64  `json:"tx_bytes"`
	LastHandshakeAt string `json:"last_handshake_at,omitempty"` // RFC3339, "" if never
}

type PeerPathState struct {
	PeerPublicKey string `json:"peer_public_key"`
	State         string `json:"state"`
	Endpoint      string `json:"endpoint,omitempty"`
}

// FlowRecord is one aggregated overlay flow observed on the reporting
// node. Src is the flow initiator (conntrack's original direction);
// TxBytes/TxPackets flow initiator->responder, Rx the reverse. All
// counter values are deltas since the previous successful report.
// Header-level data only — payloads are never captured.
type FlowRecord struct {
	Protocol  int    `json:"protocol"` // IP protocol number (6 tcp, 17 udp, ...)
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DstIP     string `json:"dst_ip"`
	DstPort   int    `json:"dst_port"`
	TxBytes   int64  `json:"tx_bytes"`
	RxBytes   int64  `json:"rx_bytes"`
	TxPackets int64  `json:"tx_packets"`
	RxPackets int64  `json:"rx_packets"`
}

// ProxyEvent is one reverse-proxy access-log entry ingested from the
// reporting node's reverse proxy (e.g. Traefik). Values are as the proxy
// logged them; the mesh only stores and displays them.
type ProxyEvent struct {
	At         string `json:"at"`     // RFC3339
	Method     string `json:"method"` // GET/POST/...
	Host       string `json:"host"`   // request host
	Path       string `json:"path"`   // request path
	Status     int    `json:"status"` // HTTP status code
	DurationMS int64  `json:"duration_ms"`
	ReqBytes   int64  `json:"req_bytes"`
	RespBytes  int64  `json:"resp_bytes"`
	ClientIP   string `json:"client_ip"`
	Service    string `json:"service,omitempty"` // backend/router name
}
