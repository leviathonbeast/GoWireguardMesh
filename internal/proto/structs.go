package proto

// EnrollRequest is sent by a peer during enrollment.
type EnrollRequest struct {
	SetupKey   string `json:"setup_key"`
	PublicKey  string `json:"public_key"`
	Hostname   string `json:"hostname,omitempty"`
	ListenPort int    `json:"listen_port,omitempty"`

	// PublicEndpoint is the enrollee's STUN-discovered public ip:port,
	// "" when discovery failed or was disabled.
	PublicEndpoint string `json:"public_endpoint,omitempty"`
}

// EnrollResponse is returned after successful enrollment.
type EnrollResponse struct {
	PeerID       int                  `json:"peer_id"`
	AssignedIP   string               `json:"assigned_ip"`
	AssignedIP6  string               `json:"assigned_ip6,omitempty"`
	NetworkCIDR  string               `json:"network_cidr"`
	NetworkCIDR6 string               `json:"network_cidr6,omitempty"`
	DNS          DNSConfig            `json:"dns,omitempty"`
	Peers        []PeerConfigResponse `json:"peers"`
	ACL          *ACLPolicy           `json:"acl,omitempty"`

	// GatewayRoutes lists the overlay CIDRs (a routed mobile peer's
	// /32 and /128) for which THIS agent is the gateway. When non-empty
	// the agent enables IP forwarding and a FORWARD accept for its
	// overlay interface WITHOUT masquerading, so the mobile peer keeps
	// its overlay source IP end-to-end. Empty for non-gateway agents.
	GatewayRoutes []string `json:"gateway_routes,omitempty"`

	// AuthToken authenticates subsequent agent requests (telemetry
	// reports). Rotated on every enrollment, including idempotent
	// re-enrolls; only its hash is stored server-side.
	AuthToken string `json:"auth_token"`
}

type DNSConfig struct {
	Enabled       bool     `json:"enabled"`
	MagicDNS      bool     `json:"magic_dns"`
	Domain        string   `json:"domain,omitempty"`
	Nameservers   []string `json:"nameservers,omitempty"`
	SearchDomains []string `json:"search_domains,omitempty"`
}

// PeerConfigResponse is a JSON-safe representation of the peer
// configuration the agent needs to configure WireGuard locally.
//
// This intentionally does NOT mirror all of wgtypes.PeerConfig.
// It contains only wire-level state, not local apply semantics.
type PeerConfigResponse struct {
	PublicKey string `json:"public_key"`

	PresharedKey *string `json:"preshared_key,omitempty"`

	Endpoint *string `json:"endpoint,omitempty"`

	EndpointCandidates []EndpointCandidate `json:"endpoint_candidates,omitempty"`

	// PunchEpoch is a control-plane coordination hint. When it
	// increases, relayed agents probe direct candidates immediately
	// instead of waiting for their normal retry cooldown.
	PunchEpoch int `json:"punch_epoch,omitempty"`

	// Seconds.
	PersistentKeepaliveInterval *int `json:"persistent_keepalive_interval,omitempty"`

	AllowedIPs []string `json:"allowed_ips"`
}

type EndpointCandidate struct {
	Endpoint string `json:"endpoint"`
	Type     string `json:"type"`     // lan, stun
	Priority int    `json:"priority"` // larger wins
}

type ACLPolicy struct {
	DefaultPolicy string    `json:"default_policy"` // allow or deny
	Rules         []ACLRule `json:"rules,omitempty"`
}

type ACLRule struct {
	SrcIP    string `json:"src_ip,omitempty"` // empty means any
	SrcIP6   string `json:"src_ip6,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"` // empty means any
	DstIP6   string `json:"dst_ip6,omitempty"`
	Protocol string `json:"protocol"` // any, tcp, udp, icmp, icmpv6
	PortMin  int    `json:"port_min,omitempty"`
	PortMax  int    `json:"port_max,omitempty"`
}
