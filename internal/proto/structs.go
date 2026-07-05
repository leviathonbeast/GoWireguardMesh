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
	Peers        []PeerConfigResponse `json:"peers"`

	// AuthToken authenticates subsequent agent requests (telemetry
	// reports). Rotated on every enrollment, including idempotent
	// re-enrolls; only its hash is stored server-side.
	AuthToken string `json:"auth_token"`
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

	// Seconds.
	PersistentKeepaliveInterval *int `json:"persistent_keepalive_interval,omitempty"`

	AllowedIPs []string `json:"allowed_ips"`
}

type EndpointCandidate struct {
	Endpoint string `json:"endpoint"`
	Type     string `json:"type"`     // lan, stun
	Priority int    `json:"priority"` // larger wins
}
