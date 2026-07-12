package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"gowireguard/internal/store"
)

// loadOrGenerateAdminToken follows the project's load-or-generate
// pattern: a 0600 file holding a random hex token that protects the
// admin API and web UI.
func loadOrGenerateAdminToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			raw := make([]byte, 32)
			if _, err := rand.Read(raw); err != nil {
				return "", fmt.Errorf("generate admin token: %w", err)
			}

			token := hex.EncodeToString(raw)

			if err := os.WriteFile(path, []byte(token+"\n"), 0600); err != nil {
				return "", fmt.Errorf("write admin token file %q: %w", path, err)
			}

			return token, nil
		}

		return "", fmt.Errorf("read admin token file %q: %w", path, err)
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("admin token file %q is empty", path)
	}

	return token, nil
}

// loadOrGenerateSessionKey returns the HMAC key that signs web-UI session
// cookies. It is stored separately from the admin token so that rotating
// UI passwords or the bearer token does not silently invalidate the other,
// and so a leaked bearer token cannot be used to forge session cookies.
func loadOrGenerateSessionKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		key, derr := hex.DecodeString(strings.TrimSpace(string(data)))
		if derr != nil || len(key) < 32 {
			return nil, fmt.Errorf("session key file %q is malformed", path)
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read session key file %q: %w", path, err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0600); err != nil {
		return nil, fmt.Errorf("write session key file %q: %w", path, err)
	}
	return key, nil
}

// requireAdmin wraps admin handlers with bearer-token auth. The web UI
// can also authenticate with a signed HttpOnly session cookie, so the
// dashboard bundle does not need to be public just to render a login
// screen.
func (s *server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		presented, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		bearerOK := ok && subtle.ConstantTimeCompare([]byte(presented), []byte(s.adminToken)) == 1
		if !bearerOK && !s.validUISession(r) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		next(w, r)
	}
}

type peerJSON struct {
	ID              int64  `json:"id"`
	PublicKey       string `json:"public_key"`
	AssignedIP      string `json:"assigned_ip"`
	AssignedIP6     string `json:"assigned_ip6,omitempty"`
	PeerType        string `json:"peer_type"`
	GatewayPeerID   int64  `json:"gateway_peer_id,omitempty"`   // routing gateway for a mobile peer
	GatewayEndpoint string `json:"gateway_endpoint,omitempty"`  // address a static peer dials
	HasStoredConfig bool   `json:"has_stored_config,omitempty"` // GET /api/peers/{id}/config can rebuild it
	HealthStatus    string `json:"health_status"`
	LastSeenAgeSec  int64  `json:"last_seen_age_seconds,omitempty"`
	Hostname        string `json:"hostname,omitempty"`
	ListenPort      int    `json:"listen_port,omitempty"`
	ObservedIP      string `json:"observed_ip,omitempty"`
	PublicEndpoint  string `json:"public_endpoint,omitempty"`
	NATType         string `json:"nat_type,omitempty"` // easy | hard; absent when unknown
	CreatedAt       string `json:"created_at"`
	LastSeenAt      string `json:"last_seen_at,omitempty"`
	RevokedAt       string `json:"revoked_at,omitempty"`
}

type setupKeyJSON struct {
	ID           int64  `json:"id"`
	Key          string `json:"key"`
	Name         string `json:"name,omitempty"`
	CreatedAt    string `json:"created_at"`
	ExpiresAt    string `json:"expires_at,omitempty"`
	RevokedAt    string `json:"revoked_at,omitempty"`
	MaxUses      int    `json:"max_uses"` // 0 = unlimited
	UsesConsumed int    `json:"uses_consumed"`
}

const networkMigrationConfirm = "REASSIGN OVERLAY NETWORK"

type networkMigrationRequest struct {
	NetworkCIDR  string `json:"network_cidr"`
	NetworkCIDR6 string `json:"network_cidr6"`
	Confirm      string `json:"confirm,omitempty"`
}

type peerAddressRequest struct {
	AssignedIP  string `json:"assigned_ip"`
	AssignedIP6 string `json:"assigned_ip6,omitempty"`
}

type dnsConfigRequest struct {
	Enabled       bool     `json:"enabled"`
	MagicDNS      bool     `json:"magic_dns"`
	Domain        string   `json:"domain,omitempty"`
	Nameservers   []string `json:"nameservers,omitempty"`
	SearchDomains []string `json:"search_domains,omitempty"`
}

type peerPingJSON struct {
	PeerID         int64  `json:"peer_id"`
	Status         string `json:"status"`
	LastSeenAt     string `json:"last_seen_at,omitempty"`
	LastSeenAgeSec int64  `json:"last_seen_age_seconds,omitempty"`
}

func (s *server) handleListPeers(w http.ResponseWriter, r *http.Request) {
	peers, err := s.store.ListPeers(r.Context())
	if err != nil {
		slog.Error("list peers failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	out := make([]peerJSON, 0, len(peers))
	for _, p := range peers {
		out = append(out, peerInfoJSON(p))
	}

	writeJSON(w, http.StatusOK, out)
}

func peerInfoJSON(p store.PeerInfo) peerJSON {
	health, age := peerHealth(p.LastSeenAt, p.RevokedAt, p.PeerType)
	return peerJSON{
		ID:              p.ID,
		PublicKey:       p.PublicKey,
		AssignedIP:      p.AssignedIP,
		AssignedIP6:     p.AssignedIP6,
		PeerType:        peerType(p.PeerType),
		GatewayPeerID:   p.GatewayPeerID,
		GatewayEndpoint: p.GatewayEndpoint,
		HasStoredConfig: p.HasStoredConfig,
		HealthStatus:    health,
		LastSeenAgeSec:  age,
		Hostname:        p.Hostname,
		ListenPort:      p.ListenPort,
		ObservedIP:      p.ObservedIP,
		PublicEndpoint:  p.PublicEndpoint,
		NATType:         p.NATType,
		CreatedAt:       p.CreatedAt,
		LastSeenAt:      p.LastSeenAt,
		RevokedAt:       p.RevokedAt,
	}
}

func (s *server) handlePingPeer(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}

	peers, err := s.store.ListPeers(r.Context())
	if err != nil {
		slog.Error("ping peer failed", "peer_id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	for _, p := range peers {
		if p.ID != id {
			continue
		}

		status, age := peerHealth(p.LastSeenAt, p.RevokedAt, p.PeerType)
		writeJSON(w, http.StatusOK, peerPingJSON{
			PeerID:         p.ID,
			Status:         status,
			LastSeenAt:     p.LastSeenAt,
			LastSeenAgeSec: age,
		})
		return
	}

	writeError(w, http.StatusNotFound, "peer not found")
}

func peerHealth(lastSeenAt, revokedAt, kind string) (string, int64) {
	if revokedAt != "" {
		return "revoked", 0
	}
	if peerType(kind) == "static" {
		return "static", 0
	}
	if lastSeenAt == "" {
		return "offline", 0
	}

	lastSeen, err := time.Parse(time.RFC3339Nano, lastSeenAt)
	if err != nil {
		return "unknown", 0
	}

	age := int64(time.Since(lastSeen).Seconds())
	switch {
	case age <= 90:
		return "online", age
	case age <= 300:
		return "stale", age
	default:
		return "offline", age
	}
}

func peerType(kind string) string {
	switch kind {
	case "static":
		return "static"
	default:
		return "agent"
	}
}

func (s *server) handleListSetupKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.store.ListSetupKeys(r.Context())
	if err != nil {
		slog.Error("list setup keys failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	out := make([]setupKeyJSON, 0, len(keys))
	for _, k := range keys {
		out = append(out, setupKeyJSON(k))
	}

	writeJSON(w, http.StatusOK, out)
}

func (s *server) handleGetNetwork(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.currentNetworkConfig())
}

func (s *server) handleGetDNS(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.CurrentDNSConfig(r.Context())
	if err != nil {
		slog.Error("get dns config failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, cfg)
}

func (s *server) handleUpdateDNS(w http.ResponseWriter, r *http.Request) {
	var req dnsConfigRequest
	if !decodeJSON(w, r, 64<<10, &req) {
		return
	}

	cfg, err := s.store.UpdateDNSConfig(r.Context(), store.DNSConfig{
		Enabled:       req.Enabled,
		MagicDNS:      req.MagicDNS,
		Domain:        req.Domain,
		Nameservers:   req.Nameservers,
		SearchDomains: req.SearchDomains,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	slog.Info("admin updated dns settings", "enabled", cfg.Enabled, "domain", cfg.Domain, "nameservers", strings.Join(cfg.Nameservers, ","))
	s.audit(r, "dns_update", http.StatusOK,
		fmt.Sprintf("enabled=%t nameservers=%s domain=%s search=%s",
			cfg.Enabled,
			strings.Join(cfg.Nameservers, ","),
			cfg.Domain,
			strings.Join(cfg.SearchDomains, ","),
		))
	s.signalSync("dns_update")
	writeJSON(w, http.StatusOK, cfg)
}

func (s *server) handlePreviewNetworkMigration(w http.ResponseWriter, r *http.Request) {
	target4, target6, ok := s.parseNetworkMigrationRequest(w, r)
	if !ok {
		return
	}

	plan, err := s.store.PreviewNetworkMigration(r.Context(), target4, target6)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	plan.Message = "Preview only. Applying this plan reassigns overlay IPs in the control plane; running peers adopt their new self IP from the next report response."

	writeJSON(w, http.StatusOK, plan)
}

func (s *server) handleApplyNetworkMigration(w http.ResponseWriter, r *http.Request) {
	var req networkMigrationRequest
	if !decodeJSON(w, r, 64<<10, &req) {
		return
	}
	if req.Confirm != networkMigrationConfirm {
		writeError(w, http.StatusBadRequest, `confirm must be "REASSIGN OVERLAY NETWORK"`)
		return
	}

	target4, target6, ok := parseNetworkMigrationTarget(w, req)
	if !ok {
		return
	}

	plan, err := s.store.ApplyNetworkMigration(r.Context(), target4, target6)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.setNetworkConfig(plan.Target)
	plan.Message = "Overlay assignments were updated. Running peers adopt their new interface address from the next report response; restart/re-enroll also receives the new assignment."
	s.audit(r, "network_migrate", http.StatusOK,
		fmt.Sprintf("%s -> %s, %s -> %s, peers=%d",
			plan.Current.NetworkCIDR, plan.Target.NetworkCIDR,
			plan.Current.NetworkCIDR6, plan.Target.NetworkCIDR6,
			len(plan.Changes),
		))
	s.signalSync("network_migrate")

	writeJSON(w, http.StatusOK, plan)
}

func (s *server) parseNetworkMigrationRequest(w http.ResponseWriter, r *http.Request) (netip.Prefix, netip.Prefix, bool) {
	var req networkMigrationRequest
	if !decodeJSON(w, r, 64<<10, &req) {
		return netip.Prefix{}, netip.Prefix{}, false
	}

	return parseNetworkMigrationTarget(w, req)
}

func parseNetworkMigrationTarget(w http.ResponseWriter, req networkMigrationRequest) (netip.Prefix, netip.Prefix, bool) {
	target4, err := parseNetwork4(req.NetworkCIDR)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return netip.Prefix{}, netip.Prefix{}, false
	}

	target6, err := parseNetwork6(req.NetworkCIDR6)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return netip.Prefix{}, netip.Prefix{}, false
	}

	return target4, target6, true
}

func (s *server) handleCreateSetupKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name,omitempty"`
		MaxUses   int    `json:"max_uses"`             // 0 = unlimited
		ExpiresIn string `json:"expires_in,omitempty"` // Go duration, "" = never
	}

	if !decodeJSON(w, r, 64<<10, &req) {
		return
	}

	var expiresIn time.Duration

	if req.ExpiresIn != "" {
		d, err := time.ParseDuration(req.ExpiresIn)
		if err != nil {
			writeError(w, http.StatusBadRequest, "expires_in must be a Go duration (e.g. \"24h\")")
			return
		}

		expiresIn = d
	}

	key, err := s.store.CreateNamedSetupKey(r.Context(), req.Name, req.MaxUses, expiresIn)
	if err != nil {
		slog.Error("create setup key failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	slog.Info("admin created setup key", "name", req.Name, "max_uses", req.MaxUses, "expires_in", req.ExpiresIn)
	s.audit(r, "setup_key_create", http.StatusOK, fmt.Sprintf("name=%q max_uses=%d expires_in=%q", req.Name, req.MaxUses, req.ExpiresIn))
	writeJSON(w, http.StatusOK, map[string]string{"key": key})
}

func (s *server) handleRevokeSetupKey(w http.ResponseWriter, r *http.Request) {
	s.handleRevoke(w, r, s.store.RevokeSetupKey, "setup key")
}

func (s *server) handleRevokePeer(w http.ResponseWriter, r *http.Request) {
	s.handleRevoke(w, r, s.store.RevokePeer, "peer")
}

func (s *server) handleRemovePeer(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}

	switch err := s.store.RemovePeer(r.Context(), id); {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "peer not found or not revoked")
	case err != nil:
		slog.Error("remove peer failed", "peer_id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
	default:
		slog.Info("admin removed peer", "peer_id", id)
		s.audit(r, "peer_remove", http.StatusOK, fmt.Sprintf("peer id=%d", id))
		s.signalSync("peer_remove")
		writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
	}
}

func (s *server) handleUpdatePeerAddress(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}

	var req peerAddressRequest
	if !decodeJSON(w, r, 64<<10, &req) {
		return
	}

	peer, err := s.store.UpdatePeerAddress(r.Context(), id, req.AssignedIP, req.AssignedIP6)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "peer not found or revoked")
		return
	case errors.Is(err, store.ErrAddressInUse):
		writeError(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	slog.Info("admin updated peer address", "peer_id", id, "assigned_ip", peer.AssignedIP, "assigned_ip6", peer.AssignedIP6)
	s.audit(r, "peer_address_update", http.StatusOK,
		fmt.Sprintf("peer id=%d assigned_ip=%s assigned_ip6=%s", id, peer.AssignedIP, peer.AssignedIP6))
	s.signalSync("peer_address_update")
	writeJSON(w, http.StatusOK, peerInfoJSON(peer))
}

func (s *server) handleRevoke(w http.ResponseWriter, r *http.Request, revoke func(context.Context, int64) error, kind string) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}

	switch err := revoke(r.Context(), id); {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found or already revoked")
	case err != nil:
		slog.Error("revoke failed", "kind", kind, "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
	default:
		slog.Info("admin revoked", "kind", kind, "id", id)
		s.audit(r, "revoke", http.StatusOK, fmt.Sprintf("%s id=%d", kind, id))
		if kind == "peer" {
			s.signalSync("peer_revoke")
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
	}
}
