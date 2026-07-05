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

// requireAdmin wraps admin handlers with bearer-token auth.
func (s *server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		presented, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(presented), []byte(s.adminToken)) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		next(w, r)
	}
}

type peerJSON struct {
	ID             int64  `json:"id"`
	PublicKey      string `json:"public_key"`
	AssignedIP     string `json:"assigned_ip"`
	AssignedIP6    string `json:"assigned_ip6,omitempty"`
	HealthStatus   string `json:"health_status"`
	LastSeenAgeSec int64  `json:"last_seen_age_seconds,omitempty"`
	Hostname       string `json:"hostname,omitempty"`
	ListenPort     int    `json:"listen_port,omitempty"`
	ObservedIP     string `json:"observed_ip,omitempty"`
	PublicEndpoint string `json:"public_endpoint,omitempty"`
	CreatedAt      string `json:"created_at"`
	LastSeenAt     string `json:"last_seen_at,omitempty"`
	RevokedAt      string `json:"revoked_at,omitempty"`
}

type setupKeyJSON struct {
	ID           int64  `json:"id"`
	Key          string `json:"key"`
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
		health, age := peerHealth(p.LastSeenAt, p.RevokedAt)
		out = append(out, peerJSON{
			ID:             p.ID,
			PublicKey:      p.PublicKey,
			AssignedIP:     p.AssignedIP,
			AssignedIP6:    p.AssignedIP6,
			HealthStatus:   health,
			LastSeenAgeSec: age,
			Hostname:       p.Hostname,
			ListenPort:     p.ListenPort,
			ObservedIP:     p.ObservedIP,
			PublicEndpoint: p.PublicEndpoint,
			CreatedAt:      p.CreatedAt,
			LastSeenAt:     p.LastSeenAt,
			RevokedAt:      p.RevokedAt,
		})
	}

	writeJSON(w, http.StatusOK, out)
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

		status, age := peerHealth(p.LastSeenAt, p.RevokedAt)
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

func peerHealth(lastSeenAt, revokedAt string) (string, int64) {
	if revokedAt != "" {
		return "revoked", 0
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

	key, err := s.store.CreateSetupKey(r.Context(), req.MaxUses, expiresIn)
	if err != nil {
		slog.Error("create setup key failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	slog.Info("admin created setup key", "max_uses", req.MaxUses, "expires_in", req.ExpiresIn)
	s.audit(r, "setup_key_create", http.StatusOK, fmt.Sprintf("max_uses=%d expires_in=%q", req.MaxUses, req.ExpiresIn))
	writeJSON(w, http.StatusOK, map[string]string{"key": key})
}

func (s *server) handleRevokeSetupKey(w http.ResponseWriter, r *http.Request) {
	s.handleRevoke(w, r, s.store.RevokeSetupKey, "setup key")
}

func (s *server) handleRevokePeer(w http.ResponseWriter, r *http.Request) {
	s.handleRevoke(w, r, s.store.RevokePeer, "peer")
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
		writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
	}
}
