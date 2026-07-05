package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
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

func (s *server) handleListPeers(w http.ResponseWriter, r *http.Request) {
	peers, err := s.store.ListPeers(r.Context())
	if err != nil {
		log.Printf("list peers: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	out := make([]peerJSON, 0, len(peers))
	for _, p := range peers {
		out = append(out, peerJSON(p))
	}

	writeJSON(w, http.StatusOK, out)
}

func (s *server) handleListSetupKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.store.ListSetupKeys(r.Context())
	if err != nil {
		log.Printf("list setup keys: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	out := make([]setupKeyJSON, 0, len(keys))
	for _, k := range keys {
		out = append(out, setupKeyJSON(k))
	}

	writeJSON(w, http.StatusOK, out)
}

func (s *server) handleCreateSetupKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MaxUses   int    `json:"max_uses"`             // 0 = unlimited
		ExpiresIn string `json:"expires_in,omitempty"` // Go duration, "" = never
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
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
		log.Printf("create setup key: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	log.Printf("admin created setup key (max_uses=%d, expires_in=%q)", req.MaxUses, req.ExpiresIn)
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
		log.Printf("revoke %s %d: %v", kind, id, err)
		writeError(w, http.StatusInternalServerError, "internal error")
	default:
		log.Printf("admin revoked %s %d", kind, id)
		s.audit(r, "revoke", http.StatusOK, fmt.Sprintf("%s id=%d", kind, id))
		writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
	}
}
