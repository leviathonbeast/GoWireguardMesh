package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"gowireguard/internal/store"
)

// relayClient talks to the relay's control API on behalf of agents.
type relayClient struct {
	host       string // public data-plane address agents dial
	controlURL string
	secret     string
	http       *http.Client
}

func newRelayClient(host, controlURL, secretFile string) (*relayClient, error) {
	data, err := os.ReadFile(secretFile)
	if err != nil {
		return nil, fmt.Errorf("read relay secret %q: %w", secretFile, err)
	}

	return &relayClient{
		host:       host,
		controlURL: controlURL,
		secret:     strings.TrimSpace(string(data)),
		http:       &http.Client{Timeout: 5 * time.Second},
	}, nil
}

// allocate requests (or re-fetches, idempotently) the port pair for
// pairID and returns both ports.
func (rc *relayClient) allocate(pairID string) (portA, portB int, err error) {
	body, err := json.Marshal(map[string]string{"pair_id": pairID})
	if err != nil {
		return 0, 0, fmt.Errorf("encode allocate request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, rc.controlURL+"/allocate", bytes.NewReader(body))
	if err != nil {
		return 0, 0, fmt.Errorf("build allocate request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+rc.secret)

	resp, err := rc.http.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("call relay control: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return 0, 0, fmt.Errorf("read relay response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("relay control returned %s: %s", resp.Status, strings.TrimSpace(string(raw)))
	}

	var out struct {
		PortA int `json:"port_a"`
		PortB int `json:"port_b"`
	}

	if err := json.Unmarshal(raw, &out); err != nil {
		return 0, 0, fmt.Errorf("decode relay response: %w", err)
	}

	return out.PortA, out.PortB, nil
}

// handleRelayPair provisions a relay path between the authenticated
// peer and one other peer. Each side calls this independently and
// receives its own port; the pair is shared because the pair id is
// derived from the sorted public keys.
func (s *server) handleRelayPair(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	peerID, err := s.store.AuthenticatePeer(r.Context(), token)
	if err != nil {
		if errors.Is(err, store.ErrUnauthorized) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		log.Printf("relay-pair auth: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")

		return
	}

	if s.relay == nil {
		writeError(w, http.StatusServiceUnavailable, "no relay configured")
		return
	}

	var req struct {
		PeerPublicKey string `json:"peer_public_key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PeerPublicKey == "" {
		writeError(w, http.StatusBadRequest, "peer_public_key is required")
		return
	}

	selfKey, targetOK, err := s.store.RelayPairKeys(r.Context(), peerID, req.PeerPublicKey)
	if err != nil {
		log.Printf("relay-pair lookup for peer %d: %v", peerID, err)
		writeError(w, http.StatusInternalServerError, "internal error")

		return
	}

	if !targetOK {
		writeError(w, http.StatusNotFound, "unknown or revoked target peer")
		return
	}

	// One allocation per unordered pair: derive the id from the
	// sorted keys so both sides land on the same forwarding session.
	lo, hi := selfKey, req.PeerPublicKey
	if lo > hi {
		lo, hi = hi, lo
	}

	sum := sha256.Sum256([]byte(lo + "|" + hi))
	pairID := hex.EncodeToString(sum[:16])

	portA, portB, err := s.relay.allocate(pairID)
	if err != nil {
		log.Printf("relay allocate for peer %d: %v", peerID, err)
		writeError(w, http.StatusBadGateway, "relay unavailable")

		return
	}

	// Convention: port A serves the lexicographically smaller key.
	port := portA
	if selfKey != lo {
		port = portB
	}

	endpoint := net.JoinHostPort(s.relay.host, strconv.Itoa(port))

	log.Printf("relay pair %s: peer %d gets %s", pairID[:8], peerID, endpoint)
	writeJSON(w, http.StatusOK, map[string]string{"endpoint": endpoint})
}
