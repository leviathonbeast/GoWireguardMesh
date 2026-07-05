package main

import (
	"bytes"
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

	"gowireguard/internal/relay"
	"gowireguard/internal/store"
)

// relayAllocator hands out forwarding port pairs. Implemented by the
// embedded in-process relay and by the HTTP client for a standalone
// relay host.
type relayAllocator interface {
	allocate(pairID string) (portA, portB int, err error)
}

// embeddedRelay adapts internal/relay for in-process use: no control
// hop, no shared secret.
type embeddedRelay struct {
	rs *relay.Server
}

func (e embeddedRelay) allocate(pairID string) (int, int, error) {
	return e.rs.Allocate(pairID)
}

// relayClient talks to a standalone relay's control API.
type relayClient struct {
	controlURL string
	secret     string
	http       *http.Client
}

func newRelayClient(controlURL, secretFile string) (*relayClient, error) {
	data, err := os.ReadFile(secretFile)
	if err != nil {
		return nil, fmt.Errorf("read relay secret %q: %w", secretFile, err)
	}

	return &relayClient{
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

	if resp.StatusCode == http.StatusServiceUnavailable {
		return 0, 0, fmt.Errorf("%w: %s", relay.ErrPortsExhausted, strings.TrimSpace(string(raw)))
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

	peerID, overlayIP, err := s.store.AuthenticatePeer(r.Context(), token)
	if err != nil {
		if errors.Is(err, store.ErrUnauthorized) {
			s.audit(r, "relay_pair_rejected", http.StatusUnauthorized, err.Error())
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		log.Printf("relay-pair auth: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")

		return
	}

	enrichRequest(r, peerID, overlayIP)

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

	// One allocation per unordered pair: both sides land on the same
	// forwarding session.
	pairID := relayPairID(selfKey, req.PeerPublicKey)

	portA, portB, err := s.relay.allocate(pairID)
	if err != nil {
		log.Printf("relay allocate for peer %d: %v", peerID, err)

		if errors.Is(err, relay.ErrPortsExhausted) {
			writeError(w, http.StatusServiceUnavailable, "relay port range exhausted")
			return
		}

		writeError(w, http.StatusBadGateway, "relay unavailable")

		return
	}

	// Convention: port A serves the lexicographically smaller key, so
	// the two sides pick opposite ports of the same pair.
	port := portA
	if selfKey > req.PeerPublicKey {
		port = portB
	}

	endpoint := net.JoinHostPort(s.relayHost, strconv.Itoa(port))

	log.Printf("relay pair %s: peer %d gets %s", pairID[:8], peerID, endpoint)
	s.audit(r, "relay_pair", http.StatusOK, "udp relay via "+endpoint)
	writeJSON(w, http.StatusOK, map[string]string{"endpoint": endpoint})
}
