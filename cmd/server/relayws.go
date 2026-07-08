package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gorilla/websocket"

	"gowireguard/internal/store"
)

// wsFrameConn adapts a websocket connection to relay.FrameConn: each
// binary message is one WireGuard datagram.
type wsFrameConn struct {
	conn *websocket.Conn
}

func (c wsFrameConn) ReadFrame() ([]byte, error) {
	for {
		mt, data, err := c.conn.ReadMessage()
		if err != nil {
			return nil, err
		}
		if mt == websocket.BinaryMessage {
			return data, nil
		}
	}
}

func (c wsFrameConn) WriteFrame(b []byte) error {
	return c.conn.WriteMessage(websocket.BinaryMessage, b)
}

func (c wsFrameConn) Close() error {
	return c.conn.Close()
}

// handleRelayWS bridges two authenticated peers over WebSocket. The
// agent reaches this on the control plane's own port, so relayed
// traffic needs no firewall holes beyond the one already open for the
// API (443 behind a proxy) — matching the "only 443 + WireGuard"
// posture. Only available with the embedded relay, which shares this
// process's store for auth and ACL checks.
func (s *server) handleRelayWS(w http.ResponseWriter, r *http.Request) {
	if s.wsHub == nil {
		http.Error(w, "websocket relay not enabled", http.StatusServiceUnavailable)
		return
	}

	// Auth mirrors /report: the peer's enrollment token. Browsers
	// cannot set Authorization on a WebSocket, but agents can, and
	// this endpoint is agent-only.
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	peerID, overlayIP, err := s.store.AuthenticatePeer(r.Context(), token)
	if err != nil {
		if errors.Is(err, store.ErrUnauthorized) {
			s.audit(r, "relay_ws_rejected", http.StatusUnauthorized, err.Error())
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		slog.Error("relay-ws auth failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)

		return
	}

	enrichRequest(r, peerID, overlayIP)

	target := r.URL.Query().Get("peer")
	if target == "" {
		http.Error(w, "peer query parameter required", http.StatusBadRequest)
		return
	}

	selfKey, targetOK, err := s.store.RelayPairKeys(r.Context(), peerID, target)
	if err != nil {
		slog.Error("relay-ws pair lookup failed", "peer_id", peerID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)

		return
	}

	if !targetOK {
		http.Error(w, "unknown or revoked target peer", http.StatusNotFound)
		return
	}

	pairID := relayPairID(selfKey, target)

	// Relay sessions are long-lived while the server arms per-request
	// Read/WriteTimeout deadlines — but net/http clears both on Hijack
	// (hijackLocked does SetDeadline(time.Time{})), so the upgraded
	// connection is deliberately deadline-free from here on.
	// TestRelayWSSurvivesServerTimeouts pins that behavior.
	conn, err := websocket.Upgrade(w, r, nil, 1024, 1024)
	if err != nil {
		// Upgrade already wrote a response.
		return
	}

	// No overall deadline: relay sessions are long-lived. The read
	// loop ends when either side disconnects.
	conn.SetReadLimit(1 << 16)

	fc := wsFrameConn{conn: conn}

	slog.Info("relay-ws session opened", "peer_id", peerID, "pair", pairID[:8])
	s.audit(r, "relay_ws_open", http.StatusOK, "websocket relay pair "+pairID[:8])

	if err := s.wsHub.Serve(pairID, selfKey, fc); err != nil {
		conn.Close()
	} else {
		conn.Close()
	}

	slog.Info("relay-ws session closed", "peer_id", peerID, "pair", pairID[:8])
	s.audit(r, "relay_ws_close", http.StatusOK, "websocket relay pair "+pairID[:8])
}

// relayPairID derives the shared pair identifier from two public keys,
// order-independent — the same scheme the UDP relay path uses.
func relayPairID(keyA, keyB string) string {
	lo, hi := keyA, keyB
	if lo > hi {
		lo, hi = hi, lo
	}

	sum := sha256.Sum256([]byte(lo + "|" + hi))

	return hex.EncodeToString(sum[:16])
}
