package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/coder/websocket"

	"gowireguard/internal/store"
)

// wsFrameConn adapts a websocket connection to relay.FrameConn: each
// binary message is one WireGuard datagram.
type wsFrameConn struct {
	conn *websocket.Conn
	ctx  context.Context
}

func (c wsFrameConn) ReadFrame() ([]byte, error) {
	_, data, err := c.conn.Read(c.ctx)
	return data, err
}

func (c wsFrameConn) WriteFrame(b []byte) error {
	return c.conn.Write(c.ctx, websocket.MessageBinary, b)
}

func (c wsFrameConn) Close() error {
	return c.conn.Close(websocket.StatusNormalClosure, "")
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

		log.Printf("relay-ws auth: %v", err)
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
		log.Printf("relay-ws lookup for peer %d: %v", peerID, err)
		http.Error(w, "internal error", http.StatusInternalServerError)

		return
	}

	if !targetOK {
		http.Error(w, "unknown or revoked target peer", http.StatusNotFound)
		return
	}

	pairID := relayPairID(selfKey, target)

	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		// Accept already wrote a response.
		return
	}

	// No overall deadline: relay sessions are long-lived. The read
	// loop ends when either side disconnects.
	conn.SetReadLimit(1 << 16)

	fc := wsFrameConn{conn: conn, ctx: context.Background()}

	log.Printf("relay-ws: peer %d joined pair %s", peerID, pairID[:8])
	s.audit(r, "relay_ws_open", http.StatusOK, "websocket relay pair "+pairID[:8])

	if err := s.wsHub.Serve(pairID, selfKey, fc); err != nil {
		conn.Close(websocket.StatusInternalError, "relay closed")
	} else {
		conn.Close(websocket.StatusNormalClosure, "")
	}

	log.Printf("relay-ws: peer %d left pair %s", peerID, pairID[:8])
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
