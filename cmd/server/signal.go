package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"gowireguard/internal/store"
)

const (
	signalReadLimit    = 64 << 10
	signalWriteTimeout = 5 * time.Second
)

type signalMessage struct {
	Type    string          `json:"type"`
	From    string          `json:"from,omitempty"`
	To      string          `json:"to,omitempty"`
	At      string          `json:"at,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type signalHub struct {
	mu      sync.Mutex
	clients map[string]*signalClient
}

type signalClient struct {
	peerID    int64
	publicKey string
	conn      *websocket.Conn
	writeMu   sync.Mutex
}

func newSignalHub() *signalHub {
	return &signalHub{clients: make(map[string]*signalClient)}
}

func (h *signalHub) register(c *signalClient) {
	h.mu.Lock()
	old := h.clients[c.publicKey]
	h.clients[c.publicKey] = c
	h.mu.Unlock()

	if old != nil && old != c {
		_ = old.conn.Close()
	}
}

func (h *signalHub) unregister(c *signalClient) {
	h.mu.Lock()
	if h.clients[c.publicKey] == c {
		delete(h.clients, c.publicKey)
	}
	h.mu.Unlock()
}

func (h *signalHub) send(to string, msg signalMessage) bool {
	h.mu.Lock()
	c := h.clients[to]
	h.mu.Unlock()
	if c == nil {
		return false
	}

	return c.write(msg) == nil
}

func (h *signalHub) broadcast(msg signalMessage) int {
	h.mu.Lock()
	clients := make([]*signalClient, 0, len(h.clients))
	for _, c := range h.clients {
		clients = append(clients, c)
	}
	h.mu.Unlock()

	n := 0
	for _, c := range clients {
		if c.write(msg) == nil {
			n++
		}
	}

	return n
}

func (c *signalClient) write(msg signalMessage) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	if err := c.conn.SetWriteDeadline(time.Now().Add(signalWriteTimeout)); err != nil {
		return err
	}
	defer c.conn.SetWriteDeadline(time.Time{})

	return c.conn.WriteMessage(websocket.TextMessage, b)
}

func (s *server) signalSync(reason string) {
	if s.signalHub == nil {
		return
	}

	payload, _ := json.Marshal(map[string]string{"reason": reason})
	n := s.signalHub.broadcast(signalMessage{
		Type:    "sync-now",
		At:      time.Now().UTC().Format(time.RFC3339Nano),
		Payload: payload,
	})
	if n > 0 {
		slog.Debug("signal sync broadcast", "reason", reason, "peers", n)
	}
}

func (s *server) handleSignalWS(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	peerID, overlayIP, err := s.store.AuthenticatePeer(r.Context(), token)
	if err != nil {
		if errors.Is(err, store.ErrUnauthorized) {
			s.audit(r, "signal_rejected", http.StatusUnauthorized, err.Error())
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		slog.Error("signal auth failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)

		return
	}

	enrichRequest(r, peerID, overlayIP)

	self, _, err := s.store.PeersForID(r.Context(), peerID)
	if err != nil {
		slog.Error("signal peer lookup failed", "peer_id", peerID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	conn, err := websocket.Upgrade(w, r, nil, 1024, 1024)
	if err != nil {
		return
	}
	conn.SetReadLimit(signalReadLimit)

	client := &signalClient{
		peerID:    peerID,
		publicKey: self.PublicKey,
		conn:      conn,
	}

	s.signalHub.register(client)
	defer s.signalHub.unregister(client)
	defer conn.Close()

	slog.Info("signal session opened", "peer_id", peerID)
	s.audit(r, "signal_open", http.StatusOK, "signal websocket opened")

	_ = client.write(signalMessage{
		Type: "hello",
		To:   self.PublicKey,
		At:   time.Now().UTC().Format(time.RFC3339Nano),
	})

	for {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if mt != websocket.TextMessage {
			continue
		}

		if err := s.handleSignalMessage(r.Context(), client, data); err != nil {
			_ = client.write(signalMessage{
				Type:    "error",
				At:      time.Now().UTC().Format(time.RFC3339Nano),
				Payload: json.RawMessage(fmt.Sprintf("%q", err.Error())),
			})
		}
	}

	slog.Info("signal session closed", "peer_id", peerID)
	s.audit(r, "signal_close", http.StatusOK, "signal websocket closed")
}

func (s *server) handleSignalMessage(ctx context.Context, client *signalClient, data []byte) error {
	var msg signalMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return fmt.Errorf("invalid signal message")
	}
	if msg.Type == "" {
		return fmt.Errorf("signal type required")
	}
	if msg.Type == "hello" || msg.To == "" {
		return nil
	}

	_, others, err := s.store.PeersForID(ctx, client.peerID)
	if err != nil {
		slog.Error("signal target lookup failed", "peer_id", client.peerID, "error", err)
		return fmt.Errorf("target lookup failed")
	}

	targetOK := false
	for _, peer := range others {
		if peer.PublicKey == msg.To {
			targetOK = true
			break
		}
	}
	if !targetOK {
		return fmt.Errorf("unknown or revoked target peer")
	}

	msg.From = client.publicKey
	msg.At = time.Now().UTC().Format(time.RFC3339Nano)
	if !s.signalHub.send(msg.To, msg) {
		return fmt.Errorf("target peer is not connected to signal")
	}

	return nil
}
