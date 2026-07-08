package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	signalReconnectMin = 2 * time.Second
	signalReconnectMax = 30 * time.Second
)

type agentSignalMessage struct {
	Type    string          `json:"type"`
	From    string          `json:"from,omitempty"`
	To      string          `json:"to,omitempty"`
	At      string          `json:"at,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

func (t *telemetryReporter) runSignal(stop <-chan struct{}) {
	backoff := signalReconnectMin

	for {
		select {
		case <-stop:
			return
		default:
		}

		wsURL, err := signalWSURL(t.serverURL)
		if err != nil {
			slog.Debug("signal disabled", "error", err)
			return
		}

		conn, err := t.dialSignal(stop, wsURL)
		if err != nil {
			slog.Debug("signal dial failed", "error", err)
			if !sleepSignalBackoff(stop, backoff) {
				return
			}
			backoff = nextSignalBackoff(backoff)
			continue
		}

		slog.Info("signal connected")
		backoff = signalReconnectMin

		if err := t.readSignal(stop, conn); err != nil {
			slog.Debug("signal disconnected", "error", err)
		}

		if !sleepSignalBackoff(stop, backoff) {
			return
		}
		backoff = nextSignalBackoff(backoff)
	}
}

func (t *telemetryReporter) dialSignal(stop <-chan struct{}, wsURL string) (*websocket.Conn, error) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		select {
		case <-stop:
			cancel()
		case <-done:
		}
	}()

	conn, resp, err := t.wsDialer.DialContext(ctx, wsURL, http.Header{"Authorization": {"Bearer " + t.authToken}})
	close(done)
	cancel()

	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("dial signal ws: %s", resp.Status)
		}
		return nil, fmt.Errorf("dial signal ws: %w", err)
	}

	conn.SetReadLimit(64 << 10)

	return conn, nil
}

func (t *telemetryReporter) readSignal(stop <-chan struct{}, conn *websocket.Conn) error {
	done := make(chan struct{})

	go func() {
		select {
		case <-stop:
			_ = conn.Close()
		case <-done:
		}
	}()

	defer func() {
		close(done)
		_ = conn.Close()
	}()

	for {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			select {
			case <-stop:
				return nil
			default:
				return err
			}
		}
		if mt != websocket.TextMessage {
			continue
		}

		var msg agentSignalMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			slog.Debug("invalid signal message ignored", "error", err)
			continue
		}

		switch msg.Type {
		case "hello":
			continue
		case "sync-now":
			slog.Debug("signal requested immediate sync")
			t.syncOnce(true)
		default:
			slog.Debug("unknown signal message ignored", "type", msg.Type)
		}
	}
}

func sleepSignalBackoff(stop <-chan struct{}, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-stop:
		return false
	case <-timer.C:
		return true
	}
}

func nextSignalBackoff(d time.Duration) time.Duration {
	d *= 2
	if d > signalReconnectMax {
		return signalReconnectMax
	}
	return d
}

func signalWSURL(serverURL string) (string, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return "", fmt.Errorf("parse server url %q: %w", serverURL, err)
	}

	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	default:
		return "", fmt.Errorf("unsupported server url scheme %q", u.Scheme)
	}

	u.Path = strings.TrimRight(u.Path, "/") + "/signal"
	u.RawQuery = ""

	return u.String(), nil
}
