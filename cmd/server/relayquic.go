package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	quic "github.com/quic-go/quic-go"

	"gowireguard/internal/store"
)

const relayQUICALPN = "wgmesh-relay/1"

type quicRelayAuth struct {
	Token  string `json:"token"`
	Target string `json:"target"`
}

type quicFrameConn struct{ conn *quic.Conn }

func (c quicFrameConn) ReadFrame() ([]byte, error) {
	return c.conn.ReceiveDatagram(context.Background())
}
func (c quicFrameConn) WriteFrame(b []byte) error { return c.conn.SendDatagram(b) }
func (c quicFrameConn) Close() error              { return c.conn.CloseWithError(0, "closed") }

func relayEndpointHost(raw string) string {
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return host
	}
	return strings.Trim(raw, "[]")
}

func (s *server) handleRelayQUICInfo(w http.ResponseWriter, r *http.Request) {
	if s.quicHub == nil || s.quicEndpoint == "" {
		http.Error(w, "quic relay not enabled", http.StatusServiceUnavailable)
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	peerID, _, err := s.store.AuthenticatePeer(r.Context(), token)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Peer string `json:"peer_public_key"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if _, ok, err := s.store.RelayPairKeys(r.Context(), peerID, req.Peer); err != nil || !ok {
		http.Error(w, "unknown or revoked target peer", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"endpoint": s.quicEndpoint})
}

// quicFileTLSConfig serves the QUIC relay from an on-disk pair (the
// self-signed/pinned mode); ACME mode passes certmagic's config instead.
func quicFileTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load QUIC TLS certificate: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{relayQUICALPN},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func (s *server) startQUICRelay(port int, tlsConf *tls.Config) (func(), error) {
	ln, err := quic.ListenAddr(net.JoinHostPort("", fmt.Sprint(port)), tlsConf,
		&quic.Config{EnableDatagrams: true, KeepAlivePeriod: 20 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("listen QUIC relay: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			conn, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			go s.serveQUICRelay(conn)
		}
	}()
	slog.Info("QUIC relay enabled", "endpoint", s.quicEndpoint, "udp_port", port)

	return func() { cancel(); _ = ln.Close() }, nil
}

func (s *server) serveQUICRelay(conn *quic.Conn) {
	defer conn.CloseWithError(0, "closed")
	ctx := conn.Context()
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return
	}

	var auth quicRelayAuth
	if err := json.NewDecoder(io.LimitReader(stream, 64<<10)).Decode(&auth); err != nil {
		_ = conn.CloseWithError(1, "invalid authentication")
		return
	}
	peerID, _, err := s.store.AuthenticatePeer(ctx, auth.Token)
	if err != nil {
		if errors.Is(err, store.ErrUnauthorized) {
			_ = conn.CloseWithError(2, "unauthorized")
		}
		return
	}
	selfKey, targetOK, err := s.store.RelayPairKeys(ctx, peerID, auth.Target)
	if err != nil || !targetOK {
		_ = conn.CloseWithError(3, "target unavailable")
		return
	}
	if !conn.ConnectionState().SupportsDatagrams.Remote {
		_ = conn.CloseWithError(4, "datagrams required")
		return
	}
	if _, err := stream.Write([]byte("ok\n")); err != nil {
		return
	}
	_ = stream.Close()

	pairID := relayPairID(selfKey, auth.Target)
	slog.Info("relay-quic session opened", "peer_id", peerID, "pair", pairID[:8])
	_ = s.quicHub.Serve(pairID, selfKey, quicFrameConn{conn: conn})
}
