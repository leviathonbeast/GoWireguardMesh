package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gowireguard/internal/proto"
	"gowireguard/internal/store"
)

// handleReport ingests agent telemetry. Authenticated by the peer
// auth token issued at enrollment, not by setup keys.
func (s *server) handleReport(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	peerID, err := s.store.AuthenticatePeer(r.Context(), token)
	if err != nil {
		if errors.Is(err, store.ErrUnauthorized) {
			log.Printf("report rejected: %v", err)
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		log.Printf("report auth failed: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	var report proto.ReportRequest

	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&report); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if err := s.store.ApplyReport(r.Context(), peerID, s.clientIP(r), &report); err != nil {
		log.Printf("apply report from peer %d: %v", peerID, err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// The response doubles as config sync: the agent applies this
	// peer list, so membership and endpoint changes propagate within
	// one report interval.
	others, err := s.store.PeersForID(r.Context(), peerID)
	if err != nil {
		log.Printf("build sync payload for peer %d: %v", peerID, err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, proto.ReportResponse{Peers: s.buildPeerEntries(others)})
}

type linkStatJSON struct {
	PeerID          int64  `json:"peer_id"`
	PeerHostname    string `json:"peer_hostname,omitempty"`
	PeerIP          string `json:"peer_ip"`
	RemotePeerID    int64  `json:"remote_peer_id"`
	RemoteHostname  string `json:"remote_hostname,omitempty"`
	RemoteIP        string `json:"remote_ip"`
	RxBytes         int64  `json:"rx_bytes"`
	TxBytes         int64  `json:"tx_bytes"`
	LastHandshakeAt string `json:"last_handshake_at,omitempty"`
	UpdatedAt       string `json:"updated_at"`
}

type flowJSON struct {
	ID           int64  `json:"id"`
	PeerID       int64  `json:"peer_id"`
	PeerHostname string `json:"peer_hostname,omitempty"`
	Protocol     int    `json:"protocol"`
	SrcIP        string `json:"src_ip"`
	SrcPort      int    `json:"src_port"`
	DstIP        string `json:"dst_ip"`
	DstPort      int    `json:"dst_port"`
	TxBytes      int64  `json:"tx_bytes"`
	RxBytes      int64  `json:"rx_bytes"`
	TxPackets    int64  `json:"tx_packets"`
	RxPackets    int64  `json:"rx_packets"`
	ReportedAt   string `json:"reported_at"`
}

func (s *server) handleListLinkStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.store.ListLinkStats(r.Context())
	if err != nil {
		log.Printf("list link stats: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	out := make([]linkStatJSON, 0, len(stats))
	for _, l := range stats {
		out = append(out, linkStatJSON(l))
	}

	writeJSON(w, http.StatusOK, out)
}

func (s *server) handleListFlows(w http.ResponseWriter, r *http.Request) {
	limit := 100

	if q := r.URL.Query().Get("limit"); q != "" {
		n, err := strconv.Atoi(q)
		if err != nil || n < 1 || n > 1000 {
			writeError(w, http.StatusBadRequest, "limit must be 1-1000")
			return
		}

		limit = n
	}

	flows, err := s.store.RecentFlows(r.Context(), limit)
	if err != nil {
		log.Printf("list flows: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	out := make([]flowJSON, 0, len(flows))
	for _, f := range flows {
		out = append(out, flowJSON(f))
	}

	writeJSON(w, http.StatusOK, out)
}

// pruneFlowsLoop deletes expired flow rows hourly until ctx ends.
func (s *server) pruneFlowsLoop(ctx context.Context, retention time.Duration) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		n, err := s.store.PruneFlows(ctx, retention)
		if err != nil {
			log.Printf("prune flows: %v", err)
		} else if n > 0 {
			log.Printf("pruned %d flow rows older than %s", n, retention)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
