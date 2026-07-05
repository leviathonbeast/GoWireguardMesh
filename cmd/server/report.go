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

	peerID, overlayIP, err := s.store.AuthenticatePeer(r.Context(), token)
	if err != nil {
		if errors.Is(err, store.ErrUnauthorized) {
			log.Printf("[server] report rejected: %v", err)
			// Auth failures are audited (routine successful reports
			// are not — they would flood the log every 30s).
			s.audit(r, "report_rejected", http.StatusUnauthorized, err.Error())
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		log.Printf("[server] report auth failed: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	enrichRequest(r, peerID, overlayIP)

	var report proto.ReportRequest

	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&report); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if err := s.store.ApplyReport(r.Context(), peerID, s.clientIP(r), &report); err != nil {
		log.Printf("[server] apply report from peer %d: %v", peerID, err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// The response doubles as config sync: the agent applies this
	// peer list, so membership, endpoint, ACL, and PSK changes
	// propagate within one report interval.
	self, others, err := s.store.PeersForID(r.Context(), peerID)
	if err != nil {
		log.Printf("[server] build sync payload for peer %d: %v", peerID, err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	entries, err := s.buildPeerEntries(self, others)
	if err != nil {
		log.Printf("[server] build sync payload for peer %d: %v", peerID, err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, proto.ReportResponse{Peers: entries})
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
	ProtocolName string `json:"protocol_name"` // tcp/udp/icmp/...
	Direction    string `json:"direction"`     // egress/ingress/transit, from the reporter's view
	SrcIP        string `json:"src_ip"`
	SrcPort      int    `json:"src_port"`
	DstIP        string `json:"dst_ip"`
	DstPort      int    `json:"dst_port"`
	IngressPort  int    `json:"ingress_port"` // port traffic arrives on at the reporter
	EgressPort   int    `json:"egress_port"`  // port traffic leaves from at the reporter
	TxBytes      int64  `json:"tx_bytes"`
	RxBytes      int64  `json:"rx_bytes"`
	TxPackets    int64  `json:"tx_packets"`
	RxPackets    int64  `json:"rx_packets"`
	ReportedAt   string `json:"reported_at"`
}

// protocolName maps IP protocol numbers to names.
func protocolName(p int) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	default:
		return strconv.Itoa(p)
	}
}

// flowDirection classifies a flow relative to the reporting peer's
// overlay IP. Conntrack's original tuple is initiator->responder, so
// src == the reporter means it opened the connection (egress); dst ==
// the reporter means something reached in to it (ingress). Ingress and
// egress ports are labeled from the reporter's own vantage: the port
// on its side that traffic arrives at vs. leaves from.
func flowDirection(peerIP, peerIP6, srcIP string, srcPort int, dstIP string, dstPort int) (dir string, ingressPort, egressPort int) {
	switch {
	case srcIP == peerIP || (peerIP6 != "" && srcIP == peerIP6):
		// Reporter initiated: it sends from srcPort, replies arrive there.
		return "egress", srcPort, dstPort
	case dstIP == peerIP || (peerIP6 != "" && dstIP == peerIP6):
		// Reporter received: traffic arrives on dstPort, it replies from dstPort.
		return "ingress", dstPort, srcPort
	default:
		return "transit", dstPort, srcPort
	}
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
		dir, ingressPort, egressPort := flowDirection(f.PeerIP, f.PeerIP6, f.SrcIP, f.SrcPort, f.DstIP, f.DstPort)

		out = append(out, flowJSON{
			ID:           f.ID,
			PeerID:       f.PeerID,
			PeerHostname: f.PeerHostname,
			Protocol:     f.Protocol,
			ProtocolName: protocolName(f.Protocol),
			Direction:    dir,
			SrcIP:        f.SrcIP,
			SrcPort:      f.SrcPort,
			DstIP:        f.DstIP,
			DstPort:      f.DstPort,
			IngressPort:  ingressPort,
			EgressPort:   egressPort,
			TxBytes:      f.TxBytes,
			RxBytes:      f.RxBytes,
			TxPackets:    f.TxPackets,
			RxPackets:    f.RxPackets,
			ReportedAt:   f.ReportedAt,
		})
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
