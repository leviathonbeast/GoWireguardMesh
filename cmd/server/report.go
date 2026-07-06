package main

import (
	"context"
	"errors"
	"log/slog"
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
			slog.Warn("report rejected", "error", err)
			// Auth failures are audited (routine successful reports
			// are not — they would flood the log every 30s).
			s.audit(r, "report_rejected", http.StatusUnauthorized, err.Error())
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		slog.Error("report auth failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	enrichRequest(r, peerID, overlayIP)

	var report proto.ReportRequest

	// 4MB bounds a burst of buffered flow records from a busy agent.
	if !decodeJSON(w, r, 4<<20, &report) {
		return
	}

	if err := s.store.ApplyReport(r.Context(), peerID, s.clientIP(r), &report); err != nil {
		slog.Error("apply report failed", "peer_id", peerID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// The response doubles as config sync: the agent applies this
	// peer list, so membership, endpoint, ACL, and PSK changes
	// propagate within one report interval.
	self, others, err := s.store.PeersForID(r.Context(), peerID)
	if err != nil {
		slog.Error("build sync payload failed", "peer_id", peerID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if err := s.coordinatePunches(r.Context(), self, others, report.PathStates); err != nil {
		slog.Debug("coordinate punch failed", "peer_id", peerID, "error", err)
	}

	entries, err := s.buildPeerEntries(self, others)
	if err != nil {
		slog.Error("build sync payload failed", "peer_id", peerID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	cfg := s.currentNetworkConfig()
	acl, err := s.buildACLPolicy(r.Context())
	if err != nil {
		slog.Error("build acl sync payload failed", "peer_id", peerID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, proto.ReportResponse{
		AssignedIP:   self.AssignedIP,
		AssignedIP6:  self.AssignedIP6,
		NetworkCIDR:  cfg.NetworkCIDR,
		NetworkCIDR6: cfg.NetworkCIDR6,
		Peers:        entries,
		ACL:          acl,
	})
}

func (s *server) coordinatePunches(ctx context.Context, self store.PeerRow, others []store.PeerRow, paths []proto.PeerPathState) error {
	if len(paths) == 0 {
		return nil
	}

	visible := make(map[string]store.PeerRow, len(others))
	for _, p := range others {
		visible[p.PublicKey] = p
	}

	online, err := s.onlinePeers(ctx, 2*time.Minute)
	if err != nil {
		return err
	}

	now := time.Now()
	for _, p := range paths {
		remote, ok := visible[p.PeerPublicKey]
		if !ok {
			continue
		}

		if shouldBumpPunchEpoch(punchDecision{
			state:            p.State,
			remoteOnline:     online[p.PeerPublicKey],
			selfCandidates:   len(endpointCandidates(remote, self)),
			remoteCandidates: len(endpointCandidates(self, remote)),
		}) {
			s.bumpPunchEpoch(self.PublicKey, remote.PublicKey, now)
		}
	}

	return nil
}

func (s *server) onlinePeers(ctx context.Context, maxAge time.Duration) (map[string]bool, error) {
	peers, err := s.store.ListPeers(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	out := make(map[string]bool, len(peers))
	for _, p := range peers {
		if p.RevokedAt != "" || p.LastSeenAt == "" {
			continue
		}
		seen, err := time.Parse(time.RFC3339Nano, p.LastSeenAt)
		if err != nil {
			continue
		}
		out[p.PublicKey] = now.Sub(seen) <= maxAge
	}

	return out, nil
}

type punchDecision struct {
	state            string
	remoteOnline     bool
	selfCandidates   int
	remoteCandidates int
}

func shouldBumpPunchEpoch(d punchDecision) bool {
	switch d.state {
	case "ws-relay", "udp-relay":
	default:
		return false
	}

	return d.remoteOnline && d.selfCandidates > 0 && d.remoteCandidates > 0
}

func (s *server) bumpPunchEpoch(keyA, keyB string, now time.Time) {
	pairID := relayPairID(keyA, keyB)

	s.punchMu.Lock()
	defer s.punchMu.Unlock()

	if s.punchEpochs == nil {
		s.punchEpochs = make(map[string]punchEpoch)
	}

	cur := s.punchEpochs[pairID]
	if !cur.bumpedAt.IsZero() && now.Sub(cur.bumpedAt) < punchCooldown {
		return
	}

	cur.epoch++
	cur.bumpedAt = now
	s.punchEpochs[pairID] = cur
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
	PathState       string `json:"path_state,omitempty"`
	PathEndpoint    string `json:"path_endpoint,omitempty"`
	PathUpdatedAt   string `json:"path_updated_at,omitempty"`
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
		slog.Error("list link stats failed", "error", err)
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
		slog.Error("list flows failed", "error", err)
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
			slog.Error("prune flows failed", "error", err)
		} else if n > 0 {
			slog.Debug("pruned flow rows", "count", n, "retention", retention)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
