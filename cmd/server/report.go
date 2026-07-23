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

	// Same allowlist as enrollment: only parseable endpoints of known
	// types may enter the store — they fan out into every agent's
	// WireGuard config. Dropping all of them means "no update", which
	// matches ApplyReport's empty-list contract.
	report.Candidates = validAgentCandidates(report.Candidates)

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
	dnsCfg, err := s.store.CurrentDNSConfig(r.Context())
	if err != nil {
		slog.Error("build dns sync payload failed", "peer_id", peerID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	acl, err := s.buildACLPolicy(r.Context())
	if err != nil {
		slog.Error("build acl sync payload failed", "peer_id", peerID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, proto.ReportResponse{
		AssignedIP:     self.AssignedIP,
		AssignedIP6:    self.AssignedIP6,
		NetworkCIDR:    cfg.NetworkCIDR,
		NetworkCIDR6:   cfg.NetworkCIDR6,
		DNS:            dnsConfigProto(dnsCfg),
		Peers:          entries,
		ACL:            acl,
		GatewayRoutes:  gatewayRoutesFor(self, others),
		ExitNodeActive: exitNodeActiveFor(self, others),
		STUNServers:    s.stunServers,
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

		// Reaching direct ends the relay episode: re-arm coordination so a
		// future relay episode for this pair gets a fresh attempt budget.
		if p.State == "direct" {
			s.resetPunchAttempts(self.PublicKey, remote.PublicKey)
			continue
		}

		if shouldBumpPunchEpoch(punchDecision{
			state:            p.State,
			remoteOnline:     online[p.PeerPublicKey],
			selfCandidates:   len(s.pairCandidates(remote, self)),
			remoteCandidates: len(s.pairCandidates(self, remote)),
			selfNAT:          self.NATType,
			remoteNAT:        remote.NATType,
		}) {
			if s.bumpPunchEpoch(self.PublicKey, remote.PublicKey, now) {
				// Hole punching needs both sides sending at the same
				// time. The reporter gets the new epoch in this very
				// response; the remote would otherwise sit on it for up
				// to a full report interval, probing candidates out of
				// step. A targeted sync-now collapses that skew to
				// about a second. Best effort: a peer without a signal
				// connection still picks the epoch up on its next tick.
				s.signalPeerSync(remote.PublicKey, "punch")
			}
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
	selfNAT          string // "easy", "hard", "static" (pinned, punchable), "" unknown
	remoteNAT        string
}

func shouldBumpPunchEpoch(d punchDecision) bool {
	switch d.state {
	case "quic-relay", "ws-relay", "udp-relay":
	default:
		return false
	}

	// Two endpoint-dependent ("hard"/symmetric) NATs cannot hole-punch:
	// each side's mapping toward the other is one neither side can
	// discover. Skipping the coordination leaves their relay undisturbed
	// and saves the attempt budget for topology changes. One hard side is
	// still worth trying — the easy side's mapping is punchable. Unknown
	// ("") NATs always get the benefit of the doubt.
	if d.selfNAT == "hard" && d.remoteNAT == "hard" {
		return false
	}

	return d.remoteOnline && d.selfCandidates > 0 && d.remoteCandidates > 0
}

// bumpPunchEpoch advances the pair's punch epoch and reports whether it
// actually did (false while resting on the attempt cap or cooldown), so
// the caller only signals the remote peer for real punch windows.
func (s *server) bumpPunchEpoch(keyA, keyB string, now time.Time) bool {
	pairID := relayPairID(keyA, keyB)

	s.punchMu.Lock()
	defer s.punchMu.Unlock()

	if s.punchEpochs == nil {
		s.punchEpochs = make(map[string]punchEpoch)
	}

	cur := s.punchEpochs[pairID]

	// Give up coordinating after a few tries this relay episode; the pair
	// then settles on relay until it goes direct (resetPunchAttempts) or an
	// agent restarts. Prevents forever-thrashing a relay that cannot punch.
	if cur.attempts >= maxPunchAttempts {
		return false
	}

	// Back the cadence off per attempt (2m, 4m, 8m) so repeated failures do
	// not keep telling both agents to tear the working relay down.
	cooldown := punchCooldown << min(cur.attempts, 2)
	if !cur.bumpedAt.IsZero() && now.Sub(cur.bumpedAt) < cooldown {
		return false
	}

	cur.epoch++
	cur.attempts++
	cur.bumpedAt = now
	s.punchEpochs[pairID] = cur

	return true
}

// resetPunchAttempts re-arms coordinated punching for a pair once it has
// reached a direct path, so a later relay episode gets fresh attempts. The
// epoch counter stays monotonic (agents compare it against a high-water
// mark), only the per-episode attempt budget is cleared.
func (s *server) resetPunchAttempts(keyA, keyB string) {
	pairID := relayPairID(keyA, keyB)

	s.punchMu.Lock()
	defer s.punchMu.Unlock()

	cur, ok := s.punchEpochs[pairID]
	if !ok || cur.attempts == 0 {
		return
	}

	cur.attempts = 0
	cur.bumpedAt = time.Time{}
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
