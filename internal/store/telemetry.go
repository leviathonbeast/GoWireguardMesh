package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"gowireguard/internal/proto"
)

// AuthenticatePeer resolves a peer auth token to the peer's id.
// Returns ErrUnauthorized for unknown tokens and revoked peers alike.
func (s *Store) AuthenticatePeer(ctx context.Context, token string) (int64, error) {
	var id int64

	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM peers WHERE auth_token_hash = ? AND revoked_at IS NULL`,
		HashToken(token),
	).Scan(&id)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		return 0, fmt.Errorf("%w: unknown or revoked peer token", ErrUnauthorized)
	case err != nil:
		return 0, fmt.Errorf("authenticate peer: %w", err)
	}

	return id, nil
}

// ApplyReport ingests one telemetry report from peerID: bumps
// last_seen_at, accumulates link counter deltas, and appends flow
// rows. One transaction — a failed report is fully retriable.
func (s *Store) ApplyReport(ctx context.Context, peerID int64, report *proto.ReportRequest) error {
	now := time.Now().UTC().Format(timeFormat)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin report transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		`UPDATE peers SET last_seen_at = ? WHERE id = ?`, now, peerID,
	); err != nil {
		return fmt.Errorf("update last_seen_at: %w", err)
	}

	for _, c := range report.Counters {
		var remoteID int64

		err := tx.QueryRowContext(ctx,
			`SELECT id FROM peers WHERE public_key = ?`, c.PeerPublicKey,
		).Scan(&remoteID)

		switch {
		case errors.Is(err, sql.ErrNoRows):
			// The reporter may know peers the server has since hard-
			// deleted; skip rather than reject the whole report.
			continue
		case err != nil:
			return fmt.Errorf("look up remote peer %q: %w", c.PeerPublicKey, err)
		}

		var handshake sql.NullString
		if c.LastHandshakeAt != "" {
			handshake = sql.NullString{String: c.LastHandshakeAt, Valid: true}
		}

		if _, err := tx.ExecContext(ctx,
			`INSERT INTO link_stats (peer_id, remote_peer_id, rx_bytes, tx_bytes, last_handshake_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?)
			 ON CONFLICT (peer_id, remote_peer_id) DO UPDATE SET
			   rx_bytes = rx_bytes + excluded.rx_bytes,
			   tx_bytes = tx_bytes + excluded.tx_bytes,
			   last_handshake_at = COALESCE(excluded.last_handshake_at, last_handshake_at),
			   updated_at = excluded.updated_at`,
			peerID, remoteID, c.RxBytes, c.TxBytes, handshake, now,
		); err != nil {
			return fmt.Errorf("accumulate link stats: %w", err)
		}
	}

	for _, f := range report.Flows {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO flows (peer_id, protocol, src_ip, src_port, dst_ip, dst_port,
			                    tx_bytes, rx_bytes, tx_packets, rx_packets, reported_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			peerID, f.Protocol, f.SrcIP, f.SrcPort, f.DstIP, f.DstPort,
			f.TxBytes, f.RxBytes, f.TxPackets, f.RxPackets, now,
		); err != nil {
			return fmt.Errorf("insert flow: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit report: %w", err)
	}

	return nil
}

type LinkStat struct {
	PeerID          int64
	PeerHostname    string
	PeerIP          string
	RemotePeerID    int64
	RemoteHostname  string
	RemoteIP        string
	RxBytes         int64
	TxBytes         int64
	LastHandshakeAt string // "" if never
	UpdatedAt       string
}

func (s *Store) ListLinkStats(ctx context.Context) ([]LinkStat, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT l.peer_id, COALESCE(p.hostname, ''), p.assigned_ip,
		        l.remote_peer_id, COALESCE(r.hostname, ''), r.assigned_ip,
		        l.rx_bytes, l.tx_bytes, COALESCE(l.last_handshake_at, ''), l.updated_at
		 FROM link_stats l
		 JOIN peers p ON p.id = l.peer_id
		 JOIN peers r ON r.id = l.remote_peer_id
		 ORDER BY l.peer_id, l.remote_peer_id`,
	)
	if err != nil {
		return nil, fmt.Errorf("list link stats: %w", err)
	}
	defer rows.Close()

	out := []LinkStat{}

	for rows.Next() {
		var l LinkStat
		if err := rows.Scan(&l.PeerID, &l.PeerHostname, &l.PeerIP,
			&l.RemotePeerID, &l.RemoteHostname, &l.RemoteIP,
			&l.RxBytes, &l.TxBytes, &l.LastHandshakeAt, &l.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan link stat: %w", err)
		}

		out = append(out, l)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list link stats: %w", err)
	}

	return out, nil
}

type FlowRow struct {
	ID           int64
	PeerID       int64
	PeerHostname string
	Protocol     int
	SrcIP        string
	SrcPort      int
	DstIP        string
	DstPort      int
	TxBytes      int64
	RxBytes      int64
	TxPackets    int64
	RxPackets    int64
	ReportedAt   string
}

// RecentFlows returns the newest flow rows, most recent first.
func (s *Store) RecentFlows(ctx context.Context, limit int) ([]FlowRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT f.id, f.peer_id, COALESCE(p.hostname, ''), f.protocol,
		        f.src_ip, f.src_port, f.dst_ip, f.dst_port,
		        f.tx_bytes, f.rx_bytes, f.tx_packets, f.rx_packets, f.reported_at
		 FROM flows f
		 JOIN peers p ON p.id = f.peer_id
		 ORDER BY f.id DESC
		 LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list flows: %w", err)
	}
	defer rows.Close()

	out := []FlowRow{}

	for rows.Next() {
		var f FlowRow
		if err := rows.Scan(&f.ID, &f.PeerID, &f.PeerHostname, &f.Protocol,
			&f.SrcIP, &f.SrcPort, &f.DstIP, &f.DstPort,
			&f.TxBytes, &f.RxBytes, &f.TxPackets, &f.RxPackets, &f.ReportedAt); err != nil {
			return nil, fmt.Errorf("scan flow: %w", err)
		}

		out = append(out, f)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list flows: %w", err)
	}

	return out, nil
}

// PruneFlows deletes flow rows reported before the retention cutoff
// and returns how many were removed.
func (s *Store) PruneFlows(ctx context.Context, retention time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-retention).Format(timeFormat)

	res, err := s.db.ExecContext(ctx, `DELETE FROM flows WHERE reported_at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune flows: %w", err)
	}

	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("prune flows: %w", err)
	}

	return n, nil
}
