package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"gowireguard/internal/proto"
)

// AuthenticatePeer resolves a peer auth token to the peer's id and
// overlay IP. Returns ErrUnauthorized for unknown tokens, revoked
// peers, and (when TokenTTL is set) tokens older than the TTL — all
// indistinguishable to the caller; the wrapped detail is for logs.
func (s *Store) AuthenticatePeer(ctx context.Context, token string) (id int64, overlayIP string, err error) {
	var issuedAt sql.NullString

	err = s.db.QueryRowContext(ctx,
		`SELECT id, assigned_ip, auth_token_issued_at
		 FROM peers WHERE auth_token_hash = ? AND revoked_at IS NULL`,
		HashToken(token),
	).Scan(&id, &overlayIP, &issuedAt)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		return 0, "", fmt.Errorf("%w: unknown or revoked peer token", ErrUnauthorized)
	case err != nil:
		return 0, "", fmt.Errorf("authenticate peer: %w", err)
	}

	if s.TokenTTL > 0 && issuedAt.Valid {
		issued, perr := time.Parse(timeFormat, issuedAt.String)
		if perr == nil && time.Since(issued) > s.TokenTTL {
			return 0, "", fmt.Errorf("%w: token expired (issued %s, ttl %s)", ErrUnauthorized, issuedAt.String, s.TokenTTL)
		}
	}

	return id, overlayIP, nil
}

// ApplyReport ingests one telemetry report from peerID: bumps
// last_seen_at, refreshes the peer's endpoint hint material, and
// accumulates link counter deltas and flow rows. One transaction — a
// failed report is fully retriable.
func (s *Store) ApplyReport(ctx context.Context, peerID int64, observedIP string, report *proto.ReportRequest) error {
	now := time.Now().UTC().Format(timeFormat)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin report transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		`UPDATE peers SET last_seen_at = ?,
		        observed_ip = COALESCE(?, observed_ip),
		        public_endpoint = COALESCE(?, public_endpoint)
		 WHERE id = ?`,
		now, nullable(observedIP), nullable(report.PublicEndpoint), peerID,
	); err != nil {
		return fmt.Errorf("update last_seen_at: %w", err)
	}

	// This is the hottest write path (every agent, every interval), so
	// avoid per-row work: one key→id map instead of a SELECT per
	// counter/path row, and statements prepared once per report instead
	// of re-parsed per row (Tx.ExecContext has no statement cache in
	// modernc/sqlite).
	if len(report.Counters) > 0 || len(report.PathStates) > 0 {
		idByKey, err := peerIDsByPublicKey(ctx, tx)
		if err != nil {
			return err
		}

		if len(report.Counters) > 0 {
			stmt, err := tx.PrepareContext(ctx,
				`INSERT INTO link_stats (peer_id, remote_peer_id, rx_bytes, tx_bytes, last_handshake_at, updated_at)
				 VALUES (?, ?, ?, ?, ?, ?)
				 ON CONFLICT (peer_id, remote_peer_id) DO UPDATE SET
				   rx_bytes = rx_bytes + excluded.rx_bytes,
				   tx_bytes = tx_bytes + excluded.tx_bytes,
				   last_handshake_at = COALESCE(excluded.last_handshake_at, last_handshake_at),
				   updated_at = excluded.updated_at`,
			)
			if err != nil {
				return fmt.Errorf("prepare link stats upsert: %w", err)
			}
			defer stmt.Close()

			for _, c := range report.Counters {
				remoteID, known := idByKey[c.PeerPublicKey]
				if !known {
					// The reporter may know peers the server has since
					// hard-deleted; skip rather than reject the report.
					continue
				}

				var handshake sql.NullString
				if c.LastHandshakeAt != "" {
					handshake = sql.NullString{String: c.LastHandshakeAt, Valid: true}
				}

				if _, err := stmt.ExecContext(ctx,
					peerID, remoteID, c.RxBytes, c.TxBytes, handshake, now,
				); err != nil {
					return fmt.Errorf("accumulate link stats: %w", err)
				}
			}
		}

		if len(report.PathStates) > 0 {
			stmt, err := tx.PrepareContext(ctx,
				`INSERT INTO peer_paths (peer_id, remote_peer_id, state, endpoint, updated_at)
				 VALUES (?, ?, ?, ?, ?)
				 ON CONFLICT (peer_id, remote_peer_id) DO UPDATE SET
				   state = excluded.state,
				   endpoint = excluded.endpoint,
				   updated_at = excluded.updated_at`,
			)
			if err != nil {
				return fmt.Errorf("prepare path state upsert: %w", err)
			}
			defer stmt.Close()

			// Snapshot pre-report states so we can log connection
			// transitions (direct established / relay fallback) before
			// the upsert overwrites them.
			prevStates, err := currentPathStates(ctx, tx, peerID)
			if err != nil {
				return err
			}

			evStmt, err := tx.PrepareContext(ctx,
				`INSERT INTO connection_events (reporter_peer_id, remote_peer_id, kind, from_state, to_state)
				 VALUES (?, ?, ?, ?, ?)`,
			)
			if err != nil {
				return fmt.Errorf("prepare connection event insert: %w", err)
			}
			defer evStmt.Close()

			for _, p := range report.PathStates {
				remoteID, known := idByKey[p.PeerPublicKey]
				if !known {
					continue
				}

				if kind, ok := connectionEventKind(prevStates[remoteID], p.State); ok {
					if _, err := evStmt.ExecContext(ctx,
						peerID, remoteID, kind, nullable(prevStates[remoteID]), p.State,
					); err != nil {
						return fmt.Errorf("insert connection event: %w", err)
					}
				}

				if _, err := stmt.ExecContext(ctx,
					peerID, remoteID, p.State, nullable(p.Endpoint), now,
				); err != nil {
					return fmt.Errorf("upsert path state: %w", err)
				}
			}
		}
	}

	if len(report.Flows) > 0 {
		stmt, err := tx.PrepareContext(ctx,
			`INSERT INTO flows (peer_id, protocol, src_ip, src_port, dst_ip, dst_port,
			                    tx_bytes, rx_bytes, tx_packets, rx_packets, reported_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		)
		if err != nil {
			return fmt.Errorf("prepare flow insert: %w", err)
		}
		defer stmt.Close()

		for _, f := range report.Flows {
			if _, err := stmt.ExecContext(ctx,
				peerID, f.Protocol, f.SrcIP, f.SrcPort, f.DstIP, f.DstPort,
				f.TxBytes, f.RxBytes, f.TxPackets, f.RxPackets, now,
			); err != nil {
				return fmt.Errorf("insert flow: %w", err)
			}
		}
	}

	if len(report.ProxyEvents) > 0 {
		stmt, err := tx.PrepareContext(ctx,
			`INSERT INTO proxy_events
			   (peer_id, at, method, host, path, status, duration_ms, req_bytes, resp_bytes, client_ip, service)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		)
		if err != nil {
			return fmt.Errorf("prepare proxy event insert: %w", err)
		}
		defer stmt.Close()

		for _, e := range report.ProxyEvents {
			at := e.At
			if at == "" {
				at = now
			}

			if _, err := stmt.ExecContext(ctx,
				peerID, at, nullable(e.Method), nullable(e.Host), nullable(e.Path),
				e.Status, e.DurationMS, e.ReqBytes, e.RespBytes, nullable(e.ClientIP), nullable(e.Service),
			); err != nil {
				return fmt.Errorf("insert proxy event: %w", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit report: %w", err)
	}

	return nil
}

// currentPathStates loads the reporter's stored path state per remote
// peer, so a report can be diffed against it to detect connection
// transitions worth logging.
func currentPathStates(ctx context.Context, tx *sql.Tx, peerID int64) (map[int64]string, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT remote_peer_id, state FROM peer_paths WHERE peer_id = ?`, peerID)
	if err != nil {
		return nil, fmt.Errorf("load path states: %w", err)
	}
	defer rows.Close()

	out := make(map[int64]string)

	for rows.Next() {
		var (
			id    int64
			state string
		)
		if err := rows.Scan(&id, &state); err != nil {
			return nil, fmt.Errorf("scan path state: %w", err)
		}
		out[id] = state
	}

	return out, rows.Err()
}

// peerIDsByPublicKey loads the full key→id map once, replacing a
// SELECT per report row. The peers table is small (one row per node)
// while reports can carry hundreds of rows.
func peerIDsByPublicKey(ctx context.Context, tx *sql.Tx) (map[string]int64, error) {
	rows, err := tx.QueryContext(ctx, `SELECT public_key, id FROM peers`)
	if err != nil {
		return nil, fmt.Errorf("list peer ids: %w", err)
	}
	defer rows.Close()

	out := make(map[string]int64)

	for rows.Next() {
		var (
			key string
			id  int64
		)

		if err := rows.Scan(&key, &id); err != nil {
			return nil, fmt.Errorf("scan peer id: %w", err)
		}

		out[key] = id
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list peer ids: %w", err)
	}

	return out, nil
}

// RelayPairKeys resolves the requesting peer's public key and checks
// the relay target is a known, active peer.
func (s *Store) RelayPairKeys(ctx context.Context, selfID int64, targetPublicKey string) (selfKey string, targetOK bool, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT public_key FROM peers WHERE id = ?`, selfID,
	).Scan(&selfKey)
	if err != nil {
		return "", false, fmt.Errorf("look up peer %d: %w", selfID, err)
	}

	var n int

	err = s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM peers WHERE public_key = ? AND revoked_at IS NULL`,
		targetPublicKey,
	).Scan(&n)
	if err != nil {
		return "", false, fmt.Errorf("look up target peer: %w", err)
	}

	return selfKey, n > 0, nil
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
	PathState       string
	PathEndpoint    string
	PathUpdatedAt   string
}

func (s *Store) ListLinkStats(ctx context.Context) ([]LinkStat, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT pp.peer_id, COALESCE(p.hostname, ''), p.assigned_ip,
		        pp.remote_peer_id, COALESCE(r.hostname, ''), r.assigned_ip,
		        COALESCE(l.rx_bytes, 0), COALESCE(l.tx_bytes, 0),
		        COALESCE(l.last_handshake_at, ''), COALESCE(l.updated_at, pp.updated_at),
		        pp.state, COALESCE(pp.endpoint, ''), pp.updated_at
		 FROM peer_paths pp
		 JOIN peers p ON p.id = pp.peer_id
		 JOIN peers r ON r.id = pp.remote_peer_id
		 LEFT JOIN link_stats l ON l.peer_id = pp.peer_id AND l.remote_peer_id = pp.remote_peer_id
		 ORDER BY pp.peer_id, pp.remote_peer_id`,
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
			&l.RxBytes, &l.TxBytes, &l.LastHandshakeAt, &l.UpdatedAt,
			&l.PathState, &l.PathEndpoint, &l.PathUpdatedAt); err != nil {
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
	PeerIP       string // reporter's IPv4 overlay IP, for direction labeling
	PeerIP6      string // reporter's IPv6 overlay IP, "" when not configured
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
		`SELECT f.id, f.peer_id, COALESCE(p.hostname, ''), p.assigned_ip, COALESCE(p.assigned_ip6, ''), f.protocol,
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
		if err := rows.Scan(&f.ID, &f.PeerID, &f.PeerHostname, &f.PeerIP, &f.PeerIP6, &f.Protocol,
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
