package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// AuditEntry is one security-relevant event. Routine telemetry
// reports are NOT audited (they would flood the table); auth
// failures, enrollments, revocations, ACL and key changes, and relay
// sessions are. detail must never contain a secret.
type AuditEntry struct {
	Event        string
	PeerID       int64  // 0 = none
	OverlayIP    string // peer's WireGuard IP, when known
	RemoteIP     string // underlay source as the server saw it
	ForwardedFor string // raw X-Forwarded-For chain
	UserAgent    string
	Method       string
	Path         string
	Status       int
	Detail       string
}

// Audit appends one entry. Auditing must never break the request it
// describes, so callers log-and-continue on error rather than failing.
func (s *Store) Audit(ctx context.Context, e AuditEntry) error {
	var peerID sql.NullInt64
	if e.PeerID > 0 {
		peerID = sql.NullInt64{Int64: e.PeerID, Valid: true}
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_log
		   (event, peer_id, overlay_ip, remote_ip, forwarded_for, user_agent, method, path, status, detail)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Event, peerID, nullable(e.OverlayIP), nullable(e.RemoteIP),
		nullable(e.ForwardedFor), nullable(e.UserAgent),
		nullable(e.Method), nullable(e.Path), e.Status, nullable(e.Detail),
	)
	if err != nil {
		return fmt.Errorf("write audit entry: %w", err)
	}

	return nil
}

type AuditRow struct {
	ID           int64
	At           string
	Event        string
	PeerID       int64  // 0 = none
	PeerHostname string // "" if none/unknown
	OverlayIP    string
	RemoteIP     string
	ForwardedFor string
	UserAgent    string
	Method       string
	Path         string
	Status       int
	Detail       string
}

// ListAuditLog returns the newest audit entries, most recent first.
func (s *Store) ListAuditLog(ctx context.Context, limit int) ([]AuditRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT a.id, a.at, a.event,
		        COALESCE(a.peer_id, 0), COALESCE(p.hostname, ''),
		        COALESCE(a.overlay_ip, ''), COALESCE(a.remote_ip, ''),
		        COALESCE(a.forwarded_for, ''), COALESCE(a.user_agent, ''),
		        COALESCE(a.method, ''), COALESCE(a.path, ''),
		        COALESCE(a.status, 0), COALESCE(a.detail, '')
		 FROM audit_log a
		 LEFT JOIN peers p ON p.id = a.peer_id
		 ORDER BY a.id DESC
		 LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list audit log: %w", err)
	}
	defer rows.Close()

	out := []AuditRow{}

	for rows.Next() {
		var a AuditRow
		if err := rows.Scan(&a.ID, &a.At, &a.Event,
			&a.PeerID, &a.PeerHostname, &a.OverlayIP, &a.RemoteIP,
			&a.ForwardedFor, &a.UserAgent, &a.Method, &a.Path,
			&a.Status, &a.Detail); err != nil {
			return nil, fmt.Errorf("scan audit row: %w", err)
		}

		out = append(out, a)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list audit log: %w", err)
	}

	return out, nil
}

// PruneAuditLog deletes audit rows older than the retention cutoff.
func (s *Store) PruneAuditLog(ctx context.Context, retention time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-retention).Format(timeFormat)

	res, err := s.db.ExecContext(ctx, `DELETE FROM audit_log WHERE at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune audit log: %w", err)
	}

	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("prune audit log: %w", err)
	}

	return n, nil
}
