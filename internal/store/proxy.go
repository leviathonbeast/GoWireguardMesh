package store

import (
	"context"
	"fmt"
	"time"
)

// ProxyEventRow is one reverse-proxy access-log entry with the reporting
// peer resolved to a hostname.
type ProxyEventRow struct {
	ID           int64
	At           string
	PeerID       int64
	PeerHostname string
	Method       string
	Host         string
	Path         string
	Status       int
	DurationMS   int64
	ReqBytes     int64
	RespBytes    int64
	ClientIP     string
	Service      string
}

// ListProxyEvents returns the newest reverse-proxy access-log entries,
// most recent first.
func (s *Store) ListProxyEvents(ctx context.Context, limit int) ([]ProxyEventRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT pe.id, pe.at, COALESCE(pe.peer_id, 0), COALESCE(p.hostname, ''),
		        COALESCE(pe.method, ''), COALESCE(pe.host, ''), COALESCE(pe.path, ''),
		        COALESCE(pe.status, 0), COALESCE(pe.duration_ms, 0),
		        COALESCE(pe.req_bytes, 0), COALESCE(pe.resp_bytes, 0),
		        COALESCE(pe.client_ip, ''), COALESCE(pe.service, '')
		 FROM proxy_events pe
		 LEFT JOIN peers p ON p.id = pe.peer_id
		 ORDER BY pe.id DESC
		 LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list proxy events: %w", err)
	}
	defer rows.Close()

	out := []ProxyEventRow{}

	for rows.Next() {
		var e ProxyEventRow
		if err := rows.Scan(&e.ID, &e.At, &e.PeerID, &e.PeerHostname,
			&e.Method, &e.Host, &e.Path, &e.Status, &e.DurationMS,
			&e.ReqBytes, &e.RespBytes, &e.ClientIP, &e.Service); err != nil {
			return nil, fmt.Errorf("scan proxy event: %w", err)
		}
		out = append(out, e)
	}

	return out, rows.Err()
}

// PruneProxyEvents deletes access-log entries older than the retention
// window, returning how many rows were removed.
func (s *Store) PruneProxyEvents(ctx context.Context, retention time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-retention).Format(timeFormat)

	res, err := s.db.ExecContext(ctx, `DELETE FROM proxy_events WHERE at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune proxy events: %w", err)
	}

	n, _ := res.RowsAffected()

	return n, nil
}
