package store

import (
	"context"
	"fmt"
	"time"
)

// connectionEventKind classifies a path-state transition into a loggable
// connection event, or reports ok=false when the change is not worth an
// event (unchanged, a relay-transport-only change, or an intermediate
// probing state). prev is "" on the first observation of a pair.
func connectionEventKind(prev, next string) (kind string, ok bool) {
	if prev == next {
		return "", false
	}

	switch next {
	case "direct":
		return "direct", true
	case "ws-relay", "udp-relay":
		if prev == "ws-relay" || prev == "udp-relay" {
			return "", false // relay transport changed, not a new relay event
		}
		return "relay", true
	default:
		return "", false // probing-direct and anything else: not an event
	}
}

// ConnectionEventRow is one peer-to-peer connection lifecycle event with
// both ends resolved to hostnames.
type ConnectionEventRow struct {
	ID               int64
	At               string
	Kind             string // direct | relay
	FromState        string // "" when first observed
	ToState          string
	ReporterPeerID   int64
	ReporterHostname string
	RemotePeerID     int64
	RemoteHostname   string
}

// ListConnectionEvents returns the newest connection events, most recent
// first.
func (s *Store) ListConnectionEvents(ctx context.Context, limit int) ([]ConnectionEventRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT ce.id, ce.at, ce.kind, COALESCE(ce.from_state, ''), ce.to_state,
		        ce.reporter_peer_id, COALESCE(rp.hostname, ''),
		        ce.remote_peer_id, COALESCE(mp.hostname, '')
		 FROM connection_events ce
		 LEFT JOIN peers rp ON rp.id = ce.reporter_peer_id
		 LEFT JOIN peers mp ON mp.id = ce.remote_peer_id
		 ORDER BY ce.id DESC
		 LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list connection events: %w", err)
	}
	defer rows.Close()

	out := []ConnectionEventRow{}

	for rows.Next() {
		var e ConnectionEventRow
		if err := rows.Scan(&e.ID, &e.At, &e.Kind, &e.FromState, &e.ToState,
			&e.ReporterPeerID, &e.ReporterHostname,
			&e.RemotePeerID, &e.RemoteHostname); err != nil {
			return nil, fmt.Errorf("scan connection event: %w", err)
		}
		out = append(out, e)
	}

	return out, rows.Err()
}

// PruneConnectionEvents deletes events older than the retention window,
// returning how many rows were removed.
func (s *Store) PruneConnectionEvents(ctx context.Context, retention time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-retention).Format(timeFormat)

	res, err := s.db.ExecContext(ctx, `DELETE FROM connection_events WHERE at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune connection events: %w", err)
	}

	n, _ := res.RowsAffected()

	return n, nil
}
