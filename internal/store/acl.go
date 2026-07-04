package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ACLRule is one ALLOW rule. Nil peer IDs mean "any peer"; matching
// is bidirectional. Rules only take effect under default-deny.
type ACLRule struct {
	ID        int64
	SrcPeerID *int64
	SrcLabel  string // hostname or IP, "any" for wildcard
	DstPeerID *int64
	DstLabel  string
	CreatedAt string
}

func (s *Store) ListACLRules(ctx context.Context) ([]ACLRule, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT r.id, r.src_peer_id, r.dst_peer_id, r.created_at,
		        COALESCE(ps.hostname, ps.assigned_ip, ''),
		        COALESCE(pd.hostname, pd.assigned_ip, '')
		 FROM acl_rules r
		 LEFT JOIN peers ps ON ps.id = r.src_peer_id
		 LEFT JOIN peers pd ON pd.id = r.dst_peer_id
		 ORDER BY r.id`,
	)
	if err != nil {
		return nil, fmt.Errorf("list acl rules: %w", err)
	}
	defer rows.Close()

	out := []ACLRule{}

	for rows.Next() {
		var (
			r        ACLRule
			src, dst sql.NullInt64
		)

		if err := rows.Scan(&r.ID, &src, &dst, &r.CreatedAt, &r.SrcLabel, &r.DstLabel); err != nil {
			return nil, fmt.Errorf("scan acl rule: %w", err)
		}

		if src.Valid {
			r.SrcPeerID = &src.Int64
		} else {
			r.SrcLabel = "any"
		}

		if dst.Valid {
			r.DstPeerID = &dst.Int64
		} else {
			r.DstLabel = "any"
		}

		out = append(out, r)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list acl rules: %w", err)
	}

	return out, nil
}

// CreateACLRule adds an ALLOW rule. Nil means "any peer". Referenced
// peers must exist (FK enforced).
func (s *Store) CreateACLRule(ctx context.Context, srcPeerID, dstPeerID *int64) (int64, error) {
	if srcPeerID != nil && dstPeerID != nil && *srcPeerID == *dstPeerID {
		return 0, errors.New("src and dst are the same peer")
	}

	var src, dst sql.NullInt64

	if srcPeerID != nil {
		src = sql.NullInt64{Int64: *srcPeerID, Valid: true}
	}

	if dstPeerID != nil {
		dst = sql.NullInt64{Int64: *dstPeerID, Valid: true}
	}

	res, err := s.db.ExecContext(ctx,
		`INSERT INTO acl_rules (src_peer_id, dst_peer_id) VALUES (?, ?)`, src, dst,
	)
	if err != nil {
		return 0, fmt.Errorf("insert acl rule: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("insert acl rule: %w", err)
	}

	return id, nil
}

func (s *Store) DeleteACLRule(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM acl_rules WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete acl rule %d: %w", id, err)
	}

	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete acl rule %d: %w", id, err)
	}

	if n == 0 {
		return fmt.Errorf("delete acl rule %d: %w", id, ErrNotFound)
	}

	return nil
}
