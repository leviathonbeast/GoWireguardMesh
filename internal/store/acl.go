package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// ACLRule is one ALLOW rule. Nil peer IDs mean "any peer"; matching
// is bidirectional. Rules only take effect under default-deny.
type ACLRule struct {
	ID        int64
	SrcPeerID *int64
	SrcLabel  string // hostname or IP, "any" for wildcard
	DstPeerID *int64
	DstLabel  string
	Name      string
	Protocol  string // any, tcp, udp, icmp, icmpv6
	PortMin   *int64
	PortMax   *int64
	CreatedAt string
}

func (s *Store) ListACLRules(ctx context.Context) ([]ACLRule, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT r.id, r.src_peer_id, r.dst_peer_id,
		        COALESCE(r.name, ''), COALESCE(r.protocol, 'any'), r.port_min, r.port_max,
		        r.created_at,
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
			r                ACLRule
			src, dst         sql.NullInt64
			portMin, portMax sql.NullInt64
		)

		if err := rows.Scan(&r.ID, &src, &dst, &r.Name, &r.Protocol, &portMin, &portMax,
			&r.CreatedAt, &r.SrcLabel, &r.DstLabel); err != nil {
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

		if portMin.Valid {
			r.PortMin = &portMin.Int64
		}
		if portMax.Valid {
			r.PortMax = &portMax.Int64
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
	return s.CreateACLRuleDetailed(ctx, ACLRule{SrcPeerID: srcPeerID, DstPeerID: dstPeerID, Protocol: "any"})
}

func (s *Store) CreateACLRuleDetailed(ctx context.Context, rule ACLRule) (int64, error) {
	return insertACLRule(ctx, s.db, rule)
}

type aclWriter interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func insertACLRule(ctx context.Context, q aclWriter, rule ACLRule) (int64, error) {
	srcPeerID, dstPeerID := rule.SrcPeerID, rule.DstPeerID
	if srcPeerID != nil && dstPeerID != nil && *srcPeerID == *dstPeerID {
		return 0, errors.New("src and dst are the same peer")
	}

	protocol, portMin, portMax, err := normalizeACLService(rule.Protocol, rule.PortMin, rule.PortMax)
	if err != nil {
		return 0, err
	}

	var src, dst sql.NullInt64

	if srcPeerID != nil {
		src = sql.NullInt64{Int64: *srcPeerID, Valid: true}
	}

	if dstPeerID != nil {
		dst = sql.NullInt64{Int64: *dstPeerID, Valid: true}
	}

	res, err := q.ExecContext(ctx,
		`INSERT INTO acl_rules (src_peer_id, dst_peer_id, name, protocol, port_min, port_max)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		src, dst, nullable(rule.Name), protocol, portMin, portMax,
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

func (s *Store) ImportACLRules(ctx context.Context, rules []ACLRule, replace bool) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin acl import: %w", err)
	}
	defer tx.Rollback()

	if replace {
		if _, err := tx.ExecContext(ctx, `DELETE FROM acl_rules`); err != nil {
			return 0, fmt.Errorf("clear acl rules: %w", err)
		}
	}

	for i, rule := range rules {
		if _, err := insertACLRule(ctx, tx, rule); err != nil {
			return 0, fmt.Errorf("import acl rule %d: %w", i+1, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit acl import: %w", err)
	}

	return len(rules), nil
}

func normalizeACLService(protocol string, portMin, portMax *int64) (string, sql.NullInt64, sql.NullInt64, error) {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol == "" {
		protocol = "any"
	}

	switch protocol {
	case "any", "tcp", "udp", "icmp", "icmpv6":
	default:
		return "", sql.NullInt64{}, sql.NullInt64{}, fmt.Errorf("protocol must be any, tcp, udp, icmp, or icmpv6")
	}

	if protocol == "icmp" || protocol == "icmpv6" {
		if portMin != nil || portMax != nil {
			return "", sql.NullInt64{}, sql.NullInt64{}, fmt.Errorf("%s rules cannot specify ports", protocol)
		}
		return protocol, sql.NullInt64{}, sql.NullInt64{}, nil
	}

	if portMin == nil && portMax == nil {
		return protocol, sql.NullInt64{}, sql.NullInt64{}, nil
	}

	min := int64(0)
	max := int64(0)
	if portMin != nil {
		min = *portMin
	}
	if portMax != nil {
		max = *portMax
	} else {
		max = min
	}
	if portMin == nil {
		min = max
	}

	if min < 1 || min > 65535 || max < 1 || max > 65535 || min > max {
		return "", sql.NullInt64{}, sql.NullInt64{}, fmt.Errorf("port range must be 1-65535 with min <= max")
	}

	return protocol,
		sql.NullInt64{Int64: min, Valid: true},
		sql.NullInt64{Int64: max, Valid: true},
		nil
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
