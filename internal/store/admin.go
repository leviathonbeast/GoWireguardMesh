package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// ErrNotFound is returned by revoke operations when the target row
// does not exist or is already revoked.
var ErrNotFound = errors.New("not found or already revoked")

// ErrAddressInUse is returned when an operator tries to assign an overlay
// address already reserved by another peer, including revoked peers.
var ErrAddressInUse = errors.New("address already assigned")

type PeerInfo struct {
	ID             int64
	PublicKey      string
	AssignedIP     string
	AssignedIP6    string // "" when the IPv6 overlay is not configured
	Hostname       string // "" if unset
	ListenPort     int    // 0 if unset
	ObservedIP     string // "" if unknown
	PublicEndpoint string // "" if unknown
	CreatedAt      string
	LastSeenAt     string // "" if never
	RevokedAt      string // "" if active
}

type SetupKeyInfo struct {
	ID           int64
	Key          string
	Name         string
	CreatedAt    string
	ExpiresAt    string // "" if never
	RevokedAt    string // "" if active
	MaxUses      int    // 0 = unlimited
	UsesConsumed int
}

func (s *Store) ListPeers(ctx context.Context) ([]PeerInfo, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, public_key, assigned_ip, COALESCE(assigned_ip6, ''), hostname, listen_port,
		        COALESCE(observed_ip, ''), COALESCE(public_endpoint, ''),
		        created_at, last_seen_at, revoked_at
		 FROM peers ORDER BY id`,
	)
	if err != nil {
		return nil, fmt.Errorf("list peers: %w", err)
	}
	defer rows.Close()

	out := []PeerInfo{}

	for rows.Next() {
		var (
			p        PeerInfo
			hostname sql.NullString
			port     sql.NullInt64
			lastSeen sql.NullString
			revoked  sql.NullString
		)

		if err := rows.Scan(&p.ID, &p.PublicKey, &p.AssignedIP, &p.AssignedIP6, &hostname, &port,
			&p.ObservedIP, &p.PublicEndpoint,
			&p.CreatedAt, &lastSeen, &revoked); err != nil {
			return nil, fmt.Errorf("scan peer: %w", err)
		}

		p.Hostname = hostname.String
		p.ListenPort = int(port.Int64)
		p.LastSeenAt = lastSeen.String
		p.RevokedAt = revoked.String

		out = append(out, p)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list peers: %w", err)
	}

	return out, nil
}

func (s *Store) ListSetupKeys(ctx context.Context) ([]SetupKeyInfo, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, key, COALESCE(name, ''), created_at, expires_at, revoked_at, max_uses, uses_consumed
		 FROM setup_keys ORDER BY id`,
	)
	if err != nil {
		return nil, fmt.Errorf("list setup keys: %w", err)
	}
	defer rows.Close()

	out := []SetupKeyInfo{}

	for rows.Next() {
		var (
			k       SetupKeyInfo
			expires sql.NullString
			revoked sql.NullString
			maxUses sql.NullInt64
		)

		if err := rows.Scan(&k.ID, &k.Key, &k.Name, &k.CreatedAt, &expires, &revoked,
			&maxUses, &k.UsesConsumed); err != nil {
			return nil, fmt.Errorf("scan setup key: %w", err)
		}

		k.ExpiresAt = expires.String
		k.RevokedAt = revoked.String
		k.MaxUses = int(maxUses.Int64)

		out = append(out, k)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list setup keys: %w", err)
	}

	return out, nil
}

// RevokeSetupKey marks a setup key revoked. Revocation also blocks the
// idempotent re-enroll path for peers that enrolled with this key.
func (s *Store) RevokeSetupKey(ctx context.Context, id int64) error {
	return s.revoke(ctx, "setup_keys", id)
}

// RevokePeer marks a peer revoked. The row (and its assigned IP) is
// kept: revoked peers stop appearing in enrollment responses, but
// their address is never reallocated while the row exists.
func (s *Store) RevokePeer(ctx context.Context, id int64) error {
	return s.revoke(ctx, "peers", id)
}

// RemovePeer permanently deletes an already-revoked peer. Foreign-key
// cascades remove live topology/ACL references, while audit rows keep
// their historical event text and lose the peer_id reference.
func (s *Store) RemovePeer(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM peers WHERE id = ? AND revoked_at IS NOT NULL`, id)
	if err != nil {
		return fmt.Errorf("remove peer %d: %w", id, err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("remove peer %d: %w", id, err)
	}
	if rows == 0 {
		return fmt.Errorf("remove peer %d: %w", id, ErrNotFound)
	}

	return nil
}

func (s *Store) UpdatePeerAddress(ctx context.Context, id int64, assignedIP, assignedIP6 string) (PeerInfo, error) {
	addr4, err := validateOverlayAddr("assigned_ip", assignedIP, s.network4(), true)
	if err != nil {
		return PeerInfo{}, err
	}

	var addr6 netip.Addr
	if s.v6Enabled() {
		addr6, err = validateOverlayAddr("assigned_ip6", assignedIP6, s.network6(), true)
		if err != nil {
			return PeerInfo{}, err
		}
	} else if strings.TrimSpace(assignedIP6) != "" {
		return PeerInfo{}, fmt.Errorf("assigned_ip6 cannot be set when IPv6 overlay is disabled")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PeerInfo{}, fmt.Errorf("begin peer address update: %w", err)
	}
	defer tx.Rollback()

	if err := ensurePeerAddressFree(ctx, tx, "assigned_ip", id, addr4.String()); err != nil {
		return PeerInfo{}, err
	}

	nextIP6 := sql.NullString{}
	if addr6.IsValid() {
		nextIP6 = sql.NullString{String: addr6.String(), Valid: true}
		if err := ensurePeerAddressFree(ctx, tx, "assigned_ip6", id, addr6.String()); err != nil {
			return PeerInfo{}, err
		}
	}

	res, err := tx.ExecContext(ctx,
		`UPDATE peers SET assigned_ip = ?, assigned_ip6 = ? WHERE id = ? AND revoked_at IS NULL`,
		addr4.String(), nextIP6, id,
	)
	if err != nil {
		return PeerInfo{}, fmt.Errorf("update peer %d address: %w", id, err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return PeerInfo{}, fmt.Errorf("update peer %d address: %w", id, err)
	}
	if rows == 0 {
		return PeerInfo{}, fmt.Errorf("update peer %d address: %w", id, ErrNotFound)
	}

	peer, err := getPeerInfo(ctx, tx, id)
	if err != nil {
		return PeerInfo{}, err
	}

	if err := tx.Commit(); err != nil {
		return PeerInfo{}, fmt.Errorf("commit peer address update: %w", err)
	}

	return peer, nil
}

func validateOverlayAddr(field, raw string, prefix netip.Prefix, required bool) (netip.Addr, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		if required {
			return netip.Addr{}, fmt.Errorf("%s is required", field)
		}
		return netip.Addr{}, nil
	}

	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%s must be an IP address: %w", field, err)
	}
	if !prefix.Contains(addr) {
		return netip.Addr{}, fmt.Errorf("%s %s is outside overlay network %s", field, addr, prefix)
	}
	if addr == prefix.Addr() {
		return netip.Addr{}, fmt.Errorf("%s cannot be the overlay network address %s", field, addr)
	}

	if prefix.Addr().Is4() != addr.Is4() {
		return netip.Addr{}, fmt.Errorf("%s has wrong IP family for %s", field, prefix)
	}

	return addr, nil
}

func ensurePeerAddressFree(ctx context.Context, tx *sql.Tx, column string, selfID int64, ip string) error {
	var existingID int64
	err := tx.QueryRowContext(ctx,
		`SELECT id FROM peers WHERE `+column+` = ? AND id != ? LIMIT 1`,
		ip, selfID,
	).Scan(&existingID)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return fmt.Errorf("check %s availability: %w", column, err)
	default:
		return fmt.Errorf("%w: %s belongs to peer %d", ErrAddressInUse, ip, existingID)
	}
}

func getPeerInfo(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, id int64) (PeerInfo, error) {
	var (
		p        PeerInfo
		hostname sql.NullString
		port     sql.NullInt64
		lastSeen sql.NullString
		revoked  sql.NullString
	)

	err := q.QueryRowContext(ctx,
		`SELECT id, public_key, assigned_ip, COALESCE(assigned_ip6, ''), hostname, listen_port,
		        COALESCE(observed_ip, ''), COALESCE(public_endpoint, ''),
		        created_at, last_seen_at, revoked_at
		 FROM peers WHERE id = ?`,
		id,
	).Scan(&p.ID, &p.PublicKey, &p.AssignedIP, &p.AssignedIP6, &hostname, &port,
		&p.ObservedIP, &p.PublicEndpoint,
		&p.CreatedAt, &lastSeen, &revoked)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PeerInfo{}, fmt.Errorf("peer %d: %w", id, ErrNotFound)
		}
		return PeerInfo{}, fmt.Errorf("look up peer %d: %w", id, err)
	}

	p.Hostname = hostname.String
	p.ListenPort = int(port.Int64)
	p.LastSeenAt = lastSeen.String
	p.RevokedAt = revoked.String

	return p, nil
}

func (s *Store) revoke(ctx context.Context, table string, id int64) error {
	// table is one of two compile-time constants, never user input.
	res, err := s.db.ExecContext(ctx,
		`UPDATE `+table+` SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		time.Now().UTC().Format(timeFormat), id,
	)
	if err != nil {
		return fmt.Errorf("revoke %s %d: %w", table, id, err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("revoke %s %d: %w", table, id, err)
	}

	if rows == 0 {
		return fmt.Errorf("revoke %s %d: %w", table, id, ErrNotFound)
	}

	return nil
}
