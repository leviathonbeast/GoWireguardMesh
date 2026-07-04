package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrNotFound is returned by revoke operations when the target row
// does not exist or is already revoked.
var ErrNotFound = errors.New("not found or already revoked")

type PeerInfo struct {
	ID         int64
	PublicKey  string
	AssignedIP string
	Hostname   string // "" if unset
	ListenPort int    // 0 if unset
	CreatedAt  string
	LastSeenAt string // "" if never
	RevokedAt  string // "" if active
}

type SetupKeyInfo struct {
	ID           int64
	Key          string
	CreatedAt    string
	ExpiresAt    string // "" if never
	RevokedAt    string // "" if active
	MaxUses      int    // 0 = unlimited
	UsesConsumed int
}

func (s *Store) ListPeers(ctx context.Context) ([]PeerInfo, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, public_key, assigned_ip, hostname, listen_port,
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

		if err := rows.Scan(&p.ID, &p.PublicKey, &p.AssignedIP, &hostname, &port,
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
		`SELECT id, key, created_at, expires_at, revoked_at, max_uses, uses_consumed
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

		if err := rows.Scan(&k.ID, &k.Key, &k.CreatedAt, &expires, &revoked,
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
