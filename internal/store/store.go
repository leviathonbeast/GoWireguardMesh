// Package store owns all SQLite access for the control plane.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"time"

	_ "modernc.org/sqlite"
)

// ErrUnauthorized covers every setup-key failure: unknown, revoked,
// expired, exhausted, or mismatched on re-enroll. These must be
// indistinguishable on the wire (uniform 401); the wrapped detail
// exists only for server-side logs.
var ErrUnauthorized = errors.New("unauthorized")

// timeFormat matches the schema's strftime('%Y-%m-%dT%H:%M:%fZ')
// defaults so lexicographic comparison in SQL stays valid. Never
// compare these against datetime('now'), which omits the T, the Z,
// and milliseconds — mixed formats break string ordering.
const timeFormat = "2006-01-02T15:04:05.000Z"

type Store struct {
	db      *sql.DB
	network netip.Prefix
}

type PeerRow struct {
	ID         int64
	PublicKey  string
	AssignedIP string
}

type EnrollResult struct {
	Peer    PeerRow
	Others  []PeerRow
	Created bool // false on idempotent re-enroll

	// AuthToken authenticates the peer's subsequent reports. Fresh on
	// every enrollment (re-enrolls rotate it); only the hash persists.
	AuthToken string
}

// newAuthToken mints a peer auth token and the hash stored in its place.
func newAuthToken() (token, hash string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate auth token: %w", err)
	}

	token = base64.RawURLEncoding.EncodeToString(raw)

	return token, HashToken(token), nil
}

// HashToken maps a peer auth token to its stored form.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Open opens (creating if needed) the SQLite database at path and
// ensures the schema exists. FK enforcement is per-connection, so it
// must ride in the DSN where it applies to every pooled connection.
// _txlock=immediate makes BeginTx take the write lock up front,
// serializing enrollments instead of failing them mid-transaction.
func Open(path string, network netip.Prefix, schemaSQL string) (*Store, error) {
	dsn := fmt.Sprintf(
		"file:%s?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_txlock=immediate",
		path,
	)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database %q: %w", path, err)
	}

	if err := ensureSchema(db, schemaSQL); err != nil {
		db.Close()
		return nil, err
	}

	return &Store{db: db, network: network.Masked()}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

// schemaVersion is the current PRAGMA user_version. schema.sql is the
// v1 baseline; later versions are applied as migrations on top.
const schemaVersion = 2

var migrations = map[int]string{
	2: migrationV2,
}

// migrationV2 adds telemetry: per-peer auth tokens (issued at
// enrollment, hash only), accumulated per-link WireGuard counters,
// and conntrack flow logs.
const migrationV2 = `
ALTER TABLE peers ADD COLUMN auth_token_hash TEXT;

CREATE INDEX idx_peers_auth_token_hash ON peers(auth_token_hash);

CREATE TABLE link_stats (
    peer_id           INTEGER NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    remote_peer_id    INTEGER NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    rx_bytes          INTEGER NOT NULL DEFAULT 0,
    tx_bytes          INTEGER NOT NULL DEFAULT 0,
    last_handshake_at TEXT,
    updated_at        TEXT NOT NULL,
    PRIMARY KEY (peer_id, remote_peer_id)
);

CREATE TABLE flows (
    id          INTEGER PRIMARY KEY,
    peer_id     INTEGER NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    protocol    INTEGER NOT NULL,
    src_ip      TEXT NOT NULL,
    src_port    INTEGER NOT NULL,
    dst_ip      TEXT NOT NULL,
    dst_port    INTEGER NOT NULL,
    tx_bytes    INTEGER NOT NULL,
    rx_bytes    INTEGER NOT NULL,
    tx_packets  INTEGER NOT NULL,
    rx_packets  INTEGER NOT NULL,
    reported_at TEXT NOT NULL
);

CREATE INDEX idx_flows_reported_at ON flows(reported_at);
CREATE INDEX idx_flows_peer_id ON flows(peer_id);
`

func ensureSchema(db *sql.DB, schemaSQL string) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}

	if version == 0 {
		var n int

		err := db.QueryRow(
			`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'peers'`,
		).Scan(&n)
		if err != nil {
			return fmt.Errorf("check schema: %w", err)
		}

		if n == 0 {
			if _, err := db.Exec(schemaSQL); err != nil {
				return fmt.Errorf("apply base schema: %w", err)
			}
		}

		// Databases from before versioning are the v1 baseline.
		version = 1

		if _, err := db.Exec(`PRAGMA user_version = 1`); err != nil {
			return fmt.Errorf("set schema version: %w", err)
		}
	}

	for v := version + 1; v <= schemaVersion; v++ {
		sql, ok := migrations[v]
		if !ok {
			return fmt.Errorf("missing migration for schema version %d", v)
		}

		if _, err := db.Exec(sql); err != nil {
			return fmt.Errorf("apply migration v%d: %w", v, err)
		}

		if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, v)); err != nil {
			return fmt.Errorf("set schema version %d: %w", v, err)
		}
	}

	return nil
}

// CreateSetupKey mints a new provisioning token. maxUses <= 0 means
// unlimited; expiresIn == 0 means never expires. A negative expiresIn
// creates an already-expired key (useful for testing).
func (s *Store) CreateSetupKey(ctx context.Context, maxUses int, expiresIn time.Duration) (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate setup key: %w", err)
	}

	key := base64.RawURLEncoding.EncodeToString(raw)

	var uses sql.NullInt64
	if maxUses > 0 {
		uses = sql.NullInt64{Int64: int64(maxUses), Valid: true}
	}

	var expires sql.NullString
	if expiresIn != 0 {
		expires = sql.NullString{
			String: time.Now().UTC().Add(expiresIn).Format(timeFormat),
			Valid:  true,
		}
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO setup_keys (key, max_uses, expires_at) VALUES (?, ?, ?)`,
		key, uses, expires,
	)
	if err != nil {
		return "", fmt.Errorf("insert setup key: %w", err)
	}

	return key, nil
}

// Enroll registers a peer atomically: token consumption, IP allocation,
// and the peer INSERT commit together or not at all.
//
// Idempotent re-enroll: if public_key is already registered, the
// existing row is returned (the response-lost/retry case) — provided
// the presented setup key is the same one used originally and has not
// been revoked since. Expiry and exhaustion do NOT block a retry: a
// single-use key is exhausted by the very enrollment being retried.
func (s *Store) Enroll(ctx context.Context, setupKey, publicKey, hostname string, listenPort int) (*EnrollResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	var (
		existing      PeerRow
		enrolledKeyID int64
	)

	err = tx.QueryRowContext(ctx,
		`SELECT id, assigned_ip, setup_key_id FROM peers WHERE public_key = ?`,
		publicKey,
	).Scan(&existing.ID, &existing.AssignedIP, &enrolledKeyID)

	switch {
	case err == nil:
		return s.reEnroll(ctx, tx, setupKey, publicKey, existing, enrolledKeyID)
	case errors.Is(err, sql.ErrNoRows):
		// New enrollment; fall through.
	default:
		return nil, fmt.Errorf("look up peer: %w", err)
	}

	now := time.Now().UTC().Format(timeFormat)

	res, err := tx.ExecContext(ctx,
		`UPDATE setup_keys
		 SET uses_consumed = uses_consumed + 1
		 WHERE key = ?
		   AND revoked_at IS NULL
		   AND (expires_at IS NULL OR expires_at > ?)
		   AND (max_uses IS NULL OR uses_consumed < max_uses)`,
		setupKey, now,
	)
	if err != nil {
		return nil, fmt.Errorf("consume setup key: %w", err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("consume setup key: %w", err)
	}

	if rows == 0 {
		return nil, fmt.Errorf("%w: %s", ErrUnauthorized, diagnoseKey(ctx, tx, setupKey, now))
	}

	var keyID int64
	if err := tx.QueryRowContext(ctx,
		`SELECT id FROM setup_keys WHERE key = ?`, setupKey,
	).Scan(&keyID); err != nil {
		return nil, fmt.Errorf("look up setup key id: %w", err)
	}

	ip, err := s.allocateIP(ctx, tx)
	if err != nil {
		return nil, err
	}

	var host sql.NullString
	if hostname != "" {
		host = sql.NullString{String: hostname, Valid: true}
	}

	var port sql.NullInt64
	if listenPort > 0 {
		port = sql.NullInt64{Int64: int64(listenPort), Valid: true}
	}

	token, tokenHash, err := newAuthToken()
	if err != nil {
		return nil, err
	}

	insert, err := tx.ExecContext(ctx,
		`INSERT INTO peers (public_key, assigned_ip, hostname, listen_port, setup_key_id, auth_token_hash)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		publicKey, ip, host, port, keyID, tokenHash,
	)
	if err != nil {
		return nil, fmt.Errorf("insert peer: %w", err)
	}

	peerID, err := insert.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("insert peer: %w", err)
	}

	others, err := listOthers(ctx, tx, publicKey)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit enrollment: %w", err)
	}

	return &EnrollResult{
		Peer:      PeerRow{ID: peerID, PublicKey: publicKey, AssignedIP: ip},
		Others:    others,
		Created:   true,
		AuthToken: token,
	}, nil
}

// reEnroll handles the idempotent path. The presented key must exist,
// match the key the peer originally enrolled with, and not be revoked.
func (s *Store) reEnroll(ctx context.Context, tx *sql.Tx, setupKey, publicKey string, existing PeerRow, enrolledKeyID int64) (*EnrollResult, error) {
	var (
		presentedID int64
		revokedAt   sql.NullString
	)

	err := tx.QueryRowContext(ctx,
		`SELECT id, revoked_at FROM setup_keys WHERE key = ?`, setupKey,
	).Scan(&presentedID, &revokedAt)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, fmt.Errorf("%w: re-enroll with unknown setup key", ErrUnauthorized)
	case err != nil:
		return nil, fmt.Errorf("look up setup key: %w", err)
	case revokedAt.Valid:
		return nil, fmt.Errorf("%w: re-enroll with revoked setup key", ErrUnauthorized)
	case presentedID != enrolledKeyID:
		return nil, fmt.Errorf("%w: re-enroll setup key does not match original enrollment", ErrUnauthorized)
	}

	// Rotate the auth token: the original was only ever stored as a
	// hash, so a retrying agent needs a fresh one to keep reporting.
	token, tokenHash, err := newAuthToken()
	if err != nil {
		return nil, err
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE peers SET auth_token_hash = ? WHERE id = ?`, tokenHash, existing.ID,
	); err != nil {
		return nil, fmt.Errorf("rotate auth token: %w", err)
	}

	others, err := listOthers(ctx, tx, publicKey)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit re-enroll: %w", err)
	}

	existing.PublicKey = publicKey

	return &EnrollResult{Peer: existing, Others: others, Created: false, AuthToken: token}, nil
}

// allocateIP returns the lowest free host address in the overlay
// network. Revoked peers keep their rows, so their IPs stay reserved;
// an IP is only ever reused after a hard DELETE. That is deliberate:
// cryptokey routing means a reused IP cannot impersonate the old
// peer, but holding IPs of revoked peers avoids confusing any state
// (monitoring, logs, ACLs later) that still references them.
func (s *Store) allocateIP(ctx context.Context, tx *sql.Tx) (string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT assigned_ip FROM peers`)
	if err != nil {
		return "", fmt.Errorf("list assigned ips: %w", err)
	}
	defer rows.Close()

	used := make(map[netip.Addr]bool)

	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return "", fmt.Errorf("scan assigned ip: %w", err)
		}

		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return "", fmt.Errorf("parse assigned ip %q from database: %w", raw, err)
		}

		used[addr] = true
	}

	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("list assigned ips: %w", err)
	}

	// Skip the network address itself; start at the first host.
	for ip := s.network.Addr().Next(); s.network.Contains(ip); ip = ip.Next() {
		if !used[ip] {
			return ip.String(), nil
		}
	}

	return "", fmt.Errorf("network %s has no free addresses", s.network)
}

func listOthers(ctx context.Context, tx *sql.Tx, publicKey string) ([]PeerRow, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT id, public_key, assigned_ip
		 FROM peers
		 WHERE revoked_at IS NULL AND public_key != ?
		 ORDER BY id`,
		publicKey,
	)
	if err != nil {
		return nil, fmt.Errorf("list peers: %w", err)
	}
	defer rows.Close()

	var out []PeerRow

	for rows.Next() {
		var p PeerRow
		if err := rows.Scan(&p.ID, &p.PublicKey, &p.AssignedIP); err != nil {
			return nil, fmt.Errorf("scan peer: %w", err)
		}

		out = append(out, p)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list peers: %w", err)
	}

	return out, nil
}

// diagnoseKey explains (for logs only) why the consumption UPDATE
// matched no rows. Best effort: on query error it still returns a
// usable string.
func diagnoseKey(ctx context.Context, tx *sql.Tx, setupKey, now string) string {
	var (
		revokedAt sql.NullString
		expiresAt sql.NullString
		maxUses   sql.NullInt64
		consumed  int64
	)

	err := tx.QueryRowContext(ctx,
		`SELECT revoked_at, expires_at, max_uses, uses_consumed FROM setup_keys WHERE key = ?`,
		setupKey,
	).Scan(&revokedAt, &expiresAt, &maxUses, &consumed)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "unknown setup key"
	case err != nil:
		return fmt.Sprintf("setup key rejected (diagnosis failed: %v)", err)
	case revokedAt.Valid:
		return "setup key revoked at " + revokedAt.String
	case expiresAt.Valid && expiresAt.String <= now:
		return "setup key expired at " + expiresAt.String
	case maxUses.Valid && consumed >= maxUses.Int64:
		return fmt.Sprintf("setup key exhausted (%d/%d uses)", consumed, maxUses.Int64)
	default:
		return "setup key rejected for unknown reason"
	}
}
