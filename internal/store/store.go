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

	// DefaultAllow is the ACL default policy: true means every peer
	// sees every peer unless the operator adds rules; false means
	// only rule-connected pairs see each other. Set once at startup.
	DefaultAllow bool

	// TokenTTL bounds how long a peer auth token stays valid after
	// issue. Agents re-enroll (rotating the token) at startup and on
	// expiry. Zero means no expiry. Set once at startup.
	TokenTTL time.Duration
}

type PeerRow struct {
	ID         int64
	PublicKey  string
	AssignedIP string

	// Endpoint hint material, in preference order.
	PublicEndpoint string // STUN-discovered ip:port, "" if unknown
	ObservedIP     string // enroll/report source IP, "" if unknown
	ListenPort     int    // 0 if unknown
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

// nullable maps "" to NULL so empty updates never clobber stored
// values guarded by COALESCE.
func nullable(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
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
const schemaVersion = 5

var migrations = map[int]string{
	2: migrationV2,
	3: migrationV3,
	4: migrationV4,
	5: migrationV5,
}

// migrationV5 adds a durable audit log for security-relevant events
// and records when each peer's auth token was issued, so tokens can
// expire.
const migrationV5 = `
ALTER TABLE peers ADD COLUMN auth_token_issued_at TEXT;

CREATE TABLE audit_log (
    id            INTEGER PRIMARY KEY,
    at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    event         TEXT NOT NULL,
    peer_id       INTEGER REFERENCES peers(id) ON DELETE SET NULL,
    overlay_ip    TEXT,          -- the peer's WireGuard overlay IP, when known
    remote_ip     TEXT,          -- underlay source as the server saw it
    forwarded_for TEXT,          -- raw X-Forwarded-For chain (proxy hops)
    user_agent    TEXT,
    method        TEXT,
    path          TEXT,
    status        INTEGER,
    detail        TEXT           -- event-specific note; never a secret
);

CREATE INDEX idx_audit_log_at ON audit_log(at);
CREATE INDEX idx_audit_log_event ON audit_log(event);
CREATE INDEX idx_audit_log_peer ON audit_log(peer_id);
`

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

// migrationV3 adds endpoint distribution: the underlay address the
// server observed the peer at (enroll/report source), and the public
// endpoint the peer discovered itself via STUN. The STUN endpoint is
// preferred when handing out hints; observed_ip:listen_port is the
// same-network fallback.
const migrationV3 = `
ALTER TABLE peers ADD COLUMN observed_ip TEXT;
ALTER TABLE peers ADD COLUMN public_endpoint TEXT;
`

// migrationV4 adds ACL rules. Rules are ALLOW rules, matched
// bidirectionally, with NULL meaning "any peer"; they only take
// effect under --default-policy deny. Enforcement is visibility:
// a peer never even receives config for peers it may not reach.
const migrationV4 = `
CREATE TABLE acl_rules (
    id          INTEGER PRIMARY KEY,
    src_peer_id INTEGER REFERENCES peers(id) ON DELETE CASCADE,
    dst_peer_id INTEGER REFERENCES peers(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
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
func (s *Store) Enroll(ctx context.Context, setupKey, publicKey, hostname string, listenPort int, observedIP, publicEndpoint string) (*EnrollResult, error) {
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
		`SELECT id, assigned_ip, setup_key_id,
		        COALESCE(public_endpoint, ''), COALESCE(observed_ip, ''), COALESCE(listen_port, 0)
		 FROM peers WHERE public_key = ?`,
		publicKey,
	).Scan(&existing.ID, &existing.AssignedIP, &enrolledKeyID,
		&existing.PublicEndpoint, &existing.ObservedIP, &existing.ListenPort)

	switch {
	case err == nil:
		return s.reEnroll(ctx, tx, setupKey, publicKey, existing, enrolledKeyID, observedIP, publicEndpoint, listenPort)
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
		`INSERT INTO peers (public_key, assigned_ip, hostname, listen_port, setup_key_id, auth_token_hash, auth_token_issued_at, observed_ip, public_endpoint)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		publicKey, ip, host, port, keyID, tokenHash, now,
		nullable(observedIP), nullable(publicEndpoint),
	)
	if err != nil {
		return nil, fmt.Errorf("insert peer: %w", err)
	}

	peerID, err := insert.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("insert peer: %w", err)
	}

	others, err := listVisible(ctx, tx, peerID, s.DefaultAllow)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit enrollment: %w", err)
	}

	return &EnrollResult{
		Peer: PeerRow{
			ID:             peerID,
			PublicKey:      publicKey,
			AssignedIP:     ip,
			PublicEndpoint: publicEndpoint,
			ObservedIP:     observedIP,
			ListenPort:     listenPort,
		},
		Others:    others,
		Created:   true,
		AuthToken: token,
	}, nil
}

// reEnroll handles the idempotent path. The presented key must exist,
// match the key the peer originally enrolled with, and not be revoked.
func (s *Store) reEnroll(ctx context.Context, tx *sql.Tx, setupKey, publicKey string, existing PeerRow, enrolledKeyID int64, observedIP, publicEndpoint string, listenPort int) (*EnrollResult, error) {
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

	// Refresh endpoint material along with the token: agents may come
	// back with a different listen port or address, and stale values
	// here become bad hints handed to every other peer.
	var port sql.NullInt64
	if listenPort > 0 {
		port = sql.NullInt64{Int64: int64(listenPort), Valid: true}
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE peers SET auth_token_hash = ?,
		        auth_token_issued_at = ?,
		        observed_ip = COALESCE(?, observed_ip),
		        public_endpoint = COALESCE(?, public_endpoint),
		        listen_port = COALESCE(?, listen_port)
		 WHERE id = ?`,
		tokenHash, time.Now().UTC().Format(timeFormat),
		nullable(observedIP), nullable(publicEndpoint), port, existing.ID,
	); err != nil {
		return nil, fmt.Errorf("rotate auth token: %w", err)
	}

	others, err := listVisible(ctx, tx, existing.ID, s.DefaultAllow)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit re-enroll: %w", err)
	}

	// Mirror the UPDATE's COALESCE semantics so the result row (used
	// for pairwise endpoint hints) matches what was just stored.
	existing.PublicKey = publicKey

	if observedIP != "" {
		existing.ObservedIP = observedIP
	}

	if publicEndpoint != "" {
		existing.PublicEndpoint = publicEndpoint
	}

	if listenPort > 0 {
		existing.ListenPort = listenPort
	}

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

// querier lets peer-list queries run inside or outside a transaction.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// listVisible returns the active peers selfID is allowed to reach.
// Under default-allow that is everyone else; under default-deny a
// peer is visible only when an ACL rule connects the pair. A rule
// matches bidirectionally, with NULL as a wildcard for "any peer".
// Filtering here IS the enforcement: an unauthorized peer never
// learns the other's key, overlay IP, or endpoint.
func listVisible(ctx context.Context, q querier, selfID int64, defaultAllow bool) ([]PeerRow, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT p.id, p.public_key, p.assigned_ip,
		        COALESCE(p.public_endpoint, ''), COALESCE(p.observed_ip, ''), COALESCE(p.listen_port, 0)
		 FROM peers p
		 WHERE p.revoked_at IS NULL AND p.id != ?
		   AND (? OR EXISTS (
		       SELECT 1 FROM acl_rules r
		       WHERE (r.src_peer_id IS NULL OR r.src_peer_id IN (?, p.id))
		         AND (r.dst_peer_id IS NULL OR r.dst_peer_id IN (?, p.id))
		   ))
		 ORDER BY p.id`,
		selfID, defaultAllow, selfID, selfID,
	)
	if err != nil {
		return nil, fmt.Errorf("list peers: %w", err)
	}
	defer rows.Close()

	var out []PeerRow

	for rows.Next() {
		var p PeerRow
		if err := rows.Scan(&p.ID, &p.PublicKey, &p.AssignedIP,
			&p.PublicEndpoint, &p.ObservedIP, &p.ListenPort); err != nil {
			return nil, fmt.Errorf("scan peer: %w", err)
		}

		out = append(out, p)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list peers: %w", err)
	}

	return out, nil
}

// PeersForID returns the reporting agent's own row (used for pairwise
// endpoint hints) and the peers visible to it — the sync payload.
func (s *Store) PeersForID(ctx context.Context, id int64) (PeerRow, []PeerRow, error) {
	self := PeerRow{ID: id}

	err := s.db.QueryRowContext(ctx,
		`SELECT public_key, assigned_ip,
		        COALESCE(public_endpoint, ''), COALESCE(observed_ip, ''), COALESCE(listen_port, 0)
		 FROM peers WHERE id = ?`, id,
	).Scan(&self.PublicKey, &self.AssignedIP,
		&self.PublicEndpoint, &self.ObservedIP, &self.ListenPort)
	if err != nil {
		return PeerRow{}, nil, fmt.Errorf("look up peer %d: %w", id, err)
	}

	others, err := listVisible(ctx, s.db, id, s.DefaultAllow)
	if err != nil {
		return PeerRow{}, nil, err
	}

	return self, others, nil
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
