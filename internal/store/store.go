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
	"sync"
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
	db *sql.DB

	networkMu sync.RWMutex
	network   netip.Prefix

	// DefaultAllow is the ACL default policy: true means every peer
	// sees every peer unless the operator adds rules; false means
	// only rule-connected pairs see each other. Set once at startup.
	DefaultAllow bool

	// TokenTTL bounds how long a peer auth token stays valid after
	// issue. Agents re-enroll (rotating the token) at startup and on
	// expiry. Zero means no expiry. Set once at startup.
	TokenTTL time.Duration

	// Network6 is the IPv6 ULA overlay. The server configures a
	// default prefix, but the zero value keeps store tests and any
	// non-server callers IPv4-only. Set once at startup, like
	// DefaultAllow.
	Network6 netip.Prefix
}

// v6Enabled reports whether the mesh hands out IPv6 overlay addresses.
func (s *Store) v6Enabled() bool { return s.network6().IsValid() }

func (s *Store) network4() netip.Prefix {
	s.networkMu.RLock()
	defer s.networkMu.RUnlock()

	return s.network
}

func (s *Store) network6() netip.Prefix {
	s.networkMu.RLock()
	defer s.networkMu.RUnlock()

	return s.Network6
}

func (s *Store) setNetworks(network4, network6 netip.Prefix) {
	s.networkMu.Lock()
	defer s.networkMu.Unlock()

	s.network = network4.Masked()
	s.Network6 = network6.Masked()
}

type PeerRow struct {
	ID          int64
	PublicKey   string
	AssignedIP  string
	AssignedIP6 string // "" when the IPv6 overlay is not configured

	// PeerType is "agent" (runs the wgmesh agent) or "static" (an
	// imported WireGuard client such as an iPhone).
	PeerType string

	// GatewayPeerID is the agent peer that routes this static/mobile
	// peer's overlay /32 into the mesh; 0 when unset (unrouted static
	// peer or a normal agent).
	GatewayPeerID int64

	// Endpoint hint material, in preference order.
	PublicEndpoint string // STUN-discovered ip:port, "" if unknown
	ObservedIP     string // enroll/report source IP, "" if unknown
	ListenPort     int    // 0 if unknown

	// CandidatesJSON is the agent's self-reported candidate list (a
	// JSON array of proto.AgentCandidate), "" if never reported.
	CandidatesJSON string

	// NATType is the agent's NAT classification: "easy", "hard", or
	// "" (unknown / never reported).
	NATType string
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
// busy_timeout makes a second concurrent writer wait (up to 5s) for
// the lock instead of failing instantly with SQLITE_BUSY — without
// it, _txlock=immediate turns concurrent enroll/report bursts into
// intermittent 500s.
func Open(path string, network netip.Prefix, schemaSQL string) (*Store, error) {
	dsn := fmt.Sprintf(
		"file:%s?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_txlock=immediate",
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
const schemaVersion = 16

var migrations = map[int]string{
	2:  migrationV2,
	3:  migrationV3,
	4:  migrationV4,
	5:  migrationV5,
	6:  migrationV6,
	7:  migrationV7,
	8:  migrationV8,
	9:  migrationV9,
	10: migrationV10,
	11: migrationV11,
	12: migrationV12,
	13: migrationV13,
	14: migrationV14,
	15: migrationV15,
	16: migrationV16,
}

// migrationV16 adds agent-gathered NAT-traversal material. candidates is
// a JSON array of {endpoint, type} the agent reported for itself (host
// interface addresses, UPnP/NAT-PMP mappings) — endpoint hints only the
// agent can know, merged into pairwise candidate lists next to the
// STUN/observed data the server already tracks. nat_type is the agent's
// classification of its NAT's mapping behavior ("easy"/"hard"/NULL);
// the control plane skips coordinating hole punches for hard<->hard
// pairs, which cannot punch, so their relays stay undisturbed.
const migrationV16 = `
ALTER TABLE peers ADD COLUMN candidates TEXT;
ALTER TABLE peers ADD COLUMN nat_type TEXT;
`

// migrationV15 lets the admin UI show a static peer's WireGuard config
// again after it was created, instead of only once at creation time.
//
// private_key_enc holds the device's private key sealed by internal/keyseal
// (AES-GCM under a subkey of the mesh PSK master, bound to the peer's public
// key), so the database alone does not disclose it. gateway_endpoint records
// the address the device dials, which is chosen per device at creation and
// is not recoverable from the gateway peer's row.
//
// Both are NULL for agents, and for static peers created before v15 or
// enrolled with an operator-supplied key that the control plane never saw;
// those peers simply have no config to re-show.
const migrationV15 = `
ALTER TABLE peers ADD COLUMN private_key_enc TEXT;
ALTER TABLE peers ADD COLUMN gateway_endpoint TEXT;
`

// migrationV14 adds admin user accounts for username/password login to the
// web UI. auth_source distinguishes local (password_hash set) from future
// OIDC-provisioned users. session_epoch is bumped on password change / forced
// logout to invalidate that user's existing session cookies. The agent enroll
// path and programmatic API keep using the bearer admin token, unaffected.
const migrationV14 = `
CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL DEFAULT '',
    auth_source   TEXT NOT NULL DEFAULT 'local',
    session_epoch INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
`

// migrationV13 records which agent peer routes each static/mobile peer's
// overlay /32 into the mesh. A routed mobile peer keeps its own overlay
// source IP end-to-end: its gateway agent forwards (does not NAT) between
// the mobile and the mesh, and every other agent learns the mobile's /32
// via that gateway peer's AllowedIPs. NULL means "no gateway" (an
// unrouted/legacy static peer). ON DELETE SET NULL so revoking a gateway
// agent detaches its mobiles rather than cascading them away.
const migrationV13 = `
ALTER TABLE peers ADD COLUMN gateway_peer_id INTEGER REFERENCES peers(id) ON DELETE SET NULL;
`

// migrationV12 distinguishes normal wgmesh agents, which report telemetry,
// from static/mobile WireGuard peers, which are managed by config import and
// will never call /report.
const migrationV12 = `
ALTER TABLE peers ADD COLUMN peer_type TEXT NOT NULL DEFAULT 'agent';

UPDATE peers
SET peer_type = 'static'
WHERE setup_key_id IN (
    SELECT id FROM setup_keys WHERE COALESCE(name, '') LIKE 'static peer%'
);
`

// migrationV11 records reverse-proxy access-log entries (e.g. from
// Traefik) that agents tail and ship, for the dashboard Proxy Events log.
const migrationV11 = `
CREATE TABLE proxy_events (
    id          INTEGER PRIMARY KEY,
    peer_id     INTEGER REFERENCES peers(id) ON DELETE SET NULL,
    at          TEXT NOT NULL,
    method      TEXT,
    host        TEXT,
    path        TEXT,
    status      INTEGER,
    duration_ms INTEGER,
    req_bytes   INTEGER,
    resp_bytes  INTEGER,
    client_ip   TEXT,
    service     TEXT
);

CREATE INDEX idx_proxy_events_at ON proxy_events(at);
`

// migrationV10 records peer-to-peer connection lifecycle events (a direct
// connection established, a relay fallback) derived from path-state
// transitions, for the dashboard connection log.
const migrationV10 = `
CREATE TABLE connection_events (
    id               INTEGER PRIMARY KEY,
    at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    reporter_peer_id INTEGER NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    remote_peer_id   INTEGER NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    kind             TEXT NOT NULL,   -- direct | relay
    from_state       TEXT,            -- previous path state (NULL = first observation)
    to_state         TEXT NOT NULL    -- new path state (direct/ws-relay/udp-relay)
);

CREATE INDEX idx_connection_events_at ON connection_events(at);
`

// migrationV9 adds operator-friendly names for setup keys and turns
// ACL rules into service-level policies. Peer visibility still uses
// the src/dst pair; protocol and port range describe the service
// allowed between the pair and are returned through the admin API.
const migrationV9 = `
ALTER TABLE setup_keys ADD COLUMN name TEXT;

ALTER TABLE acl_rules ADD COLUMN name TEXT;
ALTER TABLE acl_rules ADD COLUMN protocol TEXT NOT NULL DEFAULT 'any';
ALTER TABLE acl_rules ADD COLUMN port_min INTEGER;
ALTER TABLE acl_rules ADD COLUMN port_max INTEGER;
`

// migrationV8 records the agent's selected path for each peer pair
// (direct, ws-relay, udp-relay, probing-direct) so the UI can show
// path state independently of byte-counter changes.
const migrationV8 = `
CREATE TABLE peer_paths (
    peer_id        INTEGER NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    remote_peer_id INTEGER NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    state          TEXT NOT NULL,
    endpoint       TEXT,
    updated_at     TEXT NOT NULL,
    PRIMARY KEY (peer_id, remote_peer_id)
);
`

// migrationV7 stores operator-editable settings that must survive a
// process restart. Overlay CIDRs live here once the server initializes
// them from flags/defaults, and the web UI updates them during network
// migrations.
const migrationV7 = `
CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
`

// migrationV6 adds the IPv6 overlay address. It is NULL until peers
// re-enroll against a server with Network6 configured. A partial
// unique index enforces one v6 address per peer without constraining
// the NULLs (SQLite can't add a UNIQUE column via ALTER TABLE, so the
// index is separate).
const migrationV6 = `
ALTER TABLE peers ADD COLUMN assigned_ip6 TEXT;

CREATE UNIQUE INDEX idx_peers_assigned_ip6
    ON peers(assigned_ip6) WHERE assigned_ip6 IS NOT NULL;
`

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
	return s.CreateNamedSetupKey(ctx, "", maxUses, expiresIn)
}

func (s *Store) CreateNamedSetupKey(ctx context.Context, name string, maxUses int, expiresIn time.Duration) (string, error) {
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
		`INSERT INTO setup_keys (key, name, max_uses, expires_at) VALUES (?, ?, ?, ?)`,
		key, nullable(name), uses, expires,
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
		`SELECT id, assigned_ip, COALESCE(assigned_ip6, ''), setup_key_id,
		        COALESCE(public_endpoint, ''), COALESCE(observed_ip, ''), COALESCE(listen_port, 0)
		 FROM peers WHERE public_key = ?`,
		publicKey,
	).Scan(&existing.ID, &existing.AssignedIP, &existing.AssignedIP6, &enrolledKeyID,
		&existing.PublicEndpoint, &existing.ObservedIP, &existing.ListenPort)

	switch {
	case err == nil:
		return s.reEnroll(ctx, tx, setupKey, publicKey, hostname, existing, enrolledKeyID, observedIP, publicEndpoint, listenPort)
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

	var ip6 string
	if s.v6Enabled() {
		ip6, err = s.allocateIP6(ctx, tx)
		if err != nil {
			return nil, err
		}
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
		`INSERT INTO peers (public_key, assigned_ip, assigned_ip6, hostname, listen_port, setup_key_id, auth_token_hash, auth_token_issued_at, observed_ip, public_endpoint)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		publicKey, ip, nullable(ip6), host, port, keyID, tokenHash, now,
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
			AssignedIP6:    ip6,
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
func (s *Store) reEnroll(ctx context.Context, tx *sql.Tx, setupKey, publicKey, hostname string, existing PeerRow, enrolledKeyID int64, observedIP, publicEndpoint string, listenPort int) (*EnrollResult, error) {
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

	// Backfill an IPv6 overlay address if this peer first enrolled
	// before Network6 was configured. Agents re-enroll at every startup,
	// so existing peers pick up a v6 address on their next launch
	// without any explicit migration sweep. "" leaves the column
	// untouched via COALESCE below.
	var ip6Backfill string
	if s.v6Enabled() && existing.AssignedIP6 == "" {
		ip6Backfill, err = s.allocateIP6(ctx, tx)
		if err != nil {
			return nil, err
		}
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
			        assigned_ip6 = COALESCE(?, assigned_ip6),
			        hostname = COALESCE(?, hostname),
			        observed_ip = COALESCE(?, observed_ip),
			        public_endpoint = COALESCE(?, public_endpoint),
			        listen_port = COALESCE(?, listen_port)
			 WHERE id = ?`,
		tokenHash, time.Now().UTC().Format(timeFormat), nullable(ip6Backfill),
		nullable(hostname), nullable(observedIP), nullable(publicEndpoint), port, existing.ID,
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

	if ip6Backfill != "" {
		existing.AssignedIP6 = ip6Backfill
	}

	return &EnrollResult{Peer: existing, Others: others, Created: false, AuthToken: token}, nil
}

// allocateIP returns the lowest free IPv4 host address in the overlay.
func (s *Store) allocateIP(ctx context.Context, tx *sql.Tx) (string, error) {
	return allocateAddr(ctx, tx, s.network4(), "assigned_ip")
}

// allocateIP6 returns the lowest free IPv6 overlay host address. Only
// called when the v6 overlay is enabled.
func (s *Store) allocateIP6(ctx context.Context, tx *sql.Tx) (string, error) {
	return allocateAddr(ctx, tx, s.network6(), "assigned_ip6")
}

// allocateAddr returns the lowest free host address in prefix, treating
// every non-NULL value already in column as taken. Revoked peers keep
// their rows, so their addresses stay reserved; an address is only ever
// reused after a hard DELETE. That is deliberate: cryptokey routing
// means a reused address cannot impersonate the old peer, but holding
// addresses of revoked peers avoids confusing state (monitoring, logs,
// ACLs) that still references them.
//
// column is one of two compile-time constants, never user input. The
// walk is O(N) in the number of peers regardless of prefix size — it
// returns the first gap, so a sparse /64 never iterates its full range.
func allocateAddr(ctx context.Context, tx *sql.Tx, prefix netip.Prefix, column string) (string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+column+` FROM peers WHERE `+column+` IS NOT NULL`)
	if err != nil {
		return "", fmt.Errorf("list %s: %w", column, err)
	}
	defer rows.Close()

	used := make(map[netip.Addr]bool)

	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return "", fmt.Errorf("scan %s: %w", column, err)
		}

		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return "", fmt.Errorf("parse %s %q from database: %w", column, raw, err)
		}

		used[addr] = true
	}

	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("list %s: %w", column, err)
	}

	// Skip the network address itself; start at the first host.
	for ip := prefix.Addr().Next(); prefix.Contains(ip); ip = ip.Next() {
		if !used[ip] {
			return ip.String(), nil
		}
	}

	return "", fmt.Errorf("overlay network %s has no free addresses", prefix)
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
		`SELECT p.id, p.public_key, p.assigned_ip, COALESCE(p.assigned_ip6, ''),
		        COALESCE(p.peer_type, 'agent'), COALESCE(p.gateway_peer_id, 0),
		        COALESCE(p.public_endpoint, ''), COALESCE(p.observed_ip, ''), COALESCE(p.listen_port, 0),
		        COALESCE(p.candidates, ''), COALESCE(p.nat_type, '')
		 FROM peers p
		 WHERE p.revoked_at IS NULL AND p.id != ?
		   AND (? OR p.gateway_peer_id = ? OR EXISTS (
		       SELECT 1 FROM acl_rules r
		       WHERE (r.src_peer_id IS NULL OR r.src_peer_id IN (?, p.id))
		         AND (r.dst_peer_id IS NULL OR r.dst_peer_id IN (?, p.id))
		   ))
		 ORDER BY p.id`,
		selfID, defaultAllow, selfID, selfID, selfID,
	)
	if err != nil {
		return nil, fmt.Errorf("list peers: %w", err)
	}
	defer rows.Close()

	var out []PeerRow

	for rows.Next() {
		var p PeerRow
		if err := rows.Scan(&p.ID, &p.PublicKey, &p.AssignedIP, &p.AssignedIP6,
			&p.PeerType, &p.GatewayPeerID,
			&p.PublicEndpoint, &p.ObservedIP, &p.ListenPort,
			&p.CandidatesJSON, &p.NATType); err != nil {
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
		`SELECT public_key, assigned_ip, COALESCE(assigned_ip6, ''),
		        COALESCE(peer_type, 'agent'), COALESCE(gateway_peer_id, 0),
		        COALESCE(public_endpoint, ''), COALESCE(observed_ip, ''), COALESCE(listen_port, 0),
		        COALESCE(candidates, ''), COALESCE(nat_type, '')
		 FROM peers WHERE id = ?`, id,
	).Scan(&self.PublicKey, &self.AssignedIP, &self.AssignedIP6,
		&self.PeerType, &self.GatewayPeerID,
		&self.PublicEndpoint, &self.ObservedIP, &self.ListenPort,
		&self.CandidatesJSON, &self.NATType)
	if err != nil {
		return PeerRow{}, nil, fmt.Errorf("look up peer %d: %w", id, err)
	}

	others, err := listVisible(ctx, s.db, id, s.DefaultAllow)
	if err != nil {
		return PeerRow{}, nil, err
	}

	return self, others, nil
}

// UpdatePeerCandidates replaces peerID's self-reported candidate list.
// Separate from Enroll so enrollment's signature (and its idempotent
// re-enroll semantics) stay untouched; losing this write is harmless
// because every report re-sends the current list.
func (s *Store) UpdatePeerCandidates(ctx context.Context, peerID int64, candidatesJSON string) error {
	if candidatesJSON == "" {
		return nil
	}

	if _, err := s.db.ExecContext(ctx,
		`UPDATE peers SET candidates = ? WHERE id = ?`, candidatesJSON, peerID,
	); err != nil {
		return fmt.Errorf("update peer candidates: %w", err)
	}

	return nil
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
