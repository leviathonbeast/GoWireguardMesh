-- IMPORTANT: FK enforcement is per-connection. Go DSN must include:
--   file:mesh.db?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)

PRAGMA foreign_keys = ON;

-- =========================
-- Setup keys (provisioning tokens)
-- =========================
CREATE TABLE setup_keys (
    id              INTEGER PRIMARY KEY,

    key             TEXT NOT NULL UNIQUE,

    created_at      TEXT NOT NULL
                    DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),

    expires_at      TEXT,

    revoked_at      TEXT,

    max_uses        INTEGER,   -- NULL = unlimited
    uses_consumed   INTEGER NOT NULL DEFAULT 0,

    CHECK (
        max_uses IS NULL OR max_uses >= 0
    ),

    CHECK (
        uses_consumed >= 0
    ),

    -- Never allow over-consumption
    CHECK (
        max_uses IS NULL
        OR uses_consumed <= max_uses
    )
);

-- =========================
-- Peers (registered nodes)
-- =========================
CREATE TABLE peers (
    id              INTEGER PRIMARY KEY,

    public_key      TEXT NOT NULL UNIQUE,

    assigned_ip     TEXT NOT NULL UNIQUE,  -- invariant: one IP per peer

    hostname        TEXT,

    listen_port     INTEGER,

    last_seen_at    TEXT,

    created_at      TEXT NOT NULL
                    DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),

    revoked_at      TEXT,

    setup_key_id    INTEGER NOT NULL
                    REFERENCES setup_keys(id)
                    ON DELETE RESTRICT,

    CHECK (
        listen_port IS NULL
        OR (listen_port BETWEEN 1 AND 65535)
    )
);

-- =========================
-- Indexes for performance
-- =========================
CREATE INDEX idx_peers_setup_key_id
    ON peers(setup_key_id);

CREATE INDEX idx_peers_last_seen_at
    ON peers(last_seen_at);

CREATE INDEX idx_setup_keys_expires_at
    ON setup_keys(expires_at);

-- =========================
-- Atomic key consumption pattern
-- =========================
-- Use this when issuing a peer or consuming a setup key
--
-- Returns success if a row was updated; otherwise the key is invalid,
-- expired, revoked, or exhausted.
--
-- NOTE: This is intentionally not wrapped in a trigger so that the
-- application controls transaction boundaries.
--
-- Example usage:
--
-- UPDATE setup_keys
-- SET uses_consumed = uses_consumed + 1
-- WHERE key = ?
--   AND revoked_at IS NULL
--   AND (expires_at IS NULL OR expires_at > datetime('now'))
--   AND (max_uses IS NULL OR uses_consumed < max_uses);
