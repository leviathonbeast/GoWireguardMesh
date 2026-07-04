# wgmesh

A self-hosted WireGuard mesh networking system written in Go from scratch — a
NetBird/Tailscale-style overlay network with full control and no premium
paywalls.

Peers get stable identities (WireGuard keypairs), enroll against a central
control plane with setup keys, receive an overlay IP from CGNAT space
(`100.64.0.0/16` by default), and configure their WireGuard interface with the
full peer list automatically.

## Status

Working today:

- **Agent** — creates the WireGuard interface, assigns the overlay address,
  configures peers, tears down cleanly on SIGINT/SIGTERM. Verified end-to-end
  between two VMs (pings both ways, endpoint roaming observed).
- **Control plane** — HTTPS enrollment with setup keys (expiry, max uses,
  revocation), atomic IP allocation, idempotent re-enroll, network-wide
  preshared key distribution. Backed by SQLite.
- **Web UI** — React + TypeScript admin interface (embedded in the server
  binary): list/revoke peers and setup keys, mint new setup keys. Protected
  by a bearer token.
- **TLS** — built-in self-signed certificates for standalone use (agents pin
  the cert), or plain HTTP behind a TLS-terminating reverse proxy (Traefik).
- **Telemetry** — agents report per-peer WireGuard transfer counters and
  conntrack-based overlay flow logs (5-tuple, bytes, packets — headers only,
  never payloads) every 30s. The server accumulates link stats, tracks peer
  liveness (`last_seen_at`), stores flows with configurable retention, and
  shows both in the web UI.

Not built yet (roadmap, in order): config sync (new peers pushed to existing
ones), STUN + UDP hole punching, relay fallback, DNS, ACLs.

## Layout

```
cmd/agent/       node agent (runs on every machine in the mesh, needs root)
cmd/server/      control plane (enrollment API + admin API + web UI)
cmd/relay/       relay server (not yet implemented)
internal/proto/  JSON wire structs shared by agent and server
internal/store/  all SQLite access (schema, setup keys, atomic enrollment)
internal/psk/    network-wide preshared key load-or-generate
internal/tlsutil/ self-signed certificate load-or-generate
web/             admin web UI (React + TypeScript, Vite)
schema.sql       canonical database schema (embedded into the server binary)
```

## Requirements

- Go 1.26+
- Linux with the `wireguard` kernel module (agent only; the server runs
  anywhere and needs no root)
- No cgo — SQLite is pure Go (`modernc.org/sqlite`)

## Build

The web UI is prebuilt into `web/dist` and embedded by `go:embed`, so a
plain Go build works without a Node toolchain:

```sh
go build -o bin/server ./cmd/server
go build -o bin/agent  ./cmd/agent
```

After changing the UI source, rebuild the bundle first:

```sh
cd web && npm install && npm run build
```

## Setting up the control plane

Start the server (creates `mesh.db`, the schema, a self-signed TLS
certificate, the network PSK, and the admin token on first run):

```sh
./bin/server --listen 0.0.0.0:8443 --tls-hosts "localhost,127.0.0.1,192.168.1.10"
```

Include every address agents will dial in `--tls-hosts` — SANs are baked in
at generation time (delete `cert.pem`/`key.pem` to re-issue).

Generated secrets, all 0600, all worth backing up alongside `mesh.db`:

- `mesh-psk.key` — network-wide WireGuard preshared key handed to every
  peer; losing it strands enrolled peers on a different PSK than new ones
- `admin-token` — bearer token for the web UI and admin API
- `key.pem` — TLS private key (`cert.pem` is the public half agents pin)

Mint a setup key from the CLI (or use the web UI):

```sh
./bin/server newkey --db mesh.db                    # unlimited uses, never expires
./bin/server newkey --db mesh.db --max-uses 1       # single enrollment
./bin/server newkey --db mesh.db --expires-in 24h   # valid for one day
```

Flags for `server`:

| Flag | Default | Purpose |
|---|---|---|
| `--listen` | `127.0.0.1:8080` | listen address |
| `--db` | `mesh.db` | SQLite database path |
| `--network` | `100.64.0.0/16` | overlay network; peers get the lowest free IP |
| `--psk-file` | `mesh-psk.key` | network preshared key file |
| `--no-tls` | off | plain HTTP: behind a TLS-terminating proxy, or dev |
| `--tls-cert` / `--tls-key` | `cert.pem` / `key.pem` | TLS cert/key; self-signed pair generated if missing |
| `--tls-hosts` | `localhost,127.0.0.1` | SANs for a generated certificate |
| `--admin-token-file` | `admin-token` | admin bearer token file |
| `--flow-retention` | `168h` | how long flow log rows are kept (pruned hourly) |

### Deploying behind Traefik (or another TLS-terminating proxy)

If a reverse proxy handles your certificates, run the control plane on
plain HTTP bound to a non-public address and let the proxy terminate TLS:

```sh
./bin/server --listen 127.0.0.1:8080 --no-tls
```

Traefik router (file provider sketch):

```yaml
http:
  routers:
    wgmesh:
      rule: Host(`mesh.example.com`)
      entryPoints: [websecure]
      tls: { certResolver: letsencrypt }
      service: wgmesh
  services:
    wgmesh:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:8080
```

Agents then talk to `https://mesh.example.com` with a real certificate, so
no `--server-ca` pinning is needed. Never expose the `--no-tls` port
directly — setup keys, the PSK, and the admin token cross that hop in
cleartext.

## Web UI

The server serves the admin interface at `/` (same port as the API). Open
it, paste the contents of `admin-token`, and you can list peers, mint setup
keys with max-uses/expiry, and revoke peers or keys. The UI lives in `web/`
(React + TypeScript); `npm run dev` starts a Vite dev server that proxies
API calls to a locally running control plane on `127.0.0.1:8080`.

The admin API behind it (all require `Authorization: Bearer <admin-token>`):

| Endpoint | Purpose |
|---|---|
| `GET /api/peers` | list all peers, including revoked |
| `POST /api/peers/{id}/revoke` | revoke a peer (kept out of future enrollment responses; IP stays reserved) |
| `GET /api/setup-keys` | list all setup keys |
| `POST /api/setup-keys` | create a key: `{"max_uses": 0, "expires_in": "24h"}` |
| `POST /api/setup-keys/{id}/revoke` | revoke a key (also blocks re-enroll with it) |
| `GET /api/link-stats` | accumulated per-link transfer totals + last handshake |
| `GET /api/flows?limit=100` | recent overlay flow log entries |

## Telemetry

Enrollment returns a per-peer `auth_token` (only its SHA-256 hash is stored;
re-enrolling rotates it, which also revokes the old one). The agent then
POSTs to `/report` every `--report-interval` (default 30s) with:

- **Link counters** — per-remote-peer rx/tx deltas from the WireGuard kernel
  counters, plus the last handshake time. Deltas survive agent restarts
  (kernel counters reset when the interface is recreated) and failed reports
  (pending data is kept until the server accepts it). Every report — even an
  empty one — bumps the peer's `last_seen_at`, so it doubles as a heartbeat.
- **Flow logs** — overlay-only flows read from conntrack: protocol, src/dst
  address and port, byte/packet deltas in both directions. Src is the flow
  initiator. Header data only; payloads are never captured.

Flow collection requires conntrack accounting; the agent enables
`net.netfilter.nf_conntrack_acct` itself (it runs as root). If conntrack is
unavailable, flow logs are disabled with a warning and counters still work.

Revoking a peer also cuts off its reporting (the token check excludes
revoked peers).

## Joining a node to the mesh

On each machine (root required — the agent creates network interfaces):

```sh
# behind Traefik (real certificate):
sudo ./bin/agent --server https://mesh.example.com --setup-key <token>

# standalone server with a self-signed certificate — pin it:
sudo ./bin/agent --server https://192.168.1.10:8443 --setup-key <token> \
  --server-ca cert.pem
```

The agent will:

1. Load or generate its private key (`--key-file`, default `wgkey.key`,
   0600). The keypair is the node's permanent identity — created once,
   reused forever. Never delete it casually.
2. POST its **public** key to `/enroll` (the private key never leaves the
   machine).
3. Receive its assigned overlay IP and the current peer list, including the
   network PSK and keepalive interval.
4. Create the `wg-int` interface, assign the address, configure all peers,
   and block until SIGINT/SIGTERM, then tear the interface down.

Re-running the agent is safe: enrollment is idempotent, so a node that
re-enrolls with the same public key and its original setup key gets its
existing assignment back — even if that key has since expired or been
exhausted.

**Current limitation:** peers learn about each other at enrollment time only.
A node enrolled *before* you does not hear about you until it re-enrolls
(restart its agent). Live config sync is the next roadmap item. Peer
endpoints are also not distributed yet — until STUN lands, at least one side
of each pair must be able to reach the other (e.g. same LAN or a public IP),
and WireGuard's endpoint roaming takes over from the first authenticated
packet.

### Standalone mode (no control plane)

The original manual flags still work for point-to-point testing:

```sh
sudo ./bin/agent --addr 100.64.0.1/16 \
  --peer-key <base64-pubkey> \
  --peer-addr 100.64.0.2/32 \
  --peer-endpoint 192.168.1.20:51820 \
  --peer-psk <base64-psk>          # optional
```

## Enrollment API

`POST /enroll`

```json
{ "setup_key": "…", "public_key": "…", "hostname": "…", "listen_port": 51820 }
```

Success (`200`):

```json
{
  "peer_id": 2,
  "assigned_ip": "100.64.0.2",
  "network_cidr": "100.64.0.0/16",
  "peers": [
    {
      "public_key": "…",
      "preshared_key": "…",
      "persistent_keepalive_interval": 25,
      "allowed_ips": ["100.64.0.1/32"],
      "endpoint": null
    }
  ]
}
```

Every setup-key failure — unknown, expired, revoked, exhausted, or a
re-enroll with the wrong key — returns a uniform `401
{"error":"unauthorized"}`. The real reason is only written to the server log,
so the wire leaks nothing about which keys exist or their state.

## Design decisions worth knowing

- **Overlay vs underlay.** Overlay addresses live in CGNAT space
  (`100.64.0.0/16`); endpoints are underlay (LAN/public) addresses.
  AllowedIPs *is* the routing table (cryptokey routing) — an unroutable
  overlay IP means no peer claims it.
- **Atomic enrollment.** Token consumption, IP allocation, and the peer
  INSERT commit in one transaction (`BEGIN IMMEDIATE` via `_txlock=immediate`).
  A failure anywhere before COMMIT leaves the setup key unspent.
- **FK enforcement is per-connection in SQLite.** The DSN carries
  `_pragma=foreign_keys(1)` so every pooled connection gets it. Ad-hoc
  inspection with the `sqlite3` CLI needs `PRAGMA foreign_keys = ON;` too.
- **Timestamp format.** All timestamps are `%Y-%m-%dT%H:%M:%fZ` (matching the
  schema defaults) and compared lexicographically. Never compare against
  `datetime('now')` — it omits the `T`/`Z` and breaks string ordering.
- **IP reuse.** Revoked peers keep their rows, so their IPs stay reserved;
  an address is only reused after a hard `DELETE`. Cryptokey routing means a
  reused IP can't impersonate the old peer anyway.
- **Network-wide PSK.** One preshared key for the whole mesh, not per
  peer-pair — per-pair would need an O(n²) key table. A deliberate tradeoff;
  revisit if per-pair secrecy matters later.
