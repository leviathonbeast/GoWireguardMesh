# wgmesh

A self-hosted WireGuard mesh networking system written in Go from scratch — a
NetBird/Tailscale-style overlay network with full control and no premium
paywalls.

Peers get stable identities (WireGuard keypairs), enroll against a central
control plane with setup keys, receive an overlay IP from CGNAT space
(`100.64.0.0/16` by default), and configure their WireGuard interface with the
peers they are allowed to reach — automatically, and kept in sync.

For production hardening and the VPS + per-service-sidecar deployment model,
see [SECURITY.md](SECURITY.md).

## Status

- **Agent** — creates the WireGuard interface, assigns the overlay address,
  configures peers, and keeps them synced; tears down cleanly on
  SIGINT/SIGTERM. Verified end-to-end between two VMs (pings both ways,
  endpoint roaming and relay fallback observed).
- **Control plane** — HTTP(S) enrollment with setup keys (expiry, max uses,
  revocation), atomic IP allocation, idempotent re-enroll. Backed by SQLite
  with versioned migrations.
- **Config sync** — every telemetry report returns the peer list the caller
  is allowed to see; the agent applies it as an incremental diff. New peers,
  endpoint changes, ACL changes, and PSK rotations propagate mesh-wide within
  one report interval, no restarts.
- **NAT traversal** — STUN discovery, endpoint hints distributed at
  enrollment and via sync (with a same-NAT hairpin fallback to LAN
  addresses), and a relay fallback (WebSocket over the API port, or raw UDP)
  that agents switch to automatically when a direct handshake never forms.
- **Per-pair preshared keys** — every peer pair gets a unique PSK derived
  server-side with HKDF from a master secret. No O(n²) key storage;
  compromising one pair reveals nothing about another.
- **ACLs** — `--default-policy deny` segments the mesh; peers only ever
  receive config for peers a rule connects them to (visibility *is* the
  enforcement). Managed in the web UI, propagate within one report interval.
- **Telemetry** — per-peer transfer counters, liveness, and conntrack flow
  logs (5-tuple, bytes, packets, direction — headers only, never payloads),
  with configurable retention.
- **Security & auditing** — TLS (built-in self-signed or behind a proxy),
  per-source rate limiting, optional peer-token expiry, a durable audit log
  and a redacted JSON access log, and automatic host-firewall management
  with startup reconciliation. See [SECURITY.md](SECURITY.md).
- **Web UI** — React + TypeScript, embedded in the server binary: peers,
  a NetBird-style traffic/activity feed with search, ACL and setup-key
  management, and the audit log. Bearer-token protected.
- **Platforms** — Linux (kernel WireGuard). The agent also cross-compiles
  for Windows (embedded userspace wireguard-go + Wintun), experimental.

Not built yet (roadmap): DNS, relay→direct downgrade, WireGuard-key
signature auth, PSK-master rotation.

## Layout

```
cmd/agent/        node agent (runs on every machine in the mesh, needs root)
cmd/server/       control plane (enrollment + admin API + web UI + embedded relay)
cmd/relay/        standalone relay (UDP forwarder + control API), for a separate host
internal/proto/   JSON wire structs shared by agent and server
internal/store/   all SQLite access (schema+migrations, enrollment, telemetry, acl, audit)
internal/psk/     PSK master load-or-generate + HKDF pair-key derivation
internal/relay/   relay core: UDP pair forwarder + WebSocket hub
internal/tlsutil/ self-signed certificate load-or-generate
internal/firewall/ host firewall management (firewalld/ufw/nftables/iptables/netsh)
web/              admin web UI (React + TypeScript, Vite)
deploy/           systemd units for server, agent, and relay
schema.sql        canonical database schema (embedded into the server binary)
SECURITY.md       production hardening + deployment topology
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
certificate, the PSK master, and the admin token on first run):

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
| `--network` | `100.64.0.0/16` | IPv4 overlay network; peers get the lowest free IP |
| `--network6` | off | optional IPv6 overlay network; peers also get the lowest free IPv6 |
| `--psk-file` | `mesh-psk.key` | PSK master file (never distributed; per-pair keys derive from it) |
| `--no-tls` | off | plain HTTP: behind a TLS-terminating proxy, or dev (warns if exposed) |
| `--tls-cert` / `--tls-key` | `cert.pem` / `key.pem` | TLS cert/key; self-signed pair generated if missing |
| `--tls-hosts` | `localhost,127.0.0.1` | SANs for a generated certificate |
| `--admin-token-file` | `admin-token` | admin bearer token file |
| `--default-policy` | `allow` | ACL default: `allow` (open mesh) or `deny` (rule-connected pairs only) |
| `--trust-proxy` | off | trust `X-Forwarded-For` for client IPs (only behind a proxy) |
| `--manage-firewall` | on | open the API port on the host firewall; reconciles + removes on exit |
| **Relay** | | |
| `--relay-embedded` | off | run the relay in-process (single binary); needs `--relay-host` |
| `--relay-host` | — | address agents dial for relayed traffic (enables relay fallback) |
| `--relay-port-min`/`-max` | `51900`/`51999` | embedded relay UDP forwarding range |
| `--relay-control` | `http://127.0.0.1:8081` | standalone relay control API URL |
| `--relay-secret-file` | `relay-secret` | standalone relay shared secret |
| **Telemetry & security** | | |
| `--token-ttl` | `0` (never) | peer auth-token lifetime; agents re-enroll to refresh |
| `--rate-limit` / `--rate-burst` | `20` / `40` | per-source req/s + burst on public endpoints (0 = off) |
| `--access-log` | `memory` | request tracing: `memory` for UI/API ring, `stdout` for JSONL shipping, `off` |
| `--access-log-size` | `1000` | in-memory request ring size |
| `--flow-retention` | `168h` | flow-log retention (pruned hourly) |
| `--audit-retention` | `2160h` (90d) | audit-log retention (pruned daily) |

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
it, paste the contents of `admin-token`, and use the tabs:

- **Peers** — registered peers with status, overlay IP, endpoint, last seen;
  revoke inline.
- **Traffic** — liveness, per-link totals, and a NetBird-style traffic-event
  feed (both peer names resolved, protocol/port, ingress/egress ports, and
  `↓ rx / ↑ tx`) with a **search box** (ip / port / hostname / protocol).
- **Access** — ACL rules (with the default policy shown) and setup-key
  management.
- **Audit** — the security activity log (colored by outcome) with search.

The UI lives in `web/` (React + TypeScript); `npm run dev` starts a Vite dev
server that proxies API calls to a control plane on `127.0.0.1:8080`.

The admin API behind it (all require `Authorization: Bearer <admin-token>`):

| Endpoint | Purpose |
|---|---|
| `GET /api/peers` | list all peers, including revoked |
| `POST /api/peers/{id}/revoke` | revoke a peer (kept out of enrollment responses; IP stays reserved) |
| `GET /api/setup-keys` · `POST /api/setup-keys` | list / create (`{"max_uses":0,"expires_in":"24h"}`) |
| `POST /api/setup-keys/{id}/revoke` | revoke a key (also blocks re-enroll with it) |
| `GET /api/acl` · `POST /api/acl` · `POST /api/acl/{id}/delete` | list / create / delete ACL rules |
| `GET /api/link-stats` | accumulated per-link transfer totals + last handshake |
| `GET /api/flows?limit=100` | recent flow log entries (direction, protocol, ports, bytes) |
| `GET /api/audit?limit=200` | security audit log |
| `GET /api/access-log?limit=200` | recent request log when `--access-log=memory` |

`GET /healthz` is unauthenticated, for liveness probes.

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

## NAT traversal

Connectivity is attempted in this order, all automatic:

1. **STUN.** Before creating the interface, the agent binds the WireGuard
   port, asks a STUN server (`--stun-server`, default Google's) how that
   port appears from the internet, and sends the result with its
   enrollment. Probing from the *same port* WireGuard will use is what
   makes the discovered mapping valid for tunnel traffic — on
   endpoint-independent NATs, at least. Symmetric NATs defeat this and
   fall through to the relay.
2. **Endpoint hints.** The server distributes each peer's best-known
   endpoint: its STUN result if it has one, otherwise the address the
   control plane observed it at plus its listen port (which is what makes
   same-LAN meshes work with zero configuration). Hints are only hints —
   WireGuard roaming overrides them as soon as real traffic arrives, and
   config sync never rewrites the endpoint of an already-known peer, so a
   roamed connection is never dragged back to a stale hint.
3. **Relay fallback.** If a peer has produced no handshake for 60s, the
   agent moves it onto a relay. The relay is a deliberately dumb
   forwarder: it never parses what it carries — all traffic is WireGuard
   ciphertext, so it can drop packets but not read or forge them. This
   replaces TURN, which kernel WireGuard cannot speak (the kernel owns
   the UDP socket). Two transports, chosen by `--relay-transport` on the
   agent:

   - **websocket** (default): the agent opens a WebSocket to the control
     plane's own port and pumps datagrams through a loopback UDP proxy
     that the peer's endpoint points at — kernel WireGuard never knows
     the transport isn't UDP. Because it rides the existing API port,
     relayed traffic needs **no firewall holes beyond 443** and
     traverses UDP-blocking networks (the NetBird-parity posture). It is
     WireGuard-over-TCP, so it is the last resort. Embedded relay only —
     auth reuses the peer's enrollment token and the store.
   - **udp**: the raw UDP forwarder. The control plane allocates a port
     pair per peer pair, each side points its endpoint at its port, and
     the relay cross-forwards. Faster (no TCP head-of-line blocking) but
     needs the relay's port range reachable. Works with both embedded
     and standalone relays.

Relay setup, two shapes:

- **Embedded (default choice, NetBird-style single binary):** run the
  control plane with `--relay-embedded --relay-host <address agents
  dial>`. The relay lives in the server process — no second binary, no
  shared secret, no control hop. Serves both transports: WebSocket over
  the API port (nothing extra to open), and UDP over
  `--relay-port-min/--relay-port-max` (default 51900-51999) for agents
  that opt into `--relay-transport udp`.
- **Standalone (`cmd/relay`):** UDP only, for when the relay needs its
  own public-IP host. Run `relay` with `--port-min/--port-max`, keep the
  control port (8081) reachable from the control plane only, copy its
  generated `relay-secret` to the server host, and start the server
  with `--relay-host <public-ip> --relay-control <url>`. Agents must use
  `--relay-transport udp`.

For UDP, exhaustion of the port range returns 503 and each peer pair
consumes two ports.

### Firewall posture

With the embedded relay and the default WebSocket transport, a full
mesh needs, on the control-plane host: **443** (or 8443) for the API,
web UI, enrollment, telemetry, *and* relayed traffic — one port. Agents
need nothing inbound; WireGuard's own port is opened locally by
`--manage-firewall` for direct connectivity but is not required for the
relay path. That matches NetBird's "443 plus WireGuard" posture. Opt
into `--relay-transport udp` only when you want the relay's throughput
and can open its port range.

## Host firewall integration

All three binaries open their own ports on the host firewall at startup
and remove the rules on shutdown (`--manage-firewall`, on by default):
the agent its WireGuard listen port (udp), the server its API port (tcp),
the relay its forwarding range (udp, only when `--port-min/--port-max`
is set — ephemeral ports cannot be pre-opened). The backend is detected
in order: firewalld, ufw, nftables (component-owned table), iptables;
on Windows, Windows Defender Firewall via netsh. firewalld rules are
runtime-only on purpose — a component that is not running should not
leave holes, and it re-adds its rule on every start. No backend or no
privileges is a warning, never fatal.

## Deployment

- **systemd**: units for all three binaries in [deploy/](deploy/), with
  install steps in each file's header comment.
- **Docker**: `docker-compose.yml` runs the control plane with the embedded
  relay as a single service (`RELAY_PUBLIC_IP` required). The Dockerfile has
  separate `server`, `relay`, and `agent` targets; the `agent` target is
  meant to be sidecar'd next to a service (`network_mode: service:<svc>`,
  `NET_ADMIN`) — see the sidecar example in [SECURITY.md](SECURITY.md).
- **Back up** `mesh.db`, `mesh-psk.key` (the PSK master — losing it strands
  every peer), `admin-token`, and (built-in TLS) `key.pem`. Details and a
  cron sketch in [SECURITY.md](SECURITY.md).

### Honest production status

Suitable today: trusted-LAN, public-endpoint, and VPS-fronted meshes at
homelab scale. See [SECURITY.md](SECURITY.md) for the hardening checklist
before exposing the control plane. Known limits: no DNS; single-writer
SQLite (fine for hundreds of peers, not thousands); bearer-token (not
key-signature) peer auth; no PSK-master rotation; relay is store-and-forward
with no bandwidth accounting and no relay→direct downgrade; symmetric-to-
symmetric NAT always relays; the Windows agent is unvalidated on real
hardware.

## ACLs

Run the server with `--default-policy deny` and the mesh starts fully
segmented: no peer sees any other until a rule connects them. Rules are
ALLOW rules, matched in both directions, with "any" as a wildcard on
either side; manage them in the web UI's Access tab or via
`GET/POST /api/acl` and `POST /api/acl/{id}/delete`. Changes — including
deletions — propagate within one report interval: agents remove peers
that vanish from their sync payload, tearing down the tunnel.

Under the default `allow` policy rules exist but have no effect, so you
can stage rules before flipping the policy.

## Windows agent (experimental, untested on real hardware)

The agent cross-compiles for Windows (`GOOS=windows go build ./cmd/agent`)
with these differences:

- There is no kernel WireGuard to drive, so the agent embeds
  wireguard-go as a library: it creates a Wintun adapter in-process,
  runs the userspace WireGuard device, and exposes the standard UAPI
  pipe that wgctrl speaks. No external binaries needed — just download
  `wintun.dll` (amd64) from [wintun.net](https://www.wintun.net) and
  place it next to `agent.exe`.
- Addressing uses `netsh`; run from an elevated (Administrator) prompt.
- Flow telemetry is Linux-only (no conntrack); link counters, config
  sync, STUN, and relay fallback all work.

Treat it as a starting point: it compiles and follows documented Wintun
behavior, but has not been validated on a real Windows host.

## Joining a node to the mesh

On each machine (root required — the agent creates network interfaces):

```sh
# behind Traefik (real certificate):
sudo ./bin/agent --server https://mesh.example.com --setup-key <token>

# standalone server with a self-signed certificate — pin it:
sudo ./bin/agent --server https://192.168.1.10:8443 --setup-key <token> \
  --server-ca cert.pem
```

Useful agent flags: `--listen-port 51820` (pin the WireGuard port — strongly
recommended so the firewall rule is stable across restarts), `--server-ca`
(pin a self-signed server cert), `--relay-transport websocket|udp`,
`--stun-server`, `--key-file`, `--manage-firewall`.

The agent will:

1. Load or generate its private key (`--key-file`, default `wgkey.key`,
   0600). The keypair is the node's permanent identity — created once,
   reused forever. Never delete it casually.
2. Discover its public endpoint via STUN, then POST its **public** key to
   `/enroll` (the private key never leaves the machine).
3. Receive its assigned overlay IPs, an auth token, and the peers it may
   reach — each with its per-pair PSK, endpoint hint, and keepalive.
4. Create the `wg-int` interface, assign the address(es), configure peers, and
   report telemetry every 30s. Each report response re-syncs the peer list,
   so membership/endpoint/ACL/PSK changes land within one interval. Blocks
   until SIGINT/SIGTERM, then tears the interface down.

Re-running the agent is safe: enrollment is idempotent, so a node that
re-enrolls with the same public key and its original setup key gets its
existing assignment back (a fresh auth token each time) — even if that key
has since expired or been exhausted.

### Standalone mode (no control plane)

The original manual flags still work for point-to-point testing:

```sh
sudo ./bin/agent --addr 100.64.0.1/16 \
  --addr6 fd00:100:64::1/64 \
  --peer-key <base64-pubkey> \
  --peer-addr 100.64.0.2/32 \
  --peer-addr6 fd00:100:64::2/128 \
  --peer-endpoint 192.168.1.20:51820 \
  --peer-psk <base64-psk>          # optional
```

## Enrollment API

`POST /enroll`

```json
{
  "setup_key": "…",
  "public_key": "…",
  "hostname": "…",
  "listen_port": 51820,
  "public_endpoint": "203.0.113.10:51820"
}
```

Success (`200`):

```json
{
  "peer_id": 2,
  "assigned_ip": "100.64.0.2",
  "assigned_ip6": "fd00:100:64::2",
  "network_cidr": "100.64.0.0/16",
  "network_cidr6": "fd00:100:64::/64",
  "auth_token": "…",
  "peers": [
    {
      "public_key": "…",
      "preshared_key": "…",
      "persistent_keepalive_interval": 25,
      "allowed_ips": ["100.64.0.1/32", "fd00:100:64::1/128"],
      "endpoint": "203.0.113.11:51820"
    }
  ]
}
```

`auth_token` authenticates the agent's subsequent `/report`, `/relay-pair`,
and `/relay-ws` calls (rotated on every enrollment; only its hash is stored).
`endpoint` is the server's best hint for that peer and may be null when
unknown. `peers` contains only the peers this node is allowed to reach.

Every setup-key failure — unknown, expired, revoked, exhausted, or a
re-enroll with the wrong key — returns a uniform `401
{"error":"unauthorized"}`. The real reason goes to the server log and the
audit trail only, so the wire leaks nothing about which keys exist.

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
- **Per-pair PSKs without storage.** `mesh-psk.key` is a master secret
  that never leaves the server; each pair's PSK is
  `HKDF(master, sort(pubA, pubB))` — symmetric by construction, unique
  per pair, zero rows of key storage.
