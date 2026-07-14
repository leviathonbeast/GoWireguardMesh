# wgmesh — full documentation

Reference for every module, flag, and deployment mode. New here? Start with the [README](README.md); this is the deep dive. Production hardening and deployment topology: **[SECURITY.md](SECURITY.md)**.

## Contents

- **Modules:** [Control plane](#control-plane) · [Agent](#agent) · [Web UI](#web-ui) · [Relay & NAT traversal](#relay--nat-traversal) · [DNS](#dns) · [ACLs](#acls) · [Telemetry](#telemetry) · [Firewall](#firewall)
- **Serving TLS:** [Direct ACME](#tls-direct-lets-encrypt) · [SNI passthrough](#tls-sni-passthrough) · [Behind a proxy](#tls-behind-a-proxy)
- **Deploy:** [Docker & Gitea](#deployment) · [Mobile (iPhone/Android)](#mobile-iphone--android) · [Windows](#windows-agent)
- **Reference:** [Layout](#layout) · [Enrollment API](#enrollment-api) · [Design notes](#design-notes) · [Production status](#production-status)

See the [README](README.md) for install and quick start.

## Layout

```
cmd/agent/         node agent (every mesh machine, needs root)
cmd/server/        control plane (enrollment + admin API + web UI + embedded relay)
cmd/relay/         standalone relay (UDP forwarder), for a separate host
internal/proto/    JSON wire structs shared by agent and server
internal/store/    all SQLite access (schema, enrollment, telemetry, acl, audit)
internal/psk/      PSK master + HKDF pair-key derivation
internal/relay/    relay core (UDP forwarder + WebSocket hub)
internal/tlsutil/  self-signed cert load-or-generate
internal/firewall/ host firewall (firewalld/ufw/nftables/iptables/netsh)
web/               admin UI (React + TypeScript, Vite)
deploy/            systemd units + compose templates
schema.sql         canonical DB schema (embedded)
```

The UI is embedded via `go:embed`, so plain `go build` needs no Node. After editing UI source, rebuild the bundle: `cd web && npm install && npm run build`.

---

## Control plane

`cmd/server` — enrollment, admin API, web UI, and (optionally) an embedded relay in one binary, backed by SQLite.

**Generated secrets** (0600, back up alongside `mesh.db`):

- `mesh-psk.key` — PSK master; **losing it strands every enrolled peer**
- `admin-token` — admin API bearer + first-boot admin password
- `session.key` — signs UI session cookies (rotating logs everyone out)
- `key.pem` / `cert.pem` — built-in TLS keypair (agents pin `cert.pem`)

**Setup keys:**

```sh
./bin/server newkey --db mesh.db                 # unlimited, never expires
./bin/server newkey --db mesh.db --max-uses 1    # single use
./bin/server newkey --db mesh.db --expires-in 24h
./bin/server newkey --db mesh.db --name jellyfin # named for auditing
```

### Server flags

| Flag | Default | Purpose |
|---|---|---|
| `--listen` | `127.0.0.1:8080` | listen address |
| `--db` | `mesh.db` | SQLite path |
| `--network` / `--network6` | `100.64.0.0/16` / `fd00:100:64::/64` | overlay ranges; peers get the lowest free IP |
| `--psk-file` | `mesh-psk.key` | PSK master (never distributed) |
| `--default-policy` | `allow` | ACL default: `allow` or `deny` |
| `--keepalive` | `25` | WireGuard PersistentKeepalive (s, 5–120); lower toward 10–15 if idle peers behind aggressive NATs flap direct→relay |
| `--admin-user` | `admin` | seeded admin username (initial password = admin token) |
| `--token-ttl` | `0` (never) | peer auth-token lifetime |
| **TLS** | | |
| `--no-tls` | off | plain HTTP (dev, or behind a TLS proxy) |
| `--tls-cert` / `--tls-key` | `cert.pem` / `key.pem` | cert/key; self-signed if missing |
| `--tls-hosts` | `localhost,127.0.0.1` | SANs for a generated cert |
| `--acme-domain` | — | auto Let's Encrypt cert (Cloudflare DNS-01); agents then need no `--server-ca` |
| `--acme-email` | — | ACME account email |
| `--acme-dns-token-file` | `$CLOUDFLARE_API_TOKEN` | Cloudflare token (scope: Zone→DNS→Edit) |
| `--acme-storage` | `acme` | cert dir (**must persist**) |
| `--acme-staging` | off | LE staging CA (testing, no rate limits) |
| `--trust-proxy` / `--trusted-proxies` | off / — | trust `X-Forwarded-For` from any source / from listed CIDRs (preferred) |
| `--proxy-protocol` | off | accept PROXY protocol from `--trusted-proxies` (SNI passthrough) |
| **Relay** | | |
| `--relay-embedded` | off | run relay in-process (needs `--relay-host`) |
| `--relay-host` | — | address agents dial for relayed traffic |
| `--relay-host6` | — | optional v6 address of the relay host; lets agents refresh their v6 endpoint against the mesh's STUN |
| `--relay-quic-port` | `51890` | QUIC datagram relay port |
| `--relay-port-min` / `-max` | `51900` / `51999` | UDP relay range |
| `--stun-port` | `3478` | mesh STUN (this port + next; `0` disables) |
| `--relay-control` / `--relay-secret-file` | `http://127.0.0.1:8081` / `relay-secret` | standalone relay control API / secret |
| **DNS** | | |
| `--dns-enabled` | off | push DNS to agents |
| `--dns-nameservers` | — | resolver IPs to push (e.g. CoreDNS overlay IPs) |
| `--dns-domain` / `--dns-search-domains` | `vpn` / — | mesh domain / search domains |
| `--dns-magic` | on | peer-name DNS behavior for the mesh domain |
| **Ops** | | |
| `--manage-firewall` | on | open the API port on the host firewall; removed on exit |
| `--rate-limit` / `--rate-burst` | `20` / `40` | per-source req/s + burst (0 = off) |
| `--access-log` / `--access-log-size` | `memory` / `1000` | `memory` (UI ring) · `stdout` (JSONL) · `off` |
| `--flow-retention` / `--audit-retention` | `168h` / `2160h` | log retention |
| `--log-level` | `info` | `debug`·`info`·`warn`·`error` |

---

## Agent

`cmd/agent` — creates the `wg-int` interface, enrolls, configures peers, keeps them synced, tears down cleanly on SIGINT/SIGTERM. On Linux it drives **kernel WireGuard** via netlink, so established links keep forwarding even if the agent restarts.

```sh
# behind a proxy with a real cert:
sudo ./bin/agent --server https://mesh.example.com --setup-key <token>

# standalone server with self-signed cert — pin it:
sudo ./bin/agent --server https://192.168.1.10:8443 --setup-key <token> --server-ca cert.pem
```

**On start:** loads/generates its keypair (`--key-file`, the node's permanent identity — don't delete it), discovers its endpoint via STUN, POSTs its **public** key to `/enroll`, receives overlay IPs + auth token + reachable peers, brings up `wg-int` (MTU 1420 + TCP MSS clamp so large transfers survive PMTU-blackholed paths), and reports telemetry every 30s. Re-running is safe — enrollment is idempotent, so a node reusing its key gets its assignment back even if the setup key later expires.

### Key agent flags

| Flag | Purpose |
|---|---|
| `--listen-port 51820` | pin the WireGuard port (stable firewall rule) |
| `--server-ca` | pin a self-signed server cert |
| `--advertise-endpoint host:51820` | pin the public endpoint peers dial; overrides STUN and survives re-checks — for hosts whose observed address lies (docker-sidecar on a VPS looks symmetric via hairpin NAT) |
| `--relay-transport auto\|websocket\|udp` | relay path (default `auto` = QUIC then WebSocket) |
| `--direct-probe=false` | keep a relay pinned after fallback (reverse-proxy/service sidecars) |
| `--port-mapping=false` | don't ask the router to forward the WG port (UPnP/NAT-PMP) |
| `--dns-fallback=false` | resolv.conf mode: don't keep original nameservers as fallback |
| `--gateway-nat-cidrs 100.78.0.9/32` | masquerade static/mobile peers through this agent (legacy; prefer routed mobiles) |
| `--no-ipv6-endpoints` | never advertise IPv6 direct endpoints for this host (v4 + overlay v6 unaffected) |
| `--stun-server`, `--key-file`, `--manage-firewall` | STUN server / key path / firewall toggle |

### Standalone mode (no control plane)

Manual point-to-point config still works:

```sh
sudo ./bin/agent --addr 100.64.0.1/16 --addr6 fd00:100:64::1/64 \
  --peer-key <pubkey> --peer-addr 100.64.0.2/32 \
  --peer-endpoint 192.168.1.20:51820 --peer-psk <psk>   # psk optional
```

---

## Web UI

Served at `/` on the API port. Anonymous visitors get only a login form; the React bundle loads after credentials validate and a signed HttpOnly session cookie is set. The SPA never handles a token — nothing in `localStorage` to steal.

First boot seeds one admin (`--admin-user`) whose password is the **admin token**; change it under **Account**. Passwords are argon2id; changing one invalidates that user's sessions. Session cookies use `session.key`, kept separate from the admin token.

**Network:** Overview · Peers (status, revoke, **add device** → QR config) · Policies (ACL rules) · Setup Keys.
**Monitor:** Traffic Events (per-link path + searchable feed) · Proxy Events (Traefik log ingest) · Audit Events.
**Admin:** Settings (overlay re-IP + DNS push) · Account (users, password).

Responsive (sidebar → drawer on phones); 5s auto-refresh toggle. Dev: `cd web && npm run dev` proxies API calls to `127.0.0.1:8080`.

### Admin API

Requires `Authorization: Bearer <admin-token>` or the session cookie.

| Endpoint | Purpose |
|---|---|
| `GET /api/peers` | list peers (incl. revoked) |
| `POST /api/mobile-peers` | create static/mobile peer, return importable config |
| `GET /api/peers/{id}/config` | rebuild a static peer's config (audited) |
| `GET /api/peers/{id}/ping` | liveness from last report |
| `POST /api/peers/{id}/revoke` | revoke (IP stays reserved) |
| `GET /api/network` · `POST /api/network/preview` · `.../apply` | overlay re-IP |
| `GET`/`POST /api/setup-keys` · `POST /api/setup-keys/{id}/revoke` | setup keys |
| `GET`/`POST /api/acl` · `POST /api/acl/{id}/delete` | ACL rules |
| `GET /api/link-stats` · `/api/flows` · `/api/audit` · `/api/access-log` | telemetry / logs |

`GET /healthz` is unauthenticated, for probes.

---

## Relay & NAT traversal

Connectivity is attempted in this order, all automatic:

1. **Router port mapping (UPnP/NAT-PMP)** — `--port-mapping` (on) asks the router to forward the WG port. Narrow by design: own listen port only, UDP, lease-limited (30 min), labeled `wgmesh-agent`, removed on shutdown; double-NAT is detected and skipped.
2. **STUN** — the agent probes from the *same port* WireGuard uses so the mapping is valid for tunnel traffic. With a relay, the mesh serves **its own STUN** (`--stun-port` + next); periodic re-checks catch IP changes and classify NAT as **easy** (hole-punchable) or **hard** (symmetric) — shown per peer, used to skip unpunchable hard↔hard pairs.
3. **Endpoint candidates** — the server distributes each peer's ordered candidates (host addresses, router mappings, STUN, relay-observed live mapping, server-observed source, and a reachability-proven IPv6 endpoint). Ordering flips on topology: a working global-v6 (`stun6`) path ranks first when present (no NAT to traverse); then same WAN IP → LAN paths, different NATs → mappings/STUN, private v4 only on a shared /24. Hints only; WireGuard roaming overrides them.

   **IPv6 direct paths** — the agent probes STUN over v6 from the WireGuard port; a reflected address (proving the port is actually reachable over v6) is advertised as a `stun6` candidate and, because v6 needs no NAT traversal, preferred over every v4 path. It's only advertised when v6 genuinely works — no connectivity, a firewalled port, or `--no-ipv6-endpoints` yields nothing, so peers never waste probes on unreachable v6. `host6` interface candidates are likewise gated on the agent managing its own firewall (SLAAC privacy addresses are always skipped). Set `--relay-host6` on the server to let agents refresh their v6 endpoint against the mesh's own STUN instead of a public one.
4. **Relay fallback** — if a direct peer goes silent 90s, the agent moves it to a relay. The relay is a dumb forwarder: it only ever sees WireGuard ciphertext (can drop, never read or forge), on a lock-free path that rejects non-WireGuard-shaped packets. Replaces TURN, which kernel WireGuard can't speak.

**Relay transports** (`--relay-transport auto` tries first two):

- **quic** (`--relay-quic-port`, 51890/udp) — authenticated session, then opaque ciphertext in QUIC datagrams; oversized frames fragmented end-to-end.
- **websocket** — rides the API port (443), so relayed traffic needs **no holes beyond 443** and crosses UDP-blocking networks. WireGuard-over-TCP = last resort. Embedded relay only.
- **udp** (`--relay-port-min/-max`, 51900–51999) — raw forwarder, one port pair per peer pair. Fastest; needs the range reachable. Embedded or standalone.

Relayed pairs periodically retry direct. When both peers are online with candidates (and not both hard NATs), the control plane bumps a punch epoch and pushes `sync-now` over the **`/signal` WebSocket** so both agents probe within ~1s of each other — simultaneity is what lands hole punching. The signal socket also triggers immediate re-sync after DNS/ACL/peer/network changes; `/report` is the fallback.

**Relay setup:**

- **Embedded** (single binary): `--relay-embedded --relay-host <addr>`. No second binary, no shared secret. Serves QUIC + WebSocket + UDP + STUN, all advertised automatically.
- **Standalone** (`cmd/relay`, UDP only, own public IP): run `relay` with `--port-min/--port-max`, copy its `relay-secret` to the server, start the server with `--relay-host <ip> --relay-control <url>`. Agents use `--relay-transport udp`.

---

## DNS

Point agents at your own resolver (e.g. CoreDNS authoritative for `.vpn`) from **Settings → DNS**, or at boot:

```sh
./bin/server --dns-enabled --dns-nameservers 100.78.0.7,fd32:d2ad:be4f::7 --dns-domain vpn
```

DNS is **split** by default: only mesh/search domains route to the mesh resolver; normal internet names use the host's existing DNS. Linux agents use `resolvectl` (`default-route=false`); without systemd-resolved they take over `/etc/resolv.conf` and keep the original nameservers as fallback (`--dns-fallback`, on). Windows uses NRPT rules. Applied at enrollment and on sync.

---

## ACLs

`--default-policy deny` starts the mesh fully segmented — no peer sees another until a rule connects them (visibility *is* the enforcement). Rules are ALLOW, bidirectional, with `any` wildcards, each carrying an optional name + protocol + port range. Manage in **Policies** or via `/api/acl`. Changes propagate within one report interval; agents tear down tunnels to peers that vanish from their sync.

Under `allow`, rules exist but do nothing — stage them before flipping. Current enforcement is peer visibility; packet-level port/protocol blocking is a future agent phase.

---

## Telemetry

Every `/report` (default 30s, authed by the enrollment `auth_token`) carries:

- **Link counters** — per-peer rx/tx deltas + last handshake; survive restarts and failed reports. Every report bumps `last_seen_at` (doubles as heartbeat).
- **Flow logs** — overlay-only conntrack 5-tuples with byte/packet deltas. **Headers only, never payloads.** Needs conntrack accounting (the agent enables it); disabled with a warning if unavailable, counters still work.

Revoking a peer cuts off its reporting.

---

## Firewall

All three binaries open their own host-firewall ports at startup and remove them on shutdown (`--manage-firewall`, on): agent → WG port; server → API port (+ relay range + STUN with the embedded relay); relay → its range + STUN. Backend detected in order: firewalld · ufw · nftables · iptables · (Windows) netsh. No backend or no privileges is a warning, never fatal.

**Posture:** a full mesh needs **51890/udp** (QUIC) + **443/tcp** (WebSocket fallback) on the control plane; agents need nothing inbound. Matches NetBird's "443 + WireGuard" posture. Open the UDP relay range only for `--relay-transport udp`.

---

## Serving TLS

### TLS: direct Let's Encrypt

With a Cloudflare-hosted domain, the server holds its own auto-renewing cert — no proxy in the mesh path, agents validate via WebPKI (drop `--server-ca`):

```sh
CLOUDFLARE_API_TOKEN=... ./bin/server --listen 0.0.0.0:8443 \
  --acme-domain mesh.example.com --relay-embedded --relay-host mesh.example.com
```

DNS-01 needs no port 80/443 for challenges. Token scope: Zone→DNS→Edit. Keep `--acme-storage` on a persistent volume (or every boot re-issues and hits rate limits). `--relay-host` must be a covered DNS name, not an IP.

### TLS: SNI passthrough

When another proxy owns 443, route the mesh hostname by TLS SNI at the TCP level — untouched — so its middleware/certs/DNS stay out of the mesh path, and agents keep a bare `https://mesh.example.com`:

```yaml
tcp:
  routers:
    wgmesh:
      entryPoints: [websecure]
      rule: "HostSNI(`mesh.example.com`)"
      service: wgmesh
      tls: { passthrough: true }
  services:
    wgmesh:
      loadBalancer:
        proxyProtocol: { version: 2 }
        servers: [{ address: "wgmesh-server:8443" }]
```

Add `--proxy-protocol --trusted-proxies <proxy subnet>` on the server: passthrough makes all connections appear from the proxy, and the PROXY header (honored only from trusted sources) restores real client IPs for rate limiting and logs. Direct connections still work alongside.

### TLS: behind a proxy

If the proxy terminates TLS, run plain HTTP on a private address:

```sh
./bin/server --listen 127.0.0.1:8080 --no-tls --trusted-proxies <proxy subnet>
```

```yaml
http:
  routers:
    wgmesh:
      rule: Host(`mesh.example.com`)
      entryPoints: [websecure]
      tls: { certResolver: letsencrypt }
      service: wgmesh
  services:
    wgmesh: { loadBalancer: { servers: [{ url: http://127.0.0.1:8080 }] } }
```

Agents then use `https://mesh.example.com`, no `--server-ca`. **Never expose the `--no-tls` port directly** — secrets cross that hop in cleartext.

---

## Deployment

- **systemd** — units for all three binaries in [deploy/](deploy/) (install steps in each header).
- **Docker** — `docker-compose.yml` (control plane + embedded relay). The Dockerfile has `server`/`relay`/`agent` targets; the agent is sidecar'd (`network_mode: service:<svc>`, `NET_ADMIN`, `/dev/net/tun`) — see `deploy/docker-compose.agent.yml`.
- **Debian + Traefik** — `deploy/docker-compose.debian.yml`: production server template expecting an external `proxy` network, publishing no host ports. Copy `deploy/debian-server.env.example` to `/opt/wgmesh/server.env`, edit, `docker compose --env-file … -f … up -d`.
- **Gitea Actions** — `.gitea/workflows/docker-images.yml` builds/pushes `server`/`agent`/`relay` on `v*` tags. Needs a `REGISTRY_TOKEN` secret (package-write); set `REGISTRY` if not `gitea.mynetbird.uk`. Tagging `v*` also creates a Gitea release with linux + windows binaries + `sha256sums.txt`.
- **Back up** `mesh.db`, `mesh-psk.key`, `admin-token`, and `key.pem` — see [SECURITY.md](SECURITY.md).

Sidecar example:

```yaml
services:
  myservice-wg:
    image: gitea.mynetbird.uk/<owner>/wgmesh-agent:latest
    entrypoint: ["/usr/local/bin/agent"]
    network_mode: "service:myservice"
    cap_add: [NET_ADMIN]
    devices: ["/dev/net/tun:/dev/net/tun"]
    command: >
      --server https://mesh.example.com --setup-key ${WGMESH_SETUP_KEY}
      --listen-port 51820 --key-file /data/wgkey.key --manage-firewall=false
    volumes: ["myservice-wg:/data"]
volumes: { myservice-wg: {} }
```

---

## Mobile (iPhone / Android)

iOS/Android can't run the agent (native VPN APIs required), so they join as **static/mobile WireGuard peers** via the official WireGuard app.

**Web UI:** **Peers → add device** → name it, pick a gateway agent, confirm the endpoint → scan the QR (**Add tunnel → Create from QR code**). The device's details page reshows the QR/`.conf` later (rebuilt against the current overlay/DNS; each read audited).

**API:**

```bash
curl -sS https://mesh.example.com/api/mobile-peers \
  -H "Authorization: Bearer $WGMESH_ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"iphone","gateway_public_key":"<gw-pubkey>","gateway_endpoint":"mesh.example.com:51820"}'
```

`deploy/mobile-peer-qr.sh` does the same from a terminal (needs `jq`, `qrencode`).

**Routed, not NAT'd:** every agent learns the phone's `/32` folded into the gateway peer's `AllowedIPs`, and the gateway forwards **without masquerading** — so the phone keeps its own overlay source IP end-to-end, and ACLs/flows/audit attribute traffic to it correctly. The gateway must be a wgmesh **agent**, reachable over UDP; it enables forwarding + a FORWARD `ACCEPT` automatically (Linux only). For Docker sidecars, keep `NET_ADMIN` and set `net.ipv4.ip_forward: "1"` (+ `net.ipv6.conf.all.forwarding` for v6 mobiles) if the sysctls are read-only.

**Key storage:** the control plane seals the device private key with AES-256-GCM under a `mesh-psk.key` subkey (DB alone can't disclose it; DB + PSK master can). Pass your own `private_key` to keep the server from ever holding it — shown once, not stored.

**Limits:** no WebSocket relay / signal / telemetry / live re-IP for mobiles. Changing overlay CIDR, DNS, or endpoint means re-importing. Legacy `--gateway-nat-cidrs` still masquerades instead of routing (hides the phone's source IP).

---

## Windows agent

*Experimental — compiles and follows documented Wintun behavior, but unvalidated on real hardware.*

Cross-compiles with `GOOS=windows go build ./cmd/agent`. Differences: embeds userspace wireguard-go + Wintun (place `wintun.dll` from [wintun.net](https://www.wintun.net) next to `agent.exe`); addressing via `netsh` (run elevated); no flow telemetry (no conntrack) — everything else works. Runs as a service:

```powershell
mkdir C:\ProgramData\wgmesh-agent
copy .\agent.exe .\wintun.dll C:\ProgramData\wgmesh-agent\

C:\ProgramData\wgmesh-agent\agent.exe service install --server https://mesh.example.com `
  --setup-key <token> --listen-port 51820 --key-file C:\ProgramData\wgmesh-agent\wgkey.key
C:\ProgramData\wgmesh-agent\agent.exe service start
# service update | status | restart | stop | remove
```

`service update` swaps in a newer `agent.exe` without reinstalling.

### Desktop GUI (`agent-gui.exe`)

A [Fyne](https://fyne.io) tray build for interactive Windows machines: tray icon shows connection state (gray/amber/green/red) with Connect/Disconnect; tabs for Peers (live path state), Settings (server/key/transport, persisted per user), and Logs. The agent loop runs in-process, so it needs elevation (offers a UAC relaunch on Connect) and refuses to run while the `wgmesh-agent` service is active.

Fyne needs cgo, so it's behind a build tag / separate binary (plain `agent.exe` stays pure Go):

```powershell
go build -tags gui -ldflags "-H windowsgui -s -w" -o agent-gui.exe .\cmd\agent
```

Cross-compile from Linux with a mingw-w64 toolchain via `WINDOWS_CC=... ./deploy/build.sh`. CI attaches both `.exe`s to each `v*` release.

---

## Enrollment API

`POST /enroll`:

```json
{ "setup_key": "…", "public_key": "…", "hostname": "…",
  "listen_port": 51820, "public_endpoint": "203.0.113.10:51820" }
```

`200`:

```json
{ "peer_id": 2, "assigned_ip": "100.64.0.2", "assigned_ip6": "fd00:100:64::2",
  "network_cidr": "100.64.0.0/16", "network_cidr6": "fd00:100:64::/64",
  "auth_token": "…",
  "peers": [ { "public_key": "…", "preshared_key": "…",
    "persistent_keepalive_interval": 25,
    "allowed_ips": ["100.64.0.1/32", "fd00:100:64::1/128"],
    "endpoint": "203.0.113.11:51820" } ] }
```

`auth_token` (rotated per enrollment, only its hash stored) authenticates `/report`, `/signal`, `/relay-pair`, `/relay-ws`. `peers` holds only reachable peers. Every setup-key failure returns a uniform `401 {"error":"unauthorized"}` — the wire leaks nothing about which keys exist.

---

## Design notes

- **Overlay vs underlay** — overlay IPs are CGNAT space; endpoints are LAN/public. `AllowedIPs` *is* the routing table (cryptokey routing).
- **Atomic enrollment** — token consumption + IP allocation + peer INSERT commit in one `BEGIN IMMEDIATE` transaction; failure before COMMIT leaves the key unspent.
- **Per-pair PSKs, zero storage** — `mesh-psk.key` never leaves the server; each pair's PSK is `HKDF(master, sort(pubA, pubB))`, unique per pair.
- **IP reuse** — revoked peers keep their rows (IP stays reserved) until a hard DELETE; cryptokey routing means a reused IP can't impersonate the old peer.
- **SQLite specifics** — FK enforcement is per-connection (`_pragma=foreign_keys(1)`); timestamps are `%Y-%m-%dT%H:%M:%fZ` compared lexicographically (never `datetime('now')`).

---

## Production status

Suitable today: trusted-LAN, public-endpoint, and VPS-fronted meshes at homelab scale — see [SECURITY.md](SECURITY.md) before exposing the control plane. **Limits:** single-writer SQLite (hundreds of peers, not thousands); bearer-token (not key-signature) peer auth; no PSK-master rotation; relay has no bandwidth accounting; symmetric↔symmetric NAT may still relay; Windows agent unvalidated on real hardware. **Roadmap:** WireGuard-key signature auth, PSK-master rotation.
