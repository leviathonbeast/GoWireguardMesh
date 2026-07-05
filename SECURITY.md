# wgmesh security & production deployment

This is the hardening checklist for running wgmesh outside a trusted LAN
— specifically the target topology: **control plane on a public VPS**,
**agents sidecar'd next to homelab services**.

## Threat model in one paragraph

The control plane is the crown jewel: it hands out overlay IPs, setup
keys, per-pair PSK material, and relay paths. A compromised control
plane compromises the mesh. Agents hold their own WireGuard private key
(never sent anywhere) and a bearer auth token (telemetry + relay). The
relay sees only WireGuard ciphertext — it can drop or delay, never read
or forge. Setup keys and the admin token are bearer secrets: whoever
holds one can act with it, so they must never cross an untrusted network
in cleartext.

## Tier 1 — do these before the control plane faces the internet

### 1. TLS is mandatory on a public VPS

Never expose `--no-tls` to the internet. Two options:

- **Behind a reverse proxy (recommended):** run
  `server --no-tls --listen 127.0.0.1:8080 --trust-proxy` and let
  Traefik/Caddy/nginx terminate TLS on 443. `--trust-proxy` makes the
  server read the real client IP from `X-Forwarded-For` (needed for
  correct endpoint hints and audit logs). The server binds loopback so
  the proxy is the only way in.
- **Built-in TLS:** `server --tls-hosts mesh.example.com` generates a
  self-signed cert; agents pin it with `--server-ca cert.pem`. Fine for
  a closed fleet, awkward for browsers.

The server warns loudly if it is serving plain HTTP on a non-loopback
address without `--trust-proxy`.

### 2. Rate limiting (on by default)

Public endpoints (`/enroll`, `/report`, `/relay-pair`, `/relay-ws`) are
throttled per source IP (`--rate-limit`, `--rate-burst`). This blunts
setup-key brute forcing and relay exhaustion. Keyed on the real client
IP, so it works correctly behind a trusted proxy. Admin routes are
gated by the admin token instead.

### 3. Pin the agent's WireGuard port

Run agents with `--listen-port 51820` (or any fixed port). Auto-selected
random ports mean a new firewall rule per restart — the source of leaked
open ports. With `--manage-firewall` on, the firewall backend now also
**reconciles on startup**: it records the ports it opened and removes
any a previous run left behind (crash, `kill -9`), closing that leak.

## Tier 2 — do these before trusting it with anything sensitive

### 4. Expire peer auth tokens

`--token-ttl 720h` (say) bounds how long a leaked report/relay token is
usable. Agents re-enroll at startup (rotating the token) and after
expiry. Zero (default) means no expiry.

### 5. Run the control plane unprivileged

The server only needs privileges to manage the host firewall. On a VPS
you typically open 443 once by hand and run the server as a normal user
with `--manage-firewall=false`. The systemd unit
(`deploy/wgmesh-server.service`) uses `DynamicUser` — pair it with
`--manage-firewall=false`.

### 6. Back up the state, guard the secrets

Back up together (all live in the server's working directory):

- `mesh.db` — the whole mesh (peers, keys, ACLs, audit log)
- `mesh-psk.key` — **HKDF master for every pair PSK**; losing it strands
  every peer, leaking it derives every pair key
- `admin-token`, `key.pem` (built-in TLS only)

```sh
# nightly, from cron/systemd-timer on the VPS
sqlite3 mesh.db ".backup '/backup/mesh-$(date +%F).db'"
cp mesh-psk.key admin-token /backup/       # 0600, offsite
```

All secret files are written `0600`. Keep them out of the container
image and out of git (`.gitignore` covers them).

## Auditing & logging

Two layers, by design:

- **Audit log** (durable, in `audit_log`, viewable in the UI's Audit
  tab and `GET /api/audit`): security events only — enroll, re-enroll,
  revoke, ACL create/delete, setup-key create, relay sessions, and all
  auth failures. Each row records the event, the peer (id + overlay/
  WireGuard IP), the underlay `remote_ip` the server saw, the raw
  `X-Forwarded-For` proxy chain, user-agent, method, path, and status.
  Retained `--audit-retention` (default 90d), pruned daily.
- **Access log** (request firehose): *every* request, with method, path,
  status, duration, original IP, proxy chain, the authenticated peer's
  overlay IP, and a **redacted** header dump. `Authorization`, `Cookie`,
  and the WebSocket key are never logged. `--access-log=memory` (default)
  keeps a bounded ring for the UI's Access tab and `GET /api/access-log`;
  `--access-log=stdout` emits JSONL for a log shipper; `--access-log=off`
  disables request tracing. Do not persist telemetry reports to the
  audit table (they would flood it every 30s).

Flow logs are labeled per the reporting peer's vantage: **direction**
(egress = it opened the connection, ingress = something reached in),
protocol name (tcp/udp/icmp), and **ingress/egress port numbering** —
the port traffic arrives on vs. leaves from at that peer. Header data
only; payloads are never captured.

## Topology notes

### Control plane on a public VPS

- Bind loopback + Traefik on 443 + `--trust-proxy`, or built-in TLS.
- Open only what you need: 443/tcp (API + web UI + WebSocket relay).
  With the default WebSocket relay transport, that single port also
  carries relayed traffic — no UDP range required. Add the UDP relay
  range only if you set `--relay-transport udp` for throughput.
- Optional dual-stack overlay: keep `--network` as the IPv4 overlay and
  add a ULA such as `--network6 fd00:100:64::/64` if your services need
  IPv6 addresses inside the mesh. Existing peers pick up IPv6 on their
  next re-enroll/start.
- Firewall the VPS with your provider's security groups too; the
  built-in firewall management is defense in depth, not the perimeter.

### Agents sidecar'd per service (docker compose)

Each service gets its own agent container sharing the service's network
namespace, so the service reaches the mesh on the overlay IP:

```yaml
services:
  myservice:
    image: myservice
    # ...

  myservice-wg:
    image: wgmesh-agent           # built from the agent Dockerfile target
    network_mode: "service:myservice"   # share the service's netns
    cap_add: [NET_ADMIN]
    environment:
      WGMESH_SETUP_KEY: ${WGMESH_SETUP_KEY}
    command: >
      --server https://mesh.example.com
      --setup-key ${WGMESH_SETUP_KEY}
      --listen-port 51820
      --key-file /data/wgkey.key
      --manage-firewall=false
    volumes:
      - myservice-wg:/data
volumes:
  myservice-wg:
```

Sidecar specifics:

- `network_mode: service:<svc>` puts the agent's `wg-int` in the
  service's namespace — the service then binds/reaches overlay IPs
  directly. (Don't use host networking, or every sidecar fights over
  one `wg-int`.)
- `NET_ADMIN` is required (interface creation); nothing else.
- `--manage-firewall=false` inside a container — there is no host
  firewall to manage from in the namespace; open ports on the host if
  needed.
- Give each sidecar its **own** `--key-file` volume so identities are
  distinct and persistent across restarts.
- Use a **multi-use setup key** (or one per service) delivered via your
  compose secret mechanism, not committed.
- STUN from behind Docker NAT often returns the host's mapping; on the
  same host, peers fall back to observed-IP hints or the relay. The
  WebSocket relay works even where UDP is fully blocked.

## Known limitations (honest)

- Bearer tokens, not WireGuard-key signatures, authenticate reports; TTL
  mitigates leakage but signature auth would remove the bearer secret.
- No PSK-master rotation without re-enrolling the fleet.
- Single-writer SQLite: fine for hundreds of peers, not thousands.
- Relay is store-and-forward UDP/WebSocket with no bandwidth accounting.
- The Windows agent has not been exercised on real hardware.
