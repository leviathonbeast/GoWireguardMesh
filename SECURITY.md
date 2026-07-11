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

The relay's forwarding ports are necessarily open to the world (peer
addresses are learned from their first packets), so those legs are
defended in the packet path: datagrams that are not WireGuard-shaped
(wrong type byte, reserved bytes, or size) are dropped without being
forwarded, without updating the learned peer address, and without
keeping the pair alive; and once a leg has an address, only a
handshake-shaped message can move it. An off-path attacker who finds a
relay port can therefore neither inject junk into a peer's WireGuard
socket nor redirect the ciphertext stream to themselves with spoofed
data packets. (A spoofed *handshake-shaped* packet can still move a
leg's address — the relay cannot verify WireGuard crypto — but the
stream it steals is ciphertext, and the real peer re-handshakes and
reclaims the leg within seconds.) The agent-side WebSocket relay proxy
pins its loopback counterpart to kernel WireGuard's own listen port, so
no other local process — including a service container sharing the
agent's network namespace — can hijack or feed the relay stream.

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

The web UI is protected by username/password accounts (argon2id at rest;
first boot seeds `admin` with the admin token as its password — change it).
Anonymous visitors only receive a tiny server-rendered login form; the
dashboard bundle/assets are served only after login sets a signed HttpOnly
`SameSite=Strict` session cookie (HMAC key in `session.key`, separate from
the admin token, so a leaked bearer token cannot forge cookies). The SPA
itself holds **no credential at all** — nothing in sessionStorage or
localStorage for an XSS payload to steal; every browser request rides the
cookie, and `SameSite=Strict` plus the same-origin CSP covers CSRF. All
API JSON is served `Cache-Control: no-store`, so setup keys and device
configs never land in a browser or proxy cache. The admin **bearer token
remains valid for the API** (curl, automation): treat it like root for the
mesh — keep TLS strict, never log or share it, and rotate `admin-token` if
it leaks.

### 2. Rate limiting (on by default)

Public endpoints (`/enroll`, `/report`, `/relay-pair`, `/relay-ws`, and the
UI login form) are
throttled per source IP (`--rate-limit`, `--rate-burst`). This blunts
setup-key brute forcing and relay exhaustion. Keyed on the real client
IP, so it works correctly behind a trusted proxy. Admin routes are
gated by the admin token instead.

With `--trust-proxy`, the client IP is the **rightmost**
`X-Forwarded-For` entry — the one your proxy appended and vouches for.
A client-supplied `X-Forwarded-For` prefix cannot spoof the
rate-limiter key or the audit identity (the full header chain is still
recorded for forensics). This assumes exactly **one** trusted proxy in
front; a CDN-then-proxy chain would need a trusted-hop count this
project deliberately doesn't grow.

### 2b. Built-in HTTP hardening (no flags, always on)

- **Server timeouts** — header 10s, read/write 60s, idle 120s, 64KB
  header cap. A handful of slow-drip connections can no longer pin
  goroutines forever (slowloris). Long-lived WebSocket relay sessions
  are unaffected: `net/http` clears connection deadlines when the
  upgrade hijacks the connection (a regression test pins this).
- **Request body caps** — every JSON endpoint is size-bounded
  (`/enroll` 64KB, `/report` 4MB, `/relay-pair` 4KB, admin 64KB);
  oversized bodies get `413`. An unbounded decode on a public endpoint
  is a memory-exhaustion vector.
- **TLS 1.3 floor** — built-in TLS refuses anything older; every
  legitimate client (our agents, modern browsers) speaks 1.3. When
  Traefik terminates TLS this is the proxy's job instead.
- **Security headers** — every response carries a same-origin
  `Content-Security-Policy`, `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and (over
  TLS) HSTS. The CSP prevents injected markup from loading off-origin
  script; the dashboard itself is not served until the signed UI session
  cookie exists.
- **Graceful shutdown** — SIGINT/SIGTERM drains the server and runs
  cleanup, so firewall rules the server opened are removed instead of
  leaking until the next start's reconciliation.
- **SQLite `busy_timeout`** — concurrent writers queue up to 5s
  instead of failing instantly, so enroll/report bursts don't surface
  as intermittent 500s.

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

Agents also report per-peer path state (`direct`, `ws-relay`, `udp-relay`,
`probing-direct`) so operators can see whether traffic is on the preferred
direct path or temporarily riding a relay.

Console logging is leveled (`--log-level` on both binaries, default
`info`): rejections and auth failures log at `warn`, internal errors at
`error`, per-tick chatter (agent sync diffs, prune counts) at `debug`.
`--log-level=warn` gives a quiet console that still surfaces everything
security-relevant; the access-log stream is independent of this level.

## Topology notes

### Control plane on a public VPS

- Bind loopback + Traefik on 443 + `--trust-proxy`, or built-in TLS.
- Open only what you need: 443/tcp (API + web UI + WebSocket relay).
  With the default WebSocket relay transport, that single port also
  carries relayed traffic — no UDP range required. Add the UDP relay
  range only if you set `--relay-transport udp` for throughput.
- Dual-stack overlay: keep `--network` as the IPv4 overlay and override
  the default ULA with `--network6 <cidr>` if you need a different IPv6
  mesh range. The web UI can migrate both overlay CIDRs with a preview
  and explicit confirmation; running agents adopt the new self address
  from the next report response, and restart/re-enroll also returns the
  new assignment.
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
    entrypoint: ["/usr/local/bin/agent"]
    network_mode: "service:myservice"   # share the service's netns
    cap_add: [NET_ADMIN]
    devices:
      - /dev/net/tun:/dev/net/tun
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
- Setup keys are stored (and listed in the UI) in plaintext — a
  deliberate UX tradeoff so keys stay copyable. Hash-at-rest with
  show-once-at-creation was considered and deferred; treat the database
  file's confidentiality accordingly.
- Static (phone/appliance) peers' private keys are stored, so the admin
  UI can show their config and QR code again. They are sealed with
  AES-256-GCM under an HKDF subkey of the PSK master and bound to the
  peer's public key, so `mesh.db` alone does not disclose them — but an
  attacker holding both `mesh.db` and `mesh-psk.key` recovers every
  device key, just as they already recover every pair PSK. Keep the two
  files in different backup domains, or supply your own private key at
  creation (`private_key`), which is never stored and forgoes re-showing
  the config. Reads of a stored config are audited as
  `mobile_peer_config_view`.
- No PSK-master rotation without re-enrolling the fleet. Rotating it also
  strands every stored device config: the sealed keys no longer open, and
  those devices must be re-created.
- Single-writer SQLite: fine for hundreds of peers, not thousands.
- Relay is store-and-forward UDP/WebSocket with no bandwidth accounting.
- The Windows agent has not been exercised on real hardware.
