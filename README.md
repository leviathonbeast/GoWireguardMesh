# wgmesh

A self-hosted WireGuard mesh — a NetBird/Tailscale-style overlay network in Go, no paywalls. Peers enroll against a central control plane with setup keys, get overlay IPs from CGNAT/ULA space (`100.64.0.0/16`, `fd00:100:64::/64`), and automatically stay configured with the peers they're allowed to reach.

- Kernel WireGuard data plane (links survive agent restarts)
- Automatic NAT traversal: STUN, hole punching, and a relay fallback over 443
- Per-pair preshared keys, ACL segmentation, embedded web UI, DNS push
- Exit nodes: route a machine's entire internet traffic out another agent (assigned in the UI)
- Single binary control plane with an optional built-in relay

## Build

The web UI is prebuilt and embedded, so a plain Go build needs no Node toolchain:

```sh
go build -o bin/server ./cmd/server
go build -o bin/agent  ./cmd/agent
```

Requires Go 1.26+ (no cgo). Agents need the Linux `wireguard` kernel module; the server runs anywhere and needs no root.

## Quick start

```sh
# 1. control plane — creates mesh.db, a TLS cert, the PSK master, and the admin token
./bin/server --listen 0.0.0.0:8443 --tls-hosts "127.0.0.1,mesh.example.com"

# 2. mint a setup key
./bin/server newkey --db mesh.db --name laptop

# 3. join a node (root — it creates a network interface)
sudo ./bin/agent --server https://192.168.1.10:8443 --setup-key <token> --server-ca cert.pem
```

The agent enrolls, gets an overlay IP, brings up `wg-int`, and connects to its peers. Add more nodes with the same steps; they find each other automatically.

**Web UI** — open the server's address in a browser. First login is user `admin` with the generated `admin-token` as the password; set a real one under **Account**. From there: peers, traffic, ACL policies, setup keys, DNS, and the audit log.

## Documentation

- **[DOCS.md](DOCS.md)** — full reference: every flag, the web UI and admin API, relay/NAT-traversal internals, DNS, ACLs, TLS modes (direct Let's Encrypt, SNI passthrough, behind a proxy), Docker/Gitea deployment, mobile (iPhone/Android), and the Windows agent.
- **[SECURITY.md](SECURITY.md)** — production hardening and the VPS + per-service-sidecar deployment topology.

## Repository layout

```
cmd/agent/    node agent (every mesh machine, needs root)
cmd/server/   control plane (enrollment + admin API + web UI + embedded relay)
cmd/relay/    standalone relay (UDP forwarder), for a separate host
internal/     proto · store (SQLite) · psk · relay · tlsutil · firewall
web/          admin UI (React + TypeScript, Vite)
deploy/       systemd units + compose templates
```

## Status

Suitable today for trusted-LAN, public-endpoint, and VPS-fronted meshes at homelab scale (read [SECURITY.md](SECURITY.md) before exposing the control plane). Known limits: single-writer SQLite (hundreds of peers, not thousands), bearer-token peer auth, no PSK-master rotation, and an experimental Windows agent unvalidated on real hardware.
