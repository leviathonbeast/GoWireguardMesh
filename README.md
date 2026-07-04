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
- **Control plane** — HTTP enrollment with setup keys (expiry, max uses,
  revocation), atomic IP allocation, idempotent re-enroll, network-wide
  preshared key distribution. Backed by SQLite.

Not built yet (roadmap, in order): config sync (new peers pushed to existing
ones), STUN + UDP hole punching, relay fallback, DNS, ACLs.

## Layout

```
cmd/agent/       node agent (runs on every machine in the mesh, needs root)
cmd/server/      control plane (enrollment API + setup key management)
cmd/relay/       relay server (not yet implemented)
internal/proto/  JSON wire structs shared by agent and server
internal/store/  all SQLite access (schema, setup keys, atomic enrollment)
internal/psk/    network-wide preshared key load-or-generate
schema.sql       canonical database schema (embedded into the server binary)
```

## Requirements

- Go 1.26+
- Linux with the `wireguard` kernel module (agent only; the server runs
  anywhere and needs no root)
- No cgo — SQLite is pure Go (`modernc.org/sqlite`)

## Build

```sh
go build -o bin/server ./cmd/server
go build -o bin/agent  ./cmd/agent
```

## Setting up the control plane

Start the server (creates `mesh.db` and the schema on first run):

```sh
./bin/server --listen 0.0.0.0:8080 --db mesh.db --network 100.64.0.0/16
```

On first start it also generates `mesh-psk.key` — the network-wide WireGuard
preshared key handed to every peer. Keep it 0600 and back it up alongside the
database; losing it strands enrolled peers on a different PSK than new ones.

Mint a setup key (prints the token to stdout):

```sh
./bin/server newkey --db mesh.db                    # unlimited uses, never expires
./bin/server newkey --db mesh.db --max-uses 1       # single enrollment
./bin/server newkey --db mesh.db --expires-in 24h   # valid for one day
```

Flags for `server`:

| Flag | Default | Purpose |
|---|---|---|
| `--listen` | `127.0.0.1:8080` | HTTP listen address |
| `--db` | `mesh.db` | SQLite database path |
| `--network` | `100.64.0.0/16` | overlay network; peers get the lowest free IP |
| `--psk-file` | `mesh-psk.key` | network preshared key file |

> **Security note:** enrollment currently runs over plain HTTP. That is
> acceptable on a trusted LAN during development only — setup keys and the
> PSK cross the wire in cleartext. TLS is planned before any public exposure.

## Joining a node to the mesh

On each machine (root required — the agent creates network interfaces):

```sh
sudo ./bin/agent --server http://<control-plane>:8080 --setup-key <token>
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
