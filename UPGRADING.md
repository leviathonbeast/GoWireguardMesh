# Upgrading

Operator actions needed when moving between releases. Not a changelog:
a release only appears here if upgrading to it takes more than pulling
the new image or binary.

The `release` workflow copies the section matching a tag into that
release's notes, so these steps show up next to the binaries on the
Releases page.

## v0.9.4

Agent-side only; the control plane needs no change.

The Windows GUI peer list now identifies peers by their control-plane
hostname instead of overlay IP and a truncated key. Nothing to
configure: the name comes from the sync payload a peer was enrolled
with. Peers enrolled without a hostname keep showing their overlay IP
and sort to the bottom of the list.

## v0.9.3

Agent-side fix; the control plane needs no change.

Agents kept falling back from the QUIC relay to the HTTPS WebSocket on
an ACME control plane, logging:

```
QUIC relay unavailable; falling back to HTTPS WebSocket
error="... x509: cannot validate certificate for <ip> because it
doesn't contain any IP SANs"
```

Traffic still flowed over the fallback, so this is a performance fix
rather than an outage one. It takes effect per agent as each is
upgraded — Linux and Windows alike.

## v0.9.2

**Schema v18.** Additive migration, applied automatically on first
start; peers and settings are preserved. Tested upgrading a v0.9.1
database in place.

Upgrade the server before the agents. Agents now report their build and
the UI flags any running something other than the control plane's, so
until an agent is upgraded its version column shows a dash — expected,
not a fault.

## v0.8.8

**The server and relay containers now run unprivileged as UID 65532.**
Only the agent still needs root (it creates the WireGuard interface and
drives netlink and iptables).

A `/data` volume written by an older root-running image is owned by
root, so the new server cannot write its database. The symptom is a
restart loop with:

```
read schema version: attempt to write a readonly database (1544)
```

Fix it once, before starting the new image:

```sh
docker compose down
docker compose run --rm --user 0 --entrypoint chown <service> -R 65532:65533 /data
docker compose up -d
```

`<service>` is the compose service name (`docker compose config
--services`), not the container name. If the entrypoint gets in the way,
do it from the host instead:

```sh
docker volume inspect <volume> --format '{{.Mountpoint}}'
chown -R 65532:65533 <that path>
```

Fresh deployments need nothing: the image creates `/data` owned by
65532.

Also in this release, `mesh.db` and its `-wal`/`-shm` sidecars are
tightened to `0600` on every open. No action needed — existing files are
corrected in place.
