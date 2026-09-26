# Multi-stage build for all wgmesh binaries.
# Targets: server (default), relay, agent — pick with `--target` or
# compose `build.target`.

# --- web UI ---
FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# --- Go binaries ---
FROM golang:1.27-alpine AS build
ARG GIT_COMMIT=unknown
# VERSION is the release tag; binaries report it to the control plane so
# the web UI can flag agents running an older build. Empty off a tag,
# where buildinfo falls back to the short commit.
ARG VERSION=
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
RUN LDFLAGS="-X gowireguard/internal/buildinfo.GitCommit=${GIT_COMMIT}"; \
    if [ -n "${VERSION}" ]; then LDFLAGS="$LDFLAGS -X gowireguard/internal/buildinfo.Version=${VERSION}"; fi; \
    CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o /out/server ./cmd/server \
 && CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o /out/relay ./cmd/relay \
 && CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o /out/agent ./cmd/agent

# --- relay ---
# Runs unprivileged: the relay only forwards UDP/WebSocket on
# unprivileged ports and writes its secret to /data. UID 65532 matches
# the server so a shared volume needs one owner.
FROM alpine:3.22 AS relay
RUN apk add --no-cache ca-certificates \
 && adduser -S -u 65532 -h /data wgmesh \
 && chown wgmesh /data
COPY --from=build /out/relay /usr/local/bin/relay
WORKDIR /data
USER 65532
ENTRYPOINT ["relay"]

# --- agent (needs NET_ADMIN + host networking at runtime) ---
# Deliberately stays root: it creates the WireGuard interface, writes
# routes and policy rules, and drives iptables/nftables. NET_ADMIN
# without root is not enough for the netlink and iptables work here.
FROM alpine:3.22 AS agent
RUN apk add --no-cache ca-certificates iptables
COPY --from=build /out/agent /usr/local/bin/agent
WORKDIR /data
ENTRYPOINT ["agent"]

# --- server (default target) ---
# Runs unprivileged: the control plane is a plain HTTP service over
# SQLite and needs no capabilities. The default --listen port (8080) is
# unprivileged, and built-in TLS uses ACME DNS-01, so nothing here has
# to bind :80/:443. A pre-existing /data volume from an older root-run
# deployment must be chowned to 65532 once — see docker-compose.yml.
FROM alpine:3.22 AS server
RUN apk add --no-cache ca-certificates \
 && adduser -S -u 65532 -h /data wgmesh \
 && chown wgmesh /data
COPY --from=build /out/server /usr/local/bin/server
WORKDIR /data
EXPOSE 8080
USER 65532
ENTRYPOINT ["server"]
