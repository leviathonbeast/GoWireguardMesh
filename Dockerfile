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
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -o /out/server ./cmd/server \
 && CGO_ENABLED=0 go build -o /out/relay ./cmd/relay \
 && CGO_ENABLED=0 go build -o /out/agent ./cmd/agent

# --- relay ---
FROM alpine:3.21 AS relay
RUN apk add --no-cache ca-certificates
COPY --from=build /out/relay /usr/local/bin/relay
WORKDIR /data
ENTRYPOINT ["relay"]

# --- agent (needs NET_ADMIN + host networking at runtime) ---
FROM alpine:3.21 AS agent
RUN apk add --no-cache ca-certificates
COPY --from=build /out/agent /usr/local/bin/agent
WORKDIR /data
ENTRYPOINT ["agent"]

# --- server (default target) ---
FROM alpine:3.21 AS server
RUN apk add --no-cache ca-certificates
COPY --from=build /out/server /usr/local/bin/server
WORKDIR /data
EXPOSE 8080
ENTRYPOINT ["server"]
