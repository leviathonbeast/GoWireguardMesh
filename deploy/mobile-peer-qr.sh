#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage:
  WGMESH_ADMIN_TOKEN=... deploy/mobile-peer-qr.sh \
    --server https://mesh.example.com \
    --name iphone \
    --gateway-public-key <gateway-peer-public-key> \
    --gateway-endpoint mesh.example.com:51820 \
    [--out iphone.conf] [--png iphone.png]

Requires: curl, jq, qrencode

The gateway peer must be an active wgmesh AGENT reachable over UDP. The mesh
routes the mobile's /32 through it without NAT, so the phone keeps its overlay
source IP end-to-end; the gateway agent enables IP forwarding automatically.

The QR code is for the official WireGuard iOS/Android app:
  WireGuard app -> Add tunnel -> Create from QR code
USAGE
}

server=""
name=""
gateway_public_key=""
gateway_endpoint=""
out=""
png=""
admin_token="${WGMESH_ADMIN_TOKEN:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server)
      server="${2:-}"
      shift 2
      ;;
    --name)
      name="${2:-}"
      shift 2
      ;;
    --gateway-public-key)
      gateway_public_key="${2:-}"
      shift 2
      ;;
    --gateway-endpoint)
      gateway_endpoint="${2:-}"
      shift 2
      ;;
    --admin-token)
      admin_token="${2:-}"
      shift 2
      ;;
    --out)
      out="${2:-}"
      shift 2
      ;;
    --png)
      png="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

missing=0
for bin in curl jq qrencode; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "missing required command: $bin" >&2
    missing=1
  fi
done
if [[ "$missing" -ne 0 ]]; then
  echo "Debian/Ubuntu: sudo apt install curl jq qrencode" >&2
  exit 2
fi

if [[ -z "$server" || -z "$name" || -z "$gateway_public_key" || -z "$gateway_endpoint" || -z "$admin_token" ]]; then
  usage
  exit 2
fi

server="${server%/}"
if [[ -z "$out" ]]; then
  safe_name="$(printf '%s' "$name" | tr -cs 'A-Za-z0-9._-' '-')"
  out="${safe_name:-mobile}.conf"
fi

payload="$(
  jq -n \
    --arg name "$name" \
    --arg gateway_public_key "$gateway_public_key" \
    --arg gateway_endpoint "$gateway_endpoint" \
    '{name: $name, gateway_public_key: $gateway_public_key, gateway_endpoint: $gateway_endpoint}'
)"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

http_status="$(
  curl -sS \
    -o "$tmp" \
    -w '%{http_code}' \
    "$server/api/mobile-peers" \
    -H "Authorization: Bearer $admin_token" \
    -H "Content-Type: application/json" \
    -d "$payload"
)"

if [[ "$http_status" != "200" ]]; then
  echo "mobile peer API returned HTTP $http_status" >&2
  jq . "$tmp" >&2 || cat "$tmp" >&2
  exit 1
fi

jq -r '.config' "$tmp" > "$out"
chmod 600 "$out"

echo "saved WireGuard config: $out" >&2
jq -r '.warnings[]? | "warning: " + .' "$tmp" >&2
echo >&2
echo "Scan this in the WireGuard mobile app:" >&2
qrencode -t ansiutf8 < "$out"

if [[ -n "$png" ]]; then
  qrencode -o "$png" < "$out"
  chmod 600 "$png"
  echo "saved QR PNG: $png" >&2
fi
