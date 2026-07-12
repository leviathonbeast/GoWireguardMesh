#!/usr/bin/env bash
#
# Build all wgmesh binaries for Linux and Windows in one go.
#
#   deploy/build.sh          # build Go binaries into ./bin
#   deploy/build.sh --web    # also rebuild the web UI first (needs npm)
#
# Output is static (CGO disabled) and stripped, ready to copy to a host.
# The web UI is embedded from the committed web/dist, so --web is only
# needed after changing web/src.

set -euo pipefail

# Resolve the repo root from this script's location, so it runs from
# anywhere.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

OUT="${OUT:-bin}"
export CGO_ENABLED=0
GIT_COMMIT="$(git rev-parse HEAD 2>/dev/null || printf unknown)"
if ! git diff --quiet --ignore-submodules HEAD 2>/dev/null; then
	GIT_COMMIT="${GIT_COMMIT}-dirty"
fi

# --web: rebuild the embedded UI bundle (only if npm is available).
if [[ "${1:-}" == "--web" ]]; then
	if command -v npm >/dev/null 2>&1; then
		echo ">> rebuilding web UI"
		(cd web && npm install --no-audit --no-fund && npm run build)
	else
		echo "!! npm not found; skipping web build (using committed web/dist)"
	fi
fi

# build GOOS GOARCH CMD OUTFILE
build() {
	local goos="$1" goarch="$2" cmd="$3" out="$4"
	printf '>> %-8s %-6s cmd/%-7s -> %s/%s\n' "$goos" "$goarch" "$cmd" "$OUT" "$out"
	GOOS="$goos" GOARCH="$goarch" \
		go build -trimpath -ldflags "-s -w -X gowireguard/internal/buildinfo.GitCommit=$GIT_COMMIT" -o "$OUT/$out" "./cmd/$cmd"
}

echo "== building wgmesh (output: $OUT/) =="
mkdir -p "$OUT"

# Linux amd64 — control plane + agent. The relay is built into the
# server (run it with --relay-embedded), so you do NOT need a separate
# relay binary unless the relay must run on a different host than the
# control plane (e.g. a public relay fronting a control plane that
# isn't publicly reachable). Uncomment below only for that case.
build linux amd64 server "server"
build linux amd64 agent  "agent"
# build linux amd64 relay "relay"     # standalone relay, separate host only

# Windows amd64 — agent (sidecar/desktop) and the control plane.
build windows amd64 agent  "agent.exe"
build windows amd64 server "server.exe"

# Windows amd64 — desktop GUI agent (Fyne + system tray). Fyne needs
# cgo, so this builds only when a mingw-w64 cross compiler is around;
# set WINDOWS_CC to point at one explicitly (gcc or clang targeting
# x86_64-w64-mingw32, e.g. from llvm-mingw or mingw64-cross-gcc).
# On a Windows box with gcc installed, plain
#   go build -tags gui -ldflags "-H windowsgui -s -w" ./cmd/agent
# does the same thing.
WINDOWS_CC="${WINDOWS_CC:-$(command -v x86_64-w64-mingw32-gcc || true)}"
if [[ -n "$WINDOWS_CC" ]]; then
	printf '>> %-8s %-6s cmd/%-7s -> %s/%s (gui, cgo)\n' windows amd64 agent "$OUT" agent-gui.exe
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC="$WINDOWS_CC" \
		go build -trimpath -tags gui -ldflags "-s -w -H windowsgui -X gowireguard/internal/buildinfo.GitCommit=$GIT_COMMIT" -o "$OUT/agent-gui.exe" ./cmd/agent
else
	echo "!! no x86_64-w64-mingw32 compiler found; skipping agent-gui.exe (set WINDOWS_CC to enable)"
fi

# Add more targets as needed, e.g. a Raspberry Pi:
#   build linux arm64 agent "agent-arm64"

echo
echo "== done =="
ls -lh "$OUT"
