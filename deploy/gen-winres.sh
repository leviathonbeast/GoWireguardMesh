#!/usr/bin/env bash
#
# Regenerate cmd/agent/resource_windows_amd64.syso from
# cmd/agent/winres/agent.rc (+ agent.ico). The .syso is checked in, so
# this only needs to run when the icon or version block changes.
#
# Needs a windres for x86_64 Windows: llvm-windres/x86_64-w64-mingw32-windres
# (llvm-mingw or mingw-w64). Set WINDRES to override autodetection.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

WINDRES="${WINDRES:-$(command -v x86_64-w64-mingw32-windres || command -v llvm-windres || true)}"
if [[ -z "$WINDRES" ]]; then
	echo "!! no windres found; set WINDRES (llvm-mingw or mingw-w64 provide one)" >&2
	exit 1
fi

cd "$ROOT/cmd/agent/winres"
"$WINDRES" --target=pe-x86-64 -O coff -i agent.rc -o ../resource_windows_amd64.syso
echo "wrote cmd/agent/resource_windows_amd64.syso"
