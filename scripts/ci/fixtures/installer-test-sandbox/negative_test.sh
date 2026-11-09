#!/usr/bin/env bash
# Fixture (installer-test-sandbox, negative): the same invocations inside a sandbox (a mktemp
# dir with HOME pointed into it). Nothing here may be flagged.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/installers/linux/postinst.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp:?}"' EXIT
export HOME="$tmp/home"
mkdir -p "$HOME"
bash "$SCRIPT" --prefix "$tmp"
out=$(CITRATE_INSTALL_DIR="$tmp" "$SCRIPT" 2>&1) || true
"$ROOT/scripts/ops/regenesis.sh" --dry-run >/dev/null || true
