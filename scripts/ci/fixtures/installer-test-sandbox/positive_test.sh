#!/usr/bin/env bash
# Fixture (installer-test-sandbox, positive): a test that runs installer / ops scripts with the
# real HOME. Every marked line must be flagged.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/installers/linux/postinst.sh"
tmp="$(mktemp -d)"
bash "$SCRIPT" --prefix "$tmp" # FLAG
out=$(CITRATE_INSTALL_DIR="$tmp" "$SCRIPT" 2>&1) || true # FLAG
if CITRATE_REPO_ROOT="$tmp" \
   "$ROOT/scripts/ops/regenesis.sh" --dry-run >/dev/null; then # FLAG
  echo ok
fi
run() { sh "${SCRIPT}" "$@"; } # FLAG
grep -q pipefail "$SCRIPT"
rm -rf "${tmp:?}"
