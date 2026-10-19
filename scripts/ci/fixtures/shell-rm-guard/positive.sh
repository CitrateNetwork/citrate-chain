#!/usr/bin/env bash
# Fixture (shell-rm-guard, positive): every recursive rm below starts with an unguarded
# variable, so an unset or empty value would widen the delete. Each line must be flagged.
set -euo pipefail
rm -rf "$WORK"
rm -rf "${STAGE}/payload"
rm -fr $BUILD_DIR/out
rm -r -f "$(dirname "$0")/cache"
trap 'rm -rf "$tmp"' EXIT
if true; then rm -R "$1"; fi
