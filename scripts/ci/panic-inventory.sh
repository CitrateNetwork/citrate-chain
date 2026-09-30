#!/usr/bin/env bash
# panic-inventory.sh — measure the PRODUCTION panic surface (PANIC-S1).
#
# Runs clippy over production targets only (`--lib --bins`: #[cfg(test)] code is
# not compiled) with every lint that marks a way release code can panic, then
# aggregates per crate x lint. `[profile.release] overflow-checks = true`, so
# unchecked arithmetic is a panic class too.
#
# Uses its own target dir so the extra lint flags don't invalidate the normal
# clippy cache (and vice versa).
#
# Usage:
#   scripts/ci/panic-inventory.sh                       # print the total
#   scripts/ci/panic-inventory.sh --summary out.json    # per-crate x lint counts
#   scripts/ci/panic-inventory.sh --sites sites.json    # every site (for the ledger)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

LINTS=(unwrap_used expect_used panic unreachable indexing_slicing
       arithmetic_side_effects string_slice)
FLAGS=()
for l in "${LINTS[@]}"; do FLAGS+=(-W "clippy::$l"); done

RAW="$(mktemp)"; trap 'rm -f "$RAW"' EXIT
CARGO_TARGET_DIR="${PANIC_INVENTORY_TARGET_DIR:-$REPO_ROOT/target/panic-inventory}" \
  cargo clippy --workspace --lib --bins --quiet --message-format=json -- "${FLAGS[@]}" > "$RAW"
python3 "$REPO_ROOT/scripts/ci/panic_inventory.py" "$RAW" "$@"
