#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "Running Slint visual proof suite (snapshots + journeys)..."
# Use exact suite name — NOT a loose filter that could match 0 tests
OUTPUT=$(cargo test -p citrate-gui-native --bin citrate-gui-native ui_visual_proof_suite -- --nocapture 2>&1)
echo "$OUTPUT"

# Fail-safe: verify at least 1 test actually ran (not a zero-test false pass)
if echo "$OUTPUT" | grep -q "0 passed"; then
    echo "ERROR: Zero tests executed. The proof suite did not run."
    exit 1
fi
if echo "$OUTPUT" | grep -q "running 0 tests"; then
    echo "ERROR: Zero tests matched. Check the test filter name."
    exit 1
fi

echo
echo "Snapshot artifacts:"
ls -1 "$ROOT_DIR/target/gui-snapshots/"*.png 2>/dev/null | wc -l
echo "PNG files in $ROOT_DIR/target/gui-snapshots/"
