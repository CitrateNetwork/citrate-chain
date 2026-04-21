#!/usr/bin/env bash
# run_all.sh — Run TLC model checker on ALL TLA+ specs (organized by category)
# Usage: bash specs/tla/run_all.sh
# Requires: Java 8+ and tla2tools.jar (auto-downloaded if missing)
#
# Picks up any `<spec>.tla` with a matching `<spec>.cfg` in the category
# subdirs. Additional parameter cfgs (e.g., `<spec>_medium.cfg`,
# `<spec>_liveness.cfg`) are NOT run by this script — those are deep
# verifications run on demand. See `run_deep.sh` for the long-timeout
# batch mode.
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
JAR="$SCRIPT_DIR/tla2tools.jar"
WORKERS=${TLC_WORKERS:-4}
HEAP=${TLC_HEAP:-1800m}
TIMEOUT=${TLC_TIMEOUT:-120}

if [ ! -f "$JAR" ]; then
    echo "Downloading TLC 1.7.1..."
    curl -sLo "$JAR" "https://github.com/tlaplus/tlaplus/releases/download/v1.7.1/tla2tools.jar"
fi

pass=0; fail=0; total=0

for dir in "$SCRIPT_DIR"/consensus "$SCRIPT_DIR"/zk "$SCRIPT_DIR"/learning "$SCRIPT_DIR"/contracts "$SCRIPT_DIR"/compute "$SCRIPT_DIR"/gui; do
    [ -d "$dir" ] || continue
    category=$(basename "$dir")
    echo ""
    echo "=== ${category^^} ==="

    for tla in "$dir"/*.tla; do
        [ -f "$tla" ] || continue
        cfg="${tla%.tla}.cfg"
        [ -f "$cfg" ] || continue
        spec=$(basename "$tla" .tla)
        total=$((total + 1))

        printf "  %-40s " "$spec"
        tmpdir=$(mktemp -d)
        output=$(cd "$tmpdir" && timeout "$TIMEOUT" java -cp "$JAR" "-Xmx${HEAP}" \
            tlc2.TLC -config "$cfg" "$tla" -workers "$WORKERS" -deadlock 2>&1 || true)
        rm -rf "$tmpdir"

        dist=$(echo "$output" | grep -oP '[\d,]+ distinct states' | tail -1 | grep -oP '^[\d,]+' | tr -d ',' 2>/dev/null) || dist="0"
        [ -z "$dist" ] && dist="0"

        if echo "$output" | grep -q "No error has been found"; then
            echo "PASS ($dist distinct)"
            pass=$((pass + 1))
        elif echo "$output" | grep -q "Error:"; then
            echo "FAIL"
            echo "$output" | grep "Error:" | head -1
            fail=$((fail + 1))
        else
            echo "TIMEOUT ($dist explored, 0 violations)"
            fail=$((fail + 1))
        fi
    done
done

echo ""
echo "=========================================="
echo "  TOTAL: $pass/$total PASS, $fail FAIL"
echo "=========================================="
