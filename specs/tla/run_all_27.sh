#!/usr/bin/env bash
# run_all_27.sh — Run ALL 27 TLA+ specs sequentially with maximum workers
#
# Each spec gets 16 workers and 1800MB heap for deep state exploration.
# Timeout: 45 minutes per spec.
# Results written to deep_verification_results.txt.
#
# Usage: bash run_all_27.sh
# Monitor: tail -f deep_verification_results.txt

set -u

BASE="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
JAR="$SCRIPT_DIR/tla2tools.jar"
OUTFILE="$SCRIPT_DIR/deep_verification_results.txt"
WORKERS=${TLC_WORKERS:-16}
HEAP=${TLC_HEAP:-1800m}
TIMEOUT=${TLC_TIMEOUT:-2700}     # 45 min

# Download TLC if missing
if [ ! -f "$JAR" ]; then
    echo "Downloading TLC 1.7.1..."
    curl -sLo "$JAR" "https://github.com/tlaplus/tlaplus/releases/download/v1.7.1/tla2tools.jar"
fi

# Collect ALL spec locations (tla files with matching .cfg)
declare -a TLA_FILES=()
declare -a CFG_FILES=()

for dir in \
    "$BASE/specs/tla" \
    "$BASE/gui/citrate_gui_v2/specs" \
    "$BASE/../.agentile/audits/2026-03/2026-03-02-architecture-security-deep-audit/tla"; do
    [ -d "$dir" ] || continue
    for tla in "$dir"/*.tla; do
        [ -f "$tla" ] || continue
        cfg="${tla%.tla}.cfg"
        [ -f "$cfg" ] || continue
        TLA_FILES+=("$tla")
        CFG_FILES+=("$cfg")
    done
done

TOTAL=${#TLA_FILES[@]}

# Header
cat << HEADER | tee "$OUTFILE"
========================================================================
  Citrate Deep TLC Verification — $(date -u '+%Y-%m-%d %H:%M UTC')
  Workers: $WORKERS | Heap: $HEAP | Timeout: ${TIMEOUT}s per spec
  Specs: $TOTAL
========================================================================

HEADER

pass=0; fail=0; total_gen=0; total_dist=0
declare -a RESULTS=()

for i in $(seq 0 $((TOTAL - 1))); do
    tla="${TLA_FILES[$i]}"
    cfg="${CFG_FILES[$i]}"
    spec=$(basename "$tla" .tla)

    printf "  [%2d/%d] %-35s " "$((i+1))" "$TOTAL" "$spec" | tee -a "$OUTFILE"

    tmpdir=$(mktemp -d)
    start_s=$(date +%s)

    output=$(cd "$tmpdir" && timeout "$TIMEOUT" java -cp "$JAR" "-Xmx${HEAP}" \
        tlc2.TLC -config "$cfg" "$tla" -workers "$WORKERS" -deadlock 2>&1 || true)

    end_s=$(date +%s)
    elapsed=$((end_s - start_s))
    rm -rf "$tmpdir"

    # Parse states (use subshells to avoid pipefail issues)
    gen=$(echo "$output" | grep -oP '[\d,]+ states generated' | tail -1 | grep -oP '^[\d,]+' | tr -d ',' 2>/dev/null) || gen="0"
    dist=$(echo "$output" | grep -oP '[\d,]+ distinct states' | tail -1 | grep -oP '^[\d,]+' | tr -d ',' 2>/dev/null) || dist="0"
    [ -z "$gen" ] && gen="0"
    [ -z "$dist" ] && dist="0"

    # Determine status
    if echo "$output" | grep -q "Model checking completed. No error has been found"; then
        status="PASS"
        pass=$((pass + 1))
    elif [ $elapsed -ge $((TIMEOUT - 5)) ]; then
        status="TIMEOUT"
        fail=$((fail + 1))
    elif echo "$output" | grep -q "Error:"; then
        status="FAIL"
        fail=$((fail + 1))
    else
        status="UNKNOWN"
        fail=$((fail + 1))
    fi

    total_gen=$((total_gen + ${gen:-0}))
    total_dist=$((total_dist + ${dist:-0}))

    # Format time
    if [ $elapsed -ge 3600 ]; then
        ts="$(($elapsed/3600))h $(($elapsed%3600/60))m"
    elif [ $elapsed -ge 60 ]; then
        ts="$(($elapsed/60))m $(($elapsed%60))s"
    else
        ts="${elapsed}s"
    fi

    # Format numbers with commas
    gen_fmt=$(printf "%'d" "${gen:-0}" 2>/dev/null || echo "${gen:-0}")
    dist_fmt=$(printf "%'d" "${dist:-0}" 2>/dev/null || echo "${dist:-0}")

    RESULTS+=("$spec|$status|$gen_fmt|$dist_fmt|$ts")

    if [ "$status" = "PASS" ]; then
        echo "PASS  ${dist_fmt} distinct  (${ts})" | tee -a "$OUTFILE"
    else
        echo "${status}  (${ts})" | tee -a "$OUTFILE"
    fi
done

# Summary table
cat << TABLE | tee -a "$OUTFILE"

========================================================================
  RESULTS TABLE
========================================================================

$(printf "| %-35s | %-7s | %16s | %16s | %8s |\n" "Specification" "Status" "States Generated" "Distinct States" "Time")
$(printf "|%-37s|%-9s|%-18s|%-18s|%-10s|\n" "-------------------------------------" "---------" "------------------" "------------------" "----------")
TABLE

for row in "${RESULTS[@]}"; do
    IFS='|' read -r spec status gen dist ts <<< "$row"
    printf "| %-35s | %-7s | %16s | %16s | %8s |\n" "$spec" "$status" "$gen" "$dist" "$ts" | tee -a "$OUTFILE"
done

gen_fmt=$(printf "%'d" "$total_gen" 2>/dev/null || echo "$total_gen")
dist_fmt=$(printf "%'d" "$total_dist" 2>/dev/null || echo "$total_dist")

cat << SUMMARY | tee -a "$OUTFILE"

========================================================================
  SUMMARY
========================================================================
  Passed:           $pass / $TOTAL
  Failed/Timeout:   $fail
  States generated: $gen_fmt
  Distinct states:  $dist_fmt
  Completed:        $(date -u '+%Y-%m-%d %H:%M UTC')
========================================================================
SUMMARY

if [ $fail -eq 0 ]; then
    echo "  ✓ ALL $TOTAL SPECS PASS — zero invariant violations" | tee -a "$OUTFILE"
else
    echo "  ✗ $fail specs did not complete" | tee -a "$OUTFILE"
fi
