#!/usr/bin/env bash
# run_deep.sh — Deep overnight TLC model checking for ALL 20 TLA+ specs
# Usage: bash citrate_v0.01.1/specs/tla/run_deep.sh
# Requires: Java 17+ and tla2tools.jar (auto-downloaded if missing)
#
# Configuration: 16 workers, 1800MB heap, 3600s timeout per spec
# Expected total runtime: 10-20 hours depending on state space sizes

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TLA2TOOLS="$SCRIPT_DIR/tla2tools.jar"
TLA2TOOLS_URL="https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar"
RESULTS_FILE="$SCRIPT_DIR/deep_verification_results.txt"
WORKERS="${TLC_WORKERS:-16}"
HEAP="${TLC_HEAP:-1800m}"
TIMEOUT="${TLC_TIMEOUT:-3600}"  # 60 minutes per spec

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Download tla2tools.jar if missing
if [ ! -f "$TLA2TOOLS" ]; then
    echo -e "${YELLOW}Downloading tla2tools.jar...${NC}"
    curl -fsSL -o "$TLA2TOOLS" "$TLA2TOOLS_URL"
    echo -e "${GREEN}Downloaded tla2tools.jar${NC}"
fi

# Verify Java is available
if ! command -v java &>/dev/null; then
    echo -e "${RED}ERROR: Java not found. Install Java 17+ to run TLC.${NC}"
    exit 1
fi

# All 20 specs (alphabetical order)
SPECS=(
    "AdapterProvenance"
    "BelnapLattice"
    "ByzantineDetection"
    "GhostDAGConsensus"
    "InferenceRequestLifecycle"
    "MempoolSequencer"
    "ModelLifecycle"
    "OODACycle"
    "OnboardingFlow"
    "ParaconsistentAggregation"
    "PrevrandaoPipeline"
    "SDKConnectionLifecycle"
    "SafetyInvariant"
    "SpecRegistryLifecycle"
    "TransactionExecution"
    "TrustScoring"
    "VRFChainContinuity"
    "VRFElection"
    "ZKKeyManagement"
    "ZKProofLifecycle"
)

TOTAL=${#SPECS[@]}
PASSED=0
FAILED=0
TIMED_OUT=0
declare -A SPEC_STATUS
declare -A SPEC_STATES
declare -A SPEC_TIME

START_TIME=$(date +%s)
RUN_DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Initialize results file
cat > "$RESULTS_FILE" <<HEADER
================================================================================
  Citrate Deep TLC Verification — $RUN_DATE
  Workers: $WORKERS | Heap: $HEAP | Timeout: ${TIMEOUT}s per spec
  Specs: $TOTAL
================================================================================

HEADER

echo ""
echo -e "${BOLD}======================================================${NC}"
echo -e "${BOLD}  Citrate Deep TLC Verification — $TOTAL Specs${NC}"
echo -e "${BOLD}  Workers: $WORKERS | Heap: $HEAP | Timeout: ${TIMEOUT}s${NC}"
echo -e "${BOLD}======================================================${NC}"
echo ""

COUNTER=0
for spec in "${SPECS[@]}"; do
    COUNTER=$((COUNTER + 1))
    TLA_FILE="$SCRIPT_DIR/${spec}.tla"
    CFG_FILE="$SCRIPT_DIR/${spec}.cfg"

    # Create a unique temp directory for this spec to avoid TLC metadata conflicts
    TMPDIR=$(mktemp -d "/tmp/tlc_deep_${spec}_XXXXXX")

    if [ ! -f "$TLA_FILE" ]; then
        echo -e "  [${COUNTER}/${TOTAL}] ${RED}SKIP${NC} $spec — .tla file not found"
        SPEC_STATUS[$spec]="SKIP"
        SPEC_STATES[$spec]="-"
        SPEC_TIME[$spec]="0"
        FAILED=$((FAILED + 1))
        echo "[$spec] SKIP — .tla file not found" >> "$RESULTS_FILE"
        rm -rf "$TMPDIR"
        continue
    fi

    if [ ! -f "$CFG_FILE" ]; then
        echo -e "  [${COUNTER}/${TOTAL}] ${RED}SKIP${NC} $spec — .cfg file not found"
        SPEC_STATUS[$spec]="SKIP"
        SPEC_STATES[$spec]="-"
        SPEC_TIME[$spec]="0"
        FAILED=$((FAILED + 1))
        echo "[$spec] SKIP — .cfg file not found" >> "$RESULTS_FILE"
        rm -rf "$TMPDIR"
        continue
    fi

    echo -ne "  [${COUNTER}/${TOTAL}] ${CYAN}Checking${NC} $spec... "

    SPEC_START=$(date +%s)
    EXIT_CODE=0

    # Run TLC in the temp directory with deep settings
    OUTPUT=$(cd "$TMPDIR" && timeout "$TIMEOUT" java \
        -Xmx${HEAP} \
        -XX:+UseParallelGC \
        -Djava.io.tmpdir="$TMPDIR" \
        -cp "$TLA2TOOLS" tlc2.TLC \
        -config "$CFG_FILE" \
        -workers "$WORKERS" \
        -deadlock \
        -metadir "$TMPDIR/states" \
        "$TLA_FILE" 2>&1) || EXIT_CODE=$?

    SPEC_END=$(date +%s)
    ELAPSED=$((SPEC_END - SPEC_START))
    SPEC_TIME[$spec]="$ELAPSED"

    # Format elapsed time
    if [ "$ELAPSED" -ge 60 ]; then
        ELAPSED_FMT="$((ELAPSED / 60))m $((ELAPSED % 60))s"
    else
        ELAPSED_FMT="${ELAPSED}s"
    fi

    if echo "$OUTPUT" | grep -q "Model checking completed. No error has been found."; then
        STATES=$(echo "$OUTPUT" | grep -oP '\d+ distinct states found' | head -1 || echo "? distinct states found")
        echo -e "${GREEN}PASS${NC} (${ELAPSED_FMT}) — ${STATES}"
        SPEC_STATUS[$spec]="PASS"
        SPEC_STATES[$spec]="$STATES"
        PASSED=$((PASSED + 1))
        echo "[$spec] PASS (${ELAPSED_FMT}) — $STATES" >> "$RESULTS_FILE"
    elif [ "$EXIT_CODE" -eq 124 ]; then
        echo -e "${RED}TIMEOUT${NC} (exceeded ${TIMEOUT}s)"
        SPEC_STATUS[$spec]="TIMEOUT"
        SPEC_STATES[$spec]="-"
        TIMED_OUT=$((TIMED_OUT + 1))
        FAILED=$((FAILED + 1))
        echo "[$spec] TIMEOUT (exceeded ${TIMEOUT}s)" >> "$RESULTS_FILE"
    else
        VIOLATION=$(echo "$OUTPUT" | grep -A2 "Error:" | head -3 || echo "unknown error")
        echo -e "${RED}FAIL${NC} (${ELAPSED_FMT})"
        echo "        $VIOLATION"
        SPEC_STATUS[$spec]="FAIL"
        SPEC_STATES[$spec]="-"
        FAILED=$((FAILED + 1))
        echo "[$spec] FAIL (${ELAPSED_FMT}) — $VIOLATION" >> "$RESULTS_FILE"
    fi

    # Save full output for debugging
    echo "$OUTPUT" > "$TMPDIR/output.log"

    # Clean up temp directory (state files can be huge)
    rm -rf "$TMPDIR"
done

END_TIME=$(date +%s)
TOTAL_ELAPSED=$((END_TIME - START_TIME))
TOTAL_FMT="$((TOTAL_ELAPSED / 3600))h $((TOTAL_ELAPSED % 3600 / 60))m $((TOTAL_ELAPSED % 60))s"

echo ""
echo -e "${BOLD}======================================================${NC}"
echo -e "${BOLD}  Summary: ${GREEN}${PASSED} passed${NC}, ${RED}${FAILED} failed${NC} (${TIMED_OUT} timeouts)"
echo -e "${BOLD}  Total time: ${TOTAL_FMT}${NC}"
echo -e "${BOLD}======================================================${NC}"
echo ""

# Print summary table
SEPARATOR="+---------------------------------+----------+------------+----------------------------+"
echo "$SEPARATOR"
printf "| %-31s | %-8s | %-10s | %-26s |\n" "Spec" "Result" "Time" "States"
echo "$SEPARATOR"

for spec in "${SPECS[@]}"; do
    STATUS="${SPEC_STATUS[$spec]:-SKIP}"
    STATES="${SPEC_STATES[$spec]:--}"
    ELAPSED="${SPEC_TIME[$spec]:-0}"

    if [ "$ELAPSED" -ge 60 ]; then
        ELAPSED_FMT="$((ELAPSED / 60))m $((ELAPSED % 60))s"
    else
        ELAPSED_FMT="${ELAPSED}s"
    fi

    printf "| %-31s | %-8s | %10s | %-26s |\n" "$spec" "$STATUS" "$ELAPSED_FMT" "$STATES"
done

echo "$SEPARATOR"
echo ""

# Append summary table to results file
{
    echo ""
    echo "================================================================================"
    echo "  SUMMARY TABLE"
    echo "================================================================================"
    echo ""
    echo "$SEPARATOR"
    printf "| %-31s | %-8s | %-10s | %-26s |\n" "Spec" "Result" "Time" "States"
    echo "$SEPARATOR"

    for spec in "${SPECS[@]}"; do
        STATUS="${SPEC_STATUS[$spec]:-SKIP}"
        STATES="${SPEC_STATES[$spec]:--}"
        ELAPSED="${SPEC_TIME[$spec]:-0}"

        if [ "$ELAPSED" -ge 60 ]; then
            ELAPSED_FMT="$((ELAPSED / 60))m $((ELAPSED % 60))s"
        else
            ELAPSED_FMT="${ELAPSED}s"
        fi

        printf "| %-31s | %-8s | %10s | %-26s |\n" "$spec" "$STATUS" "$ELAPSED_FMT" "$STATES"
    done

    echo "$SEPARATOR"
    echo ""
    echo "Total: $PASSED passed, $FAILED failed ($TIMED_OUT timeouts)"
    echo "Total time: $TOTAL_FMT"
    echo "Run completed: $(date '+%Y-%m-%d %H:%M:%S')"
} >> "$RESULTS_FILE"

echo "Results saved to: $RESULTS_FILE"

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi

echo -e "${GREEN}All $TOTAL specs passed deep verification.${NC}"
exit 0
