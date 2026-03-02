#!/usr/bin/env bash
# run_all.sh — Run TLC model checker on all protocol-level TLA+ specs
# Usage: bash citrate_v0.01.1/specs/tla/run_all.sh
# Requires: Java 17+ and tla2tools.jar (auto-downloaded if missing)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TLA2TOOLS="$SCRIPT_DIR/tla2tools.jar"
TLA2TOOLS_URL="https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar"
TIMEOUT="${TLC_TIMEOUT:-900}"  # 15 minutes per spec

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

# Specs to check (filename without extension)
SPECS=(
    "GhostDAGConsensus"
    "MempoolSequencer"
    "VRFElection"
)

PASSED=0
FAILED=0
ERRORS=()

echo "========================================"
echo "  TLC Model Checker — Citrate Protocol"
echo "========================================"
echo ""

for spec in "${SPECS[@]}"; do
    TLA_FILE="$SCRIPT_DIR/${spec}.tla"
    CFG_FILE="$SCRIPT_DIR/${spec}.cfg"

    if [ ! -f "$TLA_FILE" ]; then
        echo -e "${RED}SKIP${NC} $spec — .tla file not found"
        FAILED=$((FAILED + 1))
        ERRORS+=("$spec: .tla file missing")
        continue
    fi

    if [ ! -f "$CFG_FILE" ]; then
        echo -e "${RED}SKIP${NC} $spec — .cfg file not found"
        FAILED=$((FAILED + 1))
        ERRORS+=("$spec: .cfg file missing")
        continue
    fi

    echo -n "Checking $spec... "

    # Run TLC with timeout
    OUTPUT=$(timeout "$TIMEOUT" java -XX:+UseParallelGC \
        -cp "$TLA2TOOLS" tlc2.TLC \
        -config "$CFG_FILE" \
        -workers auto \
        -deadlock \
        "$TLA_FILE" 2>&1) || EXIT_CODE=$?

    EXIT_CODE=${EXIT_CODE:-0}

    if echo "$OUTPUT" | grep -q "Model checking completed. No error has been found."; then
        STATES=$(echo "$OUTPUT" | grep -oP '\d+ distinct states found' | head -1 || echo "")
        echo -e "${GREEN}PASS${NC} ${STATES}"
        PASSED=$((PASSED + 1))
    elif [ "$EXIT_CODE" -eq 124 ]; then
        echo -e "${RED}TIMEOUT${NC} (exceeded ${TIMEOUT}s)"
        FAILED=$((FAILED + 1))
        ERRORS+=("$spec: timeout after ${TIMEOUT}s")
    else
        VIOLATION=$(echo "$OUTPUT" | grep -A2 "Error:" | head -3 || echo "unknown error")
        echo -e "${RED}FAIL${NC}"
        echo "  $VIOLATION"
        FAILED=$((FAILED + 1))
        ERRORS+=("$spec: $VIOLATION")
    fi
done

echo ""
echo "========================================"
echo "  Results: ${PASSED} passed, ${FAILED} failed"
echo "========================================"

if [ ${#ERRORS[@]} -gt 0 ]; then
    echo ""
    echo "Failures:"
    for err in "${ERRORS[@]}"; do
        echo "  - $err"
    done
    exit 1
fi

echo -e "${GREEN}All specs passed.${NC}"
exit 0
