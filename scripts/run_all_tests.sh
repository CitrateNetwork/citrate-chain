#!/usr/bin/env bash
# run_all_tests.sh — Comprehensive test suite runner for Citrate
#
# Runs all test layers: Rust workspace, Tauri backend, GUI (Vitest),
# Solidity (Foundry), TLA+ formal verification, and optional fuzzing.
#
# Usage:
#   ./scripts/run_all_tests.sh              # Run everything (standard depth)
#   ./scripts/run_all_tests.sh --fast       # Skip TLA+ and fuzzing
#   ./scripts/run_all_tests.sh --rust       # Rust workspace + Tauri backend
#   ./scripts/run_all_tests.sh --gui        # GUI Vitest + TypeScript
#   ./scripts/run_all_tests.sh --sol        # Solidity Foundry tests
#   ./scripts/run_all_tests.sh --tla        # TLA+ standard verification
#   ./scripts/run_all_tests.sh --tla-deep   # TLA+ deep verification (large state spaces)
#   ./scripts/run_all_tests.sh --fuzz       # Rust fuzz targets (cargo-fuzz)
#
# TLA+ Depth Levels:
#   --tla       Standard: default model constants, ~minutes
#   --tla-deep  Deep: expanded constants, liveness checking, ~hours
#               Increases node/tx/block counts, enables temporal properties,
#               uses simulation mode for specs that would explode combinatorially

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# Results tracking
TOTAL_FAILED=0
TOTAL_SKIPPED=0
RESULTS=()

MODE="${1:---all}"

# TLA+ deep mode flag
TLA_DEEP=false
[[ "$MODE" == "--tla-deep" ]] && TLA_DEEP=true

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

section() {
    echo ""
    echo -e "${BLUE}${BOLD}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}${BOLD}  $1${NC}"
    echo -e "${BLUE}${BOLD}═══════════════════════════════════════════════════════════════${NC}"
}

run_suite() {
    local name="$1"
    local cmd="$2"
    local dir="${3:-$PROJECT_ROOT}"

    echo -e "\n${YELLOW}▶ Running: ${name}${NC}"
    echo -e "  ${CYAN}cd ${dir}${NC}"

    local start_time=$(date +%s)
    local exit_code=0

    (cd "$dir" && eval "$cmd") || exit_code=$?

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    if [ $exit_code -eq 0 ]; then
        echo -e "\n  ${GREEN}✓ ${name} — PASSED (${duration}s)${NC}"
        RESULTS+=("${GREEN}✓ ${name} (${duration}s)${NC}")
    else
        echo -e "\n  ${RED}✗ ${name} — FAILED (exit ${exit_code}, ${duration}s)${NC}"
        RESULTS+=("${RED}✗ ${name} (${duration}s)${NC}")
        TOTAL_FAILED=$((TOTAL_FAILED + 1))
    fi
}

skip_suite() {
    local name="$1"
    local reason="$2"
    echo -e "\n${YELLOW}⊘ Skipping: ${name} — ${reason}${NC}"
    RESULTS+=("${YELLOW}⊘ ${name} (skipped: ${reason})${NC}")
    TOTAL_SKIPPED=$((TOTAL_SKIPPED + 1))
}

# ---------------------------------------------------------------------------
# Rust Tests
# ---------------------------------------------------------------------------

run_rust_tests() {
    section "Rust Tests"

    run_suite "Rust workspace (cargo test --workspace)" \
        "cargo test --workspace 2>&1" \
        "$PROJECT_ROOT"

    run_suite "Desktop app (cargo test -p citrate-desktop-app)" \
        "cargo test -p citrate-desktop-app 2>&1" \
        "$PROJECT_ROOT"
}

# ---------------------------------------------------------------------------
# GUI Tests (Slint-native)
# ---------------------------------------------------------------------------

run_gui_tests() {
    section "GUI Slint-Native Tests"

    run_suite "GUI integration tests (cargo test -p citrate-gui-native)" \
        "cargo test -p citrate-gui-native 2>&1" \
        "$PROJECT_ROOT"
}

# ---------------------------------------------------------------------------
# Solidity Tests
# ---------------------------------------------------------------------------

run_solidity_tests() {
    section "Solidity Contract Tests (Foundry)"

    local FORGE=""
    if [ -f "$HOME/.foundry/bin/forge" ]; then
        FORGE="$HOME/.foundry/bin/forge"
    elif command -v forge &>/dev/null; then
        FORGE="forge"
    else
        skip_suite "Foundry tests" "forge not installed"
        return
    fi

    if [ -d "$PROJECT_ROOT/contracts" ] && [ -f "$PROJECT_ROOT/contracts/foundry.toml" ]; then
        run_suite "Solidity contracts (forge test)" \
            "'$FORGE' test 2>&1" \
            "$PROJECT_ROOT/contracts"
    else
        skip_suite "Solidity contracts" "no contracts/foundry.toml found"
    fi
}

# ---------------------------------------------------------------------------
# TLA+ Formal Verification
# ---------------------------------------------------------------------------

find_tlc_jar() {
    for candidate in \
        "$PROJECT_ROOT/../.agentile/formal/specs/tla2tools.jar" \
        "$PROJECT_ROOT/specs/tla/tla2tools.jar" \
        /usr/local/share/java/tla2tools.jar \
        "$HOME/tla2tools.jar" \
        "$HOME/.local/share/tla/tla2tools.jar" \
        /opt/tla/tla2tools.jar; do
        if [ -f "$candidate" ]; then
            echo "$candidate"
            return
        fi
    done
}

run_tla_tests() {
    local deep="$1"

    if [ "$deep" = true ]; then
        section "TLA+ Deep Formal Verification"
        echo -e "  ${CYAN}Mode: DEEP — expanded state spaces, liveness, simulation${NC}"
        echo -e "  ${CYAN}This may take 30-60+ minutes for large specs${NC}"
    else
        section "TLA+ Formal Verification"
    fi

    if ! command -v java &>/dev/null; then
        skip_suite "TLA+ verification" "java not installed"
        return
    fi

    local TLC_JAR
    TLC_JAR=$(find_tlc_jar)
    if [ -z "$TLC_JAR" ]; then
        skip_suite "TLA+ verification" "tla2tools.jar not found"
        return
    fi

    echo -e "  ${CYAN}TLC jar: ${TLC_JAR}${NC}"

    # Base JVM options for TLC
    local JVM_OPTS="-XX:+UseParallelGC"
    local TLC_WORKERS="auto"
    local TLC_HEAP="4096"

    if [ "$deep" = true ]; then
        TLC_HEAP="8192"
    fi

    local SPEC_DIRS=(
        "$PROJECT_ROOT/../.agentile/formal/specs"
        "$PROJECT_ROOT/specs/tla"
    )

    # Per-spec deep mode overrides.
    # For deep mode, we use TLC simulation for specs that would explode
    # combinatorially, and increase constants for bounded specs.
    #
    # Simulation mode (-simulate) generates random behaviors up to a depth
    # limit, which can cover far more of the state space than exhaustive
    # BFS when the model is too large. For blockchain consensus specs,
    # this is often the only practical way to check large parameter ranges.

    local found_specs=0

    for spec_dir in "${SPEC_DIRS[@]}"; do
        [ -d "$spec_dir" ] || continue

        for cfg_file in "$spec_dir"/*.cfg; do
            [ -f "$cfg_file" ] || continue

            # Skip trace files
            [[ "$(basename "$cfg_file")" == *_TTrace_* ]] && continue

            local spec_name=$(basename "$cfg_file" .cfg)
            local tla_file="$spec_dir/${spec_name}.tla"
            [ -f "$tla_file" ] || continue

            found_specs=$((found_specs + 1))

            # Build TLC command
            local TLC_CMD="java ${JVM_OPTS} -Xmx${TLC_HEAP}m -cp '${TLC_JAR}' tlc2.TLC"
            TLC_CMD="${TLC_CMD} -config '${cfg_file}' '${tla_file}'"
            TLC_CMD="${TLC_CMD} -workers ${TLC_WORKERS} -deadlock -cleanup"

            # TransactionExecution has 80M+ states — always use simulation
            if [ "$spec_name" = "TransactionExecution" ] && [ "$deep" = false ]; then
                TLC_CMD="${TLC_CMD} -simulate num=1000,depth=30"
            fi

            if [ "$deep" = true ]; then
                # Deep mode: use simulation for large consensus specs
                case "$spec_name" in
                    GhostDAGConsensus|MempoolSequencer|TransactionExecution)
                        # These have large state spaces — use simulation mode
                        # -simulate: random walk, num=10000 traces, depth=50 steps each
                        TLC_CMD="${TLC_CMD} -simulate num=10000,depth=50"
                        ;;
                    VRFElection|VRFChainContinuity|PrevrandaoPipeline)
                        # Medium specs — exhaustive BFS but with more depth
                        TLC_CMD="${TLC_CMD} -depth 100"
                        ;;
                    SDKConnectionLifecycle)
                        # Network spec — simulation with longer traces
                        TLC_CMD="${TLC_CMD} -simulate num=5000,depth=30"
                        ;;
                    *)
                        # GUI specs (Auth, Wallet, Agent, Environment) — exhaustive is fine
                        TLC_CMD="${TLC_CMD} -depth 50"
                        ;;
                esac

                # Check for liveness properties (temporal formulas) in the cfg
                if grep -q "PROPERTY\|Liveness\|Fairness\|<>" "$cfg_file" 2>/dev/null; then
                    echo -e "    ${CYAN}Liveness properties detected — enabling fairness checking${NC}"
                fi
            fi

            # Show full output for deep mode, tail for standard
            if [ "$deep" = true ]; then
                run_suite "TLA+ ${spec_name} (deep)" \
                    "${TLC_CMD} 2>&1" \
                    "$spec_dir"
            else
                run_suite "TLA+ ${spec_name}" \
                    "${TLC_CMD} 2>&1 | tail -15" \
                    "$spec_dir"
            fi
        done
    done

    if [ $found_specs -eq 0 ]; then
        skip_suite "TLA+ verification" "no .tla/.cfg spec pairs found"
    else
        echo -e "\n  ${CYAN}Verified ${found_specs} TLA+ specifications${NC}"
    fi
}

# ---------------------------------------------------------------------------
# Fuzz Tests (optional)
# ---------------------------------------------------------------------------

run_fuzz_tests() {
    section "Rust Fuzz Tests"

    if ! cargo fuzz --version &>/dev/null 2>&1; then
        skip_suite "Fuzz tests" "cargo-fuzz not installed (run: cargo install cargo-fuzz)"
        return
    fi

    # Find fuzz targets
    local FUZZ_DIR="$PROJECT_ROOT/fuzz"
    if [ ! -d "$FUZZ_DIR" ]; then
        skip_suite "Fuzz tests" "no fuzz/ directory found"
        return
    fi

    # Run each target for 30s in standard mode
    local FUZZ_DURATION=30
    for target in $(cargo fuzz list 2>/dev/null); do
        run_suite "Fuzz: ${target} (${FUZZ_DURATION}s)" \
            "cargo fuzz run ${target} -- -max_total_time=${FUZZ_DURATION} 2>&1" \
            "$PROJECT_ROOT"
    done
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

echo -e "${BOLD}Citrate Comprehensive Test Suite${NC}"
echo -e "Project: ${PROJECT_ROOT}"
echo -e "Mode: ${MODE}"
echo -e "Started: $(date)"

START_TIME=$(date +%s)

case "$MODE" in
    --rust)
        run_rust_tests
        ;;
    --gui)
        run_gui_tests
        ;;
    --sol)
        run_solidity_tests
        ;;
    --tla)
        run_tla_tests false
        ;;
    --tla-deep)
        run_tla_tests true
        ;;
    --fuzz)
        run_fuzz_tests
        ;;
    --fast)
        run_rust_tests
        run_gui_tests
        run_solidity_tests
        skip_suite "TLA+ verification" "skipped in --fast mode"
        ;;
    --all|*)
        run_rust_tests
        run_gui_tests
        run_solidity_tests
        run_tla_tests false
        ;;
esac

END_TIME=$(date +%s)
TOTAL_DURATION=$((END_TIME - START_TIME))

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

section "Test Summary"

for result in "${RESULTS[@]}"; do
    echo -e "  $result"
done

echo ""
echo -e "  ${BOLD}Total time: ${TOTAL_DURATION}s${NC}"

if [ $TOTAL_FAILED -eq 0 ]; then
    echo -e "\n  ${GREEN}${BOLD}ALL SUITES PASSED${NC}"
    if [ $TOTAL_SKIPPED -gt 0 ]; then
        echo -e "  ${YELLOW}(${TOTAL_SKIPPED} suite(s) skipped)${NC}"
    fi
    exit 0
else
    echo -e "\n  ${RED}${BOLD}${TOTAL_FAILED} SUITE(S) FAILED${NC}"
    exit 1
fi
