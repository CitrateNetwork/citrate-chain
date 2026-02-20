#!/usr/bin/env bash
# gui-smoke-test.sh — End-to-end smoke test for the Lattice Core GUI
#
# Workflow:
#   1. Build the Rust node (if not already built)
#   2. Start the devnet node
#   3. Wait for RPC readiness
#   4. Run Vitest unit/IPC contract tests
#   5. Run Playwright E2E tests (if configured)
#   6. Report results
#   7. Stop the devnet node
#
# Usage:
#   ./scripts/gui-smoke-test.sh              # Full suite
#   ./scripts/gui-smoke-test.sh --unit-only   # Skip E2E, unit tests only
#   ./scripts/gui-smoke-test.sh --skip-build  # Skip Rust build

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
GUI_DIR="$ROOT_DIR/gui/lattice-core"
NODE_BIN="$ROOT_DIR/target/release/citrate"
NODE_PID=""
RPC_URL="http://127.0.0.1:8545"
MAX_WAIT=60
UNIT_ONLY=false
SKIP_BUILD=false

# Parse arguments
for arg in "$@"; do
  case "$arg" in
    --unit-only)  UNIT_ONLY=true ;;
    --skip-build) SKIP_BUILD=true ;;
    --help|-h)
      echo "Usage: $0 [--unit-only] [--skip-build]"
      echo "  --unit-only   Run only Vitest unit tests (skip Playwright E2E)"
      echo "  --skip-build  Skip Rust node build step"
      exit 0
      ;;
  esac
done

# Color helpers
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
pass()  { echo -e "${GREEN}[PASS]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }

# Cleanup on exit
cleanup() {
  if [[ -n "$NODE_PID" ]]; then
    info "Stopping devnet node (PID $NODE_PID)..."
    kill "$NODE_PID" 2>/dev/null || true
    wait "$NODE_PID" 2>/dev/null || true
    info "Node stopped."
  fi
}
trap cleanup EXIT

# Track results
TOTAL=0
PASSED=0
FAILED=0

record_result() {
  local name="$1"
  local status="$2"
  TOTAL=$((TOTAL + 1))
  if [[ "$status" == "pass" ]]; then
    PASSED=$((PASSED + 1))
    pass "$name"
  else
    FAILED=$((FAILED + 1))
    fail "$name"
  fi
}

# ─────────────────────────────────────────────────
# Step 1: Build Rust node
# ─────────────────────────────────────────────────
if [[ "$SKIP_BUILD" == false ]]; then
  info "Building Rust node..."
  if (cd "$ROOT_DIR" && cargo build --release -p citrate-node 2>&1 | tail -5); then
    record_result "Rust node build" "pass"
  else
    record_result "Rust node build" "fail"
    fail "Cannot proceed without node binary."
    exit 1
  fi
else
  info "Skipping Rust build (--skip-build)"
fi

# Verify binary exists
if [[ ! -x "$NODE_BIN" ]]; then
  fail "Node binary not found at $NODE_BIN"
  fail "Run without --skip-build or build manually first."
  exit 1
fi

# ─────────────────────────────────────────────────
# Step 2: Start devnet node
# ─────────────────────────────────────────────────
info "Starting devnet node..."
"$NODE_BIN" devnet &>"$ROOT_DIR/run-logs/gui-smoke-devnet.log" &
NODE_PID=$!
info "Devnet started (PID $NODE_PID)"

# ─────────────────────────────────────────────────
# Step 3: Wait for RPC readiness
# ─────────────────────────────────────────────────
info "Waiting for RPC at $RPC_URL (max ${MAX_WAIT}s)..."
elapsed=0
rpc_ready=false

while [[ $elapsed -lt $MAX_WAIT ]]; do
  if curl -s -X POST "$RPC_URL" \
       -H "Content-Type: application/json" \
       -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
       | grep -q '"result"'; then
    rpc_ready=true
    break
  fi
  sleep 2
  elapsed=$((elapsed + 2))
done

if [[ "$rpc_ready" == true ]]; then
  record_result "RPC readiness" "pass"
else
  record_result "RPC readiness" "fail"
  warn "Devnet RPC did not respond within ${MAX_WAIT}s. Continuing with tests anyway..."
fi

# ─────────────────────────────────────────────────
# Step 4: Install GUI dependencies (if needed)
# ─────────────────────────────────────────────────
if [[ ! -d "$GUI_DIR/node_modules" ]]; then
  info "Installing GUI dependencies..."
  (cd "$GUI_DIR" && npm install --silent)
fi

# ─────────────────────────────────────────────────
# Step 5: Run Vitest unit + IPC contract tests
# ─────────────────────────────────────────────────
info "Running Vitest unit & IPC contract tests..."
if (cd "$GUI_DIR" && npx vitest run --reporter=dot 2>&1 | tail -5); then
  record_result "Vitest unit tests" "pass"
else
  record_result "Vitest unit tests" "fail"
fi

# ─────────────────────────────────────────────────
# Step 6: Run Playwright E2E tests (optional)
# ─────────────────────────────────────────────────
if [[ "$UNIT_ONLY" == false ]]; then
  if [[ -d "$GUI_DIR/e2e" ]] && ls "$GUI_DIR/e2e"/*.spec.ts &>/dev/null; then
    info "Running Playwright E2E tests..."
    if (cd "$GUI_DIR" && npx playwright test --reporter=line 2>&1 | tail -20); then
      record_result "Playwright E2E tests" "pass"
    else
      record_result "Playwright E2E tests" "fail"
    fi
  else
    warn "No Playwright E2E tests found in $GUI_DIR/e2e/ — skipping."
  fi
else
  info "Skipping E2E tests (--unit-only)"
fi

# ─────────────────────────────────────────────────
# Step 7: Summary
# ─────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  GUI Smoke Test Results"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Total:   $TOTAL"
echo -e "  Passed:  ${GREEN}$PASSED${NC}"
if [[ $FAILED -gt 0 ]]; then
  echo -e "  Failed:  ${RED}$FAILED${NC}"
else
  echo -e "  Failed:  0"
fi
echo ""

if [[ $FAILED -eq 0 ]]; then
  echo -e "  ${GREEN}ALL CHECKS PASSED${NC}"
  exit 0
else
  echo -e "  ${RED}SOME CHECKS FAILED${NC}"
  exit 1
fi
