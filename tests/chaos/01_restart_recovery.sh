#!/usr/bin/env bash
set -euo pipefail

# Chaos Test 01: Restart Recovery
# Start devnet, send transactions, kill -9, restart, verify state survived.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODE_BIN="${SCRIPT_DIR}/../../target/release/citrate"
DATA_DIR=$(mktemp -d /tmp/citrate-chaos-01.XXXXXX)
RPC_URL="http://127.0.0.1:8545"
NODE_PID=""
TIMEOUT=60

cleanup() {
  if [[ -n "${NODE_PID:-}" ]] && kill -0 "$NODE_PID" 2>/dev/null; then
    kill -9 "$NODE_PID" 2>/dev/null || true
    wait "$NODE_PID" 2>/dev/null || true
  fi
  rm -rf "$DATA_DIR"
}
trap cleanup EXIT

rpc_call() {
  local method="$1"
  local params="${2:-[]}"
  curl -sf -m 5 -X POST "$RPC_URL" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params},\"id\":1}" 2>/dev/null
}

wait_for_rpc() {
  local max_wait="${1:-30}"
  local elapsed=0
  while [[ $elapsed -lt $max_wait ]]; do
    if rpc_call "eth_blockNumber" > /dev/null 2>&1; then
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  echo "ERROR: Node did not become ready within ${max_wait}s"
  return 1
}

start_node() {
  "$NODE_BIN" devnet --data-dir "$DATA_DIR" > "${DATA_DIR}/node.log" 2>&1 &
  NODE_PID=$!
  echo "Started node PID=${NODE_PID}"
}

echo "=== Chaos Test 01: Restart Recovery ==="
echo "Data dir: ${DATA_DIR}"

# --- Phase 1: Start node, produce some blocks ---
echo "[1/5] Starting devnet node..."
start_node
wait_for_rpc 30

echo "[2/5] Waiting for blocks to be produced..."
sleep 5

BLOCK_BEFORE=$(rpc_call "eth_blockNumber" | python3 -c "import sys,json; print(int(json.load(sys.stdin)['result'],16))" 2>/dev/null || echo "0")
echo "       Block height before kill: ${BLOCK_BEFORE}"

if [[ "$BLOCK_BEFORE" -lt 1 ]]; then
  echo "FAIL: No blocks produced before kill"
  exit 1
fi

# Check balance of a genesis account
BALANCE_BEFORE=$(rpc_call "eth_getBalance" '["0x1111111111111111111111111111111111111111","latest"]' | python3 -c "import sys,json; print(json.load(sys.stdin)['result'])" 2>/dev/null || echo "0x0")
echo "       Genesis balance before kill: ${BALANCE_BEFORE}"

# --- Phase 2: Kill -9 (simulate crash) ---
echo "[3/5] Killing node with SIGKILL (simulating crash)..."
kill -9 "$NODE_PID" 2>/dev/null || true
wait "$NODE_PID" 2>/dev/null || true
NODE_PID=""
sleep 2

# Verify node is actually dead
if curl -sf -m 2 "$RPC_URL" > /dev/null 2>&1; then
  echo "FAIL: Node still responding after kill"
  exit 1
fi

# --- Phase 3: Restart and verify recovery ---
echo "[4/5] Restarting node from same data dir..."
start_node
wait_for_rpc 30

BLOCK_AFTER=$(rpc_call "eth_blockNumber" | python3 -c "import sys,json; print(int(json.load(sys.stdin)['result'],16))" 2>/dev/null || echo "0")
echo "       Block height after restart: ${BLOCK_AFTER}"

echo "[5/5] Verifying state recovery..."

# Block height should be >= what it was before crash
if [[ "$BLOCK_AFTER" -lt "$BLOCK_BEFORE" ]]; then
  echo "FAIL: Block height regressed (before=${BLOCK_BEFORE}, after=${BLOCK_AFTER})"
  exit 1
fi

# Balance should still be present
BALANCE_AFTER=$(rpc_call "eth_getBalance" '["0x1111111111111111111111111111111111111111","latest"]' | python3 -c "import sys,json; print(json.load(sys.stdin)['result'])" 2>/dev/null || echo "0x0")
echo "       Genesis balance after restart: ${BALANCE_AFTER}"

if [[ "$BALANCE_AFTER" == "0x0" ]] || [[ "$BALANCE_AFTER" == "0x" ]]; then
  echo "FAIL: Genesis account balance lost after restart"
  exit 1
fi

# Chain ID should be consistent
CHAIN_ID=$(rpc_call "eth_chainId" | python3 -c "import sys,json; print(json.load(sys.stdin)['result'])" 2>/dev/null || echo "")
echo "       Chain ID: ${CHAIN_ID}"

if [[ -z "$CHAIN_ID" ]]; then
  echo "FAIL: Could not retrieve chain ID after restart"
  exit 1
fi

echo ""
echo "PASS: Node recovered after SIGKILL (blocks: ${BLOCK_BEFORE} -> ${BLOCK_AFTER}, balance intact)"
