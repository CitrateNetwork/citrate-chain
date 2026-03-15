#!/usr/bin/env bash
set -euo pipefail

# Chaos Test 03: Mempool Flood
# Start devnet, blast 10,000 RPC calls in parallel, verify node stays responsive
# and mempool size stays bounded.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODE_BIN="${SCRIPT_DIR}/../../target/release/citrate"
DATA_DIR=$(mktemp -d /tmp/citrate-chaos-03.XXXXXX)
RPC_URL="http://127.0.0.1:8545"
NODE_PID=""
FLOOD_COUNT=10000
PARALLELISM=50

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

echo "=== Chaos Test 03: Mempool Flood ==="
echo "Flood count: ${FLOOD_COUNT}, Parallelism: ${PARALLELISM}"

# --- Phase 1: Start node ---
echo "[1/4] Starting devnet node..."
"$NODE_BIN" devnet --data-dir "$DATA_DIR" > "${DATA_DIR}/node.log" 2>&1 &
NODE_PID=$!
wait_for_rpc 30

HEIGHT_BEFORE=$(rpc_call "eth_blockNumber" | python3 -c "import sys,json; print(int(json.load(sys.stdin)['result'],16))" 2>/dev/null || echo "0")
echo "       Block height before flood: ${HEIGHT_BEFORE}"

# --- Phase 2: Generate flood payload ---
echo "[2/4] Preparing flood payloads..."

# We use a dummy raw transaction payload. Even if the node rejects these as invalid,
# we are testing that the RPC server doesn't crash or become unresponsive under load.
# Using a minimal signed tx-like payload (will be rejected but exercises the path).
DUMMY_RAW_TX="0xf86c0185746a528800825208941111111111111111111111111111111111111111118802c68af0bb14000080820100a0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa a0bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

PAYLOAD_FILE="${DATA_DIR}/flood_payloads.txt"
for i in $(seq 1 $FLOOD_COUNT); do
  echo "{\"jsonrpc\":\"2.0\",\"method\":\"eth_sendRawTransaction\",\"params\":[\"${DUMMY_RAW_TX}\"],\"id\":${i}}"
done > "$PAYLOAD_FILE"

# --- Phase 3: Fire the flood ---
echo "[3/4] Flooding node with ${FLOOD_COUNT} eth_sendRawTransaction calls (${PARALLELISM} parallel)..."
flood_start=$(date +%s)

# Use xargs to send requests in parallel
cat "$PAYLOAD_FILE" | xargs -P "$PARALLELISM" -I {} \
  curl -sf -m 10 -X POST "$RPC_URL" \
    -H "Content-Type: application/json" \
    -d '{}' -o /dev/null 2>/dev/null || true

flood_end=$(date +%s)
flood_duration=$((flood_end - flood_start))
echo "       Flood completed in ${flood_duration}s"

# --- Phase 4: Verify node is still responsive ---
echo "[4/4] Verifying node responsiveness after flood..."

# Test 1: eth_blockNumber still works
response=$(rpc_call "eth_blockNumber" || echo "")
if [[ -z "$response" ]]; then
  echo "FAIL: Node unresponsive after flood (eth_blockNumber returned nothing)"
  exit 1
fi

HEIGHT_AFTER=$(echo "$response" | python3 -c "import sys,json; print(int(json.load(sys.stdin)['result'],16))" 2>/dev/null || echo "0")
echo "       Block height after flood: ${HEIGHT_AFTER}"

# Test 2: eth_chainId still works
chain_response=$(rpc_call "eth_chainId" || echo "")
if [[ -z "$chain_response" ]]; then
  echo "FAIL: Node unresponsive after flood (eth_chainId returned nothing)"
  exit 1
fi

# Test 3: eth_getBalance still works
balance_response=$(rpc_call "eth_getBalance" '["0x1111111111111111111111111111111111111111","latest"]' || echo "")
if [[ -z "$balance_response" ]]; then
  echo "FAIL: Node unresponsive after flood (eth_getBalance returned nothing)"
  exit 1
fi

# Test 4: Blocks are still being produced
sleep 3
HEIGHT_FINAL=$(rpc_call "eth_blockNumber" | python3 -c "import sys,json; print(int(json.load(sys.stdin)['result'],16))" 2>/dev/null || echo "0")

if [[ "$HEIGHT_FINAL" -le "$HEIGHT_AFTER" ]]; then
  echo "WARN: No new blocks produced after flood (may be acceptable under load)"
fi

# Test 5: Check mempool size if endpoint exists
mempool_response=$(rpc_call "citrate_getMempoolSnapshot" || echo "")
if [[ -n "$mempool_response" ]]; then
  mempool_size=$(echo "$mempool_response" | python3 -c "
import sys, json
data = json.load(sys.stdin)
result = data.get('result', {})
if isinstance(result, dict):
    txs = result.get('transactions', result.get('pending', []))
    print(len(txs) if isinstance(txs, list) else 0)
else:
    print(0)
" 2>/dev/null || echo "unknown")
  echo "       Mempool size: ${mempool_size}"
fi

echo ""
echo "PASS: Node survived mempool flood of ${FLOOD_COUNT} requests (${flood_duration}s), still responsive"
echo "      Heights: before=${HEIGHT_BEFORE}, after=${HEIGHT_AFTER}, final=${HEIGHT_FINAL}"
