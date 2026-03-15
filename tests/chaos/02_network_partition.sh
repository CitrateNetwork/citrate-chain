#!/usr/bin/env bash
set -euo pipefail

# Chaos Test 02: Network Partition
# Start 2 nodes, verify sync, simulate partition by killing peer connection,
# produce blocks independently, reconnect, verify reconvergence.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODE_BIN="${SCRIPT_DIR}/../../target/release/citrate"
DATA_DIR_1=$(mktemp -d /tmp/citrate-chaos-02-node1.XXXXXX)
DATA_DIR_2=$(mktemp -d /tmp/citrate-chaos-02-node2.XXXXXX)
RPC_URL_1="http://127.0.0.1:8545"
RPC_URL_2="http://127.0.0.1:8546"
NODE_PID_1=""
NODE_PID_2=""

cleanup() {
  for pid_var in NODE_PID_1 NODE_PID_2; do
    local pid="${!pid_var:-}"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  rm -rf "$DATA_DIR_1" "$DATA_DIR_2"
}
trap cleanup EXIT

rpc_call() {
  local url="$1"
  local method="$2"
  local params="${3:-[]}"
  curl -sf -m 5 -X POST "$url" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params},\"id\":1}" 2>/dev/null
}

get_block_height() {
  local url="$1"
  rpc_call "$url" "eth_blockNumber" | python3 -c "import sys,json; print(int(json.load(sys.stdin)['result'],16))" 2>/dev/null || echo "0"
}

wait_for_rpc() {
  local url="$1"
  local max_wait="${2:-30}"
  local elapsed=0
  while [[ $elapsed -lt $max_wait ]]; do
    if rpc_call "$url" "eth_blockNumber" > /dev/null 2>&1; then
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  echo "ERROR: Node at ${url} did not become ready within ${max_wait}s"
  return 1
}

echo "=== Chaos Test 02: Network Partition ==="

# --- Phase 1: Start two nodes ---
echo "[1/6] Starting node 1 (port 8545)..."
"$NODE_BIN" devnet --data-dir "$DATA_DIR_1" --rpc-port 8545 --p2p-port 30303 \
  > "${DATA_DIR_1}/node.log" 2>&1 &
NODE_PID_1=$!
wait_for_rpc "$RPC_URL_1" 30

echo "[2/6] Starting node 2 (port 8546) with node 1 as peer..."
"$NODE_BIN" devnet --data-dir "$DATA_DIR_2" --rpc-port 8546 --p2p-port 30304 \
  --peers "127.0.0.1:30303" \
  > "${DATA_DIR_2}/node.log" 2>&1 &
NODE_PID_2=$!
wait_for_rpc "$RPC_URL_2" 30

# --- Phase 2: Verify both nodes are producing blocks ---
echo "[3/6] Waiting for both nodes to produce blocks..."
sleep 8

HEIGHT_1=$(get_block_height "$RPC_URL_1")
HEIGHT_2=$(get_block_height "$RPC_URL_2")
echo "       Node 1 height: ${HEIGHT_1}, Node 2 height: ${HEIGHT_2}"

if [[ "$HEIGHT_1" -lt 1 ]]; then
  echo "FAIL: Node 1 did not produce blocks"
  exit 1
fi
if [[ "$HEIGHT_2" -lt 1 ]]; then
  echo "FAIL: Node 2 did not produce blocks"
  exit 1
fi

# --- Phase 3: Simulate partition by killing node 2, letting node 1 advance ---
echo "[4/6] Simulating network partition (stopping node 2)..."
kill "$NODE_PID_2" 2>/dev/null || true
wait "$NODE_PID_2" 2>/dev/null || true
NODE_PID_2=""

# Let node 1 produce blocks alone
sleep 5
HEIGHT_1_PARTITIONED=$(get_block_height "$RPC_URL_1")
echo "       Node 1 height during partition: ${HEIGHT_1_PARTITIONED}"

if [[ "$HEIGHT_1_PARTITIONED" -le "$HEIGHT_1" ]]; then
  echo "FAIL: Node 1 stopped producing during partition"
  exit 1
fi

# --- Phase 4: Reconnect (restart node 2) ---
echo "[5/6] Reconnecting (restarting node 2)..."
"$NODE_BIN" devnet --data-dir "$DATA_DIR_2" --rpc-port 8546 --p2p-port 30304 \
  --peers "127.0.0.1:30303" \
  > "${DATA_DIR_2}/node2.log" 2>&1 &
NODE_PID_2=$!
wait_for_rpc "$RPC_URL_2" 30

# --- Phase 5: Verify reconvergence ---
echo "[6/6] Waiting for reconvergence (up to 30s)..."
converged=false
for i in $(seq 1 30); do
  h1=$(get_block_height "$RPC_URL_1")
  h2=$(get_block_height "$RPC_URL_2")

  # Consider converged if heights are within 2 blocks of each other
  diff=$((h1 > h2 ? h1 - h2 : h2 - h1))
  if [[ $diff -le 2 ]] && [[ $h2 -ge "$HEIGHT_1_PARTITIONED" ]]; then
    converged=true
    echo "       Converged at ${i}s: Node1=${h1}, Node2=${h2} (diff=${diff})"
    break
  fi
  sleep 1
done

if $converged; then
  echo ""
  echo "PASS: Nodes reconverged after partition"
else
  h1=$(get_block_height "$RPC_URL_1")
  h2=$(get_block_height "$RPC_URL_2")
  echo ""
  echo "FAIL: Nodes did not reconverge within 30s (Node1=${h1}, Node2=${h2})"
  exit 1
fi
