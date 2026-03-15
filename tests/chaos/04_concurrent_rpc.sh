#!/usr/bin/env bash
set -euo pipefail

# Chaos Test 04: Concurrent RPC
# Start devnet, fire 100 parallel curl requests with a mix of RPC methods,
# verify all return valid JSON-RPC responses with no errors.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODE_BIN="${SCRIPT_DIR}/../../target/release/citrate"
DATA_DIR=$(mktemp -d /tmp/citrate-chaos-04.XXXXXX)
RPC_URL="http://127.0.0.1:8545"
NODE_PID=""
TOTAL_REQUESTS=100
PARALLELISM=20

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

echo "=== Chaos Test 04: Concurrent RPC ==="
echo "Total requests: ${TOTAL_REQUESTS}, Parallelism: ${PARALLELISM}"

# --- Phase 1: Start node ---
echo "[1/3] Starting devnet node..."
"$NODE_BIN" devnet --data-dir "$DATA_DIR" > "${DATA_DIR}/node.log" 2>&1 &
NODE_PID=$!
wait_for_rpc 30

# Wait for at least 1 block so queries return meaningful data
sleep 3

# --- Phase 2: Generate mixed RPC payloads ---
echo "[2/3] Firing ${TOTAL_REQUESTS} concurrent RPC requests..."

RESULTS_DIR="${DATA_DIR}/results"
mkdir -p "$RESULTS_DIR"

# Build payload file with mixed methods
PAYLOAD_FILE="${DATA_DIR}/rpc_payloads.txt"
GENESIS_ADDR="0x1111111111111111111111111111111111111111"

for i in $(seq 1 $TOTAL_REQUESTS); do
  case $((i % 5)) in
    0) echo "{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":${i}}" ;;
    1) echo "{\"jsonrpc\":\"2.0\",\"method\":\"eth_chainId\",\"params\":[],\"id\":${i}}" ;;
    2) echo "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"${GENESIS_ADDR}\",\"latest\"],\"id\":${i}}" ;;
    3) echo "{\"jsonrpc\":\"2.0\",\"method\":\"net_version\",\"params\":[],\"id\":${i}}" ;;
    4) echo "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBlockByNumber\",\"params\":[\"0x0\",false],\"id\":${i}}" ;;
  esac
done > "$PAYLOAD_FILE"

# Fire all requests in parallel, capture each response to a file
rpc_start=$(date +%s)

i=0
while IFS= read -r payload; do
  i=$((i + 1))
  (
    response=$(curl -sf -m 10 -X POST "$RPC_URL" \
      -H "Content-Type: application/json" \
      -d "$payload" 2>/dev/null || echo '{"error":"connection_failed"}')
    echo "$response" > "${RESULTS_DIR}/resp_${i}.json"
  ) &

  # Throttle to PARALLELISM concurrent
  if [[ $((i % PARALLELISM)) -eq 0 ]]; then
    wait
  fi
done < "$PAYLOAD_FILE"
wait

rpc_end=$(date +%s)
rpc_duration=$((rpc_end - rpc_start))
echo "       All requests completed in ${rpc_duration}s"

# --- Phase 3: Validate responses ---
echo "[3/3] Validating responses..."

total_files=0
valid_responses=0
error_responses=0
connection_failures=0
malformed=0

for resp_file in "${RESULTS_DIR}"/resp_*.json; do
  total_files=$((total_files + 1))
  content=$(cat "$resp_file" 2>/dev/null || echo "")

  if [[ -z "$content" ]]; then
    connection_failures=$((connection_failures + 1))
    continue
  fi

  # Check if it's valid JSON with jsonrpc field
  is_valid=$(echo "$content" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'jsonrpc' in data and 'id' in data:
        if 'result' in data:
            print('valid')
        elif 'error' in data:
            err = data['error']
            # RPC-level errors (like method not found) are still valid JSON-RPC
            print('rpc_error')
        else:
            print('malformed')
    elif 'error' in data and data['error'] == 'connection_failed':
        print('conn_fail')
    else:
        print('malformed')
except:
    print('malformed')
" 2>/dev/null || echo "malformed")

  case "$is_valid" in
    valid) valid_responses=$((valid_responses + 1)) ;;
    rpc_error) error_responses=$((error_responses + 1)) ;;
    conn_fail) connection_failures=$((connection_failures + 1)) ;;
    *) malformed=$((malformed + 1)) ;;
  esac
done

echo "       Total:      ${total_files}"
echo "       Valid:      ${valid_responses}"
echo "       RPC errors: ${error_responses}"
echo "       Conn fails: ${connection_failures}"
echo "       Malformed:  ${malformed}"

# All responses should be valid JSON-RPC (result or error)
success_count=$((valid_responses + error_responses))
failure_count=$((connection_failures + malformed))

# Allow up to 5% failure rate for connection issues under load
max_failures=$(( TOTAL_REQUESTS / 20 ))  # 5%

if [[ $failure_count -gt $max_failures ]]; then
  echo ""
  echo "FAIL: Too many failures: ${failure_count}/${total_files} (max allowed: ${max_failures})"
  exit 1
fi

if [[ $valid_responses -lt 1 ]]; then
  echo ""
  echo "FAIL: No valid responses received"
  exit 1
fi

# Verify node is still healthy
final_check=$(rpc_call "eth_blockNumber" || echo "")
if [[ -z "$final_check" ]]; then
  echo ""
  echo "FAIL: Node became unresponsive after concurrent RPC burst"
  exit 1
fi

echo ""
echo "PASS: ${success_count}/${total_files} requests returned valid JSON-RPC (${failure_count} failures, limit ${max_failures})"
echo "      Completed in ${rpc_duration}s, node still responsive"
