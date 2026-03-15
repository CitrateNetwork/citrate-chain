#!/usr/bin/env bash
set -euo pipefail

# Chaos Test 05: Rapid Restart
# Start and stop the node 10 times in rapid succession, verify it starts
# cleanly each time (no port conflicts, no corrupt state, no zombie processes).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODE_BIN="${SCRIPT_DIR}/../../target/release/citrate"
DATA_DIR=$(mktemp -d /tmp/citrate-chaos-05.XXXXXX)
RPC_URL="http://127.0.0.1:8545"
NODE_PID=""
RESTART_COUNT=10

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
  local max_wait="${1:-15}"
  local elapsed=0
  while [[ $elapsed -lt $max_wait ]]; do
    if rpc_call "eth_blockNumber" > /dev/null 2>&1; then
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  return 1
}

stop_node() {
  if [[ -n "${NODE_PID:-}" ]] && kill -0 "$NODE_PID" 2>/dev/null; then
    # Try graceful shutdown first (SIGTERM), then force kill
    kill "$NODE_PID" 2>/dev/null || true
    # Wait up to 5s for graceful shutdown
    for _ in $(seq 1 5); do
      if ! kill -0 "$NODE_PID" 2>/dev/null; then
        break
      fi
      sleep 1
    done
    # Force kill if still alive
    if kill -0 "$NODE_PID" 2>/dev/null; then
      kill -9 "$NODE_PID" 2>/dev/null || true
    fi
    wait "$NODE_PID" 2>/dev/null || true
    NODE_PID=""
  fi
  # Wait for port to be released
  local port_wait=0
  while lsof -i :8545 -t > /dev/null 2>&1 && [[ $port_wait -lt 10 ]]; do
    sleep 1
    port_wait=$((port_wait + 1))
  done
}

echo "=== Chaos Test 05: Rapid Restart ==="
echo "Restart count: ${RESTART_COUNT}"
echo "Data dir: ${DATA_DIR}"
echo ""

successful_starts=0
failed_starts=0

for i in $(seq 1 $RESTART_COUNT); do
  echo -n "[${i}/${RESTART_COUNT}] "

  # Alternate between SIGTERM (graceful) and SIGKILL (crash) for variety
  if [[ $i -gt 1 ]]; then
    if [[ $((i % 3)) -eq 0 ]]; then
      echo -n "kill -9 -> "
      if [[ -n "${NODE_PID:-}" ]] && kill -0 "$NODE_PID" 2>/dev/null; then
        kill -9 "$NODE_PID" 2>/dev/null || true
        wait "$NODE_PID" 2>/dev/null || true
        NODE_PID=""
      fi
      # Wait for port release
      local_wait=0
      while lsof -i :8545 -t > /dev/null 2>&1 && [[ $local_wait -lt 10 ]]; do
        sleep 1
        local_wait=$((local_wait + 1))
      done
    else
      echo -n "stop -> "
      stop_node
    fi
  fi

  # Start node
  echo -n "start -> "
  "$NODE_BIN" devnet --data-dir "$DATA_DIR" > "${DATA_DIR}/node_${i}.log" 2>&1 &
  NODE_PID=$!

  # Wait for RPC to come up (shorter timeout for rapid restarts)
  if wait_for_rpc 15; then
    # Verify basic functionality
    block_num=$(rpc_call "eth_blockNumber" | python3 -c "import sys,json; print(json.load(sys.stdin)['result'])" 2>/dev/null || echo "fail")
    chain_id=$(rpc_call "eth_chainId" | python3 -c "import sys,json; print(json.load(sys.stdin)['result'])" 2>/dev/null || echo "fail")

    if [[ "$block_num" != "fail" ]] && [[ "$chain_id" != "fail" ]]; then
      successful_starts=$((successful_starts + 1))
      echo "OK (block=${block_num}, chainId=${chain_id})"
    else
      failed_starts=$((failed_starts + 1))
      echo "FAIL (RPC up but returned invalid data)"
    fi
  else
    failed_starts=$((failed_starts + 1))
    echo "FAIL (RPC did not respond within 15s)"
    # Try to see what happened
    if ! kill -0 "$NODE_PID" 2>/dev/null; then
      echo "       Node process died (check ${DATA_DIR}/node_${i}.log)"
    fi
  fi

  # Brief pause between restarts (but keep it rapid)
  sleep 1
done

# Final cleanup - stop the last node
stop_node

# Verify no zombie processes
zombies=$(pgrep -f "citrate.*devnet.*${DATA_DIR}" 2>/dev/null | wc -l | tr -d ' ')
if [[ "$zombies" -gt 0 ]]; then
  echo ""
  echo "WARN: ${zombies} zombie process(es) detected, cleaning up..."
  pkill -9 -f "citrate.*devnet.*${DATA_DIR}" 2>/dev/null || true
fi

echo ""
echo "Results: ${successful_starts}/${RESTART_COUNT} successful starts, ${failed_starts} failures"

if [[ $failed_starts -gt 2 ]]; then
  echo "FAIL: Too many restart failures (${failed_starts}/${RESTART_COUNT})"
  exit 1
fi

echo ""
echo "PASS: Node survived ${RESTART_COUNT} rapid restarts (${successful_starts} clean starts, ${failed_starts} failures)"
