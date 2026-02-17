#!/bin/bash

# 1.7: Restart Integration Test
# Produces N blocks, stops, restarts with same data dir, verifies height continuity.
# Exit 0 = pass, Exit 1 = fail

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_DIR/target/release/citrate"
DATA_DIR=$(mktemp -d)
RPC_PORT=18545
P2P_PORT=18303

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

cleanup() {
    kill "$NODE_PID" 2>/dev/null || true
    rm -rf "$DATA_DIR"
}
trap cleanup EXIT

rpc() {
    curl -s http://127.0.0.1:$RPC_PORT \
        -H "Content-Type: application/json" \
        -d "$1" 2>/dev/null
}

get_height() {
    rpc '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' | jq -r '.result // "0x0"'
}

echo "=== Restart Continuity Test (1.7) ==="
echo "  Binary: $BINARY"
echo "  Data dir: $DATA_DIR"
echo ""

# Phase 1: Start node and produce blocks
echo "[Phase 1] Starting node..."
"$BINARY" --data-dir "$DATA_DIR" --mine --rpc-addr "127.0.0.1:$RPC_PORT" --p2p-addr "127.0.0.1:$P2P_PORT" --chain-id 1337 > "$DATA_DIR/phase1.log" 2>&1 &
NODE_PID=$!
sleep 8

HEIGHT_BEFORE=$(get_height)
echo "  Block height before stop: $HEIGHT_BEFORE"

if [ "$HEIGHT_BEFORE" = "0x0" ] || [ -z "$HEIGHT_BEFORE" ]; then
    echo -e "${RED}FAIL: Node did not produce blocks${NC}"
    exit 1
fi

# Phase 2: Stop node
echo "[Phase 2] Stopping node (PID=$NODE_PID)..."
kill "$NODE_PID" 2>/dev/null
wait "$NODE_PID" 2>/dev/null || true
sleep 2

# Verify stopped
if rpc '{"jsonrpc":"2.0","method":"net_version","params":[],"id":1}' | grep -q result 2>/dev/null; then
    echo -e "${RED}FAIL: Node still running after kill${NC}"
    exit 1
fi
echo "  Node stopped."

# Phase 3: Restart with same data dir
echo "[Phase 3] Restarting node with same data dir..."
"$BINARY" --data-dir "$DATA_DIR" --mine --rpc-addr "127.0.0.1:$RPC_PORT" --p2p-addr "127.0.0.1:$P2P_PORT" --chain-id 1337 > "$DATA_DIR/phase3.log" 2>&1 &
NODE_PID=$!
sleep 8

HEIGHT_AFTER=$(get_height)
echo "  Block height after restart: $HEIGHT_AFTER"

# Verify genesis was skipped
if grep -q "Genesis block found in storage, skipping initialization" "$DATA_DIR/phase3.log"; then
    echo -e "${GREEN}PASS: Genesis initialization skipped (existing data detected)${NC}"
else
    echo -e "${RED}FAIL: Genesis was re-initialized on restart${NC}"
    exit 1
fi

# Verify DAG was loaded
if grep -q "DAG loaded.*resuming from height" "$DATA_DIR/phase3.log"; then
    RESUME_MSG=$(grep "DAG loaded" "$DATA_DIR/phase3.log" | head -1)
    echo -e "${GREEN}PASS: $RESUME_MSG${NC}"
else
    echo -e "${RED}FAIL: DAG not loaded from storage on restart${NC}"
    exit 1
fi

# Verify height increased (not reset to 1)
BEFORE_DEC=$(printf "%d" "$HEIGHT_BEFORE")
AFTER_DEC=$(printf "%d" "$HEIGHT_AFTER")

if [ "$AFTER_DEC" -gt "$BEFORE_DEC" ]; then
    echo -e "${GREEN}PASS: Height continued ($BEFORE_DEC → $AFTER_DEC)${NC}"
else
    echo -e "${RED}FAIL: Height did not continue (before=$BEFORE_DEC after=$AFTER_DEC)${NC}"
    exit 1
fi

# Check for invalid blocks
INVALIDS=$(grep -c "invalid block\|Invalid block" "$DATA_DIR/phase3.log" 2>/dev/null || true)
INVALIDS=${INVALIDS:-0}
if [ "$INVALIDS" -eq 0 ] 2>/dev/null; then
    echo -e "${GREEN}PASS: Zero invalid blocks after restart${NC}"
else
    echo -e "${RED}FAIL: $INVALIDS invalid block(s) detected${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}=== RESTART CONTINUITY TEST PASSED ===${NC}"
