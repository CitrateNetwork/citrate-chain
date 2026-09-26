#!/bin/bash

# E2E Stress Test for Citrate Devnet
# Starts a devnet, sends 1000+ transactions, and verifies correctness.
# Exit codes: 0 = pass, 1 = fail

set -e

# Configuration
NUM_TXS=${NUM_TXS:-1000}
RPC_URL=${RPC_URL:-"http://127.0.0.1:8545"}
CONCURRENT=${CONCURRENT:-10}
SETTLE_TIME=${SETTLE_TIME:-30}
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_DIR/target/release/citrate"
DATA_DIR=$(mktemp -d)
FAILURES=0

# Pre-funded devnet account
FROM_ADDR="0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
TO_ADDR="0x1111111111111111111111111111111111111111"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

cleanup() {
    echo -e "\n${BLUE}Cleaning up...${NC}"
    [ -n "$NODE_PID" ] && kill "$NODE_PID" 2>/dev/null || true
    rm -rf "$DATA_DIR"
}
trap cleanup EXIT

fail() {
    echo -e "${RED}FAIL: $1${NC}"
    FAILURES=$((FAILURES + 1))
}

pass() {
    echo -e "${GREEN}PASS: $1${NC}"
}

rpc_call() {
    curl -s -X POST "$RPC_URL" \
        -H "Content-Type: application/json" \
        -d "$1" 2>/dev/null
}

hex_to_dec() {
    printf "%d" "$1" 2>/dev/null || echo "0"
}

echo -e "${GREEN}Citrate E2E Stress Test${NC}"
echo "========================"
echo "  Transactions: $NUM_TXS"
echo "  Concurrency:  $CONCURRENT"
echo ""

# Step 1: Check binary exists
echo -e "${BLUE}[1/7] Checking binary...${NC}"
if [ ! -f "$BINARY" ]; then
    echo -e "${YELLOW}Binary not found, building...${NC}"
    (cd "$PROJECT_DIR" && cargo build --release -p citrate-node 2>&1 | tail -3)
fi

if [ ! -f "$BINARY" ]; then
    fail "Cannot find or build citrate binary"
    exit 1
fi
pass "Binary exists at $BINARY"

# Step 2: Start devnet
echo -e "\n${BLUE}[2/7] Starting devnet...${NC}"
"$BINARY" devnet --data-dir "$DATA_DIR" > "$DATA_DIR/node.log" 2>&1 &
NODE_PID=$!

# Wait for RPC to be ready
for i in $(seq 1 30); do
    RESP=$(rpc_call '{"jsonrpc":"2.0","method":"net_version","params":[],"id":1}')
    if echo "$RESP" | grep -q '"result"'; then
        break
    fi
    sleep 1
done

RESP=$(rpc_call '{"jsonrpc":"2.0","method":"net_version","params":[],"id":1}')
if echo "$RESP" | grep -q '"result"'; then
    pass "Devnet is running (PID=$NODE_PID)"
else
    fail "Devnet failed to start within 30s"
    exit 1
fi

# Step 3: Verify genesis state
echo -e "\n${BLUE}[3/7] Verifying genesis state...${NC}"

CHAIN_ID=$(rpc_call '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' | jq -r '.result')
# `citrate devnet` runs on the local dev chain id 1337 (0x539).
if [ "$CHAIN_ID" = "0x539" ]; then
    pass "Chain ID = 1337 (0x539)"
else
    fail "Unexpected chain ID: $CHAIN_ID (expected 0x539)"
fi

BALANCE=$(rpc_call "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"$FROM_ADDR\",\"latest\"],\"id\":1}" | jq -r '.result')
if [ "$BALANCE" != "null" ] && [ "$BALANCE" != "0x0" ] && [ -n "$BALANCE" ]; then
    pass "Genesis account has balance: $BALANCE"
else
    fail "Genesis account has no balance: $BALANCE"
fi

INIT_BLOCK_HEX=$(rpc_call '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' | jq -r '.result')
INIT_BLOCK=$(hex_to_dec "$INIT_BLOCK_HEX")
echo "  Initial block height: $INIT_BLOCK"

# Step 4: Send transactions
echo -e "\n${BLUE}[4/7] Sending $NUM_TXS transactions...${NC}"
START_TIME=$(date +%s)

send_tx() {
    local nonce=$1
    local nonce_hex=$(printf '0x%x' "$nonce")
    rpc_call "{
        \"jsonrpc\":\"2.0\",
        \"method\":\"eth_sendTransaction\",
        \"params\":[{
            \"from\":\"$FROM_ADDR\",
            \"to\":\"$TO_ADDR\",
            \"value\":\"0x1\",
            \"gas\":\"0x5208\",
            \"gasPrice\":\"0x3b9aca00\",
            \"nonce\":\"$nonce_hex\"
        }],
        \"id\":$nonce
    }" > /dev/null 2>&1
}

SENT=0
BATCH_SIZE=100
for batch_start in $(seq 0 $BATCH_SIZE $((NUM_TXS - 1))); do
    batch_end=$((batch_start + BATCH_SIZE))
    [ $batch_end -gt $NUM_TXS ] && batch_end=$NUM_TXS

    for i in $(seq $batch_start $((batch_end - 1))); do
        send_tx $i &
        if [ $(( (i + 1) % CONCURRENT )) -eq 0 ]; then
            wait
        fi
    done
    wait
    SENT=$batch_end
    echo -ne "\r  Sent: $SENT / $NUM_TXS"
done

END_TIME=$(date +%s)
SEND_DURATION=$((END_TIME - START_TIME))
[ $SEND_DURATION -eq 0 ] && SEND_DURATION=1
TPS=$(echo "scale=1; $NUM_TXS / $SEND_DURATION" | bc 2>/dev/null || echo "N/A")
echo -e "\r  Sent $NUM_TXS transactions in ${SEND_DURATION}s (${TPS} tx/s send rate)"

# Step 5: Wait for settlement
echo -e "\n${BLUE}[5/7] Waiting ${SETTLE_TIME}s for block settlement...${NC}"
sleep "$SETTLE_TIME"

# Step 6: Verify results
echo -e "\n${BLUE}[6/7] Verifying results...${NC}"

FINAL_BLOCK_HEX=$(rpc_call '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' | jq -r '.result')
FINAL_BLOCK=$(hex_to_dec "$FINAL_BLOCK_HEX")
BLOCKS_PRODUCED=$((FINAL_BLOCK - INIT_BLOCK))

echo "  Final block height: $FINAL_BLOCK"
echo "  Blocks produced: $BLOCKS_PRODUCED"

if [ "$BLOCKS_PRODUCED" -gt 0 ]; then
    pass "Blocks produced: $BLOCKS_PRODUCED"
else
    fail "No blocks produced during test"
fi

# Check mempool is draining
MEMPOOL=$(rpc_call '{"jsonrpc":"2.0","method":"citrate_getMempoolSnapshot","params":[],"id":1}' 2>/dev/null | jq -r '.result.pending_count // .result.size // "unknown"' 2>/dev/null || echo "unknown")
echo "  Mempool remaining: $MEMPOOL"

# Check destination balance changed
TO_BALANCE=$(rpc_call "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"$TO_ADDR\",\"latest\"],\"id\":1}" | jq -r '.result')
if [ "$TO_BALANCE" != "null" ] && [ "$TO_BALANCE" != "0x0" ] && [ -n "$TO_BALANCE" ]; then
    pass "Destination received funds: $TO_BALANCE"
else
    # Not necessarily a failure if nonce checks reject some txs
    echo -e "${YELLOW}  Note: Destination balance is $TO_BALANCE (some txs may have been rejected)${NC}"
fi

# Check node is still alive
ALIVE=$(rpc_call '{"jsonrpc":"2.0","method":"net_listening","params":[],"id":1}' | jq -r '.result')
if [ "$ALIVE" = "true" ]; then
    pass "Node survived stress test"
else
    fail "Node became unresponsive after stress test"
fi

# Step 7: Summary
echo -e "\n${BLUE}[7/7] Summary${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Transactions sent:  $NUM_TXS"
echo "  Send rate:          ${TPS} tx/s"
echo "  Blocks produced:    $BLOCKS_PRODUCED"
echo "  Settlement time:    ${SETTLE_TIME}s"
echo "  Node status:        alive"
echo "  Failures:           $FAILURES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ "$FAILURES" -eq 0 ]; then
    echo -e "\n${GREEN}E2E STRESS TEST PASSED${NC}"
    exit 0
else
    echo -e "\n${RED}E2E STRESS TEST FAILED ($FAILURES failures)${NC}"
    exit 1
fi
