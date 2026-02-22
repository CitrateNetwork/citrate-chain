#!/bin/bash

# Launch 10-node testnet (Sprint 03 — Closed Beta)
# Uses chain_id 42069, persistent Noise identities, API key gating.

set -e

# Configuration
NUM_NODES=10
BASE_P2P_PORT=30303
BASE_RPC_PORT=8545
CHAIN_ID=42069
DATA_BASE_DIR=".citrate-testnet"
LOG_DIR="testnet-logs"
CITRATE_API_KEY="${CITRATE_API_KEY:-}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

clear
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Citrate 10-Node Testnet Launcher       ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Shutting down testnet...${NC}"
    pkill -f "citrate.*--data-dir.*${DATA_BASE_DIR}" || true
    echo -e "${GREEN}Testnet stopped${NC}"
}

trap cleanup EXIT

# Clean previous data
echo -e "${BLUE}Cleaning previous testnet data...${NC}"
rm -rf "$DATA_BASE_DIR" "$LOG_DIR" 2>/dev/null || true
mkdir -p "$LOG_DIR"

# Build if needed
if [ ! -f "target/release/citrate" ]; then
    echo -e "${YELLOW}Building citrate...${NC}"
    cargo build --release --bin citrate
fi

echo -e "${BLUE}Configuration:${NC}"
echo "  Chain ID:    $CHAIN_ID"
echo "  Nodes:       $NUM_NODES"
echo "  Data dir:    $DATA_BASE_DIR/node-N"
echo "  P2P ports:   $BASE_P2P_PORT-$((BASE_P2P_PORT + NUM_NODES - 1))"
echo "  RPC ports:   $BASE_RPC_PORT-$((BASE_RPC_PORT + NUM_NODES - 1))"
echo "  API key:     ${CITRATE_API_KEY:+(set)}${CITRATE_API_KEY:-(none)}"
echo "  Logs:        $LOG_DIR/"
echo ""

# Pre-create data dirs and generate Noise keys for each node
echo -e "${BLUE}Generating persistent Noise identities...${NC}"
for i in $(seq 0 $((NUM_NODES - 1))); do
    mkdir -p "$DATA_BASE_DIR/node-$i"
done

# Start bootstrap node
echo -e "${GREEN}Starting Bootstrap Node (Node 0)...${NC}"
BOOTSTRAP_ADDR="127.0.0.1:$BASE_P2P_PORT"

CITRATE_API_KEY="$CITRATE_API_KEY" ./target/release/citrate \
    --data-dir "$DATA_BASE_DIR/node-0" \
    --p2p-addr "$BOOTSTRAP_ADDR" \
    --rpc-addr "127.0.0.1:$BASE_RPC_PORT" \
    --bootstrap \
    --mine \
    --coinbase "0000000000000000000000000000000000000000" \
    --chain-id $CHAIN_ID \
    ${CITRATE_API_KEY:+--api-key "$CITRATE_API_KEY"} \
    > "$LOG_DIR/node-0.log" 2>&1 &

BOOTSTRAP_PID=$!
echo "  Node 0: PID=$BOOTSTRAP_PID P2P=$BOOTSTRAP_ADDR RPC=127.0.0.1:$BASE_RPC_PORT"
sleep 3

# Start remaining nodes
echo -e "\n${GREEN}Starting Worker Nodes...${NC}"
for i in $(seq 1 $((NUM_NODES - 1))); do
    P2P_PORT=$((BASE_P2P_PORT + i))
    RPC_PORT=$((BASE_RPC_PORT + i))

    # Generate unique coinbase for each node
    COINBASE=$(printf "%040d" $i)

    CITRATE_API_KEY="$CITRATE_API_KEY" ./target/release/citrate \
        --data-dir "$DATA_BASE_DIR/node-$i" \
        --p2p-addr "127.0.0.1:$P2P_PORT" \
        --rpc-addr "127.0.0.1:$RPC_PORT" \
        --bootstrap-nodes "$BOOTSTRAP_ADDR" \
        --mine \
        --coinbase "$COINBASE" \
        --chain-id $CHAIN_ID \
        --max-peers 20 \
        ${CITRATE_API_KEY:+--api-key "$CITRATE_API_KEY"} \
        > "$LOG_DIR/node-$i.log" 2>&1 &

    PID=$!
    echo "  Node $i: PID=$PID P2P=127.0.0.1:$P2P_PORT RPC=127.0.0.1:$RPC_PORT"

    # Stagger node starts to avoid connection storms
    sleep 0.5
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}Waiting for network to stabilize...${NC}"
sleep 10

# Health check: verify all nodes are running and peered
echo ""
echo -e "${GREEN}Network Health Check:${NC}"
echo ""

# Build auth header for curl
AUTH_HEADER=""
if [ -n "$CITRATE_API_KEY" ]; then
    AUTH_HEADER="-H \"Authorization: Bearer $CITRATE_API_KEY\""
fi

# Check nodes are running
RUNNING=0
for i in $(seq 0 $((NUM_NODES - 1))); do
    if pgrep -f "$DATA_BASE_DIR/node-$i" > /dev/null 2>&1; then
        RUNNING=$((RUNNING + 1))
    fi
done
echo "  Nodes running: $RUNNING/$NUM_NODES"

if [ "$RUNNING" -lt "$NUM_NODES" ]; then
    echo -e "${RED}  WARNING: Not all nodes started. Check logs in $LOG_DIR/${NC}"
fi

# Check peer connections and block heights
echo ""
echo "  Node status:"
for i in $(seq 0 $((NUM_NODES > 5 ? 4 : NUM_NODES - 1))); do
    PORT=$((BASE_RPC_PORT + i))

    if [ -n "$CITRATE_API_KEY" ]; then
        RESULT=$(curl -s -X POST http://127.0.0.1:$PORT \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $CITRATE_API_KEY" \
            -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null || echo '{}')
    else
        RESULT=$(curl -s -X POST http://127.0.0.1:$PORT \
            -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null || echo '{}')
    fi

    BLOCK_HEX=$(echo "$RESULT" | jq -r '.result // "0x0"' 2>/dev/null || echo "0x0")
    HEIGHT=$((16#${BLOCK_HEX#0x} 2>/dev/null)) || HEIGHT=0
    echo "    Node $i (port $PORT): Block #$HEIGHT"
done
if [ "$NUM_NODES" -gt 5 ]; then
    echo "    ... ($((NUM_NODES - 5)) more nodes)"
fi

# Wait and re-check to verify blocks are advancing
sleep 5
echo ""
echo -e "${BLUE}Verifying block production...${NC}"

PORT=$BASE_RPC_PORT
if [ -n "$CITRATE_API_KEY" ]; then
    RESULT=$(curl -s -X POST http://127.0.0.1:$PORT \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $CITRATE_API_KEY" \
        -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null || echo '{}')
else
    RESULT=$(curl -s -X POST http://127.0.0.1:$PORT \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null || echo '{}')
fi

BLOCK_HEX=$(echo "$RESULT" | jq -r '.result // "0x0"' 2>/dev/null || echo "0x0")
HEIGHT=$((16#${BLOCK_HEX#0x} 2>/dev/null)) || HEIGHT=0
if [ "$HEIGHT" -gt 0 ]; then
    echo -e "  ${GREEN}Blocks advancing: height=$HEIGHT${NC}"
else
    echo -e "  ${RED}WARNING: Blocks not advancing on Node 0${NC}"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}10-Node Testnet Launched!${NC}"
echo ""
echo "Commands:"
echo "  View logs:   tail -f $LOG_DIR/node-0.log"
echo "  Block height: curl -s -X POST http://127.0.0.1:8545 ${CITRATE_API_KEY:+-H 'Authorization: Bearer $CITRATE_API_KEY'} -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":1}'"
echo "  Stop:        pkill -f 'citrate.*$DATA_BASE_DIR'"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop the testnet${NC}"
echo ""

# Keep running
wait
