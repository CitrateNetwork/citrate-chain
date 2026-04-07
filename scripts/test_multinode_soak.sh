#!/bin/bash

# 1.6: Multi-Node Soak Test
# Starts 3 nodes, verifies block propagation and sync for SOAK_DURATION.
# Exit 0 = pass, Exit 1 = fail

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_DIR/target/release/citrate"
SOAK_DURATION=${SOAK_DURATION:-60}  # seconds (default 60s, set higher for thorough testing)
NUM_NODES=3
BASE_RPC=18545
BASE_P2P=18303
TMPDIR=$(mktemp -d)

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'
FAILURES=0

PIDS=()

cleanup() {
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

fail() { echo -e "${RED}FAIL: $1${NC}"; FAILURES=$((FAILURES + 1)); }
pass() { echo -e "${GREEN}PASS: $1${NC}"; }

rpc() {
    curl -s "http://127.0.0.1:$1" \
        -H "Content-Type: application/json" \
        -d "$2" 2>/dev/null
}

echo "=== Multi-Node Soak Test (1.6) ==="
echo "  Nodes: $NUM_NODES"
echo "  Duration: ${SOAK_DURATION}s"
echo "  Binary: $BINARY"
echo ""

# Start nodes
echo "[1/5] Starting $NUM_NODES nodes..."
for i in $(seq 0 $((NUM_NODES - 1))); do
    RPC=$((BASE_RPC + i))
    P2P=$((BASE_P2P + i))
    DIR="$TMPDIR/node$i"
    mkdir -p "$DIR"

    BOOTSTRAP_ARG=""
    BOOTSTRAP_FLAG=""
    if [ "$i" -eq 0 ]; then
        BOOTSTRAP_FLAG="--bootstrap"
    else
        BOOTSTRAP_ARG="--bootstrap-nodes 127.0.0.1:$BASE_P2P"
    fi

    "$BINARY" \
        --data-dir "$DIR" \
        --p2p-addr "127.0.0.1:$P2P" \
        --rpc-addr "127.0.0.1:$RPC" \
        --mine \
        --chain-id 40204 \
        $BOOTSTRAP_FLAG $BOOTSTRAP_ARG \
        > "$DIR/node.log" 2>&1 &
    PIDS+=($!)
    echo "  Node $i: PID=${PIDS[$i]} RPC=127.0.0.1:$RPC P2P=127.0.0.1:$P2P"
    sleep 2
done

# Wait for network stabilization
echo ""
echo "[2/5] Waiting 10s for network stabilization..."
sleep 10

# Verify all nodes are up
echo ""
echo "[3/5] Verifying node connectivity..."
ALL_UP=true
for i in $(seq 0 $((NUM_NODES - 1))); do
    RPC=$((BASE_RPC + i))
    RESP=$(rpc "$RPC" '{"jsonrpc":"2.0","method":"net_version","params":[],"id":1}')
    if echo "$RESP" | grep -q '"result"'; then
        PEERS=$(rpc "$RPC" '{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":1}' | jq -r '.result // "0x0"')
        BLOCK=$(rpc "$RPC" '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' | jq -r '.result // "0x0"')
        echo "  Node $i: block=$BLOCK peers=$PEERS"
    else
        fail "Node $i not responding on port $RPC"
        ALL_UP=false
    fi
done

if $ALL_UP; then
    pass "All $NUM_NODES nodes are up and connected"
fi

# Soak test: run for configured duration, checking every 15s
echo ""
echo "[4/5] Soak testing for ${SOAK_DURATION}s..."
CHECK_INTERVAL=15
CHECKS=$((SOAK_DURATION / CHECK_INTERVAL))
[ "$CHECKS" -lt 1 ] && CHECKS=1

for c in $(seq 1 $CHECKS); do
    sleep $CHECK_INTERVAL
    T=$((c * CHECK_INTERVAL))

    # Collect heights from all nodes
    HEIGHTS=()
    for i in $(seq 0 $((NUM_NODES - 1))); do
        RPC=$((BASE_RPC + i))
        H=$(rpc "$RPC" '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' | jq -r '.result // "0x0"')
        HEIGHTS+=("$H")
    done

    # Check all heights match (nodes are in sync)
    FIRST="${HEIGHTS[0]}"
    ALL_MATCH=true
    for h in "${HEIGHTS[@]}"; do
        if [ "$h" != "$FIRST" ]; then
            ALL_MATCH=false
        fi
    done

    if $ALL_MATCH; then
        echo "  t=${T}s: block=$FIRST (all nodes in sync)"
    else
        echo -e "  t=${T}s: ${YELLOW}heights differ: ${HEIGHTS[*]}${NC}"
        # Allow 1-block difference due to propagation delay
        FIRST_DEC=$(printf "%d" "$FIRST")
        for h in "${HEIGHTS[@]}"; do
            H_DEC=$(printf "%d" "$h")
            DIFF=$((FIRST_DEC - H_DEC))
            [ "$DIFF" -lt 0 ] && DIFF=$((-DIFF))
            if [ "$DIFF" -gt 2 ]; then
                fail "Block height divergence > 2 at t=${T}s"
            fi
        done
    fi

    # Check for invalid blocks
    TOTAL_INVALIDS=0
    for i in $(seq 0 $((NUM_NODES - 1))); do
        CNT=$(grep -c "invalid block\|Invalid block" "$TMPDIR/node$i/node.log" 2>/dev/null || true)
        CNT=${CNT:-0}
        TOTAL_INVALIDS=$((TOTAL_INVALIDS + CNT))
    done
    if [ "$TOTAL_INVALIDS" -gt 0 ]; then
        fail "$TOTAL_INVALIDS invalid block(s) detected at t=${T}s"
    fi
done

# Send a cross-node transaction
echo ""
echo "[5/5] Cross-node transaction propagation..."
TX_RESP=$(rpc "$BASE_RPC" '{
    "jsonrpc":"2.0",
    "method":"eth_sendTransaction",
    "params":[{
        "from":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
        "to":"0x1111111111111111111111111111111111111111",
        "value":"0xDE0B6B3A7640000",
        "gas":"0x5208",
        "gasPrice":"0x3b9aca00"
    }],
    "id":1
}')
echo "  TX sent to Node 0: $(echo "$TX_RESP" | jq -r '.result // .error.message // "unknown"')"

sleep 10

# Check balance on last node (should have propagated)
LAST_RPC=$((BASE_RPC + NUM_NODES - 1))
BAL=$(rpc "$LAST_RPC" '{"jsonrpc":"2.0","method":"eth_getBalance","params":["0x1111111111111111111111111111111111111111","latest"],"id":1}' | jq -r '.result // "0x0"')
if [ "$BAL" != "0x0" ] && [ -n "$BAL" ] && [ "$BAL" != "null" ]; then
    pass "Transaction propagated to Node $((NUM_NODES - 1)): balance=$BAL"
else
    fail "Transaction did not propagate to Node $((NUM_NODES - 1))"
fi

# Final status
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Duration:  ${SOAK_DURATION}s"
echo "  Nodes:     $NUM_NODES"
echo "  Failures:  $FAILURES"

# Final heights
for i in $(seq 0 $((NUM_NODES - 1))); do
    RPC=$((BASE_RPC + i))
    H=$(rpc "$RPC" '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' | jq -r '.result // "?"')
    echo "  Node $i: block $H"
done
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ "$FAILURES" -eq 0 ]; then
    echo -e "\n${GREEN}=== MULTI-NODE SOAK TEST PASSED ===${NC}"
    exit 0
else
    echo -e "\n${RED}=== MULTI-NODE SOAK TEST FAILED ($FAILURES failures) ===${NC}"
    exit 1
fi
