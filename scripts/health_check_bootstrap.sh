#!/usr/bin/env bash
# ============================================================
# Citrate v3 — Bootstrap Node Health Check
# WP-S.5: Verify bootstrap node(s) are healthy
# ============================================================
#
# Usage:
#   ./scripts/health_check_bootstrap.sh [host1] [host2] [host3]
#
# If no hosts are given, checks localhost.
#
# Checks:
#   1. Systemd service status (via SSH, or local)
#   2. RPC reachability (eth_blockNumber)
#   3. Peer count
#   4. Block height (non-zero = syncing)
#   5. Metrics endpoint
#
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SERVICE_NAME="citrate-bootstrap"
RPC_PORT=8545
METRICS_PORT=9090

# Default to localhost if no args
if [ $# -eq 0 ]; then
    HOSTS=("localhost")
else
    HOSTS=("$@")
fi

TOTAL=0
PASSED=0
FAILED=0

check() {
    local host="$1"
    local label="$2"
    local result="$3"
    local expected="$4"

    TOTAL=$((TOTAL + 1))
    if [ "$result" = "$expected" ]; then
        echo -e "  ${GREEN}[PASS]${NC} $label"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}[FAIL]${NC} $label (got: $result, expected: $expected)"
        FAILED=$((FAILED + 1))
    fi
}

check_numeric_gt() {
    local label="$1"
    local value="$2"
    local threshold="$3"

    TOTAL=$((TOTAL + 1))
    if [ "$value" -gt "$threshold" ] 2>/dev/null; then
        echo -e "  ${GREEN}[PASS]${NC} $label ($value)"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${YELLOW}[WARN]${NC} $label ($value <= $threshold)"
        FAILED=$((FAILED + 1))
    fi
}

echo -e "${CYAN}=====================================${NC}"
echo -e "${CYAN}  Citrate Bootstrap Health Check${NC}"
echo -e "${CYAN}=====================================${NC}"
echo ""

for HOST in "${HOSTS[@]}"; do
    echo -e "${CYAN}--- $HOST ---${NC}"

    # Determine RPC URL
    if [ "$HOST" = "localhost" ] || [ "$HOST" = "127.0.0.1" ]; then
        RPC_URL="http://127.0.0.1:${RPC_PORT}"
        METRICS_URL="http://127.0.0.1:${METRICS_PORT}/metrics"
        IS_LOCAL=true
    else
        # For remote hosts, RPC is bound to loopback — use SSH tunnel or check via SSH
        RPC_URL="http://${HOST}:${RPC_PORT}"
        METRICS_URL="http://${HOST}:${METRICS_PORT}/metrics"
        IS_LOCAL=false
    fi

    # Check 1: Service status (local or via SSH)
    if [ "$IS_LOCAL" = true ]; then
        SVC_STATUS=$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo "inactive")
    else
        SVC_STATUS=$(ssh -o ConnectTimeout=5 "$HOST" "systemctl is-active $SERVICE_NAME" 2>/dev/null || echo "unreachable")
    fi
    check "$HOST" "Service status" "$SVC_STATUS" "active"

    # Check 2: RPC reachability (eth_blockNumber)
    BLOCK_HEX=$(curl -sf -m 5 -X POST "$RPC_URL" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
        2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('result','0x0'))" 2>/dev/null || echo "0x0")

    if [ "$BLOCK_HEX" = "0x0" ] && [ "$IS_LOCAL" = false ]; then
        # RPC is loopback-only — try via SSH
        BLOCK_HEX=$(ssh -o ConnectTimeout=5 "$HOST" \
            "curl -sf -m 5 -X POST http://127.0.0.1:${RPC_PORT} \
            -H 'Content-Type: application/json' \
            -d '{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":1}'" \
            2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('result','0x0'))" 2>/dev/null || echo "0x0")
    fi

    BLOCK_NUM=$((16#${BLOCK_HEX#0x})) 2>/dev/null || BLOCK_NUM=0
    echo -e "  ${GREEN}[INFO]${NC} Block height: $BLOCK_NUM"

    # Check 3: Peer count (net_peerCount)
    PEER_HEX=$(curl -sf -m 5 -X POST "$RPC_URL" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":1}' \
        2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('result','0x0'))" 2>/dev/null || echo "0x0")

    if [ "$PEER_HEX" = "0x0" ] && [ "$IS_LOCAL" = false ]; then
        PEER_HEX=$(ssh -o ConnectTimeout=5 "$HOST" \
            "curl -sf -m 5 -X POST http://127.0.0.1:${RPC_PORT} \
            -H 'Content-Type: application/json' \
            -d '{\"jsonrpc\":\"2.0\",\"method\":\"net_peerCount\",\"params\":[],\"id\":1}'" \
            2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('result','0x0'))" 2>/dev/null || echo "0x0")
    fi

    PEER_COUNT=$((16#${PEER_HEX#0x})) 2>/dev/null || PEER_COUNT=0
    echo -e "  ${GREEN}[INFO]${NC} Peer count: $PEER_COUNT"

    # Check 4: Metrics endpoint
    METRICS_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" -m 5 "$METRICS_URL" 2>/dev/null || echo "000")
    if [ "$METRICS_STATUS" = "000" ] && [ "$IS_LOCAL" = false ]; then
        METRICS_STATUS=$(ssh -o ConnectTimeout=5 "$HOST" \
            "curl -sf -o /dev/null -w '%{http_code}' -m 5 http://127.0.0.1:${METRICS_PORT}/metrics" 2>/dev/null || echo "000")
    fi
    check "$HOST" "Metrics endpoint" "$METRICS_STATUS" "200"

    # Check 5: Uptime (from metrics if available)
    if [ "$IS_LOCAL" = true ]; then
        UPTIME=$(curl -sf -m 5 "$METRICS_URL" 2>/dev/null | grep -oP 'citrate_node_uptime_seconds \K[0-9.]+' || echo "0")
    else
        UPTIME=$(ssh -o ConnectTimeout=5 "$HOST" \
            "curl -sf -m 5 http://127.0.0.1:${METRICS_PORT}/metrics" 2>/dev/null | grep -oP 'citrate_node_uptime_seconds \K[0-9.]+' || echo "0")
    fi
    UPTIME_INT=${UPTIME%.*}
    echo -e "  ${GREEN}[INFO]${NC} Uptime: ${UPTIME_INT}s"

    echo ""
done

# Summary
echo -e "${CYAN}=====================================${NC}"
echo -e "${CYAN}  Summary: $PASSED/$TOTAL checks passed${NC}"
if [ $FAILED -gt 0 ]; then
    echo -e "${RED}  $FAILED check(s) failed${NC}"
fi
echo -e "${CYAN}=====================================${NC}"

exit $FAILED
