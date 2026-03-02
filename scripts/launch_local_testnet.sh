#!/usr/bin/env bash
# ============================================================
# Citrate v3 — Local Testnet Launcher
# Starts 3 bootstrap nodes as separate processes on localhost
# ============================================================
#
# Usage:
#   ./scripts/launch_local_testnet.sh            # Start (preserve data)
#   ./scripts/launch_local_testnet.sh --clean     # Fresh start (wipe data)
#   ./scripts/launch_local_testnet.sh --mine-all  # All 3 nodes mine
#   ./scripts/launch_local_testnet.sh --status    # Check node status
#
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_ROOT/target/release/citrate"
LOG_DIR="$PROJECT_ROOT/run-logs/testnet"
PID_DIR="$PROJECT_ROOT/.testnet-pids"

# Port assignments
P2P_PORTS=(30303 30304 30305)
RPC_PORTS=(8545 8555 8565)
METRICS_PORTS=(9090 9091 9092)

# Parse flags
CLEAN=false
MINE_ALL=false
STATUS_ONLY=false

for arg in "$@"; do
    case "$arg" in
        --clean) CLEAN=true ;;
        --mine-all) MINE_ALL=true ;;
        --status) STATUS_ONLY=true ;;
        --help|-h)
            echo "Usage: $0 [--clean] [--mine-all] [--status]"
            echo ""
            echo "  --clean     Wipe data directories and start fresh"
            echo "  --mine-all  Enable mining on all 3 nodes (default: only node 1)"
            echo "  --status    Check status of running nodes and exit"
            exit 0
            ;;
    esac
done

# ---- Status check ----
show_status() {
    echo -e "${CYAN}=====================================${NC}"
    echo -e "${CYAN}  Citrate Local Testnet Status${NC}"
    echo -e "${CYAN}=====================================${NC}"
    echo ""
    printf "%-8s %-8s %-8s %-10s %-12s\n" "Node" "PID" "P2P" "RPC" "Status"
    printf "%-8s %-8s %-8s %-10s %-12s\n" "----" "---" "---" "---" "------"

    for i in 1 2 3; do
        local pid_file="$PID_DIR/boot-${i}.pid"
        local pid="-"
        local status="${RED}STOPPED${NC}"

        if [ -f "$pid_file" ]; then
            pid=$(cat "$pid_file")
            if kill -0 "$pid" 2>/dev/null; then
                # Try RPC health check
                local rpc_port="${RPC_PORTS[$((i-1))]}"
                local block=$(curl -sf -m 2 -X POST "http://localhost:${rpc_port}" \
                    -H "Content-Type: application/json" \
                    -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null \
                    | python3 -c "import sys,json; print(int(json.load(sys.stdin).get('result','0x0'),16))" 2>/dev/null || echo "?")
                status="${GREEN}RUNNING (block: ${block})${NC}"
            else
                status="${RED}DEAD (stale PID)${NC}"
            fi
        fi

        printf "%-8s %-8s %-8s %-10s " "boot-${i}" "$pid" "${P2P_PORTS[$((i-1))]}" "${RPC_PORTS[$((i-1))]}"
        echo -e "$status"
    done
    echo ""
}

if [ "$STATUS_ONLY" = true ]; then
    show_status
    exit 0
fi

# ---- Pre-flight checks ----
echo -e "${CYAN}=====================================${NC}"
echo -e "${CYAN}  Citrate Local Testnet Launcher${NC}"
echo -e "${CYAN}=====================================${NC}"
echo ""

# Check binary
if [ ! -f "$BINARY" ]; then
    echo -e "${YELLOW}Release binary not found. Building...${NC}"
    cd "$PROJECT_ROOT"
    cargo build --release -p citrate-node
fi

# ---- Stop existing nodes ----
if [ -d "$PID_DIR" ]; then
    echo -e "${YELLOW}Stopping any existing testnet nodes...${NC}"
    for pid_file in "$PID_DIR"/boot-*.pid; do
        if [ -f "$pid_file" ]; then
            pid=$(cat "$pid_file")
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null || true
                echo "  Stopped PID $pid"
            fi
            rm -f "$pid_file"
        fi
    done
    sleep 1
fi

# ---- Clean data dirs if requested ----
if [ "$CLEAN" = true ]; then
    echo -e "${YELLOW}Cleaning data directories...${NC}"
    for i in 1 2 3; do
        rm -rf "$PROJECT_ROOT/.citrate-testnet-boot-${i}"
        echo "  Removed .citrate-testnet-boot-${i}"
    done
fi

# ---- Create directories ----
mkdir -p "$LOG_DIR" "$PID_DIR"

# ---- Launch nodes ----
echo ""
echo -e "${GREEN}Starting 3 bootstrap nodes...${NC}"
echo ""

for i in 1 2 3; do
    CONFIG="$PROJECT_ROOT/node/config/testnet-boot-${i}.toml"
    DATA_DIR="$PROJECT_ROOT/.citrate-testnet-boot-${i}"
    LOG_FILE="$LOG_DIR/boot-${i}.log"
    PID_FILE="$PID_DIR/boot-${i}.pid"
    METRICS_ADDR="127.0.0.1:${METRICS_PORTS[$((i-1))]}"

    # Build bootstrap-nodes list for the OTHER two nodes
    BOOT_ARGS=""
    for j in 1 2 3; do
        if [ "$j" != "$i" ]; then
            BOOT_ARGS="$BOOT_ARGS --bootstrap-nodes 127.0.0.1:${P2P_PORTS[$((j-1))]}"
        fi
    done

    # Determine if this node should mine
    MINE_FLAG=""
    if [ "$i" = "1" ] || [ "$MINE_ALL" = true ]; then
        MINE_FLAG="--mine"
    fi

    echo -e "  ${CYAN}Node ${i}:${NC} P2P=${P2P_PORTS[$((i-1))]} RPC=${RPC_PORTS[$((i-1))]} Metrics=${METRICS_PORTS[$((i-1))]} ${MINE_FLAG:+[MINING]}"

    # Launch
    CITRATE_METRICS_ADDR="$METRICS_ADDR" \
    CITRATE_REQUIRE_VALID_SIGNATURE=0 \
    RUST_LOG=info,citrate_network=debug \
    nohup "$BINARY" \
        --config "$CONFIG" \
        --data-dir "$DATA_DIR" \
        --max-peers 200 \
        $BOOT_ARGS \
        $MINE_FLAG \
        > "$LOG_FILE" 2>&1 &

    echo "$!" > "$PID_FILE"

    # Wait for genesis init before starting next node
    sleep 2

    # Verify process is alive
    if kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo -e "  ${GREEN}Started (PID $(cat "$PID_FILE"))${NC}"
    else
        echo -e "  ${RED}FAILED to start! Check: tail -50 $LOG_FILE${NC}"
    fi
    echo ""
done

# ---- Post-launch status ----
echo -e "${GREEN}=====================================${NC}"
echo -e "${GREEN}  Local testnet is running!${NC}"
echo -e "${GREEN}=====================================${NC}"
echo ""
echo "  Node 1 (mining): http://localhost:8545"
echo "  Node 2 (relay):  http://localhost:8555"
echo "  Node 3 (relay):  http://localhost:8565"
echo ""
echo -e "${CYAN}Useful commands:${NC}"
echo "  Status:       $0 --status"
echo "  Logs:         tail -f $LOG_DIR/boot-1.log"
echo "  Block height: curl -s localhost:8545 -X POST -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":1}'"
echo "  Peer count:   curl -s localhost:8545 -X POST -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"method\":\"net_peerCount\",\"params\":[],\"id\":1}'"
echo "  Stop:         ./scripts/stop_local_testnet.sh"
echo ""
