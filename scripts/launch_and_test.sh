#!/usr/bin/env bash
# scripts/launch_and_test.sh
# Builds the unified binary, launches a multi-node local testnet,
# starts the faucet, and runs SDK integration tests.
#
# Usage:
#   ./scripts/launch_and_test.sh [--nodes N] [--skip-build] [--skip-tests] [--keep-running]
#
# Options:
#   --nodes N       Number of nodes to launch (default: 3)
#   --skip-build    Skip cargo build step
#   --skip-tests    Skip SDK integration tests
#   --keep-running  Don't shut down nodes after tests finish (interactive mode)
#   --clean         Wipe data dirs before starting
#
# Ports allocated:
#   Node 0 (bootstrap): RPC 8545, P2P 30303
#   Node 1:             RPC 8546, P2P 30304
#   Node 2:             RPC 8547, P2P 30305
#   ...
#   Faucet:             HTTP 3001

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DATA_ROOT="$PROJECT_ROOT/.citrate-testnet"
LOG_DIR="$PROJECT_ROOT/run-logs"
BINARY="$PROJECT_ROOT/target/release/citrate"
FAUCET_BINARY="$PROJECT_ROOT/target/release/faucet"

# --- Defaults ---
NUM_NODES=3
SKIP_BUILD=false
SKIP_TESTS=false
KEEP_RUNNING=false
CLEAN=false
CHAIN_ID=1337
BASE_RPC_PORT=8545
BASE_P2P_PORT=30303
FAUCET_PORT=3001

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# --- Parse args ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --nodes)        NUM_NODES="$2"; shift 2 ;;
    --skip-build)   SKIP_BUILD=true; shift ;;
    --skip-tests)   SKIP_TESTS=true; shift ;;
    --keep-running) KEEP_RUNNING=true; shift ;;
    --clean)        CLEAN=true; shift ;;
    -h|--help)
      echo "Usage: $0 [--nodes N] [--skip-build] [--skip-tests] [--keep-running] [--clean]"
      exit 0
      ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# --- Cleanup handler ---
PIDS=()
cleanup() {
  echo ""
  echo -e "${YELLOW}Shutting down...${NC}"
  for pid in "${PIDS[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  # Wait for graceful shutdown
  sleep 2
  for pid in "${PIDS[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || true
    fi
  done
  echo -e "${GREEN}All processes stopped.${NC}"
}
trap cleanup EXIT

# --- Banner ---
echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║     Citrate Multi-Node Testnet Launcher          ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"
echo "  Nodes:      $NUM_NODES"
echo "  Chain ID:   $CHAIN_ID"
echo "  RPC Ports:  $BASE_RPC_PORT - $((BASE_RPC_PORT + NUM_NODES - 1))"
echo "  P2P Ports:  $BASE_P2P_PORT - $((BASE_P2P_PORT + NUM_NODES - 1))"
echo "  Faucet:     http://127.0.0.1:$FAUCET_PORT"
echo ""

# ============================================================
# Step 1: Build
# ============================================================
if [ "$SKIP_BUILD" = false ]; then
  echo -e "${BOLD}[1/6] Building binaries...${NC}"
  cd "$PROJECT_ROOT"
  cargo build --release -p citrate-node -p citrate-faucet 2>&1 | tail -5
  echo -e "${GREEN}  Build complete.${NC}"
else
  echo -e "${YELLOW}[1/6] Skipping build (--skip-build)${NC}"
fi

if [[ ! -x "$BINARY" ]]; then
  echo -e "${RED}Error: $BINARY not found. Run without --skip-build.${NC}"
  exit 1
fi

# ============================================================
# Step 2: Clean data directories
# ============================================================
if [ "$CLEAN" = true ]; then
  echo -e "${BOLD}[2/6] Cleaning data directories...${NC}"
  rm -rf "$DATA_ROOT"
  echo -e "${GREEN}  Cleaned $DATA_ROOT${NC}"
else
  echo -e "${YELLOW}[2/6] Keeping existing data (use --clean to wipe)${NC}"
fi

mkdir -p "$DATA_ROOT" "$LOG_DIR"

# ============================================================
# Step 3: Kill any existing processes on our ports
# ============================================================
echo -e "${BOLD}[3/6] Checking for port conflicts...${NC}"
CONFLICTS=false
for i in $(seq 0 $((NUM_NODES - 1))); do
  RPC_PORT=$((BASE_RPC_PORT + i))
  P2P_PORT=$((BASE_P2P_PORT + i))
  for PORT in $RPC_PORT $P2P_PORT; do
    PID=$(lsof -ti ":$PORT" 2>/dev/null || true)
    if [[ -n "$PID" ]]; then
      echo -e "  ${YELLOW}Port $PORT in use by PID $PID — killing${NC}"
      kill "$PID" 2>/dev/null || true
      CONFLICTS=true
    fi
  done
done

# Check faucet port
FAUCET_PID=$(lsof -ti ":$FAUCET_PORT" 2>/dev/null || true)
if [[ -n "$FAUCET_PID" ]]; then
  echo -e "  ${YELLOW}Port $FAUCET_PORT in use by PID $FAUCET_PID — killing${NC}"
  kill "$FAUCET_PID" 2>/dev/null || true
  CONFLICTS=true
fi

if [ "$CONFLICTS" = true ]; then
  sleep 2
fi
echo -e "${GREEN}  Ports clear.${NC}"

# ============================================================
# Step 4: Launch nodes
# ============================================================
echo -e "${BOLD}[4/6] Launching $NUM_NODES nodes...${NC}"

# --- Node 0: Bootstrap ---
NODE0_DATA="$DATA_ROOT/node-0"
NODE0_LOG="$LOG_DIR/node-0.log"
mkdir -p "$NODE0_DATA"

echo -e "  Starting ${CYAN}Node 0${NC} (bootstrap) — RPC :$BASE_RPC_PORT  P2P :$BASE_P2P_PORT"
"$BINARY" \
  --data-dir "$NODE0_DATA" \
  --p2p-addr "127.0.0.1:$BASE_P2P_PORT" \
  --rpc-addr "127.0.0.1:$BASE_RPC_PORT" \
  --bootstrap \
  --mine \
  --chain-id "$CHAIN_ID" \
  > "$NODE0_LOG" 2>&1 &
PIDS+=($!)
echo -e "  ${GREEN}Node 0 started (PID ${PIDS[-1]})${NC}"

# Give bootstrap node time to initialize genesis and start listening
echo -e "  Waiting for bootstrap node..."
for attempt in $(seq 1 30); do
  if curl -s -X POST http://127.0.0.1:$BASE_RPC_PORT \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
    | grep -q "result" 2>/dev/null; then
    echo -e "  ${GREEN}Bootstrap node ready (attempt $attempt)${NC}"
    break
  fi
  if [ "$attempt" -eq 30 ]; then
    echo -e "  ${RED}Bootstrap node failed to start. Check $NODE0_LOG${NC}"
    tail -20 "$NODE0_LOG"
    exit 1
  fi
  sleep 2
done

# --- Nodes 1..N-1: Workers ---
for i in $(seq 1 $((NUM_NODES - 1))); do
  NODE_DATA="$DATA_ROOT/node-$i"
  NODE_LOG="$LOG_DIR/node-$i.log"
  RPC_PORT=$((BASE_RPC_PORT + i))
  P2P_PORT=$((BASE_P2P_PORT + i))
  COINBASE=$(printf '0x%040x' "$i")
  mkdir -p "$NODE_DATA"

  echo -e "  Starting ${CYAN}Node $i${NC} — RPC :$RPC_PORT  P2P :$P2P_PORT"
  "$BINARY" \
    --data-dir "$NODE_DATA" \
    --p2p-addr "127.0.0.1:$P2P_PORT" \
    --rpc-addr "127.0.0.1:$RPC_PORT" \
    --bootstrap-nodes "127.0.0.1:$BASE_P2P_PORT" \
    --mine \
    --coinbase "$COINBASE" \
    --chain-id "$CHAIN_ID" \
    > "$NODE_LOG" 2>&1 &
  PIDS+=($!)
  echo -e "  ${GREEN}Node $i started (PID ${PIDS[-1]})${NC}"
done

# Wait for worker nodes to connect and start producing
echo -e "  Waiting for worker nodes to sync..."
sleep 5

for i in $(seq 1 $((NUM_NODES - 1))); do
  RPC_PORT=$((BASE_RPC_PORT + i))
  for attempt in $(seq 1 15); do
    if curl -s -X POST "http://127.0.0.1:$RPC_PORT" \
      -H "Content-Type: application/json" \
      -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
      | grep -q "result" 2>/dev/null; then
      echo -e "  ${GREEN}Node $i ready${NC}"
      break
    fi
    if [ "$attempt" -eq 15 ]; then
      echo -e "  ${YELLOW}Node $i slow to start — check $LOG_DIR/node-$i.log${NC}"
    fi
    sleep 2
  done
done

# ============================================================
# Step 5: Start faucet
# ============================================================
echo -e "${BOLD}[5/6] Starting faucet...${NC}"
if [[ -x "$FAUCET_BINARY" ]]; then
  FAUCET_LOG="$LOG_DIR/faucet.log"
  "$FAUCET_BINARY" > "$FAUCET_LOG" 2>&1 &
  PIDS+=($!)
  echo -e "  ${GREEN}Faucet started on http://127.0.0.1:$FAUCET_PORT (PID ${PIDS[-1]})${NC}"
else
  echo -e "  ${YELLOW}Faucet binary not found — skipping${NC}"
fi

# ============================================================
# Step 6: Network status check
# ============================================================
echo ""
echo -e "${BOLD}[6/6] Network Status${NC}"
echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

for i in $(seq 0 $((NUM_NODES - 1))); do
  RPC_PORT=$((BASE_RPC_PORT + i))

  # Get block number
  BLOCK_RESP=$(curl -s -X POST "http://127.0.0.1:$RPC_PORT" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null || echo '{}')
  BLOCK_HEX=$(echo "$BLOCK_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('result','0x0'))" 2>/dev/null || echo "0x0")
  BLOCK_NUM=$((16#${BLOCK_HEX#0x})) 2>/dev/null || BLOCK_NUM=0

  # Get chain ID
  CHAIN_RESP=$(curl -s -X POST "http://127.0.0.1:$RPC_PORT" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' 2>/dev/null || echo '{}')
  CHAIN_HEX=$(echo "$CHAIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('result','0x0'))" 2>/dev/null || echo "0x0")

  ROLE="worker"
  if [ "$i" -eq 0 ]; then ROLE="bootstrap"; fi

  echo -e "  Node $i ($ROLE): Block #$BLOCK_NUM  ChainID $CHAIN_HEX  RPC :$RPC_PORT"
done

echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Check genesis accounts
echo ""
echo -e "${BOLD}Genesis Account Balances:${NC}"
for ADDR in "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" "0xfcad0b19bb29d4674531d6f115237e16afce377c"; do
  BAL_RESP=$(curl -s -X POST "http://127.0.0.1:$BASE_RPC_PORT" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"$ADDR\",\"latest\"],\"id\":1}" 2>/dev/null || echo '{}')
  BAL_HEX=$(echo "$BAL_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('result','0x0'))" 2>/dev/null || echo "0x0")
  # Convert to ETH (approximate)
  BAL_WEI=$(python3 -c "print(int('$BAL_HEX', 16))" 2>/dev/null || echo "0")
  BAL_ETH=$(python3 -c "print(f'{int(\"$BAL_HEX\", 16) / 1e18:.2f}')" 2>/dev/null || echo "0")
  SHORT_ADDR="${ADDR:0:10}...${ADDR: -4}"
  echo -e "  $SHORT_ADDR: ${GREEN}$BAL_ETH ETH${NC}"
done

# Quick send test
echo ""
echo -e "${BOLD}Quick Transaction Test:${NC}"
TX_RESP=$(curl -s -X POST "http://127.0.0.1:$BASE_RPC_PORT" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"eth_sendTransaction",
    "params":[{
      "from":"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
      "to":"0x0000000000000000000000000000000000000001",
      "value":"0xDE0B6B3A7640000",
      "gas":"0x5208"
    }],
    "id":1
  }' 2>/dev/null || echo '{}')
TX_HASH=$(echo "$TX_RESP" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('result','') or r.get('error',{}).get('message','unknown error'))" 2>/dev/null || echo "failed")

if [[ "$TX_HASH" == 0x* ]]; then
  echo -e "  ${GREEN}Transaction sent: ${TX_HASH:0:18}...${NC}"

  # Wait for receipt
  sleep 4
  RECEIPT_RESP=$(curl -s -X POST "http://127.0.0.1:$BASE_RPC_PORT" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionReceipt\",\"params\":[\"$TX_HASH\"],\"id\":1}" 2>/dev/null || echo '{}')
  STATUS=$(echo "$RECEIPT_RESP" | python3 -c "
import sys,json
r=json.load(sys.stdin).get('result')
if r: print('confirmed' if r.get('status')=='0x1' else 'failed')
else: print('pending')
" 2>/dev/null || echo "unknown")
  echo -e "  Status: ${GREEN}$STATUS${NC}"
else
  echo -e "  ${YELLOW}Transaction: $TX_HASH${NC}"
fi

# ============================================================
# SDK Integration Tests
# ============================================================
if [ "$SKIP_TESTS" = false ]; then
  echo ""
  echo -e "${BOLD}Running SDK Integration Tests...${NC}"
  echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

  SDK_DIR="$PROJECT_ROOT/sdk/javascript"
  if [[ -d "$SDK_DIR" ]] && [[ -f "$SDK_DIR/package.json" ]]; then
    cd "$SDK_DIR"

    # Install deps if needed
    if [[ ! -d "node_modules" ]]; then
      echo -e "  Installing SDK dependencies..."
      npm install 2>&1 | tail -3
    fi

    # Build SDK
    echo -e "  Building SDK..."
    npm run build 2>&1 | tail -3 || true

    # Run integration tests
    echo ""
    echo -e "  ${BOLD}Running tests against http://127.0.0.1:$BASE_RPC_PORT ...${NC}"
    RPC_URL="http://127.0.0.1:$BASE_RPC_PORT" \
    CHAIN_ID="$CHAIN_ID" \
    npx jest tests/integration/ \
      --forceExit \
      --detectOpenHandles \
      --testTimeout=60000 \
      --verbose 2>&1 | tee "$LOG_DIR/sdk-tests.log" || true

    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  Test log: $LOG_DIR/sdk-tests.log"
  else
    echo -e "  ${YELLOW}SDK not found at $SDK_DIR — skipping tests${NC}"
  fi
else
  echo -e "${YELLOW}Skipping SDK tests (--skip-tests)${NC}"
fi

# ============================================================
# Interactive mode or exit
# ============================================================
echo ""
echo -e "${BOLD}${GREEN}Testnet is running!${NC}"
echo ""
echo -e "  RPC endpoints:"
for i in $(seq 0 $((NUM_NODES - 1))); do
  echo -e "    Node $i: http://127.0.0.1:$((BASE_RPC_PORT + i))"
done
echo -e "    Faucet: http://127.0.0.1:$FAUCET_PORT"
echo ""
echo -e "  Logs: $LOG_DIR/"
echo ""
echo -e "  Unified CLI commands:"
echo -e "    ${CYAN}$BINARY wallet new${NC}"
echo -e "    ${CYAN}$BINARY wallet list${NC}"
echo -e "    ${CYAN}$BINARY wallet balance 0${NC}"
echo -e "    ${CYAN}$BINARY account create${NC}"
echo -e "    ${CYAN}$BINARY contract deploy${NC}"
echo ""

if [ "$KEEP_RUNNING" = true ]; then
  echo -e "${YELLOW}Press Ctrl+C to stop all nodes.${NC}"
  # Wait forever (cleanup will run on Ctrl+C via trap)
  while true; do
    sleep 60

    # Periodic health check
    BLOCK_RESP=$(curl -s -X POST "http://127.0.0.1:$BASE_RPC_PORT" \
      -H "Content-Type: application/json" \
      -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null || echo '{}')
    BLOCK_HEX=$(echo "$BLOCK_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('result','0x0'))" 2>/dev/null || echo "0x0")
    BLOCK_NUM=$((16#${BLOCK_HEX#0x})) 2>/dev/null || BLOCK_NUM=0
    echo -e "  [$(date +%H:%M:%S)] Block #$BLOCK_NUM — $NUM_NODES nodes running"
  done
else
  echo -e "Nodes will shut down now. Use ${CYAN}--keep-running${NC} to keep them alive."
fi
