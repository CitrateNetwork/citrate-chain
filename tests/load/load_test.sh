#!/usr/bin/env bash
#
# Citrate Load Test — sends transactions at a configurable TPS against a devnet node.
#
# Usage:
#   bash load_test.sh [OPTIONS]
#
# Options:
#   --rpc-url URL     JSON-RPC endpoint          (default: http://127.0.0.1:8545)
#   --tps N           Target transactions/second  (default: 10)
#   --duration SECS   Test duration in seconds    (default: 60)
#   --from ADDR       Sender address (hex)        (default: 0x3333333333333333333333333333333333333333)
#   --value WEI       Value per transaction       (default: 0x1)
#   --gas LIMIT       Gas limit per transaction   (default: 0x5208 = 21000)
#   --quiet           Suppress per-tx output
#   -h, --help        Show this help message
#
# Requirements: bash 4+, curl, bc (optional, for floating-point stats)

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
RPC_URL="http://127.0.0.1:8545"
TPS=10
DURATION=60
FROM="0x3333333333333333333333333333333333333333"
VALUE="0x1"
GAS="0x5208"
QUIET=false

# ── Argument parsing ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc-url)   RPC_URL="$2";  shift 2 ;;
    --tps)       TPS="$2";      shift 2 ;;
    --duration)  DURATION="$2"; shift 2 ;;
    --from)      FROM="$2";     shift 2 ;;
    --value)     VALUE="$2";    shift 2 ;;
    --gas)       GAS="$2";      shift 2 ;;
    --quiet)     QUIET=true;    shift   ;;
    -h|--help)
      sed -n '2,/^$/{ s/^# \?//; p }' "$0"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────

# Generate a pseudo-random 20-byte hex address using /dev/urandom
rand_address() {
  printf '0x%s' "$(head -c 20 /dev/urandom | xxd -p | tr -d '\n')"
}

# Current epoch time in milliseconds (portable)
now_ms() {
  date +%s%3N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1000))'
}

# Fetch the current block number from the node
get_block_number() {
  local resp
  resp=$(curl -s -X POST "$RPC_URL" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null || echo '{}')
  # Extract hex result and convert to decimal
  local hex
  hex=$(echo "$resp" | sed -n 's/.*"result"[[:space:]]*:[[:space:]]*"\(0x[0-9a-fA-F]*\)".*/\1/p')
  if [[ -z "$hex" ]]; then
    echo "0"
  else
    printf '%d\n' "$hex"
  fi
}

# Send a single eth_sendTransaction and return HTTP status + response time in ms
send_tx() {
  local to="$1"
  local nonce="$2"
  local nonce_hex
  nonce_hex=$(printf '0x%x' "$nonce")

  local start_ms end_ms elapsed_ms http_code body
  start_ms=$(now_ms)

  # Use curl to POST; capture HTTP code and body separately
  body=$(curl -s -w '\n%{http_code}' -X POST "$RPC_URL" \
    -H "Content-Type: application/json" \
    -d "{
      \"jsonrpc\":\"2.0\",
      \"method\":\"eth_sendTransaction\",
      \"params\":[{
        \"from\":\"$FROM\",
        \"to\":\"$to\",
        \"value\":\"$VALUE\",
        \"gas\":\"$GAS\",
        \"nonce\":\"$nonce_hex\"
      }],
      \"id\":$nonce
    }" 2>/dev/null || echo -e '\n000')

  end_ms=$(now_ms)
  elapsed_ms=$(( end_ms - start_ms ))

  # Last line is HTTP status code
  http_code=$(echo "$body" | tail -n1)
  body=$(echo "$body" | sed '$d')

  # Determine success: HTTP 200 and result field present (no error field)
  local success=0
  if [[ "$http_code" == "200" ]] && echo "$body" | grep -q '"result"'; then
    success=1
  fi

  echo "${success}:${elapsed_ms}"
}

# ── Pre-flight checks ────────────────────────────────────────────────────────
echo "============================================================"
echo "  Citrate Load Test"
echo "============================================================"
echo ""
echo "Configuration:"
echo "  RPC URL      : $RPC_URL"
echo "  Target TPS   : $TPS"
echo "  Duration     : ${DURATION}s"
echo "  Sender       : $FROM"
echo "  Value/tx     : $VALUE"
echo "  Gas limit    : $GAS"
echo ""

# Verify the node is reachable
if ! curl -s -o /dev/null -w '' "$RPC_URL" -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":0}' 2>/dev/null; then
  echo "ERROR: cannot reach RPC at $RPC_URL" >&2
  exit 1
fi

echo "Node is reachable. Starting load test..."
echo ""

# ── Capture starting block height ────────────────────────────────────────────
BLOCK_START=$(get_block_number)
echo "Starting block height: $BLOCK_START"
echo ""

# ── Calculate pacing ─────────────────────────────────────────────────────────
# Interval between transactions in milliseconds
if [[ "$TPS" -le 0 ]]; then
  echo "ERROR: --tps must be > 0" >&2
  exit 1
fi

TOTAL_TX=$(( TPS * DURATION ))
INTERVAL_US=$(( 1000000 / TPS ))  # microseconds between sends

echo "Plan: send $TOTAL_TX transactions over ${DURATION}s (~${TPS} tx/s)"
echo "------------------------------------------------------------"

# ── Main send loop ───────────────────────────────────────────────────────────
SENT=0
SUCCESS=0
FAILED=0
TOTAL_LATENCY_MS=0
NONCE=0

WALL_START_MS=$(now_ms)
DEADLINE_MS=$(( WALL_START_MS + DURATION * 1000 ))

while true; do
  CURRENT_MS=$(now_ms)
  if (( CURRENT_MS >= DEADLINE_MS )); then
    break
  fi

  TO_ADDR=$(rand_address)
  RESULT=$(send_tx "$TO_ADDR" "$NONCE")

  TX_SUCCESS="${RESULT%%:*}"
  TX_LATENCY="${RESULT##*:}"

  SENT=$(( SENT + 1 ))
  NONCE=$(( NONCE + 1 ))
  TOTAL_LATENCY_MS=$(( TOTAL_LATENCY_MS + TX_LATENCY ))

  if [[ "$TX_SUCCESS" == "1" ]]; then
    SUCCESS=$(( SUCCESS + 1 ))
    if [[ "$QUIET" == "false" ]]; then
      echo "  [OK]   tx #$SENT  to=$TO_ADDR  latency=${TX_LATENCY}ms"
    fi
  else
    FAILED=$(( FAILED + 1 ))
    if [[ "$QUIET" == "false" ]]; then
      echo "  [FAIL] tx #$SENT  to=$TO_ADDR  latency=${TX_LATENCY}ms"
    fi
  fi

  # Pace: sleep for the remainder of the interval
  ELAPSED_SINCE_START=$(( $(now_ms) - WALL_START_MS ))
  EXPECTED_SENT_BY_NOW=$(( (ELAPSED_SINCE_START * TPS) / 1000 ))
  if (( SENT > EXPECTED_SENT_BY_NOW )); then
    # We are ahead of schedule — sleep a bit
    SLEEP_US=$(( INTERVAL_US - (TX_LATENCY * 1000) ))
    if (( SLEEP_US > 0 )); then
      # Convert to seconds for sleep (bash sleep supports fractional seconds)
      SLEEP_SEC=$(awk "BEGIN { printf \"%.6f\", $SLEEP_US / 1000000 }")
      sleep "$SLEEP_SEC"
    fi
  fi
done

WALL_END_MS=$(now_ms)
WALL_ELAPSED_MS=$(( WALL_END_MS - WALL_START_MS ))

# ── Capture ending block height (wait a moment for any in-flight blocks) ────
sleep 2
BLOCK_END=$(get_block_number)

# ── Compute stats ────────────────────────────────────────────────────────────
if (( SENT > 0 )); then
  AVG_LATENCY_MS=$(( TOTAL_LATENCY_MS / SENT ))
else
  AVG_LATENCY_MS=0
fi

WALL_ELAPSED_SEC=$(awk "BEGIN { printf \"%.2f\", $WALL_ELAPSED_MS / 1000 }")
if (( WALL_ELAPSED_MS > 0 )); then
  ACTUAL_TPS=$(awk "BEGIN { printf \"%.2f\", ($SENT * 1000) / $WALL_ELAPSED_MS }")
else
  ACTUAL_TPS="0.00"
fi

BLOCKS_PRODUCED=$(( BLOCK_END - BLOCK_START ))

if (( SENT > 0 )); then
  SUCCESS_RATE=$(awk "BEGIN { printf \"%.1f\", ($SUCCESS * 100) / $SENT }")
else
  SUCCESS_RATE="0.0"
fi

# ── Print summary ────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  Load Test Results"
echo "============================================================"
echo ""
echo "  Duration (wall clock)  : ${WALL_ELAPSED_SEC}s"
echo "  Transactions sent      : $SENT"
echo "  Successful             : $SUCCESS"
echo "  Failed                 : $FAILED"
echo "  Success rate           : ${SUCCESS_RATE}%"
echo ""
echo "  Target TPS             : $TPS"
echo "  Actual TPS             : $ACTUAL_TPS"
echo "  Avg response time      : ${AVG_LATENCY_MS}ms"
echo ""
echo "  Block height (start)   : $BLOCK_START"
echo "  Block height (end)     : $BLOCK_END"
echo "  Blocks produced        : $BLOCKS_PRODUCED"
if (( BLOCKS_PRODUCED > 0 )); then
  TX_PER_BLOCK=$(awk "BEGIN { printf \"%.1f\", $SENT / $BLOCKS_PRODUCED }")
  echo "  Avg tx/block           : $TX_PER_BLOCK"
fi
echo ""
echo "============================================================"

# ── Exit code: non-zero if any failures ──────────────────────────────────────
if (( FAILED > 0 )); then
  exit 1
fi
exit 0
