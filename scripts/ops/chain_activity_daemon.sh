#!/usr/bin/env bash
# chain_activity_daemon.sh — keep chain 40204 busy with live Boeing activity.
#
# Runs SimulateActivity.s.sol repeatedly (one batch per "tick") so the demo
# chain looks like an active, multi-actor network: agent decisions, audit-bundle
# anchors, and FL tags accumulate continuously across blocks. Each tick is
# ~0.008 SALT, so the deployer's balance funds millions of ticks.
#
# Block time on 40204 is ~2s; a forge tick takes ~2-3s, so back-to-back ticks
# land a batch on roughly every block. Use TICK_SLEEP to throttle.
#
# Usage:
#   # source secrets first (DEPLOY_KEY), then:
#   scripts/ops/chain_activity_daemon.sh                 # run forever
#   MAX_TICKS=200 scripts/ops/chain_activity_daemon.sh   # stop after 200 ticks
#   SIM_BATCH=10 TICK_SLEEP=1 scripts/ops/chain_activity_daemon.sh
#
# Env:
#   DEPLOY_KEY   deployer/recorder private key (required)
#   RPC_URL      default https://rpc.citrate.ai
#   SIM_BATCH    decisions per tick (default 6)
#   TICK_SLEEP   seconds to sleep between ticks (default 0)
#   MAX_TICKS    stop after N ticks (default 0 = forever)
#   TICK_STATE   counter file (default contracts/addresses/.sim_tick)
set -euo pipefail

RPC_URL="${RPC_URL:-https://rpc.citrate.ai}"
SIM_BATCH="${SIM_BATCH:-6}"
TICK_SLEEP="${TICK_SLEEP:-0}"
MAX_TICKS="${MAX_TICKS:-0}"
: "${DEPLOY_KEY:?set DEPLOY_KEY (source .env.demo.local)}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACTS_DIR="$(cd "$SCRIPT_DIR/../../contracts" && pwd)"
cd "$CONTRACTS_DIR"
TICK_STATE="${TICK_STATE:-$CONTRACTS_DIR/addresses/.sim_tick}"

tick=0
[[ -f "$TICK_STATE" ]] && tick="$(cat "$TICK_STATE")"

trap 'echo; echo ">>> stopping at tick $tick (saved to $TICK_STATE)"; echo "$tick" > "$TICK_STATE"; exit 0' INT TERM

echo ">>> chain activity daemon — RPC $RPC_URL, batch $SIM_BATCH, starting at tick $tick"
count=0
while :; do
  tick=$((tick + 1)); count=$((count + 1))
  if SIM_TICK="$tick" SIM_BATCH="$SIM_BATCH" \
       forge script script/SimulateActivity.s.sol \
       --rpc-url "$RPC_URL" --private-key "$DEPLOY_KEY" --broadcast --slow >/dev/null 2>&1; then
    blk="$(cast block-number --rpc-url "$RPC_URL" 2>/dev/null || echo '?')"
    echo "  tick $tick ok  (block $blk, ~$((SIM_BATCH + 1)) txs)"
  else
    echo "  tick $tick FAILED (continuing)"
  fi
  echo "$tick" > "$TICK_STATE"
  [[ "$MAX_TICKS" -gt 0 && "$count" -ge "$MAX_TICKS" ]] && { echo ">>> reached MAX_TICKS=$MAX_TICKS"; break; }
  [[ "$TICK_SLEEP" != "0" ]] && sleep "$TICK_SLEEP"
done
