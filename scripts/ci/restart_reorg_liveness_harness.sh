#!/usr/bin/env bash
# ============================================================================
# G9/G4 LOCAL RESTART-REORG-LIVENESS HARNESS  (SRP-S4 acceptance, local repro)
# ============================================================================
# The DO fleet reroll must NOT be the test loop for restart/reorg/cold-sync
# regressions (that is the "running in circles" this repo has paid for). This
# harness reproduces the two human acceptance gates LOCALLY, over loopback,
# with several `citrate` instances — so a restart/reorg/cold-sync fix is proven
# here, test-first, BEFORE any fleet deploy.
#
#   G9  restart-proof : 1 miner + 2 followers; restart the MINER (no wipe) and
#                       a FOLLOWER mid-run; assert all tips re-converge in
#                       lockstep, state roots identical at a common height, and
#                       0 reorg-thrash (no repeated from-genesis rebuild loop).
#                       This is the gate the 2026-08-12 select_tip->genesis wedge
#                       and the follower-drain-stall would both fail.
#
#   G4  deep cold-sync: miner produces deep; a FRESH node (empty data-dir)
#                       cold-syncs genesis->head; assert it reaches the tip with
#                       0 state-root mismatches (no "state root mismatch" /
#                       "Rejected inconsistent" in its log).
#
# Usage:
#   scripts/ci/restart_reorg_liveness_harness.sh g9        # restart-proof only
#   scripts/ci/restart_reorg_liveness_harness.sh g4        # cold-sync only
#   scripts/ci/restart_reorg_liveness_harness.sh all       # both (default)
#
# Env knobs: BIN (binary path), BLOCKS_G9, BLOCKS_G4, SETTLE (convergence wait s).
#
# Exit: 0 all requested gates PASS · 1 a gate FAILED · 2 setup error.
#
# SCOPE NOTE (honest): this base harness exercises the fork-choice / drain /
# reorg / cold-sync paths WITHOUT §R' validator activation (activation left
# high), because a local ValidatorRegistry CREATE2 deploy + 32k-bond ceremony
# is a separate blocker (see scripts/ci/srp_s4_coldsync_harness.sh). Those paths
# are exactly where the select_tip->genesis + drain-stall + backwards-reorg bugs
# live. The DEEP epoch-crossing variant (§R' active across an S(E) boundary) is
# the next layer — wire the registry setup from srp_s4_coldsync_harness.sh and
# set CITRATE_VALIDATOR_ACTIVATION_HEIGHT low. Marked TODO(deep) below.
# ============================================================================
set -uo pipefail

CHAIN="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${BIN:-$CHAIN/target/release/citrate}"
SCRATCH="${SCRATCH:-$(mktemp -d -t g9g4-XXXXXX)}"
BLOCKS_G9="${BLOCKS_G9:-120}"    # restart PAST the 100-block reorg window (genesis
                                 # falls out of the retained ring here — exactly where
                                 # the backwards-reorg / select_tip->genesis clamp fails)
BLOCKS_G4="${BLOCKS_G4:-120}"    # produce this deep before the fresh cold-sync
SETTLE="${SETTLE:-45}"           # seconds allowed to re-converge / catch up
BASE_RPC=18900
BASE_P2P=30900
CHAIN_ID=40204
# Any valid funded address works as the local mining coinbase pre-activation
# (rewards sink; §R' validator gating only bites past the activation height,
# left high in this base harness). The canonical deployer is always funded.
COINBASE="${COINBASE:-0x4fAB35c8c5033c80b3a0452A873B81e6ED4ED732}"

# At-rest storage key: tests use a fixed non-secret key so nodes can open their
# encrypted store non-interactively (same convention as srp_s4_coldsync_harness).
export CITRATE_STORAGE_KEY="${CITRATE_STORAGE_KEY:-0000000000000000000000000000000000000000000000000000000000000001}"
export CITRATE_BLOCK_V2="${CITRATE_BLOCK_V2:-1}"

G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; N='\033[0m'
declare -a PIDS=()
FAILS=0

cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; rm -rf "$SCRATCH"; }
trap cleanup EXIT INT TERM

log()  { echo -e "  $*"; }
pass() { echo -e "${G}PASS${N}: $*"; }
fail() { echo -e "${R}FAIL${N}: $*"; FAILS=$((FAILS+1)); }
die()  { echo -e "${R}SETUP ERROR${N}: $*" >&2; exit 2; }

[ -x "$BIN" ] || die "binary not found/executable at $BIN — build it: cargo build --release --bin citrate"

rpc() { curl -s -m5 -X POST "http://127.0.0.1:$1" -H 'content-type: application/json' --data "$2" 2>/dev/null; }
# height of node at rpc port $1 (decimal; 0 if down)
hi()  { rpc "$1" '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' | grep -oE '"result":"0x[0-9a-f]+"' | grep -oE '0x[0-9a-f]+' | head -1 | (read h; echo $((${h:-0}))); }
# state root of node $1 at height $2 (hex string, or empty)
sr()  { rpc "$1" "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getBlockByNumber\",\"params\":[\"$(printf '0x%x' "$2")\",false]}" | grep -oE '"stateRoot":"0x[0-9a-f]+"' | grep -oE '0x[0-9a-f]+' | head -1; }
# block hash of node $1 at height $2
bh()  { rpc "$1" "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getBlockByNumber\",\"params\":[\"$(printf '0x%x' "$2")\",false]}" | grep -oE '"hash":"0x[0-9a-f]+"' | grep -oE '0x[0-9a-f]+' | head -1; }

# start_node <idx> <mine:0|1> <bootstrap_to_p2p_port|"">  -> sets NODE_RPC / NODE_PID globals
start_node() {
  local idx="$1" mine="$2" boot="$3"
  local rpcp=$((BASE_RPC + idx)) p2pp=$((BASE_P2P + idx)) dir="$SCRATCH/node$idx"
  mkdir -p "$dir"
  local args=( --data-dir "$dir" --p2p-addr "127.0.0.1:$p2pp" --rpc-addr "127.0.0.1:$rpcp" --chain-id "$CHAIN_ID" )
  [ "$mine" = 1 ] && args+=( --mine --coinbase "$COINBASE" )
  if [ -z "$boot" ]; then args+=( --bootstrap ); else args+=( --bootstrap-nodes "127.0.0.1:$boot" ); fi
  setsid nohup "$BIN" "${args[@]}" >"$dir/node.log" 2>&1 & disown
  local pid=$!
  PIDS+=( "$pid" )
  NODE_RPC=$rpcp; NODE_PID=$pid; NODE_P2P=$p2pp; NODE_DIR="$dir"
}

# wait until node at rpc $1 reaches height >= $2, up to $3 seconds
wait_height() {
  local rpcp="$1" target="$2" secs="${3:-$SETTLE}"
  for _ in $(seq 1 "$secs"); do [ "$(hi "$rpcp")" -ge "$target" ] && return 0; sleep 1; done
  return 1
}

# count reorg-thrash markers in a node log (the from-genesis rebuild loop)
thrash_count() { grep -cE "rebuilding state from genesis|beyond the in-memory reorg window|same-height-sibling wedge remediation" "$1" 2>/dev/null || echo 0; }
# count hard cold-sync failures in a node log
mismatch_count() { grep -cE "state root mismatch|Rejected inconsistent|REJECT block" "$1" 2>/dev/null || echo 0; }

# ---------------------------------------------------------------------------
gate_g9() {
  echo "== G9 restart-proof: 1 miner + 2 followers, restart miner + a follower =="
  start_node 0 1 "";           local M=$NODE_RPC;  local MP=$NODE_P2P; local MPID=$NODE_PID; local MDIR=$NODE_DIR
  start_node 1 0 "$MP";        local F1=$NODE_RPC;  local F1DIR=$NODE_DIR
  start_node 2 0 "$MP";        local F2=$NODE_RPC;  local F2DIR=$NODE_DIR
  log "miner rpc=$M  followers rpc=$F1,$F2"
  wait_height "$M" 5 40 || { fail "G9: miner never produced (see $MDIR/node.log)"; return; }
  wait_height "$F1" "$BLOCKS_G9" 90 && wait_height "$F2" "$BLOCKS_G9" 90 || { fail "G9: followers never synced to $BLOCKS_G9 pre-restart"; return; }
  log "pre-restart heights: miner=$(hi "$M") f1=$(hi "$F1") f2=$(hi "$F2")"

  # RESTART the miner (no wipe) and follower 1 (no wipe) mid-run.
  log "restarting miner (pid $MPID) + follower1 — NO wipe"
  kill "$MPID" 2>/dev/null; sleep 3
  # relaunch miner on the SAME data-dir (idx 0)
  start_node 0 1 "";           M=$NODE_RPC; MP=$NODE_P2P
  # restart follower1: find + kill it, relaunch on its data-dir (idx 1)
  pkill -f "node1 " 2>/dev/null || true
  local f1pid; f1pid=$(pgrep -f "$SCRATCH/node1" | head -1); [ -n "$f1pid" ] && kill "$f1pid" 2>/dev/null; sleep 2
  start_node 1 0 "$MP";        F1=$NODE_RPC

  # Assert re-convergence in lockstep past the restart height.
  local target=$(( BLOCKS_G9 + 20 ))
  if wait_height "$M" "$target" "$SETTLE" && wait_height "$F1" "$target" "$SETTLE" && wait_height "$F2" "$target" "$SETTLE"; then
    local hM=$(hi "$M") hF1=$(hi "$F1") hF2=$(hi "$F2")
    log "post-restart heights: miner=$hM f1=$hF1 f2=$hF2"
    # lockstep: within a small window
    local lo=$hM; for h in $hF1 $hF2; do [ "$h" -lt "$lo" ] && lo=$h; done
    local hiv=$hM; for h in $hF1 $hF2; do [ "$h" -gt "$hiv" ] && hiv=$h; done
    # identical state root at a common committed height below all tips
    local common=$(( lo - 5 )); [ "$common" -lt 1 ] && common=1
    local srM=$(sr "$M" "$common") srF1=$(sr "$F1" "$common") srF2=$(sr "$F2" "$common")
    local thM=$(thrash_count "$MDIR/node.log") thF1=$(thrash_count "$F1DIR/node.log")
    # A restart legitimately does at most a couple of reconciles; a THRASH LOOP
    # (repeated from-genesis rebuilds / beyond-reorg-window scheduling) is the wedge.
    local THRASH_MAX=3
    if [ $(( hiv - lo )) -le 10 ] && [ -n "$srM" ] && [ "$srM" = "$srF1" ] && [ "$srM" = "$srF2" ] \
       && [ "$thM" -le "$THRASH_MAX" ] && [ "$thF1" -le "$THRASH_MAX" ]; then
      pass "G9: re-converged lockstep (spread $((hiv-lo))), stateRoot@$common identical (${srM:0:14}…), thrash miner=$thM f1=$thF1 (≤$THRASH_MAX)"
    elif [ "$thM" -gt "$THRASH_MAX" ] || [ "$thF1" -gt "$THRASH_MAX" ]; then
      fail "G9: reorg-THRASH LOOP after restart — miner=$thM f1=$thF1 rebuilds (>$THRASH_MAX). This is the restart wedge; see $MDIR/node.log"
    else
      fail "G9: divergence — spread $((hiv-lo)), sr@$common M=$srM F1=$srF1 F2=$srF2, thrash M=$thM F1=$thF1"
    fi
  else
    fail "G9: did not re-converge to $target within ${SETTLE}s after restart (drain stall / wedge). miner=$(hi "$M") f1=$(hi "$F1") f2=$(hi "$F2")"
  fi
  # TODO(deep): restart across an S(E) epoch boundary with §R' active (needs the
  # local ValidatorRegistry from srp_s4_coldsync_harness + low activation height).
}

# ---------------------------------------------------------------------------
gate_g4() {
  echo "== G4 deep cold-sync: miner mines deep, a FRESH node cold-syncs genesis->head =="
  start_node 3 1 "";           local M=$NODE_RPC; local MP=$NODE_P2P; local MDIR=$NODE_DIR
  wait_height "$M" 5 40 || { fail "G4: miner never produced"; return; }
  log "mining to depth $BLOCKS_G4 …"
  wait_height "$M" "$BLOCKS_G4" 240 || { fail "G4: miner did not reach depth $BLOCKS_G4"; return; }
  local tip=$(hi "$M"); log "miner tip=$tip — launching FRESH cold-sync node"
  start_node 4 0 "$MP";        local C=$NODE_RPC; local CDIR=$NODE_DIR
  if wait_height "$C" "$tip" $(( SETTLE * 4 )); then
    local hc=$(hi "$C")
    # verify 0 state-root mismatches AND matching state roots at sampled heights
    local mm=$(mismatch_count "$CDIR/node.log"); local bad=0
    for frac in 4 2 1; do
      local hh=$(( tip / frac )); [ "$hh" -lt 1 ] && continue
      local a=$(sr "$M" "$hh") b=$(sr "$C" "$hh")
      [ -n "$a" ] && [ "$a" = "$b" ] || { bad=$((bad+1)); log "  sr mismatch @${hh}: miner=$a fresh=$b"; }
    done
    if [ "$mm" -eq 0 ] && [ "$bad" -eq 0 ]; then
      pass "G4: fresh node cold-synced to $hc/$tip, 0 state-root mismatches, sampled roots identical"
    else
      fail "G4: cold-sync unclean — log mismatches=$mm, sampled-root failures=$bad"
    fi
  else
    fail "G4: fresh node stalled cold-syncing (reached $(hi "$C")/$tip). see $CDIR/node.log"
  fi
}

# ---------------------------------------------------------------------------
MODE="${1:-all}"
echo "G9/G4 harness — bin=$BIN  scratch=$SCRATCH  blocks(g9=$BLOCKS_G9 g4=$BLOCKS_G4)  settle=${SETTLE}s"
case "$MODE" in
  g9)  gate_g9 ;;
  g4)  gate_g4 ;;
  all) gate_g9; gate_g4 ;;
  *)   die "usage: $0 [g9|g4|all]" ;;
esac
echo
if [ "$FAILS" -eq 0 ]; then echo -e "${G}RESTART-REORG-LIVENESS: ALL REQUESTED GATES PASS${N}"; exit 0
else echo -e "${R}RESTART-REORG-LIVENESS: $FAILS GATE(S) FAILED${N}"; exit 1; fi
