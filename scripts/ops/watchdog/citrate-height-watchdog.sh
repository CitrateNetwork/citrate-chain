#!/usr/bin/env bash
# citrate-height-watchdog — anti-wedge auto-recovery for the block producer.
# Polls the local RPC; if PROGRESS fails to advance for STALL_SECS, restarts
# citrate-node and fires an alert. Escalates if restarts don't clear the stall.
#
# SYNC-AWARE (2026-09-27 fix): while the node is syncing / replaying state,
# the canonical head (eth_blockNumber) legitimately stays frozen until the
# replay completes. Using the head as the liveness signal in that state made
# the watchdog restart a HEALTHY replay every STALL_SECS, resetting it to the
# last durable snapshot — a permanent halt (chain halt 2026-09-27). The fix:
# when eth_syncing != false, use eth_syncing.currentBlock as the progress
# signal. The node is only "wedged" if its progress signal (currentBlock while
# syncing, else the canonical head) is frozen for STALL_SECS.
set -u
RPC="${RPC:-http://127.0.0.1:8545}"
UNIT="${UNIT:-citrate-node}"
STALL_SECS="${STALL_SECS:-180}"      # progress must move within 3 min
POLL_SECS="${POLL_SECS:-30}"
STATE="/var/lib/citrate-watchdog/state"
mkdir -p "$(dirname "$STATE")"
ALERT="/usr/local/bin/citrate-alert.sh"

rpc() { # method -> raw json
  curl -s -m 8 -X POST "$RPC" -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":[]}"
}

now=$(date +%s)

# 1) Liveness: is the RPC answering at all?
head_json="$(rpc eth_blockNumber)"
head_hex="$(printf '%s' "$head_json" | sed -E 's/.*"result":"(0x[0-9a-fA-F]+)".*/\1/')"
if [ -z "$head_hex" ] || [ "${head_hex#0x}" = "$head_hex" ]; then
  last_down="$(cat "$STATE.downsince" 2>/dev/null || echo "$now")"
  echo "$last_down" > "$STATE.downsince"
  if [ "$((now - last_down))" -ge "$STALL_SECS" ]; then
    logger -t citrate-watchdog "RPC unreachable ${STALL_SECS}s -> restart $UNIT"
    systemctl restart "$UNIT"
    [ -x "$ALERT" ] && "$ALERT" "CITRATE NodeDown" "rpc-1 $UNIT RPC unreachable ${STALL_SECS}s; auto-restarted."
    rm -f "$STATE.downsince"
  fi
  exit 0
fi
rm -f "$STATE.downsince"

# 2) Choose the PROGRESS signal. While syncing/replaying, the canonical head is
#    frozen by design; track eth_syncing.currentBlock instead.
sync_json="$(rpc eth_syncing)"
if printf '%s' "$sync_json" | grep -q '"currentBlock"'; then
  progress="$(printf '%s' "$sync_json" | sed -E 's/.*"currentBlock":"(0x[0-9a-fA-F]+)".*/\1/')"
  mode="syncing"
else
  progress="$head_hex"
  mode="live"
fi

prev_p="$(cat "$STATE.progress" 2>/dev/null || echo)"
prev_t="$(cat "$STATE.time" 2>/dev/null || echo "$now")"
if [ "$progress" != "$prev_p" ]; then
  # progress advanced (replaying OR producing) — healthy, reset the clock
  echo "$progress" > "$STATE.progress"; echo "$now" > "$STATE.time"; rm -f "$STATE.restarts"
  exit 0
fi
# progress unchanged since prev_t
if [ "$((now - prev_t))" -ge "$STALL_SECS" ]; then
  n="$(cat "$STATE.restarts" 2>/dev/null || echo 0)"; n=$((n+1)); echo "$n" > "$STATE.restarts"
  dec=$(( $(printf '%d' "$progress") ))
  logger -t citrate-watchdog "Stall($mode): progress $progress ($dec) frozen ${STALL_SECS}s (restart #$n) -> restart $UNIT"
  systemctl restart "$UNIT"
  echo "$now" > "$STATE.time"
  if [ "$n" -ge 3 ]; then
    [ -x "$ALERT" ] && "$ALERT" "CITRATE Stall CRITICAL" "rpc-1 $mode stalled at $dec; $n auto-restarts did not clear it. MANUAL ACTION NEEDED."
  else
    [ -x "$ALERT" ] && "$ALERT" "CITRATE Stall" "rpc-1 $mode progress $dec frozen ${STALL_SECS}s; auto-restarted (#$n)."
  fi
fi
exit 0
