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
#
# OPERATOR PAUSE (2026-10 producer runbook): a replay, a drain after a rollback, a
# state copy or any planned rebuild holds the head still for hours, and a restart
# mid-replay throws the replay away (2026-09-27, 2026-10-04, 2026-10-15). Before
# any of those, pause the watchdog with `citrate-watchdog-ctl.sh pause <hours>
# <reason>`. While $STATE_DIR/PAUSE exists this script restarts nothing. A pause
# never lifts itself: past its deadline it alerts (hourly) until an operator runs
# `citrate-watchdog-ctl.sh resume`, which also re-baselines the stall clock so the
# first poll after a long pause cannot restart a node that is merely catching up.
#
# INCIDENT CONTAINMENT: `citrate-watchdog-ctl.sh contain <reason>` (runbook §11, suspected
# key compromise) writes $STATE_DIR/CONTAIN, waits for any running poll, disables this timer
# and only then stops and disables the node. While CONTAIN exists this script restarts nothing,
# with no deadline, even if the timer is re-enabled by hand.
#
# POLL LOCK: a whole poll (the marker checks, the RPC reads and any restart) runs holding an
# exclusive flock on $STATE_DIR/.poll.lock. citrate-watchdog-ctl.sh changes the markers first,
# then takes the same lock AND waits until no watchdog process is running, and reports success
# only after both, so when pause or contain returns, no poll that read the markers before they
# changed can still restart the node. If the lock is busy (a control command is running) this
# poll restarts nothing and exits.
#
# FAIL CLOSED (ARMED record): restarts need positive permission, not just the absence of a
# PAUSE. The node is restarted only if ALL of these hold at the moment of the restart:
#   - $STATE_DIR/ARMED is a readable regular file whose first line is exactly `armed=1`
#     (written only by `citrate-watchdog-ctl.sh resume`; pause and contain delete it);
#   - neither $STATE_DIR/PAUSE nor $STATE_DIR/CONTAIN exists in any form (file, directory,
#     dangling link, unreadable);
#   - this poll still holds the lock on the file currently at $STATE_DIR/.poll.lock (it was not
#     removed or replaced during the poll).
# So a PAUSE deleted by hand, a wiped or unreadable state directory, or a fresh install all
# mean "restart nothing" (with an hourly alert), never "restart freely". These conditions are
# checked at the start of the poll and again immediately before each `systemctl restart`.
set -u
RPC="${RPC:-http://127.0.0.1:8545}"
UNIT="${UNIT:-citrate-node}"
STALL_SECS="${STALL_SECS:-180}"      # progress must move within 3 min
POLL_SECS="${POLL_SECS:-30}"
STATE_DIR="${STATE_DIR:-/var/lib/citrate-watchdog}"
STATE="$STATE_DIR/state"
PAUSE_FILE="$STATE_DIR/PAUSE"
CONTAIN_FILE="$STATE_DIR/CONTAIN"
ARMED_FILE="$STATE_DIR/ARMED"
NODE_LABEL="${NODE_LABEL:-$(hostname -s 2>/dev/null || echo node)}"
ALERT="${ALERT:-/usr/local/bin/citrate-alert.sh}"
LOCK_FILE="$STATE_DIR/.poll.lock"

log() { logger -t citrate-watchdog "$*" 9>&- || true; }

# Hold the poll lock (fd 9) for the rest of this run; it is released when the script exits.
# Commands started below get `9>&-` so nothing they leave behind keeps the lock. Any failure to
# set it up (state dir missing and not creatable, lock path unusable) restarts nothing.
if ! mkdir -p "$STATE_DIR" 2>/dev/null || ! { exec 9>>"$LOCK_FILE"; } 2>/dev/null; then
  log "state dir or poll lock unusable ($LOCK_FILE); restarting nothing this poll"
  exit 0
fi
if ! flock -n 9; then
  log "a pause/contain/resume is in progress (poll lock held); not checking $UNIT this poll"
  exit 0
fi

# True if fd 9 is still the file at $LOCK_FILE (it was not removed or replaced).
lock_is_ours() {
  local held cur
  held="$(stat -L -c '%d:%i' /dev/fd/9 2>/dev/null)" || return 1
  cur="$(stat -c '%d:%i' "$LOCK_FILE" 2>/dev/null)" || return 1
  [ -n "$held" ] && [ "$held" = "$cur" ]
}
marker_present() { [ -e "$1" ] || [ -L "$1" ]; }
is_armed() {
  local line=""
  [ -f "$ARMED_FILE" ] && [ -r "$ARMED_FILE" ] || return 1
  IFS= read -r line < "$ARMED_FILE" 2>/dev/null || [ -n "$line" ] || return 1
  [ "$line" = "armed=1" ]
}
# The single restart gate. Sets $why when it refuses.
restart_permitted() {
  why=""
  lock_is_ours || { why="the poll lock file was removed or replaced during this poll"; return 1; }
  marker_present "$CONTAIN_FILE" && { why="contained"; return 1; }
  marker_present "$PAUSE_FILE" && { why="paused"; return 1; }
  is_armed || { why="not armed (no valid $ARMED_FILE)"; return 1; }
  return 0
}
# Restart the node only if the gate still allows it at this instant.
guarded_restart() {
  if ! restart_permitted; then
    log "would restart $UNIT but restarts are off ($why); restarting nothing"
    exit 0
  fi
  systemctl restart "$UNIT" 9>&-
}

if ! lock_is_ours; then
  log "poll lock file changed under this poll; restarting nothing this poll"
  exit 0
fi

rpc() { # method -> raw json
  curl -s -m 8 -X POST "$RPC" -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":[]}" 9>&-
}

now=$(date +%s)

# 0a) Incident containment (`citrate-watchdog-ctl.sh contain`): the node was stopped on
# purpose (e.g. suspected key compromise). Never restart it, never expire, never nag.
if marker_present "$CONTAIN_FILE"; then
  rm -f "$STATE.progress" "$STATE.time" "$STATE.restarts" "$STATE.downsince"
  log "CONTAINED: $UNIT stopped for an incident; not checking or restarting it"
  exit 0
fi

# 0b) Operator pause: restart nothing; forget the stall baseline.
if marker_present "$PAUSE_FILE"; then
  rm -f "$STATE.progress" "$STATE.time" "$STATE.restarts" "$STATE.downsince"
  # An unreadable or garbled PAUSE is still a pause: it just counts as past its deadline.
  until_ts="$(sed -n 's/^until=\([0-9][0-9]*\)$/\1/p' "$PAUSE_FILE" 2>/dev/null | head -1)"
  reason="$(sed -n 's/^reason=//p' "$PAUSE_FILE" 2>/dev/null | head -1)"
  [ -n "$until_ts" ] || until_ts=0
  if [ "$now" -ge "$until_ts" ]; then
    last_nag="$(cat "$STATE.nag" 2>/dev/null || echo 0)"
    case "$last_nag" in ''|*[!0-9]*) last_nag=0 ;; esac
    if [ "$((now - last_nag))" -ge 3600 ]; then
      echo "$now" > "$STATE.nag"
      log "PAUSED past its deadline ($reason); still not restarting $UNIT"
      [ -x "$ALERT" ] && "$ALERT" 9>&- "CITRATE watchdog pause expired" "$NODE_LABEL: watchdog paused for '$reason' past its deadline. Resume with citrate-watchdog-ctl.sh resume once the replay is done."
    fi
  else
    log "paused ($reason) until $until_ts; not checking $UNIT"
  fi
  exit 0
fi

# 0c) Not armed: no ARMED record and no pause. This is a fresh install, a release after
# containment, a wiped state dir, or a PAUSE that was deleted without `resume`. Restart
# nothing; alert hourly so a disarmed watchdog is never silent.
if ! is_armed; then
  rm -f "$STATE.progress" "$STATE.time" "$STATE.restarts" "$STATE.downsince"
  last_nag="$(cat "$STATE.nag" 2>/dev/null || echo 0)"
  case "$last_nag" in ''|*[!0-9]*) last_nag=0 ;; esac
  if [ "$((now - last_nag))" -ge 3600 ]; then
    echo "$now" > "$STATE.nag" 2>/dev/null || true
    log "DISARMED: no valid $ARMED_FILE; not restarting $UNIT. Arm with citrate-watchdog-ctl.sh resume"
    [ -x "$ALERT" ] && "$ALERT" 9>&- "CITRATE watchdog disarmed" "$NODE_LABEL: the watchdog has no ARMED record and no pause, so it restarts nothing. After an install or a release run citrate-watchdog-ctl.sh resume; otherwise find out who removed the pause or the record."
  else
    log "disarmed; not checking $UNIT"
  fi
  exit 0
fi
rm -f "$STATE.nag"

# 1) Liveness: is the RPC answering at all?
head_json="$(rpc eth_blockNumber)"
head_hex="$(printf '%s' "$head_json" | sed -E 's/.*"result":"(0x[0-9a-fA-F]+)".*/\1/')"
if [ -z "$head_hex" ] || [ "${head_hex#0x}" = "$head_hex" ]; then
  last_down="$(cat "$STATE.downsince" 2>/dev/null || echo "$now")"
  echo "$last_down" > "$STATE.downsince"
  if [ "$((now - last_down))" -ge "$STALL_SECS" ]; then
    log "RPC unreachable ${STALL_SECS}s -> restart $UNIT"
    guarded_restart
    [ -x "$ALERT" ] && "$ALERT" 9>&- "CITRATE NodeDown" "$NODE_LABEL $UNIT RPC unreachable ${STALL_SECS}s; auto-restarted."
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
  log "Stall($mode): progress $progress ($dec) frozen ${STALL_SECS}s (restart #$n) -> restart $UNIT"
  guarded_restart
  echo "$now" > "$STATE.time"
  if [ "$n" -ge 3 ]; then
    [ -x "$ALERT" ] && "$ALERT" 9>&- "CITRATE Stall CRITICAL" "$NODE_LABEL $mode stalled at $dec; $n auto-restarts did not clear it. MANUAL ACTION NEEDED."
  else
    [ -x "$ALERT" ] && "$ALERT" 9>&- "CITRATE Stall" "$NODE_LABEL $mode progress $dec frozen ${STALL_SECS}s; auto-restarted (#$n)."
  fi
fi
exit 0
