#!/usr/bin/env bash
# citrate-watchdog-ctl — pause, resume or inspect the height watchdog.
#
#   citrate-watchdog-ctl.sh pause <hours> <reason...>   # before a replay, drain, state copy, rebuild
#   citrate-watchdog-ctl.sh resume                      # after the node is caught up
#   citrate-watchdog-ctl.sh status
#   citrate-watchdog-ctl.sh contain <reason...>         # incident: watchdog off FIRST, then stop the node
#   citrate-watchdog-ctl.sh release <reason...>         # end containment (security response done)
#   citrate-watchdog-ctl.sh --dry-run pause 6 "rollback drain"   # print, change nothing
#
# `contain` is for a suspected key compromise (runbook §11). A stopped node with an active
# watchdog is restarted after STALL_SECS (RPC unreachable), so the order matters: (1) write
# $STATE_DIR/CONTAIN, which the watchdog honours on every poll with no deadline; (2) take the
# control lock, re-assert the marker and wait for a poll already running to finish; (3) disable and stop the watchdog
# timer; (4) stop the watchdog service; (5) only then stop and disable citrate-node, so
# neither the watchdog nor a reboot brings the signer back. Every step is checked; the first
# failure stops the command with a non-zero exit and says which step failed. `resume` refuses
# while CONTAIN exists; only `release` clears it, and it neither starts anything nor re-arms.
# A pause is a file ($STATE_DIR/PAUSE) the watchdog checks on every poll. It does not
# expire by itself: past its deadline the watchdog alerts hourly, still without
# restarting, until someone resumes. Pauses longer than 48 hours are refused.
# Resume clears the stall baseline so the first poll starts a fresh clock.
#
# ARMED record: the watchdog restarts the node only while $STATE_DIR/ARMED holds `armed=1`
# and no PAUSE or CONTAIN exists (fail closed). `resume` is the only command that writes
# ARMED; pause and contain delete it; release leaves it deleted. A fresh install is disarmed
# until the first `resume`.
#
# Ordering and locks (the guarantee: once `pause` exits 0, nothing restarts the node until
# a `resume`):
#   1. Control lock. pause, resume, contain (from step 2) and release first take an exclusive
#      flock on $STATE_DIR/.ctl.lock, so control commands never interleave: a resume cannot
#      delete a PAUSE that a concurrent pause has just written.
#   2. Markers. pause writes PAUSE and deletes ARMED; contain writes CONTAIN and deletes ARMED.
#      A poll that starts after this restarts nothing.
#   3. Drain. Wait (LOCK_WAIT_SECS in total, default 300) until this command holds the poll
#      lock on the file currently at $STATE_DIR/.poll.lock AND no watchdog process is
#      running. The lock covers a poll that read the markers before step 2; the process
#      check covers the same poll if the lock file was removed or replaced meanwhile.
#   4. Verify (pause). Under both locks, PAUSE must still carry this run's nonce and ARMED
#      must be absent; otherwise pause says NOT confirmed and exits 1.
# If any step fails, pause and contain exit non-zero and say the result is NOT confirmed (the
# markers they did write stay in place).
set -euo pipefail
STATE_DIR="${STATE_DIR:-/var/lib/citrate-watchdog}"
PAUSE_FILE="$STATE_DIR/PAUSE"
CONTAIN_FILE="$STATE_DIR/CONTAIN"
ARMED_FILE="$STATE_DIR/ARMED"
NODE_UNIT="${UNIT:-citrate-node}"
WD_TIMER="citrate-height-watchdog.timer"
WD_SERVICE="citrate-height-watchdog.service"
STATE="$STATE_DIR/state"
MAX_HOURS=48
LOCK_FILE="$STATE_DIR/.poll.lock"
CTL_LOCK_FILE="$STATE_DIR/.ctl.lock"
LOCK_WAIT_SECS="${LOCK_WAIT_SECS:-300}"
# A watchdog poll's command line: the script run directly, or through bash/sh/env.
WD_PROC_RE='^([^ ]*/)?((env|bash|sh) +)*([^ ]*/)?citrate-height-watchdog\.sh( |$)'
DRY=0
if [ "${1:-}" = "--dry-run" ]; then DRY=1; shift; fi
cmd="${1:-status}"; shift || true
deadline=$(( $(date +%s) + LOCK_WAIT_SECS ))

do_or_say() { if [ "$DRY" = 1 ]; then echo "DRY RUN: $*"; else "$@"; fi; }
secs_left() { local l=$(( deadline - $(date +%s) )); [ "$l" -ge 0 ] || return 1; echo "$l"; }
same_file() { # fd, path: is the open fd still the file at path?
  local held cur
  held="$(stat -L -c '%d:%i' "/dev/fd/$1" 2>/dev/null)" || return 1
  cur="$(stat -c '%d:%i' "$2" 2>/dev/null)" || return 1
  [ -n "$held" ] && [ "$held" = "$cur" ]
}
# Take an exclusive flock on <path> as <fd> and keep it until this command exits. If the file
# is replaced while we wait, lock the new one. Fails at the deadline.
lock_path() { # fd, path
  local fd="$1" path="$2" left
  mkdir -p "$STATE_DIR" || return 1
  while :; do
    left="$(secs_left)" || return 1
    eval "exec $fd>>\"\$path\"" || return 1
    flock -w "$left" "$fd" || return 1
    same_file "$fd" "$path" && return 0
    eval "exec $fd>&-"
  done
}
take_ctl_lock() { lock_path 8 "$CTL_LOCK_FILE"; }
# Pids of running watchdog polls (fails if the process table cannot be read).
watchdog_pids() { pgrep -f -- "$WD_PROC_RE" || [ "$?" = 1 ]; }
# Hold the poll lock and wait until no watchdog poll is running at all.
drain_polls() {
  lock_path 9 "$LOCK_FILE" || return 1
  local pids
  while :; do
    pids="$(watchdog_pids)" || return 1
    [ -z "$pids" ] && return 0
    secs_left >/dev/null || return 1
    sleep 0.2
  done
}
write_marker() { # path, content
  local tmp; tmp="$(mktemp "$STATE_DIR/.marker.XXXXXX")" || return 1
  printf '%s' "$2" > "$tmp" || { rm -f "$tmp"; return 1; }
  mv -f "$tmp" "$1"
}
marker_present() { [ -e "$1" ] || [ -L "$1" ]; }
who() { printf '%s' "${SUDO_USER:-$(id -un)}"; }

case "$cmd" in
  pause)
    hours="${1:-}"; shift || true
    reason="$*"
    [[ "$hours" =~ ^[0-9]+$ ]] && [ "$hours" -ge 1 ] && [ "$hours" -le "$MAX_HOURS" ] \
      || { echo "pause: hours must be 1..$MAX_HOURS" >&2; exit 2; }
    [ -n "$reason" ] || { echo "pause: give a reason (it goes in the alerts)" >&2; exit 2; }
    reason="$(printf '%s' "$reason" | tr -d '\n\r' | cut -c1-200)"
    until_ts=$(( $(date +%s) + hours * 3600 ))
    if [ "$DRY" = 1 ]; then
      echo "DRY RUN: write $PAUSE_FILE: until=$until_ts reason=$reason; delete $ARMED_FILE"
      exit 0
    fi
    not_confirmed() {
      logger -t citrate-watchdog "pause NOT confirmed: $1" || true
      echo "pause: NOT confirmed: $1. Restarts may still happen. Do not start the maintenance: check 'systemctl status $WD_SERVICE' and 'citrate-watchdog-ctl.sh status', then run pause again." >&2
      exit 1
    }
    take_ctl_lock || not_confirmed "another control command is still running after ${LOCK_WAIT_SECS}s"
    nonce="$(date +%s%N)-$$-$RANDOM"
    write_marker "$PAUSE_FILE" "$(printf 'until=%s\nreason=%s\nby=%s\nat=%s\nnonce=%s\n' "$until_ts" "$reason" "$(who)" "$(date -u +%FT%TZ)" "$nonce")" \
      || not_confirmed "could not write $PAUSE_FILE"
    rm -f "$ARMED_FILE" || not_confirmed "could not delete $ARMED_FILE"
    # A poll that read the markers just before they changed can still restart the node: wait
    # until it has finished before saying the watchdog is paused.
    drain_polls || not_confirmed "a watchdog poll that may have started before the pause is still running after ${LOCK_WAIT_SECS}s (or the process table is unreadable)"
    grep -qxF "nonce=$nonce" "$PAUSE_FILE" 2>/dev/null || not_confirmed "$PAUSE_FILE was removed or replaced while waiting"
    ! marker_present "$ARMED_FILE" || not_confirmed "$ARMED_FILE reappeared while waiting"
    logger -t citrate-watchdog "paused for ${hours}h by $(who): $reason" || true
    echo "watchdog paused until $(date -u -d "@$until_ts" +%FT%TZ): $reason"
    ;;
  contain)
    reason="$*"
    [ -n "$reason" ] || { echo "contain: give a reason (it goes in the log)" >&2; exit 2; }
    reason="$(printf '%s' "$reason" | tr -d '\n\r' | cut -c1-200)"
    step() { # description, command...
      local d="$1"; shift
      if [ "$DRY" = 1 ]; then echo "DRY RUN: $d: $*"; return 0; fi
      "$@" || { echo "contain: FAILED at '$d' ($*). The node may still be running: stop it by hand now (systemctl stop $NODE_UNIT) after the watchdog is off." >&2; exit 1; }
    }
    write_contain() {
      mkdir -p "$STATE_DIR" || return 1
      write_marker "$CONTAIN_FILE" "$(printf 'reason=%s\nby=%s\nat=%s\n' "$reason" "$(who)" "$(date -u +%FT%TZ)")" || return 1
      rm -f "$ARMED_FILE"
    }
    # Under the control lock: re-assert the marker (a release that ran before we got the lock
    # cannot have undone it), then drain any poll in flight.
    lock_and_drain() { take_ctl_lock && write_contain && drain_polls; }
    # The marker goes first, before any wait: containment must not queue behind a stuck pause.
    step "1/5 mark containment (watchdog restarts nothing)" write_contain
    step "2/5 take the control lock and wait for a watchdog poll already running to finish (${LOCK_WAIT_SECS}s max)" lock_and_drain
    step "3/5 disable and stop the watchdog timer" systemctl disable --now "$WD_TIMER"
    step "4/5 stop the watchdog service" systemctl stop "$WD_SERVICE"
    step "5/5 stop and disable the node" systemctl disable --now "$NODE_UNIT"
    if [ "$DRY" = 0 ]; then
      logger -t citrate-watchdog "CONTAINED by $(who): $reason" || true
      echo "contained: watchdog disabled, $NODE_UNIT stopped and disabled. Report to security@citrate.ai; do not restart until the chain team says so."
    fi
    ;;
  release)
    reason="$*"
    [ -n "$reason" ] || { echo "release: give a reason (it goes in the log)" >&2; exit 2; }
    if [ "$DRY" = 0 ]; then
      take_ctl_lock || { echo "release: another control command is still running after ${LOCK_WAIT_SECS}s; try again" >&2; exit 1; }
      lock_path 9 "$LOCK_FILE" || { echo "release: a watchdog poll still holds the lock after ${LOCK_WAIT_SECS}s; try again" >&2; exit 1; }
    fi
    # ARMED stays deleted: the watchdog restarts nothing until an explicit resume.
    do_or_say rm -f "$CONTAIN_FILE" "$ARMED_FILE" "$STATE.progress" "$STATE.time" "$STATE.restarts" "$STATE.downsince" "$STATE.nag"
    if [ "$DRY" = 0 ]; then
      logger -t citrate-watchdog "containment released by $(who): $reason" || true
      echo "containment released. Nothing was started and the watchdog is still disarmed: start $NODE_UNIT and re-enable $WD_TIMER by hand when ready, then run 'citrate-watchdog-ctl.sh resume' to arm it."
    fi
    ;;
  resume)
    if [ "$DRY" = 1 ]; then
      do_or_say rm -f "$PAUSE_FILE" "$STATE.progress" "$STATE.time" "$STATE.restarts" "$STATE.downsince" "$STATE.nag"
      echo "DRY RUN: write $ARMED_FILE: armed=1"
      exit 0
    fi
    take_ctl_lock || { echo "resume: another control command is still running after ${LOCK_WAIT_SECS}s; try again" >&2; exit 1; }
    if marker_present "$CONTAIN_FILE"; then
      echo "resume: refused, the node is contained for an incident ($(sed -n 's/^reason=//p' "$CONTAIN_FILE" 2>/dev/null | head -1)). Use 'release' once the security response is done." >&2
      exit 1
    fi
    lock_path 9 "$LOCK_FILE" || { echo "resume: a watchdog poll still holds the lock after ${LOCK_WAIT_SECS}s; try again" >&2; exit 1; }
    rm -f "$PAUSE_FILE" "$STATE.progress" "$STATE.time" "$STATE.restarts" "$STATE.downsince" "$STATE.nag"
    # ARMED last: restarts become possible only once the pause and the old baseline are gone.
    write_marker "$ARMED_FILE" "$(printf 'armed=1\nby=%s\nat=%s\n' "$(who)" "$(date -u +%FT%TZ)")" \
      || { echo "resume: could not write $ARMED_FILE; the watchdog stays disarmed" >&2; exit 1; }
    logger -t citrate-watchdog "resumed (armed) by $(who)" || true
    echo "watchdog resumed and armed; stall clock re-baselined"
    ;;
  status)
    if marker_present "$CONTAIN_FILE"; then
      echo "CONTAINED"; cat "$CONTAIN_FILE" 2>/dev/null || echo "(marker unreadable)"
    elif marker_present "$PAUSE_FILE"; then
      echo "PAUSED"; cat "$PAUSE_FILE" 2>/dev/null || echo "(marker unreadable)"
    elif [ -f "$ARMED_FILE" ] && [ "$(head -n1 "$ARMED_FILE" 2>/dev/null)" = "armed=1" ]; then
      echo "ACTIVE"
    else
      echo "DISARMED (no valid $ARMED_FILE: restarts are off; run resume to arm)"
    fi
    systemctl is-active citrate-height-watchdog.timer 2>/dev/null | sed 's/^/timer: /' || true
    ;;
  *)
    echo "usage: $0 [--dry-run] pause <hours> <reason> | resume | status | contain <reason> | release <reason>" >&2; exit 2 ;;
esac
