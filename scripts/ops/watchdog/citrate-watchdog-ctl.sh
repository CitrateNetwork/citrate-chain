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
# $STATE_DIR/CONTAIN, which the watchdog honours on every poll with no deadline; (2) wait for
# a poll already running to finish and hold the poll lock; (3) disable and stop the watchdog
# timer; (4) stop the watchdog service; (5) only then stop and disable citrate-node, so
# neither the watchdog nor a reboot brings the signer back. Every step is checked; the first
# failure stops the command with a non-zero exit and says which step failed. `resume` refuses
# while CONTAIN exists; only `release` clears it, and it does not start anything.
# A pause is a file ($STATE_DIR/PAUSE) the watchdog checks on every poll. It does not
# expire by itself: past its deadline the watchdog alerts hourly, still without
# restarting, until someone resumes. Pauses longer than 48 hours are refused.
# Resume clears the stall baseline so the first poll starts a fresh clock.
#
# Poll lock: every watchdog poll holds an exclusive flock on $STATE_DIR/.poll.lock from its
# PAUSE/CONTAIN check through any restart. pause and contain write their marker first (a poll
# that starts later sees it), then wait up to LOCK_WAIT_SECS (default 300) for that lock, so a
# poll that read the markers BEFORE they were written has finished, restart included, before
# they report success. If the wait times out they exit non-zero and say the pause is NOT
# confirmed (the marker stays in place). resume and release change state under the same lock.
set -euo pipefail
STATE_DIR="${STATE_DIR:-/var/lib/citrate-watchdog}"
PAUSE_FILE="$STATE_DIR/PAUSE"
CONTAIN_FILE="$STATE_DIR/CONTAIN"
NODE_UNIT="${UNIT:-citrate-node}"
WD_TIMER="citrate-height-watchdog.timer"
WD_SERVICE="citrate-height-watchdog.service"
STATE="$STATE_DIR/state"
MAX_HOURS=48
LOCK_FILE="$STATE_DIR/.poll.lock"
LOCK_WAIT_SECS="${LOCK_WAIT_SECS:-300}"
DRY=0
if [ "${1:-}" = "--dry-run" ]; then DRY=1; shift; fi
cmd="${1:-status}"; shift || true

do_or_say() { if [ "$DRY" = 1 ]; then echo "DRY RUN: $*"; else "$@"; fi; }

# Wait for a watchdog poll in progress to finish, then hold the poll lock (fd 9) until this
# command exits. Returns non-zero if the poll is still running after LOCK_WAIT_SECS.
hold_poll_lock() {
  mkdir -p "$STATE_DIR" || return 1
  exec 9>>"$LOCK_FILE" || return 1
  flock -w "$LOCK_WAIT_SECS" 9
}

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
      echo "DRY RUN: write $PAUSE_FILE: until=$until_ts reason=$reason"
    else
      mkdir -p "$STATE_DIR"
      tmp="$(mktemp "$STATE_DIR/.PAUSE.XXXXXX")"
      printf 'until=%s\nreason=%s\nby=%s\nat=%s\n' "$until_ts" "$reason" "${SUDO_USER:-$(id -un)}" "$(date -u +%FT%TZ)" > "$tmp"
      mv "$tmp" "$PAUSE_FILE"
      # A poll that read "no PAUSE" just before the write can still restart the node: wait
      # for it to finish before saying the watchdog is paused.
      if ! hold_poll_lock; then
        logger -t citrate-watchdog "pause NOT confirmed: a poll still holds the lock after ${LOCK_WAIT_SECS}s" || true
        echo "pause: NOT confirmed. $PAUSE_FILE is written (new polls honour it), but a watchdog poll that started before it is still running after ${LOCK_WAIT_SECS}s and may still restart $NODE_UNIT. Do not start the maintenance: check 'systemctl status $WD_SERVICE', then run pause again." >&2
        exit 1
      fi
      logger -t citrate-watchdog "paused for ${hours}h by ${SUDO_USER:-$(id -un)}: $reason" || true
      echo "watchdog paused until $(date -u -d "@$until_ts" +%FT%TZ): $reason"
    fi
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
      local tmp; tmp="$(mktemp "$STATE_DIR/.CONTAIN.XXXXXX")" || return 1
      printf 'reason=%s\nby=%s\nat=%s\n' "$reason" "${SUDO_USER:-$(id -un)}" "$(date -u +%FT%TZ)" > "$tmp" || return 1
      mv "$tmp" "$CONTAIN_FILE"
    }
    step "1/5 mark containment (watchdog restarts nothing)" write_contain
    step "2/5 wait for a watchdog poll already running to finish (${LOCK_WAIT_SECS}s max)" hold_poll_lock
    step "3/5 disable and stop the watchdog timer" systemctl disable --now "$WD_TIMER"
    step "4/5 stop the watchdog service" systemctl stop "$WD_SERVICE"
    step "5/5 stop and disable the node" systemctl disable --now "$NODE_UNIT"
    if [ "$DRY" = 0 ]; then
      logger -t citrate-watchdog "CONTAINED by ${SUDO_USER:-$(id -un)}: $reason" || true
      echo "contained: watchdog disabled, $NODE_UNIT stopped and disabled. Report to security@citrate.ai; do not restart until the chain team says so."
    fi
    ;;
  release)
    reason="$*"
    [ -n "$reason" ] || { echo "release: give a reason (it goes in the log)" >&2; exit 2; }
    if [ "$DRY" = 0 ] && ! hold_poll_lock; then echo "release: a watchdog poll still holds the lock after ${LOCK_WAIT_SECS}s; try again" >&2; exit 1; fi
    do_or_say rm -f "$CONTAIN_FILE" "$STATE.progress" "$STATE.time" "$STATE.restarts" "$STATE.downsince" "$STATE.nag"
    if [ "$DRY" = 0 ]; then
      logger -t citrate-watchdog "containment released by ${SUDO_USER:-$(id -un)}: $reason" || true
      echo "containment released. Nothing was started: start $NODE_UNIT and re-enable $WD_TIMER by hand when ready."
    fi
    ;;
  resume)
    if [ -e "$CONTAIN_FILE" ]; then
      echo "resume: refused, the node is contained for an incident ($(sed -n 's/^reason=//p' "$CONTAIN_FILE" | head -1)). Use 'release' once the security response is done." >&2
      exit 1
    fi
    if [ "$DRY" = 0 ] && ! hold_poll_lock; then echo "resume: a watchdog poll still holds the lock after ${LOCK_WAIT_SECS}s; try again" >&2; exit 1; fi
    do_or_say rm -f "$PAUSE_FILE" "$STATE.progress" "$STATE.time" "$STATE.restarts" "$STATE.downsince" "$STATE.nag"
    if [ "$DRY" = 0 ]; then
      logger -t citrate-watchdog "resumed by ${SUDO_USER:-$(id -un)}" || true
      echo "watchdog resumed; stall clock re-baselined"
    fi
    ;;
  status)
    if [ -e "$CONTAIN_FILE" ]; then
      echo "CONTAINED"; cat "$CONTAIN_FILE"
    elif [ -e "$PAUSE_FILE" ]; then
      echo "PAUSED"; cat "$PAUSE_FILE"
    else
      echo "ACTIVE"
    fi
    systemctl is-active citrate-height-watchdog.timer 2>/dev/null | sed 's/^/timer: /' || true
    ;;
  *)
    echo "usage: $0 [--dry-run] pause <hours> <reason> | resume | status | contain <reason> | release <reason>" >&2; exit 2 ;;
esac
