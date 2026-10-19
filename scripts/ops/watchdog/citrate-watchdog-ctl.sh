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
# $STATE_DIR/CONTAIN, which the watchdog honours on every poll with no deadline; (2) disable
# and stop the watchdog timer; (3) stop any poll already running; (4) only then stop and
# disable citrate-node, so neither the watchdog nor a reboot brings the signer back. Every
# step is checked; the first failure stops the command with a non-zero exit and says which
# step failed. `resume` refuses while CONTAIN exists; only `release` clears it, and it does
# not start anything.
# A pause is a file ($STATE_DIR/PAUSE) the watchdog checks on every poll. It does not
# expire by itself: past its deadline the watchdog alerts hourly, still without
# restarting, until someone resumes. Pauses longer than 48 hours are refused.
# Resume clears the stall baseline so the first poll starts a fresh clock.
set -euo pipefail
STATE_DIR="${STATE_DIR:-/var/lib/citrate-watchdog}"
PAUSE_FILE="$STATE_DIR/PAUSE"
CONTAIN_FILE="$STATE_DIR/CONTAIN"
NODE_UNIT="${UNIT:-citrate-node}"
WD_TIMER="citrate-height-watchdog.timer"
WD_SERVICE="citrate-height-watchdog.service"
STATE="$STATE_DIR/state"
MAX_HOURS=48
DRY=0
if [ "${1:-}" = "--dry-run" ]; then DRY=1; shift; fi
cmd="${1:-status}"; shift || true

do_or_say() { if [ "$DRY" = 1 ]; then echo "DRY RUN: $*"; else "$@"; fi; }

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
    step "1/4 mark containment (watchdog restarts nothing)" write_contain
    step "2/4 disable and stop the watchdog timer" systemctl disable --now "$WD_TIMER"
    step "3/4 stop a watchdog poll already running" systemctl stop "$WD_SERVICE"
    step "4/4 stop and disable the node" systemctl disable --now "$NODE_UNIT"
    if [ "$DRY" = 0 ]; then
      logger -t citrate-watchdog "CONTAINED by ${SUDO_USER:-$(id -un)}: $reason" || true
      echo "contained: watchdog disabled, $NODE_UNIT stopped and disabled. Report to security@citrate.ai; do not restart until the chain team says so."
    fi
    ;;
  release)
    reason="$*"
    [ -n "$reason" ] || { echo "release: give a reason (it goes in the log)" >&2; exit 2; }
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
