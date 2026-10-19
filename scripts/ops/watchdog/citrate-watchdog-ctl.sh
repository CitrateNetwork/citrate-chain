#!/usr/bin/env bash
# citrate-watchdog-ctl — pause, resume or inspect the height watchdog.
#
#   citrate-watchdog-ctl.sh pause <hours> <reason...>   # before a replay, drain, state copy, rebuild
#   citrate-watchdog-ctl.sh resume                      # after the node is caught up
#   citrate-watchdog-ctl.sh status
#   citrate-watchdog-ctl.sh --dry-run pause 6 "rollback drain"   # print, change nothing
#
# A pause is a file ($STATE_DIR/PAUSE) the watchdog checks on every poll. It does not
# expire by itself: past its deadline the watchdog alerts hourly, still without
# restarting, until someone resumes. Pauses longer than 48 hours are refused.
# Resume clears the stall baseline so the first poll starts a fresh clock.
set -euo pipefail
STATE_DIR="${STATE_DIR:-/var/lib/citrate-watchdog}"
PAUSE_FILE="$STATE_DIR/PAUSE"
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
  resume)
    do_or_say rm -f "$PAUSE_FILE" "$STATE.progress" "$STATE.time" "$STATE.restarts" "$STATE.downsince" "$STATE.nag"
    if [ "$DRY" = 0 ]; then
      logger -t citrate-watchdog "resumed by ${SUDO_USER:-$(id -un)}" || true
      echo "watchdog resumed; stall clock re-baselined"
    fi
    ;;
  status)
    if [ -e "$PAUSE_FILE" ]; then
      echo "PAUSED"; cat "$PAUSE_FILE"
    else
      echo "ACTIVE"
    fi
    systemctl is-active citrate-height-watchdog.timer 2>/dev/null | sed 's/^/timer: /' || true
    ;;
  *)
    echo "usage: $0 [--dry-run] pause <hours> <reason> | resume | status" >&2; exit 2 ;;
esac
