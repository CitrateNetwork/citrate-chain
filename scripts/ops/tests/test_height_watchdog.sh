#!/usr/bin/env bash
# Tests for scripts/ops/watchdog/citrate-height-watchdog.sh and citrate-watchdog-ctl.sh.
#
# Hermetic: curl, systemctl, logger and the alert hook are replaced by recording shims on
# PATH, and STATE_DIR is a temp dir, so nothing on the host is restarted. Run it inside a
# throwaway namespace anyway (the restart path is a kill path):
#   unshare --user --map-root-user --pid --fork --mount-proc bash scripts/ops/tests/test_height_watchdog.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WD="$HERE/../watchdog/citrate-height-watchdog.sh"
CTL="$HERE/../watchdog/citrate-watchdog-ctl.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/rpc"
export STATE_DIR="$T/state" ALERT="$T/bin/alert" NODE_LABEL=test-node STALL_SECS=180
export PATH="$T/bin:$PATH"

# curl shim: answers eth_blockNumber / eth_syncing from files in $T/rpc.
cat > "$T/bin/curl" <<'EOF'
#!/usr/bin/env bash
# CURL_HOLD=<dir>: announce entry (<dir>/entered) and block until <dir>/go exists, to hold a
# poll mid-flight (after its PAUSE/CONTAIN check, before its restart decision).
if [ -n "${CURL_HOLD:-}" ]; then
  : > "$CURL_HOLD/entered"
  while [ ! -e "$CURL_HOLD/go" ]; do sleep 0.05; done
fi
data=""; while [ $# -gt 0 ]; do [ "$1" = "--data" ] && data="$2"; shift; done
m=$(printf '%s' "$data" | sed -E 's/.*"method":"([a-z_A-Z]+)".*/\1/')
f="$RPCDIR/$m"; [ -f "$f" ] && cat "$f"
EOF
cat > "$T/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
# Records each call, and whether containment was already marked when it ran.
c=no; [ -e "$STATE_DIR/CONTAIN" ] && c=yes
echo "$*" >> "$LOGDIR/systemctl.log"
echo "$c $*" >> "$LOGDIR/systemctl-contain.log"
echo "systemctl $*" >> "$LOGDIR/events.log"
# SYSTEMCTL_FAIL=<substring>: fail the call whose arguments contain it.
if [ -n "${SYSTEMCTL_FAIL:-}" ] && [[ "$*" == *"$SYSTEMCTL_FAIL"* ]]; then exit 1; fi
exit 0
EOF
cat > "$T/bin/logger" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "$LOGDIR/logger.log"
EOF
cat > "$T/bin/alert" <<'EOF'
#!/usr/bin/env bash
echo "$1 | $2" >> "$LOGDIR/alert.log"
EOF
chmod +x "$T/bin/"*
export RPCDIR="$T/rpc" LOGDIR="$T"

pass=0; fail=0
ok()  { pass=$((pass+1)); echo "ok   - $1"; }
bad() { fail=$((fail+1)); echo "FAIL - $1"; }
restarts() { if [ -f "$T/systemctl.log" ]; then grep -c '^restart' "$T/systemctl.log" || true; else echo 0; fi; }
reset() { rm -rf "$STATE_DIR" "$T"/*.log; }
head_is() { printf '{"jsonrpc":"2.0","id":1,"result":"%s"}' "$1" > "$T/rpc/eth_blockNumber"; }
synced() { printf '{"jsonrpc":"2.0","id":1,"result":false}' > "$T/rpc/eth_syncing"; }
syncing_at() { printf '{"jsonrpc":"2.0","id":1,"result":{"startingBlock":"%s","currentBlock":"%s","highestBlock":"0xffff"}}' "$1" "$1" > "$T/rpc/eth_syncing"; }
age_baseline() { echo $(( $(date +%s) - $1 )) > "$STATE_DIR/state.time"; }

# 1. live head advancing: no restart
reset; synced; head_is 0x10; bash "$WD"; head_is 0x11; age_baseline 600; bash "$WD"
[ "$(restarts)" = 0 ] && ok "advancing head is healthy" || bad "advancing head restarted"

# 2. frozen head past STALL_SECS: restart + alert labelled with NODE_LABEL
reset; synced; head_is 0x20; bash "$WD"; age_baseline 200; bash "$WD"
[ "$(restarts)" = 1 ] && ok "frozen head restarts once" || bad "frozen head: $(restarts) restarts"
grep -q "test-node" "$T/alert.log" && ok "alert names the node" || bad "alert label missing"

# 3. replaying (eth_syncing.currentBlock moving) with a frozen head: no restart
reset; head_is 0x30; syncing_at 0x100; bash "$WD"; syncing_at 0x180; age_baseline 900; bash "$WD"
[ "$(restarts)" = 0 ] && ok "advancing replay is healthy" || bad "replay restarted"

# 4. paused: a frozen head is NOT restarted, and the baseline is forgotten
reset; synced; head_is 0x40; bash "$WD"; age_baseline 900
bash "$CTL" pause 2 "test drain" >/dev/null
bash "$WD"; bash "$WD"
[ "$(restarts)" = 0 ] && ok "paused watchdog restarts nothing" || bad "paused watchdog restarted"
[ ! -e "$STATE_DIR/state.time" ] && ok "pause clears the stall baseline" || bad "baseline kept while paused"

# 5. pause past its deadline: alerts, still no restart, alert rate-limited
printf 'until=1\nreason=old drain\n' > "$STATE_DIR/PAUSE"
bash "$WD"; bash "$WD"
[ "$(restarts)" = 0 ] && ok "expired pause still restarts nothing" || bad "expired pause restarted"
n=$(grep -c "pause expired" "$T/alert.log" || true)
[ "$n" = 1 ] && ok "expired pause alerts once per hour" || bad "expired pause alerted $n times"

# 6. resume: first poll re-baselines (no restart even though the head is still frozen)
bash "$CTL" resume >/dev/null
bash "$WD"
[ "$(restarts)" = 0 ] && ok "first poll after resume does not restart" || bad "resume restarted immediately"
age_baseline 200; bash "$WD"
[ "$(restarts)" = 1 ] && ok "watchdog active again after resume" || bad "not active after resume"

# 7. ctl input validation and dry run
reset
if bash "$CTL" pause 0 x 2>/dev/null; then bad "pause 0 accepted"; else ok "pause 0 refused"; fi
if bash "$CTL" pause 49 x 2>/dev/null; then bad "pause 49 accepted"; else ok "pause > 48h refused"; fi
if bash "$CTL" pause 2 2>/dev/null; then bad "pause without reason accepted"; else ok "pause needs a reason"; fi
bash "$CTL" --dry-run pause 3 "dry" | grep -q "DRY RUN" && [ ! -e "$STATE_DIR/PAUSE" ] \
  && ok "dry-run pause writes nothing" || bad "dry-run pause wrote a file"
bash "$CTL" pause 3 "real" >/dev/null; st="$(bash "$CTL" status)"; grep -q PAUSED <<<"$st" && ok "status shows PAUSED" || bad "status wrong"

# 8. incident containment: watchdog off BEFORE the node stops; nothing restarts it
reset; head_is 0x50; synced; bash "$WD"
bash "$CTL" contain "suspected key compromise" >/dev/null
expected=$'yes disable --now citrate-height-watchdog.timer\nyes stop citrate-height-watchdog.service\nyes disable --now citrate-node'
[ "$(cat "$T/systemctl-contain.log")" = "$expected" ] \
  && ok "contain marks, disables the watchdog, then stops the node (in that order)" \
  || bad "contain order: $(cat "$T/systemctl-contain.log")"
# The node is down: the RPC no longer answers. Even a poll that still fires (timer
# re-enabled by hand, or one already in flight) must not restart it, ever.
rm -f "$T/rpc/eth_blockNumber" "$T/rpc/eth_syncing"
bash "$WD"; echo $(( $(date +%s) - 100000 )) > "$STATE_DIR/state.downsince"; bash "$WD"; bash "$WD"
[ "$(restarts)" = 0 ] && ok "contained node is never restarted" || bad "contained node restarted $(restarts)x"
st="$(bash "$CTL" status)"; grep -q CONTAINED <<<"$st" && ok "status shows CONTAINED" || bad "status does not show containment"
if bash "$CTL" resume 2>/dev/null; then bad "resume lifted containment"; else ok "resume refused while contained"; fi
[ -e "$STATE_DIR/CONTAIN" ] && ok "containment survives a resume attempt" || bad "CONTAIN removed by resume"
if bash "$CTL" release 2>/dev/null; then bad "release without reason accepted"; else ok "release needs a reason"; fi
: > "$T/systemctl.log"
bash "$CTL" release "security response complete" >/dev/null
[ ! -e "$STATE_DIR/CONTAIN" ] && ok "release clears containment" || bad "release kept CONTAIN"
[ ! -s "$T/systemctl.log" ] && ok "release starts nothing" || bad "release called systemctl: $(cat "$T/systemctl.log")"

# 9. contain input validation, dry run, and a failed step stops before the node is touched
reset
if bash "$CTL" contain 2>/dev/null; then bad "contain without reason accepted"; else ok "contain needs a reason"; fi
dry="$(bash "$CTL" --dry-run contain "drill")"; grep -q "DRY RUN" <<<"$dry" && [ ! -e "$STATE_DIR/CONTAIN" ] && [ ! -e "$T/systemctl.log" ] \
  && ok "dry-run contain changes nothing" || bad "dry-run contain changed state"
reset
if SYSTEMCTL_FAIL="citrate-height-watchdog.timer" bash "$CTL" contain "x" >/dev/null 2>&1; then
  bad "contain succeeded although the watchdog could not be disabled"
else
  ok "contain fails when the watchdog cannot be disabled"
fi
grep -q "citrate-node" "$T/systemctl.log" && bad "node stopped although the watchdog is still on" \
  || ok "node untouched after a failed watchdog step"
[ -e "$STATE_DIR/CONTAIN" ] && ok "containment marker still blocks restarts after a failed step" || bad "no marker after failed step"
reset
if SYSTEMCTL_FAIL="disable --now citrate-node" bash "$CTL" contain "x" >/dev/null 2>"$T/err"; then
  bad "contain reported success although the node stop failed"
else
  grep -q "FAILED at '5/5" "$T/err" && ok "a failed node stop is reported" || bad "node-stop failure message: $(cat "$T/err")"
fi

# 10. RACE: a poll that passed its PAUSE/CONTAIN check before the marker was written (held in
# its RPC read, with the stall baseline expired) must finish before pause/contain report
# success. Before the poll lock, pause returned at once and the poll then restarted the node
# during the maintenance; contain stopped the node and the poll then restarted it.
wait_for() { # file, tenths of a second
  local i=0; while [ ! -e "$1" ] && [ "$i" -lt "$2" ]; do sleep 0.1; i=$((i+1)); done; [ -e "$1" ]
}
stalled_poll_in_flight() { # leaves a poll held in its first RPC read; prints its pid
  reset; synced; head_is 0x70; bash "$WD"; age_baseline 900
  H="$T/hold"; rm -rf "$H"; mkdir -p "$H"
  CURL_HOLD="$H" bash "$WD" & echo $! > "$T/poll.pid"
  wait_for "$H/entered" 50 || { bad "poll did not reach its RPC read"; }
}

stalled_poll_in_flight; poll=$(cat "$T/poll.pid")
( bash "$CTL" pause 2 "race drain" > "$T/pause.out" 2>&1; echo "rc=$?" > "$T/pause.rc"; echo "ctl pause returned" >> "$T/events.log" ) &
ctl=$!
wait_for "$STATE_DIR/PAUSE" 50 && ok "race: pause writes its marker at once" || bad "race: no PAUSE marker"
sleep 0.5
[ ! -e "$T/pause.rc" ] && ok "race: pause waits for the poll in flight" || bad "race: pause returned while a poll was in flight: $(cat "$T/pause.out")"
: > "$H/go"; wait "$poll"; wait "$ctl"
grep -q "rc=0" "$T/pause.rc" && grep -q "watchdog paused" "$T/pause.out" && ok "race: pause then reports paused" || bad "race: pause result $(cat "$T/pause.rc" "$T/pause.out")"
last=$(tail -n1 "$T/events.log")
[ "$(restarts)" = 1 ] && [ "$last" = "ctl pause returned" ] && ok "race: the in-flight poll's restart precedes the paused report" \
  || bad "race: events after pause returned: $(cat "$T/events.log")"
n=$(restarts); bash "$WD"; age_baseline 900; bash "$WD"
[ "$(restarts)" = "$n" ] && ok "race: no restart once pause has returned" || bad "race: restarted after pause returned"

# contain: the node stop is the last action; the in-flight poll's restart comes before it.
stalled_poll_in_flight; poll=$(cat "$T/poll.pid")
( bash "$CTL" contain "race incident" > "$T/contain.out" 2>&1; echo "rc=$?" > "$T/contain.rc" ) &
ctl=$!
sleep 0.5
grep -q "disable --now citrate-node" "$T/systemctl.log" 2>/dev/null \
  && bad "race: contain stopped the node while a poll was in flight" || ok "race: contain waits for the poll before touching systemd"
: > "$H/go"; wait "$poll"; wait "$ctl"
grep -q "rc=0" "$T/contain.rc" && ok "race: contain completes" || bad "race: contain failed: $(cat "$T/contain.out")"
[ "$(head -n1 "$T/systemctl.log")" = "restart citrate-node" ] && [ "$(tail -n1 "$T/systemctl.log")" = "disable --now citrate-node" ] \
  && ok "race: nothing restarts the node after contain stops it" || bad "race: systemctl order $(cat "$T/systemctl.log")"

# A poll that never finishes: pause gives up after LOCK_WAIT_SECS, exits non-zero, says NOT
# confirmed, and leaves the marker so later polls still restart nothing.
stalled_poll_in_flight; poll=$(cat "$T/poll.pid")
if LOCK_WAIT_SECS=1 bash "$CTL" pause 2 "stuck" > "$T/pause.out" 2>&1; then
  bad "race: pause confirmed although a poll still holds the lock"
else
  grep -q "NOT confirmed" "$T/pause.out" && ok "race: a stuck poll makes pause fail, NOT confirmed" || bad "race: stuck-poll message $(cat "$T/pause.out")"
fi
[ -e "$STATE_DIR/PAUSE" ] && ok "race: the marker stays after a timed-out pause" || bad "race: marker gone after timeout"
: > "$H/go"; wait "$poll"

# While a control command holds the lock, a poll restarts nothing (it skips that round).
reset; synced; head_is 0x80; bash "$WD"; age_baseline 900
mkdir -p "$STATE_DIR"; exec 8>>"$STATE_DIR/.poll.lock"; flock -n 8
bash "$WD"
[ "$(restarts)" = 0 ] && ok "a poll skips while the lock is held" || bad "a poll restarted while the lock was held"
grep -q "poll lock held" "$T/logger.log" && ok "a skipped poll says why" || bad "skipped poll not logged"
exec 8>&-
bash "$WD"
[ "$(restarts)" = 1 ] && ok "the next poll acts once the lock is free" || bad "no restart once the lock was free ($(restarts))"

echo "watchdog tests: $pass passed, $fail failed"
[ "$fail" = 0 ]
