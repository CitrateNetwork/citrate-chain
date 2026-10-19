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
data=""; while [ $# -gt 0 ]; do [ "$1" = "--data" ] && data="$2"; shift; done
m=$(printf '%s' "$data" | sed -E 's/.*"method":"([a-z_A-Z]+)".*/\1/')
f="$RPCDIR/$m"; [ -f "$f" ] && cat "$f"
EOF
cat > "$T/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "$LOGDIR/systemctl.log"
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
bash "$CTL" pause 3 "real" >/dev/null; bash "$CTL" status | grep -q PAUSED && ok "status shows PAUSED" || bad "status wrong"

echo "watchdog tests: $pass passed, $fail failed"
[ "$fail" = 0 ]
