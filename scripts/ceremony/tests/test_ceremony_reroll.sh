#!/usr/bin/env bash
# ============================================================================
# test_ceremony_reroll.sh — integration test for ceremony-reroll.sh
# ============================================================================
#
# Exercises ceremony-reroll.sh against a hand-built fake workspace under
# /tmp, never touching the real repo. Tests every acceptance criterion
# on backlog #111:
#
#   1. Safety gate — refuses without explicit opt-in.
#   2. Real-mode gate — refuses CEREMONY_MODE=real without
#      CEREMONY_REROLL_REAL=1.
#   3. Archive — moves the data dir to a timestamped backup, does NOT
#      rm -rf it, and recreates an empty dir in its place.
#   4. Clears contracts/broadcast and contracts/cache.
#   5. Listener stop — if something is listening on the configured RPC
#      port, the script SIGTERMs it, waits, and verifies the port is
#      free.
#   6. Nothing-to-stop — if no listener, the script reports "nothing
#      to stop" and exits 0.
#   7. Recovery — the archive the script prints can be mv'd back into
#      place to restore the pre-reroll state.
#
# Exit code:
#   0   all checks passed
#   1+  at least one check failed (stdout shows which)
#
# Run:
#   ./test_ceremony_reroll.sh
#
# Prereqs: bash, python3 (for a cheap listener mock), ss or lsof.
#
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REROLL_SCRIPT="$SCRIPT_DIR/../ceremony-reroll.sh"

# ---- assertion helpers ----
FAILS=0
check() {
    local desc="$1"; shift
    if "$@"; then
        echo "  PASS: $desc"
    else
        echo "  FAIL: $desc" >&2
        FAILS=$((FAILS + 1))
    fi
}

file_contains() {
    local path="$1"; local needle="$2"
    [ -f "$path" ] && grep -q "$needle" "$path"
}

dir_empty() {
    local d="$1"
    [ -d "$d" ] && [ -z "$(ls -A "$d" 2>/dev/null)" ]
}

path_missing() {
    ! [ -e "$1" ]
}

# ---- setup ----
build_fake_workspace() {
    local root="$1"
    mkdir -p "$root/.citrate-testnet-beta" "$root/contracts/broadcast" "$root/contracts/cache"
    touch "$root/Cargo.lock"
    echo "OLDSTATE-$(date +%s%N)" > "$root/.citrate-testnet-beta/marker"
    echo "stale-deploy" > "$root/contracts/broadcast/run-latest.json"
    echo "stale-cache"  > "$root/contracts/cache/compiler.json"
}

# ---- Test 1: safety gate — no opt-in ----
echo "== Test 1: refuses without --reroll or CEREMONY_REROLL=1 =="
t1_root=$(mktemp -d /tmp/reroll-t1.XXXXXX)
build_fake_workspace "$t1_root"
if CITRATE_REPO_ROOT="$t1_root" CEREMONY_DATA_DIR="$t1_root/.citrate-testnet-beta" \
   "$REROLL_SCRIPT" >/dev/null 2>&1; then
    echo "  FAIL: reroll ran without opt-in" >&2
    FAILS=$((FAILS + 1))
else
    rc=$?
    check "exit code is 1 (got $rc)" [ "$rc" = "1" ]
fi
check "data dir untouched" file_contains "$t1_root/.citrate-testnet-beta/marker" "OLDSTATE"
check "broadcast untouched" file_contains "$t1_root/contracts/broadcast/run-latest.json" "stale-deploy"
rm -rf "$t1_root"
echo

# ---- Test 2: real-mode gate ----
echo "== Test 2: refuses CEREMONY_MODE=real without CEREMONY_REROLL_REAL=1 =="
t2_root=$(mktemp -d /tmp/reroll-t2.XXXXXX)
build_fake_workspace "$t2_root"
if CITRATE_REPO_ROOT="$t2_root" CEREMONY_DATA_DIR="$t2_root/.citrate-testnet-beta" \
   CEREMONY_MODE=real "$REROLL_SCRIPT" --reroll >/dev/null 2>&1; then
    echo "  FAIL: reroll ran in real mode without second gate" >&2
    FAILS=$((FAILS + 1))
else
    rc=$?
    check "exit code is 1 (got $rc)" [ "$rc" = "1" ]
fi
check "data dir untouched (real-mode guard)" \
    file_contains "$t2_root/.citrate-testnet-beta/marker" "OLDSTATE"
rm -rf "$t2_root"
echo

# ---- Test 3: archive + recreate empty + clear forge dirs ----
echo "== Test 3: archive data dir, clear forge dirs (no listener) =="
t3_root=$(mktemp -d /tmp/reroll-t3.XXXXXX)
build_fake_workspace "$t3_root"
old_marker_content="$(cat "$t3_root/.citrate-testnet-beta/marker")"

CITRATE_REPO_ROOT="$t3_root" CEREMONY_DATA_DIR="$t3_root/.citrate-testnet-beta" \
    CEREMONY_RPC_PORT=18091 \
    "$REROLL_SCRIPT" --reroll > /tmp/reroll-t3.out 2>&1
t3_rc=$?

check "exit code is 0" [ "$t3_rc" = "0" ]
check "reports 'nothing to stop'" grep -q "nothing to stop" /tmp/reroll-t3.out
# Capture the archive dir via a glob. Because bash globs don't expand
# inside `check`'s argv redirection chain, do the lookup in a plain
# variable first and assert non-empty.
archive_dir_probe=""
for candidate in "$t3_root"/.citrate-testnet-beta.pre-reroll-*; do
    [ -d "$candidate" ] && archive_dir_probe="$candidate"
done
check "archive dir exists" [ -n "$archive_dir_probe" ]
check "fresh data dir exists" [ -d "$t3_root/.citrate-testnet-beta" ]
check "fresh data dir is empty" dir_empty "$t3_root/.citrate-testnet-beta"
check "broadcast dir cleared" path_missing "$t3_root/contracts/broadcast"
check "cache dir cleared" path_missing "$t3_root/contracts/cache"

# Recovery roundtrip: the archive should contain the original marker.
check "archive preserved old marker" \
    file_contains "$archive_dir_probe/marker" "$old_marker_content"
rm -rf "$t3_root" /tmp/reroll-t3.out
echo

# ---- Test 4: listener stop ----
echo "== Test 4: stops a running listener on the RPC port =="
t4_root=$(mktemp -d /tmp/reroll-t4.XXXXXX)
build_fake_workspace "$t4_root"
# Pick a high port unlikely to collide with anything.
TEST_PORT=18183
python3 -c "
import signal, socket, time, sys
s = socket.socket()
s.bind(('127.0.0.1', $TEST_PORT))
s.listen(1)
def on_term(*_):
    print('got SIGTERM', flush=True)
    sys.exit(0)
signal.signal(signal.SIGTERM, on_term)
time.sleep(120)
" > "$t4_root/listener.log" 2>&1 &
listener_pid=$!
# Give the listener a moment to bind.
sleep 0.5

if ! kill -0 "$listener_pid" 2>/dev/null; then
    echo "  FAIL: could not spawn fake listener" >&2
    FAILS=$((FAILS + 1))
else
    CITRATE_REPO_ROOT="$t4_root" CEREMONY_DATA_DIR="$t4_root/.citrate-testnet-beta" \
        CEREMONY_RPC_PORT=$TEST_PORT \
        "$REROLL_SCRIPT" --reroll > /tmp/reroll-t4.out 2>&1
    t4_rc=$?
    check "exit code is 0" [ "$t4_rc" = "0" ]
    check "reports 'found listener'" grep -q "found listener" /tmp/reroll-t4.out
    check "reports 'port $TEST_PORT is free'" grep -q "port $TEST_PORT is free" /tmp/reroll-t4.out
    # After a short wait, the listener should be gone.
    sleep 0.3
    if kill -0 "$listener_pid" 2>/dev/null; then
        echo "  FAIL: listener still alive after reroll" >&2
        FAILS=$((FAILS + 1))
        kill -9 "$listener_pid" 2>/dev/null || true
    else
        echo "  PASS: listener was stopped"
    fi
    check "listener received SIGTERM" grep -q "got SIGTERM" "$t4_root/listener.log"
fi
rm -rf "$t4_root" /tmp/reroll-t4.out
echo

# ---- Test 5: repo-root guard — refuses non-workspace dirs ----
echo "== Test 5: refuses to run outside a Citrate workspace =="
t5_root=$(mktemp -d /tmp/reroll-t5.XXXXXX)
# Deliberately missing Cargo.lock and contracts/.
mkdir -p "$t5_root/.citrate-testnet-beta"
if CITRATE_REPO_ROOT="$t5_root" CEREMONY_DATA_DIR="$t5_root/.citrate-testnet-beta" \
   "$REROLL_SCRIPT" --reroll >/dev/null 2>&1; then
    echo "  FAIL: reroll ran outside a workspace" >&2
    FAILS=$((FAILS + 1))
else
    rc=$?
    check "exit code is 1 (got $rc)" [ "$rc" = "1" ]
fi
check "data dir untouched (workspace guard)" [ -d "$t5_root/.citrate-testnet-beta" ]
rm -rf "$t5_root"
echo

# ---- Summary ----
if [ "$FAILS" -eq 0 ]; then
    echo "ALL TESTS PASSED"
    exit 0
else
    echo "$FAILS assertion(s) failed" >&2
    exit 1
fi
