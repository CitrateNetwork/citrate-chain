#!/usr/bin/env bash
# ============================================================================
# ceremony-reroll.sh — clean-slate pre-step for local ceremony rehearsals
# ============================================================================
#
# Problem this closes:
#
# The 2026-04-08 dry-run hit `CreateCollision` on the first DeployAll run
# because stale contract state in `.citrate-testnet-beta/` collided with the
# deployer's nonce. The fix was a hand-rolled SIGTERM + `rm -rf` + restart
# sequence that was invented on the spot and not documented anywhere. This
# script packages that sequence in a safe, reversible, explicitly-gated
# form so future rehearsals do not re-learn the same lesson.
#
# What it does:
#   1. Detects a running citrate-node listening on CEREMONY_RPC_PORT
#      (default 8545), SIGTERMs it, waits up to 10s, then SIGKILLs if
#      still alive. Prints "nothing to stop" when nothing is listening.
#   2. Archives the data directory by moving it aside with a timestamp,
#      not `rm -rf`. Archived dirs can be recovered with the printed
#      `mv` command.
#   3. Clears `contracts/broadcast/` and `contracts/cache/` so forge no
#      longer thinks stale deployments are current.
#   4. Prints a summary with the recovery command.
#
# Safety gates:
#   - Requires explicit opt-in: either `--reroll` flag or
#     CEREMONY_REROLL=1 environment variable.
#   - Refuses to fire in CEREMONY_MODE=real unless
#     CEREMONY_REROLL_REAL=1 is ALSO set. This is a two-key confirmation
#     for a destructive operation on real-ceremony state.
#   - Verifies it is running inside a Citrate repo checkout before
#     touching anything under contracts/.
#   - All failures exit non-zero without partial cleanup.
#
# Usage:
#   # Rehearsal reroll (default mode):
#   ./ceremony-reroll.sh --reroll
#
#   # Via env var:
#   CEREMONY_REROLL=1 ./ceremony-reroll.sh
#
#   # Override data dir / port:
#   CEREMONY_DATA_DIR=.citrate-devnet CEREMONY_RPC_PORT=8546 \
#     ./ceremony-reroll.sh --reroll
#
#   # Real-mode reroll (dangerous — two-key confirmation required):
#   CEREMONY_MODE=real CEREMONY_REROLL_REAL=1 \
#     ./ceremony-reroll.sh --reroll
#
# Exit codes:
#   0  reroll complete (or nothing to do)
#   1  safety gate refused (missing opt-in, wrong mode, etc.)
#   2  detected a listener but failed to stop it
#   3  filesystem operation failed (archive, mkdir, rm)
#
# ============================================================================
set -euo pipefail

# ---- Constants ----
readonly SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# REPO_ROOT defaults to this script's grandparent (the citrate_v0.01.1
# workspace) but can be overridden with CITRATE_REPO_ROOT so the reroll
# can be smoke-tested against a sandbox workspace without touching the
# real checkout.
if [ -n "${CITRATE_REPO_ROOT:-}" ]; then
    readonly REPO_ROOT="$CITRATE_REPO_ROOT"
else
    readonly REPO_ROOT="$( cd "$SCRIPT_DIR/../.." && pwd )"
fi
readonly DATA_DIR_RAW="${CEREMONY_DATA_DIR:-.citrate-testnet-beta}"
readonly BROADCAST_DIR="$REPO_ROOT/contracts/broadcast"
readonly CACHE_DIR="$REPO_ROOT/contracts/cache"
readonly RPC_PORT="${CEREMONY_RPC_PORT:-8545}"
readonly MODE="${CEREMONY_MODE:-rehearsal}"
readonly TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"

# Compute the absolute path of the data dir. Handle both absolute and
# relative specs. Relative paths are resolved against the current working
# directory, not the repo root, to match operator muscle memory.
if [[ "$DATA_DIR_RAW" = /* ]]; then
    readonly DATA_DIR="$DATA_DIR_RAW"
else
    readonly DATA_DIR="$PWD/$DATA_DIR_RAW"
fi

# ---- Colors ----
if [ -t 1 ]; then
    readonly RED='\033[0;31m'
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[1;33m'
    readonly CYAN='\033[0;36m'
    readonly BOLD='\033[1m'
    readonly NC='\033[0m'
else
    readonly RED=''
    readonly GREEN=''
    readonly YELLOW=''
    readonly CYAN=''
    readonly BOLD=''
    readonly NC=''
fi

log_step() { echo -e "${CYAN}[$(date -u +%H:%M:%S)]${NC} ${BOLD}$1${NC}"; }
log_ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
log_warn() { echo -e "  ${YELLOW}⚠${NC} $1"; }
log_err()  { echo -e "  ${RED}✗${NC} $1" >&2; }

# ---- Argument parsing ----
REROLL_REQUESTED="${CEREMONY_REROLL:-0}"
for arg in "$@"; do
    case "$arg" in
        --reroll)
            REROLL_REQUESTED=1
            ;;
        --help|-h)
            sed -n '2,60p' "${BASH_SOURCE[0]}" | sed 's/^# *//'
            exit 0
            ;;
        *)
            log_err "unknown argument: $arg"
            log_err "usage: $0 [--reroll]  (or set CEREMONY_REROLL=1)"
            exit 1
            ;;
    esac
done

# ---- Safety gates ----
if [ "$REROLL_REQUESTED" != "1" ]; then
    log_err "reroll requires explicit opt-in"
    log_err "  pass --reroll, or set CEREMONY_REROLL=1"
    exit 1
fi

if [ "$MODE" = "real" ] && [ "${CEREMONY_REROLL_REAL:-0}" != "1" ]; then
    log_err "refusing reroll in CEREMONY_MODE=real without CEREMONY_REROLL_REAL=1"
    log_err "  real-mode reroll destroys ceremony state. this is a two-key gate."
    exit 1
fi

# Sanity: verify we are inside a Citrate repo checkout. The presence
# of a top-level Cargo.lock + a contracts/ directory is enough.
if [ ! -f "$REPO_ROOT/Cargo.lock" ] || [ ! -d "$REPO_ROOT/contracts" ]; then
    log_err "not inside a Citrate workspace (no Cargo.lock or contracts/ under $REPO_ROOT)"
    log_err "  refusing to touch anything"
    exit 1
fi

log_step "ceremony-reroll :: $MODE mode :: data_dir=$DATA_DIR :: rpc_port=$RPC_PORT"

# ---- 1. Stop any running node on the RPC port ----
log_step "Step 1 — stop running node on port $RPC_PORT"

# ss -tlnp shows TCP listeners with PID. Sudo-free on Linux when
# listing your own processes; root to see others. Parse loosely.
stop_node_on_port() {
    local port="$1"
    local pid=""
    if command -v ss >/dev/null 2>&1; then
        pid="$(ss -tlnp 2>/dev/null | awk -v p=":$port" '$4 ~ p' \
            | grep -oP 'pid=\K[0-9]+' | head -1 || true)"
    elif command -v lsof >/dev/null 2>&1; then
        pid="$(lsof -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null | head -1 || true)"
    else
        log_warn "neither ss nor lsof available; cannot probe listener"
        return 0
    fi

    if [ -z "$pid" ]; then
        log_ok "nothing listening on port $port (nothing to stop)"
        return 0
    fi

    log_warn "found listener pid=$pid on port $port"
    if ! kill -TERM "$pid" 2>/dev/null; then
        log_err "failed to send SIGTERM to pid=$pid (not your process?)"
        return 2
    fi
    log_ok "sent SIGTERM to pid=$pid, waiting up to 10s"

    local i
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if ! kill -0 "$pid" 2>/dev/null; then
            log_ok "pid=$pid exited after ${i}s"
            return 0
        fi
        sleep 1
    done

    log_warn "pid=$pid still alive after 10s; sending SIGKILL"
    if ! kill -KILL "$pid" 2>/dev/null; then
        log_err "SIGKILL failed for pid=$pid"
        return 2
    fi
    # Give the kernel a beat to tear down the socket.
    sleep 1
    if kill -0 "$pid" 2>/dev/null; then
        log_err "pid=$pid survived SIGKILL (should be impossible — investigate)"
        return 2
    fi
    log_ok "pid=$pid killed"
}

if ! stop_node_on_port "$RPC_PORT"; then
    exit 2
fi

# Verify the port is actually free now.
if command -v ss >/dev/null 2>&1; then
    if ss -tln 2>/dev/null | awk '{print $4}' | grep -qE "[^0-9]$RPC_PORT\$|:$RPC_PORT\$"; then
        log_err "port $RPC_PORT is still in use after stop attempt"
        log_err "  something else is holding it — check manually before proceeding"
        exit 2
    fi
fi
log_ok "port $RPC_PORT is free"

# ---- 2. Archive the data directory ----
log_step "Step 2 — archive data dir $DATA_DIR"
archive_path=""
if [ -d "$DATA_DIR" ]; then
    archive_path="${DATA_DIR}.pre-reroll-${TIMESTAMP}"
    if ! mv "$DATA_DIR" "$archive_path"; then
        log_err "failed to move $DATA_DIR -> $archive_path"
        exit 3
    fi
    log_ok "archived $DATA_DIR -> $archive_path"
else
    log_ok "no existing data dir at $DATA_DIR (nothing to archive)"
fi

if ! mkdir -p "$DATA_DIR"; then
    log_err "failed to recreate empty data dir at $DATA_DIR"
    exit 3
fi
log_ok "created fresh $DATA_DIR"

# ---- 3. Clear forge broadcast + cache ----
log_step "Step 3 — clear forge broadcast + cache"
for dir in "$BROADCAST_DIR" "$CACHE_DIR"; do
    if [ -d "$dir" ]; then
        if ! rm -rf "$dir"; then
            log_err "failed to clear $dir"
            exit 3
        fi
        log_ok "cleared $dir"
    else
        log_ok "nothing to clear at $dir"
    fi
done

# ---- 4. Summary ----
log_step "reroll complete"
echo
echo "  mode           = $MODE"
echo "  data_dir       = $DATA_DIR  (empty, ready for fresh run)"
echo "  rpc_port       = $RPC_PORT  (free)"
if [ -n "$archive_path" ]; then
    echo "  archived_to    = $archive_path"
    echo
    echo "  to recover the archived state, run:"
    echo "    rm -rf '$DATA_DIR' && mv '$archive_path' '$DATA_DIR'"
else
    echo "  archived_to    = (nothing was there)"
fi
echo
echo "ready for a fresh ceremony rehearsal run."
