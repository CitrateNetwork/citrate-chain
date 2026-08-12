#!/usr/bin/env bash
# FORK-CHOICE-PARITY — producer store_block ⇒ ghostdag registration tripwire.
#
# ANCHOR INCIDENT
#   chain 40204 reroll wedge, 2026-08-12 — the sole validator wedged at exactly
#   height 101. node/src/producer.rs::produce_block stored each produced block
#   into the DAG store (`self.dag_store.store_block(block)`) but did NOT register
#   it into GhostDAG's in-memory tip set. Fork-choice authority for BOTH the
#   producer's parent-selection AND the drain's reorg is `GhostDag::select_tip`,
#   which reads `GhostDag.tips`. A produced block that never entered that set left
#   `select_tip` pinned to genesis while a fresh single-producer chain grew. The
#   MP-S1 "never propose backwards" clamp — bounded by SUPERSEDE_WALK_CAP = 100 —
#   masked it until the applied tip passed depth 100, then wedged at height 101.
#   THE FIX added `self.ghostdag.add_block(&block).await` right after the
#   `store_block` in produce_block (producer.rs:1372).
#
# INVARIANT ENFORCED (the CLASS, not the instance)
#   Any producer function that stores a locally-produced block into the DAG store
#   MUST also register that block into GhostDAG in the SAME function — via
#   `add_block(...)` (fresh block) or `register_existing_block(...)` (boot re-index)
#   — so the in-memory tip set that `select_tip` reads stays consistent with the
#   DAG store. A `store_block` with no accompanying registration is the fault.
#
#   This is deliberately scoped to the producer. Received blocks (admission.rs /
#   sync) already call add_block on their own store path; the boot eager-load
#   loops in producer.rs pair store_block with register_existing_block and are
#   the reason both registration forms are accepted.
#
# FALSE-POSITIVE AVOIDANCE
#   - Test code (`#[cfg(test)]` module) is excluded.
#   - Comments are stripped before matching, so the produce_block explanatory
#     comment that NAMES `add_block` cannot vacuously satisfy the check (the fix
#     must be REAL code, not prose — same discipline as the SRP tripwires).
#   - Eager-load loops satisfy the invariant via register_existing_block.
#
# Usage:
#   scripts/ci/fork_choice_add_block_parity_tripwire.sh              # scan producer.rs
#   scripts/ci/fork_choice_add_block_parity_tripwire.sh <file.rs>    # scan a specific file
#   scripts/ci/fork_choice_add_block_parity_tripwire.sh --self-test  # prove pos/neg fixtures
#
# Exit: 0 clean · 1 violation · 2 usage/setup error
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROD="$ROOT/node/src/producer.rs"

# scan_file <path> — prints one VIOLATION line per producer function that stores
# a block without a GhostDAG registration. Exit 0 = clean, 1 = violation(s).
#
# Engine: segment the file into top-level `fn` bodies by brace depth (comments
# stripped, and depth-tracking only begins once the body brace opens so that
# multi-line signatures don't truncate a function early). For each function whose
# (comment-stripped) body contains `store_block`, require `add_block` OR
# `register_existing_block` in that same body.
scan_file() {
    awk '
    function flush(   msg) {
        if (hasstore) {
            if (!hasreg) {
                printf "  VIOLATION: %s (L%d-%d) — dag_store.store_block(...) with no ghostdag.add_block / register_existing_block in the same function\n", fname, startln, NR
                viol++
            }
        }
    }
    BEGIN { infn=0; intest=0; viol=0 }
    # The test module is the tail of the file; everything after it is excluded.
    /#\[cfg\(test\)\]/ { intest=1 }
    intest { next }
    {
        strip=$0
        # Strip full-line // comments so prose that names add_block/register_existing_block
        # (e.g. the produce_block fix comment, or PIL-13 notes) cannot satisfy the check
        # and cannot unbalance brace depth.
        if (strip ~ /^[[:space:]]*\/\//) strip=""
        o = gsub(/\{/, "&", strip)
        c = gsub(/\}/, "&", strip)
        if (!infn) {
            if (strip ~ /(^|[^A-Za-z_])fn[ \t]+[A-Za-z_]/) {
                infn=1
                match(strip, /fn[ \t]+[A-Za-z_][A-Za-z0-9_]*/)
                fname=substr(strip, RSTART, RLENGTH); startln=NR
                bodyopen=(o>0); depth=o-c
                hasstore=(strip ~ /store_block/)
                hasreg=(strip ~ /add_block|register_existing_block/)
                if (bodyopen && depth<=0) { flush(); infn=0 }
            }
            next
        }
        if (strip ~ /store_block/) hasstore=1
        if (strip ~ /add_block|register_existing_block/) hasreg=1
        if (!bodyopen) { if (o>0) { bodyopen=1; depth=o-c } ; next }
        depth += o-c
        if (depth<=0) { flush(); infn=0 }
        next
    }
    END { exit (viol>0 ? 1 : 0) }
    ' "$1"
}

# ── self-test: prove the engine on the committed fixtures ───────────────────
if [ "${1:-}" = "--self-test" ]; then
    FIX="$ROOT/scripts/ci/fixtures"
    POS="$FIX/fork_choice_parity_positive.rs"
    NEG="$FIX/fork_choice_parity_negative.rs"
    for f in "$POS" "$NEG"; do
        [ -f "$f" ] || { echo "FORK-CHOICE-PARITY self-test: fixture $f not found" >&2; exit 2; }
    done
    rc=0
    echo "self-test: POSITIVE fixture (must flag)"
    if scan_file "$POS"; then
        echo "  FAIL: positive fixture did NOT trip the tripwire (engine is blind to the bug)" >&2
        rc=1
    else
        echo "  ok: positive fixture tripped as expected"
    fi
    echo "self-test: NEGATIVE fixture (must stay silent)"
    if scan_file "$NEG"; then
        echo "  ok: negative fixture stayed silent as expected"
    else
        echo "  FAIL: negative fixture tripped — store_block paired with a registration must NOT alert" >&2
        rc=1
    fi
    [ "$rc" -eq 0 ] && echo "FORK-CHOICE-PARITY self-test: PASS"
    exit "$rc"
fi

# ── main: scan the real producer (or an explicit file, for PR-time scoping) ──
TARGET="${1:-$PROD}"
[ -f "$TARGET" ] || { echo "FORK-CHOICE-PARITY tripwire: $TARGET not found" >&2; exit 2; }

out="$(scan_file "$TARGET")"; rc=$?
if [ "$rc" -ne 0 ]; then
    echo "FORK-CHOICE-PARITY VIOLATION in $TARGET:" >&2
    echo "$out" >&2
    echo >&2
    echo "A producer path stores a locally-produced block into the DAG store but never" >&2
    echo "registers it into GhostDAG. select_tip reads GhostDag.tips, so the produced" >&2
    echo "block never enters fork-choice — the exact chain-40204 reroll wedge (2026-08-12," >&2
    echo "sole validator wedged at height 101). Add self.ghostdag.add_block(&block) (fresh)" >&2
    echo "or register_existing_block(&block) (boot re-index) in the SAME function as the" >&2
    echo "store_block. Do NOT silence this by moving the store_block into a helper." >&2
    exit 1
fi

echo "FORK-CHOICE-PARITY tripwire: PASS (every producer store_block registers into GhostDAG)"
