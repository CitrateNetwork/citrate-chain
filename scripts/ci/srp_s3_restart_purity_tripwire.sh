#!/usr/bin/env bash
# SRP-S3 — restart-produce / resident-set state-root purity tripwire (regression fence).
#
# The block-2042 split-brain came from `StateDB::calculate_state_root` folding the volatile
# in-memory RESIDENT account map, so an EMPTY account materialized on one node (via read-through
# or a restart reconstruction) but not another — with identical committed state — changed the
# consensus root. Fix: EIP-158 — an empty account is indistinguishable from an absent one and MUST
# NOT be folded (`AccountState::is_empty()` + a skip in the fold). Plus: a node whose hydrated root
# does not reproduce the committed persisted root must HARD-FAIL at boot (not warn-and-continue).
# See .agentile/adrs/ADR-2026-07-21-restart-produce-purity.md and the red test
# `srp_s3_resident_empty_account_must_not_change_root`.
#
# This gate FAILS if either protection is removed. Usage: scripts/ci/srp_s3_restart_purity_tripwire.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SDB="$ROOT/core/execution/src/state/state_db.rs"
TYP="$ROOT/core/execution/src/types.rs"
MAIN="$ROOT/node/src/main.rs"
for f in "$SDB" "$TYP" "$MAIN"; do [ -f "$f" ] || { echo "SRP-S3 tripwire: $f not found" >&2; exit 2; }; done

fail=0

# 1) `calculate_state_root` MUST skip empty accounts (EIP-158). Look for an is_empty()-guarded
#    `continue` in the fold. (The fold folds `all_accounts()`; without the skip the root depends
#    on empty-account residency.)
if ! grep -Eq 'is_empty\(\)' "$SDB"; then
    echo "SRP-S3 VIOLATION: calculate_state_root no longer excludes empty accounts (EIP-158 skip removed) in state_db.rs" >&2
    fail=1
fi

# 2) `AccountState::is_empty` MUST exist (the EIP-158 predicate).
if ! grep -Eq 'fn is_empty\(&self\) -> bool' "$TYP"; then
    echo "SRP-S3 VIOLATION: AccountState::is_empty() removed from types.rs" >&2
    fail=1
fi

# 3) The boot root check MUST hard-fail (return Err), not warn-and-continue.
if ! grep -Eq 'SRP-S3 boot halt|SRP-S3 BOOT HALT' "$MAIN"; then
    echo "SRP-S3 VIOLATION: boot state-root mismatch no longer hard-fails (reverted to warn-only) in main.rs" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "SRP-S3 restart-purity tripwire: PASS (empty accounts excluded from the root; boot hard-fails on mismatch)"
fi
exit "$fail"
