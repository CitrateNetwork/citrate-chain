#!/usr/bin/env bash
# SRP-S2 — reward/re-apply state-root purity tripwire (source-level regression fence).
#
# The block-2209 split-brain came from `BlockProducer::produce_block` selecting a
# node-local "enhanced" reward path (a reward derived from the economics manager's
# staked balance / f64 reputation / dynamic pricing, credited straight to the
# validator with NO treasury and NO on-book settlement) on a transient runtime flag
# (`emit_v2_headers`). A receiver re-applying the same block through the canonical
# committed-state path could never reproduce it → StateRootMismatch → fork.
#
# The fix removed that branch: block rewards are settled ONLY through
# `Executor::settle_block_rewards[_guarded]`, a pure function of committed state,
# identical on producer + receiver + cold-sync + restart + reorg. See
# .agentile/adrs/ADR-2026-07-21-reapply-reward-purity.md and the red test
# `srp_s2_producer_receiver_reward_parity_on_restart_empty_block`.
#
# This gate FAILS if the node-local reward path is reintroduced into producer.rs.
# Usage: scripts/ci/srp_s2_reward_purity_tripwire.sh   (run from repo root)
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROD="$ROOT/node/src/producer.rs"
[ -f "$PROD" ] || { echo "SRP-S2 tripwire: $PROD not found" >&2; exit 2; }

fail=0

# Strip full-line `//` comments so the checks match ACTUAL code, never the prose that
# documents the fix (which necessarily names the removed constructs).
CODE="$(grep -vE '^\s*//' "$PROD")"

# 1) The enhanced-vs-basic reward SELECTION binding must not return. `let use_enhanced`
#    gated a consensus reward on a transient node-local flag — the exact fault. (Prose
#    references the identifier in backticks; only the `let` binding is real code.)
if printf '%s\n' "$CODE" | grep -nE 'let\s+use_enhanced\b' >/dev/null; then
    echo "SRP-S2 VIOLATION: 'let use_enhanced' reward-path selection reintroduced in producer.rs" >&2
    fail=1
fi

# 2) The enhanced reward system's credit identifiers must not return (underscore-joined
#    tokens appear only in the removed code, never in prose).
if printf '%s\n' "$CODE" | grep -nE '\b(staking_bonus|reputation_bonus|congestion_bonus|reputation_score)\b' >/dev/null; then
    echo "SRP-S2 VIOLATION: node-local enhanced-reward crediting reintroduced in producer.rs" >&2
    printf '%s\n' "$CODE" | grep -nE '\b(staking_bonus|reputation_bonus|congestion_bonus|reputation_score)\b' >&2
    fail=1
fi

# 3) The block reward must NEVER be credited via a raw set_balance in the producer;
#    it must flow through settle_block_rewards[_guarded]. There must be NO set_balance
#    on the executor anywhere in producer.rs source (the reward credit was the only one).
if printf '%s\n' "$CODE" | grep -nE 'self\.executor\.set_balance' >/dev/null; then
    echo "SRP-S2 VIOLATION: raw set_balance on the executor in producer.rs (rewards must use settle_block_rewards)" >&2
    printf '%s\n' "$CODE" | grep -nE 'self\.executor\.set_balance' >&2
    fail=1
fi

# 4) The committed-state settlement call MUST still be present (the fix must not be
#    silently gutted).
if ! grep -nE 'settle_block_rewards_guarded' "$PROD" >/dev/null; then
    echo "SRP-S2 VIOLATION: producer no longer calls settle_block_rewards_guarded (committed-state settlement removed)" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "SRP-S2 reward-purity tripwire: PASS (producer settles rewards only from committed state)"
fi
exit "$fail"
