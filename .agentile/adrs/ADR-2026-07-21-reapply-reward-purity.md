---
created: 2026-07-21T06:00:00Z
branch: srp/s2-reapply-reward-purity
author: Claude (Opus 4.8, 1M) directed by Larry Klosowski (@SaulBuilds)
status: proposed (G0 pending owner sign-off) — red test reproduces; mechanism PINNED
work_order: SRP-S2 — planset .agentile/planset/2026-07-21-srp-s2-reapply-reward-purity.md
repo: citrate-chain
spec: specs/tla/consensus/RewardApplyPurity.tla
depends-on: ADR-2026-07-21-state-root-purity.md (SRP-S1 — forward-root purity; necessary but did NOT cover reward settlement)
supersedes-context: handoffs/SRP_S2_REAPPLY_REWARD_PURITY_HANDOFF_2026-07-21.md
---

# ADR — SRP-S2: the reward-settled state root must be a pure function of committed state on every role

## Status

PROPOSED — blocks WP-2.1 (the fix) and WP-3.1 (the durable reroll). Must be red-teamed and G0
signed before the fix lands, and before any reroll (the chain is split-brain until the fix + a
clean reroll).

## Context

### The observed fault (live, reproduced — not theory)

On live chain 40204 (2026-07-21), restarting the sole miner (rpc-1) mid-operation during a fleet
binary hot-swap produced a **poisoned block 2209**: an empty, single-parent, post-activation
block whose committed `stateRoot` (`0x237bf250…`) **no honestly-synced node can reproduce**. Every
fresh boot re-executing block 2209 on the agreed 2208 state computes a *different* root
(`0x52e54249…`) and hard-rejects the block (`state root mismatch`), freezing its applied tip at
2208 while the DAG head advances → **split-brain**. No fresh node — including citrate-core — can
sync past 2209.

SRP-S1 (ADR-2026-07-21-state-root-purity) proved the **forward** state root is a pure function of
committed accounts+storage. It did **not** cover the reward-settlement path across node roles.
This is the gap it left.

### Root cause — PINNED by a live in-process reproduction

`node/src/producer.rs:899` selects the block-reward path from a **transient, node-local runtime
flag**, not from committed consensus state:

```rust
let use_enhanced = self.economics_manager.is_some() && !self.emit_v2_headers;
```

In production, `BlockProducer::with_shared_dag` **always** sets `economics_manager: Some(..)` and
constructs with `emit_v2_headers: false`; the flag is flipped to `true` only by a *later*
`with_v2_headers(true)` builder call. Any moment `use_enhanced` is `true`, `produce_block` takes
the **enhanced path** (`producer.rs:900–935`), which:

- credits a reward derived from **non-committed, node-local state** — the economics manager's
  staked balance, an `f64` `reputation_score`, and dynamic gas pricing — **directly** to the
  validator via `set_balance`;
- credits **no** treasury slice;
- **never calls** `settle_block_rewards`, so it applies **neither** the canonical basic block
  reward **nor** the §R' priority-fee vesting.

A RECEIVER's `Executor::apply_block` **always** settles through the canonical committed-state path
(`settle_block_rewards`: fixed 9 SALT validator + 1 SALT treasury, then §R'). It therefore
**cannot reproduce** the producer's enhanced credit → different root → `StateRootMismatch`.

The reproduction (`node/src/producer.rs`, test
`srp_s2_producer_receiver_reward_parity_on_restart_empty_block`) drives the **real** `produce_block`
entrypoint with a production-shaped producer (economics = Some, `emit_v2_headers` = false) that
seals one empty post-activation block, then re-applies it on an independent executor via
`apply_block`. On `main` it fails with:

```
StateRootMismatch { expected: 0x6f1d8584… (producer, enhanced: validator += 0.01 SALT),
                    got:      0xdf1c59d0… (receiver, canonical basic: 9 SALT + 1 SALT treasury) }
```

This is the block-2209 class exactly: **the producer's reward-settlement effect is not
reproducible by a clean re-apply.**

### Why the existing tests missed it

`core/execution/tests/rprime_priority_fee_parity.rs` proves producer↔receiver parity — but it
calls `Executor::settle_block_rewards` **directly**, bypassing `produce_block`'s `use_enhanced`
gate. The buggy branch was never on any test path. The fleet-fork guarantee was asserted one layer
*below* where the fork is decided.

## Decision

1. **One reward derivation, from committed state, on every role.** The block reward (basic + §R')
   is settled through the **single** `Executor::settle_block_rewards` path — the same function the
   receiver, cold-sync, restart, and reorg paths already use — on the producer too. The reward is a
   pure function of committed state (`header.height`, committed txs/receipts, the committed §R'
   epoch policy). No role may derive a reward from node-local/transient state.

2. **Kill the enhanced path unconditionally.** The node-local "enhanced" reward path
   (`producer.rs:900–935`) is **removed**. Chain 40204 is execute-on-receive / v2-only (the legacy
   v1 model is dead — see the v2-default binary), so any reward path that reads non-consensus state
   is a latent fork and has no valid remaining use. `economics_manager` remains for RPC/telemetry
   but MUST NOT influence a block's committed reward. `emit_v2_headers` MUST NOT gate reward
   selection.

3. **Producer hard-fails; it never silently diverges.** With the enhanced branch gone, the
   producer settles via `settle_block_rewards_guarded`, which already **aborts production** on any
   settlement error (leaving state byte-identical). A producer that cannot settle from committed
   state produces **no block** rather than a poisoned one. There is no "credit something node-local
   and move on" arm.

4. **Regression fence.** A red test that drives the **real** `produce_block` entrypoint (not just
   `settle_block_rewards`) and asserts producer↔receiver root parity is committed and kept green.
   A CI tripwire forbids reintroducing any `set_balance`-based reward credit outside
   `settle_block_rewards`.

## Consequences

- **Positive:** producer and receiver compute byte-identical reward-settled roots by construction;
  a miner (or any node) can restart mid-operation without poisoning a block; the reward-settled
  root is pure across producer/receiver/cold-sync/restart/reorg. Recovery becomes: land this fix →
  one clean reroll on the fixed binary → the split-brain is resolved and citrate-core cold-sync +
  close/reopen hold.
- **Negative / accepted:** the "enhanced" economics rewards (staking/reputation/congestion bonuses)
  are gone from block production. They were never consensus-safe under execute-on-receive and were
  the fault. If differentiated validator economics are ever wanted, they must be expressed as
  **committed on-chain state** settled through `settle_block_rewards` (e.g. via the §R' policy), not
  as a node-local producer credit. Tracked separately; out of scope for SRP-S2.
- **Reroll required:** the fix is Rust-only and moves no CREATE2 address (address book UNCHANGED),
  but the live chain is split-brain and cannot be un-poisoned in place — Phase 3 does one clean
  durable reroll on the fixed binary.

## Red-team notes

- *"Just ensure `emit_v2_headers` is always true after restart."* — Rejected. That keeps a
  consensus reward gated on a transient flag; any future refactor, env slip, or ordering change
  re-opens the fork. Removing the branch removes the failure mode, not just this instance.
- *"Keep the enhanced path for v1 devnets."* — Rejected. v1 is dead on 40204; a dual reward path is
  exactly the divergence surface. The basic path is correct for v1 too (it simply skips §R' below
  activation).
- *"Empty blocks vest nothing (share == 0), so the reward is trivial."* — The **basic** block
  reward is non-zero on an empty block (10 SALT → 9 + 1); the producer skipping it while the
  receiver applies it is the whole divergence. The §R' early-return is irrelevant to the fault.
- *"Could the divergence be the §R' policy/selector rehydration instead?"* — For an **empty** block
  §R' early-returns on `share.is_zero()` before any policy-dependent credit, so policy differences
  cannot change an empty block's root. The reproduction isolates the basic-reward path as the sole
  cause, matching the empirical 2209 (empty block).
