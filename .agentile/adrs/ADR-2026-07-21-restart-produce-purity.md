---
created: 2026-07-21T09:00:00Z
branch: srp/s3-restart-produced-purity
author: Claude (Opus 4.8, 1M) directed by Larry Klosowski (@SaulBuilds)
status: proposed (G0 pending owner sign-off) — mechanism CONFIRMED by a passing red test
work_order: SRP-S3 — restart-produced / resident-set state-root purity
repo: citrate-chain
spec: specs/tla/consensus/RestartProducePurity.tla
depends-on: ADR-2026-07-21-state-root-purity (SRP-S1, forward root), ADR-2026-07-21-reapply-reward-purity (SRP-S2, reward path)
supersedes-context: handoffs/SRP_S2_REROLL_EXECUTION_STATUS.md (§ SRP-S3)
---

# ADR — SRP-S3: the state root must be independent of resident-account residency (EIP-158)

## Status

PROPOSED — blocks the fix landing and the final restart-durable reroll. The chain is split-brain
(block 2042) until this lands + a clean reroll.

## Context

### The observed fault (live + reproduced)

After the SRP-S2 reroll, the fleet crossed activation 2000 with 0 mismatches (SRP-S1 + SRP-S2 both
proven). The restart-resilience gate (G9) then restarted the sole miner (rpc-1) mid-epoch,
post-activation. The FIRST post-restart block (2041) was reproduced fine by the followers; the
SECOND — block **2042, EMPTY (gasUsed 0)** — committed a root (`0x8c7c1675…`) that every honest
follower re-executing on the agreed 2041 state computes differently (`0x01a6b4a6…`) and rejects →
split-brain (followers frozen at applied-2041, miner solo-advancing). Same class as block 2209.

### Root cause (confirmed by elimination + a passing Rust red test)

On an EMPTY block the consensus root has exactly one input, and every other candidate is proven
inert: the reward is the single shared `settle_block_rewards` (byte-identical basic credit on both
roles; §R' early-returns on `share.is_zero()` before any REVM system-call); the enhanced path is
gone (SRP-S2); no transactions execute. The sole remaining input is:

> `StateDB::calculate_state_root` (`core/execution/src/state/state_db.rs:243`) rebuilds the trie
> every call by folding **`AccountManager::all_accounts()` — the volatile in-memory RESIDENT
> account map** (`:265`).

That resident map is **node-local and history-dependent**: accounts enter it lazily via
non-dirtying read-through (`load_account`), the map is never evicted on the success path, and a
restart re-derives it by bulk-loading the store (`main.rs:1018-1048`). SRP-S1 even states the
load-bearing assumption it never enforced: *"The resident map is never evicted; a restarted node
fully hydrates it first"* (`state_db.rs:261`).

The decisive facet: an **EMPTY account** (nonce 0, balance 0, no code, no storage, no perms —
carrying NO committed state) can be RESIDENT on one node but ABSENT on another **with identical
committed state**, because one node materialized it via a read-through / restart reconstruction and
the other did not. Folding it changes the root. An empty block is where this surfaces because it
runs no execution to re-materialize accounts — it folds the reconstructed image raw.

Confirmed by `core/execution/src/state/state_db.rs::srp_s3_resident_empty_account_must_not_change_root`:
two `StateDB`s with **byte-identical committed state**, one with a single extra resident empty
account, compute **different roots** on `main` — and equal roots after the fix.

This is the SRP class again (root = f(node-local history)), on the surface SRP-S1 (dirty
accumulator) and SRP-S2 (reward path) did not cover: **resident-set membership across restarts.**

## Decision

1. **EIP-158 empty-account exclusion (the class fix).** An empty account is indistinguishable from
   an absent one and MUST NOT be folded into the state root. `calculate_state_root` skips any
   account that is empty *after* its live storage_root is recomputed (`AccountState::is_empty()`).
   The folded set is then exactly the NON-EMPTY (committed-state-bearing) accounts — a pure function
   of committed state, identical across producer / receiver / cold-sync / restart / reorg,
   regardless of which empty accounts a node happened to materialize.

2. **Boot HARD-FAIL on root mismatch (safety net, SRP-S2 philosophy).** A node whose hydrated
   in-memory root does not reproduce the committed persisted root MUST refuse to start (was
   warn-and-continue at `main.rs:1072`). A node that cannot reconstruct the committed root can never
   safely produce or apply — hard-fail converts a silent fork into a safe local stop.

3. **Roots change; addresses do not.** Excluding empty accounts changes state-root *values*
   (including genesis), so the final reroll produces a **new genesis root/hash**. It moves **no
   CREATE2/contract address** (addresses derive from deployer+salt+initcode, not the state root), so
   the frozen `contracts/addresses/40204.json` stays valid — the reroll remains address-neutral.
   All genesis-hash references in handoffs are updated to the new deterministic value at reroll time.

4. **Regression fence.** The red test above is kept green; a CI tripwire forbids re-introducing an
   unconditional empty-account fold or reverting the boot check to warn-only.

## Consequences

- **Positive:** the state root is a pure function of committed state across restarts and reorgs; a
  miner or follower can be restarted mid-operation without poisoning a block; the durable
  restart-resilience gate (G9 — restart BOTH a follower and the miner) can pass. This closes the
  last known SRP surface.
- **Negative / accepted:** state-root values change (new genesis). This is correct and standard
  (Ethereum excludes empty accounts from the state trie). One clean reroll absorbs it.
- **Deferred hardening (tracked, not blocking):** a per-block producer "cold re-apply" purity gate
  (re-derive the sealed root on a store-only-hydrated executor, abort on mismatch) would catch any
  future non-empty residency/representation drift at the source; omitted now for per-block cost
  since EIP-158 closes the confirmed class and the boot hard-fail covers restart reconstruction.

## Red-team notes

- *"Just make hydration provably complete instead of changing the root."* — Rejected as primary:
  hydration completeness cannot prevent an empty account being materialized on one node and not
  another during normal read-through; the root must not depend on empty residency at all. EIP-158
  removes the dependence entirely.
- *"Could the divergent account be NON-empty (a storage/representation drift)?"* — For an empty
  block the reward accounts are byte-identical on both roles and hydration loads all persisted
  non-empty accounts+storage, so a non-empty divergence is excluded for the observed fault; the
  red test isolates the empty-account fold as the cause. The boot hard-fail + the deferred producer
  gate cover any hypothetical non-empty variant safely (stop, never fork).
- *"Does skip-empty drop a legitimately-zero account (e.g. a drained EOA)?"* — Yes, and correctly:
  a zero-balance/zero-nonce/no-code/no-storage account holds no committed state; excluding it is
  consistent across all roles (a pure function of the account's own fields), so it cannot cause
  divergence. This is exactly EIP-158.
- *"Genesis root changes — does that break the federation?"* — No: contract addresses are
  unchanged (address-neutral). Only the genesis state root / block hash changes, expected for a
  fresh reroll; handoffs are updated to the new value.
