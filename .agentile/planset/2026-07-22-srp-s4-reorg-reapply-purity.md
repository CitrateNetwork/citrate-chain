---
title: SRP-S4 — reorg/fork reapply state-root purity (the block-5,406 cold-sync wedge)
created: 2026-07-22
updated: 2026-07-23
branch: srp/s4-reward-rmw-store-purity
author: Claude (DGX / chain-ops session)
status: OPEN — mechanism localized to the fork/reorg path; exact account + fix gated on a local multi-producer reorg reproduction (WP-1.2)
supersedes: none
related: .agentile/planset/2026-07-21-srp-s3-restart-produce-purity.md, ../../citrate-core/docs/DGX_NODE_SYNC_WEDGE_RESPONSE_2026-07-22.md
history: originally scoped as "reward RMW / store read-through purity"; DGX instrumentation on 2026-07-23 REFUTED that mechanism (reward reads are pure) and re-localized it to the fork/reorg reapply path — see "What the live instrumentation proved".
---

# SRP-S4 — reorg/fork reapply state-root purity

## TL;DR

After SRP-S1/S2/S3 (all merged to `main` `f9c1551`, all their red tests green), a
from-genesis cold-sync of chain 40204 still wedges at **block 5,406**:
`state root mismatch (claimed 2d9381d2, computed 55286580)`. DGX instrumentation
(2026-07-23) proved this is **NOT** the reward read-modify-write (the reward reads are
pure) — it is a **fork/reorg reapply impurity**: block 5,406 is a **forked** height on
the live chain, and its committed root is not reproducible by a clean forward execution
**or** by the reorg reapply of the winning branch. The live chain survives only because
the producers run continuously; no fresh node can join past 5,406, and a clean reroll on
the current binary re-exposes it.

## What the live instrumentation proved (2026-07-23, DGX)

An **instrumented cold-sync against the LIVE chain** (env-gated `CITRATE_SRP_DEBUG`
logging every reward account's read value + resident/read-through flag) wedged at 5,406
and showed:

- **The basic-reward reads are PURE and RESIDENT** at 5,404/5,405/5,406:
  `treasury 0x1111…` = height−1 SALT (`resident=true`, +1/blk),
  `coinbase 0x0ecbcd85` = +9/blk (`resident=true`). **No store read-through, no anomaly.**
  → **REFUTES** the original "reward RMW reads a divergent store" hypothesis. The
  cold-sync computes a *correct* 5,406 state; the **producer committed the impure root**.
- **The wedge occurs in a REORG context.** The cold-sync log:
  `execute-on-receive: reorg to 968feeaf aborted at 117449ba — State root mismatch:
  block claims 2d9381d2, re-execution produced 55286580 (reverted to 3df034c2)`.
  Block 5,406 is a **forked height** — canonical `117449ba` (committed root `2d9381d2`)
  vs a competing DAG tip `968feeaf`. Neither the forward execution of the canonical
  block nor the reorg reapply of the competitor reproduces the committed root; both
  produce `55286580`.
- **A local single-producer chain does NOT reproduce it.** A local §R'-active chain
  (registry `0x915DdE02`, one validator, activation 2000) cold-synced clean to 6,207.
  The missing ingredient is a **fork/reorg** — which a single producer never creates.

## Mechanism (localized, not yet pinned to the account)

The impurity lives in the **fork/reorg reapply path**, `node/src/canonical_apply.rs`:

- `reorg_to` (`:486`) `state_restore`s the executor to a fork-point snapshot from the
  reorg ring, then re-applies the winning branch. The **§R' reward-policy cell is NOT
  part of `state_snapshot`** (`:27-31`), so it is captured/restored *separately*, and a
  **`registry_policy_resync` hook re-materializes the policy INSIDE the reapply loop at
  each crossed S(E)** (`:191-195`) so "the reapplied blocks' state roots are current".
- Existing tests (`reorg_across_snapshot_reproduces_cross_policy_branch`,
  `aborted_cross_policy_reorg_restores_reward_policy`) exercise cross-policy reorgs and
  **pass** — but they use a **CODELESS registry** (canonical_apply.rs:2133, 3256: "the
  registry here is codeless so its BALANCE is the on-chain vested-share"), so they
  **never exercise the §R' `creditReward` REVM storage-write path across a reorg**.

### PINNED ACCOUNT (code-grounded, 2026-07-23): the `ValidatorRegistry` STORAGE

The divergence is in the **`ValidatorRegistry` contract (`0x915DdE02`) storage** — the
`_validators` bonded-stake / `vestedRewards` mapping slots REVM writes during §R'
`creditReward`. The load-bearing facts:
- `StateDB::snapshot` DOES capture `storage_tries` + `dirty_storage` (state_db.rs:326),
  so a reorg `state_restore` rolls storage back — the divergence is NOT lost-on-restore;
  it is introduced when the **reapply re-executes `creditReward`**.
- `credit_validator_reward` (executor.rs:1426-1439) has a **storage/balance SPLIT**: REVM
  writes the registry's storage (vestedRewards/bonded), but `StateDBAdapter::commit`
  DISCARDS REVM's balance/nonce writes and the executor reconciles only the BALANCE. On a
  reorg reapply this split can leave the registry's REVM-written STORAGE diverged from a
  clean forward execution while the balance matches.
- The reward BALANCES (treasury/coinbase) are pure (proven by live instrumentation) —
  the divergence is one layer down in **contract storage**, invisible to the codeless
  test registry. Its divergent storage-root folds into EVERY subsequent state root and
  surfaces at the forked empty block 5,406.

> One-line statement: **a state root committed for a FORKED block (5,406) is not a pure
> function of committed state — the fork/reorg reapply re-executes §R' `creditReward` and
> leaves the `ValidatorRegistry`'s REVM-written STORAGE diverged (balance matches,
> storage-root does not), which no clean forward execution reproduces.**

(Empirical confirmation of the exact slot = WP-1.1 below: an in-process reorg test with a
**code-ful** registry + a §R'-vesting forked block, asserting per-storage-slot equality —
which the codeless tests structurally cannot do. This is the strong hypothesis the fix
targets; WP-1.1/1.2 turn it into a RED test.)

## The acceptance oracle (unchanged from S1–S3, extended)

A from-genesis cold-sync must match the winning branch on the state ROOT **and
per-account balance and per-storage-slot** at every height, INCLUDING forked heights.
SRP-S4 adds: **the root a node commits for a block must equal the root a clean forward
execution of that block computes — even when the block is on a reorged/forked branch.**

## Phases

### Phase 0 — Spec + ADR (G0)
| WP | Title | Acceptance |
|----|-------|-----------|
| **WP-0.1** | `specs/tla/consensus/ReorgReapplyPurity.tla` (+ `.cfg` + `_buggy.cfg`) — model two branches forking before an S(E); a role that reorgs across S(E) must commit the same per-block roots a forward execution of that branch commits. | TLC clean on the fix config; buggy (policy-cell/state not fully restored on reapply) VIOLATES `RootAgreement`. |
| **WP-0.2** | `.agentile/adrs/ADR-2026-07-23-reorg-reapply-purity.md` — decision + ≥2 adversarial red-team passes. | Accepted + red-teamed. |

### Phase 1 — Reproduce + PIN the exact account (G1)
| WP | Title | Acceptance |
|----|-------|-----------|
| **WP-1.1** | Extend the `canonical_apply` reorg harness to a **CODE-FUL `ValidatorRegistry`** (not the codeless test stub) that actually vests via `creditReward`, then reorg across the S(E) fork and assert **per-storage-slot** equality of the registry AND `reapplied_root == clean_forward_root`. This is the empirical confirmation of the PINNED ACCOUNT above. RED on `main` (registry storage-root diverges), GREEN after the fix. | A deterministic in-process reorg red test with a code-ful registry that FAILS on `main` on a registry storage slot. |
| **WP-1.2** | **Local multi-producer reorg reproduction** (the DGX harness `scripts/ci/srp_s4_coldsync_harness.sh`, extended to a SECOND competing producer that forks across an S(E)), + instrument `calculate_state_root` to dump the fold on both branches → `state-digest`/log-diff to NAME the exact account/slot the fork leaves diverged. | The exact account/slot is named; WP-1.1 reproduces that case. |

### Phase 2 — Fix (G2)
| WP | Title | Acceptance |
|----|-------|-----------|
| **WP-2.1** | Make fork resolution / reorg reapply a pure function of committed state: `state_restore` restores the FULL folded state (resident map + store) and the §R' policy cell so the reapplied/committed root == forward-execution root. | WP-1.1 RED→GREEN; SRP-S1/S2/S3 red tests + tripwires still pass; `citrate-execution` + `node` suites green (ratchet ≥ current); a new `scripts/ci/srp_s4_reorg_purity_tripwire.sh`. |

### Phase 3 — Clean reroll + durable proof (G3)
| WP | Title | Acceptance |
|----|-------|-----------|
| **WP-3.1** | ONE clean reroll on the SRP-S4 binary (both arches). Prove DEEP + FORKED: a fresh external cold-sync crosses forked heights and tracks the tip with 0 mismatches AND per-account/per-slot equality; the citrate-core bundled node (Linux + Mac) cold-syncs + close/reopen. | Deep+forked cold-sync 0 mismatches on all 4; citrate-core cold-syncs to tip; update `citrate-core/docs/DGX_NODE_SYNC_WEDGE_RESPONSE_2026-07-22.md` with the SRP-S4 resolution + new genesis. |

## Decision (for the ADR, to be red-teamed)

The state root a node commits for ANY block — forward-produced, received, reorged-to, or
reapplied after a fork — must equal the root a clean forward execution of that block
computes from committed state. The fix ensures fork resolution restores the FULL folded
state (resident account map + storage sub-tries + the §R' policy cell) so no fork branch
can commit a root a clean replay cannot reproduce — extending SRP-S1..S3's purity
guarantee to the fork/reorg-reapply path.

## Interim unblock (no reroll) — for citrate-core

Ship the app a **state snapshot** (a synced data dir at/near tip) that `NodeManager`
loads and follows live from, bypassing cold-sync. A node that never replays past the
forked wedge never hits it.

## Status of the committed red test

`core/execution/tests/srp_s4_reward_rmw_purity.rs` asserts the get_balance/store
read-through INVARIANT. That invariant is still worth guarding, BUT the live evidence
proved it is **NOT** the 5,406 mechanism (reward reads are pure). It is retained as a
defensive property test and clearly re-annotated; the authoritative SRP-S4 reproduction
is the reorg red test (WP-1.1) + the multi-producer pin (WP-1.2).

## Live-chain status

Chain 40204 (SRP-S3c reroll) is cold-sync-broken past the 5,406 fork and must NOT be
quick-rerolled on the current binary. Producers + boots stay up on continuous uptime.
`PR #94` and any reroll wait on SRP-S4.
