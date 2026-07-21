---
created: 2026-07-21T00:00:00Z
branch: main
author: Claude (Opus 4.8, 1M) directed by Larry Klosowski (@SaulBuilds)
status: accepted (G0 signed 2026-07-21 — red-team findings folded in below)
work_order: SRP (State-Root Purity) — planset .agentile/planset/2026-07-21-srp-state-root-purity.md
repo: citrate-chain
spec: specs/tla/consensus/StateRootPurity.tla (TLC: no error)
supersedes-partial: the calculate_state_root idempotency fix (PR #88) — necessary but insufficient
---

# ADR — SRP: the consensus state root must be a pure function of committed state

## Status

PROPOSED — blocks all SRP implementation WPs. Must be reviewed + red-teamed and the
gate G0 signed before any code lands (Agentile ADR-first for consensus changes).

## Context

### The observed fault (evidence, not theory)
On live chain 40204 (2026-07-20), a cold-syncing node (both aarch64 **and** x86_64 —
so NOT cross-architecture) wedged at the first empty post-activation block: it
re-executed the block on the correct parent state and computed state root `de169b8d`,
while the block (and the entire 4-node fleet) committed `493c3226`.

The decisive measurement: querying each fleet node directly for the **same** block 2557:

| node | block-2557 `stateRoot` | coinbase `eth_getBalance` @2557 |
|---|---|---|
| rpc-1 | `0xef0ca623…` | `0xc5e5bb45…` |
| boot1/2/3 | `0xef0ca623…` | `0x691b4bac…` |

**All four nodes agree on the consensus state root but hold different committed
balances at that block.** This is impossible if the root is a function of state. The
reroll's "determinism proof" measured roots (which matched) while the underlying
balances silently diverged. The chain is subtly non-deterministic *today*.

### Root cause (exact, file:line)
`StateDB::calculate_state_root` (`core/execution/src/state/state_db.rs:243-276`) folds
**only the currently-dirty accounts** (`:247`) into a **persistent, never-rebuilt**
accumulator trie `state_trie` (`:32`), then returns its root (`:275`). `commit`
(`:279-284`) clears the dirty set immediately after (`:281`). Therefore the root is a
function of each node's **dirty/insertion history**, not of committed state.

An account whose true committed balance was last written through a path that did **not**
leave it dirty for the block being sealed is **omitted from that block's fold**, and the
trie retains a *stale* value for it. Three such paths exist:
1. **Zero-amount reward guard** — `settle_block_rewards` step 1 credits only when
   `amount > U256::zero()` (`core/execution/src/executor.rs:1281`); a zero-reward block
   never dirties the coinbase, so it is not re-folded.
2. **Non-dirtying read-through** — `get_balance` on a resident miss `load_account`s the
   store value without marking dirty (`executor.rs:755-766`, `account.rs:43-46`).
3. **Eager store write bypassing the fold** — `set_balance` writes straight to the store
   when `defer_persist` is false (`executor.rs:805-818`), independent of the trie.

`eth_getBalance` reads the **store** via `get_canonical_account` (`executor.rs:646-652`),
so the store/resident representation drifts while the trie-derived root stays "consistent"
across warm nodes that share the identical accumulation history. A cold node rebuilds a
different history from genesis and folds the **true** balance, diverging.

PR #88 fixed the *insertion-order* and *storage-root-side-effect* facets
(`state_db.rs:248`, `:254-263`) but not the **accumulator staleness** — that is why the
symptom moved rather than disappeared.

## Decision

**The consensus state root MUST be a pure, history-independent function of the full
committed account + storage state, identical whether the node produced, gossip-received,
or cold-synced the block.** Formalized as `specs/tla/consensus/StateRootPurity.tla`
(invariants `Purity`, `RootAgreement`, `BalanceConservation`, `CrossRoleConvergence`;
TLC: *no error*). Concretely:

1. **Root over the authoritative committed set — precisely defined (amended per red-team
   Finding 2).** The authoritative source at root-computation time is the
   **never-evicted, fully-hydrated resident state** (`AccountManager.accounts` +
   `storage_tries`), NOT the durable store. Rationale: the store is deliberately STALE at
   root time — it is written *after* the root is computed (`apply_block_inner`:1134 root,
   :1148 persist) and it intentionally holds the ABANDONED branch during a reorg reapply
   (`reconcile_store_from` runs only after the reorg settles). **Reading the store during
   root computation is therefore FORBIDDEN** — it would fold pre-persist-lagged or
   abandoned-branch rows. The resident set is a complete authority *iff* two properties
   hold, which the fix must guarantee: (a) accounts/slots are NEVER evicted from the
   resident maps (true today — no eviction path), and (b) on **restart** the node FULLY
   hydrates the resident maps from the store before computing any root or serving. Given
   (a)+(b), `calculate_state_root` derives the trie from the full resident committed set
   each call — every account/slot represented at its current value, no reliance on "was it
   dirtied this block."
2. **Storage sub-tries are the SAME bug — in scope for S1 (red-team Finding 1, CRITICAL).**
   `calculate_state_root` folds `account.storage_root = storage_trie.root_hash()`
   (`state_db.rs:257-258`) off the persistent, never-rebuilt per-contract `storage_tries`
   accumulator (`state_db.rs:20`), which hydrates lazily/per-slot (`revm_adapter.rs:261-296`
   `cache_storage`) — so a warm/restarted node computes `storage_root` over a DIFFERENT
   subset of the same committed slots than a from-genesis node. The account-trie rebuild
   does nothing here (it *reads* the stale storage root). **The fix MUST make `storage_root`
   a pure function of a contract's committed slot set too** — rebuild each storage trie
   from its resident slot set, on the same never-evicted/fully-hydrated basis as (1). The
   empty-block symptom didn't expose this (no storage writes), so it is a *latent* second
   instance, not deferrable to S2.
3. **One representation, no store reads at root time.** Collapse the resident-map /
   durable-store / accumulator-trie triad so balance AND storage have a single source of
   truth the root reflects. Close the three omission paths: route `set_balance` through the
   dirty-tracked path (no eager store bypass during apply, `executor.rs:805-818`), and
   ensure read-through hydration (`executor.rs:755-766`; `cache_storage` `state_db.rs:95-100`)
   and zero-reward blocks (`executor.rs:1281`) cannot leave a value out of the folded set —
   because the root is now over the FULL resident set, not the dirty diff, hydration
   correctness is what matters, not dirty-tracking.
4. **Reward is committed state, not off-book.** The validator/treasury credit is part of
   the account state the root commits (`BalanceConservation`), so all roles mint the same
   supply and agree.
5. **Root scope is account+storage ONLY — stated explicitly (red-team Finding 4).** The
   root does NOT authenticate `models` / `training_jobs` (`state_db.rs:26,29`) — those are
   deterministic state a root comparison will not catch; flagged for audit posture, tracked
   separately. **Self-destruct / account deletion is UNSUPPORTED** — there is no
   `remove_account` and REVM commit ignores destruction (`revm_adapter.rs:324-407`); the
   rebuild cannot express deletion. S1 asserts (test) that no chain-40204 path self-destructs;
   deletion support is an explicit non-goal (SRP-S2 if ever needed).

**Chosen implementation stance (correctness-first):** rebuild the account trie from the
authoritative committed set on each root computation. Rationale: history-independence *by
construction*, minimal blast radius, trivially satisfies the spec + the PR-#88 tests. The
pilot's account set is small (hundreds), so the O(N) cost is negligible now; a persistent
MPT for O(log N) at scale is a tracked follow-on (SRP-S2), gated only on a benchmark
regression, never on correctness.

## Invariants this change MUST preserve (verified list, do not break)

- **StateRootPurity.tla** (new oracle): `Purity`, `RootAgreement`, `BalanceConservation`,
  `CrossRoleConvergence` (`specs/tla/consensus/StateRootPurity.tla:99-124`).
- **GenesisSafetyAcrossNodes.tla**: `StateRootFor` history-independent + injective;
  `StateRootConsistency`, `DeterministicGenesis` (`specs/tla/network/GenesisSafetyAcrossNodes.tla:42-47,146-157`).
- **PR #88 regressions** (`core/execution/src/state/state_db.rs:510` `mod idempotency_probe`):
  `calculate_state_root_is_idempotent` (`:522`),
  `producer_multicall_and_validator_singlecall_agree_with_storage` (`:543`),
  `state_root_is_operation_order_independent` (`:570`);
  `trie.rs:547 root_hash_is_insertion_order_independent`.
- **Snapshot/restore byte-exactness** incl. `state_trie` + `dirty_storage`
  (`state_db.rs:396-400,347`; `test_snapshot_restore :481`; revm EL-1 `revm_adapter.rs:1199-1229`).
- **REVM balance ownership** — executor is the sole owner of balances, REVM commits
  storage/code only (`revm_adapter.rs:337-344`).
- **Reorg store reconciliation** `reconcile_store_from` keeps store==memory
  (`executor.rs:951-1019`); **persist-failure revert** (`executor.rs:1148-1161`).
- **TransactionExecution.tla**: `BalanceConservation`, `NoNegativeBalance`,
  `NonceMonotonicity` (`specs/tla/consensus/TransactionExecution.tla:150-191`).

## Red-team (gate G0) — findings folded in

Adversarial review (2026-07-21) attacked the fix. Six findings; three were load-bearing and
changed the Decision above. Verdict was "do not sign as originally written" — resolved by the
amendments now in Decision §1–§5 and Performance.

| # | Sev | Finding | Resolution |
|---|---|---|---|
| 1 | **CRITICAL** | Storage sub-tries are the identical accumulator bug (`state_db.rs:20,257-258`); account-only rebuild leaves it live one level down. Latent (empty-block symptom didn't touch storage). | **In S1** — Decision §2. Root must rebuild storage tries over each contract's committed slot set. Acceptance test asserts **per-storage-slot** equality, not just per-account balance. |
| 2 | **HIGH** | "Account map reconciled with the durable store" is self-contradictory: resident map is incomplete (lazy hydration `executor.rs:760-761`); store is stale at root time (pre-persist `:1134`→`:1148`; abandoned-branch mid-reorg). | **Fixed** — Decision §1 pins the authority to a never-evicted, fully-hydrated resident set and **forbids store reads at root time**; restart must fully hydrate. |
| 3 | **HIGH** | Enumeration exists (`state_store.rs:206-248`) but `get_all_storage` silently drops slots with key-len ≠ 52B and truncates values to 32B (`:230,238`); `set_storage` accepts arbitrary sizes. | **Mooted + guarded** — Decision §1 forbids using the store as the root-time authority (so the lossy scan is off the consensus path). S1 adds a test asserting every chain-40204 stored slot is 32-byte-keyed/valued (EVM guarantees it, `revm_adapter.rs:357`). |
| 4 | MEDIUM | Self-destruct/deletion has no representation (no `remove_account`; REVM commit ignores destruction). `models`/`training_jobs` are deterministic state the root never commits. | **Scoped out explicitly** — Decision §5. S1 asserts no self-destruct path is exercised; models/jobs-not-root-committed is an audit-posture note. |
| 5 | MEDIUM | Perf claim "O(N accounts)" undercounts: it's O(total storage slots) × 2–3 calls/block. | **Fixed** — Performance amended to O(resident storage slots); S1 benchmark measures storage-slot rebuild, store scans forbidden. |
| 6 | REFUTED | Deep-reorg reconstruction as a corruption vector. | `reorg_to` reverts to a **retained full StateSnapshot** and rejects forks past `MAX_REORG_DEPTH`; it never reconstructs a parent from the store → a too-deep reorg **stalls (rejected)**, not corrupts. Deep-reorg reconstruction NOT pulled into S1. |

**G0 sign-off:** ACCEPTED 2026-07-21, on owner delegation (@SaulBuilds: "red-team the ADR and
sign off G0"). The core direction — history-independent root by construction, mandatory
reroll, and the per-account **+ per-slot** cold-sync acceptance test — stands; the three
load-bearing gaps are closed in the amendments above. SRP-S1 WPs must cite the amended
Decision §§ they implement.

## Consequences

- **A reroll is required after the fix.** The current live chain already carries divergent
  committed balances under a shared stale root; it cannot be "healed" forward. The fix must
  land, be spec+test-verified, then a fresh reroll (the deployment runbook is now well
  practiced — see the deployer-rotation reroll runbook) produces the first genuinely
  deterministic chain, on which cold sync (citrate-core / Mac + Linux) just works.
- **New acceptance test that matters:** cold-sync a node from genesis and assert
  **per-account balances** equal the fleet, not merely the root (the old proof's blind spot).
- **Performance (amended per red-team Finding 5):** the cost is NOT O(N accounts) — it is
  **O(total resident storage slots)** because rebuilding `storage_root` (Decision §2) walks
  every committed slot of every touched contract, and `calculate_state_root` runs **2–3×
  per block on the producer + once per receiver/drain apply** (`state_db.rs:218-222`,
  `apply_block_inner:1134`). The SRP-S1 benchmark MUST measure storage-slot rebuild cost
  (ValidatorRegistry / EntryPoint / SBT / vault can hold thousands of slots), not account
  count. The persistent-MPT follow-on (SRP-S2) is gated on a >10% regression vs the
  CLAUDE.md baseline. Store CF scans at root time are FORBIDDEN (Decision §1), so the
  worst case is bounded by resident-slot count, not RocksDB table scans.
- **TOB / audit posture:** this is a genuine consensus-safety finding caught pre-handoff;
  filing the ADR + spec + regression makes it an auditable, closed class rather than a
  latent divergence.

## Alternatives considered

1. **Patch each omission path only** (dirty the coinbase on zero-reward, dirty on
   read-through, remove the eager store write). *Rejected as primary:* it is the same
   whack-a-mole that produced this ADR — correctness would again depend on having found
   *every* path. Adopted only as belt-and-suspenders inside Decision #2, not as the root fix.
2. **Full deterministic rebuild each root computation** (chosen). Correct by construction;
   O(N) cost acceptable at pilot scale.
3. **Replace the bespoke `Trie` with a versioned persistent MPT** (e.g. state committed at
   a root you can re-open). Correct and scalable, but the largest blast radius; deferred to
   SRP-S2 as a performance follow-on, not required for correctness.
