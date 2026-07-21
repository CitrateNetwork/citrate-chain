---
created: 2026-07-21T00:00:00Z
branch: main
author: Claude (Opus 4.8, 1M) directed by Larry Klosowski (@SaulBuilds)
status: proposed
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

1. **Root over the authoritative committed set, not a dirty-diff accumulator.**
   `calculate_state_root` derives the trie from the authoritative committed account state
   (the executor's account map as the single source of truth, reconciled with the durable
   store), so every account that exists is represented at its current value **every**
   computation — no reliance on "was it dirtied this block." Whether implemented as a
   full deterministic rebuild each call or as a correctly-maintained persistent MPT keyed
   by the committed set, the acceptance oracle is identical: `Purity` + `RootAgreement`.
2. **One balance representation folded into the root.** Collapse the resident-map /
   durable-store / accumulator-trie triad so a balance has a single source of truth that
   the root reflects. Close the three omission paths: route `set_balance` through the
   dirty-tracked path (no eager store bypass during apply), and ensure read-through
   hydration cannot leave a value out of the folded set.
3. **Reward is committed state, not off-book.** The validator/treasury credit is part of
   the account state the root commits (`BalanceConservation`), so all roles mint the same
   supply and agree.

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

## Consequences

- **A reroll is required after the fix.** The current live chain already carries divergent
  committed balances under a shared stale root; it cannot be "healed" forward. The fix must
  land, be spec+test-verified, then a fresh reroll (the deployment runbook is now well
  practiced — see the deployer-rotation reroll runbook) produces the first genuinely
  deterministic chain, on which cold sync (citrate-core / Mac + Linux) just works.
- **New acceptance test that matters:** cold-sync a node from genesis and assert
  **per-account balances** equal the fleet, not merely the root (the old proof's blind spot).
- **Performance:** full-rebuild adds O(N accounts) per block; benchmarked in SRP-S1, with
  the persistent-MPT follow-on (SRP-S2) gated on a >10% regression vs the CLAUDE.md baseline.
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
