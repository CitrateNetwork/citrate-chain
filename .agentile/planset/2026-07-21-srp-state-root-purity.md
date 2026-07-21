---
created: 2026-07-21T00:00:00Z
branch: main
author: Larry Klosowski (@SaulBuilds) + Claude (Opus 4.8, 1M)
status: draft
program: SRP (State-Root Purity) — consensus state-model remediation
code: SRP-S1
repos: citrate-chain (consensus/execution) → then the deployer-rotation reroll
adr: ../adrs/ADR-2026-07-21-state-root-purity.md
spec: ../../specs/tla/consensus/StateRootPurity.tla (TLC: no error)
depends-on: nothing (this is the critical path; it BLOCKS the next reroll + citrate-core sync)
blocks: fresh-node deep sync (citrate-core Mac + Linux); the go-live reroll; TOB handoff
ratified: PENDING — owner sign-off at gate G0 (ADR red-team) before any code lands
---

> **Status (2026-07-21): DRAFT — spec + ADR written; execution gated on G0 sign-off.**
> This is a **consensus-safety** program, not a feature sprint. The chain's state root is
> not a pure function of committed state (evidence: fleet nodes agree on a block's root
> while holding different balances). Every phase leads with spec and walks the full
> Agentile loop; no phase starts before the previous gate is signed.

# Planset — SRP-S1: the state root becomes a pure function of committed state

## Goal
`calculate_state_root` becomes a pure, history-independent function of the full committed
account+storage state — identical whether a node produced, gossip-received, or cold-synced
the block — so that (a) equal roots imply equal committed balances, (b) rewards are real
committed state, and (c) a fresh node syncs any depth to head with **per-account balances
matching the fleet**. Verified against `StateRootPurity.tla` + the PR-#88 regressions, then
carried into the next reroll.

## Current truth (verified 2026-07-20/21, file:line)
- **The root is a stale accumulator, not a function of state.** `state_db.rs:243-276`
  folds ONLY dirty accounts (`:247`) into a persistent, never-rebuilt `state_trie`
  (`:32`); `commit` clears dirty right after (`:281`). Root = f(node's dirty history).
- **Three omission paths** leave a changed account out of a block's fold, retaining a
  stale trie value: zero-reward guard `executor.rs:1281`; non-dirtying read-through
  `executor.rs:755-766` / `account.rs:43-46`; eager store-write bypass `executor.rs:805-818`.
- **The divergent representation is the store** (`get_canonical_account` `executor.rs:646-652`,
  what `eth_getBalance` returns) — invisible to the trie root.
- **Live evidence:** all 4 fleet nodes share block-2557 root `0xef0ca623` but hold coinbase
  balances `0xc5e5bb45…` (rpc-1) vs `0x691b4bac…` (boots). Cold-sync computes `de169b8d` vs
  committed `493c3226`. NOT cross-arch (x86_64 + aarch64 both compute `de169b8d`).
- **Serve/sync path is already fixed + deployed** (Noise-64KiB cap → `MAX_RESPONSE_BYTES`
  60 KiB, branch `fix/85-sync-partial`, all 4 nodes hot-swapped): a fresh node now syncs
  0→2557 cleanly. The ONLY remaining blocker is this state-root purity bug at 2558.

## Scope (in)
The ADR (done, proposed); `StateRootPurity.tla` (done, TLC-clean); a red failing test that
reproduces cold-sync balance divergence; the pure-root implementation (rebuild-from-
committed-set + one balance representation + close the 3 omission paths); per-account cold-
sync determinism verification; the reroll that ships it.

## Scope (out) — honest boundaries
- **Persistent-MPT performance rework** — SRP-S2 (follow-on), gated only on a benchmark
  regression, never on correctness. S1 uses the correctness-first full rebuild.
- **The serve/Noise cap fix** — already landed (`fix/85-sync-partial`); S1 only merges it
  alongside the state-root fix into the reroll binary.
- **Reward *policy* / emission economics** — unchanged; S1 makes the reward *committed*,
  it does not change amounts (ECON owns amounts).
- **Reorg deep-history reconstruction robustness** (`reconcile_store_from` resident-bound,
  agent-1 secondary hazard) — S1 must not regress it (invariant), but the deep-reorg
  hardening beyond what purity requires is an SRP-S2 candidate.

## Phase gates + work packages
Acceptance criteria name their data source per Rule 11. **Each gate = owner sign-off
recorded before the next phase starts.** Every WP follows the full Agentile loop:
spec/ADR reference → plan → implement → test (spec + unit + integration) → gate → journal.

### Phase 0 — Spec + ADR first (gate G0) · repo: citrate-chain
| WP | Title | Acceptance |
|---|---|---|
| **WP-0.1** | **StateRootPurity.tla** — formalize the invariants (`Purity`, `RootAgreement`, `BalanceConservation`, `CrossRoleConvergence`) modeling producer/receiver/coldsync | TLC runs clean (no invariant violation). **Source:** `specs/tla/consensus/StateRootPurity.tla` + `.cfg`; `java -cp tla2tools.jar tlc2.TLC` output "No error has been found." **DONE.** |
| **WP-0.2** | **ADR-2026-07-21-state-root-purity** — the decision: root = pure function of committed state; rebuild-from-committed-set stance; full preserved-invariant list | ADR merged + **red-teamed** (a reviewer attempts to name a 4th omission path or an invariant the fix breaks; findings folded in). Every later WP cites the ADR section it implements. **Source:** the ADR + red-team notes. **This WP blocks all others.** |

### Phase 1 — Reproduce + acceptance oracle (gate G1) · repo: citrate-chain
| WP | Title | Acceptance |
|---|---|---|
| **WP-1.1** | **Red test: cold-sync balance divergence** — a Rust integration test that produces a chain (incl. an empty post-activation reward block), then re-executes it from genesis and asserts BOTH the root AND every account balance match | Test **FAILS on `main`** (reproduces `de169b8d≠493c3226` and the balance drift) and is the pass/fail oracle for Phase 2. **Source:** the test's own producer-vs-reexecution assertion. |
| **WP-1.2** | **Root-purity unit probe** — extend `state_db.rs mod idempotency_probe`: after crediting an account via each of the 3 omission paths, `calculate_state_root` MUST reflect it | New probes FAIL on `main`, encode the exact defect. **Source:** `core/execution/src/state/state_db.rs` probe asserts. |

### Phase 2 — Implement the pure root (gate G2) · repo: citrate-chain
| WP | Title | Acceptance |
|---|---|---|
| **WP-2.1** | **Root over the authoritative committed set** — `calculate_state_root` derives the trie from the full committed account state each call (history-independent), not the dirty-diff accumulator | WP-1.1 + WP-1.2 turn GREEN; **all PR-#88 regressions stay green** (`calculate_state_root_is_idempotent`, `producer_multicall_and_validator_singlecall_agree_with_storage`, `state_root_is_operation_order_independent`, `root_hash_is_insertion_order_independent`). **Source:** `cargo test -p citrate-execution` full suite. |
| **WP-2.2** | **One balance representation + close the 3 omission paths** — route `set_balance` through dirty-tracking (no eager store bypass during apply); ensure read-through hydration + zero-reward blocks cannot omit an account from the fold | `eth_getBalance` (store) == the balance folded into the root, asserted at every block in an integration test. **Source:** per-block store-balance vs root-committed-balance equality check. |
| **WP-2.3** | **Preserve snapshot/restore + reorg + persist-revert invariants** | `test_snapshot_restore`, revm EL-1 snapshot tests, `reconcile_store_from` store==memory, and HIGH-1 persist-failure revert all pass; a reorg over a post-activation reward block re-executes to the identical root. **Source:** the named tests + a reorg integration fixture. |

### Phase 3 — Determinism verification (gate G3) · repo: citrate-chain
| WP | Title | Acceptance |
|---|---|---|
| **WP-3.1** | **Local multi-producer deep-sync + reorg gate** — 2 producers + reward blocks past activation; a fresh node cold-syncs to head; assert per-account balances == producer, not just root | Fresh node reaches head; **balance-equality holds for every account** through a reorg + post-activation region. **Source:** cold-sync node `eth_getBalance` vs producer, scripted. |
| **WP-3.2** | **CI tripwire** — a from-genesis cold-sync balance-equality check wired into CI (the check the old "determinism proof" lacked) | The check fails on the pre-fix binary, passes on the fixed binary; registered in CI. **Source:** the CI job artifact. |

### Phase 4 — Reroll with the fix (gate G4) · repo: citrate-chain + fleet + droplets
| WP | Title | Acceptance |
|---|---|---|
| **WP-4.1** | **Reroll binary** = main + SRP fix + `fix/85-sync-partial` serve cap + deployer rotation (already prepped) | Binaries built both arches; CREATE2 book unchanged from the frozen `40204.json` (state-root fix does not move addresses). **Source:** `contracts/addresses/40204.json` diff + the CREATE2 tripwires. |
| **WP-4.2** | **Execute the reroll** per the practiced runbook (atomic reset → deploy → PHASE 3.5 rekey → register 4 validators → verify) | Chain live; 0 state-root mismatch AND 0 balance divergence across the fleet past activation; a fresh Linux **and** aarch64 node cold-syncs to head with matching balances. **Source:** the reroll verification (per-node root + per-account balance) + a live cold-sync. |
| **WP-4.3** | **citrate-core cold-sync proof** — the bundled node syncs to head on Linux + Mac | c1_1 sync proof passes to head; balances match the fleet. **Source:** `citrate-core/src-tauri/scripts/c1_1_node_sync_proof.sh` + balance check. |

## The Agentile loop, per sprint (how each WP is worked)
1. **Spec/ADR** — cite the ADR section + the StateRootPurity invariant the WP upholds.
2. **Plan** — WP acceptance names its data source (Rule 11); no mocks (Rule 1).
3. **Implement** — feature branch; explicit `git add <paths>`; zero `.unwrap()` in prod.
4. **Test** — spec (TLC) unchanged-clean + the WP's red→green test + the full preserved-
   invariant suite (never let a PR-#88 regression go red).
5. **Gate** — owner sign-off; benchmark run per CLAUDE.md for core-crate touches.
6. **Journal** — record the durable lesson (why the accumulator was the trap) in the sprint.

## Definition of done (program)
- `StateRootPurity.tla` green; ADR accepted + red-teamed.
- Every omission path closed; root == committed state, proven per-account (not just root).
- All PR-#88 + snapshot/reorg/persist invariants green; benchmark within 10% of baseline.
- Reroll executed; a fresh Linux + Mac citrate-core node cold-syncs to head with balances
  matching the fleet. **"Larry can open the app and it syncs"** — and TOB inherits a
  closed, spec-backed consensus-safety class, not a latent divergence.
