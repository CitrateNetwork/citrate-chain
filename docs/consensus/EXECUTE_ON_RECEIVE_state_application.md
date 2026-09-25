---
title: "Execute-on-receive — canonical state application for received blocks"
created: 2026-07-16
branch: feat/validator-registry-ed25519
author: Claude Opus 4.8 (consensus, for @SaulBuilds)
status: DESIGN — approved direction ("full execute-on-receive / state sync"), impl pending
chain: 40204
---

# Execute-on-receive: make received blocks advance world state

## 0. The finding (why this exists)

A node **never executes the transactions of a block it receives** from a peer. Confirmed
by exhaustive trace (gossip `NewBlock` @ `node/src/main.rs:1758`, sync `Blocks` @ `:1833`):
the receive path runs signature/structure validation → `validate_block_consistency`
(blue-score/work/height — *structural only*) → `dag_store.store_block` (DAG admission) →
`ghostdag.add_block` → `storage.blocks.put_block` (persists block **bytes**). No executor
call anywhere. World state (`executor.state_db` + the state store) advances **only** via
local production (`producer.rs execute_block_transactions → persist_state_changes`).
`ChainSelector::perform_reorg` updates DAG bookkeeping only — no state re-execution.

Two consequences:
1. A non-producing / consensus-only node reports **stale** account state
   (`eth_getBalance` → `executor.get_canonical_account`, which only reflects locally-produced
   blocks). Multiple independent state-producers **diverge**.
2. Received blocks get **no state-root verification** — a peer's block claiming any
   `state_root` is DAG-admitted without checking it against re-execution. This is a latent
   **consensus-safety gap** independent of VALIDATOR-S1.

VALIDATOR-S1 rides on this: membership enforcement lives in `store_block` (every node), but
the selector is populated by reading the registry against local state (`RegistrySync`), which
only a state-executing node has. Fixing execute-on-receive makes every node able to compute
membership.

## 1. Goal

When a block becomes part of the **canonical selected chain**, apply its transactions to
world state in canonical order and **reject it if the recomputed `state_root` ≠ the block's
claimed `state_root`**. Support reorgs (revert + re-apply along the new selected chain).
Every honest node, producing or not, converges on identical world state.

## 2. Design

### 2.1 Applied-tip pointer
Track `applied_tip: Hash` and `applied_height: u64` — the block whose post-execution state
the executor currently reflects. Persisted (survives restart) next to `latest_height`.
Genesis initializes `applied_tip = genesis.hash()`.

### 2.2 The apply atom (verified, revertible)
`Executor::apply_block(&self, block) -> Result<Hash, ExecutionError>`:
1. Snapshot the MVCC/journal state (see §2.5 — the delicate part).
2. For each `tx` in `block.transactions`: `execute_transaction(block_ctx, tx)`.
3. `root = calculate_state_root()`.
4. If `root != block.state_root` → **restore the snapshot** (no partial state), return
   `Err(StateRootMismatch{expected, got})`. The caller rejects the block.
5. Else `persist_state_changes()`, return `Ok(root)`.

This atom is independently valuable — it adds the missing state-root check even before
canonical-ordering/reorg land.

### 2.3 Canonical-order driver (on receive + on produce)
After a block is DAG-admitted and fork-choice picks the selected chain:
- **Fast path** — `block.selected_parent == applied_tip`: `apply_block(block)`; advance the
  pointer. This is the common case (linear canonical growth; a follower tracking the producer).
- **Extend after gap** — selected chain advanced by >1 (out-of-order arrival now connected):
  walk the selected-parent chain from `applied_tip` forward, `apply_block` each in order.
- **Reorg** — new selected tip is on a different branch: find the common ancestor `A` on the
  current applied chain, **revert state to `A`**, then `apply_block` forward along the new
  selected chain `A → … → tip`. Design: bound by finality depth (100) and the nearest BFT
  checkpoint, never reverting below a finalized checkpoint. Checkpoint finality is specified, not
  running on the testnet (see `verification/claims.json`), so this bound is not in effect today.
- **Not yet connected** (missing ancestors): defer; the driver re-runs when ancestors arrive.

The producer's local path collapses to the fast path (it already executed while sealing, so
`apply_block` there just verifies its own root and advances the pointer — or the producer
sets the pointer directly since it authored the state).

### 2.4 Reorg reversion strategy
Two options; pick per cost:
- **(A) Re-execute from a checkpoint.** Keep no undo log; on reorg, reset state to the last
  finalized checkpoint's state and re-execute forward to the new tip. Simple, robust, O(depth
  since checkpoint). Fine given checkpoints every 50–100 blocks and shallow reorgs on a BFT
  fleet. **Recommended first implementation.**
- **(B) Per-block undo journal.** Record inverse writes per applied block; reorg pops them.
  Faster for deep reorgs, more state/complexity. Defer unless (A) is too slow.

### 2.5 The MVCC/journal caveat (must be handled carefully)
State mutation goes through the executor's MVCC journal + commit-coordinator (see
`execute_tx_into_journal`, `persist_state_changes`, `simulate_transaction`'s
`state_db.snapshot()/restore()`). `apply_block` must drive the *same* commit path the
producer uses so `calculate_state_root()` reflects post-execution state, and the snapshot in
§2.2.1 must undo **journal** pending writes, not just `state_db` accounts. Getting this atom
correct is the crux of the feature — it is where a naive implementation silently corrupts
state. Implementation must reuse the producer's exact execute→root→persist sequence and add a
verified, revertible wrapper, with tests that assert (a) a good block advances state, (b) a
bad-state_root block is rejected AND leaves state untouched, (c) re-apply is idempotent.

## 3. Wiring
- Receive paths (`main.rs:1758` gossip, `:1833` sync-drain): after `store_block` + `add_block`
  succeed, invoke the canonical-order driver. On `Err(StateRootMismatch)` reject the block
  (do not persist / do not advance), score the peer down.
- Producer: after sealing + persisting, set `applied_tip = block.hash()` (it authored state).
- VALIDATOR-S1 `RegistrySync`: unchanged — once every node executes canonical blocks, its
  `simulate_transaction` read reflects the true post-S(E) state on every node, and the
  received-block sync hook becomes just "call the driver, which calls maybe_sync_registry at
  boundaries." The producer-only hook generalizes for free.

## 4. Incremental plan
1. ✅ **Atom** — `Executor::apply_block` (verified + revertible) + tests (§2.2, §2.5 tests). No
   wiring yet; adds state-root verification as a callable primitive. **DONE** (2026-07-16).
2. ✅ **Pointer + fast-path driver** — applied_tip persistence + fast-path apply on the receive
   path; state-root rejection live. Covers linear canonical growth (the common case).
   **DONE** (2026-07-16). Implementation:
   - `BlockStore::put_applied_tip` / `get_applied_tip` (CF_METADATA key `applied_tip`,
     40-byte hash‖height; SECREM-01 CONS-6 panic-free decode). Distinct from `latest_height`
     (a block can be admitted + bytes-persisted before its txs execute).
   - `node/src/canonical_apply.rs::CanonicalApplicator` — owns the shared applied-tip lock +
     the deterministic reward calculator; drives `apply_block`. `apply_received` returns
     `Applied` / `Deferred` (gap/fork, deferred to steps 3–4) / `Rejected` (bad root, state
     reverted) / `AlreadyApplied`. Seeds the tip from the persisted pointer, else from the
     latest persisted block ("state is applied through `latest_height`", true for a producer).
   - Wired at both receive seams in `main.rs` (gossip `NewBlock` + sync `Blocks`) right after
     DAG admission + `put_block`. Gated on `CITRATE_BLOCK_V2` (execute-on-receive = on).
   - **Concurrency:** `apply_block`'s snapshot/restore is NOT safe to run concurrently with the
     producer's own execute→persist. A single `Arc<Mutex<AppliedTip>>` serializes all
     state advancement: `apply_received` locks it; the producer holds the SAME lock (via
     `with_applied_tip_lock`) across its whole `produce_block` and calls `record_produced`
     before releasing. So on a node that both produces and receives (the multi-producer
     fleet), the two paths are mutually exclusive on executor state.
   - **Reward determinism (crux finding):** a receiver can only reproduce `state_root` if it
     credits the exact rewards the producer did. The **enhanced** economics reward path reads
     node-local, non-consensus state (staking manager, **f64 reputation**, dynamic pricing) and
     is unreproducible. So under v2 the producer is forced onto the **basic** reward path — a
     pure function of `header.height` + `transactions` — via `canonical_reward_config()`, the
     single source of truth shared by producer and `CanonicalApplicator::reward_credits`. If
     these ever diverge, execute-on-receive rejects every block (state_root mismatch). Recorded
     in the reroll addendum (operators must NOT rely on enhanced rewards under v2).
   - 3 driver tests (`applies_linear_extension_and_advances_tip`,
     `rejects_bad_state_root_and_leaves_state_and_tip_untouched`, `defers_non_linear_blocks`).
3. ✅ **Gap-extend** — walk-forward when the selected chain jumped. **DONE** (2026-07-16).
   `apply_received` now drives `drain_forward`: starting at the applied tip it repeatedly
   applies the unique persisted child on the selected chain (`next_persisted_extension` —
   a `get_children(tip)` filtered by `selected_parent == tip ∧ height == tip.height+1`)
   until it reaches a chain tip, a fork (≥2 selected-parent children → defer to step 4), or a
   rejection. Because `put_block` persists a block before the driver sees it, out-of-order
   delivery self-heals: a block ahead of its intermediates is `Deferred`, and the moment the
   gap is filled by a later arrival the whole contiguous suffix drains in one call. The
   received block is classified `Applied` iff the drain executed it, `Rejected` iff the drain
   reached and rejected exactly it, else `Deferred`. This subsumes the step-2 direct extension
   (the one-iteration case). Two new tests: `gap_extend_cascades_when_missing_intermediate_arrives`,
   `drains_full_chain_when_top_arrives_with_all_intermediates_present`.
   - *Fork-above-tip limitation — RESOLVED by step 4 + trigger-tested (2026-07-16):* a fork above
     the tip halts the linear drain (no wrong state applied — it just stops). The step-4 fork-choice
     trigger now drains it: `apply_received` consults fork choice and `reorg_to`s onto the winning
     branch (fork point = applied tip ⇒ a no-op restore then forward re-apply). Proven end-to-end
     through `apply_received` by `fork_choice_reorg_drains_fork_above_tip_wedge` (asserts the wedge
     exists without fork choice, then is drained with it). The fork choice is a boxed async hook
     (GhostDAG in prod, injectable in tests). *Residual:* a state-INVALID block with high blue work
     can still wedge a branch (see step 4 residual) — needs consensus↔execution feedback.
4. ✅ **Reorg**: revert-to-fork-point + re-apply. **DONE** (2026-07-16). The finalized-floor guard is
   implemented but has no effect until checkpoint finality runs (it is specified, not running).
   - **Snapshot ring:** `AppliedState` folds the applied tip together with a bounded ring of
     full `StateSnapshot`s (one per applied block, keyed by height, capped at `MAX_REORG_DEPTH`
     = 100). Every state advance — drain apply, producer `record_produced`, and reorg re-apply —
     records a snapshot; the ring prunes below the window. (`StateSnapshot`/`AccountSnapshot`
     gained `Clone`; `Executor` exposes `state_snapshot`/`state_restore`.) Chosen over
     rebuild-from-genesis (O(chain) — the live chain is already ~386k blocks) and over an
     archive trie (memory). Memory = ≤ `MAX_REORG_DEPTH` full-state clones; the reorg depth is
     bounded by that + the finalized floor. Documented tradeoff: a CoW/reverse-diff ring is the
     scale optimization.
   - **`reorg_to(new_tip)`:** walk `new_tip`'s selected-parent ancestry until it meets a retained
     applied block — that is simultaneously the fork point AND a snapshot to revert to. Guards
     (each leaves state byte-identical, I3): fork older than the window → `Rejected`; fork below
     the finalized floor → `Rejected` (I4); a missing/bad block on the winning branch → the whole
     re-apply is rolled back to an outer pre-reorg snapshot. Re-apply builds new snapshots locally
     and commits to the ring only on full success (abort leaves ring + persisted pointer untouched).
   - **Trigger:** `apply_received` now attaches GhostDAG as fork-choice; after the forward drain it
     calls `select_tip()` and, if the selected tip isn't the applied tip, `reorg_to(best)`. This
     also resolves step 3's fork-above-tip wedge (fork point = applied tip ⇒ a no-op restore then
     forward re-apply of the winning branch). Wired under `CITRATE_BLOCK_V2`; the finalized floor is
     kept in sync with the `CheckpointManager` by a 5 s poll.
   - *Residual (needs consensus↔execution feedback, beyond execute-on-receive):* a state-INVALID
     block with high blue work can be repeatedly selected by fork choice and rejected on re-apply
     (state never corrupts, but that branch can't be adopted). The fix is fork choice excluding
     blocks that fail state verification.
   - 4 reorg tests: revert+reapply, abort-on-bad-block (I3), finalized-floor refusal (I4), no-op.
5. ✅ **Generalize VALIDATOR-S1 sync** — **DONE** (2026-07-16). The driver
   (`CanonicalApplicator`) now re-syncs the proposer selector from the registry after applying a
   RECEIVED or REORGED block at a snapshot boundary `S(E) = E·1000 − 200` — so a non-producing
   node, or any node that receives/reorgs to `S(E)` from a peer, loads epoch-E membership. This
   closes the memory-noted gap (sync was producer-path only). Refinement vs the original "retire
   the producer hook": the producer hook is KEPT for locally-PRODUCED `S(E)` blocks (which never
   flow through the driver's execute path — they are recorded, not re-executed). The two hooks
   cover disjoint block sources, so there is no double-sync, and VALIDATOR-S1 activation is not
   coupled to the v2 flag. The driver's hook is also strictly more correct than the producer's on
   one axis: it re-syncs on a REORG across `S(E)` (to the new branch's registry state), which the
   producer hook never did. Registry sync is a boxed async hook (RegistrySync in prod, injectable
   in tests). Wired in `main.rs` when the registry is configured + the driver is enabled. Tests:
   `registry_sync_fires_only_at_snapshot_boundaries`, `registry_sync_absent_is_noop`.
6. ✅ **Harness** — two-node divergence test. **DONE** (2026-07-16). A component-level harness (two
   INDEPENDENT executors — a producer that builds a chain exactly as `node/src/producer.rs` does
   under v2, and a follower `CanonicalApplicator` over its own exec+store — with REAL value-transfer
   transactions, not just rewards):
   - `two_node_state_root_parity_with_transactions` — the follower reproduces the producer's
     `state_root` at EVERY height + agreeing balances (**I2**).
   - `follower_rejects_corrupted_state_root` — a flipped-root block is rejected with the follower
     left byte-identical (**I3**), then fork choice routes around it to the valid sibling.
   - `two_nodes_converge_after_reorg` — the follower on branch A converges to the producer's heavier
     branch B after a reorg (state parity restored post-reorg).
   - **Bug the harness caught + fixed:** `reorg_to` could not revert to the genesis base — `Block::
     is_genesis()` is true for ANY first block (its `selected_parent` is the genesis sentinel), so the
     ancestry walk bailed on the block itself instead of stepping to the sentinel. Fixed: drop the
     `is_genesis()` bail (only the depth cap bounds the walk) + treat a walk that reaches the seeded
     genesis-base hash (no stored block) as the fork point. A fork at genesis now reverts correctly.

## 5. Invariants
- I1 ✅: a block is admitted to the canonical chain ⇒ re-executing its txs yields its `state_root`.
  (`apply_block` verifies this; the harness proves it across nodes with real txs.)
- I2 ✅: after applying canonical block H, every honest node's `state_root` at H is identical.
  (`two_node_state_root_parity_with_transactions`, `two_nodes_converge_after_reorg`.)
- I3 ✅: a rejected (bad-root) block leaves world state byte-identical to before the attempt.
  (`rejects_bad_state_root…`, `reorg_aborts_on_bad_block…`, `follower_rejects_corrupted_state_root`.)
- I4 (specified): state is never reverted below the last finalized BFT checkpoint. The guard is tested
  (`reorg_refused_below_finalized_floor`) and the floor is synced from `CheckpointManager` in `main.rs`, but
  checkpoint finality is not running on the testnet, so the invariant is not in effect there yet.
- I5 (partial): `applied_tip` is an ancestor-or-equal of the DAG selected tip. The reorg trigger drives
  `applied_tip` toward `select_tip()` after every received block; a fully live cross-check awaits a real
  multi-node deployment (the harness uses an injected fork choice). Tracked for the post-reroll fleet.

## 6. Status
Steps 1–6 COMPLETE (2026-07-16). Execute-on-receive is feature-flagged (`CITRATE_BLOCK_V2`), off by
default, and activates at the reroll per `REROLL_ADDENDUM_*.md`. Residuals: (a) a state-INVALID block
with high blue work can wedge a branch (needs consensus↔execution feedback — fork choice excluding
state-invalid blocks); (b) the snapshot ring is bounded by `MAX_REORG_DEPTH` full-state clones — a
CoW/reverse-diff ring is the scale optimization; (c) I5 live cross-check awaits a real multi-node run.

## 7. Pre-merge adversarial review (2026-07-16) — findings + fixes
Two independent adversarial reviews before merge. The happy path was confirmed solid (reward parity
byte-for-byte, `StateSnapshot` `Clone` deeply independent, lock discipline correct). Findings fixed:
- **HIGH-1** — `apply_block` left in-memory state advanced when the durable persist failed (store
  unchanged, tip behind → next drain re-applied and wedged). Now reverts in-memory on persist failure.
- **HIGH-2 (durable reorg rollback)** — a reorg reverted in-memory via the ring but the durable store
  had no rollback, so an aborted reorg (or the reverted-account set of a successful one) left RocksDB
  diverged from memory, surfacing after a restart-following-a-reorg. **Fixed:** the reorg re-applies the
  candidate branch IN-MEMORY only (`apply_block_no_persist`), so an abort writes nothing durable; on
  success `Executor::reconcile_store_from(baseline)` writes the account+storage diff to the store and
  DELETES accounts the abandoned branch created (new `Trie::entries_map` enumeration + `delete_account`
  on the store trait). Proven by restart-simulation tests: a fresh cold-cache executor over the same
  store reads the new branch (incl. an abandoned-created account correctly deleted); an aborted reorg
  leaves the store on the old branch.
- **F1** — a drain-applied block reverted by the same call's reorg was misreported `Applied`; now
  classified against the post-reorg ring.
- **F2** — proposer-selector desync on a reorg-abort across `S(E)`; the registry re-sync now fires only
  after the reorg succeeds, so an abort never touches the selector.
- **F3** — an equal-height heavier sibling couldn't trigger a reorg (short-circuited to `AlreadyApplied`);
  now it consults fork choice.
All five fixed with tests; 95 node-bin + 538 execution-lib green, clippy clean. Remaining residual on the
reorg store fix: a crash *between* the reconcile batch and the account-deletes could momentarily leave an
abandoned account on disk — self-heals on restart (the applied-tip pointer is persisted only after
reconcile, so fork choice re-drives the reorg). LOW; documented.

**Re-review finding E (durable leak during reorg reapply) — FIXED.** `apply_block`'s eager setters
(`set_balance`/`set_code`/`set_nonce`) wrote world state to RocksDB directly, so a reorg's in-memory
`apply_block_no_persist` still leaked durable account/code (reward crediting, contract deploys) that an
abort never rolled back. Fixed with an executor `defer_persist` flag: an RAII guard engages it for the
whole `apply_block` execution, so those setters mutate in-memory + dirty-tracking only, and durable writes
happen once — at the end via `persist_state_changes`, or via `reconcile_store_from` (reorg success). Direct
callers (genesis init, RPC) leave it off and persist eagerly as before. Contract code persists through the
deferred path via a new `dirty_code` set (captured in `StateSnapshot`, so a reverted deploy is discarded).
Restart-simulation tests now also cover reward accounts across reorg success + abort.

**Intentionally eager on the `no_persist` path (NOT world state — reviewed + accepted, 3 rounds):** MVCC
`account_versions` / `global_version` (monotonic, restart-safe) and the external best-effort AI side-effect
stores (model registry, IPFS artifact pins — content-addressed + idempotent) still persist during a reorg
reapply and are not rolled back on abort. None contribute to `state_root`; their orphans are unreferenced
and harmless. Left eager deliberately, so a future reviewer does not mistake them for a deferral gap.
