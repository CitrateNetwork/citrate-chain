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
  selected chain `A → … → tip`. Bound by finality depth (100) / the nearest BFT checkpoint —
  never revert below a finalized checkpoint (reject such a reorg as a safety violation).
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
1. **Atom** — `Executor::apply_block` (verified + revertible) + tests (§2.2, §2.5 tests). No
   wiring yet; adds state-root verification as a callable primitive.
2. **Pointer + fast-path driver** — applied_tip persistence + fast-path apply on the receive
   path; state-root rejection live. Covers linear canonical growth (the common case).
3. **Gap-extend** — walk-forward when the selected chain jumped.
4. **Reorg (option A)** — revert-to-checkpoint + re-apply; checkpoint floor guard.
5. **Generalize VALIDATOR-S1 sync** — move `maybe_sync_registry` into the driver so all nodes
   sync at S(E); retire the producer-only hook.
6. **Harness** — two-node divergence test: producer + follower must reach identical state_root
   at every height; a corrupted-state_root block must be rejected fleet-wide.

## 5. Invariants
- I1: a block is admitted to the canonical chain ⇒ re-executing its txs yields its `state_root`.
- I2: after applying canonical block H, every honest node's `state_root` at H is identical.
- I3: a rejected (bad-root) block leaves world state byte-identical to before the attempt.
- I4: state is never reverted below the last finalized BFT checkpoint.
- I5: `applied_tip` is always an ancestor-or-equal of the DAG selected tip.
