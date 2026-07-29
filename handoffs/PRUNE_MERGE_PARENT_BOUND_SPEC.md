---
created: 2026-07-29
branch: fix/prune-merge-parent-bound
author: Claude Opus 5 (1M context), directed by @SaulBuilds
status: spec — owner decision required before implementation
---

# Bounding the merge-block walk so DAG pruning can be enabled

## Why this exists

Enabling `CITRATE_DAG_PRUNE_RETAIN` is the fix for the `DagStore` memory ceiling
that wedged boot1 and OOM-looped boot2/boot3 on 2026-07-29 (24 restarts between
them). The blocker `node/src/dag_prune.rs` has always documented is the
merge-block score walk. This spec says what that bound actually requires.

**Headline: it is not a code bound. It is a CONSENSUS RULE, and shipping it
without coordinated activation forks the network.** That is why this is a spec
and not a patch.

## The hazard, verified

`node/src/dag_prune.rs::merge_block_referencing_a_pruned_parent_is_rejected_not_scored`
(`#[ignore]`d; it is the acceptance test for this work). Build 1,500 blocks,
prune to a 1,000-block window (pruning point 500), then admit a block at height
1,501 whose merge parent is the height-200 block:

```
Err(MissingParent(2f76503aef5c82ea6b2006fe2df995060aad41f12eb6c1d1bef37c0c1aa66a04))
```

The chain of causation:

1. `derive_score_and_work` is O(1) for a LINEAR block — `relations`, else the D3
   durable anchor. This is why the existing prune test passes.
2. A MERGE block has no such shortcut. It falls back to `calculate_blue_set`.
3. `calculate_blue_set` → `get_or_calculate_blue_set` phase 1 walks the
   selected-parent chain resolving each ancestor through `DagStore::get_block`.
4. `DagStore::get_block` (`core/consensus/src/dag_store.rs:869`) is
   **memory-only — there is no disk fallback**. A pruned hash is simply gone.
5. Admission rejects the block.

**This is a fork, not a crash.** An unpruned peer admits that block. A pruned
peer refuses it. Two nodes then disagree about the canonical chain because of a
*local storage policy*. That is strictly worse than the OOM it was meant to cure:
an OOM is loud and recoverable, a silent validity split is neither.

## Root cause: merge-parent depth is unbounded

`validate_block_consistency` (`core/consensus/src/ghostdag.rs:745-845`) enforces:

- merge parents exist in the DAG store,
- `merge_parents.len() < max_parents`,
- no duplicate parents, no self-reference,
- no merge parent outranks the selected parent by blue score,
- height is exactly `selected_parent.height + 1`,
- timestamp is parent-monotonic,
- a blue-score feasibility band.

It does **not** bound how far BACK a merge parent may reach. A block at height
72,000 may legally merge a parent at height 5. So no window-based bound on the
blue-set walk is sound today: for any window W, a legal block can reference
outside it, and a node that bounded its walk at W would compute a *wrong score*
rather than fail — and a wrong score is a fork with no error message.

Bounding the walk therefore REQUIRES first making such blocks invalid.

## The rule

> **MP-DEPTH.** For every merge parent `mp` of block `b`:
> `b.height − mp.height ≤ MERGE_PARENT_MAX_DEPTH`.
> A block violating this is invalid and must be rejected by every node.

With MP-DEPTH enforced, the blue-set walk can terminate at
`tip − MERGE_PARENT_MAX_DEPTH` with a proof: nothing reachable as a merge parent
lies below that line, so the retained window contains everything the k-cluster
anticone computation can observe. Blocks below contribute only to the SCORE (a
counter, available O(1) from the durable anchor), never to the SET.

Required relationship, and the reason the two numbers cannot be chosen
independently:

```
MERGE_PARENT_MAX_DEPTH  <  MIN_RETAIN_BLOCKS (1,000)   <  CITRATE_DAG_PRUNE_RETAIN
                        ^                              ^
                        |                              retain window actually configured
                        the pruner must never remove a block a valid block may cite
```

## Owner decisions required

1. **`MERGE_PARENT_MAX_DEPTH` value.** It bounds how long a partitioned producer
   may be absent and still have its work merged rather than orphaned. `100`
   matches `finality_depth` and `MAX_REORG_DEPTH`; the live chain is linear
   (`mergeParentHashes: []` throughout) so nothing today comes close. Recommend
   **100** — consistent with the existing reorg floor, and 10× under the retain
   floor.
2. **Activation height.** This changes block validity, so it needs the
   VALIDATOR-S1 treatment: an activation height, all nodes upgraded before it,
   and the producer taught not to build violating blocks. Blocks below the
   activation height must be judged by the OLD rule forever, or re-validating
   history forks the chain.
3. **Whether to proceed at all right now.** The cheap alternative is resizing the
   4 GB droplets, which buys time proportional to the RAM and no more (the
   ceiling scales with chain height at 43,200 blocks/day). Pruning is the only
   fix that does not expire — but it is a consensus change, and the chain has had
   two consensus incidents this week.

## Also found — must be settled before pruning goes on

**`pruning_window` and `finality_depth` are dead parameters.** Both live in
`GhostDagParams` (`core/consensus/src/types.rs:168-172`, defaults 100,000 and
100) and are surfaced over RPC (`core/api/src/eth_rpc.rs:2507`), but **nothing in
consensus reads either one**. The pruner uses its own `CITRATE_DAG_PRUNE_RETAIN`
env var with a separate floor. So the network advertises a pruning window it does
not honour, and the number that actually governs retention is an env var on each
box. These must become one authoritative value before pruning is enabled, or
operators will tune the wrong knob.

**Suspected, NOT yet proven — anchor deletion at the pruning boundary.**
`prune()` deletes each pruned block's durable score anchor
(`persist_delete_derived_blue_score`, `dag_store.rs:990`) with the reasoning that
an anchor must not outlive its block. But after prune + RESTART, `relations` is
empty and rehydrating the OLDEST RETAINED block needs its selected parent's
score — and that parent is pruned, with its anchor deleted. The cold path would
then walk into `get_block` on a pruned hash and fail exactly as above. If real,
this breaks pruning on the LINEAR path too, which the existing prune test does
not catch because it never restarts. **Needs a prune-then-rehydrate test before
anyone enables pruning.** I have not written it; flagging rather than asserting.

## Definition of done

1. A prune-then-rehydrate test, settling the anchor question above.
2. MP-DEPTH implemented in `validate_block_consistency`, gated on the activation
   height, with the producer refusing to build violating blocks.
3. The blue-set walk bounded at the retained window, justified by MP-DEPTH.
4. `pruning_window` unified with the pruner's retain value — one source of truth.
5. `merge_block_referencing_a_pruned_parent_is_rejected_not_scored` green, ignore
   removed.
6. Only then: `CITRATE_DAG_PRUNE_RETAIN` set on the fleet.

## What is NOT blocked on any of this

The bootnodes are surviving today by being restarted. That works because the
applied-tip pointer is durable, so a restart resumes rather than replays. It is
not a fix, and boot1 showed the failure mode restarts do not cover: a node that
reaches the memory ceiling *without* being killed does not loop and recover — it
parks, RPC still answering and systemd still reporting `active`, processing
nothing. **A progress-based health check (height advancing, not process alive) is
independent of this spec, cheap, and would have caught that.** Recommend it
first, whatever is decided about pruning.
