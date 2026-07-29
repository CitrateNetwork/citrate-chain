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

**RESOLVED — the producer undoes pruning on every restart.** `Producer::with_economics`
eager-loads `for height in 0..=latest_height` from the **CHAIN** store
(`node/src/producer.rs:388`), which `dag_prune` never touches, and re-inserts every
block into the DAG store. So on a producing node, DAG pruning is erased by the next
restart and memory returns to full. Followers are unaffected (they never run that
loop, and `DagStore::load_from_persistent` reads the pruned DAG keyspace). **This
loop must be bounded to the retained window before pruning is enabled on rpc-1**,
or pruning helps every node except the one with the largest DAG.

**RESOLVED — anchor deletion is NOT a defect.** Pinned by
`dag_prune::linear_admission_survives_prune_then_restart_with_empty_relations`.
Scoring a new block only consults its SELECTED PARENT's score, and the selected
parent is at the tip — inside the retained window — so its anchor is retained too.
Nothing on the linear path ever scores against a pruned block. The anchor keyspace
stays bounded at no cost to correctness.

A caveat worth carrying: the first version of that test used
`DagStore::with_permissive_vrf_for_testing()`, which has **no persistence**, so
`put_derived_blue_score` is a silent no-op and every lookup falls through to the
deep walk. It "failed", appearing to confirm the defect. It was measuring the
no-anchor path. Any future test of anchor behaviour must use a PERSISTENT store or
it answers a different question than the one asked.

**Original text of the anchor concern, retained for provenance:**
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

1. ~~A prune-then-rehydrate test, settling the anchor question above.~~ **DONE** —
   not a defect; pinned by
   `linear_admission_survives_prune_then_restart_with_empty_relations`.
2. **PARTIALLY DONE** — MP-DEPTH is implemented in `validate_block_consistency`
   (`ghostdag.rs`), gated on `with_merge_depth_activation_height`, `None` by
   default so it is inert until scheduled. 3 tests, including one asserting it
   changes nothing before activation. **The producer does not yet refuse to build
   violating blocks** — still open.
3. The blue-set walk bounded at the retained window, justified by MP-DEPTH. **Open,
   and it cannot land before MP-DEPTH is ACTIVE on the fleet**: bounding the walk
   while blocks may still legally cite below the window computes a wrong score
   instead of an error, which is the silent fork this whole spec exists to avoid.
4. `pruning_window` unified with the pruner's retain value — one source of truth.
   **Open.**
5. Bound the producer's genesis-deep eager-load (new; see above). **Open.**
6. `merge_block_referencing_a_pruned_parent_is_rejected_not_scored` green, ignore
   removed. **Open** — it goes green with item 3.
7. Only then: `CITRATE_DAG_PRUNE_RETAIN` set on the fleet.

### Ordering constraint

Items 2 and 3 cannot ship together. MP-DEPTH must be enforced by every node, at an
agreed activation height, BEFORE any node bounds its walk. Shipping them in one
release means the first node to upgrade bounds its walk while its peers still
produce blocks it will now score differently. Two releases, with the fleet fully
upgraded and past the activation height in between.

## What is NOT blocked on any of this

The bootnodes are surviving today by being restarted. That works because the
applied-tip pointer is durable, so a restart resumes rather than replays. It is
not a fix, and boot1 showed the failure mode restarts do not cover: a node that
reaches the memory ceiling *without* being killed does not loop and recover — it
parks, RPC still answering and systemd still reporting `active`, processing
nothing. **A progress-based health check (height advancing, not process alive) is
independent of this spec, cheap, and would have caught that.** Recommend it
first, whatever is decided about pruning.
