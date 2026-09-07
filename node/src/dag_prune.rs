// citrate/node/src/dag_prune.rs
//
// SYNC-S1 D3 step 2 — bound the in-memory DAG store.
//
// Planset: citrate-federation/.agentile/planset/
//          2026-07-24-sync-s1-crash-atomic-admission-and-blueset-memory.md
//
// WHY
//
// D1 removed the Theta(N²) blue-ancestry retention, which is what OOM-killed
// every follower in the 9k-15k range. What remains is O(N): `DagStore.blocks`
// holds every block it has ever admitted, and nothing ever removes them. The
// G3 fleet run (boot3, genesis-resume to head) measured that at **~16 KB per
// block**, linear, on a ~1.4 GiB baseline — which dates the ceiling rather than
// guessing at it: a 3.9 GB follower runs out at roughly 150k blocks.
//
// WHAT WAS ACTUALLY MISSING
//
// Not the mechanism. `DagStore::prune()` has existed all along, and
// `GhostDagParams` already carries `pruning_window` and `finality_depth`
// (surfaced over RPC, never used). The blocker was that pruning BROKE score
// derivation: D1's cold path walks the selected-parent chain back to the
// nearest known score, so pruning the ancestry made the walk hit a missing
// block and admission fail. D3 step 1 (the durable `score:<hash>` anchor)
// removed that walk, so retaining deep ancestry is no longer required and this
// scheduler becomes safe to wire.
//
// SAFETY BOUNDS (why a window of 1_000 is a hard floor)
//
//   * `canonical_apply::MAX_REORG_DEPTH` = 100 — a fork older than this is
//     already refused, so a block more than 100 below the applied tip can never
//     be reorged onto.
//   * `GhostDagParams::finality_depth` = 100 — same order.
//   * `block_serve` reads the CHAIN store exclusively (verified), so serving
//     peers is completely unaffected by DAG-store pruning. This is the reason
//     pruning the DAG is far less dangerous than it sounds: the DAG store is
//     fork-choice working state, not the archive.
//
// The floor is therefore 10x the deepest revertible reorg, and the default
// window is 100x it.
//
// STILL UNBOUNDED, DELIBERATELY OUT OF SCOPE HERE
//
// A merge block's score falls back to `calculate_blue_set`, which walks the
// selected-parent chain to genesis and would fail against a pruned store. The
// live chain is entirely linear (`mergeParentHashes: []` throughout), so this is
// unexercised today — but it MUST be bounded before the DAG carries real merge
// traffic. That is why this scheduler is opt-in rather than default-on.

use std::sync::Arc;

use citrate_consensus::dag_store::DagStore;
use citrate_storage::StorageManager;
use tracing::{debug, info, warn};

/// Env var that enables DAG pruning AND sets the retain window, in blocks.
///
/// Absent => pruning disabled (the default). Opt-in because the merge-block
/// path above is not yet bounded, and because this changes the memory/retention
/// behaviour of a T1 consensus surface — it should be switched on deliberately,
/// not inherited by a node that happened to take an upgrade.
pub const RETAIN_ENV: &str = "CITRATE_DAG_PRUNE_RETAIN";

/// Hard floor on the retain window: 10x `MAX_REORG_DEPTH`. A smaller request is
/// clamped up rather than honoured — an operator typo must not be able to prune
/// inside the revertible-reorg window.
pub const MIN_RETAIN_BLOCKS: u64 = 1_000;

/// Window used when the env var is set to a non-numeric value.
pub const DEFAULT_RETAIN_BLOCKS: u64 = 10_000;

/// The configured retain window, or `None` when pruning is disabled.
pub fn configured_retain() -> Option<u64> {
    let raw = std::env::var(RETAIN_ENV).ok()?;
    let requested = raw.trim().parse::<u64>().unwrap_or(DEFAULT_RETAIN_BLOCKS);
    Some(requested.max(MIN_RETAIN_BLOCKS))
}

/// The height whose block becomes the pruning point, or `None` when there is
/// nothing safe to prune.
///
/// `prune()` removes blocks strictly BELOW the pruning point, so this returns
/// the floor of the retained range. Pure function so the policy is unit-testable
/// without a store.
pub fn pruning_point_height(applied_height: u64, retain: u64) -> Option<u64> {
    let retain = retain.max(MIN_RETAIN_BLOCKS);
    let point = applied_height.checked_sub(retain)?;
    // point == 0 would make `prune()` a no-op (nothing is below height 0) and
    // would also target genesis itself; skip until the chain is deep enough.
    if point == 0 {
        return None;
    }
    Some(point)
}

/// Run one pruning pass. Returns the number of blocks dropped from the DAG store.
///
/// Reads the canonical height->hash mapping from the CHAIN store, so the pruning
/// point is always a block on the applied chain rather than whichever sibling
/// the DAG happens to hold at that height.
pub async fn prune_once(
    storage: &StorageManager,
    dag_store: &DagStore,
    applied_height: u64,
    retain: u64,
) -> usize {
    let Some(point) = pruning_point_height(applied_height, retain) else {
        debug!("dag-prune: chain too short to prune (applied {applied_height}, retain {retain})");
        return 0;
    };

    let hash = match storage.blocks.get_block_by_height(point) {
        Ok(Some(h)) => h,
        Ok(None) => {
            debug!("dag-prune: no canonical block at height {point}; skipping this pass");
            return 0;
        }
        Err(e) => {
            warn!("dag-prune: could not read the canonical block at {point}: {e}");
            return 0;
        }
    };

    // `update_pruning_point` refuses a hash the DAG store does not hold, which
    // is the guard against pointing the window at a block this node never
    // admitted. A refusal here is benign — the next pass retries.
    if let Err(e) = dag_store.update_pruning_point(hash).await {
        debug!("dag-prune: pruning point {hash} @ {point} not usable yet: {e}");
        return 0;
    }
    match dag_store.prune().await {
        Ok(0) => 0,
        Ok(n) => {
            info!(
                "dag-prune: dropped {n} block(s) below height {point} \
                 (applied tip {applied_height}, retaining {retain})"
            );
            n
        }
        Err(e) => {
            warn!("dag-prune: prune pass failed: {e}");
            0
        }
    }
}

/// Spawn the periodic pruning task. No-op (and no task) unless [`RETAIN_ENV`] is
/// set. `applied_height` is read fresh each pass from the durable applied tip,
/// so pruning tracks the APPLIED chain and never runs ahead of executed state.
pub fn spawn(storage: Arc<StorageManager>, dag_store: Arc<DagStore>) {
    let Some(retain) = configured_retain() else {
        debug!(
            "dag-prune: disabled (set {RETAIN_ENV}=<blocks> to bound DagStore memory; \
             floor {MIN_RETAIN_BLOCKS})"
        );
        return;
    };
    info!(
        "dag-prune: ENABLED — retaining {retain} blocks in the DAG store \
         (>= {MIN_RETAIN_BLOCKS}; reorg window is 100)"
    );
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            tick.tick().await;
            let applied_height = storage
                .blocks
                .get_applied_tip()
                .ok()
                .flatten()
                .map(|(_, h)| h)
                .unwrap_or(0);
            prune_once(&storage, &dag_store, applied_height, retain).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_to_prune_on_a_short_chain() {
        // Applied tip below the window: the whole chain is inside it.
        assert_eq!(pruning_point_height(0, 10_000), None);
        assert_eq!(pruning_point_height(500, 10_000), None);
        assert_eq!(
            pruning_point_height(10_000, 10_000),
            None,
            "point would be 0"
        );
    }

    #[test]
    fn prunes_below_the_retained_window() {
        assert_eq!(pruning_point_height(11_000, 10_000), Some(1_000));
        assert_eq!(pruning_point_height(67_441, 10_000), Some(57_441));
    }

    /// An operator typo must never be able to prune inside the revertible-reorg
    /// window (MAX_REORG_DEPTH = 100). A too-small request is clamped UP.
    #[test]
    fn retain_window_is_clamped_to_the_floor() {
        // Asking to keep 10 blocks must behave as if 1_000 were asked for.
        assert_eq!(
            pruning_point_height(50_000, 10),
            Some(50_000 - MIN_RETAIN_BLOCKS)
        );
        assert_eq!(
            pruning_point_height(50_000, 0),
            Some(50_000 - MIN_RETAIN_BLOCKS)
        );
        // And the retained range always clears the reorg window by 10x.
        let point = pruning_point_height(50_000, 1).expect("clamped");
        assert!(
            50_000 - point >= 10 * 100,
            "retained range must clear MAX_REORG_DEPTH by an order of magnitude"
        );
    }

    /// End-to-end: `prune_once` must actually shrink the DAG store against real
    /// stores, and admission must keep working afterwards.
    ///
    /// This is the D3 payoff — the O(N) growth the G3 run measured at ~16 KB per
    /// block becomes O(window). Uses a retain window at the floor (1_000) with a
    /// 1_500-block chain, so the arithmetic is checkable by hand.
    #[tokio::test]
    async fn prune_once_bounds_the_dag_store_and_admission_still_works() {
        use citrate_consensus::dag_store::DagStore;
        use citrate_consensus::ghostdag::GhostDag;
        use citrate_consensus::types::{BlockBuilder, GhostDagParams, Hash, VrfProof};
        use citrate_storage::pruning::PruningConfig;

        fn mk(height: u64, parent: Hash) -> citrate_consensus::types::Block {
            let mut b = BlockBuilder::new()
                .version(2)
                .height(height)
                .parent(parent)
                .coinbase([0x33; 20])
                .timestamp(1000)
                .vrf_reveal(VrfProof {
                    proof: vec![],
                    output: Hash::new([0x5A; 32]),
                })
                .transactions(vec![])
                .state_root(Hash::default())
                .blue_score(height)
                .blue_work(citrate_consensus::types::blue_work_for_score(height))
                .build_unhashed();
            b.header.block_hash = b.compute_hash();
            b
        }

        const N: u64 = 1_500;
        const RETAIN: u64 = MIN_RETAIN_BLOCKS; // 1_000

        let dir = tempfile::tempdir().expect("tempdir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = GhostDag::new(GhostDagParams::default(), dag.clone());

        // Admit a linear chain into BOTH stores, as the admission path does.
        let mut parent = Hash::default();
        for h in 1..=N {
            let b = mk(h, parent);
            parent = b.header.block_hash;
            dag.store_block(b.clone()).await.expect("dag");
            ghostdag.add_block(&b).await.expect("admit");
            storage.blocks.put_block(&b).expect("chain");
        }
        storage.blocks.put_applied_tip(&parent, N).expect("tip");

        let before = dag.get_stats().await.total_blocks;
        assert_eq!(before, N as usize, "every block retained pre-prune");

        // One pass: point = 1500 - 1000 = 500, so heights 1..=499 go.
        let dropped = prune_once(&storage, &dag, N, RETAIN).await;
        assert_eq!(
            dropped, 499,
            "heights 1..=499 dropped (pruning point is 500)"
        );
        let after = dag.get_stats().await.total_blocks;
        assert_eq!(after, before - 499);
        assert!(
            after < before,
            "the DAG store must actually shrink — this is the O(N) -> O(window) fix"
        );

        // The retained window is intact and clears the reorg depth by 10x.
        assert!(
            dag.has_block(&parent).await,
            "the applied tip must never be pruned"
        );
        const {
            assert!(
                N - 500 >= 10 * 100,
                "retained range clears MAX_REORG_DEPTH 10x"
            )
        };

        // And the chain still grows: admitting on top of a pruned ancestry works
        // because D3 step 1 replaced the ancestry walk with a durable anchor.
        let next = mk(N + 1, parent);
        dag.store_block(next.clone()).await.expect("dag");
        ghostdag
            .add_block(&next)
            .await
            .expect("admission must survive a pruned ancestry");
        // In this fixture the chain ROOT is the height-1 block (its selected
        // parent is `Hash::default()`, so `is_genesis()` holds and it scores 1).
        // The convention is therefore score == height here, one lower than a
        // chain with a real height-0 genesis. What matters is that the sequence
        // CONTINUES unbroken across the prune.
        assert_eq!(
            ghostdag
                .get_blue_score(&next.header.block_hash)
                .await
                .unwrap(),
            N + 1,
            "score sequence continues across the prune"
        );

        // Idempotent: a second pass at the same tip has nothing new to drop.
        assert_eq!(
            prune_once(&storage, &dag, N, RETAIN).await,
            0,
            "re-running at the same applied height must be a no-op"
        );
    }

    /// RED — the hazard `prune_once_bounds_the_dag_store_and_admission_still_works`
    /// does NOT cover, and the reason pruning is still opt-in.
    ///
    /// That test admits a LINEAR block over a pruned ancestry and passes, because
    /// D3's durable score anchor makes the linear case O(1). A MERGE block is a
    /// different path entirely: `derive_score_and_work` falls back to
    /// `calculate_blue_set`, whose phase-1 walk (`get_or_calculate_blue_set`)
    /// resolves ancestors through `DagStore::get_block` — which is MEMORY-ONLY
    /// and has no disk fallback. Once the merge parent is below the pruning
    /// point, that lookup returns `BlockNotFound` and admission REJECTS a block
    /// the rest of the fleet accepts.
    ///
    /// That is not a crash, it is a FORK: an unpruned node admits the block, a
    /// pruned node refuses it, and the two disagree about the canonical chain.
    ///
    /// Nothing in `validate_block_consistency` prevents such a block. It checks
    /// merge-parent existence, `max_parents`, and that no merge parent outranks
    /// the selected parent by blue score — but imposes NO lower bound on merge
    /// parent DEPTH. A block at height 72,000 may legally merge a parent at
    /// height 5.
    ///
    /// Settles the open question in PRUNE_MERGE_PARENT_BOUND_SPEC.md: does
    /// `prune()` deleting each pruned block's durable score anchor
    /// (`persist_delete_derived_blue_score`) break the LINEAR path across a
    /// restart?
    ///
    /// The worry was concrete. `GhostDag::relations` is in-memory only and a
    /// non-producing node never runs the producer's eager-load loop, so after a
    /// restart it is EMPTY. `derive_score_and_work` then depends on the durable
    /// anchor — and prune deletes anchors along with their blocks.
    ///
    /// ANSWER: not a defect. Scoring a new block only ever consults its SELECTED
    /// PARENT's score, and the selected parent is at the tip, inside the retained
    /// window, so its anchor is retained too. Nothing scores against a pruned
    /// block on the linear path. The anchor keyspace is bounded (the reason it is
    /// deleted) at no cost to correctness.
    ///
    /// Pinned as a test rather than left as reasoning in a doc, because the
    /// conclusion depends on "the selected parent is always inside the window",
    /// which a future change to the retain floor could quietly break.
    #[tokio::test]
    async fn linear_admission_survives_prune_then_restart_with_empty_relations() {
        use citrate_consensus::dag_store::DagStore;
        use citrate_consensus::ghostdag::GhostDag;
        use citrate_consensus::types::{BlockBuilder, GhostDagParams, Hash, VrfProof};
        use citrate_storage::pruning::PruningConfig;

        fn mk(height: u64, parent: Hash) -> citrate_consensus::types::Block {
            let mut b = BlockBuilder::new()
                .version(2)
                .height(height)
                .parent(parent)
                .coinbase([0x33; 20])
                .timestamp(1000)
                .vrf_reveal(VrfProof {
                    proof: vec![],
                    output: Hash::new([0x5A; 32]),
                })
                .transactions(vec![])
                .state_root(Hash::default())
                .blue_score(height)
                .blue_work(citrate_consensus::types::blue_work_for_score(height))
                .build_unhashed();
            b.header.block_hash = b.compute_hash();
            b
        }

        const N: u64 = 1_500;
        let dir = tempfile::tempdir().expect("tempdir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        // PERSISTENT DagStore — the fixture detail that decides what this test
        // actually exercises. With the non-persistent test store,
        // `put_derived_blue_score` is a silent no-op, so the durable anchor never
        // exists and every lookup falls through to the deep walk. That measures
        // the no-anchor path, not the anchor path, and answers the wrong
        // question. A real node always has persistence here.
        let kv = Arc::new(crate::persistent_dag::RocksDbKvStore::new(
            storage.db.clone(),
        ));
        let dag = Arc::new(
            DagStore::persistent_with_strict_vrf(kv, false).expect("persistent dag store"),
        );
        let ghostdag = GhostDag::new(GhostDagParams::default(), dag.clone());

        let mut parent = Hash::default();
        for h in 1..=N {
            let b = mk(h, parent);
            parent = b.header.block_hash;
            dag.store_block(b.clone()).await.expect("dag");
            ghostdag.add_block(&b).await.expect("admit");
            storage.blocks.put_block(&b).expect("chain");
        }
        storage.blocks.put_applied_tip(&parent, N).expect("tip");
        assert!(
            dag.get_derived_blue_score(&parent).is_some(),
            "the tip's durable anchor must exist, or this test is exercising the \
             no-anchor path again rather than the question being asked"
        );
        assert_eq!(prune_once(&storage, &dag, N, MIN_RETAIN_BLOCKS).await, 499);
        assert!(
            dag.get_derived_blue_score(&parent).is_some(),
            "pruning must not delete the RETAINED tip's anchor"
        );

        // RESTART, follower-style: a brand-new GhostDag over the SAME (pruned)
        // DAG store. `relations` is empty, exactly as it is on a bootnode that
        // has just come up and never runs the producer's eager-load loop.
        let after_restart = GhostDag::new(GhostDagParams::default(), dag.clone());

        let next = mk(N + 1, parent);
        dag.store_block(next.clone()).await.expect("dag");
        after_restart
            .add_block(&next)
            .await
            .expect("linear admission must survive prune + restart with empty relations");
        assert_eq!(
            after_restart
                .get_blue_score(&next.header.block_hash)
                .await
                .expect("score"),
            N + 1,
            "the score sequence continues unbroken across prune AND restart"
        );
    }

    /// THE REMEDY, proven (post-reroll semantics, CHAIN-B-A002/A006).
    ///
    /// After the 2026-08-04 re-roll, `MERGE_DEPTH_ACTIVATION_HEIGHT` is **0**: MP-DEPTH is
    /// enforced from genesis, one validity rule for the whole chain (the pre-reroll history
    /// that once carried block 54,601 merging a height-32 parent was WIPED, so there is
    /// nothing left to stay compatible with, and a non-zero activation would itself be a
    /// fork-by-configuration hazard). This test now pins the invariant that MP-DEPTH exists
    /// to guarantee, which is exactly what makes DAG pruning safe fleet-wide:
    ///
    ///   MERGE_PARENT_MAX_DEPTH (100) < MIN_RETAIN_BLOCKS (1,000) <= retain window
    ///
    /// so no VALID block can cite a merge parent the pruner may have dropped. Concretely:
    ///   * a merge parent WITHIN the bound (depth ≤ 100) admits — the legal merges a
    ///     cold-syncing node crosses; and
    ///   * a merge parent OVER the bound (depth > 100) is REJECTED at every height,
    ///     including height 1 — so a pruned node and an unpruned node can never disagree
    ///     about such a block, because it is invalid for both.
    ///
    /// (Before this test was corrected it asserted the OPPOSITE — that a 1,301-deep merge
    /// must admit — which encoded the pre-reroll `activation = 100_000` world and failed
    /// against `activation = 0`. RC-8: the fixture, not the code, was stale.)
    #[tokio::test]
    async fn no_pruning_admits_the_deep_merge_parent_that_wedges_a_pruned_node() {
        use citrate_consensus::dag_store::DagStore;
        use citrate_consensus::ghostdag::{GhostDag, MERGE_PARENT_MAX_DEPTH};
        use citrate_consensus::types::{BlockBuilder, GhostDagParams, Hash, VrfProof};
        use citrate_storage::pruning::PruningConfig;

        fn mk(height: u64, parent: Hash, merges: Vec<Hash>) -> citrate_consensus::types::Block {
            let mut b = BlockBuilder::new()
                .version(2)
                .height(height)
                .parent(parent)
                .merge_parents(merges)
                .coinbase([0x33; 20])
                .timestamp(1000)
                .vrf_reveal(VrfProof {
                    proof: vec![],
                    output: Hash::new([0x5A; 32]),
                })
                .transactions(vec![])
                .state_root(Hash::default())
                .blue_score(height)
                .blue_work(citrate_consensus::types::blue_work_for_score(height))
                .build_unhashed();
            b.header.block_hash = b.compute_hash();
            b
        }

        const N: u64 = 1_500;
        let dir = tempfile::tempdir().expect("tempdir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = GhostDag::new(GhostDagParams::default(), dag.clone());

        // The merge block lands at height N+1, so a merge parent at height
        // `N + 1 - MERGE_PARENT_MAX_DEPTH` is EXACTLY at the bound (admits) and one at
        // `N - MERGE_PARENT_MAX_DEPTH` is one-past the bound (rejected).
        let within_bound_height = N + 1 - MERGE_PARENT_MAX_DEPTH; // depth == 100
        let over_bound_height = N - MERGE_PARENT_MAX_DEPTH; // depth == 101

        let mut parent = Hash::default();
        let mut within_bound_hash = Hash::default();
        let mut over_bound_hash = Hash::default();
        for h in 1..=N {
            let b = mk(h, parent, vec![]);
            parent = b.header.block_hash;
            if h == within_bound_height {
                within_bound_hash = b.header.block_hash;
            }
            if h == over_bound_height {
                over_bound_hash = b.header.block_hash;
            }
            dag.store_block(b.clone()).await.expect("dag");
            ghostdag.add_block(&b).await.expect("admit");
            storage.blocks.put_block(&b).expect("chain");
        }
        storage.blocks.put_applied_tip(&parent, N).expect("tip");

        // No prune pass runs (as when CITRATE_DAG_PRUNE_RETAIN is unset), so both candidate
        // merge parents are still held — this isolates MP-DEPTH from pruning.
        assert!(
            configured_retain().is_none() || std::env::var(RETAIN_ENV).is_err(),
            "this test asserts the UNPRUNED path; it is meaningless if the env var \
             is set in the test process"
        );
        assert!(dag.has_block(&within_bound_hash).await);
        assert!(dag.has_block(&over_bound_hash).await);

        // (1) A merge parent at exactly MERGE_PARENT_MAX_DEPTH admits — the legal merge a
        // cold-syncing node must be able to cross.
        let ok = mk(N + 1, parent, vec![within_bound_hash]);
        dag.store_block(ok.clone()).await.expect("dag");
        ghostdag
            .add_block(&ok)
            .await
            .expect("a merge parent within MP-DEPTH must admit");
        assert_eq!(
            ghostdag
                .get_blue_score(&ok.header.block_hash)
                .await
                .expect("score"),
            N + 1,
            "the applied chain advances past a legal merge"
        );

        // (2) A merge parent one-past the bound is REJECTED from genesis (activation = 0).
        // This is the property that makes pruning safe: no valid block cites a droppable
        // parent, so pruned and unpruned nodes never diverge on it.
        let bad = mk(N + 1, parent, vec![over_bound_hash]);
        dag.store_block(bad.clone()).await.expect("dag");
        let err = ghostdag
            .add_block(&bad)
            .await
            .expect_err("a merge parent deeper than MP-DEPTH must be rejected from genesis");
        assert!(
            format!("{err:?}").contains("MP-DEPTH")
                || format!("{err:?}").contains("below this block"),
            "rejection must be the MP-DEPTH linkage error, got: {err:?}"
        );
    }

    /// HISTORICAL — the pre-reroll 54,600 cold-sync wedge on 40204 (chain history since WIPED).
    ///
    /// Written 2026-07-29 as a synthetic hazard. Confirmed 2026-07-30 as the
    /// actual cause of "a fresh node cannot cold-sync past block 54,600":
    ///
    ///   block 54,600 `0xb3b1ee47…`  mergeParentHashes: []
    ///   block 54,601 `0xa267188c…`  mergeParentHashes: ["0x175fdf2b…"]
    ///   `0x175fdf2b…` is at **height 32** (blueScore 0x20)
    ///
    /// Block 54,601 legally merged a parent 54,569 blocks below it — an artefact
    /// of the 2026-07-27 concurrent-producer fork, under the OLD rule set where
    /// merge depth was unbounded. With `CITRATE_DAG_PRUNE_RETAIN=10000` and an
    /// applied height of 54,600 the pruning point was 44,600, so height 32 was
    /// GONE, and admission of 54,601 failed `validate_block_consistency` with
    /// `MissingParent` forever.
    ///
    /// POST-REROLL (2026-08-04, CHAIN-B-A006): this can no longer occur. The re-roll
    /// wiped that history AND set `MERGE_DEPTH_ACTIVATION_HEIGHT = 0`, so MP-DEPTH
    /// (#138) is enforced from genesis: a block merging a parent deeper than
    /// `MERGE_PARENT_MAX_DEPTH` (100) is INVALID at every height and is rejected on
    /// admission before pruning is ever consulted. Because `MERGE_PARENT_MAX_DEPTH
    /// (100) < MIN_RETAIN_BLOCKS (1,000)`, no valid block can cite a parent the pruner
    /// may drop, so pruned and unpruned nodes cannot diverge. The corrected companion
    /// `no_pruning_admits_the_deep_merge_parent_that_wedges_a_pruned_node` pins this.
    ///
    /// This stays `#[ignore]`d: it reconstructs a block shape that is now simply
    /// invalid, kept as the audit record of the wedge it once caused.
    ///
    /// Run it with: `cargo test -p citrate-node --bin citrate -- --ignored`
    #[tokio::test]
    #[ignore = "Reconstructs the pre-reroll 54,600 cold-sync wedge (block 54,601 merges height \
                32). Cannot recur post-reroll: MP-DEPTH #138 is enforced from genesis \
                (MERGE_DEPTH_ACTIVATION_HEIGHT = 0). See the corrected companion test."]
    async fn merge_block_referencing_a_pruned_parent_is_rejected_not_scored() {
        use citrate_consensus::dag_store::DagStore;
        use citrate_consensus::ghostdag::GhostDag;
        use citrate_consensus::types::{BlockBuilder, GhostDagParams, Hash, VrfProof};
        use citrate_storage::pruning::PruningConfig;

        fn mk(height: u64, parent: Hash, merges: Vec<Hash>) -> citrate_consensus::types::Block {
            let mut b = BlockBuilder::new()
                .version(2)
                .height(height)
                .parent(parent)
                .merge_parents(merges)
                .coinbase([0x33; 20])
                .timestamp(1000)
                .vrf_reveal(VrfProof {
                    proof: vec![],
                    output: Hash::new([0x5A; 32]),
                })
                .transactions(vec![])
                .state_root(Hash::default())
                .blue_score(height)
                .blue_work(citrate_consensus::types::blue_work_for_score(height))
                .build_unhashed();
            b.header.block_hash = b.compute_hash();
            b
        }

        const N: u64 = 1_500;
        const RETAIN: u64 = MIN_RETAIN_BLOCKS;

        let dir = tempfile::tempdir().expect("tempdir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = GhostDag::new(GhostDagParams::default(), dag.clone());

        let mut parent = Hash::default();
        let mut deep_hash = Hash::default();
        for h in 1..=N {
            let b = mk(h, parent, vec![]);
            parent = b.header.block_hash;
            // Remember a block that WILL be pruned (point is N - RETAIN = 500).
            if h == 200 {
                deep_hash = b.header.block_hash;
            }
            dag.store_block(b.clone()).await.expect("dag");
            ghostdag.add_block(&b).await.expect("admit");
            storage.blocks.put_block(&b).expect("chain");
        }
        storage.blocks.put_applied_tip(&parent, N).expect("tip");

        let dropped = prune_once(&storage, &dag, N, RETAIN).await;
        assert_eq!(dropped, 499);
        assert!(
            !dag.has_block(&deep_hash).await,
            "height-200 block must be gone for this test to mean anything"
        );

        // A merge block whose merge parent is now BELOW the pruning point.
        // Legal by every rule `validate_block_consistency` enforces.
        let merge = mk(N + 1, parent, vec![deep_hash]);
        dag.store_block(merge.clone()).await.expect("dag");
        let outcome = ghostdag.add_block(&merge).await;

        assert!(
            outcome.is_ok(),
            "PRUNE HAZARD: a merge block referencing a pruned parent was rejected \
             ({outcome:?}). An unpruned peer accepts this block, so the two nodes \
             now disagree about the canonical chain — a fork, caused by a purely \
             local storage policy. Bound merge-parent depth in consensus before \
             enabling pruning."
        );
    }

    #[test]
    fn disabled_unless_the_env_var_is_set() {
        // The test process may run in any order, so assert the parse rules
        // rather than mutating global env: absent => None is the contract, and
        // a set value is clamped to the floor.
        assert_eq!(
            DEFAULT_RETAIN_BLOCKS.max(MIN_RETAIN_BLOCKS),
            DEFAULT_RETAIN_BLOCKS
        );
        const {
            assert!(
                MIN_RETAIN_BLOCKS >= 10 * 100,
                "floor must clear the reorg window"
            )
        };
    }
}
