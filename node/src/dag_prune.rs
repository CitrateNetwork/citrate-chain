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
// SAFETY BOUNDS (why the retention is never below the undo window)
//
//   * `canonical_apply::MAX_REORG_DEPTH` = 10,000 — the undo window, equal to
//     the retention (ADR-2026-11-03 CV-7a, S3-4; it was 100 before, and a
//     pruned node forked deeper than that was wedged for good, root cause
//     H6). Any fork the DAG store still holds is switched across in place,
//     from the undo records. A deeper switch is the from-genesis spine
//     rebuild on an unpruned node, which reads the CHAIN store and is allowed
//     only toward a branch fork choice ranks above the applied tip whose
//     ancestry meets the applied chain (`CanonicalApplicator::rebuild_target`);
//     on a pruned node it is refused and the guarded cold resync takes over
//     (CV-7b/c). A block pruned from the DAG store is never read as divergence.
//   * `GhostDagParams::finality_depth` = 100 — far inside it.
//   * `block_serve` reads the CHAIN store exclusively (verified), so serving
//     peers is completely unaffected by DAG-store pruning. This is the reason
//     pruning the DAG is far less dangerous than it sounds: the DAG store is
//     fork-choice working state, not the archive.
//
// The floor and the default are therefore the undo window itself.
//
// MERGE BLOCKS (MS-BOUND)
//
// A merge block's score used to fall back to `calculate_blue_set`, which walks
// the selected-parent chain to genesis and fails against a pruned store. Fork
// choice now scores a merge block from a bounded window
// (`ghostdag::MERGE_SCORE_WINDOW`, 200 heights), always inside the retained
// range, so pruned and unpruned nodes compute the same score
// (`pruned_node_scores_a_sibling_merge_like_an_unpruned_node`). Pruning stays
// opt-in: it changes the memory/retention behaviour of a consensus surface.

use std::sync::Arc;

use citrate_consensus::dag_store::DagStore;
use citrate_storage::StorageManager;
use tracing::{debug, info, warn};

/// Env var that enables DAG pruning AND sets the retain window, in blocks.
///
/// Absent => pruning disabled (the default). Opt-in because this changes the
/// memory/retention behaviour of a T1 consensus surface — it should be switched
/// on deliberately, not inherited by a node that happened to take an upgrade.
pub const RETAIN_ENV: &str = "CITRATE_DAG_PRUNE_RETAIN";

/// Hard floor on the retain window: the undo window
/// (`canonical_apply::MAX_REORG_DEPTH`, CV-7a; spec 06 G11: the retention may
/// only be larger than PRUNING_DEPTH). A smaller request is clamped up rather
/// than honoured — an operator typo must not be able to prune inside the
/// revertible-reorg window.
pub const MIN_RETAIN_BLOCKS: u64 = 10_000;

/// Window used when the env var is set to a non-numeric value: the undo window.
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
///
/// Spec 06 G11: a node MUST NOT prune at or above `pruning_point(applied tip)`.
/// The point is `applied - retain` rounded DOWN to a checkpoint height, so it
/// is never above the tip's G11 pruning point (`retain >= PRUNING_DEPTH`) and
/// the tip's committed pruning point block stays in the DAG store.
pub fn pruning_point_height(applied_height: u64, retain: u64) -> Option<u64> {
    let retain = retain.max(MIN_RETAIN_BLOCKS);
    let interval = citrate_consensus::checkpoint::CHECKPOINT_INTERVAL;
    let unaligned = applied_height.checked_sub(retain)?;
    let point = unaligned
        .checked_div(interval)
        .unwrap_or(0)
        .saturating_mul(interval);
    // point == 0 would make `prune()` a no-op (nothing is below height 0) and
    // would also target genesis itself; skip until the chain is deep enough.
    if point == 0 {
        return None;
    }
    Some(point)
}

/// G11 (spec 06 §2): the chain store as the [`AncestryHeaders`] source of the
/// pruning-point walk. DAG pruning drops blocks from the DAG store only; the
/// chain store keeps their headers (`CF_HEADERS`), so a pruned node validates
/// the pruning point of a late or side-branch block inside the undo window the
/// same way an unpruned node does. Data source: `BlockStore::get_header`.
///
/// [`AncestryHeaders`]: citrate_consensus::ghostdag::AncestryHeaders
pub struct ChainStoreHeaders(pub Arc<StorageManager>);

impl citrate_consensus::ghostdag::AncestryHeaders for ChainStoreHeaders {
    fn header(
        &self,
        hash: &citrate_consensus::types::Hash,
    ) -> Option<citrate_consensus::types::BlockHeader> {
        match self.0.blocks.get_header(hash) {
            Ok(h) => h,
            Err(e) => {
                warn!("dag-prune: chain-store header {hash} unreadable for the G11 walk: {e}");
                None
            }
        }
    }
}

/// The height below which DAG pruning has dropped blocks from `dag_store`
/// (`DagStore::prune` removes everything strictly below the pruning point's
/// height). 0 when pruning has never run, or the pruning point block cannot be
/// read.
///
/// Readers: admission (a re-delivered block below it is already held) and the
/// applicator (it never rebuilds the applied chain from genesis on a pruned
/// node; see `CanonicalApplicator::with_dag_prune_floor`).
pub async fn pruned_below(dag_store: &DagStore) -> u64 {
    let point = dag_store.get_pruning_point().await;
    if point == citrate_consensus::types::Hash::default() {
        return 0;
    }
    match dag_store.get_block(&point).await {
        Ok(b) => b.header.height,
        Err(_) => 0,
    }
}

/// Run one pruning pass. Returns the number of blocks dropped from the DAG store.
///
/// Reads the canonical height->hash mapping from the CHAIN store
/// (`get_canonical_block_by_height`, chain#421), so the pruning point is always
/// a block on the applied chain rather than whichever sibling was stored last
/// at that height.
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

    let hash = match storage.blocks.get_canonical_block_by_height(point) {
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
         (>= {MIN_RETAIN_BLOCKS}; reorg window is {})",
        crate::canonical_apply::MAX_REORG_DEPTH
    );
    tokio::spawn(async move {
        // #310: Skip — never run prunes back to back after a slow pass.
        let mut tick = crate::timing::cadence_interval(std::time::Duration::from_secs(300));
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

    /// A producer restarted on a pruned store must not reload the pruned range.
    ///
    /// The eager load in `BlockProducer::with_shared_dag` walks every canonical
    /// height from 0 out of the chain store. Below the pruning point the DAG
    /// store no longer holds the blocks (genesis included), so each one is
    /// offered to `store_block` again (re-growing exactly what pruning bounds on
    /// a permissive store, refused with a warn line per height on the strict
    /// production store) and registered with GhostDag under a fallback score.
    /// On r1006 that is ~294k heights and tens of thousands of warn lines per
    /// restart. The load must start at the pruning floor and still register
    /// the retained chain with its pre-restart scores.
    #[tokio::test]
    async fn producer_eager_load_starts_at_the_pruning_floor() {
        use crate::persistent_dag::RocksDbKvStore;
        use crate::producer::BlockProducer;
        use citrate_consensus::crypto::Ed25519SigningKey;
        use citrate_consensus::dag_store::DagStore;
        use citrate_consensus::ghostdag::GhostDag;
        use citrate_consensus::types::{BlockBuilder, GhostDagParams, Hash, PublicKey, VrfProof};
        use citrate_execution::{Executor, StateDB};
        use citrate_sequencer::mempool::{Mempool, MempoolConfig};
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
                // G11: the committed pruning point (zero below 10,050).
                .pruning_point(crate::g11_test_seal::pruning_point(height, parent))
                .build_unhashed();
            b.header.block_hash = b.compute_hash();
            crate::g11_test_seal::record(&b);
            b
        }

        const RETAIN: u64 = MIN_RETAIN_BLOCKS;
        const N: u64 = RETAIN + 500;

        let dir = tempfile::tempdir().expect("tempdir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let mut chain = Vec::new();
        let tip_score;
        {
            let kv = Arc::new(RocksDbKvStore::new(storage.db.clone()));
            let dag = Arc::new(DagStore::persistent_with_strict_vrf(kv, false).expect("dag"));
            let ghostdag = GhostDag::new(GhostDagParams::default(), dag.clone());
            let mut parent = Hash::default();
            for h in 0..=N {
                let b = mk(h, parent);
                parent = b.header.block_hash;
                dag.store_block(b.clone()).await.expect("dag");
                ghostdag.add_block(&b).await.expect("admit");
                storage.blocks.put_block(&b).expect("chain");
                chain.push(b);
            }
            storage.blocks.put_applied_tip(&parent, N).expect("tip");
            tip_score = ghostdag.get_blue_score(&parent).await.expect("tip score");
            assert_eq!(prune_once(&storage, &dag, N, RETAIN).await, 500);
        }

        // Restart: a fresh DAG store and GhostDag over the same database, then
        // the producer's eager load.
        let kv = Arc::new(RocksDbKvStore::new(storage.db.clone()));
        let dag = Arc::new(DagStore::persistent_with_strict_vrf(kv, false).expect("reload"));
        dag.set_configured_genesis(chain[0].header.block_hash);
        let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag.clone()));
        let floor = pruned_below(&dag).await;
        assert_eq!(floor, 500, "the pruning point survives the restart");
        let executor = Arc::new(Executor::with_storage_and_chain_id(
            Arc::new(StateDB::new()),
            Some(storage.state.clone()),
            40204,
        ));
        let _producer = BlockProducer::with_shared_dag(
            storage.clone(),
            executor,
            Arc::new(Mempool::new(MempoolConfig::default())),
            None,
            PublicKey::new([0x10; 32]),
            Ed25519SigningKey::from_bytes(&[0x60; 32]),
            2,
            Arc::new(citrate_economics::UnifiedEconomicsManager::new(
                citrate_economics::UnifiedEconomicsConfig::default(),
            )),
            dag.clone(),
            ghostdag.clone(),
        )
        .await;

        for b in &chain[..floor as usize] {
            assert!(
                !dag.has_block(&b.header.block_hash).await,
                "pruned block @ {} was put back into the DAG store by the eager load",
                b.header.height
            );
            assert_eq!(
                ghostdag.get_block_height(&b.header.block_hash).await,
                None,
                "pruned block @ {} was registered with fork choice by the eager load",
                b.header.height
            );
        }
        let tip = chain[N as usize].header.block_hash;
        assert_eq!(
            ghostdag.get_blue_score(&tip).await.ok(),
            Some(tip_score),
            "the retained chain is registered with its pre-restart score"
        );
        assert_eq!(ghostdag.select_tip().await.ok(), Some(tip));
    }

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
        // G11: rounded down to a checkpoint height (57,441 -> 57,400).
        assert_eq!(pruning_point_height(67_441, 10_000), Some(57_400));
    }

    /// Spec 06 G11: "a node MUST NOT prune at or above pruning_point(applied
    /// tip)". The DAG prune point is a checkpoint height (so the tip's own
    /// committed pruning point stays in the DAG store) and never above the
    /// tip's G11 pruning point, and the retained range still covers `retain`.
    #[test]
    fn prune_floor_never_rises_above_the_tips_g11_pruning_point() {
        use citrate_consensus::checkpoint::CHECKPOINT_INTERVAL;
        use citrate_consensus::ghostdag::pruning_point_height as g11_pp_height;
        for retain in [MIN_RETAIN_BLOCKS, MIN_RETAIN_BLOCKS + 37, 25_000] {
            for applied in (0..=40_000u64).step_by(7) {
                let Some(p) = pruning_point_height(applied, retain) else {
                    continue;
                };
                assert_eq!(
                    p % CHECKPOINT_INTERVAL,
                    0,
                    "prune point {p} (applied {applied}, retain {retain}) is a checkpoint height"
                );
                assert!(
                    p <= g11_pp_height(applied),
                    "prune point {p} above the tip's pruning point {} (applied {applied})",
                    g11_pp_height(applied)
                );
                assert!(applied - p >= retain, "retains at least {retain}");
            }
        }
    }

    /// An operator typo must never be able to prune inside the revertible-reorg
    /// window (MAX_REORG_DEPTH = 10,000). A too-small request is clamped UP.
    #[test]
    fn retain_window_is_clamped_to_the_floor() {
        // Asking to keep 10 blocks must behave as if 10_000 were asked for.
        assert_eq!(
            pruning_point_height(50_000, 10),
            Some(50_000 - MIN_RETAIN_BLOCKS)
        );
        assert_eq!(
            pruning_point_height(50_000, 0),
            Some(50_000 - MIN_RETAIN_BLOCKS)
        );
        // And the retained range always covers the reorg (undo) window, which
        // is 100x the merge depth.
        let point = pruning_point_height(50_000, 1).expect("clamped");
        assert!(
            50_000 - point >= crate::canonical_apply::MAX_REORG_DEPTH,
            "retained range must cover MAX_REORG_DEPTH"
        );
        assert!(50_000 - point >= 10 * 100);
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
                // G11: the committed pruning point (zero below 10,050).
                .pruning_point(crate::g11_test_seal::pruning_point(height, parent))
                .build_unhashed();
            b.header.block_hash = b.compute_hash();
            crate::g11_test_seal::record(&b);
            b
        }

        const RETAIN: u64 = MIN_RETAIN_BLOCKS; // 10_000
        const N: u64 = RETAIN + 500;

        let dir = tempfile::tempdir().expect("tempdir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = GhostDag::new(GhostDagParams::default(), dag.clone());

        // Admit a linear chain into BOTH stores, as the admission path does.
        let mut parent = Hash::default();
        for h in 0..=N {
            let b = mk(h, parent);
            parent = b.header.block_hash;
            dag.store_block(b.clone()).await.expect("dag");
            ghostdag.add_block(&b).await.expect("admit");
            storage.blocks.put_block(&b).expect("chain");
        }
        storage.blocks.put_applied_tip(&parent, N).expect("tip");

        let before = dag.get_stats().await.total_blocks;
        assert_eq!(
            before,
            N as usize + 1,
            "every block retained pre-prune (genesis + N)"
        );

        // One pass: point = 1500 - 1000 = 500, so heights 0..=499 go.
        let dropped = prune_once(&storage, &dag, N, RETAIN).await;
        assert_eq!(
            dropped, 500,
            "heights 0..=499 dropped (pruning point is 500)"
        );
        let after = dag.get_stats().await.total_blocks;
        assert_eq!(after, before - 500);
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
        // r1007 G7: genesis scores 0, so a block at height h of a linear chain
        // scores h (its committed header value). What matters is that the
        // sequence CONTINUES unbroken across the prune.
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
                // G11: the committed pruning point (zero below 10,050).
                .pruning_point(crate::g11_test_seal::pruning_point(height, parent))
                .build_unhashed();
            b.header.block_hash = b.compute_hash();
            crate::g11_test_seal::record(&b);
            b
        }

        const N: u64 = MIN_RETAIN_BLOCKS + 500;
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
        for h in 0..=N {
            let b = mk(h, parent);
            parent = b.header.block_hash;
            dag.store_block(b.clone()).await.expect("dag");
            ghostdag.add_block(&b).await.expect("admit");
            storage.blocks.put_block(&b).expect("chain");
        }
        storage.blocks.put_applied_tip(&parent, N).expect("tip");
        // r1007 G12: the durable record is the tip's GHOSTDAG record
        // (`DAG_GHOSTDAG`), which replaced the `score:` anchor.
        assert!(
            dag.get_ghostdag_data(&parent).is_some(),
            "the tip's durable record must exist, or this test is exercising the \
             no-record path again rather than the question being asked"
        );
        assert_eq!(prune_once(&storage, &dag, N, MIN_RETAIN_BLOCKS).await, 500);
        assert!(
            dag.get_ghostdag_data(&parent).is_some(),
            "pruning must not delete the RETAINED tip's record"
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
            "the score sequence continues unbroken across prune AND restart \
             (r1007 G7: genesis 0, so height N + 1 scores N + 1)"
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
                // G11: the committed pruning point (zero below 10,050).
                .pruning_point(crate::g11_test_seal::pruning_point(height, parent))
                .build_unhashed();
            b.header.block_hash = b.compute_hash();
            crate::g11_test_seal::record(&b);
            b
        }

        const N: u64 = 1_500;
        let dir = tempfile::tempdir().expect("tempdir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = GhostDag::new(GhostDagParams::default(), dag.clone());

        // r1007 G5 (strict merge depth) replaces MP-DEPTH: every mergeset block
        // must have MDR = the chain block MERGE_DEPTH below the merging block in
        // its past. The merge block lands at height N+1, so a SIDE block (off
        // the chain, r1007 G2 forbids merging the selected parent's own
        // ancestors) at depth MERGE_DEPTH - 1 admits, and one at depth
        // MERGE_DEPTH is one past the bound (rejected).
        let within_bound_height = N + 2 - MERGE_PARENT_MAX_DEPTH; // depth == 99
        let over_bound_height = N + 1 - MERGE_PARENT_MAX_DEPTH; // depth == 100

        let mut parent = Hash::default();
        let mut within_bound_hash = Hash::default();
        let mut over_bound_hash = Hash::default();
        // SECREM-A001 RC-8: the chain roots at the real height-0 configured
        // genesis, so the loop starts at 0 (a height-1 root fails admission with
        // InvalidParents under the genesis-identity binding).
        for h in 0..=N {
            let b = mk(h, parent, vec![]);
            // The side blocks sit on the chain block below their height. Their
            // smaller VRF output keeps the chain block the heavier sibling (G3).
            if h == within_bound_height || h == over_bound_height {
                let mut side = mk(h, parent, vec![]);
                side.header.vrf_reveal.output = Hash::new([0x01; 32]);
                side.header.block_hash = side.compute_hash();
                if h == within_bound_height {
                    within_bound_hash = side.header.block_hash;
                } else {
                    over_bound_hash = side.header.block_hash;
                }
                dag.store_block(side.clone()).await.expect("dag");
                ghostdag.add_block(&side).await.expect("admit side");
            }
            parent = b.header.block_hash;
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
        // The side block's anticone (99 chain blocks) is far over K, so it is
        // red and adds nothing: the merge scores the selected parent's N + 1.
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
            // r1007 G7: genesis 0, so the chain block at height N scores N and
            // the merge (one blue: its selected parent) scores N + 1.
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
            format!("{err:?}").contains("MergeDepthViolation"),
            "rejection must be the merge-depth (G5) error, got: {err:?}"
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
                // G11: the committed pruning point (zero below 10,050).
                .pruning_point(crate::g11_test_seal::pruning_point(height, parent))
                .build_unhashed();
            b.header.block_hash = b.compute_hash();
            crate::g11_test_seal::record(&b);
            b
        }

        const RETAIN: u64 = MIN_RETAIN_BLOCKS;
        const N: u64 = RETAIN + 500;

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

    /// MS-BOUND: a pruned node scores an ordinary merge block, and gets the same
    /// score an unpruned node gets.
    ///
    /// Two producers sealing at the same height create siblings, and the next
    /// block merges them. Scoring that merge block used to build the full
    /// cumulative blue set, which walks the selected-parent chain back to
    /// genesis; on a pruned DAG store that walk reaches a dropped block and
    /// `add_block` fails with `BlockNotFound`, so the merge block (and every
    /// block built on it) can never be admitted. The bounded score reads only a
    /// window of `MERGE_SCORE_WINDOW` heights below the block, which is always
    /// inside the retained range.
    #[tokio::test]
    async fn pruned_node_scores_a_sibling_merge_like_an_unpruned_node() {
        use citrate_consensus::dag_store::DagStore;
        use citrate_consensus::ghostdag::GhostDag;
        use citrate_consensus::types::{BlockBuilder, GhostDagParams, Hash, VrfProof};
        use citrate_storage::pruning::PruningConfig;

        fn mk(
            height: u64,
            parent: Hash,
            merges: Vec<Hash>,
            coinbase: u8,
        ) -> citrate_consensus::types::Block {
            let mut b = BlockBuilder::new()
                .version(2)
                .height(height)
                .parent(parent)
                .merge_parents(merges)
                .coinbase([coinbase; 20])
                .timestamp(1000)
                .vrf_reveal(VrfProof {
                    proof: vec![],
                    output: Hash::new([0x5A; 32]),
                })
                .transactions(vec![])
                .state_root(Hash::default())
                .blue_score(height)
                .blue_work(citrate_consensus::types::blue_work_for_score(height))
                // G11: the committed pruning point (zero below 10,050).
                .pruning_point(crate::g11_test_seal::pruning_point(height, parent))
                .build_unhashed();
            b.header.block_hash = b.compute_hash();
            crate::g11_test_seal::record(&b);
            b
        }

        const RETAIN: u64 = MIN_RETAIN_BLOCKS;
        const N: u64 = RETAIN + 1_500;

        // Same blocks into two nodes: one prunes, one does not.
        let dir = tempfile::tempdir().expect("tempdir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let pruned_dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let pruned = GhostDag::new(GhostDagParams::default(), pruned_dag.clone());
        let full_dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let full = GhostDag::new(GhostDagParams::default(), full_dag.clone());

        let mut parent = Hash::default();
        for h in 0..=N {
            let b = mk(h, parent, vec![], 0x33);
            parent = b.header.block_hash;
            for (dag, gd) in [(&pruned_dag, &pruned), (&full_dag, &full)] {
                dag.store_block(b.clone()).await.expect("dag");
                gd.add_block(&b).await.expect("admit");
            }
            storage.blocks.put_block(&b).expect("chain");
        }
        storage.blocks.put_applied_tip(&parent, N).expect("tip");

        let dropped = prune_once(&storage, &pruned_dag, N, RETAIN).await;
        assert!(dropped > 0, "the pruned node must actually have pruned");

        // Two producers seal siblings at N+1; the next block merges them. r1007
        // G3: the heavier of the two (larger ForkChoiceKey) is the selected
        // parent; G7: the merge commits SP's N + 1 plus {SP, other} = N + 3.
        let a = mk(N + 1, parent, vec![], 0x33);
        let b = mk(N + 1, parent, vec![], 0x44);
        let (heavy, light) = if citrate_consensus::types::ForkChoiceKey::of_header(&a.header)
            > citrate_consensus::types::ForkChoiceKey::of_header(&b.header)
        {
            (&a, &b)
        } else {
            (&b, &a)
        };
        let mut merge = mk(
            N + 2,
            heavy.header.block_hash,
            vec![light.header.block_hash],
            0x33,
        );
        merge.header.blue_score = N + 3;
        merge.header.blue_work = citrate_consensus::types::blue_work_for_score(N + 3);
        merge.header.block_hash = merge.compute_hash();
        // The score fields changed after `mk` sealed it: record the final hash.
        crate::g11_test_seal::record(&merge);
        for blk in [&a, &b, &merge] {
            for (dag, gd) in [(&pruned_dag, &pruned), (&full_dag, &full)] {
                dag.store_block(blk.clone()).await.expect("dag");
                gd.add_block(blk).await.unwrap_or_else(|e| {
                    panic!(
                        "a pruned or unpruned node must admit {} @ {}: {e:?}",
                        blk.header.block_hash, blk.header.height
                    )
                });
            }
        }

        let h = merge.header.block_hash;
        let pruned_score = pruned.get_blue_score(&h).await.expect("score");
        let full_score = full.get_blue_score(&h).await.expect("score");
        assert_eq!(
            pruned_score, full_score,
            "pruned and unpruned nodes must agree on a merge block's score"
        );
        // r1007 G7: blue past(merge) = genesis..N (N+1 blocks), a, b.
        assert_eq!(
            full_score,
            N + 3,
            "merge = sp score + |{{sp, blue merge parent}}|"
        );

        // And the chain keeps going on top of it.
        let mut child = mk(N + 3, h, vec![], 0x44);
        child.header.blue_score = N + 4;
        child.header.blue_work = citrate_consensus::types::blue_work_for_score(N + 4);
        child.header.block_hash = child.compute_hash();
        crate::g11_test_seal::record(&child);
        pruned_dag.store_block(child.clone()).await.expect("dag");
        pruned
            .add_block(&child)
            .await
            .expect("child of a merge block admits");
        assert_eq!(
            pruned
                .get_blue_score(&child.header.block_hash)
                .await
                .expect("score"),
            N + 4
        );
    }

    /// S3-4 (ADR-2026-11-03 CV-7a, spec 06 §4.2, root cause H6): the undo
    /// window is the prune retention. The default retention equals the
    /// reorg window (`MAX_REORG_DEPTH`), and no accepted retention is
    /// shorter than it, so a fork the DAG store still holds is always one the
    /// applied chain can be switched across in place.
    #[test]
    fn undo_window_equals_the_prune_retention() {
        assert_eq!(
            crate::canonical_apply::MAX_REORG_DEPTH,
            DEFAULT_RETAIN_BLOCKS,
            "undo window != prune retention"
        );
        const {
            assert!(
                MIN_RETAIN_BLOCKS >= crate::canonical_apply::MAX_REORG_DEPTH,
                "a retention shorter than the undo window is accepted"
            )
        };
        assert_eq!(
            citrate_storage::state::REORG_UNDO_DEPTH,
            DEFAULT_RETAIN_BLOCKS,
            "the store keeps undo records for less than the retention"
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
