// citrate/core/consensus/src/ghostdag.rs

use crate::dag_store::DagStore;
use crate::types::{Block, BlueSet, DagRelation, GhostDagParams, Hash};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

#[derive(Error, Debug)]
pub enum GhostDagError {
    #[error("Block not found: {0}")]
    BlockNotFound(Hash),

    #[error("Invalid parent structure")]
    InvalidParents,

    #[error("Cycle detected in DAG")]
    CycleDetected,

    #[error("K-cluster violation")]
    KClusterViolation,

    // SECREM-01 CONS-1/2/3: admission-consistency rejections. A block
    // carrying any of these is structurally inadmissible regardless of
    // signature validity — a signature proves origin, not truth.
    #[error("Missing parent at admission: {0}")]
    MissingParent(Hash),

    #[error("Header height {claimed} != selected parent height + 1 ({expected})")]
    HeightMismatch { claimed: u64, expected: u64 },

    #[error("Header blue_score {claimed} outside feasible range [{min}, {max}]")]
    BlueScoreOutOfRange { claimed: u64, min: u64, max: u64 },

    #[error("Header blue_work {claimed} != canonical work for score ({expected})")]
    BlueWorkMismatch { claimed: u128, expected: u128 },

    #[error("Invalid linkage: {0}")]
    InvalidLinkage(String),
}

/// Hard cap on `blue_cache` entries.
///
/// Every entry holds a cumulative blue-ancestry set whose size grows with
/// chain length, so an unbounded map reaches O(entries × N) — the same
/// quadratic blow-up that halted chain 40204, just reached more slowly.
/// Entries are pure cache: recomputing one yields an identical set.
const MAX_BLUE_CACHE_ENTRIES: usize = 32;

/// GhostDAG consensus engine
pub struct GhostDag {
    /// Consensus parameters
    params: GhostDagParams,

    /// DAG storage
    dag_store: Arc<DagStore>,

    /// DAG relations cache
    relations: Arc<RwLock<HashMap<Hash, DagRelation>>>,

    /// Blue set cache for efficiency
    blue_cache: Arc<RwLock<HashMap<Hash, BlueSet>>>,

    /// Current tips of the DAG
    tips: Arc<RwLock<HashSet<Hash>>>,

    /// MP-DEPTH activation height. `None` = rule not enforced (the default), so
    /// this field is inert until an operator schedules it. See
    /// [`MERGE_PARENT_MAX_DEPTH`] and `handoffs/PRUNE_MERGE_PARENT_BOUND_SPEC.md`.
    merge_depth_activation_height: Option<u64>,

    /// PBA-R2 block-validity hardening (PBA-L1b-003 timestamp bound). Captured
    /// from the process-wide activation height at construction; see
    /// `crate::hardening`.
    pba_hardening: crate::hardening::PbaHardening,

    /// "DAG hydration complete" flag (restart-liveness fix, 2026-08-11). False
    /// until [`Self::reconcile_tips_from_dag_store`] has made the in-memory tip set
    /// authoritative after a restart. The applicator's runtime deep-fork rebuild
    /// gates on this instead of a block-height heuristic. See `dag_hydrated_handle`.
    dag_hydrated: Arc<AtomicBool>,
}

/// MP-DEPTH: the deepest a merge parent may sit below the block that merges it.
///
/// **This is a consensus rule, not a local policy.** It exists so that DAG
/// pruning can be enabled: a bounded merge depth is what makes it PROVABLE that
/// nothing a valid block can reference lies below the retained window, which in
/// turn is what lets the blue-set walk terminate at the window instead of
/// walking to genesis (`get_or_calculate_blue_set` phase 1) and failing against
/// a pruned store.
///
/// Without it, a block at height 72,000 may legally merge a parent at height 5,
/// and a node that bounded its walk would compute a WRONG SCORE rather than an
/// error — a silent fork. Verified live 2026-07-29: a merge block referencing a
/// pruned parent is rejected with `MissingParent` while unpruned peers accept it
/// (`dag_prune::merge_block_referencing_a_pruned_parent_is_rejected_not_scored`).
///
/// Value: 100, matching `finality_depth` and `canonical_apply::MAX_REORG_DEPTH`.
/// It bounds how long a partitioned producer can be away and still have its work
/// merged rather than orphaned. It must stay well under `MIN_RETAIN_BLOCKS`
/// (1,000) so the pruner can never remove a block a valid block may still cite:
///
///   MERGE_PARENT_MAX_DEPTH (100) < MIN_RETAIN_BLOCKS (1,000) <= retain window
pub const MERGE_PARENT_MAX_DEPTH: u64 = 100;

/// Height from which MP-DEPTH is enforced on chain 40204.
///
/// **0 since the 2026-08-04 re-roll.** The previous value (100_000) existed
/// only because chain 40204 already had ~78,000 blocks produced under the old
/// rule, and re-judging history under a new validity rule forks just as surely
/// as enforcing it early does — so the rule could only switch on at a future
/// height (owner decision 2026-07-29, ~12-hour upgrade window).
///
/// The re-roll wiped that history, so there is nothing to stay compatible with
/// and a non-zero activation is now actively dangerous. MP-DEPTH is what makes
/// bounding the blue-set walk sound, and therefore what makes DAG pruning safe:
/// the documented invariant is
///
///   MERGE_PARENT_MAX_DEPTH (100) < MIN_RETAIN_BLOCKS (1,000) <= retain window
///
/// so that no valid block can cite anything the pruner may have dropped. DAG
/// pruning is now ENABLED fleet-wide (`CITRATE_DAG_PRUNE_RETAIN=10000`, added
/// 2026-08-04 to stop the bootnodes OOM-looping). With enforcement deferred to
/// 100_000 that invariant does not hold for the first ~100k blocks: a block
/// could legally cite a merge parent deeper than the retained window, and a
/// pruned node then rejects it `MissingParent` while an unpruned peer accepts
/// it — a silent fork, exactly the shape verified live on 2026-07-29 by
/// `dag_prune::merge_block_referencing_a_pruned_parent_is_rejected_not_scored`.
/// The window is live from validator activation (2000), where multi-producer
/// merges begin.
///
/// Enforcing from genesis closes it: one validity rule for the whole chain, and
/// a cold sync from block 0 never straddles a rule change.
///
/// **Baked into `GhostDag::new` rather than passed by each call site.** There are
/// six `GhostDag::new` call sites across the node and producer; a validity rule
/// that depends on every one of them remembering a builder method is a rule that
/// will eventually be enforced by some nodes and not others, which is a fork. The
/// default IS the consensus value, and disabling it takes an explicit call.
pub const MERGE_DEPTH_ACTIVATION_HEIGHT: u64 = 0;

/// Devnet-only override for [`MERGE_DEPTH_ACTIVATION_HEIGHT`].
///
/// DANGER: this is a consensus parameter. Two nodes on the same chain with
/// different values disagree about block validity. It exists so an isolated
/// devnet can activate at a low height; never set it on 40204.
pub const MERGE_DEPTH_ACTIVATION_ENV: &str = "CITRATE_MERGE_DEPTH_ACTIVATION_HEIGHT";

impl GhostDag {
    pub fn new(params: GhostDagParams, dag_store: Arc<DagStore>) -> Self {
        let activation = std::env::var(MERGE_DEPTH_ACTIVATION_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(MERGE_DEPTH_ACTIVATION_HEIGHT);
        Self {
            params,
            dag_store,
            merge_depth_activation_height: Some(activation),
            pba_hardening: crate::hardening::PbaHardening::from_process(),
            relations: Arc::new(RwLock::new(HashMap::new())),
            blue_cache: Arc::new(RwLock::new(HashMap::new())),
            tips: Arc::new(RwLock::new(HashSet::new())),
            dag_hydrated: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Schedule MP-DEPTH enforcement from `height` onward.
    ///
    /// A validity rule, so it MUST be activated by height rather than switched
    /// on at upgrade time: a node enforcing it while a peer does not disagree
    /// about which blocks are valid, which is a fork. Blocks below `height` are
    /// judged by the old rule forever — re-validating history under a new rule
    /// forks the chain just as surely.
    ///
    /// Rollout order: upgrade every node, THEN pick a height comfortably beyond
    /// the slowest upgrade, and confirm the producer refuses to build violating
    /// blocks before it arrives.
    pub fn with_merge_depth_activation_height(mut self, height: u64) -> Self {
        self.merge_depth_activation_height = Some(height);
        self
    }

    /// Disable MP-DEPTH entirely. For tests and isolated devnets that build
    /// deliberately deep merges; never for a node on a shared chain.
    pub fn without_merge_depth_enforcement(mut self) -> Self {
        self.merge_depth_activation_height = None;
        self
    }

    /// Override the PBA-R2 hardening activation (tests / isolated devnets).
    pub fn with_pba_hardening(mut self, hardening: crate::hardening::PbaHardening) -> Self {
        self.pba_hardening = hardening;
        self
    }

    /// The PBA-R2 hardening this instance enforces.
    pub fn pba_hardening(&self) -> crate::hardening::PbaHardening {
        self.pba_hardening
    }

    /// Whether MP-DEPTH is enforced for a block at `height`. `None` activation
    /// means never — the default, so an upgraded binary changes nothing until
    /// an activation height is set deliberately.
    pub fn merge_depth_enforced_at(&self, height: u64) -> bool {
        matches!(self.merge_depth_activation_height, Some(a) if height >= a)
    }

    /// Get consensus parameters
    pub fn params(&self) -> &GhostDagParams {
        &self.params
    }

    /// Calculate blue set for a block following GhostDAG rules
    pub async fn calculate_blue_set(&self, block: &Block) -> Result<BlueSet, GhostDagError> {
        // Check cache first
        if let Some(cached) = self.blue_cache.read().await.get(&block.hash()) {
            return Ok(cached.clone());
        }

        let mut blue_set = BlueSet::new();

        // Genesis block is always blue
        if block.is_genesis() {
            blue_set.insert(block.hash());
            self.insert_blue_cache_bounded(block.hash(), blue_set.clone())
                .await;
            return Ok(blue_set);
        }

        // Get selected parent's blue set
        let selected_parent_blue = self
            .get_or_calculate_blue_set(&block.selected_parent())
            .await?;

        // Start with selected parent's blue set
        blue_set.blocks = selected_parent_blue.blocks.clone();
        blue_set.score = selected_parent_blue.score;

        // Calculate blue blocks among merge parents
        let blue_merge_parents = self
            .calculate_blue_merge_parents(block, &selected_parent_blue)
            .await?;

        // Add blue merge parents to blue set
        for parent_hash in &blue_merge_parents {
            let parent_blue_set = self.get_or_calculate_blue_set(parent_hash).await?;
            blue_set.blocks.extend(parent_blue_set.blocks);
        }

        // Add current block to blue set and recompute score from set size
        blue_set.blocks.insert(block.hash());
        blue_set.score = blue_set.blocks.len() as u64;
        // SECREM-01 CONS-2: work is always derived from the recomputed
        // score (canonical fn in types.rs) — never copied from a header.
        blue_set.work = crate::types::blue_work_for_score(blue_set.score);

        // Cache the result
        self.insert_blue_cache_bounded(block.hash(), blue_set.clone())
            .await;

        info!(
            "Calculated blue set for block {}: score={}",
            block.hash(),
            blue_set.score
        );
        Ok(blue_set)
    }

    /// Calculate which merge parents are blue according to k-cluster rule
    async fn calculate_blue_merge_parents(
        &self,
        block: &Block,
        selected_parent_blue: &BlueSet,
    ) -> Result<Vec<Hash>, GhostDagError> {
        let mut blue_parents = Vec::new();
        let mut red_parents = Vec::new();

        for merge_parent in &block.header.merge_parent_hashes {
            if self
                .is_blue_candidate(merge_parent, selected_parent_blue, &blue_parents)
                .await?
            {
                blue_parents.push(*merge_parent);
            } else {
                red_parents.push(*merge_parent);
            }
        }

        debug!(
            "Block {} has {} blue and {} red merge parents",
            block.hash(),
            blue_parents.len(),
            red_parents.len()
        );

        Ok(blue_parents)
    }

    /// Check if a block can be blue according to k-cluster rule
    async fn is_blue_candidate(
        &self,
        candidate: &Hash,
        selected_parent_blue: &BlueSet,
        current_blue_parents: &[Hash],
    ) -> Result<bool, GhostDagError> {
        // The k-cluster rule only cares whether the anticone count
        // exceeds k — not the exact count. We pass k as an upper bound
        // so `count_blue_anticone` can short-circuit after k+1 hits,
        // instead of walking the entire blue set (thousands of entries
        // on a long-running chain) with an O(BFS_depth) call each.
        //
        // Before this bound, validation of a single block at chain
        // height 14k+ was doing millions of BFS visits and OOM-killing
        // the node (observed on testnet-beta, Apr 2026). See
        // `count_blue_anticone` docs.
        let k = self.params.k as usize;
        let anticone_size = self
            .count_blue_anticone(candidate, selected_parent_blue, current_blue_parents, k + 1)
            .await?;

        Ok(anticone_size <= k)
    }

    /// Count blue blocks in anticone, short-circuiting once the count
    /// reaches `max_count` (the caller only needs to know whether the
    /// count exceeds a threshold, not the exact total).
    ///
    /// **Why the bound matters**: each pair of `is_ancestor_of` calls
    /// does a BFS up to `MAX_BFS_DEPTH` ancestors, allocating a
    /// HashSet + VecDeque per call. A reference blue set on a
    /// long-running chain can contain thousands of blocks, so the
    /// unbounded version did O(|blue_set| × BFS_depth) work per block
    /// validation — routinely millions of visits and the actual
    /// memory pressure behind the OOM loop on testnet-beta (Apr 2026).
    ///
    /// With `max_count = k + 1` (the k-cluster rule's threshold), this
    /// caps the work at O(k × BFS_depth) per call. For k=18, that's
    /// ~18 BFS calls worst case instead of thousands.
    async fn count_blue_anticone(
        &self,
        block: &Hash,
        reference_blue_set: &BlueSet,
        additional_blues: &[Hash],
        max_count: usize,
    ) -> Result<usize, GhostDagError> {
        let mut count = 0;

        // `is_ancestor_of(blue_block, block)` BFS-walks up from `block` down
        // to `blue_block`'s height. For the deep ancestors that dominate a
        // cumulative blue set that walk is O(depth × width) EACH, so summed
        // over the set it is Theta(N²) — the residual time cost that remained
        // after the Theta(N²) *memory* fix, and on its own enough to stop the
        // producer (~53 min for one merge block at the live chain's height).
        //
        // Walk `block`'s past ONCE instead, then answer each query by set
        // membership. Equivalent by construction: `is_ancestor_of` resolves
        // ancestry purely by reachability over `relations` parent edges, with
        // a height short-circuit that is reproduced verbatim below.
        let past = self.collect_past(block).await?;
        let heights: HashMap<Hash, u64> = {
            let relations = self.relations.read().await;
            reference_blue_set
                .blocks
                .iter()
                .chain(additional_blues.iter())
                .chain(std::iter::once(block))
                .filter_map(|h| relations.get(h).map(|r| (*h, r.height)))
                .collect()
        };
        let block_height = heights.get(block).copied();
        let is_ancestor_of_block = |candidate: &Hash| -> bool {
            if candidate == block {
                return true;
            }
            // Mirrors the structural short-circuit in `is_ancestor_of`:
            // a parent edge strictly decreases height, so an equal-or-higher
            // block can never be an ancestor.
            if let (Some(a_h), Some(d_h)) = (heights.get(candidate).copied(), block_height) {
                if a_h >= d_h {
                    return false;
                }
            }
            past.contains(candidate)
        };

        // Check against reference blue set
        for blue_block in &reference_blue_set.blocks {
            if count >= max_count {
                return Ok(count);
            }
            if !self.is_ancestor_of(block, blue_block).await? && !is_ancestor_of_block(blue_block) {
                count += 1;
            }
        }

        // Check against additional blue blocks
        for blue_block in additional_blues {
            if count >= max_count {
                return Ok(count);
            }
            if !self.is_ancestor_of(block, blue_block).await? && !is_ancestor_of_block(blue_block) {
                count += 1;
            }
        }

        Ok(count)
    }

    /// Every block reachable from `of` by parent edges, including `of` itself.
    ///
    /// Traverses exactly the edges [`Self::is_ancestor_of`] traverses
    /// (`relations` selected-parent + merge-parents), so
    /// `collect_past(d).contains(a)` answers the same question as
    /// `is_ancestor_of(a, d)` for any `a` — but once per `d` rather than once
    /// per `(a, d)` pair.
    async fn collect_past(&self, of: &Hash) -> Result<HashSet<Hash>, GhostDagError> {
        // Same absolute bound as `is_ancestor_of`, and the same refusal to
        // silently return a wrong answer when it is hit.
        const MAX_VISITED: usize = 1_000_000;

        let relations = self.relations.read().await;
        let mut visited: HashSet<Hash> = HashSet::new();
        let mut queue: VecDeque<Hash> = VecDeque::new();
        queue.push_back(*of);

        while let Some(current) = queue.pop_front() {
            if !visited.insert(current) {
                continue;
            }
            if visited.len() >= MAX_VISITED {
                tracing::error!(
                    "collect_past exceeded MAX_VISITED ({}) walking the past of {}; \
                     refusing to lie about ancestry",
                    MAX_VISITED,
                    of
                );
                return Err(GhostDagError::CycleDetected);
            }
            if let Some(relation) = relations.get(&current) {
                if relation.selected_parent != Hash::default() {
                    queue.push_back(relation.selected_parent);
                }
                for parent in &relation.merge_parents {
                    queue.push_back(*parent);
                }
            }
        }

        Ok(visited)
    }

    /// Check if `ancestor` is an ancestor of `descendant`.
    ///
    /// Closes audit finding **H-07**. The previous implementation BFS-
    /// walked up to a fixed `MAX_BFS_DEPTH = 10_000` cap and silently
    /// returned `Ok(false)` on exhaustion — turning an unknown answer
    /// into a definitively-wrong "no". On a long-running chain, this
    /// caused divergent blue-set computation between fresh-sync nodes
    /// (small relations cache, BFS cap fires often) and warm-cache
    /// nodes (large cache, no cap), producing fork-inducing blue-set
    /// disagreement.
    ///
    /// The fix uses structural height reachability: if both blocks
    /// have known heights and `ancestor.height >= descendant.height`
    /// (with `ancestor != descendant`), ancestry is impossible by
    /// the GhostDAG well-formedness rule (each parent edge strictly
    /// decreases height). Otherwise BFS up from `descendant` but
    /// prune any branch that would walk *below* `ancestor.height`,
    /// since blocks at height < `ancestor.height` cannot themselves
    /// be `ancestor` or one of `ancestor`'s descendants.
    ///
    /// The remaining work is bounded by `(descendant.height -
    /// ancestor.height) × max_dag_width`, which is a function of
    /// content (heights and DAG shape), not of cache state. This is
    /// the load-bearing property the planset's
    /// `BlueSetIsContentDetermined` invariant captures.
    ///
    /// Backward-compat fallback: if either height is unavailable
    /// (the relation hasn't been added to the cache, e.g., a unit
    /// test that constructs `DagRelation` manually with the default
    /// `height = 0`), the old BFS-with-cap path is taken and a
    /// `tracing::warn!` is logged. Production paths always go
    /// through `add_block` which records height, so the warn fires
    /// only on test surfaces.
    async fn is_ancestor_of(
        &self,
        ancestor: &Hash,
        descendant: &Hash,
    ) -> Result<bool, GhostDagError> {
        if ancestor == descendant {
            return Ok(true);
        }

        let relations = self.relations.read().await;

        let ancestor_height = relations.get(ancestor).map(|r| r.height);
        let descendant_height = relations.get(descendant).map(|r| r.height);

        // Structural short-circuit: when both heights are known,
        // ancestry is impossible whenever ancestor.height >=
        // descendant.height (we already returned early on equality).
        if let (Some(a_h), Some(d_h)) = (ancestor_height, descendant_height) {
            if a_h >= d_h {
                return Ok(false);
            }
        }

        // Hard absolute-cap to bound adversarial DAG abuse. With the
        // height pruning below this should rarely (if ever) be hit
        // by honest chains; if it IS hit we return Err so the caller
        // can decide rather than silently lying about ancestry.
        const MAX_VISITED: usize = 1_000_000;
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        queue.push_back(*descendant);

        while let Some(current) = queue.pop_front() {
            if visited.contains(&current) {
                continue;
            }
            if visited.len() >= MAX_VISITED {
                // H-07 fix: previously returned Ok(false) — silently
                // wrong. Now we return Err so the caller surfaces
                // the limit instead of producing a content-divergent
                // answer.
                tracing::error!(
                    "is_ancestor_of exceeded MAX_VISITED ({}) walking {} -> {}; \
                     refusing to lie about ancestry",
                    MAX_VISITED,
                    ancestor,
                    descendant
                );
                return Err(GhostDagError::CycleDetected);
            }
            visited.insert(current);

            if let Some(relation) = relations.get(&current) {
                if relation.selected_parent == *ancestor {
                    return Ok(true);
                }
                if relation.merge_parents.contains(ancestor) {
                    return Ok(true);
                }

                // H-07: prune branches that drop below ancestor's
                // height — they cannot reach ancestor or anything
                // above it. Only applies when ancestor's height is
                // known.
                let prune_threshold = ancestor_height;

                let sp = relation.selected_parent;
                let sp_height = relations.get(&sp).map(|r| r.height);
                let prune_sp = match (prune_threshold, sp_height) {
                    (Some(a_h), Some(p_h)) => p_h < a_h,
                    _ => false,
                };
                if !prune_sp {
                    queue.push_back(sp);
                }

                for parent in &relation.merge_parents {
                    let p_height = relations.get(parent).map(|r| r.height);
                    let prune_mp = match (prune_threshold, p_height) {
                        (Some(a_h), Some(p_h)) => p_h < a_h,
                        _ => false,
                    };
                    if !prune_mp {
                        queue.push_back(*parent);
                    }
                }
            }
        }

        Ok(false)
    }

    /// Calculate blue score for a block
    pub async fn calculate_blue_score(&self, block: &Block) -> Result<u64, GhostDagError> {
        let blue_set = self.calculate_blue_set(block).await?;
        Ok(blue_set.score)
    }

    /// Get or calculate blue set for a block.
    ///
    /// The selected-parent chain walk is **iterative** so replay of a
    /// long chain with an empty cache cannot blow the stack. Before
    /// this rewrite, a fresh startup recursed one frame per block along
    /// the selected-parent chain. On testnet-beta at chain height ~1800
    /// the main thread hit its stack limit and aborted with:
    ///
    /// ```text
    /// thread 'main' has overflowed its stack
    /// fatal runtime error: stack overflow, aborting
    /// ```
    ///
    /// Now the algorithm:
    ///
    /// 1. Walk the selected-parent chain backward, collecting each
    ///    uncached block into a `Vec`, until we hit either the cache,
    ///    genesis, or a missing block (error). All heap, no recursion.
    /// 2. Walk that list forward (oldest → newest), composing each
    ///    block's blue set from its now-cached selected parent plus
    ///    its qualified merge parents.
    ///
    /// Merge-parent calls remain recursive because merge parents form
    /// a wide-but-shallow DAG in practice, not a 1000+ deep chain.
    fn get_or_calculate_blue_set<'a>(
        &'a self,
        hash: &'a Hash,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<BlueSet, GhostDagError>> + Send + 'a>,
    > {
        Box::pin(async move {
            // Fast path: already cached
            if let Some(cached) = self.blue_cache.read().await.get(hash) {
                return Ok(cached.clone());
            }

            // --- Phase 1: unwind the selected-parent chain iteratively ---
            // `pending` holds blocks whose blue set we must compute,
            // ordered from oldest (pending.last()) to newest (pending.first()).
            let mut pending: Vec<Block> = Vec::new();
            let mut cursor = *hash;

            loop {
                if self.blue_cache.read().await.contains_key(&cursor) {
                    // Hit a cached ancestor — stop walking back.
                    break;
                }

                let block = self
                    .dag_store
                    .get_block(&cursor)
                    .await
                    .map_err(|_| GhostDagError::BlockNotFound(cursor))?;

                if block.is_genesis() {
                    // Seed the cache with genesis, then stop.
                    let mut blue = BlueSet::new();
                    blue.blocks.insert(cursor);
                    blue.score = 1;
                    self.blue_cache.write().await.insert(cursor, blue);
                    break;
                }

                let parent = block.selected_parent();
                pending.push(block);
                cursor = parent;
            }

            // --- Phase 2: compose blue sets forward, oldest first ---
            // pending is newest-first; reverse-iterate for oldest-first.
            //
            // The running set is carried in a LOCAL and only the requested
            // hash is cached at the end. Caching every intermediate here is
            // what made this Theta(N²): each of the N blocks on the walk got
            // its own cumulative ancestry set, of sizes 1..N, so a single
            // call retained ~N²/2 hashes. At the live chain's height that was
            // ~30 GB, which OOM-killed the producer and halted chain 40204 on
            // 2026-07-29 (see `merge_block_on_deep_chain_does_not_
            // materialise_quadratic_ancestry`). Peak memory is now the one
            // running set — O(N), not O(N²).
            //
            // The composed VALUES are unchanged; only what is retained is.
            // A later request for an intermediate recomputes the identical
            // set, so no caller can observe the difference.
            let mut running: Option<(Hash, BlueSet)> = None;
            for block in pending.iter().rev() {
                let bhash = block.hash();
                let sp = block.selected_parent();

                // The selected parent is either the block composed on the
                // previous iteration (the common case, walking forward down
                // a chain) or — for the first block only — the cached
                // ancestor that terminated phase 1.
                let selected_parent_blue = match running.take() {
                    Some((prev_hash, prev_blue)) if prev_hash == sp => prev_blue,
                    _ => {
                        let cache = self.blue_cache.read().await;
                        cache.get(&sp).cloned().ok_or({
                            // Should never happen — Phase 1 guarantees
                            // the selected parent is now cached.
                            GhostDagError::BlockNotFound(sp)
                        })?
                    }
                };

                let blue_merge_parents = self
                    .calculate_blue_merge_parents(block, &selected_parent_blue)
                    .await?;

                // Take the parent's set by value — the parent is not being
                // cached, so there is nothing left to share it with.
                let mut all_blocks = selected_parent_blue.blocks;
                // Merge parents: recurse, but depth here is bounded by
                // DAG width (usually <= max_parents = 10), not chain
                // length, so stack is safe.
                for p in &blue_merge_parents {
                    let pset = self.get_or_calculate_blue_set(p).await?;
                    all_blocks.extend(pset.blocks);
                }
                all_blocks.insert(bhash);

                let mut blue = BlueSet::new();
                blue.score = all_blocks.len() as u64;
                blue.blocks = all_blocks;
                running = Some((bhash, blue));
            }

            if let Some((bhash, blue)) = running {
                let result = blue.clone();
                self.insert_blue_cache_bounded(bhash, blue).await;
                // `pending` ended on the requested hash by construction.
                if bhash == *hash {
                    return Ok(result);
                }
            }

            // Phase 1 terminated immediately (the hash was already cached, or
            // it is genesis, seeded above).
            let cache = self.blue_cache.read().await;
            cache
                .get(hash)
                .cloned()
                .ok_or(GhostDagError::BlockNotFound(*hash))
        })
    }

    /// Insert into `blue_cache` under a hard entry cap.
    ///
    /// Each entry holds a cumulative ancestry set that grows with chain
    /// length, so an unbounded map is O(entries × N) — the same quadratic
    /// by a slower route. Entries are pure cache (recomputing yields an
    /// identical set), so evicting is always safe.
    async fn insert_blue_cache_bounded(&self, hash: Hash, blue: BlueSet) {
        let mut cache = self.blue_cache.write().await;
        if cache.len() >= MAX_BLUE_CACHE_ENTRIES && !cache.contains_key(&hash) {
            // Access is overwhelmingly tip-local, so the cheapest correct
            // policy is to drop an arbitrary entry rather than track
            // recency. Worst case costs one recomputation.
            if let Some(victim) = cache.keys().next().copied() {
                cache.remove(&victim);
            }
        }
        cache.insert(hash, blue);
    }

    /// Register an EXISTING block whose `blue_score`/`blue_work` are already
    /// recorded in the block header.
    ///
    /// PIL-13: the eager DAG-load loop in `BlockProducer::with_shared_dag`
    /// previously called [`Self::add_block`] for every persisted block on
    /// startup. `add_block` recomputes the full BlueSet, which (because
    /// `BlueSet.blocks` is the cumulative O(chain-length) blue ancestry)
    /// allocates O(N²) memory across N=281k blocks. The 16 GB RPC droplet
    /// kernel-OOM'd within 30 s of every restart.
    ///
    /// For blocks already on disk the score + work are durable in the
    /// header (BlockHeader.blue_score is u64, blue_work is u128, both
    /// transmitted on the wire too). Loading them is an O(1) read; no
    /// recomputation needed.
    ///
    /// **What this method does NOT do that [`Self::add_block`] does:**
    /// - It does not populate `blue_cache` with cumulative ancestry sets.
    /// - It stores a lightweight `BlueSet` (empty `blocks` HashSet, just
    ///   `score` + `work` from the header) in `relations`.
    ///
    /// **Why that's safe:** the only reader of `relations[*].blue_set` is
    /// [`Self::select_tip`], which only touches `.score`. The cumulative
    /// `.blocks` HashSet is never read out of `relations` anywhere in the
    /// tree (verified by grep at the time this method was added, PIL-13).
    ///
    /// **Where the full BlueSet IS needed:** validator-side
    /// `count_blue_anticone` (k-cluster anticone counting). That path goes
    /// through [`Self::calculate_blue_set`], which lazily walks the chain
    /// on demand and is unaffected by this lightweight registration.
    pub async fn register_existing_block(&self, block: &Block) -> Result<(), GhostDagError> {
        if !block.is_genesis() && block.selected_parent() == Hash::default() {
            return Err(GhostDagError::InvalidParents);
        }

        // SYNC-S1 D1: derive the score the SAME way the receive path does
        // (`derive_score_and_work`) instead of copying it out of the header.
        //
        // Pre-D1 this read `header.blue_score` while `add_block` recomputed set
        // cardinality, so the two paths disagreed by exactly one on the same
        // block: a tip received live scored `height + 1` and the same tip
        // rehydrated from disk after a restart scored `height`. `select_tip`
        // compares those numbers across tips, so a live tip and a rehydrated
        // tip at equal height did not compare equal — a latent fork-choice
        // inconsistency, now removed. It also keeps SECREM-01 CONS-2 intact
        // here: no header-reported score reaches the fork-choice baseline.
        //
        // Still O(1) per block: the eager rehydration loop walks blocks in
        // height order, so the selected parent is already in `relations` and
        // the linear derivation applies.
        //
        // NON-FATAL SCORE DERIVATION (restart-liveness fix, 2026-08-11). Pre-fix
        // this was `derive_score_and_work(block).await?` — all-or-nothing. When a
        // merge parent's score was unresolvable on restart (a pruned/holed merge
        // parent → `BlockNotFound` out of `calculate_blue_set`), the `?` returned
        // BEFORE the `relations` insert and the tips bookkeeping below, so the block
        // never entered the tip set AND its selected parent was never removed from
        // it — leaving a STALE ANCESTOR as a tip. `select_tip` (fork-choice for BOTH
        // the producer and the drain since #163) then returned that ancestor, so the
        // follower's drain saw no advance and the miner's rebuild was driven at a
        // stale head — the 2026-08-11 restart wedge. Fall back to the durable derived
        // anchor, then the header's own blue_score, so a score is ALWAYS available
        // and the tips bookkeeping ALWAYS runs. The fallback score is only a
        // fork-choice ranking input (never a consensus state root); an off-by-a-few
        // score on a holed merge block cannot fork state, and the authoritative
        // `calculate_blue_set` still recomputes on demand where cardinality matters.
        let blue_set = match self.derive_score_and_work(block).await {
            Ok(bs) => bs,
            Err(e) => {
                let fallback = self
                    .dag_store
                    .get_derived_blue_score(&block.hash())
                    .unwrap_or(block.header.blue_score);
                warn!(
                    "register_existing_block: score derivation for {} @ {} failed ({}) — \
                     falling back to score {} so the block still enters the tip set",
                    block.hash(),
                    block.header.height,
                    e,
                    fallback
                );
                BlueSet {
                    blocks: std::collections::HashSet::new(),
                    score: fallback,
                    work: crate::types::blue_work_for_score(fallback),
                }
            }
        };

        // SYNC-S1 D3: same durable anchor as `add_block` — the rehydration path
        // must record it too, or a node whose relations were built only by
        // eager-load starts the next process with no anchors at all.
        self.dag_store
            .put_derived_blue_score(&block.hash(), blue_set.score);

        let relation = DagRelation {
            block: block.hash(),
            selected_parent: block.selected_parent(),
            merge_parents: block.header.merge_parent_hashes.clone(),
            children: Vec::new(),
            blue_set,
            is_chain_block: true,
            height: block.header.height,
        };

        let mut relations = self.relations.write().await;
        relations.insert(block.hash(), relation);

        // Update parent's children link (matches add_block semantics)
        if let Some(parent_relation) = relations.get_mut(&block.selected_parent()) {
            parent_relation.children.push(block.hash());
        }
        for merge_parent in &block.header.merge_parent_hashes {
            if let Some(parent_relation) = relations.get_mut(merge_parent) {
                parent_relation.children.push(block.hash());
            }
        }
        drop(relations);

        // Tips bookkeeping (same as add_block)
        let mut tips = self.tips.write().await;
        tips.remove(&block.selected_parent());
        for merge_parent in &block.header.merge_parent_hashes {
            tips.remove(merge_parent);
        }
        tips.insert(block.hash());

        Ok(())
    }

    /// AUTHORITATIVE TIP REHYDRATION (restart-liveness fix, 2026-08-11). Align this
    /// GhostDag's in-memory `tips` with the DAG store's AUTHORITATIVE tip set.
    ///
    /// After a restart the eager-load loops (`producer.rs`) register only the
    /// CANONICAL single-block-per-height chain via [`Self::register_existing_block`],
    /// so `GhostDag.tips` can diverge from the true DAG tips: a sibling/fork tip is
    /// never registered, or a block whose registration failed left its parent
    /// stranded as a tip. Since #163 `select_tip` is the fork-choice authority for
    /// BOTH the producer's parent-selection AND the drain's reorg, a wrong tip set
    /// wedges restart recovery (the follower drain sees a stale ancestor as best; the
    /// miner's runtime rebuild is driven at the wrong head). `DagStore` already
    /// reconstructs its tip set authoritatively from block-header parentage on load
    /// (PIL-42, `load_from_persistent`: a block is a tip iff no stored block names it
    /// as a selected/merge parent). This copies that authoritative set in, first
    /// registering any tip missing from `relations` so `select_tip` can rank it.
    ///
    /// O(number of tips), NOT O(chain length): it only registers TIPS (a handful),
    /// never walks `calculate_blue_set` for interior blocks (PIL-13 stays intact).
    /// Returns the number of authoritative tips after reconciliation.
    pub async fn reconcile_tips_from_dag_store(&self) -> usize {
        let authoritative: Vec<Hash> = self
            .dag_store
            .get_tips()
            .await
            .into_iter()
            .map(|t| t.hash)
            .collect();

        // Ensure every authoritative tip has a `relations` entry (with a score) so
        // `select_tip` considers it. `register_existing_block` is now non-fatal, so
        // a tip whose merge-parent score is unresolvable still lands with a fallback
        // score rather than being skipped.
        for hash in &authoritative {
            let known = self.relations.read().await.contains_key(hash);
            if !known {
                if let Ok(block) = self.dag_store.get_block(hash).await {
                    if let Err(e) = self.register_existing_block(&block).await {
                        warn!(
                            "reconcile_tips_from_dag_store: could not register tip {}: {}",
                            hash, e
                        );
                    }
                }
            }
        }

        // Replace the in-memory tip set with the authoritative one (register above
        // may have mutated `tips`; the authoritative set is the final word).
        let mut tips = self.tips.write().await;
        *tips = authoritative.iter().copied().collect();
        let n = tips.len();
        drop(tips);

        // Mark hydration complete so consumers that gate on it (the applicator's
        // runtime deep-fork rebuild) stop deferring and start trusting `select_tip`.
        self.dag_hydrated.store(true, Ordering::SeqCst);
        info!(
            "reconcile_tips_from_dag_store: GhostDag tips reconciled to {} authoritative tip(s); DAG hydration complete",
            n
        );
        n
    }

    /// Shared handle to the "DAG hydration complete" flag — set true by
    /// [`Self::reconcile_tips_from_dag_store`] once the in-memory tip set is
    /// authoritative. Consumers (the applicator's runtime deep-fork rebuild) gate on
    /// this instead of a block-height heuristic: a genuinely-canonical `select_tip`
    /// head is frequently LOWER than a longer losing branch, so height cannot stand
    /// in for "hydration done". Defaults false until reconciliation runs.
    pub fn dag_hydrated_handle(&self) -> Arc<AtomicBool> {
        self.dag_hydrated.clone()
    }

    /// Add a block to the DAG
    /// SECREM-01 CONS-3 (root cause of CONS-1 + CONS-2): validate the
    /// structural linkage a header *claims* against what this node can
    /// verify from its own already-admitted ancestors. Read-only — safe to
    /// call before any persistence. `add_block` runs it unconditionally, so
    /// every ingest path that builds DAG relations (gossip, sync,
    /// efficient-sync) passes this gate and no future caller can forget it.
    ///
    /// What is enforced, and why each check exists:
    /// - **parents exist** — an unknown parent means nothing below the
    ///   block is verifiable; admitting it would let an attacker build on
    ///   phantom history.
    /// - **height == selected_parent.height + 1, exactly** — `header.height`
    ///   drives the finality boundary (CONS-1): a forged height of 10M on a
    ///   height-500 chain finalized still-reorg-eligible blocks. Heights are
    ///   validated inductively from genesis.
    /// - **selected-parent rule** — no merge parent may have a higher blue
    ///   score than the selected parent; choosing a lighter selected parent
    ///   while merging a heavier branch is a fork-choice manipulation.
    /// - **blue_score within the feasible band** `[sp+1, sp+1+|merges|]` —
    ///   each block adds itself plus at most its blue merge parents to the
    ///   blue set, so any claim outside this band is arithmetically
    ///   impossible. This kills the `u64::MAX` baseline-poisoning attack
    ///   (CONS-2): inflation is capped at `max_parents` per VRF-elected
    ///   block instead of unbounded per packet. (Exact k-cluster equality —
    ///   pinning the score to one value inside the band — is deliberately
    ///   deferred to the BlueSet-persistence rework tracked since PIL-13;
    ///   the producer itself currently writes the parent+1 approximation.
    ///   `add_block` logs any in-band drift as telemetry for that flip.)
    /// - **blue_work == blue_work_for_score(blue_score)** — work is a pure
    ///   function of score (single source of truth in `types.rs`); a
    ///   self-reported work value is never stored.
    pub async fn validate_block_consistency(&self, block: &Block) -> Result<(), GhostDagError> {
        // SECREM-A001: exempt genesis by IDENTITY, not by shape. A block
        // merely shaped like genesis (parentless, arbitrary height) must
        // fall through to the missing-parent check below, not short-circuit.
        if block.is_configured_genesis(self.dag_store.configured_genesis()) {
            return Ok(());
        }

        let header = &block.header;
        let sp_hash = block.selected_parent();
        if sp_hash == Hash::default() {
            return Err(GhostDagError::InvalidParents);
        }

        // Merge-parent structural sanity: bounded count, no duplicates,
        // no self-reference, no aliasing of the selected parent.
        let merge_parents = &header.merge_parent_hashes;
        // max_parents counts ALL parents: 1 selected + N merges.
        if merge_parents.len() >= self.params.max_parents {
            return Err(GhostDagError::InvalidLinkage(format!(
                "{} total parents (1 selected + {} merges) exceeds max_parents {}",
                merge_parents.len() + 1,
                merge_parents.len(),
                self.params.max_parents
            )));
        }
        let mut seen = std::collections::HashSet::with_capacity(merge_parents.len());
        for mp in merge_parents {
            if *mp == sp_hash {
                return Err(GhostDagError::InvalidLinkage(
                    "merge parent duplicates selected parent".to_string(),
                ));
            }
            if *mp == block.hash() {
                return Err(GhostDagError::InvalidLinkage(
                    "block lists itself as a merge parent".to_string(),
                ));
            }
            if !seen.insert(*mp) {
                return Err(GhostDagError::InvalidLinkage(format!(
                    "duplicate merge parent {mp}"
                )));
            }
        }

        // Parents must already be admitted locally.
        let sp = self
            .dag_store
            .get_block(&sp_hash)
            .await
            .map_err(|_| GhostDagError::MissingParent(sp_hash))?;

        // Height linkage is exact and inductive from genesis.
        let expected_height = sp.header.height.checked_add(1).ok_or_else(|| {
            GhostDagError::InvalidLinkage("selected parent height overflow".to_string())
        })?;
        if header.height != expected_height {
            return Err(GhostDagError::HeightMismatch {
                claimed: header.height,
                expected: expected_height,
            });
        }

        // FWA-C1-03: timestamp must be monotonic vs the selected parent.
        // Previously only a future-bound was enforced (gossip.rs); nothing
        // stopped a proposer from BACKDATING a block before its parent,
        // skewing any time-based logic that reads header.timestamp. A block
        // can never be older than the block it builds on.
        if header.timestamp < sp.header.timestamp {
            return Err(GhostDagError::InvalidLinkage(format!(
                "timestamp {} precedes selected parent's {} — must be parent-monotonic",
                header.timestamp, sp.header.timestamp
            )));
        }

        // PBA-L1b-003: and it may not run more than
        // MAX_BLOCK_TIMESTAMP_ADVANCE_SECS ahead of it. Without an upper bound
        // one block stamped u64::MAX became the tip and every honest child
        // (stamped `now`) failed the monotonic check above: a permanent halt.
        // Parent-relative so it is deterministic (a wall-clock bound is local
        // policy, enforced at ingress). Height-gated: history is never
        // re-judged under a new rule.
        if self.pba_hardening.active_at(header.height) {
            let max_ts = sp
                .header
                .timestamp
                .saturating_add(crate::hardening::MAX_BLOCK_TIMESTAMP_ADVANCE_SECS);
            if header.timestamp > max_ts {
                return Err(GhostDagError::InvalidLinkage(format!(
                    "timestamp {} is more than {}s past selected parent's {} (PBA-L1b-003)",
                    header.timestamp,
                    crate::hardening::MAX_BLOCK_TIMESTAMP_ADVANCE_SECS,
                    sp.header.timestamp
                )));
            }
        }

        // Selected-parent rule + merge-parent existence.
        for mp in merge_parents {
            let mp_block = self
                .dag_store
                .get_block(mp)
                .await
                .map_err(|_| GhostDagError::MissingParent(*mp))?;
            if mp_block.header.blue_score > sp.header.blue_score {
                return Err(GhostDagError::InvalidLinkage(format!(
                    "merge parent {} blue_score {} exceeds selected parent's {} — \
                     selected parent must be the heaviest parent",
                    mp, mp_block.header.blue_score, sp.header.blue_score
                )));
            }

            // MP-DEPTH. Before this rule there was NO lower bound on merge
            // parent depth — height, count, duplicates and blue-score ordering
            // were all checked, but a block at height 72,000 could legally merge
            // a parent at height 5. That is what makes a bounded blue-set walk
            // unsound, and therefore what blocks DAG pruning.
            //
            // Gated on an activation height: enforcing a new validity rule
            // without one splits the fleet into nodes that accept a block and
            // nodes that reject it.
            if self.merge_depth_enforced_at(header.height) {
                let depth = header.height.saturating_sub(mp_block.header.height);
                if depth > MERGE_PARENT_MAX_DEPTH {
                    return Err(GhostDagError::InvalidLinkage(format!(
                        "merge parent {} is {} blocks below this block (height {} vs {}), \
                         over the MP-DEPTH bound of {}. A merge parent deeper than the \
                         retained window cannot be scored by a pruned node, so accepting \
                         it would fork pruned nodes away from unpruned ones",
                        mp, depth, mp_block.header.height, header.height, MERGE_PARENT_MAX_DEPTH
                    )));
                }
            }
        }

        // Blue-score feasibility band, computed from the validated parent.
        let min_score = sp.header.blue_score.checked_add(1).ok_or_else(|| {
            GhostDagError::InvalidLinkage("selected parent blue_score overflow".to_string())
        })?;
        let max_score = min_score
            .checked_add(merge_parents.len() as u64)
            .ok_or_else(|| GhostDagError::InvalidLinkage("blue_score band overflow".to_string()))?;
        if header.blue_score < min_score || header.blue_score > max_score {
            return Err(GhostDagError::BlueScoreOutOfRange {
                claimed: header.blue_score,
                min: min_score,
                max: max_score,
            });
        }

        // Work is derived, never trusted.
        let expected_work = crate::types::blue_work_for_score(header.blue_score);
        if header.blue_work != expected_work {
            return Err(GhostDagError::BlueWorkMismatch {
                claimed: header.blue_work,
                expected: expected_work,
            });
        }

        Ok(())
    }

    /// SYNC-S1 D1 — the canonical blue score/work for `block`, recomputed
    /// locally, in O(1) for the linear case and WITHOUT retaining cumulative
    /// ancestry in either case.
    ///
    /// Returns a LIGHTWEIGHT [`BlueSet`]: `score` + `work` populated, `blocks`
    /// deliberately empty. Callers that genuinely need the ancestor set (only
    /// k-cluster anticone counting does) go through [`Self::calculate_blue_set`].
    ///
    /// **Why the linear derivation is exact, not an approximation.** A block
    /// with no merge parents has blue set `sp.blue_set ∪ {self}`, and `self` is
    /// by definition not in its own ancestry, so the cardinality is exactly
    /// `|sp.blue_set| + 1` — i.e. `sp.score + 1`. No union, no set, no clone.
    /// This reproduces the pre-D1 value bit-for-bit on a linear chain, which is
    /// what the live chain is (`mergeParentHashes: []` throughout).
    ///
    /// **Why it recomputes rather than trusting the header.** SECREM-01 CONS-2:
    /// a self-reported score must never reach the fork-choice baseline. The
    /// recursion base is genesis (score 1) and every step adds 1 locally, so no
    /// header value is ever consumed. `register_existing_block` uses this too,
    /// which also repairs the pre-D1 split where the receive path and the
    /// restart-rehydration path disagreed by one on the same block.
    ///
    /// A merge block still needs a real union, so it falls back to
    /// [`Self::calculate_blue_set`]. Merge blocks are rare, and the fallback is
    /// also taken when the selected parent is not yet in `relations` (a cold
    /// process that has not rehydrated the parent yet).
    async fn derive_score_and_work(&self, block: &Block) -> Result<BlueSet, GhostDagError> {
        let lightweight = |score: u64| BlueSet {
            blocks: std::collections::HashSet::new(),
            score,
            work: crate::types::blue_work_for_score(score),
        };

        // Base case: genesis is the single blue block in its own ancestry.
        if block.is_genesis() {
            return Ok(lightweight(1));
        }

        if block.header.merge_parent_hashes.is_empty() {
            let sp_score = self
                .relations
                .read()
                .await
                .get(&block.selected_parent())
                .map(|r| r.blue_set.score);
            if let Some(sp_score) = sp_score {
                return Ok(lightweight(sp_score + 1));
            }

            // SYNC-S1 D3 — durable anchor. `relations` is in-memory, so after a
            // restart the parent's score is not there, but a previous process
            // persisted it. One O(1) read replaces the walk below entirely, and
            // removes the last reason the DAG store must retain deep ancestry
            // (which is what blocks wiring `prune()`).
            if let Some(sp_score) = self
                .dag_store
                .get_derived_blue_score(&block.selected_parent())
            {
                return Ok(lightweight(sp_score + 1));
            }

            // COLD PATH — the selected parent is not in `relations`.
            //
            // This is not an edge case: `relations` is in-memory only, so after
            // EVERY restart a follower's first received block lands here. It
            // must not reach `calculate_blue_set`: that walks the
            // selected-parent chain to genesis and caches a full cumulative
            // ancestor set for EVERY block on the way (see
            // `get_or_calculate_blue_set` phase 2), which rebuilds the entire
            // Theta(N²) footprint in a single call. At the live chain's height
            // that is the ~4 GB that OOM-killed boot-3 — so routing the cold
            // path through it would have reintroduced the exact bug D1 removes,
            // once per restart.
            //
            // Instead walk back to the nearest ancestor whose score is known,
            // counting edges. `score(b) = score(cursor) + hops` because each
            // linear step adds exactly one. O(depth) time, O(1) memory, and
            // only the first block after a restart pays it — its child then
            // finds it in `relations`.
            let mut hops: u64 = 1;
            let mut cursor = block.selected_parent();
            // An honest chain cannot have more ancestors than its height; a
            // longer walk means corrupt linkage (or a cycle), so bail out to
            // the authoritative computation rather than spin.
            let max_hops = block.header.height.saturating_add(1);
            while hops <= max_hops {
                if let Some(score) = self
                    .relations
                    .read()
                    .await
                    .get(&cursor)
                    .map(|r| r.blue_set.score)
                {
                    return Ok(lightweight(score + hops));
                }
                let ancestor = self
                    .dag_store
                    .get_block(&cursor)
                    .await
                    .map_err(|_| GhostDagError::BlockNotFound(cursor))?;
                if ancestor.is_genesis() {
                    return Ok(lightweight(1 + hops));
                }
                if !ancestor.header.merge_parent_hashes.is_empty() {
                    // A merge block on the path: its own score needs a real
                    // union, so compute that ONE block authoritatively and add
                    // the remaining edges.
                    let full = self.calculate_blue_set(&ancestor).await?;
                    return Ok(lightweight(full.score + hops));
                }
                cursor = ancestor.selected_parent();
                hops += 1;
            }
        }

        let full = self.calculate_blue_set(block).await?;
        Ok(lightweight(full.score))
    }

    pub async fn add_block(&self, block: &Block) -> Result<(), GhostDagError> {
        // Validate parent structure
        if !block.is_genesis() && block.selected_parent() == Hash::default() {
            return Err(GhostDagError::InvalidParents);
        }

        // SECREM-01 CONS-3: every relation-building path passes the
        // consistency gate. Reject before any state mutation.
        self.validate_block_consistency(block).await?;

        // SYNC-S1 D1: score + work are RECOMPUTED locally (never read from the
        // header — SECREM-01 CONS-2) but WITHOUT materialising the cumulative
        // blue ancestry. See `derive_score_and_work`: for a linear block the
        // derivation is exact and O(1); only a merge block falls back to a set
        // computation. Pre-D1 this called `calculate_blue_set` unconditionally,
        // which cloned the selected parent's full ancestor set per block and
        // retained it here AND in `blue_cache` — Theta(N²) memory, the follower
        // OOM that froze every non-producing node in the 9k-15k range.
        let blue_set = self.derive_score_and_work(block).await?;

        // Invariant check replacing the old "blue_score drift" telemetry. That
        // warning compared a set-cardinality score (counts genesis and self, so
        // height + 1) against a header convention of `height`, so it fired on
        // EVERY block of a linear chain and reported a definitional off-by-one
        // as if it were consensus drift. The real invariant is that the locally
        // recomputed score sits exactly one above the header's, which is what
        // `validate_block_consistency`'s score band already pins for a linear
        // block. Anything else is a genuine inconsistency worth a warning.
        if !block.is_genesis()
            && block.header.merge_parent_hashes.is_empty()
            && blue_set.score != block.header.blue_score + 1
        {
            warn!(
                "blue_score inconsistency on {}: recomputed {} but header claims {} \
                 (expected recomputed == header + 1 for a linear block)",
                block.hash(),
                blue_set.score,
                block.header.blue_score
            );
        }

        // Create DAG relation.
        //
        // `blue_set.blocks` is intentionally EMPTY here. The only reader of
        // `relations[*].blue_set` is `select_tip`, which touches `.score` only
        // (verified by grep at PIL-13 and re-verified for D1), so retaining the
        // cumulative hash set per relation bought nothing and cost O(N²).
        let relation = DagRelation {
            block: block.hash(),
            selected_parent: block.selected_parent(),
            merge_parents: block.header.merge_parent_hashes.clone(),
            children: Vec::new(),
            blue_set: blue_set.clone(),
            is_chain_block: true, // Will be determined by chain selection
            height: block.header.height,
        };

        // SYNC-S1 D3: record the derived score durably so the next process does
        // not have to walk the selected-parent chain to re-derive it. Best
        // effort — a failure only costs a walk on the next cold start.
        self.dag_store
            .put_derived_blue_score(&block.hash(), blue_set.score);

        // Update relations
        let mut relations = self.relations.write().await;
        relations.insert(block.hash(), relation);

        // Update parent's children
        if let Some(parent_relation) = relations.get_mut(&block.selected_parent()) {
            parent_relation.children.push(block.hash());
        }
        for merge_parent in &block.header.merge_parent_hashes {
            if let Some(parent_relation) = relations.get_mut(merge_parent) {
                parent_relation.children.push(block.hash());
            }
        }
        drop(relations);

        // Update tips
        let mut tips = self.tips.write().await;

        // Remove parents from tips
        tips.remove(&block.selected_parent());
        for merge_parent in &block.header.merge_parent_hashes {
            tips.remove(merge_parent);
        }

        // Add new block as tip
        tips.insert(block.hash());

        info!(
            "Added block {} to DAG with blue score {}",
            block.hash(),
            blue_set.score
        );
        Ok(())
    }

    /// Select the best tip based on blue score
    pub async fn select_tip(&self) -> Result<Hash, GhostDagError> {
        let tips = self.tips.read().await;
        let relations = self.relations.read().await;

        let mut best_tip: Option<Hash> = None;
        let mut best_score: u64 = 0;

        for tip in tips.iter() {
            if let Some(relation) = relations.get(tip) {
                let score = relation.blue_set.score;
                // Deterministic total order matching the producer's
                // `cmp_tip_for_parent_selection` (higher blue_score first, ties
                // broken by SMALLEST hash). This is the receive-side analogue of
                // audit finding H-08: `tips` is a `HashSet`, so a bare `>` keeps
                // whichever equal-score sibling the process-random iteration order
                // surfaces first. Two producers at the same height publish
                // equal-`blue_score` sibling tips (and `blue_work` is purely
                // score-derived, so it cannot discriminate either), which made
                // different nodes latch different branches and never reorg —
                // a permanent fork. The hash tie-break MUST NOT be removed.
                let better = match best_tip {
                    None => true,
                    Some(cur) => score > best_score || (score == best_score && *tip < cur),
                };
                if better {
                    best_score = score;
                    best_tip = Some(*tip);
                }
            }
        }

        best_tip.ok_or(GhostDagError::BlockNotFound(Hash::default()))
    }

    /// Get current tips
    pub async fn get_tips(&self) -> Vec<Hash> {
        self.tips.read().await.iter().copied().collect()
    }

    /// Get blue score for a block
    pub async fn get_blue_score(&self, hash: &Hash) -> Result<u64, GhostDagError> {
        self.relations
            .read()
            .await
            .get(hash)
            .map(|r| r.blue_set.score)
            .ok_or(GhostDagError::BlockNotFound(*hash))
    }

    /// Height of a known block, or `None` if we do not hold it.
    ///
    /// Checks `relations` first (in-memory, O(1)) and falls back to the DAG
    /// store, because `relations` is empty after a restart on a non-producing
    /// node. Returns `Option` rather than `Result`: the caller (MP-DEPTH parent
    /// filtering in the producer) treats "height unknown" as "cannot judge the
    /// depth", and must not turn that into a hard failure that stops block
    /// production.
    pub async fn get_block_height(&self, hash: &Hash) -> Option<u64> {
        if let Some(h) = self.relations.read().await.get(hash).map(|r| r.height) {
            return Some(h);
        }
        self.dag_store
            .get_block(hash)
            .await
            .ok()
            .map(|b| b.header.height)
    }

    /// PIL-13 tripwire metric: the total number of cumulative blue-ancestry
    /// entries materialised in memory, across every DAG relation's stored
    /// `blue_set.blocks` plus the `blue_cache`.
    ///
    /// The PIL-13 producer leak was exactly this number growing O(N²): the
    /// eager startup loop called `add_block` per persisted block, and each
    /// call cached the FULL O(chain-length) blue ancestry. The steady-state
    /// producer path ([`Self::register_existing_block`] + header-derived
    /// scores) must keep the per-block contribution O(1) — the
    /// `producer_steady_state` integration test (core/sequencer) asserts
    /// this stays zero across an eager-load of a linear chain.
    pub async fn materialised_blue_ancestry_entries(&self) -> usize {
        let relations = self.relations.read().await;
        let from_relations: usize = relations.values().map(|r| r.blue_set.blocks.len()).sum();
        drop(relations);
        let cache = self.blue_cache.read().await;
        let from_cache: usize = cache.values().map(|b| b.blocks.len()).sum();
        from_relations + from_cache
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    fn create_test_block_with_parents(
        hash: [u8; 32],
        selected_parent: Hash,
        merge_parents: Vec<Hash>,
        blue_score: u64,
    ) -> Block {
        // SECREM-01: add_block now enforces height linkage and the
        // canonical score→work relation; these fixtures are all linear
        // (or near-linear) chains where height == blue_score, and work
        // must be the canonical derivation.
        BlockBuilder::new()
            .hash(Hash::new(hash))
            .parent(selected_parent)
            .merge_parents(merge_parents)
            .height(blue_score)
            .blue_score(blue_score)
            .blue_work(crate::types::blue_work_for_score(blue_score))
            .build_unhashed()
    }


    /// Mutation-survivor kills inside validate_block_consistency (the
    /// function PBA-L1b-003 changed): the blue-score band edges and the
    /// MP-DEPTH boundary are pinned exactly.
    #[tokio::test]
    async fn pba_r2_blue_score_band_edges_are_enforced() {
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let genesis = create_test_block_with_parents([0x21; 32], Hash::default(), vec![], 0);
        dag_store.store_block(genesis.clone()).await.unwrap();
        let gd = GhostDag::new(GhostDagParams::default(), dag_store.clone());
        let with_score = |score: u64, h: u8| {
            let mut b = create_test_block_with_parents([h; 32], genesis.hash(), vec![], 1);
            b.header.blue_score = score;
            b.header.blue_work = crate::types::blue_work_for_score(score);
            b
        };
        assert!(gd.validate_block_consistency(&with_score(1, 0x22)).await.is_ok());
        assert!(
            gd.validate_block_consistency(&with_score(0, 0x23)).await.is_err(),
            "below the band"
        );
        assert!(
            gd.validate_block_consistency(&with_score(2, 0x24)).await.is_err(),
            "above the band (no merge parents)"
        );
    }

    #[tokio::test]
    async fn pba_r2_mp_depth_boundary_is_exact() {
        fn h(i: u64) -> [u8; 32] {
            let mut b = [0u8; 32];
            b[0..8].copy_from_slice(&i.to_le_bytes());
            b[31] = 0x77;
            b
        }
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let gd = GhostDag::new(GhostDagParams::default(), dag_store.clone())
            .with_merge_depth_activation_height(0);
        let mut chain = vec![create_test_block_with_parents(h(0), Hash::default(), vec![], 0)];
        dag_store.store_block(chain[0].clone()).await.unwrap();
        let top = MERGE_PARENT_MAX_DEPTH + 1;
        for i in 1..top {
            let b = create_test_block_with_parents(h(i), chain[(i - 1) as usize].hash(), vec![], i);
            dag_store.store_block(b.clone()).await.unwrap();
            chain.push(b);
        }
        // A side block at height 1 (sibling of chain[1]) to merge.
        let side1 = create_test_block_with_parents([0xA1; 32], chain[0].hash(), vec![], 1);
        dag_store.store_block(side1.clone()).await.unwrap();
        let sp = chain[(top - 1) as usize].hash();
        let merging = |mp: Hash, tag: u8| {
            let mut b = create_test_block_with_parents([tag; 32], sp, vec![mp], top);
            b.header.blue_score = top;
            b.header.blue_work = crate::types::blue_work_for_score(top);
            b
        };
        // depth = top - 1 = MERGE_PARENT_MAX_DEPTH: allowed.
        assert!(gd.validate_block_consistency(&merging(side1.hash(), 0xB1)).await.is_ok());
        // depth = top - 0 = MERGE_PARENT_MAX_DEPTH + 1: rejected.
        let side0 = chain[0].hash();
        assert!(gd.validate_block_consistency(&merging(side0, 0xB2)).await.is_err());
    }

    /// PBA-L1b-003: the parent-relative timestamp bound, both sides of the
    /// activation height and both edges of the bound.
    #[tokio::test]
    async fn pba_l1b_003_timestamp_bound_is_height_gated_and_inclusive() {
        use crate::hardening::{PbaHardening, MAX_BLOCK_TIMESTAMP_ADVANCE_SECS as MAX};
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let mut genesis = create_test_block_with_parents([0x01; 32], Hash::default(), vec![], 0);
        genesis.header.timestamp = 1_000;
        dag_store.store_block(genesis.clone()).await.unwrap();
        let child = |ts: u64, h: u8| {
            let mut b =
                create_test_block_with_parents([h; 32], genesis.hash(), vec![], 1);
            b.header.timestamp = ts;
            b
        };
        let on = GhostDag::new(GhostDagParams::default(), dag_store.clone())
            .with_pba_hardening(PbaHardening::at(1));
        assert!(on.validate_block_consistency(&child(1_000 + MAX, 2)).await.is_ok());
        assert!(on.validate_block_consistency(&child(1_000 + MAX + 1, 3)).await.is_err());
        assert!(on.validate_block_consistency(&child(u64::MAX, 4)).await.is_err());
        assert!(on.validate_block_consistency(&child(999, 5)).await.is_err(), "monotonic");
        // Activation above this height: legacy rule (no upper bound).
        let later = GhostDag::new(GhostDagParams::default(), dag_store.clone())
            .with_pba_hardening(PbaHardening::at(2));
        assert!(later.validate_block_consistency(&child(u64::MAX, 6)).await.is_ok());
        let off = GhostDag::new(GhostDagParams::default(), dag_store.clone())
            .with_pba_hardening(PbaHardening::off());
        assert!(off.validate_block_consistency(&child(u64::MAX, 7)).await.is_ok());
        // A u64::MAX parent: the bound saturates, never panics.
        let mut far = create_test_block_with_parents([0x08; 32], genesis.hash(), vec![], 1);
        far.header.timestamp = u64::MAX;
        dag_store.store_block(far.clone()).await.unwrap();
        let mut grandchild = create_test_block_with_parents([0x09; 32], far.hash(), vec![], 2);
        grandchild.header.timestamp = u64::MAX;
        assert!(on.validate_block_consistency(&grandchild).await.is_ok());
    }

    #[tokio::test]
    async fn test_genesis_block_blue_set() {
        let params = GhostDagParams::default();
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = GhostDag::new(params, dag_store.clone());

        let genesis = create_test_block_with_parents([0xEE; 32], Hash::default(), vec![], 0);

        // Store genesis in dag_store
        dag_store.store_block(genesis.clone()).await.unwrap();

        let blue_set = ghostdag.calculate_blue_set(&genesis).await.unwrap();
        assert_eq!(blue_set.score, 1);
        assert!(blue_set.contains(&genesis.hash()));
    }

    #[tokio::test]
    async fn test_add_block() {
        let params = GhostDagParams::default();
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = GhostDag::new(params, dag_store.clone());

        // Add genesis
        let genesis = create_test_block_with_parents([0xEE; 32], Hash::default(), vec![], 0);

        // Store genesis in dag_store
        dag_store.store_block(genesis.clone()).await.unwrap();

        // Manually add genesis to cache
        let mut blue_set = BlueSet::new();
        blue_set.insert(genesis.hash());
        ghostdag
            .blue_cache
            .write()
            .await
            .insert(genesis.hash(), blue_set);

        // Add genesis relation
        let genesis_relation = DagRelation {
            block: genesis.hash(),
            selected_parent: Hash::default(),
            merge_parents: vec![],
            children: vec![],
            blue_set: BlueSet::new(),
            is_chain_block: true,
            height: 0,
        };
        ghostdag
            .relations
            .write()
            .await
            .insert(genesis.hash(), genesis_relation);

        // Add child block
        let block1 = create_test_block_with_parents([1; 32], genesis.hash(), vec![], 1);

        // Store block1 in dag_store
        dag_store.store_block(block1.clone()).await.unwrap();

        ghostdag.add_block(&block1).await.unwrap();

        // Verify tips
        let tips = ghostdag.get_tips().await;
        assert_eq!(tips.len(), 1);
        assert!(tips.contains(&block1.hash()));
    }

    /// PIN for the 2026-08-09 halt (chain 40204 @ 178,341 — a same-height sibling
    /// fork, depth 2, NO restart, healed by neither the tie-break (#160) nor the
    /// reorg-depth work). The producer selects its parent with
    /// `TipSelector::select_tip(dag_store.get_tips())` (scoring each candidate via
    /// `calculate_blue_score`), while the drain's reorg fork-choice uses
    /// `GhostDag::select_tip()` over `GhostDag.self.tips` (reading the STORED
    /// `blue_set.score`). These are TWO independent fork-choice implementations over
    /// TWO independent tip sets. #160 only aligned the tie-break COMPARATOR — it did
    /// nothing about the split state. When the two sets diverge at a sibling fork
    /// (here: the winning sibling reached the DAG store but not GhostDAG's in-memory
    /// tips — an admission/reconcile gap), the producer targets the winner while the
    /// drain still ranks its own losing tip best. The producer is then blocked every
    /// round by the MP-S1 parent/state guard, and the drain sees `best == applied
    /// tip` so it NEVER reorgs (a silent `NoChange`, no warn) — a permanent deadlock
    /// no restart clears.
    ///
    /// THE FIX is at the CONSUMER, not here: the producer now selects its parent via
    /// `GhostDag::select_tip()` (the drain's authority) instead of `TipSelector` over
    /// `DagStore::get_tips()` — see `producer::select_parents_with_ghostdag`. These
    /// two selectors remain genuinely different functions over different state, so
    /// this `assert_ne!` STAYS: it is a permanent guard that they are NOT
    /// interchangeable and must never both be used as fork choice. Producer-level
    /// agreement is covered by the MP-S1 end-to-end producer test.
    #[tokio::test]
    async fn producer_and_drain_forkchoice_diverge_on_a_sibling_fork() {
        use crate::tip_selection::{SelectionStrategy, TipSelector};

        let params = GhostDagParams::default();
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = Arc::new(GhostDag::new(params, dag_store.clone()));
        let tip_selector = Arc::new(TipSelector::new(
            dag_store.clone(),
            ghostdag.clone(),
            SelectionStrategy::HighestBlueScoreWithTieBreak,
        ));

        // genesis @0 — seed BOTH the DAG store and GhostDAG (relations + cache + tip).
        let genesis = create_test_block_with_parents([0xEE; 32], Hash::default(), vec![], 0);
        dag_store
            .store_block(genesis.clone())
            .await
            .expect("store genesis");
        let mut g_blue = BlueSet::new();
        g_blue.insert(genesis.hash());
        g_blue.score = 1;
        ghostdag
            .blue_cache
            .write()
            .await
            .insert(genesis.hash(), g_blue.clone());
        ghostdag.relations.write().await.insert(
            genesis.hash(),
            DagRelation {
                block: genesis.hash(),
                selected_parent: Hash::default(),
                merge_parents: vec![],
                children: vec![],
                blue_set: g_blue,
                is_chain_block: true,
                height: 0,
            },
        );
        ghostdag.tips.write().await.insert(genesis.hash());

        // a1 @1 — the common ancestor (fork point). Admitted to BOTH structures.
        let a1 = create_test_block_with_parents([1; 32], genesis.hash(), vec![], 1);
        dag_store.store_block(a1.clone()).await.expect("store a1");
        ghostdag.add_block(&a1).await.expect("admit a1");

        // Two equal-blue_score siblings at height 2. `winner` has the SMALLER hash,
        // so the shared tie-break (smallest hash) makes it the canonical head.
        let winner = create_test_block_with_parents([2; 32], a1.hash(), vec![], 2);
        let loser = create_test_block_with_parents([9; 32], a1.hash(), vec![], 2);
        assert!(
            winner.hash() < loser.hash(),
            "winner must be the smaller hash"
        );

        // Production desync: the LOSER (this node's own sibling) is admitted to BOTH;
        // the WINNER (peer's sibling) reached the DAG store but NOT GhostDAG's tips
        // (the admission/reconcile gap). Both are children of a1, so the DAG store
        // sees both as tips; GhostDAG's in-memory tip set sees only the loser.
        dag_store
            .store_block(loser.clone())
            .await
            .expect("store loser");
        ghostdag.add_block(&loser).await.expect("admit loser");
        dag_store
            .store_block(winner.clone())
            .await
            .expect("store winner (DAG only)");
        // (no ghostdag.add_block(&winner) — that is the gap)

        // The producer maps DAG-store tips to hashes exactly this way (producer.rs).
        let dag_tips: Vec<Hash> = dag_store.get_tips().await.iter().map(|t| t.hash).collect();
        assert!(
            dag_tips.contains(&winner.hash()) && dag_tips.contains(&loser.hash()),
            "DAG store (the producer's tip source) sees BOTH siblings"
        );

        // Producer's parent choice vs drain's reorg fork-choice.
        let producer_pick = tip_selector
            .select_tip(&dag_tips)
            .await
            .expect("producer tip selection");
        let drain_pick = ghostdag.select_tip().await.expect("drain tip selection");

        assert_eq!(
            producer_pick,
            winner.hash(),
            "producer (TipSelector over DAG-store tips) targets the smaller-hash winner"
        );
        assert_eq!(
            drain_pick,
            loser.hash(),
            "drain (GhostDag::select_tip over its own tips) stays on this node's losing sibling"
        );
        // THE BUG, pinned: the two selectors disagree → if the producer uses one and
        // the drain the other, the producer is blocked by MP-S1 while the drain never
        // reorgs → permanent silent deadlock. The fix routes the producer through the
        // drain's `GhostDag::select_tip` (producer.rs); this `assert_ne!` stays as a
        // guard that the two selectors are NOT interchangeable.
        assert_ne!(
            producer_pick, drain_pick,
            "REPRODUCED: producer and drain select different sibling heads"
        );
    }

    /// BUG 1 FIX (restart-liveness, 2026-08-11): `reconcile_tips_from_dag_store`
    /// realigns GhostDag's in-memory tip set with the DAG store's AUTHORITATIVE tip
    /// set after a restart, so `select_tip` stops returning a stale tip and matches
    /// the DAG store (and therefore the producer). Same divergence shape as the pin
    /// above — a winner sibling present in the DAG store but MISSING from GhostDAG's
    /// tips — but here we reconcile and assert `select_tip` converges on the true
    /// canonical (smaller-hash) winner.
    #[tokio::test]
    async fn reconcile_tips_from_dag_store_realigns_select_tip_with_the_authoritative_set() {
        let params = GhostDagParams::default();
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = Arc::new(GhostDag::new(params, dag_store.clone()));

        // genesis + a1 admitted to BOTH.
        let genesis = create_test_block_with_parents([0xEE; 32], Hash::default(), vec![], 0);
        dag_store
            .store_block(genesis.clone())
            .await
            .expect("store genesis");
        ghostdag.add_block(&genesis).await.expect("admit genesis");
        let a1 = create_test_block_with_parents([1; 32], genesis.hash(), vec![], 1);
        dag_store.store_block(a1.clone()).await.expect("store a1");
        ghostdag.add_block(&a1).await.expect("admit a1");

        // Two equal-score siblings; winner has the smaller hash.
        let winner = create_test_block_with_parents([2; 32], a1.hash(), vec![], 2);
        let loser = create_test_block_with_parents([9; 32], a1.hash(), vec![], 2);
        assert!(winner.hash() < loser.hash());

        // The LOSER is admitted to GhostDAG; the WINNER reaches only the DAG store
        // (the restart-rehydration gap). select_tip is stuck on the loser.
        dag_store
            .store_block(loser.clone())
            .await
            .expect("store loser");
        ghostdag.add_block(&loser).await.expect("admit loser");
        dag_store
            .store_block(winner.clone())
            .await
            .expect("store winner (DAG only)");

        assert!(!ghostdag.dag_hydrated_handle().load(Ordering::SeqCst));
        assert_eq!(
            ghostdag.select_tip().await.expect("select_tip"),
            loser.hash(),
            "before reconcile, select_tip is stuck on the stale (loser) tip"
        );

        // ── THE FIX ── reconcile to the authoritative DAG-store tip set. The
        // in-memory tip set now equals DagStore's, so the winner (previously absent
        // from GhostDAG's tips) is considered. (The permissive test store's
        // incremental get_tips also carries genesis; production's load_from_persistent
        // excludes the root. Either way the higher-score sibling wins.)
        let n = ghostdag.reconcile_tips_from_dag_store().await;
        assert!(
            n >= 2,
            "authoritative tip set includes both siblings (got {n})"
        );
        assert!(
            ghostdag.dag_hydrated_handle().load(Ordering::SeqCst),
            "reconcile marks DAG hydration complete"
        );
        assert_eq!(
            ghostdag.select_tip().await.expect("select_tip"),
            winner.hash(),
            "after reconcile, select_tip returns the true canonical (smaller-hash) winner"
        );
    }

    #[tokio::test]
    async fn test_tip_selection() {
        let params = GhostDagParams::default();
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = GhostDag::new(params, dag_store.clone());

        // Create simple chain
        let genesis = create_test_block_with_parents([0xEE; 32], Hash::default(), vec![], 0);

        // Add genesis manually
        let mut genesis_blue = BlueSet::new();
        genesis_blue.insert(genesis.hash());
        genesis_blue.score = 1;

        let genesis_relation = DagRelation {
            block: genesis.hash(),
            selected_parent: Hash::default(),
            merge_parents: vec![],
            children: vec![],
            blue_set: genesis_blue.clone(),
            is_chain_block: true,
            height: 0,
        };

        ghostdag
            .relations
            .write()
            .await
            .insert(genesis.hash(), genesis_relation);
        ghostdag
            .blue_cache
            .write()
            .await
            .insert(genesis.hash(), genesis_blue);
        ghostdag.tips.write().await.insert(genesis.hash());

        let best_tip = ghostdag.select_tip().await.unwrap();
        assert_eq!(best_tip, genesis.hash());
    }

    #[tokio::test]
    async fn test_select_tip_deterministic_tie_break_by_hash() {
        // Receive-side analogue of audit finding H-08: equal-`blue_score` sibling
        // tips (what two concurrent producers create at the same height) MUST
        // resolve to the same tip — the smallest hash — on every node regardless
        // of `HashSet` iteration order, or the fleet forks permanently. Before the
        // fix `select_tip` used a bare `>` with no tie-break and returned whichever
        // equal-score tip iteration happened to surface first.
        let params = GhostDagParams::default();
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = GhostDag::new(params, dag_store.clone());

        // Five sibling tips, all at blue_score = 7, distinct hashes.
        let tie_hashes = [
            Hash::new([0x11; 32]),
            Hash::new([0x33; 32]),
            Hash::new([0x22; 32]),
            Hash::new([0xAA; 32]),
            Hash::new([0x05; 32]),
        ];
        for h in tie_hashes.iter() {
            let mut bs = BlueSet::new();
            bs.insert(*h);
            bs.score = 7;
            let rel = DagRelation {
                block: *h,
                selected_parent: Hash::default(),
                merge_parents: vec![],
                children: vec![],
                blue_set: bs.clone(),
                is_chain_block: true,
                height: 7,
            };
            ghostdag.relations.write().await.insert(*h, rel);
            ghostdag.tips.write().await.insert(*h);
        }

        let expected = *tie_hashes.iter().min().expect("non-empty"); // 0x05..
                                                                     // HashSet iteration order varies run-to-run; the result must not.
        for _ in 0..50 {
            let got = ghostdag.select_tip().await.expect("a tip is available");
            assert_eq!(
                got, expected,
                "select_tip must deterministically pick the smallest-hash tip on a blue_score tie"
            );
        }

        // A strictly higher blue_score must win over the whole tie group even
        // though its hash is the largest — score dominates the tie-break.
        let winner = Hash::new([0xFF; 32]);
        let mut wbs = BlueSet::new();
        wbs.insert(winner);
        wbs.score = 8;
        let wrel = DagRelation {
            block: winner,
            selected_parent: Hash::default(),
            merge_parents: vec![],
            children: vec![],
            blue_set: wbs.clone(),
            is_chain_block: true,
            height: 8,
        };
        ghostdag.relations.write().await.insert(winner, wrel);
        ghostdag.tips.write().await.insert(winner);
        for _ in 0..20 {
            assert_eq!(
                ghostdag.select_tip().await.expect("a tip is available"),
                winner,
                "higher blue_score must win regardless of hash ordering"
            );
        }
    }

    #[tokio::test]
    async fn test_blue_set_with_merge_parents_unions_parents() {
        let params = GhostDagParams::default();
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = GhostDag::new(params, dag_store.clone());

        // Genesis
        let genesis = create_test_block_with_parents([0xAA; 32], Hash::default(), vec![], 0);
        dag_store.store_block(genesis.clone()).await.unwrap();

        // Prime relations/cache for genesis
        let mut gset = BlueSet::new();
        gset.insert(genesis.hash());
        ghostdag
            .blue_cache
            .write()
            .await
            .insert(genesis.hash(), gset.clone());
        let grel = DagRelation {
            block: genesis.hash(),
            selected_parent: Hash::default(),
            merge_parents: vec![],
            children: vec![],
            blue_set: gset,
            is_chain_block: true,
            height: 0,
        };
        ghostdag
            .relations
            .write()
            .await
            .insert(genesis.hash(), grel);
        ghostdag.tips.write().await.insert(genesis.hash());

        // Two parallel children of genesis: b and c
        let b = create_test_block_with_parents([0xB1; 32], genesis.hash(), vec![], 1);
        let c = create_test_block_with_parents([0xC1; 32], genesis.hash(), vec![], 1);
        dag_store.store_block(b.clone()).await.unwrap();
        dag_store.store_block(c.clone()).await.unwrap();
        ghostdag.add_block(&b).await.unwrap();
        ghostdag.add_block(&c).await.unwrap();

        // d references b as selected parent and c as merge parent
        let d = create_test_block_with_parents([0xD1; 32], b.hash(), vec![c.hash()], 2);
        dag_store.store_block(d.clone()).await.unwrap();
        ghostdag.add_block(&d).await.unwrap();

        // Blue set for d should include at least {genesis, b, c, d}
        let blue = ghostdag.calculate_blue_set(&d).await.unwrap();
        assert!(blue.contains(&genesis.hash()));
        assert!(blue.contains(&b.hash()));
        assert!(blue.contains(&c.hash()));
        assert!(blue.contains(&d.hash()));
        assert!(blue.score >= 4);
    }

    #[tokio::test]
    async fn test_count_blue_anticone_short_circuits_at_max_count() {
        // Regression test for the OOM fix (Apr 2026): count_blue_anticone
        // must stop walking once the count reaches max_count. The caller
        // (is_blue_candidate) only needs to know whether the count
        // exceeds k; walking the entire blue set is O(|blue| × BFS_depth)
        // per block and drove the testnet-beta node into a 14k-restart
        // OOM loop.
        let params = GhostDagParams::default();
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = GhostDag::new(params, dag_store.clone());

        // Build a reference blue set with many unrelated blocks — all
        // hit the "not ancestor" branch and increment count.
        let mut blue_set = BlueSet::new();
        for i in 0..200u8 {
            let mut h = [0u8; 32];
            h[0] = i;
            blue_set.insert(Hash::new(h));
        }
        blue_set.score = 200;

        let mut candidate_hash = [0u8; 32];
        candidate_hash[31] = 0xFF;
        let candidate = Hash::new(candidate_hash);

        // max_count = 5 — should return exactly 5, not 200.
        let count = ghostdag
            .count_blue_anticone(&candidate, &blue_set, &[], 5)
            .await
            .expect("count_blue_anticone should succeed");

        assert_eq!(
            count, 5,
            "expected early-exit at max_count=5, got {}",
            count
        );
    }

    /// SYNC-S1 D1 — the receive path materialises QUADRATIC blue ancestry.
    ///
    /// PIL-13 built `materialised_blue_ancestry_entries` and asserted it stays
    /// zero for the PRODUCER path (`register_existing_block`, see
    /// core/sequencer `producer_steady_state`). The RECEIVE path
    /// (`add_block`, called once per synced/gossiped block) was never held to
    /// the same invariant, and it violates it: `calculate_blue_set` clones the
    /// selected parent's full ancestor set per block, retaining it in BOTH
    /// `relations[].blue_set` and `blue_cache`.
    ///
    /// That is the follower OOM: at N≈10.9k the two copies bracket 4 GB, and
    /// `citrate-boot-3` was kernel-killed 21 times on a 3.9 GB box while the
    /// sole producer sat healthy at height 59k on 2.6 GiB. This test pins the
    /// growth ORDER, which is the property D1 has to change.
    #[tokio::test]
    async fn receive_path_retains_no_cumulative_blue_ancestry() {
        async fn entries_after(n: u64, use_receive_path: bool) -> usize {
            let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
            let ghostdag = GhostDag::new(GhostDagParams::default(), dag_store.clone());
            let genesis = create_test_block_with_parents([0xEE; 32], Hash::default(), vec![], 0);
            dag_store.store_block(genesis.clone()).await.unwrap();
            let mut prev = genesis.hash();
            let mut blocks = vec![genesis];
            for i in 1..=n {
                let mut h = [0u8; 32];
                h[0..8].copy_from_slice(&i.to_le_bytes());
                let b = create_test_block_with_parents(h, prev, vec![], i);
                dag_store.store_block(b.clone()).await.unwrap();
                prev = b.hash();
                blocks.push(b);
            }
            for b in &blocks {
                if use_receive_path {
                    ghostdag.add_block(b).await.unwrap();
                } else {
                    ghostdag.register_existing_block(b).await.unwrap();
                }
            }
            ghostdag.materialised_blue_ancestry_entries().await
        }

        // The producer path is the reference: O(1) per block, nothing retained.
        assert_eq!(
            entries_after(100, false).await,
            0,
            "register_existing_block must materialise no cumulative ancestry (PIL-13)"
        );

        // POST-D1: the receive path is held to the SAME invariant. A linear
        // chain retains no cumulative ancestry at all, because
        // `derive_score_and_work` computes score = parent.score + 1 without
        // ever building a set. Pre-D1 this retained >N²/2 entries and
        // quadrupled from N=50 to N=100.
        assert_eq!(
            entries_after(100, true).await,
            0,
            "SYNC-S1 D1: the receive path must retain no cumulative blue ancestry \
             on a linear chain — this is the follower OOM (Theta(N²) -> O(1) per block)"
        );

        // Growth is flat, not merely smaller: doubling the chain must not
        // increase retention at all.
        let at_50 = entries_after(50, true).await;
        let at_100 = entries_after(100, true).await;
        assert_eq!(
            at_50, at_100,
            "retention must not grow with chain length (N=50 -> {at_50}, N=100 -> {at_100})"
        );

        // Depth check. Pre-D1 a 2_000-block receive-path sync retained ~2M
        // ancestry entries (and ~4 GB at the live chain's 11k). It must now be
        // flat at zero, and this completing quickly also demonstrates the
        // derivation is O(1) per block in TIME, not merely in retained bytes —
        // a set-materialising implementation would be O(N²) work here.
        assert_eq!(
            entries_after(2_000, true).await,
            0,
            "a deep linear sync must retain no cumulative ancestry"
        );
    }

    /// SYNC-S1 D3 — the durable score anchor removes the cold-start walk, which
    /// is what makes DAG-store pruning possible.
    ///
    /// D1's cold path walks the selected-parent chain back to the nearest known
    /// score. That is O(1) memory but it REQUIRES the ancestry to still be in
    /// the DAG store — so it is precisely what blocks wiring `prune()`. With a
    /// persisted anchor the restart reads one key instead, so a pruned ancestry
    /// is no longer fatal.
    ///
    /// Asserts both halves: the anchor survives a simulated restart (a fresh
    /// GhostDag over the same persistent store), AND admission still works when
    /// every ancestor except the parent has been removed from the DAG store —
    /// which the pre-D3 walk could not do.
    #[tokio::test]
    async fn persisted_score_anchor_survives_restart_and_a_pruned_ancestry() {
        // Minimal in-memory KvStore so the store is genuinely "persistent"
        // across the simulated restart below.
        #[derive(Default)]
        struct MemKv {
            #[allow(clippy::type_complexity)]
            data: std::sync::Mutex<HashMap<String, HashMap<Vec<u8>, Vec<u8>>>>,
        }
        impl crate::dag_store::KvStore for MemKv {
            fn kv_get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
                Ok(self
                    .data
                    .lock()
                    .unwrap()
                    .get(cf)
                    .and_then(|m| m.get(key).cloned()))
            }
            fn kv_put(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<(), String> {
                self.data
                    .lock()
                    .unwrap()
                    .entry(cf.to_string())
                    .or_default()
                    .insert(key.to_vec(), value.to_vec());
                Ok(())
            }
            fn kv_delete(&self, cf: &str, key: &[u8]) -> Result<(), String> {
                if let Some(m) = self.data.lock().unwrap().get_mut(cf) {
                    m.remove(key);
                }
                Ok(())
            }
            fn kv_exists(&self, cf: &str, key: &[u8]) -> Result<bool, String> {
                Ok(self
                    .data
                    .lock()
                    .unwrap()
                    .get(cf)
                    .is_some_and(|m| m.contains_key(key)))
            }
            fn kv_iter_cf(&self, cf: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
                Ok(self
                    .data
                    .lock()
                    .unwrap()
                    .get(cf)
                    .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                    .unwrap_or_default())
            }
        }

        let kv = Arc::new(MemKv::default());
        let dag_store = Arc::new(
            DagStore::persistent_with_strict_vrf(kv.clone(), false).expect("persistent store"),
        );

        // Build and admit a chain in "process 1".
        let genesis = create_test_block_with_parents([0xA1; 32], Hash::default(), vec![], 0);
        dag_store.store_block(genesis.clone()).await.unwrap();
        let mut blocks = vec![genesis.clone()];
        let mut parent = genesis.hash();
        for i in 1..=40u64 {
            let mut h = [0u8; 32];
            h[0..8].copy_from_slice(&i.to_le_bytes());
            h[31] = 0xD4;
            let b = create_test_block_with_parents(h, parent, vec![], i);
            dag_store.store_block(b.clone()).await.unwrap();
            parent = b.hash();
            blocks.push(b);
        }
        {
            let gd1 = GhostDag::new(GhostDagParams::default(), dag_store.clone());
            for b in &blocks {
                gd1.add_block(b).await.expect("admit");
            }
            assert_eq!(gd1.get_blue_score(&parent).await.unwrap(), 41);
        }

        // The anchor is durable, not just in-memory.
        assert_eq!(
            dag_store.get_derived_blue_score(&parent),
            Some(41),
            "the derived score must be persisted, not only held in `relations`"
        );

        // "Process 2": a fresh GhostDag over the same store — relations empty,
        // exactly the post-restart state.
        let gd2 = GhostDag::new(GhostDagParams::default(), dag_store.clone());
        assert_eq!(
            gd2.materialised_blue_ancestry_entries().await,
            0,
            "fresh process starts with no relations"
        );

        // Now PRUNE the ancestry through the REAL production mechanism: set the
        // pruning point at height 39 and call `prune()`, which drops every block
        // below it from memory and disk. The D1 walk would hit a missing block
        // and fail; the anchor makes it a single key read.
        dag_store
            .update_pruning_point(blocks[39].hash())
            .await
            .expect("set pruning point");
        let pruned = dag_store.prune().await.expect("prune");
        assert_eq!(pruned, 39, "heights 0..=38 pruned, tip + parent retained");
        assert!(
            dag_store.get_block(&blocks[0].hash()).await.is_err(),
            "a pruned ancestor is genuinely gone from the DAG store"
        );

        // Admit the next block on top of the pruned chain.
        let mut h = [0u8; 32];
        h[0..8].copy_from_slice(&41u64.to_le_bytes());
        h[31] = 0xD4;
        let next = create_test_block_with_parents(h, parent, vec![], 41);
        dag_store.store_block(next.clone()).await.unwrap();
        gd2.add_block(&next)
            .await
            .expect("admission must succeed over a PRUNED ancestry via the durable anchor");

        assert_eq!(
            gd2.get_blue_score(&next.hash()).await.unwrap(),
            42,
            "score continues the sequence across a restart AND a pruned ancestry"
        );
        assert_eq!(
            gd2.materialised_blue_ancestry_entries().await,
            0,
            "still no cumulative ancestry materialised"
        );
    }

    /// SYNC-S1 D1 COLD PATH — a follower's FIRST block after a restart must not
    /// rebuild the O(N²) footprint.
    ///
    /// `relations` is in-memory only, so after every restart it is empty and the
    /// first received block has no registered selected parent. If that case
    /// falls through to `calculate_blue_set`, it walks to genesis caching a full
    /// cumulative ancestor set per block on the path — the entire Theta(N²)
    /// footprint, rebuilt in one call, which is the ~4 GB that OOM-killed
    /// boot-3 twenty-one times. So the restart case has to be O(1) memory too,
    /// not just the steady-state case.
    ///
    /// This is deliberately a DEEP chain: at N=1_000 the quadratic path would
    /// retain ~500k ancestry entries, so a regression is unmistakable.
    #[tokio::test]
    async fn cold_start_first_block_derives_score_without_materialising_ancestry() {
        const N: u64 = 800;
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());

        // Populate the DAG STORE only — exactly what `DagStore::load` gives a
        // node on restart. `relations` stays empty.
        let genesis = create_test_block_with_parents([0xA1; 32], Hash::default(), vec![], 0);
        dag_store.store_block(genesis.clone()).await.unwrap();
        let mut parent = genesis.hash();
        let mut tip = genesis.clone();
        for i in 1..=N {
            let mut h = [0u8; 32];
            h[0..8].copy_from_slice(&i.to_le_bytes());
            h[31] = 0xC3; // keep hashes clear of Hash::default()
            let b = create_test_block_with_parents(h, parent, vec![], i);
            dag_store.store_block(b.clone()).await.unwrap();
            parent = b.hash();
            tip = b;
        }

        let ghostdag = GhostDag::new(GhostDagParams::default(), dag_store.clone());
        assert_eq!(
            ghostdag.materialised_blue_ancestry_entries().await,
            0,
            "a freshly constructed GhostDag has an empty relations map (post-restart state)"
        );

        // The first block admitted after the restart — deepest possible cold path.
        ghostdag.add_block(&tip).await.expect("cold admit");

        assert_eq!(
            ghostdag.get_blue_score(&tip.hash()).await.unwrap(),
            N + 1,
            "cold-path derivation must agree with the warm path: genesis 1 + one per step"
        );
        assert_eq!(
            ghostdag.materialised_blue_ancestry_entries().await,
            0,
            "SYNC-S1 D1: the cold path must not materialise cumulative ancestry — \
             routing it through calculate_blue_set would retain ~N²/2 entries and \
             reintroduce the follower OOM once per restart"
        );

        // The next block up is now warm: its parent is registered, so O(1).
        let mut h = [0u8; 32];
        h[0..8].copy_from_slice(&(N + 1).to_le_bytes());
        h[31] = 0xC3;
        let next = create_test_block_with_parents(h, tip.hash(), vec![], N + 1);
        dag_store.store_block(next.clone()).await.unwrap();
        ghostdag.add_block(&next).await.expect("warm admit");
        assert_eq!(
            ghostdag.get_blue_score(&next.hash()).await.unwrap(),
            N + 2,
            "warm path continues the same sequence"
        );
        assert_eq!(
            ghostdag.materialised_blue_ancestry_entries().await,
            0,
            "still flat"
        );
    }

    /// SYNC-S1 D1 — the two DAG-registration paths agree on a block's blue
    /// score. Before D1 they did not, which is why D1 was a decision and not
    /// just a refactor.
    ///
    /// * `add_block` (receive path) sets `score = |blue_set.blocks|`, i.e. the
    ///   cardinality of the cumulative ancestry INCLUDING genesis and self —
    ///   `height + 1` on a linear chain.
    /// * `register_existing_block` (producer rehydration) sets
    ///   `score = block.header.blue_score`, which the fixtures and the live
    ///   chain set to `height`.
    ///
    /// So the SAME block gets a different fork-choice score depending on
    /// whether this node received it live or rehydrated it from disk at
    /// startup. `select_tip` compares those scores across tips, so a live
    /// tip and a rehydrated tip at equal height do not compare equal. This is
    /// a latent fork-choice inconsistency independent of the OOM, and it is
    /// why D1 is a decision and not just a refactor.
    ///
    /// This test asserts the CURRENT (mismatched) behaviour deliberately, so
    /// the mismatch cannot drift further while D1 is pending. When D1 unifies
    /// the convention this test flips to `assert_eq!`.
    #[tokio::test]
    async fn blue_score_convention_agrees_between_registration_paths() {
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        // Genesis must NOT be hashed [0u8; 32]: that equals `Hash::default()`,
        // so any direct child would satisfy `is_genesis()` (selected parent ==
        // default) and take `calculate_blue_set`'s genesis short-circuit,
        // silently making the chain degenerate.
        let genesis = create_test_block_with_parents([0xA1; 32], Hash::default(), vec![], 0);
        let b1 = create_test_block_with_parents([0xB2; 32], genesis.hash(), vec![], 1);
        assert!(
            genesis.is_genesis() && !b1.is_genesis(),
            "fixture must be a real 2-block chain"
        );
        dag_store.store_block(genesis.clone()).await.unwrap();
        dag_store.store_block(b1.clone()).await.unwrap();

        // Receive path.
        let live = GhostDag::new(GhostDagParams::default(), dag_store.clone());
        live.add_block(&genesis).await.unwrap();
        live.add_block(&b1).await.unwrap();
        let score_live = live.get_blue_score(&b1.hash()).await.unwrap();

        // Startup rehydration path.
        let rehydrated = GhostDag::new(GhostDagParams::default(), dag_store.clone());
        rehydrated.register_existing_block(&genesis).await.unwrap();
        rehydrated.register_existing_block(&b1).await.unwrap();
        let score_rehydrated = rehydrated.get_blue_score(&b1.hash()).await.unwrap();

        // POST-D1: both paths derive the score locally and inductively, so the
        // same block gets the same fork-choice score however it arrived. Pre-D1
        // this was 2 (live, set cardinality) vs 1 (rehydrated, header value),
        // so a live tip and a restart-rehydrated tip at equal height did not
        // compare equal in `select_tip`.
        assert_eq!(
            score_live, score_rehydrated,
            "SYNC-S1 D1: the receive path and the rehydration path must agree on \
             a block's blue score, or fork choice depends on how the block arrived"
        );
        assert_eq!(
            score_live, 2,
            "canonical convention: genesis == 1, each linear step adds 1 (height + 1)"
        );
        assert_eq!(
            b1.header.blue_score, 1,
            "the HEADER convention stays score == height; the recomputed score sits \
             exactly one above it, which is the invariant add_block now checks"
        );
    }

    #[tokio::test]
    async fn test_deep_chain_cold_blue_set_is_stack_safe() {
        // Regression for the stack-overflow fix (Apr 2026): on a fresh
        // start with an empty blue_cache, computing the blue set for
        // the tip of a long selected-parent chain must not recurse
        // one-frame-per-block. Before the iterative rewrite, this
        // aborted the main thread at ~1800 blocks on testnet-beta.
        //
        // We build a 4_000-block linear chain and call calculate_blue_set
        // on its tip with an EMPTY cache (no priming from add_block's
        // own cache writes). 4k is well past the pre-fix crash point
        // (~1779) and within a normal test runtime.
        let params = GhostDagParams::default();
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = GhostDag::new(params, dag_store.clone());

        // Genesis, primed into dag_store only (not into blue_cache).
        let genesis = create_test_block_with_parents([0xEE; 32], Hash::default(), vec![], 0);
        dag_store.store_block(genesis.clone()).await.unwrap();
        let mut prev = genesis.hash();

        for i in 0..4_000usize {
            let mut h = [0u8; 32];
            h[0..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
            let block = create_test_block_with_parents(h, prev, vec![], (i + 1) as u64);
            dag_store.store_block(block.clone()).await.unwrap();
            prev = block.hash();
        }

        // Compute blue set for the tip with an empty blue_cache.
        // Must not panic with stack overflow.
        let tip_block = dag_store.get_block(&prev).await.unwrap();
        let blue = ghostdag
            .calculate_blue_set(&tip_block)
            .await
            .expect("deep-chain cold blue set should succeed");

        // Primary invariant: cold computation completes without stack
        // overflow. Score and block count are both positive and
        // correlated with chain length. The exact count depends on
        // how BlueSet::insert handles hash collisions and the
        // is_genesis/blocks-insertion semantics of calculate_blue_set;
        // property-based tests cover the precise relationships.
        assert!(
            blue.blocks.len() > 3_900,
            "blue set should contain nearly all 4000 chain blocks, got {}",
            blue.blocks.len()
        );
    }

    #[tokio::test]
    async fn test_count_blue_anticone_zero_max_short_circuits_immediately() {
        // Edge case: max_count=0 must return 0 without walking at all.
        let params = GhostDagParams::default();
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = GhostDag::new(params, dag_store.clone());

        let mut blue_set = BlueSet::new();
        for i in 0..50u8 {
            let mut h = [0u8; 32];
            h[0] = i;
            blue_set.insert(Hash::new(h));
        }

        let candidate = Hash::new([0xAA; 32]);
        let count = ghostdag
            .count_blue_anticone(&candidate, &blue_set, &[], 0)
            .await
            .expect("count_blue_anticone should succeed");

        assert_eq!(count, 0);
    }

    // -----------------------------------------------------------------------
    // Property-based tests (proptest)
    // -----------------------------------------------------------------------

    use proptest::prelude::*;

    /// Build a random linear chain of `n` blocks on top of genesis.
    /// Returns (ghostdag, dag_store, block_hashes_in_order).
    async fn build_random_chain(n: usize, seed: u64) -> (GhostDag, Arc<DagStore>, Vec<Hash>) {
        let params = GhostDagParams::default();
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = GhostDag::new(params, dag_store.clone());

        // Genesis
        let genesis = create_test_block_with_parents([0xEE; 32], Hash::default(), vec![], 0);
        dag_store.store_block(genesis.clone()).await.unwrap();

        let mut gset = BlueSet::new();
        gset.insert(genesis.hash());
        gset.score = 1;
        ghostdag
            .blue_cache
            .write()
            .await
            .insert(genesis.hash(), gset.clone());
        let grel = DagRelation {
            block: genesis.hash(),
            selected_parent: Hash::default(),
            merge_parents: vec![],
            children: vec![],
            blue_set: gset,
            is_chain_block: true,
            height: 0,
        };
        ghostdag
            .relations
            .write()
            .await
            .insert(genesis.hash(), grel);
        ghostdag.tips.write().await.insert(genesis.hash());

        let mut hashes = vec![genesis.hash()];
        let mut prev = genesis.hash();

        for i in 0..n {
            let mut hash_bytes = [0u8; 32];
            // Deterministic but unique hash from seed + index
            let val = seed.wrapping_mul(31).wrapping_add(i as u64);
            hash_bytes[0..8].copy_from_slice(&val.to_le_bytes());
            hash_bytes[8] = (i & 0xFF) as u8;
            let block = create_test_block_with_parents(hash_bytes, prev, vec![], (i + 1) as u64);
            dag_store.store_block(block.clone()).await.unwrap();
            ghostdag.add_block(&block).await.unwrap();
            hashes.push(block.hash());
            prev = block.hash();
        }

        (ghostdag, dag_store, hashes)
    }

    proptest! {
        /// Property: In a linear chain, blue score increases monotonically.
        #[test]
        fn prop_linear_chain_blue_score_monotonic(n in 2..20usize, seed in 1..1000u64) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let (ghostdag, _, hashes) = build_random_chain(n, seed).await;
                let mut prev_score = 0u64;
                for hash in &hashes {
                    if let Ok(score) = ghostdag.get_blue_score(hash).await {
                        prop_assert!(score >= prev_score,
                            "Blue score decreased: {} -> {} at {:?}", prev_score, score, hash);
                        prev_score = score;
                    }
                }
                Ok(())
            })?;
        }

        /// Property: Tip selection always returns the tip with the highest blue score.
        #[test]
        fn prop_tip_is_highest_blue_score(n in 1..15usize, seed in 1..1000u64) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let (ghostdag, _, _) = build_random_chain(n, seed).await;
                let tips = ghostdag.get_tips().await;
                prop_assert!(!tips.is_empty(), "DAG must have at least one tip");

                let selected_tip = ghostdag.select_tip().await.unwrap();
                prop_assert!(tips.contains(&selected_tip),
                    "Selected tip must be in the tip set");

                // In a linear chain there should be exactly one tip
                prop_assert!(tips.len() == 1,
                    "Linear chain should have exactly 1 tip, found {}", tips.len());
                Ok(())
            })?;
        }

        /// Property: Blue set always contains the block itself.
        #[test]
        fn prop_blue_set_contains_self(n in 1..15usize, seed in 1..1000u64) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let (ghostdag, dag_store, hashes) = build_random_chain(n, seed).await;
                for hash in &hashes {
                    if let Ok(block) = dag_store.get_block(hash).await {
                        let blue_set = ghostdag.calculate_blue_set(&block).await.unwrap();
                        prop_assert!(blue_set.contains(hash),
                            "Block {:?} not in its own blue set", hash);
                    }
                }
                Ok(())
            })?;
        }

        /// Property: In a linear chain, each block's blue set is a superset of its parent's blue set.
        #[test]
        fn prop_blue_set_grows_along_chain(n in 2..15usize, seed in 1..1000u64) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let (ghostdag, dag_store, hashes) = build_random_chain(n, seed).await;
                let mut prev_score = 0u64;
                for hash in &hashes {
                    if let Ok(block) = dag_store.get_block(hash).await {
                        let blue_set = ghostdag.calculate_blue_set(&block).await.unwrap();
                        prop_assert!(blue_set.score >= prev_score,
                            "Blue set score must not decrease: {} -> {}", prev_score, blue_set.score);
                        prev_score = blue_set.score;
                    }
                }
                Ok(())
            })?;
        }
    }

    /// The activation height is a consensus constant: every node must use the
    /// same one or they disagree about validity. Pinned so a future edit is a
    /// deliberate act with a failing test attached, not a silent one-character
    /// change.
    #[test]
    fn mp_depth_activation_height_is_the_agreed_consensus_value() {
        assert_eq!(
            MERGE_DEPTH_ACTIVATION_HEIGHT, 0,
            "owner decision 2026-08-04. The re-roll wiped the ~78k blocks of \
             old-rule history that forced a future activation, so the fresh \
             chain enforces MP-DEPTH from genesis. Changing this changes which \
             blocks are valid — it requires a coordinated fleet upgrade AND a \
             re-roll, not an edit"
        );
        // A const block, so a violating edit fails to COMPILE rather than
        // failing a test somebody might not run. For a consensus constant that
        // is the right strength.
        //
        // The bound is no longer "comfortably ahead of the chain height" (that
        // guarded a deferred activation on a chain with history). The property
        // that matters now is pruning safety: enforcement must cover EVERY
        // height at which the pruner could already have dropped a citable
        // block. `node::dag_prune::MIN_RETAIN_BLOCKS` (1,000) is the smallest
        // retain window, and it lives in another crate, so the check here is
        // the stronger and simpler one — activation at genesis leaves no
        // unenforced prefix at all.
        const {
            assert!(
                MERGE_DEPTH_ACTIVATION_HEIGHT == 0,
                "MP-DEPTH must be enforced from genesis: any unenforced prefix \
                 is a window where a valid block can cite a parent the pruner \
                 may drop, and pruned/unpruned nodes then disagree about validity"
            )
        };
    }

    /// MP-DEPTH must not apply BELOW the activation height. Blocks already on
    /// the chain were produced under the old rule and must stay valid forever —
    /// re-judging history under a new rule forks just as surely as enforcing it
    /// early does.
    ///
    /// The SHIPPED activation is 0 since the 2026-08-04 re-roll, so on this
    /// chain there is no below-activation region at all. The gating mechanism
    /// still has to work for any FUTURE deferred activation, so this test now
    /// drives it explicitly with `with_merge_depth_activation_height` rather
    /// than leaning on the default. Deleting it would drop the only coverage of
    /// "do not re-judge history", which is the property that makes a staged
    /// rollout possible at all.
    #[tokio::test]
    async fn mp_depth_is_not_enforced_below_the_activation_height() {
        fn h(i: u64) -> [u8; 32] {
            let mut b = [0u8; 32];
            b[0..8].copy_from_slice(&i.to_le_bytes());
            b
        }
        const N: u64 = 300; // deeper than MERGE_PARENT_MAX_DEPTH

        // A hypothetical FUTURE deferred activation, well above the fixture.
        const DEFERRED_ACTIVATION: u64 = 100_000;

        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = GhostDag::new(GhostDagParams::default(), dag_store.clone())
            .with_merge_depth_activation_height(DEFERRED_ACTIVATION);
        assert!(
            !ghostdag.merge_depth_enforced_at(N + 1),
            "height {} is below the activation height {} — the rule must not apply",
            N + 1,
            DEFERRED_ACTIVATION
        );
        assert!(
            ghostdag.merge_depth_enforced_at(DEFERRED_ACTIVATION),
            "and it must apply from the activation height onward"
        );
        // The SHIPPED default leaves no unenforced prefix — that is the whole
        // point of activating at genesis, and it is what pruning depends on.
        let shipped = GhostDag::new(GhostDagParams::default(), dag_store.clone());
        assert!(
            shipped.merge_depth_enforced_at(0),
            "the shipped activation ({MERGE_DEPTH_ACTIVATION_HEIGHT}) must enforce \
             from genesis, or the pruner can drop a block a valid block may cite"
        );

        let genesis = create_test_block_with_parents(h(0), Hash::default(), vec![], 0);
        dag_store.store_block(genesis.clone()).await.expect("store");
        ghostdag
            .register_existing_block(&genesis)
            .await
            .expect("reg");
        let mut tip = genesis.hash();
        let mut deep = genesis.hash();
        for i in 1..=N {
            let b = create_test_block_with_parents(h(i), tip, vec![], i);
            dag_store.store_block(b.clone()).await.expect("store");
            ghostdag.register_existing_block(&b).await.expect("reg");
            if i == 10 {
                deep = b.hash(); // 290 below the merger — way over the bound
            }
            tip = b.hash();
        }

        let merger = create_test_block_with_parents(h(N + 1), tip, vec![deep], N + 1);
        dag_store.store_block(merger.clone()).await.expect("store");
        assert!(
            ghostdag.add_block(&merger).await.is_ok(),
            "with no activation height the old rule stands and this block is valid — \
             rejecting it on upgrade would fork against un-upgraded peers"
        );
    }

    /// Once activated, a merge parent deeper than the bound is invalid. This is
    /// what makes bounding the blue-set walk sound, and therefore what unblocks
    /// DAG pruning: no valid block can cite anything below the retained window.
    #[tokio::test]
    async fn mp_depth_rejects_a_too_deep_merge_parent_once_activated() {
        fn h(i: u64) -> [u8; 32] {
            let mut b = [0u8; 32];
            b[0..8].copy_from_slice(&i.to_le_bytes());
            b
        }
        const N: u64 = 300;

        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        // Activate from genesis so every block in the fixture is judged by it.
        let ghostdag = GhostDag::new(GhostDagParams::default(), dag_store.clone())
            .with_merge_depth_activation_height(0);

        let genesis = create_test_block_with_parents(h(0), Hash::default(), vec![], 0);
        dag_store.store_block(genesis.clone()).await.expect("store");
        ghostdag
            .register_existing_block(&genesis)
            .await
            .expect("reg");
        let mut tip = genesis.hash();
        let mut deep = genesis.hash();
        let mut shallow_parent = genesis.hash();
        for i in 1..=N {
            let b = create_test_block_with_parents(h(i), tip, vec![], i);
            dag_store.store_block(b.clone()).await.expect("store");
            ghostdag.register_existing_block(&b).await.expect("reg");
            if i == 10 {
                deep = b.hash();
            }
            if i == N - 1 {
                shallow_parent = b.hash();
            }
            tip = b.hash();
        }

        // Too deep: height N+1 merging height 10 is 291 below the bound of 100.
        let bad = create_test_block_with_parents(h(N + 1), tip, vec![deep], N + 1);
        dag_store.store_block(bad.clone()).await.expect("store");
        let err = ghostdag.add_block(&bad).await;
        assert!(
            err.is_err(),
            "a merge parent {} blocks deep must be rejected once MP-DEPTH is active",
            N + 1 - 10
        );

        // A sibling one height back is well inside the bound and stays valid —
        // the rule must not break ordinary DAG merging, which is the whole point
        // of multi-producer.
        let sibling = create_test_block_with_parents(h(N + 500), shallow_parent, vec![], N);
        dag_store.store_block(sibling.clone()).await.expect("store");
        ghostdag
            .register_existing_block(&sibling)
            .await
            .expect("reg");
        let good = create_test_block_with_parents(h(N + 2), tip, vec![sibling.hash()], N + 1);
        dag_store.store_block(good.clone()).await.expect("store");
        assert!(
            ghostdag.add_block(&good).await.is_ok(),
            "a merge parent inside the bound must still be accepted — MP-DEPTH \
             bounds how DEEP a merge reaches, it does not forbid merging"
        );
    }

    /// The bound must sit strictly below the pruner's retain floor, or the
    /// pruner can delete a block a valid block is still allowed to cite — which
    /// reintroduces exactly the fork this rule exists to prevent.
    #[test]
    fn mp_depth_bound_is_inside_the_prune_retain_floor() {
        const MIN_RETAIN_BLOCKS: u64 = 1_000; // node::dag_prune::MIN_RETAIN_BLOCKS
                                              // Const block for the same reason as the activation-height floor: this
                                              // invariant is not something to discover at test time.
                                              //
                                              // The message lost its `{MERGE_PARENT_MAX_DEPTH}` / `{MIN_RETAIN_BLOCKS}`
                                              // interpolation because a const context cannot format panic arguments.
                                              // Both are compile-time constants a reader can look up two lines away,
                                              // so naming the invariant precisely is worth more than echoing them.
        const {
            assert!(
                MERGE_PARENT_MAX_DEPTH < MIN_RETAIN_BLOCKS,
                "MERGE_PARENT_MAX_DEPTH must stay strictly under the pruner's \
                 retain floor (MIN_RETAIN_BLOCKS); otherwise pruning can remove a \
                 block that a valid block is still allowed to cite as a merge parent"
            )
        };
    }

    /// REGRESSION — the chain-40204 halt of 2026-07-29.
    ///
    /// PIL-13 fixed the eager-load path and SYNC-S1 D1 made the LINEAR receive
    /// path O(1); `materialised_blue_ancestry_entries` + the
    /// `producer_steady_state` test pin both. Neither covers a **merge block**.
    ///
    /// `derive_score_and_work` returns early only when `merge_parent_hashes` is
    /// empty; any block with merge parents falls through to `calculate_blue_set`,
    /// which calls `get_or_calculate_blue_set` on the selected parent. After a
    /// restart `blue_cache` is empty (that is exactly what `register_existing_block`
    /// is documented to leave behind), so phase 1 walks the selected-parent chain
    /// all the way to genesis and phase 2 then caches a FULL cumulative BlueSet
    /// for every block on the way back — Theta(N²) in chain length, materialised
    /// by a single `add_block`.
    ///
    /// That was harmless while the live chain was linear ("merge blocks are
    /// rare"). Multi-producer made merge blocks routine, and the producer then
    /// allocated ~30 GB in ~35 s at N=54,600 — OOM-killing the box and halting
    /// the chain. Followers were untouched because only the producer holds a
    /// GhostDag that admits new blocks.
    #[tokio::test]
    async fn merge_block_on_deep_chain_does_not_materialise_quadratic_ancestry() {
        // Deep enough that Theta(N²) is unmistakable against an O(N) bound,
        // small enough to stay a unit test.
        const N: u64 = 800;

        fn h(i: u64) -> [u8; 32] {
            let mut b = [0u8; 32];
            b[0..8].copy_from_slice(&i.to_le_bytes());
            b
        }

        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = GhostDag::new(GhostDagParams::default(), dag_store.clone());

        // Rehydrate a linear chain exactly as a restarting node does: every
        // block durable in the store, registered O(1), `blue_cache` left empty.
        let genesis = create_test_block_with_parents(h(0), Hash::default(), vec![], 0);
        dag_store
            .store_block(genesis.clone())
            .await
            .expect("store genesis");
        ghostdag
            .register_existing_block(&genesis)
            .await
            .expect("register genesis");

        let mut tip = genesis.hash();
        let mut parent_of_tip = genesis.hash();
        for i in 1..=N {
            let b = create_test_block_with_parents(h(i), tip, vec![], i);
            dag_store.store_block(b.clone()).await.expect("store block");
            ghostdag
                .register_existing_block(&b)
                .await
                .expect("register block");
            parent_of_tip = tip;
            tip = b.hash();
        }

        // A sibling of the tip, so the next block is a genuine merge block.
        // Its blue_score equals the selected parent's, satisfying the
        // "selected parent must be the heaviest parent" rule.
        let sibling = create_test_block_with_parents(h(N + 1_000), parent_of_tip, vec![], N);
        dag_store
            .store_block(sibling.clone())
            .await
            .expect("store sibling");
        ghostdag
            .register_existing_block(&sibling)
            .await
            .expect("register sibling");

        // Rehydration itself must materialise nothing — this is PIL-13's
        // guarantee and it still holds; the regression is what comes next.
        assert_eq!(
            ghostdag.materialised_blue_ancestry_entries().await,
            0,
            "rehydration must not materialise cumulative ancestry (PIL-13)"
        );

        let merge = create_test_block_with_parents(h(N + 2_000), tip, vec![sibling.hash()], N + 1);
        dag_store
            .store_block(merge.clone())
            .await
            .expect("store merge block");
        ghostdag
            .add_block(&merge)
            .await
            .expect("merge block must be admissible");

        let materialised = ghostdag.materialised_blue_ancestry_entries().await;
        // Admitting one block may legitimately touch a bounded window of
        // ancestry (k-cluster anticone counting). It must never scale with
        // chain length: Theta(N²) here is ~N²/2 = 320_000 entries at N=800.
        let bound = 4 * N as usize;
        assert!(
            materialised <= bound,
            "admitting ONE merge block onto a {N}-block chain materialised {materialised} \
             cumulative blue-ancestry entries (bound {bound}). This is the Theta(N²) \
             blow-up that OOM-killed the producer and halted chain 40204 at N=54,600."
        );
    }

    /// REGRESSION — the LIVE trigger of the chain-40204 halt.
    ///
    /// The companion merge-block test covers the path through
    /// `derive_score_and_work`'s fallback, but the live chain is **linear**
    /// (`mergeParentHashes: []` at every sampled height), so that is not the
    /// path production actually took.
    ///
    /// The real entry point is tip selection: `TipSelector::select_parents`
    /// and `select_highest_blue_score` call `calculate_blue_score` on each tip
    /// for EVERY block the producer builds, and that resolves through
    /// `get_or_calculate_blue_set`. After a restart `blue_cache` is empty, so
    /// the first such call walks the selected-parent chain to genesis and
    /// materialises cumulative ancestry for every block on the way back.
    ///
    /// This is producer-only — `TipSelector` is constructed in
    /// `node/src/producer.rs` — which is exactly why the three non-producing
    /// bootnodes sat at 2.0 GB while the producer took 30 GB in 35 s.
    #[tokio::test]
    async fn tip_selection_on_deep_linear_chain_does_not_materialise_quadratic_ancestry() {
        const N: u64 = 800;

        fn h(i: u64) -> [u8; 32] {
            let mut b = [0u8; 32];
            b[0..8].copy_from_slice(&i.to_le_bytes());
            b
        }

        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = GhostDag::new(GhostDagParams::default(), dag_store.clone());

        // A purely linear chain — no merge parents anywhere, matching the
        // live chain — rehydrated the way a restarting node does.
        let genesis = create_test_block_with_parents(h(0), Hash::default(), vec![], 0);
        dag_store
            .store_block(genesis.clone())
            .await
            .expect("store genesis");
        ghostdag
            .register_existing_block(&genesis)
            .await
            .expect("register genesis");

        let mut tip_block = genesis;
        for i in 1..=N {
            let b = create_test_block_with_parents(h(i), tip_block.hash(), vec![], i);
            dag_store.store_block(b.clone()).await.expect("store block");
            ghostdag
                .register_existing_block(&b)
                .await
                .expect("register block");
            tip_block = b;
        }

        assert_eq!(
            ghostdag.materialised_blue_ancestry_entries().await,
            0,
            "rehydration must not materialise cumulative ancestry (PIL-13)"
        );

        // Exactly what the producer does once per block, via TipSelector.
        ghostdag
            .calculate_blue_score(&tip_block)
            .await
            .expect("tip blue score");

        let materialised = ghostdag.materialised_blue_ancestry_entries().await;
        let bound = 4 * N as usize;
        assert!(
            materialised <= bound,
            "one tip-selection blue-score call on a {N}-block LINEAR chain materialised \
             {materialised} cumulative blue-ancestry entries (bound {bound}). This is the \
             live path that halted chain 40204."
        );
    }
}
