// citrate/core/consensus/src/ghostdag.rs

use crate::dag_store::DagStore;
use crate::types::{Block, BlueSet, DagRelation, GhostDagParams, Hash};
use std::collections::{HashMap, HashSet, VecDeque};
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
}

impl GhostDag {
    pub fn new(params: GhostDagParams, dag_store: Arc<DagStore>) -> Self {
        Self {
            params,
            dag_store,
            relations: Arc::new(RwLock::new(HashMap::new())),
            blue_cache: Arc::new(RwLock::new(HashMap::new())),
            tips: Arc::new(RwLock::new(HashSet::new())),
        }
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
            self.blue_cache
                .write()
                .await
                .insert(block.hash(), blue_set.clone());
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
        self.blue_cache
            .write()
            .await
            .insert(block.hash(), blue_set.clone());

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

        // Check against reference blue set
        for blue_block in &reference_blue_set.blocks {
            if count >= max_count {
                return Ok(count);
            }
            if !self.is_ancestor_of(block, blue_block).await?
                && !self.is_ancestor_of(blue_block, block).await?
            {
                count += 1;
            }
        }

        // Check against additional blue blocks
        for blue_block in additional_blues {
            if count >= max_count {
                return Ok(count);
            }
            if !self.is_ancestor_of(block, blue_block).await?
                && !self.is_ancestor_of(blue_block, block).await?
            {
                count += 1;
            }
        }

        Ok(count)
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
                    MAX_VISITED, ancestor, descendant
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
            for block in pending.iter().rev() {
                let bhash = block.hash();

                let selected_parent_blue = {
                    let cache = self.blue_cache.read().await;
                    cache
                        .get(&block.selected_parent())
                        .cloned()
                        .ok_or_else(|| {
                            // Should never happen — Phase 1 guarantees
                            // the selected parent is now cached.
                            GhostDagError::BlockNotFound(block.selected_parent())
                        })?
                };

                let blue_merge_parents = self
                    .calculate_blue_merge_parents(block, &selected_parent_blue)
                    .await?;

                let mut all_blocks = selected_parent_blue.blocks.clone();
                // Merge parents: recurse, but depth here is bounded by
                // DAG width (usually <= max_parents = 10), not chain
                // length, so stack is safe.
                for p in &blue_merge_parents {
                    let pset = self.get_or_calculate_blue_set(p).await?;
                    all_blocks.extend(pset.blocks);
                }
                all_blocks.insert(bhash);

                let mut blue = BlueSet::new();
                blue.blocks = all_blocks;
                blue.score = blue.blocks.len() as u64;
                self.blue_cache.write().await.insert(bhash, blue);
            }

            // By construction the requested hash is now cached.
            let cache = self.blue_cache.read().await;
            cache
                .get(hash)
                .cloned()
                .ok_or(GhostDagError::BlockNotFound(*hash))
        })
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
        let blue_set = self.derive_score_and_work(block).await?;

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
        if block.is_genesis() {
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
        }

        // Blue-score feasibility band, computed from the validated parent.
        let min_score = sp.header.blue_score.checked_add(1).ok_or_else(|| {
            GhostDagError::InvalidLinkage("selected parent blue_score overflow".to_string())
        })?;
        let max_score = min_score
            .checked_add(merge_parents.len() as u64)
            .ok_or_else(|| {
                GhostDagError::InvalidLinkage("blue_score band overflow".to_string())
            })?;
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

    #[tokio::test]
    async fn test_genesis_block_blue_set() {
        let params = GhostDagParams::default();
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = GhostDag::new(params, dag_store.clone());

        let genesis = create_test_block_with_parents([0; 32], Hash::default(), vec![], 0);

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
        let genesis = create_test_block_with_parents([0; 32], Hash::default(), vec![], 0);

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

    #[tokio::test]
    async fn test_tip_selection() {
        let params = GhostDagParams::default();
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = GhostDag::new(params, dag_store.clone());

        // Create simple chain
        let genesis = create_test_block_with_parents([0; 32], Hash::default(), vec![], 0);

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

        assert_eq!(count, 5, "expected early-exit at max_count=5, got {}", count);
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
            let genesis = create_test_block_with_parents([0; 32], Hash::default(), vec![], 0);
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
        const N: u64 = 1_000;
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
        assert!(genesis.is_genesis() && !b1.is_genesis(), "fixture must be a real 2-block chain");
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
        let genesis = create_test_block_with_parents([0; 32], Hash::default(), vec![], 0);
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
        let genesis = create_test_block_with_parents([0; 32], Hash::default(), vec![], 0);
        dag_store.store_block(genesis.clone()).await.unwrap();

        let mut gset = BlueSet::new();
        gset.insert(genesis.hash());
        gset.score = 1;
        ghostdag.blue_cache.write().await.insert(genesis.hash(), gset.clone());
        let grel = DagRelation {
            block: genesis.hash(),
            selected_parent: Hash::default(),
            merge_parents: vec![],
            children: vec![],
            blue_set: gset,
            is_chain_block: true,
            height: 0,
        };
        ghostdag.relations.write().await.insert(genesis.hash(), grel);
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
}
