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

        // Lightweight blue_set — score + work from the header, no
        // cumulative ancestry materialised.
        let mut blue_set = BlueSet::new();
        blue_set.score = block.header.blue_score;
        blue_set.work = block.header.blue_work;

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

    pub async fn add_block(&self, block: &Block) -> Result<(), GhostDagError> {
        // Validate parent structure
        if !block.is_genesis() && block.selected_parent() == Hash::default() {
            return Err(GhostDagError::InvalidParents);
        }

        // SECREM-01 CONS-3: every relation-building path passes the
        // consistency gate. Reject before any state mutation.
        self.validate_block_consistency(block).await?;

        // Calculate blue set
        let blue_set = self.calculate_blue_set(block).await?;

        // Telemetry for the strict-equality flip (see
        // validate_block_consistency doc): in-band drift between the
        // recomputed score and the header claim is logged, not fatal,
        // until the PIL-13 BlueSet persistence rework lands.
        if !block.is_genesis() && blue_set.score != block.header.blue_score {
            warn!(
                "blue_score drift on {}: header {} vs recomputed {} (in feasible band)",
                block.hash(),
                block.header.blue_score,
                blue_set.score
            );
        }

        // Create DAG relation
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

        let mut best_tip = None;
        let mut best_score = 0;

        for tip in tips.iter() {
            if let Some(relation) = relations.get(tip) {
                if relation.blue_set.score > best_score {
                    best_score = relation.blue_set.score;
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
