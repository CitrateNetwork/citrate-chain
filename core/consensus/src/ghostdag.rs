// citrate/core/consensus/src/ghostdag.rs
//
// GHOSTDAG for r1007 (ADR CV-3, planset 2026-11-03-r1007-v060
// `06_CONSENSUS_SPEC.md` §2). One blue score: the header commits the exact
// GHOSTDAG `blue_score` / `blue_work`, admission recomputes both from headers
// and rejects any mismatch, and fork choice reads the committed values.
//
// The coloring is rusty-kaspa's `GhostdagManager::ghostdag` /
// `check_blue_candidate` (kaspanet/rusty-kaspa af6ff23a,
// `consensus/src/processes/ghostdag/protocol.rs`), over the whole mergeset,
// with both k-cluster conditions. Every read is of headers and of the
// persisted per-block `GhostdagData` of blocks inside the GHOSTDAG window.

use crate::dag_store::DagStore;
use crate::types::{
    Block, BlockHeader, BlueSet, DagRelation, ForkChoiceKey, GhostDagParams, GhostdagData, Hash,
    WORK_UNIT,
};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

#[derive(Error, Debug)]
pub enum GhostDagError {
    #[error("Block not found: {0}")]
    BlockNotFound(Hash),

    /// The GHOSTDAG record of this block cannot be read or recomputed from
    /// the headers this node holds. Fail closed: never a value from another
    /// source.
    #[error("GHOSTDAG data unavailable for {0}")]
    ScoreUnavailable(Hash),

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

    /// G7: the header's blue_score is not the GHOSTDAG value.
    #[error("Header blue_score {claimed} != GHOSTDAG blue_score {expected}")]
    BlueScoreMismatch { claimed: u64, expected: u64 },

    /// G7: the header's blue_work is not the GHOSTDAG value.
    #[error("Header blue_work {claimed} != GHOSTDAG blue_work {expected}")]
    BlueWorkMismatch { claimed: u128, expected: u128 },

    /// G11: the header's pruning_point is not `chain_ancestor(B, pp_h(B))`.
    #[error(
        "Header pruning_point {claimed} != the chain block at pruning height {height} ({expected})"
    )]
    PruningPointMismatch {
        claimed: Hash,
        expected: Hash,
        height: u64,
    },

    /// G2: one parent is in the past of another.
    #[error("Parents are not an antichain: {ancestor} is in the past of {descendant}")]
    ParentsNotAntichain { ancestor: Hash, descendant: Hash },

    /// G3: the header names a selected parent that is not the heaviest parent.
    #[error("Selected parent {claimed} is not the heaviest parent {heaviest}")]
    SelectedParentNotHeaviest { claimed: Hash, heaviest: Hash },

    /// G4: |Mergeset(B)| > MERGESET_SIZE_LIMIT.
    #[error("Mergeset of {size} blocks exceeds the limit of {limit}")]
    MergesetTooLarge { size: usize, limit: usize },

    /// G5: a mergeset block does not have the merge-depth root in its past.
    #[error(
        "Mergeset block {block} is not in the future of the merge-depth root {merge_depth_root}"
    )]
    MergeDepthViolation { block: Hash, merge_depth_root: Hash },

    #[error("Invalid linkage: {0}")]
    InvalidLinkage(String),
}

/// §1.2 `K`. The r1007 value is conditional on S1 measuring the end-to-end
/// block delay (spec §1.3): it holds while 2·D·λ ≤ 10. This is the spec
/// default; `GhostDagParams::default().k` equals it.
pub const GHOSTDAG_K: u32 = 18;

/// §1.2 `MAX_PARENTS`: 1 selected + at most 9 merge parents.
pub const MAX_PARENTS: usize = 10;

/// §1.2 `MERGESET_SIZE_LIMIT` (G4): |Mergeset(B)|, selected parent included.
/// 10·K, rusty-kaspa's floor (`bps.rs`). Provisional on S1 M3.
pub const MERGESET_SIZE_LIMIT: usize = 180;

/// §1.2 `MERGE_DEPTH` (G5), in heights.
///
/// Reviewer question R3 is answered with the spec default: the STRICT rule.
/// Every block of `Mergeset*(B)` must have `MDR(B)` in its past, where
/// `MDR(B) = chain_ancestor(SP(B), max(0, height(B) - MERGE_DEPTH))`. Kaspa's
/// bounded merge depth with "kosherizing" blues is not implemented.
///
/// One consequence the spec does not spell out: a direct merge parent at
/// exactly `height(B) - MERGE_DEPTH` is rejected (it is not `MDR`, which is in
/// past(SP), so it cannot have `MDR` in its past), so the deepest admissible
/// merge parent sits `MERGE_DEPTH - 1` below the block. The pre-r1007 MP-DEPTH
/// rule admitted depth `MERGE_DEPTH`.
pub const MERGE_PARENT_MAX_DEPTH: u64 = 100;

/// Spec name for [`MERGE_PARENT_MAX_DEPTH`].
pub const MERGE_DEPTH: u64 = MERGE_PARENT_MAX_DEPTH;

/// §1.2 `GHOSTDAG_WINDOW` = 2·MERGE_DEPTH, in heights. Every read the
/// coloring of a block B makes lies in `[height(B) - GHOSTDAG_WINDOW,
/// height(B))`: G5 bounds the mergeset to the future of `MDR(B)`, and every
/// mergeset block's own parents to the future of its own merge-depth root.
/// A read that would go below it fails closed.
pub const MERGE_SCORE_WINDOW: u64 = 2 * MERGE_PARENT_MAX_DEPTH;

/// Spec name for [`MERGE_SCORE_WINDOW`].
pub const GHOSTDAG_WINDOW: u64 = MERGE_SCORE_WINDOW;

/// §1.2 `PRUNING_DEPTH` (G11), in chain blocks: a block's committed pruning
/// point sits at least this far below it. Today's `CITRATE_DAG_PRUNE_RETAIN`
/// default, promoted to a consensus constant (owner O7 open: 10,000).
pub const PRUNING_DEPTH: u64 = 10_000;

/// G11 `pp_h(B) = max(0, ⌊(height(B) − PRUNING_DEPTH) / CHECKPOINT_INTERVAL⌋ ·
/// CHECKPOINT_INTERVAL)`: always a checkpoint height, so a finalized
/// checkpoint there certifies the state a pruned node resumes from (spec §7).
pub fn pruning_point_height(height: u64) -> u64 {
    let interval = crate::checkpoint::CHECKPOINT_INTERVAL;
    height
        .saturating_sub(PRUNING_DEPTH)
        .checked_div(interval)
        .unwrap_or(0)
        .saturating_mul(interval)
}

/// Height from which merge-depth limits apply: 0, and fixed.
///
/// r1007 is a new genesis with every rule active from block 0 (ADR CV-2), so
/// G5 has no activation height. This constant is kept only because the
/// consensus manifest fingerprints it.
pub const MERGE_DEPTH_ACTIVATION_HEIGHT: u64 = 0;

/// Former devnet override for [`MERGE_DEPTH_ACTIVATION_HEIGHT`]. No longer
/// read: the r1007 rules have no environment override (spec §1.2).
pub const MERGE_DEPTH_ACTIVATION_ENV: &str = "CITRATE_MERGE_DEPTH_ACTIVATION_HEIGHT";

/// The merge-depth activation height: always [`MERGE_DEPTH_ACTIVATION_HEIGHT`].
pub fn merge_depth_activation_height() -> u64 {
    MERGE_DEPTH_ACTIVATION_HEIGHT
}

/// Bound on in-memory `GhostdagData` records when the DAG store is persistent
/// (the records are also on disk, so an evicted entry is re-read, never
/// recomputed from another source). An in-memory store keeps every record, as
/// it keeps every block.
const MAX_GHOSTDAG_CACHE_ENTRIES: usize = 65_536;

/// GhostDAG consensus engine
/// Where the G11 pruning-point walk reads a selected-chain header that the
/// DAG store no longer holds (spec 06 §2 G11, CV-7a).
///
/// At a boundary height `h` the expected pruning point is the chain ancestor at
/// `h - PRUNING_DEPTH`. For a block below the tip (a late block, or a side
/// branch forked inside the undo window, both of which a node must admit) that
/// ancestor lies below the DAG prune floor. The node's chain store keeps every
/// admitted header beyond that floor, so the walk reads it there. A header is
/// content-addressed by its hash, so its source cannot change the result: it
/// only decides whether the walk can finish. A header found nowhere still
/// fails closed (`MissingParent`).
pub trait AncestryHeaders: Send + Sync {
    /// The header of `hash`, if this source holds it.
    fn header(&self, hash: &Hash) -> Option<BlockHeader>;
}

pub struct GhostDag {
    /// Consensus parameters
    params: GhostDagParams,

    /// DAG storage
    dag_store: Arc<DagStore>,

    /// DAG relations cache. `blue_set.score` / `.work` are copies of the
    /// committed header values (G8); `blue_set.blocks` is always empty.
    relations: Arc<RwLock<HashMap<Hash, DagRelation>>>,

    /// GhostdagData records (G12). A cache over the persisted records.
    ghostdag_cache: Arc<RwLock<HashMap<Hash, Arc<GhostdagData>>>>,

    /// Records computed by the consistency gate for blocks not yet added,
    /// keyed by hash and the (selected parent, merge parents, height) they were
    /// computed from, so `add_block` right after the gate (the admission
    /// order) does not color the mergeset twice. A pure memo: an entry is used
    /// only for the same parents and height, and the record is a function of
    /// those and the immutable past.
    validated: Arc<std::sync::Mutex<VecDeque<ValidatedRecord>>>,

    /// Current tips of the DAG
    tips: Arc<RwLock<HashSet<Hash>>>,

    /// The ForkChoiceKey of every registered block, from its committed header
    /// (G8), so fork choice ranks a registered block without a store read.
    keys: Arc<RwLock<HashMap<Hash, ForkChoiceKey>>>,

    /// PBA-R2 block-validity hardening (PBA-L1b-003 timestamp bound). Captured
    /// from the process-wide activation height at construction; see
    /// `crate::hardening`.
    pba_hardening: crate::hardening::PbaHardening,

    /// "DAG hydration complete" flag (restart-liveness fix, 2026-08-11). False
    /// until [`Self::reconcile_tips_from_dag_store`] has made the in-memory tip set
    /// authoritative after a restart. The applicator's runtime deep-fork rebuild
    /// gates on this instead of a block-height heuristic. See `dag_hydrated_handle`.
    dag_hydrated: Arc<AtomicBool>,

    /// Fallback header source for the G11 pruning-point walk (see
    /// [`AncestryHeaders`]); `None` reads the DAG store only.
    ancestry: Option<Arc<dyn AncestryHeaders>>,
}

/// One entry of `GhostDag::validated`.
struct ValidatedRecord {
    hash: Hash,
    selected_parent: Hash,
    merges: Vec<Hash>,
    height: u64,
    data: GhostdagData,
}

/// How many gate results `validated` keeps (admission adds each block right
/// after gating it, so a handful suffices).
const MAX_VALIDATED_RECORDS: usize = 64;

/// One step of the coloring walk down the selected chain: the block being
/// colored itself (its partial record), or a chain block with its record.
enum ChainStep {
    New,
    Block(Hash, Arc<GhostdagData>),
}

/// `past(of) ∪ {of}` restricted to heights `>= floor`, with the floor lowered
/// on demand. Exact for every block at or above the current floor (see
/// `GhostDag::past_with_links`), so a query is answered from a walk that goes
/// only as deep as the deepest block asked about. Never below `window_floor`:
/// a query there fails closed (only an ancestry that breaks G5 reaches it).
struct LazyPast {
    of: Hash,
    window_floor: u64,
    floor: u64,
    set: Option<HashSet<Hash>>,
}

impl LazyPast {
    fn new(of: Hash, window_floor: u64, initial_floor: u64) -> Self {
        Self {
            of,
            window_floor,
            floor: initial_floor.max(window_floor),
            set: None,
        }
    }

    async fn contains(
        &mut self,
        gd: &GhostDag,
        hash: &Hash,
        height: u64,
    ) -> Result<bool, GhostDagError> {
        if height < self.window_floor {
            return Err(GhostDagError::MergeDepthViolation {
                block: *hash,
                merge_depth_root: self.of,
            });
        }
        if self.set.is_none() || height < self.floor {
            // Lower in steps, so a walk down the window is O(window) walks of
            // growing depth at worst, and one shallow walk in the common case.
            if height < self.floor {
                self.floor = height.saturating_sub(16).max(self.window_floor);
            }
            self.set = Some(gd.past_within(&self.of, self.floor).await?);
        }
        Ok(self.set.as_ref().is_some_and(|s| s.contains(hash)))
    }
}

impl GhostDag {
    pub fn new(params: GhostDagParams, dag_store: Arc<DagStore>) -> Self {
        Self {
            params,
            dag_store,
            pba_hardening: crate::hardening::PbaHardening::from_process(),
            relations: Arc::new(RwLock::new(HashMap::new())),
            ghostdag_cache: Arc::new(RwLock::new(HashMap::new())),
            validated: Arc::new(std::sync::Mutex::new(VecDeque::new())),
            tips: Arc::new(RwLock::new(HashSet::new())),
            keys: Arc::new(RwLock::new(HashMap::new())),
            dag_hydrated: Arc::new(AtomicBool::new(false)),
            ancestry: None,
        }
    }

    /// G11: read selected-chain headers the DAG store has pruned from
    /// `source` (the node's chain store) during the pruning-point walk.
    pub fn with_ancestry_headers(mut self, source: Arc<dyn AncestryHeaders>) -> Self {
        self.ancestry = Some(source);
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

    /// Get consensus parameters
    pub fn params(&self) -> &GhostDagParams {
        &self.params
    }

    // -----------------------------------------------------------------------
    // Header and record access
    // -----------------------------------------------------------------------

    /// The header of a block this node holds. A miss is `MissingParent`: the
    /// caller cannot judge without it (admission defers, never guesses).
    async fn header_of(&self, hash: &Hash) -> Result<BlockHeader, GhostDagError> {
        self.dag_store
            .get_header(hash)
            .await
            .map_err(|_| GhostDagError::MissingParent(*hash))
    }

    /// Selected parent, merge parents and height of a block this node holds,
    /// from `relations` or, after a restart, the DAG store.
    async fn links_of(&self, hash: &Hash) -> Result<(Hash, Vec<Hash>, u64), GhostDagError> {
        if let Some(r) = self.relations.read().await.get(hash) {
            return Ok((r.selected_parent, r.merge_parents.clone(), r.height));
        }
        // Header only: after a restart every stored block is a skeleton, and
        // `get_block` would reload and decode its whole body for three fields.
        let header = self
            .dag_store
            .get_header(hash)
            .await
            .map_err(|_| GhostDagError::MissingParent(*hash))?;
        Ok((
            header.selected_parent_hash,
            header.merge_parent_hashes,
            header.height,
        ))
    }

    async fn height_of(&self, hash: &Hash) -> Result<u64, GhostDagError> {
        Ok(self.links_of(hash).await?.2)
    }

    /// `of` and every block reachable from it by parent edges whose height is
    /// at least `floor`, each with its parents and height.
    ///
    /// Exact for that range, not an approximation: parent edges strictly
    /// decrease height, so every path from `of` to a block at height `>= floor`
    /// stays at or above `floor`, and cutting the walk below `floor` never hides
    /// one.
    async fn past_with_links(
        &self,
        of: &Hash,
        floor: u64,
    ) -> Result<HashMap<Hash, (Vec<Hash>, u64)>, GhostDagError> {
        // Generous: the window is GHOSTDAG_WINDOW heights times the DAG width.
        const MAX_VISITED: usize = 1_000_000;
        let mut visited: HashMap<Hash, (Vec<Hash>, u64)> = HashMap::new();
        let mut queue: VecDeque<Hash> = VecDeque::new();
        queue.push_back(*of);
        while let Some(current) = queue.pop_front() {
            if visited.contains_key(&current) {
                continue;
            }
            let (sp, merges, height) = self.links_of(&current).await?;
            if height < floor {
                continue;
            }
            let mut parents = Vec::with_capacity(merges.len().saturating_add(1));
            if sp != Hash::default() {
                parents.push(sp);
            }
            parents.extend(merges);
            // The selected parent sits exactly one height below; skip it
            // without a read once it is under the floor.
            for (i, p) in parents.iter().enumerate() {
                if i == 0 && height <= floor && sp != Hash::default() {
                    continue;
                }
                queue.push_back(*p);
            }
            visited.insert(current, (parents, height));
            if visited.len() >= MAX_VISITED {
                return Err(GhostDagError::CycleDetected);
            }
        }
        Ok(visited)
    }

    /// `of` and its past at heights `>= floor` (see [`Self::past_with_links`]).
    async fn past_within(&self, of: &Hash, floor: u64) -> Result<HashSet<Hash>, GhostDagError> {
        Ok(self.past_with_links(of, floor).await?.into_keys().collect())
    }

    /// The fork-choice key of a registered block, or of a block this node
    /// holds, from its committed header.
    pub async fn fork_choice_key(&self, hash: &Hash) -> Option<ForkChoiceKey> {
        if let Some(k) = self.keys.read().await.get(hash) {
            return Some(*k);
        }
        self.dag_store
            .get_header(hash)
            .await
            .ok()
            .map(|h| ForkChoiceKey::of_header(&h))
    }

    /// G3: the heaviest of `parents` by [`ForkChoiceKey`]. Every parent must be
    /// held (`MissingParent` otherwise).
    pub async fn heaviest_parent(&self, parents: &[Hash]) -> Result<Hash, GhostDagError> {
        let mut best: Option<ForkChoiceKey> = None;
        for p in parents {
            let key = ForkChoiceKey::of_header(&self.header_of(p).await?);
            if best.is_none_or(|b| key > b) {
                best = Some(key);
            }
        }
        best.map(|k| k.hash).ok_or(GhostDagError::InvalidParents)
    }

    /// The persisted or cached GhostdagData of a block this node holds, or,
    /// if neither has it, the record recomputed from headers (G12).
    ///
    /// Recomputation walks the selected chain down to the nearest block whose
    /// record is available (or genesis), then colors forward. If a header on
    /// that walk is missing (a pruned range) it fails closed with
    /// `MissingParent`; it never substitutes a value from anywhere else.
    pub fn ghostdag_data<'a>(
        &'a self,
        hash: &'a Hash,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Arc<GhostdagData>, GhostDagError>> + Send + 'a>,
    > {
        Box::pin(async move {
            if let Some(d) = self.cached_data(hash).await {
                return Ok(d);
            }
            // Walk down to the first block whose record is known.
            let mut pending: Vec<BlockHeader> = Vec::new();
            let mut cursor = *hash;
            loop {
                if self.cached_data(&cursor).await.is_some() {
                    break;
                }
                let header = self.header_of(&cursor).await?;
                if header.selected_parent_hash == Hash::default()
                    && header.merge_parent_hashes.is_empty()
                {
                    let g = Arc::new(genesis_data(&header));
                    self.cache_data(cursor, g.clone(), true).await;
                    break;
                }
                let next = header.selected_parent_hash;
                if let Some(prev) = pending.last() {
                    // Heights strictly fall along selected-parent edges.
                    if header.height >= prev.height {
                        return Err(GhostDagError::CycleDetected);
                    }
                }
                pending.push(header);
                cursor = next;
            }
            // Color forward, oldest first. Each step's chain reads hit records
            // computed on an earlier step (or already known).
            for header in pending.iter().rev() {
                let data = self
                    .compute_ghostdag(
                        header.selected_parent_hash,
                        &header.merge_parent_hashes,
                        header.height,
                    )
                    .await?;
                if data.blue_score != header.blue_score || data.blue_work != header.blue_work {
                    // A stored block was admitted with exactly these values, so
                    // a disagreement means the store does not hold what was
                    // admitted. Refuse rather than rank on either number.
                    warn!(
                        "GHOSTDAG record of stored block {} recomputes to score {} / work {}, \
                         but its header commits {} / {}: refusing",
                        header.block_hash,
                        data.blue_score,
                        data.blue_work,
                        header.blue_score,
                        header.blue_work
                    );
                    return Err(GhostDagError::ScoreUnavailable(header.block_hash));
                }
                self.cache_data(header.block_hash, Arc::new(data), true)
                    .await;
            }
            self.cached_data(hash)
                .await
                .ok_or(GhostDagError::ScoreUnavailable(*hash))
        })
    }

    /// Cache, then the persisted record. A persisted record counts only if it
    /// decodes, its tag binds this hash (see `DagStore::get_ghostdag_data`),
    /// and it agrees with the block's committed header.
    async fn cached_data(&self, hash: &Hash) -> Option<Arc<GhostdagData>> {
        if let Some(d) = self.ghostdag_cache.read().await.get(hash) {
            return Some(d.clone());
        }
        let stored = self.dag_store.get_ghostdag_data(hash)?;
        let header = self.dag_store.get_header(hash).await.ok()?;
        if stored.selected_parent != header.selected_parent_hash
            || stored.blue_score != header.blue_score
            || stored.blue_work != header.blue_work
        {
            debug!(
                "persisted GHOSTDAG record for {} disagrees with its header; ignored",
                hash
            );
            return None;
        }
        let d = Arc::new(stored);
        self.cache_data(*hash, d.clone(), false).await;
        Some(d)
    }

    async fn cache_data(&self, hash: Hash, data: Arc<GhostdagData>, persist: bool) {
        if persist {
            self.dag_store.put_ghostdag_data(&hash, &data);
        }
        let mut cache = self.ghostdag_cache.write().await;
        if self.dag_store.is_persistent()
            && cache.len() >= MAX_GHOSTDAG_CACHE_ENTRIES
            && !cache.contains_key(&hash)
        {
            if let Some(victim) = cache.keys().next().copied() {
                cache.remove(&victim);
            }
        }
        cache.insert(hash, data);
    }

    // -----------------------------------------------------------------------
    // GHOSTDAG (G2, G4, G5, G6, G7)
    // -----------------------------------------------------------------------

    /// `MDR(B)` for a block at `height` whose selected parent is `sp`: the
    /// chain ancestor of `sp` at `max(0, height - MERGE_DEPTH)`. Also returns
    /// SP's selected chain from `sp` down to MDR, both included.
    async fn merge_depth_root(
        &self,
        sp: Hash,
        height: u64,
    ) -> Result<(Hash, u64, HashSet<Hash>), GhostDagError> {
        let target = height.saturating_sub(MERGE_DEPTH);
        let mut chain = HashSet::new();
        let mut cursor = sp;
        loop {
            chain.insert(cursor);
            let (next, _, h) = self.links_of(&cursor).await?;
            if h <= target || next == Hash::default() {
                return Ok((cursor, h, chain));
            }
            cursor = next;
        }
    }

    /// `ghostdag(B)` for a block with selected parent `sp`, merge parents
    /// `merges` and height `height` (spec G6), with the mergeset rules it
    /// depends on: G2 (antichain), G4 (size), G5 (merge depth). Reads headers
    /// and the records of `sp`'s selected chain inside the window only.
    ///
    /// The caller checks G3 (`sp` is the heaviest parent) and G1.
    pub async fn compute_ghostdag(
        &self,
        sp: Hash,
        merges: &[Hash],
        height: u64,
    ) -> Result<GhostdagData, GhostDagError> {
        let k = self.params.k;
        let sp_header = self.header_of(&sp).await?;
        // A block with no merge parents has an empty Mergeset*: nothing to
        // color and no merge-depth rule to check, so MDR is not walked for it
        // (it is recorded as the zero hash; nothing reads it for such a block).
        // This keeps a linear block admissible on a node that retains less
        // than MERGE_DEPTH heights, as the pre-r1007 rules did.
        let mut data = GhostdagData::with_selected_parent(sp, Hash::default());

        if !merges.is_empty() {
            let (mdr, mdr_height, sp_chain) = self.merge_depth_root(sp, height).await?;
            data.merge_depth_root = mdr;
            let window_floor = height.saturating_sub(GHOSTDAG_WINDOW);
            let mut sp_past = LazyPast::new(sp, window_floor, height.saturating_sub(2));

            // G2 (part) and G5 for the direct merge parents. A merge parent at or
            // below MDR's height either is in past(SP) (G2) or cannot have MDR in
            // its past (G5): invalid either way, decided without a deeper read.
            let direct: HashSet<Hash> = merges.iter().copied().collect();
            for m in merges {
                let mh = self.height_of(m).await?;
                if mh <= mdr_height {
                    return Err(GhostDagError::MergeDepthViolation {
                        block: *m,
                        merge_depth_root: mdr,
                    });
                }
                if sp_past.contains(self, m, mh).await? {
                    return Err(GhostDagError::ParentsNotAntichain {
                        ancestor: *m,
                        descendant: sp,
                    });
                }
            }

            // G4: Mergeset*(B) by a BFS from the merge parents that stops at
            // past(SP) ∪ {SP} (Kaspa `unordered_mergeset_without_selected_parent`).
            let mut mergeset: HashMap<Hash, (Vec<Hash>, u64)> = HashMap::new();
            let mut queue: VecDeque<Hash> = merges.iter().copied().collect();
            for m in merges {
                mergeset.insert(*m, (Vec::new(), 0));
            }
            while let Some(cur) = queue.pop_front() {
                let (csp, cmerges, ch) = self.links_of(&cur).await?;
                let mut parents = Vec::with_capacity(cmerges.len().saturating_add(1));
                if csp != Hash::default() {
                    parents.push(csp);
                }
                parents.extend(cmerges);
                for p in &parents {
                    // G2: SP, or a direct merge parent, reached from a mergeset
                    // block is in the past of one of B's merge parents.
                    if *p == sp || direct.contains(p) {
                        return Err(GhostDagError::ParentsNotAntichain {
                            ancestor: *p,
                            descendant: cur,
                        });
                    }
                    if mergeset.contains_key(p) {
                        continue;
                    }
                    let ph = self.height_of(p).await?;
                    // Outside past(SP), at or below MDR's height: a mergeset
                    // block without MDR in its past (G5). Below the window the
                    // question cannot even be answered (only an invalid ancestry
                    // reaches there): invalid, and never read further.
                    if ph < window_floor {
                        return Err(GhostDagError::MergeDepthViolation {
                            block: *p,
                            merge_depth_root: mdr,
                        });
                    }
                    if sp_past.contains(self, p, ph).await? {
                        continue;
                    }
                    if ph <= mdr_height {
                        return Err(GhostDagError::MergeDepthViolation {
                            block: *p,
                            merge_depth_root: mdr,
                        });
                    }
                    mergeset.insert(*p, (Vec::new(), 0));
                    let size = mergeset.len().saturating_add(1);
                    if size > MERGESET_SIZE_LIMIT {
                        return Err(GhostDagError::MergesetTooLarge {
                            size,
                            limit: MERGESET_SIZE_LIMIT,
                        });
                    }
                    queue.push_back(*p);
                }
                mergeset.insert(cur, (parents, ch));
            }

            // G5: every mergeset block has MDR in its past. Fast path: a parent
            // on SP's selected chain at or above MDR, or a mergeset block already
            // shown to descend from MDR. Otherwise (a parent elsewhere in past(SP))
            // a bounded walk down to MDR's height decides.
            let mut by_height: Vec<(u64, Hash)> =
                mergeset.iter().map(|(h, (_, ht))| (*ht, *h)).collect();
            by_height.sort_unstable();
            let mut from_mdr: HashSet<Hash> = HashSet::new();
            for (_, x) in &by_height {
                let parents = mergeset.get(x).map(|(p, _)| p.as_slice()).unwrap_or(&[]);
                let fast = parents
                    .iter()
                    .any(|p| sp_chain.contains(p) || from_mdr.contains(p));
                if fast || self.past_within(x, mdr_height).await?.contains(&mdr) {
                    from_mdr.insert(*x);
                } else {
                    return Err(GhostDagError::MergeDepthViolation {
                        block: *x,
                        merge_depth_root: mdr,
                    });
                }
            }

            // G6: color Mergeset*(B) in ascending Key, which is topological
            // (Key strictly grows along every parent edge of admitted blocks).
            let mut candidates: Vec<(ForkChoiceKey, u64)> = Vec::with_capacity(mergeset.len());
            for (h, (_, ht)) in &mergeset {
                candidates.push((ForkChoiceKey::of_header(&self.header_of(h).await?), *ht));
            }
            candidates.sort_unstable();
            for (c, ch) in candidates {
                if self
                    .is_blue_candidate(&mut data, c.hash, ch, k, window_floor)
                    .await?
                {
                    continue;
                }
                data.mergeset_reds.push(c.hash);
            }
        }

        // G7: score and work from SP's committed values.
        let blues = data.mergeset_blues.len() as u64;
        data.blue_score = score_add(sp_header.blue_score, blues)?;
        data.blue_work = WORK_UNIT
            .checked_mul(u128::from(blues))
            .and_then(|w| sp_header.blue_work.checked_add(w))
            .ok_or_else(|| GhostDagError::InvalidLinkage("blue work overflow".to_string()))?;
        Ok(data)
    }

    /// Kaspa `check_blue_candidate`: color `candidate` blue (and update
    /// `data`) if both k-cluster conditions hold, else return false.
    ///
    /// 1. |anticone(candidate) ∩ blues| ≤ K;
    /// 2. no blue in anticone(candidate) already has K blues in its anticone.
    ///
    /// The walk visits B's partial record, then SP's record, SP(SP)'s, …, and
    /// stops at the first chain block in past(candidate): every blue older
    /// than it is in past(candidate) too. By G5 that happens at MDR(B) at the
    /// latest.
    async fn is_blue_candidate(
        &self,
        data: &mut GhostdagData,
        candidate: Hash,
        candidate_height: u64,
        k: u32,
        window_floor: u64,
    ) -> Result<bool, GhostDagError> {
        if data.mergeset_blues.len() as u64 == u64::from(k).saturating_add(1) {
            return Ok(false);
        }
        let mut past = LazyPast::new(candidate, window_floor, candidate_height.saturating_sub(2));

        let mut sizes: BTreeMap<Hash, u32> = BTreeMap::new();
        let mut anticone: u32 = 0;
        let mut step = ChainStep::New;
        loop {
            let blues: Vec<Hash> = match &step {
                ChainStep::New => data.mergeset_blues.clone(),
                ChainStep::Block(h, d) => {
                    if past.contains(self, h, self.height_of(h).await?).await? {
                        break;
                    }
                    d.mergeset_blues.clone()
                }
            };
            for b in &blues {
                if past.contains(self, b, self.height_of(b).await?).await? {
                    continue;
                }
                let s = self.blue_anticone_size(b, data).await?;
                sizes.insert(*b, s);
                anticone = anticone.saturating_add(1);
                if anticone > k || s == k {
                    return Ok(false);
                }
                if s > k {
                    return Err(GhostDagError::KClusterViolation);
                }
            }
            let next = match &step {
                ChainStep::New => data.selected_parent,
                ChainStep::Block(_, d) => d.selected_parent,
            };
            if next == Hash::default() {
                // Walked past genesis without meeting a block in past(c):
                // genesis is in the past of every block, so this cannot happen.
                return Err(GhostDagError::InvalidLinkage(format!(
                    "coloring walk for {candidate} left the selected chain"
                )));
            }
            let d = self.ghostdag_data(&next).await?;
            step = ChainStep::Block(next, d);
        }
        data.mergeset_blues.push(candidate);
        data.blues_anticone_sizes.insert(candidate, anticone);
        for (b, s) in sizes {
            data.blues_anticone_sizes.insert(b, s.saturating_add(1));
        }
        Ok(true)
    }

    /// Kaspa `blue_anticone_size`: the blue anticone size of `block` from the
    /// point of view of `context`, found in the first record on `context`'s
    /// selected chain that has it.
    async fn blue_anticone_size(
        &self,
        block: &Hash,
        context: &GhostdagData,
    ) -> Result<u32, GhostDagError> {
        if let Some(s) = context.blues_anticone_sizes.get(block) {
            return Ok(*s);
        }
        let mut cursor = context.selected_parent;
        loop {
            if cursor == Hash::default() {
                return Err(GhostDagError::InvalidLinkage(format!(
                    "{block} is not in the blue set of the context"
                )));
            }
            let d = self.ghostdag_data(&cursor).await?;
            if let Some(s) = d.blues_anticone_sizes.get(block) {
                return Ok(*s);
            }
            cursor = d.selected_parent;
        }
    }

    // -----------------------------------------------------------------------
    // Producer support
    // -----------------------------------------------------------------------

    /// The parents and GHOSTDAG record of a block this node is about to seal
    /// on `sp` (spec §9.3): `candidates` are offered as merge parents,
    /// heaviest first, and each is kept only while G2–G5 still hold and it is
    /// lighter than `sp` (G3). A candidate that would make the block invalid
    /// is dropped, never sealed.
    pub async fn parents_for_new_block(
        &self,
        sp: Hash,
        candidates: &[Hash],
    ) -> Result<(Vec<Hash>, GhostdagData), GhostDagError> {
        let max_merges = self.params.max_parents.saturating_sub(1);
        let sp_header = self.header_of(&sp).await?;
        let height = sp_header
            .height
            .checked_add(1)
            .ok_or_else(|| GhostDagError::InvalidLinkage("height overflow".to_string()))?;
        let sp_key = ForkChoiceKey::of_header(&sp_header);
        let mut offered: Vec<ForkChoiceKey> = Vec::new();
        for c in candidates {
            if *c == sp {
                continue;
            }
            if let Ok(h) = self.dag_store.get_header(c).await {
                let key = ForkChoiceKey::of_header(&h);
                if key < sp_key {
                    offered.push(key);
                }
            }
        }
        offered.sort_unstable_by(|a, b| b.cmp(a));
        offered.dedup();
        let mut merges: Vec<Hash> = Vec::new();
        let mut data = self.compute_ghostdag(sp, &merges, height).await?;
        for c in offered {
            if merges.len() >= max_merges {
                break;
            }
            let mut trial = merges.clone();
            trial.push(c.hash);
            match self.compute_ghostdag(sp, &trial, height).await {
                Ok(d) => {
                    merges = trial;
                    data = d;
                }
                Err(e) => debug!("producer: not merging {}: {}", c.hash, e),
            }
        }
        Ok((merges, data))
    }

    /// The header a block naming exactly `parents` must carry (G3, G7): its
    /// selected parent (the heaviest parent), its merge parents (the rest, in
    /// the given order), its height and its GHOSTDAG record. Fails if the
    /// parents are not held or would make the block invalid (G2, G4, G5).
    pub async fn ghostdag_for_parents(
        &self,
        parents: &[Hash],
    ) -> Result<(Hash, Vec<Hash>, u64, GhostdagData), GhostDagError> {
        let sp = self.heaviest_parent(parents).await?;
        let merges: Vec<Hash> = parents.iter().copied().filter(|p| *p != sp).collect();
        let height = self
            .height_of(&sp)
            .await?
            .checked_add(1)
            .ok_or_else(|| GhostDagError::InvalidLinkage("height overflow".to_string()))?;
        let data = self.compute_ghostdag(sp, &merges, height).await?;
        Ok((sp, merges, height, data))
    }

    // -----------------------------------------------------------------------
    // Admission
    // -----------------------------------------------------------------------

    /// SECREM-01 CONS-3 + r1007 G1–G7: validate the linkage and the GHOSTDAG
    /// values a header claims against what this node computes from the headers
    /// it holds. Read-only — safe to call before any persistence. `add_block`
    /// runs it unconditionally, so every ingest path passes this gate.
    ///
    /// - G1 structure: non-default selected parent, `1 + |merges| ≤
    ///   max_parents`, no duplicates, no self-reference, SP not repeated,
    ///   every parent admitted (`MissingParent` otherwise), `height =
    ///   height(SP) + 1`, timestamps (FWA-C1-03, PBA-L1b-003).
    /// - G3: the selected parent is the heaviest parent by [`ForkChoiceKey`].
    /// - G2, G4, G5, G6: see [`Self::compute_ghostdag`].
    /// - G7: `blue_score` and `blue_work` equal the GHOSTDAG values exactly.
    pub async fn validate_block_consistency(&self, block: &Block) -> Result<(), GhostDagError> {
        self.check_block(block).await.map(|_| ())
    }

    /// [`Self::validate_block_consistency`], returning the block's record.
    async fn check_block(&self, block: &Block) -> Result<GhostdagData, GhostDagError> {
        // SECREM-A001: exempt genesis by IDENTITY, not by shape. A block
        // merely shaped like genesis (parentless, arbitrary height) must
        // fall through to the missing-parent check below, not short-circuit.
        if block.is_configured_genesis(self.dag_store.configured_genesis()) {
            return Ok(genesis_data(&block.header));
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
                merge_parents.len().saturating_add(1),
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

        // Parents must already be admitted locally (headers only).
        let sp = self.header_of(&sp_hash).await?;
        let mut parent_keys = vec![ForkChoiceKey::of_header(&sp)];
        for mp in merge_parents {
            parent_keys.push(ForkChoiceKey::of_header(&self.header_of(mp).await?));
        }

        // Height linkage is exact and inductive from genesis.
        let expected_height = sp.height.checked_add(1).ok_or_else(|| {
            GhostDagError::InvalidLinkage("selected parent height overflow".to_string())
        })?;
        if header.height != expected_height {
            return Err(GhostDagError::HeightMismatch {
                claimed: header.height,
                expected: expected_height,
            });
        }

        // FWA-C1-03: timestamp must be monotonic vs the selected parent.
        if header.timestamp < sp.timestamp {
            return Err(GhostDagError::InvalidLinkage(format!(
                "timestamp {} precedes selected parent's {} — must be parent-monotonic",
                header.timestamp, sp.timestamp
            )));
        }

        // PBA-L1b-003: and it may not run more than
        // MAX_BLOCK_TIMESTAMP_ADVANCE_SECS ahead of it.
        if self.pba_hardening.active_at(header.height) {
            let max_ts = sp
                .timestamp
                .saturating_add(crate::hardening::MAX_BLOCK_TIMESTAMP_ADVANCE_SECS);
            if header.timestamp > max_ts {
                return Err(GhostDagError::InvalidLinkage(format!(
                    "timestamp {} is more than {}s past selected parent's {} (PBA-L1b-003)",
                    header.timestamp,
                    crate::hardening::MAX_BLOCK_TIMESTAMP_ADVANCE_SECS,
                    sp.timestamp
                )));
            }
        }

        // G3: the selected parent is derived, not chosen.
        let heaviest = parent_keys
            .iter()
            .max()
            .map(|k| k.hash)
            .ok_or(GhostDagError::InvalidParents)?;
        if heaviest != sp_hash {
            return Err(GhostDagError::SelectedParentNotHeaviest {
                claimed: sp_hash,
                heaviest,
            });
        }

        // G2, G4, G5, G6.
        let memo = {
            let v = match self.validated.lock() {
                Ok(v) => v,
                Err(p) => p.into_inner(),
            };
            v.iter()
                .find(|r| {
                    r.hash == block.hash()
                        && r.selected_parent == sp_hash
                        && r.merges == *merge_parents
                        && r.height == header.height
                })
                .map(|r| r.data.clone())
        };
        let data = match memo {
            Some(d) => d,
            None => {
                let d = self
                    .compute_ghostdag(sp_hash, merge_parents, header.height)
                    .await?;
                let mut v = match self.validated.lock() {
                    Ok(v) => v,
                    Err(p) => p.into_inner(),
                };
                if v.len() >= MAX_VALIDATED_RECORDS {
                    v.pop_front();
                }
                v.push_back(ValidatedRecord {
                    hash: block.hash(),
                    selected_parent: sp_hash,
                    merges: merge_parents.clone(),
                    height: header.height,
                    data: d.clone(),
                });
                d
            }
        };

        // G7: the committed values are exactly the GHOSTDAG values.
        if header.blue_score != data.blue_score {
            return Err(GhostDagError::BlueScoreMismatch {
                claimed: header.blue_score,
                expected: data.blue_score,
            });
        }
        if header.blue_work != data.blue_work {
            return Err(GhostDagError::BlueWorkMismatch {
                claimed: header.blue_work,
                expected: data.blue_work,
            });
        }

        // G11: the committed pruning point is the chain ancestor at pp_h(B).
        let expected_pp = self.expected_pruning_point(&sp_hash, header.height).await?;
        if header.pruning_point != expected_pp {
            return Err(GhostDagError::PruningPointMismatch {
                claimed: header.pruning_point,
                expected: expected_pp,
                height: pruning_point_height(header.height),
            });
        }
        Ok(data)
    }

    /// G11: the pruning point a block at `height` whose selected parent is
    /// `selected_parent` must commit: `chain_ancestor(B, pp_h(B))`, encoded as
    /// the zero hash while `pp_h(B) = 0` (no pruning point yet; the genesis
    /// block is implied, and genesis hashes are per network).
    ///
    /// O(1) between boundaries: SP's committed value (validated when SP was
    /// admitted) is B's whenever `pp_h(SP) = pp_h(B)`. When the boundary moves
    /// (`(height − PRUNING_DEPTH)` a multiple of the interval), it walks SP's
    /// selected chain down to `pp_h(B)`, `PRUNING_DEPTH − 1` header reads. For a
    /// block at or above the tip those headers are at or above the tip's
    /// pruning point, which the node never prunes (G11 floor). For a block
    /// below the tip (late, or on a branch inside the undo window) they reach
    /// below the DAG prune floor and come from the [`AncestryHeaders`] source.
    /// A header the walk needs and finds nowhere fails closed
    /// (`MissingParent`). The producer seals with the same function.
    pub async fn expected_pruning_point(
        &self,
        selected_parent: &Hash,
        height: u64,
    ) -> Result<Hash, GhostDagError> {
        let target = pruning_point_height(height);
        if target == 0 {
            return Ok(Hash::default());
        }
        let sp = self.header_of(selected_parent).await?;
        if pruning_point_height(sp.height) == target {
            return Ok(sp.pruning_point);
        }
        let mut cur = sp;
        loop {
            if cur.height == target {
                return Ok(cur.block_hash);
            }
            if cur.height < target || cur.selected_parent_hash == Hash::default() {
                return Err(GhostDagError::InvalidLinkage(format!(
                    "selected chain of {selected_parent} does not reach pruning height {target}"
                )));
            }
            cur = self.chain_header_of(&cur.selected_parent_hash).await?;
        }
    }

    /// A selected-chain header for the G11 walk: the DAG store, else the
    /// [`AncestryHeaders`] source, else `MissingParent` (fail closed).
    async fn chain_header_of(&self, hash: &Hash) -> Result<BlockHeader, GhostDagError> {
        match self.header_of(hash).await {
            Ok(h) => Ok(h),
            Err(e) => match self.ancestry.as_ref().and_then(|a| a.header(hash)) {
                Some(h) if h.block_hash == *hash => Ok(h),
                _ => Err(e),
            },
        }
    }

    pub async fn add_block(&self, block: &Block) -> Result<(), GhostDagError> {
        // Validate parent structure
        if !block.is_genesis() && block.selected_parent() == Hash::default() {
            return Err(GhostDagError::InvalidParents);
        }

        // SECREM-01 CONS-3: every relation-building path passes the
        // consistency gate. Reject before any state mutation.
        let data = self.check_block(block).await?;

        // G12: the record is persisted with the block's admission and read,
        // never re-derived from another source, on restart.
        self.cache_data(block.hash(), Arc::new(data), true).await;

        self.insert_relation(block).await;
        info!(
            "Added block {} to DAG with blue score {}",
            block.hash(),
            block.header.blue_score
        );
        Ok(())
    }

    /// Record `block` in `relations` and the tip set. Fork choice ranks it on
    /// its committed header values (G8).
    async fn insert_relation(&self, block: &Block) {
        let relation = DagRelation {
            block: block.hash(),
            selected_parent: block.selected_parent(),
            merge_parents: block.header.merge_parent_hashes.clone(),
            children: Vec::new(),
            blue_set: BlueSet {
                blocks: HashSet::new(),
                score: block.header.blue_score,
                work: block.header.blue_work,
            },
            is_chain_block: true,
            height: block.header.height,
        };

        self.keys
            .write()
            .await
            .insert(block.hash(), ForkChoiceKey::of_header(&block.header));
        let mut relations = self.relations.write().await;
        relations.insert(block.hash(), relation);
        if let Some(parent_relation) = relations.get_mut(&block.selected_parent()) {
            parent_relation.children.push(block.hash());
        }
        for merge_parent in &block.header.merge_parent_hashes {
            if let Some(parent_relation) = relations.get_mut(merge_parent) {
                parent_relation.children.push(block.hash());
            }
        }
        drop(relations);

        let mut tips = self.tips.write().await;
        tips.remove(&block.selected_parent());
        for merge_parent in &block.header.merge_parent_hashes {
            tips.remove(merge_parent);
        }
        tips.insert(block.hash());
    }

    /// Register an EXISTING block (one this node admitted before, read back
    /// from its DAG store on restart).
    ///
    /// CV-3: its `blue_score` / `blue_work` are the committed header values,
    /// which admission validated exactly (G7), so fork choice ranks it on them
    /// directly. Nothing is derived, so nothing can fall back to another unit,
    /// and a block whose ancestry was pruned registers like any other (G12).
    /// O(1) per block. Its GhostdagData stays on disk until a coloring walk
    /// reads it.
    pub async fn register_existing_block(&self, block: &Block) -> Result<(), GhostDagError> {
        if !block.is_genesis() && block.selected_parent() == Hash::default() {
            return Err(GhostDagError::InvalidParents);
        }
        if block.header.blue_work != crate::types::blue_work_for_score(block.header.blue_score) {
            // Not a header admission could have accepted (G7 unit work).
            return Err(GhostDagError::BlueWorkMismatch {
                claimed: block.header.blue_work,
                expected: crate::types::blue_work_for_score(block.header.blue_score),
            });
        }
        self.insert_relation(block).await;
        Ok(())
    }

    /// AUTHORITATIVE TIP REHYDRATION (restart-liveness fix, 2026-08-11). Align this
    /// GhostDag's in-memory `tips` with the DAG store's AUTHORITATIVE tip set.
    ///
    /// After a restart the eager-load loops (`producer.rs`) register only the
    /// CANONICAL single-block-per-height chain via [`Self::register_existing_block`],
    /// so `GhostDag.tips` can diverge from the true DAG tips. `DagStore` already
    /// reconstructs its tip set authoritatively from block-header parentage on load
    /// (PIL-42). This copies that authoritative set in, first registering any tip
    /// missing from `relations` so `select_tip` can rank it.
    ///
    /// O(number of tips), NOT O(chain length). Returns the number of
    /// authoritative tips after reconciliation.
    pub async fn reconcile_tips_from_dag_store(&self) -> usize {
        let authoritative: Vec<Hash> = self
            .dag_store
            .get_tips()
            .await
            .into_iter()
            .map(|t| t.hash)
            .collect();

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

        let mut tips = self.tips.write().await;
        *tips = authoritative.iter().copied().collect();
        let n = tips.len();
        drop(tips);

        self.dag_hydrated.store(true, Ordering::SeqCst);
        info!(
            "reconcile_tips_from_dag_store: GhostDag tips reconciled to {} authoritative tip(s); DAG hydration complete",
            n
        );
        n
    }

    /// Shared handle to the "DAG hydration complete" flag — set true by
    /// [`Self::reconcile_tips_from_dag_store`] once the in-memory tip set is
    /// authoritative. Defaults false until reconciliation runs.
    pub fn dag_hydrated_handle(&self) -> Arc<AtomicBool> {
        self.dag_hydrated.clone()
    }

    // -----------------------------------------------------------------------
    // Fork choice (G8)
    // -----------------------------------------------------------------------

    /// The selected tip: the registered tip with the largest
    /// [`ForkChoiceKey`] `(blue_work, vrf_output, hash)`, read from committed
    /// headers only (G8). The same order G3 uses for the selected parent, so
    /// a producer that seals on `select_tip` always names a valid SP.
    pub async fn select_tip(&self) -> Result<Hash, GhostDagError> {
        let tips: Vec<Hash> = {
            let tips = self.tips.read().await;
            let relations = self.relations.read().await;
            tips.iter()
                .filter(|t| relations.contains_key(*t))
                .copied()
                .collect()
        };
        let mut best: Option<ForkChoiceKey> = None;
        for tip in tips {
            if let Some(key) = self.fork_choice_key(&tip).await {
                if best.is_none_or(|b| key > b) {
                    best = Some(key);
                }
            }
        }
        best.map(|k| k.hash)
            .ok_or(GhostDagError::BlockNotFound(Hash::default()))
    }

    /// Get current tips
    pub async fn get_tips(&self) -> Vec<Hash> {
        self.tips.read().await.iter().copied().collect()
    }

    /// The fork-choice score of a block this node holds: its committed
    /// header `blue_score` (G8). `None` when the block is not held.
    pub async fn fork_choice_score(&self, hash: &Hash) -> Option<u64> {
        if let Some(score) = self
            .relations
            .read()
            .await
            .get(hash)
            .map(|r| r.blue_set.score)
        {
            return Some(score);
        }
        self.dag_store
            .get_header(hash)
            .await
            .ok()
            .map(|h| h.blue_score)
    }

    /// Blue score of a registered block (its committed header value).
    pub async fn get_blue_score(&self, hash: &Hash) -> Result<u64, GhostDagError> {
        self.relations
            .read()
            .await
            .get(hash)
            .map(|r| r.blue_set.score)
            .ok_or(GhostDagError::BlockNotFound(*hash))
    }

    /// Height of a known block, or `None` if we do not hold it.
    pub async fn get_block_height(&self, hash: &Hash) -> Option<u64> {
        if let Some(h) = self.relations.read().await.get(hash).map(|r| r.height) {
            return Some(h);
        }
        self.dag_store.get_header(hash).await.ok().map(|h| h.height)
    }

    // -----------------------------------------------------------------------
    // Diagnostics (not consensus)
    // -----------------------------------------------------------------------

    /// GHOSTDAG blue score of `block` (stored or not; its parents must be
    /// held), computed from headers. For an admitted block it equals the
    /// committed `header.blue_score`.
    pub async fn calculate_blue_score(&self, block: &Block) -> Result<u64, GhostDagError> {
        Ok(self.data_for_block(block).await?.blue_score)
    }

    /// The blue set of `block`: every blue block in past(block), with
    /// `score = |blocks| = blue_score(block)` (G7; the block itself is not in
    /// its own blue set, and genesis has an empty one).
    ///
    /// DIAGNOSTIC ONLY. It walks the selected chain to genesis (Θ(chain)), so
    /// no consensus path calls it: admission and fork choice use the
    /// window-bounded [`Self::compute_ghostdag`] and committed header values.
    pub async fn calculate_blue_set(&self, block: &Block) -> Result<BlueSet, GhostDagError> {
        let data = self.data_for_block(block).await?;
        let mut set = BlueSet::new();
        set.blocks.extend(data.mergeset_blues.iter().copied());
        let mut cursor = data.selected_parent;
        while cursor != Hash::default() {
            let d = self.ghostdag_data(&cursor).await?;
            set.blocks.extend(d.mergeset_blues.iter().copied());
            cursor = d.selected_parent;
        }
        set.score = data.blue_score;
        set.work = data.blue_work;
        Ok(set)
    }

    async fn data_for_block(&self, block: &Block) -> Result<Arc<GhostdagData>, GhostDagError> {
        if block.is_genesis() {
            return Ok(Arc::new(genesis_data(&block.header)));
        }
        if let Some(d) = self.cached_data(&block.hash()).await {
            return Ok(d);
        }
        let sp = self.heaviest_parent(&block.parents()).await?;
        let merges: Vec<Hash> = block.parents().into_iter().filter(|p| *p != sp).collect();
        let height = self
            .height_of(&sp)
            .await?
            .checked_add(1)
            .ok_or_else(|| GhostDagError::InvalidLinkage("height overflow".to_string()))?;
        Ok(Arc::new(self.compute_ghostdag(sp, &merges, height).await?))
    }

    /// PIL-13 tripwire metric: the number of cumulative blue-ancestry entries
    /// materialised in memory across `relations`. CV-3 keeps none (fork
    /// choice reads committed header values), so this is always 0; the
    /// `producer_steady_state` test asserts it.
    pub async fn materialised_blue_ancestry_entries(&self) -> usize {
        let relations = self.relations.read().await;
        relations.values().map(|r| r.blue_set.blocks.len()).sum()
    }
}

/// The GHOSTDAG record of a genesis block: an empty mergeset, with the
/// score and work its header commits (0 and 0 for every network genesis,
/// `citrate_economics::genesis`, as G7 requires). Genesis is admitted by
/// identity, so its header values are part of the configured genesis, and
/// every child scores from them.
fn genesis_data(header: &BlockHeader) -> GhostdagData {
    GhostdagData {
        blue_score: header.blue_score,
        blue_work: header.blue_work,
        ..GhostdagData::genesis()
    }
}

/// PANIC-S1: a blue score is bounded by chain height, so these sums cannot
/// overflow on an honest chain. If one ever did, reject (Err), never saturate:
/// a wrong score is a consensus fork, a rejected block is not.
fn score_add(a: u64, b: u64) -> Result<u64, GhostDagError> {
    a.checked_add(b)
        .ok_or_else(|| GhostDagError::InvalidLinkage("blue score overflow".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panic_s1_score_add_rejects_overflow_instead_of_panicking() {
        assert_eq!(score_add(1, 2).ok(), Some(3));
        assert_eq!(score_add(u64::MAX - 1, 1).ok(), Some(u64::MAX));
        assert!(matches!(
            score_add(u64::MAX, 1),
            Err(GhostDagError::InvalidLinkage(_))
        ));
        assert!(matches!(
            score_add(1, u64::MAX),
            Err(GhostDagError::InvalidLinkage(_))
        ));
    }
    use crate::types::*;

    /// Minimal in-memory KvStore, so a DAG store is genuinely "persistent"
    /// across a simulated restart (a fresh GhostDag over the same store).
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

    /// The producer's header construction (spec §9.3), for fixtures that
    /// merge: the selected parent is the heaviest of `parents` (G3), the rest
    /// are merge parents, and blue_score / blue_work are the GHOSTDAG values.
    async fn sealed(gd: &GhostDag, hash: [u8; 32], parents: Vec<Hash>) -> Block {
        let sp = gd.heaviest_parent(&parents).await.expect("parents held");
        let merges: Vec<Hash> = parents.into_iter().filter(|p| *p != sp).collect();
        let height = gd.height_of(&sp).await.expect("sp height") + 1;
        let data = gd
            .compute_ghostdag(sp, &merges, height)
            .await
            .expect("valid parents");
        BlockBuilder::new()
            .hash(Hash::new(hash))
            .parent(sp)
            .merge_parents(merges)
            .height(height)
            .blue_score(data.blue_score)
            .blue_work(data.blue_work)
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
        assert!(gd
            .validate_block_consistency(&with_score(1, 0x22))
            .await
            .is_ok());
        assert!(
            gd.validate_block_consistency(&with_score(0, 0x23))
                .await
                .is_err(),
            "below the band"
        );
        assert!(
            gd.validate_block_consistency(&with_score(2, 0x24))
                .await
                .is_err(),
            "above the band (no merge parents)"
        );
    }

    /// Mutation-survivor kill for the merge-depth boundary, under r1007 G5
    /// (which replaces MP-DEPTH): a mergeset block must have MDR(B) in its
    /// past, MDR(B) being the chain block MERGE_DEPTH below B. A merge parent
    /// at depth MERGE_DEPTH - 1 is admitted; at depth MERGE_DEPTH it is not
    /// (it sits at MDR's height without being MDR), nor deeper.
    #[tokio::test]
    async fn pba_r2_mp_depth_boundary_is_exact() {
        fn h(i: u64) -> [u8; 32] {
            let mut b = [0u8; 32];
            b[0..8].copy_from_slice(&i.to_le_bytes());
            b[31] = 0x77;
            b
        }
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let gd = GhostDag::new(GhostDagParams::default(), dag_store.clone());
        let mut chain = vec![create_test_block_with_parents(
            h(0),
            Hash::default(),
            vec![],
            0,
        )];
        dag_store.store_block(chain[0].clone()).await.unwrap();
        let top = MERGE_PARENT_MAX_DEPTH + 1;
        for i in 1..top {
            let b = create_test_block_with_parents(h(i), chain[(i - 1) as usize].hash(), vec![], i);
            dag_store.store_block(b.clone()).await.unwrap();
            chain.push(b);
        }
        // Side blocks at heights 1 and 2 (siblings of chain[1], chain[2]).
        let side1 = create_test_block_with_parents([0xA1; 32], chain[0].hash(), vec![], 1);
        let side2 = create_test_block_with_parents([0xA2; 32], chain[1].hash(), vec![], 2);
        dag_store.store_block(side1.clone()).await.unwrap();
        dag_store.store_block(side2.clone()).await.unwrap();
        let sp = chain[(top - 1) as usize].hash();
        // The side block's anticone holds the 99 chain blocks above it, far
        // over K, so it is red and the score is SP's + 1 = top.
        let merging =
            |mp: Hash, tag: u8| create_test_block_with_parents([tag; 32], sp, vec![mp], top);
        // depth = top - 2 = MERGE_DEPTH - 1: allowed.
        assert!(gd
            .validate_block_consistency(&merging(side2.hash(), 0xB0))
            .await
            .is_ok());
        // depth = top - 1 = MERGE_DEPTH: rejected (G5).
        assert!(matches!(
            gd.validate_block_consistency(&merging(side1.hash(), 0xB1))
                .await,
            Err(GhostDagError::MergeDepthViolation { .. })
        ));
        // depth = top = MERGE_DEPTH + 1, and in past(SP): rejected.
        let side0 = chain[0].hash();
        assert!(gd
            .validate_block_consistency(&merging(side0, 0xB2))
            .await
            .is_err());
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
            let mut b = create_test_block_with_parents([h; 32], genesis.hash(), vec![], 1);
            b.header.timestamp = ts;
            b
        };
        let on = GhostDag::new(GhostDagParams::default(), dag_store.clone())
            .with_pba_hardening(PbaHardening::at(1));
        assert!(on
            .validate_block_consistency(&child(1_000 + MAX, 2))
            .await
            .is_ok());
        assert!(on
            .validate_block_consistency(&child(1_000 + MAX + 1, 3))
            .await
            .is_err());
        assert!(on
            .validate_block_consistency(&child(u64::MAX, 4))
            .await
            .is_err());
        assert!(
            on.validate_block_consistency(&child(999, 5)).await.is_err(),
            "monotonic"
        );
        // Activation above this height: legacy rule (no upper bound).
        let later = GhostDag::new(GhostDagParams::default(), dag_store.clone())
            .with_pba_hardening(PbaHardening::at(2));
        assert!(later
            .validate_block_consistency(&child(u64::MAX, 6))
            .await
            .is_ok());
        let off = GhostDag::new(GhostDagParams::default(), dag_store.clone())
            .with_pba_hardening(PbaHardening::off());
        assert!(off
            .validate_block_consistency(&child(u64::MAX, 7))
            .await
            .is_ok());
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

        // r1007 G7: blue_score(B) counts the blue blocks in past(B), so genesis
        // has score 0 and an empty blue set (it is not in its own).
        let blue_set = ghostdag.calculate_blue_set(&genesis).await.unwrap();
        assert_eq!(blue_set.score, 0);
        assert!(!blue_set.contains(&genesis.hash()));
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
        let g_blue = BlueSet::new();
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

        // Two equal-blue_score siblings at height 2. `winner` has the LARGER hash,
        // so the shared tie-break (r1007 G8: the larger ForkChoiceKey, VRF outputs
        // equal here) makes it the canonical head.
        let winner = create_test_block_with_parents([9; 32], a1.hash(), vec![], 2);
        let loser = create_test_block_with_parents([2; 32], a1.hash(), vec![], 2);
        assert!(
            winner.hash() > loser.hash(),
            "winner must be the larger hash"
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
            "producer (TipSelector over DAG-store tips) targets the larger-key winner"
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
    /// canonical (larger-key, r1007 G8) winner.
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

        // Two equal-score siblings; winner has the larger hash (G8 Key).
        let winner = create_test_block_with_parents([9; 32], a1.hash(), vec![], 2);
        let loser = create_test_block_with_parents([2; 32], a1.hash(), vec![], 2);
        assert!(winner.hash() > loser.hash());

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
            "after reconcile, select_tip returns the true canonical (larger-key) winner"
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
        // r1007 G8: fork choice reads the committed header, so the block is held.
        dag_store.store_block(genesis.clone()).await.unwrap();
        drop(genesis_blue);
        ghostdag.tips.write().await.insert(genesis.hash());

        let best_tip = ghostdag.select_tip().await.unwrap();
        assert_eq!(best_tip, genesis.hash());
    }

    #[tokio::test]
    async fn test_select_tip_deterministic_tie_break_by_hash() {
        // Receive-side analogue of audit finding H-08: equal-`blue_score` sibling
        // tips (what two concurrent producers create at the same height) MUST
        // resolve to the same tip on every node regardless of `HashSet`
        // iteration order, or the fleet forks permanently. r1007 G8: the tip
        // with the largest ForkChoiceKey (blue_work, vrf_output, hash) wins, so
        // with equal work and VRF output, the largest hash.
        let params = GhostDagParams::default();
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = GhostDag::new(params, dag_store.clone());
        let genesis = create_test_block_with_parents([0xEE; 32], Hash::default(), vec![], 0);
        dag_store.store_block(genesis.clone()).await.unwrap();
        let mut parent = genesis.hash();
        for i in 1..7u8 {
            let b = create_test_block_with_parents([0xE0 + i; 32], parent, vec![], u64::from(i));
            dag_store.store_block(b.clone()).await.unwrap();
            ghostdag.register_existing_block(&b).await.unwrap();
            parent = b.hash();
        }

        // Five sibling tips, all at blue_score = 7, distinct hashes.
        let tie_hashes = [
            Hash::new([0x11; 32]),
            Hash::new([0x33; 32]),
            Hash::new([0x22; 32]),
            Hash::new([0xAA; 32]),
            Hash::new([0x05; 32]),
        ];
        for h in tie_hashes.iter() {
            let b = create_test_block_with_parents(*h.as_bytes(), parent, vec![], 7);
            dag_store.store_block(b.clone()).await.unwrap();
            ghostdag.add_block(&b).await.unwrap();
        }

        let expected = *tie_hashes.iter().max().expect("non-empty"); // 0xAA..
                                                                     // HashSet iteration order varies run-to-run; the result must not.
        for _ in 0..50 {
            let got = ghostdag.select_tip().await.expect("a tip is available");
            assert_eq!(
                got, expected,
                "select_tip must deterministically pick the largest-key tip on a blue_score tie"
            );
        }

        // A strictly higher blue_score must win over the whole tie group even
        // though its hash is the smallest — work dominates the tie-break.
        let winner = create_test_block_with_parents([0x01; 32], tie_hashes[0], vec![], 8);
        dag_store.store_block(winner.clone()).await.unwrap();
        ghostdag.add_block(&winner).await.unwrap();
        for _ in 0..20 {
            assert_eq!(
                ghostdag.select_tip().await.expect("a tip is available"),
                winner.hash(),
                "higher blue_score must win regardless of hash ordering"
            );
        }
    }

    #[tokio::test]
    /// PANIC-S1 G4, under r1007 G6: an ANCESTOR inside the mergeset is not in
    /// the anticone. K = 2. Main chain c <- e (SP side) and a second chain
    /// b1 <- b2, both from genesis; d merges b2, so Mergeset*(d) = {b1, b2}.
    /// When b2 is colored, b1 is already blue and is b2's ancestor, so it must
    /// NOT count: b2's blue anticone is {e, c} = 2 <= K. Counting b1 would
    /// make it 3 and wrongly color b2 red. (The old fixture merged c and e
    /// together; r1007 G2 rejects parents in each other's past, so the
    /// ancestor now reaches the mergeset through the merge parent's past.)
    async fn panic_s1_merge_parent_ancestor_is_not_counted_in_anticone() {
        let params = GhostDagParams {
            k: 2,
            ..GhostDagParams::default()
        };
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = GhostDag::new(params, dag_store.clone());

        let genesis = create_test_block_with_parents([0xAA; 32], Hash::default(), vec![], 0);
        dag_store.store_block(genesis.clone()).await.unwrap();
        ghostdag.add_block(&genesis).await.unwrap();

        let b1 = create_test_block_with_parents([0xB1; 32], genesis.hash(), vec![], 1);
        let b2 = create_test_block_with_parents([0xB2; 32], b1.hash(), vec![], 2);
        let c = create_test_block_with_parents([0xC1; 32], genesis.hash(), vec![], 1);
        let e = create_test_block_with_parents([0xE2; 32], c.hash(), vec![], 2);
        for blk in [&b1, &b2, &c, &e] {
            dag_store.store_block(blk.clone()).await.unwrap();
            ghostdag.add_block(blk).await.unwrap();
        }

        let d = sealed(&ghostdag, [0xD3; 32], vec![b2.hash(), e.hash()]).await;
        assert_eq!(d.selected_parent(), e.hash(), "0xE2 > 0xB2 at equal work");
        dag_store.store_block(d.clone()).await.unwrap();
        ghostdag.add_block(&d).await.unwrap();

        let blue = ghostdag.calculate_blue_set(&d).await.unwrap();
        assert!(blue.contains(&b1.hash()), "b1: anticone {{e, c}} = 2 <= k");
        assert!(
            blue.contains(&b2.hash()),
            "b2: anticone {{e, c}}; b1 is its ancestor, not anticone"
        );
        assert_eq!(blue.score, 5, "blue past(d) = {{genesis, c, e, b1, b2}}");
        assert_eq!(d.header.blue_score, 5);
    }

    /// Genesis seeded as the DAG root, the way the other fixtures here do it.
    async fn ms_bound_fixture(k: u32) -> (Arc<DagStore>, GhostDag, Block) {
        let params = GhostDagParams {
            k,
            ..GhostDagParams::default()
        };
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = GhostDag::new(params, dag_store.clone());
        let genesis = create_test_block_with_parents([0xAA; 32], Hash::default(), vec![], 0);
        dag_store.store_block(genesis.clone()).await.unwrap();
        ghostdag.add_block(&genesis).await.unwrap();
        (dag_store, ghostdag, genesis)
    }

    async fn ms_bound_admit(dag_store: &DagStore, ghostdag: &GhostDag, b: &Block) -> u64 {
        dag_store.store_block(b.clone()).await.unwrap();
        ghostdag.add_block(b).await.unwrap();
        ghostdag.get_blue_score(&b.hash()).await.unwrap()
    }

    /// r1007 CV-3: one unit. A merge block commits SP's score + its blue
    /// mergeset, and a linear block above it commits exactly one more. The
    /// fork-choice score of each is its header value. (Pre-r1007 the header
    /// carried `parent + 1` while fork choice ran ahead of it by the blue
    /// merge parents of the ancestry; that gap no longer exists.)
    #[tokio::test]
    async fn blue_score_check_accepts_a_linear_block_whose_ancestry_merged() {
        let (dag_store, ghostdag, genesis) = ms_bound_fixture(18).await;
        let a = create_test_block_with_parents([0xA1; 32], genesis.hash(), vec![], 1);
        let b = create_test_block_with_parents([0xB1; 32], genesis.hash(), vec![], 1);
        ms_bound_admit(&dag_store, &ghostdag, &a).await;
        ms_bound_admit(&dag_store, &ghostdag, &b).await;
        let c = sealed(&ghostdag, [0xC2; 32], vec![a.hash(), b.hash()]).await;
        assert_eq!(
            ms_bound_admit(&dag_store, &ghostdag, &c).await,
            3,
            "1 + {{b, a}}"
        );
        let d = create_test_block_with_parents([0xD3; 32], c.hash(), vec![], 3);
        let mut d = d;
        d.header.blue_score = 4;
        d.header.blue_work = crate::types::blue_work_for_score(4);
        let score = ms_bound_admit(&dag_store, &ghostdag, &d).await;
        assert_eq!(score, 4, "blue past(d) = genesis, a, b, c");
        assert_eq!(
            score, d.header.blue_score,
            "fork choice reads the committed value"
        );
        assert_eq!(
            ghostdag.get_blue_score(&c.hash()).await.unwrap(),
            c.header.blue_score,
            "the merge block itself"
        );
    }

    /// r1007 G7 replaces the old log-only check (`blue_score_inconsistent`,
    /// which flagged a fork-choice score below header + 1) with exact equality
    /// at admission: a header claiming less, or more, than the GHOSTDAG score
    /// is rejected, on a linear block and on a merge block alike.
    #[tokio::test]
    async fn blue_score_check_flags_a_score_below_header_plus_one() {
        let (dag_store, ghostdag, genesis) = ms_bound_fixture(18).await;
        let a = create_test_block_with_parents([0x71; 32], genesis.hash(), vec![], 1);
        let b = create_test_block_with_parents([0x72; 32], genesis.hash(), vec![], 1);
        ms_bound_admit(&dag_store, &ghostdag, &a).await;
        ms_bound_admit(&dag_store, &ghostdag, &b).await;
        let with_score = |mut blk: Block, score: u64| {
            blk.header.blue_score = score;
            blk.header.blue_work = crate::types::blue_work_for_score(score);
            blk
        };
        let linear = create_test_block_with_parents([0x73; 32], a.hash(), vec![], 2);
        for wrong in [0u64, 1, 3, u64::MAX] {
            assert!(
                matches!(
                    ghostdag
                        .validate_block_consistency(&with_score(linear.clone(), wrong))
                        .await,
                    Err(GhostDagError::BlueScoreMismatch { .. })
                ),
                "linear: {wrong}"
            );
        }
        assert!(ghostdag
            .validate_block_consistency(&with_score(linear, 2))
            .await
            .is_ok());
        let merge = create_test_block_with_parents([0x74; 32], b.hash(), vec![a.hash()], 2);
        for wrong in [2u64, 4] {
            assert!(
                matches!(
                    ghostdag
                        .validate_block_consistency(&with_score(merge.clone(), wrong))
                        .await,
                    Err(GhostDagError::BlueScoreMismatch { .. })
                ),
                "merge block: {wrong}"
            );
        }
        assert!(ghostdag
            .validate_block_consistency(&with_score(merge, 3))
            .await
            .is_ok());
    }

    /// The window-bounded score (what admission checks) matches the full
    /// blue-set union on the over-wide-anticone shape (k = 1, three siblings,
    /// two merged). Under r1007 G3 the selected parent is the heaviest sibling
    /// (0xE1); of b and c only the first in Key order fits next to it.
    #[tokio::test]
    async fn ms_bound_score_matches_the_full_union_on_a_k_cluster_merge() {
        let (dag_store, ghostdag, genesis) = ms_bound_fixture(1).await;
        let b = create_test_block_with_parents([0xB1; 32], genesis.hash(), vec![], 1);
        let c = create_test_block_with_parents([0xC1; 32], genesis.hash(), vec![], 1);
        let e = create_test_block_with_parents([0xE1; 32], genesis.hash(), vec![], 1);
        for blk in [&b, &c, &e] {
            ms_bound_admit(&dag_store, &ghostdag, blk).await;
        }
        let d = sealed(&ghostdag, [0xD1; 32], vec![b.hash(), c.hash(), e.hash()]).await;
        let bounded = ms_bound_admit(&dag_store, &ghostdag, &d).await;
        let full = ghostdag.calculate_blue_set(&d).await.unwrap().score;
        assert_eq!(
            bounded, full,
            "bounded score must equal the full union here"
        );
        assert_eq!(bounded, 3, "genesis, e (SP), one blue of b/c");
        let data = ghostdag.ghostdag_data(&d.hash()).await.unwrap();
        assert_eq!(data.mergeset_blues, vec![e.hash(), b.hash()]);
        assert_eq!(data.mergeset_reds, vec![c.hash()]);
    }

    /// Merging a block already in the selected parent's past would add
    /// nothing to the mergeset. Under r1007 G2 it is not tolerated: the parents
    /// must be an antichain, so the block is rejected.
    #[tokio::test]
    async fn ms_bound_merging_an_ancestor_adds_nothing() {
        let (dag_store, ghostdag, genesis) = ms_bound_fixture(18).await;
        let a = create_test_block_with_parents([0xA1; 32], genesis.hash(), vec![], 1);
        let b = create_test_block_with_parents([0xB1; 32], a.hash(), vec![], 2);
        ms_bound_admit(&dag_store, &ghostdag, &a).await;
        assert_eq!(ms_bound_admit(&dag_store, &ghostdag, &b).await, 2);
        let c = create_test_block_with_parents([0xC1; 32], b.hash(), vec![a.hash()], 3);
        assert!(matches!(
            ghostdag.validate_block_consistency(&c).await,
            Err(GhostDagError::ParentsNotAntichain { .. })
        ));
        let c = create_test_block_with_parents([0xC1; 32], b.hash(), vec![], 3);
        assert_eq!(ms_bound_admit(&dag_store, &ghostdag, &c).await, 3);
        assert_eq!(ghostdag.calculate_blue_set(&c).await.unwrap().score, 3);
    }

    /// A side branch that ran apart for longer than k blocks is red: every
    /// block of it has more than k blues of the main chain in its anticone.
    /// Under r1007 G6 the whole unmerged branch is in the mergeset, not just
    /// its tip, and all of it is red.
    #[tokio::test]
    async fn ms_bound_a_long_side_branch_is_red() {
        let (dag_store, ghostdag, genesis) = ms_bound_fixture(2).await;
        // Main chain m1..m5 and side chain s1..s4, both from genesis.
        let mut main = genesis.hash();
        for h in 1..=5u64 {
            let blk = create_test_block_with_parents([0x10 + h as u8; 32], main, vec![], h);
            ms_bound_admit(&dag_store, &ghostdag, &blk).await;
            main = blk.hash();
        }
        let mut side = genesis.hash();
        let mut sides = Vec::new();
        for h in 1..=4u64 {
            let blk = create_test_block_with_parents([0x50 + h as u8; 32], side, vec![], h);
            ms_bound_admit(&dag_store, &ghostdag, &blk).await;
            side = blk.hash();
            sides.push(side);
        }
        // Merging s4 into m6: each s_i has m1..m5 (5 > k = 2) in its anticone.
        let m6 = create_test_block_with_parents([0x99; 32], main, vec![side], 6);
        assert_eq!(
            ms_bound_admit(&dag_store, &ghostdag, &m6).await,
            6,
            "red mergeset adds nothing: sp score 5 + 1"
        );
        let data = ghostdag.ghostdag_data(&m6.hash()).await.unwrap();
        assert_eq!(data.mergeset_reds, sides, "s1..s4, in Key order");
    }

    #[tokio::test]
    /// PANIC-S1 G4: the k-cluster rule must actually colour blocks RED. With
    /// k = 1 and three genesis siblings merged into one block, the selected
    /// parent (the heaviest sibling, r1007 G3) and one more fit; the third has
    /// a blue anticone of size 2 > k, so exactly one mergeset block is red.
    async fn panic_s1_k_cluster_colours_an_over_wide_anticone_red() {
        let params = GhostDagParams {
            k: 1,
            ..GhostDagParams::default()
        };
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = GhostDag::new(params, dag_store.clone());

        let genesis = create_test_block_with_parents([0xAA; 32], Hash::default(), vec![], 0);
        dag_store.store_block(genesis.clone()).await.unwrap();
        ghostdag.add_block(&genesis).await.unwrap();

        let b = create_test_block_with_parents([0xB1; 32], genesis.hash(), vec![], 1);
        let c = create_test_block_with_parents([0xC1; 32], genesis.hash(), vec![], 1);
        let e = create_test_block_with_parents([0xE1; 32], genesis.hash(), vec![], 1);
        for blk in [&b, &c, &e] {
            dag_store.store_block(blk.clone()).await.unwrap();
            ghostdag.add_block(blk).await.unwrap();
        }

        let d = sealed(&ghostdag, [0xD1; 32], vec![b.hash(), c.hash(), e.hash()]).await;
        dag_store.store_block(d.clone()).await.unwrap();
        ghostdag.add_block(&d).await.unwrap();

        let blue = ghostdag.calculate_blue_set(&d).await.unwrap();
        assert!(blue.contains(&genesis.hash()) && blue.contains(&e.hash()));
        let blue_merges = [b.hash(), c.hash()]
            .iter()
            .filter(|h| blue.contains(h))
            .count();
        assert_eq!(
            blue_merges, 1,
            "k=1: exactly one of the two other parents fits the k-cluster"
        );
        assert_eq!(blue.score, 3, "blue past(d) = {{genesis, e, one of b/c}}");

        // CV-3: fork choice keeps no cumulative ancestry anywhere.
        assert_eq!(ghostdag.materialised_blue_ancestry_entries().await, 0);
    }

    #[tokio::test]
    async fn test_blue_set_with_merge_parents_unions_parents() {
        let params = GhostDagParams::default();
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = GhostDag::new(params, dag_store.clone());

        // Genesis
        let genesis = create_test_block_with_parents([0xAA; 32], Hash::default(), vec![], 0);
        dag_store.store_block(genesis.clone()).await.unwrap();
        ghostdag.add_block(&genesis).await.unwrap();

        // Two parallel children of genesis: b and c
        let b = create_test_block_with_parents([0xB1; 32], genesis.hash(), vec![], 1);
        let c = create_test_block_with_parents([0xC1; 32], genesis.hash(), vec![], 1);
        dag_store.store_block(b.clone()).await.unwrap();
        dag_store.store_block(c.clone()).await.unwrap();
        ghostdag.add_block(&b).await.unwrap();
        ghostdag.add_block(&c).await.unwrap();

        // d merges both (r1007 G3: c, the heavier key, is the selected parent).
        let d = sealed(&ghostdag, [0xD1; 32], vec![b.hash(), c.hash()]).await;
        dag_store.store_block(d.clone()).await.unwrap();
        ghostdag.add_block(&d).await.unwrap();

        // Blue set of d is its blue past: {genesis, b, c} (G7: not d itself).
        let blue = ghostdag.calculate_blue_set(&d).await.unwrap();
        assert!(blue.contains(&genesis.hash()));
        assert!(blue.contains(&b.hash()));
        assert!(blue.contains(&c.hash()));
        assert!(!blue.contains(&d.hash()));
        assert_eq!(blue.score, 3);
    }

    #[tokio::test]
    async fn test_count_blue_anticone_short_circuits_at_max_count() {
        // Regression for the OOM fix (Apr 2026), carried to the r1007 coloring:
        // the work per candidate is bounded by K, not by the size of the blue
        // set. Once a block holds K + 1 blues (SP included) every further
        // candidate is red without a walk (Kaspa `check_blue_candidate`).
        // K = 3, nine siblings merged: exactly K + 1 blues.
        let params = GhostDagParams {
            k: 3,
            ..GhostDagParams::default()
        };
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = GhostDag::new(params, dag_store.clone());
        let genesis = create_test_block_with_parents([0xAA; 32], Hash::default(), vec![], 0);
        dag_store.store_block(genesis.clone()).await.unwrap();
        ghostdag.add_block(&genesis).await.unwrap();
        let mut parents = Vec::new();
        for i in 0..9u8 {
            let b = create_test_block_with_parents([0x10 + i; 32], genesis.hash(), vec![], 1);
            dag_store.store_block(b.clone()).await.unwrap();
            ghostdag.add_block(&b).await.unwrap();
            parents.push(b.hash());
        }
        let d = sealed(&ghostdag, [0xDD; 32], parents).await;
        dag_store.store_block(d.clone()).await.unwrap();
        ghostdag.add_block(&d).await.unwrap();
        let data = ghostdag.ghostdag_data(&d.hash()).await.unwrap();
        assert_eq!(data.mergeset_blues.len(), 4, "K + 1 blues");
        assert_eq!(data.mergeset_reds.len(), 5);
        assert_eq!(d.header.blue_score, 1 + 4);
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

    /// SYNC-S1 D3, carried to r1007 G12 — the durable GHOSTDAG record (and the
    /// committed header score) remove the cold-start walk, which is what makes
    /// DAG-store pruning possible. Scores follow G7 (genesis 0, height h scores
    /// h on a linear chain).
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
        let kv = Arc::new(MemKv::default());
        let dag_store = Arc::new(
            DagStore::persistent_with_strict_vrf(kv.clone(), false).expect("persistent store"),
        );

        // Build and admit a chain in "process 1".
        let genesis = create_test_block_with_parents([0xA1; 32], Hash::default(), vec![], 0);
        dag_store.store_block(genesis.clone()).await.unwrap();
        let mut blocks = vec![genesis.clone()];
        let mut parent = genesis.hash();
        for i in 1..=260u64 {
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
            assert_eq!(gd1.get_blue_score(&parent).await.unwrap(), 260);
        }

        // G12: the GHOSTDAG record is durable, not just in-memory.
        assert_eq!(
            dag_store.get_ghostdag_data(&parent).map(|d| d.blue_score),
            Some(260),
            "the GHOSTDAG record must be persisted, not only held in memory"
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
        // pruning point at height 60 and call `prune()`, which drops every block
        // below it from memory and disk. r1007 G12: a node keeps the GHOSTDAG
        // window (GHOSTDAG_WINDOW = 200 heights below the next block, 61..=260
        // here) and nothing below it. (The pre-r1007 fixture kept only the tip
        // and its parent, which the windowed rules do not support.)
        dag_store
            .update_pruning_point(blocks[60].hash())
            .await
            .expect("set pruning point");
        let pruned = dag_store.prune().await.expect("prune");
        assert_eq!(pruned, 60, "heights 0..=59 pruned, the window retained");
        assert!(
            dag_store.get_block(&blocks[0].hash()).await.is_err(),
            "a pruned ancestor is genuinely gone from the DAG store"
        );

        // Admit the next block on top of the pruned chain.
        let mut h = [0u8; 32];
        h[0..8].copy_from_slice(&261u64.to_le_bytes());
        h[31] = 0xD4;
        let next = create_test_block_with_parents(h, parent, vec![], 261);
        dag_store.store_block(next.clone()).await.unwrap();
        gd2.add_block(&next)
            .await
            .expect("admission must succeed over a PRUNED ancestry via the durable anchor");

        assert_eq!(
            gd2.get_blue_score(&next.hash()).await.unwrap(),
            261,
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
            N,
            "cold-path value is the committed one: genesis 0 + one per step (G7)"
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
            N + 1,
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
            score_live, 1,
            "r1007 G7 convention: genesis == 0, each linear step adds 1 (height)"
        );
        assert_eq!(
            b1.header.blue_score, score_live,
            "CV-3: one unit; the fork-choice score IS the committed header score"
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
        // Edge case: K = 0 admits only the selected parent as blue; every
        // other mergeset block is red at once.
        let params = GhostDagParams {
            k: 0,
            ..GhostDagParams::default()
        };
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = GhostDag::new(params, dag_store.clone());
        let genesis = create_test_block_with_parents([0xAA; 32], Hash::default(), vec![], 0);
        dag_store.store_block(genesis.clone()).await.unwrap();
        ghostdag.add_block(&genesis).await.unwrap();
        let mut parents = Vec::new();
        for i in 0..5u8 {
            let b = create_test_block_with_parents([0x20 + i; 32], genesis.hash(), vec![], 1);
            dag_store.store_block(b.clone()).await.unwrap();
            ghostdag.add_block(&b).await.unwrap();
            parents.push(b.hash());
        }
        let d = sealed(&ghostdag, [0xDE; 32], parents).await;
        let data = ghostdag
            .compute_ghostdag(d.selected_parent(), &d.header.merge_parent_hashes, 2)
            .await
            .unwrap();
        assert_eq!(data.mergeset_blues, vec![d.selected_parent()]);
        assert_eq!(data.mergeset_reds.len(), 4);
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

        let gset = BlueSet::new();
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

        /// Property: a block's blue set is its blue PAST (r1007 G7): it never
        /// contains the block itself, and on a linear chain it contains the
        /// selected parent and has exactly `blue_score` members.
        #[test]
        fn prop_blue_set_contains_self(n in 1..15usize, seed in 1..1000u64) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let (ghostdag, dag_store, hashes) = build_random_chain(n, seed).await;
                for hash in &hashes {
                    if let Ok(block) = dag_store.get_block(hash).await {
                        let blue_set = ghostdag.calculate_blue_set(&block).await.unwrap();
                        prop_assert!(!blue_set.contains(hash),
                            "Block {:?} is in its own blue set", hash);
                        if !block.is_genesis() {
                            prop_assert!(blue_set.contains(&block.selected_parent()));
                        }
                        prop_assert_eq!(blue_set.blocks.len() as u64, blue_set.score);
                        prop_assert_eq!(blue_set.score, block.header.blue_score);
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
    /// same one or they disagree about validity. r1007 (ADR CV-2): every rule
    /// is active from block 0, G5 included, with no environment override.
    #[test]
    fn mp_depth_activation_height_is_the_agreed_consensus_value() {
        assert_eq!(
            MERGE_DEPTH_ACTIVATION_HEIGHT, 0,
            "r1007 is a new genesis with every rule active from block 0"
        );
        const {
            assert!(
                MERGE_DEPTH_ACTIVATION_HEIGHT == 0,
                "G5 must be enforced from genesis: any unenforced prefix is a \
                 window where a valid block can cite a parent the pruner may drop"
            )
        };
        // The former devnet override is no longer read.
        assert_eq!(merge_depth_activation_height(), 0);
        // §1.2 constants, pinned.
        assert_eq!(GHOSTDAG_K, GhostDagParams::default().k);
        assert_eq!(MAX_PARENTS, GhostDagParams::default().max_parents);
        assert_eq!(MERGESET_SIZE_LIMIT, 10 * GHOSTDAG_K as usize);
        assert_eq!(GHOSTDAG_WINDOW, 2 * MERGE_DEPTH);
    }

    /// r1007: there is no "below the activation height". G5 applies to every
    /// block from genesis, so a merge parent far deeper than MERGE_DEPTH is
    /// rejected at any height (formerly: accepted below a deferred
    /// activation, a mechanism r1007 removes; ADR CV-2, spec §0).
    #[tokio::test]
    async fn mp_depth_is_not_enforced_below_the_activation_height() {
        fn h(i: u64) -> [u8; 32] {
            let mut b = [0u8; 32];
            b[0..8].copy_from_slice(&i.to_le_bytes());
            b
        }
        const N: u64 = 300; // deeper than MERGE_PARENT_MAX_DEPTH

        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = GhostDag::new(GhostDagParams::default(), dag_store.clone());

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
        // A side block on `deep`, so the merge parent is outside past(SP) and
        // only the depth rule can reject it.
        let side = create_test_block_with_parents(h(N + 7), deep, vec![], 11);
        dag_store.store_block(side.clone()).await.expect("store");
        ghostdag.register_existing_block(&side).await.expect("reg");

        let merger = create_test_block_with_parents(h(N + 1), tip, vec![side.hash()], N + 1);
        dag_store.store_block(merger.clone()).await.expect("store");
        assert!(
            matches!(
                ghostdag.add_block(&merger).await,
                Err(GhostDagError::MergeDepthViolation { .. })
            ),
            "G5 is active from genesis: a merge parent 290 below is invalid"
        );
    }

    /// A merge parent deeper than the bound is invalid. This is what makes
    /// bounding the coloring walk sound, and therefore what makes DAG pruning
    /// safe: no valid block can cite anything below the GHOSTDAG window.
    #[tokio::test]
    async fn mp_depth_rejects_a_too_deep_merge_parent_once_activated() {
        fn h(i: u64) -> [u8; 32] {
            let mut b = [0u8; 32];
            b[0..8].copy_from_slice(&i.to_le_bytes());
            b
        }
        const N: u64 = 300;

        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = GhostDag::new(GhostDagParams::default(), dag_store.clone());

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

        // Too deep: height N+1 merging (a side block of) height 10.
        let side = create_test_block_with_parents(h(N + 9), deep, vec![], 11);
        dag_store.store_block(side.clone()).await.expect("store");
        ghostdag.register_existing_block(&side).await.expect("reg");
        let bad = create_test_block_with_parents(h(N + 1), tip, vec![side.hash()], N + 1);
        dag_store.store_block(bad.clone()).await.expect("store");
        let err = ghostdag.add_block(&bad).await;
        assert!(
            err.is_err(),
            "a merge parent {} blocks deep must be rejected",
            N + 1 - 11
        );
        // Merging an ancestor of the selected parent is rejected too (G2).
        let bad2 = create_test_block_with_parents(h(N + 3), tip, vec![deep], N + 1);
        assert!(ghostdag.add_block(&bad2).await.is_err());

        // A sibling one height back is well inside the bound and stays valid —
        // the rule must not break ordinary DAG merging, which is the whole point
        // of multi-producer. Its anticone (the tip) is within K, so it is blue.
        let sibling = create_test_block_with_parents(h(N + 500), shallow_parent, vec![], N);
        dag_store.store_block(sibling.clone()).await.expect("store");
        ghostdag
            .register_existing_block(&sibling)
            .await
            .expect("reg");
        let good = sealed(&ghostdag, h(N + 2), vec![tip, sibling.hash()]).await;
        assert_eq!(good.header.blue_score, N + 2, "SP's N + {{SP, sibling}}");
        dag_store.store_block(good.clone()).await.expect("store");
        assert!(
            ghostdag.add_block(&good).await.is_ok(),
            "a merge parent inside the bound must still be accepted — the depth rule \
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

        // r1007: the heavier of tip and sibling is SP (G3), and the header
        // commits the GHOSTDAG score (G7).
        let merge = sealed(&ghostdag, h(N + 2_000), vec![tip, sibling.hash()]).await;
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

    use crate::dag_store::KvStore as _;

    /// A DAG with merges: `width` producers seal one block per height, each
    /// naming one block of the previous height and the others it heard as
    /// parents, `height` heights above genesis. Seeded, so a failing seed
    /// reproduces. Returns the blocks in height order.
    ///
    /// r1007: headers are built the way the producer builds them (spec §9.3):
    /// the selected parent is the heaviest parent (G3) and blue_score /
    /// blue_work are the GHOSTDAG values (G7), computed on a scratch DAG.
    /// (The pre-r1007 fixture chose the selected parent at random and wrote
    /// `parent + 1`, the flawed unit CV-3 removes.)
    async fn merging_dag(seed: u64, height: u64) -> Vec<Block> {
        let mut x = seed | 1;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let scratch = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let gd = GhostDag::new(GhostDagParams::default(), scratch.clone());
        let mut id = 0u64;
        let mut next_id = || {
            id += 1;
            let mut b = [0u8; 32];
            b[0..8].copy_from_slice(&id.to_le_bytes());
            b[8..16].copy_from_slice(&seed.to_le_bytes());
            b[31] = 0x5C;
            b
        };
        let genesis = create_test_block_with_parents(next_id(), Hash::default(), vec![], 0);
        scratch.store_block(genesis.clone()).await.expect("store");
        gd.add_block(&genesis).await.expect("genesis");
        let mut all = vec![genesis.clone()];
        let mut prev: Vec<Hash> = vec![genesis.hash()];
        for _h in 1..=height {
            let width = 1 + (next() % 3) as usize;
            let mut layer = Vec::new();
            for _ in 0..width {
                // One block of the previous height, plus the rest of that
                // height this producer heard.
                let base = prev[(next() as usize) % prev.len()];
                let parents: Vec<Hash> = prev
                    .iter()
                    .copied()
                    .filter(|p| *p == base || next() % 4 != 0)
                    .collect();
                let b = sealed(&gd, next_id(), parents).await;
                scratch.store_block(b.clone()).await.expect("store");
                gd.add_block(&b).await.expect("fixture block admitted");
                layer.push(b.hash());
                all.push(b);
            }
            prev = layer;
        }
        all
    }

    /// What fork choice concludes on `gd`: the selected tip, and every tip
    /// with its score, in a canonical order (score, then the smaller hash).
    async fn fork_choice_view(gd: &GhostDag) -> Result<(Hash, Vec<(u64, Hash)>), GhostDagError> {
        let tip = gd.select_tip().await?;
        let mut ranked = Vec::new();
        for t in gd.get_tips().await {
            ranked.push((gd.get_blue_score(&t).await?, t));
        }
        ranked.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        Ok((tip, ranked))
    }

    /// A persistent strict-free store holding `blocks`, admitted through
    /// `add_block` by a first process (which records the derived scores).
    async fn admitted_store(blocks: &[Block]) -> (Arc<MemKv>, Arc<DagStore>) {
        let kv = Arc::new(MemKv::default());
        let dag_store = Arc::new(
            DagStore::persistent_with_strict_vrf(kv.clone(), false).expect("persistent store"),
        );
        let gd = GhostDag::new(GhostDagParams::default(), dag_store.clone());
        for b in blocks {
            dag_store.store_block(b.clone()).await.expect("store");
            gd.add_block(b).await.expect("admit");
        }
        (kv, dag_store)
    }

    /// S2-5 (H4), carried to r1007 CV-3: a rehydrated block is ranked on its
    /// committed header score, which IS the fork-choice unit (one score). With
    /// its ancestry pruned and its GHOSTDAG record deleted, registration still
    /// ranks it on exactly the value the first process validated, and writes
    /// nothing back.
    #[tokio::test]
    async fn register_existing_block_never_ranks_on_header_scale() {
        let blocks = merging_dag(0xA11CE, 40).await;
        let (kv, dag_store) = admitted_store(&blocks).await;
        let floor = blocks
            .iter()
            .find(|b| b.header.height == 30 && !b.header.merge_parent_hashes.is_empty())
            .or_else(|| blocks.iter().find(|b| b.header.height == 30))
            .expect("a block at the floor")
            .clone();
        let validated = dag_store
            .get_ghostdag_data(&floor.hash())
            .expect("the first process persisted the GHOSTDAG record")
            .blue_score;
        assert_eq!(validated, floor.header.blue_score, "admission enforced G7");
        dag_store
            .update_pruning_point(floor.hash())
            .await
            .expect("pruning point");
        dag_store.prune().await.expect("prune");
        // The record for the floor block is gone (a torn write, an old data dir).
        kv.kv_delete(crate::dag_store::cf::DAG_GHOSTDAG, floor.hash().as_bytes())
            .expect("delete record");
        assert!(dag_store.get_ghostdag_data(&floor.hash()).is_none());

        let gd = GhostDag::new(GhostDagParams::default(), dag_store.clone());
        gd.register_existing_block(&floor)
            .await
            .expect("a retained block registers from its committed header");
        let score = gd.get_blue_score(&floor.hash()).await.expect("ranked");
        assert_eq!(
            score, validated,
            "the block was ranked on {score}, not the score admission validated"
        );
        assert!(
            dag_store.get_ghostdag_data(&floor.hash()).is_none(),
            "registration must not write a record it did not compute"
        );
    }

    /// How a rehydrating node's score anchors can differ from the ones it wrote.
    #[derive(Debug, Clone, Copy)]
    enum CacheFault {
        Missing,
        Corrupt,
        HeaderScale,
        Foreign,
    }

    /// Apply `fault` to every persisted GHOSTDAG record of `kv` (G12). `foreign`
    /// holds the records of another node over a different DAG.
    fn fault_cache(
        kv: &MemKv,
        store: &DagStore,
        blocks: &[Block],
        fault: CacheFault,
        foreign: &MemKv,
        seed: u64,
    ) {
        let cf = crate::dag_store::cf::DAG_GHOSTDAG;
        let mut x = seed | 1;
        for (i, b) in blocks.iter().enumerate() {
            let k = b.hash().as_bytes().to_vec();
            match fault {
                CacheFault::Missing => {
                    kv.kv_delete(cf, &k).expect("delete");
                }
                CacheFault::Corrupt => {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    let v = match i % 3 {
                        0 => vec![0xFFu8; 3],                   // torn
                        1 => x.to_be_bytes().to_vec(),          // garbage
                        _ => (x as u32).to_be_bytes().to_vec(), // wrong length
                    };
                    kv.kv_put(cf, &k, &v).expect("put");
                }
                CacheFault::HeaderScale => {
                    // A well-formed, correctly tagged record on another scale
                    // (the pre-r1007 genesis = 1 convention): one too high.
                    if let Some(mut d) = store.get_ghostdag_data(&b.hash()) {
                        d.blue_score = d.blue_score.saturating_add(1);
                        d.blue_work = crate::types::blue_work_for_score(d.blue_score);
                        store.put_ghostdag_data(&b.hash(), &d);
                    }
                }
                CacheFault::Foreign => {
                    kv.kv_delete(cf, &k).expect("delete");
                }
            }
        }
        if let CacheFault::Foreign = fault {
            // Another node's records filed under OUR block hashes.
            let theirs: Vec<Vec<u8>> = foreign
                .kv_iter_cf(cf)
                .expect("iter")
                .into_iter()
                .map(|(_, v)| v)
                .collect();
            for (b, v) in blocks.iter().zip(theirs.iter().cycle()) {
                kv.kv_put(cf, b.hash().as_bytes(), v).expect("put");
            }
        }
    }

    /// S2-5 (H4) / CV-3 property: fork choice is a function of block data. A
    /// node whose GHOSTDAG records are missing, corrupt, on another scale, or
    /// copied from another node rehydrates (the production order: every
    /// height, then the authoritative tips) to the same selected tip and the
    /// same tip ranking as a node with intact records, and that ranking is the
    /// committed header blue_score of each tip. It then judges the next block
    /// exactly as the intact node does, or, where the window cannot be
    /// recomputed (a pruned store), refuses to judge it. It never reaches a
    /// different verdict.
    #[tokio::test]
    async fn fork_choice_score_is_a_function_of_block_data() {
        let foreign_blocks = merging_dag(0xF0E1, 25).await;
        let (foreign_kv, _) = admitted_store(&foreign_blocks).await;
        for seed in 1..=12u64 {
            let blocks = merging_dag(seed.wrapping_mul(0x9E37_79B9), 24 + seed % 7).await;
            // The next block, sealed by an intact, unpruned node over all tips.
            let next = {
                let (_kv, full) = admitted_store(&blocks).await;
                let gd = GhostDag::new(GhostDagParams::default(), full.clone());
                for b in &blocks {
                    gd.register_existing_block(b).await.expect("register");
                }
                gd.reconcile_tips_from_dag_store().await;
                let mut id = [0x4E; 32];
                id[0..8].copy_from_slice(&seed.to_le_bytes());
                sealed(&gd, id, gd.get_tips().await).await
            };
            for pruned in [false, true] {
                // Reference: intact records, rehydrated the production way.
                let (ref_kv, ref_store) = admitted_store(&blocks).await;
                let floor_height = 12u64;
                let rehydrate = |store: Arc<DagStore>| {
                    let blocks = blocks.clone();
                    let next = next.clone();
                    async move {
                        let gd = GhostDag::new(GhostDagParams::default(), store.clone());
                        let from = if pruned { floor_height } else { 0 };
                        for b in blocks.iter().filter(|b| b.header.height >= from) {
                            let _ = gd.register_existing_block(b).await;
                        }
                        gd.reconcile_tips_from_dag_store().await;
                        let verdict = gd.validate_block_consistency(&next).await;
                        fork_choice_view(&gd).await.map(|v| (v, verdict))
                    }
                };
                let prune = |store: Arc<DagStore>| {
                    let floor = blocks
                        .iter()
                        .find(|b| b.header.height == floor_height)
                        .expect("floor")
                        .hash();
                    async move {
                        store.update_pruning_point(floor).await.expect("pp");
                        store.prune().await.expect("prune");
                    }
                };
                if pruned {
                    prune(ref_store.clone()).await;
                }
                let _ = ref_kv;
                let (reference, ref_verdict) = rehydrate(ref_store.clone())
                    .await
                    .expect("committed values always rank");
                // CV-3: the ranking IS the committed header value. There is
                // one unit, so a tip's fork-choice score is its header's
                // blue_score, which admission validated exactly.
                for (score, tip) in &reference.1 {
                    let header = ref_store.get_header(tip).await.expect("tip header");
                    assert_eq!(
                        *score, header.blue_score,
                        "seed {seed} pruned={pruned}: tip {tip} ranked on {score}, but its \
                         committed blue_score is {}",
                        header.blue_score
                    );
                }
                if !pruned {
                    assert!(
                        ref_verdict.is_ok(),
                        "seed {seed}: the intact node rejects the next block: {ref_verdict:?}"
                    );
                }
                for fault in [
                    CacheFault::Missing,
                    CacheFault::Corrupt,
                    CacheFault::HeaderScale,
                    CacheFault::Foreign,
                ] {
                    let (kv, store) = admitted_store(&blocks).await;
                    if pruned {
                        prune(store.clone()).await;
                    }
                    fault_cache(&kv, &store, &blocks, fault, &foreign_kv, seed);
                    let (view, verdict) = rehydrate(store)
                        .await
                        .expect("committed values always rank");
                    assert_eq!(
                        view, reference,
                        "seed {seed} pruned={pruned} {fault:?}: a different fork choice"
                    );
                    match (&verdict, pruned) {
                        (Ok(()), _) => {}
                        (
                            Err(GhostDagError::MissingParent(_))
                            | Err(GhostDagError::ScoreUnavailable(_)),
                            true,
                        ) => {}
                        (Err(e), _) => panic!(
                            "seed {seed} pruned={pruned} {fault:?}: the next block was judged \
                             differently from the intact node ({ref_verdict:?}): {e}"
                        ),
                    }
                }
            }
        }
    }
}
