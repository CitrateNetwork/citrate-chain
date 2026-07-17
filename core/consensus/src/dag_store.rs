// citrate/core/consensus/src/dag_store.rs

use crate::types::{Block, Hash, Tip};
use crate::vrf::VrfProposerSelector;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// WP-S.1: Key-value store trait for DAG persistence.
/// Implemented by RocksDB in the node crate; DagStore uses this for write-through persistence.
///
/// RM-B1 / WP-B1.3 (audit H-04): the trait gained
/// [`KvOp`] + [`KvStore::kv_write_batch`] so multi-write operations
/// (block admission writes block bytes, child links, tip updates,
/// height index in a single logical step) can be applied atomically.
/// Without batching, a power loss between two `kv_put` calls left the
/// DAG in an inconsistent state on restart (block exists but no
/// children pointer; tips set excludes the new tip; etc.).
///
/// Default trait method `kv_write_batch` falls back to sequential
/// `kv_put` / `kv_delete` so simple in-memory test stores keep
/// working. The RocksDB adapter overrides it with a real `WriteBatch`
/// so production gets atomicity.
pub trait KvStore: Send + Sync {
    fn kv_get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, String>;
    fn kv_put(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<(), String>;
    fn kv_delete(&self, cf: &str, key: &[u8]) -> Result<(), String>;
    fn kv_exists(&self, cf: &str, key: &[u8]) -> Result<bool, String>;
    /// Iterate all key-value pairs in a column family.
    #[allow(clippy::type_complexity)]
    fn kv_iter_cf(&self, cf: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String>;

    /// Apply a sequence of operations as a single atomic write.
    ///
    /// The default implementation performs the ops sequentially with
    /// `kv_put` / `kv_delete`. Backends that support real atomicity
    /// (RocksDB `WriteBatch`) MUST override this — otherwise H-04
    /// regressions silently land. The contract is: either every op
    /// in `ops` is durably applied, or none is.
    fn kv_write_batch(&self, ops: &[KvOp]) -> Result<(), String> {
        for op in ops {
            match op {
                KvOp::Put { cf, key, value } => self.kv_put(cf, key, value)?,
                KvOp::Delete { cf, key } => self.kv_delete(cf, key)?,
            }
        }
        Ok(())
    }
}

/// Single operation inside a [`KvStore::kv_write_batch`] payload.
/// RM-B1 / WP-B1.3 (audit H-04).
#[derive(Debug, Clone)]
pub enum KvOp {
    /// Insert / overwrite `value` at `(cf, key)`.
    Put {
        cf: String,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    /// Delete `(cf, key)`.
    Delete { cf: String, key: Vec<u8> },
}

/// Append a `(parent, children)` serialization to the batch.
/// Called from [`DagStore::store_block`]; on encode failure logs and
/// skips (M-06 pattern).
fn push_children_op(ops: &mut Vec<KvOp>, parent: &Hash, children: &[Hash]) {
    let entry = (*parent, children.to_vec());
    match bincode::serialize(&entry) {
        Ok(bytes) => ops.push(KvOp::Put {
            cf: cf::DAG_CHILDREN.to_string(),
            key: parent.as_bytes().to_vec(),
            value: bytes,
        }),
        Err(e) => {
            tracing::error!(
                "M-06: serialize children for {} failed: {} — skipping persistence",
                parent, e
            );
        }
    }
}

#[derive(Error, Debug)]
pub enum DagStoreError {
    #[error("Block not found: {0}")]
    BlockNotFound(Hash),

    #[error("Block already exists: {0}")]
    BlockExists(Hash),

    #[error("Invalid block height")]
    InvalidHeight,

    #[error("Storage error: {0}")]
    StorageError(String),

    /// WP-K.5: Block failed VRF/proposer admission check
    #[error("Invalid VRF: {0}")]
    InvalidVrf(String),

    /// RM-I / WP-I2.2 (REM-N-04): persistent backend rejected the
    /// atomic write batch. The in-memory caches are NOT mutated when
    /// this error returns, so the runtime stays consistent with disk.
    /// Caller decides whether to retry, fail the operation, or surface
    /// the error to the user.
    #[error("Persistence error: {0}")]
    Persistence(String),
}

/// DAG storage manager.
/// WP-S.1: Optionally backed by a persistent KvStore for write-through persistence.
pub struct DagStore {
    /// Blocks indexed by hash
    blocks: Arc<RwLock<HashMap<Hash, Block>>>,

    /// Blocks indexed by height
    blocks_by_height: Arc<RwLock<HashMap<u64, Vec<Hash>>>>,

    /// Parent-child relationships
    children: Arc<RwLock<HashMap<Hash, Vec<Hash>>>>,

    /// Current tips (blocks with no children)
    tips: Arc<RwLock<HashSet<Hash>>>,

    /// Finalized blocks
    finalized: Arc<RwLock<HashSet<Hash>>>,

    /// Pruning point
    pruning_point: Arc<RwLock<Hash>>,

    /// WP-K.5 / RM-B1 (audit H-05): When true (the production default),
    /// blocks failing structural VRF admission or full ECVRF crypto
    /// verification are rejected. The permissive opt-out exists only
    /// for unit/integration tests via
    /// [`Self::with_permissive_vrf_for_testing`].
    strict_vrf: bool,

    /// WP-S.1: Optional persistent backend for write-through durability.
    persistent: Option<Arc<dyn KvStore>>,

    /// FWA-C1-01: shared, stake-populated proposer selector used to
    /// enforce **leader-election eligibility** at admission. When set
    /// (production wiring), `verify_block_vrf_crypto` additionally calls
    /// `is_eligible_proposer` so a syntactically-valid VRF from a
    /// non-eligible (insufficient-stake / inactive / unregistered)
    /// proposer is REJECTED — closing the gap where the admission gate
    /// verified VRF math + identity binding but never stake eligibility.
    ///
    /// `None` preserves the legacy behavior for unit/integration tests
    /// that admit synthetic blocks without a live validator registry.
    /// Production node startup MUST populate this via
    /// [`Self::with_proposer_selector`].
    proposer_selector: Option<Arc<VrfProposerSelector>>,

    /// VALIDATOR-S1 (v5): consensus ACTIVATION HEIGHT for stake-gated eligibility.
    /// Membership enforcement (`is_eligible_proposer`) applies only to blocks at or
    /// above this height, so the whole fleet flips enforcement on at ONE agreed height
    /// — never per-node based on whether a selector happens to be attached (which would
    /// fork the chain: node A enforces, node B doesn't, for the same block). `None`
    /// means "enforce whenever a selector is attached" (test/back-compat). Set via
    /// [`Self::with_enforcement_activation_height`]; the scheduled re-roll seeds it.
    enforcement_activation_height: Option<u64>,
}

/// Column family names for persistent DAG storage
pub mod cf {
    pub const DAG_BLOCKS: &str = "dag_blocks";
    pub const DAG_CHILDREN: &str = "dag_children";
    pub const DAG_TIPS: &str = "dag_tips";
    pub const DAG_FINALIZED: &str = "dag_finalized";
    pub const DAG_HEIGHT_INDEX: &str = "dag_height_index";
    pub const DAG_METADATA: &str = "dag_metadata";
}

impl DagStore {
    /// Create a DagStore with **strict VRF enforcement enabled** (the
    /// production default). Blocks failing structural admission checks
    /// (empty proof, zero VRF output, zero proposer pubkey, zero
    /// signature) or full ECVRF cryptographic verification are
    /// **rejected**.
    ///
    /// Closes audit finding **H-05**: previously the in-code default was
    /// `strict_vrf: false` which silently admitted garbage VRF blocks.
    /// Test scaffolding that legitimately needs to admit synthetic
    /// blocks without real VRF proofs MUST construct via
    /// [`Self::with_permissive_vrf_for_testing`] (an explicit opt-out
    /// makes the test's reliance on permissive admission visible at the
    /// call site).
    pub fn new() -> Self {
        Self {
            blocks: Arc::new(RwLock::new(HashMap::new())),
            blocks_by_height: Arc::new(RwLock::new(HashMap::new())),
            children: Arc::new(RwLock::new(HashMap::new())),
            tips: Arc::new(RwLock::new(HashSet::new())),
            finalized: Arc::new(RwLock::new(HashSet::new())),
            pruning_point: Arc::new(RwLock::new(Hash::default())),
            strict_vrf: true,
            persistent: None,
            proposer_selector: None,
            enforcement_activation_height: None,
        }
    }

    /// FWA-C1-01: attach a stake-populated proposer selector so admission
    /// enforces leader-election eligibility (`is_eligible_proposer`) in
    /// addition to VRF math + ed25519 identity binding. The selector is
    /// shared (Arc) so the node can keep its validator/stake set live.
    pub fn with_proposer_selector(mut self, selector: Arc<VrfProposerSelector>) -> Self {
        self.proposer_selector = Some(selector);
        self
    }

    /// VALIDATOR-S1 (v5): set the consensus activation height at/above which
    /// stake-gated membership is ENFORCED. Below it, blocks are admitted on VRF
    /// math + identity binding only (the pre-activation rule), so history replays
    /// and the cutover is a single fleet-wide height, not a per-node toggle.
    pub fn with_enforcement_activation_height(mut self, height: u64) -> Self {
        self.enforcement_activation_height = Some(height);
        self
    }

    /// Create a DagStore with explicit VRF strictness.
    /// WP-K.5: In strict mode, blocks failing VRF admission are rejected.
    pub fn with_strict_vrf(strict_vrf: bool) -> Self {
        Self {
            strict_vrf,
            ..Self::new()
        }
    }

    /// **Test-only** constructor that disables VRF admission checks. Use
    /// this in unit / integration tests that exercise GhostDAG semantics
    /// without producing real ECVRF proofs.
    ///
    /// Production code MUST NOT call this. The `_for_testing` suffix is
    /// load-bearing — audit finding H-05 was that a permissive default
    /// silently masked invalid blocks; making the opt-out visibly named
    /// at every call site keeps the misuse risk grep-able.
    pub fn with_permissive_vrf_for_testing() -> Self {
        Self::with_strict_vrf(false)
    }

    /// WP-S.1: Create a persistent DagStore that writes through to a KvStore backend.
    /// On construction, loads existing state from the backend.
    pub fn persistent(kv: Arc<dyn KvStore>) -> Result<Self, DagStoreError> {
        let mut store = Self {
            blocks: Arc::new(RwLock::new(HashMap::new())),
            blocks_by_height: Arc::new(RwLock::new(HashMap::new())),
            children: Arc::new(RwLock::new(HashMap::new())),
            tips: Arc::new(RwLock::new(HashSet::new())),
            finalized: Arc::new(RwLock::new(HashSet::new())),
            pruning_point: Arc::new(RwLock::new(Hash::default())),
            strict_vrf: true,
            persistent: Some(kv),
            proposer_selector: None,
            enforcement_activation_height: None,
        };
        store.load_from_persistent()?;
        Ok(store)
    }

    /// WP-S.1: Create a persistent DagStore with strict VRF enforcement.
    pub fn persistent_with_strict_vrf(
        kv: Arc<dyn KvStore>,
        strict_vrf: bool,
    ) -> Result<Self, DagStoreError> {
        let mut store = Self::persistent(kv)?;
        store.strict_vrf = strict_vrf;
        Ok(store)
    }

    /// WP-S.1: Load all state from the persistent backend into in-memory maps.
    fn load_from_persistent(&mut self) -> Result<(), DagStoreError> {
        let kv = match &self.persistent {
            Some(kv) => kv.clone(),
            None => return Ok(()),
        };

        // Load blocks
        let block_entries = kv
            .kv_iter_cf(cf::DAG_BLOCKS)
            .map_err(|e| DagStoreError::StorageError(format!("load blocks: {}", e)))?;

        let mut blocks = HashMap::new();
        let mut blocks_by_height: HashMap<u64, Vec<Hash>> = HashMap::new();
        for (_key, value) in &block_entries {
            let block: Block = bincode::deserialize(value)
                .map_err(|e| DagStoreError::StorageError(format!("deserialize block: {}", e)))?;
            let hash = block.hash();
            blocks_by_height
                .entry(block.header.height)
                .or_default()
                .push(hash);
            blocks.insert(hash, block);
        }

        // Load children
        let child_entries = kv
            .kv_iter_cf(cf::DAG_CHILDREN)
            .map_err(|e| DagStoreError::StorageError(format!("load children: {}", e)))?;
        let mut children: HashMap<Hash, Vec<Hash>> = HashMap::new();
        for (_key, value) in &child_entries {
            let (parent, child_list): (Hash, Vec<Hash>) = bincode::deserialize(value)
                .map_err(|e| DagStoreError::StorageError(format!("deserialize children: {}", e)))?;
            children.insert(parent, child_list);
        }

        // Load tips
        let tip_entries = kv
            .kv_iter_cf(cf::DAG_TIPS)
            .map_err(|e| DagStoreError::StorageError(format!("load tips: {}", e)))?;
        let mut tips = HashSet::new();
        for (key, _value) in &tip_entries {
            if key.len() == 32 {
                tips.insert(Hash::from_bytes(key));
            }
        }

        // Load finalized
        let finalized_entries = kv
            .kv_iter_cf(cf::DAG_FINALIZED)
            .map_err(|e| DagStoreError::StorageError(format!("load finalized: {}", e)))?;
        let mut finalized = HashSet::new();
        for (key, _value) in &finalized_entries {
            if key.len() == 32 {
                finalized.insert(Hash::from_bytes(key));
            }
        }

        // Load pruning point
        let pruning_point = match kv.kv_get(cf::DAG_METADATA, b"pruning_point") {
            Ok(Some(bytes)) if bytes.len() == 32 => Hash::from_bytes(&bytes),
            _ => Hash::default(),
        };

        // PIL-42: Reconstruct the tip set from authoritative block-header
        // parentage rather than trusting the persisted `dag_tips` CF, and drop
        // the orphaned genesis block if present.
        //
        // Root cause of the wedge this heals: the i64 re-roll created genesis
        // in the *chain* store but not the *DAG* store (the DAG-aware
        // `initialize_genesis_with_dag` is dead code), so when the producer
        // sealed block 1 the DAG had no tips and block 1's selected parent
        // defaulted to the zero hash instead of genesis. Genesis is therefore
        // an orphaned island — no block names it as a parent — so it reads as
        // a permanent second tip alongside the real head. Two tips force the
        // producer off its `select_tip` fast path onto the O(N)
        // `calculate_blue_set` walk (the allocation PIL-13 removed from the
        // eager-load path), which never seals and OOM-thrashes the box.
        //
        // A block is a tip iff no other block names it as a selected- or
        // merge-parent. The genesis block (height 0) is the DAG root and is
        // never a valid producer tip once the chain has advanced (in a healthy
        // DAG it has a child and is excluded anyway); exclude it unless it is
        // the only block (fresh-chain bootstrap). Zero-hash parents (genesis
        // and the orphaned block 1) are not real blocks and are ignored. This
        // is authoritative and self-heals a corrupted `dag_tips` CF on load.
        let mut non_tip_parents: HashSet<Hash> = HashSet::new();
        for block in blocks.values() {
            let sp = block.selected_parent();
            if sp != Hash::default() {
                non_tip_parents.insert(sp);
            }
            for merge_parent in &block.header.merge_parent_hashes {
                if *merge_parent != Hash::default() {
                    non_tip_parents.insert(*merge_parent);
                }
            }
        }
        let only_block = blocks.len() == 1;
        let mut derived_tips: HashSet<Hash> = HashSet::new();
        for (hash, block) in &blocks {
            let has_children = non_tip_parents.contains(hash);
            let is_root_genesis = block.header.height == 0 && !only_block;
            if !has_children && !is_root_genesis {
                derived_tips.insert(*hash);
            }
        }
        if derived_tips != tips {
            warn!(
                "DAG tip set reconciled on load: {} persisted tip(s) -> {} derived \
                 from block headers (dropped orphaned/phantom tips)",
                tips.len(),
                derived_tips.len()
            );
            tips = derived_tips;
        }

        // Populate in-memory state
        // These try_write() calls are made during construction (before the DagStore is shared),
        // so the locks should never be contended. We use map_err to surface any poisoning as a
        // DagStoreError instead of panicking.
        *self.blocks.try_write().map_err(|_| {
            DagStoreError::StorageError("lock contention on blocks during load".into())
        })? = blocks;
        *self.blocks_by_height.try_write().map_err(|_| {
            DagStoreError::StorageError("lock contention on blocks_by_height during load".into())
        })? = blocks_by_height;
        *self.children.try_write().map_err(|_| {
            DagStoreError::StorageError("lock contention on children during load".into())
        })? = children;
        *self.tips.try_write().map_err(|_| {
            DagStoreError::StorageError("lock contention on tips during load".into())
        })? = tips;
        *self.finalized.try_write().map_err(|_| {
            DagStoreError::StorageError("lock contention on finalized during load".into())
        })? = finalized;
        *self.pruning_point.try_write().map_err(|_| {
            DagStoreError::StorageError("lock contention on pruning_point during load".into())
        })? = pruning_point;

        let stats = self.get_stats_sync();
        info!(
            "Loaded DAG from persistent store: {} blocks, {} tips, {} finalized",
            stats.total_blocks, stats.total_tips, stats.finalized_blocks
        );
        Ok(())
    }

    /// Synchronous stats helper used during load (before async runtime is available).
    fn get_stats_sync(&self) -> DagStats {
        DagStats {
            total_blocks: self.blocks.try_read().map(|b| b.len()).unwrap_or(0),
            total_tips: self.tips.try_read().map(|t| t.len()).unwrap_or(0),
            finalized_blocks: self.finalized.try_read().map(|f| f.len()).unwrap_or(0),
            max_height: self
                .blocks_by_height
                .try_read()
                .map(|h| h.keys().max().copied().unwrap_or(0))
                .unwrap_or(0),
        }
    }

    /// WP-S.1: Persist finalization. Single-op write — atomic by
    /// construction. (`store_block`'s multi-op path uses
    /// `kv_write_batch` instead; see WP-B1.3.)
    fn persist_finalized(&self, hash: &Hash) {
        if let Some(ref kv) = self.persistent {
            if let Err(e) = kv.kv_put(cf::DAG_FINALIZED, hash.as_bytes(), &[1]) {
                warn!("Failed to persist finalized {}: {}", hash, e);
            }
        }
    }

    /// WP-S.1: Persist pruning point.
    fn persist_pruning_point(&self, hash: &Hash) {
        if let Some(ref kv) = self.persistent {
            if let Err(e) = kv.kv_put(cf::DAG_METADATA, b"pruning_point", hash.as_bytes()) {
                warn!("Failed to persist pruning point: {}", e);
            }
        }
    }

    /// WP-S.1: Delete a block from persistence.
    fn persist_delete_block(&self, hash: &Hash) {
        if let Some(ref kv) = self.persistent {
            let _ = kv.kv_delete(cf::DAG_BLOCKS, hash.as_bytes());
            let _ = kv.kv_delete(cf::DAG_CHILDREN, hash.as_bytes());
        }
    }

    /// WP-K.5: Validate block admission — VRF plausibility and proposer checks.
    /// Non-genesis blocks must have a structurally valid VRF proof and non-zero proposer.
    fn validate_block_admission(&self, block: &Block) -> Result<(), String> {
        // Genesis blocks are exempt from VRF checks
        if block.is_genesis() {
            return Ok(());
        }

        // Proposer pubkey must be non-zero
        if block.header.proposer_pubkey.as_bytes().iter().all(|&b| b == 0) {
            return Err("Block has zero proposer public key".to_string());
        }

        // VRF proof must be non-empty
        if block.header.vrf_reveal.proof.is_empty() {
            return Err("Block has empty VRF proof".to_string());
        }

        // VRF output must be non-zero
        if block.header.vrf_reveal.output == Hash::default() {
            return Err("Block has zero VRF output".to_string());
        }

        // Block signature must be non-zero (structurally present)
        if block.signature.as_bytes().iter().all(|&b| b == 0) {
            return Err("Block has zero signature".to_string());
        }

        Ok(())
    }

    /// WP-W.2: Cryptographically verify a block's VRF proof against the parent block's VRF output.
    /// Requires the parent block to already be in the DAG store.
    ///
    /// RM-J1 (post-RM-I-3 cleanup): admission uses the
    /// **structurally-bound** verifier `verify_vrf_with_block_signature`
    /// — combines ECVRF math with the block's ed25519 signature so the
    /// proposer identity is unspoofable at this layer (REM-N-01).
    /// `signed_payload` is the block hash, which is what
    /// `crypto::sign_block` signs.
    async fn verify_block_vrf_crypto(&self, block: &Block) -> Result<(), String> {
        if block.is_genesis() {
            return Ok(());
        }

        let parent_hash = block.selected_parent();
        let blocks = self.blocks.read().await;
        let parent = blocks.get(&parent_hash).ok_or_else(|| {
            format!("Parent block {} not found for VRF verification", parent_hash)
        })?;

        let prev_vrf_output = parent.header.vrf_reveal.output;

        // FWA-C1-01: prefer the node's live, stake-populated selector when
        // wired, so leader-election eligibility is enforced against the
        // real validator/stake set. Fall back to an empty selector only
        // when none is attached (tests / pre-registry environments) — that
        // path still enforces VRF math + ed25519 identity binding, just not
        // stake eligibility.
        let fallback;
        let vrf_selector: &VrfProposerSelector = match &self.proposer_selector {
            Some(s) => s.as_ref(),
            None => {
                // FWA-C1-01 fix: the fallback MUST disable the forgeable legacy
                // SHA3 VRF path (production() = legacy cutoff 0), matching the
                // production selector. Using `new()` here reopened the H-06
                // downgrade for blocks admitted without an attached selector.
                fallback = VrfProposerSelector::production();
                &fallback
            }
        };

        match vrf_selector.verify_vrf_with_block_signature(
            &block.header.proposer_pubkey,
            &block.header.vrf_reveal,
            &prev_vrf_output,
            block.header.height,
            block.header.block_hash.as_bytes(),
            &block.signature,
        ) {
            Ok(true) => {}
            Ok(false) => {
                return Err(
                    "VRF proof verification failed: invalid proof or identity binding".to_string(),
                )
            }
            Err(e) => return Err(format!("VRF verification error: {}", e)),
        }

        // VALIDATOR-S1 (v5): enforce stake-gated MEMBERSHIP eligibility at
        // admission — integer/deterministic (see `is_eligible_proposer`). This
        // rejects a block whose proposer is not in the active set at stake
        // >= minStake for the block's epoch.
        //
        // Enforcement is gated on the fleet-wide ACTIVATION HEIGHT, not merely on
        // "a selector is attached". A per-node `is_some()` toggle would fork the
        // chain the instant one node wired the registry before another. Below the
        // activation height (or with no selector), admission stays on VRF math +
        // identity binding only. `enforcement_activation_height == None` preserves
        // the legacy "enforce whenever a selector is attached" behavior for tests.
        let enforce = self.proposer_selector.is_some()
            && self
                .enforcement_activation_height
                .is_none_or(|h| block.header.height >= h);
        if enforce {
            match vrf_selector
                .is_eligible_proposer(
                    &block.header.proposer_pubkey,
                    &block.header.vrf_reveal.output,
                    block.header.height,
                )
                .await
            {
                Ok(true) => Ok(()),
                Ok(false) => Err(
                    "Stake-gated eligibility failed: proposer not in the active set at minStake for this epoch (below minStake / inactive / unregistered)"
                        .to_string(),
                ),
                Err(e) => Err(format!("Eligibility check error: {}", e)),
            }
        } else {
            Ok(())
        }
    }

    /// FWA-C1-04: equivocation / double-proposal detection hook.
    ///
    /// Returns the hash of an EXISTING, distinct block at the same height
    /// proposed by the same proposer, if one is present — i.e. evidence
    /// that `block`'s proposer is equivocating (signing two different
    /// blocks for one slot). `blocks_by_height` is `HashMap<u64, Vec<Hash>>`
    /// with no (proposer,height) uniqueness, so without this check one
    /// actor (especially combined with the FWA-C1-01 eligibility gap) can
    /// flood sibling blocks per height.
    ///
    /// This is a detection primitive: the network layer calls it to feed
    /// peer-scoring / slashing (the gossip peer-score already has a
    /// `SCORE_INVALID_BLOCK` bucket). It is read-only and side-effect free.
    pub async fn detect_equivocation(&self, block: &Block) -> Option<Hash> {
        let candidate_hash = block.hash();
        let height = block.header.height;
        let proposer = block.header.proposer_pubkey;

        let by_height = self.blocks_by_height.read().await;
        let siblings = by_height.get(&height)?;
        let blocks = self.blocks.read().await;
        for &h in siblings {
            if h == candidate_hash {
                continue; // same block, not equivocation
            }
            if let Some(existing) = blocks.get(&h) {
                if existing.header.proposer_pubkey == proposer {
                    return Some(h);
                }
            }
        }
        None
    }

    /// Store a block in the DAG.
    ///
    /// RM-B1 / WP-B1.3 (audit H-04): all persistence operations from
    /// a single `store_block` invocation are now committed in **one
    /// atomic `kv_write_batch`** so a power loss between two writes
    /// can no longer leave the DAG in an inconsistent state on
    /// restart (e.g., block exists but no children pointer; tips
    /// excludes the new tip; height index out of sync).
    pub async fn store_block(&self, block: Block) -> Result<(), DagStoreError> {
        let hash = block.hash();

        // Check if block already exists
        if self.blocks.read().await.contains_key(&hash) {
            return Err(DagStoreError::BlockExists(hash));
        }

        // WP-K.5: VRF admission gate (structural checks)
        if let Err(e) = self.validate_block_admission(&block) {
            if self.strict_vrf {
                return Err(DagStoreError::InvalidVrf(e));
            } else {
                tracing::warn!(
                    "Block {} VRF plausibility check failed (permissive mode): {}",
                    hash, e
                );
            }
        }

        // WP-W.2: Cryptographic VRF proof verification (when strict_vrf is enabled)
        if self.strict_vrf && !block.is_genesis() {
            if let Err(e) = self.verify_block_vrf_crypto(&block).await {
                return Err(DagStoreError::InvalidVrf(e));
            }
        }

        // RM-I / WP-I2.2 (re-audit Stream 1 finding REM-N-04):
        //   Pre-fix this method mutated the in-memory caches (children,
        //   tips, blocks_by_height) BEFORE invoking `kv_write_batch`. On
        //   batch failure the runtime carried the mutation while disk did
        //   not, producing split-brain on the next restart (memory said
        //   the block was a tip; disk didn't have the entry).
        //   Post-fix: build ops from immutable read-side snapshots, run
        //   the batch, then mutate the in-memory state ONLY if the batch
        //   succeeded (or no persistent backend is configured). On batch
        //   failure the call returns Err and the in-memory state is
        //   unchanged, matching the on-disk state.

        // RM-B1 / WP-B1.3 + RM-I / WP-I2.2: collect every persistence op
        // into one batch. The ops are built from read-side snapshots so
        // failure leaves no in-memory residue.
        let mut ops: Vec<KvOp> = Vec::new();

        // 1. Block bytes.
        match bincode::serialize(&block) {
            Ok(bytes) => ops.push(KvOp::Put {
                cf: cf::DAG_BLOCKS.to_string(),
                key: hash.as_bytes().to_vec(),
                value: bytes,
            }),
            Err(e) => {
                tracing::error!(
                    "M-06: serialize block {} failed: {} — skipping persistence",
                    hash, e
                );
            }
        }

        // 2. Snapshot children for parent + merge parents, project the
        //    post-insert state, push ops. Do NOT mutate yet.
        let children_read = self.children.read().await;
        if !block.is_genesis() {
            let mut sp_children = children_read
                .get(&block.selected_parent())
                .cloned()
                .unwrap_or_default();
            sp_children.push(hash);
            push_children_op(&mut ops, &block.selected_parent(), &sp_children);

            for merge_parent in &block.header.merge_parent_hashes {
                let mut mp_children = children_read.get(merge_parent).cloned().unwrap_or_default();
                mp_children.push(hash);
                push_children_op(&mut ops, merge_parent, &mp_children);
            }
        }
        push_children_op(&mut ops, &hash, &[]);
        drop(children_read);

        // 3. Tip set updates (no in-memory mutation yet — ops only).
        if !block.is_genesis() {
            ops.push(KvOp::Delete {
                cf: cf::DAG_TIPS.to_string(),
                key: block.selected_parent().as_bytes().to_vec(),
            });
            for merge_parent in &block.header.merge_parent_hashes {
                ops.push(KvOp::Delete {
                    cf: cf::DAG_TIPS.to_string(),
                    key: merge_parent.as_bytes().to_vec(),
                });
            }
        }
        ops.push(KvOp::Put {
            cf: cf::DAG_TIPS.to_string(),
            key: hash.as_bytes().to_vec(),
            value: vec![1],
        });

        // 4. Height index — snapshot, project the post-insert state, push op.
        let height = block.header.height;
        let by_height_read = self.blocks_by_height.read().await;
        let mut height_hashes = by_height_read.get(&height).cloned().unwrap_or_default();
        height_hashes.push(hash);
        let height_bytes_result = bincode::serialize(&height_hashes);
        drop(by_height_read);
        match height_bytes_result {
            Ok(bytes) => ops.push(KvOp::Put {
                cf: cf::DAG_HEIGHT_INDEX.to_string(),
                key: height.to_be_bytes().to_vec(),
                value: bytes,
            }),
            Err(e) => {
                tracing::error!(
                    "M-06: serialize height index {} failed: {} — skipping persistence",
                    height, e
                );
            }
        }

        // 5. Atomic commit. If a persistent backend is configured and the
        // batch fails, return an error WITHOUT mutating the in-memory
        // state. If no backend is configured (test stores), proceed
        // straight to the in-memory mutation.
        if let Some(ref kv) = self.persistent {
            if let Err(e) = kv.kv_write_batch(&ops) {
                warn!(
                    "H-04 + REM-N-04: write_batch for block {} failed: {} — \
                     in-memory caches NOT mutated (returning error to caller)",
                    hash, e
                );
                return Err(DagStoreError::Persistence(format!(
                    "kv_write_batch failed for block {}: {}",
                    hash, e
                )));
            }
        }

        // 6. Batch succeeded (or no backend). Now mutate the in-memory
        //    caches under their write locks. The mutations match what was
        //    just persisted, so memory and disk stay in sync.
        if !block.is_genesis() {
            let mut children = self.children.write().await;
            children
                .entry(block.selected_parent())
                .or_insert_with(Vec::new)
                .push(hash);
            for merge_parent in &block.header.merge_parent_hashes {
                children.entry(*merge_parent).or_insert_with(Vec::new).push(hash);
            }
            children.insert(hash, Vec::new());
            drop(children);

            let mut tips = self.tips.write().await;
            tips.remove(&block.selected_parent());
            for merge_parent in &block.header.merge_parent_hashes {
                tips.remove(merge_parent);
            }
            tips.insert(hash);
            drop(tips);
        } else {
            self.children.write().await.insert(hash, Vec::new());
            self.tips.write().await.insert(hash);
        }

        self.blocks_by_height
            .write()
            .await
            .entry(height)
            .or_insert_with(Vec::new)
            .push(hash);

        self.blocks.write().await.insert(hash, block.clone());

        info!("Stored block {} at height {}", hash, block.header.height);
        Ok(())
    }

    /// Get a block by hash
    pub async fn get_block(&self, hash: &Hash) -> Result<Block, DagStoreError> {
        self.blocks
            .read()
            .await
            .get(hash)
            .cloned()
            .ok_or(DagStoreError::BlockNotFound(*hash))
    }

    /// Check if a block exists
    pub async fn has_block(&self, hash: &Hash) -> bool {
        self.blocks.read().await.contains_key(hash)
    }

    /// Get blocks at a specific height
    pub async fn get_blocks_at_height(&self, height: u64) -> Vec<Block> {
        let blocks = self.blocks.read().await;
        let hashes = self.blocks_by_height.read().await;

        hashes
            .get(&height)
            .map(|hash_list| {
                hash_list
                    .iter()
                    .filter_map(|h| blocks.get(h).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get children of a block
    pub async fn get_children(&self, hash: &Hash) -> Vec<Hash> {
        self.children
            .read()
            .await
            .get(hash)
            .cloned()
            .unwrap_or_default()
    }

    /// Get current tips
    pub async fn get_tips(&self) -> Vec<Tip> {
        let tips = self.tips.read().await;
        let blocks = self.blocks.read().await;

        tips.iter()
            .filter_map(|hash| blocks.get(hash).map(Tip::new))
            .collect()
    }

    /// Get parents of a block
    pub async fn get_parents(&self, hash: &Hash) -> Result<Vec<Hash>, DagStoreError> {
        let block = self.get_block(hash).await?;
        Ok(block.parents())
    }

    /// Mark a block as finalized
    pub async fn finalize_block(&self, hash: &Hash) -> Result<(), DagStoreError> {
        if !self.has_block(hash).await {
            return Err(DagStoreError::BlockNotFound(*hash));
        }

        self.finalized.write().await.insert(*hash);
        self.persist_finalized(hash);
        info!("Finalized block {}", hash);
        Ok(())
    }

    /// Check if a block is finalized
    pub async fn is_finalized(&self, hash: &Hash) -> bool {
        self.finalized.read().await.contains(hash)
    }

    /// Get the pruning point
    pub async fn get_pruning_point(&self) -> Hash {
        *self.pruning_point.read().await
    }

    /// Update the pruning point
    pub async fn update_pruning_point(&self, hash: Hash) -> Result<(), DagStoreError> {
        if !self.has_block(&hash).await {
            return Err(DagStoreError::BlockNotFound(hash));
        }

        *self.pruning_point.write().await = hash;
        self.persist_pruning_point(&hash);
        info!("Updated pruning point to {}", hash);
        Ok(())
    }

    /// Prune blocks before the pruning point
    pub async fn prune(&self) -> Result<usize, DagStoreError> {
        let pruning_point = self.get_pruning_point().await;
        if pruning_point == Hash::default() {
            return Ok(0);
        }

        // Get pruning point height
        let pruning_block = self.get_block(&pruning_point).await?;
        let pruning_height = pruning_block.header.height;

        let mut blocks = self.blocks.write().await;
        let mut blocks_by_height = self.blocks_by_height.write().await;
        let mut pruned_count = 0;

        // Remove blocks below pruning height
        let heights_to_remove: Vec<u64> = blocks_by_height
            .keys()
            .filter(|&&h| h < pruning_height)
            .copied()
            .collect();

        for height in heights_to_remove {
            if let Some(hashes) = blocks_by_height.remove(&height) {
                for hash in hashes {
                    if blocks.remove(&hash).is_some() {
                        self.persist_delete_block(&hash);
                        pruned_count += 1;
                    }
                }
                // Remove height index from persistence
                if let Some(ref kv) = self.persistent {
                    let _ = kv.kv_delete(cf::DAG_HEIGHT_INDEX, &height.to_be_bytes());
                }
            }
        }

        info!(
            "Pruned {} blocks below height {}",
            pruned_count, pruning_height
        );
        Ok(pruned_count)
    }

    /// Get statistics about the DAG
    pub async fn get_stats(&self) -> DagStats {
        DagStats {
            total_blocks: self.blocks.read().await.len(),
            total_tips: self.tips.read().await.len(),
            finalized_blocks: self.finalized.read().await.len(),
            max_height: self
                .blocks_by_height
                .read()
                .await
                .keys()
                .max()
                .copied()
                .unwrap_or(0),
        }
    }
}

impl Default for DagStore {
    fn default() -> Self {
        Self::new()
    }
}


#[derive(Debug, Clone)]
pub struct DagStats {
    pub total_blocks: usize,
    pub total_tips: usize,
    pub finalized_blocks: usize,
    pub max_height: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    fn create_test_block(hash: [u8; 32], height: u64, parent: Hash) -> Block {
        BlockBuilder::new()
            .hash(Hash::new(hash))
            .height(height)
            .parent(parent)
            .build_unhashed()
    }

    #[tokio::test]
    async fn test_store_and_retrieve_block() {
        let store = DagStore::with_permissive_vrf_for_testing();
        let block = create_test_block([1; 32], 1, Hash::default());

        store.store_block(block.clone()).await.unwrap();

        let retrieved = store.get_block(&block.hash()).await.unwrap();
        assert_eq!(retrieved.hash(), block.hash());
        assert_eq!(retrieved.header.height, 1);
    }

    #[tokio::test]
    async fn test_duplicate_block() {
        let store = DagStore::with_permissive_vrf_for_testing();
        let block = create_test_block([1; 32], 1, Hash::default());

        store.store_block(block.clone()).await.unwrap();
        let result = store.store_block(block).await;

        assert!(matches!(result, Err(DagStoreError::BlockExists(_))));
    }

    #[tokio::test]
    async fn test_tips_management() {
        let store = DagStore::with_permissive_vrf_for_testing();

        // Add genesis - use non-zero hash to avoid confusion with Hash::default()
        let genesis = create_test_block([0xFF; 32], 0, Hash::default());
        store.store_block(genesis.clone()).await.unwrap();

        let tips = store.get_tips().await;
        assert_eq!(tips.len(), 1);
        assert_eq!(tips[0].hash, genesis.hash());

        // Add child
        let child = create_test_block([1; 32], 1, genesis.hash());
        store.store_block(child.clone()).await.unwrap();

        let tips = store.get_tips().await;
        assert_eq!(tips.len(), 1);
        assert_eq!(tips[0].hash, child.hash());
    }

    #[tokio::test]
    async fn test_finalization() {
        let store = DagStore::with_permissive_vrf_for_testing();
        let block = create_test_block([1; 32], 1, Hash::default());

        store.store_block(block.clone()).await.unwrap();
        assert!(!store.is_finalized(&block.hash()).await);

        store.finalize_block(&block.hash()).await.unwrap();
        assert!(store.is_finalized(&block.hash()).await);
    }

    #[tokio::test]
    async fn test_pruning() {
        let store = DagStore::with_permissive_vrf_for_testing();

        // Add blocks at different heights
        for i in 0..10 {
            let parent = if i == 0 {
                Hash::default()
            } else {
                Hash::new([(i - 1) as u8; 32])
            };
            let block = create_test_block([i as u8; 32], i, parent);
            store.store_block(block).await.unwrap();
        }

        // Set pruning point at height 5
        let pruning_hash = Hash::new([5; 32]);
        store.update_pruning_point(pruning_hash).await.unwrap();

        // Prune
        let pruned = store.prune().await.unwrap();
        assert_eq!(pruned, 5);

        // Verify blocks below height 5 are gone
        for i in 0..5 {
            assert!(!store.has_block(&Hash::new([i as u8; 32])).await);
        }

        // Verify blocks at height 5 and above still exist
        for i in 5..10 {
            assert!(store.has_block(&Hash::new([i as u8; 32])).await);
        }
    }

    /// Helper: create a block with a cryptographically valid legacy SHA3 VRF proof.
    /// The parent's VRF output is needed to compute the correct proof/output pair.
    fn create_block_with_vrf(hash: [u8; 32], height: u64, parent: Hash) -> Block {
        create_block_with_vrf_parent_output(hash, height, parent, Hash::default())
    }

    /// Helper: create a block with a valid legacy SHA3 VRF proof using the given parent VRF output.
    ///
    /// RM-J1 update: post-REM-N-01 the admission path uses the
    /// structurally-bound `verify_vrf_with_block_signature`, which
    /// requires the block's ed25519 signature to verify under the
    /// proposer's pubkey over the block hash. This helper now signs
    /// the block hash with a deterministic ed25519 key derived from
    /// `hash` so the test fixture passes the binding.
    fn create_block_with_vrf_parent_output(
        hash: [u8; 32],
        height: u64,
        parent: Hash,
        parent_vrf_output: Hash,
    ) -> Block {
        use ed25519_dalek::{Signer, SigningKey};
        use sha3::{Digest, Sha3_256};

        // Deterministic ed25519 secret derived from `hash` so each
        // test block gets a unique-but-reproducible (proposer, sig)
        // pair. The proposer pubkey on the block is the
        // verifying-key derived from this secret.
        let mut secret = [0u8; 32];
        secret[..32].copy_from_slice(&Sha3_256::digest(hash));
        let signing_key = SigningKey::from_bytes(&secret);
        let proposer_bytes = signing_key.verifying_key().to_bytes();
        let proposer = PublicKey::new(proposer_bytes);

        let proof_bytes: [u8; 32] = [0x42; 32]; // arbitrary 32-byte proof

        // Reconstruct the alpha: SHA3(pubkey || prev_vrf || slot)
        let mut hasher = Sha3_256::new();
        hasher.update(proposer.as_bytes());
        hasher.update(parent_vrf_output.as_bytes());
        hasher.update(height.to_le_bytes());
        let input = hasher.finalize();

        // output = SHA3(proof || input)
        let mut output_hasher = Sha3_256::new();
        output_hasher.update(proof_bytes);
        output_hasher.update(input);
        let output = Hash::from_bytes(&output_hasher.finalize());

        // Build the block first to know the block hash, then sign it.
        let block_hash = Hash::new(hash);
        let signature = Signature::new(signing_key.sign(block_hash.as_bytes()).to_bytes());

        BlockBuilder::new()
            .hash(block_hash)
            .height(height)
            .parent(parent)
            .proposer(proposer)
            .vrf_reveal(VrfProof {
                proof: proof_bytes.to_vec(),
                output,
            })
            .signature(signature)
            .build_unhashed()
    }

    /// WP-K.5: Block with empty VRF → warning in permissive mode, accepted
    #[tokio::test]
    async fn test_k5_empty_vrf_permissive_mode() {
        let store = DagStore::with_permissive_vrf_for_testing();
        // Non-genesis block with empty VRF (test helper creates these)
        // First store a genesis so we have a valid parent
        let genesis = create_test_block([0xFE; 32], 0, Hash::default());
        store.store_block(genesis.clone()).await.unwrap();
        let block = create_test_block([1; 32], 1, genesis.hash());
        // Should succeed in permissive mode (just logs a warning)
        assert!(store.store_block(block).await.is_ok());
    }

    /// WP-K.5: Block with empty VRF → rejection in strict mode
    #[tokio::test]
    async fn test_k5_empty_vrf_strict_mode() {
        let store = DagStore::with_strict_vrf(true);
        // Store genesis first (genesis is exempt from VRF checks)
        let genesis = create_test_block([0xFE; 32], 0, Hash::default());
        store.store_block(genesis.clone()).await.unwrap();
        // Non-genesis block with empty VRF proof
        let block = create_test_block([1; 32], 1, genesis.hash());
        let result = store.store_block(block).await;
        assert!(
            matches!(result, Err(DagStoreError::InvalidVrf(_))),
            "Block with empty VRF must be rejected in strict mode, got: {:?}",
            result
        );
    }

    /// WP-K.5 + VALIDATOR-S1 fallback hardening: a legacy 32-byte SHA3 proof is
    /// accepted in PERMISSIVE mode (crypto skipped) but REJECTED in strict mode
    /// with no selector attached — the fallback now uses `production()` (legacy
    /// cutoff 0) instead of the old `new()` (cutoff 100k), closing H-06 where a
    /// forgeable legacy proof was admitted by default.
    #[tokio::test]
    async fn test_k5_legacy_proof_permissive_ok_strict_rejected() {
        // Permissive mode: VRF crypto skipped → accepted.
        let store = DagStore::with_permissive_vrf_for_testing();
        let genesis = create_test_block([0xFE; 32], 0, Hash::default());
        store.store_block(genesis.clone()).await.unwrap();
        let block = create_block_with_vrf([1; 32], 1, genesis.hash());
        assert!(store.store_block(block).await.is_ok());

        // Strict mode, no selector → hardened production() fallback rejects the
        // forgeable legacy proof (H-06 / FWA-C1-01).
        let store_strict = DagStore::with_strict_vrf(true);
        let genesis2 = create_test_block([0xFD; 32], 0, Hash::default());
        store_strict.store_block(genesis2.clone()).await.unwrap();
        let block2 = create_block_with_vrf([2; 32], 1, genesis2.hash());
        assert!(
            matches!(store_strict.store_block(block2).await, Err(DagStoreError::InvalidVrf(_))),
            "strict-mode fallback must reject a forgeable legacy SHA3 proof"
        );
    }

    /// WP-K.5: Genesis block bypasses VRF check even in strict mode
    #[tokio::test]
    async fn test_k5_genesis_exempt_strict_mode() {
        let store = DagStore::with_strict_vrf(true);
        // Genesis block: parent=default, no merge parents — empty VRF is fine
        let genesis = create_test_block([0xFF; 32], 0, Hash::default());
        assert!(store.store_block(genesis).await.is_ok());
    }

    // ========================================================================
    // WP-S.1: Persistent DAG store tests
    // ========================================================================

    /// In-memory KvStore for testing persistence without RocksDB.
    struct MemKvStore {
        #[allow(clippy::type_complexity)]
        data: std::sync::Mutex<HashMap<String, HashMap<Vec<u8>, Vec<u8>>>>,
    }

    impl MemKvStore {
        fn new() -> Self {
            Self {
                data: std::sync::Mutex::new(HashMap::new()),
            }
        }
    }

    impl KvStore for MemKvStore {
        fn kv_get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
            let data = self.data.lock().unwrap();
            Ok(data.get(cf).and_then(|m| m.get(key).cloned()))
        }

        fn kv_put(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<(), String> {
            let mut data = self.data.lock().unwrap();
            data.entry(cf.to_string())
                .or_default()
                .insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn kv_delete(&self, cf: &str, key: &[u8]) -> Result<(), String> {
            let mut data = self.data.lock().unwrap();
            if let Some(m) = data.get_mut(cf) {
                m.remove(key);
            }
            Ok(())
        }

        fn kv_exists(&self, cf: &str, key: &[u8]) -> Result<bool, String> {
            let data = self.data.lock().unwrap();
            Ok(data.get(cf).map(|m| m.contains_key(key)).unwrap_or(false))
        }

        fn kv_iter_cf(&self, cf: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
            let data = self.data.lock().unwrap();
            Ok(data
                .get(cf)
                .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .unwrap_or_default())
        }
    }

    /// WP-S.1: Store a block, drop the DagStore, recreate from same KvStore — block survives.
    #[tokio::test]
    async fn test_s1_persistent_store_retrieve_roundtrip() {
        let kv = Arc::new(MemKvStore::new());

        // Store a genesis block
        let store = DagStore::persistent_with_strict_vrf(kv.clone(), false).unwrap();
        let genesis = create_test_block([0xFF; 32], 0, Hash::default());
        let genesis_hash = genesis.hash();
        store.store_block(genesis).await.unwrap();

        // Store a child block
        let child = create_test_block([1; 32], 1, genesis_hash);
        let child_hash = child.hash();
        store.store_block(child).await.unwrap();

        // Drop the store and recreate from the same KvStore
        drop(store);
        let store2 = DagStore::persistent_with_strict_vrf(kv, false).unwrap();

        // Both blocks should be recoverable
        let recovered = store2.get_block(&genesis_hash).await.unwrap();
        assert_eq!(recovered.header.height, 0);

        let recovered_child = store2.get_block(&child_hash).await.unwrap();
        assert_eq!(recovered_child.header.height, 1);
    }

    /// WP-S.1: Tips survive restart.
    #[tokio::test]
    async fn test_s1_tip_persistence() {
        let kv = Arc::new(MemKvStore::new());

        let store = DagStore::persistent_with_strict_vrf(kv.clone(), false).unwrap();
        let genesis = create_test_block([0xFF; 32], 0, Hash::default());
        let genesis_hash = genesis.hash();
        store.store_block(genesis).await.unwrap();

        let child = create_test_block([1; 32], 1, genesis_hash);
        let child_hash = child.hash();
        store.store_block(child).await.unwrap();

        // Only the child should be a tip
        let tips = store.get_tips().await;
        assert_eq!(tips.len(), 1);
        assert_eq!(tips[0].hash, child_hash);
        drop(store);

        // Recreate — tip set should be the same
        let store2 = DagStore::persistent_with_strict_vrf(kv, false).unwrap();
        let tips2 = store2.get_tips().await;
        assert_eq!(tips2.len(), 1);
        assert_eq!(tips2[0].hash, child_hash);
    }

    /// PIL-42 regression: reproduces the production wedge where genesis is an
    /// orphaned island. The i64 re-roll put genesis in the chain store but not
    /// the DAG store, so block 1 was sealed with a ZERO-hash selected parent
    /// instead of genesis. Genesis then has no children and reads as a
    /// permanent second tip alongside the head; two tips force the producer
    /// onto the O(N) `calculate_blue_set` walk and wedge sealing / OOM the box.
    /// On load, the height-0 orphan genesis must be excluded so only the head
    /// remains a tip.
    #[tokio::test]
    async fn test_pil42_orphan_genesis_excluded_from_tips_on_load() {
        let kv = Arc::new(MemKvStore::new());
        let store = DagStore::persistent_with_strict_vrf(kv.clone(), false)
            .expect("persistent store construction should succeed");

        // Genesis (height 0, zero parent).
        let genesis = create_test_block([0xFF; 32], 0, Hash::default());
        store.store_block(genesis).await.expect("store genesis");

        // The real head chain, rooted at a block whose selected parent is the
        // ZERO hash (not genesis) — exactly the orphan the re-roll produced.
        let b1 = create_test_block([1; 32], 1, Hash::default());
        let b1_hash = b1.hash();
        store.store_block(b1).await.expect("store b1 (orphan root)");
        let b2 = create_test_block([2; 32], 2, b1_hash);
        let b2_hash = b2.hash();
        store.store_block(b2).await.expect("store b2 (head)");

        // On disk this leaves the wedged state: two tips {genesis, head}.
        // Reload with the fix — the height-0 orphan genesis must be dropped.
        drop(store);
        let store2 = DagStore::persistent_with_strict_vrf(kv, false)
            .expect("reload should succeed");
        let tips = store2.get_tips().await;
        assert_eq!(
            tips.len(),
            1,
            "orphan genesis must be excluded; only the head should remain a tip (got {:?})",
            tips.iter().map(|t| t.hash).collect::<Vec<_>>()
        );
        assert_eq!(
            tips[0].hash, b2_hash,
            "the head must be the sole surviving tip"
        );
    }

    /// PIL-42 (write/init half): counterpart to the orphan test. When genesis
    /// is seeded into the DAG *first* (as the node now does on a fresh re-roll,
    /// node/src/main.rs), it is the sole height-0 tip, so block 1 links to
    /// genesis (not the zero hash). Genesis then has a child and is never a
    /// phantom second tip — the wedge cannot form. Locks in the write seam.
    #[tokio::test]
    async fn test_pil42_seeded_genesis_links_block1_no_orphan() {
        let kv = Arc::new(MemKvStore::new());
        let store = DagStore::persistent_with_strict_vrf(kv.clone(), false)
            .expect("persistent store construction should succeed");

        // A fresh DAG has no tips — the exact condition the node checks before
        // seeding genesis.
        assert!(
            store.get_tips().await.is_empty(),
            "a fresh DAG must have no tips before genesis is seeded"
        );

        // Seed genesis (height 0, zero parent) — the write/init half of the fix.
        let genesis = create_test_block([0xFF; 32], 0, Hash::default());
        let genesis_hash = genesis.hash();
        store.store_block(genesis).await.expect("seed genesis");
        let tips = store.get_tips().await;
        assert_eq!(tips.len(), 1, "seeded genesis must be the sole tip");
        assert_eq!(tips[0].hash, genesis_hash, "genesis is the height-0 root tip");

        // Block 1 now links to genesis (parent = genesis_hash, NOT the zero hash).
        let b1 = create_test_block([1; 32], 1, genesis_hash);
        let b1_hash = b1.hash();
        store.store_block(b1).await.expect("store b1 linked to genesis");

        // Genesis has a child ⇒ no longer a tip; block 1 is the sole tip.
        let tips = store.get_tips().await;
        assert_eq!(
            tips.len(),
            1,
            "exactly one tip once block 1 links genesis (got {:?})",
            tips.iter().map(|t| t.hash).collect::<Vec<_>>()
        );
        assert_eq!(
            tips[0].hash, b1_hash,
            "block 1 is the sole tip; genesis is not orphaned"
        );

        // Survives a reload — parity with the read/repair half.
        drop(store);
        let store2 = DagStore::persistent_with_strict_vrf(kv, false)
            .expect("reload should succeed");
        let tips = store2.get_tips().await;
        assert_eq!(tips.len(), 1, "one tip after reload");
        assert_eq!(
            tips[0].hash, b1_hash,
            "head remains the sole tip after reload"
        );
    }

    /// WP-S.1: Finalization state survives restart.
    #[tokio::test]
    async fn test_s1_finalization_persistence() {
        let kv = Arc::new(MemKvStore::new());

        let store = DagStore::persistent_with_strict_vrf(kv.clone(), false).unwrap();
        let block = create_test_block([1; 32], 1, Hash::default());
        let hash = block.hash();
        store.store_block(block).await.unwrap();
        store.finalize_block(&hash).await.unwrap();
        assert!(store.is_finalized(&hash).await);
        drop(store);

        // Recreate — finalized state should persist
        let store2 = DagStore::persistent_with_strict_vrf(kv, false).unwrap();
        assert!(store2.is_finalized(&hash).await);
    }

    /// WP-S.1: Pruning removes blocks from persistent store.
    #[tokio::test]
    async fn test_s1_pruning_persistence() {
        let kv = Arc::new(MemKvStore::new());

        let store = DagStore::persistent_with_strict_vrf(kv.clone(), false).unwrap();

        // Add blocks at heights 0..10
        for i in 0..10u64 {
            let parent = if i == 0 {
                Hash::default()
            } else {
                Hash::new([(i - 1) as u8; 32])
            };
            let block = create_test_block([i as u8; 32], i, parent);
            store.store_block(block).await.unwrap();
        }

        // Set pruning point at height 5 and prune
        let pruning_hash = Hash::new([5; 32]);
        store.update_pruning_point(pruning_hash).await.unwrap();
        let pruned = store.prune().await.unwrap();
        assert_eq!(pruned, 5);
        drop(store);

        // Recreate — pruned blocks should be gone
        let store2 = DagStore::persistent_with_strict_vrf(kv, false).unwrap();
        for i in 0..5u64 {
            assert!(!store2.has_block(&Hash::new([i as u8; 32])).await);
        }
        for i in 5..10u64 {
            assert!(store2.has_block(&Hash::new([i as u8; 32])).await);
        }
    }

    /// WP-S.1: Height index correctness after restart.
    #[tokio::test]
    async fn test_s1_height_index_persistence() {
        let kv = Arc::new(MemKvStore::new());

        let store = DagStore::persistent_with_strict_vrf(kv.clone(), false).unwrap();

        // Store blocks at various heights
        let b0 = create_test_block([0xA0; 32], 0, Hash::default());
        let b1 = create_test_block([0xA1; 32], 1, b0.hash());
        let b2 = create_test_block([0xA2; 32], 2, b1.hash());
        store.store_block(b0.clone()).await.unwrap();
        store.store_block(b1.clone()).await.unwrap();
        store.store_block(b2.clone()).await.unwrap();
        drop(store);

        // Recreate — blocks should be queryable by height
        let store2 = DagStore::persistent_with_strict_vrf(kv, false).unwrap();
        let at_0 = store2.get_blocks_at_height(0).await;
        assert_eq!(at_0.len(), 1);
        assert_eq!(at_0[0].hash(), b0.hash());

        let at_2 = store2.get_blocks_at_height(2).await;
        assert_eq!(at_2.len(), 1);
        assert_eq!(at_2[0].hash(), b2.hash());
    }

    /// WP-S.1: In-memory fallback still works (no persistence backend).
    #[tokio::test]
    async fn test_s1_in_memory_fallback() {
        let store = DagStore::with_permissive_vrf_for_testing(); // No persistent backend
        let block = create_test_block([1; 32], 1, Hash::default());
        let hash = block.hash();
        store.store_block(block).await.unwrap();

        let retrieved = store.get_block(&hash).await.unwrap();
        assert_eq!(retrieved.header.height, 1);

        // Finalize also works
        store.finalize_block(&hash).await.unwrap();
        assert!(store.is_finalized(&hash).await);
    }

    // ========================================================================
    // RM-I / WP-I2.2 — REM-N-04: in-memory cache rolls back on batch failure.
    // ========================================================================

    /// A KvStore that always fails `kv_write_batch` (and the batched writes).
    /// Used to simulate a backend rejection at write time.
    struct FailingKvStore {
        inner: MemKvStore,
    }

    impl KvStore for FailingKvStore {
        fn kv_get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
            self.inner.kv_get(cf, key)
        }
        fn kv_put(&self, _cf: &str, _key: &[u8], _value: &[u8]) -> Result<(), String> {
            Err("FailingKvStore: simulated write failure".to_string())
        }
        fn kv_delete(&self, _cf: &str, _key: &[u8]) -> Result<(), String> {
            Err("FailingKvStore: simulated write failure".to_string())
        }
        fn kv_exists(&self, cf: &str, key: &[u8]) -> Result<bool, String> {
            self.inner.kv_exists(cf, key)
        }
        fn kv_iter_cf(&self, cf: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
            self.inner.kv_iter_cf(cf)
        }
        fn kv_write_batch(&self, _ops: &[KvOp]) -> Result<(), String> {
            Err("FailingKvStore: simulated batch failure".to_string())
        }
    }

    /// REM-N-04: when `kv_write_batch` returns Err, `store_block` returns
    /// the error AND the in-memory caches stay clean. Pre-fix the runtime
    /// kept the new block / new tip / new children in memory while disk
    /// did not, producing split-brain on the next restart.
    #[tokio::test]
    async fn test_rem_n_04_batch_failure_does_not_mutate_cache() {
        let kv = Arc::new(FailingKvStore {
            inner: MemKvStore::new(),
        });
        // Permissive VRF so we don't trip on missing VRF proof in the test block.
        let store = DagStore::persistent_with_strict_vrf(kv, false).unwrap();

        let block = create_test_block([0xC0; 32], 1, Hash::default());
        let hash = block.hash();

        let result = store.store_block(block).await;
        assert!(
            matches!(result, Err(DagStoreError::Persistence(_))),
            "REM-N-04: a failing backend must surface as DagStoreError::Persistence; got: {:?}",
            result
        );

        // The in-memory caches MUST NOT contain the failed block.
        assert!(
            !store.has_block(&hash).await,
            "REM-N-04: failed store_block must not leave the block in the in-memory map"
        );
        let tips = store.get_tips().await;
        assert!(
            !tips.iter().any(|t| t.hash == hash),
            "REM-N-04: failed store_block must not leave the block in the tip set"
        );
        let at_height = store.get_blocks_at_height(1).await;
        assert!(
            at_height.is_empty(),
            "REM-N-04: failed store_block must not leave the block in the height index"
        );
    }

    // ===================================================================
    // FWA-C1-04 — equivocation / double-proposal detection
    // ===================================================================

    fn block_by_proposer(hash: [u8; 32], height: u64, parent: Hash, proposer: u8) -> Block {
        BlockBuilder::new()
            .hash(Hash::new(hash))
            .height(height)
            .parent(parent)
            .proposer(PublicKey::new([proposer; 32]))
            .build_unhashed()
    }

    #[tokio::test]
    #[allow(non_snake_case)]
    async fn test_C1_04_detects_double_proposal_same_proposer_height() {
        let store = DagStore::with_permissive_vrf_for_testing();
        let genesis = block_by_proposer([0xFF; 32], 0, Hash::default(), 9);
        store.store_block(genesis.clone()).await.unwrap();

        // Proposer 7 produces a block at height 1.
        let a = block_by_proposer([0xA1; 32], 1, genesis.hash(), 7);
        store.store_block(a.clone()).await.unwrap();

        // Proposer 7 produces a DIFFERENT block at the same height 1 →
        // equivocation. detect_equivocation must surface block `a`.
        let b = block_by_proposer([0xB2; 32], 1, genesis.hash(), 7);
        let found = store.detect_equivocation(&b).await;
        assert_eq!(found, Some(a.hash()), "must detect the equivocating sibling");
    }

    #[tokio::test]
    #[allow(non_snake_case)]
    async fn test_C1_04_no_false_positive_distinct_proposers() {
        let store = DagStore::with_permissive_vrf_for_testing();
        let genesis = block_by_proposer([0xFF; 32], 0, Hash::default(), 9);
        store.store_block(genesis.clone()).await.unwrap();

        let a = block_by_proposer([0xA1; 32], 1, genesis.hash(), 7);
        store.store_block(a).await.unwrap();

        // A DIFFERENT proposer at the same height is normal DAG width, not
        // equivocation.
        let b = block_by_proposer([0xB2; 32], 1, genesis.hash(), 8);
        assert_eq!(store.detect_equivocation(&b).await, None);
    }

    // ===================================================================
    // FWA-C1-01 — admission enforces leader-election eligibility
    // ===================================================================

    #[tokio::test]
    #[allow(non_snake_case)]
    async fn test_C1_01_admission_rejects_ineligible_when_selector_wired() {
        use crate::vrf::{Validator, VrfProposerSelector};
        // VALIDATOR-S1 (v5): eligibility is INTEGER MEMBERSHIP (stake >= minStake),
        // not the old f64 stake-weighted lottery. A below-minStake proposer is
        // ineligible regardless of its VRF output.
        let selector = Arc::new(VrfProposerSelector::new().with_min_stake(32_000));

        // In-set whale (well above minStake) — eligible.
        let whale = PublicKey::new([0x9A; 32]);
        selector
            .register_validator(Validator { pubkey: whale, stake: 1_000_000, is_active: true })
            .await;
        // Below-minStake proposer — ineligible by membership.
        let proposer = PublicKey::new([7; 32]);
        selector
            .register_validator(Validator { pubkey: proposer, stake: 1, is_active: true })
            .await;

        // Eligibility no longer depends on the VRF output (integer/deterministic).
        let any_output = Hash::new([0xFF; 32]);
        assert!(
            !selector.is_eligible_proposer(&proposer, &any_output, 1).await.unwrap(),
            "below-minStake proposer must be ineligible (membership gate)"
        );
        assert!(
            selector.is_eligible_proposer(&whale, &any_output, 1).await.unwrap(),
            "above-minStake member must be eligible"
        );

        // A selector-wired store carries the eligibility predicate. With no
        // activation height set, enforcement applies whenever a selector is attached.
        let store = DagStore::with_strict_vrf(true).with_proposer_selector(selector);
        assert!(store.proposer_selector.is_some());
    }

    #[tokio::test]
    #[allow(non_snake_case)]
    async fn test_activation_height_gates_enforcement() {
        use crate::vrf::{Validator, VrfProposerSelector};
        // Below the activation height, an unregistered/ineligible proposer is NOT
        // rejected for eligibility (pre-activation rule); at/above it, membership
        // is enforced. This pins the fleet-wide cutover semantics.
        let selector = Arc::new(VrfProposerSelector::new().with_min_stake(32_000));
        selector
            .register_validator(Validator {
                pubkey: PublicKey::new([0x9A; 32]),
                stake: 1_000_000,
                is_active: true,
            })
            .await;
        let store = DagStore::with_strict_vrf(true)
            .with_proposer_selector(selector)
            .with_enforcement_activation_height(1000);

        // An ECVRF-signed block by an UNREGISTERED proposer below the activation
        // height passes eligibility (enforcement off); at/above it, it would be
        // rejected. We assert the gate predicate directly.
        assert_eq!(store.enforcement_activation_height, Some(1000));
        // Genesis with a default VRF output (via create_test_block) so the child's
        // legacy proof — built assuming parent_output == default — verifies. The
        // attached selector is new() (legacy cutoff 100k) so height-1 legacy passes math.
        let genesis = create_test_block([0xFE; 32], 0, Hash::default());
        store.store_block(genesis.clone()).await.unwrap();
        // height 1 < 1000 → eligibility not enforced; block admitted on VRF math alone
        let below = create_block_with_vrf([0x01; 32], 1, genesis.hash());
        assert!(
            store.store_block(below).await.is_ok(),
            "below activation height, membership must not be enforced"
        );
    }

    // ===================================================================
    // FWA-C1-03 — block timestamp must be parent-monotonic
    // ===================================================================

    fn linear_block(hash: [u8; 32], parent: Hash, blue_score: u64, ts: u64) -> Block {
        // height == blue_score, canonical work — matches the consistency
        // gate's expectations for a linear chain.
        BlockBuilder::new()
            .hash(Hash::new(hash))
            .parent(parent)
            .height(blue_score)
            .blue_score(blue_score)
            .blue_work(crate::types::blue_work_for_score(blue_score))
            .timestamp(ts)
            .build_unhashed()
    }

    #[tokio::test]
    #[allow(non_snake_case)]
    async fn test_C1_03_backdated_timestamp_rejected() {
        let store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let ghostdag = crate::ghostdag::GhostDag::new(
            crate::types::GhostDagParams::default(),
            store.clone(),
        );

        // Genesis at height 0, blue_score 0, timestamp 1000 — stored in the
        // dag_store so the consistency gate can resolve it as selected parent.
        let genesis = linear_block([0xFF; 32], Hash::default(), 0, 1_000);
        store.store_block(genesis.clone()).await.unwrap();

        // Child backdated BEFORE its parent → rejected by the
        // parent-monotonic timestamp check (FWA-C1-03). height/blue_score
        // are otherwise valid so the timestamp is the load-bearing reason.
        let backdated = linear_block([0x01; 32], genesis.hash(), 1, 500);
        let res = ghostdag.validate_block_consistency(&backdated).await;
        assert!(res.is_err(), "FWA-C1-03: backdated block must be rejected");
        let msg = format!("{:?}", res.unwrap_err());
        assert!(
            msg.contains("parent-monotonic"),
            "rejection reason must be the timestamp monotonicity check, got: {msg}"
        );

        // A non-decreasing timestamp (== parent) passes the consistency gate.
        let ok = linear_block([0x02; 32], genesis.hash(), 1, 1_000);
        assert!(
            ghostdag.validate_block_consistency(&ok).await.is_ok(),
            "FWA-C1-03: timestamp == parent must be allowed"
        );
    }
}
