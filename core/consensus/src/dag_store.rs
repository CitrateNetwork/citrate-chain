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
pub trait KvStore: Send + Sync {
    fn kv_get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, String>;
    fn kv_put(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<(), String>;
    fn kv_delete(&self, cf: &str, key: &[u8]) -> Result<(), String>;
    fn kv_exists(&self, cf: &str, key: &[u8]) -> Result<bool, String>;
    /// Iterate all key-value pairs in a column family.
    fn kv_iter_cf(&self, cf: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String>;
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

    /// WP-K.5: When true, blocks failing VRF admission are rejected.
    /// When false (default/testnet), failures are logged but blocks are accepted.
    strict_vrf: bool,

    /// WP-S.1: Optional persistent backend for write-through durability.
    persistent: Option<Arc<dyn KvStore>>,
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
    pub fn new() -> Self {
        Self {
            blocks: Arc::new(RwLock::new(HashMap::new())),
            blocks_by_height: Arc::new(RwLock::new(HashMap::new())),
            children: Arc::new(RwLock::new(HashMap::new())),
            tips: Arc::new(RwLock::new(HashSet::new())),
            finalized: Arc::new(RwLock::new(HashSet::new())),
            pruning_point: Arc::new(RwLock::new(Hash::default())),
            strict_vrf: false,
            persistent: None,
        }
    }

    /// Create a DagStore with strict VRF enforcement.
    /// WP-K.5: In strict mode, blocks failing VRF admission are rejected.
    pub fn with_strict_vrf(strict_vrf: bool) -> Self {
        Self {
            strict_vrf,
            ..Self::new()
        }
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
            strict_vrf: false,
            persistent: Some(kv),
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
            let (parent, child_list): (Hash, Vec<Hash>) = bincode::deserialize(&value)
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

        // Populate in-memory state
        *self.blocks.try_write().unwrap() = blocks;
        *self.blocks_by_height.try_write().unwrap() = blocks_by_height;
        *self.children.try_write().unwrap() = children;
        *self.tips.try_write().unwrap() = tips;
        *self.finalized.try_write().unwrap() = finalized;
        *self.pruning_point.try_write().unwrap() = pruning_point;

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

    /// WP-S.1: Persist a block to the backend.
    fn persist_block(&self, block: &Block, hash: &Hash) {
        if let Some(ref kv) = self.persistent {
            let block_bytes = bincode::serialize(block).unwrap_or_default();
            if let Err(e) = kv.kv_put(cf::DAG_BLOCKS, hash.as_bytes(), &block_bytes) {
                warn!("Failed to persist block {}: {}", hash, e);
            }
        }
    }

    /// WP-S.1: Persist children map entry.
    fn persist_children(&self, parent: &Hash, children: &[Hash]) {
        if let Some(ref kv) = self.persistent {
            let entry = (*parent, children.to_vec());
            let bytes = bincode::serialize(&entry).unwrap_or_default();
            if let Err(e) = kv.kv_put(cf::DAG_CHILDREN, parent.as_bytes(), &bytes) {
                warn!("Failed to persist children for {}: {}", parent, e);
            }
        }
    }

    /// WP-S.1: Persist the tip set.
    fn persist_tip_add(&self, hash: &Hash) {
        if let Some(ref kv) = self.persistent {
            if let Err(e) = kv.kv_put(cf::DAG_TIPS, hash.as_bytes(), &[1]) {
                warn!("Failed to persist tip {}: {}", hash, e);
            }
        }
    }

    fn persist_tip_remove(&self, hash: &Hash) {
        if let Some(ref kv) = self.persistent {
            if let Err(e) = kv.kv_delete(cf::DAG_TIPS, hash.as_bytes()) {
                warn!("Failed to remove tip {}: {}", hash, e);
            }
        }
    }

    /// WP-S.1: Persist finalization.
    fn persist_finalized(&self, hash: &Hash) {
        if let Some(ref kv) = self.persistent {
            if let Err(e) = kv.kv_put(cf::DAG_FINALIZED, hash.as_bytes(), &[1]) {
                warn!("Failed to persist finalized {}: {}", hash, e);
            }
        }
    }

    /// WP-S.1: Persist height index.
    fn persist_height_index(&self, height: u64, hashes: &[Hash]) {
        if let Some(ref kv) = self.persistent {
            let bytes = bincode::serialize(hashes).unwrap_or_default();
            if let Err(e) = kv.kv_put(cf::DAG_HEIGHT_INDEX, &height.to_be_bytes(), &bytes) {
                warn!("Failed to persist height index {}: {}", height, e);
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
        let vrf_selector = VrfProposerSelector::new();

        match vrf_selector.verify_vrf_proof(
            &block.header.proposer_pubkey,
            &block.header.vrf_reveal,
            &prev_vrf_output,
            block.header.height,
        ) {
            Ok(true) => Ok(()),
            Ok(false) => Err("VRF proof verification failed: invalid proof".to_string()),
            Err(e) => Err(format!("VRF verification error: {}", e)),
        }
    }

    /// Store a block in the DAG
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

        // WP-S.1: Persist block to backend
        self.persist_block(&block, &hash);

        // Update parent-child relationships
        let mut children = self.children.write().await;

        // Add child reference to selected parent
        if !block.is_genesis() {
            let parent_children = children
                .entry(block.selected_parent())
                .or_insert_with(Vec::new);
            parent_children.push(hash);
            self.persist_children(&block.selected_parent(), parent_children);

            // Add child reference to merge parents
            for merge_parent in &block.header.merge_parent_hashes {
                let mp_children = children
                    .entry(*merge_parent)
                    .or_insert_with(Vec::new);
                mp_children.push(hash);
                self.persist_children(merge_parent, mp_children);
            }
        }

        // Initialize children list for new block
        children.insert(hash, Vec::new());
        self.persist_children(&hash, &[]);
        drop(children);

        // Update tips
        let mut tips = self.tips.write().await;

        // Remove parents from tips since they now have a child
        if !block.is_genesis() {
            tips.remove(&block.selected_parent());
            self.persist_tip_remove(&block.selected_parent());
            for merge_parent in &block.header.merge_parent_hashes {
                tips.remove(merge_parent);
                self.persist_tip_remove(merge_parent);
            }
        }

        // Add new block as a tip
        tips.insert(hash);
        self.persist_tip_add(&hash);
        drop(tips);

        // Index by height
        let height = block.header.height;
        let mut by_height = self.blocks_by_height.write().await;
        let height_hashes = by_height.entry(height).or_insert_with(Vec::new);
        height_hashes.push(hash);
        self.persist_height_index(height, height_hashes);
        drop(by_height);

        // Store the block
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
        Block {
            header: BlockHeader {
                version: 1,
                block_hash: Hash::new(hash),
                selected_parent_hash: parent,
                merge_parent_hashes: vec![],
                timestamp: 0,
                height,
                blue_score: 0,
                blue_work: 0,
                pruning_point: Hash::default(),
                proposer_pubkey: PublicKey::new([0; 32]),
                vrf_reveal: VrfProof {
                    proof: vec![],
                    output: Hash::default(),
                },
                base_fee_per_gas: 0,
                gas_used: 0,
                gas_limit: 30_000_000,
            },
            state_root: Hash::default(),
            tx_root: Hash::default(),
            receipt_root: Hash::default(),
            artifact_root: Hash::default(),
            ghostdag_params: GhostDagParams::default(),
            transactions: vec![],
            signature: Signature::new([0; 64]),
            embedded_models: vec![],
            required_pins: vec![],
            learning_embedding: None,
            learning_confidence: None,
            gradient_commitment: None,
        }
    }

    #[tokio::test]
    async fn test_store_and_retrieve_block() {
        let store = DagStore::new();
        let block = create_test_block([1; 32], 1, Hash::default());

        store.store_block(block.clone()).await.unwrap();

        let retrieved = store.get_block(&block.hash()).await.unwrap();
        assert_eq!(retrieved.hash(), block.hash());
        assert_eq!(retrieved.header.height, 1);
    }

    #[tokio::test]
    async fn test_duplicate_block() {
        let store = DagStore::new();
        let block = create_test_block([1; 32], 1, Hash::default());

        store.store_block(block.clone()).await.unwrap();
        let result = store.store_block(block).await;

        assert!(matches!(result, Err(DagStoreError::BlockExists(_))));
    }

    #[tokio::test]
    async fn test_tips_management() {
        let store = DagStore::new();

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
        let store = DagStore::new();
        let block = create_test_block([1; 32], 1, Hash::default());

        store.store_block(block.clone()).await.unwrap();
        assert!(!store.is_finalized(&block.hash()).await);

        store.finalize_block(&block.hash()).await.unwrap();
        assert!(store.is_finalized(&block.hash()).await);
    }

    #[tokio::test]
    async fn test_pruning() {
        let store = DagStore::new();

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
    fn create_block_with_vrf_parent_output(
        hash: [u8; 32],
        height: u64,
        parent: Hash,
        parent_vrf_output: Hash,
    ) -> Block {
        use sha3::{Digest, Sha3_256};

        let proposer = PublicKey::new([1; 32]);
        let proof_bytes: [u8; 32] = [0x42; 32]; // arbitrary 32-byte proof

        // Reconstruct the alpha: SHA3(pubkey || prev_vrf || slot)
        let mut hasher = Sha3_256::new();
        hasher.update(proposer.as_bytes());
        hasher.update(parent_vrf_output.as_bytes());
        hasher.update(height.to_le_bytes());
        let input = hasher.finalize();

        // output = SHA3(proof || input)
        let mut output_hasher = Sha3_256::new();
        output_hasher.update(&proof_bytes);
        output_hasher.update(&input);
        let output = Hash::from_bytes(&output_hasher.finalize());

        Block {
            header: BlockHeader {
                version: 1,
                block_hash: Hash::new(hash),
                selected_parent_hash: parent,
                merge_parent_hashes: vec![],
                timestamp: 0,
                height,
                blue_score: 0,
                blue_work: 0,
                pruning_point: Hash::default(),
                proposer_pubkey: proposer,
                vrf_reveal: VrfProof {
                    proof: proof_bytes.to_vec(),
                    output,
                },
                base_fee_per_gas: 0,
                gas_used: 0,
                gas_limit: 30_000_000,
            },
            state_root: Hash::default(),
            tx_root: Hash::default(),
            receipt_root: Hash::default(),
            artifact_root: Hash::default(),
            ghostdag_params: GhostDagParams::default(),
            transactions: vec![],
            signature: Signature::new([1; 64]),
            embedded_models: vec![],
            required_pins: vec![],
            learning_embedding: None,
            learning_confidence: None,
            gradient_commitment: None,
        }
    }

    /// WP-K.5: Block with empty VRF → warning in permissive mode, accepted
    #[tokio::test]
    async fn test_k5_empty_vrf_permissive_mode() {
        let store = DagStore::new(); // strict_vrf=false by default
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

    /// WP-K.5: Block with valid VRF structure → accepted in both modes
    #[tokio::test]
    async fn test_k5_valid_vrf_accepted() {
        // Permissive mode
        let store = DagStore::new();
        let genesis = create_test_block([0xFE; 32], 0, Hash::default());
        store.store_block(genesis.clone()).await.unwrap();
        let block = create_block_with_vrf([1; 32], 1, genesis.hash());
        assert!(store.store_block(block).await.is_ok());

        // Strict mode
        let store_strict = DagStore::with_strict_vrf(true);
        let genesis2 = create_test_block([0xFD; 32], 0, Hash::default());
        store_strict.store_block(genesis2.clone()).await.unwrap();
        let block2 = create_block_with_vrf([2; 32], 1, genesis2.hash());
        assert!(store_strict.store_block(block2).await.is_ok());
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
        let store = DagStore::persistent(kv.clone()).unwrap();
        let genesis = create_test_block([0xFF; 32], 0, Hash::default());
        let genesis_hash = genesis.hash();
        store.store_block(genesis).await.unwrap();

        // Store a child block
        let child = create_test_block([1; 32], 1, genesis_hash);
        let child_hash = child.hash();
        store.store_block(child).await.unwrap();

        // Drop the store and recreate from the same KvStore
        drop(store);
        let store2 = DagStore::persistent(kv).unwrap();

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

        let store = DagStore::persistent(kv.clone()).unwrap();
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
        let store2 = DagStore::persistent(kv).unwrap();
        let tips2 = store2.get_tips().await;
        assert_eq!(tips2.len(), 1);
        assert_eq!(tips2[0].hash, child_hash);
    }

    /// WP-S.1: Finalization state survives restart.
    #[tokio::test]
    async fn test_s1_finalization_persistence() {
        let kv = Arc::new(MemKvStore::new());

        let store = DagStore::persistent(kv.clone()).unwrap();
        let block = create_test_block([1; 32], 1, Hash::default());
        let hash = block.hash();
        store.store_block(block).await.unwrap();
        store.finalize_block(&hash).await.unwrap();
        assert!(store.is_finalized(&hash).await);
        drop(store);

        // Recreate — finalized state should persist
        let store2 = DagStore::persistent(kv).unwrap();
        assert!(store2.is_finalized(&hash).await);
    }

    /// WP-S.1: Pruning removes blocks from persistent store.
    #[tokio::test]
    async fn test_s1_pruning_persistence() {
        let kv = Arc::new(MemKvStore::new());

        let store = DagStore::persistent(kv.clone()).unwrap();

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
        let store2 = DagStore::persistent(kv).unwrap();
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

        let store = DagStore::persistent(kv.clone()).unwrap();

        // Store blocks at various heights
        let b0 = create_test_block([0xA0; 32], 0, Hash::default());
        let b1 = create_test_block([0xA1; 32], 1, b0.hash());
        let b2 = create_test_block([0xA2; 32], 2, b1.hash());
        store.store_block(b0.clone()).await.unwrap();
        store.store_block(b1.clone()).await.unwrap();
        store.store_block(b2.clone()).await.unwrap();
        drop(store);

        // Recreate — blocks should be queryable by height
        let store2 = DagStore::persistent(kv).unwrap();
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
        let store = DagStore::new(); // No persistent backend
        let block = create_test_block([1; 32], 1, Hash::default());
        let hash = block.hash();
        store.store_block(block).await.unwrap();

        let retrieved = store.get_block(&hash).await.unwrap();
        assert_eq!(retrieved.header.height, 1);

        // Finalize also works
        store.finalize_block(&hash).await.unwrap();
        assert!(store.is_finalized(&hash).await);
    }
}
