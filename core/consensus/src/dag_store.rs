// citrate/core/consensus/src/dag_store.rs

use crate::types::{Block, Hash, Tip};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::info;

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

/// DAG storage manager
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

    /// Store a block in the DAG
    pub async fn store_block(&self, block: Block) -> Result<(), DagStoreError> {
        let hash = block.hash();

        // Check if block already exists
        if self.blocks.read().await.contains_key(&hash) {
            return Err(DagStoreError::BlockExists(hash));
        }

        // WP-K.5: VRF admission gate
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

        // Update parent-child relationships
        let mut children = self.children.write().await;

        // Add child reference to selected parent
        if !block.is_genesis() {
            children
                .entry(block.selected_parent())
                .or_insert_with(Vec::new)
                .push(hash);

            // Add child reference to merge parents
            for merge_parent in &block.header.merge_parent_hashes {
                children
                    .entry(*merge_parent)
                    .or_insert_with(Vec::new)
                    .push(hash);
            }
        }

        // Initialize children list for new block
        children.insert(hash, Vec::new());
        drop(children);

        // Update tips
        let mut tips = self.tips.write().await;

        // Remove parents from tips since they now have a child
        if !block.is_genesis() {
            tips.remove(&block.selected_parent());
            for merge_parent in &block.header.merge_parent_hashes {
                tips.remove(merge_parent);
            }
        }

        // Add new block as a tip
        tips.insert(hash);
        drop(tips);

        // Index by height
        self.blocks_by_height
            .write()
            .await
            .entry(block.header.height)
            .or_insert_with(Vec::new)
            .push(hash);

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
                        pruned_count += 1;
                    }
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

    /// Helper: create a block with valid VRF structure
    fn create_block_with_vrf(hash: [u8; 32], height: u64, parent: Hash) -> Block {
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
                proposer_pubkey: PublicKey::new([1; 32]), // Non-zero proposer
                vrf_reveal: VrfProof {
                    proof: vec![1, 2, 3, 4], // Non-empty proof
                    output: Hash::new([0xAA; 32]), // Non-zero output
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
            signature: Signature::new([1; 64]), // Non-zero signature
            embedded_models: vec![],
            required_pins: vec![],
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
}
