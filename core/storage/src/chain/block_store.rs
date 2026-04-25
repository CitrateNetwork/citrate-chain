// citrate/core/storage/src/chain/block_store.rs

use crate::db::{column_families::*, RocksDB};
use anyhow::Result;
use citrate_consensus::types::{Block, BlockHeader, Hash};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::Arc;
use tracing::{debug, info};

/// Persistent metadata key for the cached latest height value.
/// RM-B1 / WP-C3.2 (audit L-STORE-01).
const LATEST_HEIGHT_KEY: &[u8] = b"latest_height";

/// Block storage manager
pub struct BlockStore {
    db: Arc<RocksDB>,
    /// RM-B1 / WP-C3.2 (audit L-STORE-01): cached latest height
    /// updated atomically inside `put_block`'s WriteBatch so
    /// `get_latest_height()` is O(1) after warm-up. Pre-fix the
    /// method iterated all of CF_METADATA on every call —
    /// after a year of 1s blocks (~31M entries), each call was
    /// many milliseconds and got compounded by the 50K-req/s
    /// rate limit into a self-DoS amplifier.
    cached_latest_height: Arc<AtomicU64>,
}

impl BlockStore {
    pub fn new(db: Arc<RocksDB>) -> Self {
        // Warm the cache from disk on construction. If the
        // metadata key is absent (fresh chain), seed at 0.
        let initial = match db.get_cf(CF_METADATA, LATEST_HEIGHT_KEY) {
            Ok(Some(bytes)) if bytes.len() == 8 => {
                u64::from_be_bytes(bytes.as_slice().try_into().unwrap_or([0u8; 8]))
            }
            _ => 0,
        };
        Self {
            db,
            cached_latest_height: Arc::new(AtomicU64::new(initial)),
        }
    }

    /// Store a complete block
    pub fn put_block(&self, block: &Block) -> Result<()> {
        let hash = block.hash();
        let block_bytes = bincode::serialize(block)?;

        let mut batch = self.db.batch();

        // Store full block
        self.db
            .batch_put_cf(&mut batch, CF_BLOCKS, hash.as_bytes(), &block_bytes)?;

        // Store header separately for quick access
        let header_bytes = bincode::serialize(&block.header)?;
        self.db
            .batch_put_cf(&mut batch, CF_HEADERS, hash.as_bytes(), &header_bytes)?;

        // Store height -> hash mapping
        let height_key = height_to_key(block.header.height);
        self.db
            .batch_put_cf(&mut batch, CF_METADATA, &height_key, hash.as_bytes())?;

        // Store parent -> children mappings for DAG
        for parent in block.parents() {
            let parent_children_key = parent_children_key(&parent);
            let mut children = self.get_children(&parent)?;
            children.push(hash);
            let children_bytes = bincode::serialize(&children)?;
            self.db.batch_put_cf(
                &mut batch,
                CF_DAG_RELATIONS,
                &parent_children_key,
                &children_bytes,
            )?;
        }

        // Store blue set information
        if block.header.blue_score > 0 {
            let blue_score_key = blue_score_key(block.header.blue_score);
            self.db
                .batch_put_cf(&mut batch, CF_BLUE_SET, &blue_score_key, hash.as_bytes())?;
        }

        // RM-B1 / WP-C3.2 (audit L-STORE-01): bump the cached
        // latest_height inside the same atomic batch as the block
        // data. On commit we update the in-memory cache; on
        // restart the cache rebuilds from the metadata key.
        let prior_height = self.cached_latest_height.load(AtomicOrdering::SeqCst);
        let new_height = prior_height.max(block.header.height);
        if new_height > prior_height {
            self.db.batch_put_cf(
                &mut batch,
                CF_METADATA,
                LATEST_HEIGHT_KEY,
                &new_height.to_be_bytes(),
            )?;
        }

        self.db.write_batch(batch)?;

        // Update the in-memory cache only after the batch commits.
        if new_height > prior_height {
            self.cached_latest_height.store(new_height, AtomicOrdering::SeqCst);
        }

        debug!("Stored block {} at height {}", hash, block.header.height);
        Ok(())
    }

    /// Get a block by hash
    pub fn get_block(&self, hash: &Hash) -> Result<Option<Block>> {
        match self.db.get_cf(CF_BLOCKS, hash.as_bytes())? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Get block header by hash
    pub fn get_header(&self, hash: &Hash) -> Result<Option<BlockHeader>> {
        match self.db.get_cf(CF_HEADERS, hash.as_bytes())? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Check if block exists
    pub fn has_block(&self, hash: &Hash) -> Result<bool> {
        self.db.exists_cf(CF_BLOCKS, hash.as_bytes())
    }

    /// Get block hash by height
    pub fn get_block_by_height(&self, height: u64) -> Result<Option<Hash>> {
        let height_key = height_to_key(height);
        match self.db.get_cf(CF_METADATA, &height_key)? {
            Some(bytes) => Ok(Some(Hash::from_bytes(&bytes))),
            None => Ok(None),
        }
    }

    /// Get children of a block
    pub fn get_children(&self, parent: &Hash) -> Result<Vec<Hash>> {
        let key = parent_children_key(parent);
        match self.db.get_cf(CF_DAG_RELATIONS, &key)? {
            Some(bytes) => Ok(bincode::deserialize(&bytes)?),
            None => Ok(Vec::new()),
        }
    }

    /// Get latest block height — O(1) after warm-up.
    ///
    /// RM-B1 / WP-C3.2 (audit L-STORE-01): pre-fix this method
    /// iterated all of CF_METADATA on every call (~31M entries
    /// after a year of 1s blocks). Combined with the 50K-req/s
    /// rate limit, every `eth_blockNumber` call was a self-DoS
    /// amplifier. Post-fix returns from an in-memory atomic
    /// counter updated inside `put_block`'s WriteBatch.
    pub fn get_latest_height(&self) -> Result<u64> {
        Ok(self.cached_latest_height.load(AtomicOrdering::SeqCst))
    }

    /// L-STORE-01 fallback: the original O(N) seek path. Used by
    /// the cache-rebuild routine on construction if the persisted
    /// `LATEST_HEIGHT_KEY` is missing or corrupt. Tests can also
    /// call this to verify the cached value matches the disk truth.
    pub fn get_latest_height_seek(&self) -> Result<u64> {
        // Iterate through height mappings to find the highest
        let mut max_height = 0u64;
        for (key, _) in self.db.iter_cf(CF_METADATA)? {
            if key.len() == 9 && key[0] == b'h' {
                let height = u64::from_be_bytes(key[1..9].try_into()?);
                max_height = max_height.max(height);
            }
        }
        // Verify the block at max_height actually exists in CF_BLOCKS.
        while max_height > 0 {
            let hk = height_to_key(max_height);
            if let Ok(Some(hash_bytes)) = self.db.get_cf(CF_METADATA, &hk) {
                let hash = Hash::from_bytes(&hash_bytes);
                if self.db.exists_cf(CF_BLOCKS, hash.as_bytes()).unwrap_or(false) {
                    return Ok(max_height);
                }
            }
            max_height -= 1;
        }
        Ok(max_height)
    }

    /// Get blocks by blue score range
    pub fn get_blocks_by_blue_score(&self, start: u64, end: u64) -> Result<Vec<Hash>> {
        let mut blocks = Vec::new();
        let start_key = blue_score_key(start);
        let end_key = blue_score_key(end);

        for (key, value) in self.db.iter_cf(CF_BLUE_SET)? {
            if key.as_ref() >= start_key.as_slice() && key.as_ref() <= end_key.as_slice() {
                blocks.push(Hash::from_bytes(&value));
            }
        }

        Ok(blocks)
    }

    /// Return the current DAG tips (blocks without known children), sorted by height descending.
    pub fn get_tips(&self) -> Result<Vec<Hash>> {
        let mut all_blocks = HashSet::new();
        for (key, _) in self.db.iter_cf(CF_BLOCKS)? {
            let key_bytes = key.as_ref();
            if key_bytes.len() == 32 {
                all_blocks.insert(Hash::from_bytes(key_bytes));
            }
        }

        let mut parents_with_children = HashSet::new();
        for (key, value) in self.db.iter_cf(CF_DAG_RELATIONS)? {
            let key_bytes = key.as_ref();
            if key_bytes.len() == 33 && key_bytes[0] == b'c' && !value.is_empty() {
                let parent_hash = Hash::from_bytes(&key_bytes[1..]);
                parents_with_children.insert(parent_hash);
            }
        }

        let mut tips: Vec<(u64, Hash)> = Vec::new();

        for hash in all_blocks.into_iter().filter(|h| !parents_with_children.contains(h)) {
            let height = self
                .get_header(&hash)?
                .map(|header| header.height)
                .unwrap_or_default();
            tips.push((height, hash));
        }

        tips.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
        Ok(tips.into_iter().map(|(_, hash)| hash).collect())
    }

    /// Delete a block and its associated data
    pub fn delete_block(&self, hash: &Hash) -> Result<()> {
        // Get block first to clean up relationships
        if let Some(block) = self.get_block(hash)? {
            let mut batch = self.db.batch();

            // Delete block
            self.db
                .batch_delete_cf(&mut batch, CF_BLOCKS, hash.as_bytes())?;

            // Delete header
            self.db
                .batch_delete_cf(&mut batch, CF_HEADERS, hash.as_bytes())?;

            // Delete height mapping
            let height_key = height_to_key(block.header.height);
            self.db
                .batch_delete_cf(&mut batch, CF_METADATA, &height_key)?;

            // Clean up parent relationships
            for parent in block.parents() {
                let parent_children_key = parent_children_key(&parent);
                if let Ok(mut children) = self.get_children(&parent) {
                    children.retain(|&child| child != *hash);
                    let children_bytes = bincode::serialize(&children)?;
                    self.db.batch_put_cf(
                        &mut batch,
                        CF_DAG_RELATIONS,
                        &parent_children_key,
                        &children_bytes,
                    )?;
                }
            }

            // Delete blue score mapping
            let blue_score_key = blue_score_key(block.header.blue_score);
            self.db
                .batch_delete_cf(&mut batch, CF_BLUE_SET, &blue_score_key)?;

            self.db.write_batch(batch)?;
            info!("Deleted block {}", hash);
        }

        Ok(())
    }

    /// Compact the block storage
    pub fn compact(&self) -> Result<()> {
        self.db.compact_cf(CF_BLOCKS)?;
        self.db.compact_cf(CF_HEADERS)?;
        self.db.compact_cf(CF_DAG_RELATIONS)?;
        self.db.compact_cf(CF_BLUE_SET)?;
        Ok(())
    }
}

// Key generation helpers
fn height_to_key(height: u64) -> Vec<u8> {
    let mut key = vec![b'h'];
    key.extend_from_slice(&height.to_be_bytes());
    key
}

fn parent_children_key(parent: &Hash) -> Vec<u8> {
    let mut key = vec![b'c'];
    key.extend_from_slice(parent.as_bytes());
    key
}

fn blue_score_key(score: u64) -> Vec<u8> {
    let mut key = vec![b'b'];
    key.extend_from_slice(&score.to_be_bytes());
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_consensus::types::{BlockBuilder, PublicKey};
    use tempfile::TempDir;

    fn create_test_block(height: u64, parent: Hash) -> Block {
        BlockBuilder::new()
            .hash(Hash::new([height as u8; 32]))
            .parent(parent)
            .height(height)
            .timestamp(1000000 + height)
            .blue_score(height * 10)
            .blue_work(height as u128 * 100)
            .proposer(PublicKey::new([1; 32]))
            .build_unhashed()
    }

    #[test]
    fn test_block_storage() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(RocksDB::open(temp_dir.path()).unwrap());
        let store = BlockStore::new(db);

        // Store blocks
        let block1 = create_test_block(1, Hash::default());
        let block2 = create_test_block(2, block1.hash());

        store.put_block(&block1).unwrap();
        store.put_block(&block2).unwrap();

        // Retrieve blocks
        let retrieved = store.get_block(&block1.hash()).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().header.height, 1);

        // Check existence
        assert!(store.has_block(&block1.hash()).unwrap());
        assert!(store.has_block(&block2.hash()).unwrap());

        // Get by height
        let hash_at_2 = store.get_block_by_height(2).unwrap();
        assert_eq!(hash_at_2, Some(block2.hash()));

        // Check children
        let children = store.get_children(&block1.hash()).unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0], block2.hash());
    }
}
