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

/// Execute-on-receive: persistent pointer to the block whose post-execution
/// world state the executor currently reflects (the "applied tip"). Distinct
/// from `latest_height` — a block can be DAG-admitted + block-bytes persisted
/// long before its transactions have been executed and its `state_root`
/// verified. The applied tip only advances when `apply_block` succeeds.
/// Stored as 32-byte hash ‖ 8-byte big-endian height (40 bytes).
pub const APPLIED_TIP_KEY: &[u8] = b"applied_tip";

/// VALIDATOR-S1 §R': the durably-persisted, materialized epoch reward snapshot —
/// the `EpochRewardPolicy` (share bps + reward minter + proposer->staker map) AND
/// the active-set + minStake needed to rebuild the proposer selector — written at
/// each snapshot boundary S(E) by `registry_sync`. On restart the node reloads
/// this BEFORE serving blocks, so it resumes with the byte-identical finalized
/// snapshot a continuously-up node holds (reading it live from the mid-epoch tip
/// would re-derive a possibly governance-mutated policy and fork). Opaque blob —
/// the node layer owns the encoding.
const REWARD_SNAPSHOT_KEY: &[u8] = b"reward_snapshot";
/// Per-epoch reward-snapshot key prefix. The full key is this prefix followed by the
/// 8-byte big-endian snapshot height S(E). Unlike the latest-only [`REWARD_SNAPSHOT_KEY`],
/// these let a reorg pre-seed rehydrate the EXACT governing-epoch policy even when the
/// most-recently-persisted snapshot is a newer epoch (a boundary-crossing reorg).
/// Bounded retention is enforced by the caller (`RegistrySync`) deleting snapshots that
/// have fallen out of the reorg window.
const REWARD_SNAPSHOT_AT_PREFIX: &[u8] = b"reward_snapshot_at:";

/// Build the per-epoch reward-snapshot key for snapshot height S(E).
fn reward_snapshot_at_key(snapshot_height: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(REWARD_SNAPSHOT_AT_PREFIX.len() + 8);
    k.extend_from_slice(REWARD_SNAPSHOT_AT_PREFIX);
    k.extend_from_slice(&snapshot_height.to_be_bytes());
    k
}

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
    /// FUA-CHAIN-01: serializes `put_block`'s read-modify-writes.
    /// The per-parent children list and the latest-height key are both
    /// RMW against RocksDB state — producer, network ingest, and sync
    /// all call `put_block` from distinct tokio tasks, so without this
    /// lock two sibling puts could each read `children=[…]`, append,
    /// and last-writer-wins a child link out of CF_DAG_RELATIONS.
    /// Reads stay lock-free.
    put_lock: std::sync::Mutex<()>,
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
            put_lock: std::sync::Mutex::new(()),
        }
    }

    /// Store a complete block
    pub fn put_block(&self, block: &Block) -> Result<()> {
        // FUA-CHAIN-01: hold the put lock across the read-modify-writes
        // (children lists + latest height) and the batch commit so
        // concurrent ingest cannot lose DAG child links or regress the
        // height. A poisoned lock means another put panicked mid-call;
        // batch commits are atomic so the store is still consistent —
        // recover rather than poisoning every later caller.
        let _put_guard = self.put_lock.lock().unwrap_or_else(|e| e.into_inner());

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

        // Store parent -> children mappings for DAG.
        // FUA-CHAIN-01: skip if already linked so a re-put of the same
        // block (producer retry, sync overlap) can't duplicate the link.
        for parent in block.parents() {
            let parent_children_key = parent_children_key(&parent);
            let mut children = self.get_children(&parent)?;
            if children.contains(&hash) {
                continue;
            }
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

        // REM-2 / WP-H1.3 (audit M-API-01): producer-path commit MUST
        // fsync. Pre-fix this used `write_batch` which returns as soon
        // as the OS page cache accepts the write — a power loss between
        // RPC ack and OS flush silently rolled back finalised state.
        // `write_batch_sync` forces RocksDB::WriteOptions::set_sync(true).
        self.db.write_batch_sync(batch)?;

        // Update the in-memory cache only after the batch commits.
        if new_height > prior_height {
            self.cached_latest_height
                .store(new_height, AtomicOrdering::SeqCst);
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
            // SECREM-01 CONS-6: a corrupt/truncated index value must not
            // panic the node (crash-loop DoS). Treat a short value as a
            // missing entry — the height behaves as a gap, which the
            // bounded serve paths (NET-1/2) already handle.
            Some(bytes) => Ok(Hash::try_from_bytes(&bytes)),
            None => Ok(None),
        }
    }

    /// Enumerate `(height, hash)` for every stored block whose height is in
    /// `[start, end]` inclusive, scanning headers (cheaper than full blocks).
    ///
    /// #85 (fresh-node forward-sync wedge): the single-hash `get_block_by_height`
    /// index is last-writer-wins, so on a multi-producer GhostDAG it drops the
    /// SIBLING blocks at each height. A joining node then never receives the
    /// merge-parents that canonical blocks reference, and every admission fails
    /// with "Missing parent at admission". DAG-aware serving needs ALL blocks at
    /// each height; this returns them so the serve path can deliver complete
    /// height-groups in topological (height-ascending) order.
    ///
    /// Cost: O(total stored headers) per call (no per-height multi-hash index
    /// exists yet). Acceptable because only a late-joining peer triggers it and
    /// the result is bounded downstream; a height→[hashes] index is the future
    /// optimization if sync-serve load ever warrants it.
    pub fn hashes_in_height_range(&self, start: u64, end: u64) -> Result<Vec<(u64, Hash)>> {
        let mut out: Vec<(u64, Hash)> = Vec::new();
        if start > end {
            return Ok(out);
        }
        for (key, value) in self.db.iter_cf(CF_HEADERS)? {
            // Key is the 32-byte block hash; value is a serialized BlockHeader.
            let Some(hash) = Hash::try_from_bytes(key.as_ref()) else {
                continue;
            };
            if let Ok(header) = bincode::deserialize::<BlockHeader>(&value) {
                if header.height >= start && header.height <= end {
                    out.push((header.height, hash));
                }
            }
        }
        Ok(out)
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
                // SECREM-01 CONS-6: corrupt short value → treat as missing.
                if let Some(hash) = Hash::try_from_bytes(&hash_bytes) {
                    if self
                        .db
                        .exists_cf(CF_BLOCKS, hash.as_bytes())
                        .unwrap_or(false)
                    {
                        return Ok(max_height);
                    }
                }
            }
            max_height -= 1;
        }
        Ok(max_height)
    }

    /// Execute-on-receive: persist the applied-tip pointer (the block whose
    /// post-execution state the executor now reflects). Written after
    /// `apply_block` succeeds. A single 40-byte value keeps the hash and
    /// height mutually consistent (no torn read across two keys).
    pub fn put_applied_tip(&self, hash: &Hash, height: u64) -> Result<()> {
        let mut buf = [0u8; 40];
        buf[..32].copy_from_slice(hash.as_bytes());
        buf[32..].copy_from_slice(&height.to_be_bytes());
        self.db.put_cf(CF_METADATA, APPLIED_TIP_KEY, &buf)
    }

    /// VALIDATOR-S1 §R': durably persist the materialized epoch reward snapshot
    /// (opaque blob — see [`REWARD_SNAPSHOT_KEY`]). Overwrites the previous epoch's
    /// snapshot; only the most-recent (greatest S(E) applied) is needed at boot.
    pub fn put_reward_snapshot(&self, blob: &[u8]) -> Result<()> {
        self.db.put_cf(CF_METADATA, REWARD_SNAPSHOT_KEY, blob)
    }

    /// VALIDATOR-S1 §R': read the persisted epoch reward snapshot, or `None` if
    /// never written (fresh node / pre-upgrade store / pre-first-snapshot boot).
    pub fn get_reward_snapshot(&self) -> Result<Option<Vec<u8>>> {
        self.db.get_cf(CF_METADATA, REWARD_SNAPSHOT_KEY)
    }

    /// VALIDATOR-S1 §R': persist the epoch reward snapshot under its OWN S(E) key (in
    /// addition to the latest-only [`put_reward_snapshot`]), so a reorg can rehydrate the
    /// exact governing epoch's policy regardless of the current tip. Bounded retention is
    /// the caller's responsibility via [`delete_reward_snapshot_at`].
    pub fn put_reward_snapshot_at(&self, snapshot_height: u64, blob: &[u8]) -> Result<()> {
        self.db
            .put_cf(CF_METADATA, &reward_snapshot_at_key(snapshot_height), blob)
    }

    /// VALIDATOR-S1 §R': read the per-epoch reward snapshot for snapshot height S(E), or
    /// `None` if never written / pruned out of the retention window.
    pub fn get_reward_snapshot_at(&self, snapshot_height: u64) -> Result<Option<Vec<u8>>> {
        self.db
            .get_cf(CF_METADATA, &reward_snapshot_at_key(snapshot_height))
    }

    /// VALIDATOR-S1 §R': delete the per-epoch reward snapshot for snapshot height S(E)
    /// (retention pruning). Deleting an absent key is a no-op.
    pub fn delete_reward_snapshot_at(&self, snapshot_height: u64) -> Result<()> {
        self.db
            .delete_cf(CF_METADATA, &reward_snapshot_at_key(snapshot_height))
    }

    /// Execute-on-receive: read the persisted applied-tip pointer, or `None`
    /// if never written (fresh node / pre-upgrade store). SECREM-01 CONS-6:
    /// a short/corrupt value decodes to `None` rather than panicking.
    pub fn get_applied_tip(&self) -> Result<Option<(Hash, u64)>> {
        match self.db.get_cf(CF_METADATA, APPLIED_TIP_KEY)? {
            Some(bytes) if bytes.len() >= 40 => {
                let hash = match Hash::try_from_bytes(&bytes[..32]) {
                    Some(h) => h,
                    None => return Ok(None),
                };
                let height = u64::from_be_bytes(
                    bytes[32..40]
                        .try_into()
                        .expect("40-byte buffer sliced to 8 bytes"),
                );
                Ok(Some((hash, height)))
            }
            _ => Ok(None),
        }
    }

    /// Get blocks by blue score range
    pub fn get_blocks_by_blue_score(&self, start: u64, end: u64) -> Result<Vec<Hash>> {
        let mut blocks = Vec::new();
        let start_key = blue_score_key(start);
        let end_key = blue_score_key(end);

        for (key, value) in self.db.iter_cf(CF_BLUE_SET)? {
            if key.as_ref() >= start_key.as_slice() && key.as_ref() <= end_key.as_slice() {
                // SECREM-01 CONS-6: skip corrupt short values, don't panic.
                if let Some(h) = Hash::try_from_bytes(&value) {
                    blocks.push(h);
                }
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
                // SECREM-01 CONS-6: key length checked above (33), so the
                // 32-byte tail is sound; use the fallible decode anyway to
                // keep the no-panic invariant uniform across this module.
                if let Some(parent_hash) = Hash::try_from_bytes(&key_bytes[1..]) {
                    parents_with_children.insert(parent_hash);
                }
            }
        }

        let mut tips: Vec<(u64, Hash)> = Vec::new();

        for hash in all_blocks
            .into_iter()
            .filter(|h| !parents_with_children.contains(h))
        {
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

    /// Remove a set of blocks (and every index entry that names them) in one
    /// atomic batch, then rewind the latest-height marker to the highest
    /// surviving block.
    ///
    /// Unlike [`Self::delete_block`], an index entry is removed only when it
    /// names a purged block: the height and blue-score maps are
    /// last-writer-wins, and a surviving sibling at the same height keeps (or
    /// takes over) its entry. Used at start-up to drop blocks that are invalid
    /// under the node's activation rules.
    pub fn purge_blocks(&self, doomed: &HashSet<Hash>) -> Result<u64> {
        let _put_guard = self.put_lock.lock().unwrap_or_else(|e| e.into_inner());
        if doomed.is_empty() {
            return Ok(self.cached_latest_height.load(AtomicOrdering::SeqCst));
        }
        let mut batch = self.db.batch();
        let mut vacated_heights: HashSet<u64> = HashSet::new();
        let mut parents: HashSet<Hash> = HashSet::new();
        for hash in doomed {
            let Some(block) = self.get_block(hash)? else {
                continue;
            };
            self.db
                .batch_delete_cf(&mut batch, CF_BLOCKS, hash.as_bytes())?;
            self.db
                .batch_delete_cf(&mut batch, CF_HEADERS, hash.as_bytes())?;
            self.db
                .batch_delete_cf(&mut batch, CF_DAG_RELATIONS, &parent_children_key(hash))?;
            let hk = height_to_key(block.header.height);
            if self.db.get_cf(CF_METADATA, &hk)?.as_deref() == Some(hash.as_bytes()) {
                self.db.batch_delete_cf(&mut batch, CF_METADATA, &hk)?;
                vacated_heights.insert(block.header.height);
            }
            let bk = blue_score_key(block.header.blue_score);
            if self.db.get_cf(CF_BLUE_SET, &bk)?.as_deref() == Some(hash.as_bytes()) {
                self.db.batch_delete_cf(&mut batch, CF_BLUE_SET, &bk)?;
            }
            parents.extend(block.parents());
        }
        for parent in parents.difference(doomed) {
            let children = self.get_children(parent)?;
            let kept: Vec<Hash> = children
                .iter()
                .copied()
                .filter(|c| !doomed.contains(c))
                .collect();
            if kept.len() != children.len() {
                let bytes = bincode::serialize(&kept)?;
                self.db.batch_put_cf(
                    &mut batch,
                    CF_DAG_RELATIONS,
                    &parent_children_key(parent),
                    &bytes,
                )?;
            }
        }

        // Surviving headers: re-point vacated heights and find the new top.
        let mut latest = 0u64;
        let mut refill: std::collections::HashMap<u64, Hash> = std::collections::HashMap::new();
        for (key, value) in self.db.iter_cf(CF_HEADERS)? {
            let Some(hash) = Hash::try_from_bytes(key.as_ref()) else {
                continue;
            };
            if doomed.contains(&hash) {
                continue;
            }
            if let Ok(header) = bincode::deserialize::<BlockHeader>(&value) {
                latest = latest.max(header.height);
                if vacated_heights.contains(&header.height) {
                    refill.entry(header.height).or_insert(hash);
                }
            }
        }
        for (height, hash) in &refill {
            self.db.batch_put_cf(
                &mut batch,
                CF_METADATA,
                &height_to_key(*height),
                hash.as_bytes(),
            )?;
        }
        self.db.batch_put_cf(
            &mut batch,
            CF_METADATA,
            LATEST_HEIGHT_KEY,
            &latest.to_be_bytes(),
        )?;
        self.db.write_batch_sync(batch)?;
        self.cached_latest_height
            .store(latest, AtomicOrdering::SeqCst);
        info!(
            "Purged {} block(s); latest stored height is now {}",
            doomed.len(),
            latest
        );
        Ok(latest)
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

    /// SECREM-01 CONS-6: a corrupt/truncated height-index value must not
    /// panic the node (crash-loop DoS). The decode path returns the height
    /// as absent instead of slicing `[..32]` on a short buffer.
    #[test]
    fn test_cons6_corrupt_height_index_does_not_panic() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(RocksDB::open(temp_dir.path()).unwrap());
        let store = BlockStore::new(db.clone());

        // Write a deliberately short (5-byte) value at the height index key.
        let short = [1u8, 2, 3, 4, 5];
        db.put_cf(CF_METADATA, &height_to_key(7), &short).unwrap();

        // Must return Ok(None), not panic.
        let got = store
            .get_block_by_height(7)
            .expect("no panic on corrupt value");
        assert_eq!(got, None);

        // try_from_bytes contract.
        assert_eq!(Hash::try_from_bytes(&short), None);
        assert!(Hash::try_from_bytes(&[9u8; 32]).is_some());
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

    /// FUA-CHAIN-01 red test (idempotency half): re-putting the same
    /// block must not duplicate its child link under the parent.
    #[test]
    fn test_fua_chain_01_duplicate_put_does_not_duplicate_child_link() {
        let temp_dir = TempDir::new().expect("tempdir");
        let db = Arc::new(RocksDB::open(temp_dir.path()).expect("open db"));
        let store = BlockStore::new(db);

        let parent = Hash::new([0xAA; 32]);
        let block = create_test_block(1, parent);
        store.put_block(&block).expect("put");
        store.put_block(&block).expect("put");

        let children = store.get_children(&parent).expect("children");
        assert_eq!(
            children.len(),
            1,
            "duplicate put must not duplicate the child link"
        );
    }

    /// FUA-CHAIN-01 red test (race half): concurrent puts of sibling
    /// blocks sharing one parent must keep EVERY child link. Pre-fix the
    /// children list was a lockless read-modify-write — last writer wins
    /// and sibling links silently vanish from CF_DAG_RELATIONS.
    #[test]
    fn test_fua_chain_01_concurrent_sibling_puts_keep_all_child_links() {
        let temp_dir = TempDir::new().expect("tempdir");
        let db = Arc::new(RocksDB::open(temp_dir.path()).expect("open db"));
        let store = Arc::new(BlockStore::new(db));

        let parent = Hash::new([0xBB; 32]);
        let mut handles = Vec::new();
        for i in 0..8u8 {
            let store = store.clone();
            handles.push(std::thread::spawn(move || {
                let block = BlockBuilder::new()
                    .hash(Hash::new([0xC0 + i; 32]))
                    .parent(parent)
                    .height(1)
                    .timestamp(1_000_000 + i as u64)
                    .blue_score(10)
                    .blue_work(100)
                    .proposer(PublicKey::new([1; 32]))
                    .build_unhashed();
                store.put_block(&block).expect("put");
            }));
        }
        for h in handles {
            h.join().expect("thread join");
        }

        let children = store.get_children(&parent).expect("children");
        assert_eq!(
            children.len(),
            8,
            "every sibling child link must survive concurrent ingest"
        );
    }

    /// FUA-CHAIN-01 red test (height half): the cached latest height must
    /// be monotone under concurrent out-of-order ingest — a lower block
    /// committing after a higher one must never regress it.
    #[test]
    fn test_fua_chain_01_height_never_regresses_under_concurrency() {
        let temp_dir = TempDir::new().expect("tempdir");
        let db = Arc::new(RocksDB::open(temp_dir.path()).expect("open db"));
        let store = Arc::new(BlockStore::new(db));

        let parent = Hash::new([0xDD; 32]);
        let mut handles = Vec::new();
        for i in 1..=16u64 {
            let store = store.clone();
            handles.push(std::thread::spawn(move || {
                let block = BlockBuilder::new()
                    .hash(Hash::new([i as u8; 32]))
                    .parent(parent)
                    .height(i)
                    .timestamp(1_000_000 + i)
                    .blue_score(i * 10)
                    .blue_work(i as u128 * 100)
                    .proposer(PublicKey::new([1; 32]))
                    .build_unhashed();
                store.put_block(&block).expect("put");
            }));
        }
        for h in handles {
            h.join().expect("thread join");
        }

        assert_eq!(
            store.get_latest_height().expect("height"),
            16,
            "height must equal the max ingested"
        );
    }
}
