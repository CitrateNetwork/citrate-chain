// citrate/core/storage/src/chain/block_store.rs

use crate::db::{column_families::*, RocksDB};
use anyhow::Result;
use citrate_consensus::types::{Block, BlockHeader, Hash};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering};
use std::sync::Arc;
use tracing::{debug, info, warn};

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
    let mut k = Vec::with_capacity(REWARD_SNAPSHOT_AT_PREFIX.len().saturating_add(8));
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
    /// Whether the tips index (`TIPS_INDEX_PREFIX`) describes this store.
    /// False only when the rebuild on open failed; `get_tips` then falls back
    /// to the full scan rather than answer from an incomplete index.
    tips_indexed: AtomicBool,
    /// S3-7: whether the sibling height index (`HEIGHT_SIBLINGS_PREFIX`) and
    /// the stored-block count (`BLOCK_COUNT_KEY`) describe this store. False
    /// only when the rebuild on open failed; the readers then answer `None`
    /// (unknown) instead of an incomplete answer.
    height_indexed: AtomicBool,
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
        let store = Self {
            db,
            cached_latest_height: Arc::new(AtomicU64::new(initial)),
            put_lock: std::sync::Mutex::new(()),
            tips_indexed: AtomicBool::new(false),
            height_indexed: AtomicBool::new(false),
        };
        match store.ensure_tips_index() {
            Ok(()) => store.tips_indexed.store(true, AtomicOrdering::SeqCst),
            Err(e) => warn!(
                "tips index could not be built ({e}); get_tips falls back to a full store scan"
            ),
        }
        match store.ensure_height_index() {
            Ok(()) => store.height_indexed.store(true, AtomicOrdering::SeqCst),
            Err(e) => warn!(
                "sibling height index could not be built ({e}); citrate_getBlocksAtHeight and \
                 the stored-block count answer unknown"
            ),
        }
        store
    }

    /// S3-7: make the sibling height index and the stored-block count describe
    /// the store. A no-op when the marker names the current latest height;
    /// otherwise (a data dir written by a binary without them) one scan of
    /// `CF_HEADERS` and an atomic rewrite of every entry, the count and the
    /// marker, as [`Self::ensure_tips_index`] does for the tips index.
    fn ensure_height_index(&self) -> Result<()> {
        let _put_guard = self.put_lock.lock().unwrap_or_else(|e| e.into_inner());
        let latest = self.cached_latest_height.load(AtomicOrdering::SeqCst);
        if self
            .db
            .get_cf(CF_METADATA, HEIGHT_INDEX_MARKER_KEY)?
            .as_deref()
            == Some(latest.to_be_bytes().as_slice())
        {
            return Ok(());
        }
        let mut entries: Vec<(u64, Hash)> = Vec::new();
        for (key, value) in self.db.iter_cf(CF_HEADERS)? {
            let Some(hash) = Hash::try_from_bytes(key.as_ref()) else {
                continue;
            };
            // A block counts (and is indexed) only when its body is stored too.
            if !self.db.exists_cf(CF_BLOCKS, hash.as_bytes())? {
                continue;
            }
            if let Ok(header) = bincode::deserialize::<BlockHeader>(&value) {
                entries.push((header.height, hash));
            }
        }
        let mut stale: Vec<Vec<u8>> = Vec::new();
        self.db
            .for_each_prefix_key_cf(CF_METADATA, HEIGHT_SIBLINGS_PREFIX, |key| {
                stale.push(key.to_vec());
                Ok(())
            })?;
        let mut batch = self.db.batch();
        for key in &stale {
            self.db.batch_delete_cf(&mut batch, CF_METADATA, key)?;
        }
        for (height, hash) in &entries {
            self.db
                .batch_put_cf(&mut batch, CF_METADATA, &sibling_key(*height, hash), &[])?;
        }
        let count = u64::try_from(entries.len()).unwrap_or(u64::MAX);
        self.db.batch_put_cf(
            &mut batch,
            CF_METADATA,
            BLOCK_COUNT_KEY,
            &count.to_be_bytes(),
        )?;
        self.db.batch_put_cf(
            &mut batch,
            CF_METADATA,
            HEIGHT_INDEX_MARKER_KEY,
            &latest.to_be_bytes(),
        )?;
        self.db.write_batch_sync(batch)?;
        info!(
            "sibling height index rebuilt from a full scan: {} block(s) at latest height {}",
            count, latest
        );
        Ok(())
    }

    fn read_block_count(&self) -> Result<u64> {
        Ok(self
            .db
            .get_cf(CF_METADATA, BLOCK_COUNT_KEY)?
            .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
            .map(u64::from_be_bytes)
            .unwrap_or(0))
    }

    /// S3-7 (`citrate_getBlocksAtHeight`): the hash of every stored block at
    /// `height`, siblings included, ascending by hash. Data source: the
    /// sibling height index (`CF_METADATA` `hsib:` ‖ height ‖ hash), written in
    /// the same batch as the block by [`Self::put_block`] and removed in the
    /// same batch by [`Self::delete_block`] / [`Self::purge_blocks`]. Unlike
    /// [`Self::get_block_by_height`] it never drops a sibling. An error when
    /// the index could not be built on open (never a partial answer).
    pub fn get_blocks_at_height(&self, height: u64) -> Result<Vec<Hash>> {
        if !self.height_indexed.load(AtomicOrdering::SeqCst) {
            anyhow::bail!("the sibling height index is not built on this node");
        }
        let prefix = sibling_prefix(height);
        let mut out = Vec::new();
        self.db
            .for_each_prefix_key_cf(CF_METADATA, &prefix, |key| {
                if let Some(hash) = key.get(prefix.len()..).and_then(Hash::try_from_bytes) {
                    out.push(hash);
                }
                Ok(())
            })?;
        out.sort();
        Ok(out)
    }

    /// S3-7 (`citrate_getDagStats.totalBlocks`): the number of blocks in this
    /// node's chain store (`CF_BLOCKS`). Data source: the `block_count_v1`
    /// counter, changed in the same batch as every block write or removal.
    /// `None` when the counter could not be built on open. A pruned store
    /// counts only what it still holds.
    pub fn stored_block_count(&self) -> Result<Option<u64>> {
        if !self.height_indexed.load(AtomicOrdering::SeqCst) {
            return Ok(None);
        }
        Ok(Some(self.read_block_count()?))
    }

    /// Make the tips index describe the store: a no-op when its marker names
    /// the current latest height, otherwise one full scan (a data dir written
    /// by a binary without the index, or one that stored blocks after this
    /// binary last wrote it) and an atomic rewrite of every tip key plus the
    /// marker.
    fn ensure_tips_index(&self) -> Result<()> {
        let _put_guard = self.put_lock.lock().unwrap_or_else(|e| e.into_inner());
        let latest = self.cached_latest_height.load(AtomicOrdering::SeqCst);
        if self
            .db
            .get_cf(CF_METADATA, TIPS_INDEX_MARKER_KEY)?
            .as_deref()
            == Some(latest.to_be_bytes().as_slice())
        {
            return Ok(());
        }
        let tips = self.scan_tips()?;
        let mut stale: Vec<Vec<u8>> = Vec::new();
        self.db
            .for_each_prefix_key_cf(CF_METADATA, TIPS_INDEX_PREFIX, |key| {
                stale.push(key.to_vec());
                Ok(())
            })?;
        let mut batch = self.db.batch();
        for key in &stale {
            self.db.batch_delete_cf(&mut batch, CF_METADATA, key)?;
        }
        for hash in &tips {
            self.db
                .batch_put_cf(&mut batch, CF_METADATA, &tip_key(hash), &[])?;
        }
        self.db.batch_put_cf(
            &mut batch,
            CF_METADATA,
            TIPS_INDEX_MARKER_KEY,
            &latest.to_be_bytes(),
        )?;
        self.db.write_batch_sync(batch)?;
        info!(
            "tips index rebuilt from a full scan: {} tip(s) at latest height {}",
            tips.len(),
            latest
        );
        Ok(())
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
        // S3-7: a re-put of a stored block does not count it twice.
        let is_new = !self.db.exists_cf(CF_BLOCKS, hash.as_bytes())?;

        let mut batch = self.db.batch();

        // S3-7: sibling height index and stored-block count, same batch.
        self.db.batch_put_cf(
            &mut batch,
            CF_METADATA,
            &sibling_key(block.header.height, &hash),
            &[],
        )?;
        if is_new {
            let count = self.read_block_count()?.saturating_add(1);
            self.db.batch_put_cf(
                &mut batch,
                CF_METADATA,
                BLOCK_COUNT_KEY,
                &count.to_be_bytes(),
            )?;
        }

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

        // Tips index (planset H7): this block is a tip unless a child was
        // stored before it; every parent stops being one.
        if !relation_has_child(
            self.db
                .get_cf(CF_DAG_RELATIONS, &parent_children_key(&hash))?
                .as_deref(),
        ) {
            self.db
                .batch_put_cf(&mut batch, CF_METADATA, &tip_key(&hash), &[])?;
        }
        for parent in block.parents() {
            self.db
                .batch_delete_cf(&mut batch, CF_METADATA, &tip_key(&parent))?;
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
            // The tips index describes the store at this height.
            self.db.batch_put_cf(
                &mut batch,
                CF_METADATA,
                TIPS_INDEX_MARKER_KEY,
                &new_height.to_be_bytes(),
            )?;
            // So do the sibling height index and the count, once built.
            if self.height_indexed.load(AtomicOrdering::SeqCst) {
                self.db.batch_put_cf(
                    &mut batch,
                    CF_METADATA,
                    HEIGHT_INDEX_MARKER_KEY,
                    &new_height.to_be_bytes(),
                )?;
            }
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

    /// The block on this node's executed chain at `height`: the block reached
    /// by following `selected_parent_hash` links down from the applied tip.
    /// This is what a by-number RPC lookup must name.
    ///
    /// [`Self::get_block_by_height`] is NOT that: it keeps the last block
    /// STORED at a height, which can be a sibling that never executed. The
    /// answer here comes from the canonical height index, which every write of
    /// the applied tip rewrites in the same batch (see
    /// [`stage_canonical_index`]). One extra read checks that the index
    /// describes the current applied tip; if it does not (a data dir written by
    /// a binary without the index), it is rebuilt before answering.
    ///
    /// * No applied tip (nothing executed yet): the stored index answers.
    /// * Above the applied tip: the stored index answers (admitted blocks that
    ///   have not executed yet; there is no canonical answer there yet).
    /// * Below a hole in the executed chain's stored ancestry: `None`, never a
    ///   guess.
    pub fn get_canonical_block_by_height(&self, height: u64) -> Result<Option<Hash>> {
        let applied = match self.get_applied_tip()? {
            Some(tip) => tip,
            None => return self.get_block_by_height(height),
        };
        let mut marker = read_canonical_marker(&self.db)?;
        if marker.map(|m| (m.hash, m.height)) != Some(applied) {
            self.sync_canonical_index()?;
            marker = read_canonical_marker(&self.db)?;
        }
        let Some(m) = marker else {
            return self.get_block_by_height(height);
        };
        if height > m.height {
            return self.get_block_by_height(height);
        }
        if height < m.floor {
            return Ok(None);
        }
        read_canonical_entry(&self.db, height)
    }

    /// The applied tip `(hash, height)` the canonical height index describes,
    /// or `None` before it has been built.
    pub fn canonical_index_tip(&self) -> Result<Option<(Hash, u64)>> {
        Ok(read_canonical_marker(&self.db)?.map(|m| (m.hash, m.height)))
    }

    /// Bring the canonical height index to the persisted applied tip. A no-op
    /// when it already describes that tip. Called on the first read after an
    /// upgrade and at node start; tip writes keep it current afterwards.
    pub fn sync_canonical_index(&self) -> Result<()> {
        let _guard = canonical_index_lock();
        let Some((hash, height)) = self.get_applied_tip()? else {
            return Ok(());
        };
        if read_canonical_marker(&self.db)?.map(|m| (m.hash, m.height)) == Some((hash, height)) {
            return Ok(());
        }
        let mut batch = self.db.batch();
        let rewritten = stage_canonical_index(&self.db, &mut batch, &hash, height)?;
        self.db.write_batch_sync(batch)?;
        if rewritten > 1 {
            info!(
                "canonical height index rebuilt to {} @ {} ({} height(s) rewritten)",
                hash, height, rewritten
            );
        }
        Ok(())
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
            if let Some((b'h', h)) = key.split_first() {
                let Ok(height_bytes) = <[u8; 8]>::try_from(h) else {
                    continue;
                };
                let height = u64::from_be_bytes(height_bytes);
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
            max_height = max_height.saturating_sub(1); // loop guard: max_height > 0
        }
        Ok(max_height)
    }

    /// Execute-on-receive: persist the applied-tip pointer (the block whose
    /// post-execution state the executor now reflects). Written after
    /// `apply_block` succeeds. A single 40-byte value keeps the hash and
    /// height mutually consistent (no torn read across two keys).
    ///
    /// The canonical height index is rewritten for the new tip in the same
    /// batch ([`stage_canonical_index`]). When it already describes this tip
    /// (the usual case: the state commit that moved the tip staged it), this is
    /// the single point write it always was.
    pub fn put_applied_tip(&self, hash: &Hash, height: u64) -> Result<()> {
        let buf = applied_tip_bytes(hash, height);
        let _guard = canonical_index_lock();
        if read_canonical_marker(&self.db)?.map(|m| (m.hash, m.height)) == Some((*hash, height)) {
            return self.db.put_cf(CF_METADATA, APPLIED_TIP_KEY, &buf);
        }
        let mut batch = self.db.batch();
        stage_canonical_index(&self.db, &mut batch, hash, height)?;
        self.db
            .batch_put_cf(&mut batch, CF_METADATA, APPLIED_TIP_KEY, &buf)?;
        self.db.write_batch_sync(batch)
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
                let hash = match Hash::try_from_bytes(&bytes) {
                    Some(h) => h,
                    None => return Ok(None),
                };
                let Some(height_bytes) =
                    bytes.get(32..40).and_then(|s| <[u8; 8]>::try_from(s).ok())
                else {
                    return Ok(None);
                };
                let height = u64::from_be_bytes(height_bytes);
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

    /// Return the current DAG tips (blocks without known children), sorted by
    /// height descending.
    ///
    /// Cost: O(tips). Read from the tips index, which every write that changes
    /// the tip set maintains in its own batch (planset H7, ADR CV-6). It used to
    /// scan every key of CF_BLOCKS and CF_DAG_RELATIONS on each call.
    pub fn get_tips(&self) -> Result<Vec<Hash>> {
        let hashes = if self.tips_indexed.load(AtomicOrdering::SeqCst) {
            let mut hashes = Vec::new();
            self.db
                .for_each_prefix_key_cf(CF_METADATA, TIPS_INDEX_PREFIX, |key| {
                    if let Some(hash) = key
                        .get(TIPS_INDEX_PREFIX.len()..)
                        .and_then(Hash::try_from_bytes)
                    {
                        hashes.push(hash);
                    }
                    Ok(())
                })?;
            hashes
        } else {
            self.scan_tips()?
        };
        let mut tips: Vec<(u64, Hash)> = Vec::with_capacity(hashes.len());
        for hash in hashes {
            let height = self
                .get_header(&hash)?
                .map(|header| header.height)
                .unwrap_or_default();
            tips.push((height, hash));
        }
        tips.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
        Ok(tips.into_iter().map(|(_, hash)| hash).collect())
    }

    /// The tip set by a full scan: every stored block whose children relation
    /// names no child. O(store). Used to build the tips index on open, and as
    /// the reference the index is tested against.
    pub fn scan_tips(&self) -> Result<Vec<Hash>> {
        let mut all_blocks = Vec::new();
        self.db.for_each_prefix_key_cf(CF_BLOCKS, &[], |key| {
            if key.len() == 32 {
                all_blocks.push(Hash::from_bytes(key));
            }
            Ok(())
        })?;
        let mut parents_with_children = HashSet::new();
        for (key, value) in self.db.iter_cf(CF_DAG_RELATIONS)? {
            let key_bytes = key.as_ref();
            if key_bytes.len() == 33
                && key_bytes.first() == Some(&b'c')
                && relation_has_child(Some(value.as_ref()))
            {
                // SECREM-01 CONS-6: key length checked above (33), so the
                // 32-byte tail is sound; use the fallible decode anyway to
                // keep the no-panic invariant uniform across this module.
                if let Some(parent_hash) = key_bytes.get(1..).and_then(Hash::try_from_bytes) {
                    parents_with_children.insert(parent_hash);
                }
            }
        }
        Ok(all_blocks
            .into_iter()
            .filter(|h| !parents_with_children.contains(h))
            .collect())
    }

    /// Delete a block and its associated data
    pub fn delete_block(&self, hash: &Hash) -> Result<()> {
        // The children lists and the tips index are read-modify-writes, as in
        // `put_block`.
        let _put_guard = self.put_lock.lock().unwrap_or_else(|e| e.into_inner());
        // Get block first to clean up relationships
        if let Some(block) = self.get_block(hash)? {
            let mut batch = self.db.batch();
            self.db
                .batch_delete_cf(&mut batch, CF_METADATA, &tip_key(hash))?;

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

            // S3-7: sibling height index and stored-block count.
            self.db.batch_delete_cf(
                &mut batch,
                CF_METADATA,
                &sibling_key(block.header.height, hash),
            )?;
            let count = self.read_block_count()?.saturating_sub(1);
            self.db.batch_put_cf(
                &mut batch,
                CF_METADATA,
                BLOCK_COUNT_KEY,
                &count.to_be_bytes(),
            )?;

            // Clean up parent relationships
            for parent in block.parents() {
                let parent_children_key = parent_children_key(&parent);
                if let Ok(mut children) = self.get_children(&parent) {
                    children.retain(|&child| child != *hash);
                    // A stored parent whose last child goes is a tip again.
                    if children.is_empty() && self.has_block(&parent)? {
                        self.db
                            .batch_put_cf(&mut batch, CF_METADATA, &tip_key(&parent), &[])?;
                    }
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
        let mut purged: u64 = 0;
        for hash in doomed {
            let Some(block) = self.get_block(hash)? else {
                continue;
            };
            purged = purged.saturating_add(1);
            // S3-7: sibling height index.
            self.db.batch_delete_cf(
                &mut batch,
                CF_METADATA,
                &sibling_key(block.header.height, hash),
            )?;
            self.db
                .batch_delete_cf(&mut batch, CF_BLOCKS, hash.as_bytes())?;
            self.db
                .batch_delete_cf(&mut batch, CF_HEADERS, hash.as_bytes())?;
            self.db
                .batch_delete_cf(&mut batch, CF_DAG_RELATIONS, &parent_children_key(hash))?;
            self.db
                .batch_delete_cf(&mut batch, CF_METADATA, &tip_key(hash))?;
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
                if kept.is_empty() && self.has_block(parent)? {
                    self.db
                        .batch_put_cf(&mut batch, CF_METADATA, &tip_key(parent), &[])?;
                }
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
        self.db.batch_put_cf(
            &mut batch,
            CF_METADATA,
            TIPS_INDEX_MARKER_KEY,
            &latest.to_be_bytes(),
        )?;
        // S3-7: stored-block count and the sibling-index marker.
        let count = self.read_block_count()?.saturating_sub(purged);
        self.db.batch_put_cf(
            &mut batch,
            CF_METADATA,
            BLOCK_COUNT_KEY,
            &count.to_be_bytes(),
        )?;
        if self.height_indexed.load(AtomicOrdering::SeqCst) {
            self.db.batch_put_cf(
                &mut batch,
                CF_METADATA,
                HEIGHT_INDEX_MARKER_KEY,
                &latest.to_be_bytes(),
            )?;
        }
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

/// Canonical height index entry prefix (`CF_METADATA`): the key is this prefix
/// followed by the 8-byte big-endian height, the value the 32-byte hash of the
/// block on the executed chain at that height. Separate from the stored index
/// (`h` ‖ height), which keeps the last block stored at a height.
const CANONICAL_HEIGHT_PREFIX: &[u8] = b"canonical_h:";

/// The applied tip the canonical index describes, and the lowest height it
/// covers: hash[32] ‖ height_be[8] ‖ floor_be[8]. Entries at `floor..=height`
/// are the executed chain of that tip; entries above `height` are leftovers of
/// an abandoned higher tip and are never read.
const CANONICAL_MARKER_KEY: &[u8] = b"canonical_tip";

/// Serialises every read-modify-write of the canonical index (staging reads
/// the marker and the entries it then overwrites). Process-wide: the block
/// store and the state store both write the applied tip.
static CANONICAL_INDEX_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Take [`CANONICAL_INDEX_LOCK`]. A poisoned lock is recovered: every index
/// write is one atomic batch, so a panic cannot leave a half-written index.
pub(crate) fn canonical_index_lock() -> std::sync::MutexGuard<'static, ()> {
    CANONICAL_INDEX_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// The 40-byte applied-tip value: hash[32] ‖ height_be[8].
pub(crate) fn applied_tip_bytes(hash: &Hash, height: u64) -> [u8; 40] {
    let mut buf = [0u8; 40];
    buf[..32].copy_from_slice(hash.as_bytes());
    buf[32..].copy_from_slice(&height.to_be_bytes());
    buf
}

fn canonical_key(height: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(CANONICAL_HEIGHT_PREFIX.len().saturating_add(8));
    key.extend_from_slice(CANONICAL_HEIGHT_PREFIX);
    key.extend_from_slice(&height.to_be_bytes());
    key
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CanonicalMarker {
    hash: Hash,
    height: u64,
    floor: u64,
}

fn read_canonical_marker(db: &RocksDB) -> Result<Option<CanonicalMarker>> {
    let Some(bytes) = db.get_cf(CF_METADATA, CANONICAL_MARKER_KEY)? else {
        return Ok(None);
    };
    // A short or corrupt marker reads as "no index": the next sync rebuilds it.
    let (Some(hash), Some(height), Some(floor)) = (
        bytes.get(..32).and_then(Hash::try_from_bytes),
        bytes
            .get(32..40)
            .and_then(|s| <[u8; 8]>::try_from(s).ok())
            .map(u64::from_be_bytes),
        bytes
            .get(40..48)
            .and_then(|s| <[u8; 8]>::try_from(s).ok())
            .map(u64::from_be_bytes),
    ) else {
        return Ok(None);
    };
    Ok(Some(CanonicalMarker {
        hash,
        height,
        floor,
    }))
}

fn read_canonical_entry(db: &RocksDB, height: u64) -> Result<Option<Hash>> {
    Ok(db
        .get_cf(CF_METADATA, &canonical_key(height))?
        .and_then(|v| Hash::try_from_bytes(&v)))
}

fn read_header(db: &RocksDB, hash: &Hash) -> Result<Option<BlockHeader>> {
    match db.get_cf(CF_HEADERS, hash.as_bytes())? {
        Some(bytes) => Ok(bincode::deserialize(&bytes).ok()),
        None => Ok(None),
    }
}

/// Stage, into `batch`, the canonical height index for the applied tip
/// `(tip, tip_height)`; returns the number of heights written. The caller
/// commits `batch` together with the applied-tip pointer while holding
/// [`canonical_index_lock`], so the index and the tip never disagree on disk.
///
/// The walk follows `selected_parent_hash` down from the tip, writing one
/// entry per height, and stops at the first height where the index of the
/// previous tip already names the same block: the previous index is the
/// executed chain of the previous tip, and the selected-parent chain below a
/// shared block is shared, so everything under it is already right. An
/// extension costs one step, a reorg its depth, and a store with no index (a
/// data dir from before this index) one walk to genesis.
///
/// A header missing from the store (or whose height does not match its
/// position) ends the walk early; the marker's floor then records the lowest
/// height the index covers, and lookups below it answer `None`.
pub(crate) fn stage_canonical_index(
    db: &RocksDB,
    batch: &mut rocksdb::WriteBatch,
    tip: &Hash,
    tip_height: u64,
) -> Result<u64> {
    let previous = read_canonical_marker(db)?;
    if previous.map(|m| (m.hash, m.height)) == Some((*tip, tip_height)) {
        return Ok(0);
    }
    let mut written = 0u64;
    let mut cur = *tip;
    let mut height = tip_height;
    let floor = loop {
        if let Some(p) = previous {
            if height >= p.floor
                && height <= p.height
                && read_canonical_entry(db, height)? == Some(cur)
            {
                break p.floor;
            }
        }
        let header = match read_header(db, &cur)? {
            Some(h) if h.height == height => h,
            // Not stored (or inconsistent): nothing at or below this height is known.
            _ => break height.saturating_add(1),
        };
        db.batch_put_cf(batch, CF_METADATA, &canonical_key(height), cur.as_bytes())?;
        written = written.saturating_add(1);
        if height == 0 {
            break 0;
        }
        cur = header.selected_parent_hash;
        height = height.saturating_sub(1); // height > 0 checked above
    };
    let mut marker = [0u8; 48];
    marker[..40].copy_from_slice(&applied_tip_bytes(tip, tip_height));
    marker[40..].copy_from_slice(&floor.to_be_bytes());
    db.batch_put_cf(batch, CF_METADATA, CANONICAL_MARKER_KEY, &marker)?;
    Ok(written)
}

// Key generation helpers
/// DAG tips index (`CF_METADATA`): this prefix followed by the 32-byte hash of
/// a stored block with no stored child. Maintained in the same batch as every
/// write that changes the tip set (`put_block`, `delete_block`,
/// `purge_blocks`), so `get_tips` reads O(tips) keys instead of scanning
/// CF_BLOCKS and CF_DAG_RELATIONS (planset H7, ADR CV-6).
const TIPS_INDEX_PREFIX: &[u8] = b"tips_idx:";

/// Present once the tips index describes the store. A data dir written by a
/// binary without the index has no marker; [`BlockStore::new`] rebuilds the
/// index from a full scan once and writes the marker in the same batch.
const TIPS_INDEX_MARKER_KEY: &[u8] = b"tips_idx_v1";

fn tip_key(hash: &Hash) -> Vec<u8> {
    let mut k = Vec::with_capacity(TIPS_INDEX_PREFIX.len().saturating_add(32));
    k.extend_from_slice(TIPS_INDEX_PREFIX);
    k.extend_from_slice(hash.as_bytes());
    k
}

/// Whether a stored `CF_DAG_RELATIONS` children value names at least one
/// child. Absent, empty, or an empty list: no child. A value that does not
/// decode counts as a child (it is not proof the block has none), as the
/// full-scan rule always did for non-empty bytes.
fn relation_has_child(value: Option<&[u8]>) -> bool {
    match value {
        None => false,
        Some([]) => false,
        Some(bytes) => match bincode::deserialize::<Vec<Hash>>(bytes) {
            Ok(children) => !children.is_empty(),
            Err(_) => true,
        },
    }
}

/// S3-7 sibling height index (`CF_METADATA`): this prefix, the 8-byte
/// big-endian height, then the 32-byte block hash; empty value. One entry per
/// stored block, so every sibling at a height is listed (the `h` ‖ height
/// index keeps only the last one stored). Non-consensus RPC metadata.
const HEIGHT_SIBLINGS_PREFIX: &[u8] = b"hsib:";

/// S3-7: number of blocks in `CF_BLOCKS`, 8-byte big-endian.
const BLOCK_COUNT_KEY: &[u8] = b"block_count_v1";

/// S3-7: the latest height at which the sibling index and the count were known
/// to describe the store (as [`TIPS_INDEX_MARKER_KEY`] for the tips index).
const HEIGHT_INDEX_MARKER_KEY: &[u8] = b"hsib_idx_v1";

fn sibling_prefix(height: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(HEIGHT_SIBLINGS_PREFIX.len().saturating_add(8));
    k.extend_from_slice(HEIGHT_SIBLINGS_PREFIX);
    k.extend_from_slice(&height.to_be_bytes());
    k
}

fn sibling_key(height: u64, hash: &Hash) -> Vec<u8> {
    let mut k = sibling_prefix(height);
    k.extend_from_slice(hash.as_bytes());
    k
}

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

    /// PANIC-S1 mutation: per-epoch reward snapshots are keyed by height, so two
    /// heights never overwrite each other or the latest-only snapshot.
    #[test]
    fn panic_s1_reward_snapshot_at_is_keyed_by_height() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(RocksDB::open(temp_dir.path()).unwrap());
        let store = BlockStore::new(db);

        store.put_reward_snapshot(b"latest").unwrap();
        store.put_reward_snapshot_at(5, b"five").unwrap();
        store.put_reward_snapshot_at(6, b"six").unwrap();

        assert_eq!(
            store.get_reward_snapshot_at(5).unwrap().as_deref(),
            Some(&b"five"[..])
        );
        assert_eq!(
            store.get_reward_snapshot_at(6).unwrap().as_deref(),
            Some(&b"six"[..])
        );
        assert_eq!(
            store.get_reward_snapshot().unwrap().as_deref(),
            Some(&b"latest"[..])
        );
        assert!(store.get_reward_snapshot_at(7).unwrap().is_none());
    }

    /// PANIC-S1 mutation: only a 33-byte `c`-prefixed relation with a non-empty child
    /// list removes a block from the tip set.
    #[test]
    fn panic_s1_get_tips_ignores_malformed_child_relations() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(RocksDB::open(temp_dir.path()).unwrap());
        let store = BlockStore::new(db.clone());

        let a = create_test_block(1, Hash::new([0xA0; 32]));
        let b = create_test_block(2, Hash::new([0xB0; 32]));
        store.put_block(&a).unwrap();
        store.put_block(&b).unwrap();

        let mut wrong_prefix = vec![b'x'];
        wrong_prefix.extend_from_slice(a.header.block_hash.as_bytes());
        db.put_cf(CF_DAG_RELATIONS, &wrong_prefix, b"nonempty")
            .unwrap();
        db.put_cf(
            CF_DAG_RELATIONS,
            &parent_children_key(&b.header.block_hash),
            b"",
        )
        .unwrap();

        let tips = store.get_tips().unwrap();
        assert!(tips.contains(&a.header.block_hash));
        assert!(tips.contains(&b.header.block_hash));
    }

    /// The applied-tip pointer written by the state store is the one the block store
    /// reads back.
    #[test]
    fn panic_s1_applied_tip_round_trips_and_short_value_is_none() {
        use citrate_execution::executor::StateStoreTrait;
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(RocksDB::open(temp_dir.path()).unwrap());
        let store = BlockStore::new(db.clone());
        let state = crate::state::StateStore::new(db.clone());

        assert!(store.get_applied_tip().unwrap().is_none());
        let tip = Hash::new([0x5A; 32]);
        state.put_applied_tip_meta(&tip, 42).unwrap();
        assert_eq!(store.get_applied_tip().unwrap(), Some((tip, 42)));

        db.put_cf(CF_METADATA, APPLIED_TIP_KEY, &[0x5A; 39])
            .unwrap();
        assert!(store.get_applied_tip().unwrap().is_none());
    }

    /// PANIC-S1 mutation: a block with a stored child is not a tip.
    #[test]
    fn panic_s1_get_tips_excludes_parents() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(RocksDB::open(temp_dir.path()).unwrap());
        let store = BlockStore::new(db);

        let parent = create_test_block(1, Hash::new([0xA0; 32]));
        let child = create_test_block(2, parent.header.block_hash);
        store.put_block(&parent).unwrap();
        store.put_block(&child).unwrap();

        assert_eq!(store.get_tips().unwrap(), vec![child.header.block_hash]);
    }

    /// Write `n` chain blocks (plus two side tips) as `put_block` lays them out,
    /// in one unsynced batch (setup speed only), then open a `BlockStore` on the
    /// result: a data dir written by an earlier binary.
    fn store_of(n: u64) -> (TempDir, BlockStore, Vec<Hash>) {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(RocksDB::open(temp_dir.path()).unwrap());
        let mk = |tag: u8, height: u64, parent: Hash| {
            let mut h = [tag; 32];
            h[..8].copy_from_slice(&height.to_be_bytes());
            BlockBuilder::new()
                .hash(Hash::new(h))
                .parent(parent)
                .height(height)
                .timestamp(1_000_000 + height)
                .blue_score(height)
                .blue_work(u128::from(height))
                .proposer(PublicKey::new([1; 32]))
                .build_unhashed()
        };
        let mut batch = db.batch();
        let write = |b: &Block, batch: &mut rocksdb::WriteBatch| {
            let hash = b.hash();
            db.batch_put_cf(
                batch,
                CF_BLOCKS,
                hash.as_bytes(),
                &bincode::serialize(b).unwrap(),
            )
            .unwrap();
            db.batch_put_cf(
                batch,
                CF_HEADERS,
                hash.as_bytes(),
                &bincode::serialize(&b.header).unwrap(),
            )
            .unwrap();
            db.batch_put_cf(
                batch,
                CF_METADATA,
                &height_to_key(b.header.height),
                hash.as_bytes(),
            )
            .unwrap();
        };
        let mut parent = Hash::default();
        let mut chain = Vec::new();
        for h in 0..n {
            let b = mk(0x11, h, parent);
            write(&b, &mut batch);
            if h > 0 {
                db.batch_put_cf(
                    &mut batch,
                    CF_DAG_RELATIONS,
                    &parent_children_key(&parent),
                    &bincode::serialize(&vec![b.hash()]).unwrap(),
                )
                .unwrap();
            }
            parent = b.hash();
            chain.push(b);
        }
        let mut tips = vec![parent];
        // Two side tips off the middle of the chain.
        let mid = chain[(n / 2) as usize].clone();
        let s1 = mk(0x22, mid.header.height + 1, mid.hash());
        let s2 = mk(0x33, mid.header.height + 1, mid.hash());
        write(&s1, &mut batch);
        write(&s2, &mut batch);
        let mid_child = chain[(n / 2 + 1) as usize].hash();
        db.batch_put_cf(
            &mut batch,
            CF_DAG_RELATIONS,
            &parent_children_key(&mid.hash()),
            &bincode::serialize(&vec![mid_child, s1.hash(), s2.hash()]).unwrap(),
        )
        .unwrap();
        db.batch_put_cf(
            &mut batch,
            CF_METADATA,
            LATEST_HEIGHT_KEY,
            &(n - 1).to_be_bytes(),
        )
        .unwrap();
        db.write_batch(batch).unwrap();
        tips.push(s1.hash());
        tips.push(s2.hash());
        (temp_dir, BlockStore::new(db), tips)
    }

    fn fastest_get_tips(store: &BlockStore) -> std::time::Duration {
        (0..5)
            .map(|_| {
                let t = std::time::Instant::now();
                std::hint::black_box(store.get_tips().unwrap());
                t.elapsed()
            })
            .min()
            .unwrap()
    }

    /// RED (planset H7, ADR CV-6). `get_tips` read every key of CF_BLOCKS and
    /// CF_DAG_RELATIONS on every call, and `citrate_getDagStats` (polled by the
    /// indexer ~1.4/s) calls it, so its cost grew with the whole store. With
    /// the same three tips, a store 100x larger must not make it measurably
    /// slower.
    #[test]
    fn get_tips_cost_is_independent_of_store_size() {
        let (_small_dir, small, small_tips) = store_of(200);
        let (_big_dir, big, big_tips) = store_of(20_000);
        let mut want = small_tips.clone();
        want.sort();
        let mut got = small.get_tips().unwrap();
        got.sort();
        assert_eq!(got, want, "small store tips");
        let mut want = big_tips.clone();
        want.sort();
        let mut got = big.get_tips().unwrap();
        got.sort();
        assert_eq!(got, want, "big store tips");

        let t_small = fastest_get_tips(&small);
        let t_big = fastest_get_tips(&big);
        eprintln!("GETTIPS 3 tips: 200 blocks {t_small:?}, 20,000 blocks {t_big:?}");
        assert!(
            t_big <= t_small * 4 + std::time::Duration::from_millis(1),
            "get_tips on 20,000 blocks took {t_big:?} vs {t_small:?} on 200: it scales with \
             the store, not with the tips"
        );
    }

    fn sorted(mut v: Vec<Hash>) -> Vec<Hash> {
        v.sort();
        v
    }

    fn dag_block(id: u16, height: u64, parents: &[Hash]) -> Block {
        let mut h = [0x5C; 32];
        h[..2].copy_from_slice(&id.to_be_bytes());
        h[2..10].copy_from_slice(&height.to_be_bytes());
        BlockBuilder::new()
            .hash(Hash::new(h))
            .parent(parents.first().copied().unwrap_or_default())
            .merge_parents(parents.iter().skip(1).copied().collect())
            .height(height)
            .timestamp(1_000_000 + height)
            .blue_score(height)
            .blue_work(u128::from(height))
            .proposer(PublicKey::new([1; 32]))
            .build_unhashed()
    }

    /// The maintained tips index answers exactly what a full scan answers,
    /// through out-of-order puts (a child stored before its parent), merges,
    /// deletes (pruning) and purges (rollback), and across a reopen.
    #[test]
    fn tips_index_matches_a_full_scan_through_put_delete_and_purge() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(RocksDB::open(temp_dir.path()).unwrap());
        let store = BlockStore::new(db.clone());
        let check = |store: &BlockStore, what: &str| {
            assert_eq!(
                sorted(store.get_tips().unwrap()),
                sorted(store.scan_tips().unwrap()),
                "{what}"
            );
        };
        // Deterministic pseudo-random DAG: each block names 1-3 parents among
        // the last 6 blocks; every 5th block is stored after its successor.
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let g = dag_block(0, 0, &[]);
        store.put_block(&g).unwrap();
        let mut blocks = vec![g];
        let mut held: Option<Block> = None;
        for id in 1..300u16 {
            let n = blocks.len();
            let k = 1 + (next() % 3) as usize;
            let mut parents = Vec::new();
            for _ in 0..k {
                let p = blocks[n - 1 - (next() as usize % n.min(6))].hash();
                if !parents.contains(&p) {
                    parents.push(p);
                }
            }
            let height = parents
                .iter()
                .filter_map(|p| blocks.iter().find(|b| b.hash() == *p))
                .map(|b| b.header.height)
                .max()
                .unwrap()
                + 1;
            let b = dag_block(id, height, &parents);
            if id % 5 == 0 {
                held = Some(b.clone());
            } else {
                store.put_block(&b).unwrap();
                if let Some(h) = held.take() {
                    store.put_block(&h).unwrap();
                }
            }
            blocks.push(b);
            check(&store, "after put");
        }
        if let Some(h) = held.take() {
            store.put_block(&h).unwrap();
        }
        check(&store, "all stored");
        // Pruning deletes the oldest blocks one by one.
        for b in blocks.iter().take(40) {
            store.delete_block(&b.hash()).unwrap();
            check(&store, "after delete");
        }
        // Deleting a tip makes its parents tips again where it was their
        // last child.
        for b in blocks.iter().rev().take(10) {
            store.delete_block(&b.hash()).unwrap();
            check(&store, "after deleting a tip");
        }
        // A rollback purges the top of the DAG in one batch.
        let doomed: HashSet<Hash> = blocks
            .iter()
            .rev()
            .skip(10)
            .take(30)
            .map(|b| b.hash())
            .collect();
        store.purge_blocks(&doomed).unwrap();
        check(&store, "after purge");
        assert!(!store.get_tips().unwrap().is_empty(), "purge leaves tips");
        let before = sorted(store.get_tips().unwrap());
        drop(store);
        let reopened = BlockStore::new(db);
        assert_eq!(sorted(reopened.get_tips().unwrap()), before, "reopen");
    }

    /// A data dir written without the index (no marker), or one an older
    /// binary extended after the index was written (marker behind the latest
    /// height), is rebuilt from a full scan on open.
    #[test]
    fn tips_index_is_rebuilt_on_open_when_missing_or_stale() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(RocksDB::open(temp_dir.path()).unwrap());
        let store = BlockStore::new(db.clone());
        let a = create_test_block(1, Hash::new([0xA0; 32]));
        let b = create_test_block(2, a.header.block_hash);
        store.put_block(&a).unwrap();
        store.put_block(&b).unwrap();
        drop(store);

        // No marker and no index: an upgraded data dir.
        db.delete_cf(CF_METADATA, TIPS_INDEX_MARKER_KEY).unwrap();
        db.delete_cf(CF_METADATA, &tip_key(&b.header.block_hash))
            .unwrap();
        let store = BlockStore::new(db.clone());
        assert_eq!(store.get_tips().unwrap(), vec![b.header.block_hash]);
        drop(store);

        // An older binary stored a child of b and bumped the latest height
        // without touching the index.
        let c = create_test_block(3, b.header.block_hash);
        db.put_cf(
            CF_BLOCKS,
            c.header.block_hash.as_bytes(),
            &bincode::serialize(&c).unwrap(),
        )
        .unwrap();
        db.put_cf(
            CF_HEADERS,
            c.header.block_hash.as_bytes(),
            &bincode::serialize(&c.header).unwrap(),
        )
        .unwrap();
        db.put_cf(
            CF_DAG_RELATIONS,
            &parent_children_key(&b.header.block_hash),
            &bincode::serialize(&vec![c.header.block_hash]).unwrap(),
        )
        .unwrap();
        db.put_cf(CF_METADATA, LATEST_HEIGHT_KEY, &3u64.to_be_bytes())
            .unwrap();
        let store = BlockStore::new(db);
        assert_eq!(store.get_tips().unwrap(), vec![c.header.block_hash]);
    }

    // ── S3-7 (CNV-RPC): sibling-complete height index and stored-block count ──

    fn sibling(height: u64, parent: Hash, tag: u8) -> Block {
        let mut b = create_test_block(height, parent);
        b.header.block_hash = Hash::new([tag; 32]);
        b
    }

    /// `citrate_getBlocksAtHeight` needs every stored block at a height. The
    /// `h‖height` index keeps only the last one stored.
    #[test]
    fn s3_7_height_index_keeps_every_sibling_and_follows_delete_and_purge() {
        let temp_dir = TempDir::new().expect("test store op");
        let db = Arc::new(RocksDB::open(temp_dir.path()).expect("test store op"));
        let store = BlockStore::new(db);
        let g = create_test_block(0, Hash::default());
        let a1 = create_test_block(1, g.hash());
        let b1 = sibling(1, g.hash(), 0xB1);
        let c1 = sibling(1, g.hash(), 0xC1);
        for b in [&g, &a1, &b1, &c1] {
            store.put_block(b).expect("test store op");
        }
        let mut want = vec![a1.hash(), b1.hash(), c1.hash()];
        want.sort();
        assert_eq!(store.get_blocks_at_height(1).expect("test store op"), want);
        assert_eq!(
            store.get_blocks_at_height(0).expect("test store op"),
            vec![g.hash()]
        );
        assert!(store
            .get_blocks_at_height(2)
            .expect("test store op")
            .is_empty());

        store.delete_block(&b1.hash()).expect("test store op");
        let mut want = vec![a1.hash(), c1.hash()];
        want.sort();
        assert_eq!(store.get_blocks_at_height(1).expect("test store op"), want);

        let doomed: HashSet<Hash> = [c1.hash()].into_iter().collect();
        store.purge_blocks(&doomed).expect("test store op");
        assert_eq!(
            store.get_blocks_at_height(1).expect("test store op"),
            vec![a1.hash()]
        );
    }

    /// `citrate_getDagStats.totalBlocks` is a maintained counter, not an
    /// estimate (chain#317): a re-put does not count twice; delete and purge
    /// count down.
    #[test]
    fn s3_7_stored_block_count_is_maintained() {
        let temp_dir = TempDir::new().expect("test store op");
        let db = Arc::new(RocksDB::open(temp_dir.path()).expect("test store op"));
        let store = BlockStore::new(db);
        assert_eq!(store.stored_block_count().expect("test store op"), Some(0));
        let g = create_test_block(0, Hash::default());
        let a1 = create_test_block(1, g.hash());
        let b1 = sibling(1, g.hash(), 0xB1);
        for b in [&g, &a1, &b1, &a1] {
            store.put_block(b).expect("test store op");
        }
        assert_eq!(store.stored_block_count().expect("test store op"), Some(3));
        store.delete_block(&b1.hash()).expect("test store op");
        assert_eq!(store.stored_block_count().expect("test store op"), Some(2));
        let doomed: HashSet<Hash> = [a1.hash()].into_iter().collect();
        store.purge_blocks(&doomed).expect("test store op");
        assert_eq!(store.stored_block_count().expect("test store op"), Some(1));
    }

    /// A data dir written by a binary without the index: the open rebuilds the
    /// sibling index and the count from the stored headers once.
    #[test]
    fn s3_7_height_index_and_count_rebuild_for_an_old_data_dir() {
        let temp_dir = TempDir::new().expect("test store op");
        let db = Arc::new(RocksDB::open(temp_dir.path()).expect("test store op"));
        let g = create_test_block(0, Hash::default());
        let a1 = create_test_block(1, g.hash());
        let b1 = sibling(1, g.hash(), 0xB1);
        for b in [&g, &a1, &b1] {
            db.put_cf(
                CF_BLOCKS,
                b.hash().as_bytes(),
                &bincode::serialize(b).expect("test store op"),
            )
            .expect("test store op");
            db.put_cf(
                CF_HEADERS,
                b.hash().as_bytes(),
                &bincode::serialize(&b.header).expect("test store op"),
            )
            .expect("test store op");
        }
        db.put_cf(CF_METADATA, LATEST_HEIGHT_KEY, &1u64.to_be_bytes())
            .expect("test store op");
        let store = BlockStore::new(db);
        let mut want = vec![a1.hash(), b1.hash()];
        want.sort();
        assert_eq!(store.get_blocks_at_height(1).expect("test store op"), want);
        assert_eq!(store.stored_block_count().expect("test store op"), Some(3));
    }
}
