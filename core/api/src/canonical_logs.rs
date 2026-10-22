// citrate/core/api/src/canonical_logs.rs
//
// The block source for `eth_getLogs`: the EXECUTED chain, not the height index.
//
// WHAT EXECUTES
//
// Exactly one block per height executes transactions: the block on the
// selected-parent chain of the applied tip. `CanonicalApplicator::drain_forward`
// (node/src/canonical_apply.rs, `next_persisted_extension`) only applies a child
// whose `selected_parent == tip.hash` and whose height is `tip.height + 1`, and
// `Executor::apply_block_inner` executes `block.transactions` of that one block.
// Merge parents (and losing siblings) are admitted and stored, but their
// transactions are never executed, so they have no receipts.
//
// WHY THE HEIGHT INDEX IS NOT ENOUGH
//
// `BlockStore::put_block` writes `height -> hash` for EVERY admitted block,
// last writer wins. A sibling that arrives after the executed block at the same
// height takes the index entry, and a reader that trusts the index then reads
// the sibling's (never executed) transactions and silently skips the executed
// block's logs. This module instead follows `selected_parent_hash` down from the
// applied tip, which names the executed block at every height.
//
// COST
//
// A walk reads one header per height between its start and `from`. To keep
// deep-history pages O(range), the resolver remembers the executed hash at every
// `CHECKPOINT_STRIDE`-th height once it is at least `SETTLED_DEPTH` below the
// applied tip, and later walks start from the nearest such checkpoint.
//
// CACHE SOUNDNESS
//
// Depth below the tip is NOT a reorg bound: `canonical_apply::MAX_REORG_DEPTH`
// only bounds the in-memory rollback, and a deeper fork is taken by the
// from-genesis spine rebuild (`recover_to_head`), bounded only by the finalized
// floor (0 until checkpoint finality is wired). Such a rebuild can replace
// history arbitrarily deep and finish at the same or a greater height between
// two RPC calls, and the abandoned blocks stay in storage.
//
// So every checkpoint is tied to verified ancestry. The cache records the
// applied tip (`anchor`) the checkpoints were collected under; every checkpoint
// is an ancestor of it. On each call, before any checkpoint is used, the
// resolver finds the highest block shared by the anchor's and the new tip's
// selected-parent chains, walking the higher side down one header at a time.
// Both chains agree at and below that block, so checkpoints at or below its
// height stay and the ones above it are dropped; the anchor then moves to the
// new tip. A tip that extends the anchor shares the anchor itself, and an older
// tip on the anchor's chain (a request that read the tip before a concurrent
// commit, or a rollback) shares itself; checkpoints are always settled below
// either, so neither drops anything. A reorg drops only the checkpoints above
// its fork. A broken walk, or tips or a fork more than `MAX_ANCHOR_WALK` away,
// drops every checkpoint. The walk costs one header per block between the two
// tips and the fork, so it is amortised over chain growth.
//
// A walk runs outside the cache lock, so the anchor usually moves while it
// runs (other requests re-anchor). Its checkpoints are ancestors of the tip it
// started from, which was the anchor at that moment. `generation` changes
// whenever a re-anchor may have dropped one of them: a walk only finds heights
// up to `high_water - SETTLED_DEPTH` (`high_water` = the highest anchor of the
// generation), so a fork at or above that height cannot touch them, and a
// lower fork, a full drop or a purge starts a new generation. A walk publishes
// what it found only when the generation is unchanged since it started.
// Gating on the anchor itself would throw cold-fill progress away whenever the
// tip moves.
//
// MISSING ANCESTORS: ERROR WINS
//
// When the executed chain cannot be followed down to `fromBlock` (a missing or
// malformed ancestor), the resolver returns `LogIndexError::Unavailable`
// (-32603); it never returns the part of the range it could reach. Any other
// range resolver that is combined with this one (for example a finality-tag
// range walk that stops at a missing ancestor) must adopt the same rule: a
// broken walk is an error, never a silently shortened answer.
//
// PER-REQUEST BOUNDS
//
// The resolver returns hashes only; bodies are loaded and dropped one block at a
// time by the caller, so memory per request is one block plus the matched logs.
// Header reads per request are capped at `MAX_HEADER_WALK`. A cold cache deep
// below the tip needs more: the request publishes the checkpoints it reached and
// returns a retryable error, and only one such fill runs at a time.

use std::collections::BTreeMap;
use std::sync::Mutex;

use citrate_consensus::types::{Block, Hash};
use citrate_storage::StorageManager;

/// The widest `eth_getLogs` range: `toBlock - fromBlock` may be at most this
/// (1,001 heights, the same window the old clamp served).
pub const MAX_LOG_BLOCK_RANGE: u64 = 1_000;

/// JSON-RPC error code for a range over [`MAX_LOG_BLOCK_RANGE`]. The repo uses
/// -32005 for "limit exceeded" (see `rate_limit::check_method_budget`).
pub const LOG_RANGE_LIMIT_CODE: i64 = -32005;

/// Operator switch that restores the legacy behaviour: an over-limit range is
/// silently clamped to `fromBlock..=fromBlock+1000` instead of erroring. Set to
/// `1` only while a client that sends unbounded ranges is being migrated; a
/// clamped answer is indistinguishable from "no logs after fromBlock+1000".
pub const LEGACY_CLAMP_ENV: &str = "CITRATE_RPC_GETLOGS_CLAMP_RANGE";

/// Checkpoints are only collected at least this far below the applied tip, so
/// the cache holds stable history rather than churning near the tip. This is a
/// cache policy, not the soundness argument (see "CACHE SOUNDNESS" above).
pub const SETTLED_DEPTH: u64 = 1_000;

/// Widest tip advance the anchor check walks; a larger jump since the previous
/// call drops the cache instead (the next deep query re-walks from the tip).
pub const MAX_ANCHOR_WALK: u64 = 16 * CHECKPOINT_STRIDE;

/// Spacing of cached settled checkpoints.
pub const CHECKPOINT_STRIDE: u64 = 1_024;

/// Whether the node runs with the legacy silent clamp ([`LEGACY_CLAMP_ENV`]).
pub fn legacy_clamp_from_env() -> bool {
    std::env::var(LEGACY_CLAMP_ENV)
        .map(|v| {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false)
}

/// The last height an `eth_getLogs` over `from..=to` reads, or the -32005 error
/// for a range wider than [`MAX_LOG_BLOCK_RANGE`] (unless `legacy_clamp`).
pub fn bound_log_range(from: u64, to: u64, legacy_clamp: bool) -> Result<u64, jsonrpc_core::Error> {
    let limit_to = from.saturating_add(MAX_LOG_BLOCK_RANGE);
    if to <= limit_to {
        return Ok(to);
    }
    if legacy_clamp {
        return Ok(limit_to);
    }
    Err(jsonrpc_core::Error {
        code: jsonrpc_core::ErrorCode::ServerError(LOG_RANGE_LIMIT_CODE),
        message: format!(
            "eth_getLogs range too large: fromBlock 0x{from:x} to toBlock 0x{to:x} spans more than {MAX_LOG_BLOCK_RANGE} blocks; request it in pages"
        ),
        data: Some(serde_json::json!({
            "maxBlockRange": MAX_LOG_BLOCK_RANGE,
            "fromBlock": format!("0x{from:x}"),
            "toBlock": format!("0x{to:x}"),
        })),
    })
}

#[derive(Default)]
struct CacheState {
    /// height -> executed block hash. Every entry is on the selected-parent
    /// chain of `anchor`.
    checkpoints: BTreeMap<u64, Hash>,
    /// The applied tip the checkpoints were verified against.
    anchor: Option<(Hash, u64)>,
    /// Bumped every time checkpoints a walk in flight may hold are invalidated.
    /// Unchanged between two points in time means every entry a walk found in
    /// between is still on the anchor's chain.
    generation: u64,
    /// Highest anchor height since `generation` last changed. Every walk of
    /// this generation started at a tip at most this high, so every checkpoint
    /// it can find is at most `high_water - SETTLED_DEPTH`.
    high_water: u64,
}

impl CacheState {
    /// Re-anchor the cache on the current applied tip. Checkpoints at or below
    /// the highest block the old anchor and the new tip share stay (they are on
    /// both chains); the rest are dropped. A tip that extends the anchor, or an
    /// older tip on the anchor's chain (a request that read the tip before a
    /// concurrent commit), shares everything below it, so nothing is dropped.
    fn reanchor(&mut self, storage: &StorageManager, tip_hash: Hash, tip_height: u64) {
        match self.anchor {
            Some((hash, height)) if hash == tip_hash && height == tip_height => return,
            Some((hash, height)) => {
                match common_ancestor(storage, hash, height, tip_hash, tip_height) {
                    // The anchor is an ancestor of the tip: a pure extension.
                    Some((shared_hash, _)) if shared_hash == hash => {}
                    Some((_, shared)) => {
                        // Keep `..=shared`. Walks in flight found heights of at most
                        // `high_water - SETTLED_DEPTH`; only when that is above the
                        // shared height can they hold an entry of the old branch.
                        let _dropped = self.checkpoints.split_off(&shared.saturating_add(1));
                        if shared < self.high_water.saturating_sub(SETTLED_DEPTH) {
                            self.bump_generation(tip_height);
                        }
                    }
                    None => self.drop_checkpoints(tip_height),
                }
            }
            None => self.drop_checkpoints(tip_height),
        }
        self.anchor = Some((tip_hash, tip_height));
        self.high_water = self.high_water.max(tip_height);
    }

    /// Forget every checkpoint and start a new generation, so walks that began
    /// under the old one do not publish into the new one.
    fn drop_checkpoints(&mut self, tip_height: u64) {
        self.checkpoints.clear();
        self.bump_generation(tip_height);
    }

    fn bump_generation(&mut self, tip_height: u64) {
        self.generation = self.generation.wrapping_add(1);
        self.high_water = tip_height;
    }
}

/// The highest block on both selected-parent chains, as `(hash, height)`, or
/// `None` when a chain cannot be followed (missing or malformed header), the
/// tips are more than [`MAX_ANCHOR_WALK`] apart, or finding the shared block
/// takes more than [`MAX_ANCHOR_WALK`] header reads.
fn common_ancestor(
    storage: &StorageManager,
    a: Hash,
    a_height: u64,
    b: Hash,
    b_height: u64,
) -> Option<(Hash, u64)> {
    if a_height.abs_diff(b_height) > MAX_ANCHOR_WALK {
        return None;
    }
    let header_height = |hash: &Hash| -> Option<(u64, Hash)> {
        let header = storage.blocks.get_header(hash).ok().flatten()?;
        Some((header.height, header.selected_parent_hash))
    };
    let (mut a, mut b) = (a, b);
    let (mut ah, mut a_parent) = header_height(&a)?;
    let (mut bh, mut b_parent) = header_height(&b)?;
    let mut reads: u64 = 2;
    loop {
        if a == b {
            return (ah == bh).then_some((a, ah));
        }
        if reads >= MAX_ANCHOR_WALK {
            return None;
        }
        reads = reads.saturating_add(1);
        // Step the higher side (either on a tie) to its selected parent;
        // heights must strictly decrease along a chain.
        if ah >= bh {
            if ah == 0 {
                return None;
            }
            let (h, p) = header_height(&a_parent)?;
            if h >= ah {
                return None;
            }
            (a, ah, a_parent) = (a_parent, h, p);
        } else {
            let (h, p) = header_height(&b_parent)?;
            if h >= bh {
                return None;
            }
            (b, bh, b_parent) = (b_parent, h, p);
        }
    }
}

/// Why the resolver could not name the executed blocks of a range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogIndexError {
    /// The walk needed more than the per-request header budget. Checkpoints it
    /// collected are kept, so the same request makes progress when retried.
    /// Also returned when another request is already filling the cold cache.
    Retry(String),
    /// The executed chain cannot be followed (missing or malformed ancestor).
    Unavailable(String),
}

impl std::fmt::Display for LogIndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogIndexError::Retry(m) | LogIndexError::Unavailable(m) => f.write_str(m),
        }
    }
}

/// JSON-RPC error code for a retryable [`LogIndexError::Retry`] ("resource
/// unavailable", EIP-1474).
pub const LOG_INDEX_RETRY_CODE: i64 = -32002;

impl LogIndexError {
    /// The JSON-RPC error `eth_getLogs` returns for this condition.
    pub fn to_rpc_error(&self) -> jsonrpc_core::Error {
        match self {
            LogIndexError::Retry(m) => jsonrpc_core::Error {
                code: jsonrpc_core::ErrorCode::ServerError(LOG_INDEX_RETRY_CODE),
                message: format!("eth_getLogs: {m}; retry the same request"),
                data: Some(serde_json::json!({ "retryable": true })),
            },
            LogIndexError::Unavailable(m) => jsonrpc_core::Error {
                code: jsonrpc_core::ErrorCode::InternalError,
                message: format!("eth_getLogs: {m}"),
                data: None,
            },
        }
    }
}

/// Most headers one request may read while resolving its range (the anchor
/// check is bounded separately by [`MAX_ANCHOR_WALK`]). With a warm cache any
/// allowed range needs at most `SETTLED_DEPTH + MAX_LOG_BLOCK_RANGE +
/// CHECKPOINT_STRIDE` reads; only a cold walk deep into history exceeds it, and
/// that walk is split across retries.
pub const MAX_HEADER_WALK: u64 = 64 * CHECKPOINT_STRIDE;

/// Settled-checkpoint cache shared by every `eth_getLogs` call on one handler.
pub struct ExecutedChainIndex {
    state: Mutex<CacheState>,
    /// Held by the one request allowed to run a walk longer than the budget
    /// (a cold-cache fill); others get [`LogIndexError::Retry`] instead of
    /// repeating the same scan.
    fill: Mutex<()>,
    walk_budget: u64,
    /// Test seam: runs once, after a walk and before it publishes, so a test
    /// can interleave another request deterministically. Absent from non-test
    /// builds.
    #[cfg(test)]
    before_publish: Mutex<Option<BeforePublish>>,
}

#[cfg(test)]
type BeforePublish = Box<dyn FnOnce(&ExecutedChainIndex) + Send>;

impl Default for ExecutedChainIndex {
    fn default() -> Self {
        Self::with_walk_budget(MAX_HEADER_WALK)
    }
}

impl ExecutedChainIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// An index whose per-request header budget is `walk_budget` (at least 1).
    pub fn with_walk_budget(walk_budget: u64) -> Self {
        Self {
            state: Mutex::new(CacheState::default()),
            fill: Mutex::new(()),
            walk_budget: walk_budget.max(1),
            #[cfg(test)]
            before_publish: Mutex::new(None),
        }
    }

    /// Number of cached checkpoints (tests / diagnostics).
    pub fn checkpoint_count(&self) -> usize {
        self.state
            .lock()
            .map(|s| s.checkpoints.len())
            .unwrap_or_default()
    }

    /// `(height, hash)` of the executed blocks with height in `from..=to`,
    /// ascending (the canonical execution order). Only hashes are returned:
    /// callers load one body at a time ([`load_executed_block`]) so a request
    /// never holds a whole range of blocks. Heights above the applied tip have
    /// not executed and are absent. [`LogIndexError::Unavailable`] when the
    /// executed chain cannot be followed down to `from` — never a silently
    /// shortened answer; [`LogIndexError::Retry`] when the walk would exceed
    /// the per-request header budget.
    pub fn executed_hashes(
        &self,
        storage: &StorageManager,
        from: u64,
        to: u64,
    ) -> Result<Vec<(u64, Hash)>, LogIndexError> {
        let Some((tip_hash, tip_height)) =
            applied_anchor(storage).map_err(LogIndexError::Unavailable)?
        else {
            return Ok(Vec::new());
        };
        let to = to.min(tip_height);
        if from > to {
            return Ok(Vec::new());
        }
        let settled_below = tip_height.saturating_sub(SETTLED_DEPTH);

        let (mut cursor, mut expect_at_most, start_generation) = {
            let mut st = self
                .state
                .lock()
                .map_err(|_| LogIndexError::Unavailable("log index lock poisoned".into()))?;
            // Before any checkpoint is trusted: the tip must extend the anchor
            // the checkpoints were collected under.
            st.reanchor(storage, tip_hash, tip_height);
            let nearest = if to <= settled_below {
                st.checkpoints
                    .range(to..=settled_below)
                    .next()
                    .map(|(h, hash)| (*h, *hash))
            } else {
                None
            };
            let (cursor, start) = match nearest {
                Some((h, hash)) if storage.blocks.has_block(&hash).unwrap_or(false) => (hash, h),
                Some(_) => {
                    // A checkpoint whose block is gone: the store changed under
                    // us (purge). Start over from the tip.
                    st.drop_checkpoints(tip_height);
                    (tip_hash, tip_height)
                }
                None => (tip_hash, tip_height),
            };
            (cursor, start, st.generation)
        };

        // Heights strictly decrease along the walk, so it reads at most
        // `start - from + 1` headers. A longer walk than the budget is a cold
        // fill: one request at a time runs it, each run bounded by the budget.
        let span = expect_at_most.saturating_sub(from).saturating_add(1);
        let _fill_guard = if span > self.walk_budget {
            match self.fill.try_lock() {
                Ok(g) => Some(g),
                Err(std::sync::TryLockError::WouldBlock) => {
                    return Err(LogIndexError::Retry(
                        "log index is warming (another request is filling it)".into(),
                    ))
                }
                Err(std::sync::TryLockError::Poisoned(p)) => Some(p.into_inner()),
            }
        } else {
            None
        };

        let mut found: Vec<(u64, Hash)> = Vec::new();
        let mut out_rev: Vec<(u64, Hash)> = Vec::new();
        let mut reads: u64 = 0;
        let mut exhausted = false;
        loop {
            if reads >= self.walk_budget {
                exhausted = true;
                break;
            }
            reads = reads.saturating_add(1);
            let header = storage
                .blocks
                .get_header(&cursor)
                .map_err(|e| LogIndexError::Unavailable(format!("header {cursor}: {e}")))?
                .ok_or_else(|| {
                    LogIndexError::Unavailable(format!(
                        "executed chain broken: block {cursor} is not stored"
                    ))
                })?;
            let h = header.height;
            if h > expect_at_most {
                return Err(LogIndexError::Unavailable(format!(
                    "executed chain malformed: block {cursor} at height {h} above its child"
                )));
            }
            if h <= settled_below && h.checked_rem(CHECKPOINT_STRIDE) == Some(0) {
                found.push((h, cursor));
            }
            if h <= to && h >= from {
                out_rev.push((h, cursor));
            }
            if h <= from || h == 0 {
                break;
            }
            expect_at_most = h.saturating_sub(1);
            cursor = header.selected_parent_hash;
        }

        #[cfg(test)]
        {
            let hook = self.before_publish.lock().ok().and_then(|mut h| h.take());
            if let Some(hook) = hook {
                hook(self);
            }
        }

        if !found.is_empty() {
            if let Ok(mut st) = self.state.lock() {
                // The found hashes are ancestors of the tip this walk started
                // from. With the generation unchanged, every anchor move since
                // was a verified extension of that tip, so they are ancestors
                // of the current anchor too (see "CACHE SOUNDNESS").
                if st.generation == start_generation {
                    st.checkpoints.extend(found);
                }
            }
        }
        if exhausted {
            return Err(LogIndexError::Retry(format!(
                "log index is warming (reached height {expect_at_most} toward {from})"
            )));
        }
        out_rev.reverse();
        Ok(out_rev)
    }
}

/// The body of an executed block named by [`ExecutedChainIndex::executed_hashes`].
pub fn load_executed_block(storage: &StorageManager, hash: &Hash) -> Result<Block, LogIndexError> {
    storage
        .blocks
        .get_block(hash)
        .map_err(|e| LogIndexError::Unavailable(format!("block {hash}: {e}")))?
        .ok_or_else(|| {
            LogIndexError::Unavailable(format!("executed chain broken: block {hash} has no body"))
        })
}

/// The block the executor's state reflects: the persisted applied tip, or — on a
/// store that never wrote one — the block the height index names at the stored
/// head.
fn applied_anchor(storage: &StorageManager) -> Result<Option<(Hash, u64)>, String> {
    if let Some(tip) = storage
        .blocks
        .get_applied_tip()
        .map_err(|e| format!("applied tip: {e}"))?
    {
        return Ok(Some(tip));
    }
    let head = storage
        .blocks
        .get_latest_height()
        .map_err(|e| format!("latest height: {e}"))?;
    Ok(storage
        .blocks
        .get_block_by_height(head)
        .map_err(|e| format!("height index: {e}"))?
        .map(|hash| (hash, head)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_at_the_limit_passes_unchanged() {
        assert_eq!(bound_log_range(0, 1_000, false).unwrap(), 1_000);
        assert_eq!(bound_log_range(5, 5, false).unwrap(), 5);
        assert_eq!(bound_log_range(10, 3, false).unwrap(), 3);
    }

    #[test]
    fn range_over_the_limit_errors_with_32005() {
        let e = bound_log_range(0, 1_001, false).unwrap_err();
        assert_eq!(e.code, jsonrpc_core::ErrorCode::ServerError(-32005));
        assert_eq!(e.data.unwrap()["maxBlockRange"], 1_000);
        assert!(bound_log_range(u64::MAX - 1, u64::MAX, false).is_ok());
    }

    /// While one request fills a cold cache, another that would also need a
    /// walk over the budget is told to retry instead of repeating the scan; a
    /// request that fits the budget is served.
    #[test]
    fn concurrent_cold_fill_is_not_duplicated() {
        use citrate_consensus::types::BlockBuilder;
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let storage = StorageManager::new(
            tmp.path(),
            citrate_storage::pruning::PruningConfig::default(),
        )
        .expect("storage");
        let mut parent = Hash::default();
        for h in 0..10u64 {
            let mut raw = [0u8; 32];
            raw[..8].copy_from_slice(&h.to_be_bytes());
            raw[31] = 0xA0;
            let b = BlockBuilder::new()
                .hash(Hash::new(raw))
                .parent(parent)
                .height(h)
                .build_unhashed();
            storage.blocks.put_block(&b).expect("block");
            parent = b.hash();
        }
        storage.blocks.put_applied_tip(&parent, 9).expect("tip");

        let idx = ExecutedChainIndex::with_walk_budget(3);
        let held = idx.fill.lock().expect("fill gate");
        match idx.executed_hashes(&storage, 0, 0) {
            Err(LogIndexError::Retry(m)) => assert!(m.contains("another request"), "{m}"),
            other => panic!("expected retry while a fill runs, got {other:?}"),
        }
        assert_eq!(
            idx.executed_hashes(&storage, 8, 9).expect("near tip").len(),
            2
        );
        drop(held);
        assert!(matches!(
            idx.executed_hashes(&storage, 0, 0),
            Err(LogIndexError::Retry(_))
        ));
    }

    #[test]
    fn legacy_clamp_restores_the_old_window() {
        assert_eq!(bound_log_range(7, 50_000, true).unwrap(), 1_007);
    }

    // ---- In-flight walk vs. a concurrent re-anchor (generation gate) ----

    use std::sync::Arc;

    fn gate_hash(tag: u8, h: u64) -> Hash {
        let mut raw = [0u8; 32];
        raw[..8].copy_from_slice(&h.to_be_bytes());
        raw[31] = tag;
        Hash::new(raw)
    }

    /// Stores a straight chain `tag` over `lo..=hi` on `parent`; returns the hashes.
    fn gate_branch(storage: &StorageManager, tag: u8, mut parent: Hash, lo: u64, hi: u64) -> Vec<Hash> {
        use citrate_consensus::types::BlockBuilder;
        let mut out = Vec::new();
        for h in lo..=hi {
            let b = BlockBuilder::new()
                .hash(gate_hash(tag, h))
                .parent(parent)
                .height(h)
                .build_unhashed();
            storage.blocks.put_block(&b).expect("block");
            parent = b.hash();
            out.push(parent);
        }
        out
    }

    /// Chain A over `0..=top` with the applied tip at `top`, where `top` puts a
    /// checkpoint at 1024 more than `SETTLED_DEPTH` below the tip.
    fn gate_fixture() -> (Arc<StorageManager>, tempfile::TempDir, Vec<Hash>, u64) {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let storage = Arc::new(
            StorageManager::new(tmp.path(), citrate_storage::pruning::PruningConfig::default())
                .expect("storage"),
        );
        let top = SETTLED_DEPTH + CHECKPOINT_STRIDE + 10;
        let a = gate_branch(&storage, 0xA0, Hash::default(), 0, top);
        storage.blocks.put_applied_tip(&a[top as usize], top).expect("tip");
        (storage, tmp, a, top)
    }

    /// Replaces the applied chain with chain B, forked from A at height 499 (below
    /// the 1024 checkpoint), at the same tip height.
    fn replace_below_checkpoint(storage: &StorageManager, a: &[Hash], top: u64) {
        let b = gate_branch(storage, 0xB0, a[499], 500, top);
        storage
            .blocks
            .put_applied_tip(b.last().expect("tip"), top)
            .expect("tip");
    }

    /// The query a cold walk has to answer, and what it must say after the walk.
    fn assert_serves_chain_b_at_1024(idx: &ExecutedChainIndex, storage: &StorageManager) {
        let got = idx.executed_hashes(storage, 1_024, 1_024).expect("page");
        assert_eq!(
            got,
            vec![(1_024, gate_hash(0xB0, 1_024))],
            "a checkpoint found on the replaced chain was published and served"
        );
    }

    /// A cold walk collects checkpoints on chain A. Before it publishes, another
    /// request re-anchors on chain B, which forks below those checkpoints. The
    /// walk must not publish them: the generation changed.
    #[test]
    fn in_flight_walk_does_not_publish_across_a_fork_below_its_checkpoints() {
        let (storage, _tmp, a, top) = gate_fixture();
        let idx = ExecutedChainIndex::new();
        let s = storage.clone();
        let a_hook = a.clone();
        *idx.before_publish.lock().expect("hook") = Some(Box::new(move |idx: &ExecutedChainIndex| {
            replace_below_checkpoint(&s, &a_hook, top);
            // A concurrent near-tip request on the new chain re-anchors.
            let near = idx.executed_hashes(&s, top, top).expect("near tip");
            assert_eq!(near, vec![(top, gate_hash(0xB0, top))]);
        }));
        let cold = idx.executed_hashes(&storage, 0, 0).expect("cold walk");
        assert_eq!(cold, vec![(0, a[0])], "height 0 is shared by both chains");
        assert_eq!(
            idx.checkpoint_count(),
            0,
            "the walk's chain-A checkpoints must not be published"
        );
        assert_serves_chain_b_at_1024(&idx, &storage);
    }

    /// Same interleaving, but the concurrent re-anchors take the full-drop path
    /// (`drop_checkpoints`): first a tip whose chain cannot be followed, then
    /// chain B. A full drop must start a new generation too.
    #[test]
    fn in_flight_walk_does_not_publish_across_a_full_drop() {
        let (storage, _tmp, a, top) = gate_fixture();
        let idx = ExecutedChainIndex::new();
        let s = storage.clone();
        let a_hook = a.clone();
        *idx.before_publish.lock().expect("hook") = Some(Box::new(move |idx: &ExecutedChainIndex| {
            use citrate_consensus::types::BlockBuilder;
            // A tip whose selected parent is not stored: the common-ancestor
            // walk breaks, so the cache is dropped.
            let z = BlockBuilder::new()
                .hash(gate_hash(0xC0, top))
                .parent(gate_hash(0xC0, top - 1))
                .height(top)
                .build_unhashed();
            s.blocks.put_block(&z).expect("z");
            s.blocks.put_applied_tip(&z.hash(), top).expect("tip");
            idx.executed_hashes(&s, top, top).expect("near tip on z");
            // Then chain B: re-anchoring from the broken tip drops again.
            replace_below_checkpoint(&s, &a_hook, top);
            idx.executed_hashes(&s, top, top).expect("near tip on b");
        }));
        idx.executed_hashes(&storage, 0, 0).expect("cold walk");
        assert_eq!(
            idx.checkpoint_count(),
            0,
            "the walk's chain-A checkpoints must not be published"
        );
        assert_serves_chain_b_at_1024(&idx, &storage);
    }

    /// Control: with no concurrent re-anchor the same walk publishes, so the
    /// two tests above fail only because of the interleaving.
    #[test]
    fn in_flight_walk_publishes_when_nothing_moved() {
        let (storage, _tmp, a, top) = gate_fixture();
        let idx = ExecutedChainIndex::new();
        let s = storage.clone();
        *idx.before_publish.lock().expect("hook") = Some(Box::new(move |idx: &ExecutedChainIndex| {
            // A concurrent request at the same tip changes nothing.
            idx.executed_hashes(&s, top, top).expect("near tip");
        }));
        idx.executed_hashes(&storage, 0, 0).expect("cold walk");
        assert_eq!(idx.checkpoint_count(), 2, "checkpoints at 0 and 1024");
        let got = idx.executed_hashes(&storage, 1_024, 1_024).expect("page");
        assert_eq!(got, vec![(1_024, a[1_024])]);
    }
}
