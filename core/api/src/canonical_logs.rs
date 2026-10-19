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
// is an ancestor of it. On each call, before any checkpoint is used, the new
// applied tip is checked to EXTEND the anchor: the resolver walks the new tip's
// selected-parent chain down to the anchor's height and compares hashes. A match
// means the chain only grew, so every checkpoint is still an ancestor of the new
// tip, and the anchor moves up. Anything else — a different block at the anchor
// height (chain replaced, at any depth), a lower tip, a broken walk, or a gap
// wider than `MAX_ANCHOR_WALK` — drops every checkpoint. The verification walk
// costs one header per block the tip advanced since the previous call, so it is
// amortised over chain growth.
//
// A walk runs outside the cache lock, so the tip usually advances while it runs
// (other requests re-anchor). Its checkpoints are ancestors of the tip it started
// from; they stay valid for every later anchor reached through verified
// extensions. `generation` counts the times the checkpoints were dropped (any
// other re-anchor outcome, or a purge). A walk publishes what it found only when
// the generation is unchanged since it started: the anchor may have moved, but
// only along verified extensions of the walk's start tip. Gating on the anchor
// itself would throw cold-fill progress away whenever the tip advances.
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
    /// Bumped every time `checkpoints` is dropped. Unchanged between two points
    /// in time means every anchor move in between was a verified extension.
    generation: u64,
}

impl CacheState {
    /// Re-anchor the cache on the current applied tip, keeping the checkpoints
    /// only when the tip provably extends the previous anchor.
    fn reanchor(&mut self, storage: &StorageManager, tip_hash: Hash, tip_height: u64) {
        let keep = match self.anchor {
            Some((hash, height)) if hash == tip_hash && height == tip_height => return,
            Some((hash, height)) => {
                tip_height >= height
                    && tip_height.saturating_sub(height) <= MAX_ANCHOR_WALK
                    && hash_at_height(storage, tip_hash, tip_height, height) == Some(hash)
            }
            None => false,
        };
        if !keep {
            self.drop_checkpoints();
        }
        self.anchor = Some((tip_hash, tip_height));
    }

    /// Forget every checkpoint and start a new generation, so walks that began
    /// under the old one do not publish into the new one.
    fn drop_checkpoints(&mut self) {
        self.checkpoints.clear();
        self.generation = self.generation.wrapping_add(1);
    }
}

/// The hash at `target` on the selected-parent chain of `(start, start_height)`,
/// or `None` when the chain cannot be followed (missing or malformed header).
fn hash_at_height(
    storage: &StorageManager,
    start: Hash,
    start_height: u64,
    target: u64,
) -> Option<Hash> {
    let mut cursor = start;
    let mut expect_at_most = start_height;
    loop {
        let header = storage.blocks.get_header(&cursor).ok().flatten()?;
        let h = header.height;
        if h > expect_at_most || h < target {
            return None;
        }
        if h == target {
            return Some(cursor);
        }
        expect_at_most = h.saturating_sub(1);
        cursor = header.selected_parent_hash;
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
}

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
                    st.drop_checkpoints();
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
}
