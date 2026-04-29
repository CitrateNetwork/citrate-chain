//! Real aggregator implementation. WP-3.6.
//!
//! Replaces `StubAggregator`: pulls observed embeddings for a cycle
//! from a pluggable [`EmbeddingCache`], encodes them as Belnap-
//! precompile input bytes, calls the in-process Belnap aggregator
//! ([`citrate_execution::precompiles::q16::belnap::aggregate`]), and
//! commits the result to chain via the [`ChainAdapter`].
//!
//! # Why in-process Belnap?
//!
//! The Belnap precompile (`0x0110`, RM-FL-1) is a pure deterministic
//! Q16 algorithm. Calling it in-process via the same code path as the
//! EVM dispatcher gives byte-identical results to a chain-side call —
//! no reason to round-trip through `eth_call`. The on-chain dispatcher
//! still exists so contracts can verify the daemon's claim
//! independently.
//!
//! # Idempotency contract
//!
//! Per `LearningDaemon.tla::AggregationIdempotent` and the WP-3.4
//! `check_daemon_idempotent_aggregation.py` tripwire, this fn checks
//! `state.cycle_status(cycle_id)` before any side effect. If status
//! is already `Computed` or `Committed`, the fn is a no-op.

use std::sync::Arc;

use async_trait::async_trait;
use ethereum_types::H160;
use tracing::{debug, info, warn};

use citrate_execution::precompiles::q16::belnap;

use crate::chain::ChainAdapter;
use crate::error::{DaemonError, DaemonResult};
use crate::orchestrator::Aggregator;
use crate::state::{CycleStatus, DaemonState};
use crate::types::CycleId;

/// Pluggable embedding cache. The daemon's main loop fills this as
/// `EmbeddingSubmitted` events arrive (via a side channel — IPFS,
/// HTTP, or RPC view call against the contract's submission storage).
///
/// `BelnapAggregator` calls `embeddings_for_cycle` at aggregation
/// time. Returned vector is `(submitter_address, q16_embedding,
/// q16_confidence, q16_weight)` per participant.
///
/// For RM-FL-3 slice 1 we ship a `MemoryEmbeddingCache` that tests
/// load directly. The production fetch path (IPFS pin retrieval)
/// lands in WP-3.5 slice 2 alongside the daemon binary.
pub trait EmbeddingCache: Send + Sync {
    /// Return all embedding submissions observed for this cycle.
    /// Each tuple: `(submitter, embedding[dim], confidence[dim], weight)`.
    /// All values are raw Q16 (i32) bits; dim is consistent across
    /// participants (the aggregator validates).
    fn embeddings_for_cycle(
        &self,
        cycle_id: CycleId,
    ) -> Vec<EmbeddingEntry>;
}

/// One participant's contribution to a cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddingEntry {
    /// Validator's reward address.
    pub submitter: H160,
    /// Per-dimension embedding values, raw Q16 bits.
    pub embedding: Vec<i32>,
    /// Per-dimension confidence values, raw Q16 bits.
    pub confidence: Vec<i32>,
    /// Trust weight for this participant, raw Q16 bits.
    pub weight: i32,
}

/// In-memory `EmbeddingCache` for tests.
pub struct MemoryEmbeddingCache {
    entries: std::sync::Mutex<std::collections::HashMap<CycleId, Vec<EmbeddingEntry>>>,
}

impl MemoryEmbeddingCache {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Test helper: insert an embedding entry for a cycle.
    pub fn insert(&self, cycle_id: CycleId, entry: EmbeddingEntry) {
        let mut entries = self.entries.lock().expect("lock");
        entries.entry(cycle_id).or_default().push(entry);
    }
}

impl Default for MemoryEmbeddingCache {
    fn default() -> Self {
        Self::new()
    }
}

impl EmbeddingCache for MemoryEmbeddingCache {
    fn embeddings_for_cycle(&self, cycle_id: CycleId) -> Vec<EmbeddingEntry> {
        let entries = self.entries.lock().expect("lock");
        entries.get(&cycle_id).cloned().unwrap_or_default()
    }
}

/// Real Belnap aggregator. Replaces `StubAggregator` once WP-3.6
/// lands.
pub struct BelnapAggregator<C: ChainAdapter> {
    chain: Arc<C>,
    state: Arc<DaemonState>,
    cache: Arc<dyn EmbeddingCache>,
    /// Confidence threshold for the Belnap classifier (Q16).
    /// Default ≈ 0.8 (`0x0000_CCCC`).
    threshold_pos_q16: i32,
    /// Reserved for asymmetric thresholds (currently unused — see
    /// `belnap.rs` WP-1.5 commentary).
    threshold_neg_q16: i32,
}

impl<C: ChainAdapter> BelnapAggregator<C> {
    /// Construct a new aggregator with default thresholds.
    pub fn new(
        chain: Arc<C>,
        state: Arc<DaemonState>,
        cache: Arc<dyn EmbeddingCache>,
    ) -> Self {
        // Default Q16(0.8) ≈ 0x0000_CCCC = 52428.
        let q16_zero_point_eight: i32 = 52428;
        Self {
            chain,
            state,
            cache,
            threshold_pos_q16: q16_zero_point_eight,
            threshold_neg_q16: -q16_zero_point_eight,
        }
    }

    /// Override thresholds (test helper / governance hook).
    pub fn with_thresholds(mut self, pos: i32, neg: i32) -> Self {
        self.threshold_pos_q16 = pos;
        self.threshold_neg_q16 = neg;
        self
    }

    /// Encode a list of `EmbeddingEntry` into the Belnap precompile's
    /// big-endian wire format. Mirrors
    /// `core/execution/src/precompiles/q16/belnap.rs::encode_input`
    /// (which is `#[cfg(test)]` only over there — we recreate the
    /// encoder here since the daemon needs it in production).
    fn encode_belnap_input(&self, entries: &[EmbeddingEntry]) -> DaemonResult<Vec<u8>> {
        if entries.is_empty() {
            return Err(DaemonError::Aggregation("no embeddings to aggregate".into()));
        }
        let dim = entries[0].embedding.len();
        if dim == 0 {
            return Err(DaemonError::Aggregation("embedding dim is zero".into()));
        }
        // Validate consistent shape across submissions.
        for e in entries {
            if e.embedding.len() != dim || e.confidence.len() != dim {
                return Err(DaemonError::Aggregation(format!(
                    "shape mismatch: expected dim={dim}, got embedding={} confidence={}",
                    e.embedding.len(),
                    e.confidence.len()
                )));
            }
        }
        let n = entries.len();
        if n > belnap::MAX_N {
            return Err(DaemonError::Aggregation(format!(
                "too many participants: {n} > MAX_N={}",
                belnap::MAX_N
            )));
        }
        if dim > belnap::MAX_DIM {
            return Err(DaemonError::Aggregation(format!(
                "dim too large: {dim} > MAX_DIM={}",
                belnap::MAX_DIM
            )));
        }

        let mut bytes = Vec::with_capacity(16 + 8 * n * dim + 4 * n);
        bytes.extend_from_slice(&(dim as u32).to_be_bytes());
        bytes.extend_from_slice(&(n as u32).to_be_bytes());
        for e in entries {
            for v in &e.embedding {
                bytes.extend_from_slice(&v.to_be_bytes());
            }
        }
        for e in entries {
            for v in &e.confidence {
                bytes.extend_from_slice(&v.to_be_bytes());
            }
        }
        for e in entries {
            bytes.extend_from_slice(&e.weight.to_be_bytes());
        }
        bytes.extend_from_slice(&self.threshold_pos_q16.to_be_bytes());
        bytes.extend_from_slice(&self.threshold_neg_q16.to_be_bytes());
        Ok(bytes)
    }
}

#[async_trait]
impl<C: ChainAdapter + 'static> Aggregator for BelnapAggregator<C> {
    /// Aggregate the cycle's embeddings.
    ///
    /// Idempotent (LearningDaemon.tla::AggregationIdempotent): the
    /// `cycle_status` guard at the top of this fn ensures
    /// re-running on the same cycle is a no-op once status reaches
    /// `Computed` or `Committed`.
    async fn aggregate(&self, cycle_id: CycleId) -> DaemonResult<()> {
        // Idempotency guard. The check_daemon_idempotent_aggregation
        // tripwire requires this to be in the first 20 lines of
        // body.
        let current = self.state.cycle_status(cycle_id);
        if current != CycleStatus::Pending {
            debug!(cycle_id, ?current, "aggregate skipping (idempotent — already past pending)");
            return Ok(());
        }

        // Pull observed submissions.
        let entries = self.cache.embeddings_for_cycle(cycle_id);
        if entries.is_empty() {
            warn!(cycle_id, "no embeddings observed; skipping aggregate");
            return Ok(());
        }
        info!(cycle_id, n = entries.len(), "aggregating");

        // Encode + run Belnap in process. Same byte-deterministic
        // output as a chain-side eth_call against 0x0110.
        let input_bytes = self.encode_belnap_input(&entries)?;
        let output_bytes = belnap::aggregate(&input_bytes)
            .map_err(|e| DaemonError::Aggregation(format!("belnap: {e}")))?;

        // Mark computed BEFORE submitting commit. This is the
        // "computed" intermediate state the spec requires; if the
        // commit fails, restart will see "computed" and resubmit
        // (which is idempotent at the chain level).
        self.state.set_cycle_status(cycle_id, CycleStatus::Computed)?;

        // Submit commit to chain.
        let tx_hash = self
            .chain
            .commit_aggregation(cycle_id, &output_bytes)
            .await?;
        info!(cycle_id, tx = ?tx_hash, "commit submitted");

        // Mark committed locally only after chain confirmation. The
        // chain-side AggregationCommitted event also promotes
        // local status when the orchestrator sees it (see
        // orchestrator.rs::dispatch_event), so this is the local
        // optimistic update; the event handler is the
        // authoritative confirmation.
        self.state.set_cycle_status(cycle_id, CycleStatus::Committed)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::FakeChain;
    use tempfile::TempDir;

    fn fixture() -> (Arc<FakeChain>, Arc<DaemonState>, TempDir) {
        let chain = Arc::new(FakeChain::new());
        let dir = TempDir::new().expect("tempdir");
        let state = Arc::new(DaemonState::open(dir.path()).expect("open"));
        (chain, state, dir)
    }

    fn make_entry(submitter_byte: u8, value_q16: i32) -> EmbeddingEntry {
        EmbeddingEntry {
            submitter: H160::repeat_byte(submitter_byte),
            embedding: vec![value_q16],
            confidence: vec![65536], // Q16(1.0)
            weight: 65536,
        }
    }

    #[tokio::test]
    async fn aggregator_skips_when_no_embeddings() {
        let (chain, state, _dir) = fixture();
        let cache = Arc::new(MemoryEmbeddingCache::new());
        let agg = BelnapAggregator::new(chain.clone(), state.clone(), cache);
        agg.aggregate(1).await.expect("ok");
        // No embeddings → no commit submitted → cycle stays Pending.
        assert!(chain.submitted_commits().is_empty());
        assert_eq!(state.cycle_status(1), CycleStatus::Pending);
    }

    #[tokio::test]
    async fn aggregator_commits_when_embeddings_present() {
        let (chain, state, _dir) = fixture();
        let cache = Arc::new(MemoryEmbeddingCache::new());
        // Three honest validators agree on positive direction.
        cache.insert(1, make_entry(0x01, 32768)); // Q16(0.5)
        cache.insert(1, make_entry(0x02, 32768));
        cache.insert(1, make_entry(0x03, 32768));

        let agg = BelnapAggregator::new(chain.clone(), state.clone(), cache);
        agg.aggregate(1).await.expect("ok");

        let commits = chain.submitted_commits();
        assert_eq!(commits.len(), 1);
        assert_eq!(commits[0].0, 1);
        // Output bytes: 4 bytes value + 1 byte state per dim = 5 bytes for dim=1.
        assert_eq!(commits[0].1.len(), 5);
        // State byte (last) = 1 (True) for unanimous-positive agree.
        assert_eq!(commits[0].1[4], 1);
        // Cycle status now Committed.
        assert_eq!(state.cycle_status(1), CycleStatus::Committed);
    }

    #[tokio::test]
    async fn aggregator_idempotent_when_already_computed() {
        let (chain, state, _dir) = fixture();
        let cache = Arc::new(MemoryEmbeddingCache::new());
        cache.insert(1, make_entry(0x01, 32768));

        // Pre-set state to Computed (simulating restart-after-commit-pending).
        state.set_cycle_status(1, CycleStatus::Computed).expect("ok");

        let agg = BelnapAggregator::new(chain.clone(), state.clone(), cache);
        agg.aggregate(1).await.expect("ok");

        // No new commit submitted because we skipped via the
        // idempotency guard.
        assert!(chain.submitted_commits().is_empty());
        // Status unchanged.
        assert_eq!(state.cycle_status(1), CycleStatus::Computed);
    }

    #[tokio::test]
    async fn aggregator_idempotent_when_already_committed() {
        let (chain, state, _dir) = fixture();
        let cache = Arc::new(MemoryEmbeddingCache::new());
        cache.insert(1, make_entry(0x01, 32768));

        state.set_cycle_status(1, CycleStatus::Computed).expect("ok");
        state.set_cycle_status(1, CycleStatus::Committed).expect("ok");

        let agg = BelnapAggregator::new(chain.clone(), state.clone(), cache);
        agg.aggregate(1).await.expect("ok");

        assert!(chain.submitted_commits().is_empty());
        assert_eq!(state.cycle_status(1), CycleStatus::Committed);
    }

    #[tokio::test]
    async fn aggregator_rejects_shape_mismatch() {
        let (chain, state, _dir) = fixture();
        let cache = Arc::new(MemoryEmbeddingCache::new());
        let mut bad = make_entry(0x01, 32768);
        bad.confidence = vec![32768, 32768]; // dim=2
        // First entry has dim=1 (single-element embedding); second has
        // mismatched confidence dim=2 vs embedding dim=1.
        cache.insert(1, bad);

        let agg = BelnapAggregator::new(chain.clone(), state.clone(), cache);
        let err = agg.aggregate(1).await.expect_err("rejects shape mismatch");
        assert!(format!("{err}").contains("shape mismatch"));
        // Cycle stays Pending — no partial commit.
        assert_eq!(state.cycle_status(1), CycleStatus::Pending);
    }

    #[test]
    fn memory_cache_starts_empty() {
        let cache = MemoryEmbeddingCache::new();
        assert!(cache.embeddings_for_cycle(1).is_empty());
    }

    #[test]
    fn memory_cache_returns_inserted_entries() {
        let cache = MemoryEmbeddingCache::new();
        cache.insert(1, make_entry(0x01, 100));
        cache.insert(1, make_entry(0x02, 200));
        cache.insert(2, make_entry(0x03, 300));
        assert_eq!(cache.embeddings_for_cycle(1).len(), 2);
        assert_eq!(cache.embeddings_for_cycle(2).len(), 1);
        assert_eq!(cache.embeddings_for_cycle(99).len(), 0);
    }

    #[test]
    fn aggregator_encode_round_trips_to_belnap_decode() {
        // Sanity check: our daemon-side encoder produces bytes the
        // Belnap precompile's decoder accepts (because they share
        // the wire format from RM-FL-1 WP-1.5).
        let chain = Arc::new(FakeChain::new());
        let dir = TempDir::new().expect("tempdir");
        let state = Arc::new(DaemonState::open(dir.path()).expect("open"));
        let cache = Arc::new(MemoryEmbeddingCache::new());
        let agg = BelnapAggregator::new(chain, state, cache);

        let entries = vec![make_entry(0x01, 32768), make_entry(0x02, 32768)];
        let bytes = agg.encode_belnap_input(&entries).expect("encodes");
        // The Belnap precompile must accept these bytes (forward()
        // decodes them internally; here we just confirm Ok).
        let result = belnap::aggregate(&bytes);
        assert!(result.is_ok(), "Belnap accepts our encoded bytes: {result:?}");
    }
}
