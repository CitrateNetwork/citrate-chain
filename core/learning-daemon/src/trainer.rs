//! Routing-model trainer. WP-3.7.
//!
//! Replaces `StubTrainer`: takes a cycle's aggregated embeddings,
//! trains the 3-layer MLP off-chain, quantizes weights to Q16,
//! pins them to IPFS, and commits the CID + content_sha256 to chain
//! (so precompile `0x0111` — RM-FL-2 — can consume the new weights
//! at the next inference call).
//!
//! # Pluggable backends (slice 1 vs slice 2)
//!
//! WP-3.7 slice 1 ships the trainer's PLUMBING with two trait
//! abstractions, both stubbable for tests:
//!
//!   - [`TrainingBackend`]: takes embeddings + previous weights,
//!     returns new weights. Real impl uses `candle-core` SGD
//!     (deferred to slice 2 — adds a heavyweight dep with native
//!     CUDA/MKL bindings; out of scope for a single mid-sprint
//!     session).
//!
//!   - [`IpfsClient`]: pins bytes, returns a CID. Real impl wraps
//!     a Kubo HTTP API or `citrate-storage::ipfs` (slice 2).
//!
//! Slice 1 ships [`StubTrainingBackend`] (deterministic weights from
//! the cycle id — suitable for testing the orchestration flow) and
//! [`MemoryIpfsClient`] (in-memory pin store).
//!
//! # Idempotency
//!
//! The trainer is safe to call multiple times for the same cycle. If
//! the underlying training backend is deterministic, repeat calls
//! produce identical weights bytes → identical CID → idempotent
//! chain commit (the chain side ignores duplicate
//! `setRoutingWeights` for the same `(cycle_id, cid)` tuple). The
//! orchestrator's `try_train` doesn't add a separate guard; the
//! determinism of the inputs IS the guard.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ethereum_types::H256;
use sha3::{Digest, Keccak256};
use tracing::{debug, info};

use crate::aggregator::EmbeddingCache;
use crate::chain::ChainAdapter;
use crate::error::{DaemonError, DaemonResult};
use crate::orchestrator::Trainer;
use crate::state::{CycleStatus, DaemonState};
use crate::types::{CycleId, RoutingWeights};

/// Routing-model weights as a flat Q16 vector. The interpretation
/// (layer shapes, ordering) is fixed by `RoutingShape::V1` from
/// RM-FL-2. The trainer doesn't enforce shape — it serializes
/// whatever the backend produces; the precompile validates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Q16Weights {
    /// Flat Q16 i32 values in row-major layer order:
    /// W1 || b1 || W2 || b2 || W3 || b3.
    pub values: Vec<i32>,
}

impl Q16Weights {
    /// Encode as big-endian bytes (i32 each, total = 4 * values.len()).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 * self.values.len());
        for v in &self.values {
            bytes.extend_from_slice(&v.to_be_bytes());
        }
        bytes
    }

    /// SHA256 (Keccak256 — chain-native hash) of the encoded bytes.
    /// Committed alongside the IPFS CID so the chain can detect
    /// pin tampering before consumers fetch the bytes for inference.
    pub fn content_hash(&self) -> H256 {
        let bytes = self.to_bytes();
        let hash = Keccak256::digest(&bytes);
        H256::from_slice(&hash)
    }
}

/// Pluggable training backend.
///
/// WP-3.7 slice 1 = `StubTrainingBackend` (deterministic from
/// cycle id; covers test scenarios). Slice 2 = `CandleTrainingBackend`
/// running real f32 SGD on the aggregated embeddings + quantizing
/// to Q16. The Q16-vs-f32 oracle delta is in the spec headers
/// throughout this track: training is f32, inference (precompile
/// 0x0111) is Q16, and the boundary is the quantization step at
/// the END of training.
pub trait TrainingBackend: Send + Sync {
    /// Train the routing model for `cycle_id`. The backend has
    /// access to the daemon's embedding cache + state via the
    /// trainer; this trait surface is intentionally narrow so the
    /// real impl can be swapped without touching the orchestrator.
    fn train(
        &self,
        cycle_id: CycleId,
        embeddings: &dyn EmbeddingCache,
        previous_weights: Option<&Q16Weights>,
    ) -> DaemonResult<Q16Weights>;
}

/// Stub backend that returns deterministic weights from the cycle id.
/// Used for orchestration testing — the actual values aren't
/// meaningful.
pub struct StubTrainingBackend {
    /// Number of weight values to emit (must match
    /// `RoutingShape::V1::params()` for the precompile to accept,
    /// but tests can use small values).
    pub n_weights: usize,
}

impl Default for StubTrainingBackend {
    fn default() -> Self {
        Self { n_weights: 32 }
    }
}

impl TrainingBackend for StubTrainingBackend {
    fn train(
        &self,
        cycle_id: CycleId,
        _embeddings: &dyn EmbeddingCache,
        _previous_weights: Option<&Q16Weights>,
    ) -> DaemonResult<Q16Weights> {
        // Deterministic: weight[i] = (cycle_id * 1000 + i) as Q16 raw.
        // Same cycle_id → same Q16Weights → same bytes → same CID →
        // same chain commit. That's the idempotency property the
        // trainer relies on.
        let values = (0..self.n_weights)
            .map(|i| (cycle_id as i32).saturating_mul(1000).saturating_add(i as i32))
            .collect();
        Ok(Q16Weights { values })
    }
}

/// Pluggable IPFS client. Narrow surface — the daemon only needs
/// to pin bytes and get a CID back.
#[async_trait]
pub trait IpfsClient: Send + Sync {
    /// Pin `bytes` and return a content-identifier string. Real
    /// impl uses the Kubo HTTP API; stub uses a deterministic hash.
    async fn pin(&self, bytes: &[u8]) -> DaemonResult<String>;
}

/// In-memory IPFS client for tests. Generates a deterministic CID
/// from the content hash so tests can assert exact CID values.
pub struct MemoryIpfsClient {
    pinned: Mutex<Vec<(String, Vec<u8>)>>,
}

impl MemoryIpfsClient {
    /// Create an empty pinned store.
    pub fn new() -> Self {
        Self {
            pinned: Mutex::new(Vec::new()),
        }
    }

    /// Test helper: how many distinct objects have been pinned.
    pub fn pin_count(&self) -> usize {
        self.pinned.lock().expect("lock").len()
    }

    /// Test helper: retrieve pinned bytes by CID.
    pub fn fetch(&self, cid: &str) -> Option<Vec<u8>> {
        let pinned = self.pinned.lock().expect("lock");
        pinned
            .iter()
            .find(|(c, _)| c == cid)
            .map(|(_, b)| b.clone())
    }
}

impl Default for MemoryIpfsClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl IpfsClient for MemoryIpfsClient {
    async fn pin(&self, bytes: &[u8]) -> DaemonResult<String> {
        // Deterministic CID = "cid-" + first 8 hex chars of Keccak256.
        // Real Kubo CIDs are base-CID-encoded multihashes; this stub
        // is just unique-and-deterministic enough for tests.
        let hash = Keccak256::digest(bytes);
        let cid = format!("cid-{}", hex::encode(&hash[..8]));
        let mut pinned = self.pinned.lock().expect("lock");
        // Idempotent: if already pinned, don't duplicate.
        if !pinned.iter().any(|(c, _)| c == &cid) {
            pinned.push((cid.clone(), bytes.to_vec()));
        }
        Ok(cid)
    }
}

/// Real routing-model trainer. Replaces `StubTrainer` once
/// WP-3.7 lands.
pub struct RoutingTrainer<C: ChainAdapter, I: IpfsClient, T: TrainingBackend> {
    chain: Arc<C>,
    state: Arc<DaemonState>,
    embedding_cache: Arc<dyn EmbeddingCache>,
    ipfs: Arc<I>,
    backend: Arc<T>,
    /// Optional cache of the previous cycle's weights (for SGD
    /// initialization). The daemon populates this from the last
    /// completed cycle's published weights at startup.
    previous_weights: Mutex<Option<Q16Weights>>,
}

impl<C: ChainAdapter, I: IpfsClient, T: TrainingBackend> RoutingTrainer<C, I, T> {
    /// Construct a new trainer.
    pub fn new(
        chain: Arc<C>,
        state: Arc<DaemonState>,
        embedding_cache: Arc<dyn EmbeddingCache>,
        ipfs: Arc<I>,
        backend: Arc<T>,
    ) -> Self {
        Self {
            chain,
            state,
            embedding_cache,
            ipfs,
            backend,
            previous_weights: Mutex::new(None),
        }
    }

    /// Test/operator helper: seed the trainer with weights from a
    /// previous cycle (or genesis weights at startup).
    pub fn seed_previous_weights(&self, w: Q16Weights) {
        let mut prev = self.previous_weights.lock().expect("lock");
        *prev = Some(w);
    }

    /// Helper: how many objects has the IPFS client pinned for us?
    /// (Test introspection — the production trainer doesn't track
    /// pin count, but the in-memory test fixture does.)
    pub fn ipfs(&self) -> &I {
        &self.ipfs
    }
}

#[async_trait]
impl<C, I, T> Trainer for RoutingTrainer<C, I, T>
where
    C: ChainAdapter + 'static,
    I: IpfsClient + 'static,
    T: TrainingBackend + 'static,
{
    /// Run training for `cycle_id` and publish the resulting weights.
    ///
    /// Pre-condition: `state.cycle_status(cycle_id) == Committed`.
    /// (The aggregator must have run first; without an aggregated
    /// state vector there's nothing to train against.) Returns
    /// `Err(DaemonError::Training)` if called too early.
    ///
    /// Idempotent: deterministic backend + deterministic IPFS CID
    /// → same chain commit on every call. The chain side ignores
    /// duplicate `setRoutingWeights` for the same `(cycle, cid)`.
    async fn train(&self, cycle_id: CycleId) -> DaemonResult<()> {
        // Pre-condition: cycle must be Committed (aggregation done).
        let status = self.state.cycle_status(cycle_id);
        if status != CycleStatus::Committed {
            return Err(DaemonError::Training(format!(
                "training requires cycle {cycle_id} to be Committed; got {status:?}"
            )));
        }

        debug!(cycle_id, "running training backend");
        let prev = {
            let lock = self.previous_weights.lock().expect("lock");
            lock.clone()
        };
        let new_weights = self
            .backend
            .train(cycle_id, &*self.embedding_cache, prev.as_ref())?;

        // Serialize + pin.
        let bytes = new_weights.to_bytes();
        let content_hash = new_weights.content_hash();
        let cid = self.ipfs.pin(&bytes).await?;
        info!(cycle_id, cid = %cid, "weights pinned");

        // Commit CID to chain. The ChainAdapter exposes
        // commit_routing_weights for this — added at WP-3.7 (extended
        // the trait to carry the new write).
        let tx_hash = self
            .chain
            .commit_routing_weights(cycle_id, &cid, content_hash)
            .await?;
        info!(cycle_id, tx = ?tx_hash, "routing weights committed");

        // Cache as previous_weights for the next cycle's SGD init.
        {
            let mut prev = self.previous_weights.lock().expect("lock");
            *prev = Some(new_weights);
        }

        Ok(())
    }
}

/// Public utility: build a `RoutingWeights` record (the type used in
/// `LearningEvent::AggregationCommitted`-style events) from the
/// trainer's outputs. Wraps cycle_id + ipfs_cid + content_sha256.
pub fn weights_record(
    cycle_id: CycleId,
    cid: &str,
    weights: &Q16Weights,
) -> RoutingWeights {
    RoutingWeights {
        cycle_id,
        ipfs_cid: cid.to_string(),
        content_sha256: weights.content_hash(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregator::MemoryEmbeddingCache;
    use crate::chain::FakeChain;
    use tempfile::TempDir;

    fn fixture() -> (Arc<FakeChain>, Arc<DaemonState>, TempDir) {
        let chain = Arc::new(FakeChain::new());
        let dir = TempDir::new().expect("tempdir");
        let state = Arc::new(DaemonState::open(dir.path()).expect("open"));
        (chain, state, dir)
    }

    #[test]
    fn q16_weights_to_bytes_matches_be_encoding() {
        let w = Q16Weights {
            values: vec![1, -1, 0x12345678],
        };
        let bytes = w.to_bytes();
        assert_eq!(bytes.len(), 12);
        assert_eq!(&bytes[0..4], &1i32.to_be_bytes());
        assert_eq!(&bytes[4..8], &(-1i32).to_be_bytes());
        assert_eq!(&bytes[8..12], &0x12345678i32.to_be_bytes());
    }

    #[test]
    fn q16_weights_content_hash_is_deterministic() {
        let w = Q16Weights { values: vec![1, 2, 3] };
        let h1 = w.content_hash();
        let h2 = w.content_hash();
        assert_eq!(h1, h2);
        // Different values → different hash.
        let w2 = Q16Weights { values: vec![1, 2, 4] };
        assert_ne!(w.content_hash(), w2.content_hash());
    }

    #[test]
    fn stub_backend_is_deterministic_per_cycle() {
        let backend = StubTrainingBackend::default();
        let cache = MemoryEmbeddingCache::new();
        let w1 = backend.train(7, &cache, None).expect("ok");
        let w2 = backend.train(7, &cache, None).expect("ok");
        assert_eq!(w1, w2);
        // Different cycle → different weights.
        let w3 = backend.train(8, &cache, None).expect("ok");
        assert_ne!(w1, w3);
    }

    #[tokio::test]
    async fn memory_ipfs_pin_is_deterministic() {
        let ipfs = MemoryIpfsClient::new();
        let cid1 = ipfs.pin(b"hello").await.expect("ok");
        let cid2 = ipfs.pin(b"hello").await.expect("ok");
        assert_eq!(cid1, cid2);
        // Idempotent: same content not double-pinned.
        assert_eq!(ipfs.pin_count(), 1);
        // Different content → different CID.
        let cid3 = ipfs.pin(b"world").await.expect("ok");
        assert_ne!(cid1, cid3);
        assert_eq!(ipfs.pin_count(), 2);
    }

    #[tokio::test]
    async fn memory_ipfs_fetch_round_trips() {
        let ipfs = MemoryIpfsClient::new();
        let cid = ipfs.pin(b"hello").await.expect("ok");
        let bytes = ipfs.fetch(&cid).expect("found");
        assert_eq!(bytes, b"hello");
        assert!(ipfs.fetch("cid-doesnotexist").is_none());
    }

    #[tokio::test]
    async fn trainer_rejects_when_cycle_not_committed() {
        let (chain, state, _dir) = fixture();
        let cache = Arc::new(MemoryEmbeddingCache::new());
        let ipfs = Arc::new(MemoryIpfsClient::new());
        let backend = Arc::new(StubTrainingBackend::default());
        let trainer = RoutingTrainer::new(chain, state.clone(), cache, ipfs.clone(), backend);

        // Cycle starts Pending — training must reject.
        let err = trainer.train(1).await.expect_err("rejects");
        assert!(format!("{err}").contains("training requires"));
        // No IPFS pin happened.
        assert_eq!(ipfs.pin_count(), 0);
    }

    #[tokio::test]
    async fn trainer_pins_and_commits_when_cycle_committed() {
        let (chain, state, _dir) = fixture();
        let cache = Arc::new(MemoryEmbeddingCache::new());
        let ipfs = Arc::new(MemoryIpfsClient::new());
        let backend = Arc::new(StubTrainingBackend::default());

        // Fast-forward state: aggregator already committed cycle 1.
        state.set_cycle_status(1, CycleStatus::Computed).expect("ok");
        state.set_cycle_status(1, CycleStatus::Committed).expect("ok");

        let trainer = RoutingTrainer::new(
            chain.clone(),
            state.clone(),
            cache,
            ipfs.clone(),
            backend,
        );
        trainer.train(1).await.expect("ok");

        // IPFS pinned exactly one weights bundle.
        assert_eq!(ipfs.pin_count(), 1);
        // Chain saw exactly one routing-weights commit.
        let commits = chain.routing_weights_commits();
        assert_eq!(commits.len(), 1);
        assert_eq!(commits[0].cycle_id, 1);
    }

    #[tokio::test]
    async fn trainer_idempotent_via_deterministic_inputs() {
        let (chain, state, _dir) = fixture();
        let cache = Arc::new(MemoryEmbeddingCache::new());
        let ipfs = Arc::new(MemoryIpfsClient::new());
        let backend = Arc::new(StubTrainingBackend::default());

        state.set_cycle_status(1, CycleStatus::Computed).expect("ok");
        state.set_cycle_status(1, CycleStatus::Committed).expect("ok");

        let trainer = RoutingTrainer::new(
            chain.clone(),
            state.clone(),
            cache,
            ipfs.clone(),
            backend,
        );
        trainer.train(1).await.expect("first ok");
        trainer.train(1).await.expect("second is idempotent");

        // IPFS still has 1 pin (deterministic CID, not duplicated).
        assert_eq!(ipfs.pin_count(), 1);
        // Chain has TWO commits because the FakeChain's
        // commit_routing_weights doesn't deduplicate (real
        // contract may or may not — chain-side de-dup is the
        // production guarantee). What matters here: the daemon
        // doesn't crash on repeat call, and the CID is identical.
        let commits = chain.routing_weights_commits();
        assert_eq!(commits.len(), 2);
        assert_eq!(commits[0].ipfs_cid, commits[1].ipfs_cid);
        assert_eq!(commits[0].content_sha256, commits[1].content_sha256);
    }

    #[tokio::test]
    async fn trainer_seeds_previous_weights_from_first_cycle() {
        let (chain, state, _dir) = fixture();
        let cache = Arc::new(MemoryEmbeddingCache::new());
        let ipfs = Arc::new(MemoryIpfsClient::new());
        let backend = Arc::new(StubTrainingBackend::default());

        state.set_cycle_status(1, CycleStatus::Computed).expect("ok");
        state.set_cycle_status(1, CycleStatus::Committed).expect("ok");

        let trainer = RoutingTrainer::new(
            chain.clone(),
            state.clone(),
            cache,
            ipfs.clone(),
            backend,
        );

        // No previous weights initially.
        assert!(trainer.previous_weights.lock().expect("lock").is_none());

        trainer.train(1).await.expect("ok");

        // Now previous_weights is populated for the next cycle.
        assert!(trainer.previous_weights.lock().expect("lock").is_some());
    }

    #[test]
    fn weights_record_helper_composes_correctly() {
        let w = Q16Weights { values: vec![1, 2, 3] };
        let r = weights_record(7, "cid-deadbeef", &w);
        assert_eq!(r.cycle_id, 7);
        assert_eq!(r.ipfs_cid, "cid-deadbeef");
        assert_eq!(r.content_sha256, w.content_hash());
    }
}
