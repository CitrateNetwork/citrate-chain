//! Chain abstraction.
//!
//! The daemon talks to the chain through this trait so the
//! orchestrator's decision logic is unit-testable without a live
//! RPC. The HTTP-backed implementation (`HttpChainAdapter`) lands
//! in WP-3.5 slice 2 alongside the real `eth_subscribe newHeads`
//! subscription. WP-3.5 slice 1 ships only the trait + a
//! `FakeChain` impl so the orchestrator can be developed in
//! isolation.
//!
//! Mirrors the pattern from `pool-coordinator/src/chain.rs` (CM-05
//! WP-05.2): the trait defines the surface; the fake exposes
//! direct mutation for tests; the real adapter wraps `reqwest` +
//! ABI-encoded calls.

use std::sync::Mutex;

use async_trait::async_trait;
use ethereum_types::H256;
use serde::{Deserialize, Serialize};

use crate::error::DaemonResult;
use crate::types::{BlockNumber, CycleId, EmbeddingSubmission};

/// A learning-related event the daemon observes on chain.
///
/// Decoded from `LearningCycleManager` and `LoRAFactory` event logs
/// at the watcher (`watcher.rs`) layer. The daemon's orchestrator
/// dispatches by variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LearningEvent {
    /// `LearningCycleManager.CycleOpened(cycleId, openedAtBlock,
    /// deadlineBlock)`. Marks the start of a new cycle.
    CycleOpened {
        /// New cycle id.
        cycle_id: CycleId,
        /// Block number at which the cycle opened.
        opened_at: BlockNumber,
        /// Block number at which the Collecting phase closes.
        deadline: BlockNumber,
    },

    /// `LearningCycleManager.EmbeddingSubmitted(cycleId, participant,
    /// commitmentHash)`. One per participant per cycle.
    EmbeddingSubmitted(EmbeddingSubmission),

    /// `LearningCycleManager.AggregationCommitted(cycleId,
    /// stateVectorHash)`. The chain has accepted the daemon's
    /// commit. The daemon uses this to advance `cycle_status`
    /// from "computed" to "committed" with chain confirmation.
    AggregationCommitted {
        /// Cycle id whose aggregation was committed.
        cycle_id: CycleId,
        /// Keccak256 of the encoded state vector + values.
        state_hash: H256,
    },

    /// `LearningCycleManager.CycleFinalized(cycleId)`. Rewards have
    /// been distributed on chain.
    CycleFinalized {
        /// Cycle id finalized.
        cycle_id: CycleId,
    },
}

impl LearningEvent {
    /// Cycle id this event refers to (every variant carries one).
    pub fn cycle_id(&self) -> CycleId {
        match self {
            LearningEvent::CycleOpened { cycle_id, .. } => *cycle_id,
            LearningEvent::EmbeddingSubmitted(s) => s.cycle_id,
            LearningEvent::AggregationCommitted { cycle_id, .. } => *cycle_id,
            LearningEvent::CycleFinalized { cycle_id } => *cycle_id,
        }
    }
}

/// Chain abstraction. Reads + writes that the orchestrator needs.
///
/// All methods are `async` because the production HTTP adapter is
/// async; the `FakeChain` impl satisfies the bound trivially.
#[async_trait]
pub trait ChainAdapter: Send + Sync {
    /// Highest finalized block number the chain has produced.
    async fn finalized_block_number(&self) -> DaemonResult<BlockNumber>;

    /// Hash of a finalized block. Used by the watcher's reorg
    /// detection — if the hash at a previously-processed block
    /// changes, the daemon rolls back its HWM (Gherkin scenario 7).
    async fn block_hash(&self, n: BlockNumber) -> DaemonResult<H256>;

    /// Decoded learning events in the inclusive block range
    /// `[from, to]`. The watcher calls this to backfill events
    /// when advancing HWM.
    async fn learning_events(
        &self,
        from: BlockNumber,
        to: BlockNumber,
    ) -> DaemonResult<Vec<LearningEvent>>;

    /// Submit a `commitAggregation(cycleId, stateVector, valuesQ16)`
    /// transaction. Returns the tx hash on success.
    ///
    /// Implementation note (WP-3.6): the daemon polls
    /// `eth_getTransactionReceipt` after this call to confirm
    /// inclusion before advancing local `cycle_status` to
    /// "committed". Detached fire-and-forget would violate
    /// `LearningDaemon.tla::FinalizeRequiresCommit`.
    async fn commit_aggregation(
        &self,
        cycle_id: CycleId,
        state_vector: &[u8],
    ) -> DaemonResult<H256>;

    /// Submit a `finalizeCycle(cycleId)` transaction. Returns the tx
    /// hash on success. Per `FinalizeAtMostOnce`, the chain-side
    /// guard rejects the second call; the daemon accepts the
    /// resulting revert as confirmation that finalization happened.
    async fn finalize_cycle(&self, cycle_id: CycleId) -> DaemonResult<H256>;
}

/// In-memory `ChainAdapter` for unit tests. Tests inject events +
/// observe submitted transactions to drive the orchestrator
/// through the 8 Gherkin scenarios.
///
/// Thread-safe via inner `Mutex` — tests share one fake across the
/// orchestrator + the test driver.
pub struct FakeChain {
    inner: Mutex<FakeChainInner>,
}

struct FakeChainInner {
    finalized_block: BlockNumber,
    block_hashes: std::collections::BTreeMap<BlockNumber, H256>,
    /// Each entry: (block_number, event). Events are advertised by
    /// `learning_events` only when the queried range covers their
    /// block.
    timeline: Vec<(BlockNumber, LearningEvent)>,
    /// Aggregation commits the orchestrator has submitted.
    submitted_commits: Vec<(CycleId, Vec<u8>)>,
    /// Finalize-cycle calls the orchestrator has submitted.
    submitted_finalizes: Vec<CycleId>,
    /// If set, the next call to any RPC method returns this error
    /// (one-shot — cleared after firing). Models a transient RPC
    /// outage (Gherkin scenario 5).
    next_error: Option<String>,
}

impl FakeChain {
    /// Create an empty fake chain at block 0.
    pub fn new() -> Self {
        let mut inner = FakeChainInner {
            finalized_block: 0,
            block_hashes: std::collections::BTreeMap::new(),
            timeline: Vec::new(),
            submitted_commits: Vec::new(),
            submitted_finalizes: Vec::new(),
            next_error: None,
        };
        // Genesis hash is deterministic.
        inner
            .block_hashes
            .insert(0, H256::repeat_byte(0x00));
        Self {
            inner: Mutex::new(inner),
        }
    }

    /// Test helper: advance the chain by one block. The new block
    /// gets a deterministic hash derived from its number so reorg
    /// tests can swap it via `set_block_hash`.
    pub fn produce_block(&self) -> BlockNumber {
        let mut inner = self.inner.lock().expect("lock");
        inner.finalized_block += 1;
        let n = inner.finalized_block;
        let hash = H256::from_low_u64_be(n);
        inner.block_hashes.insert(n, hash);
        n
    }

    /// Test helper: enqueue an event at a given block number. The
    /// watcher will pick it up the next time `learning_events`
    /// covers the block.
    pub fn emit_event(&self, block_number: BlockNumber, event: LearningEvent) {
        let mut inner = self.inner.lock().expect("lock");
        inner.timeline.push((block_number, event));
    }

    /// Test helper: rewrite the hash of an already-produced block,
    /// modeling a chain reorg. The watcher's reorg-detection logic
    /// should observe the mismatch.
    pub fn set_block_hash(&self, n: BlockNumber, new_hash: H256) {
        let mut inner = self.inner.lock().expect("lock");
        inner.block_hashes.insert(n, new_hash);
    }

    /// Test helper: arm the next RPC call to return an error. One-shot.
    pub fn arm_next_error(&self, msg: impl Into<String>) {
        let mut inner = self.inner.lock().expect("lock");
        inner.next_error = Some(msg.into());
    }

    /// Test helper: read out the daemon's submitted commits. Used by
    /// scenario assertions.
    pub fn submitted_commits(&self) -> Vec<(CycleId, Vec<u8>)> {
        let inner = self.inner.lock().expect("lock");
        inner.submitted_commits.clone()
    }

    /// Test helper: read out the daemon's submitted finalize calls.
    pub fn submitted_finalizes(&self) -> Vec<CycleId> {
        let inner = self.inner.lock().expect("lock");
        inner.submitted_finalizes.clone()
    }

    /// Take and clear an armed error if one is pending.
    fn take_armed_error(&self) -> Option<String> {
        let mut inner = self.inner.lock().expect("lock");
        inner.next_error.take()
    }
}

impl Default for FakeChain {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChainAdapter for FakeChain {
    async fn finalized_block_number(&self) -> DaemonResult<BlockNumber> {
        if let Some(msg) = self.take_armed_error() {
            return Err(crate::error::DaemonError::Chain(msg));
        }
        let inner = self.inner.lock().expect("lock");
        Ok(inner.finalized_block)
    }

    async fn block_hash(&self, n: BlockNumber) -> DaemonResult<H256> {
        if let Some(msg) = self.take_armed_error() {
            return Err(crate::error::DaemonError::Chain(msg));
        }
        let inner = self.inner.lock().expect("lock");
        inner
            .block_hashes
            .get(&n)
            .copied()
            .ok_or_else(|| {
                crate::error::DaemonError::Chain(format!(
                    "block {n} not produced yet (finalized={})",
                    inner.finalized_block
                ))
            })
    }

    async fn learning_events(
        &self,
        from: BlockNumber,
        to: BlockNumber,
    ) -> DaemonResult<Vec<LearningEvent>> {
        if let Some(msg) = self.take_armed_error() {
            return Err(crate::error::DaemonError::Chain(msg));
        }
        let inner = self.inner.lock().expect("lock");
        Ok(inner
            .timeline
            .iter()
            .filter(|(bn, _)| *bn >= from && *bn <= to)
            .map(|(_, e)| e.clone())
            .collect())
    }

    async fn commit_aggregation(
        &self,
        cycle_id: CycleId,
        state_vector: &[u8],
    ) -> DaemonResult<H256> {
        if let Some(msg) = self.take_armed_error() {
            return Err(crate::error::DaemonError::Chain(msg));
        }
        let mut inner = self.inner.lock().expect("lock");
        inner.submitted_commits.push((cycle_id, state_vector.to_vec()));
        // Deterministic tx hash from cycle id for test assertions.
        Ok(H256::from_low_u64_be(0xC0_00 + cycle_id))
    }

    async fn finalize_cycle(&self, cycle_id: CycleId) -> DaemonResult<H256> {
        if let Some(msg) = self.take_armed_error() {
            return Err(crate::error::DaemonError::Chain(msg));
        }
        let mut inner = self.inner.lock().expect("lock");
        // Per FinalizeAtMostOnce: the on-chain contract rejects the
        // second call. Our fake mirrors that.
        if inner.submitted_finalizes.contains(&cycle_id) {
            return Err(crate::error::DaemonError::Finalize(format!(
                "cycle {cycle_id} already finalized"
            )));
        }
        inner.submitted_finalizes.push(cycle_id);
        Ok(H256::from_low_u64_be(0xF1_00 + cycle_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fake_chain_starts_at_block_zero() {
        let chain = FakeChain::new();
        assert_eq!(chain.finalized_block_number().await.expect("ok"), 0);
        assert_eq!(
            chain.block_hash(0).await.expect("ok"),
            H256::repeat_byte(0x00)
        );
    }

    #[tokio::test]
    async fn fake_chain_produce_block_advances() {
        let chain = FakeChain::new();
        let n = chain.produce_block();
        assert_eq!(n, 1);
        assert_eq!(chain.finalized_block_number().await.expect("ok"), 1);
        assert_eq!(
            chain.block_hash(1).await.expect("ok"),
            H256::from_low_u64_be(1)
        );
    }

    #[tokio::test]
    async fn fake_chain_emit_event_visible_in_range() {
        let chain = FakeChain::new();
        chain.produce_block();
        chain.produce_block();
        chain.emit_event(
            2,
            LearningEvent::CycleOpened {
                cycle_id: 1,
                opened_at: 2,
                deadline: 100,
            },
        );
        let events = chain.learning_events(1, 2).await.expect("ok");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].cycle_id(), 1);
    }

    #[tokio::test]
    async fn fake_chain_set_block_hash_models_reorg() {
        let chain = FakeChain::new();
        chain.produce_block();
        let original = chain.block_hash(1).await.expect("ok");
        let reorg_hash = H256::repeat_byte(0xff);
        chain.set_block_hash(1, reorg_hash);
        let after = chain.block_hash(1).await.expect("ok");
        assert_ne!(original, after);
        assert_eq!(after, reorg_hash);
    }

    #[tokio::test]
    async fn fake_chain_armed_error_fires_once() {
        let chain = FakeChain::new();
        chain.arm_next_error("RPC down");
        let err = chain.finalized_block_number().await.expect_err("err");
        assert!(format!("{err}").contains("RPC down"));
        // Second call succeeds (one-shot).
        assert_eq!(chain.finalized_block_number().await.expect("ok"), 0);
    }

    #[tokio::test]
    async fn fake_chain_finalize_at_most_once() {
        let chain = FakeChain::new();
        let _ = chain.finalize_cycle(7).await.expect("first ok");
        let err = chain.finalize_cycle(7).await.expect_err("second errs");
        assert!(format!("{err}").contains("already finalized"));
    }

    #[tokio::test]
    async fn fake_chain_records_submitted_commits() {
        let chain = FakeChain::new();
        let _ = chain.commit_aggregation(3, &[1, 2, 3]).await.expect("ok");
        let _ = chain.commit_aggregation(4, &[4, 5, 6]).await.expect("ok");
        let commits = chain.submitted_commits();
        assert_eq!(commits.len(), 2);
        assert_eq!(commits[0], (3, vec![1, 2, 3]));
    }

    #[test]
    fn learning_event_cycle_id_is_uniform() {
        let opened = LearningEvent::CycleOpened {
            cycle_id: 5,
            opened_at: 10,
            deadline: 20,
        };
        assert_eq!(opened.cycle_id(), 5);

        let finalized = LearningEvent::CycleFinalized { cycle_id: 5 };
        assert_eq!(finalized.cycle_id(), 5);
    }
}
