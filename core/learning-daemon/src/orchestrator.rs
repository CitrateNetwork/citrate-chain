//! Orchestrator — main loop coordinator.
//!
//! The orchestrator wires together watcher → event dispatch →
//! aggregator/trainer/finalizer. At WP-3.5 it handles:
//!
//!   - Watcher step loop (poll + dispatch)
//!   - Event dispatch by variant
//!   - Reorg recovery
//!
//! The aggregator (WP-3.6), trainer (WP-3.7), and finalizer
//! (WP-3.8) are pluggable trait objects so the orchestrator's loop
//! logic can be tested against fakes. Implementations for those
//! traits land in their respective WPs.

use std::sync::Arc;

use async_trait::async_trait;
use tracing::{debug, info, warn};

use crate::chain::{ChainAdapter, LearningEvent};
use crate::error::{DaemonError, DaemonResult};
use crate::state::{CycleStatus, DaemonState, FinalizeStatus};
use crate::types::CycleId;
use crate::watcher::{BlockWatcher, WatcherStep};

/// Pluggable aggregator hook. Implemented at WP-3.6.
#[async_trait]
pub trait Aggregator: Send + Sync {
    /// Aggregate the embeddings observed for `cycle_id` and submit
    /// the result to chain. The chain interaction goes through the
    /// `ChainAdapter`'s `commit_aggregation` method (already on
    /// `ChainAdapter` so the trait surface stays narrow).
    ///
    /// Idempotency contract (LearningDaemon.tla::AggregationIdempotent):
    /// implementations MUST guard on `state.cycle_status(cycle_id)`
    /// and skip if it is already `Computed` or `Committed`. The
    /// `check_daemon_idempotent_aggregation.py` tripwire enforces
    /// this structurally.
    async fn aggregate(&self, cycle_id: CycleId) -> DaemonResult<()>;
}

/// Pluggable trainer hook. Implemented at WP-3.7.
#[async_trait]
pub trait Trainer: Send + Sync {
    /// Retrain the routing model for `cycle_id` using the just-
    /// aggregated embeddings; quantize to Q16; pin to IPFS;
    /// commit the CID to chain.
    async fn train(&self, cycle_id: CycleId) -> DaemonResult<()>;
}

/// Pluggable finalizer hook. Implemented at WP-3.8.
#[async_trait]
pub trait Finalizer: Send + Sync {
    /// Call `LearningCycleManager.finalizeCycle(cycle_id)` and
    /// observe the receipt. Per
    /// `LearningDaemon.tla::FinalizeAtMostOnce`, the daemon's local
    /// state machine + the on-chain contract guard combine to
    /// enforce single-call semantics.
    async fn finalize(&self, cycle_id: CycleId) -> DaemonResult<()>;
}

/// The orchestrator. Owns shared handles to the chain adapter,
/// state, and pluggable hooks.
pub struct Orchestrator<C: ChainAdapter> {
    state: Arc<DaemonState>,
    watcher: BlockWatcher<C>,
    aggregator: Arc<dyn Aggregator>,
    trainer: Arc<dyn Trainer>,
    finalizer: Arc<dyn Finalizer>,
}

impl<C: ChainAdapter + 'static> Orchestrator<C> {
    /// Construct a new orchestrator.
    pub fn new(
        chain: Arc<C>,
        state: Arc<DaemonState>,
        aggregator: Arc<dyn Aggregator>,
        trainer: Arc<dyn Trainer>,
        finalizer: Arc<dyn Finalizer>,
    ) -> Self {
        let watcher = BlockWatcher::new(chain, state.clone());
        Self {
            state,
            watcher,
            aggregator,
            trainer,
            finalizer,
        }
    }

    /// Run one orchestrator tick. Tests drive this directly; the
    /// production binary (WP-3.5 slice 2) loops it under tokio.
    pub async fn tick(&self) -> DaemonResult<()> {
        let step = self.watcher.step().await?;
        match step {
            WatcherStep::NothingToDo => {
                debug!("nothing to do");
                Ok(())
            }
            WatcherStep::Advanced { new_hwm, events } => {
                info!(new_hwm, event_count = events.len(), "advanced");
                for event in events {
                    self.dispatch_event(event).await?;
                }
                Ok(())
            }
            WatcherStep::ReorgDetected {
                fork_at,
                cached_hash: _,
                chain_hash: _,
            } => {
                warn!(fork_at, "rolling back HWM due to reorg");
                // Per Gherkin scenario 7: roll back HWM to
                // fork_at - 1. The orchestrator's next tick will
                // re-process the post-reorg range. Cycles whose
                // status was already `Committed` on chain remain
                // committed (the chain is the source of truth);
                // local `cycle_status` for cycles aggregated but
                // not yet committed can be reset by the
                // aggregator's idempotency guard on the next
                // pass — the orchestrator does NOT touch them
                // here to avoid losing partial work.
                self.state.rollback_last_processed_block(fork_at.saturating_sub(1))?;
                Ok(())
            }
        }
    }

    /// Dispatch a single decoded event.
    async fn dispatch_event(&self, event: LearningEvent) -> DaemonResult<()> {
        let cycle_id = event.cycle_id();
        match event {
            LearningEvent::CycleOpened { .. } => {
                debug!(cycle_id, "cycle opened on chain");
                // No daemon action — the cycle's status defaults to
                // Pending in the state (and stays there until the
                // close triggers aggregation).
                Ok(())
            }
            LearningEvent::EmbeddingSubmitted(submission) => {
                debug!(
                    cycle_id,
                    submitter = ?submission.submitter,
                    "embedding submitted"
                );
                // No daemon action at submission time. The
                // aggregator picks up all submissions in one shot
                // when the cycle transitions Aggregating.
                Ok(())
            }
            LearningEvent::AggregationCommitted { state_hash, .. } => {
                info!(cycle_id, ?state_hash, "aggregation committed on chain");
                let local = self.state.cycle_status(cycle_id);
                if local == CycleStatus::Computed {
                    // Promote local view to Committed.
                    self.state.set_cycle_status(cycle_id, CycleStatus::Committed)?;
                } else if local == CycleStatus::Pending {
                    // Another daemon committed for this cycle;
                    // skip our own aggregation pass and just track
                    // the chain as authoritative. We can't promote
                    // Pending → Committed in one step (NoCommitWithoutAggregate),
                    // so we record the chain truth via aggregator's
                    // path: Aggregator must be re-run to pick up the
                    // submissions even if it doesn't commit them.
                    // For WP-3.5 we just log; the full handling
                    // lands in WP-3.6.
                    debug!(
                        cycle_id,
                        "another daemon committed first; local catch-up pending WP-3.6"
                    );
                }
                Ok(())
            }
            LearningEvent::CycleFinalized { .. } => {
                info!(cycle_id, "cycle finalized on chain");
                let local = self.state.finalize_status(cycle_id);
                if local == FinalizeStatus::NotCalled {
                    // Another daemon finalized first (Gherkin
                    // scenario 4) or our finalize tx confirmed; we
                    // accept the chain's truth as canonical.
                    self.state.mark_finalized(cycle_id)?;
                }
                Ok(())
            }
        }
    }

    /// Trigger aggregation for a cycle. Called externally when the
    /// orchestrator decides the cycle is ready (cycle close
    /// detection lands at WP-3.6). Idempotent: the underlying
    /// `Aggregator` impl guards on `cycle_status` per
    /// `LearningDaemon.tla::AggregationIdempotent`.
    pub async fn try_aggregate(&self, cycle_id: CycleId) -> DaemonResult<()> {
        self.aggregator.aggregate(cycle_id).await
    }

    /// Trigger training for a cycle. Same pattern as `try_aggregate`.
    pub async fn try_train(&self, cycle_id: CycleId) -> DaemonResult<()> {
        self.trainer.train(cycle_id).await
    }

    /// Drive the orchestrator until `shutdown` resolves, sleeping
    /// `tick_interval` between ticks. Used by the production daemon
    /// binary (WP-3.5 slice 2). Tests prefer to drive `tick()`
    /// directly to keep timing deterministic.
    ///
    /// The loop swallows transient `tick()` errors with a `warn!`
    /// log so a single RPC blip doesn't take down the daemon —
    /// permanent failures (RocksDB corruption, etc.) surface via
    /// the watcher's HWM-monotonic invariant + the state layer's
    /// own panics, which are NOT caught here.
    pub async fn run_loop(
        &self,
        tick_interval: std::time::Duration,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> DaemonResult<()> {
        info!(?tick_interval, "orchestrator run_loop entering");
        loop {
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        info!("orchestrator shutdown requested; exiting run_loop");
                        return Ok(());
                    }
                }
                _ = tokio::time::sleep(tick_interval) => {
                    if let Err(e) = self.tick().await {
                        warn!(error = %e, "tick failed; continuing");
                    }
                }
            }
        }
    }

    /// Trigger finalize for a cycle. Per `FinalizeAtMostOnce` +
    /// `FinalizeRequiresCommit`, the local guards check status
    /// before delegating to the finalizer.
    pub async fn try_finalize(&self, cycle_id: CycleId) -> DaemonResult<()> {
        if self.state.finalize_status(cycle_id) == FinalizeStatus::Called {
            // Already finalized locally — don't re-fire.
            debug!(cycle_id, "already finalized locally; skipping");
            return Ok(());
        }
        if self.state.cycle_status(cycle_id) != CycleStatus::Committed {
            return Err(DaemonError::Invariant(format!(
                "FinalizeRequiresCommit violation: cycle {cycle_id} status is {:?}",
                self.state.cycle_status(cycle_id)
            )));
        }
        self.finalizer.finalize(cycle_id).await?;
        // Successful finalize → record locally.
        self.state.mark_finalized(cycle_id)?;
        Ok(())
    }
}

// ============================================================
// No-op hook implementations.
//
// Despite the legacy `Stub*` naming (kept to minimize test churn
// across this WP), these are NOT placeholder stubs awaiting real
// impls — those exist: `BelnapAggregator` (WP-3.6),
// `RoutingTrainer` (WP-3.7), `ChainFinalizer` (WP-3.8). They are
// deliberate no-op fallbacks useful for two cases:
//
//   1. Partial daemon configurations (e.g., a "watcher only" mode
//      that observes events but doesn't aggregate or train).
//   2. Integration tests that exercise watcher + dispatch paths
//      without bringing up the full hook stack.
//
// `Orchestrator::new()` requires explicit hook arguments — there
// is NO default constructor that silently wires these in. Per
// the project's CLAUDE.md "Wittgenstein Loophole" guidance,
// production daemon configurations MUST construct with real hook
// types only.
// ============================================================

/// No-op aggregator: returns `Ok(())` without modifying state.
/// See section docs above; not a placeholder — the real impl is
/// `BelnapAggregator` in `aggregator.rs`.
pub struct StubAggregator;

#[async_trait]
impl Aggregator for StubAggregator {
    /// No-op aggregate. Idempotent by construction (no side effects).
    async fn aggregate(&self, _cycle_id: CycleId) -> DaemonResult<()> {
        Ok(())
    }
}

/// No-op trainer. Real impl is `RoutingTrainer` in `trainer.rs`.
pub struct StubTrainer;

#[async_trait]
impl Trainer for StubTrainer {
    async fn train(&self, _cycle_id: CycleId) -> DaemonResult<()> {
        Ok(())
    }
}

/// No-op finalizer. Real impl is `ChainFinalizer` in `finalizer.rs`.
pub struct StubFinalizer;

#[async_trait]
impl Finalizer for StubFinalizer {
    async fn finalize(&self, _cycle_id: CycleId) -> DaemonResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::FakeChain;
    use std::time::Duration;
    use tempfile::TempDir;

    fn make_orchestrator() -> (Orchestrator<FakeChain>, Arc<FakeChain>, TempDir) {
        let chain = Arc::new(FakeChain::new());
        let dir = TempDir::new().expect("tempdir");
        let state =
            Arc::new(DaemonState::open(dir.path()).expect("state open"));
        let orch = Orchestrator::new(
            chain.clone(),
            state,
            Arc::new(StubAggregator),
            Arc::new(StubTrainer),
            Arc::new(StubFinalizer),
        );
        (orch, chain, dir)
    }

    #[tokio::test]
    async fn run_loop_exits_on_shutdown_signal() {
        let (orch, _chain, _dir) = make_orchestrator();
        let (tx, rx) = tokio::sync::watch::channel(false);
        // Fire shutdown after a short delay; run_loop must observe it
        // and return Ok(()) without panicking.
        let handle = tokio::spawn(async move {
            orch.run_loop(Duration::from_millis(20), rx).await
        });
        tokio::time::sleep(Duration::from_millis(40)).await;
        tx.send(true).expect("send shutdown");
        let result = tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("run_loop did not exit within 1s")
            .expect("join")
            .expect("run_loop returned Err");
        let _ = result;
    }

    #[tokio::test]
    async fn run_loop_exits_when_shutdown_sender_dropped() {
        // If the watch::Sender is dropped, `changed()` errors; the
        // loop treats that as a shutdown signal and exits cleanly.
        let (orch, _chain, _dir) = make_orchestrator();
        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(async move {
            orch.run_loop(Duration::from_millis(20), rx).await
        });
        tokio::time::sleep(Duration::from_millis(40)).await;
        drop(tx);
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("run_loop did not exit within 1s")
            .expect("join")
            .expect("run_loop returned Err");
    }
}
