//! Real finalizer implementation. WP-3.8.
//!
//! Replaces `StubFinalizer`: calls
//! `LearningCycleManager.finalizeCycle(cycle_id)` via the
//! [`ChainAdapter`] and marks the daemon's local state per
//! `LearningDaemon.tla::FinalizeAtMostOnce`.
//!
//! The chain-side contract enforces at-most-once independently of
//! the daemon. If two daemons race (Gherkin scenario 4), the
//! second one's tx reverts on chain with `cycle already finalized`;
//! the daemon observes the revert and reconciles its local state
//! to match the chain truth.

use std::sync::Arc;

use async_trait::async_trait;
use tracing::{debug, info, warn};

use crate::chain::ChainAdapter;
use crate::error::{DaemonError, DaemonResult};
use crate::orchestrator::Finalizer;
use crate::state::{CycleStatus, DaemonState, FinalizeStatus};
use crate::types::CycleId;

/// Real finalizer. Replaces `StubFinalizer` once WP-3.8 lands.
pub struct ChainFinalizer<C: ChainAdapter> {
    chain: Arc<C>,
    /// `state` is held for symmetry with the helper API + future
    /// extension (operator-level preconditions before submitting);
    /// the chain-side guard is the actual safety mechanism.
    _state: Arc<DaemonState>,
}

impl<C: ChainAdapter> ChainFinalizer<C> {
    /// Construct a new finalizer.
    pub fn new(chain: Arc<C>, state: Arc<DaemonState>) -> Self {
        Self { chain, _state: state }
    }
}

#[async_trait]
impl<C: ChainAdapter + 'static> Finalizer for ChainFinalizer<C> {
    /// Call `finalizeCycle(cycle_id)` and observe the receipt.
    ///
    /// Pre-conditions enforced upstream by `Orchestrator::try_finalize`:
    ///   - `state.cycle_status(cycle_id) == Committed`
    ///     (`FinalizeRequiresCommit`)
    ///   - `state.finalize_status(cycle_id) == NotCalled`
    ///     (`FinalizeAtMostOnce`)
    ///
    /// This fn additionally tolerates the chain-side race condition
    /// where another daemon already finalized the cycle. In that
    /// case the chain rejects the tx with "cycle already finalized";
    /// we treat that as success-equivalent and let the orchestrator
    /// mark the local state.
    ///
    /// Per Gherkin scenario 4: two-daemon contention must result in
    /// exactly ONE `CycleFinalized` event on chain regardless of
    /// who races first. The local `mark_finalized` happens in the
    /// orchestrator's `try_finalize` only on Ok return — if we
    /// returned an error here the local state stays NotCalled and
    /// the next `CycleFinalized` event arriving via the watcher
    /// promotes it to Called via the dispatch path.
    async fn finalize(&self, cycle_id: CycleId) -> DaemonResult<()> {
        debug!(cycle_id, "submitting finalizeCycle");
        match self.chain.finalize_cycle(cycle_id).await {
            Ok(tx_hash) => {
                info!(cycle_id, tx = ?tx_hash, "finalize confirmed");
                Ok(())
            }
            Err(DaemonError::Finalize(msg)) if is_already_finalized(&msg) => {
                // Race lost — another daemon got there first.
                // Treat as success: the chain has the cycle finalized,
                // our local view will be reconciled by the watcher's
                // CycleFinalized event handler.
                warn!(
                    cycle_id,
                    "finalize race lost ({msg}); chain has the cycle finalized — accepting as success"
                );
                Ok(())
            }
            Err(other) => Err(other),
        }
    }
}

/// Heuristic check on chain error messages for the
/// "already finalized" race outcome. The exact message depends on
/// the on-chain contract's revert string + the RPC layer's
/// error-decoding path; the substring match is conservative.
fn is_already_finalized(msg: &str) -> bool {
    let lower = msg.to_lowercase();
    lower.contains("already finalized") || lower.contains("cycle finalized")
}

/// Helper: orchestrator-friendly variant of `try_finalize` that
/// composes the local guard with the chain call. Tests use this
/// to drive the finalize path without going through the full
/// orchestrator.
pub async fn try_finalize_cycle<C: ChainAdapter + 'static>(
    chain: Arc<C>,
    state: Arc<DaemonState>,
    cycle_id: CycleId,
) -> DaemonResult<()> {
    if state.finalize_status(cycle_id) == FinalizeStatus::Called {
        debug!(cycle_id, "already finalized locally; skipping");
        return Ok(());
    }
    if state.cycle_status(cycle_id) != CycleStatus::Committed {
        return Err(DaemonError::Invariant(format!(
            "FinalizeRequiresCommit violation: cycle {cycle_id} status is {:?}",
            state.cycle_status(cycle_id)
        )));
    }
    let finalizer = ChainFinalizer::new(chain, state.clone());
    finalizer.finalize(cycle_id).await?;
    state.mark_finalized(cycle_id)?;
    Ok(())
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

    fn fast_forward_to_committed(state: &DaemonState, cycle_id: CycleId) {
        state.set_cycle_status(cycle_id, CycleStatus::Computed).expect("ok");
        state.set_cycle_status(cycle_id, CycleStatus::Committed).expect("ok");
    }

    #[tokio::test]
    async fn finalize_happy_path() {
        let (chain, state, _dir) = fixture();
        fast_forward_to_committed(&state, 1);
        try_finalize_cycle(chain.clone(), state.clone(), 1)
            .await
            .expect("ok");
        assert_eq!(state.finalize_status(1), FinalizeStatus::Called);
        assert_eq!(chain.submitted_finalizes(), vec![1]);
    }

    #[tokio::test]
    async fn finalize_idempotent_locally() {
        let (chain, state, _dir) = fixture();
        fast_forward_to_committed(&state, 1);
        try_finalize_cycle(chain.clone(), state.clone(), 1).await.expect("first");
        // Second call: local guard skips before talking to chain.
        try_finalize_cycle(chain.clone(), state.clone(), 1).await.expect("second is no-op");
        // Only one chain submission happened.
        assert_eq!(chain.submitted_finalizes().len(), 1);
    }

    #[tokio::test]
    async fn finalize_requires_commit() {
        let (chain, state, _dir) = fixture();
        // Cycle still pending; finalize must reject.
        let err = try_finalize_cycle(chain, state, 1).await.expect_err("rejects");
        assert!(format!("{err}").contains("FinalizeRequiresCommit"));
    }

    #[tokio::test]
    async fn finalize_treats_already_finalized_as_success() {
        // Pre-populate the chain with a finalize for cycle 1
        // (simulating another daemon won the race).
        let (chain, state, _dir) = fixture();
        let _ = chain.finalize_cycle(1).await.expect("first finalize");

        // Now the daemon tries to finalize: chain rejects with
        // "already finalized"; our finalizer must treat it as Ok.
        fast_forward_to_committed(&state, 1);
        try_finalize_cycle(chain.clone(), state.clone(), 1)
            .await
            .expect("treats race-loss as success");
        // Local state reflects the (chain-confirmed) finalization.
        assert_eq!(state.finalize_status(1), FinalizeStatus::Called);
    }

    #[test]
    fn is_already_finalized_recognizes_common_messages() {
        assert!(is_already_finalized("cycle 7 already finalized"));
        assert!(is_already_finalized("cycle Already Finalized!"));
        assert!(is_already_finalized("CYCLE FINALIZED"));
        assert!(!is_already_finalized("RPC timeout"));
        assert!(!is_already_finalized("nonce too low"));
    }
}
