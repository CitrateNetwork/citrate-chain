//! Block watcher.
//!
//! Observes finalized blocks via the [`ChainAdapter`], decodes
//! learning events, and feeds them to the orchestrator. Maintains
//! the forward-only HWM (`last_processed_block`) per
//! `LearningDaemon.tla::BlockHWMMonotonic` + `BlockHWMBoundedByChain`.
//!
//! # Reorg detection
//!
//! Before processing a new range `[from, to]`, the watcher
//! re-fetches the hash of `from - 1` (the last block it had
//! processed) and compares against the cached hash. If they
//! differ, a reorg has happened — the watcher returns
//! `WatcherStep::ReorgDetected { fork_at }` and the orchestrator
//! must call `state.rollback_last_processed_block(fork_at - 1)`
//! before continuing. (Gherkin scenario 7.)

use std::sync::Arc;

use ethereum_types::H256;
use tracing::{debug, info, warn};

use crate::chain::{ChainAdapter, LearningEvent};
use crate::error::DaemonResult;
use crate::state::DaemonState;
use crate::types::BlockNumber;

/// Result of one watcher tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatcherStep {
    /// No new finalized blocks to process; chain head matches HWM.
    NothingToDo,
    /// Range processed; events emitted; HWM advanced.
    Advanced {
        /// New high water mark.
        new_hwm: BlockNumber,
        /// Events decoded from the just-processed range.
        events: Vec<LearningEvent>,
    },
    /// Chain reorg detected. Orchestrator must roll back.
    ReorgDetected {
        /// Block number where the chain history diverges. The HWM
        /// should roll back to `fork_at - 1`.
        fork_at: BlockNumber,
        /// Hash the daemon had previously cached for `fork_at`.
        cached_hash: H256,
        /// Hash the chain currently reports for `fork_at`.
        chain_hash: H256,
    },
}

/// Block watcher. Owns a chain adapter handle (shared `Arc`) and a
/// pointer to the daemon state. Hash cache for reorg detection
/// lives in the watcher (not in `DaemonState`) because it's not
/// safety-critical to persist across restarts — on restart, we
/// re-fetch the hash for `last_processed_block` from the chain at
/// startup.
pub struct BlockWatcher<C: ChainAdapter> {
    chain: Arc<C>,
    state: Arc<DaemonState>,
    /// Cached hash of `last_processed_block`, refreshed on every
    /// successful step. `None` means "no block processed yet" or
    /// "watcher just started".
    last_block_hash: std::sync::Mutex<Option<(BlockNumber, H256)>>,
}

impl<C: ChainAdapter> BlockWatcher<C> {
    /// Create a new watcher.
    pub fn new(chain: Arc<C>, state: Arc<DaemonState>) -> Self {
        Self {
            chain,
            state,
            last_block_hash: std::sync::Mutex::new(None),
        }
    }

    /// Run one watcher tick: detect reorg → fetch new range →
    /// emit events → advance HWM.
    ///
    /// The orchestrator drives this in a loop. Returns the step
    /// outcome for the orchestrator to dispatch on.
    pub async fn step(&self) -> DaemonResult<WatcherStep> {
        let chain_head = self.chain.finalized_block_number().await?;
        let hwm = self.state.last_processed_block();

        if chain_head <= hwm {
            return Ok(WatcherStep::NothingToDo);
        }

        // Reorg check: confirm the previously-cached `hwm` block
        // hash still matches what the chain reports. Skip if hwm = 0
        // (genesis is special-cased in FakeChain to a fixed hash;
        // production HttpChainAdapter follows the same convention
        // because the genesis hash is fixed by the chain spec).
        if hwm > 0 {
            if let Some(reorg) = self.detect_reorg(hwm).await? {
                return Ok(reorg);
            }
        }

        let from = hwm + 1;
        let to = chain_head;
        debug!(from, to, "fetching learning events");

        let events = self.chain.learning_events(from, to).await?;
        let new_head_hash = self.chain.block_hash(to).await?;

        // Advance HWM atomically.
        self.state.set_last_processed_block(to)?;
        {
            let mut cache = self.last_block_hash.lock().expect("lock");
            *cache = Some((to, new_head_hash));
        }

        info!(
            from,
            to,
            event_count = events.len(),
            "watcher advanced"
        );

        Ok(WatcherStep::Advanced {
            new_hwm: to,
            events,
        })
    }

    /// Check whether the cached hash for `block_number` matches
    /// what the chain currently reports. Returns `Some(ReorgDetected)`
    /// if mismatched.
    async fn detect_reorg(
        &self,
        block_number: BlockNumber,
    ) -> DaemonResult<Option<WatcherStep>> {
        let chain_hash = self.chain.block_hash(block_number).await?;
        let cached = {
            let cache = self.last_block_hash.lock().expect("lock");
            *cache
        };
        if let Some((cached_n, cached_hash)) = cached {
            if cached_n == block_number && cached_hash != chain_hash {
                warn!(
                    block_number,
                    cached = %cached_hash,
                    chain = %chain_hash,
                    "reorg detected"
                );
                return Ok(Some(WatcherStep::ReorgDetected {
                    fork_at: block_number,
                    cached_hash,
                    chain_hash,
                }));
            }
        }
        // Either no cache yet (first step after startup) or hash matches.
        Ok(None)
    }

    /// Manually refresh the cached hash for the current HWM.
    /// Called on startup so the watcher's first step has a baseline
    /// for reorg detection.
    pub async fn prime_hash_cache(&self) -> DaemonResult<()> {
        let hwm = self.state.last_processed_block();
        if hwm == 0 {
            return Ok(());
        }
        let hash = self.chain.block_hash(hwm).await?;
        let mut cache = self.last_block_hash.lock().expect("lock");
        *cache = Some((hwm, hash));
        Ok(())
    }
}

// Tests live in `tests/lifecycle.rs` because they exercise the full
// daemon pipeline (chain + state + watcher) and need `tempfile`
// (a dev-dependency, not available to unit tests in lib.rs without
// extra wiring).
//
// Keep this module's coverage by writing focused unit tests in the
// integration test file rather than here — the trait + state
// boundary makes that the natural seam.
