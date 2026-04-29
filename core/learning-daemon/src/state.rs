//! Daemon persistent state. RocksDB-backed; survives process death
//! per `LearningDaemon.tla::RestartSafety`.
//!
//! Column families:
//!
//!   - `meta` — single key `"last_processed_block"` carrying the
//!     forward-only HWM.
//!   - `cycle_status` — key = cycle_id (BE u64), value = bincode-
//!     encoded [`CycleStatus`].
//!   - `finalize_status` — key = cycle_id (BE u64), value = bincode-
//!     encoded [`FinalizeStatus`].
//!
//! All writes go through `WriteBatch` for atomicity within an
//! orchestrator step; reads use the in-memory cache populated at
//! startup by replaying RocksDB.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, DB};
use serde::{Deserialize, Serialize};

use crate::error::{DaemonError, DaemonResult};
use crate::types::{BlockNumber, CycleId};

/// Per-cycle aggregation status. Forward-only: pending → computed
/// → committed. Per `LearningDaemon.tla::AggregationIdempotent` and
/// `NoCommitWithoutAggregate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CycleStatus {
    /// Cycle has been observed open on chain; no aggregation done yet.
    Pending,
    /// Daemon has computed the local Belnap aggregation; not yet
    /// submitted to chain.
    Computed,
    /// Daemon has submitted `commitAggregation` and observed the
    /// receipt. The aggregation is now visible on chain.
    Committed,
}

/// Per-cycle finalization status. Per `FinalizeAtMostOnce`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalizeStatus {
    /// `finalizeCycle` has not yet been called for this cycle.
    NotCalled,
    /// `finalizeCycle` has been called and the receipt confirms
    /// inclusion. The on-chain contract enforces at-most-once
    /// regardless of what the daemon thinks.
    Called,
}

/// Column family names.
const CF_META: &str = "meta";
const CF_CYCLE_STATUS: &str = "cycle_status";
const CF_FINALIZE_STATUS: &str = "finalize_status";

/// Single key under `meta` cf.
const META_LAST_BLOCK: &[u8] = b"last_processed_block";

/// Daemon's persistent state, backed by RocksDB. Wraps a single DB
/// handle behind a `Mutex` so the orchestrator + watcher can share
/// it without async-mutex overhead (writes are bursty; lock
/// contention is negligible).
pub struct DaemonState {
    db: Arc<DB>,
    /// In-memory cache populated from RocksDB at startup. Reads go
    /// here; writes go through to RocksDB AND update the cache.
    /// The cache is the source of truth for hot reads; RocksDB is
    /// the source of truth across restarts.
    cache: Mutex<DaemonStateCache>,
}

#[derive(Debug, Default)]
struct DaemonStateCache {
    last_processed_block: BlockNumber,
    cycle_status: HashMap<CycleId, CycleStatus>,
    finalize_status: HashMap<CycleId, FinalizeStatus>,
}

impl DaemonState {
    /// Open (or create) the daemon's RocksDB at the given path.
    /// Replays existing column families into the in-memory cache.
    ///
    /// **Corruption handling** (Gherkin scenario 6): if RocksDB
    /// reports a corruption error on open, this method returns
    /// `Err(DaemonError::Persistence)`. Per the Gherkin contract,
    /// the daemon's startup wrapper is expected to log the error
    /// at `target=daemon.fatal` and exit non-zero.
    pub fn open(path: impl AsRef<Path>) -> DaemonResult<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_META, Options::default()),
            ColumnFamilyDescriptor::new(CF_CYCLE_STATUS, Options::default()),
            ColumnFamilyDescriptor::new(CF_FINALIZE_STATUS, Options::default()),
        ];

        let db = DB::open_cf_descriptors(&opts, path, cfs)?;
        let cache = Self::replay_cache(&db)?;
        Ok(Self {
            db: Arc::new(db),
            cache: Mutex::new(cache),
        })
    }

    /// Replay all column families into the in-memory cache.
    fn replay_cache(db: &DB) -> DaemonResult<DaemonStateCache> {
        let mut cache = DaemonStateCache::default();

        // Last processed block.
        let cf_meta = db
            .cf_handle(CF_META)
            .ok_or_else(|| DaemonError::Persistence("missing meta cf".into()))?;
        if let Some(bytes) = db.get_cf(&cf_meta, META_LAST_BLOCK)? {
            if bytes.len() == 8 {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&bytes);
                cache.last_processed_block = u64::from_be_bytes(buf);
            } else {
                return Err(DaemonError::Persistence(format!(
                    "meta last_processed_block has wrong length: {}",
                    bytes.len()
                )));
            }
        }

        // Cycle status.
        let cf_cycle = db.cf_handle(CF_CYCLE_STATUS).ok_or_else(|| {
            DaemonError::Persistence("missing cycle_status cf".into())
        })?;
        let iter = db.iterator_cf(&cf_cycle, rocksdb::IteratorMode::Start);
        for kv in iter {
            let (k, v) = kv?;
            if k.len() != 8 {
                return Err(DaemonError::Persistence(format!(
                    "cycle_status key has wrong length: {}",
                    k.len()
                )));
            }
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&k);
            let cycle_id = u64::from_be_bytes(buf);
            let status: CycleStatus = bincode::deserialize(&v)?;
            cache.cycle_status.insert(cycle_id, status);
        }

        // Finalize status.
        let cf_final = db.cf_handle(CF_FINALIZE_STATUS).ok_or_else(|| {
            DaemonError::Persistence("missing finalize_status cf".into())
        })?;
        let iter = db.iterator_cf(&cf_final, rocksdb::IteratorMode::Start);
        for kv in iter {
            let (k, v) = kv?;
            if k.len() != 8 {
                return Err(DaemonError::Persistence(format!(
                    "finalize_status key has wrong length: {}",
                    k.len()
                )));
            }
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&k);
            let cycle_id = u64::from_be_bytes(buf);
            let status: FinalizeStatus = bincode::deserialize(&v)?;
            cache.finalize_status.insert(cycle_id, status);
        }

        Ok(cache)
    }

    /// Read the current high water mark.
    pub fn last_processed_block(&self) -> BlockNumber {
        let cache = self.cache.lock().expect("lock");
        cache.last_processed_block
    }

    /// Advance the high water mark. Forward-only — fires
    /// `Err(DaemonError::Invariant)` if the caller tries to set a
    /// value below the current HWM
    /// (`LearningDaemon.tla::BlockHWMMonotonic`).
    pub fn set_last_processed_block(&self, n: BlockNumber) -> DaemonResult<()> {
        let mut cache = self.cache.lock().expect("lock");
        if n < cache.last_processed_block {
            return Err(DaemonError::Invariant(format!(
                "BlockHWMMonotonic violation: tried {} < current {}",
                n, cache.last_processed_block
            )));
        }
        let cf_meta = self.db.cf_handle(CF_META).ok_or_else(|| {
            DaemonError::Persistence("missing meta cf".into())
        })?;
        let mut batch = WriteBatch::default();
        batch.put_cf(&cf_meta, META_LAST_BLOCK, n.to_be_bytes());
        self.db.write(batch)?;
        cache.last_processed_block = n;
        Ok(())
    }

    /// **Reorg recovery only.** Roll back the HWM to a lower block
    /// because the chain reorged. Per Gherkin scenario 7, this is a
    /// rare path; the orchestrator must verify the consistency of
    /// any cycles whose status is "computed" or "committed" before
    /// continuing.
    ///
    /// Bypasses the forward-only check in `set_last_processed_block`.
    pub fn rollback_last_processed_block(&self, n: BlockNumber) -> DaemonResult<()> {
        let mut cache = self.cache.lock().expect("lock");
        let cf_meta = self.db.cf_handle(CF_META).ok_or_else(|| {
            DaemonError::Persistence("missing meta cf".into())
        })?;
        let mut batch = WriteBatch::default();
        batch.put_cf(&cf_meta, META_LAST_BLOCK, n.to_be_bytes());
        self.db.write(batch)?;
        cache.last_processed_block = n;
        Ok(())
    }

    /// Read the status of a cycle. Returns `Pending` if the cycle
    /// has never been recorded (the absence of a record means we
    /// haven't aggregated yet).
    pub fn cycle_status(&self, cycle_id: CycleId) -> CycleStatus {
        let cache = self.cache.lock().expect("lock");
        cache
            .cycle_status
            .get(&cycle_id)
            .copied()
            .unwrap_or(CycleStatus::Pending)
    }

    /// Set the status for a cycle. Per `AggregationIdempotent` +
    /// `NoCommitWithoutAggregate`: pending → computed → committed.
    /// Backwards transitions return `Err(DaemonError::Invariant)`.
    pub fn set_cycle_status(
        &self,
        cycle_id: CycleId,
        new_status: CycleStatus,
    ) -> DaemonResult<()> {
        let mut cache = self.cache.lock().expect("lock");
        let current = cache
            .cycle_status
            .get(&cycle_id)
            .copied()
            .unwrap_or(CycleStatus::Pending);
        if !is_valid_cycle_transition(current, new_status) {
            return Err(DaemonError::Invariant(format!(
                "invalid cycle_status transition for cycle {cycle_id}: {current:?} -> {new_status:?}"
            )));
        }
        let cf_cycle = self.db.cf_handle(CF_CYCLE_STATUS).ok_or_else(|| {
            DaemonError::Persistence("missing cycle_status cf".into())
        })?;
        let value = bincode::serialize(&new_status)?;
        let mut batch = WriteBatch::default();
        batch.put_cf(&cf_cycle, cycle_id.to_be_bytes(), value);
        self.db.write(batch)?;
        cache.cycle_status.insert(cycle_id, new_status);
        Ok(())
    }

    /// Read the finalize status of a cycle. Defaults to `NotCalled`.
    pub fn finalize_status(&self, cycle_id: CycleId) -> FinalizeStatus {
        let cache = self.cache.lock().expect("lock");
        cache
            .finalize_status
            .get(&cycle_id)
            .copied()
            .unwrap_or(FinalizeStatus::NotCalled)
    }

    /// Mark a cycle finalized. Per `FinalizeAtMostOnce`: must
    /// transition NotCalled → Called only. Re-firing returns
    /// `Err(DaemonError::Invariant)`.
    pub fn mark_finalized(&self, cycle_id: CycleId) -> DaemonResult<()> {
        let mut cache = self.cache.lock().expect("lock");
        let current = cache
            .finalize_status
            .get(&cycle_id)
            .copied()
            .unwrap_or(FinalizeStatus::NotCalled);
        if current == FinalizeStatus::Called {
            return Err(DaemonError::Invariant(format!(
                "FinalizeAtMostOnce violation for cycle {cycle_id}"
            )));
        }
        let cf_final = self.db.cf_handle(CF_FINALIZE_STATUS).ok_or_else(|| {
            DaemonError::Persistence("missing finalize_status cf".into())
        })?;
        let value = bincode::serialize(&FinalizeStatus::Called)?;
        let mut batch = WriteBatch::default();
        batch.put_cf(&cf_final, cycle_id.to_be_bytes(), value);
        self.db.write(batch)?;
        cache.finalize_status.insert(cycle_id, FinalizeStatus::Called);
        Ok(())
    }
}

/// Forward-only cycle-status transition rule. `LearningDaemon.tla::
/// AggregationIdempotent` + `NoCommitWithoutAggregate`.
fn is_valid_cycle_transition(from: CycleStatus, to: CycleStatus) -> bool {
    use CycleStatus::*;
    match (from, to) {
        // Identity (re-set is idempotent).
        (a, b) if a == b => true,
        (Pending, Computed) => true,
        (Computed, Committed) => true,
        // No backward transitions; no jump from Pending → Committed.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fresh_state() -> (DaemonState, TempDir) {
        let dir = TempDir::new().expect("tempdir");
        let state = DaemonState::open(dir.path()).expect("open");
        (state, dir)
    }

    #[test]
    fn fresh_state_starts_at_block_zero() {
        let (state, _dir) = fresh_state();
        assert_eq!(state.last_processed_block(), 0);
    }

    #[test]
    fn last_processed_block_forward_only() {
        let (state, _dir) = fresh_state();
        state.set_last_processed_block(5).expect("ok");
        assert_eq!(state.last_processed_block(), 5);
        state.set_last_processed_block(10).expect("ok");
        assert_eq!(state.last_processed_block(), 10);
        let err = state.set_last_processed_block(7).expect_err("backward rejects");
        assert!(format!("{err}").contains("BlockHWMMonotonic"));
    }

    #[test]
    fn rollback_bypasses_forward_only_check() {
        let (state, _dir) = fresh_state();
        state.set_last_processed_block(10).expect("ok");
        state.rollback_last_processed_block(7).expect("rollback ok");
        assert_eq!(state.last_processed_block(), 7);
    }

    #[test]
    fn cycle_status_pending_by_default() {
        let (state, _dir) = fresh_state();
        assert_eq!(state.cycle_status(42), CycleStatus::Pending);
    }

    #[test]
    fn cycle_status_pending_to_computed_to_committed() {
        let (state, _dir) = fresh_state();
        state
            .set_cycle_status(1, CycleStatus::Computed)
            .expect("pending → computed ok");
        assert_eq!(state.cycle_status(1), CycleStatus::Computed);
        state
            .set_cycle_status(1, CycleStatus::Committed)
            .expect("computed → committed ok");
        assert_eq!(state.cycle_status(1), CycleStatus::Committed);
    }

    #[test]
    fn cycle_status_no_jump_from_pending_to_committed() {
        let (state, _dir) = fresh_state();
        let err = state
            .set_cycle_status(1, CycleStatus::Committed)
            .expect_err("rejects jump");
        assert!(format!("{err}").contains("invalid cycle_status transition"));
    }

    #[test]
    fn cycle_status_no_backward_transition() {
        let (state, _dir) = fresh_state();
        state.set_cycle_status(1, CycleStatus::Computed).expect("ok");
        let err = state
            .set_cycle_status(1, CycleStatus::Pending)
            .expect_err("rejects backward");
        assert!(format!("{err}").contains("invalid cycle_status transition"));
    }

    #[test]
    fn finalize_at_most_once() {
        let (state, _dir) = fresh_state();
        state.mark_finalized(7).expect("first call ok");
        let err = state.mark_finalized(7).expect_err("second call rejects");
        assert!(format!("{err}").contains("FinalizeAtMostOnce"));
    }

    #[test]
    fn restart_safety_state_survives_reopen() {
        let dir = TempDir::new().expect("tempdir");
        // First incarnation.
        {
            let state = DaemonState::open(dir.path()).expect("open 1");
            state.set_last_processed_block(42).expect("ok");
            state.set_cycle_status(1, CycleStatus::Computed).expect("ok");
            state.set_cycle_status(1, CycleStatus::Committed).expect("ok");
            state.mark_finalized(1).expect("ok");
        } // First incarnation drops; RocksDB closes.
        // Second incarnation — same path, fresh process.
        let state = DaemonState::open(dir.path()).expect("open 2");
        assert_eq!(state.last_processed_block(), 42);
        assert_eq!(state.cycle_status(1), CycleStatus::Committed);
        assert_eq!(state.finalize_status(1), FinalizeStatus::Called);
    }

    #[test]
    fn cycle_status_idempotent_set() {
        let (state, _dir) = fresh_state();
        state.set_cycle_status(1, CycleStatus::Computed).expect("ok");
        // Setting the same status again is fine.
        state.set_cycle_status(1, CycleStatus::Computed).expect("idempotent");
    }

    #[test]
    fn is_valid_cycle_transition_table() {
        use CycleStatus::*;
        assert!(is_valid_cycle_transition(Pending, Pending));
        assert!(is_valid_cycle_transition(Pending, Computed));
        assert!(!is_valid_cycle_transition(Pending, Committed));
        assert!(is_valid_cycle_transition(Computed, Computed));
        assert!(is_valid_cycle_transition(Computed, Committed));
        assert!(!is_valid_cycle_transition(Computed, Pending));
        assert!(is_valid_cycle_transition(Committed, Committed));
        assert!(!is_valid_cycle_transition(Committed, Computed));
        assert!(!is_valid_cycle_transition(Committed, Pending));
    }
}
