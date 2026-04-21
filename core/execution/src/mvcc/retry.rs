//! Retry harness — wraps [`CommitCoordinator`] with bounded-retry
//! semantics and a fallback-to-serial path.
//!
//! # Spec mapping
//!
//! Implements the full execute-commit-retry-fallback flow proven by
//! `specs/tla/consensus/ExecutorMVCC.tla`. One call to
//! [`RetryHarness::execute`] corresponds to one tx's lifecycle through
//! the spec:
//!
//! 1. **PickUpTx + LocalExecute** — the user-supplied closure populates
//!    a fresh pinned journal. (Multiple times on retry.)
//! 2. **TryCommit** — `CommitCoordinator::try_commit` is called.
//!    Returns `Committed` → done; returns `Aborted` → go to step 3.
//! 3. **AbortAndRetry** — retries (step 1) up to `MaxRetries` times.
//! 4. **FallbackToSerial** — on retry exhaustion, call
//!    `CommitCoordinator::commit_exclusive` which holds the commit lock
//!    across execute + commit so no conflict can occur.
//!
//! The TLA+ `Progress` temporal property proves the flow terminates:
//! fallback always succeeds (unconditional commit under exclusive lock),
//! so every tx eventually reaches `TxCommitted`.
//!
//! # Metrics
//!
//! Three counters track observed behavior:
//! - `commits` — tx committed via CAS on first or subsequent retry
//! - `retries` — a single `try_commit` aborted; the harness is about to
//!   try again
//! - `fallbacks` — all retries exhausted; the tx committed via
//!   `commit_exclusive`
//!
//! In a healthy workload, `fallbacks` should be a small fraction of
//! `commits`. A high ratio indicates either MaxRetries is too low or
//! the workload has pathological contention (the latter is the
//! adversarial case the fallback exists for).

use crate::mvcc::commit::{CommitCoordinator, CommitOutcome};
use crate::mvcc::scratch_journal::ScratchJournal;
use crate::mvcc::version::ReadVersion;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Default retry budget before falling back to serial execution.
///
/// Matches the model parameter in `ExecutorMVCC.tla` (which uses 3 for
/// tractability) scaled up for production: 8 retries gives adversarial
/// workloads room to make progress via CAS before burdening the
/// serial path.
pub const DEFAULT_MAX_RETRIES: usize = 8;

/// Aggregate metrics for the retry harness.
///
/// Uses atomic counters for lockless concurrent access. Designed to be
/// wrapped in an `Arc` and shared across workers.
#[derive(Debug, Default)]
pub struct RetryMetrics {
    pub commits: AtomicU64,
    pub retries: AtomicU64,
    pub fallbacks: AtomicU64,
}

impl RetryMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn commits(&self) -> u64 {
        self.commits.load(Ordering::Relaxed)
    }

    pub fn retries(&self) -> u64 {
        self.retries.load(Ordering::Relaxed)
    }

    pub fn fallbacks(&self) -> u64 {
        self.fallbacks.load(Ordering::Relaxed)
    }

    /// Ratio of retries to commits. Healthy workloads have a ratio well
    /// below 1.0; ratios above 1.0 indicate high contention.
    pub fn retry_ratio(&self) -> f64 {
        let c = self.commits() as f64;
        let r = self.retries() as f64;
        if c == 0.0 {
            0.0
        } else {
            r / c
        }
    }

    /// Ratio of fallbacks to commits. Healthy workloads have this at
    /// near-zero; non-zero means some txs burned through their retry
    /// budget and needed the serial path.
    pub fn fallback_ratio(&self) -> f64 {
        let c = self.commits() as f64;
        let f = self.fallbacks() as f64;
        if c == 0.0 {
            0.0
        } else {
            f / c
        }
    }
}

/// Result of a successful execute — whether via CAS or fallback path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitSuccess {
    /// The version at which this tx's writes became visible.
    pub new_version: ReadVersion,
    /// Number of CAS retries before this tx committed. Zero means
    /// the first attempt succeeded. Equal to MaxRetries means the
    /// fallback-to-serial path was taken.
    pub retries: usize,
    /// Whether the fallback-to-serial path was taken.
    pub fallback_used: bool,
}

/// The retry harness.
///
/// Cheap to construct and clone (shares the coordinator and metrics via
/// `Arc` internally). Typical usage: construct once at executor init,
/// clone into worker contexts.
#[derive(Debug, Clone)]
pub struct RetryHarness {
    coord: CommitCoordinator,
    metrics: Arc<RetryMetrics>,
    max_retries: usize,
}

impl RetryHarness {
    /// Construct with a fresh coordinator and default retry budget.
    pub fn new() -> Self {
        Self {
            coord: CommitCoordinator::new(),
            metrics: Arc::new(RetryMetrics::new()),
            max_retries: DEFAULT_MAX_RETRIES,
        }
    }

    /// Construct with a specific coordinator. Useful when the executor
    /// already owns a coordinator and wants to share it.
    pub fn with_coordinator(coord: CommitCoordinator) -> Self {
        Self {
            coord,
            metrics: Arc::new(RetryMetrics::new()),
            max_retries: DEFAULT_MAX_RETRIES,
        }
    }

    /// Set a custom retry budget. Returns self by move for fluent use.
    pub fn with_max_retries(mut self, n: usize) -> Self {
        self.max_retries = n;
        self
    }

    /// Underlying coordinator — for direct access when the harness
    /// abstraction isn't needed.
    pub fn coordinator(&self) -> &CommitCoordinator {
        &self.coord
    }

    /// Metrics accessor.
    pub fn metrics(&self) -> &Arc<RetryMetrics> {
        &self.metrics
    }

    /// Current global version.
    pub fn current_version(&self) -> ReadVersion {
        self.coord.current_version()
    }

    /// Execute a tx with bounded retries and fallback-to-serial.
    ///
    /// The closure is called at least once and at most `max_retries + 1`
    /// times. Each call receives a freshly pinned journal; the closure
    /// records reads and writes on it. After the closure returns, the
    /// harness attempts commit. On conflict, it retries up to
    /// `max_retries` times, then falls back to the serial path.
    ///
    /// Returns the successful commit's outcome.
    ///
    /// # Panics
    ///
    /// Does not panic under normal use. The underlying `try_commit` /
    /// `commit_exclusive` panic only if a journal is unpinned, but the
    /// harness always pins journals it hands out.
    pub fn execute<F>(&self, mut execute: F) -> CommitSuccess
    where
        F: FnMut(&mut ScratchJournal, ReadVersion),
    {
        // --- Fast path: bounded retries ---
        for attempt in 0..self.max_retries {
            let mut journal = self.coord.new_pinned_journal();
            let pin = journal
                .pinned_version()
                .expect("new_pinned_journal returns a pinned journal");
            execute(&mut journal, pin);

            match self.coord.try_commit(&journal) {
                CommitOutcome::Committed { new_version } => {
                    self.metrics.commits.fetch_add(1, Ordering::Relaxed);
                    return CommitSuccess {
                        new_version,
                        retries: attempt,
                        fallback_used: false,
                    };
                }
                CommitOutcome::Aborted { .. } => {
                    self.metrics.retries.fetch_add(1, Ordering::Relaxed);
                    // loop to next attempt
                }
            }
        }

        // --- Slow path: fallback to serial ---
        self.metrics.fallbacks.fetch_add(1, Ordering::Relaxed);
        let new_version = self.coord.commit_exclusive(|journal, pin| {
            execute(journal, pin);
        });
        // Record the fallback commit in the commit counter too so that
        // "total commits" is a consistent count regardless of path.
        self.metrics.commits.fetch_add(1, Ordering::Relaxed);
        CommitSuccess {
            new_version,
            retries: self.max_retries,
            fallback_used: true,
        }
    }
}

impl Default for RetryHarness {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mvcc::scratch_journal::PendingWrite;
    use crate::types::Address;
    use primitive_types::U256;
    use std::sync::Barrier;
    use std::thread;

    fn addr(n: u8) -> Address {
        let mut a = [0u8; 20];
        a[0] = n;
        Address(a)
    }

    fn balance_write(bal: u64) -> PendingWrite {
        PendingWrite {
            new_balance: Some(U256::from(bal)),
            new_nonce: None,
            new_code: None,
        }
    }

    #[test]
    fn new_harness_defaults() {
        let h = RetryHarness::new();
        assert_eq!(h.current_version(), ReadVersion::from_raw(0));
        assert_eq!(h.metrics().commits(), 0);
        assert_eq!(h.metrics().retries(), 0);
        assert_eq!(h.metrics().fallbacks(), 0);
    }

    #[test]
    fn first_attempt_commit_no_retries() {
        let h = RetryHarness::new();
        let result = h.execute(|journal, _pin| {
            journal.record_write(addr(1), balance_write(100));
        });
        assert_eq!(result.new_version, ReadVersion::from_raw(1));
        assert_eq!(result.retries, 0);
        assert!(!result.fallback_used);
        assert_eq!(h.metrics().commits(), 1);
        assert_eq!(h.metrics().retries(), 0);
        assert_eq!(h.metrics().fallbacks(), 0);
    }

    #[test]
    fn retry_metrics_accumulate_on_first_abort_then_success() {
        // Force exactly one retry: pre-bump account 1's tracker version
        // high, and only READ account 1 on the first attempt. The
        // second attempt's read set is empty, so validation succeeds.
        //
        // Avoids calling coord.try_commit from inside the closure —
        // that would deadlock during the fallback path where
        // commit_exclusive holds the commit lock.
        let h = RetryHarness::new();
        let coord = h.coordinator().clone();

        // Pre-bump account 1's tracker version so any read of it fails.
        coord.tracker().bump(addr(1), ReadVersion::from_raw(100));

        let attempt = Arc::new(std::sync::Mutex::new(0usize));
        let attempt_clone = Arc::clone(&attempt);

        let result = h.execute(|journal, _pin| {
            let mut a = attempt_clone.lock().unwrap();
            *a += 1;
            // Only read account 1 on the first attempt; subsequent
            // attempts have an empty read set and commit cleanly.
            if *a == 1 {
                journal.record_read(addr(1));
            }
            journal.record_write(addr(2), balance_write(100));
        });

        assert_eq!(result.retries, 1, "exactly one retry (first attempt aborts, second commits)");
        assert!(!result.fallback_used);
        assert_eq!(h.metrics().retries(), 1);
        assert_eq!(h.metrics().commits(), 1);
        assert_eq!(h.metrics().fallbacks(), 0);
        assert_eq!(*attempt.lock().unwrap(), 2, "closure called twice");
    }

    #[test]
    fn retry_exhaustion_triggers_fallback() {
        // Every CAS attempt aborts because account 1's tracker version
        // is pre-pushed above any reachable pin. After max_retries
        // consecutive aborts, the harness falls back to commit_exclusive,
        // which doesn't validate the read set — so the fallback succeeds.
        //
        // Rationale for bypassing try_commit in the closure (vs. using
        // it to simulate an "external" commit): commit_exclusive holds
        // the commit lock across the closure, and calling try_commit
        // recursively on the same lock would deadlock. Using direct
        // tracker writes avoids the re-entrancy and still triggers the
        // abort path exactly as the spec describes.
        let h = RetryHarness::new().with_max_retries(2);
        let coord = h.coordinator().clone();

        // Pre-set account 1's tracker version to an unreachable value.
        // With u64::MAX/2, any natural pin will be below it, so any
        // read of account 1 invalidates the read set.
        coord
            .tracker()
            .bump(addr(1), ReadVersion::from_raw(u64::MAX / 2));

        let result = h.execute(|journal, _pin| {
            journal.record_read(addr(1));
            journal.record_write(addr(2), balance_write(100));
        });

        assert!(result.fallback_used, "retries exhausted → fallback used");
        assert_eq!(result.retries, 2, "recorded retries = max_retries");
        assert_eq!(h.metrics().fallbacks(), 1);
        assert_eq!(h.metrics().retries(), 2);
        // Fallback commit is counted in commits too, for consistency.
        assert_eq!(h.metrics().commits(), 1);
    }

    #[test]
    fn sequential_txs_all_commit() {
        let h = RetryHarness::new();
        for i in 0..10u8 {
            let r = h.execute(|journal, _pin| {
                journal.record_write(addr(i), balance_write(i as u64));
            });
            assert!(!r.fallback_used, "sequential non-conflicting should never fall back");
            assert_eq!(r.retries, 0);
        }
        assert_eq!(h.current_version(), ReadVersion::from_raw(10));
        assert_eq!(h.metrics().commits(), 10);
        assert_eq!(h.metrics().retries(), 0);
        assert_eq!(h.metrics().fallbacks(), 0);
    }

    #[test]
    fn concurrent_disjoint_executions_all_first_try() {
        // 16 workers with disjoint writes — all succeed on first try,
        // zero retries, zero fallbacks.
        let h = Arc::new(RetryHarness::new());
        let handles: Vec<_> = (0..16u8)
            .map(|i| {
                let h = Arc::clone(&h);
                thread::spawn(move || {
                    h.execute(|journal, _pin| {
                        journal.record_write(addr(i), balance_write(i as u64));
                    })
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|t| t.join().unwrap()).collect();

        for r in &results {
            assert!(!r.fallback_used);
        }
        assert_eq!(h.current_version(), ReadVersion::from_raw(16));
        assert_eq!(h.metrics().commits(), 16);
        // Some incidental retries possible if Disjoint workers happen to
        // hit the mutex at exactly the same nanosecond — but fallbacks
        // should still be zero with 16 workers.
        assert_eq!(h.metrics().fallbacks(), 0);
    }

    #[test]
    fn concurrent_high_contention_eventually_all_commit() {
        // 8 workers all writing to account 1 from synchronized pins.
        // With 8 retries each, they should all eventually commit via
        // retry + retry + ... + possibly fallback. Total commits = 8.
        let h = Arc::new(RetryHarness::new());
        let barrier = Arc::new(Barrier::new(8));

        let handles: Vec<_> = (0..8u8)
            .map(|i| {
                let h = Arc::clone(&h);
                let b = Arc::clone(&barrier);
                thread::spawn(move || {
                    b.wait();
                    h.execute(|journal, _pin| {
                        journal.record_write(addr(1), balance_write(i as u64));
                    })
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|t| t.join().unwrap()).collect();

        // All 8 eventually commit (via retry or fallback)
        assert_eq!(results.len(), 8);
        assert_eq!(h.current_version(), ReadVersion::from_raw(8));
        assert_eq!(h.metrics().commits(), 8);

        // On this config, fallbacks are possible but not required. The
        // key invariant is total commits = 8.
        let fallbacks = h.metrics().fallbacks();
        let retries = h.metrics().retries();
        // Sanity: if we had no retries, something's wrong with the test
        // (8 workers writing account 1 should cause serialization on
        // the commit lock, and some of them should observe abort)
        // Actually since only ONE writes-without-read, none actually
        // conflict on read set — account 1's version bumps but no
        // worker has account 1 in its read set. So all commit without
        // abort. Let me adjust the test to include a read-write.
        println!(
            "high-contention metrics: retries={} fallbacks={}",
            retries, fallbacks
        );
    }

    #[test]
    fn high_contention_with_read_write_triggers_retries() {
        // 8 workers EACH reading and writing account 1 from a synchronized
        // pin. This triggers the true abort-retry-or-fallback cycle.
        let h = Arc::new(RetryHarness::new().with_max_retries(16));
        let barrier = Arc::new(Barrier::new(8));

        let handles: Vec<_> = (0..8u8)
            .map(|i| {
                let h = Arc::clone(&h);
                let b = Arc::clone(&barrier);
                thread::spawn(move || {
                    b.wait();
                    h.execute(|journal, _pin| {
                        journal.record_read(addr(1));
                        journal.record_write(addr(1), balance_write(i as u64));
                    })
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(results.len(), 8);
        assert_eq!(h.current_version(), ReadVersion::from_raw(8));
        assert_eq!(h.metrics().commits(), 8);

        // With 8 workers synchronized on a common pin, at least 7 of
        // them will see an aborted first attempt. Retries should be
        // substantial; fallbacks depend on scheduler + MaxRetries=16.
        assert!(
            h.metrics().retries() >= 7,
            "expected >=7 retries from synchronized conflict, got {}",
            h.metrics().retries()
        );
    }

    #[test]
    fn retry_metrics_ratios_sane() {
        let m = RetryMetrics::new();
        assert_eq!(m.retry_ratio(), 0.0);
        assert_eq!(m.fallback_ratio(), 0.0);

        m.commits.store(10, Ordering::Relaxed);
        m.retries.store(4, Ordering::Relaxed);
        m.fallbacks.store(1, Ordering::Relaxed);

        assert_eq!(m.retry_ratio(), 0.4);
        assert_eq!(m.fallback_ratio(), 0.1);
    }
}
