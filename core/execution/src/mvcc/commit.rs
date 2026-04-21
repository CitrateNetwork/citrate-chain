//! Commit coordinator — the atomic `TryCommit` action.
//!
//! Composes [`StateVersion`], [`AccountVersionTracker`], and
//! [`ScratchJournal`] into the single atomic operation proven by
//! `specs/tla/consensus/ExecutorMVCC.tla` as the `TryCommit` action:
//!
//! ```tla
//! TryCommit(w) ==
//!     /\ workerStatus[w] = StatusReady
//!     /\ ReadSetValid(w)                    \* Validity check
//!     /\ globalVersion < MaxVersion
//!     /\ accountVersion' = ...bump writes to newVer...
//!     /\ globalVersion' = newVer            \* Version bump
//!     /\ txStatus'[tx] = TxCommitted
//!     /\ commitOrder' = Append(commitOrder, tx)
//!     ...
//! ```
//!
//! # Concurrency
//!
//! The implementation holds a short critical section via
//! [`parking_lot::Mutex`] around *only* the validate-and-bump path.
//! Transaction **execution** — which is the 99%-time-cost part —
//! happens entirely outside any lock. Workers execute in full
//! parallel; only the final `try_commit` step is serialized.
//!
//! This is a correct-but-simple starting point. Block-STM's
//! full lockless optimization (per-account CAS with provisional
//! markers) can come in a later WP if the short critical section
//! becomes a measurable bottleneck.
//!
//! # Invariants preserved
//!
//! This module preserves all 14 safety invariants + 1 action property
//! + 1 liveness property proven in `ExecutorMVCC.tla`:
//!
//! - `GlobalVersionTracksCommits` — every successful commit advances
//!   `state_version` by exactly one
//! - `AccountVersionBoundedByCommits` — account versions only advance
//!   via the atomic bump-all inside the critical section
//! - `ReadyWorkerCommitOrRetry` — `try_commit` returns either
//!   `Committed` (commit succeeded) or `Aborted` (retry needed),
//!   never gets stuck
//! - `NoLostUpdate` — the mutex guarantees that between `validate`
//!   and `bump_all`, no other commit slips through and invalidates
//!   the worker's read set unnoticed

use crate::mvcc::read_set::ReadSet;
use crate::mvcc::scratch_journal::ScratchJournal;
use crate::mvcc::version::{ReadVersion, StateVersion};
use crate::mvcc::version_tracker::AccountVersionTracker;
use parking_lot::Mutex;
use std::sync::Arc;

/// Outcome of a commit attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitOutcome {
    /// Commit succeeded. The new global version is included — this is
    /// the version at which the committed writes are visible to
    /// subsequent readers.
    Committed {
        /// The new global version after this commit.
        new_version: ReadVersion,
    },

    /// Commit aborted; the worker must retry.
    Aborted {
        /// Why the commit was rejected.
        reason: AbortReason,
        /// The current global version at the moment of abort. Workers
        /// use this to re-pin before re-executing.
        current_version: ReadVersion,
    },
}

/// Reason for an aborted commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortReason {
    /// An intervening commit wrote to at least one account in this
    /// worker's read set. The read-set check (`ReadSetValid`) failed.
    ///
    /// Corresponds to TLA+ `AbortAndRetry` preconditon `~ReadSetValid(w)`.
    ReadSetInvalidated,
}

/// Orchestrator for MVCC commits.
///
/// Typically held as a single instance shared across all workers in
/// the executor, wrapped in an `Arc`. Cheap to clone.
///
/// # Example
///
/// ```ignore
/// let coord = Arc::new(CommitCoordinator::new());
///
/// // Worker thread:
/// let mut journal = coord.new_pinned_journal();
/// // ... execute tx against the pinned snapshot, populating journal ...
/// match coord.try_commit(&journal) {
///     CommitOutcome::Committed { new_version } => {
///         // Drain journal into state DB, emit receipt, etc.
///     }
///     CommitOutcome::Aborted { .. } => {
///         // Clear journal, re-pin, re-execute
///     }
/// }
/// ```
#[derive(Debug, Clone, Default)]
pub struct CommitCoordinator {
    inner: Arc<CommitCoordinatorInner>,
}

#[derive(Debug, Default)]
struct CommitCoordinatorInner {
    state_version: StateVersion,
    tracker: AccountVersionTracker,
    /// Mutex guarding the validate-and-bump critical section. Not held
    /// during tx execution; only during the atomic commit step.
    commit_lock: Mutex<()>,
}

impl CommitCoordinator {
    /// Construct a new coordinator at genesis state (global version 0,
    /// no account versions tracked).
    pub fn new() -> Self {
        Self::default()
    }

    /// Read the current global version without committing.
    ///
    /// Suitable for pinning new workers: a worker calling this followed
    /// by `journal.pin_at(...)` is atomically pinned at some version
    /// that existed at the read moment. Subsequent commits may advance
    /// the version, but that's handled by the retry path.
    pub fn current_version(&self) -> ReadVersion {
        self.inner.state_version.load()
    }

    /// Convenience: create a fresh journal pinned at the current version.
    pub fn new_pinned_journal(&self) -> ScratchJournal {
        let mut journal = ScratchJournal::new();
        journal.pin_at(self.current_version());
        journal
    }

    /// Access the account version tracker for reads during tx execution.
    ///
    /// Workers need this to see per-account versions when resolving
    /// reads from state — the snapshot they observe is "the latest
    /// committed value at or before my pinned version."
    pub fn tracker(&self) -> &AccountVersionTracker {
        &self.inner.tracker
    }

    /// Attempt to commit a worker's journal.
    ///
    /// Holds the commit lock for a short critical section during which:
    /// 1. The journal's read set is validated against current account versions
    /// 2. If valid, the global version is advanced and account versions
    ///    for the journal's write set are bumped to the new version
    ///
    /// Returns `CommitOutcome::Committed` with the new version on success,
    /// or `CommitOutcome::Aborted` with the current version on conflict.
    ///
    /// Panics if called on an unpinned journal — this indicates a
    /// missing `pin_at` call earlier in the worker lifecycle.
    pub fn try_commit(&self, journal: &ScratchJournal) -> CommitOutcome {
        assert!(
            journal.is_pinned(),
            "CommitCoordinator::try_commit called on unpinned journal — \
             the worker must call pin_at() before execution; see TLA+ \
             invariant IdleWorkerHasNoTx"
        );

        let _guard = self.inner.commit_lock.lock();

        // --- Validation: is the read set still consistent with current
        //     account versions under our pinned version? ---
        if !self.inner.tracker.validate(journal.read_set()) {
            return CommitOutcome::Aborted {
                reason: AbortReason::ReadSetInvalidated,
                current_version: self.inner.state_version.load(),
            };
        }

        // --- Commit: advance version + bump write-set accounts ---
        // Unconditional advance is safe because we hold the commit lock
        // (no other worker can be in this critical section).
        let new_version = self.inner.state_version.advance_unconditional();
        self.inner
            .tracker
            .bump_all(journal.write_set().iter().copied(), new_version);

        CommitOutcome::Committed { new_version }
    }

    /// Check whether a read set would still be valid against current
    /// tracker state. Does not take the commit lock — useful for
    /// speculative workers that want to short-circuit before the full
    /// commit attempt.
    ///
    /// Note: a true result here doesn't guarantee the subsequent
    /// `try_commit` will succeed — the validation race is resolved
    /// only by the mutex. But a false result guarantees `try_commit`
    /// would abort, letting callers skip straight to retry.
    pub fn is_read_set_likely_valid(&self, read_set: &ReadSet) -> bool {
        self.inner.tracker.validate(read_set)
    }

    /// Execute a closure under exclusive commit-lock access and commit
    /// the resulting journal unconditionally.
    ///
    /// Maps to the TLA+ `FallbackToSerial` action: when a worker has
    /// exhausted its retry budget, it takes the exclusive path where
    /// no other commit can race. Because we hold the commit lock for
    /// the full duration of `execute`, the journal's reads see
    /// guaranteed-consistent state and its writes are applied
    /// atomically without possibility of abort.
    ///
    /// The closure receives a freshly pinned journal and the pin
    /// version. It is expected to populate the journal's read and
    /// write sets + pending writes.
    ///
    /// # Warning
    ///
    /// Holding the commit lock across the closure blocks every other
    /// commit attempt for the duration. Use only for the genuine
    /// fallback path, not as an optimization.
    pub fn commit_exclusive<F>(&self, execute: F) -> ReadVersion
    where
        F: FnOnce(&mut ScratchJournal, ReadVersion),
    {
        let _guard = self.inner.commit_lock.lock();

        // Pin at current version INSIDE the lock, so no race window
        let pin = self.inner.state_version.load();
        let mut journal = ScratchJournal::new();
        journal.pin_at(pin);

        // Run user code under the lock
        execute(&mut journal, pin);

        // Unconditional commit — no other worker can be committing,
        // so CAS-style conflict is impossible.
        let new_version = self.inner.state_version.advance_unconditional();
        self.inner
            .tracker
            .bump_all(journal.write_set().iter().copied(), new_version);

        new_version
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mvcc::scratch_journal::PendingWrite;
    use crate::types::Address;
    use primitive_types::U256;
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
    fn new_coordinator_at_genesis_version() {
        let coord = CommitCoordinator::new();
        assert_eq!(coord.current_version(), ReadVersion::from_raw(0));
    }

    #[test]
    fn single_empty_journal_commit_succeeds() {
        let coord = CommitCoordinator::new();
        let journal = coord.new_pinned_journal();
        let outcome = coord.try_commit(&journal);
        match outcome {
            CommitOutcome::Committed { new_version } => {
                assert_eq!(new_version, ReadVersion::from_raw(1));
            }
            other => panic!("expected Committed, got {:?}", other),
        }
        assert_eq!(coord.current_version(), ReadVersion::from_raw(1));
    }

    #[test]
    fn commit_bumps_tracker_for_write_set_accounts() {
        let coord = CommitCoordinator::new();
        let mut journal = coord.new_pinned_journal();
        journal.record_write(addr(1), balance_write(100));
        journal.record_write(addr(2), balance_write(200));

        let outcome = coord.try_commit(&journal);
        assert!(matches!(outcome, CommitOutcome::Committed { .. }));

        // Accounts 1 and 2 bumped to v1; account 3 unchanged at v0.
        assert_eq!(coord.tracker().version_of(&addr(1)), ReadVersion::from_raw(1));
        assert_eq!(coord.tracker().version_of(&addr(2)), ReadVersion::from_raw(1));
        assert_eq!(coord.tracker().version_of(&addr(3)), ReadVersion::from_raw(0));
    }

    #[test]
    fn invalidated_read_set_aborts() {
        let coord = CommitCoordinator::new();

        // Worker A: pin at v0, read account 1, plan a write to account 2
        let mut journal_a = coord.new_pinned_journal();
        journal_a.record_read(addr(1));
        journal_a.record_write(addr(2), balance_write(100));

        // Worker B (simulated): commits a write to account 1, bumping
        // its version to v1
        let mut journal_b = coord.new_pinned_journal();
        journal_b.record_write(addr(1), balance_write(50));
        let outcome_b = coord.try_commit(&journal_b);
        assert!(matches!(outcome_b, CommitOutcome::Committed { .. }));

        // Worker A now tries to commit — its read of account 1 is
        // invalidated because account 1 is at v1 and A pinned at v0.
        let outcome_a = coord.try_commit(&journal_a);
        match outcome_a {
            CommitOutcome::Aborted { reason, current_version } => {
                assert_eq!(reason, AbortReason::ReadSetInvalidated);
                assert_eq!(current_version, ReadVersion::from_raw(1));
            }
            other => panic!("expected Aborted(ReadSetInvalidated), got {:?}", other),
        }
    }

    #[test]
    fn disjoint_workers_both_commit() {
        // Two workers pinning at the same version, with completely
        // disjoint read/write sets — both should commit (the second
        // doesn't invalidate the first's reads).
        let coord = CommitCoordinator::new();

        let mut journal_a = coord.new_pinned_journal();
        journal_a.record_read(addr(1));
        journal_a.record_write(addr(2), balance_write(100));

        let mut journal_b = coord.new_pinned_journal();
        journal_b.record_read(addr(3));
        journal_b.record_write(addr(4), balance_write(200));

        assert!(matches!(coord.try_commit(&journal_a), CommitOutcome::Committed { .. }));
        assert!(matches!(coord.try_commit(&journal_b), CommitOutcome::Committed { .. }));
        assert_eq!(coord.current_version(), ReadVersion::from_raw(2));
    }

    #[test]
    fn conflicting_workers_first_wins_second_aborts() {
        // Two workers pin at v0. Both want to write account 1. First
        // commits (account 1 → v1). Second's read of account 1 (if it
        // reads before writing) is invalidated.
        let coord = CommitCoordinator::new();

        let mut journal_a = coord.new_pinned_journal();
        journal_a.record_read(addr(1));
        journal_a.record_write(addr(1), balance_write(100));

        let mut journal_b = coord.new_pinned_journal();
        journal_b.record_read(addr(1));
        journal_b.record_write(addr(1), balance_write(200));

        assert!(matches!(coord.try_commit(&journal_a), CommitOutcome::Committed { .. }));
        let outcome_b = coord.try_commit(&journal_b);
        assert!(matches!(
            outcome_b,
            CommitOutcome::Aborted {
                reason: AbortReason::ReadSetInvalidated,
                ..
            }
        ));
    }

    #[test]
    fn commit_after_abort_retry_succeeds() {
        // Full retry cycle: worker pins, executes, aborts, re-pins,
        // re-executes, commits.
        let coord = CommitCoordinator::new();

        // First attempt: pin at v0, plan to write account 1
        let mut journal = coord.new_pinned_journal();
        journal.record_read(addr(1));
        journal.record_write(addr(1), balance_write(100));

        // Intervening commit by someone else
        let mut intervening = coord.new_pinned_journal();
        intervening.record_write(addr(1), balance_write(50));
        assert!(matches!(coord.try_commit(&intervening), CommitOutcome::Committed { .. }));

        // Our journal aborts
        assert!(matches!(
            coord.try_commit(&journal),
            CommitOutcome::Aborted { .. }
        ));

        // Retry: re-pin at current version, re-record the work, commit
        journal.pin_at(coord.current_version());
        journal.record_read(addr(1));
        journal.record_write(addr(1), balance_write(100));
        assert!(matches!(coord.try_commit(&journal), CommitOutcome::Committed { .. }));
    }

    #[test]
    fn is_read_set_likely_valid_predicts_success() {
        let coord = CommitCoordinator::new();

        let mut journal = coord.new_pinned_journal();
        journal.record_read(addr(1));
        assert!(coord.is_read_set_likely_valid(journal.read_set()));

        // Invalidate
        let mut other = coord.new_pinned_journal();
        other.record_write(addr(1), balance_write(50));
        coord.try_commit(&other);

        // Now our read set is invalid
        assert!(!coord.is_read_set_likely_valid(journal.read_set()));
    }

    #[test]
    #[should_panic(expected = "CommitCoordinator::try_commit called on unpinned journal")]
    fn try_commit_on_unpinned_journal_panics() {
        let coord = CommitCoordinator::new();
        let journal = ScratchJournal::new(); // not pinned
        let _ = coord.try_commit(&journal);
    }

    #[test]
    fn concurrent_disjoint_commits_all_succeed() {
        // 16 workers, each writing to its own distinct account — no
        // conflicts, all should commit, final version = 16.
        let coord = CommitCoordinator::new();
        let coord = Arc::new(coord);

        let handles: Vec<_> = (0..16u8)
            .map(|i| {
                let coord = Arc::clone(&coord);
                thread::spawn(move || {
                    let mut journal = coord.new_pinned_journal();
                    journal.record_write(addr(i), balance_write(i as u64));
                    coord.try_commit(&journal)
                })
            })
            .collect();

        let outcomes: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let committed = outcomes
            .iter()
            .filter(|o| matches!(o, CommitOutcome::Committed { .. }))
            .count();
        assert_eq!(committed, 16);
        assert_eq!(coord.current_version(), ReadVersion::from_raw(16));
    }

    #[test]
    fn concurrent_conflicting_commits_from_same_pin_exactly_one_wins() {
        // 8 workers ALL pinning at the same version via a Barrier, all
        // reading + writing account 1. Exactly one wins the race;
        // the rest abort with ReadSetInvalidated. This is the canonical
        // "racing commits from a common pin" scenario the TLA+ spec
        // models under TryCommit + AbortAndRetry.
        use std::sync::Barrier;

        let coord = Arc::new(CommitCoordinator::new());
        let barrier = Arc::new(Barrier::new(8));

        let handles: Vec<_> = (0..8u8)
            .map(|i| {
                let coord = Arc::clone(&coord);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    // All threads pin at v0 before any commit happens.
                    let mut journal = coord.new_pinned_journal();
                    journal.record_read(addr(1));
                    journal.record_write(addr(1), balance_write(i as u64));
                    // Synchronize so every worker has pinned before any
                    // worker attempts commit.
                    barrier.wait();
                    coord.try_commit(&journal)
                })
            })
            .collect();

        let outcomes: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let committed = outcomes
            .iter()
            .filter(|o| matches!(o, CommitOutcome::Committed { .. }))
            .count();
        let aborted = outcomes
            .iter()
            .filter(|o| matches!(o, CommitOutcome::Aborted { reason: AbortReason::ReadSetInvalidated, .. }))
            .count();

        assert_eq!(committed, 1, "exactly one worker from a common pin commits");
        assert_eq!(aborted, 7, "the seven losers all abort with ReadSetInvalidated");
        assert_eq!(coord.current_version(), ReadVersion::from_raw(1));
    }

    #[test]
    fn concurrent_conflicting_commits_without_barrier_make_progress() {
        // Unsynchronized variant: 8 workers all writing account 1 but
        // pinning at whenever they wake up. At least one commits; the
        // rest either commit (if they pinned after a winner) or abort
        // (if they raced a winner). No panic, no deadlock, total
        // version == total commits.
        let coord = Arc::new(CommitCoordinator::new());

        let handles: Vec<_> = (0..8u8)
            .map(|i| {
                let coord = Arc::clone(&coord);
                thread::spawn(move || {
                    let mut journal = coord.new_pinned_journal();
                    journal.record_read(addr(1));
                    journal.record_write(addr(1), balance_write(i as u64));
                    coord.try_commit(&journal)
                })
            })
            .collect();

        let outcomes: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let committed = outcomes
            .iter()
            .filter(|o| matches!(o, CommitOutcome::Committed { .. }))
            .count();

        // At least one commits; invariant: version count matches commit count.
        assert!(committed >= 1, "at least one must commit");
        assert_eq!(
            coord.current_version(),
            ReadVersion::from_raw(committed as u64),
            "GlobalVersionTracksCommits: version should equal commit count"
        );
    }
}
