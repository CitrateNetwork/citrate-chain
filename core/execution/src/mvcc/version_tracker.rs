//! Per-account version tracking.
//!
//! For every account touched by a committed transaction, the executor
//! records the [`ReadVersion`] at which that account was last written.
//! At commit time, a worker's [`ReadSet`](super::read_set::ReadSet) is
//! valid iff every account in it has a recorded version not exceeding
//! the worker's pinned read version.
//!
//! # Spec mapping
//!
//! Corresponds to the TLA+ variable `accountVersion` in
//! `specs/tla/consensus/ExecutorMVCC.tla`:
//!
//! ```tla
//! VARIABLES
//!     accountVersion,     \* [Accounts -> 0..MaxVersion]
//!     ...
//! ```
//!
//! The TLA+ invariants proved over this variable are preserved here
//! operationally:
//!
//! - `AccountVersionBound` — every tracked version is bounded by
//!   the global commit version; enforced because we only bump via
//!   [`AccountVersionTracker::bump`] on successful commit, and the
//!   commit path increments the global version first.
//! - `AccountVersionBoundedByCommits` — every tracked version is
//!   bounded by the total commit count; same mechanism.
//!
//! # Concurrency
//!
//! Backed by [`DashMap`], so reads and writes scale across workers
//! without a global mutex. Unseen accounts read as `ReadVersion(0)`
//! — the "genesis version" — meaning a worker pinning at or above 0
//! (which is always true) cannot have its read set invalidated by a
//! never-written account.
//!
//! # Persistence
//!
//! **This sprint (P950-A-2 WP-A.2.2) keeps versions in memory only.**
//! On restart, version history is lost — which means all prior reads
//! are conservatively considered invalidated (safe but pessimistic).
//! A follow-up WP persists versions alongside the state trie column
//! family in RocksDB for full durability.

use crate::mvcc::version::ReadVersion;
use crate::types::Address;
use dashmap::DashMap;
use std::sync::Arc;

/// Per-account version tracker, backed by a concurrent map.
///
/// Designed to be shared across worker threads via [`Arc`]. All methods
/// are lockless in the common case (no account contention) and use
/// DashMap's sharded locking under contention.
#[derive(Debug, Clone, Default)]
pub struct AccountVersionTracker {
    versions: Arc<DashMap<Address, ReadVersion>>,
}

impl AccountVersionTracker {
    /// Construct an empty tracker. Every account reads as
    /// [`ReadVersion(0)`](ReadVersion::from_raw) until first bump.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read the version for an account.
    ///
    /// Returns `ReadVersion(0)` for accounts never seen — this is the
    /// "genesis version" semantic: the account has never been written,
    /// so any read sees its initial state.
    pub fn version_of(&self, addr: &Address) -> ReadVersion {
        self.versions
            .get(addr)
            .map(|v| *v)
            .unwrap_or(ReadVersion::from_raw(0))
    }

    /// Bump the version for an account to the given value.
    ///
    /// Monotonicity is *not* enforced in the tracker — callers are
    /// responsible for feeding monotonically-increasing versions
    /// (typically from [`StateVersion::try_advance`](super::version::StateVersion::try_advance)).
    /// Bumping with a smaller value silently overwrites, which is
    /// acceptable given the spec-level `AccountVersionBoundedByCommits`
    /// invariant is enforced by the commit path, not by this helper.
    pub fn bump(&self, addr: Address, new_version: ReadVersion) {
        self.versions.insert(addr, new_version);
    }

    /// Bump every account in an iterator to the given version.
    ///
    /// Maps to the TLA+ `TryCommit` action's effect on `accountVersion`:
    /// every account in the committing worker's `WriteSet` has its
    /// version set to the new global version.
    pub fn bump_all<I>(&self, addrs: I, new_version: ReadVersion)
    where
        I: IntoIterator<Item = Address>,
    {
        for addr in addrs {
            self.bump(addr, new_version);
        }
    }

    /// Check whether a read set is valid against the current tracker
    /// state.
    ///
    /// Convenience wrapper over
    /// [`ReadSet::is_valid_at`](super::read_set::ReadSet::is_valid_at)
    /// that captures the tracker as the version oracle. Equivalent to
    /// `read_set.is_valid_at(|a| tracker.version_of(a))`.
    pub fn validate(&self, read_set: &super::read_set::ReadSet) -> bool {
        read_set.is_valid_at(|a| self.version_of(a))
    }

    /// Number of tracked accounts. Useful for metrics and tests.
    pub fn len(&self) -> usize {
        self.versions.len()
    }

    /// Whether no account has been bumped yet.
    pub fn is_empty(&self) -> bool {
        self.versions.is_empty()
    }

    /// Clear all tracked versions. Intended for test harnesses and
    /// for chain reorg paths that need to reset state. Not part of
    /// the happy-path commit flow.
    pub fn clear(&self) {
        self.versions.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mvcc::read_set::ReadSet;
    use std::sync::Arc;
    use std::thread;

    fn addr(n: u8) -> Address {
        let mut a = [0u8; 20];
        a[0] = n;
        Address(a)
    }

    #[test]
    fn new_tracker_is_empty() {
        let t = AccountVersionTracker::new();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn unseen_account_reads_as_version_zero() {
        // The genesis-version semantic: never-written accounts are at 0.
        // This means any worker pinning at version >= 0 can include them
        // in its read set without fear of invalidation.
        let t = AccountVersionTracker::new();
        assert_eq!(t.version_of(&addr(1)), ReadVersion::from_raw(0));
    }

    #[test]
    fn bump_sets_version() {
        let t = AccountVersionTracker::new();
        t.bump(addr(1), ReadVersion::from_raw(5));
        assert_eq!(t.version_of(&addr(1)), ReadVersion::from_raw(5));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn bump_all_sets_many() {
        let t = AccountVersionTracker::new();
        t.bump_all([addr(1), addr(2), addr(3)], ReadVersion::from_raw(7));
        assert_eq!(t.version_of(&addr(1)), ReadVersion::from_raw(7));
        assert_eq!(t.version_of(&addr(2)), ReadVersion::from_raw(7));
        assert_eq!(t.version_of(&addr(3)), ReadVersion::from_raw(7));
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn validate_against_empty_readset_always_valid() {
        let t = AccountVersionTracker::new();
        t.bump(addr(1), ReadVersion::from_raw(100));
        let mut rs = ReadSet::new();
        rs.pin_at(ReadVersion::from_raw(0));
        assert!(t.validate(&rs));
    }

    #[test]
    fn validate_unchanged_readset_is_valid() {
        let t = AccountVersionTracker::new();
        // Account 1 was bumped to version 3
        t.bump(addr(1), ReadVersion::from_raw(3));
        // Worker pins at version 5 — well after the bump
        let mut rs = ReadSet::new();
        rs.pin_at(ReadVersion::from_raw(5));
        rs.record_read(addr(1));
        // Account version (3) ≤ pinned (5), so valid
        assert!(t.validate(&rs));
    }

    #[test]
    fn validate_intervening_bump_invalidates() {
        let t = AccountVersionTracker::new();
        // Worker pinned at version 3, records read of account 1
        let mut rs = ReadSet::new();
        rs.pin_at(ReadVersion::from_raw(3));
        rs.record_read(addr(1));
        // Before commit: valid (no bumps yet, account at version 0)
        assert!(t.validate(&rs));
        // An intervening commit bumps account 1 to version 5
        t.bump(addr(1), ReadVersion::from_raw(5));
        // Now worker's read set is invalid: account 1 at v5 > pin v3
        assert!(!t.validate(&rs));
    }

    #[test]
    fn validate_bump_on_disjoint_account_is_irrelevant() {
        // Non-interference check: bumping account 2 does not invalidate
        // a read set containing only account 1.
        let t = AccountVersionTracker::new();
        let mut rs = ReadSet::new();
        rs.pin_at(ReadVersion::from_raw(3));
        rs.record_read(addr(1));
        t.bump(addr(2), ReadVersion::from_raw(99));
        assert!(t.validate(&rs), "bumping disjoint account 2 must not invalidate read of account 1");
    }

    #[test]
    fn clear_resets_tracker() {
        let t = AccountVersionTracker::new();
        t.bump(addr(1), ReadVersion::from_raw(5));
        t.bump(addr(2), ReadVersion::from_raw(7));
        t.clear();
        assert!(t.is_empty());
        assert_eq!(t.version_of(&addr(1)), ReadVersion::from_raw(0));
    }

    #[test]
    fn concurrent_bumps_different_accounts_race_safely() {
        // Spawn threads that each bump different accounts; all bumps
        // must be visible at the end. Validates lockless-read + sharded-
        // write path under moderate contention.
        let t = Arc::new(AccountVersionTracker::new());
        let handles: Vec<_> = (0..32u8)
            .map(|i| {
                let t = Arc::clone(&t);
                thread::spawn(move || {
                    t.bump(addr(i), ReadVersion::from_raw(i as u64 + 1));
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        for i in 0..32u8 {
            assert_eq!(
                t.version_of(&addr(i)),
                ReadVersion::from_raw(i as u64 + 1),
                "account {} lost its bump",
                i
            );
        }
    }

    #[test]
    fn concurrent_bumps_same_account_last_writer_wins() {
        // Not a correctness property of the spec (we expect callers to
        // feed monotonically-increasing versions), but a robustness
        // property: concurrent bumps on the same key don't panic and
        // leave a consistent final value.
        let t = Arc::new(AccountVersionTracker::new());
        let handles: Vec<_> = (1..=16u64)
            .map(|v| {
                let t = Arc::clone(&t);
                thread::spawn(move || {
                    t.bump(addr(1), ReadVersion::from_raw(v));
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // Final version is some value in 1..=16 — not guaranteed which.
        let final_v = t.version_of(&addr(1)).as_u64();
        assert!(
            (1..=16).contains(&final_v),
            "final version {} out of range 1..=16",
            final_v
        );
    }

    #[test]
    fn validate_mimics_readset_closure_semantics() {
        // The `validate` method should be equivalent to calling
        // `read_set.is_valid_at` directly with a tracker-backed closure.
        let t = AccountVersionTracker::new();
        t.bump(addr(1), ReadVersion::from_raw(2));
        t.bump(addr(2), ReadVersion::from_raw(5));

        let mut rs = ReadSet::new();
        rs.pin_at(ReadVersion::from_raw(4));
        rs.record_read(addr(1)); // v2 ≤ 4 ✓
        rs.record_read(addr(2)); // v5 > 4 ✗

        let via_method = t.validate(&rs);
        let via_closure = rs.is_valid_at(|a| t.version_of(a));
        assert_eq!(via_method, via_closure);
        assert!(!via_method, "account 2 at v5 should invalidate pin v4");
    }
}
