//! Read set — the accounts a worker observed during tx execution.
//!
//! Corresponds to the TLA+ variable `workerReadSet[w]`. Used at commit time
//! to determine whether any observation was invalidated by intervening
//! commits.

use crate::mvcc::version::ReadVersion;
use crate::types::Address;
use std::collections::HashSet;

/// The set of accounts read by a worker during tx execution.
///
/// Populated incrementally as the EVM reads state. At commit time, the
/// accompanying [`ReadVersion`] and per-account version vector are used
/// to check validity — see [`ReadSet::is_valid_at`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReadSet {
    accounts: HashSet<Address>,
    pinned_version: Option<ReadVersion>,
}

impl ReadSet {
    /// Construct an empty read set not yet pinned. A worker calls
    /// [`Self::pin_at`] when it acquires a tx.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin this read set to a specific version. Clears any prior accounts —
    /// a fresh pin means a fresh observation window.
    ///
    /// Maps to the "reset" step inside `PickUpTx` in the TLA+ spec.
    pub fn pin_at(&mut self, version: ReadVersion) {
        self.accounts.clear();
        self.pinned_version = Some(version);
    }

    /// Record that the worker read the given account.
    ///
    /// Called by the EVM storage bridge whenever a SLOAD or BALANCE-class
    /// op touches an account. Idempotent.
    pub fn record_read(&mut self, address: Address) {
        self.accounts.insert(address);
    }

    /// Has this set been pinned?
    pub fn is_pinned(&self) -> bool {
        self.pinned_version.is_some()
    }

    /// The pinned version, if any.
    pub fn pinned_version(&self) -> Option<ReadVersion> {
        self.pinned_version
    }

    /// Number of accounts in the set.
    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    /// Iterate over the accounts in arbitrary order.
    pub fn iter(&self) -> impl Iterator<Item = &Address> {
        self.accounts.iter()
    }

    /// Whether the read set is still valid against a function producing
    /// per-account versions.
    ///
    /// Maps to the TLA+ predicate
    /// `ReadSetValid(w) == \A a \in workerReadSet[w] : accountVersion[a] <= workerReadVersion[w]`.
    ///
    /// The `account_version` closure produces the current per-account
    /// version for any given address. The read set is valid iff every
    /// account in the set has an account-version not exceeding the pinned
    /// version.
    ///
    /// Panics if the set was never pinned — callers must always pin before
    /// validating (see the `PickUpTx` → `LocalExecute` → `TryCommit` flow).
    pub fn is_valid_at<F>(&self, mut account_version: F) -> bool
    where
        F: FnMut(&Address) -> ReadVersion,
    {
        let pinned = self.pinned_version.expect(
            "ReadSet::is_valid_at called on unpinned set — this indicates a \
             missing pin_at() call in the worker lifecycle; see TLA+ invariant \
             IdleWorkerHasNoTx",
        );
        self.accounts.iter().all(|a| account_version(a) <= pinned)
    }

    /// Reset the set to empty and unpinned. Called on commit or abort.
    pub fn clear(&mut self) {
        self.accounts.clear();
        self.pinned_version = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> Address {
        let mut a = [0u8; 20];
        a[0] = n;
        Address(a)
    }

    #[test]
    fn new_read_set_is_empty_and_unpinned() {
        let rs = ReadSet::new();
        assert!(rs.is_empty());
        assert!(!rs.is_pinned());
        assert_eq!(rs.pinned_version(), None);
    }

    #[test]
    fn pin_at_sets_version_and_clears_accounts() {
        let mut rs = ReadSet::new();
        rs.record_read(addr(1));
        rs.record_read(addr(2));
        assert_eq!(rs.len(), 2);

        rs.pin_at(ReadVersion::from_raw(5));
        assert!(rs.is_empty());
        assert_eq!(rs.pinned_version(), Some(ReadVersion::from_raw(5)));
    }

    #[test]
    fn record_read_is_idempotent() {
        let mut rs = ReadSet::new();
        rs.pin_at(ReadVersion::from_raw(0));
        rs.record_read(addr(1));
        rs.record_read(addr(1));
        rs.record_read(addr(1));
        assert_eq!(rs.len(), 1);
    }

    #[test]
    fn is_valid_at_empty_set_always_valid() {
        let mut rs = ReadSet::new();
        rs.pin_at(ReadVersion::from_raw(3));
        assert!(rs.is_valid_at(|_| ReadVersion::from_raw(100)));
    }

    #[test]
    fn is_valid_at_unchanged_accounts_valid() {
        let mut rs = ReadSet::new();
        rs.pin_at(ReadVersion::from_raw(5));
        rs.record_read(addr(1));
        rs.record_read(addr(2));

        // Both accounts still at version ≤ 5
        assert!(rs.is_valid_at(|a| {
            if *a == addr(1) {
                ReadVersion::from_raw(3)
            } else {
                ReadVersion::from_raw(5)
            }
        }));
    }

    #[test]
    fn is_valid_at_invalidated_account_invalid() {
        let mut rs = ReadSet::new();
        rs.pin_at(ReadVersion::from_raw(5));
        rs.record_read(addr(1));
        rs.record_read(addr(2));

        // addr(1) has been bumped past the pin
        assert!(!rs.is_valid_at(|a| {
            if *a == addr(1) {
                ReadVersion::from_raw(7)
            } else {
                ReadVersion::from_raw(5)
            }
        }));
    }

    #[test]
    #[should_panic(expected = "ReadSet::is_valid_at called on unpinned set")]
    fn is_valid_at_unpinned_panics() {
        let rs = ReadSet::new();
        let _ = rs.is_valid_at(|_| ReadVersion::from_raw(0));
    }

    #[test]
    fn clear_resets_state() {
        let mut rs = ReadSet::new();
        rs.pin_at(ReadVersion::from_raw(5));
        rs.record_read(addr(1));
        rs.clear();
        assert!(rs.is_empty());
        assert!(!rs.is_pinned());
    }

    #[test]
    fn iter_yields_all_accounts() {
        let mut rs = ReadSet::new();
        rs.pin_at(ReadVersion::from_raw(0));
        rs.record_read(addr(1));
        rs.record_read(addr(2));
        rs.record_read(addr(3));

        let collected: HashSet<Address> = rs.iter().copied().collect();
        assert_eq!(collected.len(), 3);
        assert!(collected.contains(&addr(1)));
        assert!(collected.contains(&addr(2)));
        assert!(collected.contains(&addr(3)));
    }
}
