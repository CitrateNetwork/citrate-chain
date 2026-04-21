//! Write set — the accounts a worker intends to write.
//!
//! Corresponds to the TLA+ variable `workerWriteSet[w]` in its
//! accounts-only form. For the full account → value mapping of pending
//! writes, see [`ScratchJournal`](super::scratch_journal).

use crate::types::Address;
use std::collections::HashSet;

/// The set of accounts a worker has modified during tx execution.
///
/// Populated as the EVM mutates state; at commit time, these accounts
/// have their per-account versions bumped to the new global version.
///
/// Intentionally separate from the scratch journal so queries about
/// "which accounts will be written" don't require dragging around the
/// values. This mirrors the TLA+ model, which tracks write *sets* and
/// write *values* orthogonally.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WriteSet {
    accounts: HashSet<Address>,
}

impl WriteSet {
    /// An empty write set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that the worker will write the given account.
    ///
    /// Called by the EVM storage bridge whenever a SSTORE or BALANCE-
    /// update op targets an account. Idempotent.
    pub fn record_write(&mut self, address: Address) {
        self.accounts.insert(address);
    }

    /// Whether this account is in the write set.
    pub fn contains(&self, address: &Address) -> bool {
        self.accounts.contains(address)
    }

    /// Number of accounts to be written.
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

    /// Whether this write set and another are disjoint.
    ///
    /// Two workers whose write sets are disjoint cannot invalidate each
    /// other at commit time — the `NonInterferenceForIndependent`
    /// property in `ExecutorMVCC.tla` is a direct consequence of this
    /// observation combined with the CAS correctness of `TryCommit`.
    pub fn is_disjoint_from(&self, other: &WriteSet) -> bool {
        self.accounts.is_disjoint(&other.accounts)
    }

    /// Whether this write set intersects a read set (given as an
    /// iterator). Used when checking whether committing this worker
    /// would invalidate another worker's snapshot.
    pub fn intersects<'a, I>(&self, read_set_accounts: I) -> bool
    where
        I: IntoIterator<Item = &'a Address>,
    {
        read_set_accounts.into_iter().any(|a| self.accounts.contains(a))
    }

    /// Reset the set to empty. Called on commit or abort.
    pub fn clear(&mut self) {
        self.accounts.clear();
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
    fn new_write_set_is_empty() {
        let ws = WriteSet::new();
        assert!(ws.is_empty());
        assert_eq!(ws.len(), 0);
    }

    #[test]
    fn record_write_is_idempotent() {
        let mut ws = WriteSet::new();
        ws.record_write(addr(1));
        ws.record_write(addr(1));
        ws.record_write(addr(1));
        assert_eq!(ws.len(), 1);
        assert!(ws.contains(&addr(1)));
    }

    #[test]
    fn disjoint_sets_are_disjoint() {
        let mut a = WriteSet::new();
        a.record_write(addr(1));
        a.record_write(addr(2));

        let mut b = WriteSet::new();
        b.record_write(addr(3));
        b.record_write(addr(4));

        assert!(a.is_disjoint_from(&b));
        assert!(b.is_disjoint_from(&a));
    }

    #[test]
    fn overlapping_sets_are_not_disjoint() {
        let mut a = WriteSet::new();
        a.record_write(addr(1));
        a.record_write(addr(2));

        let mut b = WriteSet::new();
        b.record_write(addr(2));
        b.record_write(addr(3));

        assert!(!a.is_disjoint_from(&b));
    }

    #[test]
    fn intersects_detects_overlap() {
        let mut ws = WriteSet::new();
        ws.record_write(addr(1));
        ws.record_write(addr(2));

        let reads = [addr(2), addr(3)];
        assert!(ws.intersects(reads.iter()));

        let disjoint_reads = [addr(4), addr(5)];
        assert!(!ws.intersects(disjoint_reads.iter()));
    }

    #[test]
    fn clear_resets() {
        let mut ws = WriteSet::new();
        ws.record_write(addr(1));
        ws.record_write(addr(2));
        ws.clear();
        assert!(ws.is_empty());
    }

    #[test]
    fn iter_yields_all_accounts() {
        let mut ws = WriteSet::new();
        ws.record_write(addr(1));
        ws.record_write(addr(2));
        ws.record_write(addr(3));
        let collected: HashSet<Address> = ws.iter().copied().collect();
        assert_eq!(collected.len(), 3);
    }
}
