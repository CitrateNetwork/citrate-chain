//! Scratch journal — per-worker pending writes prior to commit.
//!
//! Combines the [`ReadSet`](super::read_set::ReadSet) (for validity checks)
//! with a pending-writes map (for replay on commit). At commit time, if
//! `ReadSet::is_valid_at` returns true and the CAS on `StateVersion`
//! succeeds, the journal is drained into the real state DB.
//!
//! Corresponds to a worker's full transactional context in the TLA+ spec:
//! `(workerReadVersion, workerReadSet, workerWriteSet)` bundled together
//! with the tx being processed.

use crate::mvcc::read_set::ReadSet;
use crate::mvcc::version::ReadVersion;
use crate::mvcc::write_set::WriteSet;
use crate::types::Address;
use primitive_types::U256;
use std::collections::HashMap;

/// One entry in the journal: the pending post-state for a single account.
///
/// Kept deliberately minimal (balance + nonce + code presence) — storage
/// slot writes are handled by the EVM's own cache and flushed through the
/// journal on commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingWrite {
    pub new_balance: Option<U256>,
    pub new_nonce: Option<u64>,
    pub new_code: Option<Vec<u8>>,
}

impl PendingWrite {
    pub fn new() -> Self {
        Self {
            new_balance: None,
            new_nonce: None,
            new_code: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.new_balance.is_none() && self.new_nonce.is_none() && self.new_code.is_none()
    }
}

impl Default for PendingWrite {
    fn default() -> Self {
        Self::new()
    }
}

/// A worker's full scratch state during tx execution.
///
/// Holds:
/// - the pinned [`ReadVersion`]
/// - the [`ReadSet`] (accounts observed, for validity check)
/// - the [`WriteSet`] (accounts to be written, for version bumps on commit)
/// - pending per-account mutations (balance/nonce/code) for commit drain
/// - pending per-slot storage mutations (Sprint P950-A-5 WP-A.5.1) for
///   commit drain. These are the EVM `SSTORE` writes that REVM would
///   otherwise apply eagerly to state; journal-mediation keeps concurrent
///   workers isolated from each other's pending storage updates.
///
/// On successful `TryCommit`, the journal is drained: for every account
/// in the [`WriteSet`], the pending write is applied to the state DB and
/// the account's per-account version is bumped to the new global version.
/// Storage slots in `pending_storage` are flushed to `state_db.set_storage`
/// at the same point. The [`ReadSet`] is *not* drained — its role ends at
/// the CAS check.
#[derive(Debug, Clone, Default)]
pub struct ScratchJournal {
    read_set: ReadSet,
    write_set: WriteSet,
    pending: HashMap<Address, PendingWrite>,
    /// (address, slot-key-bytes) → slot-value-bytes, for EVM storage writes
    /// buffered during REVM execution. Sprint P950-A-5 WP-A.5.1.
    pending_storage: HashMap<(Address, Vec<u8>), Vec<u8>>,
}

impl ScratchJournal {
    /// Create a fresh, unpinned scratch journal.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin this journal to a specific state version. Clears all prior
    /// pending writes — a fresh pin means a fresh attempt.
    ///
    /// Maps to the reset step inside `PickUpTx` in the TLA+ spec.
    pub fn pin_at(&mut self, version: ReadVersion) {
        self.read_set.pin_at(version);
        self.write_set.clear();
        self.pending.clear();
        self.pending_storage.clear();
    }

    /// Whether the journal has been pinned.
    pub fn is_pinned(&self) -> bool {
        self.read_set.is_pinned()
    }

    /// The pinned version, if any.
    pub fn pinned_version(&self) -> Option<ReadVersion> {
        self.read_set.pinned_version()
    }

    /// Record that the worker read an account. Updates the read set.
    pub fn record_read(&mut self, address: Address) {
        self.read_set.record_read(address);
    }

    /// Record a pending write to an account. Updates the write set and
    /// stores the new post-state.
    ///
    /// Repeated writes to the same account overwrite earlier pending
    /// values within the same journal — in the real EVM, this is what
    /// happens when a tx touches an account multiple times.
    pub fn record_write(&mut self, address: Address, write: PendingWrite) {
        self.write_set.record_write(address);
        self.pending.insert(address, write);
    }

    /// Get the pending write for an account, if any.
    ///
    /// Used by the EVM cache to serve reads-after-writes-by-this-tx
    /// from the journal rather than from the pinned snapshot.
    pub fn pending_write(&self, address: &Address) -> Option<&PendingWrite> {
        self.pending.get(address)
    }

    /// Access the read set (for validity checks at CAS time).
    pub fn read_set(&self) -> &ReadSet {
        &self.read_set
    }

    /// Access the write set (for version bumping at commit time).
    pub fn write_set(&self) -> &WriteSet {
        &self.write_set
    }

    /// Iterate over all pending writes in arbitrary order.
    ///
    /// Used at commit time to drain the journal into the real state DB.
    pub fn iter_writes(&self) -> impl Iterator<Item = (&Address, &PendingWrite)> {
        self.pending.iter()
    }

    /// Number of pending writes.
    pub fn write_count(&self) -> usize {
        self.pending.len()
    }

    // ------------------------------------------------------------------------
    // Pending storage slots — Sprint P950-A-5 WP-A.5.1
    // ------------------------------------------------------------------------

    /// Record a pending EVM storage-slot write.
    ///
    /// Called by `StateDBAdapter::DatabaseCommit::commit` when REVM flushes
    /// its internal cache. Keys/values are raw bytes per EVM convention
    /// (typically 32-byte big-endian).
    ///
    /// Repeated writes to the same (addr, key) overwrite in-place — REVM
    /// squashes intermediate values internally, so this code path sees
    /// only the final post-tx value per slot, but we handle repeats
    /// defensively.
    ///
    /// Also records the address in the WriteSet so MVCC version bumps
    /// include accounts that only changed via storage (not balance/nonce).
    pub fn record_storage_write(&mut self, address: Address, key: Vec<u8>, value: Vec<u8>) {
        self.write_set.record_write(address);
        self.pending_storage.insert((address, key), value);
    }

    /// Look up a pending storage-slot write made earlier in this same tx.
    ///
    /// Enables read-your-writes semantics within a single tx: if the tx
    /// `SSTORE`d slot X then `SLOAD`s slot X, the load sees the pending
    /// value from this journal — not the stale value in state_db.
    pub fn pending_storage(&self, address: &Address, key: &[u8]) -> Option<&[u8]> {
        self.pending_storage
            .get(&(*address, key.to_vec()))
            .map(|v| v.as_slice())
    }

    /// Iterate over all pending storage writes in arbitrary order.
    ///
    /// Used at commit time to drain slot updates into the real state DB.
    pub fn iter_storage_writes(&self) -> impl Iterator<Item = (&(Address, Vec<u8>), &Vec<u8>)> {
        self.pending_storage.iter()
    }

    /// Number of pending storage-slot writes.
    pub fn storage_write_count(&self) -> usize {
        self.pending_storage.len()
    }

    /// Clear the journal entirely. Called on commit (after drain) or on
    /// abort (journal is thrown away).
    pub fn clear(&mut self) {
        self.read_set.clear();
        self.write_set.clear();
        self.pending.clear();
        self.pending_storage.clear();
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

    fn balance_write(bal: u64) -> PendingWrite {
        PendingWrite {
            new_balance: Some(U256::from(bal)),
            new_nonce: None,
            new_code: None,
        }
    }

    #[test]
    fn new_journal_is_unpinned_and_empty() {
        let j = ScratchJournal::new();
        assert!(!j.is_pinned());
        assert_eq!(j.pinned_version(), None);
        assert_eq!(j.write_count(), 0);
    }

    #[test]
    fn pin_at_initializes_read_set_and_clears_writes() {
        let mut j = ScratchJournal::new();
        j.pin_at(ReadVersion::from_raw(0));
        j.record_write(addr(1), balance_write(100));
        assert_eq!(j.write_count(), 1);

        // Re-pin: fresh attempt, everything cleared.
        j.pin_at(ReadVersion::from_raw(5));
        assert_eq!(j.pinned_version(), Some(ReadVersion::from_raw(5)));
        assert_eq!(j.write_count(), 0);
    }

    #[test]
    fn record_write_populates_write_set_and_pending() {
        let mut j = ScratchJournal::new();
        j.pin_at(ReadVersion::from_raw(0));
        j.record_write(addr(1), balance_write(100));
        j.record_write(addr(2), balance_write(200));

        assert_eq!(j.write_count(), 2);
        assert!(j.write_set().contains(&addr(1)));
        assert!(j.write_set().contains(&addr(2)));
        assert_eq!(
            j.pending_write(&addr(1)).unwrap().new_balance,
            Some(U256::from(100))
        );
    }

    #[test]
    fn repeated_write_overwrites_pending_value() {
        let mut j = ScratchJournal::new();
        j.pin_at(ReadVersion::from_raw(0));
        j.record_write(addr(1), balance_write(100));
        j.record_write(addr(1), balance_write(200));
        // Still only one entry in the write set; pending has latest value.
        assert_eq!(j.write_count(), 1);
        assert_eq!(
            j.pending_write(&addr(1)).unwrap().new_balance,
            Some(U256::from(200))
        );
    }

    #[test]
    fn record_read_updates_read_set_not_write_set() {
        let mut j = ScratchJournal::new();
        j.pin_at(ReadVersion::from_raw(0));
        j.record_read(addr(1));
        assert!(!j.write_set().contains(&addr(1)));
        assert_eq!(j.read_set().len(), 1);
    }

    #[test]
    fn iter_writes_yields_all_pending() {
        let mut j = ScratchJournal::new();
        j.pin_at(ReadVersion::from_raw(0));
        j.record_write(addr(1), balance_write(100));
        j.record_write(addr(2), balance_write(200));
        j.record_write(addr(3), balance_write(300));

        let collected: HashMap<Address, u64> = j
            .iter_writes()
            .map(|(a, w)| (*a, w.new_balance.unwrap().as_u64()))
            .collect();

        assert_eq!(collected.len(), 3);
        assert_eq!(collected[&addr(1)], 100);
        assert_eq!(collected[&addr(2)], 200);
        assert_eq!(collected[&addr(3)], 300);
    }

    #[test]
    fn clear_resets_everything() {
        let mut j = ScratchJournal::new();
        j.pin_at(ReadVersion::from_raw(5));
        j.record_read(addr(1));
        j.record_write(addr(2), balance_write(100));

        j.clear();
        assert!(!j.is_pinned());
        assert_eq!(j.write_count(), 0);
        assert!(j.read_set().is_empty());
        assert!(j.write_set().is_empty());
    }

    #[test]
    fn pending_write_is_empty_when_no_fields_set() {
        let pw = PendingWrite::new();
        assert!(pw.is_empty());
    }

    #[test]
    fn pending_write_not_empty_when_balance_set() {
        let pw = balance_write(100);
        assert!(!pw.is_empty());
    }
}
