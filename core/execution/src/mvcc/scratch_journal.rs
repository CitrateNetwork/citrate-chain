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
    /// RM-B1 / WP-B5.4 (audit H-03): set when the executing tx
    /// invokes `code_by_hash` (e.g., REVM EXTCODESIZE / EXTCODECOPY
    /// against a contract whose code might be replaced by a
    /// concurrent SELFDESTRUCT+CREATE2 commit). The MVCC commit
    /// coordinator inspects this and falls back to serial commit
    /// rather than risk a stale-code read.
    requires_serial_commit: bool,
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
        // H-03: fresh attempt resets the serial-commit flag.
        self.requires_serial_commit = false;
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

    /// RM-B1 / WP-B5.4 (audit H-03): mark this tx as requiring
    /// serial commit because it invoked `code_by_hash`. Without
    /// this defense, a concurrent SELFDESTRUCT+CREATE2 in another
    /// tx could replace the code under us and our commit would
    /// land with stale-code-derived state.
    pub fn mark_requires_serial_commit(&mut self) {
        self.requires_serial_commit = true;
    }

    /// Whether this journal has been marked as requiring serial
    /// commit (set by `mark_requires_serial_commit`).
    pub fn requires_serial_commit(&self) -> bool {
        self.requires_serial_commit
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

    // ------------------------------------------------------------------------
    // Balance / nonce journaling (Sprint P950-A-5 WP-A.5.2)
    // ------------------------------------------------------------------------
    //
    // The executor currently writes gas deductions, nonce increments, and
    // gas refunds directly to `state_db.accounts`. For concurrent
    // execution, those writes must route through the journal so that
    // concurrent workers don't see each other's pending accounting.
    //
    // These methods provide the journal side of the route. The executor
    // wiring lands in a subsequent commit (the full WP-A.5.2 integration);
    // for now these are primitives + read-your-writes that the adapter
    // can already use.

    /// Record a pending balance write for an account. Overwrites any
    /// prior pending balance for the same address — the executor's
    /// idempotency guarantees keep this safe (check_nonce, set_balance,
    /// increment_nonce each happen at most once per tx).
    pub fn record_balance(&mut self, address: Address, new_balance: U256) {
        self.write_set.record_write(address);
        let entry = self.pending.entry(address).or_default();
        entry.new_balance = Some(new_balance);
    }

    /// Record a pending nonce write for an account.
    pub fn record_nonce(&mut self, address: Address, new_nonce: u64) {
        self.write_set.record_write(address);
        let entry = self.pending.entry(address).or_default();
        entry.new_nonce = Some(new_nonce);
    }

    /// Record a pending code write for an account (contract deployment).
    pub fn record_code(&mut self, address: Address, code: Vec<u8>) {
        self.write_set.record_write(address);
        let entry = self.pending.entry(address).or_default();
        entry.new_code = Some(code);
    }

    /// Look up a pending balance write for read-your-writes within a tx.
    /// Returns `None` if no pending balance write for this address —
    /// caller falls through to `state_db`.
    pub fn pending_balance(&self, address: &Address) -> Option<U256> {
        self.pending.get(address).and_then(|pw| pw.new_balance)
    }

    /// Look up a pending nonce write for read-your-writes within a tx.
    pub fn pending_nonce(&self, address: &Address) -> Option<u64> {
        self.pending.get(address).and_then(|pw| pw.new_nonce)
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

    /// Discard pending writes only — clear `pending` (balance/nonce/code)
    /// and `pending_storage`, but preserve the `read_set`, `write_set`,
    /// and the pinned version.
    ///
    /// Used on the tx failure path: the tx's state mutations must be
    /// rolled back, but we still need to record gas-burn + nonce-increment
    /// before draining, and we want the read/write-set tracking to persist
    /// so MVCC version bumps remain conservative (any account REVM touched
    /// during the failed attempt still gets its version bumped, preventing
    /// stale reads by concurrent workers).
    pub fn discard_writes(&mut self) {
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

    // ------------------------------------------------------------------------
    // Sprint P950-A-5 WP-A.5.1 + WP-A.5.2 tests: storage + balance + nonce
    // journaling with read-your-writes.
    // ------------------------------------------------------------------------

    #[test]
    fn record_storage_write_populates_pending_and_write_set() {
        let mut j = ScratchJournal::new();
        j.pin_at(ReadVersion::from_raw(0));

        let key = vec![0u8; 32];
        let value = vec![42u8; 32];
        j.record_storage_write(addr(1), key.clone(), value.clone());

        assert_eq!(j.storage_write_count(), 1);
        assert_eq!(j.pending_storage(&addr(1), &key), Some(value.as_slice()));
        // Storage write also records the account in the write set
        assert!(j.write_set().contains(&addr(1)));
    }

    #[test]
    fn pending_storage_miss_returns_none() {
        let mut j = ScratchJournal::new();
        j.pin_at(ReadVersion::from_raw(0));
        assert!(j.pending_storage(&addr(1), &[0u8; 32]).is_none());
    }

    #[test]
    fn storage_writes_cleared_on_pin() {
        let mut j = ScratchJournal::new();
        j.pin_at(ReadVersion::from_raw(0));
        j.record_storage_write(addr(1), vec![1; 32], vec![2; 32]);
        assert_eq!(j.storage_write_count(), 1);

        // Re-pin = fresh attempt
        j.pin_at(ReadVersion::from_raw(1));
        assert_eq!(j.storage_write_count(), 0);
    }

    #[test]
    fn record_balance_populates_pending_and_write_set() {
        let mut j = ScratchJournal::new();
        j.pin_at(ReadVersion::from_raw(0));

        j.record_balance(addr(1), U256::from(1000));
        assert_eq!(j.pending_balance(&addr(1)), Some(U256::from(1000)));
        assert!(j.write_set().contains(&addr(1)));
        // No nonce pending
        assert_eq!(j.pending_nonce(&addr(1)), None);
    }

    #[test]
    fn record_nonce_populates_pending_and_write_set() {
        let mut j = ScratchJournal::new();
        j.pin_at(ReadVersion::from_raw(0));

        j.record_nonce(addr(1), 42);
        assert_eq!(j.pending_nonce(&addr(1)), Some(42));
        assert!(j.write_set().contains(&addr(1)));
    }

    #[test]
    fn balance_and_nonce_coexist_on_same_account() {
        let mut j = ScratchJournal::new();
        j.pin_at(ReadVersion::from_raw(0));

        j.record_balance(addr(1), U256::from(500));
        j.record_nonce(addr(1), 7);

        assert_eq!(j.pending_balance(&addr(1)), Some(U256::from(500)));
        assert_eq!(j.pending_nonce(&addr(1)), Some(7));
        // Only one pending entry for the account
        assert_eq!(j.write_count(), 1);
    }

    #[test]
    fn record_code_populates_pending() {
        let mut j = ScratchJournal::new();
        j.pin_at(ReadVersion::from_raw(0));

        let code = vec![0x60, 0x00, 0x60, 0x00];
        j.record_code(addr(1), code.clone());
        assert_eq!(
            j.pending_write(&addr(1)).and_then(|pw| pw.new_code.as_ref()),
            Some(&code)
        );
    }

    #[test]
    fn clear_resets_storage_map_too() {
        let mut j = ScratchJournal::new();
        j.pin_at(ReadVersion::from_raw(0));
        j.record_storage_write(addr(1), vec![1; 32], vec![2; 32]);
        j.record_balance(addr(1), U256::from(100));
        j.clear();

        assert_eq!(j.storage_write_count(), 0);
        assert_eq!(j.pending_balance(&addr(1)), None);
        assert_eq!(j.write_count(), 0);
    }

    #[test]
    fn discard_writes_clears_pending_but_preserves_sets_and_pin() {
        let mut j = ScratchJournal::new();
        j.pin_at(ReadVersion::from_raw(7));
        j.record_read(addr(1));
        j.record_balance(addr(2), U256::from(100));
        j.record_storage_write(addr(3), vec![1; 32], vec![2; 32]);

        j.discard_writes();

        assert_eq!(j.pending_balance(&addr(2)), None);
        assert_eq!(j.storage_write_count(), 0);
        assert_eq!(j.write_count(), 0);
        // Sets + pin preserved — conservative version bumping still happens
        assert!(j.is_pinned());
        assert_eq!(j.pinned_version(), Some(ReadVersion::from_raw(7)));
        assert!(j.read_set().iter().any(|a| *a == addr(1)));
        assert!(j.write_set().contains(&addr(2)));
        assert!(j.write_set().contains(&addr(3)));
    }

    #[test]
    fn discard_writes_then_rerecord_lets_final_drain_apply_only_rerecorded() {
        let mut j = ScratchJournal::new();
        j.pin_at(ReadVersion::from_raw(0));
        // Initial "optimistic" writes (e.g., pre-REVM gas deduction,
        // REVM-issued storage writes, REVM-issued value transfer).
        j.record_balance(addr(1), U256::from(50));
        j.record_storage_write(addr(2), vec![1; 32], vec![99; 32]);
        j.record_nonce(addr(1), 42);

        // Tx fails mid-execution. Discard the pending state, re-record
        // only the failure-mode accounting (gas-burn + nonce-increment).
        j.discard_writes();
        j.record_balance(addr(1), U256::from(30)); // gas-burn amount
        j.record_nonce(addr(1), 43);

        // Drain sees only the failure-mode records.
        let balances: HashMap<Address, u64> = j
            .iter_writes()
            .filter_map(|(a, w)| w.new_balance.map(|b| (*a, b.as_u64())))
            .collect();
        assert_eq!(balances.len(), 1);
        assert_eq!(balances[&addr(1)], 30);
        let nonces: HashMap<Address, u64> = j
            .iter_writes()
            .filter_map(|(a, w)| w.new_nonce.map(|n| (*a, n)))
            .collect();
        assert_eq!(nonces[&addr(1)], 43);
        assert_eq!(j.storage_write_count(), 0);
    }
}
