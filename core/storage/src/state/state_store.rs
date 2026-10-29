// citrate/core/storage/src/state/state_store.rs

use crate::db::{column_families::*, RocksDB};
use anyhow::Result;
use citrate_consensus::types::Hash;
use citrate_execution::executor::{
    BlockUndo, ReceiptIndexBatch, StateStorageChange, StateStoreTrait,
};
use citrate_execution::types::{AccountState, Address, JobId, ModelId, ModelState, TrainingJob};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// A storage key or value as persisted: raw bytes of any length.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StorageBytes(pub Vec<u8>);

impl StorageBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

/// One persisted contract-storage record: `((address, key), value)`.
pub type StorageRecord = ((Address, StorageBytes), StorageBytes);

/// The hydration view a node had before the storage-root hardening fork: only
/// records whose key is a 32-byte slot survive, and each value is cut or
/// zero-padded to 32 bytes. Kept bit for bit, because a restarted node below
/// the activation height must rebuild exactly the state it rebuilt before.
pub fn legacy_hydration_view(records: Vec<StorageRecord>) -> Vec<StorageRecord> {
    records
        .into_iter()
        .filter_map(|((address, key), value)| {
            if key.0.len() != 32 {
                return None;
            }
            let mut word = [0u8; 32];
            if let Some(head) = value.0.first_chunk::<32>() {
                word = *head;
            }
            Some(((address, key), StorageBytes(word.to_vec())))
        })
        .collect()
}

/// Undo records are kept for this many applied heights: the node's reorg
/// window (`canonical_apply::MAX_REORG_DEPTH`, which asserts it is equal). With
/// the records of heights `t-99..=t` a node at tip `t` can rebuild the state of
/// every height `t-100..=t` after a restart.
pub const REORG_UNDO_DEPTH: u64 = 100;

/// Largest undo record kept, encoded. A bigger one is skipped (the block is
/// left without a record): it would only shorten the window a restart can
/// rebuild, and it keeps one oversized block from bloating every commit.
pub const MAX_UNDO_RECORD_BYTES: usize = 8 * 1024 * 1024;

/// `CF_METADATA` key prefix of the undo records (big-endian height follows).
/// Metadata, not a column family of its own, so a binary without it still
/// opens the database.
const REORG_UNDO_PREFIX: &[u8] = b"reorg_undo:";

fn reorg_undo_key(height: u64) -> Vec<u8> {
    let mut key = REORG_UNDO_PREFIX.to_vec();
    key.extend_from_slice(&height.to_be_bytes());
    key
}

fn reorg_undo_height(key: &[u8]) -> Option<u64> {
    let rest = key.strip_prefix(REORG_UNDO_PREFIX)?;
    let bytes = <[u8; 8]>::try_from(rest).ok()?;
    Some(u64::from_be_bytes(bytes))
}

/// Whether height `h` is inside the kept window at tip height `tip`.
fn in_undo_window(h: u64, tip: u64) -> bool {
    h <= tip && h > tip.saturating_sub(REORG_UNDO_DEPTH)
}

/// Test-only fault injection for undo-record staging, per thread.
#[cfg(test)]
pub(crate) mod test_undo_faults {
    use std::cell::Cell;
    thread_local! {
        static FAIL: Cell<bool> = const { Cell::new(false) };
    }
    pub(crate) fn set_fail_staging(on: bool) {
        FAIL.with(|c| c.set(on));
    }
    pub(crate) fn fail_staging() -> bool {
        FAIL.with(|c| c.get())
    }
}

/// State storage manager
pub struct StateStore {
    db: Arc<RocksDB>,
}

impl StateStoreTrait for StateStore {
    fn put_account(&self, address: &Address, account: &AccountState) -> Result<()> {
        let account_bytes = bincode::serialize(account)?;
        self.db.put_cf(CF_ACCOUNTS, &address.0, &account_bytes)?;
        debug!("Stored account state for {}", address);
        Ok(())
    }

    fn get_account(&self, address: &Address) -> Result<Option<AccountState>> {
        match self.db.get_cf(CF_ACCOUNTS, &address.0)? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    fn put_code(&self, code_hash: &Hash, code: &[u8]) -> Result<()> {
        self.db.put_cf(CF_CODE, code_hash.as_bytes(), code)?;
        debug!("Stored contract code with hash {}", code_hash);
        Ok(())
    }

    /// PIL-13b: override the default `Ok(None)` so the REVM Database
    /// adapter can fall through to disk for code reads on cold cache.
    /// Forwards to the inherent [`StateStore::get_code`] (reads from
    /// RocksDB column family `CF_CODE`). Before this override the
    /// trait default returned `Ok(None)` and REVM saw all deployed
    /// contracts as having no bytecode after a restart, silently
    /// emitting `0x` from `eth_call`.
    fn get_code(&self, code_hash: &Hash) -> Result<Option<Vec<u8>>> {
        StateStore::get_code(self, code_hash)
    }

    fn put_storage(&self, address: &Address, key: &[u8], value: &[u8]) -> Result<()> {
        let storage_key = storage_key(address, key);
        self.db.put_cf(CF_STORAGE, &storage_key, value)?;
        Ok(())
    }

    /// PIL-13b: override the default `Ok(None)` so the REVM Database
    /// adapter can fall through to disk for storage reads on cold cache.
    /// Forwards to the inherent [`StateStore::get_storage`] (reads from
    /// RocksDB column family `CF_STORAGE`).
    fn get_storage(&self, address: &Address, key: &[u8]) -> Result<Option<Vec<u8>>> {
        StateStore::get_storage(self, address, key)
    }

    fn delete_storage(&self, address: &Address, key: &[u8]) -> Result<()> {
        let storage_key = storage_key(address, key);
        self.db.delete_cf(CF_STORAGE, &storage_key)?;
        Ok(())
    }

    fn delete_account(&self, address: &Address) -> Result<()> {
        self.db.delete_cf(CF_ACCOUNTS, &address.0)?;
        Ok(())
    }

    fn write_state_batch_sync(
        &self,
        accounts: &[(Address, AccountState)],
        storage: &[StateStorageChange],
    ) -> Result<()> {
        self.write_state_batch_with_applied_tip(
            accounts,
            storage,
            None,
            &ReceiptIndexBatch::default(),
        )
    }

    /// SRP-S3b: atomically persist the state batch AND the applied-tip pointer in ONE
    /// cross-CF RocksDB `WriteBatch`, so the durable state and the committed applied tip
    /// can never diverge across a crash/restart (see the trait doc). The applied-tip key
    /// (`CF_METADATA`/`APPLIED_TIP_KEY`) is written in the SAME batch as the account +
    /// storage mutations — the whole thing commits or nothing does.
    fn write_state_batch_with_applied_tip(
        &self,
        accounts: &[(Address, AccountState)],
        storage: &[StateStorageChange],
        applied_tip: Option<(Hash, u64)>,
        index: &ReceiptIndexBatch,
    ) -> Result<()> {
        if accounts.is_empty() && storage.is_empty() && applied_tip.is_none() && index.is_empty() {
            return Ok(());
        }

        let mut batch = self.db.batch();
        for (address, account) in accounts {
            let account_bytes = bincode::serialize(account)?;
            self.db
                .batch_put_cf(&mut batch, CF_ACCOUNTS, &address.0, &account_bytes)?;
        }
        for change in storage {
            let storage_key = storage_key(&change.address, &change.key);
            match &change.value {
                Some(value) => {
                    self.db
                        .batch_put_cf(&mut batch, CF_STORAGE, &storage_key, value)?;
                }
                None => {
                    self.db
                        .batch_delete_cf(&mut batch, CF_STORAGE, &storage_key)?;
                }
            }
        }
        // C1-R: the block's RPC receipt index commits in this same batch.
        crate::chain::transaction_store::stage_receipt_index(&self.db, &mut batch, index)?;
        // chain#421: the canonical height index moves with the tip, in this batch,
        // and so does the block's undo record (the pre-images read here, before
        // the batch overwrites them).
        let _index_guard = match applied_tip {
            Some((hash, height)) => {
                let guard = crate::chain::block_store::canonical_index_lock();
                self.stage_block_undo(&mut batch, accounts, storage, (hash, height))?;
                self.stage_applied_tip_locked(&mut batch, &hash, height)?;
                Some(guard)
            }
            None => None,
        };

        self.db.write_batch_sync(batch)?;
        debug!(
            "Stored finalized state batch: {} account(s), {} storage mutation(s), tip={}",
            accounts.len(),
            storage.len(),
            applied_tip.is_some()
        );
        Ok(())
    }

    /// #126 (crash-consistent reorg commit): persist a REORG store reconciliation —
    /// account puts, storage changes, account DELETIONS, contract CODE, and the
    /// applied-tip pointer — in ONE cross-CF `WriteBatch` committed with
    /// `write_batch_sync` (fsync). The whole reconciliation commits or nothing does,
    /// so a crash can never leave the durable applied tip out of step with durable
    /// state (the reorg fork on restart this closes). Mirrors the atomic layout of
    /// [`Self::write_state_batch_with_applied_tip`] but also carries account deletes
    /// (`CF_ACCOUNTS`) and contract code (`CF_CODE`) in the same batch.
    fn write_reorg_batch_sync(
        &self,
        accounts: &[(Address, AccountState)],
        storage: &[StateStorageChange],
        account_dels: &[Address],
        code: &[(Hash, Vec<u8>)],
        applied_tip: Option<(Hash, u64)>,
        index: &ReceiptIndexBatch,
        undo: &[BlockUndo],
    ) -> Result<()> {
        if accounts.is_empty()
            && storage.is_empty()
            && account_dels.is_empty()
            && code.is_empty()
            && applied_tip.is_none()
            && index.is_empty()
            && undo.is_empty()
        {
            return Ok(());
        }

        let mut batch = self.db.batch();
        for (address, account) in accounts {
            let account_bytes = bincode::serialize(account)?;
            self.db
                .batch_put_cf(&mut batch, CF_ACCOUNTS, &address.0, &account_bytes)?;
        }
        for change in storage {
            let storage_key = storage_key(&change.address, &change.key);
            match &change.value {
                Some(value) => {
                    self.db
                        .batch_put_cf(&mut batch, CF_STORAGE, &storage_key, value)?;
                }
                None => {
                    self.db
                        .batch_delete_cf(&mut batch, CF_STORAGE, &storage_key)?;
                }
            }
        }
        for address in account_dels {
            self.db
                .batch_delete_cf(&mut batch, CF_ACCOUNTS, &address.0)?;
        }
        for (code_hash, code) in code {
            self.db
                .batch_put_cf(&mut batch, CF_CODE, code_hash.as_bytes(), code)?;
        }
        // C1-R: the block's RPC receipt index commits in this same batch.
        crate::chain::transaction_store::stage_receipt_index(&self.db, &mut batch, index)?;
        // The winning branch's undo records replace the kept window, in this batch.
        if let (Some((_, height)), false) = (applied_tip, undo.is_empty()) {
            self.stage_branch_undo(&mut batch, undo, height)?;
        }
        // chain#421: the canonical height index moves with the tip, in this batch.
        let _index_guard = match applied_tip {
            Some((hash, height)) => Some(self.stage_applied_tip(&mut batch, &hash, height)?),
            None => None,
        };

        self.db.write_batch_sync(batch)?;
        debug!(
            "Stored reorg reconcile batch: {} put, {} storage, {} delete(s), {} code, tip={}",
            accounts.len(),
            storage.len(),
            account_dels.len(),
            code.len(),
            applied_tip.is_some()
        );
        Ok(())
    }

    /// SRP-S3b: persist the applied-tip pointer alone (non-atomic fallback path). The
    /// atomic [`Self::write_state_batch_with_applied_tip`] is preferred for the commit path.
    fn put_applied_tip_meta(&self, hash: &Hash, height: u64) -> Result<()> {
        let mut batch = self.db.batch();
        let _index_guard = self.stage_applied_tip(&mut batch, hash, height)?;
        self.db.write_batch_sync(batch)
    }

    /// C1-R: the receipt index on its own, as one fsync'd batch. The commit paths
    /// stage it inside their state batch instead; this override keeps the
    /// standalone trait method honest for any caller of the default fallback.
    fn put_receipt_index(&self, index: &ReceiptIndexBatch) -> Result<()> {
        if index.is_empty() {
            return Ok(());
        }
        let mut batch = self.db.batch();
        crate::chain::transaction_store::stage_receipt_index(&self.db, &mut batch, index)?;
        self.db.write_batch_sync(batch)
    }

    // Sprint P950-A-4 WP-A.4.3: persist MVCC per-account versions.

    fn put_account_version(&self, address: &Address, version: u64) -> Result<()> {
        self.db
            .put_cf(CF_ACCOUNT_VERSIONS, &address.0, &version.to_be_bytes())?;
        Ok(())
    }

    fn put_account_versions(&self, entries: &[(Address, u64)]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let mut batch = self.db.batch();
        for (addr, ver) in entries {
            self.db
                .batch_put_cf(&mut batch, CF_ACCOUNT_VERSIONS, &addr.0, &ver.to_be_bytes())?;
        }
        self.db.write_batch(batch)?;
        Ok(())
    }

    fn get_all_account_versions(&self) -> Result<Vec<(Address, u64)>> {
        let mut out = Vec::new();
        let iter = self.db.iter_cf(CF_ACCOUNT_VERSIONS)?;
        for (key, value) in iter {
            // Skip the global-version sentinel key (all 0xFF) — handled by
            // get_global_version() separately. Addresses are 20 bytes;
            // anything else is ignored defensively.
            if key.len() != 20 {
                continue;
            }
            let mut addr_bytes = [0u8; 20];
            addr_bytes.copy_from_slice(&key);
            if addr_bytes == [0xFF; 20] {
                continue;
            }
            if value.len() == 8 {
                let mut ver_bytes = [0u8; 8];
                ver_bytes.copy_from_slice(&value);
                out.push((Address(addr_bytes), u64::from_be_bytes(ver_bytes)));
            }
        }
        Ok(out)
    }

    fn put_global_version(&self, version: u64) -> Result<()> {
        self.db
            .put_cf(CF_ACCOUNT_VERSIONS, &[0xFFu8; 20], &version.to_be_bytes())?;
        Ok(())
    }

    fn get_global_version(&self) -> Result<Option<u64>> {
        match self.db.get_cf(CF_ACCOUNT_VERSIONS, &[0xFFu8; 20])? {
            Some(bytes) if bytes.len() == 8 => {
                let mut ver_bytes = [0u8; 8];
                ver_bytes.copy_from_slice(&bytes);
                Ok(Some(u64::from_be_bytes(ver_bytes)))
            }
            _ => Ok(None),
        }
    }
}

impl StateStore {
    /// Stage the applied-tip pointer and the canonical height index for it into
    /// `batch` (same key + layout as `BlockStore::put_applied_tip`). The returned
    /// guard must be held until `batch` is committed: staging reads the index it
    /// rewrites, so two tip writers must not interleave.
    fn stage_applied_tip(
        &self,
        batch: &mut rocksdb::WriteBatch,
        hash: &Hash,
        height: u64,
    ) -> Result<std::sync::MutexGuard<'static, ()>> {
        let guard = crate::chain::block_store::canonical_index_lock();
        self.stage_applied_tip_locked(batch, hash, height)?;
        Ok(guard)
    }

    /// [`Self::stage_applied_tip`] for a caller that already holds the
    /// canonical index lock.
    fn stage_applied_tip_locked(
        &self,
        batch: &mut rocksdb::WriteBatch,
        hash: &Hash,
        height: u64,
    ) -> Result<()> {
        crate::chain::block_store::stage_canonical_index(&self.db, batch, hash, height)?;
        self.db.batch_put_cf(
            batch,
            CF_METADATA,
            crate::chain::block_store::APPLIED_TIP_KEY,
            &crate::chain::block_store::applied_tip_bytes(hash, height),
        )
    }

    /// The durable applied tip, read the way `BlockStore::get_applied_tip`
    /// reads it.
    fn durable_tip(&self) -> Result<Option<(Hash, u64)>> {
        let Some(bytes) = self
            .db
            .get_cf(CF_METADATA, crate::chain::block_store::APPLIED_TIP_KEY)?
        else {
            return Ok(None);
        };
        let hash = Hash::try_from_bytes(&bytes);
        let height = bytes
            .get(32..40)
            .and_then(|s| <[u8; 8]>::try_from(s).ok())
            .map(u64::from_be_bytes);
        Ok(hash.zip(height))
    }

    /// Stage the undo record of the block a linear commit applies at `tip`:
    /// the stored value of every account and slot the batch writes, read
    /// before the batch commits, with the previous durable tip as parent.
    /// Records outside the kept window are deleted in the same batch. A
    /// rewrite at the tip already durable adds the pre-images of keys its
    /// record does not hold yet, so the record keeps reverting to the parent.
    ///
    /// A read that fails leaves the block without a record (and removes any
    /// stale one at its height) instead of failing the commit: the records are
    /// local metadata, and a missing one only shortens the window a restart
    /// can rebuild.
    fn stage_block_undo(
        &self,
        batch: &mut rocksdb::WriteBatch,
        accounts: &[(Address, AccountState)],
        storage: &[StateStorageChange],
        tip: (Hash, u64),
    ) -> Result<()> {
        let (hash, height) = tip;
        match self.block_undo(accounts, storage, tip) {
            Ok(Some(record)) => {
                self.db.batch_put_cf(
                    batch,
                    CF_METADATA,
                    &reorg_undo_key(height),
                    &bincode::serialize(&record)?,
                )?;
                self.stage_undo_window(batch, height)
            }
            Ok(None) => {
                // A rewrite at the durable tip whose record names another block
                // (or none): it cannot be rebuilt from here, so drop it.
                self.db
                    .batch_delete_cf(batch, CF_METADATA, &reorg_undo_key(height))?;
                self.stage_undo_window(batch, height)
            }
            Err(e) => {
                warn!(
                    "reorg window: no undo record for block {hash} @ {height} ({e}); a restart \
                     can revert no further than this height"
                );
                self.db
                    .batch_delete_cf(batch, CF_METADATA, &reorg_undo_key(height))?;
                self.stage_undo_window(batch, height)
            }
        }
    }

    /// The record [`Self::stage_block_undo`] stages: a new one (replacing any
    /// record at the height, e.g. an abandoned branch's), or, at the tip that
    /// is already durable, its own record extended. `None` when the tip is
    /// already durable and the record at its height names another block or
    /// parent (or there is none).
    fn block_undo(
        &self,
        accounts: &[(Address, AccountState)],
        storage: &[StateStorageChange],
        tip: (Hash, u64),
    ) -> Result<Option<BlockUndo>> {
        let (hash, height) = tip;
        let parent = self.durable_tip()?;
        let mut record = if parent == Some(tip) {
            match self.get_reorg_undo(height)? {
                Some(r) if r.hash == hash && r.height == height => r,
                _ => return Ok(None),
            }
        } else {
            BlockUndo {
                height,
                hash,
                parent,
                accounts: Vec::new(),
                storage: Vec::new(),
                models_jobs: None,
            }
        };
        let held_accounts: std::collections::HashSet<Address> =
            record.accounts.iter().map(|(a, _)| *a).collect();
        for (address, _) in accounts {
            if held_accounts.contains(address) {
                continue;
            }
            let before = match self.db.get_cf(CF_ACCOUNTS, &address.0)? {
                Some(bytes) => Some(bincode::deserialize::<AccountState>(&bytes)?),
                None => None,
            };
            record.accounts.push((*address, before));
        }
        let held_slots: std::collections::HashSet<(Address, Vec<u8>)> = record
            .storage
            .iter()
            .map(|(a, k, _)| (*a, k.clone()))
            .collect();
        for change in storage {
            if held_slots.contains(&(change.address, change.key.clone())) {
                continue;
            }
            let before = self
                .db
                .get_cf(CF_STORAGE, &storage_key(&change.address, &change.key))?;
            record
                .storage
                .push((change.address, change.key.clone(), before));
        }
        Ok(Some(record))
    }

    /// Stage a reorg's undo records (the winning branch's, computed by the
    /// node from its in-memory states) and drop every other record outside the
    /// window at the new tip `tip`, including the abandoned branch's above it.
    fn stage_branch_undo(
        &self,
        batch: &mut rocksdb::WriteBatch,
        undo: &[BlockUndo],
        tip: u64,
    ) -> Result<()> {
        for record in undo.iter().filter(|r| in_undo_window(r.height, tip)) {
            self.db.batch_put_cf(
                batch,
                CF_METADATA,
                &reorg_undo_key(record.height),
                &bincode::serialize(record)?,
            )?;
        }
        self.stage_undo_window(batch, tip)
    }

    /// Delete, in `batch`, every kept record outside the window at `tip`.
    fn stage_undo_window(&self, batch: &mut rocksdb::WriteBatch, tip: u64) -> Result<()> {
        #[cfg(test)]
        if test_undo_faults::fail_staging() {
            anyhow::bail!("injected undo staging failure");
        }
        for height in self.reorg_undo_heights()? {
            if !in_undo_window(height, tip) {
                self.db
                    .batch_delete_cf(batch, CF_METADATA, &reorg_undo_key(height))?;
            }
        }
        Ok(())
    }

    pub fn new(db: Arc<RocksDB>) -> Self {
        Self { db }
    }

    /// Add the model and training-job pre-images to the record of the block
    /// `hash` at `height` (see [`BlockUndo::models_jobs`]). `Ok(false)` when no
    /// record names that block (nothing is written). A lost write only leaves
    /// the record unusable for a revert, so it is not fsync'd.
    pub fn complete_reorg_undo(
        &self,
        height: u64,
        hash: Hash,
        models_jobs: citrate_execution::executor::ModelJobUndo,
    ) -> Result<bool> {
        let _guard = crate::chain::block_store::canonical_index_lock();
        match self.get_reorg_undo(height)? {
            Some(mut record) if record.hash == hash => {
                record.models_jobs = Some(models_jobs);
                self.db.put_cf(
                    CF_METADATA,
                    &reorg_undo_key(height),
                    &bincode::serialize(&record)?,
                )?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Heights that hold an undo record, ascending.
    pub fn reorg_undo_heights(&self) -> Result<Vec<u64>> {
        let mut heights = Vec::new();
        self.db
            .for_each_prefix_key_cf(CF_METADATA, REORG_UNDO_PREFIX, |key| {
                if let Some(h) = reorg_undo_height(key) {
                    heights.push(h);
                }
                Ok(())
            })?;
        Ok(heights)
    }

    /// The undo record of the block applied at `height`, if one is kept. A
    /// record that does not decode is an error, never "absent".
    pub fn get_reorg_undo(&self, height: u64) -> Result<Option<BlockUndo>> {
        match self.db.get_cf(CF_METADATA, &reorg_undo_key(height))? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Store account state
    pub fn put_account(&self, address: &Address, account: &AccountState) -> Result<()> {
        let account_bytes = bincode::serialize(account)?;
        self.db.put_cf(CF_ACCOUNTS, &address.0, &account_bytes)?;
        debug!("Stored account state for {}", address);
        Ok(())
    }

    /// Get account state
    pub fn get_account(&self, address: &Address) -> Result<Option<AccountState>> {
        match self.db.get_cf(CF_ACCOUNTS, &address.0)? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Get all accounts (for state root calculation)
    pub fn get_all_accounts(&self) -> Result<Vec<(Address, AccountState)>> {
        let mut accounts = Vec::new();
        let iter = self.db.iter_cf(CF_ACCOUNTS)?;

        for (key, value) in iter {
            if key.len() == 20 {
                let mut addr_bytes = [0u8; 20];
                addr_bytes.copy_from_slice(&key);
                let address = Address(addr_bytes);
                let account: AccountState = bincode::deserialize(&value)?;
                accounts.push((address, account));
            }
        }

        Ok(accounts)
    }

    /// Every persisted contract-storage record, with its exact key and value
    /// bytes: the node's restart-hydration source.
    ///
    /// The executor writes 32-byte EVM slots and also its own variable-length
    /// records (the governance admin, pending and applied parameters, model CID
    /// and artifact indexes), so no key or value shape is assumed beyond the
    /// 20-byte address prefix every writer puts first. A record shorter than
    /// that cannot have come from a writer here and is an error, never skipped.
    ///
    /// Below the storage-root hardening height a restarted node applies
    /// [`legacy_hydration_view`] to this result, so legacy roots are unchanged.
    pub fn get_all_storage(&self) -> Result<Vec<StorageRecord>> {
        let mut storage = Vec::new();
        let iter = self.db.iter_cf(CF_STORAGE)?;

        for (key, value) in iter {
            let Some((addr_part, key_part)) = key.split_first_chunk::<20>() else {
                anyhow::bail!(
                    "storage record with a {}-byte key: shorter than the 20-byte address \
                     prefix (corrupt store)",
                    key.len()
                );
            };
            storage.push((
                (Address(*addr_part), StorageBytes(key_part.to_vec())),
                StorageBytes(value.to_vec()),
            ));
        }

        Ok(storage)
    }

    /// Delete account state
    pub fn delete_account(&self, address: &Address) -> Result<()> {
        self.db.delete_cf(CF_ACCOUNTS, &address.0)?;
        Ok(())
    }

    /// Store contract storage value
    pub fn put_storage(&self, address: &Address, key: &[u8], value: &[u8]) -> Result<()> {
        let storage_key = storage_key(address, key);
        self.db.put_cf(CF_STORAGE, &storage_key, value)?;
        Ok(())
    }

    /// Get contract storage value
    pub fn get_storage(&self, address: &Address, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let storage_key = storage_key(address, key);
        self.db.get_cf(CF_STORAGE, &storage_key)
    }

    /// Delete contract storage value
    pub fn delete_storage(&self, address: &Address, key: &[u8]) -> Result<()> {
        let storage_key = storage_key(address, key);
        self.db.delete_cf(CF_STORAGE, &storage_key)?;
        Ok(())
    }

    /// Store contract code
    pub fn put_code(&self, code_hash: &Hash, code: &[u8]) -> Result<()> {
        self.db.put_cf(CF_CODE, code_hash.as_bytes(), code)?;
        debug!("Stored contract code with hash {}", code_hash);
        Ok(())
    }

    /// Get contract code
    pub fn get_code(&self, code_hash: &Hash) -> Result<Option<Vec<u8>>> {
        self.db.get_cf(CF_CODE, code_hash.as_bytes())
    }

    /// Store model state
    pub fn put_model(&self, model_id: &ModelId, model: &ModelState) -> Result<()> {
        let model_bytes = bincode::serialize(model)?;
        self.db
            .put_cf(CF_MODELS, model_id.0.as_bytes(), &model_bytes)?;

        // Index by owner
        let owner_key = owner_model_key(&model.owner, model_id);
        self.db.put_cf(CF_METADATA, &owner_key, &[])?;

        debug!("Stored model {:?}", model_id);
        Ok(())
    }

    /// Get model state
    pub fn get_model(&self, model_id: &ModelId) -> Result<Option<ModelState>> {
        match self.db.get_cf(CF_MODELS, model_id.0.as_bytes())? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Get models by owner
    pub fn get_models_by_owner(&self, owner: &Address) -> Result<Vec<ModelId>> {
        let prefix = owner_model_prefix(owner);
        let mut model_ids = Vec::new();

        for (key, _) in self.db.prefix_iter_cf(CF_METADATA, &prefix)? {
            if let Some(model_hash_bytes) = key.get(prefix.len()..).filter(|r| !r.is_empty()) {
                if model_hash_bytes.len() == 32 {
                    let mut hash_array = [0u8; 32];
                    hash_array.copy_from_slice(model_hash_bytes);
                    model_ids.push(ModelId(Hash::new(hash_array)));
                }
            }
        }

        Ok(model_ids)
    }

    /// Store training job
    pub fn put_training_job(&self, job: &TrainingJob) -> Result<()> {
        let job_bytes = bincode::serialize(job)?;
        self.db
            .put_cf(CF_TRAINING, job.id.0.as_bytes(), &job_bytes)?;

        // Index by owner
        let owner_key = owner_job_key(&job.owner, &job.id);
        self.db.put_cf(CF_METADATA, &owner_key, &[])?;

        debug!("Stored training job {:?}", job.id);
        Ok(())
    }

    /// Get training job
    pub fn get_training_job(&self, job_id: &JobId) -> Result<Option<TrainingJob>> {
        match self.db.get_cf(CF_TRAINING, job_id.0.as_bytes())? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Store state root for a block
    pub fn put_state_root(&self, block_hash: &Hash, state_root: &Hash) -> Result<()> {
        let key = state_root_key(block_hash);
        self.db.put_cf(CF_STATE, &key, state_root.as_bytes())?;
        Ok(())
    }

    /// Get state root for a block
    pub fn get_state_root(&self, block_hash: &Hash) -> Result<Option<Hash>> {
        let key = state_root_key(block_hash);
        match self.db.get_cf(CF_STATE, &key)? {
            // SECREM-01 CONS-6: a corrupt/truncated state-root value must
            // not panic the node — treat it as absent.
            Some(bytes) => Ok(Hash::try_from_bytes(&bytes)),
            None => Ok(None),
        }
    }

    /// Create a state snapshot at a specific block
    pub fn create_snapshot(
        &self,
        block_hash: &Hash,
        accounts: Vec<(Address, AccountState)>,
    ) -> Result<()> {
        let mut batch = self.db.batch();

        for (address, account) in accounts {
            let snapshot_key = snapshot_account_key(block_hash, &address);
            let account_bytes = bincode::serialize(&account)?;
            self.db
                .batch_put_cf(&mut batch, CF_STATE, &snapshot_key, &account_bytes)?;
        }

        self.db.write_batch(batch)?;
        info!("Created state snapshot at block {}", block_hash);
        Ok(())
    }

    /// Get account from snapshot
    pub fn get_snapshot_account(
        &self,
        block_hash: &Hash,
        address: &Address,
    ) -> Result<Option<AccountState>> {
        let key = snapshot_account_key(block_hash, address);
        match self.db.get_cf(CF_STATE, &key)? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Compact state storage
    pub fn compact(&self) -> Result<()> {
        self.db.compact_cf(CF_STATE)?;
        self.db.compact_cf(CF_ACCOUNTS)?;
        self.db.compact_cf(CF_STORAGE)?;
        self.db.compact_cf(CF_CODE)?;
        self.db.compact_cf(CF_MODELS)?;
        self.db.compact_cf(CF_TRAINING)?;
        Ok(())
    }
}

// Key generation helpers
fn storage_key(address: &Address, key: &[u8]) -> Vec<u8> {
    let mut storage_key = Vec::with_capacity(key.len().saturating_add(20));
    storage_key.extend_from_slice(&address.0);
    storage_key.extend_from_slice(key);
    storage_key
}

fn owner_model_key(owner: &Address, model_id: &ModelId) -> Vec<u8> {
    let mut key = vec![b'm'];
    key.extend_from_slice(&owner.0);
    key.extend_from_slice(model_id.0.as_bytes());
    key
}

fn owner_model_prefix(owner: &Address) -> Vec<u8> {
    let mut prefix = vec![b'm'];
    prefix.extend_from_slice(&owner.0);
    prefix
}

fn owner_job_key(owner: &Address, job_id: &JobId) -> Vec<u8> {
    let mut key = vec![b'j'];
    key.extend_from_slice(&owner.0);
    key.extend_from_slice(job_id.0.as_bytes());
    key
}

fn state_root_key(block_hash: &Hash) -> Vec<u8> {
    let mut key = vec![b'r'];
    key.extend_from_slice(block_hash.as_bytes());
    key
}

fn snapshot_account_key(block_hash: &Hash, address: &Address) -> Vec<u8> {
    let mut key = vec![b's'];
    key.extend_from_slice(block_hash.as_bytes());
    key.extend_from_slice(&address.0);
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_execution::types::Address;
    use primitive_types::U256;
    use tempfile::TempDir;

    #[test]
    fn test_account_storage() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(RocksDB::open(temp_dir.path()).unwrap());
        let store = StateStore::new(db);

        let address = Address([1; 20]);
        let account = AccountState {
            nonce: 10,
            balance: U256::from(1000),
            storage_root: Hash::default(),
            code_hash: Hash::default(),
            model_permissions: vec![],
        };

        // Store account
        store.put_account(&address, &account).unwrap();

        // Retrieve account
        let retrieved = store.get_account(&address).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().nonce, 10);
    }

    fn acct(balance: u64) -> AccountState {
        AccountState {
            nonce: 0,
            balance: U256::from(balance),
            storage_root: Hash::default(),
            code_hash: Hash::default(),
            model_permissions: vec![],
        }
    }

    fn block_hash(height: u64) -> Hash {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&height.to_be_bytes());
        b[31] = 0xB1;
        Hash::new(b)
    }

    fn slot(address: Address, key: &[u8], value: Option<&[u8]>) -> StateStorageChange {
        StateStorageChange {
            address,
            key: key.to_vec(),
            value: value.map(|v| v.to_vec()),
        }
    }

    /// A linear commit stages its block's undo record in the same batch: the
    /// stored values it overwrites (absent ones as `None`) and the previous
    /// durable tip as parent.
    #[test]
    fn a_tip_commit_records_the_pre_images_it_overwrites() {
        let temp_dir = TempDir::new().unwrap();
        let store = StateStore::new(Arc::new(RocksDB::open(temp_dir.path()).unwrap()));
        let (a, b) = (Address([1; 20]), Address([2; 20]));
        let none = ReceiptIndexBatch::default();
        store
            .write_state_batch_with_applied_tip(
                &[(a, acct(10))],
                &[slot(a, b"k", Some(b"v1"))],
                Some((block_hash(1), 1)),
                &none,
            )
            .unwrap();
        store
            .write_state_batch_with_applied_tip(
                &[(a, acct(20)), (b, acct(5))],
                &[slot(a, b"k", None), slot(a, b"j", Some(b"x"))],
                Some((block_hash(2), 2)),
                &none,
            )
            .unwrap();
        let rec = store.get_reorg_undo(2).unwrap().expect("record");
        assert_eq!(rec.hash, block_hash(2));
        assert_eq!(rec.parent, Some((block_hash(1), 1)));
        assert_eq!(rec.accounts, vec![(a, Some(acct(10))), (b, None)]);
        assert_eq!(
            rec.storage,
            vec![
                (a, b"k".to_vec(), Some(b"v1".to_vec())),
                (a, b"j".to_vec(), None)
            ]
        );
        // A second write at the same tip extends the record with new keys only:
        // the pre-images still describe the parent.
        store
            .write_state_batch_with_applied_tip(
                &[(a, acct(30)), (Address([3; 20]), acct(1))],
                &[],
                Some((block_hash(2), 2)),
                &none,
            )
            .unwrap();
        let rec = store.get_reorg_undo(2).unwrap().expect("record");
        assert_eq!(
            rec.accounts,
            vec![(a, Some(acct(10))), (b, None), (Address([3; 20]), None)]
        );
        assert_eq!(rec.parent, Some((block_hash(1), 1)));
    }

    /// A record at the height of a new block that names another block (an
    /// abandoned branch's, left after a crash between a reorg's revert and its
    /// commit) is replaced, not extended; a rewrite at the durable tip whose
    /// record names another block drops it. Model pre-images are added to the
    /// record of the named block only.
    #[test]
    fn a_stale_record_at_the_height_is_replaced_not_merged() {
        let temp_dir = TempDir::new().unwrap();
        let store = StateStore::new(Arc::new(RocksDB::open(temp_dir.path()).unwrap()));
        let (a, b) = (Address([1; 20]), Address([2; 20]));
        let none = ReceiptIndexBatch::default();
        let commit = |accts: &[(Address, AccountState)], tip: (Hash, u64)| {
            store
                .write_state_batch_with_applied_tip(accts, &[], Some(tip), &none)
                .unwrap()
        };
        commit(&[(a, acct(1))], (block_hash(1), 1));
        commit(&[(a, acct(2)), (b, acct(9))], (block_hash(2), 2));
        // Back to the fork point at 1 (a reorg's revert): record 2 stays.
        store
            .write_reorg_batch_sync(&[], &[], &[], &[], Some((block_hash(1), 1)), &none, &[])
            .unwrap();
        // The other branch's block at 2: a new record, nothing of the stale one.
        let other = Hash::new([0xEE; 32]);
        commit(&[(a, acct(3))], (other, 2));
        let rec = store.get_reorg_undo(2).unwrap().expect("record");
        assert_eq!(rec.hash, other);
        assert_eq!(rec.parent, Some((block_hash(1), 1)));
        assert_eq!(
            rec.accounts,
            vec![(a, Some(acct(2)))],
            "pre-image from the store"
        );
        assert!(rec.models_jobs.is_none());
        // Model pre-images go to the named block's record only.
        let mj = citrate_execution::executor::ModelJobUndo::default();
        assert!(!store
            .complete_reorg_undo(2, block_hash(2), mj.clone())
            .unwrap());
        assert!(store.complete_reorg_undo(2, other, mj.clone()).unwrap());
        assert_eq!(
            store.get_reorg_undo(2).unwrap().unwrap().models_jobs,
            Some(mj)
        );
        // A rewrite at the durable tip (other @ 2) keeps and extends its record...
        commit(&[(Address([5; 20]), acct(1))], (other, 2));
        let rec = store.get_reorg_undo(2).unwrap().expect("record");
        assert_eq!(rec.accounts.len(), 2);
        assert!(
            rec.models_jobs.is_some(),
            "the completed record stays usable"
        );
        // ...but a record that names another block at the durable tip is dropped.
        let stale = BlockUndo {
            height: 2,
            hash: block_hash(2),
            ..Default::default()
        };
        store
            .db
            .put_cf(
                CF_METADATA,
                &reorg_undo_key(2),
                &bincode::serialize(&stale).unwrap(),
            )
            .unwrap();
        commit(&[(Address([6; 20]), acct(1))], (other, 2));
        assert!(store.get_reorg_undo(2).unwrap().is_none());
    }

    /// Records are kept for exactly the last REORG_UNDO_DEPTH heights; a reorg
    /// commit replaces the window with the winning branch's records and drops
    /// the abandoned ones above its tip; a commit without records (the revert
    /// to the fork point, an abort) leaves them all.
    #[test]
    fn undo_records_keep_exactly_the_window() {
        let temp_dir = TempDir::new().unwrap();
        let store = StateStore::new(Arc::new(RocksDB::open(temp_dir.path()).unwrap()));
        let a = Address([1; 20]);
        let none = ReceiptIndexBatch::default();
        for h in 1..=150u64 {
            store
                .write_state_batch_with_applied_tip(
                    &[(a, acct(h))],
                    &[],
                    Some((block_hash(h), h)),
                    &none,
                )
                .unwrap();
        }
        assert_eq!(
            store.reorg_undo_heights().unwrap(),
            (51..=150).collect::<Vec<u64>>()
        );
        // Revert to a fork point at 140: no records passed, nothing changes.
        store
            .write_reorg_batch_sync(&[], &[], &[], &[], Some((block_hash(140), 140)), &none, &[])
            .unwrap();
        assert_eq!(
            store.reorg_undo_heights().unwrap(),
            (51..=150).collect::<Vec<u64>>()
        );
        // The winning branch 141..=145 commits with its records.
        let winner: Vec<BlockUndo> = (141..=145u64)
            .map(|h| BlockUndo {
                height: h,
                hash: Hash::new([h as u8; 32]),
                parent: None,
                accounts: vec![(a, Some(acct(h - 1)))],
                storage: vec![],
                models_jobs: None,
            })
            .collect();
        store
            .write_reorg_batch_sync(
                &[],
                &[],
                &[],
                &[],
                Some((Hash::new([145; 32]), 145)),
                &none,
                &winner,
            )
            .unwrap();
        assert_eq!(
            store.reorg_undo_heights().unwrap(),
            (46..=145).filter(|h| *h >= 51).collect::<Vec<u64>>(),
            "abandoned 146..=150 dropped; nothing below the window"
        );
        assert_eq!(
            store.get_reorg_undo(143).unwrap().map(|r| r.hash),
            Some(Hash::new([143; 32]))
        );
        assert_eq!(
            store.get_reorg_undo(140).unwrap().map(|r| r.hash),
            Some(block_hash(140)),
            "the shared chain's records stay"
        );
    }

    /// Undo records are local metadata: a failure while staging one (a read,
    /// an encode, a window scan) never fails the consensus commit. The state
    /// and the tip commit, and the block is left without a record (a shorter
    /// window a restart can rebuild, never a wrong one). The same for a reorg
    /// commit carrying the winning branch's records.
    #[test]
    fn an_undo_staging_failure_never_fails_the_commit() {
        let temp_dir = TempDir::new().expect("tempdir");
        let store = StateStore::new(Arc::new(RocksDB::open(temp_dir.path()).expect("open")));
        let a = Address([1; 20]);
        let none = ReceiptIndexBatch::default();
        store
            .write_state_batch_with_applied_tip(
                &[(a, acct(1))],
                &[],
                Some((block_hash(1), 1)),
                &none,
            )
            .expect("block 1");
        assert!(store.get_reorg_undo(1).expect("read").is_some(), "fixture");

        test_undo_faults::set_fail_staging(true);
        let linear = store.write_state_batch_with_applied_tip(
            &[(a, acct(2))],
            &[slot(a, b"k", Some(b"v"))],
            Some((block_hash(2), 2)),
            &none,
        );
        let winner = [BlockUndo {
            height: 3,
            hash: block_hash(3),
            parent: Some((block_hash(2), 2)),
            accounts: vec![(a, Some(acct(2)))],
            storage: vec![],
            models_jobs: Some(Default::default()),
        }];
        let reorg = store.write_reorg_batch_sync(
            &[(a, acct(3))],
            &[],
            &[],
            &[],
            Some((block_hash(3), 3)),
            &none,
            &winner,
        );
        test_undo_faults::set_fail_staging(false);

        assert!(
            linear.is_ok(),
            "a linear commit must not fail on its undo record: {linear:?}"
        );
        assert!(
            reorg.is_ok(),
            "a reorg commit must not fail on its undo records: {reorg:?}"
        );
        assert_eq!(store.durable_tip().expect("tip"), Some((block_hash(3), 3)));
        assert_eq!(
            store.get_account(&a).expect("account").map(|s| s.balance),
            Some(U256::from(3u64))
        );
        assert_eq!(
            store.get_storage(&a, b"k").expect("slot"),
            Some(b"v".to_vec())
        );
        assert!(
            store.get_reorg_undo(2).expect("read").is_none(),
            "no record for the linear block"
        );
        assert!(
            store.get_reorg_undo(3).expect("read").is_none(),
            "no record for the reorg block"
        );
        assert!(
            store.get_reorg_undo(1).expect("read").is_some(),
            "records already kept stay"
        );
    }

    /// An undo record larger than the cap is not kept (a warning, no record
    /// at that height); the commit itself goes through. Linear and reorg alike.
    #[test]
    fn an_oversized_undo_record_is_skipped() {
        let temp_dir = TempDir::new().expect("tempdir");
        let store = StateStore::new(Arc::new(RocksDB::open(temp_dir.path()).expect("open")));
        let a = Address([1; 20]);
        let none = ReceiptIndexBatch::default();
        let big = vec![0xAB; MAX_UNDO_RECORD_BYTES + 1];
        store
            .write_state_batch_with_applied_tip(
                &[(a, acct(1))],
                &[slot(a, b"big", Some(&big))],
                Some((block_hash(1), 1)),
                &none,
            )
            .expect("block 1");
        // Block 2 overwrites the big slot: its pre-image is over the cap.
        store
            .write_state_batch_with_applied_tip(
                &[(a, acct(2))],
                &[slot(a, b"big", Some(b"small"))],
                Some((block_hash(2), 2)),
                &none,
            )
            .expect("block 2 commits");
        assert_eq!(store.durable_tip().expect("tip"), Some((block_hash(2), 2)));
        assert!(
            store.get_reorg_undo(2).expect("read").is_none(),
            "an oversized record is not kept"
        );
        assert!(store.get_reorg_undo(1).expect("read").is_some());
        // A reorg's winning record over the cap is skipped; the others are kept.
        let records = [
            BlockUndo {
                height: 3,
                hash: block_hash(3),
                parent: Some((block_hash(2), 2)),
                accounts: vec![(a, Some(acct(2)))],
                storage: vec![(a, b"big".to_vec(), Some(big.clone()))],
                models_jobs: Some(Default::default()),
            },
            BlockUndo {
                height: 4,
                hash: block_hash(4),
                parent: Some((block_hash(3), 3)),
                accounts: vec![(a, Some(acct(3)))],
                storage: vec![],
                models_jobs: Some(Default::default()),
            },
        ];
        store
            .write_reorg_batch_sync(
                &[(a, acct(4))],
                &[],
                &[],
                &[],
                Some((block_hash(4), 4)),
                &none,
                &records,
            )
            .expect("reorg commits");
        assert!(
            store.get_reorg_undo(3).expect("read").is_none(),
            "an oversized winning record is not kept"
        );
        assert_eq!(
            store.get_reorg_undo(4).expect("read").map(|r| r.hash),
            Some(block_hash(4))
        );
    }

    #[test]
    fn test_storage_operations() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(RocksDB::open(temp_dir.path()).unwrap());
        let store = StateStore::new(db);

        let address = Address([1; 20]);

        // Store value
        store.put_storage(&address, b"key1", b"value1").unwrap();

        // Retrieve value
        let value = store.get_storage(&address, b"key1").unwrap();
        assert_eq!(value, Some(b"value1".to_vec()));

        // Delete value
        store.delete_storage(&address, b"key1").unwrap();
        assert!(store.get_storage(&address, b"key1").unwrap().is_none());
    }
}
