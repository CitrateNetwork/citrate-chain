// citrate/core/storage/src/chain/transaction_store.rs

use crate::db::{column_families::*, RocksDB};
use anyhow::Result;
use citrate_consensus::types::{Hash, Transaction};
use citrate_execution::executor::{ReceiptIndexBatch, ReceiptReconcileMarker};
use citrate_execution::types::TransactionReceipt;
use std::sync::Arc;
use tracing::{debug, warn};

/// Transaction and receipt storage
pub struct TransactionStore {
    db: Arc<RocksDB>,
}

impl TransactionStore {
    pub fn new(db: Arc<RocksDB>) -> Self {
        Self { db }
    }

    /// Store a transaction
    pub fn put_transaction(&self, tx: &Transaction) -> Result<()> {
        let tx_bytes = bincode::serialize(tx)?;
        self.db
            .put_cf(CF_TRANSACTIONS, tx.hash.as_bytes(), &tx_bytes)?;

        // Index by sender
        let sender_key = sender_tx_key(&tx.from, tx.nonce);
        self.db
            .put_cf(CF_METADATA, &sender_key, tx.hash.as_bytes())?;

        debug!("Stored transaction {}", tx.hash);
        Ok(())
    }

    /// Store multiple transactions in batch
    pub fn put_transactions(&self, txs: &[Transaction]) -> Result<()> {
        let mut batch = self.db.batch();

        for tx in txs {
            let tx_bytes = bincode::serialize(tx)?;
            self.db
                .batch_put_cf(&mut batch, CF_TRANSACTIONS, tx.hash.as_bytes(), &tx_bytes)?;

            let sender_key = sender_tx_key(&tx.from, tx.nonce);
            self.db
                .batch_put_cf(&mut batch, CF_METADATA, &sender_key, tx.hash.as_bytes())?;
        }

        // REM-2 / WP-H1.3 (audit M-API-01): producer-path commit MUST
        // fsync. Pre-fix used the non-fsync `write_batch`; a power loss
        // between RPC ack and OS flush could leave a block on disk with
        // its tx index missing. `write_batch_sync` forces fsync.
        self.db.write_batch_sync(batch)?;
        debug!("Stored {} transactions", txs.len());
        Ok(())
    }

    /// Get a transaction by hash
    pub fn get_transaction(&self, hash: &Hash) -> Result<Option<Transaction>> {
        match self.db.get_cf(CF_TRANSACTIONS, hash.as_bytes()) {
            Ok(Some(bytes)) => match bincode::deserialize::<Transaction>(&bytes) {
                Ok(tx) => Ok(Some(tx)),
                Err(e) => {
                    tracing::error!(
                        "bincode deserialize failed for tx 0x{}: {} (data len={})",
                        hex::encode(hash.as_bytes()),
                        e,
                        bytes.len()
                    );
                    Err(e.into())
                }
            },
            Ok(None) => {
                tracing::debug!(
                    "tx 0x{} not found in CF_TRANSACTIONS",
                    hex::encode(hash.as_bytes())
                );
                Ok(None)
            }
            Err(_e) => {
                // Fallback: iterate CF to find the key (workaround for rare I/O errors)
                for (k, v) in self.db.iter_cf(CF_TRANSACTIONS)? {
                    if k.as_ref() == hash.as_bytes() {
                        let tx: Transaction = bincode::deserialize(&v)?;
                        return Ok(Some(tx));
                    }
                }
                Ok(None)
            }
        }
    }

    /// Check if transaction exists
    pub fn has_transaction(&self, hash: &Hash) -> Result<bool> {
        self.db.exists_cf(CF_TRANSACTIONS, hash.as_bytes())
    }

    /// Store a transaction receipt
    pub fn put_receipt(&self, tx_hash: &Hash, receipt: &TransactionReceipt) -> Result<()> {
        let receipt_bytes = bincode::serialize(receipt)?;
        self.db
            .put_cf(CF_RECEIPTS, tx_hash.as_bytes(), &receipt_bytes)?;

        // Index by block
        let block_tx_key = block_tx_key(&receipt.block_hash, tx_hash);
        self.db.put_cf(CF_METADATA, &block_tx_key, &[])?;

        debug!("Stored receipt for transaction {}", tx_hash);
        Ok(())
    }

    /// Store multiple receipts in batch
    pub fn put_receipts(&self, receipts: &[(Hash, TransactionReceipt)]) -> Result<()> {
        let mut batch = self.db.batch();

        for (tx_hash, receipt) in receipts {
            let receipt_bytes = bincode::serialize(receipt)?;
            self.db
                .batch_put_cf(&mut batch, CF_RECEIPTS, tx_hash.as_bytes(), &receipt_bytes)?;

            let block_tx_key = block_tx_key(&receipt.block_hash, tx_hash);
            self.db
                .batch_put_cf(&mut batch, CF_METADATA, &block_tx_key, &[])?;
        }

        // REM-2 / WP-H1.3 (audit M-API-01): producer-path commit MUST
        // fsync. Loss of a receipt for a finalised tx surfaces as
        // `eth_getTransactionReceipt` returning null for a confirmed
        // hash — exactly the cross-CF atomicity gap REM-2 calls out.
        self.db.write_batch_sync(batch)?;
        debug!("Stored {} receipts", receipts.len());
        Ok(())
    }

    /// Get a transaction receipt
    pub fn get_receipt(&self, tx_hash: &Hash) -> Result<Option<TransactionReceipt>> {
        match self.db.get_cf(CF_RECEIPTS, tx_hash.as_bytes())? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Get all transactions in a block
    pub fn get_block_transactions(&self, block_hash: &Hash) -> Result<Vec<Hash>> {
        let prefix = block_tx_prefix(block_hash);
        let mut tx_hashes = Vec::new();

        for (key, _) in self.db.prefix_iter_cf(CF_METADATA, &prefix)? {
            // Ensure the key actually starts with the expected prefix, since
            // RocksDB prefix iterator requires a configured prefix extractor.
            if let Some(tx_hash_bytes) = key
                .strip_prefix(prefix.as_slice())
                .filter(|r| !r.is_empty())
            {
                if tx_hash_bytes.len() == 32 {
                    let mut hash_array = [0u8; 32];
                    hash_array.copy_from_slice(tx_hash_bytes);
                    tx_hashes.push(Hash::new(hash_array));
                }
            }
        }

        Ok(tx_hashes)
    }

    /// Delete a transaction and its receipt
    pub fn delete_transaction(&self, hash: &Hash) -> Result<()> {
        let mut batch = self.db.batch();

        // Delete transaction
        self.db
            .batch_delete_cf(&mut batch, CF_TRANSACTIONS, hash.as_bytes())?;

        // Delete receipt if exists
        if let Some(receipt) = self.get_receipt(hash)? {
            self.db
                .batch_delete_cf(&mut batch, CF_RECEIPTS, hash.as_bytes())?;

            // Delete block index
            let block_tx_key = block_tx_key(&receipt.block_hash, hash);
            self.db
                .batch_delete_cf(&mut batch, CF_METADATA, &block_tx_key)?;
        }

        self.db.write_batch(batch)?;
        Ok(())
    }

    /// Compact transaction storage
    pub fn compact(&self) -> Result<()> {
        self.db.compact_cf(CF_TRANSACTIONS)?;
        self.db.compact_cf(CF_RECEIPTS)?;
        Ok(())
    }
}

/// C1-R: stage a [`ReceiptIndexBatch`] into `batch` with the producer's exact
/// layout (`put_transactions` + `put_receipts`), so the caller can commit it in the
/// same `write_batch_sync` as the block's state and applied-tip pointer.
///
/// Removals are staged FIRST: for each abandoned `(block, tx)` the `t‖block‖tx`
/// marker is deleted, and the receipt is deleted only when the stored receipt still
/// names that block (a receipt already moved to another block is left alone). Puts
/// follow, so a tx re-executed on the winning branch ends with its new receipt —
/// RocksDB applies a batch's operations in order.
pub(crate) fn stage_receipt_index(
    db: &RocksDB,
    batch: &mut rocksdb::WriteBatch,
    index: &ReceiptIndexBatch,
) -> Result<()> {
    for (block_hash, tx_hash) in &index.removals {
        db.batch_delete_cf(batch, CF_METADATA, &block_tx_key(block_hash, tx_hash))?;
        let remove = match read_stored_receipt(db, tx_hash)? {
            StoredReceipt::Absent => false,
            StoredReceipt::Decoded(stored) => stored.block_hash == *block_hash,
            // It cannot be served, and which block it names is unknown: it
            // leaves with the block it was indexed under. Never an error: the
            // receipt index must not decide whether a removal commits.
            StoredReceipt::Undecodable(e) => {
                warn!(
                    "C1-R: removing the undecodable stored receipt of {tx_hash} (indexed under {block_hash}): {e}"
                );
                true
            }
        };
        if remove {
            db.batch_delete_cf(batch, CF_RECEIPTS, tx_hash.as_bytes())?;
        }
    }
    for tx in &index.transactions {
        let tx_bytes = bincode::serialize(tx)?;
        db.batch_put_cf(batch, CF_TRANSACTIONS, tx.hash.as_bytes(), &tx_bytes)?;
        db.batch_put_cf(
            batch,
            CF_METADATA,
            &sender_tx_key(&tx.from, tx.nonce),
            tx.hash.as_bytes(),
        )?;
    }
    for receipt in &index.receipts {
        let receipt_bytes = bincode::serialize(receipt)?;
        db.batch_put_cf(
            batch,
            CF_RECEIPTS,
            receipt.tx_hash.as_bytes(),
            &receipt_bytes,
        )?;
        db.batch_put_cf(
            batch,
            CF_METADATA,
            &block_tx_key(&receipt.block_hash, &receipt.tx_hash),
            &[],
        )?;
    }
    match index.reconcile_marker {
        Some(ReceiptReconcileMarker::Set(hash, height)) => {
            db.batch_put_cf(
                batch,
                CF_METADATA,
                RECEIPT_RECONCILE_KEY,
                &encode_reconcile_marker(&hash, height),
            )?;
        }
        Some(ReceiptReconcileMarker::Clear) => {
            db.batch_delete_cf(batch, CF_METADATA, RECEIPT_RECONCILE_KEY)?;
        }
        None => {}
    }
    Ok(())
}

/// C1-R: a stored receipt as the receipt-index reconcile reads it. The index
/// is RPC data, not consensus data: a value that does not decode (damaged, or
/// written with a different receipt layout) is reported, not raised, so it can
/// never stop a reorg or a rebuild. Storage read errors stay errors.
#[derive(Debug)]
pub enum StoredReceipt {
    /// Nothing stored under the transaction hash.
    Absent,
    /// The stored receipt.
    Decoded(TransactionReceipt),
    /// A value is stored but does not decode as a receipt.
    Undecodable(bincode::Error),
}

fn read_stored_receipt(db: &RocksDB, tx_hash: &Hash) -> Result<StoredReceipt> {
    Ok(match db.get_cf(CF_RECEIPTS, tx_hash.as_bytes())? {
        None => StoredReceipt::Absent,
        Some(bytes) => match bincode::deserialize(&bytes) {
            Ok(r) => StoredReceipt::Decoded(r),
            Err(e) => StoredReceipt::Undecodable(e),
        },
    })
}

/// C1-R: `CF_METADATA` key of the [`ReceiptReconcileMarker`] (value: block hash
/// `[32]` ‖ height big-endian `[8]`, the applied-tip layout).
const RECEIPT_RECONCILE_KEY: &[u8] = b"receipt_reconcile_from";

fn encode_reconcile_marker(hash: &Hash, height: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(40);
    buf.extend_from_slice(hash.as_bytes());
    buf.extend_from_slice(&height.to_be_bytes());
    buf
}

impl TransactionStore {
    /// C1-R: the stored receipt of `tx_hash` for the receipt-index reconcile:
    /// like [`Self::get_receipt`], but a value that does not decode is
    /// [`StoredReceipt::Undecodable`] instead of an error. A read error is
    /// still an error.
    pub fn get_stored_receipt(&self, tx_hash: &Hash) -> Result<StoredReceipt> {
        read_stored_receipt(&self.db, tx_hash)
    }

    /// C1-R: visit every `(block_hash, tx_hash)` entry of the block→transaction
    /// index (the `t‖block‖tx` markers written with each receipt), in key order,
    /// so the entries of one block arrive together. Streams the index instead of
    /// collecting it, so a scan of the whole chain's index holds one key at a
    /// time. Used to reconcile the receipt index against an applied chain when
    /// the old chain can no longer be walked block by block. A read error (or an
    /// `Err` from `visit`) ends the scan and is returned, never skipped.
    pub fn for_each_receipt_index_entry(
        &self,
        mut visit: impl FnMut(Hash, Hash) -> Result<()>,
    ) -> Result<()> {
        self.db.for_each_prefix_key_cf(CF_METADATA, b"t", |key| {
            let Some(rest) = key.strip_prefix(b"t".as_slice()) else {
                return Ok(());
            };
            if rest.len() != 64 {
                return Ok(()); // another metadata key that happens to start with `t`
            }
            let (block, tx) = rest.split_at(32);
            match (<[u8; 32]>::try_from(block), <[u8; 32]>::try_from(tx)) {
                (Ok(block), Ok(tx)) => visit(Hash::new(block), Hash::new(tx)),
                _ => Ok(()),
            }
        })
    }

    /// C1-R: the old applied tip recorded by an unfinished from-genesis rebuild
    /// (see [`ReceiptReconcileMarker`]), if any. A malformed value reads as absent.
    pub fn get_receipt_reconcile_marker(&self) -> Result<Option<(Hash, u64)>> {
        let Some(bytes) = self.db.get_cf(CF_METADATA, RECEIPT_RECONCILE_KEY)? else {
            return Ok(None);
        };
        let Some((hash, height)) = bytes.split_at_checked(32) else {
            return Ok(None);
        };
        match (<[u8; 32]>::try_from(hash), <[u8; 8]>::try_from(height)) {
            (Ok(hash), Ok(height)) => Ok(Some((Hash::new(hash), u64::from_be_bytes(height)))),
            _ => Ok(None),
        }
    }
}

// Key generation helpers
fn sender_tx_key(sender: &citrate_consensus::types::PublicKey, nonce: u64) -> Vec<u8> {
    let mut key = vec![b's'];
    key.extend_from_slice(sender.as_bytes());
    key.extend_from_slice(&nonce.to_be_bytes());
    key
}

fn block_tx_key(block_hash: &Hash, tx_hash: &Hash) -> Vec<u8> {
    let mut key = vec![b't'];
    key.extend_from_slice(block_hash.as_bytes());
    key.extend_from_slice(tx_hash.as_bytes());
    key
}

fn block_tx_prefix(block_hash: &Hash) -> Vec<u8> {
    let mut prefix = vec![b't'];
    prefix.extend_from_slice(block_hash.as_bytes());
    prefix
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_consensus::types::{PublicKey, Signature};
    use citrate_execution::types::Address;
    use tempfile::TempDir;

    fn create_test_transaction(nonce: u64) -> Transaction {
        Transaction {
            hash: Hash::new([nonce as u8; 32]),
            nonce,
            from: PublicKey::new([1; 32]),
            to: Some(PublicKey::new([2; 32])),
            value: 1000,
            gas_limit: 100000,
            gas_price: 1000000000,
            data: vec![],
            signature: Signature::new([1; 64]),
            tx_type: None,
            ..Default::default()
        }
    }

    fn create_test_receipt(tx_hash: Hash, block_hash: Hash) -> TransactionReceipt {
        TransactionReceipt {
            tx_hash,
            block_hash,
            block_number: 1,
            from: Address([1; 20]),
            to: Some(Address([2; 20])),
            gas_used: 21000,
            status: true,
            logs: vec![],
            output: vec![],
            eth_tx_type: 0,
            effective_gas_price: 0,
            revert_reason: None,
        }
    }

    #[test]
    fn test_transaction_storage() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(RocksDB::open(temp_dir.path()).unwrap());
        let store = TransactionStore::new(db);

        // Store transaction
        let tx = create_test_transaction(1);
        store.put_transaction(&tx).unwrap();

        // Check existence
        assert!(store.has_transaction(&tx.hash).unwrap());
    }

    #[test]
    fn test_receipt_storage() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(RocksDB::open(temp_dir.path()).unwrap());
        let store = TransactionStore::new(db);

        let tx_hash = Hash::new([1; 32]);
        let block_hash = Hash::new([2; 32]);
        let receipt = create_test_receipt(tx_hash, block_hash);

        // Store receipt
        store.put_receipt(&tx_hash, &receipt).unwrap();

        // Retrieve receipt
        let retrieved = store.get_receipt(&tx_hash).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().block_hash, block_hash);

        // Get block transactions
        let block_txs = store.get_block_transactions(&block_hash).unwrap();
        assert_eq!(block_txs.len(), 1);
        assert_eq!(block_txs[0], tx_hash);
    }

    /// Make the stored receipt of `tx` undecodable (its encoding minus the last
    /// byte).
    fn corrupt_receipt(db: &RocksDB, tx: &Hash) {
        let mut bytes = db.get_cf(CF_RECEIPTS, tx.as_bytes()).unwrap().unwrap();
        bytes.pop();
        db.put_cf(CF_RECEIPTS, tx.as_bytes(), &bytes).unwrap();
    }

    /// A removal whose stored receipt does not decode still commits: the marker
    /// and the receipt both go, and staging never fails on it. Negative
    /// controls: a decodable receipt that names another block is kept, and one
    /// that names the removed block goes.
    #[test]
    fn stage_removal_drops_an_undecodable_receipt_without_failing() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(RocksDB::open(temp_dir.path()).unwrap());
        let store = TransactionStore::new(db.clone());
        let block_a = Hash::new([0xA; 32]);
        let block_b = Hash::new([0xB; 32]);
        let (bad, moved, own) = (Hash::new([1; 32]), Hash::new([2; 32]), Hash::new([3; 32]));
        store
            .put_receipts(&[
                (bad, create_test_receipt(bad, block_a)),
                (moved, create_test_receipt(moved, block_b)),
                (own, create_test_receipt(own, block_a)),
            ])
            .unwrap();
        corrupt_receipt(&db, &bad);
        assert!(store.get_receipt(&bad).is_err(), "precondition");
        assert!(matches!(
            store.get_stored_receipt(&bad).unwrap(),
            StoredReceipt::Undecodable(_)
        ));
        assert!(matches!(
            store.get_stored_receipt(&Hash::new([9; 32])).unwrap(),
            StoredReceipt::Absent
        ));

        let index = ReceiptIndexBatch {
            removals: vec![(block_a, bad), (block_a, moved), (block_a, own)],
            ..ReceiptIndexBatch::default()
        };
        let mut batch = rocksdb::WriteBatch::default();
        stage_receipt_index(&db, &mut batch, &index).expect("staging does not fail");
        db.write_batch_sync(batch).unwrap();

        assert!(matches!(
            store.get_stored_receipt(&bad).unwrap(),
            StoredReceipt::Absent
        ));
        assert!(store.get_receipt(&own).unwrap().is_none());
        assert_eq!(
            store.get_receipt(&moved).unwrap().map(|r| r.block_hash),
            Some(block_b),
            "a receipt that names another block is kept"
        );
        assert!(store.get_block_transactions(&block_a).unwrap().is_empty());
    }

    /// The index scan streams: an `Err` from the visitor ends it at once and is
    /// returned.
    #[test]
    fn receipt_index_scan_stops_on_a_visitor_error() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(RocksDB::open(temp_dir.path()).unwrap());
        let store = TransactionStore::new(db.clone());
        let block = Hash::new([0xA; 32]);
        let txs: Vec<Hash> = (1..=3u8).map(|i| Hash::new([i; 32])).collect();
        let receipts: Vec<_> = txs
            .iter()
            .map(|t| (*t, create_test_receipt(*t, block)))
            .collect();
        store.put_receipts(&receipts).unwrap();
        let mut seen = 0u32;
        let res = store.for_each_receipt_index_entry(|_, _| {
            seen += 1;
            anyhow::bail!("stop")
        });
        assert!(res.is_err());
        assert_eq!(seen, 1);
    }

    /// The full block→transaction index scan returns exactly the `t‖block‖tx`
    /// entries, across blocks, and skips other metadata keys that start with
    /// `t` (negative control: a key of a different length, and a `u` key).
    #[test]
    fn receipt_index_entries_lists_every_block_tx_marker_only() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(RocksDB::open(temp_dir.path()).unwrap());
        let store = TransactionStore::new(db.clone());
        let block_a = Hash::new([0xA; 32]);
        let block_b = Hash::new([0xB; 32]);
        let (t1, t2, t3) = (Hash::new([1; 32]), Hash::new([2; 32]), Hash::new([3; 32]));
        store
            .put_receipts(&[
                (t1, create_test_receipt(t1, block_a)),
                (t2, create_test_receipt(t2, block_a)),
                (t3, create_test_receipt(t3, block_b)),
            ])
            .unwrap();
        db.put_cf(CF_METADATA, b"tip_like_key", b"x").unwrap();
        let mut long = block_tx_key(&block_a, &t1);
        long.push(0);
        db.put_cf(CF_METADATA, &long, &[]).unwrap();
        db.put_cf(CF_METADATA, &[b'u'; 65], &[]).unwrap();
        let mut got = Vec::new();
        store
            .for_each_receipt_index_entry(|b, t| {
                got.push((b, t));
                Ok(())
            })
            .unwrap();
        got.sort();
        let mut want = vec![(block_a, t1), (block_a, t2), (block_b, t3)];
        want.sort();
        assert_eq!(got, want);
    }

    #[test]
    fn test_block_tx_prefix_roundtrip_multiple_blocks() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(RocksDB::open(temp_dir.path()).unwrap());
        let store = TransactionStore::new(db);

        // Two blocks, two transactions each
        let block_a = Hash::new([0xA; 32]);
        let block_b = Hash::new([0xB; 32]);

        let tx_a1 = create_test_transaction(10);
        let tx_a2 = create_test_transaction(11);
        let tx_b1 = create_test_transaction(20);
        let tx_b2 = create_test_transaction(21);

        store.put_transaction(&tx_a1).unwrap();
        store.put_transaction(&tx_a2).unwrap();
        store.put_transaction(&tx_b1).unwrap();
        store.put_transaction(&tx_b2).unwrap();

        // Receipts map tx → block
        let rc_a1 = create_test_receipt(tx_a1.hash, block_a);
        let rc_a2 = create_test_receipt(tx_a2.hash, block_a);
        let rc_b1 = create_test_receipt(tx_b1.hash, block_b);
        let rc_b2 = create_test_receipt(tx_b2.hash, block_b);
        store.put_receipt(&tx_a1.hash, &rc_a1).unwrap();
        store.put_receipt(&tx_a2.hash, &rc_a2).unwrap();
        store.put_receipt(&tx_b1.hash, &rc_b1).unwrap();
        store.put_receipt(&tx_b2.hash, &rc_b2).unwrap();

        let block_a_txs = store.get_block_transactions(&block_a).unwrap();
        let block_b_txs = store.get_block_transactions(&block_b).unwrap();

        assert_eq!(block_a_txs.len(), 2);
        assert!(block_a_txs.contains(&tx_a1.hash));
        assert!(block_a_txs.contains(&tx_a2.hash));
        assert_eq!(block_b_txs.len(), 2);
        assert!(block_b_txs.contains(&tx_b1.hash));
        assert!(block_b_txs.contains(&tx_b2.hash));
    }
}
