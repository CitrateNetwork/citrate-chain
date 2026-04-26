//! REM-2 / WP-H1.3 (audit M-API-01) — producer-path durability tests.
//!
//! The re-audit (`.audit/2026-04-25-reaudit/04_FINDINGS_API_NETWORK_STORAGE.md`,
//! finding REM-2) identified that `RocksDB::write_batch_sync` was added in
//! Phase C with zero production callers. `block_store::put_block`,
//! `transaction_store::put_transactions`, `transaction_store::put_receipts`,
//! and `node::persistent_dag::kv_write_batch` all called the non-fsync
//! `write_batch` variant. A power loss between RPC ack and OS flush could
//! silently roll back finalised state.
//!
//! These tests assert that producer-path writers go through the durable
//! `write_batch_sync` path, observed via the atomic counters on `RocksDB`.

use citrate_consensus::types::{Block, BlockBuilder, Hash, PublicKey, Signature, Transaction};
use citrate_execution::executor::Executor;
use citrate_execution::types::{Address, TransactionReceipt};
use citrate_execution::StateDB;
use citrate_storage::chain::{BlockStore, TransactionStore};
use citrate_storage::db::RocksDB;
use citrate_storage::state::StateStore;
use primitive_types::U256;
use std::sync::Arc;
use tempfile::TempDir;

fn fresh_db() -> (TempDir, Arc<RocksDB>) {
    let temp_dir = TempDir::new().expect("temp dir creation should succeed");
    let db = Arc::new(RocksDB::open(temp_dir.path()).expect("RocksDB open should succeed"));
    (temp_dir, db)
}

fn make_block(height: u64, parent: Hash) -> Block {
    BlockBuilder::new()
        .hash(Hash::new([height as u8; 32]))
        .parent(parent)
        .height(height)
        .timestamp(1_000_000 + height)
        .blue_score(height * 10)
        .blue_work(height as u128 * 100)
        .proposer(PublicKey::new([1; 32]))
        .build_unhashed()
}

fn make_tx(nonce: u64) -> Transaction {
    Transaction {
        hash: Hash::new([nonce as u8; 32]),
        nonce,
        from: PublicKey::new([1; 32]),
        to: Some(PublicKey::new([2; 32])),
        value: 1000,
        gas_limit: 100_000,
        gas_price: 1_000_000_000,
        data: vec![],
        signature: Signature::new([1; 64]),
        tx_type: None,
        ..Default::default()
    }
}

fn make_receipt(tx_hash: Hash, block_hash: Hash) -> TransactionReceipt {
    TransactionReceipt {
        tx_hash,
        block_hash,
        block_number: 1,
        from: Address([1; 20]),
        to: Some(Address([2; 20])),
        gas_used: 21_000,
        status: true,
        logs: vec![],
        output: vec![],
        eth_tx_type: 0,
        effective_gas_price: 0,
    }
}

/// REM-2 / WP-H1.3: `BlockStore::put_block` is a producer-path commit.
/// It must commit the WriteBatch via `write_batch_sync`, not `write_batch`.
#[test]
fn test_rem_2_block_store_uses_write_batch_sync() {
    let (_temp, db) = fresh_db();
    let store = BlockStore::new(db.clone());

    let sync_before = db.write_batch_sync_count();
    let nosync_before = db.write_batch_count();

    let block = make_block(1, Hash::default());
    store.put_block(&block).expect("put_block should succeed");

    let sync_after = db.write_batch_sync_count();
    let nosync_after = db.write_batch_count();

    let sync_delta = sync_after - sync_before;
    let nosync_delta = nosync_after - nosync_before;

    assert!(
        sync_delta >= 1,
        "REM-2: BlockStore::put_block must commit via write_batch_sync \
         for producer-finality durability against power loss \
         (got sync_delta={}, nosync_delta={})",
        sync_delta,
        nosync_delta
    );
    assert_eq!(
        nosync_delta, 0,
        "REM-2: BlockStore::put_block must NOT use the non-fsync \
         write_batch path on the producer-finality commit \
         (got sync_delta={}, nosync_delta={})",
        sync_delta, nosync_delta
    );
}

/// K1.1: `Executor::persist_state_changes` is a producer-finalized state
/// commit. Account and storage mutations must land in one durable RocksDB
/// WriteBatch rather than a loop of point writes.
#[tokio::test]
async fn test_k1_1_executor_state_persist_uses_one_sync_batch() {
    let (_temp, db) = fresh_db();
    let store = Arc::new(StateStore::new(db.clone()));
    let state_db = Arc::new(StateDB::new());
    let executor = Executor::with_storage(state_db.clone(), Some(store.clone()));
    let address = Address([0xAB; 20]);
    let storage_key = vec![0x11; 32];
    let storage_value = vec![0x22; 32];

    state_db.accounts.set_balance(address, U256::from(1_234u64));
    state_db.set_storage(address, storage_key.clone(), storage_value.clone());

    let sync_before = db.write_batch_sync_count();
    let nosync_before = db.write_batch_count();
    let persisted = executor
        .persist_state_changes()
        .await
        .expect("persist finalized state");

    assert_eq!(persisted, 2, "one account plus one storage slot");
    assert_eq!(
        db.write_batch_sync_count() - sync_before,
        1,
        "K1.1: finalized account/storage state must commit as one sync batch"
    );
    assert_eq!(
        db.write_batch_count() - nosync_before,
        0,
        "K1.1: finalized state must not use non-fsync write_batch"
    );
    assert_eq!(
        store
            .get_account(&address)
            .expect("get account")
            .expect("persisted account")
            .balance,
        U256::from(1_234u64)
    );
    assert_eq!(
        store
            .get_storage(&address, &storage_key)
            .expect("get storage")
            .expect("persisted storage"),
        storage_value
    );

    state_db.delete_storage(address, &storage_key);
    let sync_before_delete = db.write_batch_sync_count();
    let deleted = executor
        .persist_state_changes()
        .await
        .expect("persist storage delete");
    assert_eq!(deleted, 1, "one storage deletion");
    assert_eq!(
        db.write_batch_sync_count() - sync_before_delete,
        1,
        "K1.1: storage deletion must also use the durable batch path"
    );
    assert!(
        store
            .get_storage(&address, &storage_key)
            .expect("get deleted storage")
            .is_none(),
        "storage slot should be deleted after durable batch"
    );
}

#[test]
fn test_k1_1_executor_persist_state_changes_has_no_direct_point_writes() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../execution/src/executor.rs"
    ))
    .expect("read executor source");
    let start = source
        .find("pub async fn persist_state_changes")
        .expect("persist_state_changes exists");
    let end = source[start..]
        .find("/// Store raw artifact bytes")
        .map(|offset| start + offset)
        .expect("persist_state_changes section end");
    let body = &source[start..end];

    assert!(
        body.contains("write_state_batch_sync"),
        "K1.1: Executor must route finalized state through the batch API"
    );
    assert!(
        !body.contains("store.put_account(")
            && !body.contains("store.put_storage(")
            && !body.contains("store.delete_storage("),
        "K1.1: Executor producer persistence must not use direct point writes"
    );
}

/// REM-2 / WP-H1.3: `TransactionStore::put_transactions` is a
/// producer-path commit (block-finality tx index). It must commit
/// via `write_batch_sync`.
#[test]
fn test_rem_2_transaction_store_put_transactions_uses_write_batch_sync() {
    let (_temp, db) = fresh_db();
    let store = TransactionStore::new(db.clone());

    let sync_before = db.write_batch_sync_count();
    let nosync_before = db.write_batch_count();

    let txs = vec![make_tx(1), make_tx(2)];
    store
        .put_transactions(&txs)
        .expect("put_transactions should succeed");

    let sync_delta = db.write_batch_sync_count() - sync_before;
    let nosync_delta = db.write_batch_count() - nosync_before;

    assert!(
        sync_delta >= 1,
        "REM-2: put_transactions must commit via write_batch_sync \
         (got sync_delta={}, nosync_delta={})",
        sync_delta,
        nosync_delta
    );
    assert_eq!(
        nosync_delta, 0,
        "REM-2: put_transactions must NOT use non-fsync write_batch \
         (got sync_delta={}, nosync_delta={})",
        sync_delta, nosync_delta
    );
}

/// REM-2 / WP-H1.3: `TransactionStore::put_receipts` is the
/// finality-receipt commit. Loss here surfaces as
/// `eth_getTransactionReceipt` returning null for a finalised tx.
/// Must commit via `write_batch_sync`.
#[test]
fn test_rem_2_transaction_store_put_receipts_uses_write_batch_sync() {
    let (_temp, db) = fresh_db();
    let store = TransactionStore::new(db.clone());

    let sync_before = db.write_batch_sync_count();
    let nosync_before = db.write_batch_count();

    let block_hash = Hash::new([0xAA; 32]);
    let tx_hash = Hash::new([1; 32]);
    let receipts = vec![(tx_hash, make_receipt(tx_hash, block_hash))];
    store
        .put_receipts(&receipts)
        .expect("put_receipts should succeed");

    let sync_delta = db.write_batch_sync_count() - sync_before;
    let nosync_delta = db.write_batch_count() - nosync_before;

    assert!(
        sync_delta >= 1,
        "REM-2: put_receipts must commit via write_batch_sync \
         (got sync_delta={}, nosync_delta={})",
        sync_delta,
        nosync_delta
    );
    assert_eq!(
        nosync_delta, 0,
        "REM-2: put_receipts must NOT use non-fsync write_batch \
         (got sync_delta={}, nosync_delta={})",
        sync_delta, nosync_delta
    );
}

/// REM-2 / WP-H1.3: end-to-end producer-finality bundle exercises
/// all three stores in sequence. After committing block + tx index +
/// receipts, the sync counter must have advanced by ≥3 and the
/// non-sync counter must remain at 0.
#[test]
fn test_rem_2_producer_finality_bundle_all_fsynced() {
    let (_temp, db) = fresh_db();
    let blocks = BlockStore::new(db.clone());
    let txs = TransactionStore::new(db.clone());

    let sync_before = db.write_batch_sync_count();
    let nosync_before = db.write_batch_count();

    let block = make_block(1, Hash::default());
    let tx = make_tx(1);
    let receipt = make_receipt(tx.hash, block.hash());

    blocks.put_block(&block).expect("put_block");
    txs.put_transactions(std::slice::from_ref(&tx))
        .expect("put_transactions");
    txs.put_receipts(&[(tx.hash, receipt)])
        .expect("put_receipts");

    let sync_delta = db.write_batch_sync_count() - sync_before;
    let nosync_delta = db.write_batch_count() - nosync_before;

    assert!(
        sync_delta >= 3,
        "REM-2: producer-finality bundle (block + tx + receipt) must \
         issue at least 3 write_batch_sync calls — one per store. \
         Got sync_delta={}, nosync_delta={}",
        sync_delta,
        nosync_delta
    );
    assert_eq!(
        nosync_delta, 0,
        "REM-2: no producer-finality write may use the non-fsync \
         write_batch path. Got sync_delta={}, nosync_delta={}",
        sync_delta, nosync_delta
    );
}
