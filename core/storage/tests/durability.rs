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
        revert_reason: None,
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
        body.contains("write_state_batch_sync")
            || body.contains("write_state_batch_with_applied_tip"),
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

// ---------------------------------------------------------------------------
// #126 / #32 — crash-consistent REORG store reconciliation.
//
// The linear/produce commit path was already crash-consistent (state + tip in
// one fsync'd batch). The REORG path was NOT: `reconcile_store_from` wrote the
// account/storage diff in a sync batch WITHOUT the tip, then advanced the applied
// tip via a SEPARATE non-fsync `put_cf`, with account-deletes and code as further
// separate point writes. A kill-9 between the synced state batch and the tip write
// left the durable tip out of step with durable state → genesis-replay + fork on
// restart. Fix: accounts + storage + account-deletes + code + applied-tip all commit
// in ONE `write_batch_sync`, so there is NO window in which they can tear.
// ---------------------------------------------------------------------------

/// #32 (the uncovered path): a reorg reconcile that PUTS an account, DELETES an
/// abandoned-branch account, writes new contract STORAGE + CODE, and advances the
/// APPLIED TIP must commit as exactly ONE fsync'd batch (no torn window), and after
/// reopening the store the flat state AND the applied tip must be mutually consistent
/// (both post-reorg) with the tip at the true last-durable value (no genesis fallback).
#[tokio::test]
async fn test_126_reorg_reconcile_commits_state_and_tip_in_one_sync_batch() {
    let temp = TempDir::new().expect("temp dir");
    let account_a = Address([0xA1; 20]); // modified on the winning branch
    let account_b = Address([0xB2; 20]); // abandoned-branch account → DELETED on reorg
    let contract_c = Address([0xCC; 20]); // new contract on the winning branch
    let slot_key = vec![0x01u8; 32];
    let slot_val = vec![0x02u8; 32];
    let code = vec![0x60u8, 0x00, 0x60, 0x00, 0xF3]; // trivial bytecode
    let new_tip_hash = Hash::new([0x7E; 32]);
    let new_tip_height = 424_242u64;

    let (code_hash, sync_delta, nosync_delta) = {
        let db = Arc::new(RocksDB::open(temp.path()).expect("open db"));
        let store = Arc::new(StateStore::new(db.clone()));
        let state_db = Arc::new(StateDB::new());
        let executor = Executor::with_storage(state_db.clone(), Some(store.clone()));

        // FORK-POINT world: A=100 and B=200, fully persisted (the store's baseline).
        state_db.accounts.set_balance(account_a, U256::from(100u64));
        // Snapshot with only A resident — used later to make B non-resident (deleted).
        let snap_only_a = state_db.snapshot();
        state_db.accounts.set_balance(account_b, U256::from(200u64));
        let baseline = state_db.snapshot(); // fork point == what the store reflects
        executor
            .persist_state_changes()
            .await
            .expect("persist fork-point state");

        // WINNING branch in-memory: drop B (restore the A-only set), bump A, and deploy
        // contract C with one storage slot and code.
        state_db.restore(snap_only_a);
        state_db.accounts.set_balance(account_a, U256::from(150u64));
        state_db.accounts.set_balance(contract_c, U256::from(300u64));
        let code_hash = state_db.set_code(contract_c, code.clone());
        state_db.set_storage(contract_c, slot_key.clone(), slot_val.clone());

        // The reorg commit: exactly ONE fsync'd batch carrying puts + delete + code + tip.
        let sync_before = db.write_batch_sync_count();
        let nosync_before = db.write_batch_count();
        executor
            .reconcile_store_from(&baseline, Some((new_tip_hash, new_tip_height)))
            .expect("reorg reconcile");
        let sync_delta = db.write_batch_sync_count() - sync_before;
        let nosync_delta = db.write_batch_count() - nosync_before;
        (code_hash, sync_delta, nosync_delta)
        // executor / store / state_db / db all drop here → RocksDB closes.
    };

    assert_eq!(
        sync_delta, 1,
        "#126: the whole reorg reconcile (accounts + storage + delete + code + tip) \
         must commit as ONE fsync'd batch — no torn window. Got sync_delta={}, nosync_delta={}",
        sync_delta, nosync_delta
    );
    assert_eq!(
        nosync_delta, 0,
        "#126: the reorg reconcile must not use the non-fsync write_batch path (a crash \
         could then roll back part of the commit). Got sync_delta={}, nosync_delta={}",
        sync_delta, nosync_delta
    );

    // REOPEN from disk (models the post-kill-9 restart) and assert durable state AND
    // durable tip are consistent — both post-reorg, never torn.
    let db2 = Arc::new(RocksDB::open(temp.path()).expect("reopen db"));
    let store2 = StateStore::new(db2.clone());
    let blocks2 = BlockStore::new(db2.clone());

    assert_eq!(
        store2.get_account(&account_a).expect("get A").expect("A present").balance,
        U256::from(150u64),
        "#126: winning-branch account update is durable"
    );
    assert!(
        store2.get_account(&account_b).expect("get B").is_none(),
        "#126: abandoned-branch account was deleted in the same atomic batch"
    );
    assert_eq!(
        store2.get_account(&contract_c).expect("get C").expect("C present").balance,
        U256::from(300u64),
        "#126: new contract account is durable"
    );
    assert_eq!(
        store2.get_storage(&contract_c, &slot_key).expect("get C storage"),
        Some(slot_val),
        "#126: new contract storage slot is durable"
    );
    assert_eq!(
        store2.get_code(&code_hash).expect("get code"),
        Some(code),
        "#126: contract code landed in the SAME atomic batch (not a separate point write)"
    );
    assert_eq!(
        blocks2.get_applied_tip().expect("get applied tip"),
        Some((new_tip_hash, new_tip_height)),
        "#126: the durable applied tip advanced to the winning tip IN the same batch — \
         so a restart resumes at the true last-durable tip, never a stale one (no genesis fallback)"
    );
}

/// #126: `Executor::reconcile_store_from` must route the whole reorg commit through the
/// single atomic `write_reorg_batch_sync` — NOT through separate `store.delete_account`
/// / `store.put_code` / `store.write_state_batch_sync` point writes, and NOT via a
/// separate applied-tip write. Analogous to
/// `test_k1_1_executor_persist_state_changes_has_no_direct_point_writes`.
#[test]
fn test_126_reconcile_store_from_has_no_direct_point_writes() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../execution/src/executor.rs"
    ))
    .expect("read executor source");
    let start = source
        .find("pub fn reconcile_store_from")
        .expect("reconcile_store_from exists");
    // The function ends at the next item doc-comment after its body.
    let end = source[start..]
        .find("/// EXECUTE-ON-RECEIVE — the verified")
        .map(|offset| start + offset)
        .expect("reconcile_store_from section end");
    let body = &source[start..end];

    assert!(
        body.contains("write_reorg_batch_sync"),
        "#126: reconcile_store_from must commit via the atomic write_reorg_batch_sync"
    );
    assert!(
        !body.contains("store.write_state_batch_sync(")
            && !body.contains("store.delete_account(")
            && !body.contains("store.put_code("),
        "#126: reconcile_store_from must not issue separate point writes for state / \
         account-deletes / code — they must all go through the one atomic batch"
    );
    assert!(
        !body.contains("put_applied_tip"),
        "#126: reconcile_store_from must not advance the tip via a separate (non-atomic) \
         write — the tip is threaded into write_reorg_batch_sync"
    );
}
