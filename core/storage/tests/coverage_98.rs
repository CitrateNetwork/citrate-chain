// WP-RR.8: Comprehensive integration tests targeting 98% coverage for citrate-storage.
//
// Key coverage gaps addressed:
//   - state_store.rs (36% -> ~98%): all CRUD ops, models, training jobs, snapshots, compact
//   - state_manager.rs (58% -> ~98%): register model, update weights, training jobs, LoRA,
//     inference cache, prune, stats, state root calculation
//   - block_store.rs (78% -> ~98%): put/get/delete, height index, children, tips, blue score,
//     latest height edge cases, compaction
//   - transaction_store.rs (75% -> ~98%): put/get/delete, batch, receipts, block tx index,
//     has_transaction, compact

use citrate_consensus::types::{
    Block, BlockHeader, GhostDagParams, Hash, PublicKey, Signature, Transaction, VrfProof,
};
use citrate_execution::types::{
    AccessPolicy, AccountState, Address, JobStatus, ModelMetadata, ModelState, TrainingJob,
    TransactionReceipt, UsageStats,
};
use citrate_execution::{JobId, ModelId};
use citrate_storage::chain::{BlockStore, TransactionStore};
use citrate_storage::db::RocksDB;
use citrate_storage::pruning::PruningConfig;
use citrate_storage::state::StateStore;
use citrate_storage::state_manager::StateManager;
use citrate_storage::{StorageConfig, StorageManager};
use primitive_types::U256;
use std::sync::Arc;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn open_db() -> (TempDir, Arc<RocksDB>) {
    let tmp = TempDir::new().unwrap();
    let db = Arc::new(RocksDB::open(tmp.path()).unwrap());
    (tmp, db)
}

fn make_address(byte: u8) -> Address {
    Address([byte; 20])
}

fn make_account(nonce: u64, balance: u128) -> AccountState {
    AccountState {
        nonce,
        balance: U256::from(balance),
        storage_root: Hash::default(),
        code_hash: Hash::default(),
        model_permissions: vec![],
    }
}

fn make_model_state(owner_byte: u8) -> ModelState {
    ModelState {
        owner: make_address(owner_byte),
        model_hash: Hash::new([owner_byte; 32]),
        version: 1,
        metadata: ModelMetadata {
            name: format!("Model-{}", owner_byte),
            version: "1.0".to_string(),
            description: "Test model".to_string(),
            framework: "PyTorch".to_string(),
            input_shape: vec![1, 3, 224, 224],
            output_shape: vec![1, 1000],
            size_bytes: 100_000,
            created_at: 1_700_000_000,
        },
        access_policy: AccessPolicy::Public,
        usage_stats: UsageStats::default(),
    }
}

fn make_training_job(id_byte: u8, model_byte: u8, owner_byte: u8) -> TrainingJob {
    TrainingJob {
        id: JobId(Hash::new([id_byte; 32])),
        owner: make_address(owner_byte),
        model_id: ModelId(Hash::new([model_byte; 32])),
        dataset_hash: Hash::new([id_byte.wrapping_add(1); 32]),
        participants: vec![make_address(owner_byte)],
        gradients_submitted: 0,
        gradients_required: 10,
        reward_pool: U256::from(1000u64),
        status: JobStatus::Pending,
        created_at: 1_700_000_000,
        completed_at: None,
    }
}

fn make_block(num: u8, height: u64, parent: Hash) -> Block {
    Block {
        header: BlockHeader {
            version: 1,
            block_hash: Hash::new([num; 32]),
            selected_parent_hash: parent,
            merge_parent_hashes: vec![],
            timestamp: 1_000_000 + height,
            height,
            blue_score: height * 10,
            blue_work: height as u128 * 100,
            pruning_point: Hash::default(),
            proposer_pubkey: PublicKey::new([1; 32]),
            vrf_reveal: VrfProof {
                proof: vec![],
                output: Hash::default(),
            },
            base_fee_per_gas: 0,
            gas_used: 0,
            gas_limit: 30_000_000,
        },
        state_root: Hash::default(),
        tx_root: Hash::default(),
        receipt_root: Hash::default(),
        artifact_root: Hash::default(),
        ghostdag_params: GhostDagParams::default(),
        transactions: vec![],
        signature: Signature::new([0; 64]),
        embedded_models: vec![],
        required_pins: vec![],
        learning_embedding: None,
        learning_confidence: None,
        gradient_commitment: None,
            learning_root: Hash::default(),
    }
}

fn make_block_with_merge(num: u8, height: u64, parent: Hash, merge: Vec<Hash>) -> Block {
    let mut block = make_block(num, height, parent);
    block.header.merge_parent_hashes = merge;
    block
}

fn make_tx(nonce: u64) -> Transaction {
    Transaction {
        hash: Hash::new([nonce as u8; 32]),
        nonce,
        from: PublicKey::new([1; 32]),
        to: Some(PublicKey::new([2; 32])),
        value: 1000 + nonce as u128,
        gas_limit: 21_000,
        gas_price: 1_000_000_000,
        data: vec![],
        signature: Signature::new([nonce as u8; 64]),
        tx_type: None,
        ..Default::default()
    }
}

fn make_receipt(tx_hash: Hash, block_hash: Hash, block_number: u64) -> TransactionReceipt {
    TransactionReceipt {
        tx_hash,
        block_hash,
        block_number,
        from: make_address(1),
        to: Some(make_address(2)),
        gas_used: 21_000,
        status: true,
        logs: vec![],
        output: vec![],
        eth_tx_type: 0,
        effective_gas_price: 0,
    }
}

// ===========================================================================
// STATE STORE TESTS
// ===========================================================================

#[test]
fn state_store_account_crud() {
    let (_tmp, db) = open_db();
    let store = StateStore::new(db);

    let addr = make_address(0xAA);
    let acct = make_account(5, 10_000);

    // Put + Get
    store.put_account(&addr, &acct).unwrap();
    let got = store.get_account(&addr).unwrap().unwrap();
    assert_eq!(got.nonce, 5);
    assert_eq!(got.balance, U256::from(10_000u64));

    // Overwrite
    let acct2 = make_account(10, 20_000);
    store.put_account(&addr, &acct2).unwrap();
    let got2 = store.get_account(&addr).unwrap().unwrap();
    assert_eq!(got2.nonce, 10);

    // Delete
    store.delete_account(&addr).unwrap();
    assert!(store.get_account(&addr).unwrap().is_none());
}

#[test]
fn state_store_get_nonexistent_account() {
    let (_tmp, db) = open_db();
    let store = StateStore::new(db);
    let result = store.get_account(&make_address(0xFF)).unwrap();
    assert!(result.is_none());
}

#[test]
fn state_store_get_all_accounts() {
    let (_tmp, db) = open_db();
    let store = StateStore::new(db);

    // Empty initially
    let all = store.get_all_accounts().unwrap();
    assert!(all.is_empty());

    // Insert 3 accounts
    for i in 1..=3u8 {
        store
            .put_account(&make_address(i), &make_account(i as u64, i as u128 * 100))
            .unwrap();
    }

    let all = store.get_all_accounts().unwrap();
    assert_eq!(all.len(), 3);
}

#[test]
fn state_store_contract_storage_crud() {
    let (_tmp, db) = open_db();
    let store = StateStore::new(db);
    let addr = make_address(0x01);

    // Put + Get
    store.put_storage(&addr, b"slot_0", b"value_A").unwrap();
    let val = store.get_storage(&addr, b"slot_0").unwrap().unwrap();
    assert_eq!(val, b"value_A".to_vec());

    // Overwrite
    store.put_storage(&addr, b"slot_0", b"value_B").unwrap();
    let val2 = store.get_storage(&addr, b"slot_0").unwrap().unwrap();
    assert_eq!(val2, b"value_B".to_vec());

    // Delete
    store.delete_storage(&addr, b"slot_0").unwrap();
    assert!(store.get_storage(&addr, b"slot_0").unwrap().is_none());
}

#[test]
fn state_store_storage_isolation_between_addresses() {
    let (_tmp, db) = open_db();
    let store = StateStore::new(db);

    let addr_a = make_address(0x0A);
    let addr_b = make_address(0x0B);

    store.put_storage(&addr_a, b"key", b"val_A").unwrap();
    store.put_storage(&addr_b, b"key", b"val_B").unwrap();

    assert_eq!(
        store.get_storage(&addr_a, b"key").unwrap().unwrap(),
        b"val_A".to_vec()
    );
    assert_eq!(
        store.get_storage(&addr_b, b"key").unwrap().unwrap(),
        b"val_B".to_vec()
    );
}

#[test]
fn state_store_get_all_storage() {
    let (_tmp, db) = open_db();
    let store = StateStore::new(db);

    let addr = make_address(0x01);
    // Use a 32-byte key so it matches the 52-byte key format (20 addr + 32 slot)
    let slot = [0xABu8; 32];
    let val = [0xCDu8; 32];

    store.put_storage(&addr, &slot, &val).unwrap();

    let all = store.get_all_storage().unwrap();
    // Should contain at least the entry we added (key len == 52)
    assert!(!all.is_empty());
}

#[test]
fn state_store_code_put_get() {
    let (_tmp, db) = open_db();
    let store = StateStore::new(db);

    let code_hash = Hash::new([0xDE; 32]);
    let bytecode = vec![0x60, 0x80, 0x60, 0x40, 0x52]; // sample EVM bytecode

    store.put_code(&code_hash, &bytecode).unwrap();
    let got = store.get_code(&code_hash).unwrap().unwrap();
    assert_eq!(got, bytecode);
}

#[test]
fn state_store_code_missing() {
    let (_tmp, db) = open_db();
    let store = StateStore::new(db);
    assert!(store.get_code(&Hash::new([0xFF; 32])).unwrap().is_none());
}

#[test]
fn state_store_model_crud() {
    let (_tmp, db) = open_db();
    let store = StateStore::new(db);

    let model_id = ModelId(Hash::new([0x01; 32]));
    let model = make_model_state(0x02);

    // Put + Get
    store.put_model(&model_id, &model).unwrap();
    let got = store.get_model(&model_id).unwrap().unwrap();
    assert_eq!(got.version, 1);
    assert_eq!(got.metadata.name, "Model-2");

    // Missing model
    let missing_id = ModelId(Hash::new([0xFF; 32]));
    assert!(store.get_model(&missing_id).unwrap().is_none());
}

#[test]
fn state_store_models_by_owner() {
    let (_tmp, db) = open_db();
    let store = StateStore::new(db);

    let owner = make_address(0x05);
    let model1 = ModelState {
        owner,
        ..make_model_state(0x05)
    };
    let model2 = ModelState {
        owner,
        model_hash: Hash::new([0x06; 32]),
        ..make_model_state(0x05)
    };

    let id1 = ModelId(Hash::new([0x10; 32]));
    let id2 = ModelId(Hash::new([0x11; 32]));

    store.put_model(&id1, &model1).unwrap();
    store.put_model(&id2, &model2).unwrap();

    let owner_models = store.get_models_by_owner(&owner).unwrap();
    assert_eq!(owner_models.len(), 2);

    // Different owner should have none
    let other_owner_models = store.get_models_by_owner(&make_address(0xFF)).unwrap();
    assert!(other_owner_models.is_empty());
}

#[test]
fn state_store_training_job_crud() {
    let (_tmp, db) = open_db();
    let store = StateStore::new(db);

    let job = make_training_job(0x01, 0x02, 0x03);
    store.put_training_job(&job).unwrap();

    let got = store.get_training_job(&job.id).unwrap().unwrap();
    assert_eq!(got.gradients_required, 10);
    assert_eq!(got.status, JobStatus::Pending);

    // Missing job
    let missing = JobId(Hash::new([0xFF; 32]));
    assert!(store.get_training_job(&missing).unwrap().is_none());
}

#[test]
fn state_store_state_root_put_get() {
    let (_tmp, db) = open_db();
    let store = StateStore::new(db);

    let block_hash = Hash::new([0xBB; 32]);
    let state_root = Hash::new([0xCC; 32]);

    store.put_state_root(&block_hash, &state_root).unwrap();
    let got = store.get_state_root(&block_hash).unwrap().unwrap();
    assert_eq!(got, state_root);

    // Missing state root
    let missing_block = Hash::new([0xDD; 32]);
    assert!(store.get_state_root(&missing_block).unwrap().is_none());
}

#[test]
fn state_store_snapshot_create_and_get() {
    let (_tmp, db) = open_db();
    let store = StateStore::new(db);

    let block_hash = Hash::new([0xAA; 32]);
    let addr1 = make_address(0x01);
    let addr2 = make_address(0x02);
    let acct1 = make_account(1, 100);
    let acct2 = make_account(2, 200);

    store
        .create_snapshot(
            &block_hash,
            vec![(addr1, acct1.clone()), (addr2, acct2.clone())],
        )
        .unwrap();

    let got1 = store
        .get_snapshot_account(&block_hash, &addr1)
        .unwrap()
        .unwrap();
    assert_eq!(got1.nonce, 1);
    assert_eq!(got1.balance, U256::from(100u64));

    let got2 = store
        .get_snapshot_account(&block_hash, &addr2)
        .unwrap()
        .unwrap();
    assert_eq!(got2.nonce, 2);

    // Missing snapshot account
    let missing_addr = make_address(0xFF);
    assert!(store
        .get_snapshot_account(&block_hash, &missing_addr)
        .unwrap()
        .is_none());

    // Missing snapshot block
    let other_block = Hash::new([0xEE; 32]);
    assert!(store
        .get_snapshot_account(&other_block, &addr1)
        .unwrap()
        .is_none());
}

#[test]
fn state_store_compact_succeeds() {
    let (_tmp, db) = open_db();
    let store = StateStore::new(db);

    // Insert some data first
    store
        .put_account(&make_address(1), &make_account(1, 100))
        .unwrap();
    store.put_code(&Hash::new([1; 32]), b"code").unwrap();

    // Compact should not error
    store.compact().unwrap();
}

// ===========================================================================
// BLOCK STORE TESTS
// ===========================================================================

#[test]
fn block_store_put_get_basic() {
    let (_tmp, db) = open_db();
    let store = BlockStore::new(db);

    let block = make_block(1, 10, Hash::default());
    store.put_block(&block).unwrap();

    let got = store.get_block(&block.hash()).unwrap().unwrap();
    assert_eq!(got.header.height, 10);
    assert_eq!(got.hash(), block.hash());
}

#[test]
fn block_store_get_header() {
    let (_tmp, db) = open_db();
    let store = BlockStore::new(db);

    let block = make_block(2, 20, Hash::default());
    store.put_block(&block).unwrap();

    let header = store.get_header(&block.hash()).unwrap().unwrap();
    assert_eq!(header.height, 20);
    assert_eq!(header.blue_score, 200);
}

#[test]
fn block_store_has_block() {
    let (_tmp, db) = open_db();
    let store = BlockStore::new(db);

    let block = make_block(3, 30, Hash::default());
    assert!(!store.has_block(&block.hash()).unwrap());

    store.put_block(&block).unwrap();
    assert!(store.has_block(&block.hash()).unwrap());
}

#[test]
fn block_store_get_by_height() {
    let (_tmp, db) = open_db();
    let store = BlockStore::new(db);

    let block = make_block(4, 40, Hash::default());
    store.put_block(&block).unwrap();

    let hash = store.get_block_by_height(40).unwrap().unwrap();
    assert_eq!(hash, block.hash());

    // Missing height
    assert!(store.get_block_by_height(999).unwrap().is_none());
}

#[test]
fn block_store_children_relationship() {
    let (_tmp, db) = open_db();
    let store = BlockStore::new(db);

    let parent = make_block(1, 1, Hash::default());
    store.put_block(&parent).unwrap();

    let child1 = make_block(2, 2, parent.hash());
    let child2 = make_block(3, 2, parent.hash());
    store.put_block(&child1).unwrap();
    store.put_block(&child2).unwrap();

    let children = store.get_children(&parent.hash()).unwrap();
    assert_eq!(children.len(), 2);
    assert!(children.contains(&child1.hash()));
    assert!(children.contains(&child2.hash()));

    // Block with no children
    let children_of_child = store.get_children(&child1.hash()).unwrap();
    assert!(children_of_child.is_empty());
}

#[test]
fn block_store_latest_height() {
    let (_tmp, db) = open_db();
    let store = BlockStore::new(db);

    // Empty DB
    assert_eq!(store.get_latest_height().unwrap(), 0);

    // Insert blocks at various heights
    for h in [5u64, 10, 15, 3, 20] {
        let block = make_block(h as u8, h, Hash::default());
        store.put_block(&block).unwrap();
    }

    assert_eq!(store.get_latest_height().unwrap(), 20);
}

#[test]
fn block_store_blue_score_range() {
    let (_tmp, db) = open_db();
    let store = BlockStore::new(db);

    // Insert blocks with various blue scores
    for i in 1..=5u8 {
        let mut block = make_block(i, i as u64, Hash::default());
        block.header.blue_score = i as u64 * 100;
        store.put_block(&block).unwrap();
    }

    // Query range [200, 400] should get blue scores 200, 300, 400 -> blocks 2, 3, 4
    let results = store.get_blocks_by_blue_score(200, 400).unwrap();
    assert_eq!(results.len(), 3);
}

#[test]
fn block_store_delete_block() {
    let (_tmp, db) = open_db();
    let store = BlockStore::new(db);

    let parent = make_block(1, 1, Hash::default());
    store.put_block(&parent).unwrap();

    let child = make_block(2, 2, parent.hash());
    store.put_block(&child).unwrap();

    // Verify child exists
    assert!(store.has_block(&child.hash()).unwrap());

    // Delete child
    store.delete_block(&child.hash()).unwrap();
    assert!(!store.has_block(&child.hash()).unwrap());
    assert!(store.get_header(&child.hash()).unwrap().is_none());
    assert!(store.get_block_by_height(2).unwrap().is_none());

    // Parent's children list should be updated
    let children = store.get_children(&parent.hash()).unwrap();
    assert!(!children.contains(&child.hash()));
}

#[test]
fn block_store_delete_nonexistent_is_noop() {
    let (_tmp, db) = open_db();
    let store = BlockStore::new(db);

    // Deleting a block that doesn't exist should not error
    let fake_hash = Hash::new([0xFF; 32]);
    store.delete_block(&fake_hash).unwrap();
}

#[test]
fn block_store_tips_detection() {
    let (_tmp, db) = open_db();
    let store = BlockStore::new(db);

    // Chain: genesis -> A -> B (B is only tip)
    let genesis = make_block(0, 0, Hash::default());
    store.put_block(&genesis).unwrap();

    let a = make_block(1, 1, genesis.hash());
    store.put_block(&a).unwrap();

    let b = make_block(2, 2, a.hash());
    store.put_block(&b).unwrap();

    let tips = store.get_tips().unwrap();
    assert_eq!(tips.len(), 1);
    assert_eq!(tips[0], b.hash());
}

#[test]
fn block_store_tips_with_fork() {
    let (_tmp, db) = open_db();
    let store = BlockStore::new(db);

    let genesis = make_block(0, 0, Hash::default());
    store.put_block(&genesis).unwrap();

    // Fork: genesis -> fork_a, genesis -> fork_b
    let fork_a = make_block(1, 1, genesis.hash());
    let fork_b = make_block(2, 1, genesis.hash());
    store.put_block(&fork_a).unwrap();
    store.put_block(&fork_b).unwrap();

    let tips = store.get_tips().unwrap();
    assert_eq!(tips.len(), 2);
    assert!(tips.contains(&fork_a.hash()));
    assert!(tips.contains(&fork_b.hash()));
}

#[test]
fn block_store_merge_parents() {
    let (_tmp, db) = open_db();
    let store = BlockStore::new(db);

    let parent_a = make_block(1, 1, Hash::default());
    let parent_b = make_block(2, 1, Hash::default());
    store.put_block(&parent_a).unwrap();
    store.put_block(&parent_b).unwrap();

    // Block with merge parent
    let merge_block =
        make_block_with_merge(3, 2, parent_a.hash(), vec![parent_b.hash()]);
    store.put_block(&merge_block).unwrap();

    // Both parents should have merge_block as a child
    let children_a = store.get_children(&parent_a.hash()).unwrap();
    assert!(children_a.contains(&merge_block.hash()));

    let children_b = store.get_children(&parent_b.hash()).unwrap();
    assert!(children_b.contains(&merge_block.hash()));
}

#[test]
fn block_store_compact_succeeds() {
    let (_tmp, db) = open_db();
    let store = BlockStore::new(db);

    store.put_block(&make_block(1, 1, Hash::default())).unwrap();
    store.compact().unwrap();
}

// ===========================================================================
// TRANSACTION STORE TESTS
// ===========================================================================

#[test]
fn tx_store_put_get_single() {
    let (_tmp, db) = open_db();
    let store = TransactionStore::new(db);

    let tx = make_tx(1);
    store.put_transaction(&tx).unwrap();

    let got = store.get_transaction(&tx.hash).unwrap().unwrap();
    assert_eq!(got.nonce, 1);
    assert_eq!(got.value, 1001);
}

#[test]
fn tx_store_get_missing() {
    let (_tmp, db) = open_db();
    let store = TransactionStore::new(db);

    let result = store.get_transaction(&Hash::new([0xFF; 32])).unwrap();
    assert!(result.is_none());
}

#[test]
fn tx_store_has_transaction() {
    let (_tmp, db) = open_db();
    let store = TransactionStore::new(db);

    let tx = make_tx(5);
    assert!(!store.has_transaction(&tx.hash).unwrap());

    store.put_transaction(&tx).unwrap();
    assert!(store.has_transaction(&tx.hash).unwrap());
}

#[test]
fn tx_store_batch_put() {
    let (_tmp, db) = open_db();
    let store = TransactionStore::new(db);

    let txs: Vec<Transaction> = (10..15).map(make_tx).collect();
    store.put_transactions(&txs).unwrap();

    for tx in &txs {
        assert!(store.has_transaction(&tx.hash).unwrap());
        let got = store.get_transaction(&tx.hash).unwrap().unwrap();
        assert_eq!(got.nonce, tx.nonce);
    }
}

#[test]
fn tx_store_receipt_put_get() {
    let (_tmp, db) = open_db();
    let store = TransactionStore::new(db);

    let tx_hash = Hash::new([0x01; 32]);
    let block_hash = Hash::new([0x02; 32]);
    let receipt = make_receipt(tx_hash, block_hash, 42);

    store.put_receipt(&tx_hash, &receipt).unwrap();

    let got = store.get_receipt(&tx_hash).unwrap().unwrap();
    assert_eq!(got.block_number, 42);
    assert!(got.status);
    assert_eq!(got.gas_used, 21_000);
}

#[test]
fn tx_store_receipt_missing() {
    let (_tmp, db) = open_db();
    let store = TransactionStore::new(db);
    assert!(store.get_receipt(&Hash::new([0xFF; 32])).unwrap().is_none());
}

#[test]
fn tx_store_batch_receipts() {
    let (_tmp, db) = open_db();
    let store = TransactionStore::new(db);

    let block_hash = Hash::new([0xBB; 32]);
    let receipts: Vec<(Hash, TransactionReceipt)> = (1..=3u8)
        .map(|i| {
            let tx_hash = Hash::new([i; 32]);
            (tx_hash, make_receipt(tx_hash, block_hash, i as u64))
        })
        .collect();

    store.put_receipts(&receipts).unwrap();

    for (tx_hash, _) in &receipts {
        assert!(store.get_receipt(tx_hash).unwrap().is_some());
    }
}

#[test]
fn tx_store_block_transactions_index() {
    let (_tmp, db) = open_db();
    let store = TransactionStore::new(db);

    let block_hash = Hash::new([0xCC; 32]);

    let tx1_hash = Hash::new([0x01; 32]);
    let tx2_hash = Hash::new([0x02; 32]);

    let receipt1 = make_receipt(tx1_hash, block_hash, 10);
    let receipt2 = make_receipt(tx2_hash, block_hash, 10);

    store.put_receipt(&tx1_hash, &receipt1).unwrap();
    store.put_receipt(&tx2_hash, &receipt2).unwrap();

    let block_txs = store.get_block_transactions(&block_hash).unwrap();
    assert_eq!(block_txs.len(), 2);
    assert!(block_txs.contains(&tx1_hash));
    assert!(block_txs.contains(&tx2_hash));

    // Empty block has no transactions
    let empty_block_txs = store
        .get_block_transactions(&Hash::new([0xFF; 32]))
        .unwrap();
    assert!(empty_block_txs.is_empty());
}

#[test]
fn tx_store_delete_transaction() {
    let (_tmp, db) = open_db();
    let store = TransactionStore::new(db);

    let tx = make_tx(7);
    store.put_transaction(&tx).unwrap();

    // Also add a receipt
    let block_hash = Hash::new([0xDD; 32]);
    let receipt = make_receipt(tx.hash, block_hash, 1);
    store.put_receipt(&tx.hash, &receipt).unwrap();

    // Delete
    store.delete_transaction(&tx.hash).unwrap();

    assert!(!store.has_transaction(&tx.hash).unwrap());
    assert!(store.get_receipt(&tx.hash).unwrap().is_none());
}

#[test]
fn tx_store_delete_nonexistent() {
    let (_tmp, db) = open_db();
    let store = TransactionStore::new(db);

    // Should not error
    store.delete_transaction(&Hash::new([0xFF; 32])).unwrap();
}

#[test]
fn tx_store_compact_succeeds() {
    let (_tmp, db) = open_db();
    let store = TransactionStore::new(db);

    store.put_transaction(&make_tx(1)).unwrap();
    store.compact().unwrap();
}

// ===========================================================================
// STATE MANAGER TESTS
// ===========================================================================

#[tokio::test]
async fn state_manager_register_model() {
    let (_tmp, db) = open_db();
    let manager = StateManager::new(db);

    let model_id = ModelId(Hash::new([0x01; 32]));
    let model = make_model_state(0x02);

    manager
        .register_model(model_id, model.clone(), "QmWeightCid".to_string())
        .unwrap();

    let got = manager.get_model(&model_id).unwrap();
    assert_eq!(got.version, 1);
    assert_eq!(got.metadata.name, "Model-2");
}

#[tokio::test]
async fn state_manager_update_model_weights() {
    let (_tmp, db) = open_db();
    let manager = StateManager::new(db);

    let model_id = ModelId(Hash::new([0x10; 32]));
    let model = make_model_state(0x10);

    manager
        .register_model(model_id, model, "QmOldCid".to_string())
        .unwrap();

    manager
        .update_model_weights(model_id, "QmNewCid".to_string(), 2)
        .unwrap();

    let got = manager.get_model(&model_id).unwrap();
    assert_eq!(got.version, 2);
}

#[tokio::test]
async fn state_manager_update_nonexistent_model_weights() {
    let (_tmp, db) = open_db();
    let manager = StateManager::new(db);

    let missing_id = ModelId(Hash::new([0xFF; 32]));
    // Should not error, just no-op on the in-memory state
    manager
        .update_model_weights(missing_id, "QmNew".to_string(), 5)
        .unwrap();

    assert!(manager.get_model(&missing_id).is_none());
}

#[tokio::test]
async fn state_manager_training_job() {
    let (_tmp, db) = open_db();
    let manager = StateManager::new(db);

    let job = make_training_job(0x01, 0x02, 0x03);
    let job_id = job.id;

    manager.add_training_job(job_id, job).unwrap();

    let got = manager.get_training_job(&job_id).unwrap();
    assert_eq!(got.gradients_required, 10);
}

#[tokio::test]
async fn state_manager_training_job_missing() {
    let (_tmp, db) = open_db();
    let manager = StateManager::new(db);

    let missing = JobId(Hash::new([0xFF; 32]));
    assert!(manager.get_training_job(&missing).is_none());
}

#[tokio::test]
async fn state_manager_inference_cache() {
    let (_tmp, db) = open_db();
    let manager = StateManager::new(db);

    let result = citrate_storage::state::InferenceResult {
        model_id: ModelId(Hash::new([0x01; 32])),
        input_hash: Hash::new([0x02; 32]),
        output: vec![1, 2, 3, 4],
        gas_used: 5000,
        timestamp: 1_700_000_000,
        proof: Some(vec![0xAA, 0xBB]),
    };

    // cache_inference_result writes to "cache" CF which is not registered;
    // the in-memory AI state is still updated even though the DB persist fails.
    // We test that the method returns an error (known gap: missing CF).
    let cache_result = manager.cache_inference_result(result);
    assert!(cache_result.is_err(), "Expected error for missing 'cache' CF");

    // The in-memory cache should still have been populated before the DB write
    let stats = manager.get_ai_stats();
    assert_eq!(stats.cached_inferences, 1);
}

#[tokio::test]
async fn state_manager_lora_adapter() {
    let (_tmp, db) = open_db();
    let manager = StateManager::new(db);

    let adapter = citrate_storage::state::LoRAAdapter {
        adapter_id: Hash::new([0x20; 32]),
        base_model: ModelId(Hash::new([0x10; 32])),
        owner: make_address(0x30),
        weight_cid: "QmLoRAWeights".to_string(),
        rank: 8,
        alpha: 16.0,
        created_at: 1_700_000_000,
    };

    manager.add_lora_adapter(adapter).unwrap();

    let stats = manager.get_ai_stats();
    assert_eq!(stats.total_lora_adapters, 1);
}

#[tokio::test]
async fn state_manager_prune_inference_cache() {
    let (_tmp, db) = open_db();
    let manager = StateManager::new(db);

    // Populate the in-memory inference cache directly via the AI state tree,
    // since cache_inference_result fails on the DB persist (missing "cache" CF).
    let old_result = citrate_storage::state::InferenceResult {
        model_id: ModelId(Hash::new([0x01; 32])),
        input_hash: Hash::new([0x02; 32]),
        output: vec![1, 2, 3],
        gas_used: 1000,
        timestamp: 1_000, // very old
        proof: None,
    };

    // Use a timestamp that is guaranteed to be "now" so it survives pruning
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let recent_result = citrate_storage::state::InferenceResult {
        model_id: ModelId(Hash::new([0x03; 32])),
        input_hash: Hash::new([0x04; 32]),
        output: vec![4, 5, 6],
        gas_used: 2000,
        timestamp: now_ts,
        proof: None,
    };

    // Insert directly into the in-memory AI state (bypassing broken DB persist)
    manager.ai_state.write().cache_inference(old_result);
    manager.ai_state.write().cache_inference(recent_result);

    assert_eq!(manager.get_ai_stats().cached_inferences, 2);

    // Prune with max_age = 3600s (1 hour).
    // The old entry (timestamp=1000) will be pruned: current_time - 1000 >> 3600.
    // The recent entry (timestamp=now) will survive: current_time - now < 3600.
    manager.prune_inference_cache(3600);

    let stats = manager.get_ai_stats();
    assert_eq!(stats.cached_inferences, 1, "Only the recent entry should survive");
}

#[tokio::test]
async fn state_manager_ai_stats() {
    let (_tmp, db) = open_db();
    let manager = StateManager::new(db);

    // Empty initially
    let stats = manager.get_ai_stats();
    assert_eq!(stats.total_models, 0);
    assert_eq!(stats.active_training_jobs, 0);
    assert_eq!(stats.cached_inferences, 0);
    assert_eq!(stats.total_lora_adapters, 0);

    // Add a model
    let model_id = ModelId(Hash::new([0x01; 32]));
    manager
        .register_model(model_id, make_model_state(0x01), "Qm1".to_string())
        .unwrap();

    let stats = manager.get_ai_stats();
    assert_eq!(stats.total_models, 1);
}

#[tokio::test]
async fn state_manager_calculate_state_root_deterministic() {
    let (_tmp, db) = open_db();
    let manager = StateManager::new(db);

    // Add some state
    manager
        .state_store
        .put_account(&make_address(1), &make_account(1, 100))
        .unwrap();

    let root1 = manager.calculate_state_root().await.unwrap();
    let root2 = manager.calculate_state_root().await.unwrap();
    assert_eq!(root1, root2);
}

#[tokio::test]
async fn state_manager_state_root_changes_with_data() {
    let (_tmp, db) = open_db();
    let manager = StateManager::new(db);

    let root_empty = manager.calculate_state_root().await.unwrap();

    // Add an account
    manager
        .state_store
        .put_account(&make_address(1), &make_account(1, 100))
        .unwrap();

    let root_with_account = manager.calculate_state_root().await.unwrap();
    assert_ne!(root_empty, root_with_account);

    // Register a model (changes AI state)
    let model_id = ModelId(Hash::new([0x01; 32]));
    manager
        .register_model(model_id, make_model_state(0x01), "Qm1".to_string())
        .unwrap();

    let root_with_model = manager.calculate_state_root().await.unwrap();
    assert_ne!(root_with_account, root_with_model);
}

// ===========================================================================
// STORAGE MANAGER INTEGRATION TESTS
// ===========================================================================

#[test]
fn storage_manager_creation() {
    let tmp = TempDir::new().unwrap();
    let mgr = StorageManager::new(tmp.path(), PruningConfig::default()).unwrap();
    assert!(!mgr.is_encryption_enabled());
}

#[test]
fn storage_manager_with_config() {
    let tmp = TempDir::new().unwrap();
    let config = StorageConfig::default();
    let mgr = StorageManager::with_config(tmp.path(), config).unwrap();
    assert!(!mgr.is_encryption_enabled());
    assert!(mgr.get_encryption_stats().is_none());
}

#[test]
fn storage_manager_maximum_security_config() {
    let config = StorageConfig::maximum_security("test-node".to_string());
    assert!(config.encryption.is_some());
    assert!(config.encryption.unwrap().enabled);
}

#[test]
fn storage_manager_flush() {
    let tmp = TempDir::new().unwrap();
    let mgr = StorageManager::new(tmp.path(), PruningConfig::default()).unwrap();

    // Store some data then flush
    mgr.blocks
        .put_block(&make_block(1, 1, Hash::default()))
        .unwrap();
    mgr.flush().unwrap();
}

#[test]
fn storage_manager_get_statistics() {
    let tmp = TempDir::new().unwrap();
    let mgr = StorageManager::new(tmp.path(), PruningConfig::default()).unwrap();
    let stats = mgr.get_statistics();
    // Should return a non-empty string
    assert!(!stats.is_empty());
}

#[test]
fn storage_manager_clear_caches() {
    let tmp = TempDir::new().unwrap();
    let mgr = StorageManager::new(tmp.path(), PruningConfig::default()).unwrap();

    // Add to cache
    mgr.block_cache.put(Hash::new([1; 32]), vec![1, 2, 3]);
    mgr.state_cache.put(vec![1], vec![2]);
    assert!(!mgr.block_cache.is_empty());
    assert!(!mgr.state_cache.is_empty());

    mgr.clear_caches();
    assert!(mgr.block_cache.is_empty());
    assert!(mgr.state_cache.is_empty());
}

#[test]
fn storage_manager_persistence() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().to_path_buf();

    // Write
    {
        let mgr = StorageManager::new(&path, PruningConfig::default()).unwrap();
        let tx = make_tx(42);
        mgr.transactions.put_transaction(&tx).unwrap();
        mgr.state
            .put_account(&make_address(0xAA), &make_account(99, 999))
            .unwrap();
        mgr.flush().unwrap();
    }

    // Read back
    {
        let mgr = StorageManager::new(&path, PruningConfig::default()).unwrap();
        let tx = make_tx(42);
        assert!(mgr.transactions.has_transaction(&tx.hash).unwrap());
        let acct = mgr
            .state
            .get_account(&make_address(0xAA))
            .unwrap()
            .unwrap();
        assert_eq!(acct.nonce, 99);
    }
}

#[test]
fn storage_config_with_encryption_builder() {
    use citrate_storage::crypto::database_encryption::DatabaseEncryptionConfig;

    let config = StorageConfig::default()
        .with_encryption(DatabaseEncryptionConfig {
            enabled: true,
            node_id: "my-node".to_string(),
            ..Default::default()
        });
    assert!(config.encryption.is_some());
}

#[test]
fn storage_manager_initialize_encryption_noop_without_config() {
    let tmp = TempDir::new().unwrap();
    let mut mgr = StorageManager::new(tmp.path(), PruningConfig::default()).unwrap();
    // No encryption configured, should be a no-op
    mgr.initialize_encryption(b"password").unwrap();
    assert!(!mgr.is_encryption_enabled());
}
