// WP-H.4: Batch Transaction Atomicity Tests
//
// Tests for batch transaction execution, atomicity, snapshots, rollback,
// nonce management, and mixed transaction types.
//
// Coverage:
//   1. Execute 3 txs sequentially — all succeed, state root changes
//   2. Execute 3 txs where tx#2 has insufficient balance — tx#2 fails, tx#1 and tx#3 succeed
//   3. Snapshot before batch, execute all, verify intermediate states, rollback
//   4. Simulate atomic batch: snapshot -> execute N txs -> if any fail, restore snapshot
//   5. Verify nonce management across batch (sequential nonces)
//   6. Mixed transaction types in batch (transfer + contract call + deploy)

use citrate_consensus::types::{
    Block, BlockHeader, GhostDagParams, Hash, PublicKey, Signature,
    Transaction as ConsensusTransaction, VrfProof,
};
use citrate_execution::{address_utils, types::*, Executor, StateDB};
use primitive_types::U256;
use std::sync::Arc;

// =============================================================================
// Helpers
// =============================================================================

fn make_address(seed: u8) -> Address {
    let mut pk_bytes = [0u8; 32];
    pk_bytes[0] = seed;
    address_utils::normalize_address(&PublicKey::new(pk_bytes))
}

fn make_pubkey(seed: u8) -> PublicKey {
    let mut pk_bytes = [0u8; 32];
    pk_bytes[0] = seed;
    PublicKey::new(pk_bytes)
}

fn test_block() -> Block {
    Block {
        header: BlockHeader {
            version: 1,
            block_hash: Hash::new([0xBB; 32]),
            selected_parent_hash: Hash::default(),
            merge_parent_hashes: vec![],
            timestamp: 1_700_000_000,
            height: 1,
            blue_score: 10,
            blue_work: 1000,
            pruning_point: Hash::default(),
            proposer_pubkey: PublicKey::new([0u8; 32]),
            vrf_reveal: VrfProof {
                proof: vec![0u8; 80],
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
        signature: Signature::new([0u8; 64]),
        embedded_models: vec![],
        required_pins: vec![],
        learning_embedding: None,
        learning_confidence: None,
        gradient_commitment: None,
    }
}

fn transfer_tx(
    from: PublicKey,
    to: PublicKey,
    value: u128,
    nonce: u64,
    gas_limit: u64,
    gas_price: u64,
) -> ConsensusTransaction {
    let mut hash_bytes = [0u8; 32];
    hash_bytes[0] = nonce as u8;
    hash_bytes[1] = from.0[0];
    hash_bytes[2] = to.0[0];
    hash_bytes[3] = (value & 0xFF) as u8;
    ConsensusTransaction {
        hash: Hash::new(hash_bytes),
        nonce,
        from,
        to: Some(to),
        value,
        gas_limit,
        gas_price,
        data: vec![],
        signature: Signature::new([0u8; 64]),
        tx_type: None,
        ..Default::default()
    }
}

fn deploy_tx(
    from: PublicKey,
    bytecode: Vec<u8>,
    nonce: u64,
    gas_limit: u64,
    gas_price: u64,
) -> ConsensusTransaction {
    let mut hash_bytes = [0u8; 32];
    hash_bytes[0] = nonce as u8;
    hash_bytes[1] = 0xDD;
    hash_bytes[2] = from.0[0];
    ConsensusTransaction {
        hash: Hash::new(hash_bytes),
        nonce,
        from,
        to: None,
        value: 0,
        gas_limit,
        gas_price,
        data: bytecode,
        signature: Signature::new([0u8; 64]),
        tx_type: None,
        ..Default::default()
    }
}

fn call_tx(
    from: PublicKey,
    to: PublicKey,
    data: Vec<u8>,
    value: u128,
    nonce: u64,
    gas_limit: u64,
    gas_price: u64,
) -> ConsensusTransaction {
    let mut hash_bytes = [0u8; 32];
    hash_bytes[0] = nonce as u8;
    hash_bytes[1] = 0xCC;
    hash_bytes[2] = from.0[0];
    ConsensusTransaction {
        hash: Hash::new(hash_bytes),
        nonce,
        from,
        to: Some(to),
        value,
        gas_limit,
        gas_price,
        data,
        signature: Signature::new([0u8; 64]),
        tx_type: None,
        ..Default::default()
    }
}

fn new_executor() -> (Executor, Arc<StateDB>) {
    let state_db = Arc::new(StateDB::new());
    let executor = Executor::with_chain_id(state_db.clone(), 1337);
    (executor, state_db)
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

// =============================================================================
// 1. Execute 3 txs sequentially — all succeed, state root changes
// =============================================================================

#[test]
fn test_batch_three_sequential_transfers_all_succeed() {
    let (executor, state_db) = new_executor();
    let block = test_block();

    let sender = make_pubkey(1);
    let receiver = make_pubkey(2);
    let sender_addr = make_address(1);
    let receiver_addr = make_address(2);

    // Fund sender generously
    executor.set_balance(&sender_addr, U256::from(10_000_000u64));

    let root_before = state_db.calculate_state_root();

    // Execute 3 transfers in sequence
    let tx1 = transfer_tx(sender, receiver, 1000, 0, 100_000, 1);
    let tx2 = transfer_tx(sender, receiver, 2000, 1, 100_000, 1);
    let tx3 = transfer_tx(sender, receiver, 3000, 2, 100_000, 1);

    let receipt1 = rt().block_on(executor.execute_transaction(&block, &tx1)).unwrap();
    let receipt2 = rt().block_on(executor.execute_transaction(&block, &tx2)).unwrap();
    let receipt3 = rt().block_on(executor.execute_transaction(&block, &tx3)).unwrap();

    assert!(receipt1.status, "tx1 should succeed");
    assert!(receipt2.status, "tx2 should succeed");
    assert!(receipt3.status, "tx3 should succeed");

    // Receiver should have 1000 + 2000 + 3000 = 6000
    let receiver_balance = executor.get_balance(&receiver_addr);
    assert_eq!(receiver_balance, U256::from(6000u64));

    // State root should have changed
    let root_after = state_db.calculate_state_root();
    assert_ne!(root_before, root_after, "State root should change after txs");

    // Nonce should have incremented to 3
    let nonce = executor.get_nonce(&sender_addr);
    assert_eq!(nonce, 3);
}

// =============================================================================
// 2. Execute 3 txs where tx#2 has insufficient balance
// =============================================================================

#[test]
fn test_batch_middle_tx_insufficient_balance() {
    let (executor, _) = new_executor();
    let block = test_block();

    let sender = make_pubkey(10);
    let receiver = make_pubkey(11);
    let sender_addr = make_address(10);
    let receiver_addr = make_address(11);

    // Fund sender with enough for tx1 and tx3 but not tx2 as well
    // gas_price=0 so only value matters
    executor.set_balance(&sender_addr, U256::from(5000u64));

    // tx1: send 1000 (balance after: 5000 - 1000 = 4000)
    let tx1 = transfer_tx(sender, receiver, 1000, 0, 100_000, 0);
    let receipt1 = rt().block_on(executor.execute_transaction(&block, &tx1)).unwrap();
    assert!(receipt1.status, "tx1 should succeed");

    // tx2: send 5000 (balance is 4000, insufficient)
    let tx2 = transfer_tx(sender, receiver, 5000, 1, 100_000, 0);
    let result2 = rt().block_on(executor.execute_transaction(&block, &tx2));
    match result2 {
        Err(ExecutionError::InsufficientBalance { .. }) => {
            // Expected: tx2 fails with insufficient balance
        }
        Err(e) => panic!("Expected InsufficientBalance, got: {:?}", e),
        Ok(receipt) => {
            assert!(!receipt.status, "tx2 receipt should indicate failure");
        }
    }

    // tx3: send 500 (balance is still 4000, nonce is 1 since tx2 may or may not have incremented it)
    // We need to determine the current nonce
    let current_nonce = executor.get_nonce(&sender_addr);
    let tx3 = transfer_tx(sender, receiver, 500, current_nonce, 100_000, 0);
    let receipt3 = rt().block_on(executor.execute_transaction(&block, &tx3)).unwrap();
    assert!(receipt3.status, "tx3 should succeed");

    // Receiver should have received from tx1 + tx3
    let receiver_balance = executor.get_balance(&receiver_addr);
    assert_eq!(receiver_balance, U256::from(1500u64), "Receiver should have 1000 + 500");
}

// =============================================================================
// 3. Snapshot before batch, execute all, verify intermediate states, rollback
// =============================================================================

#[test]
fn test_snapshot_execute_verify_rollback() {
    let (executor, state_db) = new_executor();
    let block = test_block();

    let sender = make_pubkey(20);
    let receiver = make_pubkey(21);
    let sender_addr = make_address(20);
    let receiver_addr = make_address(21);

    executor.set_balance(&sender_addr, U256::from(1_000_000u64));

    // Take snapshot before batch
    let snapshot = state_db.snapshot();
    let root_before = state_db.calculate_state_root();
    let balance_before = executor.get_balance(&sender_addr);

    // Execute transactions
    let tx1 = transfer_tx(sender, receiver, 10_000, 0, 100_000, 0);
    let receipt1 = rt().block_on(executor.execute_transaction(&block, &tx1)).unwrap();
    assert!(receipt1.status);

    // Verify intermediate state after tx1
    let balance_after_tx1 = executor.get_balance(&sender_addr);
    assert_eq!(balance_after_tx1, U256::from(990_000u64));
    assert_eq!(executor.get_balance(&receiver_addr), U256::from(10_000u64));

    let tx2 = transfer_tx(sender, receiver, 20_000, 1, 100_000, 0);
    let receipt2 = rt().block_on(executor.execute_transaction(&block, &tx2)).unwrap();
    assert!(receipt2.status);

    // Verify intermediate state after tx2
    assert_eq!(executor.get_balance(&sender_addr), U256::from(970_000u64));
    assert_eq!(executor.get_balance(&receiver_addr), U256::from(30_000u64));

    let root_after = state_db.calculate_state_root();
    assert_ne!(root_before, root_after);

    // Rollback entire batch
    state_db.restore(snapshot);

    // Verify original state is restored
    let balance_restored = executor.get_balance(&sender_addr);
    assert_eq!(balance_restored, balance_before, "Sender balance should be restored");
    assert_eq!(
        executor.get_balance(&receiver_addr),
        U256::from(0u64),
        "Receiver balance should be restored to 0"
    );
    // Nonce should also be restored
    assert_eq!(executor.get_nonce(&sender_addr), 0, "Sender nonce should be restored to 0");
}

// =============================================================================
// 4. Simulate atomic batch: snapshot -> execute N txs -> if any fail, restore
// =============================================================================

#[test]
fn test_atomic_batch_all_succeed() {
    let (executor, state_db) = new_executor();
    let block = test_block();

    let sender = make_pubkey(30);
    let receiver = make_pubkey(31);
    let sender_addr = make_address(30);
    let receiver_addr = make_address(31);

    executor.set_balance(&sender_addr, U256::from(500_000u64));

    // Snapshot before atomic batch
    let snapshot = state_db.snapshot();

    let txs = vec![
        transfer_tx(sender, receiver, 1000, 0, 100_000, 0),
        transfer_tx(sender, receiver, 2000, 1, 100_000, 0),
        transfer_tx(sender, receiver, 3000, 2, 100_000, 0),
    ];

    let mut all_succeeded = true;
    let mut receipts = Vec::new();

    for tx in &txs {
        match rt().block_on(executor.execute_transaction(&block, tx)) {
            Ok(receipt) => {
                if !receipt.status {
                    all_succeeded = false;
                    break;
                }
                receipts.push(receipt);
            }
            Err(_) => {
                all_succeeded = false;
                break;
            }
        }
    }

    if !all_succeeded {
        state_db.restore(snapshot);
        panic!("Expected all transactions to succeed in atomic batch");
    }

    // All succeeded — verify state
    assert_eq!(receipts.len(), 3);
    assert_eq!(
        executor.get_balance(&receiver_addr),
        U256::from(6000u64),
        "Receiver should have total of all transfers"
    );
}

#[test]
fn test_atomic_batch_rollback_on_failure() {
    let (executor, state_db) = new_executor();
    let block = test_block();

    let sender = make_pubkey(40);
    let receiver = make_pubkey(41);
    let sender_addr = make_address(40);
    let receiver_addr = make_address(41);

    // Fund with limited balance — enough for tx1 but not for tx1 + tx2
    executor.set_balance(&sender_addr, U256::from(1500u64));

    let balance_before = executor.get_balance(&sender_addr);
    let snapshot = state_db.snapshot();

    let txs = vec![
        transfer_tx(sender, receiver, 1000, 0, 100_000, 0),
        transfer_tx(sender, receiver, 1000, 1, 100_000, 0), // will fail: only 500 left
    ];

    let mut all_succeeded = true;

    for tx in &txs {
        match rt().block_on(executor.execute_transaction(&block, tx)) {
            Ok(receipt) => {
                if !receipt.status {
                    all_succeeded = false;
                    break;
                }
            }
            Err(_) => {
                all_succeeded = false;
                break;
            }
        }
    }

    // tx2 should have failed
    assert!(!all_succeeded, "Second tx should have failed");

    // Rollback the entire batch (atomic behavior)
    state_db.restore(snapshot);

    // Verify original state
    assert_eq!(
        executor.get_balance(&sender_addr),
        balance_before,
        "Sender balance should be restored after atomic rollback"
    );
    assert_eq!(
        executor.get_balance(&receiver_addr),
        U256::from(0u64),
        "Receiver balance should be 0 after atomic rollback"
    );
}

// =============================================================================
// 5. Verify nonce management across batch (sequential nonces)
// =============================================================================

#[test]
fn test_batch_nonce_sequential() {
    let (executor, _) = new_executor();
    let block = test_block();

    let sender = make_pubkey(50);
    let receiver = make_pubkey(51);
    let sender_addr = make_address(50);

    executor.set_balance(&sender_addr, U256::from(10_000_000u64));

    assert_eq!(executor.get_nonce(&sender_addr), 0);

    // Execute with sequential nonces
    for nonce in 0..5u64 {
        let tx = transfer_tx(sender, receiver, 100, nonce, 100_000, 0);
        let receipt = rt().block_on(executor.execute_transaction(&block, &tx)).unwrap();
        assert!(receipt.status, "tx with nonce {} should succeed", nonce);
        assert_eq!(
            executor.get_nonce(&sender_addr),
            nonce + 1,
            "Nonce should be {} after tx with nonce {}",
            nonce + 1,
            nonce
        );
    }

    assert_eq!(executor.get_nonce(&sender_addr), 5);
}

#[test]
fn test_batch_nonce_out_of_order_fails() {
    let (executor, _) = new_executor();
    let block = test_block();

    let sender = make_pubkey(55);
    let receiver = make_pubkey(56);
    let sender_addr = make_address(55);

    executor.set_balance(&sender_addr, U256::from(10_000_000u64));

    // Execute nonce 0 first
    let tx0 = transfer_tx(sender, receiver, 100, 0, 100_000, 0);
    let receipt0 = rt().block_on(executor.execute_transaction(&block, &tx0)).unwrap();
    assert!(receipt0.status);

    // Try to execute nonce 0 again (replay) — should fail
    let tx0_replay = transfer_tx(sender, receiver, 100, 0, 100_000, 0);
    let result = rt().block_on(executor.execute_transaction(&block, &tx0_replay));
    assert!(result.is_err(), "Replayed nonce should fail");

    // Skip nonce 1, try nonce 2 — should fail
    let tx2 = transfer_tx(sender, receiver, 100, 2, 100_000, 0);
    let result2 = rt().block_on(executor.execute_transaction(&block, &tx2));
    assert!(result2.is_err(), "Skipped nonce should fail");

    // Nonce 1 should still work
    let tx1 = transfer_tx(sender, receiver, 100, 1, 100_000, 0);
    let receipt1 = rt().block_on(executor.execute_transaction(&block, &tx1)).unwrap();
    assert!(receipt1.status, "Correct sequential nonce should succeed");
}

// =============================================================================
// 6. Mixed transaction types in batch (transfer + contract call + deploy)
// =============================================================================

#[test]
fn test_batch_mixed_transfer_and_call() {
    let (executor, _) = new_executor();
    let block = test_block();

    let sender = make_pubkey(60);
    let receiver = make_pubkey(61);
    let contract = make_pubkey(62);
    let sender_addr = make_address(60);
    let receiver_addr = make_address(61);

    executor.set_balance(&sender_addr, U256::from(10_000_000u64));

    // tx1: plain transfer
    let tx1 = transfer_tx(sender, receiver, 5000, 0, 100_000, 0);
    let receipt1 = rt().block_on(executor.execute_transaction(&block, &tx1)).unwrap();
    assert!(receipt1.status, "Transfer tx should succeed");

    // tx2: contract call (arbitrary data to a non-contract address)
    let call_data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
    let tx2 = call_tx(sender, contract, call_data, 1000, 1, 100_000, 0);
    let receipt2 = rt().block_on(executor.execute_transaction(&block, &tx2)).unwrap();
    // Call to non-contract address still succeeds (transfers value, no code to execute)
    assert!(receipt2.status, "Contract call tx should succeed");

    // tx3: another transfer
    let tx3 = transfer_tx(sender, receiver, 3000, 2, 100_000, 0);
    let receipt3 = rt().block_on(executor.execute_transaction(&block, &tx3)).unwrap();
    assert!(receipt3.status, "Second transfer tx should succeed");

    // Verify balances
    assert_eq!(
        executor.get_balance(&receiver_addr),
        U256::from(8000u64),
        "Receiver should have 5000 + 3000"
    );
}

#[test]
fn test_batch_mixed_transfer_and_deploy() {
    let (executor, _) = new_executor();
    let block = test_block();

    let sender = make_pubkey(70);
    let receiver = make_pubkey(71);
    let sender_addr = make_address(70);
    let receiver_addr = make_address(71);

    executor.set_balance(&sender_addr, U256::from(10_000_000u64));

    // tx1: plain transfer
    let tx1 = transfer_tx(sender, receiver, 5000, 0, 100_000, 0);
    let receipt1 = rt().block_on(executor.execute_transaction(&block, &tx1)).unwrap();
    assert!(receipt1.status, "Transfer should succeed");

    // tx2: contract deploy (minimal bytecode — just STOP)
    let bytecode = vec![0x00]; // STOP opcode
    let tx2 = deploy_tx(sender, bytecode, 1, 500_000, 0);
    let receipt2 = rt().block_on(executor.execute_transaction(&block, &tx2)).unwrap();
    assert!(receipt2.status, "Deploy tx should succeed");
    assert!(receipt2.gas_used > 0, "Deploy should use some gas");

    // tx3: another transfer (nonce 2)
    let tx3 = transfer_tx(sender, receiver, 2000, 2, 100_000, 0);
    let receipt3 = rt().block_on(executor.execute_transaction(&block, &tx3)).unwrap();
    assert!(receipt3.status, "Third tx should succeed after deploy");

    // Verify final state
    assert_eq!(
        executor.get_balance(&receiver_addr),
        U256::from(7000u64),
        "Receiver should have 5000 + 2000"
    );
    assert_eq!(executor.get_nonce(&sender_addr), 3);
}

#[test]
fn test_batch_all_three_types() {
    let (executor, state_db) = new_executor();
    let block = test_block();

    let sender = make_pubkey(80);
    let receiver = make_pubkey(81);
    let contract_addr_pk = make_pubkey(82);
    let sender_addr = make_address(80);

    executor.set_balance(&sender_addr, U256::from(50_000_000u64));

    let root_before = state_db.calculate_state_root();

    // tx1: Transfer
    let tx1 = transfer_tx(sender, receiver, 1_000_000, 0, 200_000, 1);
    let receipt1 = rt().block_on(executor.execute_transaction(&block, &tx1)).unwrap();
    assert!(receipt1.status, "Transfer should succeed");

    // tx2: Deploy contract (minimal: PUSH1 0x42 PUSH1 0x00 MSTORE PUSH1 0x01 PUSH1 0x1F RETURN)
    let deploy_bytecode = vec![
        0x60, 0x42, // PUSH1 0x42
        0x60, 0x00, // PUSH1 0x00
        0x52,       // MSTORE
        0x60, 0x01, // PUSH1 0x01
        0x60, 0x1F, // PUSH1 0x1F
        0xF3,       // RETURN
    ];
    let tx2 = deploy_tx(sender, deploy_bytecode, 1, 500_000, 1);
    let receipt2 = rt().block_on(executor.execute_transaction(&block, &tx2)).unwrap();
    assert!(receipt2.status, "Deploy should succeed");

    // tx3: Call (send data + value to another address)
    let call_data = vec![0xAB, 0xCD, 0xEF, 0x01];
    let tx3 = call_tx(sender, contract_addr_pk, call_data, 500, 2, 200_000, 1);
    let receipt3 = rt().block_on(executor.execute_transaction(&block, &tx3)).unwrap();
    assert!(receipt3.status, "Call should succeed");

    let root_after = state_db.calculate_state_root();
    assert_ne!(root_before, root_after, "State root should change");

    // Verify nonces advanced correctly
    assert_eq!(executor.get_nonce(&sender_addr), 3, "Should have executed 3 txs (nonce 0,1,2)");
}

// =============================================================================
// Additional edge cases
// =============================================================================

#[test]
fn test_batch_single_tx_snapshot_restore() {
    let (executor, state_db) = new_executor();
    let block = test_block();

    let sender = make_pubkey(90);
    let receiver = make_pubkey(91);
    let sender_addr = make_address(90);

    executor.set_balance(&sender_addr, U256::from(100_000u64));

    let snapshot = state_db.snapshot();
    let balance_before = executor.get_balance(&sender_addr);

    let tx = transfer_tx(sender, receiver, 50_000, 0, 100_000, 0);
    let receipt = rt().block_on(executor.execute_transaction(&block, &tx)).unwrap();
    assert!(receipt.status);

    // Balance changed
    assert_ne!(executor.get_balance(&sender_addr), balance_before);

    // Restore
    state_db.restore(snapshot);
    assert_eq!(executor.get_balance(&sender_addr), balance_before);
    // Nonce also restored
    assert_eq!(executor.get_nonce(&sender_addr), 0);
}

#[test]
fn test_batch_state_root_changes_per_tx() {
    let (executor, state_db) = new_executor();
    let block = test_block();

    let sender = make_pubkey(95);
    let receiver = make_pubkey(96);
    let sender_addr = make_address(95);

    executor.set_balance(&sender_addr, U256::from(10_000_000u64));

    let mut roots = vec![state_db.calculate_state_root()];

    for nonce in 0..3u64 {
        let tx = transfer_tx(sender, receiver, 1000, nonce, 100_000, 0);
        let receipt = rt().block_on(executor.execute_transaction(&block, &tx)).unwrap();
        assert!(receipt.status);
        roots.push(state_db.calculate_state_root());
    }

    // All state roots should be unique (each tx changes state)
    for i in 0..roots.len() {
        for j in (i + 1)..roots.len() {
            assert_ne!(roots[i], roots[j], "State root at step {} should differ from step {}", i, j);
        }
    }
}
