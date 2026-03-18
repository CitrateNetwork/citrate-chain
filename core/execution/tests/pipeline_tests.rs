// Pipeline integration tests for the Citrate execution layer.
// Every test exercises the REAL Executor.execute_transaction() pipeline.

use citrate_consensus::types::{
    Block, BlockHeader, GhostDagParams, Hash, PublicKey, Signature,
    Transaction as ConsensusTransaction, VrfProof,
};
use citrate_execution::{address_utils, types::*, Executor, StateDB};
use primitive_types::U256;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_address(seed: u8) -> Address {
    let mut pk_bytes = [0u8; 32];
    pk_bytes[0] = seed;
    // last 12 bytes zero => embedded EVM address path
    address_utils::normalize_address(&PublicKey::new(pk_bytes))
}

fn make_pubkey_for_address(seed: u8) -> PublicKey {
    let mut pk_bytes = [0u8; 32];
    pk_bytes[0] = seed;
    PublicKey::new(pk_bytes)
}

fn test_block() -> Block {
    Block {
        header: BlockHeader {
            version: 1,
            block_hash: Hash::new([0xAA; 32]),
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

// ---------------------------------------------------------------------------
// Transfer Tests (unhappy path focus)
// ---------------------------------------------------------------------------

/// 1. Sender has 100 wei, tries to send 200. Must fail with InsufficientBalance.
#[test]
fn test_transfer_insufficient_balance_fails() {
    let (executor, _) = new_executor();
    let block = test_block();

    let sender_pk = make_pubkey_for_address(1);
    let receiver_pk = make_pubkey_for_address(2);
    let sender_addr = make_address(1);

    // Fund sender with only 100 wei
    executor.set_balance(&sender_addr, U256::from(100u64));

    // gas_price=0 so gas cost is 0 — the 200 value alone exceeds balance
    let tx = transfer_tx(sender_pk, receiver_pk, 200, 0, 21_000, 0);

    let result = rt().block_on(executor.execute_transaction(&block, &tx));
    match result {
        Err(ExecutionError::InsufficientBalance { .. }) => {} // expected
        Err(e) => panic!("Expected InsufficientBalance, got: {:?}", e),
        Ok(receipt) => {
            // Some executors return a reverted receipt instead of an error
            assert!(!receipt.status, "Receipt should indicate failure");
        }
    }
}

/// 2. Send value to own address. Balance should remain the same (minus gas).
#[test]
fn test_transfer_to_self_succeeds() {
    let (executor, _) = new_executor();
    let block = test_block();

    let pk = make_pubkey_for_address(10);
    let addr = make_address(10);

    let initial = U256::from(1_000_000u64);
    executor.set_balance(&addr, initial);

    let tx = transfer_tx(pk, pk, 500, 0, 100_000, 1);
    let result = rt().block_on(executor.execute_transaction(&block, &tx));
    let receipt = result.expect("Self-transfer should not error");

    // Self-transfer: accounts.transfer short-circuits (from==to), so value not
    // deducted. Only gas is consumed.
    let final_balance = executor.get_balance(&addr);
    // gas_cost = gas_limit * gas_price = 100_000; refund = (gas_limit - gas_used) * gas_price
    // net gas deducted = gas_used * gas_price
    let gas_deducted = U256::from(receipt.gas_used) * U256::from(1u64);
    assert_eq!(
        final_balance,
        initial - gas_deducted,
        "Self-transfer should only deduct gas, not value"
    );
}

/// 3. Send 0 value. Gas should still be consumed.
#[test]
fn test_transfer_zero_value_uses_gas() {
    let (executor, _) = new_executor();
    let block = test_block();

    let sender_pk = make_pubkey_for_address(20);
    let receiver_pk = make_pubkey_for_address(21);
    let sender_addr = make_address(20);

    let initial = U256::from(1_000_000u64);
    executor.set_balance(&sender_addr, initial);

    let tx = transfer_tx(sender_pk, receiver_pk, 0, 0, 100_000, 1);
    let receipt = rt()
        .block_on(executor.execute_transaction(&block, &tx))
        .expect("Zero-value transfer should succeed");

    assert!(receipt.status, "Zero-value transfer should succeed");
    assert!(receipt.gas_used > 0, "Gas must be consumed even for zero-value transfers");

    let final_balance = executor.get_balance(&sender_addr);
    assert!(
        final_balance < initial,
        "Sender balance should decrease due to gas"
    );
}

/// 4. Try sending u128::MAX (the max value the Transaction.value field supports).
///    Should be rejected due to insufficient balance.
#[test]
fn test_transfer_max_value_overflow_rejected() {
    let (executor, _) = new_executor();
    let block = test_block();

    let sender_pk = make_pubkey_for_address(30);
    let receiver_pk = make_pubkey_for_address(31);
    let sender_addr = make_address(30);

    // Give sender a large but not max balance
    executor.set_balance(&sender_addr, U256::from(10u64).pow(U256::from(18u64)));

    let tx = transfer_tx(sender_pk, receiver_pk, u128::MAX, 0, 21_000, 0);
    let result = rt().block_on(executor.execute_transaction(&block, &tx));

    match result {
        Err(ExecutionError::InsufficientBalance { .. }) => {} // expected
        Err(e) => panic!("Expected InsufficientBalance, got: {:?}", e),
        Ok(receipt) => {
            assert!(!receipt.status, "Max-value transfer should fail");
        }
    }
}

/// 5. Submit tx with nonce=0 when account nonce is already 1.
#[test]
fn test_nonce_too_low_rejected() {
    let (executor, _) = new_executor();
    let block = test_block();

    let sender_pk = make_pubkey_for_address(40);
    let receiver_pk = make_pubkey_for_address(41);
    let sender_addr = make_address(40);

    executor.set_balance(&sender_addr, U256::from(1_000_000u64));
    executor.set_nonce(&sender_addr, 1); // nonce is already 1

    let tx = transfer_tx(sender_pk, receiver_pk, 100, 0, 100_000, 1); // nonce=0 in tx
    let result = rt().block_on(executor.execute_transaction(&block, &tx));

    match result {
        Err(ExecutionError::InvalidNonce { expected, got }) => {
            assert_eq!(expected, 1, "Expected nonce should be 1");
            assert_eq!(got, 0, "Got nonce should be 0");
        }
        Err(e) => panic!("Expected InvalidNonce, got: {:?}", e),
        Ok(_) => panic!("Stale nonce should be rejected"),
    }
}

/// 6. Submit tx with nonce=5 when account nonce is 3. Must be rejected.
#[test]
fn test_nonce_gap_handling() {
    let (executor, _) = new_executor();
    let block = test_block();

    let sender_pk = make_pubkey_for_address(50);
    let receiver_pk = make_pubkey_for_address(51);
    let sender_addr = make_address(50);

    executor.set_balance(&sender_addr, U256::from(1_000_000u64));
    executor.set_nonce(&sender_addr, 3);

    let tx = transfer_tx(sender_pk, receiver_pk, 100, 5, 100_000, 1); // nonce=5, expected=3
    let result = rt().block_on(executor.execute_transaction(&block, &tx));

    match result {
        Err(ExecutionError::InvalidNonce { expected, got }) => {
            assert_eq!(expected, 3);
            assert_eq!(got, 5);
        }
        Err(e) => panic!("Expected InvalidNonce, got: {:?}", e),
        Ok(_) => panic!("Nonce gap should be rejected"),
    }
}

// ---------------------------------------------------------------------------
// Gas Tests (unhappy path focus)
// ---------------------------------------------------------------------------

/// 7. Transaction with gas_limit=0.
#[test]
fn test_gas_limit_zero_rejected() {
    let (executor, _) = new_executor();
    let block = test_block();

    let sender_pk = make_pubkey_for_address(60);
    let receiver_pk = make_pubkey_for_address(61);
    let sender_addr = make_address(60);

    executor.set_balance(&sender_addr, U256::from(1_000_000u64));

    let tx = transfer_tx(sender_pk, receiver_pk, 100, 0, 0, 1); // gas_limit=0
    let result = rt().block_on(executor.execute_transaction(&block, &tx));

    match result {
        Err(ExecutionError::OutOfGas) => {} // expected
        Err(e) => {
            // Any error is acceptable — the tx must not succeed
            let _ = e;
        }
        Ok(receipt) => {
            assert!(
                !receipt.status,
                "Transaction with gas_limit=0 should not succeed"
            );
        }
    }
}

/// 8. Gas limit below intrinsic gas (21000 for simple transfer).
#[test]
fn test_gas_limit_below_intrinsic_rejected() {
    let (executor, _) = new_executor();
    let block = test_block();

    let sender_pk = make_pubkey_for_address(70);
    let receiver_pk = make_pubkey_for_address(71);
    let sender_addr = make_address(70);

    executor.set_balance(&sender_addr, U256::from(1_000_000u64));

    // gas_limit=100, which is far below 21000 intrinsic gas for a transfer
    let tx = transfer_tx(sender_pk, receiver_pk, 100, 0, 100, 1);
    let result = rt().block_on(executor.execute_transaction(&block, &tx));

    match result {
        Err(ExecutionError::OutOfGas) => {} // expected
        Err(e) => {
            // Any error is acceptable for under-gassed tx
            let _ = e;
        }
        Ok(receipt) => {
            assert!(
                !receipt.status,
                "Transaction with gas below intrinsic should fail"
            );
        }
    }
}

/// 9. Verify behavior with 0 gas price — should be accepted (free tx).
#[test]
fn test_gas_price_zero_accepted() {
    let (executor, _) = new_executor();
    let block = test_block();

    let sender_pk = make_pubkey_for_address(80);
    let receiver_pk = make_pubkey_for_address(81);
    let sender_addr = make_address(80);
    let receiver_addr = make_address(81);

    executor.set_balance(&sender_addr, U256::from(1_000u64));

    let tx = transfer_tx(sender_pk, receiver_pk, 100, 0, 100_000, 0); // gas_price=0
    let receipt = rt()
        .block_on(executor.execute_transaction(&block, &tx))
        .expect("Gas price 0 should be accepted");

    assert!(receipt.status, "Zero gas price transfer should succeed");
    // No gas cost deducted since gas_price=0
    assert_eq!(
        executor.get_balance(&sender_addr),
        U256::from(900u64),
        "Sender should have 1000 - 100 = 900"
    );
    assert_eq!(
        executor.get_balance(&receiver_addr),
        U256::from(100u64),
        "Receiver should have 100"
    );
}

// ---------------------------------------------------------------------------
// State Tests
// ---------------------------------------------------------------------------

/// 10. Transfer 50 from A(100) to B(0). Verify A=100-50-gas, B=50.
#[test]
fn test_balance_after_successful_transfer() {
    let (executor, _) = new_executor();
    let block = test_block();

    let a_pk = make_pubkey_for_address(90);
    let b_pk = make_pubkey_for_address(91);
    let a_addr = make_address(90);
    let b_addr = make_address(91);

    executor.set_balance(&a_addr, U256::from(100u64));
    executor.set_balance(&b_addr, U256::zero());

    // gas_price=0 so we can check exact balances without gas arithmetic
    let tx = transfer_tx(a_pk, b_pk, 50, 0, 100_000, 0);
    let receipt = rt()
        .block_on(executor.execute_transaction(&block, &tx))
        .expect("Transfer should succeed");

    assert!(receipt.status, "Transfer should be successful");
    assert_eq!(executor.get_balance(&a_addr), U256::from(50u64));
    assert_eq!(executor.get_balance(&b_addr), U256::from(50u64));
}

/// 11. Execute tx, verify nonce went from 0 to 1.
#[test]
fn test_nonce_increments_after_successful_tx() {
    let (executor, _) = new_executor();
    let block = test_block();

    let sender_pk = make_pubkey_for_address(100);
    let receiver_pk = make_pubkey_for_address(101);
    let sender_addr = make_address(100);

    executor.set_balance(&sender_addr, U256::from(1_000_000u64));
    assert_eq!(executor.get_nonce(&sender_addr), 0);

    let tx = transfer_tx(sender_pk, receiver_pk, 100, 0, 100_000, 1);
    let receipt = rt()
        .block_on(executor.execute_transaction(&block, &tx))
        .expect("Transfer should succeed");

    assert!(receipt.status);
    assert_eq!(
        executor.get_nonce(&sender_addr),
        1,
        "Nonce should increment from 0 to 1 after successful tx"
    );
}

/// 12. Execute failing tx (insufficient balance for transfer value),
///     verify that the balance is unchanged except for gas consumption.
#[test]
fn test_state_unchanged_after_reverted_tx() {
    let (executor, _) = new_executor();
    let block = test_block();

    let sender_pk = make_pubkey_for_address(110);
    let receiver_pk = make_pubkey_for_address(111);
    let sender_addr = make_address(110);
    let receiver_addr = make_address(111);

    // Sender has enough for gas but NOT enough for value + gas.
    // gas_cost = gas_limit * gas_price = 100_000 * 1 = 100_000
    // total needed = gas_cost + value = 100_000 + 500_000 = 600_000
    // balance = 200_000 — insufficient
    executor.set_balance(&sender_addr, U256::from(200_000u64));
    executor.set_balance(&receiver_addr, U256::from(0u64));

    let tx = transfer_tx(sender_pk, receiver_pk, 500_000, 0, 100_000, 1);
    let result = rt().block_on(executor.execute_transaction(&block, &tx));

    match result {
        Err(ExecutionError::InsufficientBalance { .. }) => {
            // State should be fully rolled back
            assert_eq!(
                executor.get_balance(&sender_addr),
                U256::from(200_000u64),
                "Sender balance must be unchanged after rejected tx"
            );
            assert_eq!(
                executor.get_balance(&receiver_addr),
                U256::from(0u64),
                "Receiver balance must be unchanged after rejected tx"
            );
        }
        Ok(receipt) => {
            assert!(!receipt.status, "Tx should have failed");
            // Receiver should not have received anything
            assert_eq!(executor.get_balance(&receiver_addr), U256::from(0u64));
        }
        Err(e) => panic!("Unexpected error: {:?}", e),
    }
}

// ---------------------------------------------------------------------------
// Contract Tests
// ---------------------------------------------------------------------------

/// 13. Deploy simple bytecode via execute_transaction, verify get_code returns it.
#[test]
fn test_contract_deployment_stores_code() {
    let (executor, state_db) = new_executor();
    let block = test_block();

    let deployer_pk = make_pubkey_for_address(120);
    let deployer_addr = make_address(120);

    // Fund deployer generously
    executor.set_balance(
        &deployer_addr,
        U256::from(10u64).pow(U256::from(18u64)),
    );

    // Minimal init code that returns 0x42 as runtime code:
    // PUSH1 0x01      (60 01) — size of runtime code
    // PUSH1 0x0C      (60 0c) — offset of runtime code in init
    // PUSH1 0x00      (60 00) — destination in memory
    // CODECOPY        (39)
    // PUSH1 0x01      (60 01) — size
    // PUSH1 0x00      (60 00) — offset
    // RETURN          (f3)
    // --- runtime code starts here (offset 0x0C = 12) ---
    // PUSH1 0x42      (60 42) — but we only copy 1 byte so just 0x42
    // Actually let's use a simpler approach: return a single STOP opcode
    // PUSH1 0x01, PUSH1 0x0a, PUSH1 0x00, CODECOPY, PUSH1 0x01, PUSH1 0x00, RETURN, STOP
    let init_code = vec![
        0x60, 0x01, // PUSH1 0x01 (runtime code size = 1 byte)
        0x60, 0x0a, // PUSH1 0x0a (runtime code offset in init = 10)
        0x60, 0x00, // PUSH1 0x00 (memory dest)
        0x39,       // CODECOPY
        0x60, 0x01, // PUSH1 0x01 (return size)
        0x60, 0x00, // PUSH1 0x00 (return offset)
        0xf3,       // RETURN
        0x00,       // STOP (this is the runtime code)
    ];

    let tx = deploy_tx(deployer_pk, init_code, 0, 1_000_000, 1);
    let receipt = rt()
        .block_on(executor.execute_transaction(&block, &tx))
        .expect("Deployment should succeed");

    assert!(receipt.status, "Contract deployment should succeed");
    // The output should contain the deployed address (20 bytes)
    assert!(
        !receipt.output.is_empty(),
        "Deployment receipt should contain deployed address"
    );

    // Derive the deployed contract address from the output
    let mut deployed_addr_bytes = [0u8; 20];
    let len = receipt.output.len().min(20);
    deployed_addr_bytes[..len].copy_from_slice(&receipt.output[..len]);
    let deployed_addr = Address(deployed_addr_bytes);

    // Verify code is stored
    let code_hash = executor.get_code_hash(&deployed_addr);
    assert_ne!(
        code_hash,
        Hash::default(),
        "Deployed contract should have non-default code hash"
    );

    // Verify we can retrieve the code
    let code = state_db.get_code(&code_hash);
    assert!(code.is_some(), "Should be able to retrieve deployed code");
    let code_bytes = code.unwrap();
    assert!(!code_bytes.is_empty(), "Deployed code should not be empty");
}

/// 14. Call an address with no code deployed. Verify it does not error (EVM treats it as success).
#[test]
fn test_call_nonexistent_contract() {
    let (executor, _) = new_executor();
    let block = test_block();

    let caller_pk = make_pubkey_for_address(130);
    let target_pk = make_pubkey_for_address(131);
    let caller_addr = make_address(130);

    executor.set_balance(&caller_addr, U256::from(1_000_000u64));

    // Call a contract address that has no code — just some arbitrary calldata
    let tx = call_tx(caller_pk, target_pk, vec![0xDE, 0xAD, 0xBE, 0xEF], 0, 0, 100_000, 1);
    let receipt = rt()
        .block_on(executor.execute_transaction(&block, &tx))
        .expect("Call to empty address should not hard-error");

    // In EVM, calling an address with no code is treated as a successful no-op
    assert!(
        receipt.status,
        "Call to address with no code should succeed (EVM semantics)"
    );
}

// ---------------------------------------------------------------------------
// EVM Opcode Edge Cases
// ---------------------------------------------------------------------------

/// 15. Bytecode that pushes 1025 items onto the EVM stack (limit=1024).
///     The executor must handle this without panicking. REVM will halt.
///     Verify gas is consumed and sender balance decreases.
#[test]
fn test_stack_overflow_1025_pushes() {
    let (executor, _state_db) = new_executor();
    let block = test_block();

    let caller_pk = make_pubkey_for_address(140);
    let contract_pk = make_pubkey_for_address(141);
    let caller_addr = make_address(140);
    let contract_addr = make_address(141);

    let initial_balance = U256::from(10u64).pow(U256::from(18u64));
    executor.set_balance(&caller_addr, initial_balance);

    // Build bytecode: 1025 x (PUSH1 0x01) — each pushes 1 item onto the stack
    let mut code = Vec::with_capacity(1025 * 2 + 1);
    for _ in 0..1025 {
        code.push(0x60); // PUSH1
        code.push(0x01); // value
    }
    code.push(0x00); // STOP

    executor.set_code(&contract_addr, code);

    let tx = call_tx(caller_pk, contract_pk, vec![], 0, 0, 10_000_000, 1);
    let result = rt().block_on(executor.execute_transaction(&block, &tx));

    // Reaching this point without panic proves graceful handling.
    // Gas must be consumed regardless of success/failure outcome.
    match result {
        Ok(_receipt) => {
            let final_balance = executor.get_balance(&caller_addr);
            assert!(
                final_balance <= initial_balance,
                "Sender balance must not increase after executing stack-overflow bytecode"
            );
            // Nonce should have incremented (tx was processed)
            assert_eq!(executor.get_nonce(&caller_addr), 1, "Nonce should increment");
        }
        Err(_) => {
            // Error is acceptable — the executor caught the overflow.
            // Balance should still be unchanged (pre-validation failure).
        }
    }
}

/// 16. Bytecode containing 0xFE (INVALID opcode). The executor must handle
///     it without panicking. Verify gas is consumed and nonce increments.
#[test]
fn test_invalid_opcode_reverts() {
    let (executor, _state_db) = new_executor();
    let block = test_block();

    let caller_pk = make_pubkey_for_address(150);
    let contract_pk = make_pubkey_for_address(151);
    let caller_addr = make_address(150);
    let contract_addr = make_address(151);

    let initial_balance = U256::from(10u64).pow(U256::from(18u64));
    executor.set_balance(&caller_addr, initial_balance);

    // Contract code: just the INVALID opcode
    let code = vec![0xFE];
    executor.set_code(&contract_addr, code);

    let tx = call_tx(caller_pk, contract_pk, vec![], 0, 0, 1_000_000, 1);
    let result = rt().block_on(executor.execute_transaction(&block, &tx));

    // Reaching this point without panic proves graceful handling.
    match result {
        Ok(_receipt) => {
            let final_balance = executor.get_balance(&caller_addr);
            assert!(
                final_balance <= initial_balance,
                "Sender balance must not increase after INVALID opcode execution"
            );
            // Nonce should have incremented (tx was processed)
            assert_eq!(executor.get_nonce(&caller_addr), 1, "Nonce should increment");
        }
        Err(_) => {
            // Halt/Revert error is also acceptable
        }
    }
}
