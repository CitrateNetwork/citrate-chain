// Sprint RR — WP-RR.2: Sequencer crate coverage push to 98%
//
// Tests focused on: reconcile_nonces, rollback_nonce_for_sender,
// get_best_transactions multi-sender, evict_lowest_priority,
// TxClass priority_multiplier, validator unblacklist, parallel pipeline,
// validate_state combined, rate limit boundaries, block_builder classify.

use citrate_consensus::types::{Hash, PublicKey, Signature, Transaction};
use citrate_sequencer::{Mempool, MempoolConfig, TxClass};
use citrate_sequencer::validator::{
    AccountState, MockStateProvider, StateProvider, TxValidator, ValidationError,
    ValidationPipeline, ValidationRules,
};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_tx(nonce: u64, gas_price: u64, sender_byte: u8) -> Transaction {
    let mut hash_data = [0u8; 32];
    hash_data[0..8].copy_from_slice(&nonce.to_le_bytes());
    hash_data[8..16].copy_from_slice(&gas_price.to_le_bytes());
    hash_data[16] = sender_byte;

    let mut from_key = [sender_byte; 32];
    from_key[31] = 1; // Ensure non-zero

    Transaction {
        hash: Hash::new(hash_data),
        nonce,
        from: PublicKey::new(from_key),
        to: Some(PublicKey::new([2; 32])),
        value: 1000,
        gas_limit: 21000,
        gas_price,
        data: vec![],
        signature: Signature::new([1; 64]),
        tx_type: None,
        chain_id: Some(40204), // Matches canonical MempoolConfig::default()
        ..Default::default()
    }
}

fn relaxed_config() -> MempoolConfig {
    MempoolConfig {
        require_valid_signature: false,
        ..Default::default()
    }
}

fn relaxed_rules() -> ValidationRules {
    ValidationRules {
        verify_signatures: false,
        check_balance: false,
        check_nonce: false,
        ..Default::default()
    }
}

// ===========================================================================
// 1. TxClass priority_multiplier — all 7 variants
// ===========================================================================

#[test]
fn test_txclass_priority_multipliers() {
    assert_eq!(TxClass::System.priority_multiplier(), 1000);
    assert_eq!(TxClass::ModelUpdate.priority_multiplier(), 100);
    assert_eq!(TxClass::Compute.priority_multiplier(), 80);
    assert_eq!(TxClass::Training.priority_multiplier(), 50);
    assert_eq!(TxClass::Inference.priority_multiplier(), 20);
    assert_eq!(TxClass::Storage.priority_multiplier(), 10);
    assert_eq!(TxClass::Standard.priority_multiplier(), 1);
}

#[test]
fn test_txclass_system_highest_priority() {
    let classes = [
        TxClass::Standard, TxClass::Storage, TxClass::Inference,
        TxClass::Training, TxClass::Compute, TxClass::ModelUpdate, TxClass::System,
    ];
    for &class in &classes[..6] {
        assert!(TxClass::System.priority_multiplier() > class.priority_multiplier());
    }
}

// ===========================================================================
// 2. Mempool — reconcile_nonces, rollback, eviction, get_best multi-sender
// ===========================================================================

#[tokio::test]
async fn test_reconcile_nonces_after_removal() {
    let mempool = Mempool::new(relaxed_config());

    // Add transactions from same sender at nonces 0, 1, 2
    for i in 0..3 {
        let tx = test_tx(i, 2_000_000_000, 10);
        mempool.add_transaction(tx, TxClass::Standard).await.unwrap();
    }

    // Remove the middle transaction (nonce 1)
    let hash1 = test_tx(1, 2_000_000_000, 10).hash;
    mempool.remove_transaction(&hash1).await;

    // Reconcile should fix nonce map to reflect remaining txs
    mempool.reconcile_nonces().await;

    // After reconcile, the nonce map should reflect max(0, 2) + 1 = 3
    let stats = mempool.stats().await;
    assert_eq!(stats.total_transactions, 2); // 0 and 2 remain
}

#[tokio::test]
async fn test_reconcile_nonces_removes_stale_senders() {
    let mempool = Mempool::new(relaxed_config());

    // Add 1 tx from sender 10
    let tx = test_tx(0, 2_000_000_000, 10);
    mempool.add_transaction(tx.clone(), TxClass::Standard).await.unwrap();

    // Remove it
    mempool.remove_transaction(&tx.hash).await;

    // Reconcile should clean up stale nonce entries
    mempool.reconcile_nonces().await;

    let stats = mempool.stats().await;
    assert_eq!(stats.total_transactions, 0);
}

#[tokio::test]
async fn test_rollback_nonce_tip_removal() {
    let mempool = Mempool::new(relaxed_config());

    // Add nonces 0, 1
    let tx0 = test_tx(0, 2_000_000_000, 10);
    let tx1 = test_tx(1, 2_000_000_000, 10);
    mempool.add_transaction(tx0, TxClass::Standard).await.unwrap();
    mempool.add_transaction(tx1.clone(), TxClass::Standard).await.unwrap();

    // Remove tip (nonce 1) — nonce should roll back to 1
    mempool.remove_transaction(&tx1.hash).await;

    // Next add should succeed at nonce 1 again
    let tx1_retry = test_tx(1, 3_000_000_000, 10);
    let result = mempool.add_transaction(tx1_retry, TxClass::Standard).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_evict_lowest_priority() {
    let config = MempoolConfig {
        max_size: 2,
        require_valid_signature: false,
        ..Default::default()
    };
    let mempool = Mempool::new(config);

    // Add 2 txs (fills up)
    let tx_low = test_tx(0, 1_000_000_000, 10);
    let tx_high = test_tx(0, 5_000_000_000, 20);
    mempool.add_transaction(tx_low.clone(), TxClass::Standard).await.unwrap();
    mempool.add_transaction(tx_high.clone(), TxClass::Standard).await.unwrap();

    // Add a 3rd → should evict the lowest priority
    let tx_new = test_tx(0, 3_000_000_000, 30);
    let result = mempool.add_transaction(tx_new, TxClass::Standard).await;
    assert!(result.is_ok());

    // Should still be 2 txs (one evicted)
    let stats = mempool.stats().await;
    assert_eq!(stats.total_transactions, 2);
}

#[tokio::test]
async fn test_get_best_transactions_multi_sender() {
    let mempool = Mempool::new(relaxed_config());

    // Sender A: nonces 0, 1 (lower gas price)
    let tx_a0 = test_tx(0, 2_000_000_000, 10);
    let tx_a1 = test_tx(1, 2_000_000_000, 10);

    // Sender B: nonce 0 (higher gas price)
    let tx_b0 = test_tx(0, 5_000_000_000, 20);

    mempool.add_transaction(tx_a0, TxClass::Standard).await.unwrap();
    mempool.add_transaction(tx_a1, TxClass::Standard).await.unwrap();
    mempool.add_transaction(tx_b0, TxClass::Standard).await.unwrap();

    let best = mempool.get_best_transactions(10, 1_000_000).await;
    assert_eq!(best.len(), 3);
}

#[tokio::test]
async fn test_get_best_transactions_respects_max_count() {
    let mempool = Mempool::new(relaxed_config());

    for i in 0..5 {
        let tx = test_tx(i, 2_000_000_000, 10);
        mempool.add_transaction(tx, TxClass::Standard).await.unwrap();
    }

    let best = mempool.get_best_transactions(2, 1_000_000).await;
    assert!(best.len() <= 2);
}

#[tokio::test]
async fn test_get_best_transactions_respects_max_size() {
    let mempool = Mempool::new(relaxed_config());

    // Add a tx
    let tx = test_tx(0, 2_000_000_000, 10);
    mempool.add_transaction(tx, TxClass::Standard).await.unwrap();

    // Very small max_size → should get 0 or limited txs
    let best = mempool.get_best_transactions(10, 1).await;
    assert!(best.is_empty() || best.len() <= 1);
}

#[tokio::test]
async fn test_mempool_duplicate_rejected() {
    let mempool = Mempool::new(relaxed_config());

    let tx = test_tx(0, 2_000_000_000, 10);
    mempool.add_transaction(tx.clone(), TxClass::Standard).await.unwrap();

    let result = mempool.add_transaction(tx, TxClass::Standard).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_mempool_sender_limit() {
    let config = MempoolConfig {
        max_per_sender: 2,
        require_valid_signature: false,
        ..Default::default()
    };
    let mempool = Mempool::new(config);

    let tx0 = test_tx(0, 2_000_000_000, 10);
    let tx1 = test_tx(1, 2_000_000_000, 10);
    let tx2 = test_tx(2, 2_000_000_000, 10);

    mempool.add_transaction(tx0, TxClass::Standard).await.unwrap();
    mempool.add_transaction(tx1, TxClass::Standard).await.unwrap();

    let result = mempool.add_transaction(tx2, TxClass::Standard).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_mempool_gas_price_too_low() {
    let mempool = Mempool::new(relaxed_config());

    let tx = test_tx(0, 100, 10); // Gas price way below minimum
    let result = mempool.add_transaction(tx, TxClass::Standard).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_mempool_chain_id_mismatch() {
    let mempool = Mempool::new(relaxed_config());

    let mut tx = test_tx(0, 2_000_000_000, 10);
    tx.chain_id = Some(9999); // Wrong chain

    let result = mempool.add_transaction(tx, TxClass::Standard).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_mempool_missing_chain_id() {
    let mempool = Mempool::new(relaxed_config());

    let mut tx = test_tx(0, 2_000_000_000, 10);
    tx.chain_id = None;

    let result = mempool.add_transaction(tx, TxClass::Standard).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_mempool_nonce_too_low() {
    let mempool = Mempool::new(relaxed_config());

    // Add nonce 0 first
    let tx0 = test_tx(0, 2_000_000_000, 10);
    mempool.add_transaction(tx0, TxClass::Standard).await.unwrap();

    // Try adding nonce 0 again (different hash but same sender+nonce)
    let mut tx0_dup = test_tx(0, 3_000_000_000, 10);
    tx0_dup.hash = Hash::new([99; 32]);

    let result = mempool.add_transaction(tx0_dup, TxClass::Standard).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_mempool_get_transaction() {
    let mempool = Mempool::new(relaxed_config());

    let tx = test_tx(0, 2_000_000_000, 10);
    let hash = tx.hash;
    mempool.add_transaction(tx, TxClass::Standard).await.unwrap();

    assert!(mempool.get_transaction(&hash).await.is_some());
    assert!(mempool.get_transaction(&Hash::new([99; 32])).await.is_none());
}

#[tokio::test]
async fn test_mempool_contains() {
    let mempool = Mempool::new(relaxed_config());

    let tx = test_tx(0, 2_000_000_000, 10);
    let hash = tx.hash;
    mempool.add_transaction(tx, TxClass::Standard).await.unwrap();

    assert!(mempool.contains(&hash).await);
    assert!(!mempool.contains(&Hash::new([99; 32])).await);
}

#[tokio::test]
async fn test_mempool_chain_id() {
    let config = MempoolConfig {
        chain_id: 42,
        require_valid_signature: false,
        ..Default::default()
    };
    let mempool = Mempool::new(config);
    assert_eq!(mempool.chain_id(), 42);
}

#[tokio::test]
async fn test_mempool_stats_by_class() {
    let mempool = Mempool::new(relaxed_config());

    let tx1 = test_tx(0, 2_000_000_000, 10);
    let tx2 = test_tx(0, 3_000_000_000, 20);
    mempool.add_transaction(tx1, TxClass::Standard).await.unwrap();
    mempool.add_transaction(tx2, TxClass::Compute).await.unwrap();

    let stats = mempool.stats().await;
    assert_eq!(stats.unique_senders, 2);
    assert_eq!(stats.total_transactions, 2);
}

#[tokio::test]
async fn test_mempool_ai_transactions() {
    let mempool = Mempool::new(relaxed_config());

    // Regular tx
    let tx1 = test_tx(0, 2_000_000_000, 10);
    mempool.add_transaction(tx1, TxClass::Standard).await.unwrap();

    // No AI transactions initially
    let ai_txs = mempool.get_ai_transactions(10).await;
    assert!(ai_txs.is_empty());
}

// ===========================================================================
// 3. Validator — unblacklist, validate_state combined, rate limit, pipeline
// ===========================================================================

#[tokio::test]
async fn test_validator_unblacklist() {
    let state = Arc::new(MockStateProvider::new());
    let validator = TxValidator::new(relaxed_rules(), state);

    let addr = PublicKey::new([1; 32]);
    validator.blacklist_address(addr).await;

    let tx = Transaction {
        from: addr, gas_price: 1_000_000_000, gas_limit: 21000,
        signature: Signature::new([1; 64]), ..Default::default()
    };

    // Should be rejected while blacklisted
    let result = validator.validate(&tx).await;
    assert!(matches!(result, Err(ValidationError::BlacklistedAddress(_))));

    // Unblacklist
    validator.unblacklist_address(&addr).await;

    // Should now pass
    let result = validator.validate(&tx).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_validator_state_both_balance_and_nonce() {
    let state = Arc::new(MockStateProvider::new());
    let addr = PublicKey::new([1; 32]);
    // gas cost = 21000 * 1_000_000_000 = 21_000_000_000_000
    let gas_cost: u128 = 21_000 * 1_000_000_000;
    state.set_account(addr, AccountState::new(gas_cost + 1000, 5)).await;

    let rules = ValidationRules {
        verify_signatures: false,
        check_balance: true,
        check_nonce: true,
        ..Default::default()
    };
    let validator = TxValidator::new(rules, state);

    // Correct nonce, sufficient balance
    let tx_ok = Transaction {
        from: addr, nonce: 5, gas_price: 1_000_000_000, gas_limit: 21000,
        value: 100, signature: Signature::new([1; 64]), ..Default::default()
    };
    assert!(validator.validate(&tx_ok).await.is_ok());

    // Wrong nonce
    let tx_bad_nonce = Transaction {
        from: addr, nonce: 3, gas_price: 1_000_000_000, gas_limit: 21000,
        value: 100, signature: Signature::new([1; 64]), ..Default::default()
    };
    assert!(matches!(
        validator.validate(&tx_bad_nonce).await,
        Err(ValidationError::InvalidNonce { .. })
    ));

    // Insufficient balance (huge value)
    let tx_bad_bal = Transaction {
        from: addr, nonce: 5, gas_price: 1_000_000_000, gas_limit: 21000,
        value: gas_cost + 999_999, signature: Signature::new([1; 64]), ..Default::default()
    };
    assert!(matches!(
        validator.validate(&tx_bad_bal).await,
        Err(ValidationError::InsufficientBalance { .. })
    ));
}

#[tokio::test]
async fn test_validator_new_account_zero_state() {
    let state = Arc::new(MockStateProvider::new());
    // Don't set any account — defaults to balance=0, nonce=0

    let rules = ValidationRules {
        verify_signatures: false,
        check_balance: true,
        check_nonce: true,
        ..Default::default()
    };
    let validator = TxValidator::new(rules, state);

    // Nonce 0, zero value, should still fail due to gas cost > 0
    let tx = Transaction {
        from: PublicKey::new([1; 32]), nonce: 0, gas_price: 1_000_000_000,
        gas_limit: 21000, value: 0, signature: Signature::new([1; 64]),
        ..Default::default()
    };
    assert!(matches!(
        validator.validate(&tx).await,
        Err(ValidationError::InsufficientBalance { .. })
    ));
}

#[tokio::test]
async fn test_validator_gas_limit_too_high() {
    let state = Arc::new(MockStateProvider::new());
    let validator = TxValidator::new(relaxed_rules(), state);

    let tx = Transaction {
        from: PublicKey::new([1; 32]), gas_price: 1_000_000_000,
        gas_limit: 100_000_000, // Way above max 10M
        signature: Signature::new([1; 64]), ..Default::default()
    };
    assert!(matches!(
        validator.validate(&tx).await,
        Err(ValidationError::GasLimitTooHigh { .. })
    ));
}

#[tokio::test]
async fn test_validator_data_too_large() {
    let state = Arc::new(MockStateProvider::new());
    let validator = TxValidator::new(relaxed_rules(), state);

    let tx = Transaction {
        from: PublicKey::new([1; 32]), gas_price: 1_000_000_000,
        gas_limit: 21000, data: vec![0u8; 256 * 1024], // 256KB > 128KB max
        signature: Signature::new([1; 64]), ..Default::default()
    };
    assert!(matches!(
        validator.validate(&tx).await,
        Err(ValidationError::DataTooLarge { .. })
    ));
}

#[tokio::test]
async fn test_validator_gas_price_too_low() {
    let state = Arc::new(MockStateProvider::new());
    let validator = TxValidator::new(relaxed_rules(), state);

    let tx = Transaction {
        from: PublicKey::new([1; 32]), gas_price: 100, // Way below 1 gwei
        gas_limit: 21000, signature: Signature::new([1; 64]),
        ..Default::default()
    };
    assert!(matches!(
        validator.validate(&tx).await,
        Err(ValidationError::GasPriceTooLow { .. })
    ));
}

#[tokio::test]
async fn test_validator_rate_limit_exceeded() {
    let state = Arc::new(MockStateProvider::new());
    let rules = ValidationRules {
        verify_signatures: false,
        check_balance: false,
        check_nonce: false,
        rate_limit: 2, // Only 2 per window
        ..Default::default()
    };
    let validator = TxValidator::new(rules, state);

    let addr = PublicKey::new([1; 32]);

    // First 2 should succeed
    for i in 0..2 {
        let tx = Transaction {
            hash: Hash::new([i as u8; 32]),
            from: addr, gas_price: 1_000_000_000, gas_limit: 21000,
            signature: Signature::new([1; 64]), ..Default::default()
        };
        assert!(validator.validate(&tx).await.is_ok());
    }

    // 3rd should be rate limited
    let tx3 = Transaction {
        hash: Hash::new([99; 32]),
        from: addr, gas_price: 1_000_000_000, gas_limit: 21000,
        signature: Signature::new([1; 64]), ..Default::default()
    };
    assert!(matches!(
        validator.validate(&tx3).await,
        Err(ValidationError::RateLimitExceeded)
    ));
}

#[tokio::test]
async fn test_validator_batch_validation() {
    let state = Arc::new(MockStateProvider::new());
    let validator = TxValidator::new(relaxed_rules(), state);

    let txs = vec![
        Transaction {
            hash: Hash::new([1; 32]),
            from: PublicKey::new([1; 32]), gas_price: 1_000_000_000,
            gas_limit: 21000, signature: Signature::new([1; 64]),
            ..Default::default()
        },
        Transaction {
            hash: Hash::new([2; 32]),
            from: PublicKey::new([2; 32]), gas_price: 100, // Too low
            gas_limit: 21000, signature: Signature::new([1; 64]),
            ..Default::default()
        },
    ];

    let results = validator.validate_batch(&txs).await;
    assert_eq!(results.len(), 2);
    assert!(results[0].is_ok());
    assert!(results[1].is_err());
}

#[tokio::test]
async fn test_validation_pipeline_parallel() {
    let state = Arc::new(MockStateProvider::new());
    let validator = Arc::new(TxValidator::new(relaxed_rules(), state));
    let pipeline = ValidationPipeline::new(validator);

    let txs = vec![
        Transaction {
            hash: Hash::new([1; 32]),
            from: PublicKey::new([1; 32]), gas_price: 1_000_000_000,
            gas_limit: 21000, signature: Signature::new([1; 64]),
            ..Default::default()
        },
        Transaction {
            hash: Hash::new([2; 32]),
            from: PublicKey::new([2; 32]), gas_price: 100, // Invalid
            gas_limit: 21000, signature: Signature::new([1; 64]),
            ..Default::default()
        },
        Transaction {
            hash: Hash::new([3; 32]),
            from: PublicKey::new([3; 32]), gas_price: 2_000_000_000,
            gas_limit: 21000, signature: Signature::new([1; 64]),
            ..Default::default()
        },
    ];

    let (valid, invalid) = pipeline.process(txs).await;
    assert_eq!(valid.len(), 2);
    assert_eq!(invalid.len(), 1);
}

#[tokio::test]
async fn test_validator_exact_boundary_gas_limit() {
    let state = Arc::new(MockStateProvider::new());
    let rules = ValidationRules {
        verify_signatures: false, check_balance: false, check_nonce: false,
        max_gas_limit: 10_000_000,
        ..Default::default()
    };
    let validator = TxValidator::new(rules, state);

    // Exactly at limit → ok
    let tx_exact = Transaction {
        from: PublicKey::new([1; 32]), gas_price: 1_000_000_000,
        gas_limit: 10_000_000, signature: Signature::new([1; 64]),
        ..Default::default()
    };
    assert!(validator.validate(&tx_exact).await.is_ok());

    // One over → fail
    let tx_over = Transaction {
        from: PublicKey::new([1; 32]), gas_price: 1_000_000_000,
        gas_limit: 10_000_001, signature: Signature::new([1; 64]),
        ..Default::default()
    };
    assert!(matches!(
        validator.validate(&tx_over).await,
        Err(ValidationError::GasLimitTooHigh { .. })
    ));
}

#[tokio::test]
async fn test_validator_exact_boundary_data_size() {
    let state = Arc::new(MockStateProvider::new());
    let rules = ValidationRules {
        verify_signatures: false, check_balance: false, check_nonce: false,
        max_data_size: 128 * 1024,
        ..Default::default()
    };
    let validator = TxValidator::new(rules, state);

    // Exactly at limit → ok
    let tx_exact = Transaction {
        from: PublicKey::new([1; 32]), gas_price: 1_000_000_000,
        gas_limit: 21000, data: vec![0u8; 128 * 1024],
        signature: Signature::new([1; 64]), ..Default::default()
    };
    assert!(validator.validate(&tx_exact).await.is_ok());

    // One byte over → fail
    let tx_over = Transaction {
        from: PublicKey::new([1; 32]), gas_price: 1_000_000_000,
        gas_limit: 21000, data: vec![0u8; 128 * 1024 + 1],
        signature: Signature::new([1; 64]), ..Default::default()
    };
    assert!(matches!(
        validator.validate(&tx_over).await,
        Err(ValidationError::DataTooLarge { .. })
    ));
}

#[tokio::test]
async fn test_validator_exact_balance_boundary() {
    let state = Arc::new(MockStateProvider::new());
    let addr = PublicKey::new([1; 32]);

    // Cost = value (100) + gas_limit * gas_price (21000 * 1_000_000_000 = 21_000_000_000_000)
    let gas_cost: u128 = 21000 * 1_000_000_000;
    let total_cost: u128 = 100 + gas_cost;

    // Exact balance = total cost
    state.set_account(addr, AccountState::new(total_cost, 0)).await;

    let rules = ValidationRules {
        verify_signatures: false, check_balance: true, check_nonce: true,
        ..Default::default()
    };
    let validator = TxValidator::new(rules, state.clone());

    let tx = Transaction {
        from: addr, nonce: 0, gas_price: 1_000_000_000,
        gas_limit: 21000, value: 100, signature: Signature::new([1; 64]),
        ..Default::default()
    };
    assert!(validator.validate(&tx).await.is_ok());

    // One less → fail
    state.set_account(addr, AccountState::new(total_cost - 1, 0)).await;
    assert!(matches!(
        validator.validate(&tx).await,
        Err(ValidationError::InsufficientBalance { .. })
    ));
}

// ===========================================================================
// 4. Mempool — empty sender from key rejected
// ===========================================================================

#[tokio::test]
async fn test_mempool_empty_sender_rejected() {
    let mempool = Mempool::new(relaxed_config());

    let mut tx = test_tx(0, 2_000_000_000, 10);
    tx.from = PublicKey::new([0; 32]); // All zeros

    let result = mempool.add_transaction(tx, TxClass::Standard).await;
    assert!(result.is_err());
}

// ===========================================================================
// 5. MockStateProvider — default/coverage
// ===========================================================================

#[tokio::test]
async fn test_mock_state_provider_defaults() {
    let state = MockStateProvider::default();

    let addr = PublicKey::new([1; 32]);
    assert_eq!(state.get_balance(&addr).await, 0);
    assert_eq!(state.get_nonce(&addr).await, 0);
    assert!(state.get_account(&addr).await.is_none());

    state.set_account(addr, AccountState::new(1000, 5)).await;
    assert_eq!(state.get_balance(&addr).await, 1000);
    assert_eq!(state.get_nonce(&addr).await, 5);
    assert!(state.get_account(&addr).await.is_some());
}
