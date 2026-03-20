// Sprint HARDEN — WP-H.5: Executor Rollback Hardening Tests
//
// Verifies snapshot/restore correctness under various failure modes.
// All tests use real StateDB (no mocks).

use citrate_execution::state::state_db::StateDB;
use citrate_execution::types::Address;
use primitive_types::U256;

fn test_addr(b: u8) -> Address {
    Address([b; 20])
}

// ─────────────────────────────────────────────────────────────────────
// Test 1: Snapshot and restore preserves original balance and nonce
// ─────────────────────────────────────────────────────────────────────

#[test]
fn test_snapshot_restore_preserves_state() {
    let db = StateDB::new();
    let alice = test_addr(1);

    db.accounts.set_balance(alice, U256::from(1000));
    db.accounts.set_nonce(alice, 5);

    let snap = db.snapshot();

    db.accounts.set_balance(alice, U256::from(9999));
    db.accounts.set_nonce(alice, 99);
    assert_eq!(db.accounts.get_balance(&alice), U256::from(9999));

    db.restore(snap);

    assert_eq!(db.accounts.get_balance(&alice), U256::from(1000));
    assert_eq!(db.accounts.get_nonce(&alice), 5);
}

// ─────────────────────────────────────────────────────────────────────
// Test 2: Snapshot restore clears new accounts created after snapshot
// ─────────────────────────────────────────────────────────────────────

#[test]
fn test_snapshot_restore_clears_new_accounts() {
    let db = StateDB::new();
    let alice = test_addr(1);
    let bob = test_addr(2);

    db.accounts.set_balance(alice, U256::from(1000));
    let snap = db.snapshot();

    db.accounts.set_balance(bob, U256::from(500));
    assert_eq!(db.accounts.get_balance(&bob), U256::from(500));

    db.restore(snap);
    assert_eq!(db.accounts.get_balance(&bob), U256::zero());
}

// ─────────────────────────────────────────────────────────────────────
// Test 3: Nested snapshots work correctly
// ─────────────────────────────────────────────────────────────────────

#[test]
fn test_nested_snapshots() {
    let db = StateDB::new();
    let alice = test_addr(1);

    db.accounts.set_balance(alice, U256::from(100));
    let snap1 = db.snapshot();

    db.accounts.set_balance(alice, U256::from(200));
    let snap2 = db.snapshot();

    db.accounts.set_balance(alice, U256::from(300));

    db.restore(snap2);
    assert_eq!(db.accounts.get_balance(&alice), U256::from(200));

    db.restore(snap1);
    assert_eq!(db.accounts.get_balance(&alice), U256::from(100));
}

// ─────────────────────────────────────────────────────────────────────
// Test 4: Contract storage rollback (byte-level API)
// ─────────────────────────────────────────────────────────────────────

#[test]
fn test_storage_rollback() {
    let db = StateDB::new();
    let contract = test_addr(10);
    let key = b"slot_42".to_vec();

    db.set_storage(contract, key.clone(), b"value_100".to_vec());
    let snap = db.snapshot();

    db.set_storage(contract, key.clone(), b"value_999".to_vec());
    assert_eq!(db.get_storage(&contract, &key), Some(b"value_999".to_vec()));

    db.restore(snap);
    assert_eq!(db.get_storage(&contract, &key), Some(b"value_100".to_vec()));
}

// ─────────────────────────────────────────────────────────────────────
// Test 5: Code storage rollback
// ─────────────────────────────────────────────────────────────────────

#[test]
fn test_code_rollback() {
    let db = StateDB::new();
    let contract = test_addr(10);
    let code1 = vec![0x60, 0x80, 0x60, 0x40, 0x52];
    let code2 = vec![0xFF, 0xFE];

    let hash1 = db.set_code(contract, code1.clone());
    let snap = db.snapshot();

    let _hash2 = db.set_code(contract, code2.clone());

    db.restore(snap);
    assert_eq!(db.get_code(&hash1), Some(code1));
}

// ─────────────────────────────────────────────────────────────────────
// Test 6: Multiple rollbacks don't corrupt state
// ─────────────────────────────────────────────────────────────────────

#[test]
fn test_repeated_rollbacks() {
    let db = StateDB::new();
    let alice = test_addr(1);

    db.accounts.set_balance(alice, U256::from(1000));

    for i in 0..100u64 {
        let snap = db.snapshot();
        db.accounts.set_balance(alice, U256::from(i * 100));
        db.restore(snap);
    }

    assert_eq!(db.accounts.get_balance(&alice), U256::from(1000));
}

// ─────────────────────────────────────────────────────────────────────
// Test 7: Large state rollback (200 accounts)
// ─────────────────────────────────────────────────────────────────────

#[test]
fn test_large_state_rollback() {
    let db = StateDB::new();

    for i in 1u8..=200 {
        let addr = Address([i; 20]);
        db.accounts.set_balance(addr, U256::from(i as u64 * 100));
    }

    let snap = db.snapshot();

    for i in 1u8..=200 {
        let addr = Address([i; 20]);
        db.accounts.set_balance(addr, U256::from(99999));
    }

    db.restore(snap);

    for i in 1u8..=200 {
        let addr = Address([i; 20]);
        assert_eq!(
            db.accounts.get_balance(&addr),
            U256::from(i as u64 * 100),
            "Account {} balance wrong after rollback", i
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// Test 8: Snapshot after restore produces valid new snapshot
// ─────────────────────────────────────────────────────────────────────

#[test]
fn test_snapshot_after_restore() {
    let db = StateDB::new();
    let alice = test_addr(1);

    db.accounts.set_balance(alice, U256::from(100));
    let snap1 = db.snapshot();

    db.accounts.set_balance(alice, U256::from(200));
    db.restore(snap1);
    assert_eq!(db.accounts.get_balance(&alice), U256::from(100));

    // Take new snapshot AFTER restore
    let snap2 = db.snapshot();
    db.accounts.set_balance(alice, U256::from(300));

    db.restore(snap2);
    assert_eq!(db.accounts.get_balance(&alice), U256::from(100));
}

// ─────────────────────────────────────────────────────────────────────
// Test 9: Concurrent storage slots rollback independently
// ─────────────────────────────────────────────────────────────────────

#[test]
fn test_multiple_storage_slots_rollback() {
    let db = StateDB::new();
    let contract = test_addr(10);

    db.set_storage(contract, b"slot_0".to_vec(), b"val_0".to_vec());
    db.set_storage(contract, b"slot_1".to_vec(), b"val_1".to_vec());
    db.set_storage(contract, b"slot_2".to_vec(), b"val_2".to_vec());

    let snap = db.snapshot();

    db.set_storage(contract, b"slot_0".to_vec(), b"changed_0".to_vec());
    db.set_storage(contract, b"slot_1".to_vec(), b"changed_1".to_vec());
    // slot_2 not changed

    db.restore(snap);

    assert_eq!(db.get_storage(&contract, b"slot_0"), Some(b"val_0".to_vec()));
    assert_eq!(db.get_storage(&contract, b"slot_1"), Some(b"val_1".to_vec()));
    assert_eq!(db.get_storage(&contract, b"slot_2"), Some(b"val_2".to_vec()));
}

// ─────────────────────────────────────────────────────────────────────
// Test 10: Rollback with mixed account + storage mutations
// ─────────────────────────────────────────────────────────────────────

#[test]
fn test_mixed_account_and_storage_rollback() {
    let db = StateDB::new();
    let alice = test_addr(1);
    let contract = test_addr(10);

    db.accounts.set_balance(alice, U256::from(1000));
    db.set_storage(contract, b"key".to_vec(), b"original".to_vec());

    let snap = db.snapshot();

    db.accounts.set_balance(alice, U256::from(0));
    db.set_storage(contract, b"key".to_vec(), b"mutated".to_vec());

    db.restore(snap);

    assert_eq!(db.accounts.get_balance(&alice), U256::from(1000));
    assert_eq!(db.get_storage(&contract, b"key"), Some(b"original".to_vec()));
}
