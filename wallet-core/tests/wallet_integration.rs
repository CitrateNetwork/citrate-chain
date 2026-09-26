// B1.1-F-1: native-only — full pipeline through `KeyManager` + `chain`.
#![cfg(feature = "native")]
//! Integration tests — full wallet pipeline.
//!
//! Tests the complete flow: create account → unlock → build tx → sign → verify.
//! Also tests cross-module interactions: keys + session + chain.

use citrate_wallet_core::keys::KeyManager;
use citrate_wallet_core::chain::TransactionBuilder;
use citrate_wallet_core::session::SessionManager;
use citrate_wallet_core::types::KeyType;
use std::path::PathBuf;

fn test_path() -> PathBuf {
    std::env::temp_dir().join(format!("citrate_integ_{}", uuid::Uuid::new_v4()))
}

// =========================================================================
// FULL PIPELINE: Create → Unlock → Sign → Verify
// =========================================================================

#[tokio::test]
async fn test_full_ed25519_pipeline() {
    let path = test_path();
    let mgr = KeyManager::new(&path);

    // 1. Create account with mnemonic
    let result = mgr.create_account("strongpassword1", "Primary").expect("create");
    assert!(!result.mnemonic.is_empty());
    let words: Vec<&str> = result.mnemonic.split_whitespace().collect();
    assert_eq!(words.len(), 24, "Must generate 24-word mnemonic");

    // 2. Unlock
    let count = mgr.unlock("strongpassword1").expect("unlock");
    assert_eq!(count, 1);

    // 3. Get signing key
    let key = mgr.get_signing_key(&result.address).expect("get key");
    assert_eq!(key.key_type(), KeyType::Ed25519);

    // 4. Build and sign transaction
    let signed_tx = TransactionBuilder::new()
        .to("0xb5ddd4eb356ddf3bf51eb3aec1ed28213be59129")
        .value(1_000_000_000_000_000_000) // 1 SALT
        .chain_id(40204)
        .gas_limit(21_000)
        .gas_price(1_000_000_000)
        .sign(
            match &key {
                citrate_wallet_core::keys::UnifiedKey::Ed25519(k) => k,
                _ => panic!("Expected Ed25519 key"),
            },
            0, // nonce
        )
        .expect("sign tx");

    // 5. Verify transaction properties
    assert!(!signed_tx.hash.is_empty());
    assert!(!signed_tx.signature.is_empty());
    assert_eq!(signed_tx.chain_id, 40204);
    assert_eq!(signed_tx.nonce, 0);
    assert_eq!(signed_tx.value, 1_000_000_000_000_000_000);
    assert!(!signed_tx.raw.is_empty());

    // 6. Lock wallet
    mgr.lock();
    assert!(!mgr.is_unlocked());

    // 7. Verify key is no longer accessible
    assert!(mgr.get_signing_key(&result.address).is_err());

    std::fs::remove_dir_all(&path).ok();
}

#[tokio::test]
async fn test_full_secp256k1_pipeline() {
    let path = test_path();
    let mgr = KeyManager::new(&path);

    // 1. Create secp256k1 account
    let result = mgr.create_secp256k1_account("strongpassword1", "EVM").expect("create secp");

    // 2. Unlock and get key
    mgr.unlock("strongpassword1").expect("unlock");
    let key = mgr.get_signing_key(&result.address).expect("get key");
    assert_eq!(key.key_type(), KeyType::Secp256k1);

    // 3. Sign data with secp256k1
    let sig = key.sign(b"transaction hash bytes here");
    assert_eq!(sig.len(), 64, "ECDSA signature must be 64 bytes (r + s)");

    // 4. Lock
    mgr.lock();
    assert!(mgr.get_signing_key(&result.address).is_err());

    std::fs::remove_dir_all(&path).ok();
}

// =========================================================================
// MNEMONIC RECOVERY PIPELINE
// =========================================================================

#[tokio::test]
async fn test_full_recovery_pipeline() {
    let path1 = test_path();
    let mgr1 = KeyManager::new(&path1);

    // 1. Create account and capture mnemonic
    let original = mgr1.create_account("strongpassword1", "Original").expect("create");
    let mnemonic = original.mnemonic.clone();
    let original_address = original.address.clone();

    // 2. Sign a transaction with original key
    mgr1.unlock("strongpassword1").expect("unlock");
    let key1 = mgr1.get_signing_key(&original_address).expect("get key");
    let sig1 = key1.sign(b"recovery test data");

    // 3. Simulate wallet loss — new path, new manager
    let path2 = test_path();
    let mgr2 = KeyManager::new(&path2);

    // 4. Recover from mnemonic
    let recovered = mgr2.recover_from_mnemonic(&mnemonic, "newpassword12", "Recovered")
        .expect("recover");

    assert_eq!(original_address, recovered.address, "Recovered address must match original");

    // 5. Sign the same data — must produce identical signature
    mgr2.unlock("newpassword12").expect("unlock recovered");
    let key2 = mgr2.get_signing_key(&recovered.address).expect("get recovered key");
    let sig2 = key2.sign(b"recovery test data");

    assert_eq!(sig1, sig2, "Recovered key must produce identical signature");

    std::fs::remove_dir_all(&path1).ok();
    std::fs::remove_dir_all(&path2).ok();
}

// =========================================================================
// SESSION + KEY INTERACTION
// =========================================================================

#[tokio::test]
async fn test_session_manager_with_key_manager() {
    let path = test_path();
    let mgr = KeyManager::new(&path);
    let mut session = SessionManager::new(3, 300, 60);

    let result = mgr.create_account("strongpassword1", "Primary").expect("create");

    // Simulate wrong password attempts via session manager
    session.record_failure(&result.address).expect("attempt 1");
    session.record_failure(&result.address).expect("attempt 2");

    // Not locked out yet — can still unlock
    assert!(!session.is_locked_out(&result.address));
    mgr.unlock("strongpassword1").expect("unlock with correct password");
    session.record_success(&result.address);
    assert!(session.is_session_active(&result.address));

    // Sign while session is active
    let key = mgr.get_signing_key(&result.address).expect("get key");
    let _ = key.sign(b"while session active");

    // End session
    session.end_session(&result.address);
    mgr.lock();
    assert!(!session.is_session_active(&result.address));
    assert!(!mgr.is_unlocked());

    std::fs::remove_dir_all(&path).ok();
}

#[tokio::test]
async fn test_lockout_blocks_key_usage() {
    let path = test_path();
    let mgr = KeyManager::new(&path);
    let mut session = SessionManager::new(3, 300, 60);

    let result = mgr.create_account("strongpassword1", "Primary").expect("create");

    // Trigger lockout
    let _ = session.record_failure(&result.address);
    let _ = session.record_failure(&result.address);
    let _ = session.record_failure(&result.address);
    assert!(session.is_locked_out(&result.address));

    // Even with correct password, the session manager says locked out
    // The application layer should check is_locked_out BEFORE calling unlock
    // This test verifies the pattern works
    assert!(session.is_locked_out(&result.address));

    std::fs::remove_dir_all(&path).ok();
}

// =========================================================================
// MULTI-ACCOUNT INTERACTIONS
// =========================================================================

#[tokio::test]
async fn test_multi_account_independence() {
    let path = test_path();
    let mgr = KeyManager::new(&path);

    let a1 = mgr.create_account("password1234", "Account 1").expect("create 1");
    let a2 = mgr.create_account("password1234", "Account 2").expect("create 2");
    let a3 = mgr.create_secp256k1_account("password1234", "EVM Account").expect("create 3");

    // All three should have unique addresses
    assert_ne!(a1.address, a2.address);
    assert_ne!(a1.address, a3.address);
    assert_ne!(a2.address, a3.address);

    // Unlock all
    let count = mgr.unlock("password1234").expect("unlock all");
    assert_eq!(count, 3);

    // Sign with each — signatures must differ
    let k1 = mgr.get_signing_key(&a1.address).expect("key 1");
    let k2 = mgr.get_signing_key(&a2.address).expect("key 2");
    let k3 = mgr.get_signing_key(&a3.address).expect("key 3");

    let data = b"multi-account test";
    let sig1 = k1.sign(data);
    let sig2 = k2.sign(data);
    let sig3 = k3.sign(data);

    assert_ne!(sig1, sig2, "Different keys must produce different signatures");
    assert_ne!(sig1, sig3);
    assert_ne!(sig2, sig3);

    // Delete one account — others unaffected
    mgr.delete_account(&a2.address, "password1234").expect("delete a2");
    assert_eq!(mgr.list_accounts().len(), 2);

    // Remaining accounts still accessible
    mgr.lock();
    let count = mgr.unlock("password1234").expect("unlock remaining");
    assert_eq!(count, 2);

    std::fs::remove_dir_all(&path).ok();
}

// =========================================================================
// PERSIST AND RELOAD
// =========================================================================

#[tokio::test]
async fn test_full_persist_reload_cycle() {
    let path = test_path();

    // Phase 1: Create accounts and sign
    {
        let mgr = KeyManager::new(&path);
        mgr.create_account("password1234", "Ed25519").expect("create ed");
        mgr.create_secp256k1_account("password1234", "Secp256k1").expect("create secp");
    } // manager dropped, state only on disk

    // Phase 2: Reload from disk and verify
    {
        let mgr = KeyManager::new(&path);
        mgr.load().expect("load from disk");

        let accounts = mgr.list_accounts();
        assert_eq!(accounts.len(), 2, "Both accounts should survive reload");
        assert_eq!(accounts[0].key_type, KeyType::Ed25519);
        assert_eq!(accounts[1].key_type, KeyType::Secp256k1);

        // Unlock with original password
        let count = mgr.unlock("password1234").expect("unlock reloaded");
        assert_eq!(count, 2);

        // Sign with both
        for account in &accounts {
            let key = mgr.get_signing_key(&account.address).expect("get key");
            let sig = key.sign(b"reloaded test");
            assert_eq!(sig.len(), 64);
        }
    }

    std::fs::remove_dir_all(&path).ok();
}

// =========================================================================
// TRANSACTION CHAIN ID ISOLATION
// =========================================================================

#[tokio::test]
async fn test_same_key_different_chains_different_signatures() {
    let path = test_path();
    let mgr = KeyManager::new(&path);
    mgr.create_account("strongpassword1", "Primary").expect("create");
    mgr.unlock("strongpassword1").expect("unlock");
    let accounts = mgr.list_accounts();
    let key = mgr.get_signing_key(&accounts[0].address).expect("key");

    let ed_key = match &key {
        citrate_wallet_core::keys::UnifiedKey::Ed25519(k) => k,
        _ => panic!("Expected Ed25519"),
    };

    let to_addr = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    let tx_citrate = TransactionBuilder::new()
        .to(to_addr)
        .value(1000)
        .chain_id(40204)
        .sign(ed_key, 0).expect("sign citrate");

    let tx_ethereum = TransactionBuilder::new()
        .to(to_addr)
        .value(1000)
        .chain_id(1)
        .sign(ed_key, 0).expect("sign ethereum");

    // Ed25519 native path: `sign` uses the v2 digest, which binds chain_id,
    // so the signatures differ across chains (see
    // `test_ed25519_signature_binds_chain_id`).
    assert_ne!(tx_citrate.signature, tx_ethereum.signature);
    assert_ne!(tx_citrate.hash, tx_ethereum.hash);

    std::fs::remove_dir_all(&path).ok();
}
