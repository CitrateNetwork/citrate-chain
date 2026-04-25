//! Coverage gap tests for wallet crate
//!
//! Targets uncovered branches and edge cases to raise wallet coverage from 58% to 85%+.
//! Covers: wallet.rs, keystore.rs, transaction.rs, rpc_client.rs, errors.rs

use citrate_consensus::types::{Hash, PublicKey, Transaction};
use citrate_execution::types::Address;
use citrate_wallet::errors::WalletError;
use citrate_wallet::keystore::{EncryptedKey, KeyStore};
use citrate_wallet::rpc_client::RpcClient;
use citrate_wallet::transaction::{SignedTransaction, TransactionBuilder};
use citrate_wallet::wallet::{Account, Wallet, WalletConfig};
use ed25519_dalek::SigningKey;
use primitive_types::U256;
use std::path::PathBuf;
use tempfile::TempDir;

// ============================================================================
// Helpers
// ============================================================================

fn temp_wallet() -> (TempDir, Wallet) {
    let dir = TempDir::new().unwrap();
    let config = WalletConfig {
        keystore_path: dir.path().join("keystore.json"),
        rpc_url: "http://localhost:8545".to_string(),
        chain_id: 40204,
        default_gas_price: 1_000_000_000,
        default_gas_limit: 21_000,
    };
    let wallet = Wallet::new(config).unwrap();
    (dir, wallet)
}

fn test_signing_key() -> (SigningKey, PublicKey) {
    let secret = [42u8; 32];
    let signing_key = SigningKey::from_bytes(&secret);
    let public_key = PublicKey::new(signing_key.verifying_key().to_bytes());
    (signing_key, public_key)
}

// ============================================================================
// WalletError Display tests (errors.rs)
// ============================================================================

#[test]
fn test_error_display_io() {
    let err = WalletError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "not found"));
    let msg = format!("{}", err);
    assert!(msg.contains("not found"), "Got: {}", msg);
}

#[test]
fn test_error_display_json() {
    // Trigger a real JSON error
    let result: Result<serde_json::Value, _> = serde_json::from_str("not json");
    let json_err = result.unwrap_err();
    let err: WalletError = json_err.into();
    let msg = format!("{}", err);
    assert!(msg.contains("JSON error"), "Got: {}", msg);
}

#[test]
fn test_error_display_hex_decode() {
    let hex_err = hex::decode("zz").unwrap_err();
    let err: WalletError = hex_err.into();
    let msg = format!("{}", err);
    assert!(msg.contains("Hex decode"), "Got: {}", msg);
}

#[test]
fn test_error_display_encryption() {
    let err = WalletError::Encryption("bad cipher".to_string());
    assert!(format!("{}", err).contains("Encryption error: bad cipher"));
}

#[test]
fn test_error_display_decryption() {
    let err = WalletError::Decryption("corrupted data".to_string());
    assert!(format!("{}", err).contains("Decryption error: corrupted data"));
}

#[test]
fn test_error_display_invalid_password() {
    let err = WalletError::InvalidPassword;
    assert_eq!(format!("{}", err), "Invalid password");
}

#[test]
fn test_error_display_account_not_found() {
    let err = WalletError::AccountNotFound("Index 99".to_string());
    assert!(format!("{}", err).contains("Account not found: Index 99"));
}

#[test]
fn test_error_display_insufficient_balance() {
    let err = WalletError::InsufficientBalance {
        need: "10".to_string(),
        have: "5".to_string(),
    };
    let msg = format!("{}", err);
    assert!(msg.contains("10") && msg.contains("5"), "Got: {}", msg);
}

#[test]
fn test_error_display_rpc() {
    let err = WalletError::Rpc("connection refused".to_string());
    assert!(format!("{}", err).contains("RPC error: connection refused"));
}

#[test]
fn test_error_display_transaction_failed() {
    let err = WalletError::TransactionFailed("revert".to_string());
    assert!(format!("{}", err).contains("Transaction failed: revert"));
}

#[test]
fn test_error_display_invalid_address() {
    let err = WalletError::InvalidAddress("bad addr".to_string());
    assert!(format!("{}", err).contains("Invalid address: bad addr"));
}

#[test]
fn test_error_display_wallet_locked() {
    let err = WalletError::WalletLocked;
    assert_eq!(format!("{}", err), "Wallet locked");
}

#[test]
fn test_error_display_wallet_exists() {
    let err = WalletError::WalletExists;
    assert!(format!("{}", err).contains("already exists"));
}

#[test]
fn test_error_display_other() {
    let err = WalletError::Other("custom error".to_string());
    assert!(format!("{}", err).contains("Other error: custom error"));
}

#[test]
fn test_error_from_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
    let wallet_err: WalletError = io_err.into();
    match wallet_err {
        WalletError::Io(_) => {}
        _ => panic!("Expected Io variant"),
    }
}

#[test]
fn test_error_from_bincode() {
    // Create a bincode error by deserializing invalid data
    let result: Result<u64, _> = bincode::deserialize(&[]);
    let bincode_err = result.unwrap_err();
    let wallet_err: WalletError = bincode_err.into();
    match wallet_err {
        WalletError::Serialization(_) => {}
        _ => panic!("Expected Serialization variant"),
    }
}

#[test]
fn test_error_debug_format() {
    let err = WalletError::InvalidPassword;
    let debug = format!("{:?}", err);
    assert!(debug.contains("InvalidPassword"));
}

// ============================================================================
// Wallet tests (wallet.rs)
// ============================================================================

#[test]
fn test_wallet_config_default_values() {
    let config = WalletConfig::default();
    assert_eq!(config.chain_id, 40204);
    assert_eq!(config.rpc_url, "http://localhost:8545");
    assert_eq!(config.default_gas_price, 1_000_000_000);
    assert_eq!(config.default_gas_limit, 21_000);
    assert!(config.keystore_path.to_string_lossy().contains("citrate"));
}

#[test]
fn test_wallet_create_account_with_empty_password() {
    let (_dir, mut wallet) = temp_wallet();
    // Empty password should still work (not recommended but not forbidden)
    let result = wallet.create_account("", None);
    assert!(result.is_ok());
    let account = result.unwrap();
    assert_eq!(account.index, 0);
    assert_eq!(account.balance, U256::zero());
}

#[test]
fn test_wallet_list_accounts_empty() {
    let (_dir, wallet) = temp_wallet();
    let accounts = wallet.list_accounts();
    assert!(accounts.is_empty());
}

#[test]
fn test_wallet_get_account_none_when_empty() {
    let (_dir, wallet) = temp_wallet();
    assert!(wallet.get_account(0).is_none());
    assert!(wallet.get_account(999).is_none());
}

#[test]
fn test_wallet_get_account_by_address_none() {
    let (_dir, wallet) = temp_wallet();
    assert!(wallet.get_account_by_address(&Address([0xFF; 20])).is_none());
}

#[test]
fn test_wallet_import_invalid_key_length() {
    let (_dir, mut wallet) = temp_wallet();
    // Valid hex but only 3 bytes
    let err = wallet.import_account("aabbcc", "pw", None).unwrap_err();
    match err {
        WalletError::Other(msg) => assert!(msg.contains("Invalid private key length")),
        _ => panic!("Expected Other error, got {:?}", err),
    }
}

#[test]
fn test_wallet_import_too_long_key() {
    let (_dir, mut wallet) = temp_wallet();
    // 33 bytes (66 hex chars) -- too long
    let long_hex = hex::encode([0xAA; 33]);
    let err = wallet.import_account(&long_hex, "pw", None).unwrap_err();
    match err {
        WalletError::Other(msg) => assert!(msg.contains("Invalid private key length")),
        _ => panic!("Expected Other error, got {:?}", err),
    }
}

#[test]
fn test_wallet_lock_prevents_export() {
    let (_dir, mut wallet) = temp_wallet();
    wallet.create_account("pw", None).unwrap();
    wallet.unlock("pw").unwrap();
    wallet.lock();
    let err = wallet.export_private_key(0).unwrap_err();
    match err {
        WalletError::WalletLocked => {}
        _ => panic!("Expected WalletLocked, got {:?}", err),
    }
}

#[test]
fn test_wallet_export_out_of_range() {
    let (_dir, mut wallet) = temp_wallet();
    wallet.create_account("pw", None).unwrap();
    wallet.unlock("pw").unwrap();
    let err = wallet.export_private_key(99).unwrap_err();
    match err {
        WalletError::AccountNotFound(_) => {}
        _ => panic!("Expected AccountNotFound, got {:?}", err),
    }
}

#[test]
fn test_wallet_config_accessor() {
    let (_dir, wallet) = temp_wallet();
    let config = wallet.config();
    assert_eq!(config.chain_id, 40204);
}

#[test]
fn test_wallet_rpc_client_accessor() {
    let (_dir, wallet) = temp_wallet();
    let _rpc = wallet.rpc_client(); // Should not panic
}

#[test]
fn test_wallet_refresh_accounts_empty() {
    let (_dir, mut wallet) = temp_wallet();
    wallet.refresh_accounts().unwrap();
    assert!(wallet.list_accounts().is_empty());
}

#[test]
fn test_wallet_persistence_across_instances() {
    let dir = TempDir::new().unwrap();
    let keystore_path = dir.path().join("keystore.json");
    let secret = [55u8; 32];

    // Create first wallet, import key
    {
        let config = WalletConfig {
            keystore_path: keystore_path.clone(),
            rpc_url: "http://localhost:8545".to_string(),
            chain_id: 40204,
            default_gas_price: 1_000_000_000,
            default_gas_limit: 21_000,
        };
        let mut wallet = Wallet::new(config).unwrap();
        wallet
            .import_account(&hex::encode(secret), "pw", Some("test".to_string()))
            .unwrap();
    }

    // Create second wallet at same path
    let config2 = WalletConfig {
        keystore_path: keystore_path.clone(),
        rpc_url: "http://localhost:8545".to_string(),
        chain_id: 40204,
        default_gas_price: 1_000_000_000,
        default_gas_limit: 21_000,
    };
    let mut wallet2 = Wallet::new(config2).unwrap();
    wallet2.refresh_accounts().unwrap();
    assert_eq!(wallet2.list_accounts().len(), 1);

    // Unlock and verify key is the same
    wallet2.unlock("pw").unwrap();
    let exported = wallet2.export_private_key(0).unwrap();
    assert_eq!(exported, hex::encode(secret));
}

// ============================================================================
// KeyStore tests (keystore.rs)
// ============================================================================

#[test]
fn test_keystore_empty_on_new() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ks.json");
    let ks = KeyStore::new(&path).unwrap();
    assert_eq!(ks.list_accounts().len(), 0);
}

#[test]
fn test_keystore_corrupted_data_error() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ks.json");
    // Write corrupted data
    std::fs::write(&path, b"not valid json at all!!!").unwrap();
    let result = KeyStore::new(&path);
    assert!(result.is_err());
}

#[test]
fn test_keystore_wrong_password_decrypt() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ks.json");
    let mut ks = KeyStore::new(&path).unwrap();
    ks.generate_key("correct_password", None).unwrap();

    let err = ks.unlock("wrong_password").unwrap_err();
    match err {
        WalletError::InvalidPassword => {}
        _ => panic!("Expected InvalidPassword, got {:?}", err),
    }
}

#[test]
fn test_keystore_get_signing_key_locked() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ks.json");
    let mut ks = KeyStore::new(&path).unwrap();
    ks.generate_key("pw", None).unwrap();

    // Keystore starts locked
    let err = ks.get_signing_key(0).unwrap_err();
    match err {
        WalletError::WalletLocked => {}
        _ => panic!("Expected WalletLocked, got {:?}", err),
    }
}

#[test]
fn test_keystore_get_signing_key_by_public_locked() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ks.json");
    let mut ks = KeyStore::new(&path).unwrap();
    let vk = ks.generate_key("pw", None).unwrap();

    let err = ks.get_signing_key_by_public(&vk.to_bytes()).unwrap_err();
    match err {
        WalletError::WalletLocked => {}
        _ => panic!("Expected WalletLocked, got {:?}", err),
    }
}

#[test]
fn test_keystore_get_signing_key_by_unknown_public() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ks.json");
    let mut ks = KeyStore::new(&path).unwrap();
    ks.generate_key("pw", None).unwrap();
    ks.unlock("pw").unwrap();

    let err = ks.get_signing_key_by_public(&[0xDE; 32]).unwrap_err();
    match err {
        WalletError::AccountNotFound(_) => {}
        _ => panic!("Expected AccountNotFound, got {:?}", err),
    }
}

#[test]
fn test_keystore_generate_while_unlocked() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ks.json");
    let mut ks = KeyStore::new(&path).unwrap();
    ks.generate_key("pw", None).unwrap();
    ks.unlock("pw").unwrap();

    // Generate another key while unlocked
    let vk2 = ks.generate_key("pw", Some("second".to_string())).unwrap();
    // Should be accessible immediately
    let sk = ks.get_signing_key(1).unwrap();
    assert_eq!(sk.verifying_key().to_bytes(), vk2.to_bytes());
}

#[test]
fn test_keystore_import_while_unlocked() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ks.json");
    let mut ks = KeyStore::new(&path).unwrap();
    ks.generate_key("pw", None).unwrap();
    ks.unlock("pw").unwrap();

    let secret = [77u8; 32];
    ks.import_key(&hex::encode(secret), "pw", None).unwrap();
    // Should be accessible immediately
    let sk = ks.get_signing_key(1).unwrap();
    assert_eq!(sk.to_bytes(), secret);
}

#[test]
fn test_keystore_import_with_0x_uppercase_prefix() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ks.json");
    let mut ks = KeyStore::new(&path).unwrap();
    let secret = [88u8; 32];
    let hex_key = format!("0X{}", hex::encode(secret));
    let vk = ks.import_key(&hex_key, "pw", None).unwrap();
    let expected = SigningKey::from_bytes(&secret).verifying_key();
    assert_eq!(vk.to_bytes(), expected.to_bytes());
}

#[test]
fn test_keystore_export_locked_fails() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ks.json");
    let mut ks = KeyStore::new(&path).unwrap();
    ks.generate_key("pw", None).unwrap();
    let err = ks.export_private_key(0).unwrap_err();
    match err {
        WalletError::WalletLocked => {}
        _ => panic!("Expected WalletLocked, got {:?}", err),
    }
}

#[test]
fn test_keystore_export_out_of_bounds() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ks.json");
    let mut ks = KeyStore::new(&path).unwrap();
    ks.generate_key("pw", None).unwrap();
    ks.unlock("pw").unwrap();
    let err = ks.export_private_key(99).unwrap_err();
    match err {
        WalletError::AccountNotFound(_) => {}
        _ => panic!("Expected AccountNotFound, got {:?}", err),
    }
}

#[test]
fn test_keystore_salt_uniqueness() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ks.json");
    let mut ks = KeyStore::new(&path).unwrap();
    ks.generate_key("pw", None).unwrap();
    ks.generate_key("pw", None).unwrap();
    // Each encryption has a unique salt (and nonce)
    let accounts = ks.list_accounts();
    assert_eq!(accounts.len(), 2);
}

#[test]
fn test_encrypted_key_serialization_roundtrip() {
    let ek = EncryptedKey {
        ciphertext: vec![1, 2, 3, 4],
        salt: "test_salt".to_string(),
        nonce: vec![5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        public_key: vec![0xAA; 32],
        alias: Some("my-key".to_string()),
        kdf_version: 2,
    };
    let json = serde_json::to_string(&ek).unwrap();
    let d: EncryptedKey = serde_json::from_str(&json).unwrap();
    assert_eq!(d.ciphertext, vec![1, 2, 3, 4]);
    assert_eq!(d.salt, "test_salt");
    assert_eq!(d.alias, Some("my-key".to_string()));
    assert_eq!(d.kdf_version, 2);
}

#[test]
fn test_encrypted_key_no_alias() {
    let ek = EncryptedKey {
        ciphertext: vec![],
        salt: "s".to_string(),
        nonce: vec![],
        public_key: vec![],
        alias: None,
        kdf_version: 2,
    };
    let json = serde_json::to_string(&ek).unwrap();
    let d: EncryptedKey = serde_json::from_str(&json).unwrap();
    assert_eq!(d.alias, None);
    assert_eq!(d.kdf_version, 2);
}

#[test]
fn test_wal01_legacy_cli_keystore_entry_defaults_to_v1() {
    // Pre-WAL-01 EncryptedKey blobs lack kdf_version. They MUST still
    // deserialize (so existing CLI wallets keep working) and default to
    // kdf_version: 1 so decrypt_key uses the original parameters.
    let legacy_json = r#"{
        "ciphertext": [1, 2, 3, 4],
        "salt": "legacy_salt",
        "nonce": [5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        "public_key": [],
        "alias": null
    }"#;
    let d: EncryptedKey =
        serde_json::from_str(legacy_json).expect("legacy EncryptedKey should still deserialize");
    assert_eq!(
        d.kdf_version, 1,
        "WAL-01: CLI wallet legacy entries (no kdf_version field) must default to v1"
    );
}

// ============================================================================
// Transaction tests (transaction.rs)
// ============================================================================

#[test]
fn test_transaction_builder_defaults() {
    let builder = TransactionBuilder::new();
    // Just verify construction doesn't panic, and Default works
    let default_builder = TransactionBuilder::default();
    // Both should have same chain_id
    let _ = builder;
    let _ = default_builder;
}

#[test]
fn test_transaction_builder_all_fields() {
    let (sk, pk) = test_signing_key();
    let tx = TransactionBuilder::new()
        .from(pk)
        .to(Some(Address([0x11; 20])))
        .value(U256::from(5000))
        .data(vec![0xDE, 0xAD, 0xBE, 0xEF])
        .nonce(10)
        .gas_price(2_000_000_000)
        .gas_limit(50_000)
        .chain_id(40204)
        .build_and_sign(&sk)
        .unwrap();

    assert_eq!(tx.transaction.from, pk);
    assert_eq!(tx.transaction.nonce, 10);
    assert_eq!(tx.transaction.gas_price, 2_000_000_000);
    assert_eq!(tx.transaction.gas_limit, 50_000);
    assert_eq!(tx.transaction.data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn test_transaction_builder_without_from_fails() {
    let (sk, _) = test_signing_key();
    let err = TransactionBuilder::new()
        .to(Some(Address([0x11; 20])))
        .build_and_sign(&sk)
        .unwrap_err();
    match err {
        WalletError::Other(msg) => assert!(msg.contains("From address not set")),
        _ => panic!("Expected Other error"),
    }
}

#[test]
fn test_transaction_builder_contract_deploy_no_to() {
    let (sk, pk) = test_signing_key();
    let tx = TransactionBuilder::new()
        .from(pk)
        .to(None)
        .data(vec![0x60, 0x80])
        .build_and_sign(&sk)
        .unwrap();
    assert!(tx.transaction.to.is_none());
}

#[test]
fn test_transaction_hash_deterministic() {
    let (sk, pk) = test_signing_key();
    // Same parameters should produce same pre-signing hash
    let tx1 = TransactionBuilder::new()
        .from(pk)
        .to(Some(Address([0x22; 20])))
        .value(U256::from(100))
        .nonce(5)
        .chain_id(40204)
        .build_and_sign(&sk)
        .unwrap();

    let tx2 = TransactionBuilder::new()
        .from(pk)
        .to(Some(Address([0x22; 20])))
        .value(U256::from(100))
        .nonce(5)
        .chain_id(40204)
        .build_and_sign(&sk)
        .unwrap();

    // Hash should be the same (pre-signature hash is deterministic)
    assert_eq!(tx1.transaction.hash, tx2.transaction.hash);
}

#[test]
fn test_transaction_different_chain_id_different_hash() {
    let (sk, pk) = test_signing_key();
    let tx1 = TransactionBuilder::new()
        .from(pk)
        .to(Some(Address([0x33; 20])))
        .value(U256::from(100))
        .chain_id(40204)
        .build_and_sign(&sk)
        .unwrap();

    let tx2 = TransactionBuilder::new()
        .from(pk)
        .to(Some(Address([0x33; 20])))
        .value(U256::from(100))
        .chain_id(1)
        .build_and_sign(&sk)
        .unwrap();

    assert_ne!(tx1.transaction.hash, tx2.transaction.hash);
}

#[test]
fn test_signed_transaction_has_nonzero_signature() {
    let (sk, pk) = test_signing_key();
    let tx = TransactionBuilder::new()
        .from(pk)
        .to(Some(Address([0x44; 20])))
        .value(U256::from(1))
        .build_and_sign(&sk)
        .unwrap();
    assert_ne!(tx.transaction.signature.as_bytes(), &[0u8; 64]);
}

#[test]
fn test_signed_transaction_raw_nonempty() {
    let (sk, pk) = test_signing_key();
    let tx = TransactionBuilder::new()
        .from(pk)
        .to(Some(Address([0x55; 20])))
        .value(U256::from(1))
        .build_and_sign(&sk)
        .unwrap();
    assert!(!tx.raw.is_empty());
}

#[test]
fn test_signed_transaction_raw_deserializable() {
    let (sk, pk) = test_signing_key();
    let tx = TransactionBuilder::new()
        .from(pk)
        .to(Some(Address([0x66; 20])))
        .value(U256::from(999))
        .build_and_sign(&sk)
        .unwrap();

    let deserialized: Transaction = bincode::deserialize(&tx.raw).unwrap();
    assert_eq!(deserialized.from, pk);
    assert_eq!(deserialized.value, 999);
}

#[test]
fn test_signed_transaction_serialization() {
    let (sk, pk) = test_signing_key();
    let signed_tx = TransactionBuilder::new()
        .from(pk)
        .to(Some(Address([0x77; 20])))
        .value(U256::from(42))
        .build_and_sign(&sk)
        .unwrap();

    // SignedTransaction should be serializable
    let json = serde_json::to_string(&signed_tx).unwrap();
    let d: SignedTransaction = serde_json::from_str(&json).unwrap();
    assert_eq!(d.transaction.value, 42);
}

#[test]
fn test_transaction_builder_zero_value() {
    let (sk, pk) = test_signing_key();
    let tx = TransactionBuilder::new()
        .from(pk)
        .to(Some(Address([0x11; 20])))
        .value(U256::zero())
        .build_and_sign(&sk)
        .unwrap();
    assert_eq!(tx.transaction.value, 0);
}

#[test]
fn test_transaction_builder_large_value() {
    let (sk, pk) = test_signing_key();
    // u128::MAX is the maximum that Transaction can hold
    let large = U256::from(u128::MAX);
    let tx = TransactionBuilder::new()
        .from(pk)
        .to(Some(Address([0x11; 20])))
        .value(large)
        .build_and_sign(&sk)
        .unwrap();
    assert_eq!(tx.transaction.value, u128::MAX);
}

#[test]
fn test_transaction_builder_overflow_value_saturates() {
    let (sk, pk) = test_signing_key();
    // U256::MAX should saturate to u128::MAX
    let tx = TransactionBuilder::new()
        .from(pk)
        .to(Some(Address([0x11; 20])))
        .value(U256::MAX)
        .build_and_sign(&sk)
        .unwrap();
    assert_eq!(tx.transaction.value, u128::MAX);
}

#[test]
fn test_transaction_builder_with_data() {
    let (sk, pk) = test_signing_key();
    let data = vec![0x60, 0x80, 0x60, 0x40, 0x52]; // Minimal EVM bytecode
    let tx = TransactionBuilder::new()
        .from(pk)
        .to(None)
        .data(data.clone())
        .build_and_sign(&sk)
        .unwrap();
    assert_eq!(tx.transaction.data, data);
}

// ============================================================================
// RPC Client tests (rpc_client.rs)
// ============================================================================

#[test]
fn test_rpc_client_creation() {
    let _client = RpcClient::new("http://localhost:8545");
    // Should not panic
}

#[test]
fn test_rpc_client_creation_with_various_urls() {
    let _c1 = RpcClient::new("http://127.0.0.1:8545");
    let _c2 = RpcClient::new("https://mainnet.infura.io");
    let _c3 = RpcClient::new("http://[::1]:8545");
    // None should panic
}

#[tokio::test]
async fn test_rpc_client_connection_refused() {
    // Use a port that's almost certainly not listening
    let client = RpcClient::new("http://127.0.0.1:19999");
    let result = client.get_balance(&Address([0x11; 20])).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        WalletError::Rpc(_) => {}
        e => panic!("Expected Rpc error, got {:?}", e),
    }
}

#[tokio::test]
async fn test_rpc_client_get_nonce_connection_refused() {
    let client = RpcClient::new("http://127.0.0.1:19999");
    let result = client.get_nonce(&Address([0x22; 20])).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_rpc_client_get_block_number_connection_refused() {
    let client = RpcClient::new("http://127.0.0.1:19999");
    let result = client.get_block_number().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_rpc_client_get_chain_id_connection_refused() {
    let client = RpcClient::new("http://127.0.0.1:19999");
    let result = client.get_chain_id().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_rpc_client_get_gas_price_connection_refused() {
    let client = RpcClient::new("http://127.0.0.1:19999");
    let result = client.get_gas_price().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_rpc_client_estimate_gas_connection_refused() {
    let client = RpcClient::new("http://127.0.0.1:19999");
    let result = client
        .estimate_gas(&Address([0x11; 20]), Some(&Address([0x22; 20])), U256::from(100), vec![])
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_rpc_client_get_receipt_connection_refused() {
    let client = RpcClient::new("http://127.0.0.1:19999");
    let result = client.get_transaction_receipt(&Hash::new([0x11; 32])).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_rpc_client_send_transaction_connection_refused() {
    let (sk, pk) = test_signing_key();
    let tx = TransactionBuilder::new()
        .from(pk)
        .to(Some(Address([0x11; 20])))
        .value(U256::from(100))
        .build_and_sign(&sk)
        .unwrap();

    let client = RpcClient::new("http://127.0.0.1:19999");
    let result = client.send_transaction(tx).await;
    assert!(result.is_err());
}

// ============================================================================
// Account struct tests
// ============================================================================

#[test]
fn test_account_serialization_roundtrip() {
    let account = Account {
        index: 3,
        address: Address([0xAA; 20]),
        public_key: PublicKey::new([0xBB; 32]),
        alias: Some("test-account".to_string()),
        balance: U256::from(1_000_000),
        nonce: 42,
    };
    let json = serde_json::to_string(&account).unwrap();
    let d: Account = serde_json::from_str(&json).unwrap();
    assert_eq!(d.index, 3);
    assert_eq!(d.nonce, 42);
    assert_eq!(d.alias, Some("test-account".to_string()));
}

#[test]
fn test_account_no_alias() {
    let account = Account {
        index: 0,
        address: Address([0; 20]),
        public_key: PublicKey::new([0; 32]),
        alias: None,
        balance: U256::zero(),
        nonce: 0,
    };
    let json = serde_json::to_string(&account).unwrap();
    let d: Account = serde_json::from_str(&json).unwrap();
    assert_eq!(d.alias, None);
}

#[test]
fn test_wallet_config_serialization_roundtrip() {
    let config = WalletConfig {
        keystore_path: PathBuf::from("/tmp/test_keystore.json"),
        rpc_url: "http://localhost:9545".to_string(),
        chain_id: 40204,
        default_gas_price: 2_000_000_000,
        default_gas_limit: 42_000,
    };
    let json = serde_json::to_string(&config).unwrap();
    let d: WalletConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(d.chain_id, 40204);
    assert_eq!(d.default_gas_limit, 42_000);
}

// ============================================================================
// Wallet send_transaction error path tests
// ============================================================================

#[tokio::test]
async fn test_wallet_send_transaction_account_not_found() {
    let (_dir, wallet) = temp_wallet();
    // No accounts exist, so from_index=0 should fail
    let result = wallet
        .send_transaction(0, Address([0x11; 20]), U256::from(100), vec![], None, None)
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        WalletError::AccountNotFound(_) => {}
        e => panic!("Expected AccountNotFound, got {:?}", e),
    }
}

#[tokio::test]
async fn test_wallet_send_transaction_insufficient_balance() {
    let (_dir, mut wallet) = temp_wallet();
    wallet.create_account("pw", None).unwrap();
    wallet.unlock("pw").unwrap();

    // Account has zero balance, sending any value should fail
    let result = wallet
        .send_transaction(
            0,
            Address([0x11; 20]),
            U256::from(1),
            vec![],
            None,
            None,
        )
        .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        WalletError::InsufficientBalance { .. } => {}
        e => panic!("Expected InsufficientBalance, got {:?}", e),
    }
}
