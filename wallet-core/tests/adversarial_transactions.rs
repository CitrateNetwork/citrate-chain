//! Adversarial tests for transaction building and signing.
//!
//! Attack surfaces: overflow, replay, malleability, cross-chain,
//! nonce manipulation, gas manipulation, data injection.

use citrate_wallet_core::chain::{TransactionBuilder, RpcClient};
use citrate_wallet_core::keys::UnifiedKey;
use ed25519_dalek::SigningKey as Ed25519SigningKey;

fn test_key() -> Ed25519SigningKey {
    Ed25519SigningKey::generate(&mut rand::rngs::OsRng)
}

// =========================================================================
// REPLAY PROTECTION
// =========================================================================

#[test]
fn test_different_chain_ids_produce_different_hashes() {
    let key = test_key();
    let tx1 = TransactionBuilder::new()
        .to("0xb5ddd4eb356ddf3bf51eb3aec1ed28213be59129")
        .value(1000)
        .chain_id(1) // Ethereum mainnet
        .sign(&key, 0).expect("sign chain 1");
    let tx2 = TransactionBuilder::new()
        .to("0xb5ddd4eb356ddf3bf51eb3aec1ed28213be59129")
        .value(1000)
        .chain_id(40204) // Citrate
        .sign(&key, 0).expect("sign chain 40204");

    assert_ne!(tx1.hash, tx2.hash, "Cross-chain replay must be prevented by different hashes");
    assert_ne!(tx1.signature, tx2.signature, "Signatures must differ across chains");
}

#[test]
fn test_different_nonces_produce_different_hashes() {
    let key = test_key();
    let tx1 = TransactionBuilder::new().value(1000).sign(&key, 0).expect("nonce 0");
    let tx2 = TransactionBuilder::new().value(1000).sign(&key, 1).expect("nonce 1");
    assert_ne!(tx1.hash, tx2.hash, "Different nonces must produce different hashes");
}

#[test]
fn test_same_params_produce_same_hash() {
    let key = test_key();
    let tx1 = TransactionBuilder::new()
        .to("0xabc")
        .value(1000)
        .chain_id(40204)
        .sign(&key, 5).expect("sign 1");
    let tx2 = TransactionBuilder::new()
        .to("0xabc")
        .value(1000)
        .chain_id(40204)
        .sign(&key, 5).expect("sign 2");

    assert_eq!(tx1.hash, tx2.hash, "Same params must produce same hash (deterministic)");
    assert_eq!(tx1.signature, tx2.signature, "Ed25519 signatures must be deterministic");
}

// =========================================================================
// VALUE OVERFLOW / UNDERFLOW
// =========================================================================

#[test]
fn test_max_u128_value() {
    let key = test_key();
    let tx = TransactionBuilder::new()
        .value(u128::MAX)
        .sign(&key, 0);
    assert!(tx.is_ok(), "Max u128 value should not panic");
}

#[test]
fn test_zero_value() {
    let key = test_key();
    let tx = TransactionBuilder::new()
        .value(0)
        .sign(&key, 0).expect("zero value");
    assert_eq!(tx.value, 0);
}

#[test]
fn test_max_nonce() {
    let key = test_key();
    let tx = TransactionBuilder::new()
        .value(1000)
        .sign(&key, u64::MAX);
    assert!(tx.is_ok(), "Max nonce should not panic");
}

#[test]
fn test_max_gas_price() {
    let key = test_key();
    let tx = TransactionBuilder::new()
        .gas_price(u64::MAX)
        .sign(&key, 0);
    assert!(tx.is_ok(), "Max gas price should not panic");
}

#[test]
fn test_max_gas_limit() {
    let key = test_key();
    let tx = TransactionBuilder::new()
        .gas_limit(u64::MAX)
        .sign(&key, 0);
    assert!(tx.is_ok(), "Max gas limit should not panic");
}

#[test]
fn test_zero_gas_limit() {
    let key = test_key();
    let tx = TransactionBuilder::new()
        .gas_limit(0)
        .sign(&key, 0).expect("zero gas");
    assert_eq!(tx.gas_limit, 0);
}

#[test]
fn test_zero_gas_price() {
    let key = test_key();
    let tx = TransactionBuilder::new()
        .gas_price(0)
        .sign(&key, 0).expect("zero gas price");
    assert_eq!(tx.gas_price, 0);
}

// =========================================================================
// DATA PAYLOAD ATTACKS
// =========================================================================

#[test]
fn test_large_data_payload() {
    let key = test_key();
    let data = vec![0xABu8; 100_000]; // 100KB payload
    let tx = TransactionBuilder::new()
        .data(data.clone())
        .sign(&key, 0).expect("large data");
    assert_eq!(tx.data.len(), 100_000);
}

#[test]
fn test_empty_data() {
    let key = test_key();
    let tx = TransactionBuilder::new()
        .data(vec![])
        .sign(&key, 0).expect("empty data");
    assert!(tx.data.is_empty());
}

#[test]
fn test_data_with_null_bytes() {
    let key = test_key();
    let data = vec![0x00; 100];
    let tx = TransactionBuilder::new()
        .data(data)
        .sign(&key, 0).expect("null data");
    assert_eq!(tx.data.len(), 100);
}

// =========================================================================
// ADDRESS ATTACKS
// =========================================================================

#[test]
fn test_to_address_with_injection() {
    let key = test_key();
    // SQL-style injection in address
    let tx = TransactionBuilder::new()
        .to("0x' OR 1=1; DROP TABLE --")
        .value(1000)
        .sign(&key, 0);
    // Should not panic — the address is just bytes in the hash
    assert!(tx.is_ok());
}

#[test]
fn test_to_address_empty() {
    let key = test_key();
    let tx = TransactionBuilder::new()
        .to("")
        .value(1000)
        .sign(&key, 0);
    assert!(tx.is_ok(), "Empty to-address should not panic");
}

#[test]
fn test_contract_deploy_no_to() {
    let key = test_key();
    let tx = TransactionBuilder::new()
        .data(vec![0x60, 0x80, 0x60, 0x40])
        .gas_limit(1_000_000)
        .sign(&key, 0).expect("deploy");
    assert!(tx.to.is_none(), "Contract deploy has no to-address");
}

// =========================================================================
// CHAIN ID ATTACKS
// =========================================================================

#[test]
fn test_chain_id_zero() {
    let key = test_key();
    let tx = TransactionBuilder::new()
        .chain_id(0)
        .value(1000)
        .sign(&key, 0);
    assert!(tx.is_ok(), "Chain ID 0 should not panic");
}

#[test]
fn test_chain_id_max() {
    let key = test_key();
    let tx = TransactionBuilder::new()
        .chain_id(u64::MAX)
        .value(1000)
        .sign(&key, 0);
    assert!(tx.is_ok(), "Max chain ID should not panic");
}

// =========================================================================
// SIGNATURE PROPERTIES
// =========================================================================

#[test]
fn test_signature_length_ed25519() {
    let key = test_key();
    let tx = TransactionBuilder::new()
        .value(1000)
        .sign(&key, 0).expect("sign");
    assert_eq!(tx.signature.len(), 128, "Ed25519 signature = 64 bytes = 128 hex chars");
}

#[test]
fn test_signature_changes_with_different_key() {
    let key1 = test_key();
    let key2 = test_key();
    let tx1 = TransactionBuilder::new().value(1000).sign(&key1, 0).expect("sign 1");
    let tx2 = TransactionBuilder::new().value(1000).sign(&key2, 0).expect("sign 2");
    assert_ne!(tx1.signature, tx2.signature, "Different keys must produce different signatures");
    // But same hash (same content)
    assert_eq!(tx1.hash, tx2.hash, "Same content produces same hash regardless of signer");
}

#[test]
fn test_raw_bytes_not_empty() {
    let key = test_key();
    let tx = TransactionBuilder::new().value(1000).sign(&key, 0).expect("sign");
    assert!(!tx.raw.is_empty(), "Serialized transaction must not be empty");
    assert!(tx.raw.len() > 100, "Serialized transaction should be substantial");
}

#[test]
fn test_from_field_matches_signer() {
    let key = test_key();
    let expected_from = hex::encode(key.verifying_key().to_bytes());
    let tx = TransactionBuilder::new().value(1000).sign(&key, 0).expect("sign");
    assert_eq!(tx.from, expected_from, "From field must match the signing key's public key");
}

// =========================================================================
// UNIFIED KEY SIGNING
// =========================================================================

#[test]
fn test_unified_ed25519_sign_consistency() {
    let key = test_key();
    let unified = UnifiedKey::Ed25519(key.clone());

    let data = b"test transaction data";
    let sig1 = unified.sign(data);
    let sig2 = unified.sign(data);
    assert_eq!(sig1, sig2, "UnifiedKey Ed25519 signing must be deterministic");
}

#[test]
fn test_unified_secp256k1_sign_consistency() {
    let key = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    let unified = UnifiedKey::Secp256k1(key);

    let data = b"test transaction data";
    let sig1 = unified.sign(data);
    let sig2 = unified.sign(data);
    assert_eq!(sig1, sig2, "UnifiedKey secp256k1 signing must be deterministic (RFC 6979)");
}

#[test]
fn test_unified_key_types_produce_different_signatures() {
    // Same 32 bytes interpreted as both Ed25519 and secp256k1
    let secret: [u8; 32] = rand::random();
    let ed_key = Ed25519SigningKey::from_bytes(&secret);
    let secp_key = k256::ecdsa::SigningKey::from_bytes((&secret).into()).expect("secp key");

    let ed_unified = UnifiedKey::Ed25519(ed_key);
    let secp_unified = UnifiedKey::Secp256k1(secp_key);

    let data = b"same data different curves";
    let ed_sig = ed_unified.sign(data);
    let secp_sig = secp_unified.sign(data);

    assert_ne!(ed_sig, secp_sig, "Different curves must produce different signatures from same secret");
}

// =========================================================================
// RPC RESPONSE PARSING
// =========================================================================

#[test]
fn test_rpc_client_creation() {
    let client = RpcClient::new("https://rpc.citrate.ai");
    // Should not panic on creation
    let _ = client;
}

#[test]
fn test_rpc_client_localhost() {
    let client = RpcClient::new("http://localhost:8545");
    let _ = client;
}

#[test]
fn test_rpc_client_invalid_url() {
    // Invalid URLs should be accepted at creation time (fail at request time)
    let client = RpcClient::new("not-a-url");
    let _ = client;
}
