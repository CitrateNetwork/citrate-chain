// Sprint PP: Wallet known-answer tests
// Tests ed25519 RFC 8032 public key derivation, sign/verify roundtrip,
// wrong-key verification, Argon2 parameter minimums, AES-GCM
// nonce uniqueness, and keystore corruption detection.

use citrate_wallet::keystore::{EncryptedKey, KeyStore};
use ed25519_dalek::{Signer, SigningKey, Verifier};
use tempfile::TempDir;

// ============================================================
// Helpers
// ============================================================

fn temp_keystore() -> (TempDir, KeyStore) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("keystore.json");
    let ks = KeyStore::new(&path).unwrap();
    (dir, ks)
}

// ============================================================
// 1. RFC 8032 Test Vector 1: public key derivation + sign/verify
// ============================================================

#[test]
fn test_ed25519_rfc8032_test_vector_1() {
    // RFC 8032 Section 7.1 — TEST 1
    // Secret key (seed): 32 bytes of zeros
    // Expected public key:
    //   3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29

    let seed = [0u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    // Verify public key matches the known answer from RFC 8032
    let expected_pk =
        hex::decode("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29")
            .unwrap();
    assert_eq!(
        verifying_key.to_bytes(),
        expected_pk.as_slice(),
        "Public key must match RFC 8032 Test Vector 1"
    );

    // Sign the empty message and verify round-trip
    let message = b"";
    let signature = signing_key.sign(message);
    verifying_key
        .verify(message, &signature)
        .expect("Signature for empty message must verify with RFC 8032 key");

    // Signature must be deterministic (same key + message = same sig)
    let signature2 = signing_key.sign(message);
    assert_eq!(
        signature.to_bytes(),
        signature2.to_bytes(),
        "Ed25519 signatures must be deterministic"
    );
}

// ============================================================
// 2. RFC 8032 Test Vector 2: public key derivation + sign/verify
// ============================================================

#[test]
fn test_ed25519_rfc8032_test_vector_2() {
    // RFC 8032 Section 7.1 — TEST 2
    // Secret key (seed):
    //   4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb
    // Expected public key:
    //   3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
    // Message: 0x72 (single byte 'r')

    let seed =
        hex::decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
            .unwrap();
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed);

    let signing_key = SigningKey::from_bytes(&seed_arr);
    let verifying_key = signing_key.verifying_key();

    // Verify public key matches RFC 8032 Test Vector 2
    let expected_pk =
        hex::decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
            .unwrap();
    assert_eq!(
        verifying_key.to_bytes(),
        expected_pk.as_slice(),
        "Public key must match RFC 8032 Test Vector 2"
    );

    // Sign the specified message and verify round-trip
    let message = &[0x72u8];
    let signature = signing_key.sign(message);
    verifying_key
        .verify(message, &signature)
        .expect("Signature for 0x72 must verify with RFC 8032 key");

    // Signature must be deterministic
    let signature2 = signing_key.sign(message);
    assert_eq!(
        signature.to_bytes(),
        signature2.to_bytes(),
        "Ed25519 signatures must be deterministic"
    );
}

// ============================================================
// 3. Sign/verify roundtrip with known key
// ============================================================

#[test]
fn test_ed25519_sign_verify_roundtrip() {
    let seed = [0x42u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let message = b"Citrate bridge deposit 1.5 ETH";
    let signature = signing_key.sign(message);

    // Verify succeeds with correct key and message
    verifying_key
        .verify(message, &signature)
        .expect("Roundtrip verify must succeed");

    // Verify fails with modified message
    let altered = b"Citrate bridge deposit 9.9 ETH";
    assert!(
        verifying_key.verify(altered, &signature).is_err(),
        "Verification must fail with altered message"
    );
}

// ============================================================
// 4. Wrong key verification fails
// ============================================================

#[test]
fn test_ed25519_wrong_key_verification_fails() {
    let key_a = SigningKey::from_bytes(&[0x01; 32]);
    let key_b = SigningKey::from_bytes(&[0x02; 32]);

    let message = b"cross-chain transfer";
    let signature = key_a.sign(message);

    // Correct key succeeds
    key_a
        .verifying_key()
        .verify(message, &signature)
        .expect("Correct key must verify");

    // Wrong key fails
    assert!(
        key_b.verifying_key().verify(message, &signature).is_err(),
        "Wrong key must fail verification"
    );
}

// ============================================================
// 5. Keystore Argon2 params — WAL-01 (rewritten)
//
// Pre-WAL-01 this test asserted the OWASP *floor* (m>=19456, t>=2)
// against `argon2::Params::default()`. That assertion held even when the
// keystore was vulnerable: the default *is* at the floor. The test
// reassured but did not protect.
//
// Per docs/security/KDF_POLICY.md and planset Section 6
// (tests-that-hid-vulnerabilities), this test is now rewritten to assert
// the *observable production property* — every freshly generated entry
// declares `kdf_version >= 2`, which transitively means OWASP-recommended
// parameters are in use (m=65536, t=3, p=4, output_len=32).
//
// The legacy floor is still documented in a sibling test below for
// historical awareness.
// ============================================================

#[test]
fn test_keystore_argon2_params_minimum() {
    // WAL-01: Production keystores write `kdf_version >= 2`. Verify by
    // generating a key through the public API and inspecting the on-disk
    // record.
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("keystore.json");
    let mut ks = KeyStore::new(&path).expect("keystore");
    ks.generate_key("strongpassword12345", None)
        .expect("generate_key under v2 KDF should succeed");

    let bytes = std::fs::read(&path).expect("read keystore JSON");
    let entries: Vec<EncryptedKey> =
        serde_json::from_slice(&bytes).expect("parse keystore JSON");
    assert_eq!(entries.len(), 1);

    assert!(
        entries[0].kdf_version >= 2,
        "WAL-01: keystore generated by the current code wrote kdf_version={}, \
         expected >= 2. See docs/security/KDF_POLICY.md.",
        entries[0].kdf_version,
    );
}

#[test]
fn test_keystore_argon2_legacy_floor_still_recognized() {
    // Documents (without enforcing as a production gate) that the
    // legacy default at OWASP floor is what `kdf_version: 1` represents.
    // This is informational — production never writes v1 — but the
    // dispatcher must still honor v1 on read for backward compatibility.
    let params = argon2::Params::default();
    assert!(
        params.m_cost() >= 19_456,
        "OWASP floor: memory >= 19456 KiB, got {}",
        params.m_cost()
    );
    assert!(
        params.t_cost() >= 2,
        "OWASP floor: iterations >= 2, got {}",
        params.t_cost()
    );
}

// ============================================================
// 6. AES-GCM nonce uniqueness
// ============================================================

#[test]
fn test_aes_gcm_nonce_uniqueness() {
    let (_dir, mut ks) = temp_keystore();

    let password = "test-password-nonce";
    ks.generate_key(password, Some("key-1".to_string())).unwrap();
    ks.generate_key(password, Some("key-2".to_string())).unwrap();

    let accounts = ks.list_accounts();
    assert_eq!(accounts.len(), 2);

    // Read the raw encrypted keys to compare nonces and ciphertexts
    let keystore_path = _dir.path().join("keystore.json");
    let data = std::fs::read(&keystore_path).unwrap();
    let encrypted_keys: Vec<EncryptedKey> = serde_json::from_slice(&data).unwrap();
    assert_eq!(encrypted_keys.len(), 2);

    // Nonces must differ
    assert_ne!(
        encrypted_keys[0].nonce, encrypted_keys[1].nonce,
        "AES-GCM nonces must be unique across encryptions"
    );

    // Ciphertexts must differ (different keys + different nonces)
    assert_ne!(
        encrypted_keys[0].ciphertext, encrypted_keys[1].ciphertext,
        "Ciphertexts must differ when nonces differ"
    );
}

// ============================================================
// 7. Keystore corruption detection (single byte flip)
// ============================================================

#[test]
fn test_keystore_corruption_single_byte() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("keystore.json");

    let password = "corruption-test-pw";
    let secret = [0x77u8; 32];

    // Create keystore with a known key
    {
        let mut ks = KeyStore::new(&path).unwrap();
        ks.import_key(&hex::encode(secret), password, None).unwrap();
    }

    // Read the keystore file, corrupt 1 byte in the ciphertext, write back
    let data = std::fs::read(&path).unwrap();
    let mut encrypted_keys: Vec<EncryptedKey> = serde_json::from_slice(&data).unwrap();
    assert!(!encrypted_keys[0].ciphertext.is_empty());

    // Flip a bit in the middle of the ciphertext
    let mid = encrypted_keys[0].ciphertext.len() / 2;
    encrypted_keys[0].ciphertext[mid] ^= 0xFF;

    // Write corrupted keystore back
    let corrupted_data = serde_json::to_vec_pretty(&encrypted_keys).unwrap();
    std::fs::write(&path, corrupted_data).unwrap();

    // Attempt to decrypt: must fail
    let mut ks = KeyStore::new(&path).unwrap();
    let result = ks.unlock(password);
    assert!(
        result.is_err(),
        "Decrypting a corrupted ciphertext must fail"
    );
}
