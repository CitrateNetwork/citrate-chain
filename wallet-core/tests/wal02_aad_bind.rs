//! WAL-02 — wallet-core AES-GCM AAD binding regression tests.
//!
//! Audit finding `WAL-02` (HIGH): the keystore's AES-256-GCM seal/open
//! ran with no associated authenticated data (AAD), so an attacker who
//! could write to the keystore on disk could swap a `(ciphertext, salt,
//! nonce)` triple onto a different entry's `(address, key_type)`
//! metadata and decrypt to the wrong identity. The audit cited a
//! type-confusion path: change `key_type` from Ed25519 to Secp256k1
//! and the wallet derives a different on-chain identity from the same
//! 32-byte secret.
//!
//! Sprint RM-A3 / WP-A3.1 binds metadata as AAD per `keystore_v2_aad`:
//!
//!     AAD = b"citrate-keystore-v2"
//!         || kdf_version (4 LE bytes)
//!         || key_type    (0 = Ed25519, 1 = Secp256k1)
//!         || address     (UTF-8)
//!
//! These tests construct a v2 keystore, write its bytes to disk, mutate
//! one metadata field, and assert the next unlock attempt fails (the
//! GCM tag rejects the tampered AAD).

use citrate_wallet_core::keys::KeyManager;
use citrate_wallet_core::types::{EncryptedKeyEntry, KeyType};
use std::path::PathBuf;

fn fresh_keystore() -> PathBuf {
    std::env::temp_dir().join(format!("citrate_wal02_aad_{}", uuid::Uuid::new_v4()))
}

fn read_entries(path: &std::path::Path) -> Vec<EncryptedKeyEntry> {
    let json = std::fs::read_to_string(path.join("keys.json")).expect("read keys.json");
    serde_json::from_str(&json).expect("parse keys.json")
}

fn write_entries(path: &std::path::Path, entries: &[EncryptedKeyEntry]) {
    let json = serde_json::to_string_pretty(entries).expect("serialize");
    std::fs::write(path.join("keys.json"), json).expect("write keys.json");
}

// =========================================================================
// CORE PROPERTY: WAL-02 substitution attacks are detected
// =========================================================================

#[test]
fn test_wal02_address_substitution_rejected() {
    // Two accounts in the same keystore. Swap the first entry's
    // ciphertext/salt/nonce onto the second entry's address — the
    // metadata mismatch must trip the AAD check.
    let path = fresh_keystore();
    let km = KeyManager::new(&path);
    km.create_account("strongpassword12345", "Alice")
        .expect("create alice");
    km.create_account("strongpassword12345", "Bob")
        .expect("create bob");

    let mut entries = read_entries(&path);
    assert_eq!(entries.len(), 2);

    // Substitute alice's ciphertext/salt/nonce onto bob's metadata.
    let alice_ciphertext = entries[0].ciphertext.clone();
    let alice_salt = entries[0].salt.clone();
    let alice_nonce = entries[0].nonce.clone();

    entries[1].ciphertext = alice_ciphertext;
    entries[1].salt = alice_salt;
    entries[1].nonce = alice_nonce;
    write_entries(&path, &entries);

    // Reload and try to unlock — Bob's entry now has Alice's blob but
    // Bob's address. The AAD includes address bytes so the tag check
    // must fail. unlock() reports the specific entry's failure via
    // returning fewer-than-total successful unlocks (or InvalidPassword).
    let km2 = KeyManager::new(&path);
    km2.load().expect("load");
    let result = km2.unlock("strongpassword12345");
    // Either:
    //   (a) unlock returns Err(InvalidPassword) because at least one
    //       entry failed AAD verification, OR
    //   (b) unlock returns Ok(count) where count < entries.len().
    // Both are acceptable failure modes per WAL-02. The bug pre-fix:
    // unlock would return Ok(2) and the substituted blob would decrypt
    // (because there was no AAD to bind metadata).
    match result {
        Err(_) => { /* AAD reject — pass */ }
        Ok(count) => assert!(
            count < 2,
            "WAL-02: substituted entry must fail decryption, got count={}",
            count
        ),
    }
}

#[test]
fn test_wal02_key_type_tamper_rejected() {
    // Flip the key_type field on a v2 entry — the AAD bytes change,
    // the GCM tag fails to verify, decrypt returns InvalidPassword.
    //
    // Pre-fix: this would return Ok(()) because key_type was not in
    // AAD, so the decrypted secret bytes would be re-interpreted under
    // the wrong key type and the wallet would derive a different
    // on-chain identity.
    let path = fresh_keystore();
    let km = KeyManager::new(&path);
    km.create_account("strongpassword12345", "Primary")
        .expect("create");

    let mut entries = read_entries(&path);
    assert_eq!(entries[0].kdf_version, 2);
    assert_eq!(entries[0].key_type, KeyType::Ed25519);
    entries[0].key_type = KeyType::Secp256k1;
    write_entries(&path, &entries);

    let km2 = KeyManager::new(&path);
    km2.load().expect("load");
    let result = km2.unlock("strongpassword12345");
    assert!(
        result.is_err() || matches!(result, Ok(0)),
        "WAL-02: key_type tamper must reject decrypt; got {:?}",
        result
    );
}

#[test]
fn test_wal02_address_string_tamper_rejected() {
    let path = fresh_keystore();
    let km = KeyManager::new(&path);
    km.create_account("strongpassword12345", "Primary")
        .expect("create");

    let mut entries = read_entries(&path);
    let original_address = entries[0].address.clone();
    // Flip a single byte of the address — even a 1-byte change must
    // perturb the AAD enough to fail the tag check.
    let mut tampered = original_address.clone();
    let last = tampered.pop().expect("non-empty");
    let new_last = if last == 'a' { 'b' } else { 'a' };
    tampered.push(new_last);
    entries[0].address = tampered;
    write_entries(&path, &entries);

    let km2 = KeyManager::new(&path);
    km2.load().expect("load");
    let result = km2.unlock("strongpassword12345");
    assert!(
        result.is_err() || matches!(result, Ok(0)),
        "WAL-02: address tamper must reject decrypt; got {:?}",
        result
    );
}

#[test]
fn test_wal02_kdf_version_downgrade_rejected() {
    // Downgrade attack: rewrite kdf_version from 2 -> 1. Pre-fix this
    // would route through the legacy decrypt path (no AAD) and might
    // accidentally succeed because the v2 ciphertext was encrypted
    // without AAD before WAL-02. Post-fix:
    //   - v1 entries decrypt without AAD (legacy path)
    //   - v2 entries decrypt WITH AAD
    // A v2 entry whose kdf_version is rewritten to 1 will be derived
    // with v1 Argon2 params (different key) AND attempted with no AAD
    // (different protocol). The Argon2 mismatch alone is enough to
    // fail the tag check. This test pins both behaviours.
    let path = fresh_keystore();
    let km = KeyManager::new(&path);
    km.create_account("strongpassword12345", "Primary")
        .expect("create");

    let mut entries = read_entries(&path);
    entries[0].kdf_version = 1;
    write_entries(&path, &entries);

    let km2 = KeyManager::new(&path);
    km2.load().expect("load");
    let result = km2.unlock("strongpassword12345");
    assert!(
        result.is_err() || matches!(result, Ok(0)),
        "WAL-02: kdf_version downgrade must reject decrypt; got {:?}",
        result
    );
}

// =========================================================================
// HAPPY PATH: untouched v2 entries unlock cleanly
// =========================================================================

#[test]
fn test_wal02_untouched_v2_entry_unlocks() {
    let path = fresh_keystore();
    let km = KeyManager::new(&path);
    km.create_account("strongpassword12345", "Primary")
        .expect("create");
    km.lock();

    let km2 = KeyManager::new(&path);
    km2.load().expect("load");
    let count = km2.unlock("strongpassword12345").expect("unlock");
    assert_eq!(
        count, 1,
        "WAL-02: an untouched v2 entry must continue to unlock cleanly"
    );
}

#[test]
fn test_wal02_round_trip_through_secp256k1_account() {
    let path = fresh_keystore();
    let km = KeyManager::new(&path);
    km.create_secp256k1_account("strongpassword12345", "Evm")
        .expect("create secp");
    km.lock();

    let km2 = KeyManager::new(&path);
    km2.load().expect("load");
    let count = km2.unlock("strongpassword12345").expect("unlock");
    assert_eq!(count, 1);
}
