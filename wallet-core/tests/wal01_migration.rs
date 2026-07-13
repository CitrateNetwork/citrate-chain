// B1.1-F-1: native-only — exercises `KeyManager` KDF migration.
#![cfg(feature = "native")]
//! WP-A1.3 — KDF migration v1 → v2 regression tests.
//!
//! Verifies the lazy-migration path documented in
//! `docs/security/KDF_POLICY.md` §4.2:
//!
//!   * Read-only unlock is side-effect-free (v1 entry stays v1).
//!   * Explicit `migrate_to_current_kdf` upgrades v1 entries in place.
//!   * Migration is idempotent (calling on a v2 keystore is a no-op).
//!   * `has_legacy_kdf_entries` correctly reports the keystore's state.
//!   * Wrong password leaves the keystore untouched (atomic).
//!
//! Sprint: RM-A1, WP-A1.3
//! Closes: WAL-01 (migration aspect)

use citrate_wallet_core::keys::KeyManager;
use serde_json::Value;
use std::path::{Path, PathBuf};

fn fresh_keystore() -> PathBuf {
    std::env::temp_dir().join(format!("citrate_wal01_mig_{}", uuid::Uuid::new_v4()))
}

fn read_entries_json(keystore_path: &Path) -> Vec<Value> {
    let path = keystore_path.join("keys.json");
    let content = std::fs::read_to_string(&path)
        .expect("keystore JSON should exist after create_account");
    serde_json::from_str(&content).expect("keystore JSON should parse as JSON array")
}

/// Build a keystore on disk with a single v1 (legacy) entry by injecting
/// the JSON directly. Mirrors the shape of pre-WAL-01 entries: no
/// `kdf_version` field, encrypted under `Argon2::default()` parameters.
///
/// Returns the path of the keystore directory.
fn build_v1_keystore(password: &str) -> PathBuf {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use argon2::Argon2;
    use base64::Engine;

    let path = fresh_keystore();
    std::fs::create_dir_all(&path).expect("create keystore dir");

    // Generate a deterministic Ed25519 key for the test entry.
    let secret_bytes: [u8; 32] = [0x42; 32];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
    let pubkey = signing_key.verifying_key().to_bytes();
    let public_key_hex = hex::encode(pubkey);

    // Derive an EVM-style address (last 20 bytes of Keccak256(pubkey)).
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();
    hasher.update(pubkey);
    let hash = hasher.finalize();
    let address = format!("0x{}", hex::encode(&hash[12..32]));

    // Encrypt under Argon2 defaults (the v1 path).
    let salt: [u8; 16] = [0x11; 16];
    let nonce_bytes: [u8; 12] = [0x22; 12];
    let mut derived_key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), &salt, &mut derived_key)
        .expect("v1 KDF should derive a key");
    let cipher = Aes256Gcm::new_from_slice(&derived_key).expect("AES init");
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, secret_bytes.as_ref())
        .expect("AES encrypt");

    // Write a v1 entry — note the *missing* kdf_version field.
    let v1_json = format!(
        r#"[{{
            "public_key_hex": "{}",
            "address": "{}",
            "label": "v1-legacy",
            "key_type": "Ed25519",
            "ciphertext": "{}",
            "salt": "{}",
            "nonce": "{}",
            "created_at": 1700000000
        }}]"#,
        public_key_hex,
        address,
        base64::engine::general_purpose::STANDARD.encode(&ciphertext),
        base64::engine::general_purpose::STANDARD.encode(salt),
        base64::engine::general_purpose::STANDARD.encode(nonce_bytes),
    );
    std::fs::write(path.join("keys.json"), v1_json).expect("write v1 keystore");

    path
}

// =========================================================================
// CORE PROPERTIES
// =========================================================================

#[test]
fn test_wal01_v1_keystore_unlocks_under_legacy_params() {
    // Sanity check: a v1 entry on disk still unlocks under Argon2::default()
    // via the `argon2_for_version(KDF_VERSION_LEGACY)` dispatcher.
    let password = "v1-legacy-password";
    let path = build_v1_keystore(password);

    let km = KeyManager::new(&path);
    km.load().expect("load v1 keystore");
    let count = km
        .unlock(password)
        .expect("v1 entry should unlock under legacy params");
    assert_eq!(count, 1, "exactly one v1 entry should unlock");
}

#[test]
fn test_wal01_unlock_does_not_auto_migrate() {
    // Read-only unlock leaves the on-disk entry untouched. The
    // `kdf_version` field stays at its serde-default (1).
    let password = "v1-legacy-password";
    let path = build_v1_keystore(password);

    let km = KeyManager::new(&path);
    km.load().expect("load");
    km.unlock(password).expect("unlock");
    km.lock();

    let entries = read_entries_json(&path);
    let kdf_version = entries[0]
        .get("kdf_version")
        .and_then(|v| v.as_u64());
    assert!(
        kdf_version.is_none() || kdf_version == Some(1),
        "WAL-01 / WP-A1.3: read-only unlock must NOT auto-migrate. \
         Migration is opt-in via `migrate_to_current_kdf`. \
         Got kdf_version: {:?}",
        kdf_version
    );
    assert!(
        km.has_legacy_kdf_entries(),
        "has_legacy_kdf_entries must report true for an unmigrated v1 keystore"
    );
}

#[test]
fn test_wal01_explicit_migrate_upgrades_v1_to_v2() {
    let password = "v1-legacy-password";
    let path = build_v1_keystore(password);

    let km = KeyManager::new(&path);
    km.load().expect("load");
    let upgraded = km
        .migrate_to_current_kdf(password)
        .expect("migration should succeed under correct password");
    assert_eq!(upgraded, 1, "exactly one entry should have been migrated");

    // Verify on disk: kdf_version is now 2.
    let entries = read_entries_json(&path);
    let kdf_version = entries[0]
        .get("kdf_version")
        .and_then(|v| v.as_u64())
        .expect("post-migration entry must have explicit kdf_version field");
    assert_eq!(
        kdf_version, 2,
        "WAL-01 / WP-A1.3: migrate_to_current_kdf must rewrite v1 entries as v2"
    );

    // Verify the migrated entry still unlocks under the same password.
    let km2 = KeyManager::new(&path);
    km2.load().expect("load post-migration");
    let count = km2
        .unlock(password)
        .expect("migrated entry should unlock");
    assert_eq!(count, 1, "migrated entry should unlock");
    assert!(
        !km2.has_legacy_kdf_entries(),
        "post-migration keystore should report no legacy entries"
    );
}

#[test]
fn test_wal01_migration_is_idempotent_on_v2_keystore() {
    // A keystore created by current code (v2 from the start) should be
    // a no-op on migrate_to_current_kdf.
    let path = fresh_keystore();
    let km = KeyManager::new(&path);
    km.create_account("strongpassword12345", "v2-from-start")
        .expect("create v2 account");

    let upgraded_first = km
        .migrate_to_current_kdf("strongpassword12345")
        .expect("idempotent migration on v2 keystore");
    assert_eq!(
        upgraded_first, 0,
        "WP-A1.3: migration on a v2 keystore must be a no-op (0 upgrades)"
    );

    let upgraded_second = km
        .migrate_to_current_kdf("strongpassword12345")
        .expect("second migration call still no-op");
    assert_eq!(upgraded_second, 0);
}

#[test]
fn test_wal01_migration_fails_atomically_on_wrong_password() {
    // Wrong password must NOT corrupt the keystore. The v1 entry stays
    // intact, no v2 record is written, no half-migrated state.
    let password = "correct-password-12345";
    let wrong_password = "wrong-password-XXXXX";
    let path = build_v1_keystore(password);

    let km = KeyManager::new(&path);
    km.load().expect("load");

    let result = km.migrate_to_current_kdf(wrong_password);
    assert!(
        result.is_err(),
        "WP-A1.3: migration with wrong password must error, not silently corrupt the keystore"
    );

    // Keystore unchanged on disk.
    let entries = read_entries_json(&path);
    let kdf_version = entries[0]
        .get("kdf_version")
        .and_then(|v| v.as_u64());
    assert!(
        kdf_version.is_none() || kdf_version == Some(1),
        "WP-A1.3: failed migration must leave keystore at v1, got kdf_version: {:?}",
        kdf_version
    );

    // And the entry still unlocks under the *correct* password.
    let km2 = KeyManager::new(&path);
    km2.load().expect("load after failed migration");
    let count = km2
        .unlock(password)
        .expect("v1 entry should still unlock under correct password");
    assert_eq!(count, 1, "atomicity: keystore unaltered by failed migration");
}

#[test]
fn test_wal01_has_legacy_kdf_entries_empty_keystore() {
    // An empty keystore reports no legacy entries.
    let path = fresh_keystore();
    let km = KeyManager::new(&path);
    assert!(
        !km.has_legacy_kdf_entries(),
        "empty keystore should not report legacy entries"
    );
}

#[test]
fn test_wal01_migration_preserves_address_and_pubkey() {
    // Migrating v1 → v2 must NOT change the on-chain identity. The
    // address and public key bytes must be byte-identical before and
    // after migration.
    let password = "v1-legacy-password";
    let path = build_v1_keystore(password);

    let entries_pre = read_entries_json(&path);
    let address_pre = entries_pre[0]["address"].as_str().expect("pre address");
    let pubkey_pre = entries_pre[0]["public_key_hex"].as_str().expect("pre pubkey");

    let km = KeyManager::new(&path);
    km.load().expect("load");
    km.migrate_to_current_kdf(password).expect("migrate");

    let entries_post = read_entries_json(&path);
    let address_post = entries_post[0]["address"].as_str().expect("post address");
    let pubkey_post = entries_post[0]["public_key_hex"].as_str().expect("post pubkey");

    assert_eq!(
        address_pre, address_post,
        "WP-A1.3: migration must preserve address (identity invariant)"
    );
    assert_eq!(
        pubkey_pre, pubkey_post,
        "WP-A1.3: migration must preserve pubkey (identity invariant)"
    );

    // Also: created_at preserved, label preserved.
    assert_eq!(entries_pre[0]["created_at"], entries_post[0]["created_at"]);
    assert_eq!(entries_pre[0]["label"], entries_post[0]["label"]);

    // But the ciphertext and salt MUST differ — we re-encrypted under
    // fresh randomness.
    assert_ne!(
        entries_pre[0]["ciphertext"], entries_post[0]["ciphertext"],
        "WP-A1.3: migrated ciphertext must use a fresh nonce/salt"
    );
}
