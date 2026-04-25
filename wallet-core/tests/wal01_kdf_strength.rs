//! WP-A1.1 / WAL-01 — Argon2 KDF strength regression tests.
//!
//! Audit finding: WAL-01 (CRITICAL) — `Argon2::default()` is at the OWASP
//! 2024 floor (m=19 MiB, t=2, p=1). Per `docs/security/KDF_POLICY.md`, every
//! production keystore entry MUST be written under v2 parameters
//! (m=64 MiB, t=3, p=4, output_len=32).
//!
//! The discriminating observable is the `kdf_version` field on each
//! `EncryptedKeyEntry`. v1 (legacy) entries have `kdf_version = 1`; new
//! entries written by post-fix code have `kdf_version >= 2`. This test
//! creates an account through the public `KeyManager::create_account` API
//! and inspects the on-disk JSON to verify the field landed correctly.
//!
//! Spec: `docs/security/KDF_POLICY.md`
//! Sprint: RM-A1, WP-A1.1
//! Closes: WAL-01

use citrate_wallet_core::keys::KeyManager;
use proptest::prelude::*;
use serde_json::Value;
use std::path::PathBuf;

/// The minimum acceptable `kdf_version` per `docs/security/KDF_POLICY.md`.
///
/// `1` (legacy) is acceptable on **read** for backward compatibility, but
/// every freshly-written entry MUST be `>= 2`.
const MIN_KDF_VERSION_FOR_NEW_ENTRY: u64 = 2;

fn fresh_keystore() -> PathBuf {
    std::env::temp_dir().join(format!("citrate_wal01_kdf_{}", uuid::Uuid::new_v4()))
}

fn read_keystore_json(keystore_path: &std::path::Path) -> Vec<Value> {
    let path = keystore_path.join("keys.json");
    let content = std::fs::read_to_string(&path)
        .expect("keystore JSON should exist after create_account");
    serde_json::from_str(&content)
        .expect("keystore JSON should parse as a JSON array")
}

// =========================================================================
// CORE PROPERTY: every newly-written entry has kdf_version >= 2
// =========================================================================

#[test]
fn test_wal01_create_account_writes_kdf_version_v2() {
    let path = fresh_keystore();
    let km = KeyManager::new(&path);

    km.create_account("strongpassword12345", "primary")
        .expect("create_account should succeed with valid password");

    let entries = read_keystore_json(&path);
    assert_eq!(entries.len(), 1, "exactly one entry should be on disk");

    let entry = &entries[0];
    let kdf_version = entry
        .get("kdf_version")
        .and_then(|v| v.as_u64())
        .unwrap_or_else(|| panic!(
            "WAL-01: keystore entry missing required `kdf_version` field. \
             Entry: {}. Per docs/security/KDF_POLICY.md, every freshly \
             written entry must declare its KDF version (>= 2 in production).",
            serde_json::to_string_pretty(entry).unwrap_or_default(),
        ));

    assert!(
        kdf_version >= MIN_KDF_VERSION_FOR_NEW_ENTRY,
        "WAL-01: kdf_version is {}, expected >= {}. \
         New entries must use OWASP-recommended Argon2id parameters per \
         docs/security/KDF_POLICY.md. Default Argon2 parameters are at the \
         OWASP floor and not acceptable for production keystores.",
        kdf_version,
        MIN_KDF_VERSION_FOR_NEW_ENTRY,
    );
}

#[test]
fn test_wal01_import_account_writes_kdf_version_v2() {
    let path = fresh_keystore();
    let km = KeyManager::new(&path);

    // Deterministic test key (32 bytes of 0x42).
    let key_hex = hex::encode([0x42u8; 32]);
    km.import_account(&key_hex, "strongpassword12345", "imported")
        .expect("import_account should succeed");

    let entries = read_keystore_json(&path);
    let entry = &entries[0];
    let kdf_version = entry
        .get("kdf_version")
        .and_then(|v| v.as_u64())
        .expect(
            "WAL-01: imported entry missing required `kdf_version` field. \
             import_account must mirror create_account's KDF policy.",
        );
    assert!(
        kdf_version >= MIN_KDF_VERSION_FOR_NEW_ENTRY,
        "WAL-01 (import path): kdf_version is {}, expected >= {}",
        kdf_version,
        MIN_KDF_VERSION_FOR_NEW_ENTRY,
    );
}

#[test]
fn test_wal01_secp256k1_account_writes_kdf_version_v2() {
    let path = fresh_keystore();
    let km = KeyManager::new(&path);

    km.create_secp256k1_account("strongpassword12345", "evm-account")
        .expect("create_secp256k1_account should succeed");

    let entries = read_keystore_json(&path);
    let entry = &entries[0];
    let kdf_version = entry
        .get("kdf_version")
        .and_then(|v| v.as_u64())
        .expect(
            "WAL-01: secp256k1 entry missing required `kdf_version` field. \
             create_secp256k1_account must use v2 KDF params.",
        );
    assert!(
        kdf_version >= MIN_KDF_VERSION_FOR_NEW_ENTRY,
        "WAL-01 (secp256k1 path): kdf_version is {}, expected >= {}",
        kdf_version,
        MIN_KDF_VERSION_FOR_NEW_ENTRY,
    );
}

#[test]
fn test_wal01_recover_from_mnemonic_writes_kdf_version_v2() {
    let path = fresh_keystore();
    let km = KeyManager::new(&path);

    // 24-word BIP39 test mnemonic.
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon \
                  abandon abandon abandon abandon abandon abandon abandon abandon \
                  abandon abandon abandon abandon abandon abandon abandon art";
    km.recover_from_mnemonic(phrase, "strongpassword12345", "recovered")
        .expect("recover_from_mnemonic should succeed for a valid 24-word phrase");

    let entries = read_keystore_json(&path);
    let entry = &entries[0];
    let kdf_version = entry
        .get("kdf_version")
        .and_then(|v| v.as_u64())
        .expect(
            "WAL-01: recovered entry missing required `kdf_version` field. \
             recover_from_mnemonic must use v2 KDF params.",
        );
    assert!(
        kdf_version >= MIN_KDF_VERSION_FOR_NEW_ENTRY,
        "WAL-01 (mnemonic recovery path): kdf_version is {}, expected >= {}",
        kdf_version,
        MIN_KDF_VERSION_FOR_NEW_ENTRY,
    );
}

// =========================================================================
// PROPERTY-BASED: across many (password, label) inputs, every freshly
// written entry has kdf_version >= 2
// =========================================================================

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 16,
        // Argon2 v2 takes ~250 ms per call; keep iteration count small but
        // sufficient to flush out parameter regressions.
        ..ProptestConfig::default()
    })]

    /// Vary the password and label; the KDF version always lands at >= 2.
    ///
    /// Failure mode this catches: a future refactor that retains the
    /// `kdf_version` field on the type but writes `1` (or omits the field
    /// via a serde default that returns 1) instead of the current value.
    #[test]
    fn prop_create_account_always_writes_kdf_version_v2(
        password in "[a-zA-Z0-9!@#$%^&*]{8,32}",
        label in "[A-Za-z0-9_-]{1,16}",
    ) {
        let path = fresh_keystore();
        let km = KeyManager::new(&path);

        km.create_account(&password, &label)
            .map_err(|e| TestCaseError::fail(format!("create_account failed: {:?}", e)))?;

        let entries = read_keystore_json(&path);
        prop_assert_eq!(entries.len(), 1);
        let kdf_version = entries[0]
            .get("kdf_version")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| TestCaseError::fail(
                "kdf_version missing from JSON".to_string(),
            ))?;
        prop_assert!(
            kdf_version >= MIN_KDF_VERSION_FOR_NEW_ENTRY,
            "kdf_version was {}, expected >= {}",
            kdf_version,
            MIN_KDF_VERSION_FOR_NEW_ENTRY,
        );
    }
}

// =========================================================================
// LATENCY HEURISTIC: post-fix create_account should NOT complete in <50 ms
//
// Default Argon2 parameters complete in ~30-60 ms on a modern desktop.
// The OWASP-recommended params we adopt in WP-A1.1 take ~200-400 ms. This
// gives a soft signal that the caller actually used the stronger params,
// independent of any field-name reflection.
//
// Marked #[ignore] today because:
//   (a) running this test in CI without per-runner calibration is flaky,
//   (b) WP-A1.2 introduces a proper calibration bench in
//       wallet-core/benches/argon2_calibration.rs.
//
// Run manually via `cargo test --test wal01_kdf_strength latency -- --ignored`
// =========================================================================

#[test]
#[ignore]
fn test_wal01_create_account_latency_consistent_with_v2_params() {
    let path = fresh_keystore();
    let km = KeyManager::new(&path);

    let start = std::time::Instant::now();
    km.create_account("strongpassword12345", "latency")
        .expect("create_account should succeed");
    let elapsed = start.elapsed();

    // Default Argon2 (m=19 MiB, t=2, p=1) is typically <80 ms.
    // OWASP-recommended (m=64 MiB, t=3, p=4) is typically >150 ms.
    // We assert >100 ms as a generous threshold. Failure means the call
    // is suspiciously fast — likely back to the default parameters.
    assert!(
        elapsed.as_millis() >= 100,
        "WAL-01: create_account took {}ms, expected >=100ms with v2 KDF params. \
         A sub-100ms time strongly suggests Argon2 reverted to defaults. \
         Run wallet-core/benches/argon2_calibration.rs to verify.",
        elapsed.as_millis(),
    );
    assert!(
        elapsed.as_millis() <= 1500,
        "WAL-01: create_account took {}ms, exceeding the 1500ms upper bound. \
         Either the runner is unusually slow or the params are over-tuned. \
         Run wallet-core/benches/argon2_calibration.rs and consider the \
         LowMemory profile per docs/security/KDF_POLICY.md §3.3.",
        elapsed.as_millis(),
    );
}
