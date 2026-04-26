//! RM-G2.1 / audit CX-01 + WAL-03 — legacy → unified keystore migration test.
//!
//! Round-trip: write two entries through the legacy `wallet::KeyStore`
//! API, run the migrator, open the target file with
//! `citrate_wallet_core::KeyManager`, assert both addresses are present
//! and that signing under the new envelope produces the same signatures
//! the legacy keystore would have.
//!
//! Spec: ADR `.agentile/docs/adr/ADR-RM-G2-1-keystore-consolidation.md`.

use citrate_wallet::keystore::{migrate_to_unified_keystore, KeyStore};
use ed25519_dalek::Signer;
use tempfile::TempDir;

const PW: &str = "rm-g2-1-migration-test";

#[test]
fn rm_g2_1_round_trip_two_entries() {
    let dir = TempDir::new().expect("tempdir");
    let legacy_path = dir.path().join("legacy.json");
    let unified_path = dir.path().join("unified.json");

    // Seed the legacy store with two entries under the same password.
    let mut legacy = KeyStore::new(&legacy_path).expect("new keystore");
    let vk_a = legacy
        .generate_key(PW, Some("alpha".to_string()))
        .expect("generate alpha");
    let vk_b = legacy
        .generate_key(PW, Some("beta".to_string()))
        .expect("generate beta");

    // Capture the legacy-side signature of a known message under each
    // key. Post-migration, the same signing keys must produce
    // bit-identical signatures (the migration only changes the
    // encryption envelope, not the secret bytes).
    legacy.unlock(PW).expect("unlock legacy");
    let msg = b"RM-G2.1 migration parity check";
    let sig_a_legacy = legacy
        .get_signing_key(0)
        .expect("alpha sk")
        .sign(msg)
        .to_bytes();
    let sig_b_legacy = legacy
        .get_signing_key(1)
        .expect("beta sk")
        .sign(msg)
        .to_bytes();

    // Run the migrator. Returns the count of entries written.
    let migrated = migrate_to_unified_keystore(&mut legacy, PW, &unified_path)
        .expect("migration succeeds");
    assert_eq!(migrated, 2, "must migrate both legacy entries");

    // Re-lock the legacy store immediately — the migrator already
    // does this; assert defensively.
    drop(legacy);

    // Open the new keystore via the unified KeyManager API and unlock.
    let manager = citrate_wallet_core::KeyManager::new(&unified_path);
    manager.load().expect("load unified");
    manager.unlock(PW).expect("unlock unified");

    // Both legacy addresses must now appear in the unified keystore.
    let addr_a = citrate_wallet_core::keys::derive_address_from_ed25519(&vk_a.to_bytes());
    let addr_b = citrate_wallet_core::keys::derive_address_from_ed25519(&vk_b.to_bytes());
    let accounts = manager.list_accounts();
    let addresses: Vec<&str> = accounts.iter().map(|a| a.address.as_str()).collect();
    assert!(addresses.contains(&addr_a.as_str()), "alpha must round-trip");
    assert!(addresses.contains(&addr_b.as_str()), "beta must round-trip");

    // Sign the same `msg` via the unified manager. Because ed25519 is
    // deterministic, the signatures must match the legacy ones —
    // bit-identical signatures are the strongest possible parity check
    // (different secret bytes would produce different signatures).
    let key_a = manager.get_signing_key(&addr_a).expect("alpha key");
    let key_b = manager.get_signing_key(&addr_b).expect("beta key");
    let sig_a_unified = key_a.sign(msg);
    let sig_b_unified = key_b.sign(msg);
    assert_eq!(
        &sig_a_unified[..], &sig_a_legacy[..],
        "alpha signature must be identical pre/post migration",
    );
    assert_eq!(
        &sig_b_unified[..], &sig_b_legacy[..],
        "beta signature must be identical pre/post migration",
    );
}

#[test]
fn rm_g2_1_migration_with_wrong_password_fails_cleanly() {
    let dir = TempDir::new().expect("tempdir");
    let legacy_path = dir.path().join("legacy.json");
    let unified_path = dir.path().join("unified.json");

    let mut legacy = KeyStore::new(&legacy_path).expect("new keystore");
    let _ = legacy
        .generate_key(PW, Some("alpha".to_string()))
        .expect("generate alpha");

    // Wrong password — the legacy unlock fails first, so no
    // partial unified file is written.
    let err = migrate_to_unified_keystore(&mut legacy, "WRONG-PASSWORD", &unified_path)
        .expect_err("must fail on wrong password");
    let _ = err; // any error type is acceptable; the contract is "no panic, no partial output"

    assert!(
        !unified_path.exists(),
        "no unified file must be created when migration aborts",
    );
}
