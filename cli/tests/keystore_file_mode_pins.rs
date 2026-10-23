// The CLI keystore file mode, pinned at `save_key` when it overwrites a file.
//
// `save_key` opens the file with mode 0600 and then sets 0600 explicitly. The
// open mode only applies when the file is created; when an existing keystore
// is overwritten, `OpenOptions::mode` leaves its old permissions in place, so
// only the explicit chmod keeps the key owner-only. The existing mode test
// writes a fresh file, so it stayed green with the chmod removed. These tests
// overwrite a pre-existing world-readable file.
//
// Unix only. Writes only to a temporary directory.
#![cfg(unix)]

use citrate_cli::utils::keystore::{load_key, save_key};
use ed25519_dalek::SigningKey;
use std::os::unix::fs::PermissionsExt;

fn mode(path: &std::path::Path) -> u32 {
    std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

#[test]
fn overwriting_a_world_readable_keystore_leaves_it_owner_only() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("key.json");
    std::fs::write(&path, b"{}").expect("seed file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod 644");
    assert_eq!(
        mode(&path),
        0o644,
        "precondition: the seeded file is world-readable"
    );

    let key = SigningKey::from_bytes(&[0x42u8; 32]);
    save_key(&key, "correct horse battery", &path).expect("save over the existing file");

    assert_eq!(
        mode(&path),
        0o600,
        "an overwritten keystore must be 0600, got {:o}",
        mode(&path)
    );
    // The overwrite really replaced the content (not a no-op on the old file).
    let loaded = load_key(&path, "correct horse battery").expect("load");
    assert_eq!(loaded.to_bytes(), key.to_bytes());
}

#[test]
fn overwriting_a_group_writable_keystore_clears_every_non_owner_bit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("key.json");
    std::fs::write(&path, b"{}").expect("seed file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).expect("chmod 666");

    save_key(
        &SigningKey::from_bytes(&[0x43u8; 32]),
        "correct horse battery",
        &path,
    )
    .expect("save over the existing file");

    assert_eq!(
        mode(&path) & 0o077,
        0,
        "group/other bits must be cleared, got {:o}",
        mode(&path)
    );
}
