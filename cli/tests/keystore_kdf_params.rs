// The CLI keystore's key-derivation cost, pinned at `save_key`.
//
// A keystore written by `save_key` must decrypt with a key derived by Argon2id
// at m = 65536 KiB, t = 3, p = 1 (the same parameters as wallet-core). The
// existing round-trip tests use the crate's own derive function on both sides,
// so they still pass if the parameters are lowered; this test derives the key
// independently.
//
// Writes only to a temporary directory.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use citrate_cli::utils::keystore::save_key;
use ed25519_dalek::SigningKey;

const PASSWORD: &str = "correct horse battery";

fn derive(password: &str, salt: &[u8], m_kib: u32, t: u32, p: u32) -> [u8; 32] {
    let params = Params::new(m_kib, t, p, Some(32)).expect("params");
    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("argon2");
    key
}

fn field(v: &serde_json::Value, name: &str) -> Vec<u8> {
    hex::decode(v[name].as_str().expect(name)).expect("hex")
}

fn decrypt(key: &[u8; 32], nonce: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
        .decrypt(Nonce::from_slice(nonce), ct)
        .ok()
}

#[test]
fn a_new_keystore_decrypts_only_with_the_full_cost_argon2id_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("key.json");
    let sk = SigningKey::from_bytes(&[0x5Au8; 32]);
    save_key(&sk, PASSWORD, &path).expect("save");

    let ks: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
    assert_eq!(ks["kdf_version"], 2);
    let salt = field(&ks, "salt");
    let nonce = field(&ks, "nonce");
    let ct = field(&ks, "encrypted_key");

    let full = derive(PASSWORD, &salt, 65_536, 3, 1);
    assert_eq!(
        decrypt(&full, &nonce, &ct).as_deref(),
        Some(sk.to_bytes().as_slice()),
        "the keystore key must be Argon2id(m=65536 KiB, t=3, p=1) of the password"
    );

    // A cheaper derivation of the same password must not open it.
    let cheap = derive(PASSWORD, &salt, 8, 1, 1);
    assert!(decrypt(&cheap, &nonce, &ct).is_none());
}
