//citrate/cli/src/utils/keystore.rs
//
// Ed25519 keystore - aligned with wallet for account portability

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::fs;
use std::path::Path;
use zeroize::Zeroizing;

/// Legacy KDF: SHA3-256(password‖salt) folded 10 000 times. NOT memory-hard.
/// Written by pre-CHAIN-B-E001 CLI builds. Accepted on read only, never
/// written by the current code.
const KDF_VERSION_LEGACY_SHA3: u32 = 1;

/// Current KDF: Argon2id (m=65536 KiB, t=3, p=1, out=32) — OWASP 2024
/// parameters, matching `wallet-core`'s `KDF_VERSION_CURRENT`. This is the
/// only KDF the current code writes (CHAIN-B-E001).
const KDF_VERSION_ARGON2ID: u32 = 2;

/// Minimum password length for newly written keystores, mirroring
/// `wallet-core`'s 8-char floor (CHAIN-B-E001).
const MIN_PASSWORD_LEN: usize = 8;

fn default_kdf_version_legacy() -> u32 {
    KDF_VERSION_LEGACY_SHA3
}

#[derive(Serialize, Deserialize)]
struct Keystore {
    version: u32,
    key_type: String, // "ed25519" for new keys
    encrypted_key: String,
    salt: String,
    nonce: String,
    public_key: Option<String>, // Store public key for reference
    /// KDF used to derive the AES-256-GCM key from the password.
    ///   1 = legacy SHA3-256 x10000 (read-only back-compat)
    ///   2 = Argon2id (current; CHAIN-B-E001)
    /// Absent on pre-E001 keystores, which default to `1`.
    #[serde(default = "default_kdf_version_legacy")]
    kdf_version: u32,
}

/// Save an ed25519 signing key to an encrypted keystore file.
///
/// New keystores are always written with Argon2id (`kdf_version: 2`) and a
/// minimum password length (CHAIN-B-E001), and the file is created 0600 on
/// Unix (CHAIN-B-E002).
pub fn save_key(signing_key: &SigningKey, password: &str, path: &Path) -> Result<()> {
    if password.len() < MIN_PASSWORD_LEN {
        anyhow::bail!(
            "Password too short: {} chars (minimum {})",
            password.len(),
            MIN_PASSWORD_LEN
        );
    }

    // Generate random salt
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);

    // Derive encryption key from password (Argon2id v2). The derived key is
    // wrapped in Zeroizing so its bytes are wiped when this scope ends.
    let encryption_key = derive_key_argon2id(password, &salt)?;

    // Generate random nonce for AES-GCM
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the private key using AES-256-GCM
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(encryption_key.as_ref()));
    let key_bytes = Zeroizing::new(signing_key.to_bytes());

    let ciphertext = cipher
        .encrypt(nonce, key_bytes.as_ref())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    // Store public key for reference (not encrypted)
    let public_key = signing_key.verifying_key();

    let keystore = Keystore {
        version: 2, // Version 2 = ed25519
        key_type: "ed25519".to_string(),
        encrypted_key: hex::encode(ciphertext),
        salt: hex::encode(salt),
        nonce: hex::encode(nonce_bytes),
        public_key: Some(hex::encode(public_key.to_bytes())),
        kdf_version: KDF_VERSION_ARGON2ID,
    };

    // Create parent directory if needed (0700 on Unix, mirroring wallet-core)
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
    }

    let json = serde_json::to_string_pretty(&keystore)?;
    // PBA-L4-009: create the file 0600 from the start. `fs::write` created it
    // with the umask mode (commonly 0644) and chmod-ed afterwards, leaving a
    // window in which the encrypted key was world-readable.
    {
        use std::io::Write;
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(path)
            .with_context(|| format!("Failed to write keystore to {:?}", path))?;
        f.write_all(json.as_bytes())
            .with_context(|| format!("Failed to write keystore to {:?}", path))?;
    }

    // CHAIN-B-E002: restrict the keystore file to owner-only (0600). Without
    // this the file inherits umask (commonly 0644, world-readable).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("Failed to set 0600 on {:?}", path))?;
    }

    Ok(())
}

/// Load an ed25519 signing key from an encrypted keystore file.
///
/// Dispatches on `kdf_version`: Argon2id (v2, current) and the legacy
/// SHA3-256 KDF (v1) both decrypt so existing keystores keep opening.
pub fn load_key(path: &Path, password: &str) -> Result<SigningKey> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("Failed to read keystore from {:?}", path))?;

    let keystore: Keystore = serde_json::from_str(&contents).context("Invalid keystore format")?;

    // Check key type
    if keystore.version >= 2 && keystore.key_type != "ed25519" {
        anyhow::bail!("Unsupported key type: {}", keystore.key_type);
    }

    // Decode salt and nonce
    let salt = hex::decode(&keystore.salt).context("Invalid salt format")?;
    let nonce_bytes = hex::decode(&keystore.nonce).context("Invalid nonce format")?;
    // PBA-L4-009: `Nonce::from_slice` PANICS on a length other than 12; a
    // corrupted or hostile keystore must be an error, not a crash.
    if nonce_bytes.len() != 12 {
        anyhow::bail!(
            "Invalid keystore nonce length: {} bytes (expected 12)",
            nonce_bytes.len()
        );
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Derive key from password under the entry's declared KDF version.
    let encryption_key = match keystore.kdf_version {
        KDF_VERSION_ARGON2ID => derive_key_argon2id(password, &salt)?,
        KDF_VERSION_LEGACY_SHA3 => derive_key_legacy_sha3(password, &salt),
        unknown => anyhow::bail!(
            "Unknown kdf_version {} on keystore; expected 1 (legacy SHA3) or 2 (Argon2id)",
            unknown
        ),
    };

    // Decrypt the private key
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(encryption_key.as_ref()));
    let ciphertext =
        hex::decode(&keystore.encrypted_key).context("Invalid encrypted key format")?;

    let plaintext = Zeroizing::new(cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| {
        anyhow::anyhow!("Decryption failed - invalid password or corrupted keystore")
    })?);

    // Convert to ed25519 signing key
    let key_bytes: [u8; 32] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid key length"))?;

    Ok(SigningKey::from_bytes(&key_bytes))
}

/// Argon2id KDF (current). Memory-hard, OWASP 2024 parameters — matches
/// `wallet-core`'s `KDF_VERSION_CURRENT`. Returns the 32-byte AES key wrapped
/// in `Zeroizing` so it is wiped on drop (CHAIN-B-E001).
fn derive_key_argon2id(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(65536, 3, 1, Some(32))
        .map_err(|e| anyhow::anyhow!("Invalid Argon2 params: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| anyhow::anyhow!("Argon2id derivation failed: {}", e))?;
    Ok(key)
}

/// Legacy SHA3-256 KDF (read-only). SHA3-256(password‖salt) folded 10 000
/// times — NOT memory-hard. Retained only to decrypt pre-CHAIN-B-E001
/// keystores; never used for new writes.
fn derive_key_legacy_sha3(password: &str, salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    let mut hasher = Sha3_256::new();

    // Initial hash
    hasher.update(password.as_bytes());
    hasher.update(salt);
    let mut hash = hasher.finalize();

    // Apply 10000 iterations to strengthen the key derivation
    for _ in 0..10000 {
        let mut new_hasher = Sha3_256::new();
        new_hasher.update(hash);
        new_hasher.update(password.as_bytes());
        new_hasher.update(salt);
        hash = new_hasher.finalize();
    }

    key.copy_from_slice(&hash);
    key
}

#[cfg(test)]
mod tests_pba_l4_009 {
    use super::*;

    /// PBA-L4-009: a keystore whose nonce is not 12 bytes must fail cleanly
    /// (it used to panic inside `Nonce::from_slice`).
    #[test]
    fn pba_l4_009_bad_nonce_length_is_an_error_not_a_panic() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("ks.json");
        let key = SigningKey::from_bytes(&[3u8; 32]);
        save_key(&key, "correct horse battery", &path).expect("save");
        let raw = std::fs::read_to_string(&path).expect("read");
        let mut v: serde_json::Value = serde_json::from_str(&raw).expect("json");
        v["nonce"] = serde_json::Value::String(hex::encode([0u8; 11]));
        std::fs::write(&path, v.to_string()).expect("write");
        let r = std::panic::catch_unwind(|| load_key(&path, "correct horse battery"));
        let r = r.expect("load_key must not panic on an 11-byte nonce");
        assert!(r.is_err(), "an 11-byte nonce must be rejected");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn test_save_and_load_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.json");

        let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
        save_key(&signing_key, "password123", &path).expect("save");

        let loaded = load_key(&path, "password123").expect("load");
        assert_eq!(loaded.to_bytes(), signing_key.to_bytes());
    }

    #[test]
    fn test_wrong_password_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.json");

        let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
        save_key(&signing_key, "correct-horse", &path).expect("save");

        let result = load_key(&path, "wrong-horse");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_nonexistent_file_fails() {
        let result = load_key(Path::new("/tmp/nonexistent_keystore_citrate.json"), "pw");
        assert!(result.is_err());
    }

    #[test]
    fn test_keystore_stores_public_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.json");

        let signing_key = SigningKey::from_bytes(&[0x11u8; 32]);
        save_key(&signing_key, "password123", &path).expect("save");

        let contents = std::fs::read_to_string(&path).expect("read");
        let keystore: serde_json::Value = serde_json::from_str(&contents).expect("parse");
        assert_eq!(keystore["version"], 2);
        assert_eq!(keystore["key_type"], "ed25519");
        assert!(keystore["public_key"].is_string());

        let stored_pubkey = keystore["public_key"]
            .as_str()
            .expect("public_key is a string");
        let expected_pubkey = hex::encode(signing_key.verifying_key().to_bytes());
        assert_eq!(stored_pubkey, expected_pubkey);
    }

    /// CHAIN-B-E001: new keystores must be written with Argon2id (kdf_version 2),
    /// not the fast legacy SHA3 KDF.
    #[test]
    fn test_e001_new_keystore_uses_argon2id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("kdf.json");

        let signing_key = SigningKey::from_bytes(&[0x24u8; 32]);
        save_key(&signing_key, "password123", &path).expect("save");

        let contents = std::fs::read_to_string(&path).expect("read");
        let keystore: serde_json::Value = serde_json::from_str(&contents).expect("parse");
        assert_eq!(
            keystore["kdf_version"], 2,
            "new keystores must record kdf_version=2 (Argon2id)"
        );
    }

    /// CHAIN-B-E001: passwords below the minimum length are rejected on save.
    #[test]
    fn test_e001_rejects_short_password() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("short.json");

        let signing_key = SigningKey::from_bytes(&[0x55u8; 32]);
        // 1-char password (the value the auditor got a keystore out of) must fail.
        let result = save_key(&signing_key, "a", &path);
        assert!(result.is_err(), "1-char password must be rejected");
        assert!(
            !path.exists(),
            "no keystore should be written for a short password"
        );

        // A 7-char password is still below the 8-char floor.
        assert!(save_key(&signing_key, "short77", &path).is_err());
        // Exactly 8 chars is accepted.
        assert!(save_key(&signing_key, "eightchr", &path).is_ok());
    }

    /// CHAIN-B-E001: a legacy SHA3 keystore (kdf_version 1) must still open, so
    /// existing accounts are not locked out by the Argon2id migration.
    #[test]
    fn test_e001_legacy_sha3_keystore_still_loads() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("legacy.json");

        // Hand-build a v1 keystore with the legacy SHA3 KDF.
        let signing_key = SigningKey::from_bytes(&[0x77u8; 32]);
        let password = "legacy-password";
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        let enc_key = derive_key_legacy_sha3(password, &salt);

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(enc_key.as_ref()));
        let ciphertext = cipher
            .encrypt(nonce, signing_key.to_bytes().as_ref())
            .expect("encrypt");

        let legacy = serde_json::json!({
            "version": 2,
            "key_type": "ed25519",
            "encrypted_key": hex::encode(ciphertext),
            "salt": hex::encode(salt),
            "nonce": hex::encode(nonce_bytes),
            "public_key": hex::encode(signing_key.verifying_key().to_bytes()),
            "kdf_version": 1,
        });
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&legacy).expect("serialize legacy keystore"),
        )
        .expect("write");

        let loaded = load_key(&path, password).expect("legacy keystore must still load");
        assert_eq!(loaded.to_bytes(), signing_key.to_bytes());
    }

    /// CHAIN-B-E001: a keystore file that predates the `kdf_version` field
    /// (field absent) must be treated as legacy SHA3 and still open.
    #[test]
    fn test_e001_missing_kdf_version_defaults_to_legacy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nofield.json");

        let signing_key = SigningKey::from_bytes(&[0x33u8; 32]);
        let password = "legacy-password";
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        let enc_key = derive_key_legacy_sha3(password, &salt);

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(enc_key.as_ref()));
        let ciphertext = cipher
            .encrypt(nonce, signing_key.to_bytes().as_ref())
            .expect("encrypt");

        // No kdf_version key at all.
        let legacy = serde_json::json!({
            "version": 2,
            "key_type": "ed25519",
            "encrypted_key": hex::encode(ciphertext),
            "salt": hex::encode(salt),
            "nonce": hex::encode(nonce_bytes),
            "public_key": hex::encode(signing_key.verifying_key().to_bytes()),
        });
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&legacy).expect("serialize legacy keystore"),
        )
        .expect("write");

        let loaded = load_key(&path, password).expect("field-less keystore must load");
        assert_eq!(loaded.to_bytes(), signing_key.to_bytes());
    }

    /// CHAIN-B-E002: the saved keystore file must be 0600 (owner-only) on Unix.
    #[cfg(unix)]
    #[test]
    fn test_e002_keystore_file_mode_is_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("perms.json");

        let signing_key = SigningKey::from_bytes(&[0x99u8; 32]);
        save_key(&signing_key, "password123", &path).expect("save");

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "keystore file must be 0600, got {:o}",
            mode & 0o777
        );
    }
}
