use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Algorithm, Argon2, Params, Version,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::errors::WalletError;

// =========================================================================
// KDF version registry — mirrors citrate-wallet-core::keys
// See docs/security/KDF_POLICY.md (canonical) and audit finding WAL-01.
// =========================================================================

/// Legacy: pre-WAL-01 entries written with `Argon2::default()`.
const KDF_VERSION_LEGACY: u32 = 1;

/// Current production: OWASP 2024 recommended Argon2id parameters
/// (m=65536, t=3, p=4, output_len=32).
const KDF_VERSION_CURRENT: u32 = 2;

/// Default for entries on disk that lack the field.
fn default_kdf_version_legacy() -> u32 {
    KDF_VERSION_LEGACY
}

/// Construct the Argon2 instance for a given KDF version.
///
/// Mirrors `citrate_wallet_core::keys::argon2_for_version`. The two
/// keystore implementations are consolidated under sprint RM-G2; until
/// then, both must hold to the same KDF policy table.
fn argon2_for_version(version: u32) -> Result<Argon2<'static>, WalletError> {
    match version {
        KDF_VERSION_LEGACY => Ok(Argon2::default()),
        KDF_VERSION_CURRENT => {
            let params = Params::new(65536, 3, 4, Some(32))
                .expect("WAL-01: Argon2 v2 params (m=65536, t=3, p=4, out=32) are statically valid; see docs/security/KDF_POLICY.md");
            Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
        }
        unknown => Err(WalletError::Decryption(format!(
            "WAL-01: unknown kdf_version {} on keystore entry; expected 1 or 2 \
             (see docs/security/KDF_POLICY.md). Refusing to derive key.",
            unknown
        ))),
    }
}

/// Encrypted key storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKey {
    /// Encrypted private key
    pub ciphertext: Vec<u8>,
    /// Salt for key derivation
    pub salt: String,
    /// Nonce for AES-GCM
    pub nonce: Vec<u8>,
    /// Public key (not encrypted)
    pub public_key: Vec<u8>,
    /// Optional key alias
    pub alias: Option<String>,
    /// KDF parameter version. See `docs/security/KDF_POLICY.md`.
    /// Defaults to 1 (legacy) for entries on disk that lack the field.
    #[serde(default = "default_kdf_version_legacy")]
    pub kdf_version: u32,
}

/// Key store for managing encrypted keys
pub struct KeyStore {
    /// Path to keystore file
    path: PathBuf,
    /// Encrypted keys
    keys: Vec<EncryptedKey>,
    /// Decrypted keys (in memory when unlocked)
    unlocked: Vec<SigningKey>,
    /// Whether keystore is locked
    locked: bool,
}

impl KeyStore {
    /// Create new keystore at path
    pub fn new(path: impl AsRef<Path>) -> Result<Self, WalletError> {
        let path = path.as_ref().to_path_buf();

        // Load existing keys if file exists
        let keys = if path.exists() {
            let data = std::fs::read(&path)?;
            serde_json::from_slice(&data)?
        } else {
            Vec::new()
        };

        Ok(Self {
            path,
            keys,
            unlocked: Vec::new(),
            locked: true,
        })
    }

    /// Generate new key pair
    pub fn generate_key(
        &mut self,
        password: &str,
        alias: Option<String>,
    ) -> Result<VerifyingKey, WalletError> {
        // Generate new signing key
        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();

        // Encrypt and store
        let encrypted = self.encrypt_key(&signing_key, password)?;

        let mut encrypted_key = encrypted;
        encrypted_key.alias = alias;
        encrypted_key.public_key = verifying_key.to_bytes().to_vec();

        self.keys.push(encrypted_key);

        // Save to disk
        self.save()?;

        // Add to unlocked if keystore is unlocked
        if !self.locked {
            self.unlocked.push(signing_key);
        }

        Ok(verifying_key)
    }

    /// Import existing key
    pub fn import_key(
        &mut self,
        private_key_hex: &str,
        password: &str,
        alias: Option<String>,
    ) -> Result<VerifyingKey, WalletError> {
        let hex_str = private_key_hex.strip_prefix("0x")
            .or_else(|| private_key_hex.strip_prefix("0X"))
            .unwrap_or(private_key_hex);
        let private_bytes = hex::decode(hex_str)?;

        if private_bytes.len() != 32 {
            return Err(WalletError::Other("Invalid private key length".to_string()));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&private_bytes);

        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifying_key = signing_key.verifying_key();

        // Encrypt and store
        let mut encrypted = self.encrypt_key(&signing_key, password)?;
        encrypted.alias = alias;
        encrypted.public_key = verifying_key.to_bytes().to_vec();

        self.keys.push(encrypted);

        // Save to disk
        self.save()?;

        // Add to unlocked if keystore is unlocked
        if !self.locked {
            self.unlocked.push(signing_key);
        }

        Ok(verifying_key)
    }

    /// Unlock keystore with password
    pub fn unlock(&mut self, password: &str) -> Result<(), WalletError> {
        // Try to decrypt all keys
        let mut unlocked = Vec::new();

        for encrypted_key in &self.keys {
            let signing_key = self.decrypt_key(encrypted_key, password)?;
            unlocked.push(signing_key);
        }

        self.unlocked = unlocked;
        self.locked = false;

        Ok(())
    }

    /// Lock keystore
    pub fn lock(&mut self) {
        self.unlocked.clear();
        self.locked = true;
    }

    /// Get signing key by index
    pub fn get_signing_key(&self, index: usize) -> Result<&SigningKey, WalletError> {
        if self.locked {
            return Err(WalletError::WalletLocked);
        }

        self.unlocked
            .get(index)
            .ok_or_else(|| WalletError::AccountNotFound(format!("Index {}", index)))
    }

    /// Get signing key by public key
    pub fn get_signing_key_by_public(&self, public_key: &[u8]) -> Result<&SigningKey, WalletError> {
        if self.locked {
            return Err(WalletError::WalletLocked);
        }

        for (i, encrypted) in self.keys.iter().enumerate() {
            if encrypted.public_key == public_key {
                return self.get_signing_key(i);
            }
        }

        Err(WalletError::AccountNotFound(
            "Public key not found".to_string(),
        ))
    }

    /// List all accounts
    pub fn list_accounts(&self) -> Vec<(usize, Vec<u8>, Option<String>)> {
        self.keys
            .iter()
            .enumerate()
            .map(|(i, k)| (i, k.public_key.clone(), k.alias.clone()))
            .collect()
    }

    /// Encrypt a signing key
    ///
    /// Always writes with `KDF_VERSION_CURRENT` per
    /// `docs/security/KDF_POLICY.md`. Closes WAL-01.
    fn encrypt_key(
        &self,
        signing_key: &SigningKey,
        password: &str,
    ) -> Result<EncryptedKey, WalletError> {
        // Generate salt
        let salt = SaltString::generate(&mut OsRng);

        // Derive key from password using current KDF parameters.
        let argon2 = argon2_for_version(KDF_VERSION_CURRENT)?;
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| WalletError::Encryption(e.to_string()))?;

        // Get the hash bytes for AES key
        let hash_bytes = password_hash.hash
            .ok_or_else(|| WalletError::Encryption("argon2 hash output missing".to_string()))?;
        let key_bytes = hash_bytes.as_bytes();

        // Ensure we have exactly 32 bytes for AES-256
        let mut aes_key = [0u8; 32];
        aes_key.copy_from_slice(&key_bytes[..32]);

        // Create cipher
        let key = Key::<Aes256Gcm>::from_slice(&aes_key);
        let cipher = Aes256Gcm::new(key);

        // Generate nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt private key
        let plaintext = signing_key.to_bytes();
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| WalletError::Encryption(e.to_string()))?;

        Ok(EncryptedKey {
            ciphertext,
            salt: salt.to_string(),
            nonce: nonce_bytes.to_vec(),
            public_key: signing_key.verifying_key().to_bytes().to_vec(),
            alias: None,
            kdf_version: KDF_VERSION_CURRENT,
        })
    }

    /// Decrypt an encrypted key
    ///
    /// Selects the Argon2 parameter set from `encrypted.kdf_version` so
    /// legacy entries continue to unlock under their original parameters.
    fn decrypt_key(
        &self,
        encrypted: &EncryptedKey,
        password: &str,
    ) -> Result<SigningKey, WalletError> {
        // Parse salt
        let salt = SaltString::from_b64(&encrypted.salt)
            .map_err(|e| WalletError::Decryption(e.to_string()))?;

        // Derive key from password using the entry's declared KDF version.
        let argon2 = argon2_for_version(encrypted.kdf_version)?;
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| WalletError::Decryption(e.to_string()))?;

        // Get the hash bytes for AES key
        let hash_bytes = password_hash.hash
            .ok_or_else(|| WalletError::Decryption("argon2 hash output missing".to_string()))?;
        let key_bytes = hash_bytes.as_bytes();

        // Ensure we have exactly 32 bytes for AES-256
        let mut aes_key = [0u8; 32];
        aes_key.copy_from_slice(&key_bytes[..32]);

        // Create cipher
        let key = Key::<Aes256Gcm>::from_slice(&aes_key);
        let cipher = Aes256Gcm::new(key);

        // Decrypt
        let nonce = Nonce::from_slice(&encrypted.nonce);
        let plaintext = cipher
            .decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|_| WalletError::InvalidPassword)?;

        // Convert to signing key
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&plaintext);

        Ok(SigningKey::from_bytes(&key_bytes))
    }

    /// Save keystore to disk
    fn save(&self) -> Result<(), WalletError> {
        let data = serde_json::to_vec_pretty(&self.keys)?;
        std::fs::write(&self.path, data)?;
        // PT-08: Restrict keystore file to owner-only access (prevent other users from reading)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&self.path, perms)?;
        }
        Ok(())
    }

    /// Export private key (requires unlock)
    pub fn export_private_key(&self, index: usize) -> Result<String, WalletError> {
        if self.locked {
            return Err(WalletError::WalletLocked);
        }

        let signing_key = self.get_signing_key(index)?;
        Ok(hex::encode(signing_key.to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_keystore() -> (TempDir, KeyStore) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keystore.json");
        let ks = KeyStore::new(&path).unwrap();
        (dir, ks)
    }

    // ── Key Generation ──

    #[test]
    fn test_generate_key_returns_valid_verifying_key() {
        let (_dir, mut ks) = temp_keystore();
        let vk = ks.generate_key("password123", None).unwrap();
        // Ed25519 verifying key is 32 bytes
        assert_eq!(vk.to_bytes().len(), 32);
    }

    #[test]
    fn test_generate_key_produces_unique_keys() {
        let (_dir, mut ks) = temp_keystore();
        let vk1 = ks.generate_key("password123", None).unwrap();
        let vk2 = ks.generate_key("password123", None).unwrap();
        assert_ne!(vk1.to_bytes(), vk2.to_bytes());
    }

    #[test]
    fn test_generate_key_stores_alias() {
        let (_dir, mut ks) = temp_keystore();
        ks.generate_key("password123", Some("my-account".to_string()))
            .unwrap();
        let accounts = ks.list_accounts();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].2, Some("my-account".to_string()));
    }

    #[test]
    fn test_generate_key_increments_index() {
        let (_dir, mut ks) = temp_keystore();
        ks.generate_key("pw", None).unwrap();
        ks.generate_key("pw", None).unwrap();
        ks.generate_key("pw", None).unwrap();
        let accounts = ks.list_accounts();
        assert_eq!(accounts.len(), 3);
        assert_eq!(accounts[0].0, 0);
        assert_eq!(accounts[1].0, 1);
        assert_eq!(accounts[2].0, 2);
    }

    // ── Key Import ──

    #[test]
    fn test_import_key_with_0x_prefix() {
        let (_dir, mut ks) = temp_keystore();
        let secret = [42u8; 32];
        let hex_key = format!("0x{}", hex::encode(secret));
        let vk = ks.import_key(&hex_key, "pw", None).unwrap();
        let expected = SigningKey::from_bytes(&secret).verifying_key();
        assert_eq!(vk.to_bytes(), expected.to_bytes());
    }

    #[test]
    fn test_import_key_without_prefix() {
        let (_dir, mut ks) = temp_keystore();
        let secret = [42u8; 32];
        let hex_key = hex::encode(secret);
        let vk = ks.import_key(&hex_key, "pw", None).unwrap();
        let expected = SigningKey::from_bytes(&secret).verifying_key();
        assert_eq!(vk.to_bytes(), expected.to_bytes());
    }

    #[test]
    fn test_import_key_invalid_length_rejected() {
        let (_dir, mut ks) = temp_keystore();
        let err = ks.import_key("abcdef", "pw", None).unwrap_err();
        match err {
            WalletError::Other(msg) => assert!(msg.contains("Invalid private key length")),
            _ => panic!("Expected Other error, got {:?}", err),
        }
    }

    #[test]
    fn test_import_key_invalid_hex_rejected() {
        let (_dir, mut ks) = temp_keystore();
        let err = ks.import_key("not_hex_at_all_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "pw", None).unwrap_err();
        match err {
            WalletError::HexDecode(_) => {}
            _ => panic!("Expected HexDecode error, got {:?}", err),
        }
    }

    // ── Encryption / Decryption Round-trip ──

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (_dir, mut ks) = temp_keystore();
        let secret = [7u8; 32];
        let hex_key = hex::encode(secret);
        ks.import_key(&hex_key, "correct-password", None).unwrap();

        // Unlock with correct password should succeed
        ks.unlock("correct-password").unwrap();
        let recovered = ks.get_signing_key(0).unwrap();
        assert_eq!(recovered.to_bytes(), secret);
    }

    #[test]
    fn test_wrong_password_fails_unlock() {
        let (_dir, mut ks) = temp_keystore();
        ks.generate_key("correct-password", None).unwrap();
        let err = ks.unlock("wrong-password").unwrap_err();
        match err {
            WalletError::InvalidPassword => {}
            _ => panic!("Expected InvalidPassword, got {:?}", err),
        }
    }

    #[test]
    fn test_nonce_uniqueness_across_encryptions() {
        let (_dir, mut ks) = temp_keystore();
        ks.generate_key("pw", None).unwrap();
        ks.generate_key("pw", None).unwrap();
        // Each encryption should have a unique nonce
        assert_ne!(ks.keys[0].nonce, ks.keys[1].nonce);
    }

    // ── Lock / Unlock ──

    #[test]
    fn test_locked_keystore_rejects_get_signing_key() {
        let (_dir, mut ks) = temp_keystore();
        ks.generate_key("pw", None).unwrap();
        // Keystore starts locked
        let err = ks.get_signing_key(0).unwrap_err();
        match err {
            WalletError::WalletLocked => {}
            _ => panic!("Expected WalletLocked, got {:?}", err),
        }
    }

    #[test]
    fn test_unlock_then_lock_clears_keys() {
        let (_dir, mut ks) = temp_keystore();
        ks.generate_key("pw", None).unwrap();
        ks.unlock("pw").unwrap();
        assert!(ks.get_signing_key(0).is_ok());

        ks.lock();
        let err = ks.get_signing_key(0).unwrap_err();
        match err {
            WalletError::WalletLocked => {}
            _ => panic!("Expected WalletLocked after lock, got {:?}", err),
        }
    }

    #[test]
    fn test_unlock_decrypts_multiple_keys() {
        let (_dir, mut ks) = temp_keystore();
        let s1 = [1u8; 32];
        let s2 = [2u8; 32];
        ks.import_key(&hex::encode(s1), "pw", None).unwrap();
        ks.import_key(&hex::encode(s2), "pw", None).unwrap();

        ks.unlock("pw").unwrap();
        assert_eq!(ks.get_signing_key(0).unwrap().to_bytes(), s1);
        assert_eq!(ks.get_signing_key(1).unwrap().to_bytes(), s2);
    }

    // ── get_signing_key edge cases ──

    #[test]
    fn test_get_signing_key_out_of_bounds() {
        let (_dir, mut ks) = temp_keystore();
        ks.generate_key("pw", None).unwrap();
        ks.unlock("pw").unwrap();
        let err = ks.get_signing_key(99).unwrap_err();
        match err {
            WalletError::AccountNotFound(_) => {}
            _ => panic!("Expected AccountNotFound, got {:?}", err),
        }
    }

    #[test]
    fn test_get_signing_key_by_public() {
        let (_dir, mut ks) = temp_keystore();
        let vk = ks.generate_key("pw", None).unwrap();
        ks.unlock("pw").unwrap();

        let pk_bytes = vk.to_bytes();
        let signing_key = ks.get_signing_key_by_public(&pk_bytes).unwrap();
        assert_eq!(signing_key.verifying_key().to_bytes(), pk_bytes);
    }

    #[test]
    fn test_get_signing_key_by_unknown_public_key() {
        let (_dir, mut ks) = temp_keystore();
        ks.generate_key("pw", None).unwrap();
        ks.unlock("pw").unwrap();
        let err = ks.get_signing_key_by_public(&[0xFF; 32]).unwrap_err();
        match err {
            WalletError::AccountNotFound(_) => {}
            _ => panic!("Expected AccountNotFound, got {:?}", err),
        }
    }

    // ── Export ──

    #[test]
    fn test_export_private_key_matches_imported() {
        let (_dir, mut ks) = temp_keystore();
        let secret = [42u8; 32];
        ks.import_key(&hex::encode(secret), "pw", None).unwrap();
        ks.unlock("pw").unwrap();

        let exported = ks.export_private_key(0).unwrap();
        assert_eq!(exported, hex::encode(secret));
    }

    #[test]
    fn test_export_private_key_locked_fails() {
        let (_dir, mut ks) = temp_keystore();
        ks.generate_key("pw", None).unwrap();
        let err = ks.export_private_key(0).unwrap_err();
        match err {
            WalletError::WalletLocked => {}
            _ => panic!("Expected WalletLocked, got {:?}", err),
        }
    }

    // ── Persistence ──

    #[test]
    fn test_keystore_persistence_across_instances() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keystore.json");
        let secret = [55u8; 32];

        // Create and populate keystore
        {
            let mut ks = KeyStore::new(&path).unwrap();
            ks.import_key(&hex::encode(secret), "pw", Some("test-alias".to_string()))
                .unwrap();
        }

        // Reload from disk
        let mut ks2 = KeyStore::new(&path).unwrap();
        assert_eq!(ks2.list_accounts().len(), 1);
        assert_eq!(ks2.list_accounts()[0].2, Some("test-alias".to_string()));

        // Verify decryption still works after reload
        ks2.unlock("pw").unwrap();
        assert_eq!(ks2.get_signing_key(0).unwrap().to_bytes(), secret);
    }

    #[test]
    fn test_empty_keystore_creates_fresh() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nonexistent_keystore.json");
        let ks = KeyStore::new(&path).unwrap();
        assert_eq!(ks.list_accounts().len(), 0);
    }
}
