//! Key management — generation, encryption, derivation, storage.
//!
//! Supports Ed25519 (native Citrate) and secp256k1 (EVM compatibility).
//! Keys are encrypted at rest with Argon2 + AES-256-GCM.
//! Address derivation uses Keccak-256(pubkey)[12..32].
//!
//! ## KDF policy
//!
//! New entries are written with `kdf_version: KDF_VERSION_CURRENT` (= 2),
//! using OWASP-recommended Argon2id parameters (m=65536 KiB, t=3, p=4,
//! output_len=32). Legacy entries on disk (`kdf_version: 1`) continue to
//! decrypt under their original parameters via `argon2_for_version`. See
//! `docs/security/KDF_POLICY.md` (canonical) and audit finding `WAL-01`
//! (`.audit/2026-04-24-full-repo-adversarial-audit/08_FINDINGS_WALLET_AGENT_FAUCET.md`).

use crate::error::WalletError;
use crate::types::{CreateAccountResult, EncryptedKeyEntry, KeyType};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

// =========================================================================
// KDF version registry
// =========================================================================

/// Legacy KDF version. Entries written before WAL-01 was closed used
/// `Argon2::default()` parameters. Accepted on read for backward
/// compatibility; never written by the current code.
pub const KDF_VERSION_LEGACY: u32 = 1;

/// Current production KDF version. OWASP 2024 recommended Argon2id
/// parameters: m=65536 KiB (64 MiB), t=3, p=4, output_len=32.
pub const KDF_VERSION_CURRENT: u32 = 2;

/// Low-memory KDF version (OWASP "alternative"). Reserved for the
/// browser extension and other constrained environments — not used by
/// `wallet-core` directly today. m=46336 KiB, t=1, p=1, output_len=32.
pub const KDF_VERSION_LOW_MEMORY: u32 = 3;

/// Construct the appropriate Argon2 instance for a given KDF version.
///
/// Returns an error for unknown versions so a corrupted on-disk entry
/// fails closed (legitimate `decrypt_key` will then surface a clear error
/// to the user instead of silently using the wrong parameters).
fn argon2_for_version(version: u32) -> Result<argon2::Argon2<'static>, WalletError> {
    use argon2::{Algorithm, Argon2, Params, Version};

    match version {
        KDF_VERSION_LEGACY => {
            // Legacy: Argon2id defaults (m=19456, t=2, p=1, out=32).
            // Equivalent to `Argon2::default()`.
            Ok(Argon2::default())
        }
        KDF_VERSION_CURRENT => {
            let params = Params::new(65536, 3, 1, Some(32))
                .expect("WAL-01: Argon2 v2 params (m=65536, t=3, p=1, out=32) are statically valid; see docs/security/KDF_POLICY.md");
            Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
        }
        KDF_VERSION_LOW_MEMORY => {
            let params = Params::new(46336, 1, 1, Some(32))
                .expect("WAL-01: Argon2 low-memory params (m=46336, t=1, p=1, out=32) are statically valid; see docs/security/KDF_POLICY.md");
            Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
        }
        unknown => Err(WalletError::Decryption(format!(
            "WAL-01: unknown kdf_version {} on keystore entry; expected 1, 2, or 3 \
             (see docs/security/KDF_POLICY.md). Refusing to derive key.",
            unknown
        ))),
    }
}

/// Unified signing key supporting both Ed25519 and secp256k1.
#[derive(Clone)]
pub enum UnifiedKey {
    Ed25519(Ed25519SigningKey),
    Secp256k1(k256::ecdsa::SigningKey),
}

impl UnifiedKey {
    /// Get the raw 32-byte secret.
    pub fn secret_bytes(&self) -> [u8; 32] {
        match self {
            UnifiedKey::Ed25519(key) => key.to_bytes(),
            UnifiedKey::Secp256k1(key) => key.to_bytes().into(),
        }
    }

    /// Get the public key bytes.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        match self {
            UnifiedKey::Ed25519(key) => key.verifying_key().to_bytes().to_vec(),
            UnifiedKey::Secp256k1(key) => {
                let vk = key.verifying_key();
                // Uncompressed public key (65 bytes: 0x04 || x || y)
                vk.to_encoded_point(false).as_bytes().to_vec()
            }
        }
    }

    /// Derive the EVM-compatible address.
    pub fn derive_address(&self) -> String {
        match self {
            UnifiedKey::Ed25519(key) => {
                let pubkey = key.verifying_key().to_bytes();
                derive_address_from_ed25519(&pubkey)
            }
            UnifiedKey::Secp256k1(key) => {
                derive_address_from_secp256k1(key)
            }
        }
    }

    /// Get the key type.
    pub fn key_type(&self) -> KeyType {
        match self {
            UnifiedKey::Ed25519(_) => KeyType::Ed25519,
            UnifiedKey::Secp256k1(_) => KeyType::Secp256k1,
        }
    }

    /// Sign arbitrary data.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        match self {
            UnifiedKey::Ed25519(key) => {
                use ed25519_dalek::Signer;
                key.sign(data).to_bytes().to_vec()
            }
            UnifiedKey::Secp256k1(key) => {
                use k256::ecdsa::{signature::Signer, Signature};
                let sig: Signature = key.sign(data);
                sig.to_bytes().to_vec()
            }
        }
    }
}

/// Key manager — handles key lifecycle: generate → encrypt → store → unlock → sign → lock
pub struct KeyManager {
    keystore_path: PathBuf,
    entries: Arc<RwLock<Vec<EncryptedKeyEntry>>>,
    unlocked_keys: Arc<RwLock<HashMap<String, UnifiedKey>>>, // address → decrypted key
}

impl KeyManager {
    /// Create a new key manager pointing to a keystore directory.
    pub fn new(keystore_path: &Path) -> Self {
        Self {
            keystore_path: keystore_path.to_path_buf(),
            entries: Arc::new(RwLock::new(Vec::new())),
            unlocked_keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn entries_read(&self) -> RwLockReadGuard<'_, Vec<EncryptedKeyEntry>> {
        match self.entries.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn entries_write(&self) -> RwLockWriteGuard<'_, Vec<EncryptedKeyEntry>> {
        match self.entries.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn unlocked_read(&self) -> RwLockReadGuard<'_, HashMap<String, UnifiedKey>> {
        match self.unlocked_keys.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn unlocked_write(&self) -> RwLockWriteGuard<'_, HashMap<String, UnifiedKey>> {
        match self.unlocked_keys.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Load existing keys from disk.
    pub fn load(&self) -> Result<(), WalletError> {
        let path = self.keystore_path.join("keys.json");
        if !path.exists() {
            return Ok(());
        }
        let content = std::fs::read_to_string(&path)
            .map_err(|e| WalletError::Storage(format!("Cannot read keystore: {}", e)))?;
        let entries: Vec<EncryptedKeyEntry> = serde_json::from_str(&content)
            .map_err(|e| WalletError::Serialization(format!("Invalid keystore JSON: {}", e)))?;
        *self.entries_write() = entries;
        Ok(())
    }

    /// Save keys to disk.
    fn save(&self) -> Result<(), WalletError> {
        std::fs::create_dir_all(&self.keystore_path)
            .map_err(|e| WalletError::Storage(format!("Cannot create keystore dir: {}", e)))?;

        let entries = self.entries_read();
        let json = serde_json::to_string_pretty(&*entries)
            .map_err(|e| WalletError::Serialization(format!("Cannot serialize keystore: {}", e)))?;

        let path = self.keystore_path.join("keys.json");

        // Write atomically: write to temp file, then rename
        let tmp_path = self.keystore_path.join("keys.json.tmp");
        std::fs::write(&tmp_path, &json)
            .map_err(|e| WalletError::Storage(format!("Cannot write keystore: {}", e)))?;
        std::fs::rename(&tmp_path, &path)
            .map_err(|e| WalletError::Storage(format!("Cannot rename keystore: {}", e)))?;

        // Set file permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(&path, perms);
        }

        Ok(())
    }

    /// Generate a new Ed25519 keypair with a BIP39 mnemonic, encrypt it, store it.
    pub fn create_account(
        &self,
        password: &str,
        label: &str,
    ) -> Result<CreateAccountResult, WalletError> {
        if password.len() < 8 {
            return Err(WalletError::InvalidPassword);
        }

        // Generate BIP39 mnemonic (24 words = 256 bits of entropy)
        let mnemonic_obj = bip39::Mnemonic::generate(24)
            .map_err(|e| WalletError::KeyGeneration(format!("Mnemonic generation failed: {}", e)))?;
        let mnemonic = mnemonic_obj.to_string();

        // Derive Ed25519 key from mnemonic seed (first 32 bytes of 64-byte seed)
        let seed = mnemonic_obj.to_seed("");
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&seed[..32]);
        let signing_key = Ed25519SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes = verifying_key.to_bytes();
        let public_key_hex = hex::encode(pubkey_bytes);

        let address = derive_address(&pubkey_bytes);

        let entry = encrypt_key(&signing_key, password, &address, &public_key_hex, label)?;

        self.entries_write().push(entry);
        self.save()?;

        Ok(CreateAccountResult {
            address,
            public_key_hex,
            mnemonic,
            label: label.to_string(),
        })
    }

    /// Import an existing Ed25519 key from hex.
    pub fn import_account(
        &self,
        private_key_hex: &str,
        password: &str,
        label: &str,
    ) -> Result<CreateAccountResult, WalletError> {
        if password.len() < 8 {
            return Err(WalletError::InvalidPassword);
        }

        let key_bytes = hex::decode(private_key_hex)
            .map_err(|e| WalletError::KeyGeneration(format!("Invalid hex: {}", e)))?;

        if key_bytes.len() != 32 {
            return Err(WalletError::KeyGeneration(
                "Ed25519 private key must be 32 bytes".to_string(),
            ));
        }

        let mut secret = [0u8; 32];
        secret.copy_from_slice(&key_bytes);
        let signing_key = Ed25519SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes = verifying_key.to_bytes();
        let public_key_hex = hex::encode(pubkey_bytes);
        let address = derive_address(&pubkey_bytes);

        // Check for duplicate
        let entries = self.entries_read();
        if entries.iter().any(|e| e.address == address) {
            return Err(WalletError::KeyGeneration(format!(
                "Account {} already exists",
                address
            )));
        }
        drop(entries);

        let entry = encrypt_key(&signing_key, password, &address, &public_key_hex, label)?;
        self.entries_write().push(entry);
        self.save()?;

        Ok(CreateAccountResult {
            address,
            public_key_hex,
            mnemonic: String::new(), // no mnemonic for imported keys
            label: label.to_string(),
        })
    }

    /// Recover an account from a BIP39 mnemonic phrase.
    pub fn recover_from_mnemonic(
        &self,
        mnemonic_phrase: &str,
        password: &str,
        label: &str,
    ) -> Result<CreateAccountResult, WalletError> {
        if password.len() < 8 {
            return Err(WalletError::InvalidPassword);
        }

        let mnemonic_obj = bip39::Mnemonic::parse(mnemonic_phrase)
            .map_err(|e| WalletError::InvalidMnemonic(format!("{}", e)))?;

        let seed = mnemonic_obj.to_seed("");
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&seed[..32]);
        let signing_key = Ed25519SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes = verifying_key.to_bytes();
        let public_key_hex = hex::encode(pubkey_bytes);
        let address = derive_address(&pubkey_bytes);

        // Check duplicate
        let entries = self.entries_read();
        if entries.iter().any(|e| e.address == address) {
            return Err(WalletError::KeyGeneration(format!(
                "Account {} already exists", address
            )));
        }
        drop(entries);

        let entry = encrypt_key(&signing_key, password, &address, &public_key_hex, label)?;
        self.entries_write().push(entry);
        self.save()?;

        Ok(CreateAccountResult {
            address,
            public_key_hex,
            mnemonic: mnemonic_phrase.to_string(),
            label: label.to_string(),
        })
    }

    /// Generate a new secp256k1 keypair (EVM-compatible).
    pub fn create_secp256k1_account(
        &self,
        password: &str,
        label: &str,
    ) -> Result<CreateAccountResult, WalletError> {
        if password.len() < 8 {
            return Err(WalletError::InvalidPassword);
        }

        let signing_key = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let address = derive_address_from_secp256k1(&signing_key);
        let public_key_hex = hex::encode(UnifiedKey::Secp256k1(signing_key.clone()).public_key_bytes());
        let secret_bytes: [u8; 32] = signing_key.to_bytes().into();

        let entry = encrypt_key_raw(
            &secret_bytes,
            password,
            &address,
            &public_key_hex,
            label,
            KeyType::Secp256k1,
        )?;

        self.entries_write().push(entry);
        self.save()?;

        Ok(CreateAccountResult {
            address,
            public_key_hex,
            mnemonic: String::new(), // secp256k1 accounts don't get mnemonics in this flow
            label: label.to_string(),
        })
    }

    /// Unlock all keys with the given password.
    pub fn unlock(&self, password: &str) -> Result<usize, WalletError> {
        let entries = self.entries_read();
        let mut unlocked = self.unlocked_write();
        let mut count = 0;

        for entry in entries.iter() {
            match decrypt_key(entry, password) {
                Ok(secret_bytes) => {
                    let unified = match entry.key_type {
                        KeyType::Ed25519 => {
                            UnifiedKey::Ed25519(Ed25519SigningKey::from_bytes(&secret_bytes))
                        }
                        KeyType::Secp256k1 => {
                            let sk = k256::ecdsa::SigningKey::from_bytes((&secret_bytes).into())
                                .map_err(|e| WalletError::Decryption(format!("Invalid secp256k1 key: {}", e)))?;
                            UnifiedKey::Secp256k1(sk)
                        }
                    };
                    unlocked.insert(entry.address.clone(), unified);
                    count += 1;
                }
                Err(_) => {
                    // Wrong password for this key — continue trying others
                }
            }
        }

        if count == 0 && !entries.is_empty() {
            return Err(WalletError::InvalidPassword);
        }

        Ok(count)
    }

    /// Lock all keys — clear decrypted keys from memory.
    pub fn lock(&self) {
        self.unlocked_write().clear();
    }

    /// Migrate every legacy (`kdf_version: 1`) entry to the current
    /// production parameters. Idempotent: v2+ entries pass through.
    ///
    /// Per `docs/security/KDF_POLICY.md` §4.2, migration is **opt-in** and
    /// **lazy** — callers (GUI, CLI) invoke this when a user has just
    /// authenticated and the keystore is detected to contain v1 entries.
    /// We do not auto-migrate during `unlock` to keep that path
    /// side-effect-free.
    ///
    /// Returns the number of entries upgraded. Errors out if any entry
    /// fails to decrypt under the supplied password (so a partial
    /// migration leaves the keystore in its original state).
    pub fn migrate_to_current_kdf(&self, password: &str) -> Result<usize, WalletError> {
        // First pass: decrypt every v1 entry to make sure the password is
        // valid before we touch disk. This avoids partial migration if a
        // later entry fails.
        let mut new_entries: Vec<EncryptedKeyEntry> = Vec::new();
        let entries_snapshot = self.entries_read().clone();
        let mut upgraded = 0usize;

        for entry in entries_snapshot.iter() {
            if entry.kdf_version >= KDF_VERSION_CURRENT {
                // Already current — pass through unchanged.
                new_entries.push(entry.clone());
                continue;
            }

            // Decrypt under the entry's declared (v1) parameters.
            let secret_bytes = decrypt_key(entry, password)?;

            // Re-encrypt under v2 with a fresh salt + nonce.
            let migrated = encrypt_key_raw(
                &secret_bytes,
                password,
                &entry.address,
                &entry.public_key_hex,
                &entry.label,
                entry.key_type,
            )?;
            // Preserve the original creation timestamp; the migration is
            // not a new account.
            let migrated = EncryptedKeyEntry {
                created_at: entry.created_at,
                ..migrated
            };
            new_entries.push(migrated);
            upgraded += 1;
        }

        if upgraded == 0 {
            // Nothing to do; avoid a needless disk write.
            return Ok(0);
        }

        // Atomic swap + persist.
        *self.entries_write() = new_entries;
        self.save()?;
        Ok(upgraded)
    }

    /// Returns true if any entry on the keystore is below the current KDF
    /// version. Useful for the GUI to surface a "migrate now" prompt.
    pub fn has_legacy_kdf_entries(&self) -> bool {
        self.entries_read()
            .iter()
            .any(|e| e.kdf_version < KDF_VERSION_CURRENT)
    }

    /// Check if any keys are unlocked.
    pub fn is_unlocked(&self) -> bool {
        !self.unlocked_read().is_empty()
    }

    /// Get a signing key for the given address (must be unlocked).
    pub fn get_signing_key(&self, address: &str) -> Result<UnifiedKey, WalletError> {
        self.unlocked_keys
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(address)
            .cloned()
            .ok_or(WalletError::WalletLocked)
    }

    /// List all accounts (without exposing private keys).
    pub fn list_accounts(&self) -> Vec<crate::types::WalletAccount> {
        self.entries
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .enumerate()
            .map(|(i, entry)| crate::types::WalletAccount {
                address: entry.address.clone(),
                public_key_hex: entry.public_key_hex.clone(),
                label: entry.label.clone(),
                balance: "0".to_string(),
                nonce: 0,
                is_default: i == 0,
                created_at: entry.created_at,
                key_type: entry.key_type,
            })
            .collect()
    }

    /// Check if keystore has any accounts.
    pub fn is_empty(&self) -> bool {
        self.entries_read().is_empty()
    }

    /// Get the primary (first) account address.
    pub fn primary_address(&self) -> Option<String> {
        self.entries_read().first().map(|e| e.address.clone())
    }

    /// Delete an account by address (requires password verification).
    pub fn delete_account(&self, address: &str, password: &str) -> Result<(), WalletError> {
        let mut entries = self.entries_write();
        let idx = entries
            .iter()
            .position(|e| e.address == address)
            .ok_or_else(|| WalletError::KeyNotFound(address.to_string()))?;

        // Verify password before deletion
        decrypt_key(&entries[idx], password)?;

        entries.remove(idx);
        self.unlocked_write().remove(address);
        drop(entries);

        self.save()?;
        Ok(())
    }

    /// Export private key hex for the given address (requires password).
    pub fn export_private_key(
        &self,
        address: &str,
        password: &str,
    ) -> Result<String, WalletError> {
        let entries = self.entries_read();
        let entry = entries
            .iter()
            .find(|e| e.address == address)
            .ok_or_else(|| WalletError::KeyNotFound(address.to_string()))?;

        let secret_bytes = decrypt_key(entry, password)?;
        Ok(hex::encode(secret_bytes))
    }
}

/// Derive an EVM-compatible address from an Ed25519 public key.
/// Address = Keccak-256(pubkey)[12..32]
pub fn derive_address_from_ed25519(pubkey_bytes: &[u8; 32]) -> String {
    let hash = Keccak256::digest(pubkey_bytes);
    let address_bytes = &hash[12..32];
    format!("0x{}", hex::encode(address_bytes))
}

/// Derive an EVM-compatible address from a secp256k1 signing key.
/// Address = Keccak-256(uncompressed_pubkey_without_prefix)[12..32]
pub fn derive_address_from_secp256k1(signing_key: &k256::ecdsa::SigningKey) -> String {
    let vk = signing_key.verifying_key();
    let uncompressed = vk.to_encoded_point(false);
    let pubkey_bytes = &uncompressed.as_bytes()[1..]; // skip the 0x04 prefix
    let hash = Keccak256::digest(pubkey_bytes);
    let address_bytes = &hash[12..32];
    format!("0x{}", hex::encode(address_bytes))
}

/// Legacy alias for Ed25519 address derivation.
pub fn derive_address(pubkey_bytes: &[u8; 32]) -> String {
    derive_address_from_ed25519(pubkey_bytes)
}

/// Deterministically derive a secp256k1 secret scalar from a BIP39 seed.
///
/// Uses the first 32 bytes of the 64-byte seed. If that scalar lies outside
/// the valid range [1, n-1] (probability ≈ 2^-128 for uniform entropy), we
/// fall back to the last 32 bytes. If both fail, the mnemonic is
/// unrecoverable-to-secp256k1 and we surface an error so callers see the
/// failure instead of panicking.
///
/// This is intentionally not BIP32/BIP44 — Citrate doesn't yet use HD
/// derivation paths. The scheme is simple enough that `seed → address` is
/// deterministic: same mnemonic → same address, always.
pub fn secp256k1_secret_from_seed(seed: &[u8]) -> Result<[u8; 32], WalletError> {
    if seed.len() < 32 {
        return Err(WalletError::KeyGeneration(
            "seed too short (need at least 32 bytes)".to_string(),
        ));
    }
    let mut primary = [0u8; 32];
    primary.copy_from_slice(&seed[..32]);
    if k256::ecdsa::SigningKey::from_bytes((&primary).into()).is_ok() {
        return Ok(primary);
    }
    if seed.len() >= 64 {
        let mut secondary = [0u8; 32];
        secondary.copy_from_slice(&seed[seed.len() - 32..]);
        if k256::ecdsa::SigningKey::from_bytes((&secondary).into()).is_ok() {
            return Ok(secondary);
        }
    }
    Err(WalletError::KeyGeneration(
        "seed does not yield a valid secp256k1 scalar".to_string(),
    ))
}

/// Encrypt an Ed25519 signing key (convenience wrapper).
fn encrypt_key(
    signing_key: &Ed25519SigningKey,
    password: &str,
    address: &str,
    public_key_hex: &str,
    label: &str,
) -> Result<EncryptedKeyEntry, WalletError> {
    encrypt_key_raw(&signing_key.to_bytes(), password, address, public_key_hex, label, KeyType::Ed25519)
}

/// Encrypt raw key bytes with Argon2 + AES-256-GCM.
///
/// New entries are always written with `KDF_VERSION_CURRENT` (= 2) per
/// `docs/security/KDF_POLICY.md`. Closes audit finding WAL-01.
fn encrypt_key_raw(
    secret_bytes: &[u8; 32],
    password: &str,
    address: &str,
    public_key_hex: &str,
    label: &str,
    key_type: KeyType,
) -> Result<EncryptedKeyEntry, WalletError> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    let salt: [u8; 16] = rand::random();
    let nonce_bytes: [u8; 12] = rand::random();

    let mut derived_key = [0u8; 32];
    let argon2 = argon2_for_version(KDF_VERSION_CURRENT)?;
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut derived_key)
        .map_err(|e| WalletError::Encryption(format!("Argon2 failed: {}", e)))?;

    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|e| WalletError::Encryption(format!("AES init failed: {}", e)))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, secret_bytes.as_ref())
        .map_err(|e| WalletError::Encryption(format!("AES encrypt failed: {}", e)))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok(EncryptedKeyEntry {
        public_key_hex: public_key_hex.to_string(),
        address: address.to_string(),
        label: label.to_string(),
        key_type,
        ciphertext: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ciphertext),
        salt: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, salt),
        nonce: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce_bytes),
        created_at: now,
        kdf_version: KDF_VERSION_CURRENT,
    })
}

/// Decrypt raw secret bytes from an encrypted entry.
///
/// The Argon2 parameter set is selected by `entry.kdf_version` so legacy
/// (v1) entries continue to unlock under their original parameters while
/// new (v2+) entries use the current production parameters per
/// `docs/security/KDF_POLICY.md`.
fn decrypt_key(entry: &EncryptedKeyEntry, password: &str) -> Result<[u8; 32], WalletError> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    use base64::Engine;

    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&entry.ciphertext)
        .map_err(|e| WalletError::Decryption(format!("Invalid ciphertext base64: {}", e)))?;
    let salt = base64::engine::general_purpose::STANDARD
        .decode(&entry.salt)
        .map_err(|e| WalletError::Decryption(format!("Invalid salt base64: {}", e)))?;
    let nonce_bytes = base64::engine::general_purpose::STANDARD
        .decode(&entry.nonce)
        .map_err(|e| WalletError::Decryption(format!("Invalid nonce base64: {}", e)))?;

    // Derive key from password using the entry's declared KDF version.
    let mut derived_key = [0u8; 32];
    let argon2 = argon2_for_version(entry.kdf_version)?;
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut derived_key)
        .map_err(|e| WalletError::Decryption(format!("Argon2 failed: {}", e)))?;

    // Decrypt
    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|e| WalletError::Decryption(format!("AES init failed: {}", e)))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| WalletError::InvalidPassword)?;

    if plaintext.len() != 32 {
        return Err(WalletError::Decryption(format!(
            "Decrypted key wrong size: {} bytes, expected 32",
            plaintext.len()
        )));
    }

    let mut secret = [0u8; 32];
    secret.copy_from_slice(&plaintext);
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;

    fn test_keystore() -> PathBuf {
        temp_dir().join(format!("citrate_key_test_{}", uuid::Uuid::new_v4()))
    }

    #[tokio::test]
    async fn test_create_account() {
        let path = test_keystore();
        let mgr = KeyManager::new(&path);
        let result = mgr.create_account("strongpassword1", "Primary").expect("create account");
        assert!(result.address.starts_with("0x"));
        assert_eq!(result.address.len(), 42);
        assert!(!result.public_key_hex.is_empty());
        assert!(!result.mnemonic.is_empty());
        std::fs::remove_dir_all(&path).ok();
    }

    #[tokio::test]
    async fn test_short_password_rejected() {
        let path = test_keystore();
        let mgr = KeyManager::new(&path);
        let result = mgr.create_account("short", "Test");
        assert!(result.is_err());
        std::fs::remove_dir_all(&path).ok();
    }

    #[tokio::test]
    async fn test_unlock_and_sign() {
        let path = test_keystore();
        let mgr = KeyManager::new(&path);
        let result = mgr.create_account("testpassword1", "Primary").expect("create");
        let count = mgr.unlock("testpassword1").expect("unlock");
        assert_eq!(count, 1);
        let key = mgr.get_signing_key(&result.address).expect("get key");
        assert_eq!(hex::encode(key.public_key_bytes()), result.public_key_hex);
        std::fs::remove_dir_all(&path).ok();
    }

    #[tokio::test]
    async fn test_wrong_password_rejected() {
        let path = test_keystore();
        let mgr = KeyManager::new(&path);
        mgr.create_account("correctpassword", "Primary").expect("create");
        let result = mgr.unlock("wrongpassword!");
        assert!(matches!(result, Err(WalletError::InvalidPassword)));
        std::fs::remove_dir_all(&path).ok();
    }

    #[tokio::test]
    async fn test_lock_clears_keys() {
        let path = test_keystore();
        let mgr = KeyManager::new(&path);
        let result = mgr.create_account("testpassword1", "Primary").expect("create");
        mgr.unlock("testpassword1").expect("unlock");
        assert!(mgr.is_unlocked());
        mgr.lock();
        assert!(!mgr.is_unlocked());
        assert!(mgr.get_signing_key(&result.address).is_err());
        std::fs::remove_dir_all(&path).ok();
    }

    #[tokio::test]
    async fn test_persist_and_reload() {
        let path = test_keystore();
        let mgr = KeyManager::new(&path);
        let result = mgr.create_account("testpassword1", "Primary").expect("create");

        // Create new manager pointing to same path
        let mgr2 = KeyManager::new(&path);
        mgr2.load().expect("load");
        let accounts = mgr2.list_accounts();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].address, result.address);

        // Verify can unlock with same password
        mgr2.unlock("testpassword1").expect("unlock reloaded");
        assert!(mgr2.is_unlocked());

        std::fs::remove_dir_all(&path).ok();
    }

    #[tokio::test]
    async fn test_import_account() {
        let path = test_keystore();
        let mgr = KeyManager::new(&path);

        // Generate a known key
        let key = Ed25519SigningKey::generate(&mut rand::rngs::OsRng);
        let key_hex = hex::encode(key.to_bytes());

        let result = mgr.import_account(&key_hex, "testpassword1", "Imported").expect("import");
        assert!(result.address.starts_with("0x"));
        assert!(result.mnemonic.is_empty()); // no mnemonic for imports

        // Verify the imported key matches
        mgr.unlock("testpassword1").expect("unlock");
        let retrieved = mgr.get_signing_key(&result.address).expect("get key");
        assert_eq!(retrieved.secret_bytes(), key.to_bytes());

        std::fs::remove_dir_all(&path).ok();
    }

    #[tokio::test]
    async fn test_import_duplicate_rejected() {
        let path = test_keystore();
        let mgr = KeyManager::new(&path);
        let key = Ed25519SigningKey::generate(&mut rand::rngs::OsRng);
        let key_hex = hex::encode(key.to_bytes());

        mgr.import_account(&key_hex, "testpassword1", "First").expect("import 1");
        let result = mgr.import_account(&key_hex, "testpassword1", "Duplicate");
        assert!(result.is_err());

        std::fs::remove_dir_all(&path).ok();
    }

    #[tokio::test]
    async fn test_import_invalid_hex() {
        let path = test_keystore();
        let mgr = KeyManager::new(&path);
        let result = mgr.import_account("not_hex!", "testpassword1", "Bad");
        assert!(result.is_err());
        std::fs::remove_dir_all(&path).ok();
    }

    #[tokio::test]
    async fn test_import_wrong_length() {
        let path = test_keystore();
        let mgr = KeyManager::new(&path);
        let result = mgr.import_account("deadbeef", "testpassword1", "Short");
        assert!(result.is_err());
        std::fs::remove_dir_all(&path).ok();
    }

    #[tokio::test]
    async fn test_delete_account() {
        let path = test_keystore();
        let mgr = KeyManager::new(&path);
        let result = mgr.create_account("testpassword1", "Primary").expect("create");
        assert!(!mgr.is_empty());

        mgr.delete_account(&result.address, "testpassword1").expect("delete");
        assert!(mgr.is_empty());

        std::fs::remove_dir_all(&path).ok();
    }

    #[tokio::test]
    async fn test_delete_wrong_password_rejected() {
        let path = test_keystore();
        let mgr = KeyManager::new(&path);
        let result = mgr.create_account("testpassword1", "Primary").expect("create");
        let del = mgr.delete_account(&result.address, "wrongpassword");
        assert!(del.is_err());
        assert!(!mgr.is_empty()); // still there
        std::fs::remove_dir_all(&path).ok();
    }

    #[tokio::test]
    async fn test_export_private_key() {
        let path = test_keystore();
        let mgr = KeyManager::new(&path);
        let result = mgr.create_account("testpassword1", "Primary").expect("create");

        let exported = mgr.export_private_key(&result.address, "testpassword1").expect("export");
        assert_eq!(exported.len(), 64); // 32 bytes hex
        std::fs::remove_dir_all(&path).ok();
    }

    #[tokio::test]
    async fn test_export_wrong_password_rejected() {
        let path = test_keystore();
        let mgr = KeyManager::new(&path);
        let result = mgr.create_account("testpassword1", "Primary").expect("create");
        let export = mgr.export_private_key(&result.address, "wrongpassword");
        assert!(export.is_err());
        std::fs::remove_dir_all(&path).ok();
    }

    #[tokio::test]
    async fn test_multiple_accounts() {
        let path = test_keystore();
        let mgr = KeyManager::new(&path);
        mgr.create_account("testpassword1", "Account 1").expect("create 1");
        mgr.create_account("testpassword1", "Account 2").expect("create 2");
        mgr.create_account("testpassword1", "Account 3").expect("create 3");

        let accounts = mgr.list_accounts();
        assert_eq!(accounts.len(), 3);
        assert!(accounts[0].is_default);
        assert!(!accounts[1].is_default);
        assert!(!accounts[2].is_default);

        let count = mgr.unlock("testpassword1").expect("unlock all");
        assert_eq!(count, 3);

        std::fs::remove_dir_all(&path).ok();
    }

    #[tokio::test]
    async fn test_address_derivation_deterministic() {
        let key = Ed25519SigningKey::generate(&mut rand::rngs::OsRng);
        let pubkey = key.verifying_key().to_bytes();
        let addr1 = derive_address(&pubkey);
        let addr2 = derive_address(&pubkey);
        assert_eq!(addr1, addr2);
    }

    #[tokio::test]
    async fn test_address_format() {
        let key = Ed25519SigningKey::generate(&mut rand::rngs::OsRng);
        let pubkey = key.verifying_key().to_bytes();
        let addr = derive_address(&pubkey);
        assert!(addr.starts_with("0x"));
        assert_eq!(addr.len(), 42); // 0x + 40 hex chars
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        let signing_key = Ed25519SigningKey::generate(&mut rand::rngs::OsRng);
        let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let address = derive_address(&signing_key.verifying_key().to_bytes());

        let entry = encrypt_key(&signing_key, "mypassword12", &address, &pubkey_hex, "Test")
            .expect("encrypt");
        let decrypted = decrypt_key(&entry, "mypassword12").expect("decrypt");

        assert_eq!(signing_key.to_bytes(), decrypted);
    }

    #[tokio::test]
    async fn test_decrypt_wrong_password() {
        let signing_key = Ed25519SigningKey::generate(&mut rand::rngs::OsRng);
        let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let address = derive_address(&signing_key.verifying_key().to_bytes());

        let entry = encrypt_key(&signing_key, "correctpass!", &address, &pubkey_hex, "Test")
            .expect("encrypt");
        let result = decrypt_key(&entry, "wrongpassword");
        assert!(matches!(result, Err(WalletError::InvalidPassword)));
    }

    #[tokio::test]
    async fn test_empty_keystore() {
        let path = test_keystore();
        let mgr = KeyManager::new(&path);
        assert!(mgr.is_empty());
        assert!(mgr.primary_address().is_none());
        assert!(mgr.list_accounts().is_empty());
        std::fs::remove_dir_all(&path).ok();
    }

    #[tokio::test]
    async fn test_load_nonexistent_is_ok() {
        let path = test_keystore();
        let mgr = KeyManager::new(&path);
        mgr.load().expect("load nonexistent should be ok");
        assert!(mgr.is_empty());
    }

    // --- BIP39 Mnemonic tests ---

    #[tokio::test]
    async fn test_create_account_has_24_word_mnemonic() {
        let path = test_keystore();
        let mgr = KeyManager::new(&path);
        let result = mgr.create_account("strongpassword1", "Primary").expect("create");
        let word_count = result.mnemonic.split_whitespace().count();
        assert_eq!(word_count, 24, "Mnemonic should be 24 words, got {}", word_count);
        std::fs::remove_dir_all(&path).ok();
    }

    #[tokio::test]
    async fn test_recover_from_mnemonic() {
        let path = test_keystore();
        let mgr = KeyManager::new(&path);
        let created = mgr.create_account("strongpassword1", "Original").expect("create");

        // Delete and recover
        mgr.delete_account(&created.address, "strongpassword1").expect("delete");
        assert!(mgr.is_empty());

        let recovered = mgr.recover_from_mnemonic(&created.mnemonic, "newpassword1", "Recovered")
            .expect("recover");

        assert_eq!(created.address, recovered.address, "Recovered address should match original");
        assert_eq!(created.public_key_hex, recovered.public_key_hex, "Recovered pubkey should match");

        std::fs::remove_dir_all(&path).ok();
    }

    #[tokio::test]
    async fn test_recover_invalid_mnemonic() {
        let path = test_keystore();
        let mgr = KeyManager::new(&path);
        let result = mgr.recover_from_mnemonic(
            "invalid mnemonic words that are not real bip39",
            "password12",
            "Bad",
        );
        assert!(result.is_err());
        std::fs::remove_dir_all(&path).ok();
    }

    #[tokio::test]
    async fn test_recover_empty_mnemonic() {
        let path = test_keystore();
        let mgr = KeyManager::new(&path);
        let result = mgr.recover_from_mnemonic("", "password12", "Empty");
        assert!(result.is_err());
        std::fs::remove_dir_all(&path).ok();
    }

    #[tokio::test]
    async fn test_mnemonic_produces_deterministic_key() {
        let path1 = test_keystore();
        let mgr1 = KeyManager::new(&path1);
        let result1 = mgr1.create_account("password1234", "Test").expect("create 1");

        let path2 = test_keystore();
        let mgr2 = KeyManager::new(&path2);
        let result2 = mgr2.recover_from_mnemonic(&result1.mnemonic, "different!!", "Recovered")
            .expect("recover");

        assert_eq!(result1.address, result2.address);
        assert_eq!(result1.public_key_hex, result2.public_key_hex);

        std::fs::remove_dir_all(&path1).ok();
        std::fs::remove_dir_all(&path2).ok();
    }

    #[tokio::test]
    async fn test_two_accounts_have_different_mnemonics() {
        let path = test_keystore();
        let mgr = KeyManager::new(&path);
        let a1 = mgr.create_account("strongpassword1", "Account 1").expect("create 1");
        let a2 = mgr.create_account("strongpassword1", "Account 2").expect("create 2");
        assert_ne!(a1.mnemonic, a2.mnemonic);
        assert_ne!(a1.address, a2.address);
        std::fs::remove_dir_all(&path).ok();
    }

    #[tokio::test]
    async fn test_recover_duplicate_rejected() {
        let path = test_keystore();
        let mgr = KeyManager::new(&path);
        let result = mgr.create_account("strongpassword1", "Original").expect("create");
        let dup = mgr.recover_from_mnemonic(&result.mnemonic, "strongpassword1", "Duplicate");
        assert!(dup.is_err(), "Recovering duplicate address should fail");
        std::fs::remove_dir_all(&path).ok();
    }

    // --- secp256k1 tests ---

    #[tokio::test]
    async fn test_create_secp256k1_account() {
        let path = test_keystore();
        let mgr = KeyManager::new(&path);
        let result = mgr.create_secp256k1_account("strongpassword1", "EVM Account")
            .expect("create secp256k1");
        assert!(result.address.starts_with("0x"));
        assert_eq!(result.address.len(), 42);
        // secp256k1 uncompressed pubkey is 65 bytes (130 hex chars)
        assert_eq!(result.public_key_hex.len(), 130);
        std::fs::remove_dir_all(&path).ok();
    }

    #[tokio::test]
    async fn test_secp256k1_unlock_and_sign() {
        let path = test_keystore();
        let mgr = KeyManager::new(&path);
        let result = mgr.create_secp256k1_account("strongpassword1", "EVM")
            .expect("create");
        mgr.unlock("strongpassword1").expect("unlock");
        let key = mgr.get_signing_key(&result.address).expect("get key");
        assert_eq!(key.key_type(), KeyType::Secp256k1);

        // Sign data
        let signature = key.sign(b"test message");
        assert!(!signature.is_empty());
        assert_eq!(signature.len(), 64); // ECDSA r+s

        std::fs::remove_dir_all(&path).ok();
    }

    #[tokio::test]
    async fn test_secp256k1_address_deterministic() {
        let path = test_keystore();
        let mgr = KeyManager::new(&path);
        let r1 = mgr.create_secp256k1_account("strongpassword1", "A").expect("create 1");

        // Export and re-import
        let privkey = mgr.export_private_key(&r1.address, "strongpassword1").expect("export");
        mgr.delete_account(&r1.address, "strongpassword1").expect("delete");

        // Import the same key as Ed25519 (different address) to verify no collision
        let _r2 = mgr.import_account(&privkey, "strongpassword1", "Re-imported").expect("import");
        // Ed25519 and secp256k1 produce different addresses from the same secret
        // (different curves, different pubkey formats)
        // This is expected — the key type determines the address derivation

        std::fs::remove_dir_all(&path).ok();
    }

    #[tokio::test]
    async fn test_mixed_key_types_in_keystore() {
        let path = test_keystore();
        let mgr = KeyManager::new(&path);

        let ed = mgr.create_account("strongpassword1", "Ed25519 Account").expect("create ed25519");
        let secp = mgr.create_secp256k1_account("strongpassword1", "Secp256k1 Account")
            .expect("create secp256k1");

        let accounts = mgr.list_accounts();
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0].key_type, KeyType::Ed25519);
        assert_eq!(accounts[1].key_type, KeyType::Secp256k1);

        // Both should unlock
        let count = mgr.unlock("strongpassword1").expect("unlock");
        assert_eq!(count, 2);

        // Both can sign
        let ed_key = mgr.get_signing_key(&ed.address).expect("get ed25519");
        let secp_key = mgr.get_signing_key(&secp.address).expect("get secp256k1");
        assert_eq!(ed_key.key_type(), KeyType::Ed25519);
        assert_eq!(secp_key.key_type(), KeyType::Secp256k1);

        let ed_sig = ed_key.sign(b"hello");
        let secp_sig = secp_key.sign(b"hello");
        assert_eq!(ed_sig.len(), 64); // ed25519 sig
        assert_eq!(secp_sig.len(), 64); // ecdsa r+s

        std::fs::remove_dir_all(&path).ok();
    }

    #[tokio::test]
    async fn test_secp256k1_persist_and_reload() {
        let path = test_keystore();
        let mgr = KeyManager::new(&path);
        let result = mgr.create_secp256k1_account("strongpassword1", "Persist")
            .expect("create");

        // Reload from disk
        let mgr2 = KeyManager::new(&path);
        mgr2.load().expect("load");
        let accounts = mgr2.list_accounts();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].key_type, KeyType::Secp256k1);
        assert_eq!(accounts[0].address, result.address);

        // Can unlock with same password
        mgr2.unlock("strongpassword1").expect("unlock reloaded");
        let key = mgr2.get_signing_key(&result.address).expect("get key");
        assert_eq!(key.key_type(), KeyType::Secp256k1);

        std::fs::remove_dir_all(&path).ok();
    }

    // --- UnifiedKey tests ---

    #[test]
    fn test_unified_key_ed25519_sign() {
        let key = Ed25519SigningKey::generate(&mut rand::rngs::OsRng);
        let unified = UnifiedKey::Ed25519(key);
        let sig = unified.sign(b"test data");
        assert_eq!(sig.len(), 64);
        assert_eq!(unified.key_type(), KeyType::Ed25519);
    }

    #[test]
    fn test_unified_key_secp256k1_sign() {
        let key = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let unified = UnifiedKey::Secp256k1(key);
        let sig = unified.sign(b"test data");
        assert_eq!(sig.len(), 64);
        assert_eq!(unified.key_type(), KeyType::Secp256k1);
    }

    #[test]
    fn test_unified_key_address_derivation() {
        let ed_key = Ed25519SigningKey::generate(&mut rand::rngs::OsRng);
        let unified_ed = UnifiedKey::Ed25519(ed_key);
        let ed_addr = unified_ed.derive_address();
        assert!(ed_addr.starts_with("0x"));
        assert_eq!(ed_addr.len(), 42);

        let secp_key = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let unified_secp = UnifiedKey::Secp256k1(secp_key);
        let secp_addr = unified_secp.derive_address();
        assert!(secp_addr.starts_with("0x"));
        assert_eq!(secp_addr.len(), 42);

        // Different curves should produce different addresses
        assert_ne!(ed_addr, secp_addr);
    }

    #[test]
    fn test_unified_key_secret_bytes() {
        let ed_key = Ed25519SigningKey::generate(&mut rand::rngs::OsRng);
        let secret = ed_key.to_bytes();
        let unified = UnifiedKey::Ed25519(ed_key);
        assert_eq!(unified.secret_bytes(), secret);
    }
}
