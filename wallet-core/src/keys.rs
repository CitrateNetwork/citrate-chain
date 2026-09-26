//! Key management — generation, encryption, derivation, storage.
//!
//! Supports Ed25519 (native Citrate) and secp256k1 (EVM compatibility).
//! Keys are encrypted at rest with Argon2 + AES-256-GCM.
//! Address derivation uses Keccak-256(pubkey)[12..32].
//!
//! ## KDF policy
//!
//! New entries are written with `kdf_version: KDF_VERSION_CURRENT` (= 2),
//! using OWASP-recommended Argon2id parameters (m=65536 KiB, t=3, p=1,
//! output_len=32). Legacy entries on disk (`kdf_version: 1`) continue to
//! decrypt under their original parameters via `argon2_for_version`. See
//! `docs/security/KDF_POLICY.md` (canonical) and audit finding `WAL-01`
//! (`.audit/2026-04-24-full-repo-adversarial-audit/08_FINDINGS_WALLET_AGENT_FAUCET.md`).
//!
//! Note (RM-I / WP-I2.3): the doc string above previously read `p=4`
//! while the production code at `argon2_for_version(KDF_VERSION_CURRENT)`
//! constructs with `p=1`. The 2026-04-25 re-audit caught the doc drift.
//! OWASP 2024 still meets its security floor at `p=1` with the current
//! `m=65536, t=3` settings, so the code is correct; the doc is now
//! aligned to the code. If a future revision raises `p` to 4 or 8, this
//! comment must be updated in lock-step.

use crate::error::WalletError;
use crate::types::KeyType;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

// Keystore-path imports (native-only): the on-disk `KeyManager` and its
// encrypt/decrypt helpers. The lean `crypto` build derives + signs keys
// but never persists them, so none of this is compiled there.
#[cfg(feature = "native")]
use crate::types::{CreateAccountResult, EncryptedKeyEntry};
#[cfg(feature = "native")]
use std::collections::HashMap;
#[cfg(feature = "native")]
use std::path::{Path, PathBuf};
#[cfg(feature = "native")]
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

// =========================================================================
// KDF version registry (native-only — used by the keystore encrypt path)
// =========================================================================

/// Legacy KDF version. Entries written before WAL-01 was closed used
/// `Argon2::default()` parameters. Accepted on read for backward
/// compatibility; never written by the current code.
#[cfg(feature = "native")]
pub const KDF_VERSION_LEGACY: u32 = 1;

/// Current production KDF version. OWASP 2024 recommended Argon2id
/// parameters: m=65536 KiB (64 MiB), t=3, p=1, output_len=32.
///
/// RM-I / WP-I2.3 doc-drift fix: this comment previously said `p=4`
/// but the dispatcher constructs with `p=1`. OWASP's 2024 cheat-sheet
/// lists `p=1` as acceptable at this `(m, t)` setting — the security
/// floor is met. Comment now matches code.
#[cfg(feature = "native")]
pub const KDF_VERSION_CURRENT: u32 = 2;

/// Low-memory KDF version (OWASP "alternative"). Reserved for the
/// browser extension and other constrained environments — not used by
/// `wallet-core` directly today. m=46336 KiB, t=1, p=1, output_len=32.
#[cfg(feature = "native")]
pub const KDF_VERSION_LOW_MEMORY: u32 = 3;

/// Construct the appropriate Argon2 instance for a given KDF version.
///
/// Returns an error for unknown versions so a corrupted on-disk entry
/// fails closed (legitimate `decrypt_key` will then surface a clear error
/// to the user instead of silently using the wrong parameters).
///
/// `pub(crate)` so the in-module mutation-test guard
/// (`kdf_dispatcher_tests::test_wal01_v2_dispatcher_returns_owasp_recommended_params`)
/// can pin the parameter set directly. Without that test, a regression
/// to `Ok(Argon2::default())` survives the round-trip suite — see
/// `tools/mutants/RESULTS_2026_04_24.md`.
#[cfg(feature = "native")]
pub(crate) fn argon2_for_version(version: u32) -> Result<argon2::Argon2<'static>, WalletError> {
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
    ///
    /// PBA-L4-011: returned in `Zeroizing` so the copy is wiped on drop
    /// (it used to be a plain `[u8; 32]` that lingered on the stack).
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        match self {
            UnifiedKey::Ed25519(key) => Zeroizing::new(key.to_bytes()),
            UnifiedKey::Secp256k1(key) => Zeroizing::new(key.to_bytes().into()),
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
///
/// Native-only: this is the on-disk keystore. It persists Argon2 +
/// AES-GCM encrypted entries to a `dirs`-derived path and depends on
/// `citrate_security::Aead`. The lean `crypto` build has no keystore —
/// consumers hold the seed elsewhere and call the stateless
/// `secp256k1_from_mnemonic`/`secp256k1_from_seed` primitives.
#[cfg(feature = "native")]
pub struct KeyManager {
    keystore_path: PathBuf,
    entries: Arc<RwLock<Vec<EncryptedKeyEntry>>>,
    unlocked_keys: Arc<RwLock<HashMap<String, UnifiedKey>>>, // address → decrypted key
}

#[cfg(feature = "native")]
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

        // WAL-04: Derive Ed25519 key from mnemonic seed (first 32 bytes of
        // 64-byte seed). Both `seed` and `secret` are wrapped so their
        // bytes are zeroed when the locals go out of scope. The
        // SigningKey itself zeroizes on drop via ed25519-dalek 2.x's
        // ZeroizeOnDrop derive.
        let seed: Zeroizing<Vec<u8>> = Zeroizing::new(mnemonic_obj.to_seed("").to_vec());
        let mut secret: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
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

        // WAL-04: imported private key bytes wrapped in Zeroizing so they
        // are erased when this scope exits. SigningKey itself zeroizes on
        // drop via ed25519-dalek 2.x's ZeroizeOnDrop derive.
        let key_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
            hex::decode(private_key_hex)
                .map_err(|e| WalletError::KeyGeneration(format!("Invalid hex: {}", e)))?,
        );

        if key_bytes.len() != 32 {
            return Err(WalletError::KeyGeneration(
                "Ed25519 private key must be 32 bytes".to_string(),
            ));
        }

        let mut secret: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
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

        // WAL-04: seed + derived secret bytes are zeroed on drop.
        let seed: Zeroizing<Vec<u8>> = Zeroizing::new(mnemonic_obj.to_seed("").to_vec());
        let mut secret: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
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
        // WAL-04: zeroize the secp256k1 secret bytes on drop. The k256
        // SigningKey itself zeroizes via the k256 crate's Drop impl, but
        // the intermediate `[u8; 32]` here is a fresh copy that needs
        // explicit erasure.
        let secret_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(signing_key.to_bytes().into());

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
                            let sk = k256::ecdsa::SigningKey::from_bytes((&*secret_bytes).into())
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
            // WAL-04: wrap so the secret is zeroed when the iteration
            // ends or on early-return via `?`.
            let secret_bytes: Zeroizing<[u8; 32]> = decrypt_key(entry, password)?;

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

        // WAL-04: hold the decrypted key in Zeroizing so the bytes are
        // erased after we encode them as hex. The hex String itself is
        // returned to the caller, who is documented as responsible for
        // wrapping it (Zeroizing<String>) and dropping promptly.
        let secret_bytes: Zeroizing<[u8; 32]> = decrypt_key(entry, password)?;
        Ok(hex::encode(secret_bytes.as_ref()))
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

// RM-G2.2 / WAL-10: `secp256k1_secret_from_seed` was deleted.
//
// The function deterministically mapped a BIP39 seed to a
// secp256k1 scalar (so a mnemonic could recover an EVM address).
// The audit flagged it as dead code — it had no callers in the
// workspace and no product-spec entry for "EVM mnemonic recovery".
// Re-introducing it would be feature work, not cleanup, and BIP32
// HD derivation is the correct path for that feature when it
// lands (so a seed maps to multiple addresses, not just one).
// Re-add via a proper sprint when EVM mnemonic recovery is on the
// roadmap.
//
// That sprint is `feat/wal-bip44-secp256k1-hd` (CORE-B1 / B1.1.0).
// The re-add below is the "proper" one the comment prescribed: full
// BIP32 → BIP44 HD derivation (a seed maps to many indexed keys, not
// one), delegated to the vetted iqlusion `bip32` crate on its
// pure-Rust k256 backend (no bespoke HMAC-SHA512 crypto). See
// `secp256k1_from_mnemonic` / `secp256k1_from_seed`.

// =========================================================================
// BIP44 secp256k1 HD derivation (B1.1.0 / feat/wal-bip44-secp256k1-hd).
//
// Standard flow: BIP39 mnemonic → 64-byte seed (empty passphrase) →
// BIP32 master → BIP44 path `m/44'/60'/0'/0/{index}` → k256 SigningKey.
//
// Coin type 60' is Ethereum/EVM (SLIP-44). Chain 40204 is EVM-compatible
// (`UnifiedKey::derive_address` = Keccak-256(uncompressed_pubkey[1..])
// [12..32]), so the standard MetaMask/Ledger BIP44 path applies and a
// mnemonic recovered elsewhere resolves to the same address here.
//
// These are STATELESS pure functions: they never touch `KeyManager`,
// the keystore, `save`, disk, or a session. citrate-core B1.1 (Option A)
// seals the seed in the A2 vault and needs only this primitive.
//
// Crypto is delegated to the iqlusion `bip32` crate (pure-Rust k256
// backend, no C-FFI / no native `secp256k1-sys`; WASM-compatible). We do
// NOT hand-roll the BIP32 HMAC-SHA512 child-key ladder. The named vector
// `abandon abandon ... about` → `m/44'/60'/0'/0/0` →
// `0x9858EfFD232B4033E47d90003D41EC34EcaEda94` is pinned in the tests.
// =========================================================================

/// The BIP44 derivation path prefix for Ethereum/EVM accounts
/// (`m/44'/60'/0'/0`). The final child index is appended per account.
/// Coin type 60' = Ethereum (SLIP-44); applies to EVM chain 40204.
const BIP44_EVM_PATH_PREFIX: &str = "m/44'/60'/0'/0";

/// Derive a BIP44 secp256k1 signing key from a 64-byte BIP39 seed.
///
/// Path: `m/44'/60'/0'/0/{account_index}`. Returns a
/// `UnifiedKey::Secp256k1` whose `derive_address()` is the standard EVM
/// address for that seed + index.
///
/// This is the seed→key helper (the mnemonic-agnostic core).
/// `secp256k1_from_mnemonic` is the mnemonic→seed→key convenience wrapper.
///
/// WAL-04: the caller owns the seed's lifetime; this function does not
/// copy it into any longer-lived buffer. The two SECRETS are erased: the
/// 64-byte seed is held in `Zeroizing` by the mnemonic wrapper, and the
/// returned leaf `SigningKey` zeroizes on drop via k256. NOTE: bip32 0.5.3
/// does NOT implement Zeroize/Drop on `ExtendedKeyAttrs`, so the XPrv's
/// chain code is left as stack residue (not zeroized) — low impact, since
/// the chain code is not the private scalar and the leaf key IS zeroized.
pub fn secp256k1_from_seed(
    seed: &[u8],
    account_index: u32,
) -> Result<UnifiedKey, WalletError> {
    use core::str::FromStr;

    let path_str = format!("{}/{}", BIP44_EVM_PATH_PREFIX, account_index);
    let path = bip32::DerivationPath::from_str(&path_str).map_err(|e| {
        WalletError::KeyGeneration(format!("BIP44: invalid derivation path {}: {}", path_str, e))
    })?;

    // XPrv::derive_from_path runs the BIP32 HMAC-SHA512 child-key ladder
    // over the seed. Fails closed on a bad seed length or an out-of-range
    // scalar (the crate re-derives on the astronomically-unlikely invalid
    // child; we surface any residual error rather than panic).
    let xprv = bip32::XPrv::derive_from_path(seed, &path).map_err(|e| {
        WalletError::KeyGeneration(format!(
            "BIP44: HD derivation failed for {}: {}",
            path_str, e
        ))
    })?;

    // For the k256 backend, `bip32::PrivateKey` IS `k256::ecdsa::SigningKey`.
    // Clone the leaf out of the extended key; the leaf `SigningKey` zeroizes
    // via k256. The XPrv chain code is dropped here but NOT zeroized (bip32
    // 0.5.3 lacks Zeroize on ExtendedKeyAttrs) — stack residue, low impact.
    let signing_key: k256::ecdsa::SigningKey = xprv.private_key().clone();
    Ok(UnifiedKey::Secp256k1(signing_key))
}

/// Derive a BIP44 secp256k1 signing key from a BIP39 mnemonic phrase.
///
/// Standard, mnemonic-recoverable EVM key: parses and checksum-validates
/// the mnemonic, converts it to a 64-byte seed with an EMPTY passphrase
/// (the MetaMask/standard default), then derives
/// `m/44'/60'/0'/0/{account_index}`.
///
/// Returns `UnifiedKey::Secp256k1(SigningKey)`. Use
/// `UnifiedKey::derive_address()` for the EVM address and
/// `chain::TransactionBuilder::sign_secp256k1` / `UnifiedKey::sign` to
/// sign — the derived key is a real EVM signer.
///
/// STATELESS: does not persist anything. Errors (never panics) on an
/// empty, short, or checksum-invalid mnemonic.
///
/// WAL-04: the 64-byte seed is held in a `Zeroizing` buffer and erased
/// when this function returns; the returned `SigningKey` zeroizes on drop.
pub fn secp256k1_from_mnemonic(
    mnemonic: &str,
    account_index: u32,
) -> Result<UnifiedKey, WalletError> {
    let mnemonic_obj = bip39::Mnemonic::parse(mnemonic.trim())
        .map_err(|e| WalletError::InvalidMnemonic(format!("{}", e)))?;

    // Empty-passphrase seed — the standard/MetaMask default that makes the
    // named vector reproduce. WAL-04: zeroize the seed on scope exit.
    let seed: Zeroizing<[u8; 64]> = Zeroizing::new(mnemonic_obj.to_seed(""));
    secp256k1_from_seed(seed.as_ref(), account_index)
}

/// Encrypt an Ed25519 signing key (convenience wrapper).
#[cfg(feature = "native")]
fn encrypt_key(
    signing_key: &Ed25519SigningKey,
    password: &str,
    address: &str,
    public_key_hex: &str,
    label: &str,
) -> Result<EncryptedKeyEntry, WalletError> {
    encrypt_key_raw(&signing_key.to_bytes(), password, address, public_key_hex, label, KeyType::Ed25519)
}

// =========================================================================
// WAL-02 — AES-GCM AAD canonical encoding.
//
// Every v2 (`KDF_VERSION_CURRENT`) keystore entry binds the following
// metadata as Associated Authenticated Data into the GCM tag:
//
//   AAD = b"citrate-keystore-v2"
//       || kdf_version (4 LE bytes)
//       || key_type    (1 byte: 0 = Ed25519, 1 = Secp256k1)
//       || address     (UTF-8 bytes, no length prefix — fixed by domain)
//
// An attacker who can swap the (ciphertext, salt, nonce) triple onto a
// different entry's `(address, key_type, kdf_version)` metadata will
// fail decryption: the GCM tag was computed over the original AAD and
// won't verify against the substituted metadata. Closes WAL-02 (HIGH).
//
// `kdf_version` is included even though the dispatcher already
// branches on it — including it in AAD prevents a downgrade attack
// where the field is rewritten from v2 to v1 to skip the AAD check.
//
// v1 (legacy) entries decrypt without AAD for backward compatibility.
// See `decrypt_key` for the version-dispatch.
// =========================================================================

#[cfg(feature = "native")]
const KEYSTORE_AAD_DOMAIN: &[u8] = b"citrate-keystore-v2";

#[cfg(feature = "native")]
fn keystore_v2_aad(kdf_version: u32, key_type: KeyType, address: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        KEYSTORE_AAD_DOMAIN.len() + 4 + 1 + address.len(),
    );
    aad.extend_from_slice(KEYSTORE_AAD_DOMAIN);
    aad.extend_from_slice(&kdf_version.to_le_bytes());
    aad.push(match key_type {
        KeyType::Ed25519 => 0u8,
        KeyType::Secp256k1 => 1u8,
    });
    aad.extend_from_slice(address.as_bytes());
    aad
}

/// Encrypt raw key bytes with Argon2 + AES-256-GCM.
///
/// New entries are always written with `KDF_VERSION_CURRENT` (= 2) per
/// `docs/security/KDF_POLICY.md`. WAL-01: KDF strength. WAL-02: AAD bind
/// (routed through `citrate_security::Aead`, the canonical AEAD
/// wrapper added in WP-A3.3).
#[cfg(feature = "native")]
fn encrypt_key_raw(
    secret_bytes: &[u8; 32],
    password: &str,
    address: &str,
    public_key_hex: &str,
    label: &str,
    key_type: KeyType,
) -> Result<EncryptedKeyEntry, WalletError> {
    let salt: [u8; 16] = rand::random();
    let nonce_bytes: [u8; 12] = rand::random();

    // WAL-04: derived_key is the AES-256 key; wrap so its bytes are zeroed
    // when the local goes out of scope. Aead::new copies the bytes into
    // its own state so we don't need the buffer to persist.
    let mut derived_key: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    let argon2 = argon2_for_version(KDF_VERSION_CURRENT)?;
    argon2
        .hash_password_into(password.as_bytes(), &salt, derived_key.as_mut())
        .map_err(|e| WalletError::Encryption(format!("Argon2 failed: {}", e)))?;

    let aead = citrate_security::Aead::new(&derived_key)
        .map_err(|e| WalletError::Encryption(format!("AEAD init failed: {}", e)))?;

    // WAL-02: bind metadata as AAD for v2 entries.
    let aad = keystore_v2_aad(KDF_VERSION_CURRENT, key_type, address);
    let ciphertext = aead
        .seal(&nonce_bytes, secret_bytes.as_ref(), &aad)
        .map_err(|e| WalletError::Encryption(format!("AEAD seal failed: {}", e)))?;

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
///
/// **WAL-02**: v2 entries require AAD verification. The AAD is computed
/// from `(kdf_version, key_type, address)` per `keystore_v2_aad`. A
/// substitution attack — swapping a `(ciphertext, salt, nonce)` triple
/// onto a different entry's metadata — fails the GCM tag check and
/// surfaces as `WalletError::InvalidPassword` to the caller. The legacy
/// v1 path decrypts without AAD for backward compatibility.
#[cfg(feature = "native")]
/// PBA-L4-011: the decrypted secret is returned in `Zeroizing`, so no caller
/// can hold it in a plain array that outlives its use.
fn decrypt_key(
    entry: &EncryptedKeyEntry,
    password: &str,
) -> Result<Zeroizing<[u8; 32]>, WalletError> {
    use base64::Engine;

    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&entry.ciphertext)
        .map_err(|e| WalletError::Decryption(format!("Invalid ciphertext base64: {}", e)))?;
    let salt = base64::engine::general_purpose::STANDARD
        .decode(&entry.salt)
        .map_err(|e| WalletError::Decryption(format!("Invalid salt base64: {}", e)))?;
    let nonce_bytes_vec = base64::engine::general_purpose::STANDARD
        .decode(&entry.nonce)
        .map_err(|e| WalletError::Decryption(format!("Invalid nonce base64: {}", e)))?;
    if nonce_bytes_vec.len() != 12 {
        return Err(WalletError::Decryption(format!(
            "Invalid nonce length: {} bytes, expected 12",
            nonce_bytes_vec.len()
        )));
    }
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&nonce_bytes_vec);

    // WAL-04: Derive key under the entry's declared KDF version. Wrap
    // in Zeroizing so the bytes are erased when this scope ends.
    let mut derived_key: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    let argon2 = argon2_for_version(entry.kdf_version)?;
    argon2
        .hash_password_into(password.as_bytes(), &salt, derived_key.as_mut())
        .map_err(|e| WalletError::Decryption(format!("Argon2 failed: {}", e)))?;

    // WAL-02: dispatch on kdf_version. v1 (legacy) entries decrypt
    // without AAD; v2+ entries enforce the AAD binding documented at
    // `keystore_v2_aad`. The v2+ path routes through the canonical
    // `citrate_security::Aead` wrapper (WP-A3.3); the v1 path uses
    // raw aes-gcm because legacy entries on disk were encrypted
    // without AAD and that contract is preserved for read.
    let plaintext_vec: Vec<u8> = match entry.kdf_version {
        KDF_VERSION_LEGACY => {
            // Legacy v1: no AAD. Use raw aes-gcm. This is the ONE
            // production call site of the raw API; the Semgrep rule
            // wal-02-aead-no-aad documents this exception.
            use aes_gcm::aead::Aead as RawAead;
            use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
            let cipher = Aes256Gcm::new_from_slice(derived_key.as_ref())
                .map_err(|e| WalletError::Decryption(format!("AES init failed: {}", e)))?;
            let nonce = Nonce::from_slice(&nonce_bytes);
            cipher
                .decrypt(nonce, ciphertext.as_ref())
                .map_err(|_| WalletError::InvalidPassword)?
        }
        KDF_VERSION_CURRENT | KDF_VERSION_LOW_MEMORY => {
            let aead = citrate_security::Aead::new(&derived_key)
                .map_err(|e| WalletError::Decryption(format!("AEAD init failed: {}", e)))?;
            let aad = keystore_v2_aad(entry.kdf_version, entry.key_type, &entry.address);
            aead.open(&nonce_bytes, &ciphertext, &aad)
                .map_err(|_| WalletError::InvalidPassword)?
        }
        _ => {
            return Err(WalletError::Decryption(format!(
                "WAL-02: unknown kdf_version {} on keystore entry; refusing to decrypt",
                entry.kdf_version
            )));
        }
    };
    let plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(plaintext_vec);

    if plaintext.len() != 32 {
        return Err(WalletError::Decryption(format!(
            "Decrypted key wrong size: {} bytes, expected 32",
            plaintext.len()
        )));
    }

    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(plaintext.as_slice());
    Ok(secret)
}

// The full keystore test suite exercises `KeyManager` (disk persistence,
// Argon2 + AES-GCM encrypt/decrypt) and `#[tokio::test]`, so it is
// native-only. The crypto-only BIP44/UnifiedKey vectors live in the
// separate `crypto_tests` module below, which compiles WITHOUT `native`.
#[cfg(all(test, feature = "native"))]
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
        assert_eq!(*retrieved.secret_bytes(), key.to_bytes());

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

        assert_eq!(signing_key.to_bytes(), *decrypted);
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
        assert_eq!(*unified.secret_bytes(), secret);
    }

    // ================================================================
    // B1.1.0 — BIP44 secp256k1 HD derivation (feat/wal-bip44-secp256k1-hd).
    //
    // Red-test-first (Rule 11): these assert the published named vector
    // and fail before `secp256k1_from_mnemonic` exists.
    // ================================================================

    /// The canonical MetaMask / standard-BIP44 test vector.
    const ABANDON_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon about";
    /// `abandon…about` at `m/44'/60'/0'/0/0`, EIP-55 checksummed.
    const ABANDON_ADDR_INDEX0_EIP55: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";

    #[test]
    fn test_b110_canonical_bip44_vector_index0() {
        // Named vector: the published MetaMask/standard address. Assert
        // exact EIP-55 checksum match (via address::to_eip55_checksum),
        // not just lowercase equality.
        let key = secp256k1_from_mnemonic(ABANDON_MNEMONIC, 0)
            .expect("canonical mnemonic must derive");
        assert_eq!(key.key_type(), KeyType::Secp256k1, "must be a secp256k1 key");

        let derived_lower = key.derive_address();
        let derived_eip55 = crate::address::to_eip55_checksum(&derived_lower);
        assert_eq!(
            derived_eip55, ABANDON_ADDR_INDEX0_EIP55,
            "m/44'/60'/0'/0/0 for the abandon…about mnemonic must be the published EVM address"
        );
    }

    #[test]
    fn test_b110_seed_helper_matches_mnemonic_wrapper() {
        // secp256k1_from_seed (the seed→key core) must agree with the
        // mnemonic wrapper for the same seed + index.
        let m = bip39::Mnemonic::parse(ABANDON_MNEMONIC).expect("parse");
        let seed = m.to_seed("");
        let via_seed = secp256k1_from_seed(&seed, 0).expect("seed derive");
        let via_mnemonic = secp256k1_from_mnemonic(ABANDON_MNEMONIC, 0).expect("mnemonic derive");
        assert_eq!(
            via_seed.derive_address(),
            via_mnemonic.derive_address(),
            "seed helper and mnemonic wrapper must derive the same key"
        );
        assert_eq!(
            crate::address::to_eip55_checksum(&via_seed.derive_address()),
            ABANDON_ADDR_INDEX0_EIP55
        );
    }

    #[test]
    fn test_b110_hd_distinct_index_and_determinism() {
        // HD, not single-key: a different index gives a different,
        // deterministic address; re-deriving index 0 reproduces the vector.
        let k0 = secp256k1_from_mnemonic(ABANDON_MNEMONIC, 0).expect("index 0");
        let k1 = secp256k1_from_mnemonic(ABANDON_MNEMONIC, 1).expect("index 1");
        let a0 = k0.derive_address();
        let a1 = k1.derive_address();
        assert_ne!(a0, a1, "index 0 and index 1 must derive distinct addresses (HD)");

        // Determinism: re-derive index 0 and index 1.
        let a0_again = secp256k1_from_mnemonic(ABANDON_MNEMONIC, 0)
            .expect("re-derive 0")
            .derive_address();
        let a1_again = secp256k1_from_mnemonic(ABANDON_MNEMONIC, 1)
            .expect("re-derive 1")
            .derive_address();
        assert_eq!(a0, a0_again, "index 0 must be deterministic");
        assert_eq!(a1, a1_again, "index 1 must be deterministic");
        assert_eq!(
            crate::address::to_eip55_checksum(&a0),
            ABANDON_ADDR_INDEX0_EIP55,
            "re-derived index 0 must reproduce the named vector"
        );
    }

    #[test]
    fn test_b110_ecrecover_roundtrip_proves_evm_signer() {
        // Round-trip: derive → sign a prehash → ecrecover to the derived
        // address. Proves the HD key is a real EVM signer, not just a
        // string that happens to match a vector.
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

        let key = secp256k1_from_mnemonic(ABANDON_MNEMONIC, 0).expect("derive");
        let signing_key = match &key {
            UnifiedKey::Secp256k1(sk) => sk.clone(),
            _ => panic!("expected secp256k1"),
        };
        let derived_addr = key.derive_address();

        // 32-byte message digest (stand-in for an EIP-155 signing hash).
        let msg_hash = Keccak256::digest(b"citrate B1.1.0 ecrecover round-trip");

        let (signature, recovery_id): (Signature, RecoveryId) = signing_key
            .sign_prehash(&msg_hash)
            .expect("prehash sign");

        // ecrecover the verifying key from (hash, sig, recovery_id).
        let recovered_vk =
            VerifyingKey::recover_from_prehash(&msg_hash, &signature, recovery_id)
                .expect("recover verifying key");

        // Address of the recovered key.
        let uncompressed = recovered_vk.to_encoded_point(false);
        let recovered_hash = Keccak256::digest(&uncompressed.as_bytes()[1..]);
        let recovered_addr = format!("0x{}", hex::encode(&recovered_hash[12..32]));

        assert_eq!(
            recovered_addr, derived_addr,
            "ecrecover(sig) must equal the derived EVM address — the key is a real EVM signer"
        );
    }

    #[test]
    fn test_b110_invalid_mnemonic_bad_checksum_errors_not_panic() {
        // 12 valid BIP39 words but a wrong final checksum word.
        let bad = "abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon abandon";
        // Map Ok → address string so `expect_err` only needs a Debug Ok
        // type (UnifiedKey deliberately isn't Debug — no key material in
        // debug output).
        let err = secp256k1_from_mnemonic(bad, 0)
            .map(|k| k.derive_address())
            .expect_err("bad checksum must error, not panic");
        assert!(
            matches!(err, WalletError::InvalidMnemonic(_)),
            "expected InvalidMnemonic, got {:?}",
            err
        );
    }

    #[test]
    fn test_b110_invalid_word_errors() {
        let bad = "zzzz abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon about";
        let err = secp256k1_from_mnemonic(bad, 0)
            .map(|k| k.derive_address())
            .expect_err("non-wordlist token must error");
        assert!(matches!(err, WalletError::InvalidMnemonic(_)));
    }

    #[test]
    fn test_b110_empty_and_short_mnemonic_rejected() {
        assert!(
            matches!(
                secp256k1_from_mnemonic("", 0),
                Err(WalletError::InvalidMnemonic(_))
            ),
            "empty mnemonic must be rejected"
        );
        assert!(
            matches!(
                secp256k1_from_mnemonic("abandon abandon about", 0),
                Err(WalletError::InvalidMnemonic(_))
            ),
            "short (non-standard-length) mnemonic must be rejected"
        );
    }
}

// =========================================================================
// WAL-01 mutation-killer: pin the dispatcher's parameter set in-module.
//
// The integration tests in `tests/wal01_kdf_strength.rs` cannot kill a
// mutation that replaces `argon2_for_version` with `Ok(Default::default())`
// because they construct `Argon2::new(...)` directly to compute the KAT
// — the dispatcher is bypassed. This module-internal test calls the
// dispatcher directly and inspects its `Params` accessors, so any
// mutation of the v2 arm is caught.
//
// See `tools/mutants/RESULTS_2026_04_24.md` for the campaign that
// surfaced this gap.
// =========================================================================

// KDF dispatcher tests pin the Argon2 parameter set — native-only, since
// `argon2_for_version` and the KDF version constants are native-gated.
#[cfg(all(test, feature = "native"))]
mod kdf_dispatcher_tests {
    use super::*;

    #[test]
    fn test_wal01_v2_dispatcher_returns_owasp_recommended_params() {
        let argon2 = argon2_for_version(KDF_VERSION_CURRENT)
            .expect("KDF_VERSION_CURRENT is a known version");
        let params = argon2.params();
        assert_eq!(
            params.m_cost(),
            65536,
            "WAL-01: dispatcher v2 m_cost must be 65536 KiB; got {}",
            params.m_cost()
        );
        assert_eq!(
            params.t_cost(),
            3,
            "WAL-01: dispatcher v2 t_cost must be 3; got {}",
            params.t_cost()
        );
        assert_eq!(
            params.p_cost(),
            1,
            "WAL-01: dispatcher v2 p_cost must be 1 (calibrated; see KDF_POLICY.md §3.5); got {}",
            params.p_cost()
        );
        assert_eq!(
            params.output_len(),
            Some(32),
            "WAL-01: dispatcher v2 output_len must be 32 bytes (AES-256); got {:?}",
            params.output_len()
        );
    }

    #[test]
    fn test_wal01_v2_dispatcher_differs_from_default() {
        // Mutation-killer: catches `Ok(Default::default())` in the v2 arm.
        let v2 = argon2_for_version(KDF_VERSION_CURRENT)
            .expect("v2 dispatcher succeeds");
        let default_argon2 = argon2::Argon2::default();
        assert_ne!(
            v2.params().m_cost(),
            default_argon2.params().m_cost(),
            "WAL-01: dispatcher v2 m_cost must NOT equal Argon2::default()'s m_cost. \
             A regression here means the dispatcher has been collapsed to defaults."
        );
    }

    #[test]
    fn test_wal01_legacy_dispatcher_matches_default() {
        // The KDF_VERSION_LEGACY arm IS supposed to return Argon2::default()
        // — pin that contract so the legacy unlock path keeps working.
        let v1 = argon2_for_version(KDF_VERSION_LEGACY)
            .expect("v1 dispatcher succeeds");
        let default_argon2 = argon2::Argon2::default();
        assert_eq!(v1.params().m_cost(), default_argon2.params().m_cost());
        assert_eq!(v1.params().t_cost(), default_argon2.params().t_cost());
        assert_eq!(v1.params().p_cost(), default_argon2.params().p_cost());
    }

    #[test]
    fn test_wal01_low_memory_dispatcher_returns_owasp_alternative_params() {
        let argon2 = argon2_for_version(KDF_VERSION_LOW_MEMORY)
            .expect("KDF_VERSION_LOW_MEMORY is a known version");
        let params = argon2.params();
        assert_eq!(params.m_cost(), 46336);
        assert_eq!(params.t_cost(), 1);
        assert_eq!(params.p_cost(), 1);
        assert_eq!(params.output_len(), Some(32));
    }

    #[test]
    fn test_wal01_unknown_kdf_version_rejected() {
        // Pinning the error path: an unknown version must NOT silently
        // fall back to defaults; it must error so the caller can surface
        // a clear "corrupt keystore" message.
        let result = argon2_for_version(999);
        assert!(
            result.is_err(),
            "WAL-01: unknown kdf_version must return Err, not silently default"
        );
        let err_msg = format!("{:?}", result.expect_err("expected Err"));
        assert!(
            err_msg.contains("unknown kdf_version") || err_msg.contains("999"),
            "Error message should reference the unknown version: {}",
            err_msg
        );
    }
}

// =========================================================================
// B1.1-F-1 — crypto-only smoke tests.
//
// These compile and run in the LEAN build (WITHOUT the `native` feature),
// proving the crown-jewel BIP44 derivation + signing path stands alone.
// They deliberately avoid `KeyManager`, the keystore, `dirs`, tokio, and
// any native-gated symbol. The `native` suite above already covers these
// same vectors; this module is what makes the guarantee testable in the
// crypto-only configuration a downstream (citrate-core) actually links.
//
// Run explicitly with:
//   cargo test -p citrate-wallet-core --no-default-features \
//       --features crypto crypto_only
// =========================================================================
#[cfg(test)]
mod crypto_only_smoke {
    use super::*;

    /// The canonical MetaMask / standard-BIP44 test vector.
    const ABANDON_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon about";
    /// `abandon…about` at `m/44'/60'/0'/0/0`, EIP-55 checksummed.
    const ABANDON_ADDR_INDEX0_EIP55: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";

    #[test]
    fn crypto_only_canonical_bip44_vector_index0() {
        // The whole point of B1.1-F-1: this must derive the published
        // MetaMask address WITHOUT the native/keystore stack compiled in.
        let key = secp256k1_from_mnemonic(ABANDON_MNEMONIC, 0)
            .expect("canonical mnemonic must derive in the lean build");
        assert_eq!(key.key_type(), KeyType::Secp256k1);

        let derived = crate::address::to_eip55_checksum(&key.derive_address());
        assert_eq!(
            derived, ABANDON_ADDR_INDEX0_EIP55,
            "lean crypto build must reproduce the named BIP44 vector"
        );
    }

    #[test]
    fn crypto_only_seed_helper_and_unified_sign() {
        // secp256k1_from_seed agrees with the mnemonic wrapper, and the
        // returned UnifiedKey signs (proves signing works lean).
        let seed = bip39::Mnemonic::parse(ABANDON_MNEMONIC)
            .expect("parse")
            .to_seed("");
        let key = secp256k1_from_seed(&seed, 0).expect("seed derive");
        assert_eq!(
            crate::address::to_eip55_checksum(&key.derive_address()),
            ABANDON_ADDR_INDEX0_EIP55
        );

        let sig = key.sign(b"citrate B1.1-F-1 lean signing");
        assert_eq!(sig.len(), 64, "secp256k1 ECDSA r||s is 64 bytes");
        assert!(!key.public_key_bytes().is_empty());
    }

    #[test]
    fn crypto_only_bip39_generate_and_parse() {
        // BIP39 gen/parse must be available lean (with zeroize enabled).
        let m = bip39::Mnemonic::generate(24).expect("generate 24-word mnemonic");
        assert_eq!(m.to_string().split_whitespace().count(), 24);
        let reparsed = bip39::Mnemonic::parse(m.to_string()).expect("re-parse");
        assert_eq!(reparsed.to_string(), m.to_string());
    }
}
