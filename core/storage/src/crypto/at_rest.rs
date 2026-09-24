// SPDX-License-Identifier: Apache-2.0
// Encryption at rest for the RocksDB access layer (STOR-EAR, 2026-07-04).
//
// This module is the engine behind `RocksDB::open_encrypted`. Design:
//
// - VALUES ONLY are encrypted; record keys stay plaintext so iteration,
//   prefix scans and the height/metadata indexes keep working unchanged.
//   Key material in this schema (block hashes, tx hashes, addresses,
//   heights) is public chain data — the sensitive payloads are the values
//   (account state, contract storage, code, model weights, tx bodies).
// - AES-256-GCM per value with a per-column-family subkey derived from a
//   single 32-byte master key via BLAKE3 `derive_key` (same pattern as
//   citrate-comms `EncryptedStore`).
// - AAD binds each ciphertext to (column family, record key): an encrypted
//   value cannot be replayed under a different key or moved to another CF
//   without failing AEAD authentication.
// - `encryption.meta` in the data dir persists the format version, KDF
//   parameters + salt (for password-derived keys) and a key commitment, so
//   the same key material decrypts across restarts and a wrong key is
//   rejected at open time with an explicit error.
// - No migration path: opening an existing plaintext DB with encryption
//   enabled (or an encrypted DB without) fails with an error telling the
//   operator to wipe-and-resync. See `RocksDB::open`/`open_encrypted`.
//
// Nonce bound: nonces are 96-bit random (thread-local CSPRNG, OS-seeded).
// NIST SP 800-38D limits
// random-nonce AES-GCM to 2^32 encryptions per key; per-CF subkeys
// partition writes across 20+ keys, keeping each far below the bound for
// the desktop-node workload this mode targets. Key rotation (wipe-and-
// resync with a new key) resets the count.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroizing;

use super::QSSP_MAGIC;
use crate::db::column_families::all_column_families;

/// Version byte for the compact at-rest value format. Version 1 is the
/// full `EncryptionEnvelope` header format (see `envelope.rs`); version 2
/// is this module's compact format: magic(4) | version(1) | algorithm(1) |
/// nonce(12) | ciphertext+tag.
pub const AT_REST_VALUE_VERSION: u8 = 2;

/// Algorithm byte: AES-256-GCM (crypto-agility seam — a future algorithm
/// bumps this byte without re-encrypting existing data).
pub const AT_REST_ALG_AES_256_GCM: u8 = 0x01;

/// Fixed prefix length before the ciphertext: magic + version + algorithm + nonce.
const VALUE_PREFIX_LEN: usize = 4 + 1 + 1 + 12;
/// AES-GCM authentication tag length.
const TAG_LEN: usize = 16;
/// Minimum length of a well-formed sealed value (empty plaintext).
const MIN_SEALED_LEN: usize = VALUE_PREFIX_LEN + TAG_LEN;

/// Name of the metadata file persisted next to the RocksDB files.
pub const ENCRYPTION_META_FILE: &str = "encryption.meta";

/// BLAKE3 derive_key context prefix for per-column-family subkeys.
const CF_KEY_CONTEXT_PREFIX: &str = "citrate-storage/at-rest/v1/cf/";
/// BLAKE3 derive_key context for the key commitment stored in encryption.meta.
const COMMITMENT_CONTEXT: &str = "citrate-storage/at-rest/v1/key-commitment";

/// Errors from the encryption-at-rest layer.
#[derive(Debug, thiserror::Error)]
pub enum AtRestError {
    #[error(
        "encryption key does not match this database (key commitment mismatch in \
         encryption.meta). If the key or password is lost the data cannot be recovered — \
         wipe the data directory and resync"
    )]
    WrongKey,

    #[error(
        "data directory '{0}' contains an existing UNENCRYPTED database but encryption is \
         enabled. In-place migration is not supported — wipe the data directory and resync \
         with encryption enabled"
    )]
    PlaintextDbWithEncryptionEnabled(String),

    #[error(
        "data directory '{0}' contains an ENCRYPTED database ({ENCRYPTION_META_FILE} present) \
         but encryption is not enabled. Open it with the original key, or wipe the data \
         directory and resync unencrypted"
    )]
    EncryptedDbWithoutEncryption(String),

    #[error(
        "data directory '{0}' contains values in the encrypted format but \
         {ENCRYPTION_META_FILE} is missing. Restore the metadata file, or wipe the data \
         directory and resync"
    )]
    EncryptedValuesWithoutMeta(String),

    #[error(
        "stored value in column family '{0}' is not in the encrypted format — the database \
         appears to contain plaintext data. Wipe the data directory and resync with \
         encryption enabled"
    )]
    NotEncrypted(String),

    #[error(
        "failed to decrypt value in column family '{0}': AEAD authentication failed \
         (corrupted data or wrong key)"
    )]
    DecryptFailed(String),

    #[error("encryption failed for column family '{0}'")]
    EncryptFailed(String),

    #[error("unsupported encrypted value format (version {0}, algorithm {1})")]
    UnsupportedFormat(u8, u8),

    #[error("{ENCRYPTION_META_FILE} is invalid: {0}")]
    InvalidMeta(String),

    #[error("{ENCRYPTION_META_FILE} I/O error: {0}")]
    MetaIo(String),

    #[error("password key derivation failed: {0}")]
    KdfFailed(String),
}

/// 32-byte master key material for encryption at rest.
///
/// Deliberately key-source-agnostic: the desktop GUI supplies the bytes
/// (typically loaded from the OS keyring app-side — keyring integration
/// does NOT live in core/storage) or derives them from a password via
/// [`EncryptionKey::derive_from_password`]. Zeroized on drop.
#[derive(Clone)]
pub struct EncryptionKey(Zeroizing<[u8; 32]>);

impl EncryptionKey {
    /// Wrap caller-supplied 32-byte key material (e.g. from the OS keyring).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Generate a fresh random key (OsRng). Intended for first-run flows
    /// that store the key in an OS keyring app-side.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(Zeroizing::new(bytes))
    }

    /// Derive the master key from a password with Argon2id (RFC 9106)
    /// using persisted parameters + salt from `encryption.meta`.
    ///
    /// Data source: pure KDF over `password` and `kdf` (salt + cost params).
    pub fn derive_from_password(password: &[u8], kdf: &PasswordKdf) -> Result<Self, AtRestError> {
        use argon2::{Algorithm, Argon2, Params, Version};

        if password.is_empty() {
            return Err(AtRestError::KdfFailed("password must not be empty".into()));
        }

        let salt = hex::decode(&kdf.salt)
            .map_err(|e| AtRestError::KdfFailed(format!("invalid salt hex: {e}")))?;

        let params = Params::new(kdf.m_cost_kib, kdf.t_cost, kdf.p_cost, Some(32))
            .map_err(|e| AtRestError::KdfFailed(format!("invalid Argon2 parameters: {e}")))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key = Zeroizing::new([0u8; 32]);
        argon2
            .hash_password_into(password, &salt, key.as_mut())
            .map_err(|e| AtRestError::KdfFailed(e.to_string()))?;

        Ok(Self(key))
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Commitment over the key material — stored in `encryption.meta` and
    /// checked at open time so a wrong key fails fast with [`AtRestError::WrongKey`]
    /// instead of garbled reads. One-way (BLAKE3 KDF), does not reveal the key;
    /// testing a password guess against it costs a full Argon2id derivation.
    pub fn commitment(&self) -> [u8; 32] {
        blake3::derive_key(COMMITMENT_CONTEXT, self.as_bytes())
    }
}

impl std::fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("EncryptionKey").field(&"[REDACTED]").finish()
    }
}

/// Argon2id parameters + salt persisted in `encryption.meta` so the same
/// password re-derives the same key across restarts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordKdf {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Iterations.
    pub t_cost: u32,
    /// Parallelism lanes.
    pub p_cost: u32,
    /// Hex-encoded random salt (32 bytes).
    pub salt: String,
}

impl PasswordKdf {
    /// Generate parameters with a fresh random 32-byte salt.
    /// Defaults: 64 MiB, t=3, p=4 (OWASP-recommended interactive profile).
    pub fn generate() -> Self {
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        Self {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 4,
            salt: hex::encode(salt),
        }
    }
}

/// Where the master key comes from.
#[derive(Clone)]
pub enum KeySource {
    /// Caller-supplied 32-byte key material (GUI loads it from the OS
    /// keyring app-side; core/storage never touches the keyring).
    Raw(EncryptionKey),
    /// Derive from a password with Argon2id. Salt + cost parameters are
    /// generated on first open and persisted in `encryption.meta`; later
    /// opens re-derive with the persisted values.
    Password(Zeroizing<Vec<u8>>),
}

impl std::fmt::Debug for KeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Raw(_) => write!(f, "KeySource::Raw([REDACTED])"),
            Self::Password(_) => write!(f, "KeySource::Password([REDACTED])"),
        }
    }
}

/// Configuration for encryption at rest. `StorageConfig.encryption = Some(..)`
/// turns it on; the default is OFF (server/sequencer/bootnode deployments
/// keep the raw plaintext path and its performance).
#[derive(Debug, Clone)]
pub struct EncryptionAtRestConfig {
    pub key_source: KeySource,
}

impl EncryptionAtRestConfig {
    /// Encryption with caller-supplied 32-byte key material.
    pub fn with_raw_key(key: [u8; 32]) -> Self {
        Self {
            key_source: KeySource::Raw(EncryptionKey::from_bytes(key)),
        }
    }

    /// Encryption with an [`EncryptionKey`].
    pub fn with_key(key: EncryptionKey) -> Self {
        Self {
            key_source: KeySource::Raw(key),
        }
    }

    /// Encryption with an Argon2id password-derived key (salt persisted in
    /// `encryption.meta`).
    pub fn with_password(password: impl AsRef<[u8]>) -> Self {
        Self {
            key_source: KeySource::Password(Zeroizing::new(password.as_ref().to_vec())),
        }
    }
}

/// How the key is derived, as recorded in `encryption.meta`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum KdfMeta {
    /// Raw 32-byte key supplied by the application (e.g. OS keyring).
    RawKey,
    /// Argon2id password derivation with persisted parameters.
    Argon2id(PasswordKdf),
}

/// Persistent encryption metadata, stored as JSON in
/// `<data_dir>/encryption.meta`. Doubles as the "this database is
/// encrypted" marker used for plaintext/encrypted mismatch detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionMeta {
    /// Metadata format version (1).
    pub format_version: u32,
    /// AEAD cipher identifier ("aes-256-gcm").
    pub cipher: String,
    /// Value envelope format version ([`AT_REST_VALUE_VERSION`]).
    pub value_format: u8,
    /// Key derivation record (raw key vs Argon2id params + salt).
    pub kdf: KdfMeta,
    /// Hex-encoded BLAKE3 key commitment (32 bytes).
    pub key_commitment: String,
    /// Unix timestamp of creation.
    pub created_at: u64,
}

impl EncryptionMeta {
    /// Path of the metadata file inside a data directory.
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join(ENCRYPTION_META_FILE)
    }

    /// Load the metadata file if present. `Ok(None)` when the marker does
    /// not exist (unencrypted database or fresh directory).
    pub fn load(data_dir: &Path) -> Result<Option<Self>, AtRestError> {
        let path = Self::path(data_dir);
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(&path).map_err(|e| AtRestError::MetaIo(e.to_string()))?;
        let meta: Self =
            serde_json::from_str(&raw).map_err(|e| AtRestError::InvalidMeta(e.to_string()))?;
        if meta.format_version != 1 {
            return Err(AtRestError::InvalidMeta(format!(
                "unsupported format_version {}",
                meta.format_version
            )));
        }
        Ok(Some(meta))
    }

    /// Atomically persist the metadata file (write temp + fsync + rename).
    pub fn store(&self, data_dir: &Path) -> Result<(), AtRestError> {
        use std::io::Write;

        std::fs::create_dir_all(data_dir).map_err(|e| AtRestError::MetaIo(e.to_string()))?;
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| AtRestError::InvalidMeta(e.to_string()))?;

        let tmp = data_dir.join(format!("{ENCRYPTION_META_FILE}.tmp"));
        {
            let mut f =
                std::fs::File::create(&tmp).map_err(|e| AtRestError::MetaIo(e.to_string()))?;
            f.write_all(json.as_bytes())
                .map_err(|e| AtRestError::MetaIo(e.to_string()))?;
            f.sync_all().map_err(|e| AtRestError::MetaIo(e.to_string()))?;
        }
        std::fs::rename(&tmp, Self::path(data_dir))
            .map_err(|e| AtRestError::MetaIo(e.to_string()))?;
        Ok(())
    }

    fn commitment_bytes(&self) -> Result<[u8; 32], AtRestError> {
        let raw = hex::decode(&self.key_commitment)
            .map_err(|e| AtRestError::InvalidMeta(format!("invalid key_commitment hex: {e}")))?;
        raw.try_into().map_err(|_| {
            AtRestError::InvalidMeta("key_commitment must be 32 bytes".to_string())
        })
    }
}

/// Live encryption/decryption counters (relaxed atomics; observability only).
#[derive(Debug, Default)]
struct Counters {
    encryptions: AtomicU64,
    decryptions: AtomicU64,
    bytes_encrypted: AtomicU64,
    bytes_decrypted: AtomicU64,
}

/// Snapshot of at-rest encryption statistics.
#[derive(Debug, Clone, Default)]
pub struct AtRestStats {
    pub encryptions: u64,
    pub decryptions: u64,
    pub bytes_encrypted: u64,
    pub bytes_decrypted: u64,
}

/// Value cipher for the RocksDB access layer: seals/opens every value with
/// a per-column-family AES-256-GCM subkey. Constructed once at open time
/// (per-CF cipher instances are cached — no per-operation key schedule).
pub struct AtRestCipher {
    /// Master key, retained (zeroizing) for on-demand subkey derivation of
    /// column families not known at construction time.
    master: Zeroizing<[u8; 32]>,
    /// Pre-built ciphers for all statically-known column families.
    ciphers: HashMap<&'static str, Aes256Gcm>,
    /// BLAKE3 key commitment (matches encryption.meta).
    commitment: [u8; 32],
    counters: Counters,
}

impl std::fmt::Debug for AtRestCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AtRestCipher")
            .field("commitment", &hex::encode(&self.commitment[..8]))
            .field("column_families", &self.ciphers.len())
            .finish()
    }
}

impl AtRestCipher {
    /// Build the cipher from master key material, pre-deriving subkeys for
    /// every known column family.
    pub fn new(key: &EncryptionKey) -> Self {
        let mut ciphers = HashMap::new();
        for cf in all_column_families() {
            ciphers.insert(cf, Self::cipher_for_master(key.as_bytes(), cf));
        }
        Self {
            master: Zeroizing::new(*key.as_bytes()),
            ciphers,
            commitment: key.commitment(),
            counters: Counters::default(),
        }
    }

    /// Resolve the key source against a data directory and construct the
    /// cipher, enforcing the meta/marker rules:
    ///
    /// - fresh directory (no DB, no meta): create `encryption.meta`.
    /// - meta present: derive/verify the key against the stored commitment
    ///   (wrong key/password → [`AtRestError::WrongKey`]).
    /// - existing DB without meta: plaintext database —
    ///   [`AtRestError::PlaintextDbWithEncryptionEnabled`] (no auto-migration).
    pub fn open_or_init(
        data_dir: &Path,
        config: &EncryptionAtRestConfig,
    ) -> Result<Self, AtRestError> {
        let meta = EncryptionMeta::load(data_dir)?;
        // RocksDB creates CURRENT on first open; its presence means an
        // existing database lives here.
        let db_exists = data_dir.join("CURRENT").exists();

        match meta {
            Some(meta) => {
                // Existing encrypted database (or interrupted first open):
                // resolve the key and verify it against the commitment.
                let key = match (&config.key_source, &meta.kdf) {
                    (KeySource::Raw(key), _) => key.clone(),
                    (KeySource::Password(password), KdfMeta::Argon2id(kdf)) => {
                        EncryptionKey::derive_from_password(password, kdf)?
                    }
                    (KeySource::Password(_), KdfMeta::RawKey) => {
                        return Err(AtRestError::InvalidMeta(
                            "database was initialized with a raw key, but a password was \
                             supplied — provide the original 32-byte key"
                                .to_string(),
                        ));
                    }
                };
                if key.commitment() != meta.commitment_bytes()? {
                    return Err(AtRestError::WrongKey);
                }
                Ok(Self::new(&key))
            }
            None if db_exists => Err(AtRestError::PlaintextDbWithEncryptionEnabled(
                data_dir.display().to_string(),
            )),
            None => {
                // Fresh directory: resolve the key (generating KDF salt for
                // the password path) and persist encryption.meta before any
                // data is written.
                let (key, kdf_meta) = match &config.key_source {
                    KeySource::Raw(key) => (key.clone(), KdfMeta::RawKey),
                    KeySource::Password(password) => {
                        let kdf = PasswordKdf::generate();
                        let key = EncryptionKey::derive_from_password(password, &kdf)?;
                        (key, KdfMeta::Argon2id(kdf))
                    }
                };
                let meta = EncryptionMeta {
                    format_version: 1,
                    cipher: "aes-256-gcm".to_string(),
                    value_format: AT_REST_VALUE_VERSION,
                    kdf: kdf_meta,
                    key_commitment: hex::encode(key.commitment()),
                    created_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                };
                meta.store(data_dir)?;
                Ok(Self::new(&key))
            }
        }
    }

    fn cipher_for_master(master: &[u8; 32], cf: &str) -> Aes256Gcm {
        // Per-CF subkey via BLAKE3 KDF; context string embeds the CF name
        // for domain separation (citrate-comms EncryptedStore pattern).
        let context = format!("{CF_KEY_CONTEXT_PREFIX}{cf}");
        let subkey = blake3::derive_key(&context, master);
        // 32-byte key length is correct by construction.
        Aes256Gcm::new_from_slice(&subkey).expect("AES-256-GCM accepts 32-byte keys")
    }

    fn cipher_for(&self, cf: &str) -> Aes256Gcm {
        match self.ciphers.get(cf) {
            Some(cipher) => cipher.clone(),
            // Column family added after construction — derive on demand.
            None => Self::cipher_for_master(&self.master, cf),
        }
    }

    /// AAD = column family || 0x00 || record key: binds each ciphertext to
    /// its exact location in the database.
    fn aad(cf: &str, record_key: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(cf.len() + 1 + record_key.len());
        aad.extend_from_slice(cf.as_bytes());
        aad.push(0x00);
        aad.extend_from_slice(record_key);
        aad
    }

    /// Encrypt a value for storage under (cf, record_key).
    pub fn seal(&self, cf: &str, record_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, AtRestError> {
        let cipher = self.cipher_for(cf);

        // thread_rng is a CSPRNG (ChaCha12, periodically reseeded from the
        // OS): cryptographically sound for nonce generation and avoids a
        // getrandom syscall on every write (hot path).
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);

        let aad = Self::aad(cf, record_key);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| AtRestError::EncryptFailed(cf.to_string()))?;

        let mut out = Vec::with_capacity(VALUE_PREFIX_LEN + ciphertext.len());
        out.extend_from_slice(&QSSP_MAGIC);
        out.push(AT_REST_VALUE_VERSION);
        out.push(AT_REST_ALG_AES_256_GCM);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);

        self.counters.encryptions.fetch_add(1, Ordering::Relaxed);
        self.counters
            .bytes_encrypted
            .fetch_add(plaintext.len() as u64, Ordering::Relaxed);

        Ok(out)
    }

    /// Decrypt a stored value read from (cf, record_key).
    pub fn open_value(
        &self,
        cf: &str,
        record_key: &[u8],
        stored: &[u8],
    ) -> Result<Vec<u8>, AtRestError> {
        if stored.len() < 4 || stored[0..4] != QSSP_MAGIC {
            return Err(AtRestError::NotEncrypted(cf.to_string()));
        }
        if stored.len() < MIN_SEALED_LEN {
            return Err(AtRestError::DecryptFailed(cf.to_string()));
        }
        let version = stored[4];
        let algorithm = stored[5];
        if version != AT_REST_VALUE_VERSION || algorithm != AT_REST_ALG_AES_256_GCM {
            return Err(AtRestError::UnsupportedFormat(version, algorithm));
        }

        let cipher = self.cipher_for(cf);
        let nonce = &stored[6..6 + 12];
        let aad = Self::aad(cf, record_key);

        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: &stored[VALUE_PREFIX_LEN..],
                    aad: &aad,
                },
            )
            .map_err(|_| AtRestError::DecryptFailed(cf.to_string()))?;

        self.counters.decryptions.fetch_add(1, Ordering::Relaxed);
        self.counters
            .bytes_decrypted
            .fetch_add(plaintext.len() as u64, Ordering::Relaxed);

        Ok(plaintext)
    }

    /// Check whether stored bytes carry the at-rest envelope prefix.
    pub fn looks_sealed(stored: &[u8]) -> bool {
        stored.len() >= MIN_SEALED_LEN
            && stored[0..4] == QSSP_MAGIC
            && stored[4] == AT_REST_VALUE_VERSION
    }

    /// Key commitment of the active key (matches `encryption.meta`).
    pub fn key_commitment(&self) -> [u8; 32] {
        self.commitment
    }

    /// Snapshot of encryption/decryption counters.
    pub fn stats(&self) -> AtRestStats {
        AtRestStats {
            encryptions: self.counters.encryptions.load(Ordering::Relaxed),
            decryptions: self.counters.decryptions.load(Ordering::Relaxed),
            bytes_encrypted: self.counters.bytes_encrypted.load(Ordering::Relaxed),
            bytes_decrypted: self.counters.bytes_decrypted.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_key() -> EncryptionKey {
        EncryptionKey::from_bytes([7u8; 32])
    }

    #[test]
    fn seal_open_roundtrip() {
        let cipher = AtRestCipher::new(&test_key());
        let plaintext = b"account state bytes";
        let sealed = cipher
            .seal("accounts", b"addr-1", plaintext)
            .expect("seal should succeed");
        assert!(AtRestCipher::looks_sealed(&sealed));
        assert_ne!(&sealed[VALUE_PREFIX_LEN..], plaintext.as_slice());
        let opened = cipher
            .open_value("accounts", b"addr-1", &sealed)
            .expect("open should succeed");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn empty_value_roundtrip() {
        let cipher = AtRestCipher::new(&test_key());
        let sealed = cipher
            .seal("metadata", b"marker", b"")
            .expect("seal empty should succeed");
        assert_eq!(sealed.len(), MIN_SEALED_LEN);
        let opened = cipher
            .open_value("metadata", b"marker", &sealed)
            .expect("open empty should succeed");
        assert!(opened.is_empty());
    }

    #[test]
    fn aad_binds_cf_and_record_key() {
        let cipher = AtRestCipher::new(&test_key());
        let sealed = cipher
            .seal("accounts", b"addr-1", b"value")
            .expect("seal should succeed");

        // Same CF, different record key → authentication failure.
        let err = cipher
            .open_value("accounts", b"addr-2", &sealed)
            .expect_err("moved record key must fail");
        assert!(matches!(err, AtRestError::DecryptFailed(_)));

        // Different CF, same record key → authentication failure.
        let err = cipher
            .open_value("state", b"addr-1", &sealed)
            .expect_err("moved CF must fail");
        assert!(matches!(err, AtRestError::DecryptFailed(_)));
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let cipher = AtRestCipher::new(&test_key());
        let sealed = cipher
            .seal("blocks", b"h1", b"block bytes")
            .expect("seal should succeed");

        let other = AtRestCipher::new(&EncryptionKey::from_bytes([8u8; 32]));
        let err = other
            .open_value("blocks", b"h1", &sealed)
            .expect_err("wrong key must fail");
        assert!(matches!(err, AtRestError::DecryptFailed(_)));
    }

    #[test]
    fn plaintext_value_rejected() {
        let cipher = AtRestCipher::new(&test_key());
        let err = cipher
            .open_value("blocks", b"h1", b"raw plaintext value")
            .expect_err("plaintext must be rejected");
        assert!(matches!(err, AtRestError::NotEncrypted(_)));
    }

    #[test]
    fn commitment_is_deterministic_and_key_bound() {
        let a = EncryptionKey::from_bytes([1u8; 32]);
        let b = EncryptionKey::from_bytes([1u8; 32]);
        let c = EncryptionKey::from_bytes([2u8; 32]);
        assert_eq!(a.commitment(), b.commitment());
        assert_ne!(a.commitment(), c.commitment());
        // Commitment must not equal the key itself.
        assert_ne!(&a.commitment(), a.as_bytes());
    }

    #[test]
    fn password_derivation_deterministic_with_persisted_salt() {
        let kdf = PasswordKdf {
            m_cost_kib: 8 * 1024, // small for test speed
            t_cost: 1,
            p_cost: 1,
            salt: hex::encode([9u8; 32]),
        };
        let k1 = EncryptionKey::derive_from_password(b"hunter2!", &kdf)
            .expect("derivation should succeed");
        let k2 = EncryptionKey::derive_from_password(b"hunter2!", &kdf)
            .expect("derivation should succeed");
        assert_eq!(k1.commitment(), k2.commitment());

        let wrong = EncryptionKey::derive_from_password(b"hunter3!", &kdf)
            .expect("derivation should succeed");
        assert_ne!(k1.commitment(), wrong.commitment());
    }

    #[test]
    fn meta_store_load_roundtrip() {
        let tmp = TempDir::new().expect("tempdir");
        let key = test_key();
        let meta = EncryptionMeta {
            format_version: 1,
            cipher: "aes-256-gcm".to_string(),
            value_format: AT_REST_VALUE_VERSION,
            kdf: KdfMeta::Argon2id(PasswordKdf::generate()),
            key_commitment: hex::encode(key.commitment()),
            created_at: 1_800_000_000,
        };
        meta.store(tmp.path()).expect("store should succeed");

        let loaded = EncryptionMeta::load(tmp.path())
            .expect("load should succeed")
            .expect("meta should exist");
        assert_eq!(loaded.key_commitment, meta.key_commitment);
        assert_eq!(loaded.kdf, meta.kdf);
        assert_eq!(loaded.value_format, AT_REST_VALUE_VERSION);
    }

    #[test]
    fn open_or_init_fresh_then_reopen_and_wrong_key() {
        let tmp = TempDir::new().expect("tempdir");
        let config = EncryptionAtRestConfig::with_raw_key([3u8; 32]);

        // Fresh directory → meta created.
        let cipher =
            AtRestCipher::open_or_init(tmp.path(), &config).expect("fresh init should succeed");
        assert!(EncryptionMeta::path(tmp.path()).exists());

        // Same key reopens.
        let reopened =
            AtRestCipher::open_or_init(tmp.path(), &config).expect("reopen should succeed");
        assert_eq!(cipher.key_commitment(), reopened.key_commitment());

        // Wrong key is rejected at open.
        let wrong = EncryptionAtRestConfig::with_raw_key([4u8; 32]);
        let err = AtRestCipher::open_or_init(tmp.path(), &wrong)
            .expect_err("wrong key must be rejected");
        assert!(matches!(err, AtRestError::WrongKey));
    }

    #[test]
    fn open_or_init_password_salt_persists() {
        let tmp = TempDir::new().expect("tempdir");
        let config = EncryptionAtRestConfig::with_password("correct horse battery staple");

        let first =
            AtRestCipher::open_or_init(tmp.path(), &config).expect("fresh init should succeed");
        let second =
            AtRestCipher::open_or_init(tmp.path(), &config).expect("reopen should succeed");
        // Same password + persisted salt → same key.
        assert_eq!(first.key_commitment(), second.key_commitment());

        let wrong = EncryptionAtRestConfig::with_password("wrong password");
        let err = AtRestCipher::open_or_init(tmp.path(), &wrong)
            .expect_err("wrong password must be rejected");
        assert!(matches!(err, AtRestError::WrongKey));
    }

    #[test]
    fn open_or_init_rejects_existing_plaintext_db() {
        let tmp = TempDir::new().expect("tempdir");
        // Simulate an existing RocksDB (CURRENT marker) without encryption.meta.
        std::fs::write(tmp.path().join("CURRENT"), b"MANIFEST-000001\n").expect("write CURRENT");

        let config = EncryptionAtRestConfig::with_raw_key([3u8; 32]);
        let err = AtRestCipher::open_or_init(tmp.path(), &config)
            .expect_err("plaintext db must be rejected");
        assert!(matches!(
            err,
            AtRestError::PlaintextDbWithEncryptionEnabled(_)
        ));
    }
}
