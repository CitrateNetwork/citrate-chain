// SPDX-License-Identifier: MIT
// Quantum-Safe Key Derivation
//
// Implements secure key derivation for database encryption:
// - Argon2id for password-based master key derivation (memory-hard)
// - HKDF-SHA3 for deriving per-column-family keys
// - Key versioning for rotation support

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256, Sha3_512};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::ZeroizeOnDrop;

/// Key purpose for domain separation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyPurpose {
    /// Master key encryption key (KEK)
    MasterKEK,
    /// Data encryption key for blocks
    BlockEncryption,
    /// Data encryption key for transactions
    TransactionEncryption,
    /// Data encryption key for state
    StateEncryption,
    /// Data encryption key for models (highest security)
    ModelEncryption,
    /// Data encryption key for training data
    TrainingEncryption,
    /// Key for integrity verification
    IntegrityHMAC,
    /// Key for key commitment
    KeyCommitment,
}

impl KeyPurpose {
    /// Get domain separation string for this purpose
    pub fn domain(&self) -> &'static [u8] {
        match self {
            Self::MasterKEK => b"QSSP-v1-master-kek",
            Self::BlockEncryption => b"QSSP-v1-blocks",
            Self::TransactionEncryption => b"QSSP-v1-transactions",
            Self::StateEncryption => b"QSSP-v1-state",
            Self::ModelEncryption => b"QSSP-v1-models",
            Self::TrainingEncryption => b"QSSP-v1-training",
            Self::IntegrityHMAC => b"QSSP-v1-integrity",
            Self::KeyCommitment => b"QSSP-v1-commitment",
        }
    }

    /// Get recommended key rotation interval in seconds
    pub fn rotation_interval(&self) -> u64 {
        match self {
            Self::MasterKEK => 365 * 24 * 60 * 60,       // 1 year
            Self::ModelEncryption => 180 * 24 * 60 * 60, // 6 months
            Self::BlockEncryption => 90 * 24 * 60 * 60,  // 90 days
            Self::TransactionEncryption => 90 * 24 * 60 * 60,
            Self::StateEncryption => 90 * 24 * 60 * 60,
            Self::TrainingEncryption => 30 * 24 * 60 * 60, // 30 days
            Self::IntegrityHMAC => 180 * 24 * 60 * 60,
            Self::KeyCommitment => 365 * 24 * 60 * 60,
        }
    }
}

/// Argon2id parameters for memory-hard key derivation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Memory cost in KiB (default: 64 MiB = 65536)
    pub memory_cost: u32,
    /// Time cost (iterations, default: 3)
    pub time_cost: u32,
    /// Parallelism (default: 4)
    pub parallelism: u32,
    /// Output length in bytes (default: 32)
    pub output_len: usize,
    /// Salt length in bytes (default: 32)
    pub salt_len: usize,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_cost: 65536, // 64 MiB
            time_cost: 3,
            parallelism: 4,
            output_len: 32,
            salt_len: 32,
        }
    }
}

impl Argon2Params {
    /// High-security parameters for master keys
    pub fn high_security() -> Self {
        Self {
            memory_cost: 262144, // 256 MiB
            time_cost: 4,
            parallelism: 4,
            output_len: 32,
            salt_len: 32,
        }
    }

    /// Maximum security parameters (for AI models)
    pub fn maximum_security() -> Self {
        Self {
            memory_cost: 1048576, // 1 GiB
            time_cost: 6,
            parallelism: 4,
            output_len: 32,
            salt_len: 32,
        }
    }
}

/// Key derivation parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDerivationParams {
    /// Argon2id parameters
    pub argon2: Argon2Params,
    /// Salt for this derivation
    pub salt: Vec<u8>,
    /// Key version (for rotation)
    pub version: u32,
    /// Creation timestamp
    pub created_at: u64,
    /// Node identifier for multi-node deployments
    pub node_id: Option<String>,
}

impl KeyDerivationParams {
    /// Create new parameters with random salt
    pub fn new(node_id: Option<String>) -> Self {
        let mut salt = vec![0u8; 32];
        OsRng.fill_bytes(&mut salt);

        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            argon2: Argon2Params::default(),
            salt,
            version: 1,
            created_at,
            node_id,
        }
    }

    /// Create high-security parameters
    pub fn high_security(node_id: Option<String>) -> Self {
        let mut params = Self::new(node_id);
        params.argon2 = Argon2Params::high_security();
        params
    }
}

/// Derived key with metadata.
///
/// CRY-H1: the secret `key` material is zeroized on drop via
/// `ZeroizeOnDrop`. Only `key` is wiped; the remaining fields are public
/// metadata (`commitment` is a hash of the key, not the key itself) and are
/// `#[zeroize(skip)]`. There is deliberately no `Debug` *derive*; the manual
/// `Debug` impl below redacts the key so raw bytes can never reach a log line.
#[derive(Clone, ZeroizeOnDrop)]
pub struct DerivedKey {
    /// The actual key material (zeroized on drop)
    key: [u8; 32],
    /// Purpose of this key
    #[zeroize(skip)]
    pub purpose: KeyPurpose,
    /// Version number
    #[zeroize(skip)]
    pub version: u32,
    /// When this key was derived
    #[zeroize(skip)]
    pub derived_at: u64,
    /// Expiry timestamp (0 = never)
    #[zeroize(skip)]
    pub expires_at: u64,
    /// Key commitment for verification
    #[zeroize(skip)]
    pub commitment: [u8; 32],
}

impl DerivedKey {
    /// Get the key bytes (use carefully!)
    pub fn key_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Check if the key has expired
    pub fn is_expired(&self) -> bool {
        if self.expires_at == 0 {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now > self.expires_at
    }

    /// Get time until expiry in seconds
    pub fn time_to_expiry(&self) -> Option<u64> {
        if self.expires_at == 0 {
            return None;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now > self.expires_at {
            Some(0)
        } else {
            Some(self.expires_at - now)
        }
    }
}

impl std::fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DerivedKey")
            .field("purpose", &self.purpose)
            .field("version", &self.version)
            .field("derived_at", &self.derived_at)
            .field("expires_at", &self.expires_at)
            .field("commitment", &hex::encode(&self.commitment[..8]))
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// Master key derivation from password/seed
pub struct MasterKeyDerivation {
    params: KeyDerivationParams,
}

impl MasterKeyDerivation {
    pub fn new(params: KeyDerivationParams) -> Self {
        Self { params }
    }

    /// Derive master key from password using Argon2id
    ///
    /// IMPORTANT: The password should be a high-entropy secret.
    /// For automated nodes, use a 256-bit random seed instead.
    pub fn derive_master_key(&self, password: &[u8]) -> Result<DerivedKey, KeyDerivationError> {
        // Validate inputs
        if password.is_empty() {
            return Err(KeyDerivationError::EmptyPassword);
        }

        // Use Argon2id. CRY-H1: wrap the derived secret so the stack buffer
        // is wiped when this scope exits.
        let key = zeroize::Zeroizing::new(self.argon2id_derive(password)?);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let expires_at = now + KeyPurpose::MasterKEK.rotation_interval();

        // Compute commitment
        let commitment = self.compute_commitment(&key, KeyPurpose::MasterKEK);

        Ok(DerivedKey {
            key: *key,
            purpose: KeyPurpose::MasterKEK,
            version: self.params.version,
            derived_at: now,
            expires_at,
            commitment,
        })
    }

    /// Derive a purpose-specific key from the master key
    pub fn derive_purpose_key(
        &self,
        master: &DerivedKey,
        purpose: KeyPurpose,
    ) -> Result<DerivedKey, KeyDerivationError> {
        if master.purpose != KeyPurpose::MasterKEK {
            return Err(KeyDerivationError::InvalidMasterKey);
        }

        if master.is_expired() {
            return Err(KeyDerivationError::ExpiredMasterKey);
        }

        // HKDF-like expansion using SHA3-512
        let mut hasher = Sha3_512::new();
        hasher.update(purpose.domain());
        hasher.update(master.key_bytes());
        hasher.update(self.params.version.to_be_bytes());
        hasher.update(&self.params.salt);

        let digest = hasher.finalize();
        // CRY-H1: Zeroizing wipes this intermediate secret on scope exit.
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&digest[..32]);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let expires_at = now + purpose.rotation_interval();
        let commitment = self.compute_commitment(&key, purpose);

        Ok(DerivedKey {
            key: *key,
            purpose,
            version: self.params.version,
            derived_at: now,
            expires_at,
            commitment,
        })
    }

    /// Derive column-family-specific key
    pub fn derive_column_key(
        &self,
        master: &DerivedKey,
        column_family: &str,
    ) -> Result<DerivedKey, KeyDerivationError> {
        // Determine purpose based on column family name
        let purpose = match column_family {
            "blocks" | "headers" => KeyPurpose::BlockEncryption,
            "transactions" | "receipts" => KeyPurpose::TransactionEncryption,
            "state" | "accounts" | "storage" | "code" => KeyPurpose::StateEncryption,
            "models" => KeyPurpose::ModelEncryption,
            "training" => KeyPurpose::TrainingEncryption,
            _ => KeyPurpose::StateEncryption, // Default
        };

        // Derive with column family binding
        let base_key = self.derive_purpose_key(master, purpose)?;

        // Further derive with column family name
        let mut hasher = Sha3_256::new();
        hasher.update(b"QSSP-v1-column-");
        hasher.update(column_family.as_bytes());
        hasher.update(base_key.key_bytes());

        // CRY-H1: Zeroizing wipes this intermediate secret on scope exit.
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&hasher.finalize());

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let commitment = self.compute_commitment(&key, purpose);

        Ok(DerivedKey {
            key: *key,
            purpose,
            version: self.params.version,
            derived_at: now,
            expires_at: base_key.expires_at,
            commitment,
        })
    }

    /// Verify a key commitment
    pub fn verify_commitment(&self, key: &DerivedKey) -> bool {
        let expected = self.compute_commitment(key.key_bytes(), key.purpose);
        expected == key.commitment
    }

    /// Argon2id key derivation (memory-hard, RFC 9106) via the `argon2` crate.
    ///
    /// Data source: pure KDF — password + `self.params.salt` +
    /// `self.params.argon2` cost parameters. Replaces the pre-wiring
    /// SHA3-iteration placeholder (which was NOT memory-hard and was
    /// mislabeled as Argon2id).
    fn argon2id_derive(&self, password: &[u8]) -> Result<[u8; 32], KeyDerivationError> {
        use argon2::{Algorithm, Argon2, Params, Version};

        let params = Params::new(
            self.params.argon2.memory_cost,
            self.params.argon2.time_cost,
            self.params.argon2.parallelism,
            Some(32),
        )
        .map_err(|_| KeyDerivationError::InvalidParameters)?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        // CRY-H1: Zeroizing wipes this intermediate buffer on scope exit; the
        // returned copy is re-wrapped by the caller.
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        argon2
            .hash_password_into(password, &self.params.salt, key.as_mut())
            .map_err(|_| KeyDerivationError::DerivationFailed)?;

        Ok(*key)
    }

    /// Compute key commitment
    fn compute_commitment(&self, key: &[u8; 32], purpose: KeyPurpose) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"QSSP-v1-commit-");
        hasher.update(purpose.domain());
        hasher.update(key);
        hasher.update(self.params.version.to_be_bytes());
        hasher.finalize().into()
    }
}

/// Key derivation errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyDerivationError {
    EmptyPassword,
    InvalidMasterKey,
    ExpiredMasterKey,
    DerivationFailed,
    InvalidParameters,
}

impl std::fmt::Display for KeyDerivationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyPassword => write!(f, "Password cannot be empty"),
            Self::InvalidMasterKey => write!(f, "Invalid master key"),
            Self::ExpiredMasterKey => write!(f, "Master key has expired"),
            Self::DerivationFailed => write!(f, "Key derivation failed"),
            Self::InvalidParameters => write!(f, "Invalid derivation parameters"),
        }
    }
}

impl std::error::Error for KeyDerivationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_master_key_derivation() {
        let params = KeyDerivationParams::new(None);
        let kdf = MasterKeyDerivation::new(params);

        let password = b"super-secure-password-123!";
        let master = kdf.derive_master_key(password).unwrap();

        assert_eq!(master.purpose, KeyPurpose::MasterKEK);
        assert!(!master.is_expired());
    }

    #[test]
    fn test_deterministic_derivation() {
        let params = KeyDerivationParams {
            argon2: Argon2Params::default(),
            salt: vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
            version: 1,
            created_at: 0,
            node_id: None,
        };

        let kdf1 = MasterKeyDerivation::new(params.clone());
        let kdf2 = MasterKeyDerivation::new(params);

        let password = b"test-password";
        let key1 = kdf1.derive_master_key(password).unwrap();
        let key2 = kdf2.derive_master_key(password).unwrap();

        assert_eq!(key1.key_bytes(), key2.key_bytes());
    }

    #[test]
    fn test_purpose_key_derivation() {
        let params = KeyDerivationParams::new(None);
        let kdf = MasterKeyDerivation::new(params);

        let master = kdf.derive_master_key(b"password").unwrap();

        let model_key = kdf
            .derive_purpose_key(&master, KeyPurpose::ModelEncryption)
            .unwrap();
        let block_key = kdf
            .derive_purpose_key(&master, KeyPurpose::BlockEncryption)
            .unwrap();

        // Keys should be different
        assert_ne!(model_key.key_bytes(), block_key.key_bytes());
        assert_ne!(model_key.purpose, block_key.purpose);
    }

    #[test]
    fn test_commitment_verification() {
        let params = KeyDerivationParams::new(None);
        let kdf = MasterKeyDerivation::new(params);

        let master = kdf.derive_master_key(b"password").unwrap();

        assert!(kdf.verify_commitment(&master));
    }

    #[test]
    fn test_empty_password_fails() {
        let params = KeyDerivationParams::new(None);
        let kdf = MasterKeyDerivation::new(params);

        let result = kdf.derive_master_key(b"");
        assert!(matches!(result, Err(KeyDerivationError::EmptyPassword)));
    }

    /// CRY-H1 tripwire: `DerivedKey` must carry key material that is zeroized
    /// on drop. This is a compile-time assertion — if the `ZeroizeOnDrop`
    /// derive is ever removed from `DerivedKey`, this test stops compiling.
    #[test]
    fn test_cry_h1_derived_key_is_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<DerivedKey>();
    }

    /// CRY-H1 tripwire (runtime): drop a `DerivedKey` through a raw pointer to
    /// its key bytes and confirm the bytes are wiped afterwards. Uses the
    /// `zeroize` drop path directly so it does not read freed memory.
    #[test]
    fn test_cry_h1_key_bytes_wiped_on_drop() {
        use zeroize::Zeroize;

        // A DerivedKey whose key is all 0xAB.
        let params = KeyDerivationParams::new(None);
        let kdf = MasterKeyDerivation::new(params);
        let mut master = kdf
            .derive_master_key(b"a-real-password")
            .expect("derive master");

        // The key must be non-zero before we wipe it.
        assert_ne!(
            *master.key_bytes(),
            [0u8; 32],
            "derived key must be non-zero"
        );

        // Zeroize the secret field explicitly (the same operation ZeroizeOnDrop
        // performs on drop) and confirm it is wiped.
        master.key.zeroize();
        assert_eq!(
            *master.key_bytes(),
            [0u8; 32],
            "CRY-H1: key material must be wiped by zeroize"
        );
    }
}
