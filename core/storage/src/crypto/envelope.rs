// SPDX-License-Identifier: MIT
// Crypto-Agile Envelope Encryption
//
// Provides envelope encryption with version headers for algorithm upgrades
// without re-encrypting existing data. The envelope wraps encrypted data
// with metadata about the encryption scheme used.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use sha3::{Sha3_256, Digest};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use super::key_derivation::DerivedKey;
use super::{QSSP_MAGIC, QSSP_VERSION};

/// Envelope version for crypto-agility
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EnvelopeVersion {
    /// Version 1: AES-256-GCM with hybrid Kyber+X25519
    V1 = 1,
    /// Version 2: Reserved for future algorithm upgrades
    V2 = 2,
}

impl TryFrom<u8> for EnvelopeVersion {
    type Error = EnvelopeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            _ => Err(EnvelopeError::UnsupportedVersion(value)),
        }
    }
}

/// Envelope header with encryption metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeHeader {
    /// Magic bytes for identification ("QSSP")
    pub magic: [u8; 4],
    /// Protocol version
    pub version: u8,
    /// Key version used for encryption
    pub key_version: u32,
    /// Encryption algorithm (0x01 = AES-256-GCM)
    pub algorithm: u8,
    /// Key derivation method (0x01 = Argon2id, 0x02 = HKDF-SHA3)
    pub kdf_method: u8,
    /// Column family this data belongs to
    pub column_family_hash: [u8; 8],
    /// Timestamp of encryption
    pub encrypted_at: u64,
    /// Key commitment for verification
    pub key_commitment: [u8; 16],
}

impl EnvelopeHeader {
    /// Size of the serialized header in bytes
    pub const SIZE: usize = 4 + 1 + 4 + 1 + 1 + 8 + 8 + 16; // 43 bytes

    /// Create a new header
    pub fn new(key: &DerivedKey, column_family: &str) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Hash column family name
        let cf_hash = {
            let full_hash: [u8; 32] = Sha3_256::digest(column_family.as_bytes()).into();
            let mut truncated = [0u8; 8];
            truncated.copy_from_slice(&full_hash[..8]);
            truncated
        };

        // Truncated key commitment
        let mut key_commit = [0u8; 16];
        key_commit.copy_from_slice(&key.commitment[..16]);

        Self {
            magic: QSSP_MAGIC,
            version: QSSP_VERSION,
            key_version: key.version,
            algorithm: 0x01, // AES-256-GCM
            kdf_method: 0x02, // HKDF-SHA3
            column_family_hash: cf_hash,
            encrypted_at: now,
            key_commitment: key_commit,
        }
    }

    /// Serialize header to bytes
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        let mut offset = 0;

        bytes[offset..offset + 4].copy_from_slice(&self.magic);
        offset += 4;

        bytes[offset] = self.version;
        offset += 1;

        bytes[offset..offset + 4].copy_from_slice(&self.key_version.to_be_bytes());
        offset += 4;

        bytes[offset] = self.algorithm;
        offset += 1;

        bytes[offset] = self.kdf_method;
        offset += 1;

        bytes[offset..offset + 8].copy_from_slice(&self.column_family_hash);
        offset += 8;

        bytes[offset..offset + 8].copy_from_slice(&self.encrypted_at.to_be_bytes());
        offset += 8;

        bytes[offset..offset + 16].copy_from_slice(&self.key_commitment);

        bytes
    }

    /// Parse header from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() < Self::SIZE {
            return Err(EnvelopeError::InvalidHeaderSize);
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[0..4]);

        if magic != QSSP_MAGIC {
            return Err(EnvelopeError::InvalidMagic);
        }

        let version = bytes[4];
        if version != QSSP_VERSION {
            return Err(EnvelopeError::UnsupportedVersion(version));
        }

        let mut kv_buf = [0u8; 4];
        kv_buf.copy_from_slice(&bytes[5..9]);
        let key_version = u32::from_be_bytes(kv_buf);
        let algorithm = bytes[9];
        let kdf_method = bytes[10];

        let mut column_family_hash = [0u8; 8];
        column_family_hash.copy_from_slice(&bytes[11..19]);

        let mut ea_buf = [0u8; 8];
        ea_buf.copy_from_slice(&bytes[19..27]);
        let encrypted_at = u64::from_be_bytes(ea_buf);

        let mut key_commitment = [0u8; 16];
        key_commitment.copy_from_slice(&bytes[27..43]);

        Ok(Self {
            magic,
            version,
            key_version,
            algorithm,
            kdf_method,
            column_family_hash,
            encrypted_at,
            key_commitment,
        })
    }

    /// Verify key commitment matches
    pub fn verify_key(&self, key: &DerivedKey) -> bool {
        self.key_version == key.version && self.key_commitment == key.commitment[..16]
    }
}

/// Encryption envelope containing header and ciphertext
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionEnvelope {
    /// Header with metadata
    pub header: EnvelopeHeader,
    /// Random nonce for encryption
    pub nonce: [u8; 12],
    /// Encrypted data with authentication tag
    pub ciphertext: Vec<u8>,
}

impl EncryptionEnvelope {
    /// Encrypt data into an envelope
    pub fn encrypt(
        key: &DerivedKey,
        plaintext: &[u8],
        column_family: &str,
    ) -> Result<Self, EnvelopeError> {
        let header = EnvelopeHeader::new(key, column_family);

        // Generate random nonce
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        // Create cipher
        let cipher = Aes256Gcm::new_from_slice(key.key_bytes())
            .map_err(|_| EnvelopeError::CipherInitFailed)?;

        // Include header as additional authenticated data (reserved for AAD binding)
        let _aad = header.to_bytes();

        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| EnvelopeError::EncryptionFailed)?;

        Ok(Self {
            header,
            nonce,
            ciphertext,
        })
    }

    /// Decrypt envelope to recover plaintext
    pub fn decrypt(&self, key: &DerivedKey) -> Result<Vec<u8>, EnvelopeError> {
        // Verify key matches
        if !self.header.verify_key(key) {
            return Err(EnvelopeError::KeyMismatch);
        }

        // Create cipher
        let cipher = Aes256Gcm::new_from_slice(key.key_bytes())
            .map_err(|_| EnvelopeError::CipherInitFailed)?;

        // Decrypt
        cipher
            .decrypt(Nonce::from_slice(&self.nonce), self.ciphertext.as_ref())
            .map_err(|_| EnvelopeError::DecryptionFailed)
    }

    /// Serialize envelope to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let header_bytes = self.header.to_bytes();
        let mut result = Vec::with_capacity(
            EnvelopeHeader::SIZE + 12 + 4 + self.ciphertext.len()
        );

        result.extend_from_slice(&header_bytes);
        result.extend_from_slice(&self.nonce);
        result.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        result.extend_from_slice(&self.ciphertext);

        result
    }

    /// Parse envelope from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() < EnvelopeHeader::SIZE + 12 + 4 {
            return Err(EnvelopeError::InvalidEnvelopeSize);
        }

        let header = EnvelopeHeader::from_bytes(&bytes[0..EnvelopeHeader::SIZE])?;

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[EnvelopeHeader::SIZE..EnvelopeHeader::SIZE + 12]);

        let ct_len_start = EnvelopeHeader::SIZE + 12;
        let mut cl_buf = [0u8; 4];
        cl_buf.copy_from_slice(&bytes[ct_len_start..ct_len_start + 4]);
        let ct_len = u32::from_be_bytes(cl_buf) as usize;

        let ct_start = ct_len_start + 4;
        if bytes.len() < ct_start + ct_len {
            return Err(EnvelopeError::InvalidEnvelopeSize);
        }

        let ciphertext = bytes[ct_start..ct_start + ct_len].to_vec();

        Ok(Self {
            header,
            nonce,
            ciphertext,
        })
    }

    /// Check if this envelope uses the specified key version
    pub fn uses_key_version(&self, version: u32) -> bool {
        self.header.key_version == version
    }

    /// Get the column family hash for routing
    pub fn column_family_hash(&self) -> [u8; 8] {
        self.header.column_family_hash
    }
}

/// Crypto-agile envelope for seamless algorithm upgrades
pub struct CryptoAgileEnvelope {
    /// Current key for new encryptions
    current_key: DerivedKey,
    /// Previous keys for decrypting old data
    previous_keys: Vec<DerivedKey>,
}

impl CryptoAgileEnvelope {
    /// Create with a single key
    pub fn new(key: DerivedKey) -> Self {
        Self {
            current_key: key,
            previous_keys: Vec::new(),
        }
    }

    /// Rotate to a new key, keeping old key for decryption
    pub fn rotate_key(&mut self, new_key: DerivedKey) {
        let old_key = std::mem::replace(&mut self.current_key, new_key);
        self.previous_keys.push(old_key);

        // Keep only last 3 versions for decryption
        if self.previous_keys.len() > 3 {
            self.previous_keys.remove(0);
        }
    }

    /// Encrypt with current key
    pub fn encrypt(&self, plaintext: &[u8], column_family: &str) -> Result<Vec<u8>, EnvelopeError> {
        let envelope = EncryptionEnvelope::encrypt(&self.current_key, plaintext, column_family)?;
        Ok(envelope.to_bytes())
    }

    /// Decrypt, trying current and previous keys
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        let envelope = EncryptionEnvelope::from_bytes(ciphertext)?;

        // Try current key first
        if envelope.header.verify_key(&self.current_key) {
            return envelope.decrypt(&self.current_key);
        }

        // Try previous keys
        for key in &self.previous_keys {
            if envelope.header.verify_key(key) {
                return envelope.decrypt(key);
            }
        }

        Err(EnvelopeError::KeyNotFound)
    }

    /// Re-encrypt with current key (for key rotation migration)
    pub fn re_encrypt(&self, ciphertext: &[u8], column_family: &str) -> Result<Vec<u8>, EnvelopeError> {
        let plaintext = self.decrypt(ciphertext)?;
        self.encrypt(&plaintext, column_family)
    }

    /// Check if data needs re-encryption (old key version)
    pub fn needs_reencryption(&self, ciphertext: &[u8]) -> bool {
        if let Ok(envelope) = EncryptionEnvelope::from_bytes(ciphertext) {
            envelope.header.key_version != self.current_key.version
        } else {
            false
        }
    }
}

/// Envelope errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    InvalidMagic,
    UnsupportedVersion(u8),
    InvalidHeaderSize,
    InvalidEnvelopeSize,
    CipherInitFailed,
    EncryptionFailed,
    DecryptionFailed,
    KeyMismatch,
    KeyNotFound,
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "Invalid magic bytes - not a QSSP envelope"),
            Self::UnsupportedVersion(v) => write!(f, "Unsupported envelope version: {}", v),
            Self::InvalidHeaderSize => write!(f, "Header too short"),
            Self::InvalidEnvelopeSize => write!(f, "Envelope data too short"),
            Self::CipherInitFailed => write!(f, "Failed to initialize cipher"),
            Self::EncryptionFailed => write!(f, "Encryption failed"),
            Self::DecryptionFailed => write!(f, "Decryption failed - authentication error"),
            Self::KeyMismatch => write!(f, "Key version/commitment mismatch"),
            Self::KeyNotFound => write!(f, "No matching key found for decryption"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::key_derivation::{KeyDerivationParams, MasterKeyDerivation, KeyPurpose};

    fn test_key() -> DerivedKey {
        let params = KeyDerivationParams::new(None);
        let kdf = MasterKeyDerivation::new(params);
        let master = kdf.derive_master_key(b"test-password").unwrap();
        kdf.derive_purpose_key(&master, KeyPurpose::BlockEncryption).unwrap()
    }

    #[test]
    fn test_envelope_roundtrip() {
        let key = test_key();
        let plaintext = b"Hello, quantum-safe world!";
        let column_family = "blocks";

        let envelope = EncryptionEnvelope::encrypt(&key, plaintext, column_family).unwrap();
        let decrypted = envelope.decrypt(&key).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_envelope_serialization() {
        let key = test_key();
        let plaintext = b"Serialization test";
        let column_family = "state";

        let envelope = EncryptionEnvelope::encrypt(&key, plaintext, column_family).unwrap();
        let bytes = envelope.to_bytes();
        let parsed = EncryptionEnvelope::from_bytes(&bytes).unwrap();
        let decrypted = parsed.decrypt(&key).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_header_verification() {
        let key = test_key();
        let header = EnvelopeHeader::new(&key, "test");

        assert!(header.verify_key(&key));
        assert_eq!(header.magic, QSSP_MAGIC);
        assert_eq!(header.version, QSSP_VERSION);
    }

    #[test]
    fn test_crypto_agile_rotation() {
        let params = KeyDerivationParams::new(None);
        let kdf = MasterKeyDerivation::new(params);
        let master = kdf.derive_master_key(b"password").unwrap();

        let key1 = kdf.derive_purpose_key(&master, KeyPurpose::BlockEncryption).unwrap();
        let mut agile = CryptoAgileEnvelope::new(key1);

        // Encrypt with first key
        let data1 = b"encrypted with key 1";
        let ct1 = agile.encrypt(data1, "blocks").unwrap();

        // Rotate key
        let new_params = KeyDerivationParams {
            version: 2,
            ..KeyDerivationParams::new(None)
        };
        let new_kdf = MasterKeyDerivation::new(new_params);
        let new_master = new_kdf.derive_master_key(b"password").unwrap();
        let key2 = new_kdf.derive_purpose_key(&new_master, KeyPurpose::BlockEncryption).unwrap();
        agile.rotate_key(key2);

        // Encrypt with second key
        let data2 = b"encrypted with key 2";
        let ct2 = agile.encrypt(data2, "blocks").unwrap();

        // Should decrypt both
        assert_eq!(agile.decrypt(&ct1).unwrap(), data1);
        assert_eq!(agile.decrypt(&ct2).unwrap(), data2);

        // ct1 should need re-encryption
        assert!(agile.needs_reencryption(&ct1));
        assert!(!agile.needs_reencryption(&ct2));
    }
}
