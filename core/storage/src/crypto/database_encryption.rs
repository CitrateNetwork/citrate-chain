// SPDX-License-Identifier: MIT
// Database Encryption Layer
//
// Provides transparent encryption for RocksDB operations using the
// Quantum-Safe Storage Protocol (QSSP). Encrypts data at the column
// family level with support for key rotation.

use super::envelope::CryptoAgileEnvelope;
use super::key_derivation::{DerivedKey, KeyDerivationParams, KeyPurpose, MasterKeyDerivation};
use super::key_commitment::{KeyCommitment, KeyLifecycleManager, KeyRotationProof, RotationReason};
use sha3::{Sha3_256, Digest};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Configuration for database encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseEncryptionConfig {
    /// Enable encryption (can be disabled for debugging)
    pub enabled: bool,
    /// Encrypt column families selectively
    pub encrypt_column_families: HashMap<String, bool>,
    /// Key rotation interval in seconds
    pub key_rotation_interval: u64,
    /// Node identifier for key management
    pub node_id: String,
    /// Security level (Standard, High, Maximum)
    pub security_level: SecurityLevelConfig,
    /// Enable compression before encryption
    pub compress_before_encrypt: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityLevelConfig {
    /// For block data
    pub blocks: String,
    /// For transaction data
    pub transactions: String,
    /// For state data
    pub state: String,
    /// For AI models (highest security)
    pub models: String,
}

impl Default for DatabaseEncryptionConfig {
    fn default() -> Self {
        let mut encrypt_cf = HashMap::new();
        // Encrypt sensitive column families by default
        encrypt_cf.insert("blocks".to_string(), true);
        encrypt_cf.insert("headers".to_string(), true);
        encrypt_cf.insert("transactions".to_string(), true);
        encrypt_cf.insert("receipts".to_string(), true);
        encrypt_cf.insert("state".to_string(), true);
        encrypt_cf.insert("accounts".to_string(), true);
        encrypt_cf.insert("storage".to_string(), true);
        encrypt_cf.insert("code".to_string(), true);
        encrypt_cf.insert("models".to_string(), true);
        encrypt_cf.insert("training".to_string(), true);
        // Metadata and indexes may be encrypted for full protection
        encrypt_cf.insert("metadata".to_string(), true);
        encrypt_cf.insert("blue_set".to_string(), false); // DAG data, less sensitive
        encrypt_cf.insert("dag_relations".to_string(), false);

        Self {
            enabled: true,
            encrypt_column_families: encrypt_cf,
            key_rotation_interval: 90 * 24 * 60 * 60, // 90 days
            node_id: "default-node".to_string(),
            security_level: SecurityLevelConfig {
                blocks: "High".to_string(),
                transactions: "High".to_string(),
                state: "High".to_string(),
                models: "Maximum".to_string(),
            },
            compress_before_encrypt: true,
        }
    }
}

/// Per-column-family encryption key
#[derive(Clone)]
pub struct ColumnFamilyKey {
    /// The derived key
    key: DerivedKey,
    /// Column family name
    pub column_family: String,
    /// Encryption envelope for this CF
    envelope: Arc<RwLock<CryptoAgileEnvelope>>,
}

impl ColumnFamilyKey {
    fn new(key: DerivedKey, column_family: String) -> Self {
        let envelope = CryptoAgileEnvelope::new(key.clone());
        Self {
            key,
            column_family,
            envelope: Arc::new(RwLock::new(envelope)),
        }
    }

    /// Rotate the key
    pub fn rotate(&self, new_key: DerivedKey) {
        let mut envelope = self.envelope.write().unwrap_or_else(|e| e.into_inner());
        envelope.rotate_key(new_key);
    }
}

impl std::fmt::Debug for ColumnFamilyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ColumnFamilyKey")
            .field("column_family", &self.column_family)
            .field("key_version", &self.key.version)
            .finish()
    }
}

/// Encrypted value wrapper
#[derive(Debug, Clone)]
pub struct EncryptedValue {
    /// Raw encrypted bytes (envelope format)
    pub data: Vec<u8>,
}

impl EncryptedValue {
    /// Check if this value is encrypted (has QSSP header)
    pub fn is_encrypted(data: &[u8]) -> bool {
        data.len() >= 4 && &data[0..4] == b"QSSP"
    }

    /// Get the key version used for encryption
    pub fn key_version(&self) -> Option<u32> {
        if !Self::is_encrypted(&self.data) {
            return None;
        }
        if self.data.len() < 9 {
            return None;
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&self.data[5..9]);
        Some(u32::from_be_bytes(buf))
    }
}

/// Decrypted value wrapper
#[derive(Debug, Clone)]
pub struct DecryptedValue {
    pub data: Vec<u8>,
}

/// Database encryption manager
pub struct EncryptedDatabase {
    /// Configuration
    config: DatabaseEncryptionConfig,
    /// Master key derivation
    kdf: MasterKeyDerivation,
    /// Master key (derived from password)
    master_key: Option<DerivedKey>,
    /// Per-column-family keys
    column_keys: RwLock<HashMap<String, ColumnFamilyKey>>,
    /// Key lifecycle manager
    lifecycle: RwLock<KeyLifecycleManager>,
    /// Statistics
    stats: RwLock<EncryptionStats>,
}

/// Encryption statistics
#[derive(Debug, Default, Clone)]
pub struct EncryptionStats {
    pub total_encryptions: u64,
    pub total_decryptions: u64,
    pub bytes_encrypted: u64,
    pub bytes_decrypted: u64,
    pub cache_hits: u64,
    pub reencryptions: u64,
    pub errors: u64,
}

impl EncryptedDatabase {
    /// Create a new encrypted database manager
    pub fn new(config: DatabaseEncryptionConfig) -> Self {
        let node_id_hash: [u8; 32] = Sha3_256::digest(config.node_id.as_bytes()).into();

        let kdf_params = KeyDerivationParams::high_security(Some(config.node_id.clone()));

        Self {
            config,
            kdf: MasterKeyDerivation::new(kdf_params),
            master_key: None,
            column_keys: RwLock::new(HashMap::new()),
            lifecycle: RwLock::new(KeyLifecycleManager::new(node_id_hash)),
            stats: RwLock::new(EncryptionStats::default()),
        }
    }

    /// Initialize with password/seed
    pub fn initialize(&mut self, password: &[u8]) -> Result<(), DatabaseEncryptionError> {
        if !self.config.enabled {
            return Ok(());
        }

        // Derive master key
        let master = self.kdf.derive_master_key(password)
            .map_err(|_| DatabaseEncryptionError::KeyDerivationFailed)?;

        // Register with lifecycle manager
        {
            let mut lifecycle = self.lifecycle.write().unwrap_or_else(|e| e.into_inner());
            lifecycle.register_key(master.key_bytes(), master.version, KeyPurpose::MasterKEK as u8);
        }

        // Derive column family keys
        let mut column_keys = self.column_keys.write().unwrap_or_else(|e| e.into_inner());
        for (cf_name, enabled) in &self.config.encrypt_column_families {
            if *enabled {
                let cf_key = self.kdf.derive_column_key(&master, cf_name)
                    .map_err(|_| DatabaseEncryptionError::KeyDerivationFailed)?;
                column_keys.insert(cf_name.clone(), ColumnFamilyKey::new(cf_key, cf_name.clone()));
            }
        }

        self.master_key = Some(master);
        Ok(())
    }

    /// Check if encryption is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled && self.master_key.is_some()
    }

    /// Check if a column family should be encrypted
    pub fn should_encrypt(&self, column_family: &str) -> bool {
        if !self.is_enabled() {
            return false;
        }
        self.config.encrypt_column_families
            .get(column_family)
            .copied()
            .unwrap_or(false)
    }

    /// Encrypt a value for storage
    pub fn encrypt(&self, column_family: &str, key: &[u8], value: &[u8]) -> Result<EncryptedValue, DatabaseEncryptionError> {
        if !self.should_encrypt(column_family) {
            // Return value as-is if encryption disabled for this CF
            return Ok(EncryptedValue { data: value.to_vec() });
        }

        let column_keys = self.column_keys.read().unwrap_or_else(|e| e.into_inner());
        let cf_key = column_keys.get(column_family)
            .ok_or(DatabaseEncryptionError::ColumnFamilyNotFound(column_family.to_string()))?;

        // Optionally compress before encryption
        let data_to_encrypt = if self.config.compress_before_encrypt {
            self.compress(value)?
        } else {
            value.to_vec()
        };

        // Build AAD from column family and key (reserved for future envelope AAD binding)
        let _aad = self.build_aad(column_family, key);

        // Encrypt using envelope
        let envelope = cf_key.envelope.read().unwrap_or_else(|e| e.into_inner());
        let encrypted = envelope.encrypt(&data_to_encrypt, column_family)
            .map_err(|e| DatabaseEncryptionError::EncryptionFailed(e.to_string()))?;

        // Update stats
        {
            let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
            stats.total_encryptions += 1;
            stats.bytes_encrypted += value.len() as u64;
        }

        Ok(EncryptedValue { data: encrypted })
    }

    /// Decrypt a value from storage
    pub fn decrypt(&self, column_family: &str, _key: &[u8], encrypted: &[u8]) -> Result<DecryptedValue, DatabaseEncryptionError> {
        // Check if this is actually encrypted
        if !EncryptedValue::is_encrypted(encrypted) {
            // Not encrypted, return as-is
            return Ok(DecryptedValue { data: encrypted.to_vec() });
        }

        if !self.should_encrypt(column_family) {
            return Ok(DecryptedValue { data: encrypted.to_vec() });
        }

        let column_keys = self.column_keys.read().unwrap_or_else(|e| e.into_inner());
        let cf_key = column_keys.get(column_family)
            .ok_or(DatabaseEncryptionError::ColumnFamilyNotFound(column_family.to_string()))?;

        // Decrypt using envelope
        let envelope = cf_key.envelope.read().unwrap_or_else(|e| e.into_inner());
        let decrypted = envelope.decrypt(encrypted)
            .map_err(|e| DatabaseEncryptionError::DecryptionFailed(e.to_string()))?;

        // Decompress if needed
        let data = if self.config.compress_before_encrypt {
            self.decompress(&decrypted)?
        } else {
            decrypted
        };

        // Update stats
        {
            let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
            stats.total_decryptions += 1;
            stats.bytes_decrypted += data.len() as u64;
        }

        Ok(DecryptedValue { data })
    }

    /// Rotate keys for a column family
    pub fn rotate_column_key(&self, column_family: &str, new_password: &[u8]) -> Result<KeyRotationProof, DatabaseEncryptionError> {
        let master = self.master_key.as_ref()
            .ok_or(DatabaseEncryptionError::NotInitialized)?;

        // Derive new master key
        let new_master = self.kdf.derive_master_key(new_password)
            .map_err(|_| DatabaseEncryptionError::KeyDerivationFailed)?;

        // Derive new column key
        let new_cf_key = self.kdf.derive_column_key(&new_master, column_family)
            .map_err(|_| DatabaseEncryptionError::KeyDerivationFailed)?;

        // Create rotation proof
        let mut lifecycle = self.lifecycle.write().unwrap_or_else(|e| e.into_inner());
        let (_, proof) = lifecycle.rotate_key(
            master.key_bytes(),
            new_cf_key.key_bytes(),
            new_cf_key.version,
            KeyPurpose::StateEncryption as u8,
            RotationReason::Scheduled,
        ).map_err(|_| DatabaseEncryptionError::RotationFailed)?;

        // Update column key
        let mut column_keys = self.column_keys.write().unwrap_or_else(|e| e.into_inner());
        if let Some(cf_key) = column_keys.get(column_family) {
            cf_key.rotate(new_cf_key.clone());
        } else {
            column_keys.insert(column_family.to_string(), ColumnFamilyKey::new(new_cf_key, column_family.to_string()));
        }

        Ok(proof)
    }

    /// Check if data needs re-encryption (old key version)
    pub fn needs_reencryption(&self, column_family: &str, encrypted: &[u8]) -> bool {
        if !EncryptedValue::is_encrypted(encrypted) {
            return false;
        }

        let column_keys = self.column_keys.read().unwrap_or_else(|e| e.into_inner());
        if let Some(cf_key) = column_keys.get(column_family) {
            let envelope = cf_key.envelope.read().unwrap_or_else(|e| e.into_inner());
            envelope.needs_reencryption(encrypted)
        } else {
            false
        }
    }

    /// Re-encrypt data with current key
    pub fn reencrypt(&self, column_family: &str, key: &[u8], encrypted: &[u8]) -> Result<EncryptedValue, DatabaseEncryptionError> {
        let decrypted = self.decrypt(column_family, key, encrypted)?;
        let reencrypted = self.encrypt(column_family, key, &decrypted.data)?;

        {
            let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
            stats.reencryptions += 1;
        }

        Ok(reencrypted)
    }

    /// Get encryption statistics
    pub fn get_stats(&self) -> EncryptionStats {
        self.stats.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Export key commitments for on-chain anchoring
    pub fn export_key_commitments(&self) -> Vec<KeyCommitment> {
        let lifecycle = self.lifecycle.read().unwrap_or_else(|e| e.into_inner());
        let trail = lifecycle.export_audit_trail();

        let mut commitments = Vec::new();
        if let Some(current) = trail.current_commitment {
            commitments.push(current);
        }
        commitments
    }

    /// Get rotation history
    pub fn get_rotation_history(&self) -> Vec<KeyRotationProof> {
        let lifecycle = self.lifecycle.read().unwrap_or_else(|e| e.into_inner());
        lifecycle.get_rotation_history().to_vec()
    }

    // ==================== Internal Methods ====================

    fn build_aad(&self, column_family: &str, key: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(column_family.len() + key.len() + 8);
        aad.extend_from_slice(column_family.as_bytes());
        aad.push(0x00); // Separator
        aad.extend_from_slice(key);
        aad
    }

    fn compress(&self, data: &[u8]) -> Result<Vec<u8>, DatabaseEncryptionError> {
        // Simple LZ4-style compression placeholder
        // In production, use lz4 or zstd crate
        // For now, just prepend a "not compressed" marker
        let mut result = Vec::with_capacity(data.len() + 1);
        result.push(0x00); // 0 = not compressed, 1 = LZ4, 2 = zstd
        result.extend_from_slice(data);
        Ok(result)
    }

    fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, DatabaseEncryptionError> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        let compression_type = data[0];
        match compression_type {
            0x00 => Ok(data[1..].to_vec()), // Not compressed
            0x01 => Err(DatabaseEncryptionError::CompressionNotSupported("LZ4".to_string())),
            0x02 => Err(DatabaseEncryptionError::CompressionNotSupported("zstd".to_string())),
            _ => Err(DatabaseEncryptionError::InvalidCompressionType(compression_type)),
        }
    }
}

/// Database encryption errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatabaseEncryptionError {
    NotInitialized,
    KeyDerivationFailed,
    EncryptionFailed(String),
    DecryptionFailed(String),
    ColumnFamilyNotFound(String),
    RotationFailed,
    CompressionNotSupported(String),
    InvalidCompressionType(u8),
}

impl std::fmt::Display for DatabaseEncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInitialized => write!(f, "Database encryption not initialized"),
            Self::KeyDerivationFailed => write!(f, "Key derivation failed"),
            Self::EncryptionFailed(e) => write!(f, "Encryption failed: {}", e),
            Self::DecryptionFailed(e) => write!(f, "Decryption failed: {}", e),
            Self::ColumnFamilyNotFound(cf) => write!(f, "Column family not found: {}", cf),
            Self::RotationFailed => write!(f, "Key rotation failed"),
            Self::CompressionNotSupported(alg) => write!(f, "Compression not supported: {}", alg),
            Self::InvalidCompressionType(t) => write!(f, "Invalid compression type: {}", t),
        }
    }
}

impl std::error::Error for DatabaseEncryptionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_database_roundtrip() {
        let config = DatabaseEncryptionConfig::default();
        let mut db = EncryptedDatabase::new(config);

        // Initialize with password
        db.initialize(b"test-password-123").unwrap();

        // Test encryption/decryption
        let cf = "state";
        let key = b"account:0x1234";
        let value = b"balance:1000000000000000000";

        let encrypted = db.encrypt(cf, key, value).unwrap();
        assert!(EncryptedValue::is_encrypted(&encrypted.data));

        let decrypted = db.decrypt(cf, key, &encrypted.data).unwrap();
        assert_eq!(decrypted.data, value);
    }

    #[test]
    fn test_unencrypted_column_family() {
        let mut config = DatabaseEncryptionConfig::default();
        config.encrypt_column_families.insert("dag_relations".to_string(), false);

        let mut db = EncryptedDatabase::new(config);
        db.initialize(b"password").unwrap();

        let cf = "dag_relations";
        let key = b"parent:0x1234";
        let value = b"children:[0x5678,0x9abc]";

        let result = db.encrypt(cf, key, value).unwrap();
        // Should NOT be encrypted
        assert!(!EncryptedValue::is_encrypted(&result.data));
        assert_eq!(result.data, value);
    }

    #[test]
    fn test_encryption_stats() {
        let config = DatabaseEncryptionConfig::default();
        let mut db = EncryptedDatabase::new(config);
        db.initialize(b"password").unwrap();

        // Perform some operations
        let encrypted = db.encrypt("blocks", b"key1", b"value1").unwrap();
        db.decrypt("blocks", b"key1", &encrypted.data).unwrap();

        let stats = db.get_stats();
        assert_eq!(stats.total_encryptions, 1);
        assert_eq!(stats.total_decryptions, 1);
    }

    #[test]
    fn test_needs_reencryption() {
        let config = DatabaseEncryptionConfig::default();
        let mut db = EncryptedDatabase::new(config);
        db.initialize(b"password").unwrap();

        let encrypted = db.encrypt("state", b"key", b"value").unwrap();

        // Immediately after encryption, should NOT need re-encryption
        assert!(!db.needs_reencryption("state", &encrypted.data));
    }

    #[test]
    fn test_model_encryption_highest_security() {
        let config = DatabaseEncryptionConfig::default();
        let mut db = EncryptedDatabase::new(config);
        db.initialize(b"secure-password").unwrap();

        // Model data should be encrypted
        assert!(db.should_encrypt("models"));

        let model_weights = vec![0u8; 1024]; // Simulated model weights
        let encrypted = db.encrypt("models", b"model:gpt-4", &model_weights).unwrap();

        assert!(EncryptedValue::is_encrypted(&encrypted.data));

        let decrypted = db.decrypt("models", b"model:gpt-4", &encrypted.data).unwrap();
        assert_eq!(decrypted.data, model_weights);
    }
}
