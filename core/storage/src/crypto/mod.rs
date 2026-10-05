// SPDX-License-Identifier: Apache-2.0
// Citrate Quantum-Safe Storage Protocol (QSSP)
//
// This module implements post-quantum cryptography for database encryption at rest.
// It provides defense against "Harvest Now, Decrypt Later" (HNDL) attacks by using
// hybrid classical + post-quantum encryption schemes.

pub mod at_rest;
mod bytes;
pub mod database_encryption;
pub mod envelope;
pub mod key_commitment;
pub mod key_derivation;
pub mod quantum_safe;

#[cfg(test)]
mod benchmarks;

pub use at_rest::{
    AtRestCipher, AtRestError, AtRestStats, EncryptionAtRestConfig, EncryptionKey, EncryptionMeta,
    KdfMeta, KeySource, PasswordKdf, ENCRYPTION_META_FILE,
};
pub use database_encryption::{
    ColumnFamilyKey, DatabaseEncryptionConfig, DecryptedValue, EncryptedDatabase, EncryptedValue,
};
pub use envelope::{CryptoAgileEnvelope, EncryptionEnvelope, EnvelopeHeader, EnvelopeVersion};
pub use key_commitment::{KeyCommitment, KeyLifecycleEvent, KeyRotationProof, OnChainKeyAnchor};
pub use key_derivation::{
    Argon2Params, DerivedKey, KeyDerivationParams, KeyPurpose, MasterKeyDerivation,
};
pub use quantum_safe::{
    HybridEncapsulation, HybridKEM, KeyEncapsulationMechanism, QuantumSafeConfig, SecurityLevel,
};

/// QSSP Protocol Version
pub const QSSP_VERSION: u8 = 1;

/// Magic bytes for encrypted data identification
pub const QSSP_MAGIC: [u8; 4] = [0x51, 0x53, 0x53, 0x50]; // "QSSP"

/// Supported post-quantum algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PQAlgorithm {
    /// CRYSTALS-Kyber (ML-KEM) - NIST standardized
    Kyber768,
    Kyber1024,
    /// Future: CRYSTALS-Dilithium for signatures
    Dilithium3,
    /// Future: SPHINCS+ for hash-based signatures
    SphincsSha2_256f,
}

/// Supported classical algorithms (for hybrid mode)
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ClassicalAlgorithm {
    /// X25519 ECDH
    X25519,
    /// Future: P-384 for higher security margin
    P384,
}

/// Symmetric encryption algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SymmetricAlgorithm {
    /// AES-256-GCM (AEAD)
    Aes256Gcm,
    /// ChaCha20-Poly1305 (AEAD, alternative)
    ChaCha20Poly1305,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert_eq!(QSSP_VERSION, 1);
        assert_eq!(&QSSP_MAGIC, b"QSSP");
    }
}
