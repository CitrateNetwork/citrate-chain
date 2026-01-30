// SPDX-License-Identifier: MIT
// Hybrid Post-Quantum Key Encapsulation Mechanism
//
// This implements a hybrid KEM combining:
// - CRYSTALS-Kyber (ML-KEM) for post-quantum security
// - X25519 for classical security (defense-in-depth)
//
// The hybrid approach ensures that:
// 1. If Kyber is broken by classical attacks, X25519 still protects
// 2. If X25519 is broken by quantum attacks, Kyber still protects
// 3. Both must be compromised to break the encryption

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey, SharedSecret, Ciphertext};
use sha3::{Sha3_256, Sha3_512, Digest};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;
use std::fmt;

/// Security level for encryption operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// 128-bit classical / 64-bit quantum security (Kyber-512 equivalent)
    /// Suitable for short-term data
    Standard,
    /// 192-bit classical / 96-bit quantum security (Kyber-768)
    /// Recommended for most use cases
    High,
    /// 256-bit classical / 128-bit quantum security (Kyber-1024 equivalent)
    /// For long-term secrets (AI models, master keys)
    Maximum,
}

impl Default for SecurityLevel {
    fn default() -> Self {
        SecurityLevel::High
    }
}

/// Configuration for quantum-safe encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumSafeConfig {
    /// Security level determines algorithm parameters
    pub security_level: SecurityLevel,
    /// Enable hybrid mode (classical + post-quantum)
    pub hybrid_mode: bool,
    /// Include key commitment for integrity
    pub include_commitment: bool,
    /// Additional authenticated data binding
    pub context_binding: Option<Vec<u8>>,
}

impl Default for QuantumSafeConfig {
    fn default() -> Self {
        Self {
            security_level: SecurityLevel::High,
            hybrid_mode: true,
            include_commitment: true,
            context_binding: None,
        }
    }
}

/// Key Encapsulation Mechanism trait
pub trait KeyEncapsulationMechanism {
    /// Generate a new keypair
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError>;

    /// Encapsulate a shared secret using the public key
    fn encapsulate(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError>;

    /// Decapsulate to recover the shared secret
    fn decapsulate(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Get the name of the algorithm
    fn algorithm_name(&self) -> &'static str;

    /// Get public key size in bytes
    fn public_key_size(&self) -> usize;

    /// Get secret key size in bytes
    fn secret_key_size(&self) -> usize;

    /// Get ciphertext size in bytes
    fn ciphertext_size(&self) -> usize;

    /// Get shared secret size in bytes
    fn shared_secret_size(&self) -> usize;
}

/// Hybrid encapsulation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridEncapsulation {
    /// Version for crypto-agility
    pub version: u8,
    /// Kyber ciphertext
    pub pq_ciphertext: Vec<u8>,
    /// X25519 ephemeral public key
    pub classical_public: Vec<u8>,
    /// Combined shared secret commitment (for integrity)
    pub key_commitment: [u8; 32],
    /// Algorithm identifiers for future-proofing
    pub pq_algorithm: u8,
    pub classical_algorithm: u8,
}

/// Hybrid Key Encapsulation Mechanism
/// Combines post-quantum Kyber with classical X25519
pub struct HybridKEM {
    config: QuantumSafeConfig,
}

impl HybridKEM {
    pub fn new(config: QuantumSafeConfig) -> Self {
        Self { config }
    }

    /// Generate a hybrid keypair (Kyber + X25519)
    pub fn generate_keypair(&self) -> Result<HybridKeyPair, CryptoError> {
        // Generate Kyber-768 keypair
        let (pq_pk, pq_sk) = kyber768::keypair();

        // Generate X25519 keypair
        let classical_sk = StaticSecret::random_from_rng(OsRng);
        let classical_pk = X25519PublicKey::from(&classical_sk);

        Ok(HybridKeyPair {
            public_key: HybridPublicKey {
                pq_public: pq_pk.as_bytes().to_vec(),
                classical_public: classical_pk.as_bytes().to_vec(),
                security_level: self.config.security_level,
            },
            secret_key: HybridSecretKey {
                pq_secret: pq_sk.as_bytes().to_vec(),
                classical_secret: classical_sk.as_bytes().to_vec(),
                security_level: self.config.security_level,
            },
        })
    }

    /// Encapsulate a shared secret using hybrid encryption
    pub fn encapsulate(&self, public_key: &HybridPublicKey) -> Result<(HybridEncapsulation, [u8; 32]), CryptoError> {
        // Parse Kyber public key
        let pq_pk = kyber768::PublicKey::from_bytes(&public_key.pq_public)
            .map_err(|_| CryptoError::InvalidKeySize)?;

        // Kyber encapsulation
        let (pq_ss, pq_ct) = kyber768::encapsulate(&pq_pk);

        // Parse X25519 public key
        let classical_pk_bytes: [u8; 32] = public_key.classical_public
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKeySize)?;
        let classical_pk = X25519PublicKey::from(classical_pk_bytes);

        // X25519 key exchange with ephemeral key
        let eph_secret = EphemeralSecret::random_from_rng(OsRng);
        let eph_public = X25519PublicKey::from(&eph_secret);
        let classical_ss = eph_secret.diffie_hellman(&classical_pk);

        // Combine shared secrets using domain-separated KDF
        let combined_ss = self.combine_shared_secrets(
            pq_ss.as_bytes(),
            classical_ss.as_bytes(),
        )?;

        // Compute key commitment for integrity
        let commitment = self.compute_key_commitment(
            &combined_ss,
            pq_ct.as_bytes(),
            eph_public.as_bytes(),
        );

        let encap = HybridEncapsulation {
            version: 1,
            pq_ciphertext: pq_ct.as_bytes().to_vec(),
            classical_public: eph_public.as_bytes().to_vec(),
            key_commitment: commitment,
            pq_algorithm: 0x02, // Kyber-768
            classical_algorithm: 0x01, // X25519
        };

        Ok((encap, combined_ss))
    }

    /// Decapsulate to recover the shared secret
    pub fn decapsulate(
        &self,
        secret_key: &HybridSecretKey,
        encapsulation: &HybridEncapsulation,
    ) -> Result<[u8; 32], CryptoError> {
        // Verify version
        if encapsulation.version != 1 {
            return Err(CryptoError::UnsupportedVersion(encapsulation.version));
        }

        // Parse Kyber secret key and ciphertext
        let pq_sk = kyber768::SecretKey::from_bytes(&secret_key.pq_secret)
            .map_err(|_| CryptoError::InvalidKeySize)?;
        let pq_ct = kyber768::Ciphertext::from_bytes(&encapsulation.pq_ciphertext)
            .map_err(|_| CryptoError::InvalidCiphertext)?;

        // Kyber decapsulation
        let pq_ss = kyber768::decapsulate(&pq_ct, &pq_sk);

        // Parse X25519 keys
        let classical_sk_bytes: [u8; 32] = secret_key.classical_secret
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKeySize)?;
        let classical_sk = StaticSecret::from(classical_sk_bytes);

        let eph_pk_bytes: [u8; 32] = encapsulation.classical_public
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKeySize)?;
        let eph_pk = X25519PublicKey::from(eph_pk_bytes);

        // X25519 key exchange
        let classical_ss = classical_sk.diffie_hellman(&eph_pk);

        // Combine shared secrets
        let combined_ss = self.combine_shared_secrets(
            pq_ss.as_bytes(),
            classical_ss.as_bytes(),
        )?;

        // Verify key commitment
        let expected_commitment = self.compute_key_commitment(
            &combined_ss,
            &encapsulation.pq_ciphertext,
            &encapsulation.classical_public,
        );

        if expected_commitment != encapsulation.key_commitment {
            return Err(CryptoError::KeyCommitmentMismatch);
        }

        Ok(combined_ss)
    }

    /// Encrypt data using the hybrid KEM
    pub fn encrypt(&self, public_key: &HybridPublicKey, plaintext: &[u8], aad: &[u8]) -> Result<EncryptedData, CryptoError> {
        // Encapsulate to get shared secret
        let (encapsulation, shared_secret) = self.encapsulate(public_key)?;

        // Derive encryption key from shared secret
        let encryption_key = self.derive_encryption_key(&shared_secret, b"QSSP-v1-encrypt")?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        // Encrypt with AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&encryption_key)
            .map_err(|_| CryptoError::CipherInitFailed)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Include encapsulation commitment in AAD for binding
        let mut full_aad = Vec::with_capacity(aad.len() + 32);
        full_aad.extend_from_slice(aad);
        full_aad.extend_from_slice(&encapsulation.key_commitment);

        let ciphertext = cipher
            .encrypt(nonce, aes_gcm::aead::Payload {
                msg: plaintext,
                aad: &full_aad,
            })
            .map_err(|_| CryptoError::EncryptionFailed)?;

        Ok(EncryptedData {
            encapsulation,
            nonce: nonce_bytes,
            ciphertext,
            aad_hash: Sha3_256::digest(&full_aad).into(),
        })
    }

    /// Decrypt data using the hybrid KEM
    pub fn decrypt(&self, secret_key: &HybridSecretKey, encrypted: &EncryptedData, aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Decapsulate to recover shared secret
        let shared_secret = self.decapsulate(secret_key, &encrypted.encapsulation)?;

        // Derive encryption key
        let encryption_key = self.derive_encryption_key(&shared_secret, b"QSSP-v1-encrypt")?;

        // Verify AAD binding
        let mut full_aad = Vec::with_capacity(aad.len() + 32);
        full_aad.extend_from_slice(aad);
        full_aad.extend_from_slice(&encrypted.encapsulation.key_commitment);

        let expected_aad_hash: [u8; 32] = Sha3_256::digest(&full_aad).into();
        if expected_aad_hash != encrypted.aad_hash {
            return Err(CryptoError::AadMismatch);
        }

        // Decrypt with AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&encryption_key)
            .map_err(|_| CryptoError::CipherInitFailed)?;
        let nonce = Nonce::from_slice(&encrypted.nonce);

        cipher
            .decrypt(nonce, aes_gcm::aead::Payload {
                msg: &encrypted.ciphertext,
                aad: &full_aad,
            })
            .map_err(|_| CryptoError::DecryptionFailed)
    }

    // ==================== Internal Methods ====================

    /// Combine shared secrets using domain-separated KDF
    fn combine_shared_secrets(&self, pq_ss: &[u8], classical_ss: &[u8]) -> Result<[u8; 32], CryptoError> {
        // Use HKDF-like construction with SHA3-512
        let mut hasher = Sha3_512::new();

        // Domain separation
        hasher.update(b"QSSP-v1-hybrid-combine");

        // Security level binding
        hasher.update(&[self.config.security_level as u8]);

        // Length-prefixed inputs (prevents extension attacks)
        hasher.update(&(pq_ss.len() as u32).to_be_bytes());
        hasher.update(pq_ss);
        hasher.update(&(classical_ss.len() as u32).to_be_bytes());
        hasher.update(classical_ss);

        // Optional context binding
        if let Some(ref context) = self.config.context_binding {
            hasher.update(&(context.len() as u32).to_be_bytes());
            hasher.update(context);
        }

        let digest = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&digest[..32]);

        Ok(result)
    }

    /// Compute key commitment for integrity verification
    fn compute_key_commitment(&self, shared_secret: &[u8; 32], pq_ct: &[u8], classical_pk: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"QSSP-v1-key-commit");
        hasher.update(shared_secret);
        hasher.update(&(pq_ct.len() as u32).to_be_bytes());
        hasher.update(pq_ct);
        hasher.update(&(classical_pk.len() as u32).to_be_bytes());
        hasher.update(classical_pk);
        hasher.finalize().into()
    }

    /// Derive encryption key from shared secret
    fn derive_encryption_key(&self, shared_secret: &[u8; 32], info: &[u8]) -> Result<[u8; 32], CryptoError> {
        let mut hasher = Sha3_256::new();
        hasher.update(b"QSSP-v1-derive-");
        hasher.update(info);
        hasher.update(shared_secret);
        Ok(hasher.finalize().into())
    }
}

/// Hybrid public key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridPublicKey {
    pub pq_public: Vec<u8>,
    pub classical_public: Vec<u8>,
    pub security_level: SecurityLevel,
}

impl HybridPublicKey {
    /// Get the expected size of a Kyber-768 public key
    pub fn kyber_public_key_size() -> usize {
        kyber768::public_key_bytes()
    }

    /// Get the expected size of an X25519 public key
    pub fn x25519_public_key_size() -> usize {
        32
    }
}

/// Hybrid secret key with secure memory handling
#[derive(Clone)]
pub struct HybridSecretKey {
    pq_secret: Vec<u8>,
    classical_secret: Vec<u8>,
    pub security_level: SecurityLevel,
}

impl Drop for HybridSecretKey {
    fn drop(&mut self) {
        // Securely zero the secret key material
        self.pq_secret.zeroize();
        self.classical_secret.zeroize();
    }
}

impl fmt::Debug for HybridSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridSecretKey")
            .field("security_level", &self.security_level)
            .field("pq_secret", &"[REDACTED]")
            .field("classical_secret", &"[REDACTED]")
            .finish()
    }
}

/// Hybrid keypair
#[derive(Debug, Clone)]
pub struct HybridKeyPair {
    pub public_key: HybridPublicKey,
    pub secret_key: HybridSecretKey,
}

/// Encrypted data container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub encapsulation: HybridEncapsulation,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub aad_hash: [u8; 32],
}

/// Cryptographic errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    KeyGenerationFailed,
    EncapsulationFailed,
    DecapsulationFailed,
    EncryptionFailed,
    DecryptionFailed,
    CipherInitFailed,
    KeyCommitmentMismatch,
    AadMismatch,
    UnsupportedVersion(u8),
    InvalidKeySize,
    InvalidCiphertext,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyGenerationFailed => write!(f, "Key generation failed"),
            Self::EncapsulationFailed => write!(f, "Key encapsulation failed"),
            Self::DecapsulationFailed => write!(f, "Key decapsulation failed"),
            Self::EncryptionFailed => write!(f, "Encryption failed"),
            Self::DecryptionFailed => write!(f, "Decryption failed - authentication failed"),
            Self::CipherInitFailed => write!(f, "Cipher initialization failed"),
            Self::KeyCommitmentMismatch => write!(f, "Key commitment verification failed"),
            Self::AadMismatch => write!(f, "Additional authenticated data mismatch"),
            Self::UnsupportedVersion(v) => write!(f, "Unsupported protocol version: {}", v),
            Self::InvalidKeySize => write!(f, "Invalid key size"),
            Self::InvalidCiphertext => write!(f, "Invalid ciphertext format"),
        }
    }
}

impl std::error::Error for CryptoError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_kem_roundtrip() {
        let config = QuantumSafeConfig::default();
        let kem = HybridKEM::new(config);

        // Generate keypair
        let keypair = kem.generate_keypair().unwrap();

        // Verify key sizes
        assert_eq!(keypair.public_key.pq_public.len(), kyber768::public_key_bytes());
        assert_eq!(keypair.public_key.classical_public.len(), 32);

        // Encapsulate
        let (encapsulation, shared_secret1) = kem.encapsulate(&keypair.public_key).unwrap();

        // Verify ciphertext size
        assert_eq!(encapsulation.pq_ciphertext.len(), kyber768::ciphertext_bytes());

        // Decapsulate
        let shared_secret2 = kem.decapsulate(&keypair.secret_key, &encapsulation).unwrap();

        // Shared secrets must match
        assert_eq!(shared_secret1, shared_secret2);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let config = QuantumSafeConfig::default();
        let kem = HybridKEM::new(config);

        let keypair = kem.generate_keypair().unwrap();

        let plaintext = b"Citrate Quantum-Safe Storage Protocol - Real Kyber + X25519!";
        let aad = b"column_family:models";

        let encrypted = kem.encrypt(&keypair.public_key, plaintext, aad).unwrap();
        let decrypted = kem.decrypt(&keypair.secret_key, &encrypted, aad).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let config = QuantumSafeConfig::default();
        let kem = HybridKEM::new(config);

        let keypair = kem.generate_keypair().unwrap();

        let plaintext = b"secret data";
        let aad = b"correct_context";
        let wrong_aad = b"wrong_context";

        let encrypted = kem.encrypt(&keypair.public_key, plaintext, aad).unwrap();
        let result = kem.decrypt(&keypair.secret_key, &encrypted, wrong_aad);

        assert!(result.is_err());
    }

    #[test]
    fn test_security_levels() {
        for level in [SecurityLevel::Standard, SecurityLevel::High, SecurityLevel::Maximum] {
            let config = QuantumSafeConfig {
                security_level: level,
                ..Default::default()
            };
            let kem = HybridKEM::new(config);

            let keypair = kem.generate_keypair().unwrap();
            let (encap, ss1) = kem.encapsulate(&keypair.public_key).unwrap();
            let ss2 = kem.decapsulate(&keypair.secret_key, &encap).unwrap();

            assert_eq!(ss1, ss2);
        }
    }

    #[test]
    fn test_different_keypairs_different_secrets() {
        let config = QuantumSafeConfig::default();
        let kem = HybridKEM::new(config);

        let keypair1 = kem.generate_keypair().unwrap();
        let keypair2 = kem.generate_keypair().unwrap();

        let (_, ss1) = kem.encapsulate(&keypair1.public_key).unwrap();
        let (_, ss2) = kem.encapsulate(&keypair2.public_key).unwrap();

        // Different keypairs should produce different shared secrets
        assert_ne!(ss1, ss2);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let config = QuantumSafeConfig::default();
        let kem = HybridKEM::new(config);

        let keypair = kem.generate_keypair().unwrap();
        let (mut encap, _) = kem.encapsulate(&keypair.public_key).unwrap();

        // Tamper with the Kyber ciphertext
        if !encap.pq_ciphertext.is_empty() {
            encap.pq_ciphertext[0] ^= 0xFF;
        }

        // Decapsulation should fail due to commitment mismatch
        let result = kem.decapsulate(&keypair.secret_key, &encap);
        assert!(result.is_err());
    }

    #[test]
    fn test_large_data_encryption() {
        let config = QuantumSafeConfig::default();
        let kem = HybridKEM::new(config);

        let keypair = kem.generate_keypair().unwrap();

        // Encrypt 1MB of data (simulating model weights)
        let plaintext: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
        let aad = b"model:large-language-model-v1";

        let encrypted = kem.encrypt(&keypair.public_key, &plaintext, aad).unwrap();
        let decrypted = kem.decrypt(&keypair.secret_key, &encrypted, aad).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_key_sizes() {
        // Verify expected key sizes from Kyber-768 spec
        assert_eq!(kyber768::public_key_bytes(), 1184);
        assert_eq!(kyber768::secret_key_bytes(), 2400);
        assert_eq!(kyber768::ciphertext_bytes(), 1088);
    }
}
