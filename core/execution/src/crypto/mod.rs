// citrate/core/execution/src/crypto/mod.rs

// Cryptography module for secure model storage and privacy-preserving inference

pub mod ecdh;
pub mod encryption;
pub mod key_manager;
pub mod secure_enclave;
pub mod shamir;

pub use encryption::{
    decrypt_model, encrypt_model, EncryptedKey, EncryptedModel, EncryptionConfig,
    EncryptionMetadata, ModelEncryption, RecipientPublicKeys,
};

pub use key_manager::{AccessPolicy, DerivedKey, KeyManager, KeyPurpose};

#[cfg(target_os = "macos")]
pub use secure_enclave::{AppleSecureEnclave, Attestation, SecureEnclaveInterface};
