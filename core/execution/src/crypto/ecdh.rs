// citrate/core/execution/src/crypto/ecdh.rs

//! ECDH key exchange using secp256k1 (k256 crate)
//!
//! Implements ECIES (Elliptic Curve Integrated Encryption Scheme) with:
//! - k256 for real secp256k1 EC point multiplication
//! - HKDF-SHA256 for key derivation
//! - AES-256-GCM for authenticated encryption
//!
//! Migration note: This replaces the previous XOR-based placeholder.
//! Any data encrypted with the old scheme is unrecoverable and must be re-encrypted.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use k256::{
    ecdh::EphemeralSecret,
    elliptic_curve::sec1::ToEncodedPoint,
    PublicKey, SecretKey,
};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// ECIES (Elliptic Curve Integrated Encryption Scheme) implementation
/// Uses secp256k1 curve for compatibility with Ethereum
pub struct ECIES {
    /// Private key (32 bytes)
    private_key: [u8; 32],
    /// Public key (compressed, 33 bytes)
    public_key: [u8; 33],
}

/// Encrypted message with ECIES
#[derive(Debug, Clone)]
pub struct ECIESMessage {
    /// Ephemeral public key
    pub ephemeral_pubkey: [u8; 33],
    /// Encrypted data
    pub ciphertext: Vec<u8>,
    /// Authentication tag
    pub auth_tag: [u8; 16],
    /// Nonce for AES-GCM
    pub nonce: [u8; 12],
}

impl ECIES {
    /// Generate new ECIES keypair using k256
    pub fn generate() -> Result<Self> {
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key_point = secret_key.public_key();

        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&secret_key.to_bytes());

        let compressed = public_key_point.to_encoded_point(true);
        let mut public_key = [0u8; 33];
        public_key.copy_from_slice(compressed.as_bytes());

        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Create ECIES from existing private key
    pub fn from_private_key(private_key: [u8; 32]) -> Result<Self> {
        let public_key = Self::derive_public_key(&private_key)?;
        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Get public key
    pub fn public_key(&self) -> [u8; 33] {
        self.public_key
    }

    /// Encrypt data for a recipient
    pub fn encrypt(&self, data: &[u8], recipient_pubkey: &[u8; 33]) -> Result<ECIESMessage> {
        // Generate ephemeral keypair for this message
        let ephemeral = Self::generate()?;

        // Perform ECDH to get shared secret
        let shared_secret = Self::ecdh(&ephemeral.private_key, recipient_pubkey)?;

        // Derive encryption key using HKDF
        let (enc_key, _mac_key) = Self::derive_keys(&shared_secret)?;

        // Generate random nonce
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        // Encrypt with AES-256-GCM
        let cipher = Aes256Gcm::new(Key::from_slice(&enc_key));
        let aes_nonce = Nonce::from_slice(&nonce);

        // Add associated data for authentication
        let associated_data = [&ephemeral.public_key[..], recipient_pubkey].concat();

        let encrypted_data = cipher
            .encrypt(
                aes_nonce,
                aes_gcm::aead::Payload {
                    msg: data,
                    aad: &associated_data,
                },
            )
            .map_err(|e| anyhow!("AES encryption failed: {:?}", e))?;

        // Split ciphertext and auth tag
        if encrypted_data.len() < 16 {
            return Err(anyhow!("Invalid encrypted data length"));
        }

        let (ciphertext, tag_bytes) = encrypted_data.split_at(encrypted_data.len() - 16);
        let mut auth_tag = [0u8; 16];
        auth_tag.copy_from_slice(tag_bytes);

        Ok(ECIESMessage {
            ephemeral_pubkey: ephemeral.public_key,
            ciphertext: ciphertext.to_vec(),
            auth_tag,
            nonce,
        })
    }

    /// Decrypt data from sender
    pub fn decrypt(&self, message: &ECIESMessage) -> Result<Vec<u8>> {
        // Perform ECDH with ephemeral public key
        let shared_secret = Self::ecdh(&self.private_key, &message.ephemeral_pubkey)?;

        // Derive same keys
        let (enc_key, _mac_key) = Self::derive_keys(&shared_secret)?;

        // Reconstruct full ciphertext with auth tag
        let mut full_ciphertext = message.ciphertext.clone();
        full_ciphertext.extend_from_slice(&message.auth_tag);

        // Decrypt with AES-256-GCM
        let cipher = Aes256Gcm::new(Key::from_slice(&enc_key));
        let aes_nonce = Nonce::from_slice(&message.nonce);

        // Reconstruct associated data
        let associated_data = [&message.ephemeral_pubkey[..], &self.public_key[..]].concat();

        let decrypted = cipher
            .decrypt(
                aes_nonce,
                aes_gcm::aead::Payload {
                    msg: &full_ciphertext,
                    aad: &associated_data,
                },
            )
            .map_err(|e| anyhow!("AES decryption failed: {:?}", e))?;

        Ok(decrypted)
    }

    /// Perform real ECDH key exchange using k256 (secp256k1)
    fn ecdh(private_key: &[u8; 32], public_key: &[u8; 33]) -> Result<[u8; 32]> {
        let sk = SecretKey::from_slice(private_key)
            .map_err(|e| anyhow!("Invalid private key: {}", e))?;
        let pk = PublicKey::from_sec1_bytes(public_key)
            .map_err(|e| anyhow!("Invalid public key: {}", e))?;

        // Real elliptic curve Diffie-Hellman: shared_point = sk * pk
        let shared_secret = k256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());

        let mut result = [0u8; 32];
        result.copy_from_slice(shared_secret.raw_secret_bytes().as_slice());
        Ok(result)
    }

    /// Derive encryption and MAC keys from shared secret using HKDF-SHA256
    fn derive_keys(shared_secret: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
        // HKDF-Extract
        let mut mac = HmacSha256::new_from_slice(b"CITRATE_ECIES_SALT")
            .map_err(|e| anyhow!("HMAC init failed: {}", e))?;
        mac.update(shared_secret);
        let prk = mac.finalize().into_bytes();

        // HKDF-Expand for encryption key
        let mut mac_enc = HmacSha256::new_from_slice(&prk)
            .map_err(|e| anyhow!("HMAC init failed: {}", e))?;
        mac_enc.update(b"CITRATE_ENC_KEY");
        mac_enc.update(&[0x01]);
        let enc_key_bytes = mac_enc.finalize().into_bytes();

        // HKDF-Expand for MAC key
        let mut mac_auth = HmacSha256::new_from_slice(&prk)
            .map_err(|e| anyhow!("HMAC init failed: {}", e))?;
        mac_auth.update(b"CITRATE_MAC_KEY");
        mac_auth.update(&[0x02]);
        let mac_key_bytes = mac_auth.finalize().into_bytes();

        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        enc_key.copy_from_slice(&enc_key_bytes);
        mac_key.copy_from_slice(&mac_key_bytes);

        Ok((enc_key, mac_key))
    }

    /// Derive public key from private key using real secp256k1 point multiplication
    fn derive_public_key(private_key: &[u8; 32]) -> Result<[u8; 33]> {
        let sk = SecretKey::from_slice(private_key)
            .map_err(|e| anyhow!("Invalid private key for pubkey derivation: {}", e))?;
        let pk = sk.public_key();
        let compressed = pk.to_encoded_point(true);
        let mut public_key = [0u8; 33];
        public_key.copy_from_slice(compressed.as_bytes());
        Ok(public_key)
    }

    /// Validate public key by attempting to decode it on the secp256k1 curve
    pub fn validate_public_key(pubkey: &[u8; 33]) -> bool {
        PublicKey::from_sec1_bytes(pubkey).is_ok()
    }

    /// Convert to hex string for debugging
    pub fn to_hex(&self) -> String {
        hex::encode(self.public_key)
    }
}

/// Secure key exchange for model encryption
pub struct ModelKeyExchange {
    ecies: ECIES,
}

impl ModelKeyExchange {
    /// Create new key exchange instance
    pub fn new() -> Result<Self> {
        Ok(Self {
            ecies: ECIES::generate()?,
        })
    }

    /// Get public key for sharing
    pub fn public_key(&self) -> [u8; 33] {
        self.ecies.public_key()
    }

    /// Encrypt symmetric key for recipient
    pub fn encrypt_key_for_recipient(
        &self,
        symmetric_key: &[u8; 32],
        recipient_pubkey: &[u8; 33],
    ) -> Result<ECIESMessage> {
        self.ecies.encrypt(symmetric_key, recipient_pubkey)
    }

    /// Decrypt symmetric key from sender
    pub fn decrypt_key_from_sender(&self, message: &ECIESMessage) -> Result<[u8; 32]> {
        let decrypted = self.ecies.decrypt(message)?;
        if decrypted.len() != 32 {
            return Err(anyhow!("Invalid symmetric key length"));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&decrypted);
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecies_roundtrip() {
        let alice = ECIES::generate().unwrap();
        let bob = ECIES::generate().unwrap();

        let message = b"Hello, secure world!";

        // Alice encrypts for Bob
        let encrypted = alice.encrypt(message, &bob.public_key()).unwrap();

        // Bob decrypts Alice's message
        let decrypted = bob.decrypt(&encrypted).unwrap();

        assert_eq!(message, decrypted.as_slice());
    }

    #[test]
    fn test_cross_party_shared_secret() {
        // Verify that alice(priv) * bob(pub) == bob(priv) * alice(pub)
        let alice = ECIES::generate().unwrap();
        let bob = ECIES::generate().unwrap();

        let secret_ab = ECIES::ecdh(&alice.private_key, &bob.public_key()).unwrap();
        let secret_ba = ECIES::ecdh(&bob.private_key, &alice.public_key()).unwrap();

        assert_eq!(
            secret_ab, secret_ba,
            "ECDH shared secrets must be identical regardless of direction"
        );
    }

    #[test]
    fn test_different_keys_different_secrets() {
        let alice = ECIES::generate().unwrap();
        let bob = ECIES::generate().unwrap();
        let charlie = ECIES::generate().unwrap();

        let secret_ab = ECIES::ecdh(&alice.private_key, &bob.public_key()).unwrap();
        let secret_ac = ECIES::ecdh(&alice.private_key, &charlie.public_key()).unwrap();

        assert_ne!(
            secret_ab, secret_ac,
            "Different key pairs must produce different shared secrets"
        );
    }

    #[test]
    fn test_invalid_key_rejection() {
        let alice = ECIES::generate().unwrap();

        // Invalid public key (all zeros with 0x02 prefix is not a valid curve point)
        let mut invalid_pubkey = [0u8; 33];
        invalid_pubkey[0] = 0x02;
        let result = ECIES::ecdh(&alice.private_key, &invalid_pubkey);
        assert!(result.is_err(), "Should reject invalid public key");

        // Invalid prefix
        let mut bad_prefix_key = [0x05; 33];
        bad_prefix_key[0] = 0x05;
        let result = ECIES::ecdh(&alice.private_key, &bad_prefix_key);
        assert!(result.is_err(), "Should reject key with invalid prefix");
    }

    #[test]
    fn test_validate_public_key_real_curve() {
        let ecies = ECIES::generate().unwrap();
        assert!(
            ECIES::validate_public_key(&ecies.public_key()),
            "Generated public key must validate"
        );

        // Random bytes with valid prefix are NOT valid curve points
        let mut fake_key = [0x42; 33];
        fake_key[0] = 0x02;
        assert!(
            !ECIES::validate_public_key(&fake_key),
            "Random bytes should not be valid curve points"
        );
    }

    #[test]
    fn test_key_exchange() {
        let alice_kx = ModelKeyExchange::new().unwrap();
        let bob_kx = ModelKeyExchange::new().unwrap();

        let symmetric_key = [42u8; 32];

        // Alice encrypts symmetric key for Bob
        let encrypted_key = alice_kx
            .encrypt_key_for_recipient(&symmetric_key, &bob_kx.public_key())
            .unwrap();

        // Bob decrypts symmetric key
        let decrypted_key = bob_kx.decrypt_key_from_sender(&encrypted_key).unwrap();

        assert_eq!(symmetric_key, decrypted_key);
    }

    #[test]
    fn test_from_private_key_roundtrip() {
        let original = ECIES::generate().unwrap();
        let restored = ECIES::from_private_key(original.private_key).unwrap();

        assert_eq!(
            original.public_key(),
            restored.public_key(),
            "Restoring from private key must produce same public key"
        );
    }

    #[test]
    fn test_malformed_message() {
        let bob = ECIES::generate().unwrap();

        let malformed_message = ECIESMessage {
            ephemeral_pubkey: [0u8; 33],
            ciphertext: vec![1, 2, 3],
            auth_tag: [0u8; 16],
            nonce: [0u8; 12],
        };

        let result = bob.decrypt(&malformed_message);
        assert!(result.is_err());
    }

    #[test]
    fn test_large_message_encryption() {
        let alice = ECIES::generate().unwrap();
        let bob = ECIES::generate().unwrap();

        // Test with a larger payload (simulating model key material)
        let large_message = vec![0xAB; 1024];

        let encrypted = alice.encrypt(&large_message, &bob.public_key()).unwrap();
        let decrypted = bob.decrypt(&encrypted).unwrap();

        assert_eq!(large_message, decrypted);
    }
}
