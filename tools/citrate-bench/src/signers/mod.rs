//! Signer management: keystore loading, the signer type, and the
//! multi-signer pool that assigns work to nonce lanes.
//!
//! The signer type holds the decrypted private key in a `Zeroizing`
//! wrapper so that dropping a signer overwrites the key material. The
//! only way to obtain a signer is via `keystore::load` which prompts
//! for or reads a passphrase.

pub mod keystore;
pub mod pool;

use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// A decrypted signer. The 32-byte private key is held inside a
/// `Zeroizing` buffer and cleared on drop.
pub struct Signer {
    pub address: [u8; 20],
    key: Zeroizing<[u8; 32]>,
}

impl Signer {
    /// Build a signer from raw private key bytes. The bytes are copied
    /// into the zeroizing buffer; callers should themselves zero the
    /// source once this returns.
    pub fn from_key_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::Signing(format!(
                "private key must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(bytes);
        let address = derive_eth_address(&key)?;
        Ok(Self { address, key })
    }

    /// Accessor for the signing key bytes. Only used by the
    /// in-crate transaction signer; do not expose publicly.
    pub(crate) fn key_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Hex-encoded 0x-prefixed address string.
    pub fn address_hex(&self) -> String {
        format!("0x{}", hex::encode(self.address))
    }
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material. Address is public.
        f.debug_struct("Signer")
            .field("address", &self.address_hex())
            .finish()
    }
}

/// Derive the 20-byte Ethereum address from a 32-byte secp256k1
/// private key by taking the last 20 bytes of
/// `keccak256(uncompressed_pubkey[1..])`.
fn derive_eth_address(key_bytes: &[u8; 32]) -> Result<[u8; 20]> {
    let key = SigningKey::from_bytes(key_bytes.into())
        .map_err(|e| Error::Signing(format!("invalid secp256k1 key: {e}")))?;
    let verifying_key = key.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let bytes = point.as_bytes();
    let hash = Keccak256::digest(&bytes[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_canonical_address_for_key_one() {
        // Private key 0x0000...0001 corresponds to the well-known address
        // 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf (case-insensitive).
        let mut key = [0u8; 32];
        key[31] = 1;
        let s = Signer::from_key_bytes(&key).expect("signer");
        assert_eq!(
            s.address_hex().to_lowercase(),
            "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );
    }

    #[test]
    fn rejects_wrong_length_key() {
        assert!(Signer::from_key_bytes(&[0u8; 31]).is_err());
        assert!(Signer::from_key_bytes(&[0u8; 33]).is_err());
    }

    #[test]
    fn debug_does_not_leak_key() {
        let mut key = [0u8; 32];
        key[0] = 0x42;
        let s = Signer::from_key_bytes(&key).expect("signer");
        let printed = format!("{s:?}");
        assert!(!printed.contains("42"));
        assert!(printed.contains("0x"));
    }
}
