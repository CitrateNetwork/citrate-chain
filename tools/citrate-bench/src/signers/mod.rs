//! Signer management: keystore loading, the signer type, and the
//! multi-signer pool that assigns work to nonce lanes.
//!
//! The signer type holds the decrypted private key in a `Zeroizing`
//! wrapper so that dropping a signer overwrites the key material. The
//! typical way to obtain a signer is via `keystore::load` which
//! prompts for or reads a passphrase. For throwaway benches against
//! ephemeral (pre-reroll) chains there is also `load_from_private_keys_file`
//! which reads raw 32-byte hex keys from disk — it is explicitly a
//! convenience path for burn accounts and must never be used for
//! keys that hold real value.

pub mod keystore;
pub mod pool;

use std::path::Path;

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

/// Load a set of signers from a plaintext private-keys file.
///
/// The file format is one 32-byte secp256k1 key per line, as hex
/// (optional `0x` prefix). Blank lines and lines beginning with `#`
/// are ignored. Keys are zeroed out of the intermediate buffer after
/// each signer is constructed.
///
/// This path exists for throwaway benches against ephemeral chains
/// where managing a Foundry keystore would be pointless overhead.
/// **Never use it for keys that hold real value** — plaintext key
/// storage has obvious and unmitigated risks.
pub fn load_from_private_keys_file(path: &Path) -> Result<Vec<Signer>> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| Error::Keystore(format!("read private-keys file: {e}")))?;
    let mut signers = Vec::new();
    for (lineno, raw_line) in contents.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let stripped = line.strip_prefix("0x").or_else(|| line.strip_prefix("0X")).unwrap_or(line);
        if stripped.len() != 64 {
            return Err(Error::Keystore(format!(
                "private-keys file line {}: expected 64 hex chars, got {}",
                lineno + 1,
                stripped.len()
            )));
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(stripped, bytes.as_mut()).map_err(|e| {
            Error::Keystore(format!(
                "private-keys file line {}: hex decode: {e}",
                lineno + 1
            ))
        })?;
        signers.push(Signer::from_key_bytes(bytes.as_ref())?);
        // bytes zeroed on drop
    }
    if signers.is_empty() {
        return Err(Error::Keystore(
            "private-keys file contained zero usable keys".into(),
        ));
    }
    Ok(signers)
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

    #[test]
    fn load_from_private_keys_file_parses_three_keys() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            f,
            "# a comment, should be skipped\n\
             0x0000000000000000000000000000000000000000000000000000000000000001\n\
             \n\
             0000000000000000000000000000000000000000000000000000000000000002\n\
             0X0000000000000000000000000000000000000000000000000000000000000003"
        )
        .expect("write");
        f.flush().expect("flush");
        let signers =
            load_from_private_keys_file(f.path()).expect("load_from_private_keys_file");
        assert_eq!(signers.len(), 3);
        // Well-known address for private key = 1:
        assert_eq!(
            signers[0].address_hex().to_lowercase(),
            "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );
    }

    #[test]
    fn load_from_private_keys_file_rejects_bad_length() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(f, "0xdeadbeef").expect("write");
        f.flush().expect("flush");
        assert!(load_from_private_keys_file(f.path()).is_err());
    }

    #[test]
    fn load_from_private_keys_file_rejects_empty_file() {
        let f = tempfile::NamedTempFile::new().expect("tempfile");
        assert!(load_from_private_keys_file(f.path()).is_err());
    }
}
