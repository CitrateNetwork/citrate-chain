//! Recompute and sign the `CitrateWalletFactory` deploy permit.
//!
//! The on-chain `permitDigest` is:
//!
//! ```solidity
//! keccak256(abi.encode(
//!     address(this),      // factory
//!     block.chainid,
//!     userId,             // bytes32
//!     keccak256(initData),
//!     expiresAt           // uint256
//! ))
//! ```
//!
//! and the signature the factory verifies is `eth_personal_sign`-shaped
//! (EIP-191) so it can be produced by any standard secp256k1 signer
//! (a hardware key, KMS, or the operator wallet on `auth.citrate.ai`).

use ethabi::Token;
use ethereum_types::{Address, H256, U256};
use k256::ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, Signature, SigningKey};

use crate::address::keccak256;

/// Errors from permit construction.
#[derive(Debug, thiserror::Error)]
pub enum PermitError {
    /// The signing key bytes were not a valid secp256k1 scalar.
    #[error("invalid signing key: {0}")]
    InvalidSigningKey(#[from] k256::ecdsa::Error),
    /// EIP-191 wrapping produced an unexpected shape (should not happen).
    #[error("EIP-191 wrap failed")]
    Eip191WrapFailed,
}

/// Compute the permit digest the factory's `identitySigner` signs.
pub fn permit_digest(
    factory: Address,
    chain_id: u64,
    user_id: &[u8; 32],
    init_data: &[u8],
    expires_at: u64,
) -> H256 {
    let init_data_hash = keccak256(init_data);

    let encoded = ethabi::encode(&[
        Token::Address(factory),
        Token::Uint(U256::from(chain_id)),
        Token::FixedBytes(user_id.to_vec()),
        Token::FixedBytes(init_data_hash.to_vec()),
        Token::Uint(U256::from(expires_at)),
    ]);

    H256::from_slice(&keccak256(&encoded))
}

/// Wrap a digest in the EIP-191 ("personal_sign") prefix and produce a
/// 65-byte secp256k1 signature using `signing_key`. Returns the
/// signature in the `(r, s, v)` packed shape the factory expects.
///
/// `v` is `27 + recovery_id` (the same convention OpenZeppelin's
/// `ECDSA.tryRecover` accepts).
pub fn sign_permit(signing_key: &[u8; 32], digest: H256) -> Result<[u8; 65], PermitError> {
    let key = SigningKey::from_slice(signing_key)?;

    let eth_hash = eth_signed_message_hash(digest);

    // Use prehash signer so we can sign the 32-byte hash directly.
    let (signature, recovery_id): (Signature, RecoveryId) = key.sign_prehash(eth_hash.as_bytes())?;
    let r = signature.r().to_bytes();
    let s = signature.s().to_bytes();
    let v: u8 = 27u8 + Into::<u8>::into(recovery_id);

    let mut sig = [0u8; 65];
    sig[0..32].copy_from_slice(&r);
    sig[32..64].copy_from_slice(&s);
    sig[64] = v;
    Ok(sig)
}

/// `keccak256("\x19Ethereum Signed Message:\n32" || digest)` — the
/// EIP-191 envelope OpenZeppelin's `MessageHashUtils.toEthSignedMessageHash`
/// produces.
pub fn eth_signed_message_hash(digest: H256) -> H256 {
    let prefix = b"\x19Ethereum Signed Message:\n32";
    let mut buf = Vec::with_capacity(prefix.len() + 32);
    buf.extend_from_slice(prefix);
    buf.extend_from_slice(digest.as_bytes());
    H256::from_slice(&keccak256(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{signature::hazmat::PrehashVerifier, VerifyingKey};

    fn fixed_signing_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        k[31] = 0xA1;
        k
    }

    #[test]
    fn permit_digest_is_deterministic() {
        let factory = Address::from_slice(&[0x11u8; 20]);
        let user_id = [0x22u8; 32];
        let init_data = vec![0xaau8; 100];
        let d1 = permit_digest(factory, 40204, &user_id, &init_data, 1_700_000_000);
        let d2 = permit_digest(factory, 40204, &user_id, &init_data, 1_700_000_000);
        assert_eq!(d1, d2);
    }

    #[test]
    fn permit_digest_changes_with_each_parameter() {
        let f1 = Address::from_slice(&[0x11u8; 20]);
        let f2 = Address::from_slice(&[0x12u8; 20]);
        let u1 = [0x22u8; 32];
        let u2 = [0x23u8; 32];
        let i1 = vec![1u8, 2, 3];
        let i2 = vec![4u8, 5, 6];
        let base = permit_digest(f1, 40204, &u1, &i1, 1);
        assert_ne!(base, permit_digest(f2, 40204, &u1, &i1, 1));
        assert_ne!(base, permit_digest(f1, 40205, &u1, &i1, 1));
        assert_ne!(base, permit_digest(f1, 40204, &u2, &i1, 1));
        assert_ne!(base, permit_digest(f1, 40204, &u1, &i2, 1));
        assert_ne!(base, permit_digest(f1, 40204, &u1, &i1, 2));
    }

    #[test]
    fn sign_permit_produces_65_byte_signature_with_valid_v() {
        let key = fixed_signing_key();
        let digest = H256::from_slice(&[0xCDu8; 32]);
        let sig = sign_permit(&key, digest).expect("sign");
        assert_eq!(sig.len(), 65);
        // v MUST be 27 or 28.
        assert!(sig[64] == 27 || sig[64] == 28);
    }

    #[test]
    fn sign_permit_is_verifiable_by_corresponding_public_key() {
        let key = fixed_signing_key();
        let digest = H256::from_slice(&[0xCDu8; 32]);
        let signing_key = SigningKey::from_slice(&key).expect("signing key");
        let verifying_key: VerifyingKey = *signing_key.verifying_key();

        let sig = sign_permit(&key, digest).expect("sign");
        // Re-build the signature object from r/s for verification.
        let r = k256::FieldBytes::clone_from_slice(&sig[0..32]);
        let s = k256::FieldBytes::clone_from_slice(&sig[32..64]);
        let recovered_sig = Signature::from_scalars(r, s).expect("scalars");

        // The signer hashed the EIP-191 envelope, so verification hashes
        // the same envelope.
        let eth_hash = eth_signed_message_hash(digest);
        verifying_key
            .verify_prehash(eth_hash.as_bytes(), &recovered_sig)
            .expect("signature verifies against signer's pubkey");
    }

    #[test]
    fn eth_signed_message_hash_is_deterministic_and_distinct_from_raw() {
        let digest = H256::from_slice(&[0x77u8; 32]);
        let h1 = eth_signed_message_hash(digest);
        let h2 = eth_signed_message_hash(digest);
        assert_eq!(h1, h2);
        assert_ne!(h1, digest);
    }
}
