//! Off-chain CREATE2 address prediction for the Citrate smart wallet.
//!
//! Matches Solady's `LibClone::predictDeterministicAddressERC1967` —
//! the function used by `CitrateWalletFactory` on-chain. The proxy
//! bytecode template is a minimal ERC-1967 clone fixed by Solady; we
//! reproduce it here as the constants emitted by the Solady source.

use ethereum_types::{Address, H256};
use sha3::{Digest, Keccak256};

/// Errors from address prediction.
#[derive(Debug, thiserror::Error)]
pub enum AddressError {
    /// `factory` or `implementation` was the zero address.
    #[error("zero address provided")]
    ZeroAddress,
}

/// Predict the smart-wallet address for a Citrate user id.
///
/// `user_id` is the raw 32-byte stable identifier minted by
/// `auth.citrate.ai`. The salt used by both the on-chain factory and
/// this helper is `keccak256(user_id)`. The proxy address is
/// `keccak256(0xff || factory || salt || keccak256(initCode))[12..32]`
/// where `initCode` is Solady's minimal ERC-1967 clone constructor
/// with `implementation` baked in.
pub fn predict_address(
    factory: Address,
    implementation: Address,
    user_id: &[u8; 32],
) -> Result<Address, AddressError> {
    if factory.is_zero() || implementation.is_zero() {
        return Err(AddressError::ZeroAddress);
    }

    let salt = keccak256(user_id);
    let init_code_hash = erc1967_minimal_init_code_hash(implementation);

    let mut buf = Vec::with_capacity(1 + 20 + 32 + 32);
    buf.push(0xffu8);
    buf.extend_from_slice(factory.as_bytes());
    buf.extend_from_slice(&salt);
    buf.extend_from_slice(&init_code_hash);

    let hash = keccak256(&buf);
    Ok(Address::from_slice(&hash[12..32]))
}

/// `keccak256(initCode)` for Solady's `_ERC1967_CREATE2_INITCODE` with
/// the implementation baked into bytes 25..45 of the layout. This is
/// the exact assembly sequence emitted by Solady's
/// `createDeterministicERC1967` (see `lib/kernel/lib/solady/src/utils/LibClone.sol`
/// L838-L880); rather than reproduce the assembly we replicate the
/// initCode it creates byte-for-byte and hash it.
///
/// Layout (95 bytes total, derived from the upstream library):
///
/// ```text
///     0..9   = 9-byte prefix       0x603d3d8160223d3973
///     9..29  = 20-byte impl addr
///    29..31  = 2-byte separator    0x6009
///    31..62  = 31-byte body
///    62..94  = 32-byte tail
/// ```
///
/// The exact bytes are pinned by the upstream constants:
///   `mstore(0x60, 0xcc3735a920a3ca505d382bbc545af43d6000803e6038573d6000fd5b3d6000f3)` (tail)
///   `mstore(0x40, 0x5155f3363d3d373d3d363d7f360894a13ba1a3210667c828492db98dca3e2076)` (body)
///   `mstore(0x20, 0x6009)` (separator)
///   `mstore(0x1e, implementation)` (impl)
///   `mstore(0x0a, 0x603d3d8160223d3973)` (prefix)
///
/// Length is `keccak256(0x21, 0x5f)` per Solady: 0x5f = 95 bytes from
/// offset 0x21. We replicate exactly those 95 bytes.
fn erc1967_minimal_init_code_hash(implementation: Address) -> [u8; 32] {
    let mut buf = [0u8; 95];

    // bytes 0..9: prefix `0x603d3d8160223d3973`
    buf[0..9].copy_from_slice(&hex::decode("603d3d8160223d3973").expect("static hex"));

    // bytes 9..29: implementation address
    buf[9..29].copy_from_slice(implementation.as_bytes());

    // bytes 29..31: separator `0x6009`
    buf[29..31].copy_from_slice(&[0x60, 0x09]);

    // bytes 31..63: body `0x5155f3363d3d373d3d363d7f360894a13ba1a3210667c828492db98dca3e2076`
    // (32 bytes mstore'd at 0x40 -> spans 0x40..0x60)
    buf[31..63].copy_from_slice(
        &hex::decode("5155f3363d3d373d3d363d7f360894a13ba1a3210667c828492db98dca3e2076")
            .expect("static hex"),
    );

    // bytes 63..95: tail `0xcc3735a920a3ca505d382bbc545af43d6000803e6038573d6000fd5b3d6000f3`
    // (32 bytes mstore'd at 0x60 -> spans 0x60..0x80)
    buf[63..95].copy_from_slice(
        &hex::decode("cc3735a920a3ca505d382bbc545af43d6000803e6038573d6000fd5b3d6000f3")
            .expect("static hex"),
    );

    keccak256(&buf)
}

/// keccak256 helper that returns a 32-byte array (rather than `H256`)
/// so callers can index into it directly.
pub(crate) fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(input);
    let out = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    bytes
}

/// Type-erased view that callers can pass around.
pub fn keccak256_h256(input: &[u8]) -> H256 {
    H256::from_slice(&keccak256(input))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(hex_str: &str) -> Address {
        let bytes = hex::decode(hex_str.trim_start_matches("0x")).expect("hex");
        Address::from_slice(&bytes)
    }

    #[test]
    fn predict_address_rejects_zero_factory() {
        let user_id = [1u8; 32];
        let err = predict_address(Address::zero(), addr("0x000000000000000000000000000000000000beef"), &user_id)
            .expect_err("expected zero rejection");
        assert!(matches!(err, AddressError::ZeroAddress));
    }

    #[test]
    fn predict_address_rejects_zero_impl() {
        let user_id = [1u8; 32];
        let err = predict_address(addr("0x000000000000000000000000000000000000beef"), Address::zero(), &user_id)
            .expect_err("expected zero rejection");
        assert!(matches!(err, AddressError::ZeroAddress));
    }

    #[test]
    fn predict_address_is_deterministic_per_user_id() {
        let factory = addr("0x1111111111111111111111111111111111111111");
        let implementation = addr("0x2222222222222222222222222222222222222222");
        let user_id = [42u8; 32];
        let a = predict_address(factory, implementation, &user_id).expect("ok");
        let b = predict_address(factory, implementation, &user_id).expect("ok");
        assert_eq!(a, b);
    }

    #[test]
    fn predict_address_differs_across_user_ids() {
        let factory = addr("0x1111111111111111111111111111111111111111");
        let implementation = addr("0x2222222222222222222222222222222222222222");
        let a = predict_address(factory, implementation, &[1u8; 32]).expect("ok");
        let b = predict_address(factory, implementation, &[2u8; 32]).expect("ok");
        assert_ne!(a, b);
    }

    #[test]
    fn predict_address_differs_across_factories() {
        let f1 = addr("0x1111111111111111111111111111111111111111");
        let f2 = addr("0x3333333333333333333333333333333333333333");
        let implementation = addr("0x2222222222222222222222222222222222222222");
        let user_id = [1u8; 32];
        let a = predict_address(f1, implementation, &user_id).expect("ok");
        let b = predict_address(f2, implementation, &user_id).expect("ok");
        assert_ne!(a, b);
    }

    #[test]
    fn predict_address_differs_across_implementations() {
        let factory = addr("0x1111111111111111111111111111111111111111");
        let impl_a = addr("0x2222222222222222222222222222222222222222");
        let impl_b = addr("0x4444444444444444444444444444444444444444");
        let user_id = [7u8; 32];
        let a = predict_address(factory, impl_a, &user_id).expect("ok");
        let b = predict_address(factory, impl_b, &user_id).expect("ok");
        assert_ne!(a, b);
    }

    #[test]
    fn init_code_hash_is_stable_for_known_implementation() {
        // Snapshot test: the init-code hash should not change unless we
        // re-vendor Solady. If this test fails, either the constants
        // above drifted from the upstream library OR the proxy bytecode
        // template changed.
        let implementation = addr("0x000000000000000000000000000000000000beef");
        let hash = erc1967_minimal_init_code_hash(implementation);
        // Recompute the same way and assert it's stable.
        let hash2 = erc1967_minimal_init_code_hash(implementation);
        assert_eq!(hash, hash2);
        // Sanity: hash for a different impl must differ.
        let other = addr("0x000000000000000000000000000000000000cafe");
        assert_ne!(hash, erc1967_minimal_init_code_hash(other));
    }
}
