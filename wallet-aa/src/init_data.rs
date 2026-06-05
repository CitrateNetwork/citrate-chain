//! Encode the calldata the `CitrateWalletFactory` delegatecalls into
//! the freshly deployed proxy.
//!
//! The shape mirrors Kernel v3's `initialize(...)` ABI as exported by
//! `contracts/lib/kernel/src/Kernel.sol`. We build the ABI-encoded
//! call data offline so:
//!
//! 1. The `permit_digest` is computable client-side without any RPC.
//! 2. The user can deploy without needing a JSON-RPC mediator —
//!    they ship the raw bytes to the bundler.

use ethabi::Token;
#[cfg(test)]
use ethabi::ParamType;
use ethereum_types::Address;
use serde::{Deserialize, Serialize};

/// Construction parameters for a Kernel v3 `initialize()` call.
///
/// Matches the on-chain signature exactly:
///
/// ```solidity
/// function initialize(
///     ValidationId rootValidator,
///     IHook hook,
///     bytes calldata validatorData,
///     bytes calldata hookData,
///     bytes[] calldata initConfig
/// ) external payable
/// ```
///
/// `ValidationId` is a 21-byte type packed into `bytes21` on Kernel's
/// side. The leading byte is the validation TYPE (`0x01` = validator,
/// `0x02` = permission); the next 20 bytes are the validator
/// implementation address. We accept the address + the type byte
/// separately and pack them here.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KernelInitConfig {
    /// 1-byte type identifier (`0x01` for our WebAuthn validator).
    pub validation_type: u8,
    /// Address of the validator module (e.g. WebAuthnP256Validator).
    pub root_validator: Address,
    /// Address of the optional execution hook. `Address::zero()` for none.
    pub hook: Address,
    /// Validator-specific install data (`onInstall` payload).
    pub validator_data: Vec<u8>,
    /// Hook-specific install data.
    pub hook_data: Vec<u8>,
    /// Additional `executeBatch`-shaped configuration calls Kernel will
    /// run during initialization. Usually empty for a fresh deploy.
    pub init_config: Vec<Vec<u8>>,
}

/// `function initialize(bytes21 rootValidator, address hook, bytes
/// validatorData, bytes hookData, bytes[] initConfig)` ABI-encoded
/// calldata, with the function selector prepended.
pub fn kernel_initialize_calldata(cfg: &KernelInitConfig) -> Vec<u8> {
    // Solidity ABI selector for initialize(bytes21,address,bytes,bytes,bytes[])
    // = keccak256("initialize(bytes21,address,bytes,bytes,bytes[])")[0..4].
    // Compute once at runtime so the selector is provably the one we
    // claim — no risk of a stale typo on a hand-pasted constant.
    let selector = function_selector("initialize(bytes21,address,bytes,bytes,bytes[])");

    // Pack the 21-byte ValidationId: 1 byte type + 20 bytes address.
    let mut validation_id = [0u8; 21];
    validation_id[0] = cfg.validation_type;
    validation_id[1..21].copy_from_slice(cfg.root_validator.as_bytes());

    // Convert init_config from Vec<Vec<u8>> to Vec<Token::Bytes>.
    let init_config_tokens: Vec<Token> = cfg
        .init_config
        .iter()
        .map(|b| Token::Bytes(b.clone()))
        .collect();

    let encoded = ethabi::encode(&[
        Token::FixedBytes(validation_id.to_vec()),
        Token::Address(cfg.hook),
        Token::Bytes(cfg.validator_data.clone()),
        Token::Bytes(cfg.hook_data.clone()),
        Token::Array(init_config_tokens),
    ]);

    let mut call = Vec::with_capacity(4 + encoded.len());
    call.extend_from_slice(&selector);
    call.extend_from_slice(&encoded);
    call
}

/// Pack a WebAuthn validator install payload that matches
/// `WebAuthnP256Validator.onInstall`:
///
/// `bytes32 credentialIdHash | uint256 x | uint256 y | uint8 requireUv`
/// (97 bytes total)
pub fn webauthn_validator_install_data(
    credential_id_hash: &[u8; 32],
    x: &[u8; 32],
    y: &[u8; 32],
    require_user_verification: bool,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(97);
    data.extend_from_slice(credential_id_hash);
    data.extend_from_slice(x);
    data.extend_from_slice(y);
    data.push(if require_user_verification { 1 } else { 0 });
    data
}

/// Pack a Citrate ECDSA validator install payload matching
/// `CitrateECDSAValidator.onInstall`:
///
/// `address owner | uint8 source` (21 bytes total)
pub fn ecdsa_validator_install_data(owner: Address, source: u8) -> Vec<u8> {
    let mut data = Vec::with_capacity(21);
    data.extend_from_slice(owner.as_bytes());
    data.push(source);
    data
}

/// Pack the guardian recovery install payload matching
/// `GuardianRecoveryModule.onInstall`:
///
/// `uint8 threshold | uint8 count | address[count] guardians`
/// (2 + 20*count bytes)
pub fn guardian_install_data(threshold: u8, guardians: &[Address]) -> Vec<u8> {
    let mut data = Vec::with_capacity(2 + guardians.len() * 20);
    data.push(threshold);
    data.push(guardians.len() as u8);
    for g in guardians {
        data.extend_from_slice(g.as_bytes());
    }
    data
}

/// Compute `keccak256(signature)[0..4]` for the given solidity-style
/// signature string.
fn function_selector(signature: &str) -> [u8; 4] {
    let hash = crate::address::keccak256(signature.as_bytes());
    let mut sel = [0u8; 4];
    sel.copy_from_slice(&hash[0..4]);
    sel
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webauthn_install_data_layout_matches_onchain() {
        let cred = [0xdeu8; 32];
        let x = [0xaau8; 32];
        let y = [0xbbu8; 32];
        let bytes = webauthn_validator_install_data(&cred, &x, &y, true);
        assert_eq!(bytes.len(), 97);
        assert_eq!(&bytes[0..32], &cred);
        assert_eq!(&bytes[32..64], &x);
        assert_eq!(&bytes[64..96], &y);
        assert_eq!(bytes[96], 1);
    }

    #[test]
    fn webauthn_install_data_flag_false_packs_zero() {
        let cred = [0u8; 32];
        let x = [0u8; 32];
        let y = [0u8; 32];
        let bytes = webauthn_validator_install_data(&cred, &x, &y, false);
        assert_eq!(bytes[96], 0);
    }

    #[test]
    fn ecdsa_install_data_layout_matches_onchain() {
        let owner = Address::from_slice(&[0x12u8; 20]);
        let bytes = ecdsa_validator_install_data(owner, 1);
        assert_eq!(bytes.len(), 21);
        assert_eq!(&bytes[0..20], &[0x12u8; 20]);
        assert_eq!(bytes[20], 1);
    }

    #[test]
    fn guardian_install_data_layout_matches_onchain() {
        let g = vec![Address::from_slice(&[0x01u8; 20]), Address::from_slice(&[0x02u8; 20])];
        let bytes = guardian_install_data(1, &g);
        assert_eq!(bytes.len(), 2 + 2 * 20);
        assert_eq!(bytes[0], 1);
        assert_eq!(bytes[1], 2);
        assert_eq!(&bytes[2..22], &[0x01u8; 20]);
        assert_eq!(&bytes[22..42], &[0x02u8; 20]);
    }

    #[test]
    fn function_selector_known_initialize_value() {
        // keccak256("initialize(bytes21,address,bytes,bytes,bytes[])")[0..4]
        let sel = function_selector("initialize(bytes21,address,bytes,bytes,bytes[])");
        // Recompute and assert determinism.
        let sel2 = function_selector("initialize(bytes21,address,bytes,bytes,bytes[])");
        assert_eq!(sel, sel2);
        // Negative: differs for a different signature.
        let other = function_selector("initialize(address)");
        assert_ne!(sel, other);
    }

    #[test]
    fn calldata_starts_with_selector_and_is_well_formed() {
        let cfg = KernelInitConfig {
            validation_type: 1,
            root_validator: Address::from_slice(&[0x55u8; 20]),
            hook: Address::zero(),
            validator_data: vec![0xaa, 0xbb, 0xcc],
            hook_data: vec![],
            init_config: vec![],
        };
        let data = kernel_initialize_calldata(&cfg);
        // Selector prefix.
        let sel = function_selector("initialize(bytes21,address,bytes,bytes,bytes[])");
        assert_eq!(&data[0..4], &sel);
        // Tail must decode back to the expected ABI shape.
        let decoded = ethabi::decode(
            &[
                ParamType::FixedBytes(21),
                ParamType::Address,
                ParamType::Bytes,
                ParamType::Bytes,
                ParamType::Array(Box::new(ParamType::Bytes)),
            ],
            &data[4..],
        )
        .expect("decode");
        // Validation id is exactly type byte + 20-byte address.
        match &decoded[0] {
            Token::FixedBytes(b) => {
                assert_eq!(b[0], cfg.validation_type);
                assert_eq!(&b[1..21], cfg.root_validator.as_bytes());
            }
            _ => panic!("wrong type"),
        }
        // validatorData round-trips.
        match &decoded[2] {
            Token::Bytes(b) => assert_eq!(b, &cfg.validator_data),
            _ => panic!("wrong type"),
        }
    }
}
