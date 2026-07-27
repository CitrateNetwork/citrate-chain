//! DevX developer commands (DEVX-S3): the federation contract table and embedded
//! Citrate Keyring address prediction, at parity with the JS/Python SDKs and the
//! on-chain factory.
//!
//! Address prediction mirrors Solady `LibClone::predictDeterministicAddressERC1967`,
//! the exact scheme `CitrateWalletFactory.predictAddress` uses on-chain and the
//! `citrate-wallet-aa` crate replicates. The parity test pins the on-chain vector
//! (`predictAddress(0x4242…) = 0x1615Af12…`), so this stays honest against a reroll.
//!
//! Addresses come from the vendored federation contract artifact (single source of
//! truth), synced from `citrate-federation/contract/federation-contract.json`.

use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use sha3::{Digest, Keccak256};

use clap::Subcommand;

const CONTRACT_JSON: &str = include_str!("../../federation-contract.json");

// Solady minimal ERC-1967 clone initcode segments (implementation embedded at bytes 9..29).
const INIT_PREFIX: [u8; 9] = [0x60, 0x3d, 0x3d, 0x81, 0x60, 0x22, 0x3d, 0x39, 0x73];
const INIT_SEP: [u8; 2] = [0x60, 0x09];
const INIT_BODY: [u8; 32] = [
    0x51, 0x55, 0xf3, 0x36, 0x3d, 0x3d, 0x37, 0x3d, 0x3d, 0x36, 0x3d, 0x7f, 0x36, 0x08, 0x94, 0xa1,
    0x3b, 0xa1, 0xa3, 0x21, 0x06, 0x67, 0xc8, 0x28, 0x49, 0x2d, 0xb9, 0x8d, 0xca, 0x3e, 0x20, 0x76,
];
const INIT_TAIL: [u8; 32] = [
    0xcc, 0x37, 0x35, 0xa9, 0x20, 0xa3, 0xca, 0x50, 0x5d, 0x38, 0x2b, 0xbc, 0x54, 0x5a, 0xf4, 0x3d,
    0x60, 0x00, 0x80, 0x3e, 0x60, 0x38, 0x57, 0x3d, 0x60, 0x00, 0xfd, 0x5b, 0x3d, 0x60, 0x00, 0xf3,
];

#[derive(Subcommand)]
pub enum DevxCommands {
    /// Print the federation contract table (addresses, chainId, endpoints).
    Contract {
        /// Section: all | chain | aa | identity | gateway | entitlements
        #[arg(long, default_value = "all")]
        section: String,
    },
    /// Predict the embedded Citrate Keyring address for a user.
    PredictAddress {
        /// 0x-prefixed 32-byte userId.
        #[arg(long)]
        user_id: Option<String>,
        /// OIDC subject UUID: keccak256(lowercase) becomes the userId.
        #[arg(long)]
        uuid: Option<String>,
    },
}

fn keccak(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

fn contract() -> Result<Value> {
    serde_json::from_str(CONTRACT_JSON).context("parsing vendored federation-contract.json")
}

fn parse_addr20(v: &Value) -> Result<[u8; 20]> {
    let s = v.as_str().ok_or_else(|| anyhow!("expected an address string"))?;
    let bytes = hex::decode(s.strip_prefix("0x").unwrap_or(s)).context("address hex")?;
    if bytes.len() != 20 {
        return Err(anyhow!("address must be 20 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// `keccak256(0xff || factory || keccak256(userId) || keccak256(initCode))[12..32]`.
fn predict_address(factory: [u8; 20], implementation: [u8; 20], user_id: &[u8; 32]) -> [u8; 20] {
    let mut init = Vec::with_capacity(95);
    init.extend_from_slice(&INIT_PREFIX);
    init.extend_from_slice(&implementation);
    init.extend_from_slice(&INIT_SEP);
    init.extend_from_slice(&INIT_BODY);
    init.extend_from_slice(&INIT_TAIL);
    let init_hash = keccak(&init);
    let salt = keccak(user_id);

    let mut buf = Vec::with_capacity(85);
    buf.push(0xff);
    buf.extend_from_slice(&factory);
    buf.extend_from_slice(&salt);
    buf.extend_from_slice(&init_hash);
    let hash = keccak(&buf);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    addr
}

/// EIP-55 checksummed hex for a 20-byte address.
fn to_checksum(addr: &[u8; 20]) -> String {
    let lower = hex::encode(addr);
    let hash = keccak(lower.as_bytes());
    let mut out = String::from("0x");
    for (i, ch) in lower.chars().enumerate() {
        if ch.is_ascii_digit() {
            out.push(ch);
        } else {
            let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0xf;
            out.push(if nibble >= 8 { ch.to_ascii_uppercase() } else { ch });
        }
    }
    out
}

fn resolve_user_id(user_id: Option<String>, uuid: Option<String>) -> Result<[u8; 32]> {
    if let Some(u) = uuid {
        Ok(keccak(u.to_lowercase().as_bytes()))
    } else if let Some(uid) = user_id {
        let bytes = hex::decode(uid.strip_prefix("0x").unwrap_or(&uid)).context("userId hex")?;
        if bytes.len() != 32 {
            return Err(anyhow!("userId must be 32 bytes, got {}", bytes.len()));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    } else {
        Err(anyhow!("provide --user-id or --uuid"))
    }
}

pub fn execute(cmd: DevxCommands) -> Result<()> {
    match cmd {
        DevxCommands::Contract { section } => {
            let c = contract()?;
            let out = match section.as_str() {
                "chain" => c["chain"].clone(),
                "aa" => serde_json::json!({ "aaStack": c["aaStack"], "membership": c["membership"] }),
                "identity" => c["identity"].clone(),
                "gateway" => c["gateway"].clone(),
                "entitlements" => c["entitlements"].clone(),
                _ => serde_json::json!({
                    "chain": c["chain"], "aaStack": c["aaStack"], "membership": c["membership"],
                    "identity": c["identity"], "entitlements": c["entitlements"], "gateway": c["gateway"],
                }),
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        DevxCommands::PredictAddress { user_id, uuid } => {
            let uid = resolve_user_id(user_id, uuid)?;
            let c = contract()?;
            let factory = parse_addr20(&c["aaStack"]["CitrateWalletFactory"])?;
            let implementation = parse_addr20(&c["aaStack"]["CitrateWallet"])?;
            let addr = predict_address(factory, implementation, &uid);
            let out = serde_json::json!({
                "userId": format!("0x{}", hex::encode(uid)),
                "address": to_checksum(&addr),
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predicts_the_onchain_vector() {
        // On-chain CitrateWalletFactory.predictAddress(0x4242…) = 0x1615Af12… (2026-07-25),
        // and the JS + Python SDKs produce the same. Rust parity.
        let c = contract().expect("artifact parses");
        let factory = parse_addr20(&c["aaStack"]["CitrateWalletFactory"]).expect("factory");
        let implementation = parse_addr20(&c["aaStack"]["CitrateWallet"]).expect("impl");
        let uid = [0x42u8; 32];
        let addr = predict_address(factory, implementation, &uid);
        assert_eq!(to_checksum(&addr), "0x1615Af127952c4e4987D7b597bDD7cb8B49aFB89");
    }

    #[test]
    fn uuid_derivation_is_lowercase_keccak() {
        let a = resolve_user_id(None, Some("DEADBEEF-0000-4000-8000-000000000000".into())).expect("upper");
        let b = resolve_user_id(None, Some("deadbeef-0000-4000-8000-000000000000".into())).expect("lower");
        assert_eq!(a, b);
    }

    #[test]
    fn rejects_missing_user_id() {
        assert!(resolve_user_id(None, None).is_err());
    }
}
