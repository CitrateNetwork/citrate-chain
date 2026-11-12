//citrate/cli/src/commands/governance.rs

use anyhow::{Context, Result};
use clap::Subcommand;
use colored::Colorize;
use serde_json::json;

use crate::commands::signer::{self, SignerArgs};
use crate::config::Config;

#[derive(Subcommand)]
pub enum GovernanceCommands {
    /// Set governance admin (address hex)
    SetAdmin {
        address: String,
        #[command(flatten)]
        signer: SignerArgs,
    },

    /// Queue parameter update with timelock
    QueueParam {
        key: String,
        value: String,
        eta: u64,
        #[command(flatten)]
        signer: SignerArgs,
    },

    /// Execute parameter update after timelock
    ExecuteParam {
        key: String,
        #[command(flatten)]
        signer: SignerArgs,
    },

    /// Get parameter value
    GetParam { key: String },
}

pub async fn execute(cmd: GovernanceCommands, config: &Config) -> Result<()> {
    match cmd {
        GovernanceCommands::SetAdmin { address, signer } => {
            call_precompile(config, &signer, encode_set_admin(&address)?).await?;
            println!("{}", "✓ Admin updated".green());
        }
        GovernanceCommands::QueueParam {
            key,
            value,
            eta,
            signer,
        } => {
            call_precompile(config, &signer, encode_queue_param(&key, &value, eta)?).await?;
            println!("{}", "✓ Parameter queued".green());
        }
        GovernanceCommands::ExecuteParam { key, signer } => {
            call_precompile(config, &signer, encode_execute_param(&key)?).await?;
            println!("{}", "✓ Parameter executed".green());
        }
        GovernanceCommands::GetParam { key } => {
            let out = eth_call_precompile(config, encode_get_param(&key)?).await?;
            println!("{} {}", "Param bytes:".cyan(), out);
        }
    }
    Ok(())
}

fn precompile_address() -> String {
    "0x0000000000000000000000000000000000001003".to_string()
}

fn selector(sig: &str) -> [u8; 4] {
    use sha3::{Digest, Keccak256};
    let [a, b, c, d, ..]: [u8; 32] = Keccak256::digest(sig.as_bytes()).into();
    [a, b, c, d]
}

fn pad32(mut v: Vec<u8>) -> Vec<u8> {
    let rem = v.len() % 32;
    if rem != 0 {
        v.extend(vec![0u8; 32usize.saturating_sub(rem)]);
    }
    v
}

fn encode_address(addr_hex: &str) -> Result<[u8; 32]> {
    let s = addr_hex.trim_start_matches("0x");
    let bytes = hex::decode(s).context("Invalid address hex")?;
    let mut out = [0u8; 32];
    if let Ok(addr) = <[u8; 20]>::try_from(bytes.as_slice()) {
        let (_, tail) = out.split_at_mut(12);
        tail.copy_from_slice(&addr);
    } else if let Ok(word) = <[u8; 32]>::try_from(bytes.as_slice()) {
        out = word;
    } else {
        anyhow::bail!("Address must be 20 or 32 bytes");
    }
    Ok(out)
}

fn encode_bytes(b: &[u8]) -> Vec<u8> {
    // ABI dynamic bytes: length(32) + data + padding
    let mut out = Vec::new();
    let mut len = [0u8; 32];
    let l = b.len() as u64;
    len[24..32].copy_from_slice(&l.to_be_bytes());
    out.extend_from_slice(&len);
    out.extend_from_slice(b);
    pad32(out)
}

fn encode_set_admin(addr_hex: &str) -> Result<String> {
    let mut data = Vec::new();
    data.extend_from_slice(&selector("setAdmin(address)"));
    data.extend_from_slice(&encode_address(addr_hex)?);
    Ok(format!("0x{}", hex::encode(data)))
}

fn encode_queue_param(key: &str, value: &str, eta: u64) -> Result<String> {
    // key as bytes32 (UTF-8 padded/truncated)
    let mut key32 = [0u8; 32];
    let kb = key.as_bytes();
    for (dst, src) in key32.iter_mut().zip(kb) {
        *dst = *src;
    }

    // ABI: selector | key32 | offset(bytes) | eta(32) | dynamic bytes
    let mut data = Vec::new();
    data.extend_from_slice(&selector("queueSetParam(bytes32,bytes,uint64)"));
    data.extend_from_slice(&key32);
    // offset = 0x40
    data.extend_from_slice(&{
        let mut off = [0u8; 32];
        off[31] = 0x40;
        off
    });
    let mut eta_be = [0u8; 32];
    eta_be[24..32].copy_from_slice(&eta.to_be_bytes());
    data.extend_from_slice(&eta_be);
    // dynamic bytes encoding
    let vb = encode_bytes(value.as_bytes());
    data.extend_from_slice(&vb);
    Ok(format!("0x{}", hex::encode(data)))
}

fn encode_execute_param(key: &str) -> Result<String> {
    let mut key32 = [0u8; 32];
    let kb = key.as_bytes();
    for (dst, src) in key32.iter_mut().zip(kb) {
        *dst = *src;
    }
    let mut data = Vec::new();
    data.extend_from_slice(&selector("executeSetParam(bytes32)"));
    data.extend_from_slice(&key32);
    Ok(format!("0x{}", hex::encode(data)))
}

fn encode_get_param(key: &str) -> Result<String> {
    let mut key32 = [0u8; 32];
    let kb = key.as_bytes();
    for (dst, src) in key32.iter_mut().zip(kb) {
        *dst = *src;
    }
    let mut data = Vec::new();
    data.extend_from_slice(&selector("getParam(bytes32)"));
    data.extend_from_slice(&key32);
    Ok(format!("0x{}", hex::encode(data)))
}

/// Sign and send a governance precompile call (0x…1003) with the local signer.
async fn call_precompile(
    config: &Config,
    signer_args: &SignerArgs,
    data_hex: String,
) -> Result<()> {
    let mut to = [0u8; 20];
    let raw_to = hex::decode(precompile_address().trim_start_matches("0x"))
        .context("governance precompile address")?;
    if raw_to.len() != 20 {
        anyhow::bail!("governance precompile address is not 20 bytes");
    }
    to.copy_from_slice(&raw_to);
    let data = hex::decode(data_hex.trim_start_matches("0x")).context("encoded call data")?;
    let sent = signer::sign_and_send(config, signer_args, Some(to), 0, data).await?;
    println!("Transaction: {}", sent.hash.cyan());
    if !signer::receipt_ok(&sent.receipt) {
        anyhow::bail!(
            "Governance call reverted (receipt status {})",
            sent.receipt
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("missing")
        );
    }
    Ok(())
}

/// The call object for a read of the governance precompile. A read needs no
/// sender, so `from` is set only when a default account is configured.
fn eth_call_object(from: Option<&str>, to: &str, data: &str) -> Result<serde_json::Value> {
    let mut obj = json!({ "to": to, "data": data });
    if let (Some(from), Some(map)) = (from, obj.as_object_mut()) {
        map.insert("from".into(), json!(from));
    }
    Ok(obj)
}

async fn eth_call_precompile(config: &Config, data_hex: String) -> Result<String> {
    let to = precompile_address();
    let resp = reqwest::Client::new()
        .post(&config.rpc_endpoint)
        .json(&json!({
            "jsonrpc":"2.0",
            "method":"eth_call",
            "params":[eth_call_object(config.default_account.as_deref(), &to, &data_hex)?, "latest"],
            "id": 1
        }))
        .send()
        .await?;
    let v: serde_json::Value = resp.json().await?;
    if let Some(err) = v.get("error") {
        anyhow::bail!(err.to_string());
    }
    Ok(v.get("result")
        .unwrap_or(&serde_json::Value::Null)
        .as_str()
        .unwrap_or("")
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `governance get-param` is a read; it must work with no default account.
    #[test]
    fn get_param_call_needs_no_default_account() {
        let obj = match eth_call_object(None, "0x0000000000000000000000000000000000001003", "0x01")
        {
            Ok(v) => v,
            Err(e) => panic!("read refused without a default account: {e}"),
        };
        assert!(obj.get("from").is_none(), "{obj}");
        assert_eq!(obj["to"], "0x0000000000000000000000000000000000001003");
        let with = eth_call_object(Some("0xabc"), "0x1003", "0x").unwrap_or_default();
        assert_eq!(with["from"], "0xabc");
    }

    #[test]
    fn test_precompile_address_is_fixed() {
        let addr = precompile_address();
        assert_eq!(addr, "0x0000000000000000000000000000000000001003");
    }

    #[test]
    fn test_selector_keccak_4bytes() {
        let sel = selector("setAdmin(address)");
        assert_eq!(sel.len(), 4);
        // Verify deterministic
        let sel2 = selector("setAdmin(address)");
        assert_eq!(sel, sel2);
        // Different signatures should produce different selectors
        let sel3 = selector("getParam(bytes32)");
        assert_ne!(sel, sel3);
    }

    #[test]
    fn test_pad32_no_padding_needed() {
        let v = vec![0u8; 32];
        let padded = pad32(v.clone());
        assert_eq!(padded.len(), 32);
    }

    #[test]
    fn test_pad32_adds_padding() {
        let v = vec![0u8; 10];
        let padded = pad32(v);
        assert_eq!(padded.len(), 32);
        // Last 22 bytes should be zeros (padding)
        assert!(padded[10..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_pad32_multiple_of_32() {
        let v = vec![0xAA; 64];
        let padded = pad32(v);
        assert_eq!(padded.len(), 64); // Already aligned
    }

    #[test]
    fn test_encode_address_20_bytes() {
        let addr_hex = "0x1111111111111111111111111111111111111111";
        let encoded = encode_address(addr_hex).expect("valid address");
        assert_eq!(encoded.len(), 32);
        // First 12 bytes should be zero (left-padded)
        assert!(encoded[..12].iter().all(|&b| b == 0));
        // Last 20 bytes should be the address
        assert_eq!(encoded[12..], [0x11; 20]);
    }

    #[test]
    fn test_encode_address_32_bytes() {
        let addr_hex = hex::encode([0xAA; 32]);
        let encoded = encode_address(&addr_hex).expect("valid 32-byte");
        assert_eq!(encoded, [0xAA; 32]);
    }

    #[test]
    fn test_encode_address_invalid_length() {
        let result = encode_address("0xabcdef"); // 3 bytes
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_set_admin_format() {
        let result =
            encode_set_admin("0x1111111111111111111111111111111111111111").expect("encode");
        assert!(result.starts_with("0x"));
        // selector (4 bytes = 8 hex) + address word (32 bytes = 64 hex) + "0x" prefix
        assert_eq!(result.len(), 2 + (4 + 32) * 2);
    }

    #[test]
    fn test_encode_get_param_format() {
        let result = encode_get_param("minStake").expect("encode");
        assert!(result.starts_with("0x"));
        // selector (4) + key32 (32) = 36 bytes = 72 hex + 2 prefix
        assert_eq!(result.len(), 2 + (4 + 32) * 2);
    }

    #[test]
    fn test_encode_execute_param_format() {
        let result = encode_execute_param("blockTime").expect("encode");
        assert!(result.starts_with("0x"));
        assert_eq!(result.len(), 2 + (4 + 32) * 2);
    }

    #[test]
    fn test_encode_bytes_dynamic() {
        let data = b"hello";
        let encoded = encode_bytes(data);
        // Length word (32 bytes) + data (5 bytes) + padding to 32 = 64 bytes
        assert_eq!(encoded.len(), 64);
        // Check length field (big-endian u64 at offset 24)
        assert_eq!(encoded[31], 5);
        // Check data
        assert_eq!(&encoded[32..37], b"hello");
    }
}
