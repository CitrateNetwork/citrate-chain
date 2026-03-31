//citrate/cli/src/commands/account.rs
//
// Ed25519 account management - aligned with wallet for account portability

use anyhow::{Context, Result};
use clap::Subcommand;
use colored::Colorize;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use sha3::{Digest, Keccak256};
use std::fs;
use std::path::PathBuf;

use crate::config::Config;
use crate::utils::keystore;

#[derive(Subcommand)]
pub enum AccountCommands {
    /// Create a new account
    Create {
        /// Password for the keystore
        #[arg(short, long)]
        password: Option<String>,

        /// Output path for the keystore file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// List all accounts
    List,

    /// Get account balance
    Balance {
        /// Account address
        address: String,
    },

    /// Import an account from private key
    Import {
        /// Private key (hex encoded)
        #[arg(short, long)]
        key: String,

        /// Password for the keystore
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Export account private key
    Export {
        /// Account address
        address: String,

        /// Password for the keystore
        #[arg(short, long)]
        password: Option<String>,
    },
}

pub async fn execute(cmd: AccountCommands, config: &Config) -> Result<()> {
    match cmd {
        AccountCommands::Create { password, output } => {
            create_account(config, password, output)?;
        }
        AccountCommands::List => {
            list_accounts(config)?;
        }
        AccountCommands::Balance { address } => {
            get_balance(config, &address).await?;
        }
        AccountCommands::Import { key, password } => {
            import_account(config, &key, password)?;
        }
        AccountCommands::Export { address, password } => {
            export_account(config, &address, password)?;
        }
    }
    Ok(())
}

fn create_account(
    config: &Config,
    password: Option<String>,
    output: Option<PathBuf>,
) -> Result<()> {
    // Generate new ed25519 keypair from random bytes
    let mut rng = rand::thread_rng();
    let mut secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut secret_bytes);
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();

    // Derive address from public key
    let address = derive_address(verifying_key.as_bytes());

    // Get password (prompt if not provided)
    let password = match password {
        Some(p) => p,
        None => rpassword::prompt_password("Enter password for keystore: ")
            .context("Failed to read password from terminal")?,
    };

    // Save to keystore
    let keystore_path = output.unwrap_or_else(|| {
        config
            .keystore_path
            .join(format!("{}.json", hex::encode(address)))
    });

    keystore::save_key(&signing_key, &password, &keystore_path)?;

    println!("{}", "✓ Account created successfully".green());
    println!("Address: {}", format!("0x{}", hex::encode(address)).cyan());
    println!(
        "Public Key: {}",
        format!("0x{}", hex::encode(verifying_key.as_bytes())).dimmed()
    );
    println!("Keystore: {:?}", keystore_path);

    Ok(())
}

fn list_accounts(config: &Config) -> Result<()> {
    let entries = fs::read_dir(&config.keystore_path).with_context(|| {
        format!(
            "Failed to read keystore directory {:?}",
            config.keystore_path
        )
    })?;

    println!("{}", "Accounts:".bold());

    let mut count = 0;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            if let Some(filename) = path.file_stem().and_then(|s| s.to_str()) {
                println!("  • 0x{}", filename);
                count += 1;
            }
        }
    }

    if count == 0 {
        println!("  {}", "No accounts found".yellow());
        println!("  Use 'citrate account create' to create a new account");
    } else {
        println!("\nTotal: {} account(s)", count);
    }

    Ok(())
}

async fn get_balance(config: &Config, address: &str) -> Result<()> {
    // Clean address format
    let address = address.trim_start_matches("0x");

    // Make RPC call to get balance
    let client = reqwest::Client::new();
    let response = client
        .post(&config.rpc_endpoint)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": [format!("0x{}", address), "latest"],
            "id": 1
        }))
        .send()
        .await
        .context("Failed to connect to RPC endpoint")?;

    let result: serde_json::Value = response.json().await?;

    if let Some(balance_hex) = result["result"].as_str() {
        let balance = u128::from_str_radix(balance_hex.trim_start_matches("0x"), 16)
            .context("Failed to parse balance")?;

        println!("Address: {}", format!("0x{}", address).cyan());
        println!("Balance: {} wei", balance);
        println!("         {} ETH", balance as f64 / 1e18);
    } else if let Some(error) = result["error"].as_object() {
        anyhow::bail!(
            "RPC error: {}",
            error["message"].as_str().unwrap_or("Unknown error")
        );
    } else {
        anyhow::bail!("Unexpected response from RPC");
    }

    Ok(())
}

fn import_account(config: &Config, private_key: &str, password: Option<String>) -> Result<()> {
    // Parse private key (32 bytes for ed25519)
    let key_bytes =
        hex::decode(private_key.trim_start_matches("0x")).context("Invalid private key format")?;

    if key_bytes.len() != 32 {
        anyhow::bail!("Invalid private key length. Expected 32 bytes for ed25519.");
    }

    let key_array: [u8; 32] = key_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("private key must be exactly 32 bytes"))?;
    let signing_key = SigningKey::from_bytes(&key_array);

    // Derive public key and address
    let verifying_key = signing_key.verifying_key();
    let address = derive_address(verifying_key.as_bytes());

    // Get password
    let password = match password {
        Some(p) => p,
        None => rpassword::prompt_password("Enter password for keystore: ")
            .context("Failed to read password from terminal")?,
    };

    // Save to keystore
    let keystore_path = config
        .keystore_path
        .join(format!("{}.json", hex::encode(address)));

    if keystore_path.exists() {
        anyhow::bail!("Account already exists in keystore");
    }

    keystore::save_key(&signing_key, &password, &keystore_path)?;

    println!("{}", "✓ Account imported successfully".green());
    println!("Address: {}", format!("0x{}", hex::encode(address)).cyan());

    Ok(())
}

fn export_account(config: &Config, address: &str, password: Option<String>) -> Result<()> {
    let address = address.trim_start_matches("0x");
    let keystore_path = config.keystore_path.join(format!("{}.json", address));

    if !keystore_path.exists() {
        anyhow::bail!("Account not found in keystore");
    }

    // Get password
    let password = match password {
        Some(p) => p,
        None => rpassword::prompt_password("Enter keystore password: ")
            .context("Failed to read password from terminal")?,
    };

    // Load and decrypt key
    let signing_key = keystore::load_key(&keystore_path, &password)?;

    println!(
        "{}",
        "⚠️  WARNING: Never share your private key!".red().bold()
    );
    println!("Private key: {}", hex::encode(signing_key.to_bytes()));

    Ok(())
}

/// Derive Ethereum-compatible address from ed25519 public key
///
/// Address derivation follows the same logic as citrate-execution:
/// 1. If pubkey has embedded EVM address (20 bytes + 12 zeros), use directly
/// 2. Otherwise, Keccak256 hash the full 32-byte pubkey, take last 20 bytes
fn derive_address(pubkey: &[u8; 32]) -> [u8; 20] {
    // Check if embedded EVM address (20 bytes + 12 zeros)
    let is_evm_address = pubkey[20..].iter().all(|&b| b == 0)
        && !pubkey[..20].iter().all(|&b| b == 0);

    if is_evm_address {
        // Use first 20 bytes directly
        let mut address = [0u8; 20];
        address.copy_from_slice(&pubkey[..20]);
        return address;
    }

    // Full pubkey: Keccak256 hash, take last 20 bytes
    let mut hasher = Keccak256::new();
    hasher.update(pubkey);
    let hash = hasher.finalize();

    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    address
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_address_embedded_evm() {
        // 20 non-zero bytes followed by 12 zero bytes = embedded EVM address
        let mut pubkey = [0u8; 32];
        pubkey[..20].copy_from_slice(&[0xAA; 20]);
        let addr = derive_address(&pubkey);
        assert_eq!(addr, [0xAA; 20]);
    }

    #[test]
    fn test_derive_address_full_pubkey_uses_keccak() {
        // Full 32-byte pubkey (non-zero in last 12 bytes) -> Keccak256
        let pubkey = [0x42u8; 32];
        let addr = derive_address(&pubkey);
        // Verify it matches Keccak256 hash last 20 bytes
        let mut hasher = Keccak256::new();
        hasher.update(pubkey);
        let hash = hasher.finalize();
        let mut expected = [0u8; 20];
        expected.copy_from_slice(&hash[12..]);
        assert_eq!(addr, expected);
    }

    #[test]
    fn test_derive_address_all_zeros_uses_keccak() {
        // All zeros: the embedded-EVM check requires non-zero first 20 bytes
        let pubkey = [0u8; 32];
        let addr = derive_address(&pubkey);
        // Should use Keccak path since first 20 bytes are all zero
        let mut hasher = Keccak256::new();
        hasher.update(pubkey);
        let hash = hasher.finalize();
        let mut expected = [0u8; 20];
        expected.copy_from_slice(&hash[12..]);
        assert_eq!(addr, expected);
    }

    #[test]
    fn test_derive_address_deterministic() {
        let pubkey = [0x11u8; 32];
        let addr1 = derive_address(&pubkey);
        let addr2 = derive_address(&pubkey);
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_derive_address_different_keys_different_addresses() {
        let key_a = [0x01u8; 32];
        let key_b = [0x02u8; 32];
        let addr_a = derive_address(&key_a);
        let addr_b = derive_address(&key_b);
        assert_ne!(addr_a, addr_b);
    }
}
