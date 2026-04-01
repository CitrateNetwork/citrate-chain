//! Shared types for the wallet core.

use serde::{Deserialize, Serialize};

/// Wallet configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    pub keystore_path: String,
    pub rpc_url: String,
    pub chain_id: u64,
    pub network: String,
    pub default_gas_price: u64,
    pub default_gas_limit: u64,
    pub session_timeout_secs: u64,
    pub max_failed_attempts: u32,
    pub lockout_duration_secs: u64,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            keystore_path: default_keystore_path(),
            // Testnet-primary: use public RPC since embedded node doesn't serve HTTP RPC
            rpc_url: "https://rpc.citrate.ai".to_string(),
            chain_id: 40204,
            network: "testnet".to_string(),
            default_gas_price: 1_000_000_000, // 1 Gwei
            default_gas_limit: 21_000,
            session_timeout_secs: 900, // 15 minutes
            max_failed_attempts: 5,
            lockout_duration_secs: 300, // 5 minutes
        }
    }
}

fn default_keystore_path() -> String {
    dirs::data_local_dir()
        .map(|d| d.join("citrate-wallet").join("keystore").to_string_lossy().to_string())
        .unwrap_or_else(|| ".citrate-wallet/keystore".to_string())
}

/// A wallet account with derived address and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAccount {
    pub address: String,
    pub public_key_hex: String,
    pub label: String,
    pub balance: String,
    pub nonce: u64,
    pub is_default: bool,
    pub created_at: u64,
    pub key_type: KeyType,
}

/// Supported key types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    Ed25519,
    Secp256k1,
}

/// Encrypted key storage format (JSON on disk)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKeyEntry {
    pub public_key_hex: String,
    pub address: String,
    pub label: String,
    pub key_type: KeyType,
    pub ciphertext: String,    // base64-encoded AES-256-GCM ciphertext
    pub salt: String,          // base64-encoded Argon2 salt
    pub nonce: String,         // base64-encoded 12-byte AES nonce
    pub created_at: u64,
}

/// Result of creating a new account
#[derive(Debug, Clone)]
pub struct CreateAccountResult {
    pub address: String,
    pub public_key_hex: String,
    pub mnemonic: String,
    pub label: String,
}

/// Network configuration presets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub name: String,
    pub chain_id: u64,
    pub rpc_url: String,
    pub explorer_url: Option<String>,
    pub faucet_url: Option<String>,
}

impl NetworkConfig {
    pub fn devnet() -> Self {
        Self {
            name: "devnet".to_string(),
            chain_id: 40204,
            rpc_url: "http://localhost:8545".to_string(),
            explorer_url: None,
            faucet_url: None,
        }
    }

    pub fn testnet() -> Self {
        Self {
            name: "testnet".to_string(),
            chain_id: 40204,
            rpc_url: "https://rpc.citrate.ai".to_string(),
            explorer_url: Some("https://explorer.citrate.ai".to_string()),
            faucet_url: Some("https://faucet.citrate.ai".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = WalletConfig::default();
        assert_eq!(config.chain_id, 40204);
        assert_eq!(config.default_gas_limit, 21_000);
        assert_eq!(config.session_timeout_secs, 900);
        assert_eq!(config.max_failed_attempts, 5);
    }

    #[test]
    fn test_config_serialization() {
        let config = WalletConfig::default();
        let json = serde_json::to_string(&config).expect("serialize config");
        let deser: WalletConfig = serde_json::from_str(&json).expect("deserialize config");
        assert_eq!(deser.chain_id, config.chain_id);
    }

    #[test]
    fn test_network_presets() {
        let devnet = NetworkConfig::devnet();
        assert_eq!(devnet.chain_id, 40204);
        assert!(devnet.rpc_url.contains("localhost"));

        let testnet = NetworkConfig::testnet();
        assert_eq!(testnet.chain_id, 40204);
        assert!(testnet.rpc_url.contains("rpc.citrate.ai"));
    }

    #[test]
    fn test_key_type_equality() {
        assert_eq!(KeyType::Ed25519, KeyType::Ed25519);
        assert_ne!(KeyType::Ed25519, KeyType::Secp256k1);
    }

    #[test]
    fn test_encrypted_key_entry_serialization() {
        let entry = EncryptedKeyEntry {
            public_key_hex: "deadbeef".to_string(),
            address: "0x1234".to_string(),
            label: "Primary".to_string(),
            key_type: KeyType::Ed25519,
            ciphertext: "base64cipher".to_string(),
            salt: "base64salt".to_string(),
            nonce: "base64nonce".to_string(),
            created_at: 1711555200,
        };
        let json = serde_json::to_string(&entry).expect("serialize entry");
        let deser: EncryptedKeyEntry = serde_json::from_str(&json).expect("deserialize entry");
        assert_eq!(deser.label, "Primary");
        assert_eq!(deser.key_type, KeyType::Ed25519);
    }
}
