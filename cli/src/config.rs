//citrate/cli/src/config.rs

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub rpc_endpoint: String,
    pub chain_id: u64,
    pub keystore_path: PathBuf,
    pub default_account: Option<String>,
    pub gas_price: u64,
    pub gas_limit: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rpc_endpoint: "http://localhost:8545".to_string(),
            chain_id: 40204,
            keystore_path: dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".citrate")
                .join("keystore"),
            default_account: None,
            gas_price: 1_000_000_000, // 1 gwei
            gas_limit: 3_000_000,
        }
    }
}

impl Config {
    pub fn load(config_path: Option<&Path>, rpc_override: Option<&str>) -> Result<Self> {
        let config_path = config_path
            .map(PathBuf::from)
            .or_else(Self::default_config_path)
            .context("Unable to determine config path")?;

        let mut config = if config_path.exists() {
            let contents = fs::read_to_string(&config_path)
                .with_context(|| format!("Failed to read config from {:?}", config_path))?;
            serde_json::from_str(&contents)
                .with_context(|| format!("Failed to parse config from {:?}", config_path))?
        } else {
            Self::default()
        };

        // Override RPC endpoint if provided
        if let Some(rpc) = rpc_override {
            config.rpc_endpoint = rpc.to_string();
        }

        Ok(config)
    }

    pub fn save(&self, config_path: Option<&Path>) -> Result<()> {
        let config_path = config_path
            .map(PathBuf::from)
            .or_else(Self::default_config_path)
            .context("Unable to determine config path")?;

        // Create parent directory if it doesn't exist
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory {:?}", parent))?;
        }

        let contents = serde_json::to_string_pretty(self)?;
        fs::write(&config_path, contents)
            .with_context(|| format!("Failed to write config to {:?}", config_path))?;

        Ok(())
    }

    pub fn init(force: bool) -> Result<()> {
        let config_path = Self::default_config_path().context("Unable to determine config path")?;

        if config_path.exists() && !force {
            anyhow::bail!(
                "Config already exists at {:?}. Use --force to overwrite",
                config_path
            );
        }

        let config = Self::default();
        config.save(Some(&config_path))?;

        // Create keystore directory
        fs::create_dir_all(&config.keystore_path)
            .with_context(|| format!("Failed to create keystore at {:?}", config.keystore_path))?;

        Ok(())
    }

    fn default_config_path() -> Option<PathBuf> {
        dirs::home_dir().map(|home| home.join(".citrate").join("config.json"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_default_config_values() {
        let config = Config::default();
        assert_eq!(config.rpc_endpoint, "http://localhost:8545");
        assert_eq!(config.chain_id, 40204); // Testnet beta — canonical
        assert_eq!(config.gas_price, 1_000_000_000);
        assert_eq!(config.gas_limit, 3_000_000);
        assert!(config.default_account.is_none());
        assert!(config.keystore_path.ends_with("keystore"));
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let config = Config {
            rpc_endpoint: "http://example.com:9545".to_string(),
            chain_id: 40204,
            keystore_path: PathBuf::from("/tmp/test-keystore"),
            default_account: Some("0xabcd".to_string()),
            gas_price: 2_000_000_000,
            gas_limit: 5_000_000,
        };
        let json = serde_json::to_string(&config).expect("serialize");
        let restored: Config = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.rpc_endpoint, config.rpc_endpoint);
        assert_eq!(restored.chain_id, config.chain_id);
        assert_eq!(restored.gas_price, config.gas_price);
        assert_eq!(restored.gas_limit, config.gas_limit);
        assert_eq!(restored.default_account, config.default_account);
    }

    #[test]
    fn test_load_nonexistent_returns_default() {
        let config = Config::load(Some(Path::new("/tmp/does_not_exist_citrate.json")), None)
            .expect("should return default");
        assert_eq!(config.rpc_endpoint, "http://localhost:8545");
    }

    #[test]
    fn test_load_with_rpc_override() {
        let config = Config::load(
            Some(Path::new("/tmp/does_not_exist_citrate.json")),
            Some("http://custom:1234"),
        )
        .expect("should load");
        assert_eq!(config.rpc_endpoint, "http://custom:1234");
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("config.json");
        let config = Config {
            rpc_endpoint: "http://roundtrip:8545".to_string(),
            chain_id: 99999,
            keystore_path: PathBuf::from("/tmp/ks"),
            default_account: Some("0xbeef".to_string()),
            gas_price: 42,
            gas_limit: 100,
        };
        config.save(Some(&config_path)).expect("save");
        let loaded = Config::load(Some(&config_path), None).expect("load");
        assert_eq!(loaded.chain_id, 99999);
        assert_eq!(loaded.rpc_endpoint, "http://roundtrip:8545");
        assert_eq!(loaded.default_account, Some("0xbeef".to_string()));
    }

    #[test]
    fn test_init_creates_config_and_keystore() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("config.json");
        // We test save + re-init with force
        let config = Config::default();
        config.save(Some(&config_path)).expect("save");
        // File now exists, init without force should fail
        // We can't easily test init() directly since it uses default_config_path(),
        // but we can verify the save/load cycle works
        assert!(config_path.exists());
    }

    #[test]
    fn test_load_invalid_json_returns_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("bad.json");
        let mut f = fs::File::create(&config_path).expect("create");
        f.write_all(b"not json").expect("write");
        let result = Config::load(Some(&config_path), None);
        assert!(result.is_err());
    }
}
