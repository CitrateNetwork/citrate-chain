use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// Chain configuration
    pub chain: ChainConfig,

    /// Network configuration
    pub network: NetworkConfig,

    /// RPC configuration
    pub rpc: RpcConfig,

    /// Storage configuration
    pub storage: StorageConfig,

    /// Mining configuration
    pub mining: MiningConfig,

    /// Validator configuration
    #[serde(default)]
    pub validator: ValidatorConfig,

    /// VRF configuration (WP-W.2)
    #[serde(default)]
    pub vrf: VrfConfig,

    /// Checkpoint configuration (WP-W.2)
    #[serde(default)]
    pub checkpoint: CheckpointNodeConfig,
}

/// VRF configuration for proposer election verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VrfConfig {
    /// Require cryptographic VRF proof verification.
    /// Default: true (enforced on non-devnet profiles).
    #[serde(default = "default_strict_vrf")]
    pub strict_vrf: bool,

    /// Accept legacy SHA3 proofs during migration period.
    /// When true, both ECVRF-P256-SHA256 and legacy SHA3 proofs are accepted.
    #[serde(default)]
    pub migration_mode: bool,
}

fn default_strict_vrf() -> bool {
    true
}

impl Default for VrfConfig {
    fn default() -> Self {
        Self {
            strict_vrf: true,
            migration_mode: false,
        }
    }
}

/// Checkpoint configuration for node-level BFT finality.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointNodeConfig {
    /// Checkpoint interval in blocks.
    #[serde(default = "default_checkpoint_interval")]
    pub interval: u64,

    /// Committee size.
    #[serde(default = "default_committee_size")]
    pub committee_size: usize,

    /// Quorum threshold (2/3 + 1 of committee).
    #[serde(default = "default_quorum_threshold")]
    pub quorum_threshold: usize,
}

fn default_checkpoint_interval() -> u64 {
    50
}

fn default_committee_size() -> usize {
    100
}

fn default_quorum_threshold() -> usize {
    67
}

impl Default for CheckpointNodeConfig {
    fn default() -> Self {
        Self {
            interval: 50,
            committee_size: 100,
            quorum_threshold: 67,
        }
    }
}

/// Validator and production mode configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorConfig {
    /// Production mode: enforces fail-closed behavior for validators
    /// When true, the node will refuse to start without validators configured
    /// Default: false (permissive for development)
    #[serde(default)]
    pub production_mode: bool,

    /// Initial validator public keys (hex-encoded 32-byte keys)
    /// In production mode, at least one validator must be configured
    #[serde(default)]
    pub validators: Vec<String>,

    /// IPFS API endpoint for model pin verification
    #[serde(default = "default_ipfs_url")]
    pub ipfs_api_url: String,

    /// Pin check interval in seconds
    #[serde(default = "default_check_interval")]
    pub check_interval_secs: u64,

    /// Grace period before slashing in hours
    #[serde(default = "default_grace_period")]
    pub grace_period_hours: u64,
}

fn default_ipfs_url() -> String {
    "http://127.0.0.1:5001".to_string()
}

fn default_check_interval() -> u64 {
    3600 // 1 hour
}

fn default_grace_period() -> u64 {
    24 // 24 hours
}

impl Default for ValidatorConfig {
    fn default() -> Self {
        Self {
            production_mode: false,
            validators: vec![],
            ipfs_api_url: default_ipfs_url(),
            check_interval_secs: default_check_interval(),
            grace_period_hours: default_grace_period(),
        }
    }
}

impl ValidatorConfig {
    /// Create a production configuration that enforces validator presence
    pub fn production(validators: Vec<String>) -> Self {
        Self {
            production_mode: true,
            validators,
            ipfs_api_url: default_ipfs_url(),
            check_interval_secs: default_check_interval(),
            grace_period_hours: default_grace_period(),
        }
    }

    /// Validate configuration, returning error if production mode constraints are violated
    pub fn validate(&self) -> Result<(), String> {
        if self.production_mode && self.validators.is_empty() {
            return Err(
                "FAIL-CLOSED: production_mode=true requires at least one validator. \
                 Configure validators in [validator] section or set production_mode=false for development.".to_string()
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainConfig {
    /// Chain ID
    pub chain_id: u64,

    /// Genesis block hash (empty for new chain)
    pub genesis_hash: Option<String>,

    /// Block time in seconds
    pub block_time: u64,

    /// GhostDAG K parameter
    pub ghostdag_k: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// P2P listen address
    pub listen_addr: SocketAddr,

    /// Bootstrap nodes
    pub bootstrap_nodes: Vec<String>,

    /// Max peers
    pub max_peers: usize,

    /// Allowed peer Noise public keys (hex-encoded).
    /// When non-empty, only peers whose Noise key is in this list can connect.
    /// When empty (default), all peers are allowed (open mode / devnet).
    #[serde(default)]
    pub allowed_peers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcConfig {
    /// RPC enabled
    pub enabled: bool,

    /// RPC listen address
    pub listen_addr: SocketAddr,

    /// WebSocket listen address
    pub ws_addr: SocketAddr,

    /// Allow eth_sendTransaction (unsigned, arbitrary-from transactions).
    /// SECURITY (C-02): Must only be true in devnet/dev mode.
    #[serde(default)]
    pub allow_eth_send_transaction: bool,

    /// API key for gating all JSON-RPC requests.
    /// When set, every request must present this key via Bearer token, X-API-Key header, or query param.
    /// When None, all requests are allowed (devnet mode).
    #[serde(default)]
    pub api_key: Option<String>,

    /// Configurable CORS origins for JSON-RPC and REST servers.
    /// When empty (default), no CORS headers are sent (browser cross-origin blocked).
    /// Use ["*"] for open access (devnet only).
    /// WP-X.1: F-08 remediation.
    #[serde(default)]
    pub cors_origins: Vec<String>,

    /// API key for REST endpoints that mutate state (deploy, inference, training, lora).
    /// When set, these endpoints require Authorization: Bearer <key>.
    /// Read-only endpoints (/v1/models, /health) remain open.
    /// WP-X.1: F-07 remediation.
    #[serde(default)]
    pub rest_api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// Data directory
    pub data_dir: PathBuf,

    /// Prune old blocks
    pub pruning: bool,

    /// Blocks to keep if pruning
    pub keep_blocks: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MiningConfig {
    /// Enable mining
    pub enabled: bool,

    /// Coinbase address (hex)
    pub coinbase: String,

    /// Target block time (seconds)
    pub target_block_time: u64,

    /// Min gas price
    pub min_gas_price: u64,
}

impl Default for NodeConfig {
    fn default() -> Self {
        // Check for chain ID from environment variable, default to 40204
        let chain_id = std::env::var("CITRATE_CHAIN_ID")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(40204);

        Self {
            chain: ChainConfig {
                chain_id,
                genesis_hash: None,
                block_time: 5,
                ghostdag_k: 18,
            },
            network: NetworkConfig {
                listen_addr: "127.0.0.1:30303".parse().unwrap(),
                bootstrap_nodes: vec![],
                max_peers: 50,
                allowed_peers: vec![],
            },
            rpc: RpcConfig {
                enabled: true,
                listen_addr: "127.0.0.1:8545".parse().unwrap(),
                ws_addr: "127.0.0.1:8546".parse().unwrap(),
                allow_eth_send_transaction: false, // Secure default
                api_key: None,
                cors_origins: vec![], // Secure default: no CORS headers
                rest_api_key: None,
            },
            storage: StorageConfig {
                data_dir: dirs::home_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join(".citrate"),
                pruning: false,
                keep_blocks: 100000,
            },
            mining: MiningConfig {
                enabled: true,
                coinbase: "0x0000000000000000000000000000000000000000".to_string(),
                target_block_time: 5,
                min_gas_price: 1_000_000_000,
            },
            validator: ValidatorConfig::default(),
            vrf: VrfConfig::default(),
            checkpoint: CheckpointNodeConfig::default(),
        }
    }
}

impl NodeConfig {
    /// Validate the entire configuration
    /// Returns error if any subsystem constraints are violated
    pub fn validate(&self) -> Result<(), String> {
        // Validate validator configuration (fail-closed in production)
        self.validator.validate()?;
        Ok(())
    }

    /// Create devnet configuration
    /// Chain ID can be overridden via CITRATE_CHAIN_ID environment variable
    pub fn devnet() -> Self {
        let mut config = Self::default();
        // Chain ID already set from env var in default(), only override if not set
        if std::env::var("CITRATE_CHAIN_ID").is_err() {
            config.chain.chain_id = 40204;
        }
        config.mining.enabled = true;
        config.mining.target_block_time = 2; // Fast blocks for testing
        // C-02: Allow eth_sendTransaction only in devnet mode
        config.rpc.allow_eth_send_transaction = true;
        // WP-X.1: Permissive CORS in devnet
        config.rpc.cors_origins = vec!["*".to_string()];
        // Bind RPC to all interfaces so Tailscale/LAN peers can reach it
        config.rpc.listen_addr = "0.0.0.0:8545".parse().unwrap();
        // WP-W.2: Permissive VRF in devnet (no strict verification)
        config.vrf.strict_vrf = false;
        config
    }

    /// Load from file
    pub fn from_file(path: &PathBuf) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: NodeConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// Save to file
    #[allow(dead_code)]
    pub fn save(&self, path: &PathBuf) -> anyhow::Result<()> {
        let content = toml::to_string_pretty(self)?;
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        // Clear env var to ensure deterministic defaults
        std::env::remove_var("CITRATE_CHAIN_ID");

        let config = NodeConfig::default();

        assert_eq!(config.chain.chain_id, 40204);
        assert_eq!(config.chain.block_time, 5);
        assert_eq!(config.chain.ghostdag_k, 18);
        assert_eq!(config.chain.genesis_hash, None);

        assert_eq!(config.rpc.enabled, true);
        assert_eq!(
            config.rpc.listen_addr,
            "127.0.0.1:8545".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            config.rpc.ws_addr,
            "127.0.0.1:8546".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(config.rpc.allow_eth_send_transaction, false);
        assert!(config.rpc.cors_origins.is_empty());

        assert_eq!(config.network.max_peers, 50);
        assert_eq!(
            config.network.listen_addr,
            "127.0.0.1:30303".parse::<SocketAddr>().unwrap()
        );

        assert_eq!(config.mining.enabled, true);
        assert_eq!(config.mining.target_block_time, 5);
        assert_eq!(config.mining.min_gas_price, 1_000_000_000);

        assert_eq!(config.vrf.strict_vrf, true);
        assert_eq!(config.vrf.migration_mode, false);
    }

    #[test]
    fn test_devnet_config() {
        std::env::remove_var("CITRATE_CHAIN_ID");

        let config = NodeConfig::devnet();

        assert_eq!(config.chain.chain_id, 40204);
        assert_eq!(config.mining.target_block_time, 2);
        assert_eq!(config.mining.enabled, true);
        assert_eq!(config.rpc.allow_eth_send_transaction, true);
        assert_eq!(config.rpc.cors_origins, vec!["*".to_string()]);
        assert_eq!(
            config.rpc.listen_addr,
            "0.0.0.0:8545".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(config.vrf.strict_vrf, false);
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        std::env::remove_var("CITRATE_CHAIN_ID");

        let original = NodeConfig::default();
        let toml_str = toml::to_string_pretty(&original).expect("serialize to TOML");
        let deserialized: NodeConfig =
            toml::from_str(&toml_str).expect("deserialize from TOML");

        assert_eq!(deserialized.chain.chain_id, original.chain.chain_id);
        assert_eq!(deserialized.chain.block_time, original.chain.block_time);
        assert_eq!(deserialized.chain.ghostdag_k, original.chain.ghostdag_k);
        assert_eq!(deserialized.rpc.enabled, original.rpc.enabled);
        assert_eq!(deserialized.rpc.listen_addr, original.rpc.listen_addr);
        assert_eq!(deserialized.rpc.ws_addr, original.rpc.ws_addr);
        assert_eq!(deserialized.network.max_peers, original.network.max_peers);
        assert_eq!(deserialized.mining.enabled, original.mining.enabled);
        assert_eq!(
            deserialized.mining.target_block_time,
            original.mining.target_block_time
        );
        assert_eq!(deserialized.storage.pruning, original.storage.pruning);
        assert_eq!(
            deserialized.storage.keep_blocks,
            original.storage.keep_blocks
        );
        assert_eq!(deserialized.vrf.strict_vrf, original.vrf.strict_vrf);
        assert_eq!(
            deserialized.checkpoint.interval,
            original.checkpoint.interval
        );
    }

    #[test]
    fn test_validator_config_production() {
        let validators = vec!["aabbccdd".to_string()];
        let config = ValidatorConfig::production(validators.clone());

        assert_eq!(config.production_mode, true);
        assert_eq!(config.validators, validators);
        assert_eq!(config.ipfs_api_url, "http://127.0.0.1:5001");
        assert_eq!(config.check_interval_secs, 3600);
        assert_eq!(config.grace_period_hours, 24);
    }

    #[test]
    fn test_validator_config_validate_requires_validators() {
        // Production mode with empty validators should fail
        let config = ValidatorConfig {
            production_mode: true,
            validators: vec![],
            ..ValidatorConfig::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("FAIL-CLOSED"));

        // Production mode with validators should succeed
        let config = ValidatorConfig::production(vec!["aabb".to_string()]);
        assert!(config.validate().is_ok());

        // Non-production mode with empty validators should succeed
        let config = ValidatorConfig::default();
        assert!(config.validate().is_ok());
    }
}
