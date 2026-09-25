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
    #[allow(dead_code)]
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

    /// Genesis profile selector.
    /// Determines which pre-built genesis account set to use when initializing a new chain.
    /// Values: "default" (devnet accounts), "testnet_beta" (public testnet),
    ///         "team_testnet" (team validator-funded genesis), "mainnet".
    /// When absent, the profile is inferred from chain_id for backward compatibility.
    #[serde(default)]
    pub genesis_profile: Option<String>,

    /// PBA-R2 block-validity hardening activation height
    /// (`citrate_consensus::hardening`): tx signature + canonical-id checks on
    /// import (PBA-L1b-001), content-bound `tx_root` (PBA-L1b-002) and the
    /// parent-relative timestamp bound (PBA-L1b-003).
    ///
    /// A CONSENSUS PARAMETER: every node on a chain must agree on it.
    /// Absent (the default, and every shipped 40204 profile) = the rules are
    /// off. Dev profiles set `0` (active from genesis). The env var
    /// `CITRATE_PBA_HARDENING_HEIGHT` (a height, or `off`) overrides it.
    /// Owner runbook: `docs/consensus/PBA_HARDENING_ACTIVATION.md`.
    #[serde(default)]
    pub pba_hardening_height: Option<u64>,
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

    /// PBA-L1a-008: reverse-proxy addresses whose `X-Forwarded-For` /
    /// `X-Real-IP` headers identify the real client for per-client rate
    /// limiting. Empty (default) = every client shares one bucket.
    ///
    /// The HTTP server cannot see the TCP peer address, so forwarding headers
    /// are honoured from ANY connection once this is set. The node therefore
    /// refuses to start with `trusted_proxies` set unless RPC is bound to a
    /// loopback address (so only the co-located proxy can connect).
    #[serde(default)]
    pub trusted_proxies: Vec<std::net::IpAddr>,

    /// PBA-L1a-023: `Host` header allowlist for the HTTP RPC server (see
    /// `citrate_api::server::rpc_host_allowlist`). Empty = loopback-only Host
    /// names when RPC is loopback-bound and not proxied; any Host otherwise.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
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

/// Parse a hardcoded socket address literal. Infallible for valid literals;
/// uses `unreachable!` instead of `unwrap`/`expect` for the zero-panic vanity goal.
fn hardcoded_addr(s: &str) -> SocketAddr {
    s.parse()
        .unwrap_or_else(|_| unreachable!("BUG: invalid hardcoded address literal: {}", s))
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
                genesis_profile: None,
                pba_hardening_height: None,
            },
            network: NetworkConfig {
                listen_addr: hardcoded_addr("127.0.0.1:30303"),
                bootstrap_nodes: vec![],
                max_peers: 50,
                allowed_peers: vec![],
            },
            rpc: RpcConfig {
                enabled: true,
                listen_addr: hardcoded_addr("127.0.0.1:8545"),
                ws_addr: hardcoded_addr("127.0.0.1:8546"),
                allow_eth_send_transaction: false, // Secure default
                api_key: None,
                cors_origins: vec![], // Secure default: no CORS headers
                rest_api_key: None,
                trusted_proxies: vec![],
                allowed_hosts: vec![],
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
                // Empty string means "no coinbase configured". The node will
                // skip block production unless --coinbase is provided on the CLI
                // or set in the config file. This prevents rewards going to 0x000.
                coinbase: String::new(),
                // Default block time — testnet target per CLAUDE.md is 1–2s.
                // Mainnet.toml explicitly overrides to 5s for conservatism,
                // so lowering the default doesn't affect mainnet.
                target_block_time: 1,
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
        config.chain.genesis_profile = Some("default".to_string());
        // PBA-R2: dev profile enforces the hardened validity rules from genesis.
        config.chain.pba_hardening_height = Some(0);
        config.mining.enabled = true;
        config.mining.target_block_time = 2; // Fast blocks for testing
                                             // C-02: Allow eth_sendTransaction only in devnet mode
        config.rpc.allow_eth_send_transaction = true;
        // WP-X.1: Permissive CORS in devnet
        config.rpc.cors_origins = vec!["*".to_string()];
        // Bind RPC to all interfaces so Tailscale/LAN peers can reach it
        config.rpc.listen_addr = hardcoded_addr("0.0.0.0:8545");
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
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
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

        assert!(config.rpc.enabled);
        assert_eq!(
            config.rpc.listen_addr,
            "127.0.0.1:8545".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            config.rpc.ws_addr,
            "127.0.0.1:8546".parse::<SocketAddr>().unwrap()
        );
        assert!(!config.rpc.allow_eth_send_transaction);
        assert!(config.rpc.cors_origins.is_empty());

        assert_eq!(config.network.max_peers, 50);
        assert_eq!(
            config.network.listen_addr,
            "127.0.0.1:30303".parse::<SocketAddr>().unwrap()
        );

        assert!(config.mining.enabled);
        assert_eq!(config.mining.target_block_time, 1);
        assert_eq!(config.mining.min_gas_price, 1_000_000_000);

        assert!(config.vrf.strict_vrf);
        assert!(!config.vrf.migration_mode);
    }

    #[test]
    fn test_devnet_config() {
        std::env::remove_var("CITRATE_CHAIN_ID");

        let config = NodeConfig::devnet();

        assert_eq!(config.chain.chain_id, 40204);
        assert_eq!(config.mining.target_block_time, 2);
        assert!(config.mining.enabled);
        assert!(config.rpc.allow_eth_send_transaction);
        assert_eq!(config.rpc.cors_origins, vec!["*".to_string()]);
        assert_eq!(
            config.rpc.listen_addr,
            "0.0.0.0:8545".parse::<SocketAddr>().unwrap()
        );
        assert!(!config.vrf.strict_vrf);
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        std::env::remove_var("CITRATE_CHAIN_ID");

        let original = NodeConfig::default();
        let toml_str = toml::to_string_pretty(&original).expect("serialize to TOML");
        let deserialized: NodeConfig = toml::from_str(&toml_str).expect("deserialize from TOML");

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

        assert!(config.production_mode);
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
        assert!(result.unwrap_err().contains("FAIL-CLOSED"));

        // Production mode with validators should succeed
        let config = ValidatorConfig::production(vec!["aabb".to_string()]);
        assert!(config.validate().is_ok());

        // Non-production mode with empty validators should succeed
        let config = ValidatorConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_team_testnet_toml_parses() {
        // Verify the team-testnet.toml file is valid against NodeConfig
        let toml_content = include_str!("../config/team-testnet.toml");
        let config: NodeConfig =
            toml::from_str(toml_content).expect("team-testnet.toml must parse as valid NodeConfig");

        assert_eq!(config.chain.chain_id, 40204);
        assert_eq!(config.chain.block_time, 2);
        assert_eq!(config.chain.ghostdag_k, 18);
        assert_eq!(
            config.chain.genesis_profile.as_deref(),
            Some("team_testnet")
        );

        assert_eq!(
            config.network.listen_addr,
            "0.0.0.0:30303".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(config.network.max_peers, 20);
        assert!(config.network.bootstrap_nodes.is_empty());

        assert!(config.rpc.enabled);
        // PBA-L1a-012: the team profile used to serve unsigned
        // eth_sendTransaction on 0.0.0.0:8545 (chain 40204). It is now
        // loopback-only with unsigned send disabled.
        assert!(!config.rpc.allow_eth_send_transaction);
        assert!(config.rpc.listen_addr.ip().is_loopback());
        assert!(config.rpc.ws_addr.ip().is_loopback());
        // Team/public configs must use explicit origins, not wildcard
        assert_eq!(
            config.rpc.cors_origins,
            vec![
                "http://localhost:3000".to_string(),
                "https://citrate.ai".to_string(),
                "https://explorer.citrate.ai".to_string(),
            ]
        );
        assert!(
            !config.rpc.cors_origins.contains(&"*".to_string()),
            "Team/public configs must not use wildcard CORS"
        );

        assert!(config.mining.enabled);
        assert_eq!(config.mining.target_block_time, 2);

        assert!(!config.validator.production_mode);
        assert!(config.vrf.strict_vrf);
        assert!(!config.vrf.migration_mode);

        assert_eq!(config.checkpoint.interval, 50);
        assert_eq!(config.checkpoint.committee_size, 10);
        assert_eq!(config.checkpoint.quorum_threshold, 7);
    }

    #[test]
    fn test_testnet_toml_parses_with_strict_vrf() {
        let toml_content = include_str!("../config/testnet.toml");
        let config: NodeConfig =
            toml::from_str(toml_content).expect("testnet.toml must parse as valid NodeConfig");

        assert_eq!(config.chain.chain_id, 40204);
        assert_eq!(config.chain.block_time, 1);
        assert!(config.rpc.enabled);
        assert!(config.vrf.strict_vrf);
        assert!(!config.vrf.migration_mode);
    }

    #[test]
    fn test_mainnet_toml_parses_with_strict_vrf() {
        let toml_content = include_str!("../config/mainnet.toml");
        let config: NodeConfig =
            toml::from_str(toml_content).expect("mainnet.toml must parse as valid NodeConfig");

        assert_eq!(config.chain.chain_id, 40204);
        assert!(config.validator.production_mode);
        assert!(config.vrf.strict_vrf);
        assert!(!config.vrf.migration_mode);
    }

    #[test]
    fn test_genesis_profile_none_by_default() {
        std::env::remove_var("CITRATE_CHAIN_ID");
        let config = NodeConfig::default();
        assert!(config.chain.genesis_profile.is_none());
    }

    #[test]
    fn test_devnet_uses_default_genesis_profile() {
        std::env::remove_var("CITRATE_CHAIN_ID");
        let config = NodeConfig::devnet();
        assert_eq!(config.chain.genesis_profile.as_deref(), Some("default"));
    }

    /// R2: the node resolves the activation height through the ONE shared
    /// resolver (env override, else `[chain] pba_hardening_height`) and
    /// publishes it before constructing any gated component.
    #[test]
    fn pba_r2_node_uses_the_shared_resolver_before_components() {
        let main = include_str!("main.rs");
        let start = main.find("async fn start_node(").expect("start_node");
        let body = &main[start..];
        let init = body
            .find("citrate_consensus::hardening::init_pba_hardening_height(")
            .expect("start_node must publish via init_pba_hardening_height");
        for ctor in ["GhostDag::new(", "Executor::with_storage(", "SyncManager::new(", "GossipProtocol::new("] {
            let at = body.find(ctor).unwrap_or_else(|| panic!("{ctor} in start_node"));
            assert!(init < at, "activation must be published before {ctor}");
        }
        assert!(
            !main.contains("activation::set_pba_hardening_height(config.chain"),
            "no second publication path that bypasses the env override"
        );
    }
}

/// PBA-R2 release-prep finding: a node configured ONLY through the
/// `CITRATE_PBA_HARDENING_HEIGHT` env override must activate every gated rule
/// (consensus-layer and execution-layer) at the same height as a node
/// configured through `[chain].pba_hardening_height`, or it forks at H.
#[cfg(test)]
mod pba_activation_env_tests {
    use super::*;
    use citrate_consensus::hardening::{
        init_pba_hardening_height, resolve_pba_hardening_height, set_pba_hardening_height,
        PbaHardening, PBA_HARDENING_ENV,
    };
    use citrate_consensus::types::{BlockBuilder, Hash, PublicKey, Signature, Transaction};
    use citrate_execution::revm_adapter::{
        execute_contract_call_with_context, BlockContext, ValueSemantics,
    };
    use citrate_execution::types::{
        AccessPolicy, Address, ModelId, ModelMetadata, ModelState, UsageStats,
    };
    use citrate_execution::{Executor, StateDB};
    use primitive_types::U256;
    use std::sync::Arc;

    /// Far above every height other node unit tests use, so publishing it
    /// process-wide cannot change their behaviour.
    const H: u64 = 5_000_000;

    /// Serialises the two tests that mutate `CITRATE_PBA_HARDENING_HEIGHT`.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn staticcall_ok(target: [u8; 20], block_number: u64) -> bool {
        let state = Arc::new(StateDB::new());
        let caller = Address([0x11; 20]);
        let fwd = Address([0x22; 20]);
        state
            .accounts
            .set_balance(caller, U256::from(10u64).pow(U256::from(18u64)));
        let mut code = vec![0x36, 0x5f, 0x5f, 0x37, 0x60, 0x20, 0x5f, 0x36, 0x5f, 0x73];
        code.extend_from_slice(&target);
        code.extend_from_slice(&[0x5a, 0xfa, 0x60, 0x20, 0x52, 0x60, 0x40, 0x5f, 0xf3]);
        state.set_code(fwd, code);
        let (out, _, _) = execute_contract_call_with_context(
            state,
            caller,
            fwd,
            vec![0xAB; 4],
            U256::zero(),
            5_000_000,
            U256::from(1_000_000_000u64),
            40204,
            block_number,
            1_000_000,
            BlockContext::default(),
            None,
            None,
            None,
            ValueSemantics::RevmAuthoritative,
        )
        .expect("forwarder executes");
        out[63] == 1
    }

    async fn inference_status(height: u64) -> bool {
        let state = Arc::new(StateDB::new());
        let sender = PublicKey::new([0x5A; 32]);
        let from = citrate_execution::address_utils::normalize_address(&sender);
        state
            .accounts
            .set_balance(from, U256::from(10u64).pow(U256::from(21u64)));
        let mid = ModelId(Hash::new([0x4D; 32]));
        state
            .register_model(
                mid,
                ModelState {
                    owner: Address([0xAA; 20]),
                    model_hash: Hash::new([1; 32]),
                    version: 1,
                    metadata: ModelMetadata::default(),
                    access_policy: AccessPolicy::Public,
                    usage_stats: UsageStats::default(),
                },
            )
            .expect("model");
        let exec = Executor::new(state);
        let mut data = vec![0x02, 0, 0, 0];
        data.extend_from_slice(mid.0.as_bytes());
        let tx = Transaction {
            hash: Hash::new([0x19; 32]),
            from: sender,
            to: Some(PublicKey::new([0x77; 32])),
            gas_limit: 2_000_000,
            gas_price: 1_000_000_000,
            data,
            signature: Signature::new([1; 64]),
            chain_id: Some(40204),
            ..Default::default()
        };
        let blk = BlockBuilder::new()
            .hash(Hash::new([7; 32]))
            .parent(Hash::default())
            .height(height)
            .timestamp(1_000_000)
            .build_unhashed();
        exec.execute_transaction(&blk, &tx)
            .await
            .expect("executes")
            .status
    }

    #[tokio::test]
    async fn env_override_activates_every_gated_path() {
        // Config says "unset"; only the env override schedules H.
        let cfg = NodeConfig::default();
        assert_eq!(cfg.chain.pba_hardening_height, None);
        let resolved = {
            let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            std::env::set_var(PBA_HARDENING_ENV, H.to_string());
            // Exactly what start_node does: resolve (env over TOML) and publish.
            let r = init_pba_hardening_height(cfg.chain.pba_hardening_height);
            std::env::remove_var(PBA_HARDENING_ENV);
            r
        };
        assert_eq!(resolved, Ok(Some(H)), "env override must be honoured");

        // Consensus-layer view (CHAIN-CONS rules) and execution-layer view
        // read the SAME store.
        assert!(PbaHardening::from_process().active_at(H));
        assert!(!PbaHardening::from_process().active_at(H - 1));
        assert!(citrate_execution::activation::pba_hardening_active(H));
        assert!(!citrate_execution::activation::pba_hardening_active(H - 1));

        // PBA-L1a-022 (REVM bridge flag, shared by -013 and -025): reserved
        // precompile call fails from H, legacy below.
        let mut reserved = [0u8; 20];
        reserved[18] = 0x01;
        reserved[19] = 0x04;
        assert!(staticcall_ok(reserved, H - 1), "legacy below H");
        assert!(!staticcall_ok(reserved, H), "hardened from H");

        // PBA-L1a-019 (executor): in-consensus inference reverts from H.
        assert!(inference_status(H - 1).await, "legacy below H");
        assert!(!inference_status(H).await, "hardened from H");

        set_pba_hardening_height(None);
    }

    #[test]
    fn env_override_off_and_garbage() {
        let mut cfg = NodeConfig::default();
        cfg.chain.pba_hardening_height = Some(10);
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(PBA_HARDENING_ENV, "off");
        let off = resolve_pba_hardening_height(cfg.chain.pba_hardening_height);
        std::env::set_var(PBA_HARDENING_ENV, "soon");
        let bad = resolve_pba_hardening_height(cfg.chain.pba_hardening_height);
        std::env::remove_var(PBA_HARDENING_ENV);
        assert_eq!(off, Ok(None));
        assert!(bad.is_err(), "unparseable override must abort start-up");
        assert_eq!(
            resolve_pba_hardening_height(cfg.chain.pba_hardening_height),
            Ok(Some(10))
        );
    }
}
