use anyhow::Result;
use clap::{Parser, Subcommand};
use citrate_api::{EthSubscriptionServer, RpcConfig, RpcServer};
use citrate_consensus::crypto;
use citrate_execution::{Executor, StateDB};
use citrate_economics::{UnifiedEconomicsManager, UnifiedEconomicsConfig, StakeholderType};
use citrate_network::peer::PeerId;
use citrate_network::peer::{PeerManager, PeerManagerConfig};
use citrate_network::{NetworkTransport, GossipProtocol, GossipConfig, Discovery, DiscoveryConfig, SyncManager, SyncConfig};
use citrate_sequencer::mempool::{Mempool, MempoolConfig};
use citrate_storage::{pruning::PruningConfig, StorageConfig, StorageManager};
use citrate_storage::crypto::at_rest::EncryptionAtRestConfig;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

mod adapters;
mod artifact;
mod block_serve;
pub mod bundled_model;
mod canonical_apply;
mod commands;
mod config;
mod genesis;
mod inference;
pub mod logging;
pub mod metrics;
mod model_manager;
mod model_verifier;
mod network_inference;
mod persistent_dag;
mod producer;
mod registry_sync;
mod contribution_recorder;
mod sync;

use config::NodeConfig;
use citrate_consensus::dag_store::DagStore;
use citrate_consensus::ghostdag::GhostDag;
use citrate_consensus::types::GhostDagParams;
use genesis::{initialize_genesis_state, initialize_genesis_state_with_profile, GenesisConfig};
use producer::BlockProducer;

/// The canonical public testnet config, embedded at compile time so a fresh
/// install joins the testnet without install.sh having to drop a file
/// (turnkey onboarding, workstream D). On first run with no config present the
/// node materialises this to ~/.citrate/node.toml after the network choice.
const TESTNET_BETA_CONFIG: &str = include_str!("../config/testnet-beta.toml");

/// First-run network selection. Returns the chosen [`NodeConfig`] and persists
/// it to `~/.citrate/node.toml` so the choice is sticky on subsequent launches.
///
/// Selection precedence: explicit `--network`, else an interactive prompt when
/// stdin is a TTY, else a testnet default for non-interactive (service) starts.
fn first_run_select_config(network_flag: Option<&str>) -> anyhow::Result<NodeConfig> {
    use std::io::IsTerminal;

    let join_testnet = match network_flag.map(|s| s.trim().to_ascii_lowercase()) {
        Some(s) if s == "testnet" => true,
        Some(s) if s == "local" || s == "devnet" => false,
        Some(other) => {
            anyhow::bail!("--network must be 'testnet' or 'local', got '{}'", other);
        }
        None => {
            if std::io::stdin().is_terminal() {
                prompt_join_testnet()
            } else {
                tracing::info!(
                    "First run, no config, non-interactive — defaulting to the public testnet. \
                     Pass --network local for an isolated devnet."
                );
                true
            }
        }
    };

    let config = if join_testnet {
        toml::from_str::<NodeConfig>(TESTNET_BETA_CONFIG)
            .map_err(|e| anyhow::anyhow!("embedded testnet config is invalid: {}", e))?
    } else {
        NodeConfig::default()
    };

    // Persist the choice so the next launch auto-loads it (and the user can edit it).
    if let Some(home) = dirs::home_dir() {
        let path = home.join(".citrate").join("node.toml");
        match config.save(&path) {
            Ok(()) => tracing::info!(
                "First-run setup: wrote {} config to {}",
                if join_testnet { "testnet" } else { "local devnet" },
                path.display()
            ),
            Err(e) => tracing::warn!("Could not persist first-run config to {}: {}", path.display(), e),
        }
    }
    Ok(config)
}

/// Interactive testnet-vs-local prompt for first run on a TTY.
fn prompt_join_testnet() -> bool {
    use std::io::Write;
    print!(
        "\nWelcome to Citrate. This looks like a first run.\n\
         Join the public Citrate testnet, or run an isolated local devnet?\n\
         \n  [T] Join testnet  (connect to the live network and sync)  (default)\n  \
         [L] Local devnet  (a private chain on this machine)\n\nChoice [T/L]: "
    );
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return true; // default to testnet on read error
    }
    !matches!(line.trim().to_ascii_lowercase().as_str(), "l" | "local" | "devnet")
}

#[derive(Parser)]
#[command(name = "citrate")]
#[command(about = "Citrate blockchain node")]
struct Cli {
    /// Configuration file path
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Network to join on first run when no config exists: "testnet" or "local".
    /// Skips the interactive prompt. If unset and stdin is a TTY the node asks;
    /// non-interactively (service/daemon) it defaults to testnet.
    #[arg(long, value_name = "testnet|local")]
    network: Option<String>,

    /// Data directory
    #[arg(short, long, value_name = "DIR")]
    data_dir: Option<PathBuf>,

    /// Enable mining
    #[arg(long)]
    mine: bool,

    /// P2P listen address (e.g., 0.0.0.0:30303)
    #[arg(long, value_name = "ADDR")]
    p2p_addr: Option<String>,

    /// Bootstrap nodes (can be specified multiple times)
    /// Format: peer_id@ip:port or ip:port
    #[arg(long, value_name = "NODE")]
    bootstrap_nodes: Vec<String>,

    /// RPC listen address (e.g., 127.0.0.1:8545)
    #[arg(long, value_name = "ADDR")]
    rpc_addr: Option<String>,

    /// Maximum number of peers
    #[arg(long, default_value = "50")]
    max_peers: usize,

    /// Chain ID
    #[arg(long, default_value = "40204")]
    chain_id: u64,

    /// Coinbase address for mining rewards (hex)
    #[arg(long)]
    coinbase: Option<String>,

    /// API key for JSON-RPC authentication (overrides config file and CITRATE_API_KEY env)
    #[arg(long, value_name = "KEY")]
    api_key: Option<String>,

    /// Disable RPC server
    #[arg(long)]
    no_rpc: bool,

    /// Run as bootstrap node (no active connections)
    #[arg(long)]
    bootstrap: bool,

    /// Force start even with state root mismatch (WP-K.6)
    #[arg(long)]
    force_start: bool,

    /// Subcommands
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new chain with genesis block
    Init {
        /// Chain ID (default: 40204 testnet beta; pass explicit value for other networks)
        #[arg(long, default_value = "40204")]
        chain_id: u64,
    },

    /// Run devnet with default configuration
    Devnet,

    /// Generate a new keypair for signing
    Keygen {
        /// Generate ed25519 keypair (for P2P identity). Default is secp256k1 (EVM/MetaMask compatible).
        #[arg(long)]
        ed25519: bool,
    },

    /// Manage AI models (download, pin, list)
    Model {
        #[command(subcommand)]
        command: ModelCommands,
    },

    /// Show genesis block information
    GenesisInfo,

    /// Wallet management (accounts, balances, transfers)
    Wallet {
        /// Wallet keystore path
        #[arg(short, long)]
        keystore: Option<PathBuf>,

        /// RPC URL
        #[arg(short, long, default_value = "http://localhost:8545")]
        rpc: String,

        /// Chain ID (default: 40204 testnet beta)
        #[arg(long, default_value = "40204")]
        wallet_chain_id: u64,

        #[command(subcommand)]
        command: commands::wallet::WalletCommands,
    },

    /// Account management (CLI tools)
    #[command(subcommand)]
    Account(citrate_cli::commands::account::AccountCommands),

    /// Smart contract deployment and interaction
    #[command(subcommand)]
    Contract(citrate_cli::commands::contract::ContractCommands),

    /// Network and node operations
    #[command(subcommand)]
    Network(citrate_cli::commands::network::NetworkCommands),

    /// Governance parameter management
    #[command(subcommand)]
    Governance(citrate_cli::commands::governance::GovernanceCommands),

    /// Advanced network monitoring and debugging
    #[command(subcommand)]
    Advanced(citrate_cli::commands::advanced::AdvancedCommands),

    /// Interactive wizards for setup and deployment
    #[command(subcommand)]
    Wizard(citrate_cli::commands::wizard::WizardCommands),
}

#[derive(Subcommand)]
enum ModelCommands {
    /// List all pinned models
    List,

    /// Show status of a specific model
    Status {
        /// IPFS CID of the model
        cid: String,
    },

    /// Manually pin a model by CID
    Pin {
        /// IPFS CID of the model to pin
        cid: String,
    },

    /// Unpin a model by CID
    Unpin {
        /// IPFS CID of the model to unpin
        cid: String,
    },

    /// Automatically pin all required models from genesis
    AutoPin {
        /// Data directory
        #[arg(short, long, value_name = "DIR")]
        data_dir: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize structured logging
    // Uses LOG_FORMAT env var (json, pretty, compact) and RUST_LOG for levels
    let log_config = if std::env::var("LOG_FORMAT").map(|f| f == "json").unwrap_or(false) {
        logging::LogConfig::production()
    } else {
        logging::LogConfig::from_env()
    };

    if let Err(e) = logging::init_logging(&log_config) {
        // Fallback to basic logging if structured logging fails
        eprintln!("Warning: Failed to initialize structured logging: {}", e);
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env().add_directive("citrate=info".parse()?))
            .init();
    }

    let cli = Cli::parse();

    // Handle subcommands
    match cli.command {
        Some(Commands::Init { chain_id }) => {
            init_chain(chain_id).await?;
            return Ok(());
        }
        Some(Commands::Devnet) => {
            run_devnet(
                cli.coinbase.clone(),
                cli.data_dir.clone(),
                cli.p2p_addr.clone(),
                cli.rpc_addr.clone(),
            ).await?;
            return Ok(());
        }
        Some(Commands::Keygen { ed25519 }) => {
            generate_keypair(ed25519);
            return Ok(());
        }
        Some(Commands::Model { command }) => {
            handle_model_command(command, cli.data_dir.clone()).await?;
            return Ok(());
        }
        Some(Commands::GenesisInfo) => {
            show_genesis_info()?;
            return Ok(());
        }
        Some(Commands::Wallet { keystore, rpc, wallet_chain_id, command }) => {
            commands::wallet::execute(command, keystore, rpc, wallet_chain_id).await?;
            return Ok(());
        }
        Some(Commands::Account(cmd)) => {
            let config = citrate_cli::config::Config::load(None, cli.rpc_addr.as_deref())?;
            citrate_cli::commands::account::execute(cmd, &config).await?;
            return Ok(());
        }
        Some(Commands::Contract(cmd)) => {
            let config = citrate_cli::config::Config::load(None, cli.rpc_addr.as_deref())?;
            citrate_cli::commands::contract::execute(cmd, &config).await?;
            return Ok(());
        }
        Some(Commands::Network(cmd)) => {
            let config = citrate_cli::config::Config::load(None, cli.rpc_addr.as_deref())?;
            citrate_cli::commands::network::execute(cmd, &config).await?;
            return Ok(());
        }
        Some(Commands::Governance(cmd)) => {
            let config = citrate_cli::config::Config::load(None, cli.rpc_addr.as_deref())?;
            citrate_cli::commands::governance::execute(cmd, &config).await?;
            return Ok(());
        }
        Some(Commands::Advanced(cmd)) => {
            let config = citrate_cli::config::Config::load(None, cli.rpc_addr.as_deref())?;
            citrate_cli::commands::advanced::execute(cmd, &config).await?;
            return Ok(());
        }
        Some(Commands::Wizard(cmd)) => {
            let config = citrate_cli::config::Config::load(None, cli.rpc_addr.as_deref())?;
            citrate_cli::commands::wizard::execute(cmd, &config).await?;
            return Ok(());
        }
        None => {
            // Run normal node
        }
    }

    // Load or create config.
    //
    // Resolution order (first match wins):
    //   1. --config <path>                         (explicit CLI flag)
    //   2. $CITRATE_CONFIG                          (environment override)
    //   3. ~/.citrate/node.toml                     (per-user default)
    //   4. /etc/citrate/node.toml                   (system-wide default)
    //   5. NodeConfig::default() (dev/empty)        (final fallback)
    //
    // Steps 3-4 are the "2-click install" path: the installer drops
    // testnet-beta.toml at ~/.citrate/node.toml so the bare
    // `citrate-node` invocation auto-joins the testnet mesh via the
    // baked-in bootnodes.
    let has_config_file = cli.config.is_some();
    let resolved_config_path: Option<std::path::PathBuf> = cli.config.clone().or_else(|| {
        if let Ok(env_path) = std::env::var("CITRATE_CONFIG") {
            let p = std::path::PathBuf::from(env_path);
            if p.exists() {
                tracing::info!("config: using $CITRATE_CONFIG → {}", p.display());
                return Some(p);
            }
        }
        if let Some(home) = dirs::home_dir() {
            let p = home.join(".citrate").join("node.toml");
            if p.exists() {
                tracing::info!("config: auto-loading {}", p.display());
                return Some(p);
            }
        }
        let p = std::path::PathBuf::from("/etc/citrate/node.toml");
        if p.exists() {
            tracing::info!("config: auto-loading {}", p.display());
            return Some(p);
        }
        None
    });
    let config = if let Some(config_path) = resolved_config_path {
        NodeConfig::from_file(&config_path)?
    } else {
        // First run: no config anywhere. Ask the operator whether to join the
        // public testnet or run a local devnet (honoring --network / TTY /
        // non-interactive-default), then persist the choice to
        // ~/.citrate/node.toml so it's a one-time decision. This is what makes
        // a double-clicked install auto-join + sync without manual setup.
        first_run_select_config(cli.network.as_deref())?
    };

    // Override with CLI args
    let mut config = config;
    if let Some(data_dir) = cli.data_dir {
        config.storage.data_dir = data_dir;
    }
    if cli.mine {
        config.mining.enabled = true;
    }

    // Network configuration overrides
    if let Some(p2p_addr) = cli.p2p_addr {
        config.network.listen_addr = p2p_addr
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid P2P address: {}", e))?;
    }
    if !cli.bootstrap_nodes.is_empty() {
        config.network.bootstrap_nodes = cli.bootstrap_nodes;
    }
    if let Some(rpc_addr) = cli.rpc_addr {
        config.rpc.listen_addr = rpc_addr
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid RPC address: {}", e))?;
    }
    config.network.max_peers = cli.max_peers;

    // Only override chain_id if no config file was provided
    // This allows config file to set chain_id when using --config flag
    if !has_config_file {
        // No config file provided, use CLI arg (or its default)
        config.chain.chain_id = cli.chain_id;
    }

    if let Some(coinbase) = cli.coinbase {
        config.mining.coinbase = coinbase;
    }
    if cli.no_rpc {
        config.rpc.enabled = false;
    }
    if let Some(api_key) = cli.api_key {
        config.rpc.api_key = Some(api_key);
    }

    // If running as bootstrap node, clear bootstrap_nodes list
    if cli.bootstrap {
        config.network.bootstrap_nodes.clear();
        info!(
            "Running as bootstrap node on {}",
            config.network.listen_addr
        );
    }

    // Validate configuration (fail-closed for production mode)
    // This catches production_mode=true with empty validators early
    if let Err(e) = config.validate() {
        error!("{}", e);
        return Err(anyhow::anyhow!("{}", e));
    }

    // Initialize chain if genesis block doesn't exist in storage
    // C1 fix: Check for genesis block existence, not directory existence.
    // Pre-created dirs or partial state no longer bypass genesis init.
    std::fs::create_dir_all(&config.storage.data_dir)?;

    // If a storage-at-rest key is supplied (CITRATE_STORAGE_KEY, from the parent
    // process's OS keyring), the probe MUST open the DB with the same encryption
    // config as the live `start_node` storage below — otherwise the genesis
    // probe would open a plaintext handle over an encrypted DB (or vice-versa)
    // and the mismatch guard in `open_encrypted` would reject it.
    let probe_encryption = at_rest_encryption_from_env()?;
    let probe_storage = Arc::new(StorageManager::with_config(
        &config.storage.data_dir,
        StorageConfig {
            pruning: PruningConfig::default(),
            encryption: probe_encryption,
        },
    )?);

    let has_genesis = probe_storage.blocks.get_block_by_height(0)
        .ok()
        .flatten()
        .and_then(|hash| probe_storage.blocks.get_block(&hash).ok().flatten())
        .is_some();

    if !has_genesis {
        info!("No genesis block found, initializing genesis...");

        let state_db = Arc::new(StateDB::new());
        let executor = Arc::new(Executor::with_storage(
            state_db,
            Some(probe_storage.state.clone()),
        ));

        let genesis_config = genesis::GenesisConfig {
            chain_id: config.chain.chain_id,
            ..Default::default()
        };

        let genesis_profile = config.chain.genesis_profile.as_deref();
        genesis::initialize_genesis_state_with_profile(
            probe_storage,
            executor,
            &genesis_config,
            genesis_profile,
        ).await?;
        info!("Genesis state initialized for chain ID {}", config.chain.chain_id);
    } else {
        // WP-K.6: Verify state root consistency before proceeding.
        // If persisted state diverges from genesis, the node would run with corrupted state.
        info!("Genesis block found in storage, verifying state root...");
        let genesis_block = probe_storage.blocks.get_block_by_height(0)
            .ok()
            .flatten()
            .and_then(|hash| probe_storage.blocks.get_block(&hash).ok().flatten())
            .ok_or_else(|| anyhow::anyhow!("Genesis block must exist (checked above)"))?;

        let persisted_root = probe_storage.state
            .get_state_root(&genesis_block.header.block_hash)
            .ok()
            .flatten();

        match persisted_root {
            Some(root) if root != genesis_block.state_root => {
                if config.validator.production_mode && !cli.force_start {
                    error!(
                        "FATAL: State root mismatch! Persisted: {}, Expected: {}",
                        root, genesis_block.state_root
                    );
                    error!("Use --force-start to override (data may be corrupted)");
                    return Err(anyhow::anyhow!("State root mismatch on startup"));
                } else {
                    warn!(
                        "State root mismatch (devnet mode, continuing): Persisted: {}, Expected: {}",
                        root, genesis_block.state_root
                    );
                }
            }
            Some(root) => {
                info!("State root verified: {}", root);
            }
            None => {
                // No persisted state root entry for genesis (pre-K.6 data) — skip check
                info!("No persisted state root for genesis block (pre-K.6 data), skipping verification");
            }
        }

        drop(probe_storage);
    }

    // Start node
    start_node(config).await
}

async fn handle_model_command(command: ModelCommands, data_dir: Option<PathBuf>) -> Result<()> {
    use model_manager::{ModelManager, ModelManagerConfig};

    let models_dir = data_dir.clone()
        .unwrap_or_else(|| dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join(".citrate"))
        .join("models");

    let config = ModelManagerConfig {
        models_dir: models_dir.clone(),
        ..Default::default()
    };

    let manager = ModelManager::new(config).await
        .map_err(|e| anyhow::anyhow!("Failed to create model manager: {}", e))?;

    match command {
        ModelCommands::List => {
            info!("Fetching list of pinned models...");
            let models = manager.list_pinned_models().await;

            if models.is_empty() {
                println!("No models currently pinned.");
                println!("Run 'citrate model auto-pin' to automatically pin required models.");
            } else {
                println!("\nPinned Models:");
                println!("{:-<100}", "");
                for model in models {
                    println!("Model ID: {}", model.model_id);
                    println!("CID:      {}", model.cid);
                    println!("Size:     {} MB", model.size_bytes / 1_000_000);
                    println!("Path:     {}", model.file_path.display());
                    println!("Status:   {:?}", model.status);
                    println!("{:-<100}", "");
                }
            }
        }

        ModelCommands::Status { cid } => {
            info!("Checking status of model: {}", cid);
            match manager.get_model_status(&cid).await {
                Some(status) => {
                    println!("Model CID: {}", cid);
                    println!("Status: {:?}", status);

                    if let Some(path) = manager.get_model_path(&cid).await {
                        println!("Path: {}", path.display());
                    }
                }
                None => {
                    println!("Model {} is not pinned.", cid);
                    println!("Run 'citrate model pin {}' to pin it.", cid);
                }
            }
        }

        ModelCommands::Pin { cid } => {
            println!("Pinning model from IPFS: {}", cid);

            // Check IPFS daemon first
            if let Err(e) = manager.check_ipfs_daemon().await {
                eprintln!("Error: {}", e);
                println!("\nPlease ensure IPFS is running: ipfs daemon");
                return Err(anyhow::anyhow!("IPFS daemon not available"));
            }

            // Create a RequiredModel entry for the manual pin (unknown size, no hash verification)
            let model = citrate_consensus::types::RequiredModel::new(
                citrate_consensus::types::ModelId(format!("manual-pin-{}", &cid[..8.min(cid.len())])),
                cid.clone(),
                citrate_consensus::types::Hash::new([0u8; 32]), // skip hash verification
                0, // unknown size
                0, // no slash penalty
            );

            match manager.download_and_pin_model(&model).await {
                Ok(()) => println!("Successfully pinned model {}", cid),
                Err(e) => {
                    eprintln!("Failed to pin model: {}", e);
                    return Err(anyhow::anyhow!("Pin failed: {}", e));
                }
            }
        }

        ModelCommands::Unpin { cid } => {
            info!("Unpinning model: {}", cid);
            manager.unpin_model(&cid).await
                .map_err(|e| anyhow::anyhow!("Failed to unpin model: {}", e))?;
            println!("Successfully unpinned model {}", cid);
        }

        ModelCommands::AutoPin { data_dir: cmd_data_dir } => {
            let _data_dir = cmd_data_dir
                .or(data_dir)
                .unwrap_or_else(|| dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join(".citrate"));

            info!("Initializing genesis to get required models...");

            // Load genesis config to get required models
            let genesis_config = GenesisConfig {
                timestamp: 0,
                chain_id: 40204,
                initial_accounts: vec![],
            };

            let genesis_block = genesis::create_genesis_block(&genesis_config);

            if genesis_block.required_pins.is_empty() {
                println!("No required models found in genesis block.");
                return Ok(());
            }

            println!("\nRequired Models from Genesis:");
            for model in &genesis_block.required_pins {
                println!("  - {} (CID: {}, Size: {} MB)",
                    model.model_id.0,
                    model.ipfs_cid,
                    model.size_bytes / 1_000_000
                );
            }

            println!("\nChecking IPFS daemon...");
            if let Err(e) = manager.check_ipfs_daemon().await {
                eprintln!("Error: {}", e);
                println!("\nPlease ensure IPFS is installed and running:");
                println!("  1. Install IPFS: https://docs.ipfs.tech/install/");
                println!("  2. Start daemon: ipfs daemon");
                return Err(anyhow::anyhow!("IPFS daemon not available"));
            }

            println!("IPFS daemon is running ✓\n");
            println!("Starting automatic model pinning...");
            println!("This may take a while for large models (up to {} MB total)\n",
                genesis_block.required_pins.iter().map(|m| m.size_bytes).sum::<u64>() / 1_000_000
            );

            manager.auto_pin_required_models(&genesis_block.required_pins).await
                .map_err(|e| anyhow::anyhow!("Failed to auto-pin models: {}", e))?;

            println!("\n✓ All required models have been pinned successfully!");
            println!("Models stored in: {}", models_dir.display());
        }
    }

    Ok(())
}

async fn init_chain(chain_id: u64) -> Result<()> {
    info!("Initializing new chain with ID {}", chain_id);

    let temp_dir = PathBuf::from(".citrate");
    std::fs::create_dir_all(&temp_dir)?;

    // Create storage
    let storage = Arc::new(StorageManager::new(&temp_dir, PruningConfig::default())?);

    // Create executor with persistent storage
    let state_db = Arc::new(StateDB::new());
    let executor = Arc::new(Executor::with_storage(
        state_db,
        Some(storage.state.clone()),
    ));

    // Initialize genesis
    let genesis_config = GenesisConfig {
        chain_id,
        ..Default::default()
    };

    let genesis_hash = initialize_genesis_state(storage.clone(), executor, &genesis_config).await?;

    info!(
        "Genesis block created: {:?}",
        hex::encode(&genesis_hash.as_bytes()[..8])
    );
    info!("Chain initialized in {:?}", temp_dir);

    Ok(())
}

async fn run_devnet(
    coinbase: Option<String>,
    data_dir: Option<PathBuf>,
    p2p_addr: Option<String>,
    rpc_addr: Option<String>,
) -> Result<()> {
    info!("Starting devnet...");

    let mut config = NodeConfig::devnet();
    config.storage.data_dir = data_dir.unwrap_or_else(|| PathBuf::from(".citrate-devnet"));
    config.chain.genesis_profile = Some("default".to_string());

    // Apply CLI coinbase if provided
    if let Some(cb) = coinbase {
        config.mining.coinbase = cb;
    }
    if let Some(addr) = p2p_addr {
        config.network.listen_addr = addr
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid P2P address: {}", e))?;
    }
    if let Some(addr) = rpc_addr {
        config.rpc.listen_addr = addr
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid RPC address: {}", e))?;
    }

    // Initialize chain if needed.
    // An existing but empty temp dir should still bootstrap genesis.
    std::fs::create_dir_all(&config.storage.data_dir)?;
    {
        let storage = Arc::new(StorageManager::new(
            &config.storage.data_dir,
            PruningConfig::default(),
        )?);

        let has_genesis = storage.blocks.get_block_by_height(0)
            .ok()
            .flatten()
            .and_then(|hash| storage.blocks.get_block(&hash).ok().flatten())
            .is_some();

        if !has_genesis {
            let state_db = Arc::new(StateDB::new());
            let executor = Arc::new(Executor::with_storage(
                state_db,
                Some(storage.state.clone()),
            ));

            let genesis_config = GenesisConfig {
                chain_id: config.chain.chain_id,
                ..Default::default()
            };

            initialize_genesis_state_with_profile(
                storage,
                executor,
                &genesis_config,
                Some("default"),
            )
            .await?;
            info!("Devnet chain initialized");
        } else {
            info!("Existing devnet genesis found, reusing initialized chain");
        }
    }

    // Start node with devnet config
    start_node(config).await
}

fn generate_keypair(use_ed25519: bool) {
    if use_ed25519 {
        // Ed25519 — for P2P Noise identity and native Citrate operations
        let signing_key = crypto::generate_keypair();
        let verifying_key = signing_key.verifying_key();

        println!("Ed25519 keypair generated (for P2P / native Citrate):");
        println!("Private key: {}", hex::encode(signing_key.to_bytes()));
        println!("Public key:  {}", hex::encode(verifying_key.to_bytes()));
    } else {
        // Secp256k1 — MetaMask / Foundry / EVM compatible (default)
        use k256::ecdsa::SigningKey as K256SigningKey;
        use sha3::{Digest, Keccak256};

        let secret_key = K256SigningKey::random(&mut rand::thread_rng());
        let public_key = secret_key.verifying_key();

        // Uncompressed public key (65 bytes: 0x04 || x || y)
        let pubkey_bytes = public_key.to_encoded_point(false);
        // Ethereum address = last 20 bytes of Keccak256(pubkey_xy)
        // Skip the 0x04 prefix byte
        let mut hasher = Keccak256::new();
        hasher.update(&pubkey_bytes.as_bytes()[1..]);
        let hash = hasher.finalize();
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..32]);

        let private_key_hex = hex::encode(secret_key.to_bytes());

        println!("Secp256k1 keypair generated (EVM / MetaMask compatible):");
        println!("Private key: 0x{}", private_key_hex);
        println!("Address:     0x{}", hex::encode(address));
        println!();
        println!("Import the private key into MetaMask to use this account.");
        println!("The address above will match what MetaMask displays.");
    }
}

fn show_genesis_info() -> Result<()> {
    println!("=========================================");
    println!("Genesis Block Information");
    println!("=========================================");
    println!();

    info!("Creating genesis block...");
    let genesis_config = genesis::GenesisConfig {
        timestamp: 0,
        chain_id: 40204,
        initial_accounts: vec![],
    };

    let genesis = genesis::create_genesis_block(&genesis_config);

    println!("Block Details:");
    println!("  Height: {}", genesis.header.height);
    println!("  Timestamp: {}", genesis.header.timestamp);
    println!("  Chain ID: {}", genesis_config.chain_id);
    println!("  Block Hash: {}", hex::encode(genesis.header.block_hash.as_bytes()));
    println!();

    // Embedded models
    println!("Embedded Models ({}):", genesis.embedded_models.len());
    let mut total_embedded_size = 0u64;
    for model in &genesis.embedded_models {
        let size_bytes = model.size_bytes();
        let size_mb = size_bytes as f64 / (1024.0 * 1024.0);
        total_embedded_size += size_bytes as u64;
        println!("  - Model ID: {}", model.model_id);
        println!("    Type: {:?}", model.model_type);
        println!("    Size: {:.2} MB ({} bytes)", size_mb, size_bytes);
        println!("    Metadata: {} v{}", model.metadata.name, model.metadata.version);
        println!();
    }

    let total_embedded_mb = total_embedded_size as f64 / (1024.0 * 1024.0);
    println!("Total Embedded Size: {:.2} MB ({} bytes)", total_embedded_mb, total_embedded_size);
    println!();

    // Required pins (IPFS models)
    println!("Required IPFS Pins ({}):", genesis.required_pins.len());
    let mut total_ipfs_size = 0u64;
    for pin in &genesis.required_pins {
        let size_mb = pin.size_bytes as f64 / (1024.0 * 1024.0);
        let size_gb = size_mb / 1024.0;
        total_ipfs_size += pin.size_bytes;

        println!("  - Model ID: {}", pin.model_id);
        println!("    IPFS CID: {}", pin.ipfs_cid);
        println!("    Size: {:.2} GB ({:.2} MB)", size_gb, size_mb);
        println!("    SHA256: {}", hex::encode(pin.sha256_hash.as_bytes()));
        println!();
    }

    let total_ipfs_gb = total_ipfs_size as f64 / (1024.0 * 1024.0 * 1024.0);
    println!("Total IPFS Required: {:.2} GB", total_ipfs_gb);
    println!();

    // Overall summary
    println!("=========================================");
    println!("Summary:");
    println!("  Embedded in genesis: {:.2} MB", total_embedded_mb);
    println!("  Required to pin: {:.2} GB", total_ipfs_gb);
    println!("  Total AI models: {} embedded + {} IPFS", genesis.embedded_models.len(), genesis.required_pins.len());
    println!("=========================================");

    Ok(())
}

/// Encryption-at-rest key sourcing for a light-node / desktop deployment.
///
/// The node itself is key-source-agnostic (`core/storage` was built so "the
/// desktop GUI supplies the bytes, typically from the OS keyring"): when the
/// `CITRATE_STORAGE_KEY` env var is present and holds exactly 64 lowercase/
/// uppercase hex chars (32 bytes), storage-at-rest is enabled with that raw
/// key via `EncryptionAtRestConfig::with_raw_key`. When the var is absent the
/// node keeps the default plaintext path (servers / bootnodes / sequencers are
/// unaffected). A malformed value is a hard error (fail closed) rather than a
/// silent downgrade to plaintext — an operator who asked for encryption and
/// typo'd the key must not get an unencrypted DB.
///
/// The key never touches disk from the node's side: the parent process
/// (citrate-core's SidecarSupervisor) holds it in the OS keyring and passes it
/// only through this env var to the spawned child. The commitment in
/// `<data_dir>/encryption.meta` lets a wrong key fail fast on the next open.
fn at_rest_encryption_from_env() -> Result<Option<EncryptionAtRestConfig>> {
    let raw = match std::env::var("CITRATE_STORAGE_KEY") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => return Ok(None),
    };
    let hex_str = raw.trim();
    let bytes = hex::decode(hex_str)
        .map_err(|_| anyhow::anyhow!("CITRATE_STORAGE_KEY must be 64 hex chars (32 bytes)"))?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "CITRATE_STORAGE_KEY must decode to exactly 32 bytes, got {}",
            bytes.len()
        );
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    info!("Storage encryption-at-rest ENABLED (key from CITRATE_STORAGE_KEY env)");
    Ok(Some(EncryptionAtRestConfig::with_raw_key(key)))
}

async fn start_node(config: NodeConfig) -> Result<()> {
    info!("Starting Citrate node...");
    info!("Chain ID: {}", config.chain.chain_id);
    info!("Data directory: {:?}", config.storage.data_dir);

    // Initialize metrics server
    let metrics_addr = std::env::var("CITRATE_METRICS_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:9090".to_string());
    if let Err(e) = metrics::init_metrics(&metrics_addr) {
        warn!("Failed to initialize metrics server: {}", e);
    } else {
        info!("Metrics server started on http://{}/metrics", metrics_addr);
    }

    // Record node start time for uptime tracking, and sample uptime + process
    // RSS every 15s. The RSS gauge (`process_resident_memory_bytes`) feeds the
    // PIL-13 ProducerMemoryHigh alert (>3 GB sustained 2m) — at a 15s cadence
    // the alert's `for: 2m` window always has fresh samples.
    let node_start_time = std::time::Instant::now();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(15));
        loop {
            tick.tick().await;
            metrics::record_uptime(node_start_time);
            metrics::record_process_rss();
        }
    });

    // Create storage. When CITRATE_STORAGE_KEY is set the data dir is opened
    // encrypted-at-rest (AES-256-GCM per value) with the raw key from the parent
    // process's OS keyring; absent, the default plaintext path is used.
    let storage_encryption = at_rest_encryption_from_env()?;
    let storage = Arc::new(StorageManager::with_config(
        &config.storage.data_dir,
        StorageConfig {
            pruning: PruningConfig {
                keep_blocks: config.storage.keep_blocks,
                keep_states: config.storage.keep_blocks,
                interval: Duration::from_secs(3600),
                batch_size: 1000,
                auto_prune: config.storage.pruning,
            },
            encryption: storage_encryption,
        },
    )?);

    // Create state DB and executor with persistent storage
    let state_db = Arc::new(StateDB::new());
    let state_manager = Arc::new(citrate_storage::state_manager::StateManager::new(storage.db.clone()));

    // Load existing state from storage into memory
    info!("Loading state from storage...");
    match storage.state.get_all_accounts() {
        Ok(accounts) => {
            info!("Found {} accounts in storage, loading into memory...", accounts.len());
            for (address, account) in accounts {
                debug!("Loaded account: 0x{} with balance {}", hex::encode(address.0), account.balance);
                state_db.accounts.load_account(address, account);
            }
            info!("State loaded successfully");
        }
        Err(e) => {
            warn!("Failed to load accounts from storage: {}", e);
        }
    }

    // C6 fix: Also load contract storage slots from persistent storage
    match storage.state.get_all_storage() {
        Ok(storage_slots) => {
            info!("Found {} storage slots in storage, loading into memory...", storage_slots.len());
            for ((address, storage_key), storage_value) in storage_slots {
                state_db.set_storage(address, storage_key.as_bytes().to_vec(), storage_value.as_bytes().to_vec());
            }
            // Clear dirty flags since these are loaded from storage, not new writes
            let _ = state_db.take_dirty_storage();
            info!("Storage slots loaded successfully");
        }
        Err(e) => {
            warn!("Failed to load storage slots from storage: {}", e);
        }
    }

    // Verify state root: compare in-memory trie root against last persisted state root
    {
        let memory_root = state_db.calculate_state_root();
        let latest_height = storage.blocks.get_latest_height().unwrap_or(0);
        if latest_height > 0 {
            if let Ok(Some(block_hash)) = storage.blocks.get_block_by_height(latest_height) {
                // Try dedicated state root store first, fall back to reading from block
                let persisted_root = storage.state.get_state_root(&block_hash)
                    .ok()
                    .flatten()
                    .or_else(|| {
                        storage.blocks.get_block(&block_hash)
                            .ok()
                            .flatten()
                            .map(|b| b.state_root)
                    });

                match persisted_root {
                    Some(root) if root != citrate_consensus::types::Hash::default() => {
                        if memory_root == root {
                            info!("State root verification PASSED (height {}, root={})",
                                latest_height, hex::encode(&memory_root.as_bytes()[..8]));
                        } else {
                            // SRP-S3 (restart-produce purity): a node whose hydrated
                            // in-memory root does NOT reproduce the committed persisted
                            // root MUST NOT start producing or applying blocks — it would
                            // silently seal/verify against a divergent root and fork the
                            // fleet (the block-2042 restart poison). HARD-FAIL instead of
                            // the old warn-and-continue, converting a silent fork into a
                            // safe local stop. See ADR-2026-07-21-restart-produce-purity.
                            error!("SRP-S3 BOOT HALT: state root MISMATCH at height {}: memory={} persisted={} — refusing to start (a node that cannot reconstruct the committed root would fork the fleet)",
                                latest_height,
                                hex::encode(memory_root.as_bytes()),
                                hex::encode(root.as_bytes()));
                            return Err(anyhow::anyhow!(
                                "SRP-S3 boot halt: hydrated state root {} != committed root {} at height {}",
                                hex::encode(memory_root.as_bytes()),
                                hex::encode(root.as_bytes()),
                                latest_height
                            ));
                        }
                    }
                    _ => {
                        debug!("No persisted state root for height {} — skipping verification", latest_height);
                    }
                }
            }
        }
        // Clear dirty flags from state root calculation
        state_db.accounts.clear_dirty();
    }

    // MCP + inference service
    let mcp = Arc::new(citrate_mcp::MCPService::new(storage.clone()));
    // Provider address from config.mining.coinbase (hex 0x...)
    let provider_addr = {
        let mut a = [0u8; 20];
        let s = config.mining.coinbase.trim_start_matches("0x");
        if let Ok(bytes) = hex::decode(s) {
            if bytes.len() >= 20 {
                a.copy_from_slice(&bytes[..20]);
            }
        }
        citrate_execution::types::Address(a)
    };
    // Flat provider fee = 0.01 SALT (1e16 wei)
    let provider_fee = primitive_types::U256::from(10u128.pow(16));
    let inf_svc = Arc::new(crate::inference::NodeInferenceService::new(
        mcp.clone(),
        provider_addr,
        provider_fee,
    ));

    // Artifact service with governance provider list override
    let gov_addr = {
        let mut a = [0u8; 20];
        a[18] = 0x10;
        a[19] = 0x03;
        citrate_execution::types::Address(a)
    };
    let providers_from_gov: Option<Vec<String>> = state_db
        .get_storage(&gov_addr, b"PARAM:ipfs_providers")
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        });
    let art_svc = if let Some(providers) = providers_from_gov {
        Arc::new(crate::artifact::NodeArtifactService::new_with_providers(
            providers,
        ))
    } else {
        let ipfs_api = std::env::var("CITRATE_IPFS_API").ok();
        Arc::new(crate::artifact::NodeArtifactService::new(ipfs_api))
    };

    let storage_bridge: Arc<dyn citrate_execution::executor::AIModelStorage> =
        Arc::new(adapters::StorageAdapter::new(state_manager.clone()));
    let registry_bridge: Arc<dyn citrate_execution::executor::ModelRegistryAdapter> =
        Arc::new(adapters::MCPRegistryBridge::new(mcp.clone()));

    let exec_base = Executor::with_storage(state_db, Some(storage.state.clone()));
    let executor = Arc::new(
        exec_base
            .with_ai_storage_adapter(storage_bridge)
            .with_model_registry_adapter(registry_bridge)
            .with_inference_service(inf_svc)
            .with_artifact_service(art_svc),
    );

    // Governance params: read min_gas_price override
    let governance_addr = {
        let mut a = [0u8; 20];
        a[18] = 0x10;
        a[19] = 0x03;
        citrate_execution::types::Address(a)
    };
    let mut min_gas_price_override: Option<u64> = None;
    if let Some(bytes) = executor
        .state_db()
        .get_storage(&governance_addr, b"PARAM:min_gas_price")
    {
        if bytes.len() >= 8 {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&bytes[..8]);
            min_gas_price_override = Some(u64::from_le_bytes(arr));
        } else if bytes.len() >= 4 {
            // support 32-bit little endian as fallback
            let mut arr = [0u8; 4];
            arr.copy_from_slice(&bytes[..4]);
            min_gas_price_override = Some(u32::from_le_bytes(arr) as u64);
        }
    }

    // Mempool config from env overrides
    let require_valid_signature = std::env::var("CITRATE_REQUIRE_VALID_SIGNATURE")
        .ok()
        .and_then(|v| {
            let s = v.to_lowercase();
            match s.as_str() {
                "1" | "true" | "yes" | "on" => Some(true),
                "0" | "false" | "no" | "off" => Some(false),
                _ => None,
            }
        })
        .unwrap_or({
            // Default to false in devnet mode for easier testing
            #[cfg(feature = "devnet")]
            {
                false
            }
            #[cfg(not(feature = "devnet"))]
            {
                true
            }
        });

    // Create mempool
    // Per-sender cap is overridable via CITRATE_MEMPOOL_MAX_PER_SENDER. The
    // default of 100 is the production value; benchmark and load-test runs
    // raise it (e.g., 10000) to characterize throughput at the block builder
    // level rather than being capped at the per-sender admission gate.
    // Mempool max_size is also overridable via CITRATE_MEMPOOL_MAX_SIZE so a
    // raised per-sender cap can actually be exercised.
    let mempool_max_per_sender: usize = std::env::var("CITRATE_MEMPOOL_MAX_PER_SENDER")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100);
    let mempool_max_size: usize = std::env::var("CITRATE_MEMPOOL_MAX_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10000);
    if mempool_max_per_sender != 100 || mempool_max_size != 10000 {
        tracing::info!(
            "Mempool overrides active: max_size={} max_per_sender={}",
            mempool_max_size, mempool_max_per_sender
        );
    }
    let mempool = Arc::new(Mempool::new(MempoolConfig {
        max_size: mempool_max_size,
        max_per_sender: mempool_max_per_sender,
        min_gas_price: min_gas_price_override.unwrap_or(config.mining.min_gas_price),
        tx_expiry_secs: 3600,
        allow_replacement: true,
        replacement_factor: 110,
        require_valid_signature,
        chain_id: config.chain.chain_id,
        max_nonce_gap: 16, // RM-B1 / WP-C4.1 (audit M-SEQ-01): Geth default
    }));

    // Create peer manager
    let peer_manager = Arc::new(PeerManager::new(PeerManagerConfig {
        max_peers: config.network.max_peers,
        max_inbound: config.network.max_peers / 2,
        max_outbound: config.network.max_peers / 2,
        peer_timeout: std::time::Duration::from_secs(30),
        ban_duration: std::time::Duration::from_secs(3600),
        score_threshold: -100,
    }));

    // Optionally start Prometheus metrics server
    let metrics_enabled = std::env::var("CITRATE_METRICS")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    if metrics_enabled {
        let addr_str =
            std::env::var("CITRATE_METRICS_ADDR").unwrap_or_else(|_| "0.0.0.0:9100".to_string());
        let addr: std::net::SocketAddr = match addr_str.parse() {
            Ok(a) => a,
            Err(e) => {
                tracing::error!("Invalid CITRATE_METRICS_ADDR '{}': {}, skipping metrics server", addr_str, e);
                {
                    // Infallible for a valid hardcoded literal
                    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 9100))
                }
            }
        };
        tokio::spawn(async move {
            if let Err(e) = citrate_api::metrics_server::MetricsServer::new(addr)
                .start()
                .await
            {
                tracing::warn!("Metrics server failed: {}", e);
            }
        });
        info!("Metrics server enabled at {}", addr);
    }

    // WP-K.2: Create shared DAG store and GhostDag BEFORE spawning the network
    // handler, so both the producer and network handler operate on the same DAG.
    // This ensures network-received blocks feed into the live fork-choice.
    // WP-S.1: Use persistent RocksDB-backed DAG store for restart survivability.
    // WP-W.2: Wire VRF strictness from config to DAG store
    let strict_vrf = config.vrf.strict_vrf;
    // VALIDATOR-S1 (v5): parse the ValidatorRegistry config once. When set, the node
    // enforces stake-gated proposer membership — a shared selector is attached to the DAG
    // store (admission gate) and rebuilt each epoch from the registry (registry_sync).
    // OFF by default (env unset) → no selector, no behavior change.
    let validator_registry: Option<([u8; 20], u64)> = std::env::var("CITRATE_VALIDATOR_REGISTRY")
        .ok()
        .and_then(|reg_hex| match hex::decode(reg_hex.trim().trim_start_matches("0x")) {
            Ok(bytes) if bytes.len() == 20 => {
                let mut registry = [0u8; 20];
                registry.copy_from_slice(&bytes);
                let activation_height = std::env::var("CITRATE_VALIDATOR_ACTIVATION_HEIGHT")
                    .ok()
                    .and_then(|s| s.trim().parse::<u64>().ok())
                    .unwrap_or(0);
                Some((registry, activation_height))
            }
            _ => {
                warn!("CITRATE_VALIDATOR_REGISTRY set but not a valid 0x-hex 20-byte address; stake-gating DISABLED");
                None
            }
        });
    // VALIDATOR-S1 §R': fail fast if the activation height is below the FIRST
    // materialized snapshot S(1) = EPOCH - SNAPSHOT_LAG (= 800). Below S(1) no epoch
    // policy is ever materialized, so — with the §R' hard-reject — every block at/above
    // activation but below 800 would be rejected (a node brick). Refuse to start rather
    // than silently misconfigure the fleet.
    if let Some((_, activation)) = &validator_registry {
        let s1 = registry_sync::EPOCH - registry_sync::SNAPSHOT_LAG;
        if *activation < s1 {
            return Err(anyhow::anyhow!(
                "CITRATE_VALIDATOR_ACTIVATION_HEIGHT {} is below the first snapshot S(1)={}; \
                 §R' vesting cannot be enforced before an epoch policy exists",
                activation, s1
            ));
        }
        // §R' hard-reject: teach the executor the activation height INDEPENDENTLY of the
        // (initially-None) policy cell, so a None policy at/above activation is a rejectable
        // fault rather than a silent skip (which would fork this node from the fleet).
        executor.set_validator_activation_height(*activation);
    }
    // The shared proposer selector — the SAME Arc the DAG store admits against and the
    // snapshot-sync rebuilds. production() disables the forgeable legacy VRF path.
    let validator_selector: Option<Arc<citrate_consensus::vrf::VrfProposerSelector>> = validator_registry
        .as_ref()
        .map(|_| Arc::new(citrate_consensus::vrf::VrfProposerSelector::production()));

    let shared_dag_store = {
        let kv = Arc::new(persistent_dag::RocksDbKvStore::new(storage.db.clone()));
        match DagStore::persistent_with_strict_vrf(kv, strict_vrf) {
            Ok(store) => {
                // VALIDATOR-S1: attach the shared selector + fleet-wide activation height so
                // admission enforces membership at/above the cutover. Empty until first sync.
                let store = match (&validator_selector, &validator_registry) {
                    (Some(sel), Some((_, activation))) => store
                        .with_proposer_selector(sel.clone())
                        .with_enforcement_activation_height(*activation),
                    _ => store,
                };
                info!("DAG store created with strict_vrf={}", strict_vrf);
                Arc::new(store)
            }
            Err(e) => {
                warn!("Failed to load persistent DAG, starting fresh: {}", e);
                Arc::new(DagStore::new())
            }
        }
    };
    // PIL-42 (write/init half): genesis is written to the chain store
    // (genesis.rs:165 put_block) but never the DAG store, so on a fresh chain
    // the producer seals block 1 with a zero selected-parent and orphans
    // genesis — the defect that halted testnet-beta at height 231788. Seed
    // genesis as the DAG height-0 root whenever the DAG has no tips. Idempotent:
    // a healthy restart already has tips (skipped); the load-time reconcile in
    // DagStore repairs any pre-existing corrupted tip set. Together they close
    // the orphan-genesis class at both the write and read seams.
    if shared_dag_store.get_tips().await.is_empty() {
        match storage.blocks.get_block_by_height(0) {
            Ok(Some(genesis_hash)) => match storage.blocks.get_block(&genesis_hash) {
                Ok(Some(genesis_block)) => match shared_dag_store.store_block(genesis_block).await {
                    Ok(()) => info!(
                        "Seeded genesis into DAG store as height-0 root (fresh-chain init; block 1 will link to genesis)"
                    ),
                    Err(citrate_consensus::dag_store::DagStoreError::BlockExists(_)) => {}
                    Err(e) => warn!("Failed to seed genesis into DAG store: {}", e),
                },
                Ok(None) => warn!("Genesis hash indexed but block missing; DAG not seeded"),
                Err(e) => warn!("Failed to read genesis block for DAG seed: {}", e),
            },
            Ok(None) => {} // pre-genesis boot — nothing to seed yet
            Err(e) => warn!("Failed to query genesis height for DAG seed: {}", e),
        }
    }
    let shared_ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), shared_dag_store.clone()));

    // WP-W.1: Create CheckpointManager for BFT finality vote handling
    let checkpoint_manager = {
        use citrate_consensus::checkpoint::{CheckpointConfig, CheckpointManager};
        let cp_config = CheckpointConfig::default();
        let kv = Arc::new(persistent_dag::RocksDbKvStore::new(storage.db.clone()));
        Arc::new(CheckpointManager::with_persistence(cp_config, shared_dag_store.clone(), kv))
    };

    // EXECUTE-ON-RECEIVE (step 2): the fast-path applier. Active under v2 headers
    // (CITRATE_BLOCK_V2) — the flag that makes a block's state_root reproducible by a
    // receiver (committed coinbase + deterministic basic rewards). When enabled, received
    // blocks that linearly extend the applied tip are executed + state-root-verified on
    // the receive path, and the producer holds the same lock so the two never race.
    // DEFAULT ON since the 2026-07-21 SRP reroll: v2 is the live network format, so a
    // fresh node (e.g. citrate-core via `--network testnet`) computes the same genesis
    // commitment as the fleet and cold-syncs out of the box. The legacy v1 model is dead;
    // pass CITRATE_BLOCK_V2=0 only to force an isolated v1 devnet. Safe to default-on now
    // that SRP-S2 removed the restart-poison reward path (was unsafe pre-fix).
    let execute_on_receive_enabled = std::env::var("CITRATE_BLOCK_V2")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);
    let canonical_applicator: Option<Arc<canonical_apply::CanonicalApplicator>> =
        if execute_on_receive_enabled {
            // Attach GhostDAG as the fork-choice authority so the driver reorgs
            // the applied chain toward the selected tip (step 4). Bounded revert
            // depth + finalized floor guard reverts inside the applicator.
            let mut app_builder =
                canonical_apply::CanonicalApplicator::new(executor.clone(), storage.clone())
                    .with_fork_choice(shared_ghostdag.clone());
            // VALIDATOR-S1 (step 5): attach the registry snapshot-sync so a node
            // that RECEIVES or REORGS to a snapshot block S(E) rebuilds its
            // proposer selector from the registry — not only the producer.
            if let (Some((registry, activation)), Some(sel)) = (&validator_registry, &validator_selector) {
                let rs = Arc::new(registry_sync::RegistrySync::new(
                    executor.clone(),
                    sel.clone(),
                    *registry,
                    *activation,
                    storage.clone(),
                ));
                // BOOT REHYDRATION (fixes the restart reward-policy fork AND the pre-
                // existing membership restart-brick): before the driver drains or serves
                // ANY block, restore BOTH the §R' reward policy cell AND the proposer
                // selector for the epoch governing the resumed applied tip — from the
                // durable snapshot when present, else recomputed from persisted state at
                // the greatest S(E) <= the tip. Without this, `CanonicalApplicator::new`
                // resumes from the mid-epoch tip with an empty selector (admission would
                // reject every proposer) and a None policy (the §R' hard-reject would
                // reject every block at/above activation).
                let resumed = app_builder.applied_tip().await.height;
                match rs.hydrate_on_boot(resumed).await {
                    Ok(desc) => info!("VALIDATOR-S1: boot rehydration — {}", desc),
                    Err(e) => warn!("VALIDATOR-S1: boot rehydration failed at height {}: {}", resumed, e),
                }
                app_builder = app_builder.with_registry_sync(rs);
                info!("VALIDATOR-S1: registry snapshot-sync attached to execute-on-receive driver (received/reorged S(E) blocks)");
            }
            let app = Arc::new(app_builder);
            let start = app.applied_tip().await;
            info!(
                "EXECUTE-ON-RECEIVE: fast-path applier + reorg ENABLED (received blocks executed + state-root-verified); applied head = {} @ {}",
                start.hash, start.height
            );
            // I4: keep the reorg floor in sync with BFT finality so a reorg can
            // never revert below a finalized checkpoint. Cheap poll (the applied
            // height advances ~1/s); the floor is monotonic in the checkpoint mgr.
            let floor = app.finalized_height_handle();
            let cp = checkpoint_manager.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
                loop {
                    tick.tick().await;
                    let h = cp.latest_finalized_height().await;
                    if h > floor.load(std::sync::atomic::Ordering::SeqCst) {
                        floor.store(h, std::sync::atomic::Ordering::SeqCst);
                    }
                }
            });
            Some(app)
        } else {
            None
        };

    // Start P2P listener and connect to bootstrap nodes
    {
        // Prepare head info — advertise our APPLIED tip (height + hash), NOT the
        // stored height index. A follower stores gossiped tips far ahead of its
        // applied chain; advertising the stored max makes it look caught up to
        // peers (which then pick it as a sync source and it serves them nothing)
        // and mis-drives fork choice. The applied tip is our true synced head.
        let (head_hash, head_height) = storage
            .blocks
            .get_applied_tip()
            .ok()
            .flatten()
            .unwrap_or((citrate_consensus::types::Hash::default(), 0));
        let genesis_hash = storage
            .blocks
            .get_block_by_height(0)
            .ok()
            .flatten()
            .unwrap_or_default();
        let network_id: u32 = config.chain.chain_id as u32;

        // Incoming message channel (log-only for now)
        let (in_tx, mut in_rx) =
            tokio::sync::mpsc::channel::<(PeerId, citrate_network::NetworkMessage)>(512);
        peer_manager.set_incoming(in_tx).await;
        let pm_for_rx = peer_manager.clone();
        let storage_for_handler = storage.clone();
        let mempool_for_handler = mempool.clone();
        // EXECUTE-ON-RECEIVE (step 2): clone the applier into the receive handler.
        let applicator_for_net = canonical_applicator.clone();
        // EXECUTE-ON-RECEIVE (step 3): periodic forward-drain self-heal. The receive
        // path persists blocks before applying and only drives the drain for blocks it
        // hasn't already stored, so a node holding stored-but-unapplied blocks ahead of
        // its applied tip (fresh-join / boot catch-up, or a restart with blocks stored
        // ahead) would freeze its applied tip forever while the stored height climbs.
        // This timer walks the applied tip forward through already-persisted blocks so
        // the node advances to head unattended. No-op when there is nothing to drain.
        if let Some(app) = canonical_applicator.clone() {
            tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(std::time::Duration::from_secs(1));
                loop {
                    interval.tick().await;
                    app.drive_drain().await;
                }
            });
        }
        let gossip = Arc::new(GossipProtocol::new(GossipConfig::default(), peer_manager.clone()));
        let gossip_for_rx = gossip.clone();
        // Sync manager (basic integration)
        let sync = Arc::new(SyncManager::new(SyncConfig::default()));
        let sync_for_rx = sync.clone();

        // Start transport listener and connect to bootstrap nodes
        // Sprint 03: Persistent Noise identity — load from disk or generate once.
        // WP-H.1: Derive PeerId from Noise static key so identity is cryptographically
        // bound. The old random `peer_{u64}` approach allowed identity spoofing.
        let noise_key_path = config.storage.data_dir.join("noise.key");
        // SECREM-01 CFG-1: key file is created 0600, loose permissions on an
        // existing file are tightened on load, and the serialized key bytes
        // are held in `Zeroizing` until handed to the network layer.
        let noise_keypair = load_or_generate_noise_keypair(&noise_key_path)?;
        let local_peer_id = noise_keypair.derive_peer_id();
        info!(
            "Noise identity: {}... (peer_id={})",
            &noise_keypair.public_key_hex()[..16],
            local_peer_id
        );
        // Shared LIVE head advertised in every handshake. Seeded with our current
        // applied tip and refreshed below as we apply/produce blocks — so a node
        // advertises its CURRENT head, not the genesis snapshot it booted with.
        let advertised_head =
            std::sync::Arc::new(tokio::sync::RwLock::new((head_height, head_hash)));
        let transport = NetworkTransport::new(
            peer_manager.clone(),
            local_peer_id,
            citrate_network::transport::HandshakeParams {
                network_id,
                genesis_hash,
                head: advertised_head.clone(),
            },
        )
        .with_noise(noise_keypair)
        .with_allowed_peers(config.network.allowed_peers.clone());
        // Keep the advertised head current (every 1s) from the persisted applied
        // tip, so peers see us advance and their sync triggers fire.
        {
            let advertised_head = advertised_head.clone();
            let storage_head = storage.clone();
            tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(std::time::Duration::from_secs(1));
                loop {
                    interval.tick().await;
                    if let Ok(Some((hash, height))) =
                        storage_head.blocks.get_applied_tip()
                    {
                        let mut g = advertised_head.write().await;
                        if g.0 != height {
                            *g = (height, hash);
                        }
                    }
                }
            });
        }
        let listen_addr = config.network.listen_addr;
        transport
            .start_listener(listen_addr)
            .await
            .map_err(|e| anyhow::anyhow!(format!("Failed to start P2P listener: {}", e)))?;

        // Dial configured bootstrap nodes. Accepts ip:port, hostname:port, and
        // an optional `noise_<hex>@` / `peer_id@` identity prefix. Hostnames are
        // resolved via DNS by the shared resolver so the baked hostname-based
        // testnet-beta.toml connects out of the box.
        // WP-H.2: When a bootnode declares its Noise identity, use connect_to_trusted
        // to verify the remote's Noise key matches the declared trust root.
        for s in &config.network.bootstrap_nodes {
            match citrate_network::resolve_bootnode(s).await {
                Some((Some(pid), addr)) if pid.0.starts_with("noise_") => {
                    info!("Connecting to trusted bootnode {} (identity={})", addr, pid);
                    let _ = transport.connect_to_trusted(addr, pid).await;
                }
                Some((Some(_), addr)) => {
                    warn!("Bootnode {} has no Noise identity — cannot verify trust root", addr);
                    let _ = transport.connect_to(addr).await;
                }
                Some((None, addr)) => {
                    let _ = transport.connect_to(addr).await;
                }
                None => {
                    warn!("Could not resolve bootstrap node: {}", s);
                }
            }
        }

        // Start discovery and periodic dialer
        let discovery = Arc::new(Discovery::new(
            DiscoveryConfig {
                bootstrap_nodes: config.network.bootstrap_nodes.clone(),
                max_peers: config.network.max_peers,
                ..Default::default()
            },
            peer_manager.clone(),
        ));
        discovery.init().await.ok();

        // SECREM-01 NET-3: periodic network-cache maintenance.
        // The gossip seen_* dedup caches, the peer-manager ban maps,
        // and the discovery known-peer table all have cleanup
        // helpers, but nothing ever scheduled them — so every cache
        // grew without bound for the life of the node (slow OOM).
        // Run all of them on a fixed 60s cadence; each helper is
        // idempotent and TTL/size-bounded, so the cadence only
        // affects how promptly memory is reclaimed.
        {
            let gossip_for_maint = gossip.clone();
            let pm_for_maint = peer_manager.clone();
            let discovery_for_maint = discovery.clone();
            tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(std::time::Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    // TTL-prune + hard-cap the seen block/tx/learning caches
                    gossip_for_maint.cleanup_seen_cache().await;
                    // Drop expired addr/IP/peer-ID bans
                    pm_for_maint.cleanup_expired_bans();
                    // Expire stale non-bootstrap discovery entries
                    discovery_for_maint.cleanup_expired().await;
                }
            });
        }

        let discovery_for_loop = discovery.clone();
        let transport_for_loop = transport;
        let pm_for_discovery = pm_for_rx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            loop {
                interval.tick().await;
                let candidates = discovery_for_loop.find_peers().await;
                for (id, addr) in candidates {
                    match transport_for_loop.connect_to(addr).await {
                        Ok(_) => {
                            discovery_for_loop.mark_connected(&id).await;
                            discovery_for_loop.update_attempts(&id, true).await;
                        }
                        Err(_) => {
                            discovery_for_loop.update_attempts(&id, false).await;
                        }
                    }
                }
                // Periodically request peer lists
                let _ = pm_for_discovery
                    .broadcast(&citrate_network::NetworkMessage::GetPeers)
                    .await;
            }
        });

        // Periodic sync tick: request headers/blocks and check timeouts
        let pm_for_sync = pm_for_rx.clone();
        let sync_for_loop = sync.clone();
        let storage_for_sync = storage.clone();
        tokio::spawn(async move {
            use std::collections::HashMap;
            use std::time::{Duration, Instant};
            let mut attempt_counts: HashMap<citrate_consensus::types::Hash, u32> = HashMap::new();
            let mut pending_retries: Vec<(Instant, citrate_consensus::types::Hash)> = Vec::new();
            let mut peer_failures: HashMap<String, u32> = HashMap::new();
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
            loop {
                interval.tick().await;
                let peers = pm_for_sync.get_all_peers();
                // Pick best peer by head height
                let mut best: Option<Arc<citrate_network::peer::Peer>> = None;
                let mut best_h: u64 = 0;
                let mut best_hash = citrate_consensus::types::Hash::new([0u8; 32]);
                for p in peers {
                    let info = p.info.read().await;
                    if info.state == citrate_network::peer::PeerState::Connected
                        && info.head_height > best_h
                        && peer_failures.get(&info.id.0).cloned().unwrap_or(0) < 3
                    {
                        best_h = info.head_height;
                        best_hash = info.head_hash;
                        best = Some(p.clone());
                    }
                }
                if let Some(peer) = best {
                    // CRITICAL: raise the sync target to the best peer's advertised
                    // head. The Hello/HelloAck that carries a peer's head is consumed
                    // INSIDE the transport handshake (transport.rs) to seed
                    // PeerInfo.head_height and is NEVER forwarded to the message loop,
                    // so the `NetworkMessage::Hello` handler that would call
                    // start_sync never fires. target_height therefore stayed 0, and
                    // handle_blocks declared "Synchronization complete" after every
                    // batch (last_height >= 0) — the node synced a few blocks then
                    // looped forever without pushing to the real tip. Driving
                    // start_sync here from the best peer's head (start_sync only ever
                    // RAISES the target, never lowers it) makes the target track the
                    // true head so sync walks all the way forward.
                    if best_h > 0 {
                        sync_for_loop.set_target(best_h).await;
                    }
                    let _ = best_hash; // anchor uses the applied tip, not best_hash
                    // Anchor every request on our current PERSISTED tip so sync
                    // walks forward batch by batch. The pre-fix logic preferred
                    // `last_requested_header`, which latched onto the first anchor
                    // (the genesis zero-hash) and never advanced — so any chain
                    // longer than one batch stalled at the first batch forever
                    // even once pending-clearing let requests complete. The tip
                    // advances as synced blocks persist (Blocks handler →
                    // put_block), so this drives forward progress to the head.
                    // Anchor sync on the APPLIED (execute-on-receive selected)
                    // tip — NOT the height index. `get_latest_height` /
                    // `get_block_by_height` return the highest STORED block,
                    // which on a follower that is behind is a gossiped tip
                    // stored far ahead of the applied chain (with the whole
                    // range below it missing), or a non-selected sibling
                    // (`put_block` is last-writer-wins per height). Anchoring
                    // there made the node request blocks AFTER a gap it had
                    // never filled: the server resolves that unknown/ahead
                    // anchor to nothing servable and replies "Sending 0 blocks",
                    // so the applied tip never advanced — the exact boot stall at
                    // 5580 while the stored height silently tracked the
                    // producer's tip. The applied tip is the last block we truly
                    // extended state with, so requesting ITS children is the gap
                    // we actually need. Genesis sentinel when nothing is applied.
                    let start_from = storage_for_sync
                        .blocks
                        .get_applied_tip()
                        .ok()
                        .flatten()
                        .map(|(hash, _height)| hash)
                        .unwrap_or_else(|| citrate_consensus::types::Hash::new([0u8; 32]));
                    // Request next headers and blocks from our last known point only if not saturated
                    let (ph, pb) = sync_for_loop.pending_counts().await;
                    if ph < 8 {
                        let _ = sync_for_loop.request_headers(&peer, start_from).await;
                    }
                    if pb < 8 {
                        let _ = sync_for_loop.request_blocks(&peer, start_from).await;
                    }
                }
                // Requeue timed-out requests with exponential backoff
                for (h, pid) in sync_for_loop.check_timeouts().await {
                    let entry = attempt_counts.entry(h).or_insert(0);
                    *entry = entry.saturating_add(1);
                    let backoff = (*entry).min(5); // cap exponent at 5
                    let delay_secs = 1u64 << backoff; // 2,4,8,16,32
                    pending_retries.push((Instant::now() + Duration::from_secs(delay_secs), h));
                    // Penalize the peer that timed out
                    let key = pid.0.clone();
                    let pf = peer_failures.entry(key.clone()).or_insert(0);
                    *pf = pf.saturating_add(1);
                    // Lower peer score
                    pm_for_sync.update_peer_score(&pid, -5).await;
                    // Drop (do NOT ban) a peer after repeated sync timeouts.
                    // A sync timeout is not evidence of malice, and permanently
                    // banning a pinned bootstrap/producer for one is exactly how
                    // the fleet split-brained: a bootnode banned its only block
                    // source and could never re-sync. Removing the peer lets it
                    // re-handshake fresh; we reset the failure counter so the
                    // reconnection starts from a clean slate.
                    // Never drop a peer if it is our ONLY one — doing so strands a
                    // fresh node with zero peers and it wedges permanently (observed:
                    // a follower syncing a deep chain hit a few timeouts, dropped its
                    // sole source, and never recovered). Only prune when another peer
                    // can take over; otherwise keep retrying against the one we have.
                    let (total_peers, _, _) = pm_for_sync.get_peer_counts().await;
                    if *pf >= 5 && total_peers > 1 && pm_for_sync.get_peer(&pid).is_some() {
                        pm_for_sync.remove_peer(&pid).await;
                        *pf = 0;
                        tracing::warn!(
                            "Dropped peer {} after repeated sync timeouts (will re-handshake)",
                            pid.0
                        );
                    } else if *pf >= 5 {
                        // Sole peer: reset the counter so we keep trying it rather
                        // than freezing after 5 timeouts.
                        *pf = 0;
                    }
                }
                // Issue any due retries
                let now = Instant::now();
                let mut remaining: Vec<(Instant, citrate_consensus::types::Hash)> = Vec::new();
                for (when, h) in pending_retries.drain(..) {
                    if when <= now {
                        if let Some(peer) = pm_for_sync.get_all_peers().first() {
                            let _ = sync_for_loop.request_headers(peer, h).await;
                            let _ = sync_for_loop.request_blocks(peer, h).await;
                        }
                    } else {
                        remaining.push((when, h));
                    }
                }
                pending_retries = remaining;
            }
        });
        let network_inf_executor = Arc::new(
            crate::network_inference::NodeNetworkInferenceExecutor::new(
                mcp.clone(),
                provider_addr,
            ),
        );
        let ai_handler = Arc::new(
            citrate_network::ai_handler::AINetworkHandler::new(
                state_manager.clone(),
                peer_manager.clone(),
            )
            .with_inference_executor(network_inf_executor),
        );
        let ai_handler_for_rx = ai_handler.clone();

        // WP-K.2: Clone DAG components for the network handler
        let dag_store_for_net = shared_dag_store.clone();
        let ghostdag_for_net = shared_ghostdag.clone();
        let checkpoint_mgr_for_net = checkpoint_manager.clone();

        tokio::spawn(async move {
            // SECREM-01 NET-1/2: the GetHeaders/GetBlocks handlers that used
            // `Hash::new(...)` inline moved to block_serve.rs, so the bare
            // Hash import is no longer needed here.
            use citrate_consensus::checkpoint::CheckpointVote;
            use citrate_network::NetworkMessage;
            use citrate_sequencer::mempool::TxClass;
            // #85 (deep bulk-sync wedge): blocks that fail admission ONLY because
            // their parent hasn't been applied yet are buffered here instead of
            // dropped, then re-tried when a later batch delivers the parent. The
            // pre-fix code dropped them, so a re-requested child was re-dropped
            // forever whenever its parent rode a separate, not-yet-arrived batch —
            // wedging a cold node at the first out-of-order block (observed live in
            // the contract-deploy region). Bounded to cap memory if a parent never
            // arrives; the sync loop independently re-requests missing parents.
            let mut orphan_blocks: Vec<citrate_consensus::types::Block> = Vec::new();
            while let Some((pid, msg)) = in_rx.recv().await {
                tracing::debug!("[P2P] from={} msg={:?}", pid.0, msg);
                // Handle protocol messages
                match msg {
                    NetworkMessage::Hello { head_height, head_hash, .. } => {
                        // Kick off naive sync: request blocks from genesis if behind
                        // APPLIED tip, not the stored height index: a follower
                        // stores gossiped tips far ahead of its applied chain, so
                        // get_latest_height() would report it as already caught up
                        // (7000) when it has only APPLIED to 5580 — the trigger
                        // then never fires and the node never starts syncing the
                        // gap from a genuinely-ahead peer.
                        let local_h = storage_for_handler
                            .blocks
                            .get_applied_tip()
                            .ok()
                            .flatten()
                            .map(|(_, h)| h)
                            .unwrap_or(0);
                        if head_height > local_h {
                            let _ = sync_for_rx.start_sync(head_height, head_hash).await;
                        }
                        // Also request headers
                        // Sync manager will request in periodic loop
                    }
                    NetworkMessage::HelloAck { head_height, head_hash, .. } => {
                        // APPLIED tip, not the stored height index: a follower
                        // stores gossiped tips far ahead of its applied chain, so
                        // get_latest_height() would report it as already caught up
                        // (7000) when it has only APPLIED to 5580 — the trigger
                        // then never fires and the node never starts syncing the
                        // gap from a genuinely-ahead peer.
                        let local_h = storage_for_handler
                            .blocks
                            .get_applied_tip()
                            .ok()
                            .flatten()
                            .map(|(_, h)| h)
                            .unwrap_or(0);
                        if head_height > local_h {
                            let _ = sync_for_rx.start_sync(head_height, head_hash).await;
                        }
                        // Requests are driven by periodic sync loop
                    }
                    NetworkMessage::GetBlocks { from, count, .. } => {
                        tracing::info!("Received GetBlocks request from peer {} for {} blocks starting from {:?}",
                                     pid.0, count, from);
                        // NET-2 (SECREM-01): `count` is attacker-supplied —
                        // serve through the clamped, tip-bounded path only.
                        let blocks =
                            block_serve::serve_blocks(&storage_for_handler, &from, count);

                        tracing::info!("Sending {} blocks to peer {}", blocks.len(), pid.0);
                        let _ = pm_for_rx
                            .send_to_peers(std::slice::from_ref(&pid), &NetworkMessage::Blocks { blocks })
                            .await;
                    }
                    NetworkMessage::GetPeers => {
                        // Serve a small list of peers from discovery
                        let peers = discovery.get_peers_for_exchange().await;
                        let _ = pm_for_rx
                            .send_to_peers(std::slice::from_ref(&pid), &NetworkMessage::Peers { peers })
                            .await;
                    }
                    NetworkMessage::Peers { peers } => {
                        discovery.handle_peer_exchange(peers).await;
                    }
                    NetworkMessage::GetHeaders { from, count } => {
                        tracing::info!(
                            "Received GetHeaders request from peer {} starting {:?} count {}",
                            pid.0, from, count
                        );
                        // NET-1 (SECREM-01 Critical): the previous inline
                        // loop ran `while headers.len() < count` with no tip
                        // bound and no break on missing heights — one packet
                        // with a large `count` spun to u64::MAX storage
                        // reads. All serving now goes through the clamped,
                        // tip-bounded, gap-breaking path.
                        let headers =
                            block_serve::serve_headers(&storage_for_handler, &from, count);
                        let _ = pm_for_rx
                            .send_to_peers(
                                std::slice::from_ref(&pid),
                                &NetworkMessage::Headers { headers },
                            )
                            .await;
                    }
                    NetworkMessage::Headers { headers } => {
                        let _ = sync_for_rx.handle_headers(headers).await;
                    }
                    NetworkMessage::GetTransactions { hashes } => {
                        let mut txs = Vec::new();
                        for h in hashes {
                            if let Some(tx) = mempool_for_handler.get_transaction(&h).await {
                                txs.push(tx);
                            }
                        }
                        let _ = pm_for_rx
                            .send_to_peers(
                                std::slice::from_ref(&pid),
                                &NetworkMessage::Transactions { transactions: txs },
                            )
                            .await;
                    }
                    NetworkMessage::NewTransaction { transaction } => {
                        // SECREM-01 NET-5: validate via gossip BEFORE inserting
                        // into the mempool. Pre-fix the tx was added to the
                        // mempool first and only then handed to gossip
                        // validation, so a peer could seed invalid txs into
                        // local mempool state. Gossip `handle_new_transaction`
                        // runs basic-validity checks + penalizes the peer on
                        // failure; only a passing tx reaches `add_transaction`
                        // (which applies the authoritative mempool validation).
                        let hash = transaction.hash;
                        match gossip_for_rx
                            .handle_new_transaction(transaction.clone(), &pid)
                            .await
                        {
                            Ok(()) => {
                                if !mempool_for_handler.contains(&hash).await {
                                    let _ = mempool_for_handler
                                        .add_transaction(transaction, TxClass::Standard)
                                        .await;
                                }
                            }
                            Err(e) => {
                                tracing::debug!(
                                    "Rejected gossiped tx {} from {}: {}",
                                    hex::encode(&hash.as_bytes()[..8]),
                                    pid,
                                    e
                                );
                            }
                        }
                    }
                    NetworkMessage::NewBlock { block } => {
                        // Keep this peer's advertised head FRESH from its gossip.
                        // PeerInfo.head_height is seeded once at the transport
                        // handshake and never refreshed afterward, so the sync target
                        // (driven from the best peer's head in the 2s tick) froze at
                        // the handshake value — a follower then stopped one
                        // growth-window short of a still-producing tip and never
                        // closed the gap. A gossiped block proves the peer is at least
                        // at that height, so bump it.
                        if let Some(p) = pm_for_rx.get_peer(&pid) {
                            let mut info = p.info.write().await;
                            if block.header.height > info.head_height {
                                info.head_height = block.header.height;
                                info.head_hash = block.header.block_hash;
                            }
                        }
                        // C3 fix: validate BEFORE persisting to prevent
                        // invalid blocks from polluting local storage.
                        let have = storage_for_handler
                            .blocks
                            .has_block(&block.header.block_hash)
                            .unwrap_or(false);
                        if !have {
                            // Let gossip validate (structure/signature) and propagate first
                            match gossip_for_rx.handle_new_block(block.clone(), &pid).await {
                                Ok(_) => {
                                    // SECREM-01 CONS-1/2/3: consensus-consistency
                                    // gate (parents exist, height linkage, blue
                                    // score/work recomputation) runs BEFORE any
                                    // persistence. Pre-fix, put_block ran first and
                                    // wrote the RocksDB blue-score/height indexes
                                    // from unvalidated header claims.
                                    if let Err(e) = ghostdag_for_net
                                        .validate_block_consistency(&block)
                                        .await
                                    {
                                        tracing::warn!(
                                            "Rejected inconsistent block {} from {}: {}",
                                            hex::encode(&block.header.block_hash.as_bytes()[..8]),
                                            pid,
                                            e
                                        );
                                    } else {
                                        // WP-K.2: Feed validated block into live DAG for fork-choice
                                        match dag_store_for_net.store_block(block.clone()).await {
                                            Ok(_) => {
                                                match ghostdag_for_net.add_block(&block).await {
                                                    Ok(_) => {
                                                        // Admission complete — only now persist.
                                                        let _ = storage_for_handler
                                                            .blocks
                                                            .put_block(&block);
                                                        tracing::debug!(
                                                            "Added network block {} to live DAG",
                                                            hex::encode(&block.header.block_hash.as_bytes()[..8])
                                                        );
                                                        // EXECUTE-ON-RECEIVE (step 2): fast-path
                                                        // apply if this block linearly extends the
                                                        // applied tip. Rejection is logged (a bad
                                                        // state_root doesn't unwind DAG admission
                                                        // here — reorg handling is a later step);
                                                        // the block simply never becomes the
                                                        // applied tip, so no invalid state is served.
                                                        if let Some(app) = &applicator_for_net {
                                                            match app.apply_received(&block).await {
                                                                canonical_apply::ApplyOutcome::Applied { root, height } => {
                                                                    tracing::debug!(
                                                                        "execute-on-receive applied network block @ {} (root {})",
                                                                        height, root
                                                                    );
                                                                }
                                                                canonical_apply::ApplyOutcome::Rejected(why) => {
                                                                    tracing::warn!(
                                                                        "execute-on-receive REJECTED network block {} from {}: {}",
                                                                        hex::encode(&block.header.block_hash.as_bytes()[..8]),
                                                                        pid,
                                                                        why
                                                                    );
                                                                }
                                                                // Deferred / AlreadyApplied: no state change (gap/fork/echo).
                                                                _ => {}
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        tracing::warn!(
                                                            "Block {} failed DAG admission: {}",
                                                            hex::encode(&block.header.block_hash.as_bytes()[..8]),
                                                            e
                                                        );
                                                    }
                                                }
                                            }
                                            Err(citrate_consensus::dag_store::DagStoreError::BlockExists(_)) => {
                                                // Already in DAG (e.g., from local production) — safe to ignore
                                            }
                                            Err(e) => {
                                                tracing::warn!(
                                                    "Failed to add block {} to live DAG: {}",
                                                    hex::encode(&block.header.block_hash.as_bytes()[..8]),
                                                    e
                                                );
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "Rejected invalid block {} from {}: {}",
                                        hex::encode(&block.header.block_hash.as_bytes()[..8]),
                                        pid,
                                        e
                                    );
                                }
                            }
                        }
                    }
                    NetworkMessage::Blocks { blocks } => {
                        // WP-H.4: handle_blocks now validates each block
                        let _ = sync_for_rx.handle_blocks(blocks).await;
                        // WP-H.5: Drain validated blocks and persist to chain store.
                        // Without this, synced blocks live only in SyncManager memory
                        // and are never integrated into the DAG.
                        let mut pending = sync_for_rx.drain_validated_blocks().await;
                        // #85 (deep bulk-sync wedge): admit in topological
                        // (height-ascending) order — every parent (selected OR
                        // merge) has strictly lower height than its child, and the
                        // header-height check enforces child = parent + 1, so a
                        // height sort is a valid topological order. Retry any
                        // orphans buffered from earlier batches alongside the fresh
                        // drain: a parent delivered now can unblock a child that
                        // arrived (and was buffered) in a prior, out-of-order batch.
                        pending.append(&mut orphan_blocks);
                        pending.sort_by_key(|b| b.header.height);
                        pending.dedup_by_key(|b| b.header.block_hash);

                        // Fixpoint: a block that fails admission ONLY because its
                        // parent isn't applied yet is DEFERRED (buffered), never
                        // dropped. The pre-fix code dropped it, so a re-requested
                        // child was re-dropped forever whenever its parent rode a
                        // separate not-yet-arrived batch — the live cold-sync wedge.
                        loop {
                            let mut progressed = false;
                            let mut deferred: Vec<citrate_consensus::types::Block> = Vec::new();
                            for block in std::mem::take(&mut pending) {
                                let hash = block.header.block_hash;
                                if storage_for_handler.blocks.has_block(&hash).unwrap_or(false) {
                                    continue;
                                }
                                // SECREM-01 CONS-1/2/3: consistency gate before any
                                // persistence (sync is an equally untrusted ingest).
                                match ghostdag_for_net.validate_block_consistency(&block).await {
                                    Err(citrate_consensus::ghostdag::GhostDagError::MissingParent(_)) => {
                                        // Parent not applied yet — keep for a later
                                        // batch rather than dropping (the #85 fix).
                                        deferred.push(block);
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "Rejected inconsistent synced block {}: {}",
                                            hex::encode(&hash.as_bytes()[..8]),
                                            e
                                        );
                                    }
                                    Ok(()) => {
                                        // WP-K.2: feed synced block into live DAG for fork-choice
                                        match dag_store_for_net.store_block(block.clone()).await {
                                            Ok(_) => match ghostdag_for_net.add_block(&block).await {
                                                Ok(_) => {
                                                    progressed = true;
                                                    // Admission complete — only now persist.
                                                    if let Err(e) =
                                                        storage_for_handler.blocks.put_block(&block)
                                                    {
                                                        tracing::warn!(
                                                            "Failed to persist synced block {}: {}",
                                                            hex::encode(&hash.as_bytes()[..8]),
                                                            e
                                                        );
                                                    }
                                                    // EXECUTE-ON-RECEIVE (step 2): fast-path apply of a
                                                    // synced block that linearly extends the applied tip.
                                                    if let Some(app) = &applicator_for_net {
                                                        match app.apply_received(&block).await {
                                                            canonical_apply::ApplyOutcome::Applied { root, height } => {
                                                                tracing::debug!(
                                                                    "execute-on-receive applied synced block @ {} (root {})",
                                                                    height, root
                                                                );
                                                            }
                                                            canonical_apply::ApplyOutcome::Rejected(why) => {
                                                                tracing::warn!(
                                                                    "execute-on-receive REJECTED synced block {}: {}",
                                                                    hex::encode(&hash.as_bytes()[..8]),
                                                                    why
                                                                );
                                                            }
                                                            _ => {}
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    tracing::warn!(
                                                        "Synced block {} failed DAG admission: {}",
                                                        hex::encode(&hash.as_bytes()[..8]),
                                                        e
                                                    );
                                                }
                                            },
                                            Err(citrate_consensus::dag_store::DagStoreError::BlockExists(_)) => {}
                                            Err(e) => {
                                                tracing::warn!(
                                                    "Failed to add synced block {} to live DAG: {}",
                                                    hex::encode(&hash.as_bytes()[..8]),
                                                    e
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            pending = deferred;
                            if !progressed {
                                break;
                            }
                        }
                        // Buffer unresolved orphans for the next Blocks batch (their
                        // parents are still en route); bound the buffer so a parent
                        // that never arrives can't grow it without limit.
                        const MAX_ORPHAN_BLOCKS: usize = 20_000;
                        if pending.len() > MAX_ORPHAN_BLOCKS {
                            pending.sort_by_key(|b| b.header.height);
                            pending.truncate(MAX_ORPHAN_BLOCKS);
                        }
                        orphan_blocks = pending;
                    }
                    NetworkMessage::Transactions { transactions } => {
                        for tx in transactions {
                            let _ = mempool_for_handler
                                .add_transaction(tx, TxClass::Standard)
                                .await;
                        }
                    }
                    // AI network messages: route through AINetworkHandler
                    NetworkMessage::ModelAnnounce { .. }
                    | NetworkMessage::InferenceRequest { .. }
                    | NetworkMessage::InferenceResponse { .. }
                    | NetworkMessage::TrainingJobAnnounce { .. }
                    | NetworkMessage::GradientSubmission { .. }
                    | NetworkMessage::WeightSync { .. }
                    | NetworkMessage::GetModel { .. }
                    | NetworkMessage::ModelData { .. } => {
                        match ai_handler_for_rx.handle_message(&pid, &msg).await {
                            Ok(Some(response)) => {
                                let _ = pm_for_rx
                                    .send_to_peers(std::slice::from_ref(&pid), &response)
                                    .await;
                            }
                            Ok(None) => {} // No response needed
                            Err(e) => {
                                tracing::warn!(
                                    "AI handler error for message from {}: {}",
                                    pid.0, e
                                );
                            }
                        }
                    }
                    // WP-W.1: Handle checkpoint vote messages for BFT finality
                    NetworkMessage::CheckpointVote { height, block_hash, voter_pubkey, signature } => {
                        use citrate_consensus::types::{PublicKey, Signature};
                        let voter_bytes: [u8; 32] = match voter_pubkey.as_slice().try_into() {
                            Ok(b) => b,
                            Err(_) => {
                                tracing::warn!("Invalid voter pubkey length from peer {}", pid.0);
                                continue;
                            }
                        };
                        let sig_bytes: [u8; 64] = match signature.as_slice().try_into() {
                            Ok(b) => b,
                            Err(_) => {
                                tracing::warn!("Invalid signature length from peer {}", pid.0);
                                continue;
                            }
                        };
                        let vote = CheckpointVote {
                            height,
                            block_hash,
                            voter: PublicKey::new(voter_bytes),
                            signature: Signature::new(sig_bytes),
                        };
                        match checkpoint_mgr_for_net.submit_vote(vote).await {
                            Ok(true) => {
                                tracing::info!("Checkpoint quorum reached at height {}, finalizing", height);
                                match checkpoint_mgr_for_net.finalize_checkpoint(height).await {
                                    Ok(cp) => tracing::info!("Checkpoint finalized at height {} with {} votes", cp.height, cp.votes.len()),
                                    Err(e) => tracing::warn!("Failed to finalize checkpoint at height {}: {}", height, e),
                                }
                            }
                            Ok(false) => tracing::debug!("Checkpoint vote accepted for height {}", height),
                            Err(e) => tracing::warn!("Checkpoint vote rejected from peer {}: {}", pid.0, e),
                        }
                    }
                    _ => {
                        tracing::debug!("Unhandled message variant from peer {}", pid.0);
                    }
                }
            }
        });

        // (legacy direct socket bootstrap removed; handled by NetworkTransport)
    }

    // Create unified economics manager for RPC and mining
    let economics_config = UnifiedEconomicsConfig::default();
    let mut economics_manager_temp = UnifiedEconomicsManager::new(economics_config);

    // Register initial stakeholders
    let coinbase_bytes = hex::decode(&config.mining.coinbase).unwrap_or_else(|_| vec![0; 20]);
    let mut coinbase = [0u8; 32];
    let copy_len = coinbase_bytes.len().min(32);
    coinbase[..copy_len].copy_from_slice(&coinbase_bytes[..copy_len]);
    let validator_address = citrate_execution::types::Address(coinbase[0..20].try_into().unwrap_or([0; 20]));
    let _ = economics_manager_temp.register_stakeholder(validator_address, StakeholderType::Validator);

    let economics_manager = Arc::new(economics_manager_temp);

    // WP-I.3: Create pause_flag shared between RPC server and block producer.
    // When citrate_emergencyPause is called via RPC, the producer sees the
    // flag and stops producing blocks.
    let pause_flag = Arc::new(AtomicBool::new(false));

    // Start RPC server if enabled
    let rpc_handle = if config.rpc.enabled {
        info!("Starting RPC server on {}", config.rpc.listen_addr);

        // WP-I.2: Read operator token from env for privileged RPC gating
        let operator_token = std::env::var("CITRATE_OPERATOR_TOKEN").ok()
            .filter(|t| !t.is_empty());

        // Sprint 03: API key gating — CLI flag > config file > env var
        let api_key = config.rpc.api_key.clone()
            .or_else(|| std::env::var("CITRATE_API_KEY").ok().filter(|k| !k.is_empty()));
        if api_key.is_some() {
            info!("RPC API key authentication enabled");
        }

        // WP-K.4: Detect if RPC is bound to a public (non-loopback) interface
        let is_public_bind = !config.rpc.listen_addr.ip().is_loopback();
        if is_public_bind && operator_token.is_none() {
            warn!("RPC bound to public interface ({}) without CITRATE_OPERATOR_TOKEN — operator methods disabled", config.rpc.listen_addr);
        }

        let rpc_config = RpcConfig {
            listen_addr: config.rpc.listen_addr,
            max_connections: 100,
            // WP-X.1: Propagate CORS config instead of hardcoding wildcard
            cors_origins: config.rpc.cors_origins.clone(),
            threads: 4,
            // C-02: Only allow eth_sendTransaction in devnet/dev mode
            allow_eth_send_transaction: config.rpc.allow_eth_send_transaction,
            rate_limit: citrate_api::rate_limit::RateLimitConfig {
                operator_token,
                api_key,
                is_public_bind, // WP-K.4: fail-closed on public interface
                ..Default::default()
            },
        };

        let rpc_server = RpcServer::with_economics_and_pause(
            rpc_config,
            storage.clone(),
            mempool.clone(),
            peer_manager.clone(),
            executor.clone(),
            config.chain.chain_id,
            Some(economics_manager.clone()),
            Some(pause_flag.clone()),
        );

        // PIL-12: spawn the Ethereum-compatible subscription server next
        // to the RPC server. Until this commit, main.rs constructed
        // `RpcServer` directly via `RpcServer::with_economics_and_pause`
        // and called `.spawn()` — which only binds the HTTP RPC socket.
        // Nothing ever bound `config.rpc.ws_addr`, so `wss://rpc.citrate.ai`
        // returned HTTP 405 because Caddy proxied the upgrade to the
        // HTTP JSON-RPC port instead of a real WS endpoint. Spec — and
        // `node/config/testnet-beta.toml` — both say WS lives on `:8546`.
        //
        // We use `EthSubscriptionServer` rather than `WebSocketServer`
        // because the partner expectation is standard Ethereum
        // `eth_subscribe('newHeads' | 'logs' | 'newPendingTransactions' |
        // 'syncing')` — i.e. the same JSON-RPC envelope as HTTP RPC,
        // not citrate-specific `Subscribe { id, subscription: SubscriptionType }`
        // messages (which the older WebSocketServer speaks for AI streaming).
        // `EthSubscriptionServer` exposes the standard subscriptions plus
        // a broadcast channel that the block producer hooks into via
        // `new_heads_sender()` so newly-produced blocks push to all
        // subscribers in real time.
        let ws_addr = config.rpc.ws_addr;
        let eth_subs = std::sync::Arc::new(EthSubscriptionServer::new(
            ws_addr,
            storage.clone(),
            mempool.clone(),
        ));
        // Save the new-heads broadcast sender so the producer (started
        // below) can wire blocks into the subscription feed via
        // `BlockProducer::with_new_heads_sender`. PIL-12 follow-up wires
        // this; today's commit only binds the port so the 405 stops.
        let _new_heads_sender = eth_subs.new_heads_sender();
        let eth_subs_for_spawn = eth_subs.clone();
        let ws_handle = tokio::spawn(async move {
            info!("Starting Ethereum subscription WebSocket server on {}", ws_addr);
            if let Err(e) = eth_subs_for_spawn.start().await {
                error!("Ethereum subscription server error: {}", e);
            }
        });

        Some(tokio::spawn(async move {
            match rpc_server.spawn() {
                Ok((close_handle, join_handle)) => {
                    info!("RPC server started");
                    // Keep server alive
                    tokio::signal::ctrl_c().await.ok();
                    // Signal server to close and join its OS thread
                    close_handle.close();
                    tokio::task::spawn_blocking(move || {
                        let _ = join_handle.join();
                    })
                    .await
                    .ok();
                    // PIL-12: shut the WS task down with the rest of the
                    // RPC stack on Ctrl-C so the integration tests don't
                    // leave a dangling :8546 listener on dev boxes.
                    ws_handle.abort();
                }
                Err(e) => {
                    error!("Failed to start RPC server: {}", e);
                    ws_handle.abort();
                }
            }
        }))
    } else {
        None
    };

    // Start block producer if mining is enabled and coinbase is configured
    let coinbase_str = config.mining.coinbase.trim_start_matches("0x");
    let coinbase_is_valid = !coinbase_str.is_empty()
        && coinbase_str != "0000000000000000000000000000000000000000"
        && hex::decode(coinbase_str).map(|b| b.iter().any(|&x| x != 0)).unwrap_or(false);

    if config.mining.enabled && coinbase_is_valid {
        info!("Starting block producer...");

        // Parse coinbase address
        let coinbase_bytes = hex::decode(coinbase_str).unwrap_or_else(|_| vec![0; 20]);
        let mut coinbase = [0u8; 32];
        let copy_len = coinbase_bytes.len().min(32);
        coinbase[..copy_len].copy_from_slice(&coinbase_bytes[..copy_len]);

        // WP-G.2: Generate block signing key.
        // Deterministic derivation from coinbase for devnet reproducibility.
        // Production nodes should load a persistent key from disk.
        //
        // LOAD-BEARING: this MUST be the SAME derivation the registration
        // ceremony (node/src/bin/validator_registration_ceremony.rs) uses, or the
        // pubkey registered on-chain won't match the key that signs blocks here.
        // Both call the single shared `derive_block_signing_key`; see its
        // BLOCK_SIGNING_KEY_DOMAIN doc-comment.
        let signing_key = citrate_consensus::crypto::derive_block_signing_key(&coinbase);
        info!(
            "Block signing key: proposer_pubkey={}",
            hex::encode(signing_key.verifying_key().to_bytes())
        );

        // Always use peer manager if we have one (network is already setup above)
        let producer_peer_manager = Some(peer_manager.clone());

        // Treasury percentage from governance
        let mut _treasury_percentage = 10u8;
        if let Some(bytes) = executor
            .state_db()
            .get_storage(&governance_addr, b"PARAM:treasury_percentage")
        {
            if !bytes.is_empty() {
                _treasury_percentage = bytes[0];
            }
        }

        // WP-K.2: Use shared DAG components so the producer and network handler
        // operate on the same DAG for consistent fork-choice.
        let mut producer_instance = BlockProducer::with_shared_dag(
            storage.clone(),
            executor.clone(),
            mempool.clone(),
            producer_peer_manager,
            citrate_consensus::PublicKey::new(coinbase),
            signing_key,
            config.mining.target_block_time,
            economics_manager,
            shared_dag_store.clone(),
            shared_ghostdag.clone(),
        ).await;

        // VALIDATOR-S1 (v5): when the ValidatorRegistry is configured, enable BOTH the
        // EquivocationVote signing and the epoch snapshot-sync (rebuilds the shared selector
        // — the same Arc the DAG store admits against — from the registry at each S(E)).
        // OFF by default; activates on CITRATE_VALIDATOR_REGISTRY + _ACTIVATION_HEIGHT.
        if let (Some((registry, activation_height)), Some(sel)) =
            (&validator_registry, &validator_selector)
        {
            producer_instance = producer_instance
                .with_equivocation_vote_config(producer::EquivocationVoteConfig {
                    chain_id: config.chain.chain_id,
                    registry: *registry,
                    activation_height: *activation_height,
                })
                .with_registry_sync(Arc::new(registry_sync::RegistrySync::new(
                    executor.clone(),
                    sel.clone(),
                    *registry,
                    *activation_height,
                    storage.clone(),
                )));
            info!(
                "VALIDATOR-S1: stake-gated membership ENABLED (registry 0x{}, activation height {})",
                hex::encode(registry),
                activation_height
            );
        }

        // EXECUTE-ON-RECEIVE (reroll addendum): seal version-2 headers that commit the
        // coinbase, making state_root reproducible by receivers. Feature-flagged
        // (CITRATE_BLOCK_V2=1) so it activates at the reroll; default off keeps v1 headers.
        // Uses the SINGLE parsed `execute_on_receive_enabled` (parsed once above) so the
        // producer's v2-header emission can NEVER diverge from the receive-path applier's
        // enablement — a split parse could seal v2 blocks with no applier, or vice-versa.
        if execute_on_receive_enabled {
            producer_instance = producer_instance.with_v2_headers(true);
            info!("EXECUTE-ON-RECEIVE: sealing version-2 headers (coinbase committed in block hash)");
        }

        // EXECUTE-ON-RECEIVE (step 2): share the applied-tip lock so the producer's
        // execute→persist never races the receive-path applier, and each sealed block
        // advances the applied tip. Present iff execute-on-receive (v2) is enabled.
        if let Some(app) = &canonical_applicator {
            producer_instance = producer_instance.with_applied_tip_lock(app.advance_lock());
        }

        // WP-I.3: Share the same pause_flag between RPC server and producer
        // so citrate_emergencyPause actually halts block production.
        producer_instance.set_pause_flag(pause_flag.clone());
        let producer = Arc::new(producer_instance);

        tokio::spawn(async move {
            producer.start().await;
        });

        info!("Block producer started");
    } else if config.mining.enabled && !coinbase_is_valid {
        warn!(
            "Block production DISABLED: no valid coinbase address configured. \
             Set --coinbase <0x...> or mining.coinbase in config file to earn SALT rewards."
        );
    }

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");

    // Wait for RPC to shut down
    if let Some(handle) = rpc_handle {
        handle.abort();
    }

    Ok(())
}

#[allow(dead_code)]
fn load_or_create_peer_id(data_dir: &std::path::Path) -> anyhow::Result<citrate_network::peer::PeerId> {
    use std::fs;
    use std::io::Write;
    let path = data_dir.join("peer.id");
    if let Ok(s) = fs::read_to_string(&path) {
        let id = s.trim().to_string();
        if !id.is_empty() {
            return Ok(citrate_network::peer::PeerId::new(id));
        }
    }
    let id = format!("peer_{}", rand::random::<u64>());
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let mut f = fs::File::create(&path)?;
    writeln!(f, "{}", id)?;
    Ok(citrate_network::peer::PeerId::new(id))
}

// Bootnode parsing + DNS resolution now lives in the shared
// `citrate_network::resolve_bootnode` so the node daemon, discovery, and the
// embedded-node GUIs all handle hostname bootnodes identically.

/// SECREM-01 CFG-1: Load the persistent Noise P2P identity from
/// `noise_key_path`, or generate and persist a new one.
///
/// Security properties:
/// - New key files are written with `0600` permissions (owner read/write
///   only) via `write_secret_file_0600`, never the umask default.
/// - An existing key file with group/other permission bits set is
///   tightened to `0600` on load, with a warning logged.
/// - The serialized key bytes (read buffer on load, `to_bytes()` copy on
///   generate) are held in `zeroize::Zeroizing<Vec<u8>>` and wiped when
///   this function returns. Ownership of the raw private key leaves our
///   control at `NoiseKeypair` construction: `citrate_network::NoiseKeypair`
///   stores `private: Vec<u8>` and must live for the process lifetime
///   inside `NetworkTransport` (handed off via `.with_noise()`) to perform
///   Noise_XX handshakes, so it cannot be zeroized here.
/// - Encrypt-at-rest for `noise.key` is OUT OF SCOPE for this pass and is
///   a tracked SECREM-01 follow-up — it requires a key-wrapping decision
///   (OS keychain vs. operator passphrase vs. KMS).
fn load_or_generate_noise_keypair(
    noise_key_path: &std::path::Path,
) -> anyhow::Result<citrate_network::NoiseKeypair> {
    use zeroize::Zeroizing;

    if noise_key_path.exists() {
        // SECREM-01 CFG-1 (a): tighten loose permissions on an existing key.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(noise_key_path)
                .map_err(|e| anyhow::anyhow!("Failed to stat noise key: {}", e))?;
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                warn!(
                    "Noise key file {:?} had permissions {:o}; tightening to 0600 (SECREM-01 CFG-1)",
                    noise_key_path, mode
                );
                std::fs::set_permissions(
                    noise_key_path,
                    std::fs::Permissions::from_mode(0o600),
                )
                .map_err(|e| anyhow::anyhow!("Failed to chmod noise key to 0600: {}", e))?;
            }
        }
        let key_bytes = Zeroizing::new(
            std::fs::read(noise_key_path)
                .map_err(|e| anyhow::anyhow!("Failed to read noise key: {}", e))?,
        );
        citrate_network::NoiseKeypair::from_bytes(&key_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse noise key: {}", e))
    } else {
        let kp = citrate_network::NoiseKeypair::generate();
        let key_bytes = Zeroizing::new(kp.to_bytes());
        write_secret_file_0600(noise_key_path, &key_bytes)?;
        info!("Generated new persistent Noise identity at {:?}", noise_key_path);
        Ok(kp)
    }
}

/// SECREM-01 CFG-1: Write `bytes` to a new file with `0600` permissions.
///
/// Uses `create_new` so an existing key file is never silently
/// overwritten, and sets the mode at open time (no window where the file
/// exists with umask-default permissions).
fn write_secret_file_0600(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| anyhow::anyhow!("Failed to create noise key file: {}", e))?;
    file.write_all(bytes)
        .map_err(|e| anyhow::anyhow!("Failed to write noise key: {}", e))?;
    Ok(())
}

#[cfg(test)]
mod noise_key_file_tests {
    use super::*;

    #[cfg(unix)]
    fn mode_of(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .expect("stat noise key")
            .permissions()
            .mode()
            & 0o777
    }

    /// SECREM-01 CFG-1: a freshly generated Noise key file must be 0600.
    #[test]
    #[cfg(unix)]
    fn generated_noise_key_file_is_0600() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("noise.key");
        let kp = load_or_generate_noise_keypair(&key_path).expect("generate noise key");
        assert!(key_path.exists(), "key file should be persisted");
        assert_eq!(
            mode_of(&key_path),
            0o600,
            "noise key must be written with 0600 permissions"
        );
        // Round-trip: reloading yields the same identity.
        let reloaded = load_or_generate_noise_keypair(&key_path).expect("reload noise key");
        assert_eq!(kp.derive_peer_id(), reloaded.derive_peer_id());
    }

    /// SECREM-01 CFG-1: an existing key file with loose permissions is
    /// tightened to 0600 on load without changing the identity.
    #[test]
    #[cfg(unix)]
    fn loose_noise_key_permissions_are_tightened_on_load() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("noise.key");
        let kp = load_or_generate_noise_keypair(&key_path).expect("generate noise key");
        // Simulate the pre-fix 0644 world.
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644))
            .expect("loosen permissions");
        assert_eq!(mode_of(&key_path), 0o644);
        let reloaded = load_or_generate_noise_keypair(&key_path).expect("reload noise key");
        assert_eq!(mode_of(&key_path), 0o600, "loose permissions must be tightened");
        assert_eq!(kp.derive_peer_id(), reloaded.derive_peer_id());
    }
}
