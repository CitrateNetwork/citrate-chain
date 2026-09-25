use anyhow::Result;
use citrate_api::{EthSubscriptionServer, RpcConfig, RpcServer};
use citrate_consensus::crypto;
use citrate_economics::{StakeholderType, UnifiedEconomicsConfig, UnifiedEconomicsManager};
use citrate_execution::{Executor, StateDB};
use citrate_network::peer::PeerId;
use citrate_network::peer::{PeerManager, PeerManagerConfig};
use citrate_network::{
    Discovery, DiscoveryConfig, GossipConfig, GossipProtocol, NetworkTransport, SyncConfig,
    SyncManager,
};
use citrate_sequencer::mempool::{Mempool, MempoolConfig};
use citrate_storage::crypto::at_rest::EncryptionAtRestConfig;
use citrate_storage::{pruning::PruningConfig, StorageConfig, StorageManager};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

mod adapters;
mod admission;
mod artifact;
mod block_serve;
pub mod bundled_model;
mod canonical_apply;
mod commands;
mod config;
mod consensus_manifest;
mod contribution_recorder;
mod dag_prune;
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
mod sync;
mod sync_peer;

use citrate_consensus::dag_store::DagStore;
use citrate_consensus::ghostdag::GhostDag;
use citrate_consensus::types::GhostDagParams;
use config::NodeConfig;
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
                if join_testnet {
                    "testnet"
                } else {
                    "local devnet"
                },
                path.display()
            ),
            Err(e) => tracing::warn!(
                "Could not persist first-run config to {}: {}",
                path.display(),
                e
            ),
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
    !matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "l" | "local" | "devnet"
    )
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

    /// Print this binary's consensus-alignment manifest (git SHA + features +
    /// consensus constants + a stable fingerprint). Diff the fingerprint against
    /// the fleet binary before a reroll to prove app↔fleet package alignment.
    Consensus {
        /// Emit the manifest as JSON.
        #[arg(long)]
        json: bool,
    },

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
    let log_config = if std::env::var("LOG_FORMAT")
        .map(|f| f == "json")
        .unwrap_or(false)
    {
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
            )
            .await?;
            return Ok(());
        }
        Some(Commands::Keygen { ed25519 }) => {
            generate_keypair(ed25519);
            return Ok(());
        }
        Some(Commands::Consensus { json }) => {
            let manifest = consensus_manifest::ConsensusManifest::current();
            if json {
                println!("{}", manifest.to_json());
            } else {
                manifest.print_human();
            }
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
        Some(Commands::Wallet {
            keystore,
            rpc,
            wallet_chain_id,
            command,
        }) => {
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

    let has_genesis = probe_storage
        .blocks
        .get_block_by_height(0)
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
        )
        .await?;
        info!(
            "Genesis state initialized for chain ID {}",
            config.chain.chain_id
        );
    } else {
        // WP-K.6: Verify state root consistency before proceeding.
        // If persisted state diverges from genesis, the node would run with corrupted state.
        info!("Genesis block found in storage, verifying state root...");
        let genesis_block = probe_storage
            .blocks
            .get_block_by_height(0)
            .ok()
            .flatten()
            .and_then(|hash| probe_storage.blocks.get_block(&hash).ok().flatten())
            .ok_or_else(|| anyhow::anyhow!("Genesis block must exist (checked above)"))?;

        let persisted_root = probe_storage
            .state
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

    let models_dir = data_dir
        .clone()
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".citrate")
        })
        .join("models");

    let config = ModelManagerConfig {
        models_dir: models_dir.clone(),
        ..Default::default()
    };

    let manager = ModelManager::new(config)
        .await
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
                citrate_consensus::types::ModelId(format!(
                    "manual-pin-{}",
                    &cid[..8.min(cid.len())]
                )),
                cid.clone(),
                citrate_consensus::types::Hash::new([0u8; 32]), // skip hash verification
                0,                                              // unknown size
                0,                                              // no slash penalty
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
            manager
                .unpin_model(&cid)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to unpin model: {}", e))?;
            println!("Successfully unpinned model {}", cid);
        }

        ModelCommands::AutoPin {
            data_dir: cmd_data_dir,
        } => {
            let _data_dir = cmd_data_dir.or(data_dir).unwrap_or_else(|| {
                dirs::home_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join(".citrate")
            });

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
                println!(
                    "  - {} (CID: {}, Size: {} MB)",
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
            println!(
                "This may take a while for large models (up to {} MB total)\n",
                genesis_block
                    .required_pins
                    .iter()
                    .map(|m| m.size_bytes)
                    .sum::<u64>()
                    / 1_000_000
            );

            manager
                .auto_pin_required_models(&genesis_block.required_pins)
                .await
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

        let has_genesis = storage
            .blocks
            .get_block_by_height(0)
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
    println!(
        "  Block Hash: {}",
        hex::encode(genesis.header.block_hash.as_bytes())
    );
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
        println!(
            "    Metadata: {} v{}",
            model.metadata.name, model.metadata.version
        );
        println!();
    }

    let total_embedded_mb = total_embedded_size as f64 / (1024.0 * 1024.0);
    println!(
        "Total Embedded Size: {:.2} MB ({} bytes)",
        total_embedded_mb, total_embedded_size
    );
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
    println!(
        "  Total AI models: {} embedded + {} IPFS",
        genesis.embedded_models.len(),
        genesis.required_pins.len()
    );
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
    {
        // Consensus-alignment stamp — logged at boot so field drift is diagnosable
        // from the journal (the app node and fleet MUST share this fingerprint).
        let m = consensus_manifest::ConsensusManifest::current();
        info!(
            "Consensus manifest: git={}{} halo2={} fingerprint={}",
            m.git_sha,
            if m.git_dirty { "(DIRTY)" } else { "" },
            m.feat_halo2_verifier,
            m.fingerprint
        );
        if m.git_dirty {
            warn!("Node built from a DIRTY tree — not reproducibly aligned with the fleet");
        }
    }
    info!("Chain ID: {}", config.chain.chain_id);
    info!("Data directory: {:?}", config.storage.data_dir);

    // PBA-R2: fix the block-validity hardening activation height BEFORE any
    // consensus component (GhostDag, Executor, SyncManager, GossipProtocol) is
    // constructed; each captures it at construction. A consensus parameter:
    // an unparseable override aborts start-up rather than being ignored.
    {
        // ONE store, ONE resolution order (env override, else [chain] key):
        // consensus, network and execution (`citrate_execution::activation`)
        // all read what this publishes.
        let pba = citrate_consensus::hardening::init_pba_hardening_height(
            config.chain.pba_hardening_height,
        )
        .map_err(|e| anyhow::anyhow!("{}", e))?;
        match pba {
            Some(h) => info!(
                "PBA-R2 block-validity hardening ACTIVE from height {} \
                 (tx signature + canonical id on import, content-bound tx_root, \
                 timestamp bound)",
                h
            ),
            None => info!(
                "PBA-R2 block-validity hardening not scheduled (chain.pba_hardening_height \
                 unset); legacy validity rules apply"
            ),
        }
    }

    // Initialize metrics server
    let metrics_addr =
        std::env::var("CITRATE_METRICS_ADDR").unwrap_or_else(|_| "127.0.0.1:9090".to_string());
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
    let state_manager = Arc::new(citrate_storage::state_manager::StateManager::new(
        storage.db.clone(),
    ));

    // Load existing state from storage into memory
    info!("Loading state from storage...");
    match storage.state.get_all_accounts() {
        Ok(accounts) => {
            info!(
                "Found {} accounts in storage, loading into memory...",
                accounts.len()
            );
            for (address, account) in accounts {
                debug!(
                    "Loaded account: 0x{} with balance {}",
                    hex::encode(address.0),
                    account.balance
                );
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
            info!(
                "Found {} storage slots in storage, loading into memory...",
                storage_slots.len()
            );
            for ((address, storage_key), storage_value) in storage_slots {
                state_db.set_storage(
                    address,
                    storage_key.as_bytes().to_vec(),
                    storage_value.as_bytes().to_vec(),
                );
            }
            // Clear dirty flags since these are loaded from storage, not new writes
            let _ = state_db.take_dirty_storage();
            info!("Storage slots loaded successfully");
        }
        Err(e) => {
            warn!("Failed to load storage slots from storage: {}", e);
        }
    }

    // SRP-S3b: verify the hydrated in-memory root reproduces the committed root of the
    // APPLIED TIP — the block whose post-execution state the durable store reflects — NOT
    // the latest stored block. A node legitimately stores blocks AHEAD of what it has
    // applied (execute-on-receive downloads then drains; the producer persists the block
    // before atomically advancing state+tip). Comparing against the latest BLOCK would
    // false-positive whenever blocks lead the applied tip; the applied-tip pointer and the
    // durable state are advanced ATOMICALLY (persist_state_changes_with_tip), so they must
    // always agree — a mismatch means a genuinely corrupt/divergent reconstruction.
    {
        let memory_root = state_db.calculate_state_root();
        // The applied tip = the block whose committed state the store holds. Fall back to
        // the latest block only when no applied-tip pointer exists (pre-S3b stores / fresh
        // genesis), preserving the prior behavior for those.
        let (tip_hash, tip_height) = storage
            .blocks
            .get_applied_tip()
            .ok()
            .flatten()
            .unwrap_or_else(|| {
                let h = storage.blocks.get_latest_height().unwrap_or(0);
                let hash = storage
                    .blocks
                    .get_block_by_height(h)
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                (hash, h)
            });
        if tip_height > 0 && tip_hash != citrate_consensus::types::Hash::default() {
            let committed_root = storage
                .state
                .get_state_root(&tip_hash)
                .ok()
                .flatten()
                .or_else(|| {
                    storage
                        .blocks
                        .get_block(&tip_hash)
                        .ok()
                        .flatten()
                        .map(|b| b.state_root)
                });
            match committed_root {
                Some(root) if root != citrate_consensus::types::Hash::default() => {
                    if memory_root == root {
                        info!(
                            "State root verification PASSED (applied tip height {}, root={})",
                            tip_height,
                            hex::encode(&memory_root.as_bytes()[..8])
                        );
                    } else {
                        // SRP-S3: a node whose hydrated root does NOT reproduce the applied
                        // tip's committed root MUST NOT start — it would seal/verify against
                        // a divergent root and fork the fleet. HARD-FAIL (safe local stop),
                        // never warn-and-continue. See ADR-2026-07-21-restart-produce-purity.
                        error!("SRP-S3 BOOT HALT: state root MISMATCH at applied tip height {}: memory={} committed={} — refusing to start (a node that cannot reconstruct the committed root would fork the fleet)",
                            tip_height,
                            hex::encode(memory_root.as_bytes()),
                            hex::encode(root.as_bytes()));
                        return Err(anyhow::anyhow!(
                            "SRP-S3 boot halt: hydrated state root {} != committed root {} at applied tip height {}",
                            hex::encode(memory_root.as_bytes()),
                            hex::encode(root.as_bytes()),
                            tip_height
                        ));
                    }
                }
                _ => {
                    debug!(
                        "No committed state root for applied tip height {} — skipping verification",
                        tip_height
                    );
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
            mempool_max_size,
            mempool_max_per_sender
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
    })
    // PBA-L1a-001: bound admitted nonces against the sender's COMMITTED nonce
    // (stale and far-future nonces rejected on every ingress, new senders too).
    .with_state_nonce_reader({
        let exec = executor.clone();
        Arc::new(move |pk: &citrate_consensus::types::PublicKey| {
            exec.get_nonce(&citrate_execution::address_utils::normalize_address(pk))
        })
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
                tracing::error!(
                    "Invalid CITRATE_METRICS_ADDR '{}': {}, skipping metrics server",
                    addr_str,
                    e
                );
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
                activation,
                s1
            ));
        }
        // §R' hard-reject: teach the executor the activation height INDEPENDENTLY of the
        // (initially-None) policy cell, so a None policy at/above activation is a rejectable
        // fault rather than a silent skip (which would fork this node from the fleet).
        executor.set_validator_activation_height(*activation);
    }
    // The shared proposer selector — the SAME Arc the DAG store admits against and the
    // snapshot-sync rebuilds. production() disables the forgeable legacy VRF path.
    let validator_selector: Option<Arc<citrate_consensus::vrf::VrfProposerSelector>> =
        validator_registry
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
    // PIL-42's genesis DAG seed moved into `BlockAdmission::seed_genesis` (see
    // SYNC-S1 D2 below) so that every chain-store/DAG-store consistency concern
    // lives in one module under one set of rules.
    let shared_ghostdag = Arc::new(GhostDag::new(
        GhostDagParams::default(),
        shared_dag_store.clone(),
    ));

    // WP-W.1: Create CheckpointManager for BFT finality vote handling
    let checkpoint_manager = {
        use citrate_consensus::checkpoint::{CheckpointConfig, CheckpointManager};
        let cp_config = CheckpointConfig::default();
        let kv = Arc::new(persistent_dag::RocksDbKvStore::new(storage.db.clone()));
        Arc::new(CheckpointManager::with_persistence(
            cp_config,
            shared_dag_store.clone(),
            kv,
        ))
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
            if let (Some((registry, activation)), Some(sel)) =
                (&validator_registry, &validator_selector)
            {
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
                    Err(e) => warn!(
                        "VALIDATOR-S1: boot rehydration failed at height {}: {}",
                        resumed, e
                    ),
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

    // SYNC-S1 / D2: the SINGLE path by which a block enters this node. Every
    // ingest source (gossip `NewBlock`, sync `Blocks`, the startup reconciler,
    // the genesis seed) routes through it, and it is the only code that
    // sequences the DAG-store write, the GhostDAG registration and the
    // chain-store write. See node/src/admission.rs for the failure it closes:
    // an OOM kill landing between the DAG write and the chain write used to
    // freeze a follower's applied tip permanently, because re-delivery hit
    // `store_block` -> `Err(BlockExists)` and dropped the block without ever
    // reaching `put_block`.
    //
    // Constructed at function scope (not inside the P2P block) so the genesis
    // seed and the reconcile pass run even with networking disabled.
    let block_admission = Arc::new(admission::BlockAdmission::new(
        storage.clone(),
        shared_dag_store.clone(),
        shared_ghostdag.clone(),
        canonical_applicator.clone(),
    ));

    // PIL-42: genesis must be the DAG's height-0 root or the producer seals
    // block 1 against a zero selected-parent and orphans it.
    block_admission.seed_genesis().await;

    // SYNC-S1 D3: bound DagStore memory. D1 made per-block retention O(1)
    // instead of Theta(N²), but the DAG store still keeps every block it has
    // admitted — measured at ~16 KB/block on the G3 fleet run, i.e. a 3.9 GB
    // follower runs out near 150k blocks. Opt-in via CITRATE_DAG_PRUNE_RETAIN
    // (no-op when unset) because the merge-block score path is not yet bounded.
    dag_prune::spawn(storage.clone(), shared_dag_store.clone());

    // D2.4: repair partial admissions already on disk. Any node that ran a
    // pre-D2 binary can be carrying a chain-store hole with the block sitting
    // in the DAG store, and nothing guarantees a peer offers that block again —
    // so boot repairs it rather than waiting for a re-delivery that may never
    // come. Bounded to (applied_tip, latest_height]; a no-op when healthy.
    {
        let report = block_admission.reconcile().await;
        if report.repaired_anything() {
            warn!(
                "SYNC-S1: startup reconcile REPAIRED a partial admission — chain writes \
                 completed at {:?}, DAG admissions at {:?}. This node was wedged (applied \
                 tip frozen below a store hole); the drain will now advance.",
                report.chain_writes_completed, report.dag_writes_completed
            );
        } else {
            info!(
                "SYNC-S1: startup reconcile found no partial admissions ({} ordinary sync gap(s))",
                report.gaps.len()
            );
        }
    }

    // RESTART-LIVENESS (2026-08-11): make GhostDAG's in-memory tip set AUTHORITATIVE
    // at boot. The DAG store already reconstructs its tips from block-header parentage
    // on load (PIL-42); copy that in so `select_tip` (the fork-choice authority for
    // BOTH the producer and the drain since #163) never returns a stale ancestor after
    // a restart, and mark DAG hydration complete so the applicator's runtime deep-fork
    // rebuild may fire. On a MINING node the producer's own eager-load runs this again
    // at the end of its load (producer.rs) — idempotent; the later one wins. On a
    // non-mining FOLLOWER (no producer eager-load) this is the ONLY place it runs, and
    // is exactly what unwedges the 2026-08-11 follower drain stall.
    {
        let n_tips = shared_ghostdag.reconcile_tips_from_dag_store().await;
        info!(
            "startup: reconciled GhostDAG to {} authoritative tip(s); DAG hydration complete",
            n_tips
        );
    }

    // Forward-sync liveness (handoff 2026-07-23): the highest block height we have
    // EVIDENCE the network is at, from ANY signal — gossiped NewBlock, a rejected
    // far-ahead block (MissingParentAtAdmission proves the sender is ahead of us),
    // or a Hello. The 2s sync tick drives the target off this (not only the best
    // connected peer's head, which goes stale and parks a follower one growth-window
    // short of a still-producing tip), and eth_syncing reports it as highestBlock.
    // Monotonic via fetch_max. Function-scoped so both the P2P tasks and the RPC
    // server can read it.
    let max_seen_height = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

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
        max_seen_height.fetch_max(head_height, std::sync::atomic::Ordering::Relaxed);
        let genesis_hash = storage
            .blocks
            .get_block_by_height(0)
            .ok()
            .flatten()
            .unwrap_or_default();
        // SECREM-A001: bind the shared DAG store to this chain's canonical
        // genesis identity BEFORE any network block is admitted, so a block
        // merely shaped like genesis (parentless, arbitrary height) cannot
        // bypass the admission gates.
        shared_dag_store.set_configured_genesis(genesis_hash);
        let network_id: u32 = config.chain.chain_id as u32;

        // Incoming message channel (log-only for now)
        let (in_tx, mut in_rx) =
            tokio::sync::mpsc::channel::<(PeerId, citrate_network::NetworkMessage)>(512);
        peer_manager.set_incoming(in_tx).await;
        let pm_for_rx = peer_manager.clone();
        let storage_for_handler = storage.clone();
        let mempool_for_handler = mempool.clone();
        // EXECUTE-ON-RECEIVE (step 2): the applier is reached through
        // `BlockAdmission` now (SYNC-S1 D2), not cloned into the handler
        // separately, so execute-on-receive cannot be skipped on an ingest
        // path that forgot to call it.
        // SAME-HEIGHT-SIBLING WEDGE RECOVERY (2026-08-06; chain 40204 halted at
        // 90,998 then 91,109). Before the periodic drain or the producer starts,
        // converge a node whose persisted applied tip is a NON-canonical sibling. A
        // plain restart cannot self-heal this — `CanonicalApplicator::new` seeds the
        // reorg ring with only the tip's snapshot, so `reorg_to(head)` can never
        // reach the fork point. `recover_to_head` rebuilds the executor from genesis
        // and re-applies the canonical chain from the node's OWN stored blocks
        // (repopulating the ring so the reorg at each fork converges). Atomic + a
        // no-op on a healthy node (tip already == fork-choice head).
        if let Some(app) = canonical_applicator.clone() {
            // Reconstruct the genesis world-state deterministically via the same
            // single-source init the node used at genesis, in a throwaway store.
            let scratch_dir = std::env::temp_dir()
                .join(format!("citrate-genesis-recovery-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&scratch_dir);
            let genesis_snapshot = match StorageManager::new(&scratch_dir, PruningConfig::default())
            {
                Ok(scratch_storage) => {
                    let scratch_storage = Arc::new(scratch_storage);
                    let scratch_exec = Arc::new(Executor::with_storage(
                        Arc::new(StateDB::new()),
                        Some(scratch_storage.state.clone()),
                    ));
                    let gcfg = genesis::GenesisConfig {
                        chain_id: config.chain.chain_id,
                        ..Default::default()
                    };
                    match genesis::initialize_genesis_state_with_profile(
                        scratch_storage.clone(),
                        scratch_exec.clone(),
                        &gcfg,
                        config.chain.genesis_profile.as_deref(),
                    )
                    .await
                    {
                        Ok(_) => Some(scratch_exec.state_snapshot()),
                        Err(e) => {
                            warn!("canonical recovery: genesis reconstruction failed: {}", e);
                            None
                        }
                    }
                }
                Err(e) => {
                    warn!("canonical recovery: scratch store open failed: {}", e);
                    None
                }
            };
            let _ = std::fs::remove_dir_all(&scratch_dir);
            if let Some(genesis_snapshot) = genesis_snapshot {
                let genesis_hash = storage
                    .blocks
                    .get_block_by_height(0)
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                // Wire the RUNTIME reorg fallback: with genesis in hand, the periodic
                // drain can self-heal a fork deeper than the in-memory reorg window by
                // rebuilding along the canonical spine — no manual restart (2026-08-09).
                app.set_genesis(genesis_snapshot.clone(), genesis_hash);
                // The DAG store hydrates its in-memory tips ASYNCHRONOUSLY after boot,
                // so fork-choice cannot see a competing sibling yet. WAIT until the DAG
                // is FULLY hydrated (fork-choice head reaches the top stored height),
                // then converge if we are not already on it. We deliberately do NOT
                // bail when the applied tip merely advances: the live drain re-applies
                // a low/wedged tip forward block-by-block, VERIFYING every state root
                // (calculate_state_root rebuilds the whole trie each call — an ~O(N^2)
                // crawl, hours for 90k blocks). The fast trusted rebuild converges in
                // minutes, so we fire it even while the slow drain inches along. Retry
                // a few times in case an early fork-choice view was still partial.
                let ghostdag_rec = shared_ghostdag.clone();
                let latest_stored = storage.blocks.get_latest_height().unwrap_or(0);
                tokio::spawn(async move {
                    let mut aborted = 0u32;
                    for _ in 0..600u32 {
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        let head = match ghostdag_rec.select_tip().await {
                            Ok(h) => h,
                            Err(_) => continue,
                        };
                        // Fire only once fork-choice has hydrated to the top stored
                        // height (both siblings of the wedge loaded), so we never
                        // rebuild toward a partially-loaded head.
                        let head_h = ghostdag_rec.get_block_height(&head).await.unwrap_or(0);
                        if head_h < latest_stored {
                            continue;
                        }
                        let cur = app.applied_tip().await;
                        if head == cur.hash {
                            return; // already converged / healthy — nothing to do
                        }
                        match app
                            .recover_to_head(genesis_snapshot.clone(), genesis_hash)
                            .await
                        {
                            Ok(true) => {
                                info!("canonical recovery: rebuilt applied state to the fork-choice head");
                                return;
                            }
                            Ok(false) => {
                                aborted += 1;
                                if aborted >= 5 {
                                    warn!(
                                        "canonical recovery: gave up after {} aborted attempts",
                                        aborted
                                    );
                                    return;
                                }
                                warn!("canonical recovery: attempt aborted — retrying");
                            }
                            Err(e) => {
                                warn!(
                                    "canonical recovery failed (continuing on persisted tip): {}",
                                    e
                                );
                                return;
                            }
                        }
                    }
                });
            }
        }

        // EXECUTE-ON-RECEIVE (step 3): periodic forward-drain self-heal. The receive
        // path persists blocks before applying and only drives the drain for blocks it
        // hasn't already stored, so a node holding stored-but-unapplied blocks ahead of
        // its applied tip (fresh-join / boot catch-up, or a restart with blocks stored
        // ahead) would freeze its applied tip forever while the stored height climbs.
        // This timer walks the applied tip forward through already-persisted blocks so
        // the node advances to head unattended. No-op when there is nothing to drain.
        if let Some(app) = canonical_applicator.clone() {
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
                loop {
                    interval.tick().await;
                    app.drive_drain().await;
                }
            });
        }
        let gossip = Arc::new(GossipProtocol::new(
            GossipConfig {
                genesis_hash: Some(genesis_hash),
                ..GossipConfig::default()
            },
            peer_manager.clone(),
        ));
        let gossip_for_rx = gossip.clone();
        // Sync manager (basic integration)
        // WEDGE #85: judge sync completion against THIS node's applied chain, not
        // the height of the last block handed to us. Without this a node with a
        // gap beneath the live tip declares itself synced on the first gossiped
        // tip block and stops requesting the backlog — it then drops those tip
        // blocks (parents absent), persists nothing, serves nothing, and its
        // applied tip never moves again.
        let sync = Arc::new(match canonical_applicator.as_ref() {
            Some(app) => SyncManager::new(SyncConfig::default())
                .with_local_height(app.applied_height_handle()),
            None => SyncManager::new(SyncConfig::default()),
        });
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
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
                loop {
                    interval.tick().await;
                    if let Ok(Some((hash, height))) = storage_head.blocks.get_applied_tip() {
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
                    warn!(
                        "Bootnode {} has no Noise identity — cannot verify trust root",
                        addr
                    );
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
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
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

        // #85: which peer the sync tick pulls from, plus the per-peer timeout
        // accounting behind that choice. Shared with the message handler so a
        // peer that ANSWERS clears its penalty (sync_peer.rs invariant I3) —
        // the tick task alone only ever observes failures, which is how a peer
        // could accumulate penalties it had no way to shed.
        let sync_peers = Arc::new(tokio::sync::Mutex::new(sync_peer::SyncPeerSelector::new()));

        // Periodic sync tick: request headers/blocks and check timeouts
        let pm_for_sync = pm_for_rx.clone();
        let sync_for_loop = sync.clone();
        let storage_for_sync = storage.clone();
        let max_seen_for_sync = max_seen_height.clone();
        let sync_peers_for_loop = sync_peers.clone();
        tokio::spawn(async move {
            // #150: `attempt_counts` (an unpruned HashMap keyed by every anchor
            // ever timed out — also a slow leak) and `pending_retries` are gone
            // with the stale-anchor retry queue. See the note at `check_timeouts`.
            // Round-robin index for rotating request peers when we are behind but no
            // peer qualified as "best" (forward-sync liveness fix).
            let mut rotate_idx: u64 = 0;
            // #155: last peer we logged choosing, so SYNCPEER only fires on change.
            let mut last_logged_choice: Option<String> = None;
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
            loop {
                interval.tick().await;
                // Snapshot every CONNECTED peer with the head it advertises. The
                // scan is split from the choice deliberately: `best_h` (the sync
                // TARGET) is the highest head anyone advertises, whereas the peer
                // we PULL from must additionally be ahead of us and not in the
                // penalty box. Conflating the two is what let a same-height
                // sibling win selection (sync_peer.rs, defect D1).
                let mut connected_peers: Vec<(
                    sync_peer::SyncCandidate,
                    Arc<citrate_network::peer::Peer>,
                )> = Vec::new();
                let mut best_h: u64 = 0;
                let mut best_hash = citrate_consensus::types::Hash::new([0u8; 32]);
                for p in pm_for_sync.get_all_peers() {
                    let info = p.info.read().await;
                    if info.state != citrate_network::peer::PeerState::Connected {
                        continue;
                    }
                    if info.head_height > best_h {
                        best_h = info.head_height;
                        best_hash = info.head_hash;
                    }
                    connected_peers.push((
                        sync_peer::SyncCandidate {
                            id: info.id.0.clone(),
                            head_height: info.head_height,
                        },
                        p.clone(),
                    ));
                }
                // Drive the sync target off the MAX of the best connected-peer head
                // and the max height we have evidence for ANYWHERE (gossip / a
                // rejected far-ahead block / Hello). best_h alone goes stale: a
                // follower's connected peers can stop advertising a higher head while
                // the tip keeps climbing (or the far-ahead blocks arrive via a relay
                // peer not in the peer manager), freezing the target and parking the
                // node one growth-window short of the tip — the forward-sync stall.
                // set_target only RAISES, never lowers.
                let seen = max_seen_for_sync.load(std::sync::atomic::Ordering::Relaxed);
                // Our true synced head (applied tip height). When this is below the
                // target we KNOW we are behind and must keep pulling.
                let applied_height = storage_for_sync
                    .blocks
                    .get_applied_tip()
                    .ok()
                    .flatten()
                    .map(|(_, h)| h)
                    .unwrap_or(0);
                // CHAIN-B-A007: clamp the target to a sane distance above our own
                // applied tip. `seen` is fed (in part) by unauthenticated
                // `Hello`/`HelloAck` `head_height` and gossip; a single peer
                // advertising `head_height = u64::MAX` would otherwise pin the
                // target — and `eth_syncing.highestBlock` — at u64::MAX for the
                // life of the process, and flatten the serve-quality classifier
                // whose `gap = target - applied` then never shrinks. The bound is
                // generous (10M blocks ahead) so no honest deep-sync gap is ever
                // throttled, but an absurd claim can no longer pin the target.
                const MAX_SYNC_LOOKAHEAD: u64 = 10_000_000;
                let target = best_h
                    .max(seen)
                    .min(applied_height.saturating_add(MAX_SYNC_LOOKAHEAD));
                if target > 0 {
                    sync_for_loop.set_target(target).await;
                }
                // Choose a peer to pull from — see node/src/sync_peer.rs for the
                // policy and the two live wedges it closes. In short: only peers
                // whose advertised head is ABOVE our applied tip are candidates
                // (a same-height peer serves back our own anchor and we re-import
                // it forever), and the timeout penalty de-prefers a peer without
                // ever vetoing the last one that could actually serve us.
                let candidates: Vec<sync_peer::SyncCandidate> =
                    connected_peers.iter().map(|(c, _)| c.clone()).collect();
                let chosen_id = {
                    let sel = sync_peers_for_loop.lock().await;
                    sel.select(&candidates, applied_height)
                        .map(|c| c.id.clone())
                };
                // #155: log WHICH PEER WE ARE PULLING FROM — but only when it
                // CHANGES.
                //
                // Every sync bug this week came down to "we were asking the wrong
                // peer", and answering that took SSH onto the fleet and grepping
                // the SERVER's journal for our own peer id, because the node never
                // said who it had chosen. That is the single most valuable line
                // the sync driver can emit and it did not exist.
                //
                // Change-triggered, so volume is near zero on a converged node and
                // rises exactly when selection is thrashing — which is the thing
                // worth seeing. A per-tick log would be 30 lines/minute of noise
                // that nobody reads, and the interesting event would be invisible
                // inside it.
                if chosen_id != last_logged_choice {
                    match (&chosen_id, &last_logged_choice) {
                        (Some(now), Some(before)) => tracing::info!(
                            "SYNCPEER switched {} -> {} (applied={} candidates={})",
                            &before[..14.min(before.len())],
                            &now[..14.min(now.len())],
                            applied_height,
                            candidates.len()
                        ),
                        (Some(now), None) => tracing::info!(
                            "SYNCPEER selected {} (applied={} candidates={})",
                            &now[..14.min(now.len())],
                            applied_height,
                            candidates.len()
                        ),
                        (None, Some(before)) => tracing::info!(
                            "SYNCPEER lost source (was {}, applied={} candidates={})",
                            &before[..14.min(before.len())],
                            applied_height,
                            candidates.len()
                        ),
                        (None, None) => {}
                    }
                    last_logged_choice = chosen_id.clone();
                }
                let request_peer: Option<Arc<citrate_network::peer::Peer>> =
                    if let Some(id) = chosen_id {
                        connected_peers
                            .iter()
                            .find(|(c, _)| c.id == id)
                            .map(|(_, p)| p.clone())
                    } else if applied_height < target {
                        // We have EVIDENCE we are behind (a gossiped block, a Hello,
                        // a rejected far-ahead block) but no connected peer admits to
                        // a head above ours — their advertisements are stale or were
                        // never updated. Rotate across all connected peers so we keep
                        // asking rather than parking idle; rotation (not a fixed pick)
                        // so we don't spin forever on one that only serves a side
                        // branch.
                        if connected_peers.is_empty() {
                            None
                        } else {
                            let i = (rotate_idx as usize) % connected_peers.len();
                            rotate_idx = rotate_idx.wrapping_add(1);
                            Some(connected_peers[i].1.clone())
                        }
                    } else {
                        None
                    };
                if let Some(peer) = request_peer {
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
                    let (start_from, start_height) = storage_for_sync
                        .blocks
                        .get_applied_tip()
                        .ok()
                        .flatten()
                        .unwrap_or_else(|| (citrate_consensus::types::Hash::new([0u8; 32]), 0));
                    // Request next headers and blocks from our last known point only if not saturated
                    let (ph, pb) = sync_for_loop.pending_counts().await;
                    // #151: a request that FAILS TO SEND must count against this peer.
                    //
                    // Both calls below were `let _ = ...`. A failed send records no
                    // pending request, so it can never time out — and the penalty box
                    // (#136) is driven ENTIRELY by timeouts. So a peer whose channel had
                    // closed was never de-preferred and never dropped, while the selector
                    // kept choosing it on the stale advertised head a dead peer still
                    // carries. Every request evaporated, silently, forever.
                    //
                    // Instrumented on chain 40204 after a 150s network interruption:
                    //
                    //   TICKTRACE 481 F1 ph=0 pb=0 anchor=f15e3524 peer=noise_2b492467
                    //   TICKTRACE 481 F2 req_headers=false
                    //   TICKTRACE 481 F3 req_blocks=false
                    //
                    // every 2s indefinitely — pending maps EMPTY (so neither saturation
                    // nor dedup), four peers connected, correct target, zero timeouts
                    // logged. The node was retrying a corpse.
                    //
                    // Crediting a send failure as a timeout is the right equivalence:
                    // both mean "this peer did not give us blocks", which is exactly what
                    // the penalty box acts on. That feeds the EXISTING escalation rather
                    // than adding a second policy that could disagree with it.
                    let mut send_failed = false;
                    if ph < 8
                        && sync_for_loop
                            .request_headers(&peer, start_from)
                            .await
                            .is_err()
                    {
                        send_failed = true;
                    }
                    if pb < 8
                        && sync_for_loop
                            .request_blocks(&peer, start_from, start_height)
                            .await
                            .is_err()
                    {
                        send_failed = true;
                    }
                    if send_failed {
                        let pid = peer.info.read().await.id.clone();
                        let fails = {
                            let mut sel = sync_peers_for_loop.lock().await;
                            sel.record_timeout(&pid.0)
                        };
                        // A closed channel is terminal, not slow: the writer task is gone
                        // and no future send can succeed. Evict now so the discovery
                        // re-dial (#149) replaces it, rather than waiting out a penalty
                        // count that a corpse can never earn.
                        if peer.is_closed() {
                            pm_for_sync.remove_peer(&pid).await;
                            sync_peers_for_loop.lock().await.reset(&pid.0);
                            tracing::warn!(
                                "Sync peer {} has a closed connection — evicted so it can \
                                 re-handshake (it was being selected and silently failing)",
                                pid.0
                            );
                        } else {
                            tracing::warn!(
                                "Sync request to {} failed to send ({} consecutive) — \
                                 de-preferring it as a source",
                                pid.0,
                                fails
                            );
                        }
                    }
                }
                // Retire timed-out requests and penalize the peer that owed them.
                //
                // #150 — THERE IS NO SEPARATE RETRY QUEUE ANY MORE, ON PURPOSE.
                //
                // A timed-out request was anchored at the applied tip AT THE TIME
                // IT WAS SENT. By the time any retry fires (2-32s later under the
                // old backoff) the tip has moved, so re-requesting that anchor asks
                // for a range the node has already applied. Measured live on a
                // cold-syncing node: the same four ranges re-imported 30, 25, 24 and
                // 22 times each, all at or below the applied tip, while forward
                // progress collapsed from ~700 blocks/min to ~15/min. The retries
                // also consumed the in-flight budget (`pending_counts() < 8`) that
                // the ONE useful request needs, and were issued to
                // `get_all_peers().first()` — an arbitrary peer, not the selected
                // sync source — so they frequently timed out again and re-queued.
                //
                // The 2s tick at the top of this loop already re-issues a request
                // anchored at the CURRENT applied tip to the CURRENTLY SELECTED
                // peer. That is the retry, and unlike a queued one it can never be
                // stale. The old machinery was a second, worse retry path racing
                // the good one, plus an `attempt_counts` map that was never pruned.
                //
                // Timeouts still do their real job below: they penalize the peer.
                for (_h, pid) in sync_for_loop.check_timeouts().await {
                    // Penalize the peer that timed out. This DE-PREFERS it as a
                    // sync source; it can never veto the last peer able to serve
                    // us (sync_peer.rs invariant I2).
                    let pf = {
                        let mut sel = sync_peers_for_loop.lock().await;
                        sel.record_timeout(&pid.0)
                    };
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
                    if pf >= 5 && total_peers > 1 && pm_for_sync.get_peer(&pid).is_some() {
                        pm_for_sync.remove_peer(&pid).await;
                        sync_peers_for_loop.lock().await.reset(&pid.0);
                        tracing::warn!(
                            "Dropped peer {} after repeated sync timeouts (will re-handshake)",
                            pid.0
                        );
                    } else if pf >= 5 {
                        // Sole peer: reset the counter so we keep trying it rather
                        // than freezing after 5 timeouts.
                        sync_peers_for_loop.lock().await.reset(&pid.0);
                    }
                }
            }
        });
        let network_inf_executor = Arc::new(
            crate::network_inference::NodeNetworkInferenceExecutor::new(mcp.clone(), provider_addr),
        );
        let ai_handler = Arc::new(
            citrate_network::ai_handler::AINetworkHandler::new(
                state_manager.clone(),
                peer_manager.clone(),
            )
            .with_inference_executor(network_inf_executor),
        );
        let ai_handler_for_rx = ai_handler.clone();
        // PBA-L1b-005: peer inference runs off the inbound loop, bounded.
        let inference_dispatcher = crate::network_inference::InferenceDispatcher::new(
            ai_handler.clone(),
            peer_manager.clone(),
            crate::network_inference::MAX_CONCURRENT_PEER_INFERENCES,
        );

        // WP-K.2 / SYNC-S1 D2: the network handler no longer touches the DAG
        // store or GhostDAG directly — `BlockAdmission` (below) owns both, so
        // there is exactly one place that writes them. The former
        // `dag_store_for_net` / `ghostdag_for_net` / `applicator_for_net`
        // clones existed only to feed the two open-coded admission ladders and
        // are gone with them.
        let max_seen_for_rx = max_seen_height.clone();

        // SYNC-S1 / D2: the network handler's handle on the single admission
        // path (constructed at function scope above, alongside the genesis seed
        // and the startup reconcile).
        let admission_for_net = block_admission.clone();
        let checkpoint_mgr_for_net = checkpoint_manager.clone();
        // #85: the success half of the sync-peer accounting (invariant I3) —
        // the tick task can only ever observe timeouts, so the peer that
        // actually answers has to be credited from the receive side.
        let sync_peers_for_rx = sync_peers.clone();

        // #149: how many inbound messages the loop has taken off the channel.
        // Read by the stall detector; see it for why this exists.
        let msgs_processed = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let msgs_processed_for_loop = msgs_processed.clone();
        let pm_for_stall = pm_for_rx.clone();

        let net_rx_task = tokio::spawn(async move {
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
                // #149 liveness heartbeat. Bumped BEFORE the message is handled,
                // so a loop that is stuck inside a handler stops advancing this
                // while inbound traffic keeps arriving — the signature the stall
                // detector below keys on. See that task for why a dead-task
                // watchdog (#147) cannot see this failure.
                msgs_processed_for_loop.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::debug!("[P2P] from={} msg={:?}", pid.0, msg);
                // Handle protocol messages
                match msg {
                    NetworkMessage::Hello {
                        head_height,
                        head_hash,
                        ..
                    } => {
                        // PBA-L1b-006: an unauthenticated handshake height is NOT
                        // network-height evidence (it pinned eth_syncing.highestBlock
                        // at u64::MAX for the life of the process). It still seeds
                        // this peer's advertised head, which the sync tick clamps.
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
                    NetworkMessage::HelloAck {
                        head_height,
                        head_hash,
                        ..
                    } => {
                        // PBA-L1b-006: see Hello — not recorded as network height.
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
                        let blocks = block_serve::serve_blocks(&storage_for_handler, &from, count);

                        tracing::info!("Sending {} blocks to peer {}", blocks.len(), pid.0);
                        let _ = pm_for_rx
                            .send_to_peers(
                                std::slice::from_ref(&pid),
                                &NetworkMessage::Blocks { blocks },
                            )
                            .await;
                    }
                    NetworkMessage::GetPeers => {
                        // Serve a small list of peers from discovery
                        let peers = discovery.get_peers_for_exchange().await;
                        let _ = pm_for_rx
                            .send_to_peers(
                                std::slice::from_ref(&pid),
                                &NetworkMessage::Peers { peers },
                            )
                            .await;
                    }
                    NetworkMessage::Peers { peers } => {
                        discovery.handle_peer_exchange(peers).await;
                    }
                    NetworkMessage::GetHeaders { from, count } => {
                        tracing::info!(
                            "Received GetHeaders request from peer {} starting {:?} count {}",
                            pid.0,
                            from,
                            count
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
                        let _ = sync_for_rx.handle_headers(&pid, headers).await;
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
                        // CHAIN-B-A007: network-height evidence from gossip is
                        // recorded AFTER the block passes `gossip::validate_block`
                        // (in the `Ok(_)`/`Deferred` arms below), never on the raw
                        // pre-validation header. Previously this ran an
                        // unconditional `max_seen.fetch_max(block.header.height)`
                        // here — before any structural or signature check — so one
                        // unauthenticated packet claiming `height = u64::MAX` pinned
                        // the sync target (and `eth_syncing.highestBlock`) at
                        // u64::MAX for the life of the process, which also flattens
                        // the serve-quality classifier (gap = target - applied).
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
                        // SYNC-S1 / D2: gossip runs its own validation (structure,
                        // signature, peer scoring, relay) and then hands the block to the
                        // SINGLE idempotent admission path. It no longer open-codes the
                        // store_block -> add_block -> put_block ladder.
                        //
                        // The old `has_block(chain) -> skip` gate is GONE on purpose: it
                        // consulted only the chain store, so a block half-admitted by an
                        // interrupted earlier attempt looked complete and its missing DAG
                        // write was never made. Duplicate-suppression now requires
                        // presence in BOTH stores (see admission.rs, rule R1).
                        if !admission_for_net
                            .is_fully_admitted(&block.header.block_hash)
                            .await
                        {
                            match gossip_for_rx.handle_new_block(block.clone(), &pid).await {
                                Ok(_) => {
                                    // PBA-L1b-006: gossip validation proves only a
                                    // self-consistent, self-signed header — any key
                                    // can sign height u64::MAX. The height becomes
                                    // network-height evidence once ADMITTED
                                    // (linkage verified from genesis), or clamped
                                    // when deferred (below).
                                    match admission_for_net.admit(&block).await {
                                    admission::AdmitOutcome::Admitted { completed_partial } => {
                                        sync_peer::record_verified_height(
                                            &max_seen_for_rx,
                                            block.header.height,
                                        );
                                        if completed_partial {
                                            tracing::warn!(
                                                "Completed a partial admission of gossiped block {} @ {}",
                                                hex::encode(&block.header.block_hash.as_bytes()[..8]),
                                                block.header.height
                                            );
                                        }
                                    }
                                    admission::AdmitOutcome::AlreadyAdmitted => {}
                                    admission::AdmitOutcome::Deferred { missing_parent } => {
                                        // A block we can't admit because its parent is
                                        // missing is still PROOF the network is at least
                                        // at block.height. Rejecting it is correct, but
                                        // dropping that height signal is what stalled a
                                        // far-behind follower — record it so the sync tick
                                        // pulls the gap forward instead of parking.
                                        sync_peer::record_unverified_height(
                                            &max_seen_for_rx,
                                            block.header.height,
                                            storage_for_handler
                                                .blocks
                                                .get_applied_tip()
                                                .ok()
                                                .flatten()
                                                .map(|(_, h)| h)
                                                .unwrap_or(0),
                                        );
                                        tracing::debug!(
                                            "Deferred gossiped block {} @ {} from {}: missing parent {}",
                                            hex::encode(&block.header.block_hash.as_bytes()[..8]),
                                            block.header.height,
                                            pid,
                                            hex::encode(&missing_parent.as_bytes()[..8])
                                        );
                                        // SYNC-S3 — ANCESTRY RECOVERY (the 2026-07-27 silent
                                        // partition). Recording the height signal is NOT enough.
                                        // The 2s sync tick only pulls when `applied_height <
                                        // target`, and it anchors every request at OUR OWN
                                        // applied tip — which a peer on a different branch does
                                        // not have, so it resolves the anchor to nothing and
                                        // replies "Sending 0 blocks". Live reproduction: two
                                        // producers, one dropped gossip message (B's first block,
                                        // broadcast before its peer link was up), and from then on
                                        // EVERY later block deferred on the previous undelivered
                                        // one. A issued 236 GetBlocks; B answered "Sending 0
                                        // blocks" 76/76 times, and vice versa. Both nodes stayed
                                        // "healthy" — no errors, no root mismatches — while
                                        // building permanently divergent chains.
                                        //
                                        // Fix: ask THIS peer for the missing parent directly. That
                                        // anchor is one the peer provably holds (it just sent us
                                        // its child), so the request is answerable, and
                                        // `serve_blocks` returns the anchor's whole height-group
                                        // plus everything above it — the ancestry we lack. Self-
                                        // heals at depth 1, before a deep fork can form.
                                        // `request_blocks` de-duplicates on the anchor while a
                                        // request is in flight and honours the concurrency cap, so
                                        // a run of deferrals cannot storm a peer.
                                        //
                                        // #150 — BOUNDED BY DISTANCE. This recovers a fork we
                                        // NARROWLY missed. It is not a catch-up mechanism, and
                                        // firing it while far behind actively prevents catch-up:
                                        // when the gap is large, EVERY gossiped tip block is
                                        // "missing its parent", so every one queued a request for a
                                        // parent that is itself tens of thousands of blocks deep.
                                        // Measured on boot1 at a 33k gap: 125 of 159 batches (79%)
                                        // landed at the network tip and could never be applied,
                                        // while those requests consumed the in-flight budget the
                                        // ONE useful forward request needs.
                                        //
                                        // The window is derived, not picked: `block_batch_size` (32)
                                        // x `max_concurrent_downloads` (16) is the most a node with
                                        // a full in-flight window can legitimately be behind. Past
                                        // that, the "missing parent" is not a fork, it is the gap —
                                        // and the 2s forward driver already owns the gap.
                                        let applied_now = storage_for_handler
                                            .blocks
                                            .get_applied_tip()
                                            .ok()
                                            .flatten()
                                            .map(|(_, h)| h)
                                            .unwrap_or(0);
                                        let within_reach =
                                            sync_peer::should_attempt_ancestry_recovery(
                                                block.header.height,
                                                applied_now,
                                            );
                                        if !within_reach {
                                            tracing::debug!(
                                                "SYNC-S3: skipping ancestry recovery for block @ {} \
                                                 — {} blocks above our applied tip {}; the forward \
                                                 sync driver owns this gap",
                                                block.header.height,
                                                block.header.height.saturating_sub(applied_now),
                                                applied_now
                                            );
                                        } else if let Some(peer) = pm_for_rx.get_peer(&pid) {
                                            if let Err(e) = sync_for_rx
                                                .request_blocks(
                                                    &peer,
                                                    missing_parent,
                                                    // The selected parent sits exactly one
                                                    // height below the block that deferred.
                                                    block.header.height.saturating_sub(1),
                                                )
                                                .await
                                            {
                                                tracing::debug!(
                                                    "SYNC-S3: ancestry request to {} for {} failed: {}",
                                                    pid,
                                                    hex::encode(&missing_parent.as_bytes()[..8]),
                                                    e
                                                );
                                            }
                                        }
                                    }
                                    admission::AdmitOutcome::Rejected(why) => {
                                        tracing::warn!(
                                            "Rejected inconsistent block {} from {}: {}",
                                            hex::encode(&block.header.block_hash.as_bytes()[..8]),
                                            pid,
                                            why
                                        );
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
                        // #153: the peer's standing is credited AFTER admission, on
                        // what it actually delivered — see the record_useful /
                        // record_useless call below. This used to be an
                        // unconditional `record_success(&pid.0)` right here, before
                        // a single block had been examined, so answering at all was
                        // enough to clear the penalty and stay the preferred source.
                        // WP-H.4: handle_blocks now validates each block
                        let _ = sync_for_rx.handle_blocks(&pid, blocks).await;
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
                        // CHAIN-B-A005: only re-scan the orphan buffer when this
                        // batch actually delivered something new. An empty (or
                        // duplicate-only) `Blocks` message used to trigger a full
                        // O(buffer) pass — append + fixpoint loop, each entry a
                        // chain has_block + DAG has_block + validate — on the
                        // single inbound task, at up to 200 msg/s. When the fresh
                        // drain is empty, nothing can have become admissible, so
                        // leave the buffer untouched and skip the scan (the
                        // peer-credit logic below still runs with newly_admitted=0).
                        let reprocessed_orphans = !pending.is_empty();
                        if reprocessed_orphans {
                            pending.append(&mut orphan_blocks);
                            // CHAIN-B-A005: de-duplicate by HASH (interleaving-
                            // proof) and bound by BOTH count and serialized bytes.
                            // The old `sort_by_key(height)+dedup_by_key(hash)` only
                            // collapsed adjacent equal hashes and bounded by count
                            // alone (20_000 × ~1 MiB ≈ 20 GB).
                            pending = admission::bound_orphan_buffer(pending);
                        }

                        // Fixpoint: a block that fails admission ONLY because its
                        // parent isn't applied yet is DEFERRED (buffered), never
                        // dropped. The pre-fix code dropped it, so a re-requested
                        // child was re-dropped forever whenever its parent rode a
                        // separate not-yet-arrived batch — the live cold-sync wedge.
                        // #153: how much of this response was genuinely NEW. A
                        // response that admits nothing is not service, however
                        // well-formed it was — see the credit call after the loop.
                        let mut newly_admitted: usize = 0;
                        let mut highest_admitted: u64 = 0;
                        loop {
                            let mut progressed = false;
                            let mut deferred: Vec<citrate_consensus::types::Block> = Vec::new();
                            for block in std::mem::take(&mut pending) {
                                // SYNC-S1 / D2: one call, idempotent and
                                // crash-safe. The pre-D2 body open-coded
                                // store_block -> add_block -> put_block and
                                // began with `if has_block(chain) { continue }`
                                // — a chain-store-only check that skipped a
                                // block whose DAG half was already written,
                                // and whose `Err(BlockExists) => {}` arm then
                                // dropped the block without ever reaching
                                // put_block. An OOM kill between those two
                                // writes therefore froze the applied tip
                                // permanently (boot-3 @ 10944). Presence is
                                // now established per-store inside `admit`.
                                match admission_for_net.admit(&block).await {
                                    admission::AdmitOutcome::Admitted { completed_partial } => {
                                        progressed = true;
                                        // #153: this block was NEW. Only this arm
                                        // counts — `AlreadyAdmitted` is a block we
                                        // already had, which is exactly what a peer
                                        // at our own height serves back forever.
                                        newly_admitted += 1;
                                        if block.header.height > highest_admitted {
                                            highest_admitted = block.header.height;
                                        }
                                        if completed_partial {
                                            tracing::warn!(
                                                "Completed a partial admission of synced block {} @ {}",
                                                hex::encode(&block.header.block_hash.as_bytes()[..8]),
                                                block.header.height
                                            );
                                        }
                                    }
                                    // Fully present already: no progress, but
                                    // not an orphan either — drop it from the
                                    // fixpoint set.
                                    admission::AdmitOutcome::AlreadyAdmitted => {}
                                    // Parent not admitted yet — DEFER, never
                                    // drop. A parent riding a later batch can
                                    // still unblock this child.
                                    admission::AdmitOutcome::Deferred { missing_parent } => {
                                        tracing::debug!(
                                            "Deferred synced block {} @ {}: missing parent {}",
                                            hex::encode(&block.header.block_hash.as_bytes()[..8]),
                                            block.header.height,
                                            hex::encode(&missing_parent.as_bytes()[..8])
                                        );
                                        deferred.push(block);
                                    }
                                    admission::AdmitOutcome::Rejected(why) => {
                                        tracing::warn!(
                                            "Rejected inconsistent synced block {} @ {}: {}",
                                            hex::encode(&block.header.block_hash.as_bytes()[..8]),
                                            block.header.height,
                                            why
                                        );
                                    }
                                }
                            }
                            pending = deferred;
                            if !progressed {
                                break;
                            }
                        }
                        // Buffer unresolved orphans for the next Blocks batch (their
                        // parents are still en route). CHAIN-B-A005: bound the
                        // buffer by BOTH count and serialized bytes, de-duplicated
                        // by hash, so a parent that never arrives can't grow it.
                        // Only touch the buffer when we actually reprocessed it;
                        // otherwise the fresh drain was empty and `orphan_blocks`
                        // already holds the (bounded) buffer unchanged.
                        if reprocessed_orphans {
                            orphan_blocks =
                                admission::bound_orphan_buffer(std::mem::take(&mut pending));
                        }

                        // #153 — CREDIT THE PEER ON WHAT IT ACTUALLY DELIVERED.
                        //
                        // Live on chain 40204: our node and boot3 both sat at height
                        // 177,771. Gossip had inflated boot3's advertised head to the
                        // network tip (~213k), so it passed invariant I1 and — every
                        // peer being tied at the inflated head — won the peer-id
                        // tie-break, being the lowest of the four. It answered
                        // "Sending 1 blocks" thirty times in three minutes: our own
                        // anchor group, nothing new. Each of those replies called
                        // `record_success`, clearing its penalty and confirming it as
                        // our preferred source. We sent it 63 of 66 requests while
                        // rpc-1 (at the tip) and boot1/boot2 (17k ahead) went unasked,
                        // and throughput fell from 445 to 18 blocks/min — losing
                        // ground to a chain growing at 30.
                        //
                        // The distinction the loop above already computes, and used to
                        // throw away, is the whole fix: `Admitted` is service,
                        // `AlreadyAdmitted` is not.
                        // #155: ONE call, and it needs the GAP. The same block count
                        // means opposite things at different distances from the tip:
                        // one block when we are one behind is a complete answer, one
                        // block when we are 36,000 behind is a peer that cannot carry
                        // us. Judging it absolutely is what produced two successive
                        // dead bands; the gap is the yardstick.
                        {
                            let applied_now = storage_for_handler
                                .blocks
                                .get_applied_tip()
                                .ok()
                                .flatten()
                                .map(|(_, h)| h)
                                .unwrap_or(0);
                            let target = max_seen_for_rx.load(std::sync::atomic::Ordering::Relaxed);
                            let gap = target.saturating_sub(applied_now);
                            // #156: did our own applied tip pass the anchor we
                            // asked from before this answer came back? If so the
                            // duplicate is ours, not the peer's. Measured live:
                            // rpc-1 serving a full 32/32 at 0.66s was scored
                            // Barren 191 times and driven to the -8 floor for
                            // answering exactly what we asked.
                            let stale_anchor = sync_for_rx.last_block_anchor_height() < applied_now;
                            let mut sel = sync_peers_for_rx.lock().await;
                            let quality = sel.record_serve(
                                &pid.0,
                                newly_admitted,
                                highest_admitted,
                                gap,
                                32, // SyncConfig::block_batch_size
                                stale_anchor,
                            );
                            // #155: INFO, not debug. This is the only external
                            // evidence of how the selector is scoring peers, and
                            // having it at `debug!` meant it never appeared under
                            // the `RUST_LOG=info` every node actually runs — a
                            // score-based model whose scores were unobservable.
                            //
                            // Rate is bounded by construction: only non-Material
                            // responses log, so a healthy converged node is silent
                            // and a misbehaving one is loud. That is the ratio we
                            // want in production, not the reverse.
                            if quality != sync_peer::ServeQuality::Material {
                                // #156: anchor and applied tip printed WITH the
                                // verdict. A duplicate whose anchor equals our
                                // applied tip is a different defect from one
                                // whose anchor is behind it — the first means
                                // the server resolved our anchor to nothing
                                // above it, the second means we asked a stale
                                // question. Both look identical without these
                                // two numbers, which is why six runs could not
                                // separate them.
                                tracing::info!(
                                    "SYNCSCORE peer={} {:?} new={} anchor={} applied={} gap={} score={}",
                                    &pid.0[..14.min(pid.0.len())],
                                    quality,
                                    newly_admitted,
                                    sync_for_rx.last_block_anchor_height(),
                                    applied_now,
                                    gap,
                                    sel.score(&pid.0)
                                );
                            }
                        }
                    }
                    NetworkMessage::Transactions { transactions } => {
                        // PBA-L1b-007: this node never sends GetTransactions, so
                        // every batch is unsolicited. It used to go straight into
                        // the mempool, skipping the gossip pre-filter. Same
                        // checks as NewTransaction now (basic validity + content
                        // authentication, peer penalized on failure), bounded.
                        const MAX_UNSOLICITED_TXS_PER_BATCH: usize = 256;
                        for tx in transactions.into_iter().take(MAX_UNSOLICITED_TXS_PER_BATCH) {
                            if let Ok(tx) = gossip_for_rx.prevalidate_transaction(tx, &pid).await {
                                let _ = mempool_for_handler
                                    .add_transaction(tx, TxClass::Standard)
                                    .await;
                            }
                        }
                    }
                    // PBA-L1b-005: an unpaid peer inference must never run on
                    // this loop (it stalled every other message; the stall
                    // detector then exits the node). Bounded worker, or drop.
                    NetworkMessage::InferenceRequest { .. } => {
                        let _ = inference_dispatcher.dispatch(pid.clone(), msg.clone());
                    }
                    // AI network messages: route through AINetworkHandler
                    NetworkMessage::ModelAnnounce { .. }
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
                                    pid.0,
                                    e
                                );
                            }
                        }
                    }
                    // WP-W.1: Handle checkpoint vote messages for BFT finality
                    NetworkMessage::CheckpointVote {
                        height,
                        block_hash,
                        voter_pubkey,
                        signature,
                    } => {
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
                                tracing::info!(
                                    "Checkpoint quorum reached at height {}, finalizing",
                                    height
                                );
                                match checkpoint_mgr_for_net.finalize_checkpoint(height).await {
                                    Ok(cp) => tracing::info!(
                                        "Checkpoint finalized at height {} with {} votes",
                                        cp.height,
                                        cp.votes.len()
                                    ),
                                    Err(e) => tracing::warn!(
                                        "Failed to finalize checkpoint at height {}: {}",
                                        height,
                                        e
                                    ),
                                }
                            }
                            Ok(false) => {
                                tracing::debug!("Checkpoint vote accepted for height {}", height)
                            }
                            Err(e) => tracing::warn!(
                                "Checkpoint vote rejected from peer {}: {}",
                                pid.0,
                                e
                            ),
                        }
                    }
                    _ => {
                        tracing::debug!("Unhandled message variant from peer {}", pid.0);
                    }
                }
            }
        });

        // WATCHDOG — the P2P message loop is not allowed to die quietly (#146).
        //
        // The task above is the node's ENTIRE inbound network surface: it serves
        // GetBlocks/GetHeaders, admits synced blocks, ingests gossip, and drives
        // the applied tip. Nothing else does any of that. When it stopped, the
        // process kept running and looked healthy from every angle an operator
        // checks — systemd `active (running)`, `NRestarts=0`, peers connected,
        // JSON-RPC answering, the producer still minting blocks, `eth_syncing`
        // reporting a correct gap — while the node had in fact become a black
        // hole that answered no peer and could never sync again.
        //
        // That is exactly what happened to chain 40204: an unguarded subtraction
        // in a sync PROGRESS PERCENTAGE (core/network/src/sync.rs, fixed in this
        // change) panicked this task on the sequencer at 04:31:20 on 2026-07-30,
        // immediately after it produced height 90,467. It was never noticed. The
        // sequencer went on producing ~39,000 more blocks that no node on the
        // network could fetch, three of the four fleet nodes ended up in the same
        // state, and every fresh node — desktop, fleet, explorer — stalled a few
        // hundred blocks past 90,467 with an inbound-only log. Thirty hours of
        // silent, total sync failure from one panic in a log-line calculation.
        //
        // A tokio task panic is caught by the runtime and surfaces only through
        // its JoinHandle, which nobody was holding. Hold it: if this task ever
        // ends — panic or clean return — say so at ERROR and exit non-zero so the
        // supervisor restarts a node that can actually serve. A loud restart loop
        // is a diagnosable failure; a silent zombie is not.
        tokio::spawn(async move {
            let reason = match net_rx_task.await {
                Err(e) if e.is_panic() => format!("PANICKED ({})", e),
                Err(e) => format!("was cancelled ({})", e),
                // The loop only returns when `in_rx` closes. The single sender
                // lives in `PeerManager.incoming` (set once above, held for the
                // process lifetime), so this cannot fire on peer churn — losing
                // every peer leaves the channel open and the loop parked. It
                // means the peer manager itself is gone: no P2P either way.
                Ok(()) => "exited (inbound channel closed)".to_string(),
            };
            tracing::error!(
                "FATAL: the P2P message handler {} — this node can no longer serve \
                 peers, admit synced blocks, or advance its applied tip. Exiting so \
                 the supervisor restarts it rather than running on as a node that \
                 looks healthy and syncs nothing.",
                reason
            );
            // Flush before the exit: this line is the only evidence an operator
            // will have, and the wedge it reports is invisible from outside.
            std::process::exit(1);
        });

        // STALL DETECTOR — the watchdog above catches a message loop that ENDS.
        // #149 was a loop that never ended and never ran again, which that
        // watchdog is structurally blind to: no panic, no task exit, nothing to
        // await. The fleet sat in that state for hours looking perfectly healthy.
        //
        // The discriminator is "traffic is arriving but nothing is being taken off
        // the channel". An idle node advances neither counter and must not be
        // killed, so idleness alone proves nothing — the signal has to be inbound
        // pressure with zero progress. `inbound_drops` only rises when the channel
        // is FULL, which means the loop is provably behind, so the pair
        // (drops rising, processed frozen) is unambiguous.
        tokio::spawn(async move {
            const CHECK_EVERY: std::time::Duration = std::time::Duration::from_secs(30);
            // Two consecutive stalled samples before acting: one sample can
            // straddle a legitimately long handler (a big batch admit), and
            // killing a node mid-catch-up would be its own outage.
            const STALLED_SAMPLES_BEFORE_FATAL: u32 = 2;
            let mut last_processed = 0u64;
            let mut last_drops = 0u64;
            let mut stalled_samples = 0u32;
            let mut interval = tokio::time::interval(CHECK_EVERY);
            loop {
                interval.tick().await;
                let processed = msgs_processed.load(std::sync::atomic::Ordering::Relaxed);
                let drops = pm_for_stall.inbound_drops();
                let shed_this_window = drops.saturating_sub(last_drops);
                let starved = shed_this_window > 0 && processed == last_processed;
                last_processed = processed;
                last_drops = drops;
                if !starved {
                    stalled_samples = 0;
                    continue;
                }
                stalled_samples += 1;
                tracing::warn!(
                    "P2P message loop appears stalled: {} inbound messages shed since the last \
                     check while the loop processed none (sample {}/{})",
                    shed_this_window,
                    stalled_samples,
                    STALLED_SAMPLES_BEFORE_FATAL
                );
                if stalled_samples >= STALLED_SAMPLES_BEFORE_FATAL {
                    tracing::error!(
                        "FATAL: the P2P message handler is STALLED — inbound messages are arriving \
                         and being dropped while the loop has processed none for {:?}. This node \
                         cannot serve peers or advance its applied tip. Exiting so the supervisor \
                         restarts it rather than running on as a node that looks healthy and \
                         syncs nothing.",
                        CHECK_EVERY * STALLED_SAMPLES_BEFORE_FATAL
                    );
                    std::process::exit(1);
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
    let validator_address =
        citrate_execution::types::Address(coinbase[0..20].try_into().unwrap_or([0; 20]));
    let _ =
        economics_manager_temp.register_stakeholder(validator_address, StakeholderType::Validator);

    let economics_manager = Arc::new(economics_manager_temp);

    // WP-I.3: Create pause_flag shared between RPC server and block producer.
    // When citrate_emergencyPause is called via RPC, the producer sees the
    // flag and stops producing blocks.
    let pause_flag = Arc::new(AtomicBool::new(false));

    // Start RPC server if enabled
    let rpc_handle = if config.rpc.enabled {
        info!("Starting RPC server on {}", config.rpc.listen_addr);

        // WP-I.2: Read operator token from env for privileged RPC gating
        let operator_token = std::env::var("CITRATE_OPERATOR_TOKEN")
            .ok()
            .filter(|t| !t.is_empty());

        // Sprint 03: API key gating — CLI flag > config file > env var
        let api_key = config.rpc.api_key.clone().or_else(|| {
            std::env::var("CITRATE_API_KEY")
                .ok()
                .filter(|k| !k.is_empty())
        });
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
            // CHAIN-B-D002: 4 sync workers were trivially saturated by ~4
            // concurrent slow eth_call requests (documented PIL-49 outage);
            // the RpcConfig::default() is 16. Match it so a handful of slow
            // calls cannot silence the accept queue. The per-call gas cap +
            // wall-clock timeout in eth_rpc bound each call's cost as well.
            threads: 16,
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
            // forward-sync liveness: let eth_syncing report highestBlock from the
            // sync driver's max-seen height (truthful "stalled" vs "synced").
            Some(max_seen_height.clone()),
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
            info!(
                "Starting Ethereum subscription WebSocket server on {}",
                ws_addr
            );
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
        && hex::decode(coinbase_str)
            .map(|b| b.iter().any(|&x| x != 0))
            .unwrap_or(false);

    // WP-11 (corrected): mint/load the proposer key whenever this node has a
    // coinbase, REGARDLESS of whether mining is currently enabled.
    //
    // The first cut of WP-11 did this inside the `mining.enabled` branch below,
    // which is wrong: `proposer.key` is the node's CONSENSUS IDENTITY, not a
    // mining artifact. A node cannot be REGISTERED as a validator without one,
    // and the reroll ceremony reads this file off every node before registering.
    // With it gated on mining, the three non-mining boot nodes never minted a key
    // and P2 could not register them — caught by the ceremony's own gate:
    //   `scp: /home/citrate/.citrate/proposer.key: No such file or directory`
    //
    // Minting it unconditionally also means a node can be registered now and
    // start producing later (flip `mining.enabled`, restart) WITHOUT
    // re-registering — its identity is stable across that change. Since pubkeys
    // are permanently single-use on-chain (`pubkeyEverRegistered`), an identity
    // that changed when mining was toggled would burn a registration every time.
    let proposer_signing_key = if coinbase_is_valid {
        let proposer_key_path = config.storage.data_dir.join("proposer.key");
        Some(load_or_generate_proposer_key(&proposer_key_path)?)
    } else {
        None
    };

    if config.mining.enabled && coinbase_is_valid {
        info!("Starting block producer...");

        // Parse coinbase address
        let coinbase_bytes = hex::decode(coinbase_str).unwrap_or_else(|_| vec![0; 20]);
        let mut coinbase = [0u8; 32];
        let copy_len = coinbase_bytes.len().min(32);
        coinbase[..copy_len].copy_from_slice(&coinbase_bytes[..copy_len]);

        // WP-11: the block-signing key is a PERSISTED SECRET, not a derivation.
        //
        // It used to be `Sha3_256(domain ‖ coinbase)`. The coinbase is public
        // (recoverable on-chain via `validatorInfo(pubkey).staker`, which
        // consensus forces to equal it), so that made every validator's signing
        // PRIVATE key computable by anyone — and `submitEquivocation` is
        // permissionless, so anyone could forge a double-sign and Byzantine-slash
        // any validator for 100% of its stake. See
        // `citrate_consensus::crypto::generate_block_signing_key`.
        //
        // The registered pubkey now comes FROM this file rather than from the
        // coinbase, so the ceremony reads the same file (`--node
        // <coinbase>=<STAKER_ENV>=<proposer_key_file>`) instead of re-deriving.
        // Minted above, unconditionally on a valid coinbase. Safe to expect:
        // this branch requires `coinbase_is_valid`, which is the same condition.
        let signing_key = proposer_signing_key
            .clone()
            .ok_or_else(|| anyhow::anyhow!("proposer key missing despite a valid coinbase"))?;
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
        )
        .await;

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
            info!(
                "EXECUTE-ON-RECEIVE: sealing version-2 headers (coinbase committed in block hash)"
            );
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
fn load_or_create_peer_id(
    data_dir: &std::path::Path,
) -> anyhow::Result<citrate_network::peer::PeerId> {
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
                std::fs::set_permissions(noise_key_path, std::fs::Permissions::from_mode(0o600))
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
        info!(
            "Generated new persistent Noise identity at {:?}",
            noise_key_path
        );
        Ok(kp)
    }
}

/// WP-11: load this node's persistent ed25519 block-signing (proposer) key from
/// `proposer_key_path`, or mint and persist a new one.
///
/// Deliberately mirrors [`load_or_generate_noise_keypair`] — 0600 on create,
/// loose permissions tightened with a warning on load, seed bytes held in
/// `Zeroizing` — because this key is now a REAL secret. It used to be derived
/// from the public coinbase, which meant anyone could reconstruct it and
/// Byzantine-slash the validator via the permissionless `submitEquivocation`.
/// The entire point of this function is that the key can no longer be recomputed
/// from public data, so it must be generated once and kept.
///
/// PRESERVE ACROSS WIPES: like `noise.key`, this file IS the node's registered
/// consensus identity. Deleting it mints a new pubkey that is not in the active
/// set, and the node silently stops being able to propose until it re-registers.
fn load_or_generate_proposer_key(
    proposer_key_path: &std::path::Path,
) -> anyhow::Result<citrate_consensus::crypto::Ed25519SigningKey> {
    use zeroize::{Zeroize as _, Zeroizing};

    if proposer_key_path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(proposer_key_path)
                .map_err(|e| anyhow::anyhow!("Failed to stat proposer key: {}", e))?;
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                warn!(
                    "Proposer key file {:?} had permissions {:o}; tightening to 0600 (WP-11)",
                    proposer_key_path, mode
                );
                std::fs::set_permissions(proposer_key_path, std::fs::Permissions::from_mode(0o600))
                    .map_err(|e| anyhow::anyhow!("Failed to chmod proposer key to 0600: {}", e))?;
            }
        }
        let seed_bytes = Zeroizing::new(
            std::fs::read(proposer_key_path)
                .map_err(|e| anyhow::anyhow!("Failed to read proposer key: {}", e))?,
        );
        if seed_bytes.len() != 32 {
            // Fail closed: a wrong-length file means we do not know what identity
            // this node has. Signing blocks with a key of unknown provenance is
            // worse than refusing to start.
            return Err(anyhow::anyhow!(
                "Proposer key {:?} is {} bytes, expected a 32-byte ed25519 seed",
                proposer_key_path,
                seed_bytes.len()
            ));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);
        let key = citrate_consensus::crypto::block_signing_key_from_seed(&seed);
        seed.zeroize();
        info!(
            "Loaded persistent proposer identity from {:?} (pubkey {})",
            proposer_key_path,
            hex::encode(key.verifying_key().to_bytes())
        );
        Ok(key)
    } else {
        let key = citrate_consensus::crypto::generate_block_signing_key();
        let seed_bytes = Zeroizing::new(key.to_bytes().to_vec());
        write_secret_file_0600(proposer_key_path, &seed_bytes)?;
        info!(
            "Minted a new persistent proposer identity at {:?} (pubkey {}). This key is NOT \
             recoverable from public data — back it up alongside noise.key and preserve it \
             across data-dir wipes, or the node must re-register before it can propose again.",
            proposer_key_path,
            hex::encode(key.verifying_key().to_bytes())
        );
        Ok(key)
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
        assert_eq!(
            mode_of(&key_path),
            0o600,
            "loose permissions must be tightened"
        );
        assert_eq!(kp.derive_peer_id(), reloaded.derive_peer_id());
    }
}
