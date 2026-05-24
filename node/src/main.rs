use anyhow::Result;
use clap::{Parser, Subcommand};
use citrate_api::{RpcConfig, RpcServer};
use citrate_consensus::crypto;
use citrate_execution::{Executor, StateDB};
use citrate_economics::{UnifiedEconomicsManager, UnifiedEconomicsConfig, StakeholderType};
use citrate_network::peer::PeerId;
use citrate_network::peer::{PeerManager, PeerManagerConfig};
use citrate_network::{NetworkTransport, GossipProtocol, GossipConfig, Discovery, DiscoveryConfig, SyncManager, SyncConfig};
use citrate_sequencer::mempool::{Mempool, MempoolConfig};
use citrate_storage::{pruning::PruningConfig, StorageManager};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

mod adapters;
mod artifact;
pub mod bundled_model;
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
mod contribution_recorder;
mod sync;

use config::NodeConfig;
use citrate_consensus::dag_store::DagStore;
use citrate_consensus::ghostdag::GhostDag;
use citrate_consensus::types::GhostDagParams;
use genesis::{initialize_genesis_state, initialize_genesis_state_with_profile, GenesisConfig};
use producer::BlockProducer;

#[derive(Parser)]
#[command(name = "citrate")]
#[command(about = "Citrate blockchain node")]
struct Cli {
    /// Configuration file path
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

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
        tracing::warn!(
            "No --config, $CITRATE_CONFIG, ~/.citrate/node.toml, or /etc/citrate/node.toml \
             found — running with empty defaults (no bootnodes, dev/devnet only)."
        );
        NodeConfig::default()
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

    let probe_storage = Arc::new(StorageManager::new(
        &config.storage.data_dir,
        PruningConfig::default(),
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

    // Record node start time for uptime tracking
    let _node_start_time = std::time::Instant::now();

    // Create storage
    let storage = Arc::new(StorageManager::new(
        &config.storage.data_dir,
        PruningConfig {
            keep_blocks: config.storage.keep_blocks,
            keep_states: config.storage.keep_blocks,
            interval: Duration::from_secs(3600),
            batch_size: 1000,
            auto_prune: config.storage.pruning,
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
                            warn!("State root MISMATCH at height {}: memory={} persisted={}",
                                latest_height,
                                hex::encode(memory_root.as_bytes()),
                                hex::encode(root.as_bytes()));
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
    let shared_dag_store = {
        let kv = Arc::new(persistent_dag::RocksDbKvStore::new(storage.db.clone()));
        match DagStore::persistent_with_strict_vrf(kv, strict_vrf) {
            Ok(store) => {
                info!("DAG store created with strict_vrf={}", strict_vrf);
                Arc::new(store)
            }
            Err(e) => {
                warn!("Failed to load persistent DAG, starting fresh: {}", e);
                Arc::new(DagStore::new())
            }
        }
    };
    let shared_ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), shared_dag_store.clone()));

    // WP-W.1: Create CheckpointManager for BFT finality vote handling
    let checkpoint_manager = {
        use citrate_consensus::checkpoint::{CheckpointConfig, CheckpointManager};
        let cp_config = CheckpointConfig::default();
        let kv = Arc::new(persistent_dag::RocksDbKvStore::new(storage.db.clone()));
        Arc::new(CheckpointManager::with_persistence(cp_config, shared_dag_store.clone(), kv))
    };

    // Start P2P listener and connect to bootstrap nodes
    {
        // Prepare head info
        let head_height = storage.blocks.get_latest_height().unwrap_or(0);
        let head_hash = if head_height > 0 {
            storage
                .blocks
                .get_block_by_height(head_height)
                .ok()
                .flatten()
                .unwrap_or_default()
        } else {
            citrate_consensus::types::Hash::default()
        };
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
        let noise_keypair = if noise_key_path.exists() {
            let key_bytes = std::fs::read(&noise_key_path)
                .map_err(|e| anyhow::anyhow!("Failed to read noise key: {}", e))?;
            citrate_network::NoiseKeypair::from_bytes(&key_bytes)
                .map_err(|e| anyhow::anyhow!("Failed to parse noise key: {}", e))?
        } else {
            let kp = citrate_network::NoiseKeypair::generate();
            std::fs::write(&noise_key_path, kp.to_bytes())
                .map_err(|e| anyhow::anyhow!("Failed to write noise key: {}", e))?;
            info!("Generated new persistent Noise identity at {:?}", noise_key_path);
            kp
        };
        let local_peer_id = noise_keypair.derive_peer_id();
        info!(
            "Noise identity: {}... (peer_id={})",
            &noise_keypair.public_key_hex()[..16],
            local_peer_id
        );
        let transport = NetworkTransport::new(
            peer_manager.clone(),
            local_peer_id,
            citrate_network::transport::HandshakeParams {
                network_id,
                genesis_hash,
                head_height,
                head_hash,
            },
        )
        .with_noise(noise_keypair)
        .with_allowed_peers(config.network.allowed_peers.clone());
        let listen_addr = config.network.listen_addr;
        transport
            .start_listener(listen_addr)
            .await
            .map_err(|e| anyhow::anyhow!(format!("Failed to start P2P listener: {}", e)))?;

        // Dial configured bootstrap nodes (ip:port or noise_<hex>@ip:port)
        // WP-H.2: When a bootnode declares its Noise identity, use connect_to_trusted
        // to verify the remote's Noise key matches the declared trust root.
        for s in &config.network.bootstrap_nodes {
            if let Some((pid, addr)) = parse_bootnode(s) {
                if pid.0.starts_with("noise_") {
                    info!("Connecting to trusted bootnode {} (identity={})", addr, pid);
                    let _ = transport.connect_to_trusted(addr, pid).await;
                } else {
                    warn!("Bootnode {} has no Noise identity — cannot verify trust root", addr);
                    let _ = transport.connect_to(addr).await;
                }
                continue;
            }
            // Try numeric IP:port
            if let Ok(addr) = s.parse() {
                let _ = transport.connect_to(addr).await;
                continue;
            }
            // Resolve hostname:port
            if let Ok(mut addrs) = tokio::net::lookup_host(s).await {
                if let Some(addr) = addrs.next() {
                    let _ = transport.connect_to(addr).await;
                }
            } else {
                tracing::warn!("Could not resolve bootstrap node: {}", s);
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
                for p in peers {
                    let info = p.info.read().await;
                    if info.state == citrate_network::peer::PeerState::Connected
                        && info.head_height > best_h
                        && peer_failures.get(&info.id.0).cloned().unwrap_or(0) < 3
                    {
                        best_h = info.head_height;
                        best = Some(p.clone());
                    }
                }
                if let Some(peer) = best {
                    // Determine current local head hash
                    let start_from = if let Some(h) = sync_for_loop.last_requested_header().await {
                        h
                    } else if let Some(h) = sync_for_loop.last_received_header().await {
                        h
                    } else {
                        let local_h = storage_for_sync.blocks.get_latest_height().unwrap_or(0);
                        if local_h > 0 {
                            storage_for_sync
                                .blocks
                                .get_block_by_height(local_h)
                                .ok()
                                .flatten()
                                .unwrap_or_else(|| citrate_consensus::types::Hash::new([0u8; 32]))
                        } else {
                            citrate_consensus::types::Hash::new([0u8; 32])
                        }
                    };
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
                    // Remove peer if too many failures
                    if *pf >= 5 {
                        if let Some(p) = pm_for_sync.get_peer(&pid) {
                            let addr = p.info.read().await.addr;
                            pm_for_sync.remove_peer(&pid).await;
                            pm_for_sync.ban_peer(addr).await;
                            tracing::warn!("Banned peer {} due to repeated sync timeouts", pid.0);
                        }
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
            use citrate_consensus::types::Hash;
            use citrate_consensus::checkpoint::CheckpointVote;
            use citrate_network::NetworkMessage;
            use citrate_sequencer::mempool::TxClass;
            while let Some((pid, msg)) = in_rx.recv().await {
                tracing::debug!("[P2P] from={} msg={:?}", pid.0, msg);
                // Handle protocol messages
                match msg {
                    NetworkMessage::Hello { head_height, head_hash, .. } => {
                        // Kick off naive sync: request blocks from genesis if behind
                        let local_h = storage_for_handler
                            .blocks
                            .get_latest_height()
                            .unwrap_or(0);
                        if head_height > local_h {
                            let _ = sync_for_rx.start_sync(head_height, head_hash).await;
                        }
                        // Also request headers
                        // Sync manager will request in periodic loop
                    }
                    NetworkMessage::HelloAck { head_height, head_hash, .. } => {
                        let local_h = storage_for_handler
                            .blocks
                            .get_latest_height()
                            .unwrap_or(0);
                        if head_height > local_h {
                            let _ = sync_for_rx.start_sync(head_height, head_hash).await;
                        }
                        // Requests are driven by periodic sync loop
                    }
                    NetworkMessage::GetBlocks { from, count, .. } => {
                        tracing::info!("Received GetBlocks request from peer {} for {} blocks starting from {:?}", 
                                     pid.0, count, from);
                        let mut blocks = Vec::new();

                        // Handle genesis request (zero hash)
                        if from == Hash::new([0u8; 32]) {
                            tracing::info!("Serving blocks from genesis");
                            let mut h = 0u64;
                            let end_h = count as u64;
                            while h < end_h && blocks.len() < count as usize {
                                if let Ok(Some(hash)) =
                                    storage_for_handler.blocks.get_block_by_height(h)
                                {
                                    if let Ok(Some(block)) =
                                        storage_for_handler.blocks.get_block(&hash)
                                    {
                                        blocks.push(block);
                                    }
                                }
                                h += 1;
                            }
                        } else {
                            // Get blocks after the specified hash
                            if let Ok(Some(start_block)) =
                                storage_for_handler.blocks.get_block(&from)
                            {
                                let start_h = start_block.header.height + 1;
                                let end_h = start_h.saturating_add(count as u64);
                                let mut h = start_h;
                                while h < end_h && blocks.len() < count as usize {
                                    if let Ok(Some(hash)) =
                                        storage_for_handler.blocks.get_block_by_height(h)
                                    {
                                        if let Ok(Some(block)) =
                                            storage_for_handler.blocks.get_block(&hash)
                                        {
                                            blocks.push(block);
                                        }
                                    }
                                    h += 1;
                                }
                            }
                        }

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
                        let mut headers = Vec::new();
                        if from == Hash::new([0u8; 32]) {
                            let mut h = 0u64;
                            while headers.len() < count as usize {
                                if let Ok(Some(hash)) =
                                    storage_for_handler.blocks.get_block_by_height(h)
                                {
                                    if let Ok(Some(block)) =
                                        storage_for_handler.blocks.get_block(&hash)
                                    {
                                        headers.push(block.header);
                                    }
                                }
                                h += 1;
                            }
                        } else if let Ok(Some(start_block)) =
                            storage_for_handler.blocks.get_block(&from)
                        {
                            let mut h = start_block.header.height + 1;
                            while headers.len() < count as usize {
                                if let Ok(Some(hash)) =
                                    storage_for_handler.blocks.get_block_by_height(h)
                                {
                                    if let Ok(Some(block)) =
                                        storage_for_handler.blocks.get_block(&hash)
                                    {
                                        headers.push(block.header);
                                    }
                                }
                                h += 1;
                            }
                        }
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
                        // Add to mempool if not already present
                        if !mempool_for_handler.contains(&transaction.hash).await {
                            let _ = mempool_for_handler
                                .add_transaction(transaction.clone(), TxClass::Standard)
                                .await;
                        }
                        // Let gossip handle validation + propagation
                        let _ = gossip_for_rx
                            .handle_new_transaction(transaction, &pid)
                            .await;
                    }
                    NetworkMessage::NewBlock { block } => {
                        // C3 fix: validate BEFORE persisting to prevent
                        // invalid blocks from polluting local storage.
                        let have = storage_for_handler
                            .blocks
                            .has_block(&block.header.block_hash)
                            .unwrap_or(false);
                        if !have {
                            // Let gossip validate and propagate first
                            match gossip_for_rx.handle_new_block(block.clone(), &pid).await {
                                Ok(_) => {
                                    // Block passed validation — persist it
                                    let _ = storage_for_handler.blocks.put_block(&block);
                                    // WP-K.2: Feed validated block into live DAG for fork-choice
                                    match dag_store_for_net.store_block(block.clone()).await {
                                        Ok(_) => {
                                            let _ = ghostdag_for_net.add_block(&block).await;
                                            tracing::debug!(
                                                "Added network block {} to live DAG",
                                                hex::encode(&block.header.block_hash.as_bytes()[..8])
                                            );
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
                        let validated = sync_for_rx.drain_validated_blocks().await;
                        for block in validated {
                            let hash = block.header.block_hash;
                            let have = storage_for_handler
                                .blocks
                                .has_block(&hash)
                                .unwrap_or(false);
                            if !have {
                                if let Err(e) = storage_for_handler.blocks.put_block(&block) {
                                    tracing::warn!(
                                        "Failed to persist synced block {}: {}",
                                        hex::encode(&hash.as_bytes()[..8]),
                                        e
                                    );
                                } else {
                                    // WP-K.2: Feed synced block into live DAG for fork-choice
                                    match dag_store_for_net.store_block(block.clone()).await {
                                        Ok(_) => {
                                            let _ = ghostdag_for_net.add_block(&block).await;
                                        }
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
                }
                Err(e) => {
                    error!("Failed to start RPC server: {}", e);
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
        let signing_key = {
            use sha3::{Digest as _, Sha3_256};
            let mut hasher = Sha3_256::new();
            hasher.update(b"citrate-block-signing-key-v1");
            hasher.update(coinbase);
            let seed = hasher.finalize();
            let mut seed_bytes = [0u8; 32];
            seed_bytes.copy_from_slice(&seed);
            citrate_consensus::crypto::Ed25519SigningKey::from_bytes(&seed_bytes)
        };
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

/// Parse bootnode strings in formats like:
/// - peer123@203.0.113.10:30303
/// - 203.0.113.10:30303 (peer id will be generated)
fn parse_bootnode(s: &str) -> Option<(PeerId, std::net::SocketAddr)> {
    let (peer_part, addr_part) = if let Some((pid, rest)) = s.split_once('@') {
        (Some(pid.trim()), rest.trim())
    } else {
        (None, s.trim())
    };
    let addr: std::net::SocketAddr = addr_part.parse().ok()?;
    let peer_id = peer_part
        .map(|p| PeerId::new(p.to_string()))
        .unwrap_or_else(PeerId::random);
    Some((peer_id, addr))
}
