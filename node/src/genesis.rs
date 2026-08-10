use citrate_consensus::dag_store::DagStore;
use citrate_consensus::types::{Block, Hash, PublicKey};
use citrate_economics::genesis::{self as shared_genesis, GenesisConfig as EconomicsGenesisConfig};
use citrate_execution::executor::Executor;
use citrate_storage::StorageManager;
use std::sync::Arc;

/// Calculate block hash using SHA3-256
fn calculate_block_hash(block: &Block) -> Hash {
    shared_genesis::calculate_canonical_block_hash(block)
}

/// Genesis block configuration
pub struct GenesisConfig {
    #[allow(dead_code)]
    pub chain_id: u64,
    pub timestamp: u64,
    pub initial_accounts: Vec<(PublicKey, u128)>, // (address, balance)
}

/// Canonical genesis timestamp: 2026-01-01T00:00:00Z (UTC).
/// C2 fix: All nodes MUST use this same timestamp so the genesis block hash
/// is deterministic and identical across independent node startups.
pub const CANONICAL_GENESIS_TIMESTAMP: u64 = shared_genesis::CANONICAL_GENESIS_TIMESTAMP;

impl Default for GenesisConfig {
    /// SECREM-01 CONS-7: this default is the **testnet-beta / dev genesis**
    /// — it ships well-known dev accounts (the Forge default deployer, the
    /// deterministic faucet key) with large pre-funded balances so a local
    /// or testnet node boots usable. It MUST NOT be used as a mainnet
    /// genesis: a mainnet deployment supplies its own `GenesisConfig` with
    /// real allocations. The accounts below are public, deterministic
    /// testnet keys, not a production validator set, so there is no secret
    /// material here — but the pre-funded dev balances make the
    /// testnet-vs-mainnet distinction load-bearing. Documented rather than
    /// `#[cfg(test)]`-gated because the live testnet boots from exactly
    /// this config.
    fn default() -> Self {
        Self {
            chain_id: 40204,
            timestamp: CANONICAL_GENESIS_TIMESTAMP,
            initial_accounts: vec![
                // Dev account with initial balance (ed25519)
                (PublicKey::new([1; 32]), 1_000_000_000_000_000_000), // 1 ETH worth
                // Forge default deployer account (ECDSA - first 20 bytes are the address, rest zeros)
                // Address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
                (
                    PublicKey::new([
                        0xf3, 0x9f, 0xd6, 0xe5, 0x1a, 0xad, 0x88, 0xf6, 0xf4, 0xce, 0x6a, 0xb8,
                        0x82, 0x72, 0x79, 0xcf, 0xff, 0xb9, 0x22, 0x66, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    ]),
                    10_000_000_000_000_000_000_000,
                ), // 10000 ETH for testing
                // Recovered deployer from failed transaction
                // Address: 0xfcad0b19bb29d4674531d6f115237e16afce377c
                (
                    PublicKey::new([
                        0xfc, 0xad, 0x0b, 0x19, 0xbb, 0x29, 0xd4, 0x67, 0x45, 0x31, 0xd6, 0xf1,
                        0x15, 0x23, 0x7e, 0x16, 0xaf, 0xce, 0x37, 0x7c, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    ]),
                    10_000_000_000_000_000_000_000,
                ), // 10000 ETH for testing
                // Faucet signing key account (0x6680b43af09d9b351332bf5378eb580e3b390182)
                // Deterministic key from "citrate-faucet-testnet-v1". 10M SALT.
                (
                    PublicKey::new([
                        0x66, 0x80, 0xb4, 0x3a, 0xf0, 0x9d, 0x9b, 0x35, 0x13, 0x32, 0xbf, 0x53,
                        0x78, 0xeb, 0x58, 0x0e, 0x3b, 0x39, 0x01, 0x82, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    ]),
                    10_000_000_000_000_000_000_000_000,
                ), // 10M SALT for faucet
            ],
        }
    }
}

/// Create genesis block
pub fn create_genesis_block(config: &GenesisConfig) -> Block {
    shared_genesis::create_canonical_genesis_block(config.timestamp)
}

/// Initialize genesis state
pub async fn initialize_genesis_state(
    storage: Arc<StorageManager>,
    executor: Arc<Executor>,
    config: &GenesisConfig,
) -> anyhow::Result<Hash> {
    initialize_genesis_state_with_profile(storage, executor, config, None).await
}

/// Initialize genesis state with an explicit genesis profile selector.
///
/// The `genesis_profile` chooses which economics genesis configuration to use:
/// - `Some("team_testnet")` — team testnet with 10 pre-funded validators
/// - `Some("testnet_beta")` — public testnet beta
/// - `Some("mainnet")` — mainnet genesis
/// - `None` or `Some("default")` — infer from chain_id (backward compatible)
pub async fn initialize_genesis_state_with_profile(
    storage: Arc<StorageManager>,
    executor: Arc<Executor>,
    config: &GenesisConfig,
    genesis_profile: Option<&str>,
) -> anyhow::Result<Hash> {
    // Create genesis block
    let mut genesis = create_genesis_block(config);

    // Select economics genesis config based on explicit profile or chain_id fallback
    let economics_config = match genesis_profile {
        Some("default") => {
            tracing::info!("Using default devnet genesis profile");
            EconomicsGenesisConfig::default()
        }
        Some("team_testnet") => {
            tracing::info!("Using team_testnet genesis profile (10 pre-funded validators)");
            EconomicsGenesisConfig::team_testnet_genesis()
        }
        Some("testnet_beta") => {
            tracing::info!("Using testnet_beta genesis profile");
            EconomicsGenesisConfig::testnet_beta()
        }
        Some("mainnet") => {
            tracing::info!("Using mainnet genesis profile");
            EconomicsGenesisConfig::mainnet()
        }
        _ => {
            // Backward compatible: infer from chain_id
            if config.chain_id == 40204 {
                EconomicsGenesisConfig::testnet_beta()
            } else {
                EconomicsGenesisConfig::default()
            }
        }
    };

    // Use the SHARED genesis initialization function.
    // This is the single source of truth — both standalone node and GUI call
    // the same function to ensure identical state roots and genesis hashes.
    // Invariant: DeterministicGenesis (from GenesisSafetyAcrossNodes.tla)
    let state_root_bytes =
        citrate_economics::genesis::initialize_shared_genesis_state(&executor, &economics_config);

    // The shared genesis function initializes the configured account set.
    // Legacy initial_accounts are NOT applied because they would produce a
    // different state root than the GUI's shared genesis.
    // This satisfies the DeterministicGenesis invariant from GenesisSafetyAcrossNodes.tla.
    if !config.initial_accounts.is_empty() {
        tracing::info!(
            "Skipping {} legacy initial_accounts (shared genesis function handles all accounts)",
            config.initial_accounts.len()
        );
    }

    genesis.state_root = Hash::new(state_root_bytes);

    // Calculate block hash
    genesis.header.block_hash = calculate_block_hash(&genesis);

    // Store genesis block in persistent storage
    storage.blocks.put_block(&genesis)?;

    tracing::info!(
        "Genesis block created: {:?} at height 0",
        hex::encode(&genesis.header.block_hash.as_bytes()[..8])
    );

    Ok(genesis.header.block_hash)
}

/// Initialize genesis state with DAG tracking
///
/// This variant also stores the genesis block in the DAG store for consensus tracking.
/// The DagStore maintains the DAG structure for GhostDAG consensus.
#[allow(dead_code)]
pub async fn initialize_genesis_with_dag(
    storage: Arc<StorageManager>,
    executor: Arc<Executor>,
    dag_store: Arc<DagStore>,
    config: &GenesisConfig,
) -> anyhow::Result<Hash> {
    // Use the base initialization
    let genesis_hash = initialize_genesis_state(storage.clone(), executor, config).await?;

    // Retrieve genesis block and add to DAG store
    if let Ok(Some(genesis_block)) = storage.blocks.get_block(&genesis_hash) {
        dag_store.store_block(genesis_block.clone()).await?;
        tracing::info!(
            "Genesis block added to DAG store: {:?}",
            hex::encode(&genesis_hash.as_bytes()[..8])
        );
    } else {
        tracing::warn!("Failed to retrieve genesis block for DAG store");
    }

    Ok(genesis_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_block_height_zero() {
        let config = GenesisConfig::default();
        let block = create_genesis_block(&config);

        assert_eq!(block.header.height, 0);
    }

    #[test]
    fn test_genesis_block_deterministic_hash() {
        let config = GenesisConfig::default();
        let block_a = create_genesis_block(&config);
        let block_b = create_genesis_block(&config);

        // calculate_block_hash is deterministic for identical inputs
        let hash_a = calculate_block_hash(&block_a);
        let hash_b = calculate_block_hash(&block_b);

        assert_eq!(
            hash_a, hash_b,
            "Same GenesisConfig must produce same block hash"
        );
    }

    #[test]
    fn test_genesis_canonical_timestamp() {
        // 2026-01-01T00:00:00Z
        assert_eq!(CANONICAL_GENESIS_TIMESTAMP, 1_767_225_600);

        // Verify default config uses this timestamp
        let config = GenesisConfig::default();
        assert_eq!(config.timestamp, CANONICAL_GENESIS_TIMESTAMP);
    }

    #[test]
    fn test_genesis_block_no_parents() {
        let config = GenesisConfig::default();
        let block = create_genesis_block(&config);

        assert!(
            block.header.merge_parent_hashes.is_empty(),
            "Genesis block must have no merge parents"
        );
        assert_eq!(
            block.header.selected_parent_hash,
            Hash::default(),
            "Genesis block must have zero selected parent"
        );
    }

    #[test]
    fn test_standalone_genesis_matches_shared_canonical_block() {
        let config = GenesisConfig::default();
        let standalone = create_genesis_block(&config);
        let shared = shared_genesis::create_canonical_genesis_block(
            shared_genesis::CANONICAL_GENESIS_TIMESTAMP,
        );

        assert_eq!(standalone.header.timestamp, shared.header.timestamp);
        assert_eq!(standalone.header.height, shared.header.height);
        assert_eq!(
            standalone.embedded_models.len(),
            shared.embedded_models.len()
        );
        assert_eq!(standalone.required_pins.len(), shared.required_pins.len());
        assert_eq!(
            calculate_block_hash(&standalone),
            shared_genesis::calculate_canonical_block_hash(&shared)
        );
    }
}
