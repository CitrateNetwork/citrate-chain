// citrate/core/economics/src/genesis.rs

use crate::latt_to_wei;
use crate::token::DECIMALS;
use citrate_consensus::types::{
    Block, BlockBuilder, BlockHeader, EmbeddedModel, Hash, ModelId as ConsensusModelId,
    ModelMetadata as ConsensusModelMetadata, ModelType, PublicKey, RequiredModel, VrfProof,
};
use citrate_execution::types::Address;
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

// Re-genesis 2026-04-01: Real wallet addresses (keys in .env.testnet)
pub const TESTNET_TREASURY_ADDRESS: Address = Address([
    0xac, 0xea, 0xa7, 0xd0, 0x0c, 0x02, 0x4d, 0x32, 0xe6, 0xe0,
    0xa0, 0x70, 0x94, 0xce, 0xb1, 0xa7, 0x70, 0x67, 0x86, 0xd1,
]);
// Deployer wallet for contract deployment
pub const TESTNET_DEPLOYER_ADDRESS: Address = Address([
    0x42, 0x50, 0x67, 0x5f, 0x90, 0x15, 0xe6, 0x5f, 0xc8, 0x66,
    0xf3, 0xa3, 0x73, 0xf8, 0x2b, 0xb9, 0xdf, 0xc0, 0x00, 0xc6,
]);
// Faucet signing wallet
pub const TESTNET_FAUCET_ADDRESS: Address = Address([
    0xf4, 0xad, 0xb1, 0x73, 0x4f, 0x7b, 0xd9, 0xf8, 0x97, 0x9b,
    0xd5, 0x3b, 0x2b, 0xf6, 0xd7, 0x69, 0x0d, 0x56, 0x2b, 0x6d,
]);
// Team/Dev wallet
pub const TESTNET_TEAM_ADDRESS: Address = Address([
    0xb6, 0xe9, 0xa5, 0x58, 0xa4, 0xf9, 0xdc, 0x9e, 0x3f, 0x66,
    0x7a, 0x3b, 0x44, 0x6a, 0x48, 0xbd, 0xdf, 0x67, 0x11, 0x26,
]);
// Validator coinbase wallet
pub const TESTNET_VALIDATOR_ADDRESS: Address = Address([
    0x04, 0xab, 0xae, 0x08, 0xac, 0x64, 0x3b, 0x2c, 0x51, 0x8f,
    0x22, 0xe2, 0x12, 0xa2, 0x7f, 0x7b, 0x6e, 0x14, 0xb4, 0xc3,
]);
// Legacy ecosystem address (kept for backward compat, no genesis funding)
pub const TESTNET_ECOSYSTEM_ADDRESS: Address = Address([0x22; 20]);
pub const LEGACY_FAUCET_PLACEHOLDER_ADDRESS: Address = Address([0x33; 20]);
pub const HARDHAT_DEFAULT_ADDRESS: Address = Address([
    0xf3, 0x9f, 0xd6, 0xe5, 0x1a, 0xad, 0x88, 0xf6, 0xf4, 0xce,
    0x6a, 0xb8, 0x82, 0x72, 0x79, 0xcf, 0xff, 0xb9, 0x22, 0x66,
]);
pub const FOUNDRY_RECOVERED_DEPLOYER_ADDRESS: Address = Address([
    0xfc, 0xad, 0x0b, 0x19, 0xbb, 0x29, 0xd4, 0x67, 0x45, 0x31,
    0xd6, 0xf1, 0x15, 0x23, 0x7e, 0x16, 0xaf, 0xce, 0x37, 0x7c,
]);
pub const SAUL_DEPLOYER_ADDRESS: Address = Address([
    0x9f, 0x5b, 0x15, 0x6c, 0x53, 0x30, 0x5d, 0x4b, 0x20, 0xc9,
    0x4c, 0xa0, 0x8e, 0x32, 0x19, 0xd1, 0xc0, 0xe7, 0x40, 0x1a,
]);
pub const DETERMINISTIC_FAUCET_SIGNER_ADDRESS: Address = Address([
    0x66, 0x80, 0xb4, 0x3a, 0xf0, 0x9d, 0x9b, 0x35, 0x13, 0x32,
    0xbf, 0x53, 0x78, 0xeb, 0x58, 0x0e, 0x3b, 0x39, 0x01, 0x82,
]);

fn account(address: Address, balance_latt: u64) -> GenesisAccount {
    GenesisAccount {
        address,
        balance: latt_to_wei(balance_latt),
        nonce: 0,
        code: None,
    }
}

fn create_embedded_bge_m3() -> EmbeddedModel {
    // The actual GGUF weights are optional in contributor builds.
    // The canonical genesis block still carries the model metadata shape even
    // when weights are omitted.
    let weights: &[u8] = &[];

    EmbeddedModel {
        model_id: ConsensusModelId::from_name("bge-m3"),
        model_type: ModelType::Embeddings,
        weights: weights.to_vec(),
        metadata: ConsensusModelMetadata {
            name: "BGE-M3 Embeddings".to_string(),
            version: "1.0.0".to_string(),
            context_length: 8192,
            embedding_dim: Some(1024),
            license: "MIT".to_string(),
            framework: Some("GGUF".to_string()),
        },
    }
}

fn create_required_mistral_7b() -> RequiredModel {
    let sha256_bytes: [u8; 32] = [
        0x12, 0x70, 0xd2, 0x2c, 0x0f, 0xbb, 0x3d, 0x09, 0x2f, 0xb7, 0x25, 0xd4, 0xd9, 0x6c,
        0x45, 0x7b, 0x7b, 0x68, 0x7a, 0x5f, 0x5a, 0x71, 0x5a, 0xbe, 0x1e, 0x81, 0x8d, 0xa3,
        0x03, 0xe5, 0x62, 0xb6,
    ];

    RequiredModel::new(
        ConsensusModelId::from_name("mistral-7b-instruct-v0.3"),
        "QmUsYyxg71bV8USRQ6Ccm3SdMqeWgEEVnCYkgNDaxvBTZB".to_string(),
        Hash::new(sha256_bytes),
        4_367_438_912,
        1_000_000_000_000_000_000_000,
    )
}

/// Genesis account configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisAccount {
    pub address: Address,
    pub balance: U256,
    pub nonce: u64,
    pub code: Option<Vec<u8>>,
}

/// Genesis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    /// Chain ID
    pub chain_id: u64,

    /// Initial accounts
    pub accounts: Vec<GenesisAccount>,

    /// Treasury address
    pub treasury_address: Address,

    /// Team addresses and allocations
    pub team_allocations: HashMap<Address, U256>,

    /// Ecosystem fund address
    pub ecosystem_fund: Address,

    /// Mining rewards pool (not pre-allocated, minted as needed)
    pub mining_pool_max: U256,
}

impl Default for GenesisConfig {
    fn default() -> Self {
        // Default addresses for testnet
        let treasury = TESTNET_TREASURY_ADDRESS;
        let ecosystem = TESTNET_ECOSYSTEM_ADDRESS;
        let faucet = DETERMINISTIC_FAUCET_SIGNER_ADDRESS;

        // Test accounts with initial balances
        let test_accounts = vec![
            // Faucet account (10 million SALT for testnet distribution)
            account(faucet, 10_000_000),
            // Treasury (100 million SALT)
            account(treasury, 100_000_000),
            // Ecosystem fund (250 million SALT)
            account(ecosystem, 250_000_000),
            // Test account 1
            account(Address([0x01; 20]), 1_000),
            // Test account 2
            account(Address([0x02; 20]), 1_000),
            // Hardhat / Foundry default deployer for local dev flows
            account(HARDHAT_DEFAULT_ADDRESS, 10_000),
        ];

        Self {
            chain_id: 40204, // Testnet beta
            accounts: test_accounts,
            treasury_address: treasury,
            team_allocations: HashMap::new(), // No team allocations for testnet
            ecosystem_fund: ecosystem,
            mining_pool_max: latt_to_wei(500_000_000), // 500M SALT for mining
        }
    }
}

impl GenesisConfig {
    /// Create mainnet genesis configuration
    pub fn mainnet() -> Self {
        let treasury = address_from_hex("0x1111111111111111111111111111111111111111")
            .unwrap_or_else(|e| panic!("Invalid hardcoded mainnet address: treasury: {e}"));
        let ecosystem = address_from_hex("0x2222222222222222222222222222222222222222")
            .unwrap_or_else(|e| panic!("Invalid hardcoded mainnet address: ecosystem: {e}"));

        // Team allocations (15% = 150M SALT, vested over 4 years)
        let team_allocations = HashMap::new();
        // Add team member addresses and allocations here

        Self {
            chain_id: 1, // Mainnet
            accounts: vec![
                // Treasury
                GenesisAccount {
                    address: treasury,
                    balance: latt_to_wei(100_000_000),
                    nonce: 0,
                    code: None,
                },
                // Ecosystem fund
                GenesisAccount {
                    address: ecosystem,
                    balance: latt_to_wei(250_000_000),
                    nonce: 0,
                    code: None,
                },
            ],
            treasury_address: treasury,
            team_allocations,
            ecosystem_fund: ecosystem,
            mining_pool_max: latt_to_wei(500_000_000),
        }
    }

    /// Create testnet beta genesis configuration (chain_id = 40204).
    /// Used for the closed beta testnet with peer whitelist + API key gating.
    pub fn testnet_beta() -> Self {
        // Re-genesis 2026-04-01: Clean start with real wallet addresses.
        // Keys stored in .env.testnet (NOT committed to repo).
        // Total: 1B SALT allocated across 5 accounts.
        Self {
            chain_id: 40204,
            accounts: vec![
                // Treasury — main supply, funds future allocations (500M SALT)
                account(TESTNET_TREASURY_ADDRESS, 500_000_000),
                // Faucet — dispenses 10 SALT per request to users (50M SALT)
                account(TESTNET_FAUCET_ADDRESS, 50_000_000),
                // Deployer — deploys all smart contracts (10M SALT)
                account(TESTNET_DEPLOYER_ADDRESS, 10_000_000),
                // Team/Dev — development and testing (10M SALT)
                account(TESTNET_TEAM_ADDRESS, 10_000_000),
                // Validator — block production and staking (5M SALT)
                account(TESTNET_VALIDATOR_ADDRESS, 5_000_000),
            ],
            treasury_address: TESTNET_TREASURY_ADDRESS,
            team_allocations: HashMap::new(),
            ecosystem_fund: TESTNET_TREASURY_ADDRESS, // Treasury doubles as ecosystem fund
            mining_pool_max: latt_to_wei(425_000_000), // Remaining 425M for mining rewards
        }
    }

    /// Create team testnet genesis configuration (chain_id = 40204).
    ///
    /// Pre-funds 10 team validator addresses with 100,000 SALT each for staking
    /// and operations, plus a faucet (10M SALT) and treasury (100M SALT).
    ///
    /// Validator addresses use a deterministic derivation: `0xVV00...00` where VV
    /// ranges from 0x01 to 0x0A. Team members should replace these with their
    /// actual validator addresses before a coordinated genesis.
    pub fn team_testnet_genesis() -> Self {
        let treasury = TESTNET_TREASURY_ADDRESS;
        let ecosystem = TESTNET_ECOSYSTEM_ADDRESS;
        let faucet = LEGACY_FAUCET_PLACEHOLDER_ADDRESS;

        let mut accounts = vec![
            // Faucet account (10M SALT for testnet distribution via faucet service)
            GenesisAccount {
                address: faucet,
                balance: latt_to_wei(10_000_000),
                nonce: 0,
                code: None,
            },
            // Treasury (100M SALT for governance and ecosystem development)
            GenesisAccount {
                address: treasury,
                balance: latt_to_wei(100_000_000),
                nonce: 0,
                code: None,
            },
            // Ecosystem fund (50M SALT — reduced vs beta since validators get direct funding)
            GenesisAccount {
                address: ecosystem,
                balance: latt_to_wei(50_000_000),
                nonce: 0,
                code: None,
            },
        ];

        // Pre-fund 10 team validator addresses at 100,000 SALT each.
        for i in 1u8..=10 {
            let mut addr = [0u8; 20];
            addr[0] = i;
            accounts.push(GenesisAccount {
                address: Address(addr),
                balance: latt_to_wei(100_000),
                nonce: 0,
                code: None,
            });
        }

        // Dev deployer account (Foundry default key: 0x0123456789abcdef...)
        // Address: 0xFCAd0B19bB29D4674531d6f115237E16AfCE377c
        // Pre-funded with 1M SALT for contract deployment on testnet.
        accounts.push(GenesisAccount {
            address: FOUNDRY_RECOVERED_DEPLOYER_ADDRESS,
            balance: latt_to_wei(1_000_000),
            nonce: 0,
            code: None,
        });

        // Larry's deployer wallet (0x9f5B156C53305D4b20c94ca08E3219D1C0e7401a)
        // Pre-funded with 5M SALT for contract deployment and testing.
        accounts.push(GenesisAccount {
            address: SAUL_DEPLOYER_ADDRESS,
            balance: latt_to_wei(5_000_000),
            nonce: 0,
            code: None,
        });

        // Faucet signing key account (0x6680b43af09d9b351332bf5378eb580e3b390182)
        // Deterministic key from "citrate-faucet-testnet-v1". Pre-funded with 10M SALT.
        accounts.push(GenesisAccount {
            address: DETERMINISTIC_FAUCET_SIGNER_ADDRESS,
            balance: latt_to_wei(10_000_000),
            nonce: 0,
            code: None,
        });

        Self {
            chain_id: 40204,
            accounts,
            treasury_address: treasury,
            team_allocations: HashMap::new(),
            ecosystem_fund: ecosystem,
            mining_pool_max: latt_to_wei(500_000_000),
        }
    }

    /// Get total pre-allocated supply
    pub fn total_preallocation(&self) -> U256 {
        let mut total = U256::zero();

        for account in &self.accounts {
            total += account.balance;
        }

        for balance in self.team_allocations.values() {
            total += *balance;
        }

        total
    }

    /// Validate genesis configuration
    pub fn validate(&self) -> Result<(), GenesisError> {
        // Check total allocation doesn't exceed supply
        let total_supply = U256::from(1_000_000_000) * U256::from(10).pow(U256::from(DECIMALS));
        let preallocated = self.total_preallocation();

        if preallocated + self.mining_pool_max > total_supply {
            return Err(GenesisError::ExceedsSupply);
        }

        // Check for duplicate addresses
        let mut addresses = std::collections::HashSet::new();
        for account in &self.accounts {
            if !addresses.insert(account.address) {
                return Err(GenesisError::DuplicateAddress(account.address));
            }
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GenesisError {
    #[error("Total allocation exceeds maximum supply")]
    ExceedsSupply,

    #[error("Duplicate address in genesis: {0:?}")]
    DuplicateAddress(Address),

    #[error("Invalid configuration: {0}")]
    Invalid(String),
}

// Helper function to create Address from hex string
fn address_from_hex(hex: &str) -> Result<Address, hex::FromHexError> {
    let bytes = hex::decode(hex.trim_start_matches("0x"))?;
    if bytes.len() != 20 {
        return Err(hex::FromHexError::InvalidStringLength);
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes);
    Ok(Address(addr))
}

// ============================================================================
// Shared genesis state initialization (WP-1.1 of Sprint FULL-NODE-SYNC)
//
// This function is the SINGLE SOURCE OF TRUTH for genesis state initialization.
// Both the standalone node (node/src/genesis.rs) and the GUI embedded node
// (gui/src-tauri/src/node/mod.rs) MUST call this function to ensure identical
// genesis block hashes across all nodes.
//
// Invariant (from GenesisSafetyAcrossNodes.tla):
//   DeterministicGenesis: same config → same initialized accounts → same state root → same hash
//
// Note: the executor's model registry is initialized here for runtime parity, but it is
// not currently folded into the account/storage trie state root. The embedded genesis
// model still matters for block determinism through the block artifact data.
// ============================================================================

use citrate_execution::executor::Executor;
use std::sync::Arc;

/// Genesis model ONNX bytes (147 bytes, deterministic hash).
/// Both standalone and GUI nodes use this exact file.
const GENESIS_MODEL_ONNX: &[u8] = include_bytes!("../assets/genesis_model.onnx");

/// Canonical genesis timestamp (2026-01-01T00:00:00Z).
pub const CANONICAL_GENESIS_TIMESTAMP: u64 = 1_767_225_600;

/// Build the canonical genesis block contents shared by standalone and GUI nodes.
///
/// The block hash itself is left unhashed so callers can set the state root first.
pub fn create_canonical_genesis_block(timestamp: u64) -> Block {
    let zero = Hash::default();

    let header = BlockHeader {
        version: 1,
        block_hash: zero,
        selected_parent_hash: zero,
        merge_parent_hashes: vec![],
        timestamp,
        height: 0,
        blue_score: 0,
        blue_work: 0,
        pruning_point: zero,
        proposer_pubkey: PublicKey::new([0u8; 32]),
        vrf_reveal: VrfProof {
            proof: vec![],
            output: Hash::default(),
        },
        base_fee_per_gas: 1_000_000_000,
        gas_used: 0,
        gas_limit: 30_000_000,
    };

    BlockBuilder::new()
        .header(header)
        .embedded_models(vec![create_embedded_bge_m3()])
        .required_pins(vec![create_required_mistral_7b()])
        .build_unhashed()
}

/// Calculate the canonical genesis/full block hash used by both standalone and GUI nodes.
pub fn calculate_canonical_block_hash(block: &Block) -> Hash {
    let mut hasher = Sha3_256::new();

    hasher.update(block.header.version.to_le_bytes());
    hasher.update(block.header.selected_parent_hash.as_bytes());
    for parent in &block.header.merge_parent_hashes {
        hasher.update(parent.as_bytes());
    }
    hasher.update(block.header.timestamp.to_le_bytes());
    hasher.update(block.header.height.to_le_bytes());
    hasher.update(block.header.blue_score.to_le_bytes());
    hasher.update(block.header.blue_work.to_le_bytes());
    hasher.update(block.header.pruning_point.as_bytes());
    hasher.update(block.state_root.as_bytes());
    hasher.update(block.tx_root.as_bytes());
    hasher.update(block.receipt_root.as_bytes());
    hasher.update(block.artifact_root.as_bytes());

    let hash_bytes = hasher.finalize();
    let mut hash_array = [0u8; 32];
    hash_array.copy_from_slice(&hash_bytes[..32]);
    Hash::new(hash_array)
}

/// Initialize genesis state in the executor's state DB.
///
/// This function:
/// 1. Sets balances/nonces for all accounts in the config
/// 2. Registers the genesis AI model (deterministic hash from ONNX bytes)
/// 3. Commits the state DB
/// 4. Returns the state root hash
///
/// The returned state root is used to compute the genesis block hash.
/// All nodes MUST call this function to produce matching genesis blocks.
pub fn initialize_shared_genesis_state(
    executor: &Arc<Executor>,
    config: &GenesisConfig,
) -> [u8; 32] {
    config
        .validate()
        .unwrap_or_else(|e| panic!("invalid shared genesis configuration: {e}"));

    // 1. Initialize genesis accounts
    for account in &config.accounts {
        executor.set_balance(&account.address, account.balance);
        if account.nonce > 0 {
            executor.set_nonce(&account.address, account.nonce);
        }
        if let Some(code) = &account.code {
            executor.set_code(&account.address, code.clone());
        }
        tracing::info!(
            "Genesis account 0x{}: {} SALT",
            hex::encode(account.address.0),
            account.balance / U256::from(10).pow(U256::from(18))
        );
    }

    // 2. Register genesis AI model (deterministic — same ONNX bytes on all nodes)
    executor.register_genesis_model_from_bytes(
        GENESIS_MODEL_ONNX,
        "Genesis BERT Tiny",
        CANONICAL_GENESIS_TIMESTAMP,
    );

    // 3. Commit state DB and return state root
    let state_root = executor.state_db().commit();
    let root_bytes: [u8; 32] = *state_root.as_bytes();

    tracing::info!(
        "Genesis state root: 0x{}",
        hex::encode(&root_bytes[..8])
    );

    root_bytes
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_config_validation() {
        let config = GenesisConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_total_preallocation() {
        let config = GenesisConfig::default();
        let total = config.total_preallocation();

        // 10M faucet + 100M treasury + 250M ecosystem + 2K test accounts + 10K hardhat deployer
        let expected = latt_to_wei(360_012_000);
        assert_eq!(total, expected);
    }

    #[test]
    fn test_mainnet_genesis_valid() {
        let config = GenesisConfig::mainnet();
        assert!(config.validate().is_ok());
        assert_eq!(config.chain_id, 1);
    }

    #[test]
    fn test_testnet_beta_genesis_valid() {
        let config = GenesisConfig::testnet_beta();
        assert!(config.validate().is_ok());
        assert_eq!(config.chain_id, 40204);
        assert_eq!(config.accounts.len(), 5);
    }

    #[test]
    fn test_testnet_beta_funds_faucet() {
        let config = GenesisConfig::testnet_beta();

        let faucet_account = config
            .accounts
            .iter()
            .find(|account| account.address == TESTNET_FAUCET_ADDRESS)
            .expect("testnet beta must fund faucet address");

        assert_eq!(faucet_account.balance, latt_to_wei(50_000_000));
    }

    #[test]
    fn test_testnet_beta_total_preallocation() {
        let config = GenesisConfig::testnet_beta();
        let total = config.total_preallocation();

        // Re-genesis 2026-04-01: 500M treasury + 50M faucet + 10M deployer + 10M team + 5M validator
        let expected = latt_to_wei(575_000_000);
        assert_eq!(total, expected);
    }

    #[test]
    fn test_team_testnet_genesis_valid() {
        let config = GenesisConfig::team_testnet_genesis();
        assert!(config.validate().is_ok());
        assert_eq!(config.chain_id, 40204);

        // 3 system + 10 validators + 1 dev deployer + 1 Larry deployer + 1 faucet signing key = 16 total
        assert_eq!(config.accounts.len(), 16);

        // Verify validator funding: accounts[3..13] are validators at 100,000 SALT each
        for account in &config.accounts[3..13] {
            assert_eq!(account.balance, latt_to_wei(100_000));
        }

        // Verify deployer accounts
        assert_eq!(config.accounts[13].balance, latt_to_wei(1_000_000));  // dev deployer
        assert_eq!(config.accounts[14].balance, latt_to_wei(5_000_000));  // Saul deployer

        // Verify system accounts
        assert_eq!(config.accounts[0].balance, latt_to_wei(10_000_000));  // faucet
        assert_eq!(config.accounts[1].balance, latt_to_wei(100_000_000)); // treasury
        assert_eq!(config.accounts[2].balance, latt_to_wei(50_000_000));  // ecosystem
    }

    #[test]
    fn test_team_testnet_genesis_no_duplicate_addresses() {
        let config = GenesisConfig::team_testnet_genesis();
        let mut addresses = std::collections::HashSet::new();
        for account in &config.accounts {
            assert!(
                addresses.insert(account.address),
                "Duplicate address found: {:?}",
                account.address
            );
        }
    }

    #[test]
    fn test_team_testnet_genesis_total_preallocation() {
        let config = GenesisConfig::team_testnet_genesis();
        let total = config.total_preallocation();
        // 10M faucet + 100M treasury + 50M ecosystem + 10*100K validators + 1M dev deployer + 5M Larry deployer + 10M faucet key = 177M SALT
        let expected = latt_to_wei(177_000_000);
        assert_eq!(total, expected);
    }

    #[test]
    fn test_exceeds_supply_rejected() {
        // Create a config that exceeds total supply
        let mut config = GenesisConfig::default();
        // Add an account with balance that pushes over 1B total
        config.accounts.push(GenesisAccount {
            address: Address([0xAA; 20]),
            balance: latt_to_wei(999_999_999), // This + existing ~360M > 1B with mining_pool_max
            nonce: 0,
            code: None,
        });
        assert!(matches!(config.validate(), Err(GenesisError::ExceedsSupply)));
    }

    #[test]
    fn test_duplicate_address_rejected() {
        let mut config = GenesisConfig::default();
        // Add duplicate of an existing address
        let dup_addr = config.accounts[0].address;
        config.accounts.push(GenesisAccount {
            address: dup_addr,
            balance: U256::from(1),
            nonce: 0,
            code: None,
        });
        assert!(matches!(config.validate(), Err(GenesisError::DuplicateAddress(_))));
    }

    /// WP-1.3: Genesis state root determinism test.
    ///
    /// Proves the invariant from GenesisSafetyAcrossNodes.tla:
    ///   DeterministicGenesis: same config → same state root
    ///
    /// Two independent executor instances with the same genesis config
    /// MUST produce identical state roots.
    #[test]
    fn test_genesis_state_root_deterministic() {
        use citrate_execution::state::state_db::StateDB;

        let config = GenesisConfig::team_testnet_genesis();

        // Initialize two independent executors
        let state_db_1 = Arc::new(StateDB::new());
        let executor_1 = Arc::new(Executor::with_chain_id(state_db_1, config.chain_id));
        let root_1 = initialize_shared_genesis_state(&executor_1, &config);

        let state_db_2 = Arc::new(StateDB::new());
        let executor_2 = Arc::new(Executor::with_chain_id(state_db_2, config.chain_id));
        let root_2 = initialize_shared_genesis_state(&executor_2, &config);

        assert_eq!(
            root_1, root_2,
            "Two independent executors with the same config must produce identical state roots. \
             This is the DeterministicGenesis invariant from GenesisSafetyAcrossNodes.tla."
        );

        // State root must not be zero (genesis has real accounts)
        assert_ne!(
            root_1, [0u8; 32],
            "Genesis state root must not be zero — accounts and model should be initialized."
        );
    }

    /// Proves the current runtime behavior of shared genesis model registration.
    ///
    /// The shared initializer must deterministically populate the executor's model
    /// registry, but that registry is not currently part of the committed account trie.
    #[test]
    fn test_model_registration_populates_registry() {
        use citrate_execution::state::state_db::StateDB;

        let config = GenesisConfig::team_testnet_genesis();

        // With model registration (via shared function)
        let state_db_with = Arc::new(StateDB::new());
        let executor_with = Arc::new(Executor::with_chain_id(state_db_with, config.chain_id));
        let root_with = initialize_shared_genesis_state(&executor_with, &config);

        // Without model registration (manual account init only)
        let state_db_without = Arc::new(StateDB::new());
        let executor_without = Arc::new(Executor::with_chain_id(state_db_without, config.chain_id));
        for account in &config.accounts {
            executor_without.set_balance(&account.address, account.balance);
        }
        // Deliberately skip model registration
        let root_without = executor_without.state_db().commit();
        let root_without_bytes: [u8; 32] = *root_without.as_bytes();

        assert_eq!(
            root_with, root_without_bytes,
            "The committed state root currently covers the account/storage trie only. \
             Model registration is tracked separately in the executor state."
        );
        assert_eq!(executor_with.state_db().all_models().len(), 1);
        assert_eq!(executor_without.state_db().all_models().len(), 0);
    }

    #[test]
    fn test_preallocation_with_team_allocations() {
        let mut config = GenesisConfig::default();
        let team_member = Address([0xBB; 20]);
        let team_amount = latt_to_wei(1_000);
        config.team_allocations.insert(team_member, team_amount);

        let expected = latt_to_wei(360_012_000) + team_amount;
        assert_eq!(config.total_preallocation(), expected);
    }

    #[test]
    fn test_shared_genesis_does_not_seed_undeclared_accounts() {
        use citrate_execution::state::state_db::StateDB;

        let only_declared = Address([0xAB; 20]);
        let config = GenesisConfig {
            chain_id: 40204,
            accounts: vec![account(only_declared, 123)],
            treasury_address: TESTNET_TREASURY_ADDRESS,
            team_allocations: HashMap::new(),
            ecosystem_fund: TESTNET_ECOSYSTEM_ADDRESS,
            mining_pool_max: latt_to_wei(500_000_000),
        };

        let state_db = Arc::new(StateDB::new());
        let executor = Arc::new(Executor::with_chain_id(state_db, config.chain_id));
        let _ = initialize_shared_genesis_state(&executor, &config);

        assert_eq!(executor.get_balance(&only_declared), latt_to_wei(123));
        assert_eq!(executor.get_balance(&HARDHAT_DEFAULT_ADDRESS), U256::zero());
        assert_eq!(
            executor.get_balance(&FOUNDRY_RECOVERED_DEPLOYER_ADDRESS),
            U256::zero()
        );
        assert_eq!(executor.get_balance(&SAUL_DEPLOYER_ADDRESS), U256::zero());
        assert_eq!(
            executor.get_balance(&DETERMINISTIC_FAUCET_SIGNER_ADDRESS),
            U256::zero()
        );
    }

    #[test]
    fn test_canonical_genesis_block_contains_artifacts() {
        let block = create_canonical_genesis_block(CANONICAL_GENESIS_TIMESTAMP);

        assert_eq!(block.header.timestamp, CANONICAL_GENESIS_TIMESTAMP);
        assert_eq!(block.header.height, 0);
        assert_eq!(block.embedded_models.len(), 1);
        assert_eq!(block.required_pins.len(), 1);
    }

    #[test]
    fn test_canonical_genesis_block_hash_deterministic() {
        let block_a = create_canonical_genesis_block(CANONICAL_GENESIS_TIMESTAMP);
        let block_b = create_canonical_genesis_block(CANONICAL_GENESIS_TIMESTAMP);

        assert_eq!(
            calculate_canonical_block_hash(&block_a),
            calculate_canonical_block_hash(&block_b)
        );
    }

    #[test]
    fn test_address_from_hex_invalid_length() {
        // Too short
        let result = address_from_hex("0x1234");
        assert!(result.is_err());
    }

    #[test]
    fn test_address_from_hex_valid() {
        let result = address_from_hex("0x0000000000000000000000000000000000000001");
        assert!(result.is_ok());
        let addr = result.unwrap();
        assert_eq!(addr.0[19], 1);
    }

    #[test]
    fn test_zero_balance_accounts_valid() {
        // A genesis config with zero-balance accounts should be valid
        let config = GenesisConfig {
            chain_id: 40204,
            accounts: vec![
                GenesisAccount {
                    address: Address([0x01; 20]),
                    balance: U256::zero(),
                    nonce: 0,
                    code: None,
                },
            ],
            treasury_address: Address([0x11; 20]),
            team_allocations: HashMap::new(),
            ecosystem_fund: Address([0x22; 20]),
            mining_pool_max: latt_to_wei(500_000_000),
        };
        assert!(config.validate().is_ok());
    }
}
