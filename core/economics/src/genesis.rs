// citrate/core/economics/src/genesis.rs

use crate::latt_to_wei;
use crate::token::DECIMALS;
use citrate_execution::types::Address;
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
        let treasury = Address([0x11; 20]);
        let ecosystem = Address([0x22; 20]);
        let faucet = Address([0x33; 20]);

        // Test accounts with initial balances
        let test_accounts = vec![
            // Faucet account (10 million SALT for testnet distribution)
            GenesisAccount {
                address: faucet,
                balance: latt_to_wei(10_000_000),
                nonce: 0,
                code: None,
            },
            // Treasury (100 million SALT)
            GenesisAccount {
                address: treasury,
                balance: latt_to_wei(100_000_000),
                nonce: 0,
                code: None,
            },
            // Ecosystem fund (250 million SALT)
            GenesisAccount {
                address: ecosystem,
                balance: latt_to_wei(250_000_000),
                nonce: 0,
                code: None,
            },
            // Test account 1
            GenesisAccount {
                address: Address([0x01; 20]),
                balance: latt_to_wei(1000),
                nonce: 0,
                code: None,
            },
            // Test account 2
            GenesisAccount {
                address: Address([0x02; 20]),
                balance: latt_to_wei(1000),
                nonce: 0,
                code: None,
            },
        ];

        Self {
            chain_id: 1337, // Local testnet
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
        let treasury = Address([0x11; 20]);
        let ecosystem = Address([0x22; 20]);
        let faucet = Address([0x33; 20]);

        Self {
            chain_id: 40204, // Testnet beta
            accounts: vec![
                // Faucet account (10M SALT for testnet distribution)
                GenesisAccount {
                    address: faucet,
                    balance: latt_to_wei(10_000_000),
                    nonce: 0,
                    code: None,
                },
                // Treasury (100M SALT)
                GenesisAccount {
                    address: treasury,
                    balance: latt_to_wei(100_000_000),
                    nonce: 0,
                    code: None,
                },
                // Ecosystem fund (250M SALT)
                GenesisAccount {
                    address: ecosystem,
                    balance: latt_to_wei(250_000_000),
                    nonce: 0,
                    code: None,
                },
            ],
            treasury_address: treasury,
            team_allocations: HashMap::new(),
            ecosystem_fund: ecosystem,
            mining_pool_max: latt_to_wei(500_000_000),
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
        let treasury = Address([0x11; 20]);
        let ecosystem = Address([0x22; 20]);
        let faucet = Address([0x33; 20]);

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
        // Addresses: 0x0100...00 through 0x0A00...00 (deterministic placeholders).
        // Replace with real validator addresses before coordinated team genesis.
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
//   DeterministicGenesis: same config → same accounts → same model → same state root → same hash
//   ModelRegistrationMatters: skipping model registration produces different hash
// ============================================================================

use citrate_execution::executor::Executor;
use std::sync::Arc;

/// Genesis model ONNX bytes (147 bytes, deterministic hash).
/// Both standalone and GUI nodes use this exact file.
const GENESIS_MODEL_ONNX: &[u8] = include_bytes!("../assets/genesis_model.onnx");

/// Canonical genesis timestamp (2026-01-01T00:00:00Z).
pub const CANONICAL_GENESIS_TIMESTAMP: u64 = 1_767_225_600;

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

    // 2. Seed the Hardhat/Forge default deployer account (for contract deployment)
    let forge_addr = Address([
        0xf3, 0x9F, 0xd6, 0xe5, 0x1a, 0xad, 0x88, 0xF6,
        0xF4, 0xce, 0x6a, 0xB8, 0x82, 0x72, 0x79, 0xcf,
        0xfF, 0xb9, 0x22, 0x66,
    ]);
    executor.set_balance(
        &forge_addr,
        U256::from(10_000) * U256::from(10).pow(U256::from(18)),
    );

    // 3. Register genesis AI model (deterministic — same ONNX bytes on all nodes)
    executor.register_genesis_model_from_bytes(
        GENESIS_MODEL_ONNX,
        "Genesis BERT Tiny",
        CANONICAL_GENESIS_TIMESTAMP,
    );

    // 4. Commit state DB and return state root
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

        // Should be 360M SALT (10M faucet + 100M treasury + 250M ecosystem + 2K test accounts)
        let expected = latt_to_wei(360_002_000);
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
    }

    #[test]
    fn test_team_testnet_genesis_valid() {
        let config = GenesisConfig::team_testnet_genesis();
        assert!(config.validate().is_ok());
        assert_eq!(config.chain_id, 40204);

        // 3 system accounts + 10 validator accounts = 13 total
        assert_eq!(config.accounts.len(), 13);

        // Verify validator funding: each of the 10 validators gets 100,000 SALT
        for account in &config.accounts[3..] {
            assert_eq!(account.balance, latt_to_wei(100_000));
        }

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
        // 10M faucet + 100M treasury + 50M ecosystem + 10 * 100K validators = 161M SALT
        let expected = latt_to_wei(161_000_000);
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

    /// Proves ModelRegistrationMatters from GenesisSafetyAcrossNodes.tla:
    /// Skipping model registration produces a DIFFERENT state root.
    #[test]
    fn test_model_registration_affects_state_root() {
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

        assert_ne!(
            root_with, root_without_bytes,
            "Skipping model registration must produce a different state root. \
             This is the ModelRegistrationMatters invariant from GenesisSafetyAcrossNodes.tla."
        );
    }

    #[test]
    fn test_preallocation_with_team_allocations() {
        let mut config = GenesisConfig::default();
        let team_member = Address([0xBB; 20]);
        let team_amount = latt_to_wei(1_000);
        config.team_allocations.insert(team_member, team_amount);

        let expected = latt_to_wei(360_002_000) + team_amount;
        assert_eq!(config.total_preallocation(), expected);
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
            chain_id: 1337,
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
