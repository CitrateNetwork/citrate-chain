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
