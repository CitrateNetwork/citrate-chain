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
pub const HARDHAT_SECONDARY_ADDRESS: Address = Address([
    0x70, 0x99, 0x79, 0x70, 0xc5, 0x18, 0x12, 0xdc, 0x3a, 0x01,
    0x0c, 0x7d, 0x01, 0xb5, 0x0e, 0x0d, 0x17, 0xdc, 0x79, 0xc8,
]);
pub const HARDHAT_TERTIARY_ADDRESS: Address = Address([
    0x3c, 0x44, 0xcd, 0xdd, 0xb6, 0xa9, 0x00, 0xfa, 0x2b, 0x58,
    0x5d, 0xd2, 0x99, 0xe0, 0x3d, 0x12, 0xfa, 0x42, 0x93, 0xbc,
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

/// Canonical address of Arachnid's deterministic CREATE2 deployer (EIP-2470).
///
/// Every modern Ethereum testnet (Holesky, Sepolia, …) ships this address
/// with the same 69-byte runtime so deployment tooling that depends on
/// CREATE2-at-a-known-address — including the eth-infinitism ERC-4337
/// bundler — can find it. The bundler's boot path:
///
///   1. checks `eth_getCode(ARACHNID_DEPLOYER_ADDRESS)`
///   2. if empty, broadcasts a pre-EIP-155 Nick's-method tx that deploys
///      the contract at this exact address
///
/// Citrate strictly enforces `chain_id` on every signed tx, which rejects
/// the pre-EIP-155 Nick's tx — so the bundler restart-loops forever. The
/// canonical mitigation, used by every chain that hosts ERC-4337, is to
/// stamp the deployer's runtime into genesis at this address. After that
/// the bundler sees "already deployed" and proceeds.
///
/// Source of the bytecode: https://github.com/Arachnid/deterministic-deployment-proxy
pub const ARACHNID_DETERMINISTIC_DEPLOYER_ADDRESS: Address = Address([
    0x4e, 0x59, 0xb4, 0x48, 0x47, 0xb3, 0x79, 0x57, 0x85, 0x88,
    0x92, 0x0c, 0xa7, 0x8f, 0xbf, 0x26, 0xc0, 0xb4, 0x95, 0x6c,
]);

/// 69-byte deployed runtime of {@link ARACHNID_DETERMINISTIC_DEPLOYER_ADDRESS}.
///
/// The literal bytes Arachnid's deterministic-deployment-proxy compiles to —
/// the same payload every other chain stamps at the canonical address. Do NOT
/// modify; the bundler's boot check compares against this exact runtime.
pub const ARACHNID_DETERMINISTIC_DEPLOYER_BYTECODE: &[u8] = &[
    // 7f               PUSH32                                                 (1 byte)
    0x7f,
    // ff..ff e0        immediate: 31 × 0xff then 0xe0                          (32 bytes)
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0,
    // 36 01 60 00 81 60 20 82 37 80 35 82 82 34 f5  — the CREATE2 prologue     (15 bytes)
    0x36, 0x01, 0x60, 0x00, 0x81, 0x60, 0x20, 0x82, 0x37, 0x80, 0x35, 0x82, 0x82, 0x34, 0xf5,
    // 80 15 15 60 39 57 81 82 fd 5b 80 82 52 50 50 50  — branch + epilogue    (16 bytes)
    0x80, 0x15, 0x15, 0x60, 0x39, 0x57, 0x81, 0x82, 0xfd, 0x5b, 0x80, 0x82, 0x52, 0x50, 0x50, 0x50,
    // 60 14 60 0c f3  — RETURN(0x0c, 0x14)                                    (5 bytes)
    0x60, 0x14, 0x60, 0x0c, 0xf3,
    // total 1 + 32 + 15 + 16 + 5 = 69 bytes
];

/// Genesis account that pre-deploys the Arachnid deterministic CREATE2
/// deployer at its canonical address. Used by every chain preset so the
/// ERC-4337 bundler boots regardless of which genesis profile is selected.
fn arachnid_deterministic_deployer_account() -> GenesisAccount {
    GenesisAccount {
        address: ARACHNID_DETERMINISTIC_DEPLOYER_ADDRESS,
        balance: U256::zero(),
        // Nonce 1 marks the account as a contract per EIP-161 semantics.
        // The real on-chain history is "0xMike deployed it once at nonce 0
        // of the canonical pre-EIP-155 tx" — nonce 1 is post-deploy.
        nonce: 1,
        code: Some(ARACHNID_DETERMINISTIC_DEPLOYER_BYTECODE.to_vec()),
    }
}

fn create_embedded_bge_m3() -> EmbeddedModel {
    // Post-WP-B (2026-04-21): the genesis block carries only a SHA-256
    // commitment to the off-chain weights, not the weights themselves.
    //
    // Rationale — see .audit/2026-04-21-repo-walkthrough/
    //             02_GENESIS_AND_EMBEDDED_MODELS.md for the footgun
    // analysis. The pre-WP-B design committed `weights: Vec<u8>` to
    // artifact_root, which allowed multi-gigabyte genesis blocks by
    // construction. Option 1 (Saul-approved 2026-04-21) replaces the
    // field with `weights_sha256: Hash`.
    //
    // The commitment below is the SHA-256 of the canonical BGE-M3 GGUF
    // content addressed by the project's model resolver. For the initial
    // genesis we commit to a well-known zero hash (no actual BGE-M3
    // weights shipped at this sprint); the real commitment is populated
    // when the off-chain distribution path is wired (deferred to the
    // pre-mainnet integration WP).
    //
    // Determinism property: this function is deterministic — same code
    // produces the same commitment across nodes. Verified by
    // `test_canonical_genesis_block_hash_deterministic`.

    EmbeddedModel {
        model_id: ConsensusModelId::from_name("bge-m3"),
        model_type: ModelType::Embeddings,
        // Placeholder commitment: all-zero hash. When the distribution
        // layer ships, replace with Sha256(gguf_bytes) of the canonical
        // BGE-M3 artifact. Nodes fetching the off-chain bytes compare
        // against this commitment and reject on mismatch.
        weights_sha256: Hash::default(),
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
            // Secondary and tertiary Hardhat accounts for SDK / wallet integration tests
            account(HARDHAT_SECONDARY_ADDRESS, 10_000),
            account(HARDHAT_TERTIARY_ADDRESS, 10_000),
            // Arachnid deterministic CREATE2 deployer — required for the
            // ERC-4337 bundler to boot (see helper docstring).
            arachnid_deterministic_deployer_account(),
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
                // Arachnid deterministic CREATE2 deployer — required for the
                // ERC-4337 bundler to boot on mainnet.
                arachnid_deterministic_deployer_account(),
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
                // Reserve — legacy faucet wallet, retained as a reserve (50M SALT).
                // The LIVE faucet service does NOT sign with this address; it
                // derives its signer deterministically (see the faucet signing
                // key below). Matches DEPLOYED_ADDRESSES.md ("Reserve").
                account(TESTNET_FAUCET_ADDRESS, 50_000_000),
                // Deployer — deploys all smart contracts (10M SALT)
                account(TESTNET_DEPLOYER_ADDRESS, 10_000_000),
                // Team/Dev — development and testing (10M SALT)
                account(TESTNET_TEAM_ADDRESS, 10_000_000),
                // Validator — block production and staking (5M SALT)
                account(TESTNET_VALIDATOR_ADDRESS, 5_000_000),
                // Faucet signing key — the address the live faucet service derives
                // from keccak256("citrate-faucet-testnet-v1") (faucet/src/main.rs).
                // RELEASE R1 / OPS_DGX_HANDOFF D-2: fold the pre-fund into genesis
                // so a re-roll no longer needs a manual `cast send` to top it up.
                // (10M SALT — matches DEPLOYED_ADDRESSES.md + team_testnet_genesis.)
                account(DETERMINISTIC_FAUCET_SIGNER_ADDRESS, 10_000_000),
                // Arachnid deterministic CREATE2 deployer — required for
                // the ERC-4337 bundler to boot (EW-S1 unblocker).
                arachnid_deterministic_deployer_account(),
            ],
            treasury_address: TESTNET_TREASURY_ADDRESS,
            team_allocations: HashMap::new(),
            ecosystem_fund: TESTNET_TREASURY_ADDRESS, // Treasury doubles as ecosystem fund
            // 585M pre-allocated (now incl. the 10M faucet signer) + 415M mining
            // = the 1B supply cap. The faucet pre-fund comes out of the mining pool.
            mining_pool_max: latt_to_wei(415_000_000),
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

        // Arachnid deterministic CREATE2 deployer — required for the
        // ERC-4337 bundler to boot. See helper docstring.
        accounts.push(arachnid_deterministic_deployer_account());

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

        // 10M faucet + 100M treasury + 250M ecosystem + 2K test accounts + 30K hardhat accounts
        let expected = latt_to_wei(360_032_000);
        assert_eq!(total, expected);
    }

    #[test]
    fn test_default_genesis_funds_sdk_test_accounts() {
        let config = GenesisConfig::default();

        for address in [
            HARDHAT_DEFAULT_ADDRESS,
            HARDHAT_SECONDARY_ADDRESS,
            HARDHAT_TERTIARY_ADDRESS,
        ] {
            let account = config
                .accounts
                .iter()
                .find(|account| account.address == address)
                .expect("default genesis must fund SDK test account");

            assert_eq!(account.balance, latt_to_wei(10_000));
        }
    }

    #[test]
    fn test_mainnet_genesis_valid() {
        let config = GenesisConfig::mainnet();
        assert!(config.validate().is_ok());
        assert_eq!(config.chain_id, 1);
    }

    /// WP-B: every genesis preset MUST pre-deploy Arachnid's deterministic
    /// CREATE2 deployer at its canonical address with the canonical 69-byte
    /// runtime. Without it the ERC-4337 bundler restart-loops at boot (its
    /// pre-EIP-155 deploy tx is rejected by Citrate's strict chain_id gate).
    /// See {@link arachnid_deterministic_deployer_account} docstring.
    #[test]
    fn test_arachnid_deployer_predeployed_in_every_preset() {
        for (label, config) in [
            ("default", GenesisConfig::default()),
            ("mainnet", GenesisConfig::mainnet()),
            ("testnet_beta", GenesisConfig::testnet_beta()),
            ("team_testnet_genesis", GenesisConfig::team_testnet_genesis()),
        ] {
            let arachnid = config
                .accounts
                .iter()
                .find(|a| a.address == ARACHNID_DETERMINISTIC_DEPLOYER_ADDRESS)
                .unwrap_or_else(|| panic!("{label} genesis missing Arachnid deployer"));
            assert_eq!(arachnid.balance, U256::zero(), "{label}: Arachnid balance");
            assert_eq!(arachnid.nonce, 1, "{label}: Arachnid nonce");
            let code = arachnid
                .code
                .as_ref()
                .unwrap_or_else(|| panic!("{label}: Arachnid has no code"));
            assert_eq!(
                code.as_slice(),
                ARACHNID_DETERMINISTIC_DEPLOYER_BYTECODE,
                "{label}: Arachnid runtime bytecode mismatch — \
                 every Citrate chain MUST stamp the exact canonical 69-byte \
                 deployed runtime so deployment tooling that depends on the \
                 well-known address (notably the eth-infinitism ERC-4337 \
                 bundler) finds the contract on boot"
            );
            assert_eq!(code.len(), 69, "{label}: Arachnid runtime is exactly 69 bytes");
        }
    }

    /// The Arachnid deployer's canonical address is a fixed point of
    /// every EVM chain that hosts CREATE2 tooling. Pin the address bytes
    /// to the literal so a typo in the hardcoded `Address([...])` never
    /// slips past review unnoticed.
    #[test]
    fn test_arachnid_deployer_address_is_canonical() {
        // 0x4e59b44847b379578588920cA78FbF26c0B4956C (case-insensitive).
        assert_eq!(
            ARACHNID_DETERMINISTIC_DEPLOYER_ADDRESS.0,
            [
                0x4e, 0x59, 0xb4, 0x48, 0x47, 0xb3, 0x79, 0x57, 0x85, 0x88,
                0x92, 0x0c, 0xa7, 0x8f, 0xbf, 0x26, 0xc0, 0xb4, 0x95, 0x6c,
            ]
        );
    }

    #[test]
    fn test_testnet_beta_genesis_valid() {
        let config = GenesisConfig::testnet_beta();
        assert!(config.validate().is_ok());
        assert_eq!(config.chain_id, 40204);
        // 6 funded accounts (incl. the deterministic faucet signer) + the
        // Arachnid deterministic CREATE2 deployer.
        assert_eq!(config.accounts.len(), 7);
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

    /// RELEASE R1 / OPS_DGX_HANDOFF D-2 regression: testnet_beta() MUST pre-fund
    /// the DETERMINISTIC faucet signer (0x6680…, the address the live faucet
    /// service derives from keccak256("citrate-faucet-testnet-v1")). Before this
    /// fix the address had ZERO genesis balance and every re-roll required a
    /// manual `cast send` to top it up. The legacy `node` config's
    /// `initial_accounts` listed it but those are explicitly skipped — only this
    /// economics config funds accounts.
    #[test]
    fn test_testnet_beta_funds_deterministic_faucet_signer() {
        let config = GenesisConfig::testnet_beta();

        let faucet_signer = config
            .accounts
            .iter()
            .find(|account| account.address == DETERMINISTIC_FAUCET_SIGNER_ADDRESS)
            .expect("testnet beta must pre-fund the deterministic faucet signer (R1/D-2)");

        assert_eq!(faucet_signer.balance, latt_to_wei(10_000_000));
    }

    #[test]
    fn test_testnet_beta_total_preallocation() {
        let config = GenesisConfig::testnet_beta();
        let total = config.total_preallocation();

        // 500M treasury + 50M reserve + 10M deployer + 10M team + 5M validator
        // + 10M deterministic faucet signer (R1/D-2) = 585M.
        let expected = latt_to_wei(585_000_000);
        assert_eq!(total, expected);
    }

    #[test]
    fn test_team_testnet_genesis_valid() {
        let config = GenesisConfig::team_testnet_genesis();
        assert!(config.validate().is_ok());
        assert_eq!(config.chain_id, 40204);

        // 3 system + 10 validators + 1 dev deployer + 1 Larry deployer + 1 faucet
        // signing key + 1 Arachnid CREATE2 deployer = 17 total.
        assert_eq!(config.accounts.len(), 17);

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

        // Without model registration (manual account init only). Mirrors
        // {@link initialize_shared_genesis_state} EXACTLY for the account
        // setup phase — balance, nonce, and code — so the only difference
        // between the two roots is whether model registration ran. Pre-WP-B
        // every genesis account had `code: None` so the original test set
        // only balance; the WP-B Arachnid pre-deploy has `code: Some(...)`,
        // and that has to be set here too or the precondition slips.
        let state_db_without = Arc::new(StateDB::new());
        let executor_without = Arc::new(Executor::with_chain_id(state_db_without, config.chain_id));
        for account in &config.accounts {
            executor_without.set_balance(&account.address, account.balance);
            if account.nonce > 0 {
                executor_without.set_nonce(&account.address, account.nonce);
            }
            if let Some(code) = &account.code {
                executor_without.set_code(&account.address, code.clone());
            }
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

        let expected = latt_to_wei(360_032_000) + team_amount;
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

    /// WP-P4-3 regression: CIF-03 — every initialized balance for testnet_beta()
    /// must come from a declared `config.accounts` entry, with no drift.
    ///
    /// The 2026-03-26 internal-final audit (CIF-03, High) flagged a concern
    /// that `initialize_shared_genesis_state()` was seeding extra balances
    /// outside `config.accounts`, making the declared GenesisConfig not the
    /// full economic truth. The defect was resolved (verified at HEAD: the
    /// initializer at lines ~516-529 only iterates `config.accounts`).
    ///
    /// This regression covers the actual production testnet config — the
    /// existing `test_shared_genesis_does_not_seed_undeclared_accounts`
    /// uses a synthetic 1-account config; this asserts the same property
    /// for the live `testnet_beta()` config that runs chain-id 40204.
    ///
    /// Acceptance: for each declared account, `get_balance` matches
    /// `account.balance` byte-for-byte; sum of observed balances equals
    /// `config.total_preallocation()`.
    #[test]
    fn test_p4_3_testnet_beta_declared_equals_initialized() {
        use citrate_execution::state::state_db::StateDB;

        let config = GenesisConfig::testnet_beta();
        config
            .validate()
            .expect("testnet_beta config must validate");

        let state_db = Arc::new(StateDB::new());
        let executor = Arc::new(Executor::with_chain_id(state_db, config.chain_id));
        let _root = initialize_shared_genesis_state(&executor, &config);

        let mut total_observed = U256::zero();
        for account in &config.accounts {
            let observed = executor.get_balance(&account.address);
            assert_eq!(
                observed,
                account.balance,
                "testnet_beta balance drift for 0x{}: declared {} wei, initialized {} wei",
                hex::encode(account.address.0),
                account.balance,
                observed
            );
            total_observed += observed;
        }

        // U256 doesn't implement std::iter::Sum, so fold by hand.
        let declared_total: U256 = config
            .accounts
            .iter()
            .fold(U256::zero(), |acc, a| acc + a.balance);
        assert_eq!(
            declared_total, total_observed,
            "sum of initialized balances must equal sum of declared balances"
        );
        assert_eq!(
            declared_total,
            config.total_preallocation(),
            "declared total must equal config.total_preallocation()"
        );
    }

    /// WP-P4-3 regression: same property for team_testnet_genesis(), which
    /// has 16 accounts (3 base + 10 validators + 3 deployer/faucet keys).
    /// This config is more complex than testnet_beta and covers the
    /// `accounts.push(...)` paths in `team_testnet_genesis()`.
    #[test]
    fn test_p4_3_team_testnet_declared_equals_initialized() {
        use citrate_execution::state::state_db::StateDB;

        let config = GenesisConfig::team_testnet_genesis();
        config
            .validate()
            .expect("team_testnet_genesis config must validate");

        let state_db = Arc::new(StateDB::new());
        let executor = Arc::new(Executor::with_chain_id(state_db, config.chain_id));
        let _root = initialize_shared_genesis_state(&executor, &config);

        let mut total_observed = U256::zero();
        for account in &config.accounts {
            let observed = executor.get_balance(&account.address);
            assert_eq!(
                observed,
                account.balance,
                "team_testnet balance drift for 0x{}: declared {} wei, initialized {} wei",
                hex::encode(account.address.0),
                account.balance,
                observed
            );
            total_observed += observed;
        }

        // U256 doesn't implement std::iter::Sum, so fold by hand.
        let declared_total: U256 = config
            .accounts
            .iter()
            .fold(U256::zero(), |acc, a| acc + a.balance);
        assert_eq!(declared_total, total_observed);
        assert_eq!(declared_total, config.total_preallocation());
    }
}
