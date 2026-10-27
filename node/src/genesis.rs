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

/// The genesis profile whose block 0 holds the ceremony's contracts (r1006).
pub const R1006_PROFILE: &str = "r1006";

/// Rehearsal opt-in: lets a node create or run an r1006 genesis that still has
/// placeholders (ceremony inputs, producer set, OrangeSeed). Never set on a network node.
pub const R1006_REHEARSAL_ENV: &str = "CITRATE_R1006_REHEARSAL";

/// Fail closed on an r1006 genesis that is not release-ready. `allow_rehearsal` is the
/// explicit opt-in (`CITRATE_R1006_REHEARSAL=1`); without it every missing piece is named
/// and the node refuses to start.
pub fn check_r1006_bootable(allow_rehearsal: bool) -> anyhow::Result<()> {
    let r = citrate_economics::r1006::readiness()
        .map_err(|e| anyhow::anyhow!("invalid r1006 genesis: {e}"))?;
    if r.is_release_ready() {
        return Ok(());
    }
    let missing = r.missing().join("; ");
    if allow_rehearsal {
        tracing::warn!(
            "r1006 REHEARSAL genesis ({R1006_REHEARSAL_ENV}=1): not release-ready: {missing}"
        );
        return Ok(());
    }
    anyhow::bail!(
        "the r1006 genesis in this build is not release-ready: {missing}. It must not start a \
         network. For a local rehearsal only, set {R1006_REHEARSAL_ENV}=1."
    )
}

/// The start-up guard for the genesis a node is about to run (pure, so it is unit
/// tested): `running` is the data directory's block 0.
///
/// * profile `r1006` with another (or no) block 0: refused (a fresh data directory is
///   needed; the r1006 rules would not apply to that genesis);
/// * the r1006 block 0 on another chain id: refused;
/// * the r1006 block 0 that is not release-ready: refused unless `rehearsal`;
/// * any other genesis: not this guard's concern (an unknown genesis gets no
///   genesis-keyed rule, see `citrate_consensus::hardening::genesis_rule_pin`).
pub fn r1006_boot_guard(
    chain_id: u64,
    profile: Option<&str>,
    running: Option<&[u8; 32]>,
    readiness: &citrate_economics::r1006::Readiness,
    rehearsal: bool,
) -> anyhow::Result<()> {
    let r1006 = citrate_consensus::hardening::R1006_GENESIS;
    let is_r1006 = running == Some(&r1006);
    if profile == Some(R1006_PROFILE) && !is_r1006 {
        anyhow::bail!(
            "[chain] genesis_profile = \"r1006\" but this data directory's block 0 ({}) is not \
             the r1006 genesis this build compiles ({}). Use a fresh data directory.",
            running.map(hex::encode).unwrap_or_else(|| "missing".into()),
            hex::encode(r1006)
        );
    }
    if !is_r1006 {
        return Ok(());
    }
    if chain_id != 40204 {
        anyhow::bail!("the r1006 genesis runs only on chain 40204 (configured: {chain_id})");
    }
    if readiness.is_release_ready() {
        return Ok(());
    }
    let missing = readiness.missing().join("; ");
    if rehearsal {
        tracing::warn!(
            "r1006 REHEARSAL genesis ({R1006_REHEARSAL_ENV}=1): not release-ready: {missing}"
        );
        return Ok(());
    }
    anyhow::bail!(
        "the r1006 genesis in this build is not release-ready: {missing}. It must not start a \
         network. For a local rehearsal only, set {R1006_REHEARSAL_ENV}=1."
    )
}

/// The ValidatorRegistry and activation height a node enforces. On the r1006 genesis with
/// its producer set filled, both are compiled (`compiled`): the env values
/// `CITRATE_VALIDATOR_REGISTRY` / `CITRATE_VALIDATOR_ACTIVATION_HEIGHT` may only repeat
/// them, and anything else refuses to start (a per-node value would split the fleet's
/// view of who may propose). Otherwise (`compiled` = None) the env decides, as before.
pub fn resolve_validator_registry(
    compiled: Option<([u8; 20], u64)>,
    env_registry: Option<&str>,
    env_activation: Option<&str>,
) -> anyhow::Result<Option<([u8; 20], u64)>> {
    let parse_reg = |raw: &str| -> anyhow::Result<[u8; 20]> {
        let b = hex::decode(raw.trim().trim_start_matches("0x"))
            .map_err(|e| anyhow::anyhow!("CITRATE_VALIDATOR_REGISTRY {raw}: {e}"))?;
        <[u8; 20]>::try_from(b.as_slice())
            .map_err(|_| anyhow::anyhow!("CITRATE_VALIDATOR_REGISTRY {raw}: not 20 bytes"))
    };
    let parse_act = |raw: &str| -> anyhow::Result<u64> {
        raw.trim()
            .parse::<u64>()
            .map_err(|e| anyhow::anyhow!("CITRATE_VALIDATOR_ACTIVATION_HEIGHT {raw}: {e}"))
    };
    match compiled {
        Some((reg, act)) => {
            if let Some(raw) = env_registry {
                if parse_reg(raw)? != reg {
                    anyhow::bail!(
                        "CITRATE_VALIDATOR_REGISTRY={raw} is not the ValidatorRegistry the r1006 \
                         genesis compiles (0x{}); remove it",
                        hex::encode(reg)
                    );
                }
            }
            if let Some(raw) = env_activation {
                if parse_act(raw)? != act {
                    anyhow::bail!(
                        "CITRATE_VALIDATOR_ACTIVATION_HEIGHT={raw} is not the r1006 genesis's \
                         compiled activation height {act}; remove it"
                    );
                }
            }
            Ok(Some((reg, act)))
        }
        None => match env_registry {
            None => Ok(None),
            Some(raw) => {
                let reg = parse_reg(raw)?;
                let act = env_activation.map(parse_act).transpose()?.unwrap_or(0);
                Ok(Some((reg, act)))
            }
        },
    }
}

/// Whether the rehearsal opt-in is set in the environment (exactly `1`).
pub fn r1006_rehearsal_from_env() -> bool {
    parse_r1006_rehearsal(std::env::var(R1006_REHEARSAL_ENV).ok().as_deref())
}

/// The opt-in value: exactly `1`; anything else (unset, empty, `true`, ` 1`) is off.
pub fn parse_r1006_rehearsal(v: Option<&str>) -> bool {
    v == Some("1")
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
        Some(R1006_PROFILE) => {
            tracing::info!("Using r1006 genesis profile (genesis from ceremony state)");
            EconomicsGenesisConfig::r1006()
                .map_err(|e| anyhow::anyhow!("invalid r1006 genesis: {e}"))?
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
        citrate_economics::genesis::initialize_shared_genesis_state(&executor, &economics_config)
            .map_err(|e| anyhow::anyhow!("invalid shared genesis configuration: {e}"))?;

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

    async fn build_profile(chain_id: u64, profile: Option<&str>) -> anyhow::Result<[u8; 32]> {
        use citrate_execution::StateDB;
        use citrate_storage::pruning::PruningConfig;
        let dir = tempfile::tempdir()?;
        let st = Arc::new(StorageManager::new(dir.path(), PruningConfig::default())?);
        let ex = Arc::new(Executor::with_storage_and_chain_id(
            Arc::new(StateDB::new()),
            Some(st.state.clone()),
            chain_id,
        ));
        let cfg = GenesisConfig {
            chain_id,
            ..Default::default()
        };
        let h = initialize_genesis_state_with_profile(st, ex, &cfg, profile).await?;
        Ok(*h.as_bytes())
    }

    #[test]
    fn r1006_boot_guard_cases() {
        use citrate_economics::r1006::Readiness;
        let r1006 = citrate_consensus::hardening::R1006_GENESIS;
        let r1005 = citrate_consensus::hardening::RELEASE_GENESIS[0].1;
        let unknown = [0x42u8; 32];
        let ready = Readiness {
            inputs_final: true,
            validators_final: true,
            orangeseed_present: true,
        };
        let not_ready = Readiness {
            validators_final: false,
            ..ready.clone()
        };
        let g =
            |p, run: Option<&[u8; 32]>, r: &Readiness, reh| r1006_boot_guard(40204, p, run, r, reh);
        // Release-ready r1006: boots without the opt-in.
        assert!(g(Some("r1006"), Some(&r1006), &ready, false).is_ok());
        // Not release-ready: refused, naming what is missing, unless it is a rehearsal.
        let e = g(Some("r1006"), Some(&r1006), &not_ready, false)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("not release-ready") && e.contains("producer set"),
            "{e}"
        );
        assert!(g(Some("r1006"), Some(&r1006), &not_ready, true).is_ok());
        // The r1006 block 0 is guarded whatever the configured profile says.
        assert!(g(None, Some(&r1006), &not_ready, false).is_err());
        // Profile r1006 on another genesis (r1005's, an unknown one, none): refused.
        for run in [Some(&r1005), Some(&unknown), None] {
            let e = g(Some("r1006"), run, &ready, true).unwrap_err().to_string();
            assert!(e.contains("is not the r1006 genesis"), "{e}");
        }
        // Another profile on another genesis: not this guard's concern.
        assert!(g(Some("testnet_beta"), Some(&r1005), &not_ready, false).is_ok());
        assert!(g(Some("default"), Some(&unknown), &not_ready, false).is_ok());
        // The r1006 block 0 on another chain id: refused.
        assert!(r1006_boot_guard(1337, Some("r1006"), Some(&r1006), &ready, false).is_err());
    }

    #[test]
    fn the_r1006_validator_set_is_compiled_not_per_node() {
        let reg = [0xAB; 20];
        let hex_reg = format!("0x{}", hex::encode(reg));
        let c = Some((reg, 1_000));
        assert_eq!(resolve_validator_registry(c, None, None).unwrap(), c);
        assert_eq!(
            resolve_validator_registry(c, Some(&hex_reg), Some("1000")).unwrap(),
            c
        );
        assert!(resolve_validator_registry(c, Some("0x".to_owned().as_str()), None).is_err());
        let other = format!("0x{}", hex::encode([0xCD; 20]));
        let e = resolve_validator_registry(c, Some(&other), None)
            .unwrap_err()
            .to_string();
        assert!(e.contains("not the ValidatorRegistry the r1006"), "{e}");
        let e = resolve_validator_registry(c, None, Some("800"))
            .unwrap_err()
            .to_string();
        assert!(e.contains("compiled activation height 1000"), "{e}");
        // Not compiled (another genesis, or a placeholder set): the env decides.
        assert_eq!(resolve_validator_registry(None, None, None).unwrap(), None);
        assert_eq!(
            resolve_validator_registry(None, Some(&other), Some("2000")).unwrap(),
            Some(([0xCD; 20], 2000))
        );
        assert!(resolve_validator_registry(None, Some("zz"), None).is_err());
    }

    #[test]
    fn the_rehearsal_opt_in_is_exactly_one() {
        assert!(parse_r1006_rehearsal(Some("1")));
        for v in [
            None,
            Some(""),
            Some("0"),
            Some("true"),
            Some("yes"),
            Some(" 1"),
            Some("1 "),
        ] {
            assert!(!parse_r1006_rehearsal(v), "{v:?}");
        }
    }

    /// r1006 must not reproduce r1005's block 0: the two networks are told apart by
    /// genesis hash (K6, the UI truth contract, the handshake), and r1005's compiled
    /// checkpoints are keyed by r1005's genesis, so they must not reach r1006.
    #[tokio::test]
    async fn r1006_profile_has_its_own_genesis_and_no_r1005_checkpoints() {
        use citrate_consensus::hardening::{canonical_checkpoints, RELEASE_GENESIS};
        let r1005 = RELEASE_GENESIS[0].1;
        let g = build_profile(40204, Some("r1006"))
            .await
            .expect("the r1006 genesis builds (rehearsal mode)");
        assert_ne!(
            g,
            r1005,
            "the r1006 profile reproduced r1005's block 0 {}",
            hex::encode(r1005)
        );
        assert!(
            canonical_checkpoints(&g).is_empty(),
            "r1005's checkpoints apply to r1006's genesis"
        );
        assert!(
            !canonical_checkpoints(&r1005).is_empty(),
            "negative control"
        );
    }

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
