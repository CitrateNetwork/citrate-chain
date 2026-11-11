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

/// The block 0 a genesis profile is compiled to produce, if this release pins one
/// (r1006 today). The genesis-keyed rules a genesis BUILD runs under are resolved
/// for it (`publish_mpt_rule_for_genesis_build` in main.rs, and the manifest
/// command); `None` is an unknown genesis (devnets, rehearsals), where the env or
/// config value decides, as start_node later decides for the block 0 it loads.
///
/// The r1007 genesis lane (S3-6) adds its profile here with the ceremony's
/// block-0 hash, next to its `GENESIS_ACTIVATIONS` entry (`mpt_state_root:
/// Some(0)`), so the r1007 block 0 is built and re-built under the MPT rule.
pub fn compiled_genesis_for_profile(profile: Option<&str>) -> Option<[u8; 32]> {
    match profile {
        Some(R1006_PROFILE) => Some(citrate_consensus::hardening::R1006_GENESIS),
        Some(R1007_PROFILE) => Some(citrate_consensus::hardening::R1007_GENESIS),
        _ => None,
    }
}

/// The r1007 genesis profile (ADR-2026-11-03 CV-2, S3-6): the r1006 ceremony state with
/// its own note, block 0 rooted under the MPT state root rule. Its block 0 is
/// `citrate_consensus::hardening::R1007_GENESIS`; its rules and chain parameters are the
/// genesis-keyed entries for that hash (docs/consensus/R1007_GENESIS.md).
pub const R1007_PROFILE: &str = "r1007";

/// The ValidatorRegistry binding compiled for the genesis a node runs: r1006 and r1007
/// (block 0 holds the same registry state and producer set) compile it once their
/// producer set is final; any other genesis gets `None` and the env decides
/// ([`resolve_validator_registry`]). Data source: `citrate_economics::r1006` /
/// `citrate_economics::r1007::validator_set_binding` (the compiled validators file).
pub fn compiled_validator_set(
    running_genesis: Option<&[u8; 32]>,
) -> anyhow::Result<Option<([u8; 20], u64)>> {
    use citrate_consensus::hardening::{R1006_GENESIS, R1007_GENESIS};
    match running_genesis {
        Some(g) if *g == R1006_GENESIS => citrate_economics::r1006::validator_set_binding()
            .map_err(|e| anyhow::anyhow!("invalid r1006 genesis: {e}")),
        Some(g) if *g == R1007_GENESIS => citrate_economics::r1007::validator_set_binding()
            .map_err(|e| anyhow::anyhow!("invalid r1007 genesis: {e}")),
        _ => Ok(None),
    }
}

/// On a genesis with compiled chain parameters (r1007), the node's `[checkpoint]`
/// interval, committee size and vote depth may only repeat them: a per-node value would
/// make this node propose, select and vote on other checkpoints than the fleet. `None`
/// (any other genesis): the config decides, as before. Data source: the compiled table
/// `citrate_consensus::genesis_params::GENESIS_CHAIN_PARAMS`.
pub fn check_checkpoint_params(
    params: Option<&citrate_consensus::genesis_params::GenesisChainParams>,
    checkpoint: &crate::config::CheckpointNodeConfig,
) -> anyhow::Result<()> {
    let Some(p) = params else {
        return Ok(());
    };
    let mut bad = Vec::new();
    if checkpoint.interval != p.checkpoint_interval {
        bad.push(format!(
            "interval = {} (compiled {})",
            checkpoint.interval, p.checkpoint_interval
        ));
    }
    if checkpoint.committee_size != p.committee_size {
        bad.push(format!(
            "committee_size = {} (compiled {})",
            checkpoint.committee_size, p.committee_size
        ));
    }
    if checkpoint.vote_depth != p.checkpoint_vote_depth {
        bad.push(format!(
            "vote_depth = {} (compiled {})",
            checkpoint.vote_depth, p.checkpoint_vote_depth
        ));
    }
    if bad.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "[checkpoint] {} differs from the chain parameters this genesis compiles; remove the \
         setting (a per-node value would split the fleet's checkpoints)",
        bad.join(", ")
    )
}

/// The start-up guard for the r1007 genesis (pure, unit tested), like
/// [`r1006_boot_guard`]: `running` is the data directory's block 0.
///
/// * profile `r1007` with another (or no) block 0: refused (a fresh data directory is
///   needed);
/// * the r1007 block 0 on another chain id: refused;
/// * the r1007 block 0 while the r1006 ceremony inputs it is built from are not
///   release-ready: refused unless `rehearsal` (`CITRATE_R1006_REHEARSAL=1`);
/// * any other genesis: not this guard's concern.
pub fn r1007_boot_guard(
    chain_id: u64,
    profile: Option<&str>,
    running: Option<&[u8; 32]>,
    readiness: &citrate_economics::r1006::Readiness,
    rehearsal: bool,
) -> anyhow::Result<()> {
    let r1007 = citrate_consensus::hardening::R1007_GENESIS;
    let is_r1007 = running == Some(&r1007);
    if profile == Some(R1007_PROFILE) && !is_r1007 {
        anyhow::bail!(
            "[chain] genesis_profile = \"r1007\" but this data directory's block 0 ({}) is not \
             the r1007 genesis this build compiles ({}). Use a fresh data directory.",
            running.map(hex::encode).unwrap_or_else(|| "missing".into()),
            hex::encode(r1007)
        );
    }
    if !is_r1007 {
        return Ok(());
    }
    if chain_id != 40204 {
        anyhow::bail!("the r1007 genesis runs only on chain 40204 (configured: {chain_id})");
    }
    if readiness.is_release_ready() {
        return Ok(());
    }
    let missing = readiness.missing().join("; ");
    if rehearsal {
        tracing::warn!(
            "r1007 genesis built from a REHEARSAL r1006 state ({R1006_REHEARSAL_ENV}=1): not \
             release-ready: {missing}"
        );
        return Ok(());
    }
    anyhow::bail!(
        "the r1007 genesis in this build is not release-ready: {missing}. It must not start a \
         network. For a local rehearsal only, set {R1006_REHEARSAL_ENV}=1."
    )
}

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
                         ceremony registered (0x{}), the compiled ValidatorRegistry of this \
                         genesis (r1006 and r1007 both compile it); remove it",
                        hex::encode(reg)
                    );
                }
            }
            if let Some(raw) = env_activation {
                if parse_act(raw)? != act {
                    anyhow::bail!(
                        "CITRATE_VALIDATOR_ACTIVATION_HEIGHT={raw} is not this genesis's \
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

/// A genesis validator set: `(proposer consensus key, stake)` per validator.
pub type GenesisCommittee = Vec<(PublicKey, u128)>;

/// The genesis validator set of the chain whose block 0 is `running_genesis`, as
/// `(proposer consensus key, stake)`: the epoch-0 checkpoint committee's input (spec 06
/// §7). It is compiled with the genesis, never read from config or env, so every node on
/// the same block 0 derives the same epoch-0 committee.
///
/// - r1006: the producer set `validators.json` registers in the ValidatorRegistry at
///   block 0 (`citrate_economics::r1006::genesis_validator_set`); `None` while that set
///   is a placeholder.
/// - r1007: the same set. Its block 0 registers the r1006 producers from the shared
///   validators file (R1007_GENESIS.md §3.3; producer keys are unchanged at r1007).
/// - Any other genesis (or none known): `None`. Such a chain's committees come only from
///   registry snapshots, from S(1) on. A new genesis adds its own arm here from its own
///   compiled validator file.
pub fn genesis_committee_set(
    running_genesis: Option<&[u8; 32]>,
) -> anyhow::Result<Option<GenesisCommittee>> {
    // r1007 registers the r1006 producers in its block 0 (the validators file
    // is shared, R1007_GENESIS.md §3.3), so both geneses compile the same set.
    let compiled = [
        citrate_consensus::hardening::R1006_GENESIS,
        citrate_consensus::hardening::R1007_GENESIS,
    ];
    if !running_genesis.is_some_and(|g| compiled.contains(g)) {
        return Ok(None);
    }
    let set = citrate_economics::r1006::genesis_validator_set()
        .map_err(|e| anyhow::anyhow!("invalid r1006 genesis validator set: {e}"))?;
    Ok(set.map(|v| {
        v.into_iter()
            .map(|(key, stake)| (PublicKey::new(key), stake))
            .collect()
    }))
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
/// - `Some("default")` — devnet accounts
/// - `None` — infer from chain_id (backward compatible)
///
/// Any other name is refused. A profile this build does not compile (a typo, or a
/// network whose genesis is not in this release) must never fall back to the chain-id
/// default: on 40204 that default is another network's release genesis.
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
        Some(R1007_PROFILE) => {
            tracing::info!(
                "Using r1007 genesis profile (r1006 ceremony state, MPT state root from block 0)"
            );
            EconomicsGenesisConfig::r1007()
                .map_err(|e| anyhow::anyhow!("invalid r1007 genesis: {e}"))?
        }
        Some(other) => {
            anyhow::bail!(
                "[chain] genesis_profile = {other:?} is not compiled into this build (known: \
                 default, testnet_beta, team_testnet, mainnet, r1006, r1007); refusing to build a \
                 genesis instead of falling back to the chain-id default"
            );
        }
        None => {
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

/// The MPT state root rule is process-wide, so the r1007 genesis builds in tests run in a
/// child process (the split_heal pattern): the parent's tests keep the legacy root. Any
/// test that needs the r1007 block 0 built by the node path runs
/// `genesis::tests::r1007_child_build_after_publication` with this set.
#[cfg(test)]
pub(crate) const R1007_CHILD_ENV: &str = "CITRATE_R1007_GENESIS_CHILD";

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

    async fn build_with_profile(chain_id: u64, profile: Option<&str>) -> anyhow::Result<Hash> {
        build_profile(chain_id, profile).await.map(Hash::new)
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

    /// A profile this build does not compile (for example `r1006` before its genesis
    /// lands, or a typo) is refused. It must never fall back to the chain-id default,
    /// which on 40204 is the release genesis of another network.
    #[tokio::test]
    async fn an_unknown_genesis_profile_is_refused_not_inferred() {
        for p in ["R1006", "testnet-beta", "TESTNET_BETA", "", "default "] {
            let e = match build_with_profile(40204, Some(p)).await {
                Ok(h) => panic!(
                    "genesis_profile {p:?} built block 0 {} instead of being refused",
                    hex::encode(h.as_bytes())
                ),
                Err(e) => format!("{e:#}"),
            };
            assert!(e.contains("genesis_profile"), "{e}");
        }
    }

    /// Negative control: the known profiles, and no profile at all, still build.
    #[tokio::test]
    async fn known_genesis_profiles_still_build() {
        for p in [
            None,
            Some("default"),
            Some("testnet_beta"),
            Some("team_testnet"),
            Some("mainnet"),
        ] {
            build_with_profile(40204, p)
                .await
                .expect("known profile builds");
        }
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

    /// The canonical genesis as `initialize_genesis_state_with_profile` stores it:
    /// state root set, block hash from `calculate_block_hash` (the canonical
    /// genesis encoding).
    fn stored_genesis() -> Block {
        let mut g = create_genesis_block(&GenesisConfig::default());
        g.state_root = Hash::new([0x5A; 32]);
        g.header.block_hash = calculate_block_hash(&g);
        g
    }

    /// CV-9 / H5: at startup the node re-offers the genesis it stored to the
    /// strict production DAG store (`seed_genesis`, and the eager load when
    /// nothing is pruned). Configured by its hash, genesis is exempt from the
    /// proposer/VRF admission checks. Before the fix the exemption also
    /// required `verify_hash()`, which recomputes the hash with the block-hash
    /// encoding, while genesis is hashed with the canonical genesis encoding,
    /// so the exemption never held and the store refused genesis with "zero
    /// proposer public key".
    #[tokio::test]
    async fn genesis_reoffered_to_strict_store_is_exempt() {
        let genesis = stored_genesis();
        assert!(
            !genesis.verify_hash(),
            "fixture: the stored genesis is hashed with the canonical genesis encoding"
        );
        let dag = DagStore::new(); // strict VRF, as start_node builds it
        dag.set_configured_genesis(genesis.header.block_hash);
        dag.set_slot_origin(&genesis.header)
            .expect("r1007 G9: bind the slot origin from genesis, as start_node does");
        dag.store_block(genesis.clone())
            .await
            .expect("the configured genesis must be admitted by the strict store");
        // Re-offered again (a second startup pass): already present, not invalid.
        match dag.store_block(genesis).await {
            Err(citrate_consensus::DagStoreError::BlockExists(_)) => {}
            other => panic!("a re-offered genesis must be BlockExists, got {other:?}"),
        }
    }

    /// The exemption is by identity, not by the hash field: a height-0 block
    /// that names the configured hash but carries other content is not genesis.
    #[tokio::test]
    async fn a_block_that_only_names_the_genesis_hash_is_not_exempt() {
        let genesis = stored_genesis();
        // Content the canonical genesis hash binds, changed.
        let mut forged_root = genesis.clone();
        forged_root.state_root = Hash::new([0x6B; 32]);
        // Content it does not bind (the proposer), changed: a non-inert genesis.
        let mut forged_proposer = genesis.clone();
        forged_proposer.header.proposer_pubkey = PublicKey::new([0x77; 32]);
        for (name, forged) in [("state root", forged_root), ("proposer", forged_proposer)] {
            assert!(
                !forged.is_configured_genesis(Some(genesis.header.block_hash)),
                "a genesis with a forged {name} passed as the configured genesis"
            );
            let dag = DagStore::new();
            dag.set_configured_genesis(genesis.header.block_hash);
            dag.set_slot_origin(&genesis.header)
                .expect("r1007 G9: bind the slot origin from genesis, as start_node does");
            assert!(
                dag.store_block(forged).await.is_err(),
                "the strict store admitted a genesis with a forged {name}"
            );
        }
    }

    // ---- r1007 (ADR-2026-11-03 CV-2, S3-6; docs/consensus/R1007_GENESIS.md) ----

    use super::R1007_CHILD_ENV;

    fn r1007_child(test: &str) {
        let exe = std::env::current_exe().expect("exe");
        let out = std::process::Command::new(exe)
            .args([test, "--exact", "--nocapture", "--test-threads=1"])
            .env(R1007_CHILD_ENV, "1")
            .env_remove(citrate_execution::mpt_state_root::MPT_STATE_ROOT_ENV)
            .output()
            .expect("spawn child");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "child {test} failed:\n{stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn the_r1007_profile_is_compiled_to_its_block_0() {
        use citrate_consensus::hardening::{R1006_GENESIS, R1007_GENESIS};
        assert_eq!(
            compiled_genesis_for_profile(Some(R1007_PROFILE)),
            Some(R1007_GENESIS)
        );
        assert_eq!(
            compiled_genesis_for_profile(Some(R1006_PROFILE)),
            Some(R1006_GENESIS)
        );
        for p in [None, Some("default"), Some("testnet_beta"), Some("R1007")] {
            assert_eq!(compiled_genesis_for_profile(p), None, "{p:?}");
        }
    }

    /// The node's genesis build for profile `r1007`: the MPT rule is published for the
    /// block 0 the profile compiles (main.rs `publish_mpt_rule_for_genesis_build`), and the
    /// build then produces exactly `R1007_GENESIS` (the fresh-keys alloc, D-K3 done).
    #[test]
    fn r1007_profile_builds_the_pinned_block_0_under_the_published_rule() {
        r1007_child("genesis::tests::r1007_child_build_after_publication");
    }

    #[test]
    fn r1007_child_build_after_publication() {
        if std::env::var(R1007_CHILD_ENV).is_err() {
            return;
        }
        crate::publish_mpt_rule_for_genesis_build(40204, Some(R1007_PROFILE), None)
            .expect("the r1007 rule publishes");
        assert_eq!(
            citrate_execution::mpt_state_root::mpt_state_root_height(),
            Some(0)
        );
        let rt = tokio::runtime::Runtime::new().expect("rt");
        let g = rt
            .block_on(build_profile(40204, Some(R1007_PROFILE)))
            .expect("the r1007 genesis builds from the fresh-keys alloc");
        assert_eq!(
            g,
            citrate_consensus::hardening::R1007_GENESIS,
            "the node built 0x{} for profile r1007",
            hex::encode(g)
        );
        // A configured per-node height that disagrees with the compiled one is refused.
        assert!(
            crate::publish_mpt_rule_for_genesis_build(40204, Some(R1007_PROFILE), Some(5)).is_err()
        );
    }

    /// Without the rule published (a caller that skipped the publication) the r1007 build
    /// is refused, never built under the legacy root. Under D-K3 the pending keys refuse
    /// it first; the MPT guard on the layout itself is
    /// `r1007_genesis_state_refuses_to_build_without_the_mpt_rule` (economics).
    #[test]
    fn r1007_profile_build_refuses_without_the_published_rule() {
        r1007_child("genesis::tests::r1007_child_build_without_publication");
    }

    #[test]
    fn r1007_child_build_without_publication() {
        if std::env::var(R1007_CHILD_ENV).is_err() {
            return;
        }
        citrate_execution::mpt_state_root::set_mpt_state_root_height(None);
        let rt = tokio::runtime::Runtime::new().expect("rt");
        let e = rt
            .block_on(build_profile(40204, Some(R1007_PROFILE)))
            .expect_err("refused")
            .to_string();
        assert!(e.contains("D-K3") || e.contains("MPT state root"), "{e}");
    }

    /// S3-6 genesis tripwire (fed#465 §7.1): `ValidatorRegistry.activeSet()`
    /// read against the r1007 block-0 state equals the compiled epoch-0
    /// committee (`genesis_committee_set`, from the validators file), key for
    /// key and stake for stake. The registry state delta and the list are built
    /// from one file today; this fails if a future alloc (D-K3 fresh keys)
    /// changes one without the other. Runs on the r1007 layout the build has
    /// (the r1006-keys candidate) under the MPT rule, in a child process.
    #[test]
    fn r1007_block0_active_set_is_the_genesis_committee() {
        r1007_child("genesis::tests::r1007_child_block0_active_set");
    }

    #[test]
    fn r1007_child_block0_active_set() {
        if std::env::var(R1007_CHILD_ENV).is_err() {
            return;
        }
        use citrate_consensus::types::{BlockBuilder, Signature, Transaction};
        use citrate_execution::StateDB;
        citrate_execution::mpt_state_root::set_mpt_state_root_height(Some(0));
        let cfg = EconomicsGenesisConfig::r1007().expect("the r1007 genesis");
        let ex = Arc::new(Executor::with_chain_id(Arc::new(StateDB::new()), 40204));
        citrate_economics::genesis::initialize_shared_genesis_state(&ex, &cfg)
            .expect("r1007 block-0 state");
        let (registry, _) = citrate_economics::r1007::validator_set_binding()
            .expect("binding")
            .expect("the r1007 genesis registers a final producer set");
        let mut to = [0u8; 32];
        to[..20].copy_from_slice(&registry);
        let mut from = [0u8; 32];
        from[19] = 1;
        let mut tx = Transaction {
            hash: Hash::default(),
            nonce: 0,
            from: PublicKey::new(from),
            to: Some(PublicKey::new(to)),
            value: 0,
            gas_limit: 50_000_000,
            gas_price: 1,
            data: crate::registry_sync::active_set_selector().to_vec(),
            signature: Signature::new([0u8; 64]),
            tx_type: None,
            ..Default::default()
        };
        tx.determine_type();
        let blk = BlockBuilder::new()
            .base_fee_per_gas(1_000_000_000)
            .height(0)
            .build_unhashed();
        let rt = tokio::runtime::Runtime::new().expect("rt");
        let receipt = rt
            .block_on(ex.simulate_transaction(&blk, &tx))
            .expect("activeSet() at block 0");
        assert!(
            receipt.status,
            "activeSet() reverted: {:?}",
            receipt.revert_reason
        );
        let mut on_chain: Vec<(PublicKey, u128)> =
            crate::registry_sync::decode_active_set(&receipt.output)
                .expect("decode activeSet")
                .into_iter()
                .map(|(k, st)| (PublicKey::new(k), st))
                .collect();
        let mut compiled =
            genesis_committee_set(Some(&citrate_consensus::hardening::R1007_GENESIS))
                .expect("validators file")
                .expect("the r1007 epoch-0 committee");
        on_chain.sort_by_key(|(k, st)| (k.0, *st));
        compiled.sort_by_key(|(k, st)| (k.0, *st));
        assert_eq!(compiled.len(), 7, "the seven producers");
        assert_eq!(
            on_chain, compiled,
            "block 0's activeSet() must equal the compiled epoch-0 committee"
        );
    }

    /// The node builds the r1007 block 0 at the r1007 genesis timestamp (the ceremony
    /// stamps it), not at the shared canonical one its GenesisConfig carries.
    #[test]
    fn the_r1007_profile_stamps_block_0_with_the_r1007_genesis_timestamp() {
        let src = include_str!("genesis.rs");
        let build = src
            .find("pub async fn initialize_genesis_state_with_profile(")
            .expect("the profile build");
        let body = &src[build..build + 1_200];
        assert!(
            body.contains("citrate_economics::r1007::GENESIS_TIMESTAMP"),
            "the r1007 profile must use r1007::GENESIS_TIMESTAMP for block 0"
        );
    }

    #[test]
    fn r1007_boot_guard_cases() {
        use citrate_consensus::hardening::{R1006_GENESIS, R1007_GENESIS, RELEASE_GENESIS};
        use citrate_economics::r1006::Readiness;
        let r1005 = RELEASE_GENESIS[0].1;
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
            |p, run: Option<&[u8; 32]>, r: &Readiness, reh| r1007_boot_guard(40204, p, run, r, reh);
        assert!(g(Some("r1007"), Some(&R1007_GENESIS), &ready, false).is_ok());
        let e = g(Some("r1007"), Some(&R1007_GENESIS), &not_ready, false)
            .unwrap_err()
            .to_string();
        assert!(e.contains("not release-ready"), "{e}");
        assert!(g(Some("r1007"), Some(&R1007_GENESIS), &not_ready, true).is_ok());
        assert!(g(None, Some(&R1007_GENESIS), &not_ready, false).is_err());
        // Profile r1007 on another block 0 (r1006's, r1005's, unknown, none): refused.
        for run in [Some(&R1006_GENESIS), Some(&r1005), Some(&[0x42; 32]), None] {
            let e = g(Some("r1007"), run, &ready, true).unwrap_err().to_string();
            assert!(e.contains("is not the r1007 genesis"), "{e}");
        }
        // The r1007 block 0 under another profile name still runs (the name is display).
        assert!(g(Some("r1006"), Some(&R1007_GENESIS), &ready, false).is_ok());
        assert!(g(Some("testnet_beta"), Some(&r1005), &not_ready, false).is_ok());
        assert!(
            r1007_boot_guard(1337, Some("r1007"), Some(&R1007_GENESIS), &ready, false).is_err()
        );
        // And the r1006 guard leaves the r1007 block 0 alone.
        assert!(r1006_boot_guard(40204, None, Some(&R1007_GENESIS), &not_ready, false).is_ok());
    }

    /// The same producer set, the same ValidatorRegistry, compiled: on r1007 the env may
    /// only repeat it, as on r1006, so registry snapshots and the finality committee form
    /// from the same set on every node.
    #[test]
    fn the_r1007_validator_set_is_compiled_like_r1006() {
        use citrate_consensus::hardening::{R1006_GENESIS, R1007_GENESIS};
        let r7 = compiled_validator_set(Some(&R1007_GENESIS)).expect("binding");
        let r6 = compiled_validator_set(Some(&R1006_GENESIS)).expect("binding");
        assert!(r7.is_some(), "r1007 compiles its registry binding");
        assert_eq!(r7, r6, "same registry, same activation height");
        assert_eq!(
            compiled_validator_set(Some(&[0x42; 32])).expect("none"),
            None
        );
        assert_eq!(compiled_validator_set(None).expect("none"), None);
        let (reg, act) = r7.expect("some");
        let e =
            resolve_validator_registry(r7, Some(&format!("0x{}", hex::encode([0xCD; 20]))), None)
                .unwrap_err()
                .to_string();
        assert!(e.contains("compiled ValidatorRegistry"), "{e}");
        assert_eq!(
            resolve_validator_registry(
                r7,
                Some(&format!("0x{}", hex::encode(reg))),
                Some(&act.to_string())
            )
            .expect("repeat ok"),
            r7
        );
    }

    /// The undo window is the prune retention (CV-7a), and the r1007 chain parameters
    /// name exactly the constants the node and storage run with.
    #[test]
    fn r1007_undo_window_is_the_compiled_retention() {
        let p = citrate_consensus::genesis_params::R1007_CHAIN_PARAMS;
        assert_eq!(p.undo_window, crate::canonical_apply::MAX_REORG_DEPTH);
        assert_eq!(
            p.undo_window,
            citrate_storage::state::state_store::REORG_UNDO_DEPTH
        );
        assert_eq!(p.pruning_depth, crate::dag_prune::MIN_RETAIN_BLOCKS);
        assert_eq!(p.pruning_depth, crate::dag_prune::DEFAULT_RETAIN_BLOCKS);
        assert_eq!(
            p.validator_activation_height,
            citrate_economics::r1006::R1006_VALIDATOR_ACTIVATION_HEIGHT
        );
        assert_eq!(
            p.include_gas_limit,
            crate::producer::PRODUCER_BLOCK_GAS_LIMIT,
            "INCLUDE_GAS_LIMIT"
        );
    }

    /// On a genesis with compiled chain parameters the node's `[checkpoint]` section may
    /// only repeat them: a per-node interval, committee size or vote depth would split
    /// the fleet's checkpoints. Elsewhere the config decides, as before.
    #[test]
    fn r1007_checkpoint_config_must_match_the_compiled_params() {
        use crate::config::CheckpointNodeConfig;
        let p = citrate_consensus::genesis_params::R1007_CHAIN_PARAMS;
        let ok = CheckpointNodeConfig::default();
        assert!(check_checkpoint_params(Some(&p), &ok).is_ok());
        for (name, bad) in [
            (
                "interval",
                CheckpointNodeConfig {
                    interval: 2,
                    ..ok.clone()
                },
            ),
            (
                "committee_size",
                CheckpointNodeConfig {
                    committee_size: 10,
                    ..ok.clone()
                },
            ),
            (
                "vote_depth",
                CheckpointNodeConfig {
                    vote_depth: 1,
                    ..ok.clone()
                },
            ),
        ] {
            let e = check_checkpoint_params(Some(&p), &bad)
                .unwrap_err()
                .to_string();
            assert!(e.contains(name), "{name}: {e}");
        }
        assert!(check_checkpoint_params(None, &CheckpointNodeConfig { interval: 2, ..ok }).is_ok());
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

    /// Epoch 0 (lead decision 1, 2026-11-09): the checkpoint committee below the
    /// first registry snapshot S(1) comes from the genesis validator set, which
    /// is compiled with the genesis (no config). On r1006 it is exactly the
    /// producer set `validators.json` registers in the ValidatorRegistry at
    /// block 0: each proposer key with its stake. Any other genesis compiles
    /// none (its committees come only from registry snapshots).
    #[test]
    fn genesis_committee_is_the_block_0_validator_set() {
        let r1006 = citrate_consensus::hardening::R1006_GENESIS;
        let set = genesis_committee_set(Some(&r1006))
            .expect("the r1006 validator file parses")
            .expect("r1006 compiles a final producer set");
        let file: serde_json::Value =
            serde_json::from_str(citrate_economics::r1006::R1006_VALIDATORS_JSON)
                .expect("validators.json is JSON");
        let want: Vec<(PublicKey, u128)> = file["validators"]
            .as_array()
            .expect("a validators array")
            .iter()
            .map(|v| {
                let pk = hex::decode(
                    v["proposer_pubkey"]
                        .as_str()
                        .expect("proposer_pubkey")
                        .trim_start_matches("0x"),
                )
                .expect("hex proposer key");
                let pk: [u8; 32] = pk.as_slice().try_into().expect("32-byte proposer key");
                let stake: u128 = v["stake_wei"]
                    .as_str()
                    .expect("stake_wei")
                    .parse()
                    .expect("stake fits u128");
                (PublicKey::new(pk), stake)
            })
            .collect();
        assert_eq!(want.len(), 7, "the r1006 producer set");
        assert_eq!(set, want);
        assert!(set.iter().all(|(_, s)| *s > 0));
        assert_eq!(
            genesis_committee_set(Some(&[0x42; 32])).expect("unknown genesis"),
            None
        );
        assert_eq!(genesis_committee_set(None).expect("no genesis"), None);
    }

    /// r1007 (R1007_GENESIS.md §3.3, integration item §5.2): the r1007 block 0
    /// registers the same producers as r1006 (the validators file is shared),
    /// so its epoch-0 committee is the same set. Without this arm r1007 votes
    /// form only from the first registry snapshot S(1) = 800.
    #[test]
    fn r1007_genesis_committee_is_the_shared_validator_set() {
        let r1006 = citrate_consensus::hardening::R1006_GENESIS;
        let r1007 = citrate_consensus::hardening::R1007_GENESIS;
        let want = genesis_committee_set(Some(&r1006))
            .expect("the r1006 validator file parses")
            .expect("r1006 compiles a final producer set");
        let got = genesis_committee_set(Some(&r1007))
            .expect("the shared validator file parses")
            .expect("r1007 compiles its epoch-0 committee");
        assert_eq!(got, want);
    }
}
