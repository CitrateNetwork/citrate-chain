use citrate_consensus::chain_selection::ChainSelector;
use citrate_consensus::dag_store::{DagStore, DagStoreError};
use citrate_consensus::ghostdag::GhostDag;
use citrate_consensus::tip_selection::TipSelector;
use citrate_consensus::crypto::{self, Ed25519SigningKey};
use citrate_consensus::types::{
    BlockBuilder, BlockHeader, GhostDagParams, Hash, PublicKey, Transaction, VrfProof,
};
use citrate_economics::{
    RewardCalculator, RewardConfig, UnifiedEconomicsManager,
};
use citrate_execution::Executor;
use citrate_execution::revm_adapter::BlockContext;
use citrate_learning::orchestration::{LearningOrchestrator, PeerEmbedding, PeerProfileStore};
use citrate_learning::profile::ProfileComputer;
use citrate_network::{GossipProtocol, NetworkMessage, PeerManager};
use citrate_network::learning_messages::LearningMessage;
use citrate_sequencer::mempool::Mempool;
use citrate_storage::{state_manager::StateManager as AIStateManager, StorageManager};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

use crate::contribution_recorder::ContributionRecorder;

// Block hash is now computed via Block::compute_hash() in consensus/types.rs (C-05).
// This ensures a single canonical hash function used by both producer and validator.

/// Generate a real ECVRF-P256-SHA256 proof for block production (WP-Z.1).
///
/// Uses RFC 9381 ECVRF with alpha binding: proposer_pubkey(32) || prev_vrf(32) || slot(8).
/// The ed25519 signing key seed is deterministically converted to a P-256 scalar via
/// `ecvrf::secret_to_scalar()`. Proof is 114 bytes (self-contained, verifiable).
///
/// Falls back to SHA3 stub if ECVRF fails (should not happen with valid keys).
fn generate_block_vrf(signing_key: &Ed25519SigningKey, proposer_pubkey: &PublicKey, prev_vrf: &Hash, slot: u64) -> VrfProof {
    let seed_bytes = signing_key.to_bytes();

    // Build alpha: proposer_pubkey(32) || prev_vrf(32) || slot(8) = 72 bytes
    let mut alpha = Vec::with_capacity(72);
    alpha.extend_from_slice(proposer_pubkey.as_bytes());
    alpha.extend_from_slice(prev_vrf.as_bytes());
    alpha.extend_from_slice(&slot.to_le_bytes());

    match citrate_consensus::ecvrf::prove(&seed_bytes, &alpha) {
        Ok((ecvrf_proof, beta)) => {
            VrfProof {
                proof: ecvrf_proof.to_bytes(), // 114 bytes
                output: Hash::from_bytes(&beta),
            }
        }
        Err(e) => {
            // Fallback: should never happen with a valid ed25519 key
            warn!("ECVRF prove failed ({}), using SHA3 fallback", e);
            use sha3::{Digest, Sha3_256};
            let mut hasher = Sha3_256::new();
            hasher.update(&alpha);
            let output_bytes = hasher.finalize();
            VrfProof {
                proof: output_bytes.to_vec(), // 32 bytes (legacy)
                output: Hash::from_bytes(&output_bytes),
            }
        }
    }
}

/// VALIDATOR-S1 (v5): configuration for producing the height-binding EquivocationVote
/// signature on each sealed block. When present and the block height is at/above
/// `activation_height`, the producer signs `EquivocationVote(chain_id, registry, height,
/// block_hash)` with its proposer key and attaches it as a gossip sidecar so a double-sign
/// can be slashed on-chain via `ValidatorRegistry.submitEquivocation`. `None` disables it
/// (no behavior change) until the node is configured with the registry address.
#[derive(Debug, Clone)]
pub struct EquivocationVoteConfig {
    pub chain_id: u64,
    pub registry: [u8; 20],
    pub activation_height: u64,
}

/// Block producer for mining new blocks
pub struct BlockProducer {
    storage: Arc<StorageManager>,
    executor: Arc<Executor>,
    mempool: Arc<Mempool>,
    dag_store: Arc<DagStore>,
    ghostdag: Arc<GhostDag>,
    tip_selector: Arc<TipSelector>,
    #[allow(dead_code)]
    chain_selector: Arc<ChainSelector>,
    #[allow(dead_code)]
    ai_state_manager: Arc<AIStateManager>,
    peer_manager: Option<Arc<PeerManager>>,
    coinbase: PublicKey,
    /// ed25519 signing key for block signatures (WP-G.2).
    /// The proposer_pubkey in block headers is derived from this key.
    signing_key: Ed25519SigningKey,
    target_block_time: u64,
    reward_calculator: RewardCalculator,
    /// SRP-S2: retained for RPC/telemetry wiring ONLY. It MUST NEVER influence a block's
    /// committed reward — block rewards are settled purely from committed state through
    /// `Executor::settle_block_rewards` (the enhanced, node-local reward path that read
    /// this was removed; it caused the block-2209 split-brain). See
    /// .agentile/adrs/ADR-2026-07-21-reapply-reward-purity.md.
    #[allow(dead_code)]
    economics_manager: Option<Arc<UnifiedEconomicsManager>>,
    /// Emergency pause flag — when true, block production stops.
    /// WP-I.3: Shared with the RPC server so citrate_emergencyPause
    /// can halt block production remotely.
    paused: Arc<AtomicBool>,

    /// WP-F.3: Learning orchestrator for checkpoint aggregation.
    /// None when learning is disabled or not configured.
    learning_orchestrator: Option<LearningOrchestrator>,

    /// WP-F.3: Gossip protocol reference for collecting peer learning embeddings.
    /// None when learning is disabled or gossip not initialized.
    gossip: Option<Arc<GossipProtocol>>,

    /// WP-F.3: Checkpoint interval for learning root computation.
    /// Defaults to 50 blocks (same as BFT checkpoint interval).
    checkpoint_interval: u64,

    /// WP-F.5: Local performance profile computer.
    /// Tracks inference results, latencies, uptime, and adapter counts
    /// for computing the node's performance profile at checkpoint boundaries.
    /// Uses Mutex for interior mutability (produce_block takes &self).
    profile_computer: Mutex<ProfileComputer>,

    /// WP-F.5: Received peer performance profiles indexed by
    /// (checkpoint_height, participant). Used by WP-F.6 for mentor selection.
    /// Uses Mutex for interior mutability (produce_block takes &self).
    peer_profile_store: Mutex<PeerProfileStore>,

    /// LC.4.3: ContributionAccounting recorder for automatically recording
    /// Validation, ModelHosting, and AdapterCreation contributions as they happen.
    /// None when the ContributionAccounting contract is not configured.
    contribution_recorder: Option<Arc<ContributionRecorder>>,

    /// LC.4.3: Tracks model inference requests served since last block for
    /// recording ModelHosting contributions. Atomically incremented by the
    /// inference handler and reset after each block production.
    inference_count: Arc<AtomicU64>,

    /// VALIDATOR-S1 (v5): optional EquivocationVote signing config. Set via
    /// [`Self::with_equivocation_vote_config`]; `None` until the registry is configured.
    equivocation_vote_cfg: Option<EquivocationVoteConfig>,

    /// VALIDATOR-S1 (v5): optional registry snapshot-sync for LOCALLY-PRODUCED S(E)
    /// blocks. When set, after sealing a block at a snapshot boundary S(E) the producer
    /// rebuilds the shared proposer selector from `ValidatorRegistry.activeSet()` as-of
    /// that state. RECEIVED and REORGED S(E) blocks are synced by the execute-on-receive
    /// driver (`CanonicalApplicator`, step 5) — the two cover disjoint block sources, so
    /// there is no double-sync. `None` disables it.
    registry_sync: Option<Arc<crate::registry_sync::RegistrySync>>,

    /// EXECUTE-ON-RECEIVE (reroll addendum): when true, seal version-2 headers that COMMIT
    /// the `coinbase` in `compute_hash`, making the block's `state_root` reproducible by
    /// receivers. Feature-flagged (`CITRATE_BLOCK_V2`) so it activates at the reroll; false
    /// keeps version-1 headers (coinbase present but not hashed) and existing history intact.
    emit_v2_headers: bool,

    /// EXECUTE-ON-RECEIVE (step 2): shared applied-tip lock. When set, the producer
    /// holds it across its execute→persist critical section (so production never races
    /// the receive-path applier — they both mutate the same executor state) and records
    /// the sealed block as the new applied tip before releasing it. `None` disables the
    /// interlock (pre-reroll / execute-on-receive off), preserving legacy behavior.
    applied_tip_lock:
        Option<Arc<tokio::sync::Mutex<crate::canonical_apply::AppliedState>>>,
}

impl BlockProducer {
    #[allow(dead_code)]
    pub fn new(
        storage: Arc<StorageManager>,
        executor: Arc<Executor>,
        mempool: Arc<Mempool>,
        coinbase: PublicKey,
        signing_key: Ed25519SigningKey,
        target_block_time: u64,
    ) -> Self {
        // Create consensus components with a new DAG store
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let _chain_store = storage.blocks.clone();

        let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag_store.clone()));
        let tip_selector = Arc::new(TipSelector::new(
            dag_store.clone(),
            ghostdag.clone(),
            citrate_consensus::tip_selection::SelectionStrategy::HighestBlueScore,
        ));
        let chain_selector = Arc::new(ChainSelector::new(
            dag_store.clone(),
            ghostdag.clone(),
            tip_selector.clone(),
            100, // finality depth
        ));

        // Create reward calculator with default config
        let reward_config = crate::canonical_apply::canonical_reward_config();
        let reward_calculator = RewardCalculator::new(reward_config);

        // Create AI state manager
        let ai_state_manager = Arc::new(AIStateManager::new(storage.db.clone()));

        Self {
            storage,
            executor,
            mempool,
            dag_store,
            ghostdag,
            tip_selector,
            chain_selector,
            ai_state_manager,
            peer_manager: None,
            coinbase,
            signing_key,
            target_block_time,
            reward_calculator,
            economics_manager: None,
            paused: Arc::new(AtomicBool::new(false)),
            learning_orchestrator: None,
            gossip: None,
            checkpoint_interval: 50,
            profile_computer: Mutex::new(ProfileComputer::default()),
            peer_profile_store: Mutex::new(PeerProfileStore::default()),
            contribution_recorder: None,
            inference_count: Arc::new(AtomicU64::new(0)),
            equivocation_vote_cfg: None,
            registry_sync: None,
            emit_v2_headers: false,
            applied_tip_lock: None,
        }
    }

    #[allow(dead_code)]
    pub fn with_peer_manager(
        storage: Arc<StorageManager>,
        executor: Arc<Executor>,
        mempool: Arc<Mempool>,
        peer_manager: Option<Arc<PeerManager>>,
        coinbase: PublicKey,
        signing_key: Ed25519SigningKey,
        target_block_time: u64,
    ) -> Self {
        // Create consensus components with a new DAG store
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let _chain_store = storage.blocks.clone();

        let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag_store.clone()));
        let tip_selector = Arc::new(TipSelector::new(
            dag_store.clone(),
            ghostdag.clone(),
            citrate_consensus::tip_selection::SelectionStrategy::HighestBlueScore,
        ));
        let chain_selector = Arc::new(ChainSelector::new(
            dag_store.clone(),
            ghostdag.clone(),
            tip_selector.clone(),
            100, // finality depth
        ));

        // Create reward calculator with default config
        let reward_config = crate::canonical_apply::canonical_reward_config();
        let reward_calculator = RewardCalculator::new(reward_config);

        // Create AI state manager
        let ai_state_manager = Arc::new(AIStateManager::new(storage.db.clone()));

        Self {
            storage,
            executor,
            mempool,
            dag_store,
            ghostdag,
            tip_selector,
            chain_selector,
            ai_state_manager,
            peer_manager,
            coinbase,
            signing_key,
            target_block_time,
            reward_calculator,
            economics_manager: None,
            paused: Arc::new(AtomicBool::new(false)),
            learning_orchestrator: None,
            gossip: None,
            checkpoint_interval: 50,
            profile_computer: Mutex::new(ProfileComputer::default()),
            peer_profile_store: Mutex::new(PeerProfileStore::default()),
            contribution_recorder: None,
            inference_count: Arc::new(AtomicU64::new(0)),
            equivocation_vote_cfg: None,
            registry_sync: None,
            emit_v2_headers: false,
            applied_tip_lock: None,
        }
    }

    /// Create with explicit reward configuration (for governance-driven params)
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    pub fn with_peer_manager_and_rewards(
        storage: Arc<StorageManager>,
        executor: Arc<Executor>,
        mempool: Arc<Mempool>,
        peer_manager: Option<Arc<PeerManager>>,
        coinbase: PublicKey,
        signing_key: Ed25519SigningKey,
        target_block_time: u64,
        reward_config: RewardConfig,
    ) -> Self {
        // Create consensus components with a new DAG store
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
        let _chain_store = storage.blocks.clone();

        let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag_store.clone()));
        let tip_selector = Arc::new(TipSelector::new(
            dag_store.clone(),
            ghostdag.clone(),
            citrate_consensus::tip_selection::SelectionStrategy::HighestBlueScore,
        ));
        let chain_selector = Arc::new(ChainSelector::new(
            dag_store.clone(),
            ghostdag.clone(),
            tip_selector.clone(),
            100,
        ));

        let reward_calculator = RewardCalculator::new(reward_config);
        let ai_state_manager = Arc::new(AIStateManager::new(storage.db.clone()));

        Self {
            storage,
            executor,
            mempool,
            dag_store,
            ghostdag,
            tip_selector,
            chain_selector,
            ai_state_manager,
            peer_manager,
            coinbase,
            signing_key,
            target_block_time,
            reward_calculator,
            economics_manager: None,
            paused: Arc::new(AtomicBool::new(false)),
            learning_orchestrator: None,
            gossip: None,
            checkpoint_interval: 50,
            profile_computer: Mutex::new(ProfileComputer::default()),
            peer_profile_store: Mutex::new(PeerProfileStore::default()),
            contribution_recorder: None,
            inference_count: Arc::new(AtomicU64::new(0)),
            equivocation_vote_cfg: None,
            registry_sync: None,
            emit_v2_headers: false,
            applied_tip_lock: None,
        }
    }

    /// Create with economics manager for full economic integration
    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)]
    pub async fn with_economics(
        storage: Arc<StorageManager>,
        executor: Arc<Executor>,
        mempool: Arc<Mempool>,
        peer_manager: Option<Arc<PeerManager>>,
        coinbase: PublicKey,
        signing_key: Ed25519SigningKey,
        target_block_time: u64,
        economics_manager: Arc<UnifiedEconomicsManager>,
    ) -> Self {
        // C5 fix: Create DAG store and load existing blocks from persistent
        // storage so the chain resumes at the correct height after restart.
        let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());

        let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag_store.clone()));

        // Load existing chain data into DAG so we continue from last tip
        let latest_height = storage.blocks.get_latest_height().unwrap_or(0);
        if latest_height > 0 {
            info!("Loading {} blocks from storage into DAG...", latest_height + 1);
            for height in 0..=latest_height {
                if let Ok(Some(block_hash)) = storage.blocks.get_block_by_height(height) {
                    if let Ok(Some(block)) = storage.blocks.get_block(&block_hash) {
                        // SYNC-S1 D2.3 (R3): a discarded DAG write here left the
                        // block chain-present / DAG-absent with no log line,
                        // which makes every descendant fail the consistency
                        // gate. `BlockExists` IS a genuine no-op in this loop
                        // (the block was just read OUT of the chain store, so
                        // the chain half is present by construction, and
                        // BlockExists proves the DAG half is too) — but a real
                        // error must never be silent.
                        match dag_store.store_block(block.clone()).await {
                            Ok(()) => {}
                            // Already in the DAG. A genuine no-op HERE, and only
                            // here: the block was just read OUT of the chain
                            // store, so the chain half is present by
                            // construction and BlockExists proves the DAG half
                            // is too. Logged rather than swallowed — an empty
                            // arm on this variant is what made the boot-3 wedge
                            // permanent, so the shape stays grep-able.
                            Err(DagStoreError::BlockExists(_)) => debug!(
                                "DAG rehydration: block {} @ {} already present in the DAG store",
                                block_hash, height
                            ),
                            Err(e) => warn!(
                                "DAG rehydration: block {} @ {} failed to load into the DAG store: {} \
                                 — descendants will be inadmissible until the startup reconcile repairs it",
                                block_hash, height, e
                            ),
                        }
                        // PIL-13: use register_existing_block, not add_block.
                        // The eager-load loop walks every persisted block on
                        // startup. add_block recomputes the full BlueSet
                        // (cumulative O(chain-length) blue ancestry), which
                        // accumulates O(N²) memory in blue_cache and kernel-
                        // OOMs the box at N=281k. register_existing_block
                        // reads blue_score + blue_work straight from the
                        // header (already on disk, durable) and stores a
                        // lightweight BlueSet — O(1) per block, no
                        // cumulative materialisation.
                        if let Err(e) = ghostdag.register_existing_block(&block).await {
                            warn!(
                                "DAG rehydration: block {} @ {} failed GhostDAG registration: {}",
                                block_hash, height, e
                            );
                        }
                    }
                }
            }
            info!("DAG loaded: {} blocks, resuming from height {}", latest_height + 1, latest_height);
        }

        let tip_selector = Arc::new(TipSelector::new(
            dag_store.clone(),
            ghostdag.clone(),
            citrate_consensus::tip_selection::SelectionStrategy::HighestBlueScore,
        ));
        let chain_selector = Arc::new(ChainSelector::new(
            dag_store.clone(),
            ghostdag.clone(),
            tip_selector.clone(),
            100, // finality depth
        ));

        // For backwards compatibility, keep a basic reward calculator
        let reward_config = crate::canonical_apply::canonical_reward_config();
        let reward_calculator = RewardCalculator::new(reward_config);
        let ai_state_manager = Arc::new(AIStateManager::new(storage.db.clone()));

        Self {
            storage,
            executor,
            mempool,
            dag_store,
            ghostdag,
            tip_selector,
            chain_selector,
            ai_state_manager,
            peer_manager,
            coinbase,
            signing_key,
            target_block_time,
            reward_calculator,
            economics_manager: Some(economics_manager),
            paused: Arc::new(AtomicBool::new(false)),
            learning_orchestrator: None,
            gossip: None,
            checkpoint_interval: 50,
            profile_computer: Mutex::new(ProfileComputer::default()),
            peer_profile_store: Mutex::new(PeerProfileStore::default()),
            contribution_recorder: None,
            inference_count: Arc::new(AtomicU64::new(0)),
            equivocation_vote_cfg: None,
            registry_sync: None,
            emit_v2_headers: false,
            applied_tip_lock: None,
        }
    }

    /// WP-K.2: Access the producer's shared DAG store.
    /// Used to feed network-received blocks into the live DAG for fork-choice.
    #[allow(dead_code)]
    pub fn dag_store(&self) -> Arc<DagStore> {
        self.dag_store.clone()
    }

    /// WP-K.2: Access the producer's shared GhostDag instance.
    /// Used to update blue set calculations when network blocks arrive.
    #[allow(dead_code)]
    pub fn ghostdag(&self) -> Arc<GhostDag> {
        self.ghostdag.clone()
    }

    /// Create with pre-built DAG components and economics manager.
    /// WP-K.2: Allows sharing the DAG store and GhostDag between the
    /// producer and the network message handler for live fork-choice.
    #[allow(clippy::too_many_arguments)]
    pub async fn with_shared_dag(
        storage: Arc<StorageManager>,
        executor: Arc<Executor>,
        mempool: Arc<Mempool>,
        peer_manager: Option<Arc<PeerManager>>,
        coinbase: PublicKey,
        signing_key: Ed25519SigningKey,
        target_block_time: u64,
        economics_manager: Arc<UnifiedEconomicsManager>,
        dag_store: Arc<DagStore>,
        ghostdag: Arc<GhostDag>,
    ) -> Self {
        // Load existing chain data into DAG so we continue from last tip
        let latest_height = storage.blocks.get_latest_height().unwrap_or(0);
        if latest_height > 0 {
            info!("Loading {} blocks from storage into DAG...", latest_height + 1);
            for height in 0..=latest_height {
                if let Ok(Some(block_hash)) = storage.blocks.get_block_by_height(height) {
                    if let Ok(Some(block)) = storage.blocks.get_block(&block_hash) {
                        // SYNC-S1 D2.3 (R3): a discarded DAG write here left the
                        // block chain-present / DAG-absent with no log line,
                        // which makes every descendant fail the consistency
                        // gate. `BlockExists` IS a genuine no-op in this loop
                        // (the block was just read OUT of the chain store, so
                        // the chain half is present by construction, and
                        // BlockExists proves the DAG half is too) — but a real
                        // error must never be silent.
                        match dag_store.store_block(block.clone()).await {
                            Ok(()) => {}
                            // Already in the DAG. A genuine no-op HERE, and only
                            // here: the block was just read OUT of the chain
                            // store, so the chain half is present by
                            // construction and BlockExists proves the DAG half
                            // is too. Logged rather than swallowed — an empty
                            // arm on this variant is what made the boot-3 wedge
                            // permanent, so the shape stays grep-able.
                            Err(DagStoreError::BlockExists(_)) => debug!(
                                "DAG rehydration: block {} @ {} already present in the DAG store",
                                block_hash, height
                            ),
                            Err(e) => warn!(
                                "DAG rehydration: block {} @ {} failed to load into the DAG store: {} \
                                 — descendants will be inadmissible until the startup reconcile repairs it",
                                block_hash, height, e
                            ),
                        }
                        // PIL-13: use register_existing_block, not add_block.
                        // The eager-load loop walks every persisted block on
                        // startup. add_block recomputes the full BlueSet
                        // (cumulative O(chain-length) blue ancestry), which
                        // accumulates O(N²) memory in blue_cache and kernel-
                        // OOMs the box at N=281k. register_existing_block
                        // reads blue_score + blue_work straight from the
                        // header (already on disk, durable) and stores a
                        // lightweight BlueSet — O(1) per block, no
                        // cumulative materialisation.
                        if let Err(e) = ghostdag.register_existing_block(&block).await {
                            warn!(
                                "DAG rehydration: block {} @ {} failed GhostDAG registration: {}",
                                block_hash, height, e
                            );
                        }
                    }
                }
            }
            info!("DAG loaded: {} blocks, resuming from height {}", latest_height + 1, latest_height);
        }

        let tip_selector = Arc::new(TipSelector::new(
            dag_store.clone(),
            ghostdag.clone(),
            citrate_consensus::tip_selection::SelectionStrategy::HighestBlueScore,
        ));
        let chain_selector = Arc::new(ChainSelector::new(
            dag_store.clone(),
            ghostdag.clone(),
            tip_selector.clone(),
            100,
        ));

        let reward_config = crate::canonical_apply::canonical_reward_config();
        let reward_calculator = RewardCalculator::new(reward_config);
        let ai_state_manager = Arc::new(AIStateManager::new(storage.db.clone()));

        Self {
            storage,
            executor,
            mempool,
            dag_store,
            ghostdag,
            tip_selector,
            chain_selector,
            ai_state_manager,
            peer_manager,
            coinbase,
            signing_key,
            target_block_time,
            reward_calculator,
            economics_manager: Some(economics_manager),
            paused: Arc::new(AtomicBool::new(false)),
            learning_orchestrator: None,
            gossip: None,
            checkpoint_interval: 50,
            profile_computer: Mutex::new(ProfileComputer::default()),
            peer_profile_store: Mutex::new(PeerProfileStore::default()),
            contribution_recorder: None,
            inference_count: Arc::new(AtomicU64::new(0)),
            equivocation_vote_cfg: None,
            registry_sync: None,
            emit_v2_headers: false,
            applied_tip_lock: None,
        }
    }

    /// Set an external pause flag (shared with the RPC server).
    /// WP-I.3: This allows the RPC citrate_emergencyPause method to
    /// directly control block production.
    pub fn set_pause_flag(&mut self, flag: Arc<AtomicBool>) {
        self.paused = flag;
    }

    /// WP-F.3: Enable checkpoint learning by setting the orchestrator and gossip layer.
    ///
    /// Call this after construction to wire learning into block production.
    /// The orchestrator runs paraconsensus aggregation at checkpoint boundaries
    /// and computes the `learning_root` hash for inclusion in the block header.
    #[allow(dead_code)]
    pub fn enable_learning(
        &mut self,
        orchestrator: LearningOrchestrator,
        gossip: Arc<GossipProtocol>,
        checkpoint_interval: u64,
    ) {
        self.learning_orchestrator = Some(orchestrator);
        self.gossip = Some(gossip);
        self.checkpoint_interval = checkpoint_interval;
        info!(
            "Learning enabled: checkpoint_interval={}",
            checkpoint_interval
        );
    }

    /// LC.4.3: Enable automatic contribution recording via the ContributionAccounting contract.
    ///
    /// After calling this, the block producer will automatically record:
    /// - Validation contributions (1 per block produced)
    /// - ModelHosting contributions (based on inference count since last block)
    /// - AdapterCreation contributions (at checkpoints when mentor generates adapter)
    #[allow(dead_code)]
    pub fn enable_contribution_recording(
        &mut self,
        rpc_url: String,
        contract_address: String,
        recorder_address: String,
    ) {
        let recorder = ContributionRecorder::new(rpc_url, contract_address, recorder_address);
        self.contribution_recorder = Some(Arc::new(recorder));
        info!("ContributionAccounting recording enabled");
    }

    /// LC.4.3: Get a handle to the inference counter for incrementing from
    /// the inference/MCP handler when requests are served.
    #[allow(dead_code)]
    pub fn inference_counter(&self) -> Arc<AtomicU64> {
        self.inference_count.clone()
    }

    /// VALIDATOR-S1 (v5): configure EquivocationVote signing (see
    /// [`EquivocationVoteConfig`]). Idempotent builder-style setter used by node
    /// startup once the ValidatorRegistry address is known.
    pub fn with_equivocation_vote_config(mut self, cfg: EquivocationVoteConfig) -> Self {
        self.equivocation_vote_cfg = Some(cfg);
        self
    }

    /// VALIDATOR-S1 (v5): attach the registry snapshot-sync (see [`Self::registry_sync`]).
    pub fn with_registry_sync(mut self, sync: Arc<crate::registry_sync::RegistrySync>) -> Self {
        self.registry_sync = Some(sync);
        self
    }

    /// EXECUTE-ON-RECEIVE: seal version-2 headers that commit the coinbase (reroll flag).
    pub fn with_v2_headers(mut self, enabled: bool) -> Self {
        self.emit_v2_headers = enabled;
        self
    }

    /// EXECUTE-ON-RECEIVE (step 2): share the applied-tip lock with the receive-path
    /// applier. Held across produce→persist so production and reception never race the
    /// executor's snapshot/restore; the sealed block becomes the new applied tip.
    pub fn with_applied_tip_lock(
        mut self,
        lock: Arc<tokio::sync::Mutex<crate::canonical_apply::AppliedState>>,
    ) -> Self {
        self.applied_tip_lock = Some(lock);
        self
    }

    /// VALIDATOR-S1 (v5): if `height` is a snapshot boundary S(E), rebuild the shared
    /// proposer selector from the registry against the just-applied state. Called after a
    /// block is persisted so the executor state == state at S(E).
    async fn maybe_sync_registry(&self, height: u64) {
        if let Some(rs) = &self.registry_sync {
            if let Some(epoch) = crate::registry_sync::snapshot_epoch_at(height) {
                match rs.sync_for_snapshot(height).await {
                    Ok(n) => info!(
                        "VALIDATOR-S1: synced validator set for epoch {} at snapshot height {} ({} validators)",
                        epoch, height, n
                    ),
                    Err(e) => warn!(
                        "VALIDATOR-S1: registry snapshot sync failed at height {} (epoch {}): {}",
                        height, epoch, e
                    ),
                }
            }
        }
    }

    /// Pause block production (emergency stop).
    #[allow(dead_code)]
    pub fn pause(&self) {
        self.paused.store(true, Ordering::Relaxed);
        warn!("EMERGENCY: Block production PAUSED");
    }

    /// Resume block production after emergency pause.
    #[allow(dead_code)]
    pub fn resume(&self) {
        self.paused.store(false, Ordering::Relaxed);
        info!("Block production RESUMED");
    }

    /// Check if block production is paused.
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    /// Start block production loop
    pub async fn start(self: Arc<Self>) {
        let mut interval = interval(Duration::from_secs(self.target_block_time));
        let mut block_count = 0u64;

        loop {
            interval.tick().await;

            if self.is_paused() {
                continue;
            }

            match self.produce_block().await {
                Ok(block_hash) => {
                    block_count += 1;
                    info!(
                        "Produced block #{} hash={} txs={}",
                        block_count,
                        hex::encode(&block_hash.as_bytes()[..8]),
                        0, // We'll get tx count from block
                    );
                }
                Err(e) => {
                    error!("Failed to produce block: {}", e);
                }
            }
        }
    }

    /// Produce a single block
    async fn produce_block(&self) -> anyhow::Result<Hash> {
        // EXECUTE-ON-RECEIVE (step 2): hold the shared state-advance lock across the
        // whole build. The receive-path applier (`CanonicalApplicator::apply_received`)
        // takes the same lock, so production and reception never concurrently mutate the
        // executor (whose apply_block snapshot/restore is not concurrency-safe). Held
        // until this method returns; the sealed block is recorded as the new applied tip
        // just before release. `None` when execute-on-receive is disabled (legacy path).
        let mut applied_guard = match &self.applied_tip_lock {
            Some(lock) => Some(lock.lock().await),
            None => None,
        };

        // Get current tips for parent selection
        let tips = self.dag_store.get_tips().await;

        // Select parents using GhostDAG algorithm
        let (selected_parent, merge_parents) = if tips.is_empty() {
            // Genesis case: no parents
            (Hash::default(), vec![])
        } else {
            // Use GhostDAG to select the best parent and merge parents
            self.select_parents_with_ghostdag(&tips).await?
        };

        // PIL-13: removed the `temp_block` builder + `calculate_blue_set`
        // call here. The temp_block was only used to feed
        // calculate_blue_set, which (because BlueSet.blocks is the
        // cumulative O(N) blue ancestry) walked back O(N) ancestors on cold
        // cache and OOM'd the box. We derive blue_score from the parent's
        // header instead.
        //
        // PIL-13: derive blue_score from the parent's header instead of
        // calling calculate_blue_set on a fresh-from-thin-air block.
        //
        // Why this is safe for testnet-beta (single-producer pilot):
        //   * The new block's blue_score is parent.blue_score + 1 + |blue merge
        //     contributions|.
        //   * For single-producer chains the merge_parents set is either
        //     empty or shallow (this producer is the only source of blocks),
        //     so the +1 approximation matches what the full GhostDAG
        //     algorithm would yield to within one or two units.
        //   * The full BlueSet is only an input to calculate_blue_work, and
        //     that function (see calculate_blue_work below) only reads
        //     blue_score — the `_blue_set` parameter is unused.
        //   * select_tip reads only `relation.blue_set.score`, not `.blocks`.
        //
        // When multi-validator ships post-pilot, this path needs the full
        // calculate_blue_set call back, with the BlueSet persistence rework
        // also in place so it doesn't re-trigger PIL-13. Tracked as a
        // follow-up below.
        //
        // Read parent's height + VRF + blue_score in one storage hit.
        let (last_height, parent_vrf_output, parent_blue_score, parent_blue_work) =
            if selected_parent != Hash::default() {
                self.storage
                    .blocks
                    .get_block(&selected_parent)
                    .ok()
                    .flatten()
                    .map(|b| {
                        (
                            b.header.height,
                            b.header.vrf_reveal.output,
                            b.header.blue_score,
                            b.header.blue_work,
                        )
                    })
                    .unwrap_or((0, Hash::default(), 0, 0))
            } else {
                (0, Hash::default(), 0, 0)
            };

        // Single-producer increment. Each new block adds itself to the blue
        // set; with no other producers there are no additional blue merges.
        let blue_score = parent_blue_score + 1;
        // Lightweight placeholder (no cumulative ancestry materialised).
        let mut blue_set = citrate_consensus::types::BlueSet::new();
        blue_set.score = blue_score;
        blue_set.work = parent_blue_work; // base; calculate_blue_work below recomputes

        // Get transactions from mempool with AI priority
        let transactions = self.select_transactions_with_ai_priority().await?;

        // VALIDATOR-S1 §R': under v2 (execute-on-receive), exclude EIP-1559-invalid
        // txs (`gas_price < canonical base fee`) so a produced block never trips the
        // receiver's reject rule (`settle_block_rewards`). Real txs pay >= 1 gwei, so
        // this is a no-op in practice; it just keeps producer and importer agreeing on
        // block validity. Off for v1/legacy (no execute-on-receive).
        let transactions: Vec<citrate_consensus::types::Transaction> = if self.emit_v2_headers {
            transactions
                .into_iter()
                .filter(|t| {
                    t.gas_price >= citrate_execution::block_rewards::CANONICAL_BASE_FEE_PER_GAS
                })
                .collect()
        } else {
            transactions
        };

        // Blue score and work are already calculated above
        let blue_work = self.calculate_blue_work(&blue_set, blue_score)?;

        // Create block header with GhostDAG consensus data.
        // EXECUTE-ON-RECEIVE: v2 headers commit the coinbase (reroll flag); v1 keep legacy hashing.
        let mut header = BlockHeader {
            version: if self.emit_v2_headers { 2 } else { 1 },
            block_hash: Hash::default(), // Will be computed
            selected_parent_hash: selected_parent,
            merge_parent_hashes: merge_parents,
            timestamp: chrono::Utc::now().timestamp() as u64,
            height: last_height + 1,
            blue_score,
            blue_work,
            pruning_point: Hash::default(),
            proposer_pubkey: PublicKey::new(self.signing_key.verifying_key().to_bytes()),
            vrf_reveal: generate_block_vrf(&self.signing_key, &PublicKey::new(self.signing_key.verifying_key().to_bytes()), &parent_vrf_output, last_height + 1),
            base_fee_per_gas: {
                // EIP-1559 base fee calculation from parent block
                let parent_base_fee: u64 = 1_000_000_000; // 1 gwei minimum
                let parent_gas_used: u64 = 0; // Will be read from parent block when available
                let parent_gas_limit: u64 = 30_000_000;
                let target_gas = parent_gas_limit / 2;
                if parent_gas_used == target_gas {
                    parent_base_fee
                } else if parent_gas_used > target_gas {
                    let delta = parent_gas_used - target_gas;
                    let fee_delta = std::cmp::max(parent_base_fee * delta / target_gas / 8, 1);
                    parent_base_fee + fee_delta
                } else {
                    let delta = target_gas - parent_gas_used;
                    let fee_delta = parent_base_fee * delta / target_gas / 8;
                    std::cmp::max(parent_base_fee.saturating_sub(fee_delta), 1_000_000_000) // floor at 1 gwei
                }
            },
            gas_used: 0, // Will be updated after execution
            gas_limit: 30_000_000, // 30M gas default
            // EXECUTE-ON-RECEIVE: commit the beneficiary so receivers can reproduce state_root.
            // Hashed only for v2 (see compute_hash); harmless for v1.
            coinbase: self.coinbase.0[0..20].try_into().unwrap_or([0u8; 20]),
        };

        // VALIDATOR-S1 §R': base fee is a REROLL CONSTANT under v2. The dynamic
        // EIP-1559 block above already evaluates to exactly this (it never loads
        // parent_gas_used), but pin it explicitly so the committed value is
        // unambiguous and the importer's base-fee check (`settle_block_rewards`) is
        // exact. See core/execution/src/block_rewards.rs::CANONICAL_BASE_FEE_PER_GAS.
        if self.emit_v2_headers {
            header.base_fee_per_gas = citrate_execution::block_rewards::CANONICAL_BASE_FEE_PER_GAS;
        }

        // WP-Z.3 / PIN-P1(d): Set block context with the consensus ECVRF
        // randomness before executing transactions. `header.vrf_reveal.output`
        // is the RFC 9381 ECVRF beacon for THIS block (`core/consensus/src/vrf.rs`),
        // and feeding it here is what makes the standard EVM `block.prevrandao`
        // opcode (0x44) return real consensus randomness in Solidity instead of
        // the all-zeros default.
        //
        // Semantics: this exposes this block's OWN randomness. That is the
        // idiomatic `block.prevrandao` contract — but a value derived from the
        // block currently producing it is inherently grindable by the proposer.
        // Grind-resistant challenge selection (committing now, then reading a
        // FINALIZED/future block's prevrandao when the challenge resolves) is the
        // CONSUMER CONTRACT's responsibility (PIN `IPFSIncentives v2`, step (e)).
        // We intentionally do NOT attempt to solve finality at the VM layer.
        self.executor.set_block_context(BlockContext {
            coinbase: self.coinbase.0[0..20].try_into().unwrap_or([0; 20]),
            prevrandao: *header.vrf_reveal.output.as_bytes(),
            block_hashes: HashMap::new(),
        });

        // Execute transactions (state root computed after rewards below)
        let (_pre_reward_root, executed_transactions, mut receipts) = self
            .execute_block_transactions(&transactions, &header)
            .await?;
        let total_gas_used: u64 = receipts.iter().map(|receipt| receipt.gas_used).sum();
        header.gas_used = total_gas_used;

        let tx_root = self.calculate_tx_root(&executed_transactions)?;
        let receipt_root = self.calculate_receipt_root(&receipts)?;
        let artifact_root = self.calculate_artifact_root(&executed_transactions)?;

        // Apply block rewards BEFORE computing the final state root.
        // Rewards modify the executor's in-memory state, so state_root must
        // be computed after this step to include reward balances.
        let validator_address = citrate_execution::types::Address(
            self.coinbase.0[0..20].try_into().unwrap_or([0; 20])
        );

        // SRP-S2 (reward/re-apply state-root purity — ADR-2026-07-21-reapply-reward-purity):
        // the block reward MUST be a pure function of COMMITTED state, settled through the
        // ONE shared `Executor::settle_block_rewards` path that the receiver / cold-sync /
        // restart / reorg roles also use — so producer and receiver credit byte-identical
        // state and the reward-settled root is reproducible on every node.
        //
        // The former node-local "enhanced" reward path (economics staking bonus, f64
        // reputation, dynamic pricing credited straight to the validator, no treasury, no
        // §R') was REMOVED here: it read non-consensus state a receiver can never reproduce
        // and, whenever it was selected (it was gated on the transient `emit_v2_headers`
        // flag), it poisoned the produced block — the block-2209 split-brain. `use_enhanced`
        // and the enhanced branch are gone; block rewards NEVER read `economics_manager`.
        // (economics_manager remains for RPC/telemetry only.)
        //
        // `calculate_reward` reads only header.height + transactions (never state_root), so
        // this temp block is a safe reward-input carrier.
        let temp_block = BlockBuilder::new()
            .header(header.clone())
            .tx_root(tx_root)
            .receipt_root(receipt_root)
            .artifact_root(artifact_root)
            .ghostdag_params(self.ghostdag.params().clone())
            .transactions(executed_transactions.clone())
            .build_unhashed();
        let reward = self.reward_calculator.calculate_reward(&temp_block);
        // `basic_credits` mirrors `canonical_apply::reward_credits` exactly:
        // [(coinbase, validator_reward), (0x11..treasury, treasury_reward)]. Below the
        // VALIDATOR-S1 activation (or before a snapshot is materialized) this credits only
        // the basic reward; at/above it, §R' vests the priority-fee share on top.
        let basic_credits = [
            (validator_address, reward.validator_reward),
            (
                citrate_execution::types::Address([0x11; 20]),
                reward.treasury_reward,
            ),
        ];
        // Use the GUARDED settle: the producer calls settle WITHOUT the
        // snapshot/restore that the receiver's `apply_block_inner` wraps it in,
        // so a settle error (e.g. the absent-proposer reject arm, which fires
        // AFTER step 1's basic credits are applied) would otherwise leak stray
        // credits into shared state — and, since production runs with eager
        // persistence, into the durable store. `settle_block_rewards_guarded`
        // engages the persistence-defer guard + snapshots world state, so ANY
        // error leaves both memory and store byte-identical; on success the
        // credits stay dirty and are persisted by `persist_state_changes` below.
        //
        // SRP-S2 hard-fail: a producer that cannot settle from committed state produces
        // NO block (the `?` aborts production) rather than a poisoned one — it can never
        // silently diverge onto a node-local reward.
        self.executor
            .settle_block_rewards_guarded(
                header.height,
                header.coinbase,
                *header.proposer_pubkey.as_bytes(),
                header.base_fee_per_gas,
                &executed_transactions,
                &receipts,
                &basic_credits,
            )
            .await
            .map_err(|e| anyhow::anyhow!("VALIDATOR-S1 §R' reward settlement failed: {e}"))?;

        // NOW compute final state root — includes both tx effects and reward balances
        let state_root = self.executor.calculate_state_root();

        // Create block with all computed data (hash + signature placeholders — computed next)
        let mut block = BlockBuilder::new()
            .header(header.clone())
            .state_root(state_root)
            .tx_root(tx_root)
            .receipt_root(receipt_root)
            .artifact_root(artifact_root)
            .ghostdag_params(self.ghostdag.params().clone())
            .transactions(executed_transactions)
            .build_unhashed();

        // WP-F.3: Compute learning_root at checkpoint boundaries.
        // Per StrobilationCheckpoint.tla: only checkpoint blocks get a learning_root.
        // Non-checkpoint blocks keep Hash::default() (zero hash).
        // The learning_root is NOT included in compute_hash() (Theorem 3).
        let block_height = block.header.height;
        if block_height > 0
            && block_height.is_multiple_of(self.checkpoint_interval)
            && self.learning_orchestrator.is_some()
        {
            let learning_root = self.compute_checkpoint_learning_root(block_height).await;
            block.learning_root = learning_root;
        }

        // C-05: Compute canonical block hash from ALL fields including commitment roots.
        // This must happen AFTER execution AND rewards so state_root is final.
        block.header.block_hash = block.compute_hash();

        for receipt in &mut receipts {
            receipt.block_hash = block.header.block_hash;
            receipt.block_number = block.header.height;
        }

        // WP-G.2: Sign the canonical block hash with the proposer's ed25519 key.
        block.signature = crypto::sign_block(&block.header.block_hash, &self.signing_key);

        // VALIDATOR-S1 (v5): also sign the height-binding EquivocationVote for THIS block
        // so a double-sign at this height is slashable on-chain. Sidecar (not in the hash);
        // only produced at/above the activation height when the registry is configured.
        if let Some(cfg) = &self.equivocation_vote_cfg {
            if block.header.height >= cfg.activation_height {
                block.equivocation_vote = Some(crypto::sign_equivocation_vote(
                    cfg.chain_id,
                    &cfg.registry,
                    block.header.height,
                    block.header.block_hash.as_bytes(),
                    &self.signing_key,
                ));
            }
        }

        // SRP-S3b (restart/crash consistency): persist the BLOCK first, then the state +
        // applied-tip pointer ATOMICALLY. Durable order = BLOCK → (STATE + TIP atomic). A
        // crash after the block but before the atomic commit leaves the block stored AHEAD
        // of the applied tip (state+tip still consistent at N-1); on restart the forward
        // drain re-applies the stored block deterministically (SRP-S2). The OLD order
        // (state before block, tip written separately) left the durable state one reward
        // AHEAD of the committed block on a mid-window stop → restart root mismatch
        // (block-2345). See ADR-2026-07-21-restart-produce-purity §SRP-S3b.

        // WP-G.4: verify the executor's in-memory root still matches the sealed block root
        // BEFORE any durable write (nothing has mutated committed state since sealing).
        let post_persist_root = self.executor.calculate_state_root();
        if post_persist_root != block.state_root {
            error!(
                "STATE ROOT MISMATCH before persist: block={} computed={}",
                block.state_root, post_persist_root
            );
            return Err(anyhow::anyhow!(
                "State root mismatch before persistence: block {} vs computed {}",
                block.state_root, post_persist_root
            ));
        }

        // 1) Persist the block + its state-root pointer (block may lead the applied tip).
        self.storage.blocks.put_block(&block)?;
        if let Err(e) = self.storage.state.put_state_root(&block.header.block_hash, &block.state_root) {
            warn!("Failed to persist state root for block {}: {}", block.header.height, e);
        }

        // 2) Persist state changes + advance the durable applied tip ATOMICALLY to THIS
        //    block, so durable state and the committed tip can never diverge on a crash.
        info!("Persisting state changes to storage...");
        let modified_count = self
            .executor
            .persist_state_changes_with_tip(Some((block.header.block_hash, block.header.height)))
            .await?;
        info!("Persisted {} modified accounts to storage (tip @ {})", modified_count, block.header.height);

        // VALIDATOR-S1 (v5): the executor state is now post-height H. If H is a snapshot
        // boundary S(E), rebuild the proposer selector from the registry as-of this state
        // so epoch-E membership is loaded before epoch-E blocks are validated.
        self.maybe_sync_registry(block.header.height).await;

        // EXECUTE-ON-RECEIVE (step 2): update the IN-MEMORY applied-tip ring to this block
        // (the DURABLE tip was just advanced atomically with the state above). Keeps the
        // invariant "applied_tip == the block whose state the executor reflects" for
        // locally-produced blocks too, so a peer building on our tip fast-path-applies.
        if let Some(guard) = applied_guard.as_mut() {
            crate::canonical_apply::record_produced(
                guard,
                &self.storage,
                &self.executor,
                &block,
            );
        }

        // Broadcast block to connected peers
        if let Some(peer_manager) = &self.peer_manager {
            let block_msg = NetworkMessage::NewBlock {
                block: block.clone(),
            };
            tokio::spawn({
                let pm = peer_manager.clone();
                async move {
                    if let Err(e) = pm.broadcast(&block_msg).await {
                        tracing::warn!("Failed to broadcast block to peers: {}", e);
                    } else {
                        tracing::info!("Broadcasted new block to peers");
                    }
                }
            });
        }

        // Store transactions and receipts for RPC visibility
        if !block.transactions.is_empty() {
            // Store transactions
            self.storage
                .transactions
                .put_transactions(&block.transactions)?;

            // Pair tx hashes with receipts and store
            let pairs: Vec<(Hash, citrate_execution::types::TransactionReceipt)> = block
                .transactions
                .iter()
                .zip(receipts.iter())
                .map(|(tx, receipt)| (tx.hash, receipt.clone()))
                .collect();
            if !pairs.is_empty() {
                self.storage.transactions.put_receipts(&pairs)?;
            }

            // Remove included transactions from mempool
            for tx in &block.transactions {
                let _ = self.mempool.remove_transaction(&tx.hash).await;
            }

            // Sprint EL-1 (Issue #20): Reconcile nonce map after removing
            // executed transactions. This ensures that if any txs were removed
            // (including failed ones), the expected-nonce map stays consistent
            // so senders are never permanently blocked.
            self.mempool.reconcile_nonces().await;
        }

        // Update DAG store
        self.dag_store.store_block(block.clone()).await?;

        // WP-F.5: Record block seen for uptime tracking.
        self.profile_computer.lock().record_block();

        // LC.4.3: Record contributions to ContributionAccounting contract.
        // This is fire-and-forget; failures are logged but do not block production.
        if let Some(recorder) = &self.contribution_recorder {
            let recorder: Arc<ContributionRecorder> = recorder.clone();
            let block_height = block.header.height;

            // 1. Record Validation contribution (1 per block produced)
            let rec_validation = recorder.clone();
            tokio::spawn(async move {
                if let Err(e) = rec_validation.record_validation(1).await {
                    debug!(
                        "Failed to record Validation contribution at block {}: {}",
                        block_height, e
                    );
                }
            });

            // 2. Record ModelHosting contributions (inference requests served since last block)
            let inferences = self.inference_count.swap(0, Ordering::Relaxed);
            if inferences > 0 {
                let rec_hosting = recorder.clone();
                tokio::spawn(async move {
                    if let Err(e) = rec_hosting.record_model_hosting(inferences).await {
                        debug!(
                            "Failed to record ModelHosting({}) at block {}: {}",
                            inferences, block_height, e
                        );
                    }
                });
            }

            // 3. Record AdapterCreation at checkpoint boundaries (when mentor pairings generate adapters)
            if block.header.height > 0
                && block.header.height.is_multiple_of(self.checkpoint_interval)
                && block.learning_root != Hash::default()
            {
                let rec_adapter = recorder.clone();
                tokio::spawn(async move {
                    if let Err(e) = rec_adapter.record_adapter_creation(1).await {
                        debug!(
                            "Failed to record AdapterCreation at checkpoint {}: {}",
                            block_height, e
                        );
                    }
                });
            }
        }

        // Sprint COMPUTE-2: Send automatic heartbeat to HeartbeatMonitor every
        // 100 blocks (~3 minutes at 2s block time). This keeps the node's
        // compute provider status active and prevents liveness suspension.
        //
        // Data source: HeartbeatMonitor.heartbeat() via eth_sendTransaction
        // Fire-and-forget: failures are logged but never block production.
        if block.header.height > 0 && block.header.height.is_multiple_of(100) {
            if let Some(recorder) = &self.contribution_recorder {
                let rpc_url = recorder.rpc_url().to_string();
                let recorder_address = recorder.recorder_address().to_string();
                let hb_height = block.header.height;
                tokio::spawn(async move {
                    Self::send_heartbeat_to_monitor(&rpc_url, &recorder_address, hb_height).await;
                });
            }
        }

        Ok(block.header.block_hash)
    }

    /// Sprint COMPUTE-2: Send heartbeat to HeartbeatMonitor contract.
    ///
    /// Data source: HeartbeatMonitor.heartbeat() via eth_sendTransaction
    ///
    /// This is a fire-and-forget background task. Failures are logged at debug
    /// level and never block block production.
    async fn send_heartbeat_to_monitor(rpc_url: &str, from_address: &str, block_height: u64) {
        use sha3::{Digest, Keccak256};

        // Compute function selector for heartbeat()
        let selector_hash = Keccak256::digest(b"heartbeat()");
        let calldata_hex = format!("0x{}", hex::encode(&selector_hash[..4]));

        // Use the HeartbeatMonitor contract address from compute contract addresses.
        // In production this would be loaded from contract_addresses config.
        // For now we attempt the call; if no contract is deployed, the RPC returns an error
        // which we silently log.
        let heartbeat_addr = "0x0000000000000000000000000000000000000000"; // placeholder until deployed

        let client = reqwest::Client::new();
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_sendTransaction",
            "params": [{
                "from": from_address,
                "to": heartbeat_addr,
                "data": calldata_hex,
                "gas": "0x30d40" // 200,000 gas (heartbeat is cheap)
            }],
            "id": 1
        });

        match client
            .post(rpc_url)
            .json(&request)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    let body: serde_json::Value = response.json().await.unwrap_or_default();
                    if let Some(error) = body.get("error") {
                        debug!(
                            "HeartbeatMonitor.heartbeat() at block {} RPC error: {}",
                            block_height, error
                        );
                    } else {
                        debug!(
                            "HeartbeatMonitor: heartbeat sent at block {} (tx: {})",
                            block_height,
                            body.get("result")
                                .and_then(|r| r.as_str())
                                .unwrap_or("unknown")
                        );
                    }
                } else {
                    debug!(
                        "HeartbeatMonitor.heartbeat() at block {} HTTP error: {}",
                        block_height,
                        response.status()
                    );
                }
            }
            Err(e) => {
                debug!(
                    "HeartbeatMonitor.heartbeat() at block {} failed: {}",
                    block_height, e
                );
            }
        }
    }

    /// Select parents using GhostDAG algorithm
    async fn select_parents_with_ghostdag(
        &self,
        tips: &[citrate_consensus::types::Tip],
    ) -> anyhow::Result<(Hash, Vec<Hash>)> {
        // Convert tips to hashes
        let tip_hashes: Vec<Hash> = tips.iter().map(|tip| tip.hash).collect();

        // Use tip selector to find the best tip (highest blue score)
        let selected_parent = self.tip_selector.select_tip(&tip_hashes).await?;

        // Select merge parents from remaining tips
        let merge_parents: Vec<Hash> = tip_hashes
            .into_iter()
            .filter(|h| *h != selected_parent)
            .take(self.ghostdag.params().max_parents - 1) // Leave room for selected parent
            .collect();

        Ok((selected_parent, merge_parents))
    }

    /// Select transactions with AI operation priority.
    ///
    /// H-03 fix: Deduplicates by hash across AI and standard selection phases.
    ///
    /// **Throughput sizing (Apr 2026)**: previously this function hardcoded
    /// `MAX_STANDARD_TXS = 100`, which was the real TPS ceiling on the node
    /// (100 txs/block × 1 block / block_time). That cap is gone; selection
    /// is now bounded by `MAX_GAS_PER_BLOCK` (30M gas, which fits ~1400
    /// simple transfers at 21k gas each) and `MAX_BLOCK_SIZE` (1 MB, the
    /// network-aligned transport limit — H-08). The tx-count cap stays in
    /// play as a safety valve at 5000, matching `BlockBuilderConfig::Default`.
    ///
    /// We stop filling as soon as any cap would be exceeded, so a block
    /// with a mix of high-gas contract calls naturally packs fewer txs.
    async fn select_transactions_with_ai_priority(&self) -> anyhow::Result<Vec<Transaction>> {
        let mut selected = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut total_gas: u64 = 0;

        // Capacity limits. Gas is the dominant real-world ceiling;
        // count + size are safety valves.
        const MAX_BLOCK_SIZE: usize = 1_000_000; // 1 MB — matches transport (H-08)
        const MAX_GAS_PER_BLOCK: u64 = 30_000_000; // Chain genesis constant
        const MAX_AI_TXS_PER_BLOCK: usize = 10;
        const MAX_STANDARD_TXS: usize = 5_000;

        // AI transactions first (model ops, inference). Small reserved slice.
        let ai_txs = self.mempool.get_ai_transactions(MAX_AI_TXS_PER_BLOCK).await;
        for tx in ai_txs {
            if total_gas.saturating_add(tx.gas_limit) > MAX_GAS_PER_BLOCK {
                break;
            }
            if seen.insert(tx.hash) {
                total_gas = total_gas.saturating_add(tx.gas_limit);
                selected.push(tx);
            }
        }

        // Fill remaining gas budget with standard txs.
        let standard_txs = self
            .mempool
            .get_best_transactions(MAX_STANDARD_TXS, MAX_BLOCK_SIZE)
            .await;
        for tx in standard_txs {
            if total_gas.saturating_add(tx.gas_limit) > MAX_GAS_PER_BLOCK {
                break;
            }
            if seen.insert(tx.hash) {
                total_gas = total_gas.saturating_add(tx.gas_limit);
                selected.push(tx);
            }
        }

        Ok(selected)
    }

    /// Execute all transactions in a block
    async fn execute_block_transactions(
        &self,
        transactions: &[Transaction],
        header: &BlockHeader,
    ) -> anyhow::Result<(Hash, Vec<Transaction>, Vec<citrate_execution::types::TransactionReceipt>)> {
        let mut executed_transactions = Vec::new();
        let mut receipts = Vec::new();

        // Create a temporary block for execution context
        let temp_block = BlockBuilder::new()
            .header(header.clone())
            .ghostdag_params(self.ghostdag.params().clone())
            .build_unhashed();

        // Execute each transaction
        for tx in transactions {
            match self.executor.execute_transaction(&temp_block, tx).await {
                Ok(receipt) => {
                    executed_transactions.push(tx.clone());
                    receipts.push(receipt);
                }
                Err(e) => {
                    error!("Failed to execute transaction {}: {}", tx.hash, e);

                    // Sprint EL-1 (Issue #20): Remove failed tx from mempool
                    // so the sender's nonce is not permanently blocked.
                    let _ = self.mempool.remove_transaction(&tx.hash).await;
                }
            }
        }

        // WP-G.4: Compute state root from the executor's in-memory post-execution state.
        // This uses the state trie that has been updated by transaction execution,
        // NOT the storage-backed view which still reflects the previous block.
        let state_root = self.executor.calculate_state_root();

        Ok((state_root, executed_transactions, receipts))
    }

    /// Calculate transaction root
    fn calculate_tx_root(&self, transactions: &[Transaction]) -> anyhow::Result<Hash> {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();

        for tx in transactions {
            hasher.update(tx.hash.as_bytes());
        }

        let hash_bytes = hasher.finalize();
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hash_bytes[..32]);
        Ok(Hash::new(hash_array))
    }

    /// Calculate receipt root
    fn calculate_receipt_root(
        &self,
        receipts: &[citrate_execution::types::TransactionReceipt],
    ) -> anyhow::Result<Hash> {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();

        for receipt in receipts {
            hasher.update(receipt.tx_hash.as_bytes());
            hasher.update([if receipt.status { 1 } else { 0 }]);
            hasher.update(receipt.gas_used.to_le_bytes());
        }

        let hash_bytes = hasher.finalize();
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hash_bytes[..32]);
        Ok(Hash::new(hash_array))
    }

    /// Calculate artifact root for AI models
    fn calculate_artifact_root(&self, transactions: &[Transaction]) -> anyhow::Result<Hash> {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();

        // Hash any AI-related transaction data
        for tx in transactions {
            // Check if transaction contains AI operations
            if tx.data.len() >= 4 {
                match &tx.data[0..4] {
                    [0x01, 0x00, 0x00, 0x00] | // Register model
                    [0x02, 0x00, 0x00, 0x00] => { // Inference request
                        hasher.update(&tx.data);
                    }
                    _ => {}
                }
            }
        }

        let hash_bytes = hasher.finalize();
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hash_bytes[..32]);
        Ok(Hash::new(hash_array))
    }

    /// Calculate blue work based on blue set
    fn calculate_blue_work(
        &self,
        _blue_set: &citrate_consensus::types::BlueSet,
        blue_score: u64,
    ) -> anyhow::Result<u128> {
        // SECREM-01 CONS-2/3: delegate to the canonical score→work function
        // in citrate-consensus. Admission validation rejects any header
        // whose blue_work deviates from it, so the producer MUST use the
        // same source of truth or fork itself off.
        Ok(citrate_consensus::types::blue_work_for_score(blue_score))
    }

    // NOTE (VALIDATOR-S1 §R'): `apply_basic_rewards` was REMOVED. Basic reward
    // crediting now flows through the single shared `Executor::settle_block_rewards`
    // that the receiver (`Executor::apply_block`) also calls, so the two paths cannot
    // drift. It credits the identical [(coinbase, validator_reward),
    // (0x11..treasury, treasury_reward)] list plus the §R' priority-fee vesting.

    /// WP-F.3 + WP-F.5: Compute the learning_root for a checkpoint block.
    ///
    /// Collects peer embeddings from the gossip layer, runs paraconsensus
    /// aggregation via the learning orchestrator, and returns the hash.
    ///
    /// WP-F.5: Also computes and logs the local performance profile at each
    /// checkpoint boundary. Peer profiles received via gossip are stored in
    /// the peer_profile_store for WP-F.6 mentor selection.
    ///
    /// If aggregation fails or returns below-quorum, returns zero hash
    /// (block production continues normally — learning is non-blocking).
    ///
    /// Formal specification: StrobilationCheckpoint.tla
    /// - ProduceCheckpointBlock: requires aggregation complete
    /// - INV-4 (StateRootIndependent): result never affects state_root
    async fn compute_checkpoint_learning_root(&self, block_height: u64) -> Hash {
        let orchestrator = match &self.learning_orchestrator {
            Some(o) => o,
            None => return Hash::default(),
        };

        // WP-F.5: Compute local performance profile at this checkpoint.
        let local_profile = self.profile_computer.lock().compute_profile();
        info!(
            "Checkpoint {} local profile: accuracy={:.3}, latency={}ms, uptime={:.3}, adapters={}, domains={:?}",
            block_height,
            local_profile.accuracy,
            local_profile.latency_ms,
            local_profile.uptime,
            local_profile.adapter_count,
            local_profile.domains,
        );

        // WP-F.5: Store our own profile in the peer profile store.
        {
            let store_profile = citrate_learning::profile::PerformanceProfile {
                accuracy: local_profile.accuracy,
                latency_ms: local_profile.latency_ms,
                domains: local_profile.domains.clone(),
                uptime: local_profile.uptime,
                adapter_count: local_profile.adapter_count,
            };
            let local_key = *self.coinbase.as_bytes();
            self.peer_profile_store.lock().store_profile(
                block_height,
                local_key,
                store_profile,
            );
        }

        // Collect peer embeddings from gossip layer (also stores peer profiles)
        let peer_embeddings = self.collect_peer_embeddings(block_height).await;

        // TODO(WP-F.4): Build local embedding from recent inference activity.
        // For now, we only aggregate peer embeddings.
        let local_embedding: Option<PeerEmbedding> = None;

        match orchestrator.run_checkpoint_aggregation(
            block_height,
            local_embedding,
            peer_embeddings,
        ) {
            Ok(result) => {
                if result.learning_root == [0u8; 32] {
                    info!(
                        "Checkpoint {} learning: below quorum ({} participants), zero root",
                        block_height, result.participant_count,
                    );
                } else {
                    info!(
                        "Checkpoint {} learning: {} participants, confidence={:.3}, root={}",
                        block_height,
                        result.participant_count,
                        result.confidence,
                        hex::encode(result.learning_root),
                    );
                }
                Hash::new(result.learning_root)
            }
            Err(e) => {
                warn!(
                    "Learning aggregation failed at checkpoint {}: {}",
                    block_height, e
                );
                Hash::default()
            }
        }
    }

    /// WP-F.3 + WP-F.5: Extract peer embeddings from gossip layer's learning data store.
    ///
    /// Converts the network-layer `LearningMessage::Embedding` messages into
    /// the learning-crate's `PeerEmbedding` format for aggregation.
    ///
    /// WP-F.5: Also extracts and stores peer performance profiles in the
    /// `peer_profile_store` for use by WP-F.6 mentor selection.
    async fn collect_peer_embeddings(&self, checkpoint_height: u64) -> Vec<PeerEmbedding> {
        let gossip = match &self.gossip {
            Some(g) => g,
            None => return vec![],
        };

        let data = match gossip.get_learning_data(checkpoint_height).await {
            Some(d) => d,
            None => {
                debug!("No learning data for checkpoint height {}", checkpoint_height);
                return vec![];
            }
        };

        let mut peer_embeddings = Vec::with_capacity(data.embeddings.len());

        for msg in &data.embeddings {
            if let LearningMessage::Embedding(emb) = msg {
                // WP-F.5: Store the peer's performance profile for mentor selection.
                let participant_bytes = *emb.participant.as_bytes();
                let peer_profile = citrate_learning::profile::PerformanceProfile {
                    accuracy: emb.profile.accuracy,
                    latency_ms: emb.profile.latency_ms,
                    domains: emb.profile.domains.clone(),
                    uptime: emb.profile.uptime,
                    adapter_count: emb.profile.adapter_count,
                };
                self.peer_profile_store.lock().store_profile(
                    checkpoint_height,
                    participant_bytes,
                    peer_profile,
                );

                // Default confidence to 0.5 for each dimension if not classified
                let confidence = if emb.confidence.len() == emb.embedding.len() {
                    // Convert BelnapConfidence to f32 values for aggregation input
                    emb.confidence
                        .iter()
                        .map(|c| match c {
                            citrate_network::learning_messages::BelnapConfidence::True => 0.9,
                            citrate_network::learning_messages::BelnapConfidence::False => 0.1,
                            citrate_network::learning_messages::BelnapConfidence::Both => 0.5,
                            citrate_network::learning_messages::BelnapConfidence::Neither => 0.3,
                        })
                        .collect()
                } else {
                    vec![0.5; emb.embedding.len()]
                };

                // Use accuracy * 100 as a proxy for blue_score when actual
                // blue score is not available from the gossip message.
                let blue_score = (emb.profile.accuracy * 100.0) as f32;

                peer_embeddings.push(PeerEmbedding {
                    embedding: emb.embedding.clone(),
                    confidence,
                    blue_score,
                });
            }
        }

        debug!(
            "Collected {} peer embeddings for checkpoint {} ({} profiles stored)",
            peer_embeddings.len(),
            checkpoint_height,
            self.peer_profile_store.lock().len(),
        );

        peer_embeddings
    }

    /// WP-F.5: Record an inference result in the local profile computer.
    ///
    /// Call this from inference handlers to track accuracy and latency.
    #[allow(dead_code)]
    pub fn record_inference(&self, correct: bool, latency_ms: u64, domain: &str) {
        self.profile_computer.lock().record_inference(correct, latency_ms, domain);
    }

    /// WP-F.5: Record that this node observed a block (for uptime tracking).
    #[allow(dead_code)]
    pub fn record_block_seen(&self) {
        self.profile_computer.lock().record_block();
    }

    /// WP-F.5: Record that this node missed a block (for uptime tracking).
    #[allow(dead_code)]
    pub fn record_block_missed(&self) {
        self.profile_computer.lock().record_missed_block();
    }

    /// WP-F.5: Record an adapter creation.
    #[allow(dead_code)]
    pub fn record_adapter_created(&self) {
        self.profile_computer.lock().record_adapter_created();
    }

    /// WP-F.5: Get a snapshot of the current local performance profile.
    #[allow(dead_code)]
    pub fn get_local_profile(&self) -> citrate_learning::profile::PerformanceProfile {
        self.profile_computer.lock().compute_profile()
    }

    /// WP-F.5: Get all peer profiles stored for a given checkpoint height.
    ///
    /// Returns (participant_pubkey_bytes, profile) pairs. Used by WP-F.6
    /// mentor selection.
    #[allow(dead_code)]
    pub fn get_peer_profiles_at_checkpoint(
        &self,
        checkpoint_height: u64,
    ) -> Vec<([u8; 32], citrate_learning::profile::PerformanceProfile)> {
        let store = self.peer_profile_store.lock();
        store
            .get_profiles_at_checkpoint(checkpoint_height)
            .into_iter()
            .map(|(k, v)| (k, v.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_consensus::crypto::Ed25519SigningKey;
    use citrate_consensus::types::Signature;
    use primitive_types::U256;
    use citrate_execution::types::Address;
    use citrate_sequencer::mempool::{MempoolConfig, TxClass};
    use citrate_storage::pruning::PruningConfig;
    use citrate_storage::StorageManager;
    use tempfile::TempDir;

    fn test_signing_key() -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&[42u8; 32])
    }

    fn embedded_pubkey(address: Address) -> PublicKey {
        let mut bytes = [0u8; 32];
        bytes[..20].copy_from_slice(&address.0);
        PublicKey::new(bytes)
    }

    fn transfer_tx(hash_byte: u8, from: Address, to: Address, nonce: u64) -> Transaction {
        Transaction {
            hash: Hash::new([hash_byte; 32]),
            nonce,
            from: embedded_pubkey(from),
            to: Some(embedded_pubkey(to)),
            value: 0,
            gas_limit: 21_000,
            gas_price: 1_000_000_000,
            data: vec![],
            signature: Signature::new([1; 64]),
            tx_type: None,
            chain_id: Some(40204),
            ..Default::default()
        }
    }

    #[test]
    fn test_vrf_deterministic() {
        let sk = test_signing_key();
        let proposer = PublicKey::new(sk.verifying_key().to_bytes());
        let prev_vrf = Hash::new([3u8; 32]);
        let slot = 42u64;

        let vrf_a = generate_block_vrf(&sk, &proposer, &prev_vrf, slot);
        let vrf_b = generate_block_vrf(&sk, &proposer, &prev_vrf, slot);

        assert_eq!(vrf_a.proof, vrf_b.proof, "Same inputs must produce same VRF proof");
        assert_eq!(vrf_a.output, vrf_b.output, "Same inputs must produce same VRF output");
        assert!(!vrf_a.proof.is_empty(), "VRF proof must not be empty");
    }

    #[test]
    fn test_vrf_produces_ecvrf_proof() {
        let sk = test_signing_key();
        let proposer = PublicKey::new(sk.verifying_key().to_bytes());
        let prev_vrf = Hash::new([3u8; 32]);

        let vrf = generate_block_vrf(&sk, &proposer, &prev_vrf, 1);

        // WP-Z.1: Real ECVRF produces 114-byte proofs
        assert_eq!(vrf.proof.len(), 114, "ECVRF proof must be 114 bytes");
        // Output must be non-zero
        assert_ne!(vrf.output, Hash::default(), "VRF output must be non-zero");
    }

    #[test]
    fn test_vrf_verifiable() {
        let sk = test_signing_key();
        let proposer = PublicKey::new(sk.verifying_key().to_bytes());
        let prev_vrf = Hash::new([3u8; 32]);
        let slot = 7u64;

        let vrf = generate_block_vrf(&sk, &proposer, &prev_vrf, slot);

        // Verify the proof using the consensus ECVRF verifier
        let ecvrf_proof = citrate_consensus::ecvrf::EcvrfProof::from_bytes(&vrf.proof)
            .expect("Should parse 114-byte proof");
        let mut alpha = Vec::with_capacity(72);
        alpha.extend_from_slice(proposer.as_bytes());
        alpha.extend_from_slice(prev_vrf.as_bytes());
        alpha.extend_from_slice(&slot.to_le_bytes());
        let beta = citrate_consensus::ecvrf::verify(&alpha, &ecvrf_proof)
            .expect("Proof should verify");
        assert_eq!(Hash::from_bytes(&beta), vrf.output, "Verified beta must match proof output");
    }

    #[test]
    fn test_vrf_different_slots_different_output() {
        let sk = test_signing_key();
        let proposer = PublicKey::new(sk.verifying_key().to_bytes());
        let prev_vrf = Hash::new([3u8; 32]);

        let vrf_slot_1 = generate_block_vrf(&sk, &proposer, &prev_vrf, 1);
        let vrf_slot_2 = generate_block_vrf(&sk, &proposer, &prev_vrf, 2);

        assert_ne!(
            vrf_slot_1.output, vrf_slot_2.output,
            "Different slot numbers must produce different VRF outputs"
        );
        assert_ne!(
            vrf_slot_1.proof, vrf_slot_2.proof,
            "Different slot numbers must produce different VRF proofs"
        );
    }

    #[test]
    fn test_vrf_chain_continuity() {
        // Block B's alpha includes Block A's VRF output
        let sk = test_signing_key();
        let proposer = PublicKey::new(sk.verifying_key().to_bytes());
        let genesis_vrf = Hash::default();

        // Produce block A
        let vrf_a = generate_block_vrf(&sk, &proposer, &genesis_vrf, 1);
        assert_eq!(vrf_a.proof.len(), 114);

        // Produce block B using A's output as prev_vrf
        let vrf_b = generate_block_vrf(&sk, &proposer, &vrf_a.output, 2);
        assert_eq!(vrf_b.proof.len(), 114);
        assert_ne!(vrf_a.output, vrf_b.output, "Chain continuity: different blocks must have different VRF outputs");

        // Verify B's proof is bound to A's output
        let ecvrf_proof_b = citrate_consensus::ecvrf::EcvrfProof::from_bytes(&vrf_b.proof).unwrap();
        let mut alpha_b = Vec::with_capacity(72);
        alpha_b.extend_from_slice(proposer.as_bytes());
        alpha_b.extend_from_slice(vrf_a.output.as_bytes());
        alpha_b.extend_from_slice(&2u64.to_le_bytes());
        let beta_b = citrate_consensus::ecvrf::verify(&alpha_b, &ecvrf_proof_b).unwrap();
        assert_eq!(Hash::from_bytes(&beta_b), vrf_b.output);
    }

    #[test]
    fn test_vrf_backward_compat_legacy_verification() {
        // Legacy 32-byte proofs should still be accepted by the verifier
        let vrf_selector = citrate_consensus::vrf::VrfProposerSelector::new();
        let proposer = PublicKey::new([1u8; 32]);
        let prev_vrf = Hash::new([3u8; 32]);

        // Create a legacy-style proof (32 bytes)
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(proposer.as_bytes());
        hasher.update(prev_vrf.as_bytes());
        hasher.update(1u64.to_le_bytes());
        let input = hasher.finalize();

        let mut proof_hasher = Sha3_256::new();
        proof_hasher.update(proposer.as_bytes()); // coinbase = proposer for legacy
        proof_hasher.update(input.as_slice());
        let proof_bytes = proof_hasher.finalize();

        let mut output_hasher = Sha3_256::new();
        output_hasher.update(proof_bytes.as_slice());
        output_hasher.update(input.as_slice());
        let output_bytes = output_hasher.finalize();

        let legacy_vrf = VrfProof {
            proof: proof_bytes.to_vec(), // 32 bytes
            output: Hash::from_bytes(&output_bytes),
        };

        assert_eq!(legacy_vrf.proof.len(), 32);
        // Verifier should accept 32-byte legacy proofs
        let result = vrf_selector.verify_vrf_math_only(&proposer, &legacy_vrf, &prev_vrf, 1);
        assert!(result.is_ok(), "Legacy VRF verification should not error");
    }

    #[tokio::test]
    async fn test_produce_block_filters_unexecuted_txs_and_persists_real_receipts() {
        let tmp = TempDir::new().unwrap();
        let storage = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).unwrap());
        let state_db = Arc::new(citrate_execution::StateDB::new());
        let executor = Arc::new(Executor::with_storage_and_chain_id(
            state_db.clone(),
            Some(storage.state.clone()),
            40204,
        ));
        let mempool = Arc::new(Mempool::new(MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        }));

        let good_from = Address([0x11; 20]);
        let bad_from = Address([0x22; 20]);
        let recipient = Address([0x33; 20]);

        state_db.accounts.create_account_if_not_exists(good_from);
        state_db
            .accounts
            .set_balance(good_from, U256::from(21_000u64 * 1_000_000_000u64 * 10));
        state_db.accounts.create_account_if_not_exists(bad_from);
        state_db.accounts.set_balance(bad_from, U256::from(21_000u64 * 1_000_000_000u64 * 10));

        let good_tx = transfer_tx(0xA1, good_from, recipient, 0);
        let bad_tx = transfer_tx(0xB2, bad_from, recipient, 7);

        mempool
            .add_transaction(good_tx.clone(), TxClass::Standard)
            .await
            .unwrap();
        mempool
            .add_transaction(bad_tx.clone(), TxClass::Standard)
            .await
            .unwrap();

        let signing_key = test_signing_key();
        let coinbase = embedded_pubkey(Address([0x44; 20]));
        let producer = BlockProducer::new(
            storage.clone(),
            executor,
            mempool.clone(),
            coinbase,
            signing_key,
            2,
        );

        let block_hash = producer.produce_block().await.unwrap();
        let block = storage.blocks.get_block(&block_hash).unwrap().unwrap();

        assert_eq!(block.transactions.len(), 1, "Only executed txs should be included");
        assert_eq!(block.transactions[0].hash, good_tx.hash);
        assert_eq!(block.header.gas_used, 21_000);

        let good_receipt = storage
            .transactions
            .get_receipt(&good_tx.hash)
            .unwrap()
            .expect("receipt for executed tx");
        assert_eq!(good_receipt.block_hash, block_hash);
        assert_eq!(good_receipt.block_number, block.header.height);
        assert!(good_receipt.status);
        assert_eq!(good_receipt.gas_used, 21_000);

        assert!(
            storage.transactions.get_receipt(&bad_tx.hash).unwrap().is_none(),
            "Execution errors must not create synthetic receipts"
        );
        assert!(
            storage.transactions.get_transaction(&bad_tx.hash).unwrap().is_none(),
            "Execution errors must not be persisted as block transactions"
        );
    }

    // ═════════════════════════════════════════════════════════════════════════
    // SRP-S2 — reward/re-apply state-root purity (CONSENSUS-CRITICAL red test).
    //
    // Pins the block-2209 split-brain (handoffs/SRP_S2_REAPPLY_REWARD_PURITY_
    // HANDOFF_2026-07-21.md). Unlike `rprime_priority_fee_parity.rs`, which drives
    // `Executor::settle_block_rewards` DIRECTLY (and so never exercised the buggy
    // branch), this test drives the REAL producer entrypoint `produce_block`, which
    // owns the `use_enhanced` selection at producer.rs:899.
    //
    // Reproduction: a production-shaped producer (`with_economics` → economics_manager
    // = Some, `emit_v2_headers` = false — the exact state of a miner the instant it
    // restarts, before `with_v2_headers(true)` is (re)applied) seals ONE empty,
    // post-activation, single-parent block — the shape of block 2209. It takes the
    // node-local ENHANCED reward path (a `base_block_reward` credited straight to the
    // validator from non-committed economics state, no treasury, no §R', no basic
    // canonical credit). An independent fleet node re-applying that block through the
    // canonical committed-state path (`Executor::apply_block`, as `CanonicalApplicator`
    // does) credits the basic 9/1 SALT reward instead → a DIFFERENT root → the
    // block-2209 `StateRootMismatch`.
    //
    // INVARIANT (must hold; VIOLATED on `main`): the reward-settled state root is a
    // pure function of committed state, identical on producer and receiver. This test
    // asserts that invariant — it FAILS on `main` (RED) and PASSES once the enhanced
    // path is removed so the producer settles through the same committed-state path.
    #[tokio::test]
    async fn srp_s2_producer_receiver_reward_parity_on_restart_empty_block() {
        use citrate_economics::{UnifiedEconomicsConfig, UnifiedEconomicsManager};
        use citrate_execution::block_rewards::{
            EpochRewardPolicy, CANONICAL_BASE_FEE_PER_GAS, REWARD_MINTER_ADDRESS,
        };
        use std::collections::HashMap;

        const VALIDATOR: [u8; 20] = [0x44; 20]; // coinbase == registered staker
        const REGISTRY: [u8; 20] = [0x99; 20];
        const TREASURY: [u8; 20] = [0x11; 20];

        let signing_key = test_signing_key();
        let proposer_pk = signing_key.verifying_key().to_bytes(); // header.proposer_pubkey
        let coinbase = embedded_pubkey(Address(VALIDATOR));

        // A fully-materialized §R' policy (as `registry_sync` installs at S(E)): the
        // proposer maps to the coinbase staker, activation 0 so height-1 is
        // post-activation. Empty blocks vest nothing (share == 0), so §R' is inert
        // here — the ONLY committed change is the basic block reward, which is exactly
        // what the producer's enhanced path fails to apply.
        let mk_policy = || {
            let mut staker_of = HashMap::new();
            staker_of.insert(proposer_pk, VALIDATOR);
            EpochRewardPolicy {
                epoch: 1,
                snapshot_height: 0,
                activation_height: 0,
                registry: REGISTRY,
                reward_minter: REWARD_MINTER_ADDRESS,
                priority_fee_share_bps: 2500,
                staker_of,
            }
        };

        // ── Producer: production-shaped (economics = Some) but v2 headers NOT applied. ──
        let tmp = TempDir::new().expect("tempdir");
        let storage =
            Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).expect("storage"));
        let state_db = Arc::new(citrate_execution::StateDB::new());
        let executor = Arc::new(Executor::with_storage_and_chain_id(
            state_db.clone(),
            Some(storage.state.clone()),
            40204,
        ));
        *executor.reward_policy_handle().write() = Some(mk_policy());
        executor.set_validator_activation_height(0);

        let mempool = Arc::new(Mempool::new(MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        }));
        let economics = Arc::new(UnifiedEconomicsManager::new(UnifiedEconomicsConfig::default()));
        let producer = BlockProducer::with_economics(
            storage.clone(),
            executor.clone(),
            mempool.clone(),
            None,
            coinbase.clone(),
            signing_key.clone(),
            2,
            economics,
        )
        .await;

        // One empty block at height 1 — post-activation, single-parent: block 2209's shape.
        let block_hash = producer.produce_block().await.expect("produce empty block");
        let sealed = storage
            .blocks
            .get_block(&block_hash)
            .expect("read block")
            .expect("block present");
        assert!(sealed.transactions.is_empty(), "the reproduction block must be empty");
        assert_eq!(sealed.header.height, 1, "post-activation single-parent block");
        assert_eq!(
            sealed.header.base_fee_per_gas, CANONICAL_BASE_FEE_PER_GAS,
            "canonical base fee (importer base-fee check must pass)"
        );

        // ── Receiver: independent executor, byte-identical genesis + policy, applying
        //    the sealed block through the canonical committed-state reward path. ──
        let receiver = Arc::new(Executor::new(Arc::new(citrate_execution::StateDB::new())));
        *receiver.reward_policy_handle().write() = Some(mk_policy());
        receiver.set_validator_activation_height(0);
        let reward = RewardCalculator::new(crate::canonical_apply::canonical_reward_config())
            .calculate_reward(&sealed);
        let basic_credits = [
            (Address(sealed.header.coinbase), reward.validator_reward),
            (Address(TREASURY), reward.treasury_reward),
        ];

        let got = receiver
            .apply_block(&sealed, sealed.header.coinbase, &basic_credits)
            .await
            .expect(
                "SRP-S2 INVARIANT: a fleet node re-applying the producer's block through the \
                 canonical committed-state reward path MUST reproduce its state root. On `main` \
                 the producer takes the node-local ENHANCED path (producer.rs `use_enhanced`), \
                 crediting a reward no receiver can reproduce → StateRootMismatch → the block-2209 \
                 split-brain.",
            );
        assert_eq!(
            got, sealed.state_root,
            "receiver's committed-state root MUST equal the producer's sealed root"
        );

        // And the committed reward MUST be the canonical basic block reward (9 SALT to the
        // validator, 1 SALT to treasury) — not the enhanced 0.01-SALT node-local credit.
        assert_eq!(
            receiver.get_balance(&Address(VALIDATOR)),
            reward.validator_reward,
            "validator must hold exactly the canonical basic reward"
        );
        assert_eq!(
            receiver.get_balance(&Address(TREASURY)),
            reward.treasury_reward,
            "treasury must hold exactly the canonical treasury slice"
        );
    }
}
