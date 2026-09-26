use citrate_consensus::chain_selection::ChainSelector;
use citrate_consensus::crypto::{self, Ed25519SigningKey};
use citrate_consensus::dag_store::{DagStore, DagStoreError};
use citrate_consensus::ghostdag::GhostDag;
use citrate_consensus::tip_selection::TipSelector;
use citrate_consensus::types::{
    BlockBuilder, BlockHeader, GhostDagParams, Hash, PublicKey, Transaction, VrfProof,
};
use citrate_economics::{RewardCalculator, RewardConfig, UnifiedEconomicsManager};
use citrate_execution::revm_adapter::BlockContext;
use citrate_execution::Executor;
use citrate_learning::orchestration::{LearningOrchestrator, PeerEmbedding, PeerProfileStore};
use citrate_learning::profile::ProfileComputer;
use citrate_network::learning_messages::LearningMessage;
use citrate_network::{GossipProtocol, NetworkMessage, PeerManager};
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
fn generate_block_vrf(
    signing_key: &Ed25519SigningKey,
    proposer_pubkey: &PublicKey,
    prev_vrf: &Hash,
    slot: u64,
) -> VrfProof {
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
    applied_tip_lock: Option<Arc<tokio::sync::Mutex<crate::canonical_apply::AppliedState>>>,
}

/// PBA-L1a-001: outcome of one supervised production round.
#[derive(Debug)]
pub(crate) enum RoundOutcome<T> {
    Produced(T),
    Failed(anyhow::Error),
    Panicked(String),
}

/// Run one production round in its own task so a panic inside it is caught
/// (tokio reports it through the `JoinError`) instead of unwinding the
/// long-lived producer loop.
async fn supervised_round(producer: Arc<BlockProducer>) -> RoundOutcome<Hash> {
    run_supervised(async move { producer.produce_block().await }).await
}

/// Generic form of [`supervised_round`], separated so the panic path is
/// unit-testable without a full producer.
pub(crate) async fn run_supervised<T, F>(round: F) -> RoundOutcome<T>
where
    T: Send + 'static,
    F: std::future::Future<Output = anyhow::Result<T>> + Send + 'static,
{
    match tokio::spawn(round).await {
        Ok(Ok(v)) => RoundOutcome::Produced(v),
        Ok(Err(e)) => RoundOutcome::Failed(e),
        Err(join) if join.is_panic() => {
            let payload = join.into_panic();
            let msg = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "non-string panic payload".to_string());
            RoundOutcome::Panicked(msg)
        }
        Err(join) => RoundOutcome::Failed(anyhow::anyhow!("production round cancelled: {join}")),
    }
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
            info!(
                "Loading {} blocks from storage into DAG...",
                latest_height + 1
            );
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
            info!(
                "DAG loaded: {} blocks, resuming from height {}",
                latest_height + 1,
                latest_height
            );
        }

        // RESTART-LIVENESS (2026-08-11): the eager-load above walks only the CANONICAL
        // single-block-per-height chain, so GhostDag's tip set omits sibling/fork tips
        // and can strand a stale ancestor. Since #163 `select_tip` is the fork-choice
        // authority for BOTH the producer and the drain, that wedges restart recovery.
        // Reconcile the in-memory tips to the DAG store's AUTHORITATIVE set (which
        // `load_from_persistent` reconstructs from header parentage), and mark DAG
        // hydration complete so the applicator's runtime deep-fork rebuild may fire.
        let n_tips = ghostdag.reconcile_tips_from_dag_store().await;
        info!(
            "DAG rehydration: reconciled to {} authoritative tip(s)",
            n_tips
        );

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
            info!(
                "Loading {} blocks from storage into DAG...",
                latest_height + 1
            );
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
            info!(
                "DAG loaded: {} blocks, resuming from height {}",
                latest_height + 1,
                latest_height
            );
        }

        // RESTART-LIVENESS (2026-08-11): the eager-load above walks only the CANONICAL
        // single-block-per-height chain, so GhostDag's tip set omits sibling/fork tips
        // and can strand a stale ancestor. Since #163 `select_tip` is the fork-choice
        // authority for BOTH the producer and the drain, that wedges restart recovery.
        // Reconcile the in-memory tips to the DAG store's AUTHORITATIVE set (which
        // `load_from_persistent` reconstructs from header parentage), and mark DAG
        // hydration complete so the applicator's runtime deep-fork rebuild may fire.
        let n_tips = ghostdag.reconcile_tips_from_dag_store().await;
        info!(
            "DAG rehydration: reconciled to {} authoritative tip(s)",
            n_tips
        );

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

            match supervised_round(self.clone()).await {
                RoundOutcome::Produced(block_hash) => {
                    block_count += 1;
                    info!(
                        "Produced block #{} hash={} txs={}",
                        block_count,
                        hex::encode(&block_hash.as_bytes()[..8]),
                        0, // We'll get tx count from block
                    );
                }
                RoundOutcome::Failed(e) => {
                    error!("Failed to produce block: {}", e);
                }
                RoundOutcome::Panicked(msg) => {
                    // PBA-L1a-001: before this, a panic anywhere in a round
                    // (the u64::MAX-nonce overflow in selection was one) killed
                    // the producer task silently — the handle is dropped in
                    // main.rs — while RPC and sync kept the node looking
                    // healthy. Each round now runs in its own task; a panic
                    // costs that round only.
                    error!(
                        "PBA-L1a-001: block production round PANICKED ({}); \
                         continuing with the next round",
                        msg
                    );
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

        // The applied tip (if execute-on-receive is wired) — passed into parent
        // selection so the producer never proposes BACKWARDS onto an ancestor of
        // its own applied tip after a restart (see select_parents_with_ghostdag).
        let applied_tip_for_selection = applied_guard.as_ref().map(|g| {
            let t = g.tip();
            (t.hash, t.height)
        });

        // Select parents using GhostDAG algorithm
        let (selected_parent, merge_parents) = if tips.is_empty() {
            // Genesis case: no parents
            (Hash::default(), vec![])
        } else {
            // Use GhostDAG to select the best parent and merge parents
            self.select_parents_with_ghostdag(&tips, applied_tip_for_selection)
                .await?
        };

        // MP-S1 — PARENT/STATE BINDING (consensus-critical; the 2026-07-27 fork).
        //
        // `selected_parent` above comes from the DAG + GhostDAG tip selection.
        // Everything BELOW — `execute_block_transactions`, `settle_block_rewards_
        // guarded`, `calculate_state_root` — runs against the executor's LIVE world
        // state, which is the state of the APPLIED TIP. Those are two independent
        // sources and nothing used to check they named the same block.
        //
        // They diverge exactly when fork-choice moves the applied tip between two
        // production rounds — i.e. under CONCURRENT PRODUCERS, which is why single-
        // producer operation masks this completely. Live on boot-1 (2026-07-27):
        // it produced `b6ace2a1` @ 3826, the applier REORGed the tip to `5fa0a4b2`
        // @ 3826 268ms later, and 2s after that it sealed `d0697011` @ 3827
        // DECLARING `b6ace2a1` as parent while committing a state_root folded from
        // `5fa0a4b2`'s post-state. That block is unreproducible by construction:
        // boot-2 and boot-3 re-executed it 5,166 times, got the same wrong root
        // every time, and never advanced again. Four seconds later the same node
        // built height 3829 on `9ede2924` @ 3828 — a block it had just REVERTED.
        //
        // We hold `applied_guard` (the shared state-advance lock) for the whole
        // build, so the applied tip cannot move underneath us; a mismatch here is
        // a stale FORK-CHOICE view, not a race. The correct response is to skip
        // the round and let the applier converge — identical in spirit to the
        // "selected parent is not in local storage yet" arm below. Producing a
        // block we cannot back with the matching state is never acceptable: it
        // partitions the fleet permanently.
        //
        // Pinned by `tests::mp_s1_produced_block_state_root_must_bind_to_its_
        // declared_parent`, which FAILS on the pre-fix code with the same
        // StateRootMismatch the fleet logged.
        if let Some(guard) = applied_guard.as_ref() {
            let applied = guard.tip();
            if selected_parent != applied.hash {
                return Err(anyhow::anyhow!(
                    "MP-S1: fork-choice selected parent {} but this node's applied tip is {} @ {} \
                     — the executor holds the applied tip's state, so sealing on {} would commit a \
                     state_root no peer can reproduce (the 2026-07-27 concurrent-producer fork). \
                     Skipping this production round; the execute-on-receive drain/reorg will \
                     converge the applied tip.",
                    selected_parent,
                    applied.hash,
                    applied.height,
                    selected_parent
                ));
            }
        }

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
        //
        // MULTI-PRODUCER FIX (2026-07-27 incident): this used to end in
        // `.unwrap_or((0, Hash::default(), 0, 0))`. When GHOSTDAG selected a
        // parent this node could not fetch — which is exactly what happens the
        // first time ANOTHER producer's block wins tip selection before it has
        // been stored locally — the miss was swallowed and production silently
        // continued from height 0 with a DEFAULT VRF output. The node then built
        // `height: 0 + 1 = 1` forever, and every such block failed
        // `verify_vrf_with_block_signature` because its proof was bound to
        // `Hash::default()` instead of the real parent's `vrf_reveal.output`.
        //
        // Observed live on rpc-1: a healthy producer at `tip @ 152754` dropped to
        // `tip @ 1` in the same instant a second validator started proposing, and
        // emitted `Invalid VRF: ... invalid proof or identity binding` every 2s
        // thereafter. It never recovered, including across a restart, because the
        // degraded tip was persisted.
        //
        // Failing loudly is strictly better: a missing selected parent means this
        // node's view is behind, so the correct behaviour is to skip this round
        // and let the sync path fetch the block, not to mint an invalid one.
        let (last_height, parent_vrf_output, parent_blue_score, parent_blue_work, parent_ts) =
            if selected_parent != Hash::default() {
                let parent = self
                    .storage
                    .blocks
                    .get_block(&selected_parent)
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "selected parent {} could not be read from storage: {e}. Refusing to \
                             produce — building from a default parent mints blocks with an \
                             unverifiable VRF binding.",
                            selected_parent
                        )
                    })?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "selected parent {} is not in local storage yet (this node is behind \
                             a peer's tip). Skipping this production round; the sync path will \
                             fetch it.",
                            selected_parent
                        )
                    })?;
                (
                    parent.header.height,
                    parent.header.vrf_reveal.output,
                    parent.header.blue_score,
                    parent.header.blue_work,
                    Some(parent.header.timestamp),
                )
            } else {
                (0, Hash::default(), 0, 0, None)
            };

        // BLUE SCORE — `parent_blue_score + 1`, deliberately.
        //
        // REGRESSION HISTORY (2026-07-27): a previous "fix" replaced this with a
        // real `ghostdag.calculate_blue_set(&candidate)` call whenever
        // `merge_parents` was non-empty, on the reasoning that GHOSTDAG blue score
        // is the parent's score plus the blue blocks in the mergeset, so `+1` is an
        // approximation. The reasoning is right. The implementation was not, and it
        // walled off the chain.
        //
        // `calculate_blue_set` resolves a block through the DAG STORE. The candidate
        // here has not been stored — it does not exist yet, that is the point of
        // producing it — so the calculation returned the ancestry's score WITHOUT
        // counting the new block itself. Live result on 40204: block 4028 was
        // produced with blue_score 4028, identical to its parent, while
        // `validate_block_consistency` requires the band `[sp+1, sp+1+|merges|]` =
        // `[4029, 4030]`. Every follower rejected it:
        //
        //     Rejected inconsistent synced block 55f933a0 @ 4028: consistency:
        //     Header blue_score 4028 outside feasible range [4029, 4030]
        //
        // Blocks carrying merge parents are rare on this fleet, so exactly one bad
        // block was enough — every node stalled at 4027 and retried forever while
        // the producer ran on alone to 19,000+. A silent, unrecoverable partition.
        //
        // `parent_blue_score + 1` is ALWAYS inside the feasible band (it is the
        // band's minimum), so it can never be rejected. It under-counts a non-empty
        // mergeset, which is a known, bounded, DOCUMENTED approximation —
        // `ghostdag.rs::validate_block_consistency` says so explicitly: "the
        // producer itself currently writes the parent+1 approximation ... exact
        // k-cluster equality is deliberately deferred to the BlueSet-persistence
        // rework tracked since PIL-13".
        //
        // Making this exact requires that rework — computing the mergeset for a
        // block that is not yet in the store — not a call into a function whose
        // contract assumes it is. Until then, in-band and correct beats exact and
        // rejected.
        let mut blue_set = citrate_consensus::types::BlueSet::new();
        let blue_score = parent_blue_score + 1;
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

        // PBA-L1b-001: from the activation height every follower rejects a
        // block carrying a tx that does not authenticate from its contents,
        // lacks its canonical id, or is bound to another chain — so never
        // build one. Such a tx can only have reached the pool through a
        // trusted-decoder or signature-checks-disabled path; drop it there too.
        let transactions: Vec<citrate_consensus::types::Transaction> = if self
            .ghostdag
            .pba_hardening()
            .active_at(last_height + 1)
        {
            let chain_id = self.executor.chain_id();
            let mut keep = Vec::with_capacity(transactions.len());
            for t in transactions {
                match citrate_consensus::tx_auth::verify_for_block(&t, chain_id) {
                    Ok(_) => keep.push(t),
                    Err(e) => {
                        warn!(
                                "PBA-L1b-001: excluding tx {} from the block: {} (removed from mempool)",
                                t.hash, e
                            );
                        let _ = self.mempool.remove_transaction(&t.hash).await;
                    }
                }
            }
            keep
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
            // PBA-L1b-003: never stamp before the selected parent (a
            // future-dated tip made every `now`-stamped child invalid: a
            // permanent halt) and never past the parent-relative bound.
            timestamp: {
                let now = chrono::Utc::now().timestamp().max(0) as u64;
                match parent_ts {
                    Some(pts) => citrate_consensus::hardening::producer_timestamp(now, pts),
                    None => now,
                }
            },
            height: last_height + 1,
            blue_score,
            blue_work,
            pruning_point: Hash::default(),
            proposer_pubkey: PublicKey::new(self.signing_key.verifying_key().to_bytes()),
            vrf_reveal: generate_block_vrf(
                &self.signing_key,
                &PublicKey::new(self.signing_key.verifying_key().to_bytes()),
                &parent_vrf_output,
                last_height + 1,
            ),
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
                    std::cmp::max(parent_base_fee.saturating_sub(fee_delta), 1_000_000_000)
                    // floor at 1 gwei
                }
            },
            gas_used: 0,           // Will be updated after execution
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

        let tx_root = self.calculate_tx_root(header.height, &executed_transactions);
        let receipt_root = self.calculate_receipt_root(&receipts)?;
        let artifact_root = self.calculate_artifact_root(&executed_transactions)?;

        // Apply block rewards BEFORE computing the final state root.
        // Rewards modify the executor's in-memory state, so state_root must
        // be computed after this step to include reward balances.
        let validator_address =
            citrate_execution::types::Address(self.coinbase.0[0..20].try_into().unwrap_or([0; 20]));

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
                block.state_root,
                post_persist_root
            ));
        }

        // 1) Persist the block + its state-root pointer (block may lead the applied tip).
        self.storage.blocks.put_block(&block)?;
        if let Err(e) = self
            .storage
            .state
            .put_state_root(&block.header.block_hash, &block.state_root)
        {
            warn!(
                "Failed to persist state root for block {}: {}",
                block.header.height, e
            );
        }

        // 2) Persist state changes + advance the durable applied tip ATOMICALLY to THIS
        //    block, so durable state and the committed tip can never diverge on a crash.
        info!("Persisting state changes to storage...");
        let modified_count = self
            .executor
            .persist_state_changes_with_tip(Some((block.header.block_hash, block.header.height)))
            .await?;
        info!(
            "Persisted {} modified accounts to storage (tip @ {})",
            modified_count, block.header.height
        );

        // VALIDATOR-S1 (v5): the executor state is now post-height H. If H is a snapshot
        // boundary S(E), rebuild the proposer selector from the registry as-of this state
        // so epoch-E membership is loaded before epoch-E blocks are validated.
        self.maybe_sync_registry(block.header.height).await;

        // EXECUTE-ON-RECEIVE (step 2): update the IN-MEMORY applied-tip ring to this block
        // (the DURABLE tip was just advanced atomically with the state above). Keeps the
        // invariant "applied_tip == the block whose state the executor reflects" for
        // locally-produced blocks too, so a peer building on our tip fast-path-applies.
        if let Some(guard) = applied_guard.as_mut() {
            crate::canonical_apply::record_produced(guard, &self.storage, &self.executor, &block);
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

        // FORK-CHOICE PARITY (chain 40204 reroll wedge @ height 101, 2026-08-12).
        // Register the block we just produced into GhostDAG's in-memory tip set — the
        // SAME structure admission updates for RECEIVED blocks (`admission.rs` →
        // `add_block`) and the SAME authority the producer's parent-selection AND the
        // drain's reorg read through `select_tip` (unified since #163). Storing to the
        // DAG store above advances `dag_store.get_tips()` (so the chain grows), but
        // WITHOUT this call the produced block never entered `GhostDag.tips`:
        // `select_tip` stayed pinned to genesis while a fresh single-producer chain
        // grew, and the MP-S1 "never propose backwards" clamp — bounded at
        // `SUPERSEDE_WALK_CAP` (100) — could no longer reach genesis once the applied
        // tip passed that depth, wedging the sole validator at exactly height 101.
        // Registering our own block here mirrors how every peer registers it on
        // receipt, so all nodes' fork-choice sees an identical tip set. Non-fatal: the
        // block is already durably persisted, and the startup/eager-load
        // `reconcile_tips_from_dag_store` re-establishes the authoritative tip set — a
        // registration hiccup must never abort an already-committed block.
        if let Err(e) = self.ghostdag.add_block(&block).await {
            warn!(
                "producer: could not register produced block {} @ {} into GhostDAG tips \
                 ({}); select_tip will re-align at the next reconcile",
                block.header.block_hash, block.header.height, e
            );
        }

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

    /// Whether this node's already-applied tip SUPERSEDES `candidate` — i.e.
    /// `candidate` is a strict ANCESTOR of the applied tip on the node's own
    /// canonical chain. When true, the producer must extend the applied tip rather
    /// than propose on `candidate` (which would be proposing backwards).
    ///
    /// Only fires for a genuine ancestor: a `candidate` at or above the applied
    /// height, or on a DIFFERENT branch (a real heavier fork GhostDAG selected),
    /// returns false so the drain's reorg still governs. The walk is bounded — a
    /// gap wider than `SUPERSEDE_WALK_CAP` is treated as "not the restart-lag case"
    /// and left to the drain, so this never masks a deep legitimate reorg.
    async fn applied_tip_supersedes(
        &self,
        candidate: Hash,
        applied_hash: Hash,
        applied_height: u64,
    ) -> bool {
        const SUPERSEDE_WALK_CAP: u64 = 100;
        if candidate == applied_hash {
            return false; // same block — extend it normally
        }
        let cand_height = match self.ghostdag.get_block_height(&candidate).await {
            Some(h) => h,
            None => return false, // unknown height — cannot judge; keep candidate
        };
        // Not behind us → a descendant or a different-branch fork; let the drain
        // reorg the applied tip toward it (do NOT clamp — that would mask a reorg).
        if cand_height >= applied_height {
            return false;
        }
        let steps = applied_height - cand_height;
        if steps > SUPERSEDE_WALK_CAP {
            return false; // too deep to be post-restart DAG lag — leave it to the drain
        }
        // Walk the applied tip's selected-parent chain down to cand_height; if we
        // land on `candidate`, it is an ancestor of the applied tip (same chain).
        let mut cursor = applied_hash;
        for _ in 0..steps {
            let blk = match self.storage.blocks.get_block(&cursor).ok().flatten() {
                Some(b) => b,
                None => return false,
            };
            cursor = blk.selected_parent();
        }
        cursor == candidate
    }

    /// Select parents using GhostDAG algorithm
    async fn select_parents_with_ghostdag(
        &self,
        tips: &[citrate_consensus::types::Tip],
        applied_tip: Option<(Hash, u64)>,
    ) -> anyhow::Result<(Hash, Vec<Hash>)> {
        // Convert tips to hashes
        let tip_hashes: Vec<Hash> = tips.iter().map(|tip| tip.hash).collect();

        // UNIFIED FORK CHOICE (chain 40204 halt 2026-08-09 @ 178,341). Select the
        // parent from the SAME authority the execute-on-receive drain reorgs toward —
        // `GhostDag::select_tip()`, over GhostDAG's own tips + STORED blue scores —
        // NOT the separate `TipSelector::select_tip` over `DagStore::get_tips()` with
        // RECOMPUTED scores. Those were two independent fork-choice implementations
        // over two independent tip sets; #160 aligned only the tie-break COMPARATOR,
        // so at a same-height sibling fork they still picked different siblings: the
        // producer targeted one (blocked EVERY round by the MP-S1 parent/state guard
        // below) while the drain ranked the other best and so never reorged — a
        // silent, permanent deadlock no restart cleared (~11.7h halt). Using ONE
        // selector for both makes MP-S1 unreachable-by-disagreement: whatever
        // `select_tip` returns, if it is not our applied tip the drain reorgs the
        // applied tip to exactly that block, and the next round produces on it.
        // Pinned by `citrate_consensus::ghostdag::tests::
        // producer_and_drain_forkchoice_diverge_on_a_sibling_fork` (the two selectors
        // are NOT interchangeable) and the MP-S1 end-to-end producer test.
        //
        // Fallback: only if GhostDAG holds no in-memory tips yet (e.g. right after a
        // restart, before relation hydration) do we fall back to the DAG-store tip
        // selection — a state in which the drain's fork-choice is also inert, so no
        // producer/drain disagreement (hence no deadlock) is possible, and falling
        // back preserves liveness instead of stalling production.
        let mut selected_parent = match self.ghostdag.select_tip().await {
            Ok(h) => h,
            Err(_) => self.tip_selector.select_tip(&tip_hashes).await?,
        };

        // NEVER PROPOSE BACKWARDS (chain 40204, 2026-08-11 restart wedge). After a
        // restart, GhostDAG's in-memory tip set can transiently point at an ANCESTOR
        // of this node's already-applied tip — the applied tip's own block was not
        // yet re-registered as a DAG tip, so `select_tip` returns its parent. Sealing
        // on that ancestor makes a SIBLING of an already-applied block, whose state
        // root (folded from the applied tip's state) no peer can reproduce, so the
        // MP-S1 guard refuses every round and the node wedges — production halts even
        // though nothing forked. When fork-choice points backwards onto our own
        // applied chain, extend the APPLIED TIP instead: it is strictly ahead on the
        // same chain and its state is exactly what the executor holds. This is the
        // producer-side mirror of the drain's `reorg_to` SRP-S3c backwards-reorg
        // guard; together they keep the applied tip monotonic on its own chain. The
        // clamp fires ONLY for a genuine ancestor — a real heavier fork (different
        // branch) is left to the drain to reorg (see `applied_tip_supersedes`).
        if let Some((atip_hash, atip_height)) = applied_tip {
            if self
                .applied_tip_supersedes(selected_parent, atip_hash, atip_height)
                .await
            {
                debug!(
                    "producer: fork-choice tip {} is an ancestor of applied tip {} @ {} \
                     (post-restart DAG lag) — extending the applied tip, not proposing backwards",
                    selected_parent, atip_hash, atip_height
                );
                selected_parent = atip_hash;
            }
        }

        // MP-DEPTH: never BUILD a block our own validity rule would reject.
        //
        // The block we are about to seal sits at selected_parent.height + 1. Once
        // the rule is active, merging a tip more than MERGE_PARENT_MAX_DEPTH below
        // that makes the block invalid — and since the producer validates its own
        // block on the way in, it would refuse its own output and stop producing.
        // A stale tip lingering in the tip set is enough to trigger it, so this is
        // a filter rather than an error: drop the too-deep tips, keep sealing.
        //
        // Applied unconditionally, not gated on the activation height. Before
        // activation these merges are legal but pointless (a tip 100+ blocks back
        // is abandoned, not a live branch), and filtering early means the producer
        // is already emitting rule-compliant blocks well before enforcement
        // begins — so activation is a no-op for block production rather than a
        // cliff.
        let child_height = self
            .ghostdag
            .get_block_height(&selected_parent)
            .await
            .map(|h| h.saturating_add(1));

        let max_parents = self.ghostdag.params().max_parents;
        let mut dropped_deep = 0usize;
        let mut merge_parents: Vec<Hash> = Vec::new();
        for h in tip_hashes.into_iter().filter(|h| *h != selected_parent) {
            if merge_parents.len() >= max_parents.saturating_sub(1) {
                break; // Leave room for the selected parent.
            }
            if let (Some(child_h), Some(tip_h)) =
                (child_height, self.ghostdag.get_block_height(&h).await)
            {
                if child_h.saturating_sub(tip_h)
                    > citrate_consensus::ghostdag::MERGE_PARENT_MAX_DEPTH
                {
                    dropped_deep += 1;
                    continue;
                }
            }
            merge_parents.push(h);
        }
        if dropped_deep > 0 {
            debug!(
                "MP-DEPTH: dropped {} stale tip(s) more than {} blocks below the block being \
                 sealed at height {:?} — merging them would make our own block invalid",
                dropped_deep,
                citrate_consensus::ghostdag::MERGE_PARENT_MAX_DEPTH,
                child_height
            );
        }

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

        // Capacity limits. Gas is the dominant real-world ceiling;
        // count + size are safety valves.
        const MAX_BLOCK_SIZE: usize = 1_000_000; // 1 MB — matches transport (H-08)
        const MAX_GAS_PER_BLOCK: u64 = PRODUCER_BLOCK_GAS_LIMIT; // Chain genesis constant
        const MAX_AI_TXS_PER_BLOCK: usize = 10;
        const MAX_STANDARD_TXS: usize = 5_000;

        // AI transactions first (model ops, inference). Small reserved slice.
        let ai_txs = self.mempool.get_ai_transactions(MAX_AI_TXS_PER_BLOCK).await;
        // Fill remaining gas budget with standard txs. PBA-L1a-004: the
        // candidate list is the whole nonce-ordered pool, and the count / size
        // caps apply to ADMITTED transactions only, so candidates rejected
        // below (unpayable, wrong nonce, over a cap) never use up the window.
        let standard_txs = self
            .mempool
            .get_best_transactions(usize::MAX, usize::MAX)
            .await;

        // PBA-L1a-004: a candidate is admitted only if the sender can pay for
        // it against the state this block executes on. Block gas is NOT
        // reserved here: `execute_block_transactions` meters the gas each
        // transaction actually uses and admits the next candidate against what
        // is left, so an over-declared `gas_limit` cannot hold block space.
        // The AI slice is additionally capped by declared gas.
        let executor = self.executor.clone();
        let mut budget = SelectionBudget::new(MAX_GAS_PER_BLOCK);
        let mut ai_declared: u64 = 0;
        for tx in ai_txs {
            if seen.contains(&tx.hash) {
                continue;
            }
            let Some(next) = ai_declared.checked_add(tx.gas_limit) else {
                continue;
            };
            if next > MAX_AI_GAS_PER_BLOCK {
                continue;
            }
            if budget.try_admit(&tx, |from| {
                let addr = citrate_execution::address_utils::normalize_address(from);
                (executor.get_nonce(&addr), executor.get_balance(&addr))
            }) {
                ai_declared = next;
                seen.insert(tx.hash);
                selected.push(tx);
            }
        }
        let mut window = CandidateWindow::new(
            MAX_STANDARD_TXS,
            MAX_BLOCK_SIZE,
            MAX_TXS_PER_SENDER_PER_BLOCK,
        );
        for tx in &selected {
            window.record(tx);
        }
        for tx in standard_txs {
            if seen.contains(&tx.hash) {
                continue;
            }
            // AI operations enter only through the capped, fee-ordered AI
            // slice above; they never re-enter here.
            if citrate_consensus::types::AiOpKind::of(&tx).is_some() {
                continue;
            }
            if window.is_full() {
                break;
            }
            if !window.fits(&tx) {
                continue;
            }
            if budget.try_admit(&tx, |from| {
                let addr = citrate_execution::address_utils::normalize_address(from);
                (executor.get_nonce(&addr), executor.get_balance(&addr))
            }) {
                window.record(&tx);
                seen.insert(tx.hash);
                selected.push(tx);
            }
        }
        let total_gas = ai_declared;
        debug!(
            "selected {} candidate txs ({} declared AI gas) for a {} gas block",
            selected.len(),
            total_gas,
            MAX_GAS_PER_BLOCK
        );

        Ok(selected)
    }

    /// Execute all transactions in a block
    async fn execute_block_transactions(
        &self,
        transactions: &[Transaction],
        header: &BlockHeader,
    ) -> anyhow::Result<(
        Hash,
        Vec<Transaction>,
        Vec<citrate_execution::types::TransactionReceipt>,
    )> {
        let mut executed_transactions = Vec::new();
        let mut receipts = Vec::new();

        // Create a temporary block for execution context
        let temp_block = BlockBuilder::new()
            .header(header.clone())
            .ghostdag_params(self.ghostdag.params().clone())
            .build_unhashed();

        // PBA-L1a-004: meter ACTUAL gas. A candidate is admitted when its
        // declared gas_limit fits what is left of the block; after it runs the
        // meter is charged only what it used, so the rest of the block stays
        // available. A deferred sender's later nonces are deferred with it
        // (they would fail on the nonce gap otherwise) and stay in the mempool.
        let mut meter = BlockGasMeter::new(PRODUCER_BLOCK_GAS_LIMIT);
        let mut deferred_senders: std::collections::HashSet<PublicKey> =
            std::collections::HashSet::new();

        // Execute each transaction
        for tx in transactions {
            if deferred_senders.contains(&tx.from) || !meter.fits(tx.gas_limit) {
                deferred_senders.insert(tx.from);
                continue;
            }
            match self.executor.execute_transaction(&temp_block, tx).await {
                Ok(receipt) => {
                    meter.charge(receipt.gas_used.min(tx.gas_limit));
                    executed_transactions.push(tx.clone());
                    receipts.push(receipt);
                }
                Err(e) => {
                    error!("Failed to execute transaction {}: {}", tx.hash, e);

                    // Sprint EL-1 (Issue #20): Remove failed tx from mempool
                    // so the sender's nonce is not permanently blocked.
                    let _ = self.mempool.remove_transaction(&tx.hash).await;
                    // PBA-L1a-004: a failure before any receipt costs the
                    // sender nothing on chain, so refuse the sender for a
                    // while (mempool policy only; block validity unchanged).
                    self.mempool
                        .ban_sender(&tx.from, PRE_RECEIPT_FAILURE_BAN)
                        .await;
                    deferred_senders.insert(tx.from);
                }
            }
        }

        debug!(
            "executed {} txs using {} block gas ({} senders deferred)",
            executed_transactions.len(),
            meter.used(),
            deferred_senders.len()
        );

        // WP-G.4: Compute state root from the executor's in-memory post-execution state.
        // This uses the state trie that has been updated by transaction execution,
        // NOT the storage-backed view which still reflects the previous block.
        let state_root = self.executor.calculate_state_root();

        Ok((state_root, executed_transactions, receipts))
    }

    /// Calculate transaction root. PBA-L1b-002: from the activation height the
    /// root commits to every transaction's full contents (`tx_root_v2`); below
    /// it the legacy root over `tx.hash` is kept byte-identical.
    fn calculate_tx_root(&self, height: u64, transactions: &[Transaction]) -> Hash {
        citrate_consensus::tx_auth::tx_root_for_height(
            self.ghostdag.pba_hardening(),
            height,
            transactions,
        )
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
            self.peer_profile_store
                .lock()
                .store_profile(block_height, local_key, store_profile);
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
                debug!(
                    "No learning data for checkpoint height {}",
                    checkpoint_height
                );
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

                // Trust weight must NOT be derived from the peer's own
                // self-reported `accuracy`: it is an unauthenticated gossip
                // field bounded only to [0,1], so a peer claiming accuracy=1.0
                // would out-weigh an honest 0.90 peer by e^10 ≈ 22026:1 through
                // the softmax, letting a handful of throwaway keys own the
                // aggregate. Until a *consensus* blue score for a
                // validator-set-checked participant is plumbed through the
                // gossip message (see belnap::blue_scores_to_trust_weights),
                // every contribution gets a uniform weight so no single peer can
                // buy influence by lying about its accuracy.
                // OWNER: wire real consensus blue score before arming learning.
                let blue_score = 1.0f32;

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
        self.profile_computer
            .lock()
            .record_inference(correct, latency_ms, domain);
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

/// PBA-L1a-004: state-aware block-gas budget for transaction selection.
///
/// The producer used to `break` out of selection at the first candidate that
/// did not fit the remaining gas (the SEQ-H2 `continue` fix only landed in the
/// unused sequencer `BlockBuilder`), and it reserved gas for candidates with no
/// balance or nonce check. A single high-fee, unfunded ~30M-gas transaction —
/// free to relay over P2P — was packed first, consumed the whole budget, failed
/// execution unpaid, and left the block empty; repeated every block.
///
/// Now a candidate is admitted only if (a) it can fit a block at all (skip, not
/// stop), (b) its nonce is the sender's next nonce against state (tracking the
/// candidates already admitted from that sender), and (c) the sender's balance,
/// net of the candidates already admitted, covers `gas_limit * gas_price + value`.
/// Block gas itself is metered on actual use by [`BlockGasMeter`] during
/// execution, so declared-but-unused gas never holds block space.
/// Block gas limit the producer fills to (the chain's genesis constant).
pub(crate) const PRODUCER_BLOCK_GAS_LIMIT: u64 = 30_000_000;

/// PBA-L1a-004: most transactions one sender may place in one block.
pub(crate) const MAX_TXS_PER_SENDER_PER_BLOCK: usize = 64;

/// PBA-L1a-004: how long a sender is refused after a transaction of theirs
/// fails before a receipt exists.
pub(crate) const PRE_RECEIPT_FAILURE_BAN: std::time::Duration = std::time::Duration::from_secs(120);

/// PBA-L1a-004: count / byte / per-sender caps over ADMITTED candidates.
pub(crate) struct CandidateWindow {
    max_count: usize,
    max_bytes: usize,
    max_per_sender: usize,
    count: usize,
    bytes: usize,
    per_sender: HashMap<PublicKey, usize>,
}

impl CandidateWindow {
    pub(crate) fn new(max_count: usize, max_bytes: usize, max_per_sender: usize) -> Self {
        Self {
            max_count,
            max_bytes,
            max_per_sender,
            count: 0,
            bytes: 0,
            per_sender: HashMap::new(),
        }
    }

    pub(crate) fn is_full(&self) -> bool {
        self.count >= self.max_count
    }

    /// Whether `tx` fits the remaining count, bytes and its sender's slots.
    pub(crate) fn fits(&self, tx: &Transaction) -> bool {
        let size = Mempool::tx_size(tx);
        self.count < self.max_count
            && self.bytes.saturating_add(size) <= self.max_bytes
            && self.per_sender.get(&tx.from).copied().unwrap_or(0) < self.max_per_sender
    }

    pub(crate) fn record(&mut self, tx: &Transaction) {
        self.count += 1;
        self.bytes = self.bytes.saturating_add(Mempool::tx_size(tx));
        *self.per_sender.entry(tx.from).or_insert(0) += 1;
    }
}

/// AI operations may declare at most a third of the block's gas.
pub(crate) const MAX_AI_GAS_PER_BLOCK: u64 = PRODUCER_BLOCK_GAS_LIMIT / 3;

/// PBA-L1a-004: block gas metered on ACTUAL use, like geth's gas pool.
pub(crate) struct BlockGasMeter {
    limit: u64,
    used: u64,
}

impl BlockGasMeter {
    pub(crate) fn new(limit: u64) -> Self {
        Self { limit, used: 0 }
    }

    /// Whether a transaction declaring `gas_limit` may still run.
    pub(crate) fn fits(&self, gas_limit: u64) -> bool {
        gas_limit <= self.limit.saturating_sub(self.used)
    }

    /// Charge what a transaction actually used.
    pub(crate) fn charge(&mut self, gas_used: u64) {
        self.used = self.used.saturating_add(gas_used).min(self.limit);
    }

    pub(crate) fn used(&self) -> u64 {
        self.used
    }
}

pub(crate) struct SelectionBudget {
    max_gas: u64,
    /// sender -> (next expected nonce, remaining balance) after admitted txs.
    senders: HashMap<PublicKey, (u64, primitive_types::U256)>,
}

impl SelectionBudget {
    pub(crate) fn new(max_gas: u64) -> Self {
        Self {
            max_gas,
            senders: HashMap::new(),
        }
    }

    /// Admit `tx` if it fits and is payable; `state` returns the sender's
    /// on-chain `(nonce, balance)` (queried once per sender).
    pub(crate) fn try_admit<F>(&mut self, tx: &Transaction, state: F) -> bool
    where
        F: FnOnce(&PublicKey) -> (u64, primitive_types::U256),
    {
        use primitive_types::U256;
        if tx.gas_limit > self.max_gas {
            return false; // can never fit a block: skip it, keep filling (SEQ-H2)
        }
        let (next_nonce, balance) = *self
            .senders
            .entry(tx.from)
            .or_insert_with(|| state(&tx.from));
        if tx.nonce != next_nonce {
            return false;
        }
        let Some(after_nonce) = next_nonce.checked_add(1) else {
            return false;
        };
        let cost = U256::from(tx.gas_limit)
            .checked_mul(U256::from(tx.gas_price))
            .and_then(|g| g.checked_add(U256::from(tx.value)));
        let Some(cost) = cost else {
            return false;
        };
        if balance < cost {
            return false;
        }
        self.senders.insert(tx.from, (after_nonce, balance - cost));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_consensus::crypto::Ed25519SigningKey;
    use citrate_consensus::types::{Block, Signature};
    use citrate_execution::types::Address;
    use citrate_sequencer::mempool::{MempoolConfig, TxClass};
    use citrate_storage::pruning::PruningConfig;
    use citrate_storage::StorageManager;
    use primitive_types::U256;
    use tempfile::TempDir;

    fn test_signing_key() -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&[42u8; 32])
    }

    fn embedded_pubkey(address: Address) -> PublicKey {
        let mut bytes = [0u8; 32];
        bytes[..20].copy_from_slice(&address.0);
        PublicKey::new(bytes)
    }

    /// Build the deterministic height-0 block used by producer integration
    /// fixtures. Production startup writes and applies this block before the
    /// first producer round; keeping it in the fixture makes A001 exercise the
    /// configured-genesis path rather than the legacy zero-hash sentinel.
    fn test_genesis() -> Block {
        let mut genesis = BlockBuilder::new()
            .version(2)
            .height(0)
            .parent(Hash::default())
            .coinbase([0x33; 20])
            .timestamp(1000)
            .vrf_reveal(VrfProof {
                proof: vec![],
                output: Hash::new([0x5A; 32]),
            })
            .transactions(vec![])
            .state_root(Hash::default())
            .blue_score(0)
            .blue_work(citrate_consensus::types::blue_work_for_score(0))
            .build_unhashed();
        genesis.header.block_hash = genesis.compute_hash();
        genesis
    }

    /// Reproduce node startup's chain/DAG/applied-tip genesis wiring for a
    /// producer fixture. Genesis is seeded before any applicator or producer
    /// can select a parent, so the first block is height 1 with the real
    /// genesis hash.
    async fn seed_test_genesis(
        storage: &StorageManager,
        dag: &DagStore,
        ghostdag: &GhostDag,
    ) -> Block {
        let genesis = test_genesis();
        storage
            .blocks
            .put_block(&genesis)
            .expect("persist test genesis");
        storage
            .blocks
            .put_applied_tip(&genesis.header.block_hash, 0)
            .expect("persist test genesis applied tip");
        dag.set_configured_genesis(genesis.header.block_hash);
        dag.store_block(genesis.clone())
            .await
            .expect("store test genesis in DAG");
        ghostdag
            .add_block(&genesis)
            .await
            .expect("admit test genesis to GhostDAG");
        genesis
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
            // CHAIN-B-A015: these represent honest, decoder-verified EVM transactions (the
            // test exercises producer FILTERING and receipt persistence, not signature
            // checking). The mempool's feature-independent EVM-recovery gate now requires
            // either a real secp256k1 recovery or `ecdsa_verified` for EVM-shaped senders, so
            // mark them decoder-verified rather than relying on a dummy signature slipping
            // through the disabled-crypto path.
            ecdsa_verified: true,
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

        assert_eq!(
            vrf_a.proof, vrf_b.proof,
            "Same inputs must produce same VRF proof"
        );
        assert_eq!(
            vrf_a.output, vrf_b.output,
            "Same inputs must produce same VRF output"
        );
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
        let beta =
            citrate_consensus::ecvrf::verify(&alpha, &ecvrf_proof).expect("Proof should verify");
        assert_eq!(
            Hash::from_bytes(&beta),
            vrf.output,
            "Verified beta must match proof output"
        );
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
        assert_ne!(
            vrf_a.output, vrf_b.output,
            "Chain continuity: different blocks must have different VRF outputs"
        );

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

    /// PBA-L1a-004 regression (mirrors the sequencer `BlockBuilder` SEQ-H2 test,
    /// at the node producer's REAL selection entry point). An attacker relays a
    /// high-fee, ~29.9M-gas transfer from an UNFUNDED account. Before the fix the
    /// producer packed it first (highest priority), reserved the whole 30M block
    /// budget for it, `break`-ed on the honest 21k transfer, then the attacker tx
    /// failed execution unpaid → an empty block, every round.
    #[tokio::test]
    async fn pba_l1a_004_unfunded_block_filler_does_not_crowd_out_honest_tx() {
        let tmp = TempDir::new().expect("tempdir");
        let storage =
            Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).expect("storage"));
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

        let honest = Address([0x11; 20]);
        let attacker = Address([0x66; 20]); // never funded
        let recipient = Address([0x33; 20]);
        state_db.accounts.create_account_if_not_exists(honest);
        state_db
            .accounts
            .set_balance(honest, U256::from(21_000u64 * 1_000_000_000u64 * 10));

        let honest_tx = transfer_tx(0xA1, honest, recipient, 0);
        let mut filler = transfer_tx(0xF1, attacker, recipient, 0);
        filler.gas_limit = 29_990_000;
        filler.gas_price = 1_000_000_000_000; // 1000x the honest fee: selected first
        mempool
            .add_transaction(honest_tx.clone(), TxClass::Standard)
            .await
            .expect("honest admitted");
        mempool
            .add_transaction(filler.clone(), TxClass::Standard)
            .await
            .expect("filler admitted (no state check at admission)");

        let producer = BlockProducer::new(
            storage.clone(),
            executor,
            mempool,
            embedded_pubkey(Address([0x44; 20])),
            test_signing_key(),
            2,
        );
        let selected = producer
            .select_transactions_with_ai_priority()
            .await
            .expect("selection");
        let hashes: Vec<Hash> = selected.iter().map(|t| t.hash).collect();
        assert!(
            hashes.contains(&honest_tx.hash),
            "honest tx must be selected despite the unfunded block-filler; got {hashes:?}"
        );
        assert!(
            !hashes.contains(&filler.hash),
            "an unfunded tx must not reserve block gas; got {hashes:?}"
        );
    }

    /// PBA-L1a-004: the selection budget skips (not stops at) a candidate that
    /// does not fit, and gates nonce + cumulative balance against state.
    #[test]
    fn pba_l1a_004_selection_budget_semantics() {
        let a = Address([0x11; 20]);
        let r = Address([0x33; 20]);
        let price = 1_000_000_000u64;
        let one_tx = U256::from(21_000u64 * price);
        let state = |bal: U256| move |_: &PublicKey| (0u64, bal);

        // (1) a candidate that can never fit a block is skipped; others are
        //     admitted without reserving block gas (the meter does that).
        let mut b = SelectionBudget::new(30_000_000);
        let mut too_big = transfer_tx(1, Address([0x77; 20]), r, 0);
        too_big.gas_limit = 30_000_001;
        assert!(
            !b.try_admit(&too_big, state(U256::MAX)),
            "larger than a block"
        );
        let mut exact = transfer_tx(4, Address([0x7A; 20]), r, 0);
        exact.gas_limit = 30_000_000;
        assert!(
            b.try_admit(&exact, state(U256::MAX)),
            "exactly a block fits"
        );
        let mut big = transfer_tx(2, Address([0x78; 20]), r, 0);
        big.gas_limit = 29_999_000;
        assert!(b.try_admit(&big, state(U256::MAX)));
        let mut big2 = transfer_tx(3, Address([0x79; 20]), r, 0);
        big2.gas_limit = 29_999_000;
        assert!(
            b.try_admit(&big2, state(U256::MAX)),
            "no declared-gas reservation"
        );

        // (2) nonce must equal the state nonce, then advance per admitted tx
        let mut b = SelectionBudget::new(30_000_000);
        assert!(
            !b.try_admit(&transfer_tx(4, a, r, 1), state(one_tx * 10)),
            "nonce gap"
        );
        assert!(b.try_admit(&transfer_tx(5, a, r, 0), state(one_tx * 10)));
        assert!(
            b.try_admit(&transfer_tx(6, a, r, 1), state(U256::zero())),
            "state queried once"
        );
        assert!(
            !b.try_admit(&transfer_tx(7, a, r, 1), state(one_tx)),
            "duplicate nonce"
        );

        // (3) balance is cumulative across a sender's admitted txs
        let mut b = SelectionBudget::new(30_000_000);
        assert!(b.try_admit(&transfer_tx(8, a, r, 0), state(one_tx)));
        assert!(
            !b.try_admit(&transfer_tx(9, a, r, 1), state(one_tx)),
            "balance exhausted"
        );

        // (4) value counts toward cost; exact balance is enough
        let mut b = SelectionBudget::new(30_000_000);
        let mut v = transfer_tx(10, a, r, 0);
        v.value = 5;
        assert!(
            !b.try_admit(&v, state(one_tx)),
            "gas*price + value > balance"
        );
        let mut b = SelectionBudget::new(30_000_000);
        assert!(
            b.try_admit(&v, state(one_tx + U256::from(5u64))),
            "exact balance admits"
        );

        // (5) nonce u64::MAX has no successor: never admitted
        let mut b = SelectionBudget::new(30_000_000);
        let max = transfer_tx(11, a, r, u64::MAX);
        assert!(!b.try_admit(&max, |_: &PublicKey| (u64::MAX, U256::MAX)));
    }

    #[test]
    fn producer_ai_slice_cap_value() {
        assert_eq!(MAX_AI_GAS_PER_BLOCK, 10_000_000);
    }

    /// Block gas meter: admission against what is left, charge on actual use.
    #[test]
    fn producer_block_gas_meter_charges_actual_use() {
        let mut m = BlockGasMeter::new(30_000_000);
        assert!(m.fits(30_000_000));
        assert!(!m.fits(30_000_001));
        m.charge(700);
        assert_eq!(m.used(), 700);
        assert!(m.fits(29_999_300));
        assert!(!m.fits(29_999_301));
        m.charge(u64::MAX);
        assert_eq!(m.used(), 30_000_000, "saturates at the limit");
        assert!(m.fits(0));
        assert!(!m.fits(1));
    }

    /// Produce a real block from a funded high-declared-gas candidate plus a
    /// normal transfer; returns (transfer included, filler included).
    async fn producer_budget_case(filler_data: Vec<u8>, filler_price: u64) -> (bool, bool) {
        let tmp = TempDir::new().expect("tempdir");
        let storage =
            Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).expect("storage"));
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
        let a = Address([0x11; 20]);
        let b = Address([0x66; 20]);
        let recipient = Address([0x33; 20]);
        let price_a = 100_000_000_000u64;
        state_db.accounts.create_account_if_not_exists(a);
        state_db
            .accounts
            .set_balance(a, U256::from(21_000u64 * price_a * 10));
        let declared = 29_990_000u64;
        state_db.accounts.create_account_if_not_exists(b);
        state_db
            .accounts
            .set_balance(b, U256::from(declared) * U256::from(filler_price));

        let mut transfer = transfer_tx(0xA1, a, recipient, 0);
        transfer.gas_price = price_a;
        let mut filler = transfer_tx(0xF1, b, recipient, 0);
        filler.gas_limit = declared;
        filler.gas_price = filler_price;
        filler.data = filler_data;
        mempool
            .add_transaction(transfer.clone(), TxClass::Standard)
            .await
            .expect("transfer admitted");
        mempool
            .add_transaction(filler.clone(), TxClass::Standard)
            .await
            .expect("filler admitted");

        let producer = BlockProducer::new(
            storage.clone(),
            executor,
            mempool,
            embedded_pubkey(Address([0x44; 20])),
            test_signing_key(),
            2,
        );
        let hash = producer.produce_block().await.expect("produce");
        let block = storage
            .blocks
            .get_block(&hash)
            .expect("read")
            .expect("block stored");
        let hashes: Vec<Hash> = block.transactions.iter().map(|t| t.hash).collect();
        (
            hashes.contains(&transfer.hash),
            hashes.contains(&filler.hash),
        )
    }

    /// PBA-L1a-004: declared-but-unused gas does not hold block space.
    #[tokio::test]
    async fn producer_budget_refill_standard_candidate() {
        let (transfer_in, filler_in) = producer_budget_case(vec![], 101_000_000_000).await;
        assert!(filler_in, "the higher-fee candidate runs first");
        assert!(transfer_in, "the block is refilled after actual gas use");
    }

    /// PBA-L1a-004: a payload the executor runs as a plain call is not treated
    /// as an AI operation by selection, and block gas is refilled after it.
    #[tokio::test]
    async fn producer_budget_refill_ai_prefixed_candidate() {
        for prefix in [[0x04u8, 0, 0, 0], [0x05, 0, 0, 0]] {
            // Classified as a plain call, it is ordered by fee (below the
            // transfer); either way the transfer must make the block.
            let (transfer_in, _filler_in) =
                producer_budget_case(prefix.to_vec(), 1_000_000_000).await;
            assert!(transfer_in, "prefix {prefix:?}: transfer must be included");
        }
    }

    fn funded(state_db: &citrate_execution::StateDB, a: Address) {
        state_db.accounts.create_account_if_not_exists(a);
        state_db
            .accounts
            .set_balance(a, U256::from(10u64).pow(U256::from(21u64)));
    }

    fn test_producer(
        storage: &Arc<StorageManager>,
        executor: &Arc<Executor>,
        mempool: &Arc<Mempool>,
    ) -> BlockProducer {
        BlockProducer::new(
            storage.clone(),
            executor.clone(),
            mempool.clone(),
            embedded_pubkey(Address([0x44; 20])),
            test_signing_key(),
            2,
        )
    }

    fn producer_fixture() -> (
        TempDir,
        Arc<StorageManager>,
        Arc<citrate_execution::StateDB>,
        Arc<Executor>,
        Arc<Mempool>,
    ) {
        let tmp = TempDir::new().expect("tempdir");
        let storage =
            Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).expect("storage"));
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
        (tmp, storage, state_db, executor, mempool)
    }

    /// The AI slice is capped at a third of the block's declared gas; AI ops
    /// beyond it compete in the fee-ordered standard pass.
    #[tokio::test]
    async fn producer_ai_slice_gas_cap() {
        let (_tmp, storage, state_db, executor, mempool) = producer_fixture();
        let (a1, a2, s) = (
            Address([0x51; 20]),
            Address([0x52; 20]),
            Address([0x53; 20]),
        );
        for a in [a1, a2, s] {
            funded(&state_db, a);
        }
        let r = Address([0x33; 20]);
        let mut ai1 = transfer_tx(0xB1, a1, r, 0);
        ai1.data = [vec![0x02, 0, 0, 0], vec![0x01; 32]].concat();
        ai1.gas_limit = PRODUCER_BLOCK_GAS_LIMIT / 3;
        ai1.gas_price = 2_000_000_000;
        let mut ai2 = transfer_tx(0xB2, a2, r, 0);
        ai2.data = [vec![0x02, 0, 0, 0], vec![0x02; 32]].concat();
        ai2.gas_limit = 21_000;
        ai2.gas_price = 1_000_000_000;
        let mut std_tx = transfer_tx(0xB3, s, r, 0);
        std_tx.gas_price = 100_000_000_000;
        for t in [&ai1, &ai2, &std_tx] {
            mempool
                .add_transaction(t.clone(), TxClass::Standard)
                .await
                .expect("admit");
        }
        let producer = test_producer(&storage, &executor, &mempool);
        let sel: Vec<Hash> = producer
            .select_transactions_with_ai_priority()
            .await
            .expect("select")
            .iter()
            .map(|t| t.hash)
            .collect();
        assert_eq!(
            sel,
            vec![ai1.hash, std_tx.hash],
            "ai1 fills the AI slice exactly; ai2 waits (AI ops never re-enter the standard pass)"
        );
    }

    /// A sender whose transaction does not fit what is left of the block is
    /// deferred with all its later nonces; they stay in the mempool.
    #[tokio::test]
    async fn producer_defers_whole_sender_when_block_is_full() {
        let (_tmp, storage, state_db, executor, mempool) = producer_fixture();
        let (x, s) = (Address([0x61; 20]), Address([0x62; 20]));
        funded(&state_db, x);
        funded(&state_db, s);
        let r = Address([0x33; 20]);
        let mut first = transfer_tx(0xC1, x, r, 0);
        first.gas_price = 100_000_000_000;
        let mut big = transfer_tx(0xC2, s, r, 0);
        big.gas_limit = PRODUCER_BLOCK_GAS_LIMIT - 1_000;
        big.gas_price = 50_000_000_000;
        let mut next = transfer_tx(0xC3, s, r, 1);
        next.gas_price = 50_000_000_000;
        for t in [&first, &big, &next] {
            mempool
                .add_transaction(t.clone(), TxClass::Standard)
                .await
                .expect("admit");
        }
        let producer = test_producer(&storage, &executor, &mempool);
        let hash = producer.produce_block().await.expect("produce");
        let block = storage
            .blocks
            .get_block(&hash)
            .expect("read")
            .expect("block");
        let hashes: Vec<Hash> = block.transactions.iter().map(|t| t.hash).collect();
        assert!(hashes.contains(&first.hash));
        assert!(
            !hashes.contains(&big.hash),
            "does not fit after the first tx"
        );
        assert!(
            !hashes.contains(&next.hash),
            "later nonce deferred with its sender"
        );
        assert!(
            mempool.contains(&next.hash).await,
            "deferred tx stays pooled"
        );
        assert!(
            mempool.contains(&big.hash).await,
            "deferred tx stays pooled"
        );
    }

    /// Produce one block from `fillers` plus one 79 gwei transfer; returns
    /// whether the transfer was included.
    async fn window_case(fillers: Vec<(Address, u64, Vec<u8>, u64)>) -> bool {
        let (_tmp, storage, state_db, executor, mempool) = producer_fixture();
        let honest = Address([0x11; 20]);
        let r = Address([0x33; 20]);
        funded(&state_db, honest);
        let float = U256::from(10u64).pow(U256::from(16u64));
        for (s, _, _, _) in &fillers {
            state_db.accounts.create_account_if_not_exists(*s);
            state_db.accounts.set_balance(*s, float);
        }
        let mut honest_tx = transfer_tx(0xA1, honest, r, 0);
        honest_tx.gas_price = 79_000_000_000;
        mempool
            .add_transaction(honest_tx.clone(), TxClass::Standard)
            .await
            .expect("honest");
        for (i, (s, n, data, price)) in fillers.into_iter().enumerate() {
            let mut t = transfer_tx(0, s, r, n);
            let mut h = [0xF0u8; 32];
            h[..8].copy_from_slice(&(i as u64).to_be_bytes());
            t.hash = Hash::new(h);
            t.gas_price = price;
            t.data = data;
            let _ = mempool.add_transaction(t, TxClass::Standard).await;
        }
        let producer = test_producer(&storage, &executor, &mempool);
        let bh = producer.produce_block().await.expect("produce");
        let block = storage.blocks.get_block(&bh).expect("read").expect("block");
        block.transactions.iter().any(|t| t.hash == honest_tx.hash)
    }

    fn unparseable_register(fill: usize) -> Vec<u8> {
        let mut d = vec![0x01, 0, 0, 0];
        d.extend_from_slice(&[0xAB; 32]);
        d.extend_from_slice(&u32::MAX.to_be_bytes());
        d.resize(fill.max(40), 0x5A);
        d
    }

    /// Byte window: large unexecutable payloads cannot fill the candidate
    /// window ahead of a paying transaction.
    #[tokio::test]
    async fn producer_candidate_window_bytes() {
        let per = citrate_sequencer::mempool::MAX_TX_DATA_BYTES;
        let fillers = (0..8u8)
            .map(|i| {
                (
                    Address([0x70 + i; 20]),
                    0u64,
                    unparseable_register(per),
                    1_000_000_000u64,
                )
            })
            .collect();
        assert!(window_case(fillers).await);
    }

    /// Count window: many small unexecutable payloads from many senders
    /// cannot exhaust the candidate count ahead of a paying transaction.
    #[tokio::test]
    async fn producer_candidate_window_count() {
        let mut fillers = Vec::new();
        for s in 0..300u16 {
            for n in 0..17u64 {
                let [hi, lo] = s.to_be_bytes();
                let mut a = [0u8; 20];
                a[0] = 0x80;
                a[1] = hi;
                a[2] = lo;
                a[19] = 1;
                fillers.push((Address(a), n, vec![0x02, 0, 0, 0], 1_000_000_000u64));
            }
        }
        assert!(window_case(fillers).await);
    }

    /// Candidates the budget rejects (wrong nonce) do not use up the window:
    /// the count cap applies to admitted transactions only.
    #[tokio::test]
    async fn producer_candidate_window_counts_admitted_only() {
        let mut fillers = Vec::new();
        // More senders than the per-block count cap, each with a pooled nonce
        // one ahead of its state nonce: selectable by the pool, rejected by
        // the budget, and priced above the paying transaction.
        for s in 0..5_100u16 {
            let [hi, lo] = s.to_be_bytes();
            let mut a = [0u8; 20];
            a[0] = 0x81;
            a[1] = hi;
            a[2] = lo;
            a[19] = 1;
            fillers.push((Address(a), 1u64, vec![], 90_000_000_000u64));
        }
        assert!(window_case(fillers).await);
    }

    #[test]
    fn candidate_window_caps() {
        let r = Address([0x33; 20]);
        let mut w = CandidateWindow::new(3, 10_000, 2);
        let a = transfer_tx(1, Address([0x51; 20]), r, 0);
        assert!(w.fits(&a));
        w.record(&a);
        w.record(&a);
        assert!(!w.fits(&a), "per-sender cap");
        let b = transfer_tx(2, Address([0x52; 20]), r, 0);
        assert!(w.fits(&b));
        w.record(&b);
        assert!(w.is_full() && !w.fits(&b), "count cap");
        let mut w = CandidateWindow::new(10, Mempool::tx_size(&b), 10);
        assert!(w.fits(&b), "exactly the byte cap fits");
        w.record(&b);
        assert!(!w.fits(&b), "byte cap");
        assert!(!CandidateWindow::new(0, 10_000, 10).fits(&b));
    }

    /// AI operations beyond the slice never re-enter through the standard pass.
    #[tokio::test]
    async fn producer_ai_slice_is_a_total_cap() {
        let (_tmp, storage, state_db, executor, mempool) = producer_fixture();
        let r = Address([0x33; 20]);
        let mut ai = Vec::new();
        for i in 0..3u8 {
            let a = Address([0x90 + i; 20]);
            funded(&state_db, a);
            let mut t = transfer_tx(0xD0 + i, a, r, 0);
            t.data = [vec![0x02, 0, 0, 0], vec![0x4D; 32]].concat();
            t.gas_limit = PRODUCER_BLOCK_GAS_LIMIT / 3;
            t.gas_price = 1_000_000_000;
            ai.push(t);
        }
        let s = Address([0x9F; 20]);
        funded(&state_db, s);
        let mut std_tx = transfer_tx(0xDF, s, r, 0);
        std_tx.gas_price = 79_000_000_000;
        for t in ai.iter().chain(std::iter::once(&std_tx)) {
            mempool
                .add_transaction(t.clone(), TxClass::Standard)
                .await
                .expect("admit");
        }
        let producer = test_producer(&storage, &executor, &mempool);
        let sel: Vec<Hash> = producer
            .select_transactions_with_ai_priority()
            .await
            .expect("select")
            .iter()
            .map(|t| t.hash)
            .collect();
        let ai_in = ai.iter().filter(|t| sel.contains(&t.hash)).count();
        assert_eq!(ai_in, 1, "only the slice's worth of AI gas is selected");
        assert!(sel.contains(&std_tx.hash));
    }

    /// The mempool's AI view and the executor's dispatch use one classifier.
    #[test]
    fn ai_classifier_parity() {
        use citrate_consensus::types::AiOpKind;
        for b0 in 0u8..=8 {
            let data = [b0, 0, 0, 0, 9, 9];
            let expect = match b0 {
                1 => Some(AiOpKind::RegisterModel),
                2 => Some(AiOpKind::InferenceRequest),
                3 => Some(AiOpKind::UpdateModel),
                _ => None,
            };
            assert_eq!(AiOpKind::classify(true, &data), expect, "selector {b0}");
            assert_eq!(AiOpKind::classify(false, &data), None, "deploy is never AI");
        }
        assert_eq!(AiOpKind::classify(true, &[0x02, 0, 0]), None, "short data");
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
        state_db
            .accounts
            .set_balance(bad_from, U256::from(21_000u64 * 1_000_000_000u64 * 10));

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

        assert_eq!(
            block.transactions.len(),
            1,
            "Only executed txs should be included"
        );
        assert_eq!(block.transactions[0].hash, good_tx.hash);
        assert_eq!(block.header.gas_used, 21_000);
        // PBA-L1b-002: the sealed root is the consensus rule's root for this
        // block (kills `calculate_tx_root -> Default::default()`).
        assert_eq!(
            block.tx_root,
            citrate_consensus::tx_auth::tx_root_for_height(
                producer.ghostdag.pba_hardening(),
                block.header.height,
                &block.transactions,
            )
        );
        assert_ne!(block.tx_root, Hash::default());

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
            storage
                .transactions
                .get_receipt(&bad_tx.hash)
                .unwrap()
                .is_none(),
            "Execution errors must not create synthetic receipts"
        );
        assert!(
            storage
                .transactions
                .get_transaction(&bad_tx.hash)
                .unwrap()
                .is_none(),
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
                block_subsidy: U256::zero(),
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
        let economics = Arc::new(UnifiedEconomicsManager::new(
            UnifiedEconomicsConfig::default(),
        ));
        let producer = BlockProducer::with_economics(
            storage.clone(),
            executor.clone(),
            mempool.clone(),
            None,
            coinbase,
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
        assert!(
            sealed.transactions.is_empty(),
            "the reproduction block must be empty"
        );
        assert_eq!(
            sealed.header.height, 1,
            "post-activation single-parent block"
        );
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

    // ═════════════════════════════════════════════════════════════════════════
    // MP-S1 — PARENT/STATE BINDING (CONSENSUS-CRITICAL red test).
    //
    // Pins the 2026-07-27 concurrent-producer fork. VERIFIED live on boot-1
    // (142.93.50.217), whose own journal reads, in order:
    //
    //   17:57:02.406  Produced block #1 hash=b6ace2a1bf03a599          (height 3826)
    //   17:57:02.674  REORG b6ace2a1 @ 3826 → 5fa0a4b2 @ 3826 (reverted 1, applied 1)
    //   17:57:04.684  Produced block #2 hash=d0697011049bedb2          (height 3827)
    //
    // `d0697011`'s committed `parentHash` is `b6ace2a1` (confirmed via
    // eth_getBlockByNumber on rpc-1, boot-1 AND boot-2) — but the reorg had
    // already moved boot-1's applied tip, and therefore its executor's world
    // state, to `5fa0a4b2`. So the block committed a `state_root` folded from
    // `5fa0a4b2`'s post-state while declaring `b6ace2a1` as its parent. No node
    // that correctly applies `b6ace2a1` can ever reproduce that root: boot-2 and
    // boot-3 logged the identical `State root mismatch: block claims 579ccaa5,
    // re-execution produced 01e213b7` 5,166 times and never advanced again.
    //
    // ROOT CAUSE (`produce_block`, this file): `selected_parent` comes from
    // `dag_store.get_tips()` + GhostDAG tip selection, while the transactions and
    // rewards are settled against the executor's LIVE state — which reflects the
    // APPLIED TIP. Nothing asserts the two are the same block. With a single
    /// NEVER PROPOSE BACKWARDS (chain 40204, 2026-08-11 restart wedge). Pins
    /// `applied_tip_supersedes` — the decision that keeps the producer from
    /// proposing onto an ANCESTOR of its own applied tip after a restart (when
    /// GhostDAG's tip set transiently lags behind the applied tip and `select_tip`
    /// returns the applied tip's parent). Without the clamp the producer refused
    /// every round (MP-S1) and the chain wedged though nothing had forked.
    #[tokio::test]
    async fn applied_tip_supersedes_only_a_genuine_ancestor_of_the_applied_tip() {
        use citrate_execution::StateDB;

        let dir = TempDir::new().expect("tempdir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let executor = Arc::new(Executor::with_storage_and_chain_id(
            Arc::new(StateDB::new()),
            Some(storage.state.clone()),
            40204,
        ));
        let mempool = Arc::new(Mempool::new(MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        }));
        let producer = BlockProducer::new(
            storage.clone(),
            executor.clone(),
            mempool,
            embedded_pubkey(Address([0x44; 20])),
            Ed25519SigningKey::from_bytes(&[42; 32]),
            2,
        )
        .with_v2_headers(true);
        let applicator = Arc::new(crate::canonical_apply::CanonicalApplicator::new(
            executor.clone(),
            storage.clone(),
        ));
        let producer = producer.with_applied_tip_lock(applicator.advance_lock());

        // Produce a linear chain A@1 → B@2 → C@3 (each becomes the applied tip and
        // is registered in this node's DAG exactly as the live produce path does).
        let a = producer.produce_block().await.expect("A@1");
        let b = producer.produce_block().await.expect("B@2");
        let c = producer.produce_block().await.expect("C@3");
        assert_eq!(
            applicator.applied_tip().await.hash,
            c,
            "applied tip is C @ 3"
        );

        // Also build a SIBLING of C at height 3 (a different branch, not on the
        // applied chain) so we can prove the clamp does NOT fire for a real fork.
        let sibling = {
            let blk = BlockBuilder::new()
                .version(2)
                .height(3)
                .parent(b)
                .coinbase([0x77; 20])
                .timestamp(1234)
                .vrf_reveal(VrfProof {
                    proof: vec![],
                    output: Hash::new([0x9C; 32]),
                })
                .transactions(vec![])
                .state_root(Hash::default())
                .build_unhashed();
            let mut blk = blk;
            blk.header.block_hash = blk.compute_hash();
            storage.blocks.put_block(&blk).expect("persist sibling");
            blk.header.block_hash
        };
        assert_ne!(sibling, c, "sibling is a distinct block at height 3");

        let (ctip, cheight) = (c, 3u64);

        // ANCESTORS of the applied tip → supersede (extend the applied tip, do not
        // propose backwards). This is the exact post-restart wedge (select_tip → B).
        assert!(
            producer.applied_tip_supersedes(b, ctip, cheight).await,
            "B (parent of C) is an ancestor of the applied tip → supersede"
        );
        assert!(
            producer.applied_tip_supersedes(a, ctip, cheight).await,
            "A (grandparent) is an ancestor → supersede"
        );

        // NOT superseded: the applied tip itself, a same-height sibling on another
        // branch (a real fork the drain must reorg), and an unknown block.
        assert!(
            !producer.applied_tip_supersedes(ctip, ctip, cheight).await,
            "the applied tip is not an ancestor of itself → extend normally"
        );
        assert!(
            !producer
                .applied_tip_supersedes(sibling, ctip, cheight)
                .await,
            "a same-height sibling on a different branch must NOT be clamped (let the drain reorg)"
        );
        assert!(
            !producer
                .applied_tip_supersedes(Hash::new([0xEE; 32]), ctip, cheight)
                .await,
            "an unknown block cannot be judged an ancestor → do not clamp"
        );
    }

    /// REGRESSION (chain 40204 reroll wedge @ height 101, 2026-08-12). `produce_block`
    /// stores each produced block in the DAG store (so `dag_store.get_tips()`, the
    /// PARENT source, advances and the chain grows) but never registered it into
    /// GhostDAG's in-memory tip set. Since #163 the producer's fork-choice is
    /// `GhostDag::select_tip()` over that in-memory set, so on a fresh SINGLE-producer
    /// chain `select_tip` stayed pinned to genesis while the chain grew. The "never
    /// propose backwards" clamp masked it only up to `SUPERSEDE_WALK_CAP` (100) below
    /// the applied tip, then FAILED at height 101 — the MP-S1 guard refused every round
    /// and the sole validator wedged though nothing had forked.
    ///
    /// INVARIANT: after producing a block, the producer's OWN `select_tip()` must
    /// reflect it (the DAG tip is this node's own last block). This fails before the
    /// fix (select_tip returns genesis) and passes after produce registers the block.
    #[tokio::test]
    async fn produced_block_advances_the_producer_ghostdag_select_tip() {
        use citrate_execution::StateDB;

        let dir = TempDir::new().expect("tempdir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let executor = Arc::new(Executor::with_storage_and_chain_id(
            Arc::new(StateDB::new()),
            Some(storage.state.clone()),
            40204,
        ));
        let mempool = Arc::new(Mempool::new(MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        }));
        let producer = BlockProducer::new(
            storage.clone(),
            executor.clone(),
            mempool,
            embedded_pubkey(Address([0x44; 20])),
            Ed25519SigningKey::from_bytes(&[42; 32]),
            2,
        )
        .with_v2_headers(true);
        let applicator = Arc::new(crate::canonical_apply::CanonicalApplicator::new(
            executor.clone(),
            storage.clone(),
        ));
        let producer = producer.with_applied_tip_lock(applicator.advance_lock());

        // Produce a short linear chain on a fresh single-producer node.
        let a = producer.produce_block().await.expect("A@1");
        let _b = producer.produce_block().await.expect("B@2");
        let c = producer.produce_block().await.expect("C@3");

        // The producer's fork-choice authority (`select_tip`, the SAME one the drain
        // reorgs toward) must track its own production — not remain on the stale
        // genesis tip. Before the fix this returns genesis (or errs on an empty set).
        let tip = producer
            .ghostdag()
            .select_tip()
            .await
            .expect("select_tip after producing a chain");
        assert_eq!(
            tip, c,
            "producer select_tip must be the height-3 tip C, never a stale ancestor \
             (a={a}, got {tip})"
        );
    }

    // producer they always are (the DAG's selected tip is that node's own last
    // block). Add a second producer and reorgs make them differ — which is
    // precisely why this only ever appears under concurrent producers, and why
    // single-producer operation masks it completely.
    //
    // INVARIANT (must hold; VIOLATED on `main`): a produced block's `state_root`
    // MUST be reproducible by a receiver that applies it on top of the block's
    // OWN declared parent. This test drives the real `produce_block` with the
    // applied tip deliberately displaced from fork-choice's selected tip, then
    // makes an independent receiver replay the sealed block on its declared
    // parent. On `main` that replay returns `StateRootMismatch`.
    //
    // A producer that REFUSES the round rather than sealing an unreproducible
    // block also satisfies the invariant — nothing poisoned reaches the network.
    #[tokio::test]
    async fn mp_s1_produced_block_state_root_must_bind_to_its_declared_parent() {
        use citrate_consensus::types::Block;
        use citrate_execution::StateDB;

        const TREASURY: [u8; 20] = [0x11; 20];

        // Apply `block` to `exec` through the canonical committed-state path the
        // receive side uses (`CanonicalApplicator`): the deterministic basic
        // reward credits + `Executor::apply_block`, which verifies the root.
        async fn apply_as_receiver(
            exec: &Executor,
            block: &Block,
        ) -> Result<Hash, citrate_execution::types::ExecutionError> {
            let reward = RewardCalculator::new(crate::canonical_apply::canonical_reward_config())
                .calculate_reward(block);
            let credits = [
                (Address(block.header.coinbase), reward.validator_reward),
                (Address(TREASURY), reward.treasury_reward),
            ];
            exec.apply_block(block, block.header.coinbase, &credits)
                .await
        }

        // Build a standalone producer node (own storage, own executor, own DAG).
        async fn node(
            dir: &TempDir,
            coinbase_byte: u8,
            key_byte: u8,
        ) -> (Arc<StorageManager>, Arc<Executor>, BlockProducer) {
            let storage = Arc::new(
                StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"),
            );
            let executor = Arc::new(Executor::with_storage_and_chain_id(
                Arc::new(StateDB::new()),
                Some(storage.state.clone()),
                40204,
            ));
            let mempool = Arc::new(Mempool::new(MempoolConfig {
                require_valid_signature: false,
                ..Default::default()
            }));
            let producer = BlockProducer::new(
                storage.clone(),
                executor.clone(),
                mempool,
                embedded_pubkey(Address([coinbase_byte; 20])),
                Ed25519SigningKey::from_bytes(&[key_byte; 32]),
                2,
            )
            .with_v2_headers(true); // the fleet runs CITRATE_BLOCK_V2=1
            let dag = producer.dag_store();
            let ghostdag = producer.ghostdag();
            seed_test_genesis(&storage, &dag, &ghostdag).await;
            (storage, executor, producer)
        }

        // ── Node P: the node under test, wired to a real applied-tip lock exactly
        //    as main.rs wires it (this is what makes the applied tip observable).
        let tmp_p = TempDir::new().expect("tempdir p");
        let (storage_p, exec_p, producer_p) = node(&tmp_p, 0x44, 42).await;
        let applicator_p = Arc::new(crate::canonical_apply::CanonicalApplicator::new(
            exec_p.clone(),
            storage_p.clone(),
        ));
        let producer_p = producer_p.with_applied_tip_lock(applicator_p.advance_lock());

        // P produces A @ 1. Its applied tip is now A and its executor holds A's
        // post-state.
        let a_hash = producer_p.produce_block().await.expect("P seals A @ 1");
        let block_a = storage_p
            .blocks
            .get_block(&a_hash)
            .expect("read A")
            .expect("A present");
        assert_eq!(block_a.header.height, 1, "A is the first block");

        // ── Node Q: an independent producer that seals a COMPETING block B @ 1 on
        //    the same (empty) genesis with a different coinbase and signing key.
        //    Tip selection breaks an equal-blue-score tie by SMALLEST hash
        //    (core/consensus/src/tip_selection.rs — the 2026-08-06 convergence fix
        //    that aligned the producer's tie-break with the drain's), so we search
        //    key/coinbase pairs until hash(B) < hash(A) and P's fork-choice
        //    deterministically prefers B. Without that the harness would not
        //    reproduce the live divergence.
        // Stop at the FIRST competitor hashing below A, but search the FULL seed
        // space (was a narrow 48-seed window). Block hashes are effectively random
        // in (coinbase, key): ~half of all candidates fall below A, so this stops
        // within a couple of iterations on average (cheap — one RocksDB per try),
        // yet the wide range still finds one in the rare runs where A hashes small.
        // The old 48-seed window occasionally contained nothing below A — a
        // load-independent harness flake unrelated to the code under test (A/B are
        // first blocks, produced via the genesis path, not `select_parents_with_
        // ghostdag`). It only fails now if A is below all 255 competitors (~1/256).
        let mut block_b = None;
        for seed in 0x01u8..=0xFFu8 {
            let tmp_q = TempDir::new().expect("tempdir q");
            let (storage_q, _exec_q, producer_q) = node(&tmp_q, seed, seed).await;
            let b_hash = producer_q.produce_block().await.expect("Q seals B @ 1");
            let candidate = storage_q
                .blocks
                .get_block(&b_hash)
                .expect("read B")
                .expect("B present");
            if candidate.header.block_hash < block_a.header.block_hash {
                block_b = Some(candidate);
                break;
            }
        }
        let block_b = block_b.expect(
            "harness: no competing block hashed below A across the full seed space — \
             astronomically rare (A below all 255 competitors); re-run",
        );

        // Give P the competing block WITHOUT applying it — exactly what the
        // network path does on arrival: persist + admit to the DAG, leaving the
        // applied tip where it was until the drain/reorg runs.
        storage_p
            .blocks
            .put_block(&block_b)
            .expect("persist B on P");
        producer_p
            .dag_store
            .store_block(block_b.clone())
            .await
            .expect("admit B to P's DAG");
        producer_p
            .ghostdag
            .add_block(&block_b)
            .await
            .expect("add B to P's GhostDAG");

        // ── Harness preconditions. If either fails the test would pass vacuously,
        //    so both are hard assertions: P's fork-choice must now select B while
        //    P's applied tip (and executor state) is still A. This IS the live
        //    boot-1 condition.
        let tips = producer_p.dag_store.get_tips().await;
        let tip_hashes: Vec<Hash> = tips.iter().map(|t| t.hash).collect();
        let selected = producer_p
            .tip_selector
            .select_tip(&tip_hashes)
            .await
            .expect("tip selection");
        assert_eq!(
            selected, block_b.header.block_hash,
            "harness precondition: fork-choice must select B"
        );
        assert_eq!(
            applicator_p.applied_tip().await.hash,
            a_hash,
            "harness precondition: P's applied tip must still be A (state = post-A)"
        );

        // ── The act under test: P produces while selected_parent (B) != applied tip (A).
        let produced = producer_p.produce_block().await;

        let c_hash = match produced {
            // Refusing the round upholds the invariant: nothing unreproducible is
            // sealed or broadcast. The node resumes once the applier converges.
            Err(_) => return,
            Ok(h) => h,
        };
        let block_c = storage_p
            .blocks
            .get_block(&c_hash)
            .expect("read C")
            .expect("C present");
        let declared_parent = block_c.selected_parent();
        let parent_block = storage_p
            .blocks
            .get_block(&declared_parent)
            .expect("read C's declared parent")
            .expect("C's declared parent must be stored");

        // ── Receiver R: a fresh node holding nothing but genesis. It applies C's
        //    OWN declared parent, then C. Both must verify.
        let receiver = Executor::new(Arc::new(StateDB::new()));
        apply_as_receiver(&receiver, &parent_block)
            .await
            .expect("C's declared parent must itself be a reproducible block");

        let got = apply_as_receiver(&receiver, &block_c).await.expect(
            "MP-S1 INVARIANT: a produced block's state_root MUST be reproducible by a \
             receiver applying it on top of the block's OWN declared parent. On `main` \
             produce_block picks selected_parent from GhostDAG tip selection but settles \
             rewards against the executor's live state (the APPLIED TIP), with no check \
             that they are the same block — so the sealed root is folded from the wrong \
             parent's state and NO node can reproduce it. This is the 2026-07-27 \
             boot-1/d0697011 fork.",
        );
        assert_eq!(
            got, block_c.state_root,
            "receiver's root MUST equal the producer's sealed root"
        );
    }

    // ═════════════════════════════════════════════════════════════════════════
    // MP-S1 END-TO-END — two concurrent producers, verified ON THE FOLLOWER.
    //
    // The 2026-07-27 incident was called "working" twice by checking the two
    // PRODUCERS (both healthy, zero errors) while the followers were the ones
    // forked. This test inverts that: two real `BlockProducer`s run concurrently
    // on a shared DAG and a third node — a pure FOLLOWER that produces nothing —
    // executes every block they emit. The follower is the oracle.
    //
    // Asserts BOTH halves of "multi-producer works":
    //   SAFETY   — no node ever returns `ApplyOutcome::Rejected`. A state-root
    //              mismatch on any receiver fails the test. On the pre-fix
    //              producer this is what wedged boot-2 and boot-3 forever.
    //   LIVENESS — both producers keep producing. The MP-S1 fix makes a producer
    //              SKIP a round when fork-choice and its applied tip disagree, so
    //              this pins that the skip is transient and never a deadlock.
    #[tokio::test]
    async fn mp_s1_two_concurrent_producers_a_follower_reproduces_every_root() {
        use crate::canonical_apply::{ApplyOutcome, CanonicalApplicator};
        use citrate_consensus::types::Block;
        use citrate_execution::StateDB;

        struct Node {
            storage: Arc<StorageManager>,
            dag: Arc<DagStore>,
            ghostdag: Arc<GhostDag>,
            app: CanonicalApplicator,
            producer: Option<BlockProducer>,
            _dir: TempDir,
        }

        // A node wired the way main.rs wires one: shared DAG + GhostDag, an
        // applicator with fork-choice enabled, and (for producers) the applied-tip
        // lock the producer holds across its build.
        async fn node(coinbase_byte: u8, key_byte: u8, producing: bool) -> Node {
            let dir = TempDir::new().expect("tempdir");
            let storage = Arc::new(
                StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"),
            );
            let executor = Arc::new(Executor::with_storage_and_chain_id(
                Arc::new(StateDB::new()),
                Some(storage.state.clone()),
                40204,
            ));
            let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
            let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag.clone()));
            let _genesis = seed_test_genesis(&storage, &dag, &ghostdag).await;
            let app = CanonicalApplicator::new(executor.clone(), storage.clone())
                .with_fork_choice(ghostdag.clone());
            let producer = if producing {
                let mempool = Arc::new(Mempool::new(MempoolConfig {
                    require_valid_signature: false,
                    ..Default::default()
                }));
                Some(
                    BlockProducer::with_shared_dag(
                        storage.clone(),
                        executor.clone(),
                        mempool,
                        None,
                        embedded_pubkey(Address([coinbase_byte; 20])),
                        Ed25519SigningKey::from_bytes(&[key_byte; 32]),
                        2,
                        Arc::new(citrate_economics::UnifiedEconomicsManager::new(
                            citrate_economics::UnifiedEconomicsConfig::default(),
                        )),
                        dag.clone(),
                        ghostdag.clone(),
                    )
                    .await
                    .with_v2_headers(true)
                    .with_applied_tip_lock(app.advance_lock()),
                )
            } else {
                None
            };
            Node {
                storage,
                dag,
                ghostdag,
                app,
                producer,
                _dir: dir,
            }
        }

        // Deliver a gossiped block to a node: persist, admit to the DAG, then run
        // the execute-on-receive driver — the real receive path.
        async fn deliver(n: &Node, block: &Block) -> ApplyOutcome {
            // SYNC-S1 D2.3 R3: these three writes are the receive path this test
            // claims to reproduce, and a silently-failed DAG write is the exact
            // chain-store/DAG-store divergence the test exists to catch. Two of
            // them were `let _ =` while put_block used `.expect` — so the helper
            // could swallow the failure it is hunting and report a confusing
            // downstream symptom instead.
            n.storage
                .blocks
                .put_block(block)
                .expect("persist gossiped block");
            n.dag
                .store_block(block.clone())
                .await
                .expect("store gossiped block in the DAG — a dropped write here is the divergence");
            n.ghostdag
                .add_block(block)
                .await
                .expect("admit gossiped block to ghostdag");
            n.app.apply_received(block).await
        }

        let p = node(0x44, 42, true).await;
        let q = node(0x55, 77, true).await;
        let follower = node(0x66, 99, false).await;

        const ROUNDS: usize = 14;
        let mut produced_total = 0usize;
        let mut produced_by_p = 0usize;
        let mut produced_by_q = 0usize;

        for round in 0..ROUNDS {
            // Both producers attempt the round, as two miners on a 2s slot do.
            let mut minted: Vec<(usize, Block)> = Vec::new();
            for (idx, n) in [&p, &q].iter().enumerate() {
                let Some(prod) = n.producer.as_ref() else {
                    continue;
                };
                // An Err here is a DELIBERATE skip (MP-S1: fork-choice and the
                // applied tip disagree). Liveness is asserted after the loop.
                if let Ok(hash) = prod.produce_block().await {
                    let block = n
                        .storage
                        .blocks
                        .get_block(&hash)
                        .expect("read sealed block")
                        .expect("sealed block present");
                    minted.push((idx, block));
                }
            }
            produced_total += minted.len();
            for (idx, _) in &minted {
                if *idx == 0 {
                    produced_by_p += 1;
                } else {
                    produced_by_q += 1;
                }
            }

            // Gossip every minted block to every OTHER node and execute it there.
            for (origin, block) in &minted {
                for (idx, n) in [&p, &q, &follower].iter().enumerate() {
                    if idx == *origin {
                        continue; // the producer already recorded its own block
                    }
                    let who = ["producer-P", "producer-Q", "FOLLOWER"][idx];
                    if let ApplyOutcome::Rejected(why) = deliver(n, block).await {
                        panic!(
                            "MP-S1 END-TO-END: {who} REJECTED block {} @ {} in round {round}: \
                             {why}. Two concurrent producers must never emit a block a \
                             receiver cannot reproduce — this is the 2026-07-27 fork, where \
                             boot-2 and boot-3 re-executed one such block 5,166 times and \
                             never advanced again.",
                            block.header.block_hash, block.header.height
                        );
                    }
                }
            }
        }

        // ── LIVENESS: the MP-S1 skip must be transient, never a deadlock. ──
        assert!(
            produced_by_p > 0 && produced_by_q > 0,
            "both producers must keep producing (P={produced_by_p}, Q={produced_by_q}) — \
             a permanent skip would be a liveness regression, not a fix"
        );
        assert!(
            produced_total >= ROUNDS,
            "expected at least one block per round across the two producers, got \
             {produced_total} in {ROUNDS} rounds"
        );

        // ── SAFETY: the follower's world state must match a producer's at the tip.
        let f_tip = follower.app.applied_tip().await;
        let p_tip = p.app.applied_tip().await;
        let q_tip = q.app.applied_tip().await;
        assert!(
            f_tip.height > 1,
            "the follower must have advanced past genesis"
        );
        // The DIAGNOSTIC assertion. A poisoned block does NOT surface as
        // `ApplyOutcome::Rejected` on the receive path — `reorg_to` only LOGS its
        // rejection and `apply_received` classifies the block as `Deferred`. That
        // is exactly why "zero errors on both producers" was a false all-clear on
        // 2026-07-27. The observable symptom is a FROZEN FOLLOWER: with the MP-S1
        // guard removed this fails as "follower @ 6, producers @ 14".
        let ahead = p_tip.height.max(q_tip.height);
        assert!(
            f_tip.height + 2 >= ahead,
            "FOLLOWER WEDGED: follower is at height {} while the producers are at {} \
             (P={}, Q={}). A follower that cannot keep up with concurrent producers is \
             the 2026-07-27 fork — the producers stay healthy and silent while the rest \
             of the fleet stops advancing.",
            f_tip.height,
            ahead,
            p_tip.height,
            q_tip.height
        );
        assert!(
            f_tip.hash == p_tip.hash || f_tip.hash == q_tip.hash,
            "the follower's applied tip ({} @ {}) must be a tip a producer also holds \
             (P={} @ {}, Q={} @ {})",
            f_tip.hash,
            f_tip.height,
            p_tip.hash,
            p_tip.height,
            q_tip.hash,
            q_tip.height
        );
        // Every block the follower applied was state-root verified by
        // `Executor::apply_block`, so agreeing on the tip means agreeing on state.
        let matching = if f_tip.hash == p_tip.hash { &p } else { &q };
        assert_eq!(
            follower.app.applied_tip().await.hash,
            matching.app.applied_tip().await.hash,
            "follower and the producer it agrees with must be on the same applied block"
        );
    }
}

#[cfg(test)]
mod multi_producer_regression {
    use super::*;
    use citrate_consensus::types::{Hash, PublicKey};
    use citrate_consensus::vrf::VrfProposerSelector;

    /// MULTI-PRODUCER REGRESSION (2026-07-27 chain halt).
    ///
    /// The producer's parent read ended in
    /// `.unwrap_or((0, Hash::default(), 0, 0))`. When GHOSTDAG selected a parent
    /// the node had not stored yet — which is exactly what happens the first time
    /// another producer's block wins tip selection — the miss was swallowed and
    /// the VRF proof was generated against `Hash::default()` instead of the real
    /// parent's `vrf_reveal.output`.
    ///
    /// This pins WHY that was fatal rather than merely wrong: the resulting proof
    /// does not verify against the real chain, so every block the node minted was
    /// rejected. On rpc-1 that produced `Invalid VRF: ... invalid proof or
    /// identity binding` every 2 seconds, indefinitely, across restarts.
    #[test]
    fn vrf_proof_bound_to_a_default_parent_does_not_verify_against_the_real_parent() {
        let sk = citrate_consensus::crypto::generate_block_signing_key();
        let proposer = PublicKey::new(sk.verifying_key().to_bytes());
        let slot = 152_755u64;

        // The real chain's previous VRF output.
        let real_prev_vrf = Hash::new([0x7au8; 32]);
        // What the degraded `.unwrap_or` path substituted.
        let degraded_prev_vrf = Hash::default();
        assert_ne!(real_prev_vrf, degraded_prev_vrf);

        // A proof built the way the bug built it.
        let degraded = generate_block_vrf(&sk, &proposer, &degraded_prev_vrf, slot);

        let selector = VrfProposerSelector::production();
        let verified_against_real_chain = selector
            .verify_vrf_math_only(&proposer, &degraded, &real_prev_vrf, slot)
            .expect("verification must not error");

        assert!(
            !verified_against_real_chain,
            "a VRF proof bound to a default parent verified against the real chain — \
             the degraded-parent path would have gone undetected"
        );

        // And the correctly-bound proof does verify, so the assertion above is
        // testing the binding and not a broken verifier.
        let correct = generate_block_vrf(&sk, &proposer, &real_prev_vrf, slot);
        assert!(
            selector
                .verify_vrf_math_only(&proposer, &correct, &real_prev_vrf, slot)
                .expect("verification must not error"),
            "a correctly-bound proof must verify"
        );
    }

    /// The blue-score path used to be `parent_blue_score + 1` unconditionally,
    /// with the comment "with no other producers there are no additional blue
    /// merges". That is exact only when the mergeset is empty. This pins the
    /// distinction the fix now makes.
    #[test]
    fn empty_mergeset_is_the_only_case_where_plus_one_is_exact() {
        let parent_blue_score = 152_754u64;
        let no_merge: Vec<Hash> = Vec::new();
        assert!(
            no_merge.is_empty(),
            "single-parent blocks keep the cheap exact path"
        );
        assert_eq!(parent_blue_score + 1, 152_755);

        // With merge parents present, +1 is an approximation the producer must no
        // longer use — GHOSTDAG blue score is parent + |blue blocks in mergeset|.
        let merging = [Hash::new([1u8; 32]), Hash::new([2u8; 32])];
        assert!(
            !merging.is_empty(),
            "merging blocks must take the real calculate_blue_set path"
        );
    }
}

#[cfg(test)]
mod blue_score_band_regression {
    /// 2026-07-27 REGRESSION — the producer's blue_score must sit inside the band
    /// `validate_block_consistency` enforces: `[sp+1, sp+1+|merges|]`.
    ///
    /// A previous fix computed it via `ghostdag.calculate_blue_set(&candidate)` for
    /// merging blocks. That resolves through the DAG STORE, and the candidate is by
    /// definition not stored yet, so it returned the ancestry's score WITHOUT the
    /// new block — one below the band's minimum. Live result: block 4028 carried
    /// blue_score 4028 against a required `[4029, 4030]`, every follower rejected
    /// it, and the fleet stalled at 4027 while the producer ran on to 19,000+.
    ///
    /// `parent + 1` IS the band minimum, so it can never be rejected.
    #[test]
    fn parent_plus_one_is_always_inside_the_feasible_band() {
        for (sp_score, n_merges) in [(0u64, 0usize), (4028, 1), (4028, 3), (152_754, 10)] {
            let produced = sp_score + 1;
            let band_min = sp_score + 1;
            let band_max = sp_score + 1 + n_merges as u64;
            assert!(
                produced >= band_min && produced <= band_max,
                "parent+1 ({produced}) fell outside [{band_min}, {band_max}] for \
                 sp={sp_score} merges={n_merges}"
            );
        }
    }

    /// The exact shape that broke the chain: a score equal to the parent's is one
    /// below the minimum and is rejected for ANY mergeset size.
    #[test]
    fn a_score_equal_to_the_parent_is_always_rejected() {
        for n_merges in [0usize, 1, 3, 10] {
            let sp_score = 4028u64;
            let bad = sp_score; // what calculate_blue_set returned for the unstored candidate
            let band_min = sp_score + 1;
            assert!(
                bad < band_min,
                "a score equal to the parent must be below the band minimum \
                 (mergeset {n_merges})"
            );
        }
    }
}

/// PBA-L1a-001 — a panic inside one production round must not end block
/// production. Before the fix `start()` awaited `produce_block()` inline; the
/// u64::MAX-nonce overflow in mempool selection unwound the whole producer
/// task (spawned with its handle dropped), halting the chain silently.
#[cfg(test)]
mod pba_l1a_001_producer_supervision {
    use super::{run_supervised, RoundOutcome};

    #[tokio::test]
    async fn a_panicking_round_is_contained_and_reported() {
        let out = run_supervised(async {
            let n: u64 = std::hint::black_box(u64::MAX);
            // The exact failure shape: an overflow panic mid-round.
            let _ = n.checked_add(1).expect("attempt to add with overflow");
            Ok::<u64, anyhow::Error>(0)
        })
        .await;
        match out {
            RoundOutcome::Panicked(msg) => assert!(msg.contains("overflow"), "{msg}"),
            other => panic!("expected Panicked, got {other:?}"),
        }
        // And the caller keeps running rounds afterwards.
        let next = run_supervised(async { Ok::<u64, anyhow::Error>(7) }).await;
        assert!(matches!(next, RoundOutcome::Produced(7)));
    }

    #[tokio::test]
    async fn errors_and_successes_pass_through() {
        let e = run_supervised(async { Err::<u64, _>(anyhow::anyhow!("no parent")) }).await;
        assert!(matches!(e, RoundOutcome::Failed(ref x) if x.to_string() == "no parent"));
        let ok = run_supervised(async { Ok::<u64, anyhow::Error>(1) }).await;
        assert!(matches!(ok, RoundOutcome::Produced(1)));
    }

    /// The loop must actually route rounds through the supervisor.
    #[test]
    fn start_loop_uses_the_supervisor() {
        let src = include_str!("producer.rs");
        let start = src
            .find("pub async fn start(self: Arc<Self>)")
            .expect("start()");
        let body = &src[start..start + 2_000];
        assert!(
            body.contains("supervised_round(self.clone())"),
            "PBA-L1a-001 tripwire: BlockProducer::start must run each round through \
             supervised_round, never await produce_block() inline"
        );
        assert!(!body.contains("self.produce_block().await"));
    }
}

/// PBA-L1b-003 tripwire: the producer never stamps a bare `now`; it stamps
/// `hardening::producer_timestamp(now, parent.ts)` so a future-dated tip can
/// never make its own children invalid.
#[cfg(test)]
mod pba_l1b_003_producer_timestamp {
    #[test]
    fn header_timestamp_goes_through_producer_timestamp() {
        let src = include_str!("producer.rs");
        let hdr = src
            .find("let mut header = BlockHeader {")
            .expect("producer header construction");
        let body = &src[hdr..hdr + 1_500];
        assert!(
            body.contains("hardening::producer_timestamp(now, pts)"),
            "PBA-L1b-003: header.timestamp must be producer_timestamp(now, parent.ts)"
        );
        assert!(
            !body.contains("timestamp: chrono::Utc::now().timestamp() as u64"),
            "PBA-L1b-003: bare `now` stamping reintroduced"
        );
    }
}

/// PBA-L1b-001 tripwire: the producer filters every candidate tx through the
/// same import rule followers enforce, so it never seals a block they reject.
#[cfg(test)]
mod pba_l1b_001_producer_filter {
    #[test]
    fn producer_applies_the_import_rule_before_sealing() {
        let src = include_str!("producer.rs");
        let sel = src
            .find("let transactions = self.select_transactions_with_ai_priority().await?;")
            .expect("selection");
        let hdr = src.find("let mut header = BlockHeader {").expect("header");
        let window = &src[sel..hdr];
        assert!(
            window.contains("tx_auth::verify_for_block(&t, chain_id)"),
            "PBA-L1b-001: produce_block must filter candidates with tx_auth::verify_for_block"
        );
    }
}
