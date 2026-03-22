use citrate_consensus::chain_selection::ChainSelector;
use citrate_consensus::dag_store::DagStore;
use citrate_consensus::ghostdag::GhostDag;
use citrate_consensus::tip_selection::TipSelector;
use citrate_consensus::crypto::{self, Ed25519SigningKey};
use citrate_consensus::types::{
    Block, BlockHeader, GhostDagParams, Hash, PublicKey, Signature, Transaction, VrfProof,
};
use citrate_economics::{
    RewardCalculator, RewardConfig, UnifiedEconomicsManager,
};
use citrate_execution::Executor;
use citrate_execution::revm_adapter::BlockContext;
use citrate_learning::orchestration::{LearningOrchestrator, PeerEmbedding};
use citrate_network::{GossipProtocol, NetworkMessage, PeerManager};
use citrate_network::learning_messages::LearningMessage;
use citrate_sequencer::mempool::Mempool;
use citrate_storage::{state_manager::StateManager as AIStateManager, StorageManager};
use primitive_types::U256;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

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
        let dag_store = Arc::new(DagStore::new());
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
        let reward_config = RewardConfig {
            block_reward: 10, // 10 SALT per block
            halving_interval: 2_100_000,
            inference_bonus: 1,        // 0.01 SALT per inference
            model_deployment_bonus: 1, // 1 SALT per model deployment
            treasury_percentage: 10,
            treasury_address: citrate_execution::types::Address([0x11; 20]), // Treasury address
        };
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
        let dag_store = Arc::new(DagStore::new());
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
        let reward_config = RewardConfig {
            block_reward: 10, // 10 SALT per block
            halving_interval: 2_100_000,
            inference_bonus: 1,        // 0.01 SALT per inference
            model_deployment_bonus: 1, // 1 SALT per model deployment
            treasury_percentage: 10,
            treasury_address: citrate_execution::types::Address([0x11; 20]), // Treasury address
        };
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
        let dag_store = Arc::new(DagStore::new());
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
        let dag_store = Arc::new(DagStore::new());

        let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag_store.clone()));

        // Load existing chain data into DAG so we continue from last tip
        let latest_height = storage.blocks.get_latest_height().unwrap_or(0);
        if latest_height > 0 {
            info!("Loading {} blocks from storage into DAG...", latest_height + 1);
            for height in 0..=latest_height {
                if let Ok(Some(block_hash)) = storage.blocks.get_block_by_height(height) {
                    if let Ok(Some(block)) = storage.blocks.get_block(&block_hash) {
                        let _ = dag_store.store_block(block.clone()).await;
                        let _ = ghostdag.add_block(&block).await;
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
        let reward_config = RewardConfig {
            block_reward: 10, // This will be overridden by economics manager
            halving_interval: 2_100_000,
            inference_bonus: 1,
            model_deployment_bonus: 1,
            treasury_percentage: 10,
            treasury_address: citrate_execution::types::Address([0x11; 20]),
        };
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
                        let _ = dag_store.store_block(block.clone()).await;
                        let _ = ghostdag.add_block(&block).await;
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

        let reward_config = RewardConfig {
            block_reward: 10,
            halving_interval: 2_100_000,
            inference_bonus: 1,
            model_deployment_bonus: 1,
            treasury_percentage: 10,
            treasury_address: citrate_execution::types::Address([0x11; 20]),
        };
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

        // Calculate blue set for the new block
        let temp_block = citrate_consensus::types::Block {
            header: citrate_consensus::types::BlockHeader {
                version: 1,
                block_hash: Hash::default(),
                selected_parent_hash: selected_parent,
                merge_parent_hashes: merge_parents.clone(),
                timestamp: chrono::Utc::now().timestamp() as u64,
                height: 0,     // Will be calculated
                blue_score: 0, // Will be calculated
                blue_work: 0,  // Will be calculated
                pruning_point: Hash::default(),
                proposer_pubkey: PublicKey::new(self.signing_key.verifying_key().to_bytes()),
                vrf_reveal: generate_block_vrf(&self.signing_key, &PublicKey::new(self.signing_key.verifying_key().to_bytes()), &selected_parent, 0),
                base_fee_per_gas: 1_000_000_000, // 1 gwei
                gas_used: 0,
                gas_limit: 30_000_000,
            },
            state_root: Hash::default(),
            tx_root: Hash::default(),
            receipt_root: Hash::default(),
            artifact_root: Hash::default(),
            ghostdag_params: citrate_consensus::types::GhostDagParams::default(),
            transactions: vec![],
            signature: Signature::new([0; 64]),
            embedded_models: vec![],
            required_pins: vec![],
            learning_embedding: None,
            learning_confidence: None,
            gradient_commitment: None,
            learning_root: Hash::default(),
        };

        let blue_set = self.ghostdag.calculate_blue_set(&temp_block).await?;
        let blue_score = self.ghostdag.calculate_blue_score(&temp_block).await?;

        // Get last block height and parent VRF output from selected parent
        let (last_height, parent_vrf_output) = if selected_parent != Hash::default() {
            self.storage
                .blocks
                .get_block(&selected_parent)
                .ok()
                .and_then(|b| b.map(|block| (block.header.height, block.header.vrf_reveal.output)))
                .unwrap_or((0, Hash::default()))
        } else {
            (0, Hash::default())
        };

        // Get transactions from mempool with AI priority
        let transactions = self.select_transactions_with_ai_priority().await?;

        // Blue score and work are already calculated above
        let blue_work = self.calculate_blue_work(&blue_set, blue_score)?;

        // Create block header with GhostDAG consensus data
        let header = BlockHeader {
            version: 1,
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
        };

        // WP-Z.3: Set block context with VRF output before executing transactions.
        // This ensures `block.prevrandao` returns the real VRF randomness in Solidity.
        self.executor.set_block_context(BlockContext {
            coinbase: self.coinbase.0[0..20].try_into().unwrap_or([0; 20]),
            prevrandao: *header.vrf_reveal.output.as_bytes(),
            block_hashes: HashMap::new(),
        });

        // Execute transactions (state root computed after rewards below)
        let (_pre_reward_root, receipts) = self
            .execute_block_transactions(&transactions, &header)
            .await?;
        let tx_root = self.calculate_tx_root(&transactions)?;
        let receipt_root = self.calculate_receipt_root(&receipts)?;
        let artifact_root = self.calculate_artifact_root(&transactions)?;

        // Apply block rewards BEFORE computing the final state root.
        // Rewards modify the executor's in-memory state, so state_root must
        // be computed after this step to include reward balances.
        let validator_address = citrate_execution::types::Address(
            self.coinbase.0[0..20].try_into().unwrap_or([0; 20])
        );

        if let Some(economics) = &self.economics_manager {
            info!("Economics: Applying enhanced reward system for block {}", header.height);

            let base_reward = economics.get_config().rewards_config.base_block_reward;
            let mut total_reward = base_reward;

            let staked_amount = economics.get_staked_balance(&validator_address);
            if staked_amount > primitive_types::U256::zero() {
                let staking_bonus = base_reward / primitive_types::U256::from(10);
                total_reward += staking_bonus;
                info!("Economics: Applied staking bonus of {} wei for staked amount {}", staking_bonus, staked_amount);
            }

            let reputation_score = economics.get_reputation_score(&validator_address);
            if reputation_score > 0.5 {
                let reputation_bonus = base_reward * primitive_types::U256::from((reputation_score * 20.0) as u64) / primitive_types::U256::from(100);
                total_reward += reputation_bonus;
                info!("Economics: Applied reputation bonus of {} wei for score {}", reputation_bonus, reputation_score);
            }

            let current_gas_price = economics.get_operation_cost(citrate_economics::OperationType::AIInference { compute_units: 1000 });
            if current_gas_price > economics.get_config().pricing_config.base_gas_price {
                let congestion_bonus = base_reward / primitive_types::U256::from(20);
                total_reward += congestion_bonus;
                info!("Economics: Applied congestion bonus of {} wei due to high gas prices", congestion_bonus);
            }

            let current_balance = self.executor.get_balance(&validator_address);
            self.executor.set_balance(&validator_address, current_balance + total_reward);
            info!("Economics: Applied total enhanced reward of {} wei to validator {} (base: {}, bonuses: {})",
                total_reward, hex::encode(validator_address.0), base_reward, total_reward - base_reward);

            if let Some(economic_state) = economics.get_economic_state() {
                info!("Economics: Network state - Gas price: {}, Staked: {}, Treasury: {}",
                    economic_state.gas_price, economic_state.staked_amount, economic_state.treasury_balance);
            }
        } else {
            // Basic reward system — create a temporary block for reward calculation
            // (calculate_reward only reads header.height and transactions, not state_root)
            let temp_block = Block {
                header: header.clone(),
                state_root: Hash::default(),
                tx_root,
                receipt_root,
                artifact_root,
                ghostdag_params: self.ghostdag.params().clone(),
                transactions: transactions.clone(),
                signature: Signature::default(),
                embedded_models: vec![],
                required_pins: vec![],
                learning_embedding: None,
                learning_confidence: None,
                gradient_commitment: None,
                learning_root: Hash::default(),
            };
            let reward = self.reward_calculator.calculate_reward(&temp_block);
            self.apply_basic_rewards(&reward, &validator_address);
        }

        // NOW compute final state root — includes both tx effects and reward balances
        let state_root = self.executor.calculate_state_root();

        // Create block with all computed data (hash + signature placeholders — computed next)
        let mut block = Block {
            header: header.clone(),
            state_root,
            tx_root,
            receipt_root,
            artifact_root,
            ghostdag_params: self.ghostdag.params().clone(),
            transactions,
            signature: Signature::default(), // Placeholder — signed below
            embedded_models: vec![],
            required_pins: vec![],
            learning_embedding: None,
            learning_confidence: None,
            gradient_commitment: None,
            learning_root: Hash::default(),
        };

        // WP-F.3: Compute learning_root at checkpoint boundaries.
        // Per StrobilationCheckpoint.tla: only checkpoint blocks get a learning_root.
        // Non-checkpoint blocks keep Hash::default() (zero hash).
        // The learning_root is NOT included in compute_hash() (Theorem 3).
        let block_height = block.header.height;
        if block_height > 0
            && block_height % self.checkpoint_interval == 0
            && self.learning_orchestrator.is_some()
        {
            let learning_root = self.compute_checkpoint_learning_root(block_height).await;
            block.learning_root = learning_root;
        }

        // C-05: Compute canonical block hash from ALL fields including commitment roots.
        // This must happen AFTER execution AND rewards so state_root is final.
        block.header.block_hash = block.compute_hash();

        // WP-G.2: Sign the canonical block hash with the proposer's ed25519 key.
        block.signature = crypto::sign_block(&block.header.block_hash, &self.signing_key);

        // Persist state changes from executed transactions + rewards to storage
        info!("Persisting state changes to storage...");
        let modified_count = self.executor.persist_state_changes()?;
        info!("Persisted {} modified accounts to storage", modified_count);

        // WP-G.4: Verify state root consistency after persistence.
        // The executor's in-memory state root (used in the block) must still match.
        let post_persist_root = self.executor.calculate_state_root();
        if post_persist_root != block.state_root {
            error!(
                "STATE ROOT MISMATCH after persist: block={} post_persist={}",
                block.state_root, post_persist_root
            );
            return Err(anyhow::anyhow!(
                "State root mismatch after persistence: block {} vs post-persist {}",
                block.state_root, post_persist_root
            ));
        }

        // Persist block and related data
        self.storage.blocks.put_block(&block)?;

        // Persist state root separately for fast startup verification
        if let Err(e) = self.storage.state.put_state_root(&block.header.block_hash, &block.state_root) {
            warn!("Failed to persist state root for block {}: {}", block.header.height, e);
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
            let mut pairs: Vec<(Hash, citrate_execution::types::TransactionReceipt)> = Vec::new();
            for (i, tx) in block.transactions.iter().enumerate() {
                if let Some(r) = receipts.get(i) {
                    pairs.push((tx.hash, r.clone()));
                }
            }
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

        Ok(header.block_hash)
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
    /// H-03 fix: Deduplicates by hash across AI and standard selection phases.
    async fn select_transactions_with_ai_priority(&self) -> anyhow::Result<Vec<Transaction>> {
        let mut selected = Vec::new();
        let mut seen = std::collections::HashSet::new();

        // Define capacity limits
        // H-08 fix: Use network-aligned limit (see WP-G.6)
        const MAX_BLOCK_SIZE: usize = 1_000_000; // 1MB — aligned with transport/gossip
        const MAX_AI_TXS_PER_BLOCK: usize = 10;
        const MAX_STANDARD_TXS: usize = 100;

        // Get AI transactions first (model operations, inference requests)
        let ai_txs = self.mempool.get_ai_transactions(MAX_AI_TXS_PER_BLOCK).await;
        for tx in ai_txs {
            if seen.insert(tx.hash) {
                selected.push(tx);
            }
        }

        // Fill remaining space with standard transactions, skipping duplicates
        let standard_txs = self
            .mempool
            .get_best_transactions(MAX_STANDARD_TXS, MAX_BLOCK_SIZE)
            .await;
        for tx in standard_txs {
            if seen.insert(tx.hash) {
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
    ) -> anyhow::Result<(Hash, Vec<citrate_execution::types::TransactionReceipt>)> {
        let mut receipts = Vec::new();

        // Create a temporary block for execution context
        let temp_block = Block {
            header: header.clone(),
            state_root: Hash::default(),
            tx_root: Hash::default(),
            receipt_root: Hash::default(),
            artifact_root: Hash::default(),
            ghostdag_params: self.ghostdag.params().clone(),
            transactions: vec![],
            signature: Signature::new([0; 64]),
            embedded_models: vec![],
            required_pins: vec![],
            learning_embedding: None,
            learning_confidence: None,
            gradient_commitment: None,
            learning_root: Hash::default(),
        };

        // Execute each transaction
        for tx in transactions {
            match self.executor.execute_transaction(&temp_block, tx).await {
                Ok(receipt) => receipts.push(receipt),
                Err(e) => {
                    error!("Failed to execute transaction {}: {}", tx.hash, e);

                    // Sprint EL-1 (Issue #20): Remove failed tx from mempool
                    // so the sender's nonce is not permanently blocked.
                    let _ = self.mempool.remove_transaction(&tx.hash).await;

                    // Create failed receipt
                    receipts.push(citrate_execution::types::TransactionReceipt {
                        tx_hash: tx.hash,
                        block_hash: header.block_hash,
                        block_number: header.height,
                        from: citrate_execution::types::Address::from_public_key(&tx.from),
                        to: tx
                            .to
                            .map(|pk| citrate_execution::types::Address::from_public_key(&pk)),
                        gas_used: tx.gas_limit, // All gas consumed on failure
                        status: false,
                        logs: vec![],
                        output: vec![],
                        eth_tx_type: 0,
                        effective_gas_price: 0,
                    });
                }
            }
        }

        // WP-G.4: Compute state root from the executor's in-memory post-execution state.
        // This uses the state trie that has been updated by transaction execution,
        // NOT the storage-backed view which still reflects the previous block.
        let state_root = self.executor.calculate_state_root();

        Ok((state_root, receipts))
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
        // Simplified calculation: blue_work = blue_score * difficulty
        // In production, this would consider actual proof-of-work
        Ok(blue_score as u128 * 1_000_000)
    }

    /// Apply basic rewards (fallback when economics system is not available)
    fn apply_basic_rewards(&self, reward: &citrate_economics::BlockReward, validator_address: &citrate_execution::types::Address) {
        let treasury_address = citrate_execution::types::Address([0x11; 20]);

        // Apply validator rewards
        if reward.validator_reward > U256::zero() {
            let current_balance = self.executor.get_balance(validator_address);
            self.executor.set_balance(
                validator_address,
                current_balance + reward.validator_reward,
            );
            info!(
                "Basic: Minted {} wei to validator {}",
                reward.validator_reward,
                hex::encode(validator_address.0)
            );
        }

        // Apply treasury rewards
        if reward.treasury_reward > U256::zero() {
            let current_balance = self.executor.get_balance(&treasury_address);
            self.executor
                .set_balance(&treasury_address, current_balance + reward.treasury_reward);
            info!("Basic: Minted {} wei to treasury", reward.treasury_reward);
        }
    }

    /// WP-F.3: Compute the learning_root for a checkpoint block.
    ///
    /// Collects peer embeddings from the gossip layer, runs paraconsensus
    /// aggregation via the learning orchestrator, and returns the hash.
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

        // Collect peer embeddings from gossip layer
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

    /// WP-F.3: Extract peer embeddings from gossip layer's learning data store.
    ///
    /// Converts the network-layer `LearningMessage::Embedding` messages into
    /// the learning-crate's `PeerEmbedding` format for aggregation.
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
            "Collected {} peer embeddings for checkpoint {}",
            peer_embeddings.len(),
            checkpoint_height,
        );

        peer_embeddings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_consensus::crypto::Ed25519SigningKey;

    fn test_signing_key() -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&[42u8; 32])
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
        let result = vrf_selector.verify_vrf_proof(&proposer, &legacy_vrf, &prev_vrf, 1);
        assert!(result.is_ok(), "Legacy VRF verification should not error");
    }
}
