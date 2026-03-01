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
use citrate_network::{NetworkMessage, PeerManager};
use citrate_sequencer::mempool::Mempool;
use citrate_storage::{state_manager::StateManager as AIStateManager, StorageManager};
use primitive_types::U256;
use sha3::{Digest, Sha3_256};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

// Block hash is now computed via Block::compute_hash() in consensus/types.rs (C-05).
// This ensures a single canonical hash function used by both producer and validator.

/// Generate a simplified VRF proof for block production.
///
/// WP-H.6: The input hash includes the proposer's public key and the output
/// hash includes the input, binding the proof to the proposer's identity.
/// This prevents key substitution attacks and slot/chain replay.
fn generate_block_vrf(proposer_pubkey: &PublicKey, coinbase: &PublicKey, prev_vrf: &Hash, slot: u64) -> VrfProof {
    let mut input_hasher = Sha3_256::new();
    input_hasher.update(proposer_pubkey.as_bytes()); // H.6: bind to proposer identity
    input_hasher.update(prev_vrf.as_bytes());
    input_hasher.update(slot.to_le_bytes());
    let input = input_hasher.finalize();

    let mut proof_hasher = Sha3_256::new();
    proof_hasher.update(coinbase.as_bytes());
    proof_hasher.update(&input);
    let proof_bytes = proof_hasher.finalize();

    let mut output_hasher = Sha3_256::new();
    output_hasher.update(&proof_bytes);
    output_hasher.update(&input); // H.6: bind output to (proposer, slot, prev_vrf)
    let output_bytes = output_hasher.finalize();

    VrfProof {
        proof: proof_bytes.to_vec(),
        output: Hash::from_bytes(&output_bytes),
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
        }
    }

    /// Create with explicit reward configuration (for governance-driven params)
    #[allow(dead_code)]
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
        }
    }

    /// Create with economics manager for full economic integration
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
        }
    }

    /// WP-K.2: Access the producer's shared DAG store.
    /// Used to feed network-received blocks into the live DAG for fork-choice.
    pub fn dag_store(&self) -> Arc<DagStore> {
        self.dag_store.clone()
    }

    /// WP-K.2: Access the producer's shared GhostDag instance.
    /// Used to update blue set calculations when network blocks arrive.
    pub fn ghostdag(&self) -> Arc<GhostDag> {
        self.ghostdag.clone()
    }

    /// Create with pre-built DAG components and economics manager.
    /// WP-K.2: Allows sharing the DAG store and GhostDag between the
    /// producer and the network message handler for live fork-choice.
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
        }
    }

    /// Set an external pause flag (shared with the RPC server).
    /// WP-I.3: This allows the RPC citrate_emergencyPause method to
    /// directly control block production.
    pub fn set_pause_flag(&mut self, flag: Arc<AtomicBool>) {
        self.paused = flag;
    }

    /// Pause block production (emergency stop).
    pub fn pause(&self) {
        self.paused.store(true, Ordering::Relaxed);
        warn!("EMERGENCY: Block production PAUSED");
    }

    /// Resume block production after emergency pause.
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
                vrf_reveal: generate_block_vrf(&PublicKey::new(self.signing_key.verifying_key().to_bytes()), &self.coinbase, &selected_parent, 0),
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
        };

        let blue_set = self.ghostdag.calculate_blue_set(&temp_block).await?;
        let blue_score = self.ghostdag.calculate_blue_score(&temp_block).await?;

        // Get last block height from selected parent
        let last_height = if selected_parent != Hash::default() {
            // Get parent block from storage to determine height
            self.storage
                .blocks
                .get_block(&selected_parent)
                .ok()
                .and_then(|b| b.map(|block| block.header.height))
                .unwrap_or(0)
        } else {
            0
        };

        // Get transactions from mempool with AI priority
        let transactions = self.select_transactions_with_ai_priority().await?;

        // Blue score and work are already calculated above
        let blue_work = self.calculate_blue_work(&blue_set, blue_score)?;

        // Create block header with GhostDAG consensus data
        let mut header = BlockHeader {
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
            vrf_reveal: generate_block_vrf(&PublicKey::new(self.signing_key.verifying_key().to_bytes()), &self.coinbase, &selected_parent, last_height + 1),
            base_fee_per_gas: 1_000_000_000, // 1 gwei - TODO: calculate from parent
            gas_used: 0, // Will be updated after execution
            gas_limit: 30_000_000, // 30M gas default
        };

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
                total_reward = total_reward + staking_bonus;
                info!("Economics: Applied staking bonus of {} wei for staked amount {}", staking_bonus, staked_amount);
            }

            let reputation_score = economics.get_reputation_score(&validator_address);
            if reputation_score > 0.5 {
                let reputation_bonus = base_reward * primitive_types::U256::from((reputation_score * 20.0) as u64) / primitive_types::U256::from(100);
                total_reward = total_reward + reputation_bonus;
                info!("Economics: Applied reputation bonus of {} wei for score {}", reputation_bonus, reputation_score);
            }

            let current_gas_price = economics.get_operation_cost(citrate_economics::OperationType::AIInference { compute_units: 1000 });
            if current_gas_price > economics.get_config().pricing_config.base_gas_price {
                let congestion_bonus = base_reward / primitive_types::U256::from(20);
                total_reward = total_reward + congestion_bonus;
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
        };

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
        };

        // Execute each transaction
        for tx in transactions {
            match self.executor.execute_transaction(&temp_block, tx).await {
                Ok(receipt) => receipts.push(receipt),
                Err(e) => {
                    error!("Failed to execute transaction {}: {}", tx.hash, e);
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
}
