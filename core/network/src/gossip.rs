// citrate/core/network/src/gossip.rs

// Gossip protocol implementation
use crate::{
    learning_messages::LearningMessage,
    peer::{Peer, PeerId, PeerManager},
    NetworkError, NetworkMessage,
};
use dashmap::DashMap;
use citrate_consensus::types::{Block, Hash, PublicKey, Transaction};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Peer scoring penalties / rewards applied during gossip validation.
// When a peer's cumulative score drops below score_threshold (-100 default),
// the peer is banned and disconnected.
// ---------------------------------------------------------------------------

/// Peer sent a block that failed validation (e.g. bad header, oversized).
const SCORE_INVALID_BLOCK: i32 = -25;

/// Peer sent a transaction that failed validation.
const SCORE_INVALID_TX: i32 = -10;

/// Peer relayed a valid new block (small reward to offset incidental penalties).
const SCORE_VALID_BLOCK: i32 = 1;

/// Peer relayed a valid new transaction.
const SCORE_VALID_TX: i32 = 1;

/// Peer sent excessive duplicate messages (spamming).
#[allow(dead_code)]
const SCORE_EXCESSIVE_DUPLICATES: i32 = -5;

/// Peer sent an invalid learning message (bad embedding, self-mentoring, etc.).
const SCORE_INVALID_LEARNING: i32 = -10;

/// Peer relayed a valid learning message.
const SCORE_VALID_LEARNING: i32 = 1;

#[derive(Debug, Clone)]
pub struct GossipConfig {
    /// Maximum items in seen cache
    pub max_seen_cache: usize,

    /// Seen cache TTL
    pub seen_cache_ttl: Duration,

    /// Gossip fanout (number of peers to propagate to)
    pub fanout: usize,

    /// Maximum message size
    pub max_message_size: usize,

    /// Validation timeout
    pub validation_timeout: Duration,

    /// FWA-C2-01: chain id bound into learning-gossip signature
    /// verification (cross-chain replay defense). Citrate mainnet = 40204.
    pub chain_id: u64,

    /// SECREM-A001: this chain's canonical genesis hash (from the node's
    /// `HandshakeParams.genesis_hash`). Bound into the block-admission
    /// genesis IDENTITY check so a block merely SHAPED like genesis
    /// (parentless, arbitrary height, empty VRF / zero proposer / zero
    /// signature) cannot bypass validation. `None` (the Default) accepts
    /// only the height-0 parentless shape; production sets it at startup.
    pub genesis_hash: Option<Hash>,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            max_seen_cache: 10000,
            seen_cache_ttl: Duration::from_secs(600),
            fanout: 8,
            max_message_size: 1024 * 1024, // 1MB
            validation_timeout: Duration::from_millis(100),
            chain_id: 40204,
            genesis_hash: None,
        }
    }
}

/// Seen item tracking
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SeenItem {
    hash: Hash,
    first_seen: Instant,
    propagated: bool,
}

/// Deduplication key for learning embeddings: (checkpoint_height, participant).
///
/// Each participant is allowed at most one embedding per checkpoint height.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LearningDedup {
    pub checkpoint_height: u64,
    pub participant: PublicKey,
}

/// Per-checkpoint collection of learning messages awaiting aggregation.
#[derive(Debug, Default)]
pub struct CheckpointLearningData {
    pub embeddings: Vec<LearningMessage>,
    pub adapters: Vec<LearningMessage>,
}

/// Gossip protocol implementation
pub struct GossipProtocol {
    config: GossipConfig,
    peer_manager: Arc<PeerManager>,

    // Seen caches for deduplication
    seen_blocks: Arc<DashMap<Hash, SeenItem>>,
    seen_transactions: Arc<DashMap<Hash, SeenItem>>,

    // Learning dedup: (checkpoint_height, participant) → first_seen
    seen_learning: Arc<DashMap<LearningDedup, Instant>>,

    // Per-checkpoint learning data store for aggregation
    learning_data: Arc<RwLock<HashMap<u64, CheckpointLearningData>>>,

    // Statistics
    stats: Arc<RwLock<GossipStats>>,

    /// PBA-R2 block-validity hardening: selects the `tx_root` rule by height
    /// (PBA-L1b-002). See `citrate_consensus::hardening`.
    pba_hardening: citrate_consensus::hardening::PbaHardening,
}

#[derive(Debug, Default)]
struct GossipStats {
    blocks_received: u64,
    blocks_propagated: u64,
    transactions_received: u64,
    transactions_propagated: u64,
    duplicates_filtered: u64,
    learning_received: u64,
    learning_propagated: u64,
    learning_duplicates_filtered: u64,
}

impl GossipProtocol {
    pub fn new(config: GossipConfig, peer_manager: Arc<PeerManager>) -> Self {
        Self {
            config,
            peer_manager,
            seen_blocks: Arc::new(DashMap::new()),
            seen_transactions: Arc::new(DashMap::new()),
            seen_learning: Arc::new(DashMap::new()),
            learning_data: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(GossipStats::default())),
            pba_hardening: citrate_consensus::hardening::PbaHardening::from_process(),
        }
    }

    /// The PBA-R2 hardening activation this instance enforces.
    pub fn pba_hardening(&self) -> citrate_consensus::hardening::PbaHardening {
        self.pba_hardening
    }

    /// Override the PBA-R2 hardening activation (tests / isolated devnets).
    pub fn with_pba_hardening(
        mut self,
        hardening: citrate_consensus::hardening::PbaHardening,
    ) -> Self {
        self.pba_hardening = hardening;
        self
    }

    /// Handle new block announcement
    pub async fn handle_new_block(
        &self,
        block: Block,
        from_peer: &PeerId,
    ) -> Result<(), NetworkError> {
        let hash = block.hash();

        // Check if already seen
        if let Some(seen) = self.seen_blocks.get(&hash) {
            if seen.propagated {
                self.stats.write().await.duplicates_filtered += 1;
                return Ok(());
            }
        }

        // Mark as seen
        self.seen_blocks.insert(
            hash,
            SeenItem {
                hash,
                first_seen: Instant::now(),
                propagated: false,
            },
        );

        self.stats.write().await.blocks_received += 1;

        // Validate block (full integrity checks — WP-G.3)
        if !self.validate_block(&block).await {
            warn!("Block validation failed from {}: {}", from_peer, hash);
            // Penalize peer for sending invalid block
            self.peer_manager
                .update_peer_score(from_peer, SCORE_INVALID_BLOCK)
                .await;
            return Err(NetworkError::InvalidMessage(
                format!("Block {} failed validation", hash)
            ));
        }

        // Reward peer for valid block relay
        self.peer_manager
            .update_peer_score(from_peer, SCORE_VALID_BLOCK)
            .await;

        // Propagate to other peers
        self.propagate_block(block.clone(), from_peer).await?;

        Ok(())
    }

    /// Handle new transaction announcement
    pub async fn handle_new_transaction(
        &self,
        tx: Transaction,
        from_peer: &PeerId,
    ) -> Result<(), NetworkError> {
        // PBA-L1a-006 / NET-H3: authenticate from contents and key everything
        // (dedup, seen-cache, relay) on the canonical id, never the claimed
        // `tx.hash`. An unauthenticated or forged tx is neither cached as
        // "seen" (so it cannot shadow the genuine one) nor relayed.
        let tx = match self.authenticate_transaction(tx, from_peer).await {
            Ok(tx) => tx,
            Err(e) => return Err(e),
        };
        let hash = tx.hash;

        // Check if already seen
        if let Some(seen) = self.seen_transactions.get(&hash) {
            if seen.propagated {
                self.stats.write().await.duplicates_filtered += 1;
                return Ok(());
            }
        }

        // Mark as seen
        self.seen_transactions.insert(
            hash,
            SeenItem {
                hash,
                first_seen: Instant::now(),
                propagated: false,
            },
        );

        self.stats.write().await.transactions_received += 1;

        // Validate transaction (basic checks)
        if !self.validate_transaction(&tx).await {
            warn!("Invalid transaction received from {}: {}", from_peer, hash);
            // Penalize peer for sending invalid transaction
            self.peer_manager
                .update_peer_score(from_peer, SCORE_INVALID_TX)
                .await;
            return Err(NetworkError::InvalidMessage(
                "Invalid transaction".to_string(),
            ));
        }

        // Reward peer for valid transaction relay
        self.peer_manager
            .update_peer_score(from_peer, SCORE_VALID_TX)
            .await;

        // Propagate to other peers
        self.propagate_transaction(tx.clone(), from_peer).await?;

        Ok(())
    }

    /// PBA-L1b-007: the pre-filter for transactions that arrive OUTSIDE the
    /// gossip arm (the `Transactions` response message, which this node never
    /// requests, so every batch is unsolicited): the same basic validity checks
    /// and content authentication as `handle_new_transaction`, without relay.
    pub async fn prevalidate_transaction(
        &self,
        tx: Transaction,
        from_peer: &PeerId,
    ) -> Result<Transaction, NetworkError> {
        if !self.validate_transaction(&tx).await {
            self.peer_manager
                .update_peer_score(from_peer, SCORE_INVALID_TX)
                .await;
            return Err(NetworkError::InvalidMessage("Invalid transaction".to_string()));
        }
        self.authenticate_transaction(tx, from_peer).await
    }

    /// PBA-L1a-006 / PBA-L1b-007: authenticate a peer-supplied transaction
    /// from its contents (`tx_auth::authenticate`: ed25519, or secp256k1
    /// recovery over the rebuilt legacy/2930/1559 payload) and return it with
    /// its canonical id. Penalizes the peer on failure. Used by the gossip
    /// arm and by the node's `Transactions` response arm.
    pub async fn authenticate_transaction(
        &self,
        mut tx: Transaction,
        from_peer: &PeerId,
    ) -> Result<Transaction, NetworkError> {
        match citrate_consensus::tx_auth::authenticate(&tx) {
            Ok(id) => {
                tx.hash = id;
                Ok(tx)
            }
            Err(e) => {
                self.peer_manager
                    .update_peer_score(from_peer, SCORE_INVALID_TX)
                    .await;
                Err(NetworkError::InvalidMessage(format!(
                    "unauthenticated transaction: {e}"
                )))
            }
        }
    }

    /// Propagate block to peers
    async fn propagate_block(
        &self,
        block: Block,
        exclude_peer: &PeerId,
    ) -> Result<(), NetworkError> {
        let block_hash = block.hash();

        // CHAIN-B-A014: mark the block seen-and-handled BEFORE the empty-peer
        // early return. The `propagated` flag is `handle_new_block`'s only
        // duplicate suppressor; when a node has no other peers (e.g. a single
        // attacker peer), the old code returned here before setting it, so the
        // guard never fired and the attacker could replay one block indefinitely
        // — each replay paying a full `bincode::serialize` + ed25519 verify and
        // earning `SCORE_VALID_BLOCK`. Handling is complete once validation has
        // passed; whether we had peers to relay to is irrelevant to dedup.
        if let Some(mut seen) = self.seen_blocks.get_mut(&block_hash) {
            seen.propagated = true;
        }

        let peers = self.select_gossip_peers(exclude_peer).await;

        if peers.is_empty() {
            return Ok(());
        }

        let message = NetworkMessage::NewBlock { block };

        for peer in peers {
            if let Err(e) = peer.send(message.clone()).await {
                debug!("Failed to propagate block to peer: {}", e);
            }
        }

        self.stats.write().await.blocks_propagated += 1;

        Ok(())
    }

    /// Propagate transaction to peers
    async fn propagate_transaction(
        &self,
        tx: Transaction,
        exclude_peer: &PeerId,
    ) -> Result<(), NetworkError> {
        let tx_hash = tx.hash;

        // CHAIN-B-A014: mark seen-and-handled BEFORE the empty-peer early return
        // (same replay-farming gap as `propagate_block`).
        if let Some(mut seen) = self.seen_transactions.get_mut(&tx_hash) {
            seen.propagated = true;
        }

        let peers = self.select_gossip_peers(exclude_peer).await;

        if peers.is_empty() {
            return Ok(());
        }

        let message = NetworkMessage::NewTransaction { transaction: tx };

        for peer in peers {
            if let Err(e) = peer.send(message.clone()).await {
                debug!("Failed to propagate transaction to peer: {}", e);
            }
        }

        self.stats.write().await.transactions_propagated += 1;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Learning gossip (WP-F.2)
    // -----------------------------------------------------------------------

    /// Handle an incoming learning gossip message.
    ///
    /// Deduplication: at most one embedding per (checkpoint_height, participant).
    /// Rate-limiting is enforced by the dedup key — a second embedding from the
    /// same participant at the same checkpoint is silently dropped.
    pub async fn handle_learning_message(
        &self,
        msg: LearningMessage,
        from_peer: &PeerId,
    ) -> Result<(), NetworkError> {
        // 1. Structural validation
        if let Err(e) = msg.validate() {
            warn!(
                "[INVALID_LEARNING] from={} error={}",
                from_peer.0, e
            );
            self.peer_manager
                .update_peer_score(from_peer, SCORE_INVALID_LEARNING)
                .await;
            return Err(NetworkError::InvalidMessage(e));
        }

        // 1b. FWA-C2-01: cryptographic signature verification BEFORE any
        // dedup/store/propagate. Without this a peer could broadcast an
        // embedding/adapter carrying ANY victim validator's PublicKey in
        // `participant`/`mentor` with a junk signature; the node would
        // store it under the victim's identity, re-gossip it, AND — because
        // dedup keys on the attacker-chosen participant — censor the
        // victim's genuine entry at that height. Fail closed + penalize.
        if let Err(e) = msg.verify_signature(self.config.chain_id) {
            warn!(
                "[INVALID_LEARNING_SIG] from={} error={}",
                from_peer.0, e
            );
            self.peer_manager
                .update_peer_score(from_peer, SCORE_INVALID_LEARNING)
                .await;
            return Err(NetworkError::InvalidMessage(e));
        }

        // 2. Build dedup key
        let dedup_key = match &msg {
            LearningMessage::Embedding(emb) => LearningDedup {
                checkpoint_height: emb.checkpoint_height,
                participant: emb.participant,
            },
            LearningMessage::Adapter(offer) => LearningDedup {
                checkpoint_height: offer.checkpoint_height,
                participant: offer.mentor,
            },
        };

        // 3. Check dedup cache
        if self.seen_learning.contains_key(&dedup_key) {
            self.stats.write().await.learning_duplicates_filtered += 1;
            return Ok(());
        }

        // 4. Mark as seen
        self.seen_learning.insert(dedup_key, Instant::now());
        self.stats.write().await.learning_received += 1;

        info!(
            "[LEARNING] checkpoint={} type={} from={}",
            msg.checkpoint_height(),
            match &msg {
                LearningMessage::Embedding(_) => "embedding",
                LearningMessage::Adapter(_) => "adapter",
            },
            from_peer.0,
        );

        // 5. Store in per-checkpoint collection
        {
            let mut data = self.learning_data.write().await;
            let entry = data
                .entry(msg.checkpoint_height())
                .or_default();
            match &msg {
                LearningMessage::Embedding(_) => entry.embeddings.push(msg.clone()),
                LearningMessage::Adapter(_) => entry.adapters.push(msg.clone()),
            }
        }

        // 6. Reward peer
        self.peer_manager
            .update_peer_score(from_peer, SCORE_VALID_LEARNING)
            .await;

        // 7. Propagate to other peers
        self.propagate_learning(msg, from_peer).await?;

        Ok(())
    }

    /// Propagate a learning message to gossip peers.
    async fn propagate_learning(
        &self,
        msg: LearningMessage,
        exclude_peer: &PeerId,
    ) -> Result<(), NetworkError> {
        let peers = self.select_gossip_peers(exclude_peer).await;

        if peers.is_empty() {
            return Ok(());
        }

        let network_msg = NetworkMessage::LearningGossip { message: msg };

        for peer in peers {
            if let Err(e) = peer.send(network_msg.clone()).await {
                debug!("Failed to propagate learning message to peer: {}", e);
            }
        }

        self.stats.write().await.learning_propagated += 1;

        Ok(())
    }

    /// Retrieve the collected learning data for a given checkpoint height.
    ///
    /// Returns `None` if no data has been collected for that checkpoint.
    pub async fn get_learning_data(&self, checkpoint_height: u64) -> Option<CheckpointLearningData> {
        let data = self.learning_data.read().await;
        data.get(&checkpoint_height).map(|d| CheckpointLearningData {
            embeddings: d.embeddings.clone(),
            adapters: d.adapters.clone(),
        })
    }

    /// Remove learning data for checkpoints at or below `finalized_height`.
    ///
    /// Call this when a checkpoint is finalized and the learning data has been
    /// aggregated and committed.
    pub async fn prune_learning_data(&self, finalized_height: u64) {
        let mut data = self.learning_data.write().await;
        data.retain(|&h, _| h > finalized_height);

        // Also prune the dedup cache for old checkpoints
        self.seen_learning
            .retain(|key, _| key.checkpoint_height > finalized_height);
    }

    /// Select peers for gossip propagation
    async fn select_gossip_peers(&self, exclude: &PeerId) -> Vec<Arc<Peer>> {
        let all_peers = self.peer_manager.get_all_peers();

        let mut eligible: Vec<Arc<Peer>> = Vec::new();

        for peer in all_peers {
            let info = peer.info.read().await;
            if info.id != *exclude && info.state == crate::peer::PeerState::Connected {
                eligible.push(peer.clone());
            }
        }

        // Randomly select up to fanout peers
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        eligible.shuffle(&mut rng);
        eligible.truncate(self.config.fanout);

        eligible
    }

    /// Validate block with full integrity checks (WP-G.3).
    ///
    /// Checks performed (in order):
    /// 1. BLOCK_OVERSIZED — serialized size exceeds transport limit
    /// 2. INVALID_HEIGHT — height=0 on non-genesis
    /// 3. TIMESTAMP_FUTURE — timestamp > now + 15min
    /// 4. ZERO_BLUE_SCORE — non-genesis with blue_score=0
    /// 5. MISSING_VRF — non-genesis without VRF proof
    /// 6. MISSING_PARENT — non-genesis with zero selected_parent_hash
    /// 7. HASH_MISMATCH — recomputed hash differs from advertised (C-05)
    /// 8. TX_ROOT_MISMATCH — recomputed tx_root differs from header
    /// 9. INVALID_SIGNATURE — ed25519 signature verification failed (WP-G.2)
    async fn validate_block(&self, block: &Block) -> bool {
        // SECREM-A001: genesis is an IDENTITY, not a shape. Compute it once
        // and use it for every exemption below, so a block shaped like
        // genesis at an arbitrary height cannot skip the parent / VRF /
        // proposer / signature checks.
        let is_genesis = block.is_configured_genesis(self.config.genesis_hash);
        // 1. BLOCK_OVERSIZED
        // RM-B1 / WP-B1.5 (audit M-06): on serialize failure reject
        // outright — a block that doesn't serialize cannot be sized,
        // and silently treating it as zero-size let oversized blocks
        // pass validation under the pre-fix `unwrap_or_default` path.
        let size = match bincode::serialize(block) {
            Ok(bytes) => bytes.len(),
            Err(e) => {
                warn!(
                    "[BLOCK_SERIALIZE_FAIL] block={} err={} — rejecting",
                    block.header.block_hash, e
                );
                return false;
            }
        };
        if size > self.config.max_message_size {
            warn!("[BLOCK_OVERSIZED] block={} size={}", block.header.block_hash, size);
            return false;
        }

        // 2. INVALID_HEIGHT
        if block.header.height == 0 && !is_genesis {
            warn!("[INVALID_HEIGHT] block={}", block.header.block_hash);
            return false;
        }

        // 3. TIMESTAMP_FUTURE
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Shared with the sync ingress (PBA-L1b-003); saturating.
        if !citrate_consensus::hardening::within_future_drift(block.header.timestamp, now) {
            warn!("[TIMESTAMP_FUTURE] block={} ts={} now={}", block.header.block_hash, block.header.timestamp, now);
            return false;
        }

        // 4. ZERO_BLUE_SCORE
        if block.header.blue_score == 0 && !is_genesis {
            warn!("[ZERO_BLUE_SCORE] block={}", block.header.block_hash);
            return false;
        }

        // 5. MISSING_VRF
        if !is_genesis && block.header.vrf_reveal.proof.is_empty() {
            warn!("[MISSING_VRF] block={}", block.header.block_hash);
            return false;
        }

        // 5a. INVALID_PROPOSER_PUBKEY — RM-B1 / WP-B3.1 (audit C-02):
        // reject blocks whose `proposer_pubkey` is neither an
        // embedded-EVM form nor a valid ed25519 curve point. Prevents
        // attribution-spoofing attacks where an attacker submits
        // a "natural-looking" 32-byte byte string that bypasses the
        // dual-format check while remaining off-curve. (Genesis is
        // exempt — its proposer field carries the network identity.)
        if !is_genesis && !block.header.proposer_pubkey.is_admissible() {
            warn!(
                "[INVALID_PROPOSER_PUBKEY] block={} pubkey={}",
                block.header.block_hash,
                hex::encode(block.header.proposer_pubkey.as_bytes())
            );
            return false;
        }

        // 6. MISSING_PARENT — non-genesis must reference a selected parent
        if !is_genesis && block.header.selected_parent_hash == Hash::default() {
            warn!("[MISSING_PARENT] block={}", block.header.block_hash);
            return false;
        }

        // 7. HASH_MISMATCH — recompute canonical hash from all fields (C-05)
        if !block.verify_hash_for(self.pba_hardening) {
            warn!(
                "[HASH_MISMATCH] block={} computed={}",
                block.header.block_hash,
                block.compute_hash_for(self.pba_hardening)
            );
            return false;
        }

        // 8. TX_ROOT_MISMATCH — verify tx_root matches transactions in block
        // PBA-L1b-002: content-bound root from the activation height.
        {
            let computed_tx_root = citrate_consensus::tx_auth::tx_root_for_height(
                self.pba_hardening,
                block.header.height,
                &block.transactions,
            );
            if block.tx_root != computed_tx_root {
                warn!(
                    "[TX_ROOT_MISMATCH] block={} expected={} computed={}",
                    block.header.block_hash, block.tx_root, computed_tx_root
                );
                return false;
            }
        }

        // 9. INVALID_SIGNATURE — verify ed25519 block signature (skip genesis)
        if !is_genesis {
            match citrate_consensus::crypto::verify_block_signature(block) {
                Ok(true) => { /* valid */ }
                Ok(false) => {
                    warn!(
                        "[INVALID_SIGNATURE] block={} proposer={}",
                        block.header.block_hash,
                        hex::encode(block.header.proposer_pubkey.as_bytes())
                    );
                    return false;
                }
                Err(e) => {
                    warn!(
                        "[INVALID_SIGNATURE] block={} error={}",
                        block.header.block_hash, e
                    );
                    return false;
                }
            }
        }

        true
    }

    /// Validate transaction (basic checks)
    async fn validate_transaction(&self, tx: &Transaction) -> bool {
        // Check transaction size.
        // RM-B1 / WP-B1.5 (audit M-06): on serialize failure reject
        // outright — see `validate_block` for rationale.
        let size = match bincode::serialize(tx) {
            Ok(bytes) => bytes.len(),
            Err(_) => return false,
        };
        if size > self.config.max_message_size {
            return false;
        }

        // Basic validation
        if tx.gas_price == 0 || tx.gas_limit == 0 {
            return false;
        }

        // Additional validation
        // Check gas price meets minimum
        const MIN_GAS_PRICE: u64 = 1_000_000_000; // 1 Gwei
        if tx.gas_price < MIN_GAS_PRICE {
            return false;
        }

        // Check gas limit is reasonable
        const MAX_GAS_LIMIT: u64 = 30_000_000;
        if tx.gas_limit > MAX_GAS_LIMIT {
            return false;
        }

        // Validate value doesn't overflow
        if tx.value > u128::MAX / 2 {
            return false;
        }

        // Check data size
        const MAX_TX_DATA_SIZE: usize = 128 * 1024; // 128KB
        if tx.data.len() > MAX_TX_DATA_SIZE {
            return false;
        }

        // Signature must be present (64 bytes for Ed25519)
        // Note: Actual signature verification would be done by the mempool

        true
    }

    /// Clean up old seen items
    pub async fn cleanup_seen_cache(&self) {
        let now = Instant::now();
        let ttl = self.config.seen_cache_ttl;

        // Clean blocks
        self.seen_blocks
            .retain(|_, item| now.duration_since(item.first_seen) < ttl);

        // Clean transactions
        self.seen_transactions
            .retain(|_, item| now.duration_since(item.first_seen) < ttl);

        // Clean learning dedup entries
        self.seen_learning
            .retain(|_, first_seen| now.duration_since(*first_seen) < ttl);

        // Enforce max size
        if self.seen_blocks.len() > self.config.max_seen_cache {
            // Remove oldest entries
            let mut items: Vec<_> = self
                .seen_blocks
                .iter()
                .map(|e| (*e.key(), e.value().first_seen))
                .collect();

            items.sort_by_key(|&(_, time)| time);

            let to_remove = items.len() - self.config.max_seen_cache;
            for (hash, _) in items.into_iter().take(to_remove) {
                self.seen_blocks.remove(&hash);
            }
        }

        if self.seen_transactions.len() > self.config.max_seen_cache {
            let mut items: Vec<_> = self
                .seen_transactions
                .iter()
                .map(|e| (*e.key(), e.value().first_seen))
                .collect();

            items.sort_by_key(|&(_, time)| time);

            let to_remove = items.len() - self.config.max_seen_cache;
            for (hash, _) in items.into_iter().take(to_remove) {
                self.seen_transactions.remove(&hash);
            }
        }

        // SECREM-01 NET-3: seen_learning previously had TTL-only
        // cleanup. An attacker flooding unique (checkpoint_height,
        // participant) pairs faster than the TTL expires them could
        // still grow the map without bound between cleanups, so
        // enforce the same hard max-size eviction (oldest first) as
        // the block/tx caches.
        if self.seen_learning.len() > self.config.max_seen_cache {
            let mut items: Vec<_> = self
                .seen_learning
                .iter()
                .map(|e| (*e.key(), *e.value()))
                .collect();

            items.sort_by_key(|&(_, time)| time);

            let to_remove = items.len() - self.config.max_seen_cache;
            for (key, _) in items.into_iter().take(to_remove) {
                self.seen_learning.remove(&key);
            }
        }
    }

    /// Get gossip statistics.
    ///
    /// Returns `(blocks_received, blocks_propagated, txs_received,
    /// txs_propagated, duplicates_filtered, learning_received,
    /// learning_propagated, learning_duplicates_filtered)`.
    pub async fn get_stats(&self) -> (u64, u64, u64, u64, u64, u64, u64, u64) {
        let stats = self.stats.read().await;
        (
            stats.blocks_received,
            stats.blocks_propagated,
            stats.transactions_received,
            stats.transactions_propagated,
            stats.duplicates_filtered,
            stats.learning_received,
            stats.learning_propagated,
            stats.learning_duplicates_filtered,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerManagerConfig;

    #[tokio::test]
    async fn test_seen_cache() {
        let peer_manager = Arc::new(PeerManager::new(PeerManagerConfig::default()));
        let gossip = GossipProtocol::new(GossipConfig::default(), peer_manager);

        // Use a simple hash for testing
        let hash = Hash::new([1; 32]);

        // First time seeing block
        assert!(gossip.seen_blocks.get(&hash).is_none());

        // Mark as seen
        gossip.seen_blocks.insert(
            hash,
            SeenItem {
                hash,
                first_seen: Instant::now(),
                propagated: false,
            },
        );

        // Should now be in cache
        assert!(gossip.seen_blocks.get(&hash).is_some());
    }

    #[tokio::test]
    async fn test_cache_cleanup() {
        let config = GossipConfig {
            max_seen_cache: 3,
            ..Default::default()
        };

        let peer_manager = Arc::new(PeerManager::new(PeerManagerConfig::default()));
        let gossip = GossipProtocol::new(config, peer_manager);

        // Add more items than max
        for i in 0..5 {
            let hash = Hash::new([i; 32]);
            gossip.seen_blocks.insert(
                hash,
                SeenItem {
                    hash,
                    first_seen: Instant::now() - Duration::from_secs(i as u64),
                    propagated: false,
                },
            );
        }

        gossip.cleanup_seen_cache().await;

        // Should only keep max_seen_cache items
        assert!(gossip.seen_blocks.len() <= 3);
    }

    /// SECREM-01 NET-3: seen_learning must be hard-capped at
    /// max_seen_cache (oldest evicted first), not just TTL-pruned —
    /// an attacker can mint unique (height, participant) pairs
    /// faster than the TTL expires them.
    #[tokio::test]
    async fn test_seen_learning_max_size_eviction() {
        let config = GossipConfig {
            max_seen_cache: 3,
            // Long TTL so only the max-size path can evict
            seen_cache_ttl: Duration::from_secs(3600),
            ..Default::default()
        };

        let peer_manager = Arc::new(PeerManager::new(PeerManagerConfig::default()));
        let gossip = GossipProtocol::new(config, peer_manager);

        // Add more entries than max; entry i is i seconds old, so
        // higher i = older = evicted first.
        for i in 0..6u8 {
            let key = LearningDedup {
                checkpoint_height: i as u64,
                participant: PublicKey::new([i; 32]),
            };
            gossip
                .seen_learning
                .insert(key, Instant::now() - Duration::from_secs(i as u64));
        }

        gossip.cleanup_seen_cache().await;

        assert!(
            gossip.seen_learning.len() <= 3,
            "seen_learning must be capped at max_seen_cache, got {}",
            gossip.seen_learning.len()
        );
        // Newest entries (smallest age) survive
        for i in 0..3u8 {
            let key = LearningDedup {
                checkpoint_height: i as u64,
                participant: PublicKey::new([i; 32]),
            };
            assert!(
                gossip.seen_learning.contains_key(&key),
                "newest learning entry {} must survive eviction",
                i
            );
        }
    }
}
