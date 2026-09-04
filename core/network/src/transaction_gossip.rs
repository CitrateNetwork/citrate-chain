// citrate/core/network/src/transaction_gossip.rs

// Transaction gossip handler for efficient mempool synchronization
use crate::{NetworkMessage, PeerId, PeerManager};
use anyhow::Result;
use citrate_consensus::types::{Hash, Transaction, TransactionType};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Transaction seen info
#[derive(Clone, Debug)]
struct TxSeenInfo {
    first_seen: Instant,
    peers: HashSet<PeerId>,
    broadcast_count: u32,
}

/// Transaction gossip configuration
#[derive(Clone, Debug)]
pub struct GossipConfig {
    /// Maximum transactions to keep in seen cache
    pub max_seen_txs: usize,
    /// Time to keep transactions in seen cache
    pub tx_ttl: Duration,
    /// Maximum peers to relay to at once
    pub max_relay_peers: usize,
    /// Delay before relaying AI transactions (for bundling)
    pub ai_tx_delay: Duration,
    /// CHAIN-B-NET-H4: hard cap on tx hashes tracked per peer in
    /// `peer_inventory`. Without it a peer streaming unique valid txs grows its
    /// own inventory set without bound → remote memory exhaustion.
    pub max_peer_inventory: usize,
    /// CHAIN-B-NET-H4: hard cap on the number of distinct peers tracked in
    /// `peer_inventory` (bounds the outer map).
    pub max_tracked_peers: usize,
    /// CHAIN-B-NET-H4: hard cap on the `pending_ai_txs` relay buffer.
    pub max_pending_ai_txs: usize,
    /// CHAIN-B-NET-H4: interval at which `spawn_maintenance` drives `cleanup()`.
    pub cleanup_interval: Duration,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            max_seen_txs: 100_000,
            tx_ttl: Duration::from_secs(600), // 10 minutes
            max_relay_peers: 10,
            ai_tx_delay: Duration::from_millis(100), // 100ms delay for AI tx bundling
            max_peer_inventory: 50_000,
            max_tracked_peers: 1_024,
            max_pending_ai_txs: 8_192,
            cleanup_interval: Duration::from_secs(60),
        }
    }
}

/// Transaction gossip handler for efficient mempool synchronization
pub struct TransactionGossip {
    /// Configuration
    config: GossipConfig,

    /// Peer manager
    peer_manager: Arc<PeerManager>,

    /// Transactions we've seen (hash -> info)
    seen_txs: Arc<RwLock<HashMap<Hash, TxSeenInfo>>>,

    /// AI transactions pending relay (for bundling)
    pending_ai_txs: Arc<RwLock<Vec<Transaction>>>,

    /// Transaction inventory by peer (peer -> set of tx hashes)
    peer_inventory: Arc<RwLock<HashMap<PeerId, HashSet<Hash>>>>,
}

impl TransactionGossip {
    pub fn new(peer_manager: Arc<PeerManager>, config: GossipConfig) -> Self {
        Self {
            config,
            peer_manager,
            seen_txs: Arc::new(RwLock::new(HashMap::new())),
            pending_ai_txs: Arc::new(RwLock::new(Vec::new())),
            peer_inventory: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Handle new transaction from peer
    ///
    /// RM-I / WP-I1.7 (re-audit Stream 2 finding H-NET-01 tx-gossip path):
    ///   The H-NET-01 closure in RM-C closed the block-gossip relay-before-
    ///   validate hole, but the tx-gossip path was missed. Pre-fix this
    ///   method dedup'd against `seen_txs`, marked the peer's inventory,
    ///   and immediately relayed (`relay_transaction`) without any
    ///   validation. An attacker peer could flood the network with garbage
    ///   transactions and they'd be relayed before any node validated them.
    ///   Post-fix: every newly-seen transaction is validated by
    ///   `Self::validate_transaction_static` BEFORE entering the relay
    ///   path. Invalid transactions are dropped (not relayed, not added to
    ///   `seen_txs`, not added to `peer_inventory`).
    pub async fn handle_new_transaction(&self, peer_id: &PeerId, tx: Transaction) -> Result<bool> {
        let tx_hash = tx.hash;

        // RM-I / WP-I1.7: validate-before-relay. Must run before any
        // state mutation so an invalid tx leaves no residue. Mirrors
        // `gossip.rs::validate_transaction` byte-for-byte (see comment
        // in `validate_transaction_static`). Uses the
        // `max_message_size` constant since `GossipConfig` (this
        // module's gossip config) doesn't carry it; the value matches
        // the block-gossip cap in `gossip.rs::GossipConfig::default()`.
        const MAX_TX_GOSSIP_MESSAGE_SIZE: usize = 1024 * 1024; // 1 MiB
        if !Self::validate_transaction_static(&tx, MAX_TX_GOSSIP_MESSAGE_SIZE) {
            tracing::debug!(
                "H-NET-01 (tx-gossip): rejecting invalid tx {} from peer {}",
                tx_hash,
                peer_id
            );
            return Ok(false);
        }

        // Check if we've seen this transaction
        let mut seen = self.seen_txs.write().await;
        let is_new = if let Some(info) = seen.get_mut(&tx_hash) {
            if info.peers.contains(peer_id) {
                debug!("Already received tx {} from peer {}", tx_hash, peer_id);
                return Ok(false);
            }
            info.peers.insert(peer_id.clone());
            info.broadcast_count += 1;
            let broadcast_count = info.broadcast_count;
            drop(seen);

            // Don't relay if we've already broadcasted enough
            if broadcast_count > 3 {
                return Ok(false);
            }
            false
        } else {
            // New transaction
            let mut new_info = TxSeenInfo {
                first_seen: Instant::now(),
                peers: HashSet::new(),
                broadcast_count: 0,
            };
            new_info.peers.insert(peer_id.clone());
            seen.insert(tx_hash, new_info);
            drop(seen);

            info!(
                "New transaction {} from peer {} (type: {:?})",
                tx_hash, peer_id, tx.tx_type
            );
            true
        };

        // Update peer inventory — bounded (CHAIN-B-NET-H4). The per-peer set
        // and the outer peer map were previously unbounded: a peer streaming
        // unique valid txs grew `peer_inventory[attacker]` forever until OOM.
        {
            let mut inv = self.peer_inventory.write().await;
            // Bound the number of distinct peers tracked. If we're at capacity
            // and this is a peer we don't already track, evict one arbitrary
            // existing peer to make room (FIFO-equivalent under HashMap order).
            if !inv.contains_key(peer_id) && inv.len() >= self.config.max_tracked_peers {
                if let Some(victim) = inv.keys().next().cloned() {
                    inv.remove(&victim);
                }
            }
            let set = inv.entry(peer_id.clone()).or_insert_with(HashSet::new);
            // Bound the per-peer inventory set. Drop one arbitrary existing
            // hash before inserting when at capacity.
            if set.len() >= self.config.max_peer_inventory && !set.contains(&tx_hash) {
                if let Some(victim) = set.iter().next().copied() {
                    set.remove(&victim);
                }
            }
            set.insert(tx_hash);
        }

        // Handle based on transaction type
        match tx.tx_type {
            Some(TransactionType::ModelDeploy)
            | Some(TransactionType::ModelUpdate)
            | Some(TransactionType::InferenceRequest)
            | Some(TransactionType::TrainingJob)
            | Some(TransactionType::LoraAdapter) => {
                // AI transaction - add to pending for bundled relay.
                // CHAIN-B-NET-H4: bound the buffer. Under a flood the relay
                // timer may not drain fast enough; drop new AI txs once the
                // buffer is full rather than growing without limit.
                {
                    let mut pending = self.pending_ai_txs.write().await;
                    if pending.len() < self.config.max_pending_ai_txs {
                        pending.push(tx.clone());
                    } else {
                        debug!(
                            "CHAIN-B-NET-H4: pending_ai_txs at cap ({}), dropping AI tx {}",
                            self.config.max_pending_ai_txs, tx_hash
                        );
                    }
                }

                // Schedule bundled relay
                let gossip = self.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(gossip.config.ai_tx_delay).await;
                    let _ = gossip.relay_pending_ai_txs().await;
                });
            }
            _ => {
                // Standard transaction - relay immediately
                self.relay_transaction(tx, Some(peer_id)).await?;
            }
        }

        Ok(is_new)
    }

    /// RM-I / WP-I1.7 (H-NET-01 tx-gossip): validate a transaction
    /// before it enters the relay pipeline. Mirrors the field-level
    /// checks in `gossip.rs::Gossip::validate_transaction`:
    ///   - serialise round-trip succeeds and size is within
    ///     `max_message_size`
    ///   - `gas_price >= MIN_GAS_PRICE` (1 Gwei)
    ///   - `gas_price > 0` AND `gas_limit > 0`
    ///   - `gas_limit <= MAX_GAS_LIMIT` (30 M)
    ///   - `value <= u128::MAX / 2` (overflow guard)
    ///   - `data.len() <= MAX_TX_DATA_SIZE` (128 KiB)
    ///
    /// This is intentionally a static helper so the validation can run
    /// before any RwLock acquisition. Signature verification is not done
    /// here — the mempool does the cryptographic check; this is a
    /// defence-in-depth gate against obviously-malformed payloads.
    fn validate_transaction_static(tx: &Transaction, max_message_size: usize) -> bool {
        let size = match bincode::serialize(tx) {
            Ok(bytes) => bytes.len(),
            Err(_) => return false,
        };
        if size > max_message_size {
            return false;
        }

        if tx.gas_price == 0 || tx.gas_limit == 0 {
            return false;
        }

        const MIN_GAS_PRICE: u64 = 1_000_000_000; // 1 Gwei
        if tx.gas_price < MIN_GAS_PRICE {
            return false;
        }

        const MAX_GAS_LIMIT: u64 = 30_000_000;
        if tx.gas_limit > MAX_GAS_LIMIT {
            return false;
        }

        if tx.value > u128::MAX / 2 {
            return false;
        }

        const MAX_TX_DATA_SIZE: usize = 128 * 1024;
        if tx.data.len() > MAX_TX_DATA_SIZE {
            return false;
        }

        true
    }

    /// Broadcast a new local transaction
    pub async fn broadcast_transaction(&self, tx: Transaction) -> Result<()> {
        let tx_hash = tx.hash;

        // Mark as seen
        let mut seen = self.seen_txs.write().await;
        if seen.contains_key(&tx_hash) {
            debug!("Transaction {} already broadcasted", tx_hash);
            return Ok(());
        }

        seen.insert(
            tx_hash,
            TxSeenInfo {
                first_seen: Instant::now(),
                peers: HashSet::new(),
                broadcast_count: 1,
            },
        );
        drop(seen);

        info!(
            "Broadcasting new transaction {} (type: {:?})",
            tx_hash, tx.tx_type
        );

        // Relay to peers
        self.relay_transaction(tx, None).await
    }

    /// Relay transaction to peers
    async fn relay_transaction(&self, tx: Transaction, except_peer: Option<&PeerId>) -> Result<()> {
        // Get target peers
        let all_peers = self.peer_manager.get_all_peers();
        let mut target_peers: Vec<PeerId> = Vec::new();

        for peer in all_peers.iter().take(self.config.max_relay_peers) {
            let peer_id = peer.info.read().await.id.clone();

            if let Some(except) = except_peer {
                if peer_id == *except {
                    continue;
                }
            }

            // Check if peer already has this tx
            let inventory = self.peer_inventory.read().await;
            if let Some(peer_txs) = inventory.get(&peer_id) {
                if peer_txs.contains(&tx.hash) {
                    continue;
                }
            }
            drop(inventory);

            target_peers.push(peer_id);
        }

        if !target_peers.is_empty() {
            let message = NetworkMessage::NewTransaction { transaction: tx };
            self.peer_manager
                .send_to_peers(&target_peers, &message)
                .await?;

            debug!("Relayed transaction to {} peers", target_peers.len());
        }

        Ok(())
    }

    /// Relay pending AI transactions as a bundle
    async fn relay_pending_ai_txs(&self) -> Result<()> {
        let txs: Vec<Transaction> = {
            let mut pending = self.pending_ai_txs.write().await;
            if pending.is_empty() {
                return Ok(());
            }
            pending.drain(..).collect()
        };

        info!("Relaying bundle of {} AI transactions", txs.len());

        // Send each transaction (could optimize with batch message)
        for tx in txs {
            self.relay_transaction(tx, None).await?;
        }

        Ok(())
    }

    /// Request specific transactions from peers
    pub async fn request_transactions(&self, hashes: Vec<Hash>) -> Result<()> {
        if hashes.is_empty() {
            return Ok(());
        }

        let message = NetworkMessage::GetTransactions {
            hashes: hashes.clone(),
        };
        self.peer_manager.broadcast(&message).await?;

        info!("Requested {} transactions from peers", hashes.len());
        Ok(())
    }

    /// Handle transaction response
    pub async fn handle_transactions_response(
        &self,
        peer_id: &PeerId,
        transactions: Vec<Transaction>,
    ) -> Result<()> {
        if transactions.is_empty() {
            return Ok(());
        }

        info!(
            "Received {} transactions from peer {}",
            transactions.len(),
            peer_id
        );

        // Process each transaction
        for tx in transactions {
            self.handle_new_transaction(peer_id, tx).await?;
        }

        Ok(())
    }

    /// Get mempool summary for peer
    pub async fn get_mempool_summary(&self) -> Vec<Hash> {
        let seen = self.seen_txs.read().await;
        seen.keys().cloned().collect()
    }

    /// Handle mempool request
    pub async fn handle_mempool_request(&self, peer_id: &PeerId) -> Result<()> {
        let tx_hashes = self.get_mempool_summary().await;

        let message = NetworkMessage::Mempool { tx_hashes };

        if let Some(peer) = self.peer_manager.get_peer(peer_id) {
            peer.send(message).await?;
            info!("Sent mempool summary to peer {}", peer_id);
        }

        Ok(())
    }

    /// Clean up old transactions
    pub async fn cleanup(&self) {
        let mut seen = self.seen_txs.write().await;
        let now = Instant::now();

        // Remove old transactions
        seen.retain(|hash, info| {
            let age = now.duration_since(info.first_seen);
            if age > self.config.tx_ttl {
                debug!("Removing old transaction {} from cache", hash);
                false
            } else {
                true
            }
        });

        // Limit cache size
        if seen.len() > self.config.max_seen_txs {
            let to_remove = seen.len() - self.config.max_seen_txs;
            let mut oldest: Vec<(Hash, Instant)> =
                seen.iter().map(|(h, i)| (*h, i.first_seen)).collect();
            oldest.sort_by_key(|(_h, t)| *t);

            for (hash, _) in oldest.iter().take(to_remove) {
                seen.remove(hash);
            }
        }

        // CHAIN-B-NET-H4: `peer_inventory` used to grow forever because nothing
        // pruned it. Retain only hashes still present in `seen_txs`, drop peers
        // whose set became empty, and enforce the outer peer cap.
        let live: std::collections::HashSet<Hash> = seen.keys().copied().collect();
        drop(seen);
        {
            let mut inv = self.peer_inventory.write().await;
            inv.retain(|_peer, set| {
                set.retain(|h| live.contains(h));
                !set.is_empty()
            });
            while inv.len() > self.config.max_tracked_peers {
                if let Some(victim) = inv.keys().next().cloned() {
                    inv.remove(&victim);
                } else {
                    break;
                }
            }
        }

        // Bound the AI relay buffer as a backstop to the inline cap.
        {
            let mut pending = self.pending_ai_txs.write().await;
            if pending.len() > self.config.max_pending_ai_txs {
                let overflow = pending.len() - self.config.max_pending_ai_txs;
                pending.drain(0..overflow);
            }
        }

        debug!("Cleaned up transaction gossip state");
    }

    /// CHAIN-B-NET-H4: schedule `cleanup()` on a fixed interval. Before this,
    /// `cleanup()` had zero production callers, so `max_seen_txs`/`tx_ttl` and
    /// the `peer_inventory` bound were dead config. Callers hold the returned
    /// `JoinHandle` for the lifetime of the node; the task shares the same Arc
    /// state via `Clone`.
    pub fn spawn_maintenance(&self) -> tokio::task::JoinHandle<()> {
        let gossip = self.clone();
        let interval = gossip.config.cleanup_interval;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                gossip.cleanup().await;
            }
        })
    }
}

impl Clone for TransactionGossip {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            peer_manager: self.peer_manager.clone(),
            seen_txs: self.seen_txs.clone(),
            pending_ai_txs: self.pending_ai_txs.clone(),
            peer_inventory: self.peer_inventory.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_consensus::types::{PublicKey, Signature};

    /// Helper: build a valid transaction passing the WP-I1.7
    /// validate-before-relay gate.
    fn valid_tx(hash_byte: u8, tx_type: TransactionType) -> Transaction {
        Transaction {
            hash: Hash::new([hash_byte; 32]),
            nonce: 1,
            from: PublicKey::new([2; 32]),
            to: Some(PublicKey::new([3; 32])),
            value: 1000,
            gas_limit: 21_000,
            // RM-I / WP-I1.7: 1 Gwei = MIN_GAS_PRICE in
            // validate_transaction_static; pre-fix this test used
            // gas_price=100 (below MIN_GAS_PRICE) and the validator
            // would now reject it. Updated to a valid value.
            gas_price: 1_000_000_000,
            data: vec![],
            signature: Signature::new([0; 64]),
            tx_type: Some(tx_type),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_transaction_gossip() {
        let peer_manager = Arc::new(PeerManager::new(Default::default()));
        let gossip = TransactionGossip::new(peer_manager, Default::default());

        let tx = valid_tx(1, TransactionType::Standard);

        // Test broadcasting
        assert!(gossip.broadcast_transaction(tx.clone()).await.is_ok());

        // Should be marked as seen
        let seen = gossip.seen_txs.read().await;
        assert!(seen.contains_key(&tx.hash));
        drop(seen);

        // Test handling from peer
        let peer_id = PeerId::new("test_peer".to_string());
        let is_new = gossip
            .handle_new_transaction(&peer_id, tx.clone())
            .await
            .unwrap();
        assert!(!is_new); // Should not be new since we already have it

        // Test AI transaction bundling
        let ai_tx = valid_tx(10, TransactionType::ModelDeploy);

        assert!(gossip
            .handle_new_transaction(&peer_id, ai_tx)
            .await
            .unwrap());

        // AI tx should be in pending
        let pending = gossip.pending_ai_txs.read().await;
        assert_eq!(pending.len(), 1);
    }

    // ────────────────────────────────────────────────────────────────
    // RM-I / WP-I1.7 — H-NET-01 tx-gossip validate-before-relay tests.
    // ────────────────────────────────────────────────────────────────

    /// An invalid tx (gas_price = 0) is rejected by `handle_new_transaction`
    /// BEFORE entering `seen_txs`, `peer_inventory`, or the relay path.
    #[tokio::test]
    async fn test_h_net_01_tx_gossip_invalid_tx_rejected_pre_relay() {
        let peer_manager = Arc::new(PeerManager::new(Default::default()));
        let gossip = TransactionGossip::new(peer_manager, Default::default());

        let mut bad = valid_tx(0xCA, TransactionType::Standard);
        bad.gas_price = 0; // Invalid: validator rejects gas_price == 0.

        let peer_id = PeerId::new("attacker_peer".to_string());
        let result = gossip.handle_new_transaction(&peer_id, bad.clone()).await;
        assert!(
            matches!(result, Ok(false)),
            "H-NET-01: invalid tx must return Ok(false), got {:?}",
            result
        );

        // Critically: the tx must NOT have been added to `seen_txs`.
        // Pre-fix, the dedup logic added it before validation.
        let seen = gossip.seen_txs.read().await;
        assert!(
            !seen.contains_key(&bad.hash),
            "H-NET-01: invalid tx must NOT be added to seen_txs"
        );
        drop(seen);

        // And NOT to the peer's inventory.
        let inventory = gossip.peer_inventory.read().await;
        assert!(
            inventory
                .get(&peer_id)
                .map(|s| !s.contains(&bad.hash))
                .unwrap_or(true),
            "H-NET-01: invalid tx must NOT be added to peer_inventory"
        );
    }

    /// Below-min-gas-price tx is rejected (catches the most common
    /// adversarial flood: cheap garbage tx).
    #[tokio::test]
    async fn test_h_net_01_below_min_gas_price_rejected() {
        let mut bad = valid_tx(0xCB, TransactionType::Standard);
        bad.gas_price = 1; // Below 1 Gwei minimum.
        const MAX: usize = 1024 * 1024;
        assert!(
            !TransactionGossip::validate_transaction_static(&bad, MAX),
            "H-NET-01: gas_price=1 must be rejected by validator"
        );
    }

    /// Above-max-data-size tx is rejected (catches the second common
    /// adversarial flood: huge-payload tx that exhausts memory).
    #[tokio::test]
    async fn test_h_net_01_oversize_data_rejected() {
        let mut bad = valid_tx(0xCC, TransactionType::Standard);
        bad.data = vec![0u8; 256 * 1024]; // 256 KiB > 128 KiB MAX_TX_DATA_SIZE.
        const MAX: usize = 1024 * 1024;
        assert!(
            !TransactionGossip::validate_transaction_static(&bad, MAX),
            "H-NET-01: data size > 128 KiB must be rejected"
        );
    }

    /// Positive: a valid tx passes the validator.
    #[tokio::test]
    async fn test_h_net_01_valid_tx_passes_validator() {
        let good = valid_tx(0xCD, TransactionType::Standard);
        const MAX: usize = 1024 * 1024;
        assert!(
            TransactionGossip::validate_transaction_static(&good, MAX),
            "H-NET-01: a valid tx must pass the validator"
        );
    }

    // ────────────────────────────────────────────────────────────────
    // CHAIN-B-NET-H4 — bounded transaction-gossip state.
    // ────────────────────────────────────────────────────────────────

    /// Build a valid standard tx with a caller-chosen 32-byte hash so a flood
    /// produces distinct dedup keys.
    fn valid_tx_with_hash(seed: u32) -> Transaction {
        let mut h = [0u8; 32];
        h[..4].copy_from_slice(&seed.to_le_bytes());
        let mut tx = valid_tx(0, TransactionType::Standard);
        tx.hash = Hash::new(h);
        tx
    }

    /// CHAIN-B-NET-H4 tripwire: one peer streaming unique valid txs must not
    /// grow its `peer_inventory` set without bound. Pre-fix the per-peer
    /// `HashSet<Hash>` was inserted into unconditionally → remote OOM. RED
    /// before the cap (set would reach 5_000); GREEN after (≤ cap).
    #[tokio::test]
    async fn peer_inventory_set_is_capped_under_single_peer_flood() {
        let peer_manager = Arc::new(PeerManager::new(Default::default()));
        let cfg = GossipConfig {
            max_peer_inventory: 100,
            max_tracked_peers: 8,
            max_pending_ai_txs: 16,
            ..Default::default()
        };
        let gossip = TransactionGossip::new(peer_manager, cfg);

        let peer = PeerId::new("flooder".to_string());
        for i in 0..5_000u32 {
            let _ = gossip
                .handle_new_transaction(&peer, valid_tx_with_hash(i))
                .await;
        }

        let inv = gossip.peer_inventory.read().await;
        let set_len = inv.get(&peer).map(|s| s.len()).unwrap_or(0);
        assert!(
            set_len <= 100,
            "per-peer inventory must stay within the cap; got {}",
            set_len
        );
    }

    /// CHAIN-B-NET-H4 tripwire: the outer peer map is bounded — a flood of
    /// distinct peer ids cannot grow `peer_inventory` past `max_tracked_peers`.
    #[tokio::test]
    async fn peer_inventory_map_is_capped_under_many_peers() {
        let peer_manager = Arc::new(PeerManager::new(Default::default()));
        let cfg = GossipConfig {
            max_peer_inventory: 100,
            max_tracked_peers: 8,
            max_pending_ai_txs: 16,
            ..Default::default()
        };
        let gossip = TransactionGossip::new(peer_manager, cfg);

        for i in 0..2_000u32 {
            let peer = PeerId::new(format!("peer-{i}"));
            let _ = gossip
                .handle_new_transaction(&peer, valid_tx_with_hash(i))
                .await;
        }

        let inv = gossip.peer_inventory.read().await;
        assert!(
            inv.len() <= 8,
            "tracked-peer count must stay within the cap; got {}",
            inv.len()
        );
    }

    /// CHAIN-B-NET-H4: `cleanup()` prunes `peer_inventory` entries for hashes
    /// that have aged out of `seen_txs`. Pre-fix `cleanup()` touched only
    /// `seen_txs`, so inventory kept dead hashes forever.
    #[tokio::test]
    async fn cleanup_prunes_stale_peer_inventory() {
        let peer_manager = Arc::new(PeerManager::new(Default::default()));
        // tx_ttl = 0 so every seen tx is immediately stale on cleanup.
        let cfg = GossipConfig {
            tx_ttl: Duration::from_secs(0),
            ..Default::default()
        };
        let gossip = TransactionGossip::new(peer_manager, cfg);

        let peer = PeerId::new("p".to_string());
        for i in 0..50u32 {
            let _ = gossip
                .handle_new_transaction(&peer, valid_tx_with_hash(i))
                .await;
        }
        assert!(!gossip.peer_inventory.read().await.is_empty());

        gossip.cleanup().await;

        assert!(
            gossip.seen_txs.read().await.is_empty(),
            "stale seen_txs must be swept"
        );
        assert!(
            gossip.peer_inventory.read().await.is_empty(),
            "peer_inventory must be pruned of hashes no longer in seen_txs"
        );
    }
}
