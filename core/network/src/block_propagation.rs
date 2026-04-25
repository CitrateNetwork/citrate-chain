// citrate/core/network/src/block_propagation.rs

// Block propagation handler for efficient block distribution
use crate::{NetworkMessage, PeerId, PeerManager};
use anyhow::Result;
use citrate_consensus::types::{Block, BlockHeader, Hash};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Block propagation handler for efficient block distribution
pub struct BlockPropagation {
    /// Peer manager for network operations
    peer_manager: Arc<PeerManager>,

    /// Track which blocks we've seen from which peers
    block_sources: Arc<RwLock<HashMap<Hash, HashSet<PeerId>>>>,

    /// Recent blocks we've broadcasted (to avoid re-broadcasting)
    /// RM-B1 / WP-C2.1 (audit H-NET-01): bounded recent-broadcast
    /// dedup. Pre-fix the underlying set was wiped wholesale at
    /// 1000 entries (`clear()`), letting the same hashes ping-pong
    /// after a wipe. Post-fix it's a `VecDeque` paired with a
    /// `HashSet` to evict oldest first.
    recent_broadcasts: Arc<RwLock<HashSet<Hash>>>,
    /// Insertion-order queue for `recent_broadcasts` LRU eviction.
    recent_broadcasts_order: Arc<RwLock<std::collections::VecDeque<Hash>>>,

    /// Blocks we're currently downloading
    downloading: Arc<RwLock<HashSet<Hash>>>,

    /// Block header cache
    header_cache: Arc<RwLock<HashMap<Hash, BlockHeader>>>,
}

impl BlockPropagation {
    pub fn new(peer_manager: Arc<PeerManager>) -> Self {
        Self {
            peer_manager,
            block_sources: Arc::new(RwLock::new(HashMap::new())),
            recent_broadcasts: Arc::new(RwLock::new(HashSet::new())),
            recent_broadcasts_order: Arc::new(RwLock::new(
                std::collections::VecDeque::with_capacity(1024),
            )),
            downloading: Arc::new(RwLock::new(HashSet::new())),
            header_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// RM-B1 / WP-C2.1 (audit H-NET-01): bounded LRU insert.
    /// Caller holds neither lock; this method takes both write
    /// locks for the duration. Pre-fix the dedup table was
    /// `HashSet::clear()`'d at 1000 entries, allowing replay.
    async fn track_recent_broadcast(&self, hash: Hash) {
        const MAX: usize = 1024;
        let mut set = self.recent_broadcasts.write().await;
        let mut order = self.recent_broadcasts_order.write().await;
        if set.insert(hash) {
            order.push_back(hash);
            // Evict oldest until under the cap.
            while order.len() > MAX {
                if let Some(old) = order.pop_front() {
                    set.remove(&old);
                }
            }
        }
    }

    /// Handle new block announcement.
    ///
    /// RM-B1 / WP-C2.1 (audit H-NET-01): pre-fix this method
    /// inserted the block into `header_cache` and re-broadcast it
    /// to every other peer BEFORE any consensus / signature check.
    /// One byzantine peer could saturate the network with garbage
    /// and force every peer to pay relay bandwidth + cache slots.
    /// Post-fix `block.verify_hash()` + `verify_block_signature`
    /// run BEFORE the cache insert + relay. Genesis is exempt
    /// (the genesis block carries the network identity, not a
    /// proposer signature).
    pub async fn handle_new_block(&self, peer_id: &PeerId, block: Block) -> Result<()> {
        let block_hash = block.header.block_hash;

        // Check if we've already seen this block
        let mut sources = self.block_sources.write().await;
        let peers = sources.entry(block_hash).or_insert_with(HashSet::new);

        if peers.contains(peer_id) {
            debug!(
                "Already received block {} from peer {}",
                block_hash, peer_id
            );
            return Ok(());
        }

        peers.insert(peer_id.clone());
        drop(sources);

        // H-NET-01 fix: validate-then-relay. Hash mismatch = peer
        // sent garbage; reject + don't relay.
        if !block.verify_hash() {
            warn!(
                "H-NET-01: rejecting block {} from peer {} — hash mismatch",
                block_hash, peer_id
            );
            return Err(anyhow::anyhow!(
                "H-NET-01: block hash verification failed"
            ));
        }

        // Signature verification (skip genesis).
        if !block.is_genesis() {
            match citrate_consensus::crypto::verify_block_signature(&block) {
                Ok(true) => {}
                Ok(false) => {
                    warn!(
                        "H-NET-01: rejecting block {} from peer {} — signature invalid",
                        block_hash, peer_id
                    );
                    return Err(anyhow::anyhow!(
                        "H-NET-01: block signature verification failed"
                    ));
                }
                Err(e) => {
                    warn!(
                        "H-NET-01: rejecting block {} from peer {} — signature error: {}",
                        block_hash, peer_id, e
                    );
                    return Err(anyhow::anyhow!(
                        "H-NET-01: block signature error: {}",
                        e
                    ));
                }
            }
        }

        info!("Received new block {} from peer {}", block_hash, peer_id);

        // Cache the header (only after validation).
        self.header_cache
            .write()
            .await
            .insert(block_hash, block.header.clone());

        // Propagate to other peers (but not back to sender)
        self.broadcast_block_except(block, peer_id).await?;

        Ok(())
    }

    /// Broadcast a new block to all peers
    pub async fn broadcast_block(&self, block: Block) -> Result<()> {
        let block_hash = block.header.block_hash;

        // RM-B1 / WP-C2.1 (audit H-NET-01): dedup via bounded LRU
        // instead of `HashSet::clear()` at 1000 entries.
        {
            let recent = self.recent_broadcasts.read().await;
            if recent.contains(&block_hash) {
                debug!("Block {} was recently broadcasted, skipping", block_hash);
                return Ok(());
            }
        }
        self.track_recent_broadcast(block_hash).await;

        // Broadcast to all peers
        let message = NetworkMessage::NewBlock { block };
        self.peer_manager.broadcast(&message).await?;

        info!("Broadcasted block {} to all peers", block_hash);
        Ok(())
    }

    /// Broadcast block to all peers except the specified one
    async fn broadcast_block_except(&self, block: Block, except_peer: &PeerId) -> Result<()> {
        let block_hash = block.header.block_hash;

        // H-NET-01 fix: track via bounded LRU.
        self.track_recent_broadcast(block_hash).await;

        // Get all peers except the sender
        let all_peers = self.peer_manager.get_all_peers();
        let mut target_peers: Vec<PeerId> = Vec::with_capacity(all_peers.len());

        for peer in all_peers.iter() {
            let peer_id = peer.info.read().await.id.clone();
            if peer_id != *except_peer {
                target_peers.push(peer_id);
            }
        }

        if !target_peers.is_empty() {
            let message = NetworkMessage::NewBlock { block };
            self.peer_manager
                .send_to_peers(&target_peers, &message)
                .await?;

            debug!(
                "Propagated block {} to {} peers",
                block_hash,
                target_peers.len()
            );
        }

        Ok(())
    }

    /// Request specific blocks from peers
    pub async fn request_blocks(&self, from: Hash, count: u32) -> Result<()> {
        // Mark blocks as being downloaded
        self.downloading.write().await.insert(from);

        let message = NetworkMessage::GetBlocks {
            from,
            count,
            step: 1,
        };

        // Request from all peers (could optimize to select best peers)
        self.peer_manager.broadcast(&message).await?;

        info!("Requested {} blocks starting from {}", count, from);
        Ok(())
    }

    /// Handle received blocks response
    pub async fn handle_blocks_response(&self, peer_id: &PeerId, blocks: Vec<Block>) -> Result<()> {
        if blocks.is_empty() {
            return Ok(());
        }

        info!("Received {} blocks from peer {}", blocks.len(), peer_id);

        // Remove from downloading set
        for block in &blocks {
            self.downloading
                .write()
                .await
                .remove(&block.header.block_hash);

            // Cache headers
            self.header_cache
                .write()
                .await
                .insert(block.header.block_hash, block.header.clone());
        }

        // Track sources
        let mut sources = self.block_sources.write().await;
        for block in &blocks {
            sources
                .entry(block.header.block_hash)
                .or_insert_with(HashSet::new)
                .insert(peer_id.clone());
        }

        Ok(())
    }

    /// Request block headers
    pub async fn request_headers(&self, from: Hash, count: u32) -> Result<()> {
        let message = NetworkMessage::GetHeaders { from, count };
        self.peer_manager.broadcast(&message).await?;

        info!("Requested {} headers starting from {}", count, from);
        Ok(())
    }

    /// Handle received headers
    pub async fn handle_headers_response(
        &self,
        peer_id: &PeerId,
        headers: Vec<BlockHeader>,
    ) -> Result<()> {
        if headers.is_empty() {
            return Ok(());
        }

        info!("Received {} headers from peer {}", headers.len(), peer_id);

        // Cache headers
        let mut cache = self.header_cache.write().await;
        for header in headers {
            cache.insert(header.block_hash, header);
        }

        Ok(())
    }

    /// Get cached header
    pub async fn get_cached_header(&self, hash: &Hash) -> Option<BlockHeader> {
        self.header_cache.read().await.get(hash).cloned()
    }

    /// Clean up old data.
    ///
    /// RM-B1 / WP-C2.1 (audit H-NET-01): the recent_broadcasts
    /// LRU is already self-trimming in `track_recent_broadcast`,
    /// so this method only needs to handle the header cache.
    pub async fn cleanup(&self) {

        // Clean up header cache
        let mut cache = self.header_cache.write().await;
        if cache.len() > 50000 {
            // Keep only recent headers (would need timestamp tracking in production)
            let to_remove = cache.len() / 2;
            let keys: Vec<Hash> = cache.keys().take(to_remove).cloned().collect();
            for key in keys {
                cache.remove(&key);
            }
        }

        debug!("Cleaned up block propagation caches");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_consensus::types::BlockBuilder;

    #[tokio::test]
    async fn test_block_propagation() {
        let peer_manager = Arc::new(PeerManager::new(Default::default()));
        let propagation = BlockPropagation::new(peer_manager);

        // RM-B1 / WP-C2.1 (H-NET-01): handle_new_block now
        // requires `block.verify_hash()` AND signature verification
        // for non-genesis. Use a true-genesis shape (default parent
        // + no merge parents + height 0) so the signature check is
        // skipped, and `.build()` to compute a canonical hash.
        let block = BlockBuilder::new()
            .timestamp(12345)
            .height(0) // genesis: signature check skipped
            .blue_score(0)
            .blue_work(1000)
            .state_root(Hash::new([3; 32]))
            .tx_root(Hash::new([4; 32]))
            .receipt_root(Hash::new([5; 32]))
            .artifact_root(Hash::new([6; 32]))
            .build();

        // Test broadcasting
        assert!(propagation.broadcast_block(block.clone()).await.is_ok());

        // Should skip re-broadcasting
        assert!(propagation.broadcast_block(block.clone()).await.is_ok());

        // Test header caching — handle_new_block now validates
        // hash + signature first.
        let peer_id = PeerId::new("test_peer".to_string());
        assert!(propagation
            .handle_new_block(&peer_id, block.clone())
            .await
            .is_ok());

        let cached = propagation
            .get_cached_header(&block.header.block_hash)
            .await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().block_hash, block.header.block_hash);
    }

    /// H-NET-01.1: a block with a wrong-hash header is rejected at
    /// `handle_new_block` and NOT inserted into the header cache,
    /// NOT relayed.
    #[tokio::test]
    async fn h_net_01_garbage_block_not_relayed() {
        let peer_manager = Arc::new(PeerManager::new(Default::default()));
        let propagation = BlockPropagation::new(peer_manager);

        // Build with explicit (wrong) hash — verify_hash fails.
        let block = BlockBuilder::new()
            .hash(Hash::new([0xFF; 32])) // hash that doesn't match the header content
            .parent(Hash::new([0x02; 32]))
            .height(100)
            .blue_score(50)
            .blue_work(1000)
            .build_unhashed();

        let peer_id = PeerId::new("byzantine_peer".to_string());
        let result = propagation.handle_new_block(&peer_id, block.clone()).await;
        assert!(
            result.is_err(),
            "H-NET-01: block with wrong hash MUST be rejected"
        );

        // Header cache must NOT contain the rejected block.
        let cached = propagation
            .get_cached_header(&block.header.block_hash)
            .await;
        assert!(
            cached.is_none(),
            "H-NET-01: rejected block must NOT enter header cache"
        );
    }
}
