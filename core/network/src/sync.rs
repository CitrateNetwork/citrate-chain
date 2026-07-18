// citrate/core/network/src/sync.rs

// Synchronization manager for block and header downloads
use crate::{
    peer::{Peer, PeerId},
    NetworkError, NetworkMessage,
};
use citrate_consensus::crypto;
use citrate_consensus::types::{Block, BlockHeader, Hash};
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Synchronization state
#[derive(Debug, Clone, PartialEq)]
pub enum SyncState {
    /// Not syncing
    Idle,

    /// Downloading headers
    DownloadingHeaders {
        from: Hash,
        target_height: u64,
        progress: f32,
    },

    /// Downloading blocks
    DownloadingBlocks {
        from_height: u64,
        to_height: u64,
        progress: f32,
    },

    /// Verifying downloaded data
    Verifying {
        blocks_verified: u64,
        total_blocks: u64,
    },

    /// Synchronized with network
    Synced,
}

/// Block download request
#[derive(Debug)]
#[allow(dead_code)]
struct BlockRequest {
    hash: Hash,
    peer_id: PeerId,
    requested_at: Instant,
    retries: u32,
}

/// Synchronization manager
pub struct SyncManager {
    config: SyncConfig,
    state: Arc<RwLock<SyncState>>,

    // Current sync progress
    current_height: Arc<RwLock<u64>>,
    target_height: Arc<RwLock<u64>>,

    // Download queue
    header_queue: Arc<RwLock<VecDeque<Hash>>>,
    block_queue: Arc<RwLock<VecDeque<Hash>>>,

    // Pending requests
    pending_headers: Arc<RwLock<HashMap<Hash, BlockRequest>>>,
    pending_blocks: Arc<RwLock<HashMap<Hash, BlockRequest>>>,

    // Downloaded but not yet processed
    downloaded_headers: Arc<RwLock<Vec<BlockHeader>>>,
    downloaded_blocks: Arc<RwLock<Vec<Block>>>,
    last_header_hash: Arc<RwLock<Option<Hash>>>,
    last_requested_header: Arc<RwLock<Option<Hash>>>,
}

#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Maximum concurrent block downloads
    pub max_concurrent_downloads: usize,

    /// Block request timeout
    pub request_timeout: Duration,

    /// Maximum retries for a block
    pub max_retries: u32,

    /// Batch size for header downloads
    pub header_batch_size: u32,

    /// Batch size for block downloads  
    pub block_batch_size: u32,

    /// Sync interval
    pub sync_interval: Duration,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            max_concurrent_downloads: 16,
            request_timeout: Duration::from_secs(30),
            max_retries: 3,
            header_batch_size: 2000,
            block_batch_size: 128,
            sync_interval: Duration::from_secs(1),
        }
    }
}

impl SyncManager {
    pub fn new(config: SyncConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(SyncState::Idle)),
            current_height: Arc::new(RwLock::new(0)),
            target_height: Arc::new(RwLock::new(0)),
            header_queue: Arc::new(RwLock::new(VecDeque::new())),
            block_queue: Arc::new(RwLock::new(VecDeque::new())),
            pending_headers: Arc::new(RwLock::new(HashMap::new())),
            pending_blocks: Arc::new(RwLock::new(HashMap::new())),
            downloaded_headers: Arc::new(RwLock::new(Vec::new())),
            downloaded_blocks: Arc::new(RwLock::new(Vec::new())),
            last_header_hash: Arc::new(RwLock::new(None)),
            last_requested_header: Arc::new(RwLock::new(None)),
        }
    }

    /// Get current sync state
    pub async fn get_state(&self) -> SyncState {
        self.state.read().await.clone()
    }

    /// Check if synced
    pub async fn is_synced(&self) -> bool {
        matches!(*self.state.read().await, SyncState::Synced)
    }

    /// Start synchronization
    pub async fn start_sync(&self, peer_height: u64, peer_hash: Hash) -> Result<(), NetworkError> {
        let current = *self.current_height.read().await;

        if peer_height <= current {
            *self.state.write().await = SyncState::Synced;
            return Ok(());
        }

        *self.target_height.write().await = peer_height;

        // Start with header download
        *self.state.write().await = SyncState::DownloadingHeaders {
            from: peer_hash,
            target_height: peer_height,
            progress: 0.0,
        };

        info!("Starting sync from height {} to {}", current, peer_height);

        // Queue initial header requests
        self.queue_header_downloads(peer_hash, peer_height - current)
            .await;

        Ok(())
    }

    /// Queue header downloads
    async fn queue_header_downloads(&self, from: Hash, count: u64) {
        let mut queue = self.header_queue.write().await;

        // Add to queue in batches
        let batches = count.div_ceil(self.config.header_batch_size as u64);

        for _ in 0..batches.min(10) {
            queue.push_back(from);
        }
    }

    /// Process header download request
    pub async fn request_headers(&self, peer: &Peer, from: Hash) -> Result<(), NetworkError> {
        let peer_id = peer.info.read().await.id.clone();

        // Check if already pending
        if self.pending_headers.read().await.contains_key(&from) {
            return Ok(());
        }

        // Respect concurrency: don't exceed max pending
        if self.pending_headers.read().await.len() >= self.config.max_concurrent_downloads {
            return Ok(());
        }

        // Send request
        peer.send(NetworkMessage::GetHeaders {
            from,
            count: self.config.header_batch_size,
        })
        .await?;

        // Track request
        self.pending_headers.write().await.insert(
            from,
            BlockRequest {
                hash: from,
                peer_id,
                requested_at: Instant::now(),
                retries: 0,
            },
        );

        // Update last requested header
        *self.last_requested_header.write().await = Some(from);

        Ok(())
    }

    /// Process block download request
    pub async fn request_blocks(&self, peer: &Peer, from: Hash) -> Result<(), NetworkError> {
        let peer_id = peer.info.read().await.id.clone();

        // Check if already pending
        if self.pending_blocks.read().await.contains_key(&from) {
            return Ok(());
        }

        if self.pending_blocks.read().await.len() >= self.config.max_concurrent_downloads {
            return Ok(());
        }

        // Send request
        peer.send(NetworkMessage::GetBlocks {
            from,
            count: self.config.block_batch_size,
            step: 1,
        })
        .await?;

        // Track request
        self.pending_blocks.write().await.insert(
            from,
            BlockRequest {
                hash: from,
                peer_id,
                requested_at: Instant::now(),
                retries: 0,
            },
        );

        Ok(())
    }

    /// Handle received headers
    ///
    /// WP-H.4: Headers are validated for height monotonicity before storage.
    pub async fn handle_headers(&self, headers: Vec<BlockHeader>) -> Result<(), NetworkError> {
        if headers.is_empty() {
            return Ok(());
        }

        // Validate header height monotonicity
        for window in headers.windows(2) {
            if window[1].height <= window[0].height {
                warn!(
                    "SYNC_REJECT: non-monotonic header heights ({} -> {})",
                    window[0].height, window[1].height
                );
                return Err(NetworkError::ProtocolError(
                    "non-monotonic header heights in sync response".into(),
                ));
            }
        }

        let count = headers.len();
        // Safety: non-empty guaranteed by early return above
        let (first, last) = match (headers.first(), headers.last()) {
            (Some(f), Some(l)) => (f, l),
            _ => return Ok(()),
        };
        let first_height = first.height;
        let last_height = last.height;
        let first_hash = first.block_hash;
        let last_hash = last.block_hash;
        // Retire the in-flight request this batch answers. The request anchor
        // (`from`) is the selected-parent of the first served header — the
        // server resolves `from` to the block at anchor.height+1, whose
        // selected-parent IS `from` (genesis's is the all-zero sentinel, which
        // is also the genesis-request anchor). Without this, pending_headers
        // never drains, so `check_timeouts` eventually (falsely) flags the
        // responding peer — the bug that let a bootnode ban its only block
        // source and split-brain the fleet.
        let answered_anchor = first.selected_parent_hash;
        self.pending_headers.write().await.remove(&answered_anchor);

        // Store validated headers
        self.downloaded_headers.write().await.extend(headers);

        // Update progress
        let current = *self.current_height.read().await;
        let target = *self.target_height.read().await;
        // Guard against u64 underflow: a peer on a shorter/sibling branch can
        // answer with `target`/`last_height` at or below `current` (e.g. during
        // a fork or reorg). With release `overflow-checks = true` a bare
        // subtraction panics the sync worker thread (previously observed here as
        // "attempt to subtract with overflow"). Saturate, and guard the
        // denominator so an at-tip peer reports 100% rather than dividing by 0.
        let span = target.saturating_sub(current);
        let done = last_height.saturating_sub(current);
        let progress = if span == 0 {
            100.0
        } else {
            (done as f32 / span as f32) * 100.0
        };

        *self.state.write().await = SyncState::DownloadingHeaders {
            from: first_hash,
            target_height: target,
            progress,
        };

        info!(
            "Downloaded {} headers (height {}-{}), progress: {:.1}%",
            count, first_height, last_height, progress
        );

        // Update last header hash
        *self.last_header_hash.write().await = Some(last_hash);

        // Transition to block download if headers complete
        if last_height >= target {
            self.start_block_download().await?;
        }

        Ok(())
    }

    /// Handle received blocks with full validation before import.
    ///
    /// WP-H.4: The old implementation stored blocks in memory without any
    /// validation and marked Synced based on height alone. An attacker could
    /// feed garbage blocks to a syncing node, making it believe it was synced
    /// while holding no valid chain data. Now each block is validated:
    ///
    /// 1. Hash integrity (covers header + commitment roots)
    /// 2. Signature verification (proposer key bound to block hash)
    /// 3. tx_root consistency (recomputed from transactions)
    ///
    /// Only validated blocks are stored and count toward progress.
    pub async fn handle_blocks(&self, blocks: Vec<Block>) -> Result<(), NetworkError> {
        if blocks.is_empty() {
            return Ok(());
        }

        let total = blocks.len();
        // Safety: non-empty guaranteed by early return above
        let first_height = match blocks.first() {
            Some(b) => b.header.height,
            None => return Ok(()),
        };
        // Retire the in-flight block request this batch answers, keyed by the
        // first block's selected-parent (== the `from` anchor we requested).
        // The peer responded, so the request is no longer pending regardless of
        // per-block validation below; leaving it pending would falsely time the
        // peer out. See the matching note in `handle_headers`.
        if let Some(first) = blocks.first() {
            let answered_anchor = first.header.selected_parent_hash;
            self.pending_blocks.write().await.remove(&answered_anchor);
        }
        let mut validated = Vec::with_capacity(total);
        let mut rejected = 0usize;

        for block in blocks {
            // 1. Verify canonical hash integrity
            if !block.verify_hash() {
                warn!(
                    "SYNC_REJECT: block height={} hash mismatch (tampered commitment roots)",
                    block.header.height
                );
                rejected += 1;
                continue;
            }

            // 2. Verify block signature
            match crypto::verify_block_signature(&block) {
                Ok(true) => {}
                Ok(false) => {
                    warn!(
                        "SYNC_REJECT: block height={} invalid signature",
                        block.header.height
                    );
                    rejected += 1;
                    continue;
                }
                Err(e) => {
                    warn!(
                        "SYNC_REJECT: block height={} signature error: {}",
                        block.header.height, e
                    );
                    rejected += 1;
                    continue;
                }
            }

            // 3. Verify tx_root consistency
            let computed_tx_root = {
                let mut hasher = Sha3_256::new();
                for tx in &block.transactions {
                    hasher.update(tx.hash.as_bytes());
                }
                let bytes = hasher.finalize();
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes[..32]);
                Hash::new(arr)
            };
            if block.tx_root != computed_tx_root {
                warn!(
                    "SYNC_REJECT: block height={} tx_root mismatch",
                    block.header.height
                );
                rejected += 1;
                continue;
            }

            validated.push(block);
        }

        if rejected > 0 {
            warn!(
                "Sync validation: {}/{} blocks rejected",
                rejected, total
            );
        }

        if validated.is_empty() {
            return Ok(());
        }

        let last_height = match validated.last() {
            Some(b) => b.header.height,
            None => return Ok(()),
        };
        let accepted = validated.len();

        // Store only validated blocks
        self.downloaded_blocks.write().await.extend(validated);

        // Update progress
        let current = *self.current_height.read().await;
        let target = *self.target_height.read().await;
        let progress = if target > current {
            ((last_height - current) as f32 / (target - current) as f32) * 100.0
        } else {
            100.0
        };

        *self.state.write().await = SyncState::DownloadingBlocks {
            from_height: current,
            to_height: target,
            progress,
        };

        // Only advance height based on validated blocks
        *self.current_height.write().await = last_height;

        info!(
            "Validated and imported {}/{} blocks (height {}-{}), progress: {:.1}%",
            accepted, total, first_height, last_height, progress
        );

        // Check if sync complete
        if last_height >= target {
            *self.state.write().await = SyncState::Synced;
            info!("Synchronization complete at height {}", last_height);
        }

        Ok(())
    }

    /// Start block download phase
    // LOCK ORDERING: acquires current_height, target_height, state sequentially (dropped between),
    // then holds downloaded_headers (read) + block_queue (write) simultaneously — Level 2.
    // Safe: no reverse ordering (block_queue -> downloaded_headers) exists anywhere.
    async fn start_block_download(&self) -> Result<(), NetworkError> {
        let current = *self.current_height.read().await;
        let target = *self.target_height.read().await;

        *self.state.write().await = SyncState::DownloadingBlocks {
            from_height: current,
            to_height: target,
            progress: 0.0,
        };

        info!(
            "Starting block download from height {} to {}",
            current, target
        );

        // Queue block downloads based on headers
        let headers = self.downloaded_headers.read().await;
        let mut block_queue = self.block_queue.write().await;

        // Queue blocks from downloaded headers
        for header in headers.iter().take(self.config.max_concurrent_downloads) {
            block_queue.push_back(header.block_hash);
        }

        debug!("Queued {} blocks for download", block_queue.len());

        Ok(())
    }

    /// Check for timed out requests
    pub async fn check_timeouts(&self) -> Vec<(Hash, PeerId)> {
        let mut timed_out: Vec<(Hash, PeerId)> = Vec::new();
        let now = Instant::now();

        // Check header requests
        {
            let mut to_remove: Vec<Hash> = Vec::new();
            let pending = self.pending_headers.read().await;
            for (hash, request) in pending.iter() {
                if now.duration_since(request.requested_at) > self.config.request_timeout {
                    timed_out.push((*hash, request.peer_id.clone()));
                    to_remove.push(*hash);
                }
            }
            drop(pending);
            if !to_remove.is_empty() {
                let mut pending = self.pending_headers.write().await;
                for h in to_remove {
                    pending.remove(&h);
                }
            }
        }

        // Check block requests
        {
            let mut to_remove: Vec<Hash> = Vec::new();
            let pending = self.pending_blocks.read().await;
            for (hash, request) in pending.iter() {
                if now.duration_since(request.requested_at) > self.config.request_timeout {
                    timed_out.push((*hash, request.peer_id.clone()));
                    to_remove.push(*hash);
                }
            }
            drop(pending);
            if !to_remove.is_empty() {
                let mut pending = self.pending_blocks.write().await;
                for h in to_remove {
                    pending.remove(&h);
                }
            }
        }

        if !timed_out.is_empty() {
            warn!("Sync requests timed out: {} items", timed_out.len());
        }

        timed_out
    }

    /// Get sync progress
    pub async fn get_progress(&self) -> (u64, u64, f32) {
        let current = *self.current_height.read().await;
        let target = *self.target_height.read().await;

        let progress = if target > current {
            ((current as f32 / target as f32) * 100.0).min(100.0)
        } else {
            100.0
        };

        (current, target, progress)
    }

    /// Last received header hash (if any)
    pub async fn last_received_header(&self) -> Option<Hash> {
        *self.last_header_hash.read().await
    }

    /// Last requested header hash (if any)
    pub async fn last_requested_header(&self) -> Option<Hash> {
        *self.last_requested_header.read().await
    }

    /// Current pending counts (headers, blocks)
    pub async fn pending_counts(&self) -> (usize, usize) {
        (self.pending_headers.read().await.len(), self.pending_blocks.read().await.len())
    }

    /// Drain all validated blocks that have been downloaded and verified.
    ///
    /// WP-H.5: The sync manager validates blocks on receipt (WP-H.4) but
    /// stores them in memory. The node must periodically drain these and
    /// persist them to the chain store / DAG. This method returns all
    /// validated blocks and clears the internal buffer.
    pub async fn drain_validated_blocks(&self) -> Vec<Block> {
        let mut blocks = self.downloaded_blocks.write().await;
        std::mem::take(&mut *blocks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sync_state_transitions() {
        let sync = SyncManager::new(SyncConfig::default());

        // Initially idle
        assert_eq!(sync.get_state().await, SyncState::Idle);

        // Start sync
        sync.start_sync(100, Hash::default()).await.unwrap();

        // Should be downloading headers
        match sync.get_state().await {
            SyncState::DownloadingHeaders { target_height, .. } => {
                assert_eq!(target_height, 100);
            }
            _ => panic!("Expected DownloadingHeaders state"),
        }
    }

    #[tokio::test]
    async fn test_sync_progress() {
        let sync = SyncManager::new(SyncConfig::default());

        *sync.current_height.write().await = 50;
        *sync.target_height.write().await = 100;

        let (current, target, progress) = sync.get_progress().await;

        assert_eq!(current, 50);
        assert_eq!(target, 100);
        assert_eq!(progress, 50.0);
    }

    /// Liveness regression: a completed headers response must RETIRE its
    /// pending request, keyed by the served batch's selected-parent (== the
    /// `from` anchor). Pre-fix the entry was never removed, so `check_timeouts`
    /// later flagged the responding peer as dead — the chain of events that let
    /// a bootnode permanently ban its only block source and split-brain the
    /// fleet. The anchor must be GONE from `pending_headers` after handling.
    #[tokio::test]
    async fn handle_headers_retires_pending_request() {
        use crate::PeerId;
        use citrate_consensus::types::{BlockBuilder, PublicKey};

        let sync = SyncManager::new(SyncConfig::default());
        *sync.current_height.write().await = 0;
        *sync.target_height.write().await = 100;

        // The request we sent: GetHeaders { from: anchor }.
        let anchor = Hash::new([9u8; 32]);
        sync.pending_headers.write().await.insert(
            anchor,
            BlockRequest {
                hash: anchor,
                peer_id: PeerId("peer-a".to_string()),
                requested_at: Instant::now(),
                retries: 0,
            },
        );
        assert!(sync.pending_headers.read().await.contains_key(&anchor));

        // The peer answers: the first served header's selected-parent IS the
        // anchor (server resolves `from` to anchor.height+1).
        let served = BlockBuilder::new()
            .parent(anchor)
            .height(5)
            .proposer(PublicKey::new([1; 32]))
            .build_unhashed();
        sync.handle_headers(vec![served.header])
            .await
            .expect("handle_headers");

        assert!(
            !sync.pending_headers.read().await.contains_key(&anchor),
            "pending headers request must be retired once answered"
        );
    }

    /// Same liveness guarantee for blocks. The pending entry is retired the
    /// moment the peer responds — before per-block validation — so even a batch
    /// that fails validation can never falsely time the peer out.
    #[tokio::test]
    async fn handle_blocks_retires_pending_request() {
        use crate::PeerId;
        use citrate_consensus::types::{BlockBuilder, PublicKey};

        let sync = SyncManager::new(SyncConfig::default());
        *sync.current_height.write().await = 0;
        *sync.target_height.write().await = 100;

        let anchor = Hash::new([4u8; 32]);
        sync.pending_blocks.write().await.insert(
            anchor,
            BlockRequest {
                hash: anchor,
                peer_id: PeerId("peer-b".to_string()),
                requested_at: Instant::now(),
                retries: 0,
            },
        );
        assert!(sync.pending_blocks.read().await.contains_key(&anchor));

        // Unsigned block — fails validation, but the request is still retired.
        let served = BlockBuilder::new()
            .parent(anchor)
            .height(1)
            .proposer(PublicKey::new([1; 32]))
            .build_unhashed();
        let _ = sync.handle_blocks(vec![served]).await;

        assert!(
            !sync.pending_blocks.read().await.contains_key(&anchor),
            "pending blocks request must be retired once the peer responds"
        );
    }
}
