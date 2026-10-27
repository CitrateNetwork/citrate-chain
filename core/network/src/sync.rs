// citrate/core/network/src/sync.rs

// Synchronization manager for block and header downloads
use crate::{
    peer::{Peer, PeerId},
    sync_ranges::{
        BlockLink, BlocksMatch, PeerSlot, Plan, RangeConfig, RangeCounters, RangeScheduler,
    },
    NetworkError, NetworkMessage,
};
use citrate_consensus::crypto;
use citrate_consensus::types::{Block, BlockHeader, Hash};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
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

    /// Catch-up block ranges and header anchors: what is in flight, to whom,
    /// and what still needs asking. See `sync_ranges.rs`. Replaces the old
    /// anchor-at-the-applied-tip requests and the retained header buffer
    /// (`downloaded_headers`, bounded at 64 MiB and otherwise unused).
    ranges: Arc<std::sync::Mutex<RangeScheduler>>,

    /// Ancestry-recovery block requests (SYNC-S3), keyed by anchor. Forward
    /// catch-up does not use this map; it goes through `ranges`.
    pending_blocks: Arc<RwLock<HashMap<Hash, BlockRequest>>>,

    // Validated, not yet drained into admission.
    downloaded_blocks: Arc<RwLock<Vec<Block>>>,
    last_header_hash: Arc<RwLock<Option<Hash>>>,

    /// This node's OWN applied chain height, when wired via
    /// [`SyncManager::with_local_height`].
    ///
    /// Without it the manager can only see the height of the last block it was
    /// HANDED, which is not evidence that the node holds that block's ancestry.
    /// See [`SyncManager::sync_is_complete`].
    local_height: Option<Arc<AtomicU64>>,

    /// Height of the anchor carried by the most recent `GetBlocks` we sent.
    ///
    /// #156: needed to tell "the peer had nothing for us" (its fault, Barren)
    /// from "our applied tip passed the anchor before the answer came back"
    /// (our fault, Redundant). Those are identical in response content and
    /// opposite in what they should do to the peer's standing — see
    /// `sync_peer::classify_serve`.
    last_block_anchor_height: Arc<AtomicU64>,

    /// PBA-R2 block-validity hardening: selects the `tx_root` rule by height
    /// (PBA-L1b-002). Captured from the process-wide activation at
    /// construction; see `citrate_consensus::hardening`.
    pba_hardening: citrate_consensus::hardening::PbaHardening,
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
            // Small batches so a sync RESPONSE stays close to gossip frame size.
            // Cross-region (nyc1↔fra1) the large 128-block / 2000-header responses
            // were lost on the wire (rpc-1 served in 4ms but the follower never
            // received them and timed out), while single-block gossip frames
            // delivered fine. Keeping responses tiny lets a lagging node catch a
            // gap over the same path that already carries gossip. Concurrency
            // (16 in-flight) preserves throughput despite the small per-batch size.
            header_batch_size: 64,
            // Blocks per GetBlocks request. Kept modest: large responses over a
            // cross-region link break the connection (observed: a batch of 128 to
            // a producer over the WAN → "Broken pipe", zero blocks synced). 32 is
            // a safe step up from the old 8 for throughput without over-large
            // responses; deep catch-up throughput comes from the resilient
            // multi-peer + correct-target driver, not from oversized batches.
            block_batch_size: 32,
            sync_interval: Duration::from_secs(1),
        }
    }
}

impl SyncManager {
    pub fn new(config: SyncConfig) -> Self {
        let range_len = u64::from(config.block_batch_size);
        Self {
            config,
            state: Arc::new(RwLock::new(SyncState::Idle)),
            current_height: Arc::new(RwLock::new(0)),
            target_height: Arc::new(RwLock::new(0)),
            ranges: Arc::new(std::sync::Mutex::new(RangeScheduler::new(RangeConfig {
                range_len,
                ..RangeConfig::default()
            }))),
            pending_blocks: Arc::new(RwLock::new(HashMap::new())),
            last_block_anchor_height: Arc::new(AtomicU64::new(0)),
            downloaded_blocks: Arc::new(RwLock::new(Vec::new())),
            last_header_hash: Arc::new(RwLock::new(None)),
            local_height: None,
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

    /// Wire this node's own applied-chain height so sync completion is judged
    /// against what the node actually HOLDS, not what it was last handed.
    pub fn with_local_height(mut self, handle: Arc<AtomicU64>) -> Self {
        self.local_height = Some(handle);
        self
    }

    /// This node's applied height, when the handle is wired.
    fn applied_height(&self) -> Option<u64> {
        self.local_height
            .as_ref()
            .map(|h| h.load(Ordering::Relaxed))
    }

    /// Is the node genuinely synced to `target`?
    ///
    /// **Wedge #85.** The height of the last block RECEIVED is not evidence of
    /// having synced to it. A node sitting at applied height 54,600 receives the
    /// live tip at 56,128 by gossip; pre-fix this set `current_height = 56_128`
    /// and, since `56_128 >= target`, declared "Synchronization complete" — so
    /// the node stopped requesting the 54,601..56,127 backlog it was missing.
    /// Those tip blocks were then dropped by admission (their parents were
    /// absent) and never persisted, so `drive_drain` had nothing to walk either.
    /// The node reported itself synced, served "Sending 0 blocks" to peers, and
    /// its applied tip never moved again.
    ///
    /// Completion is therefore judged against the node's OWN applied height when
    /// that is known. Falls back to the old behaviour when unwired, so a
    /// `SyncManager` without the handle is unchanged.
    pub(crate) fn sync_is_complete(local: Option<u64>, last_seen: u64, target: u64) -> bool {
        match local {
            Some(applied) => applied >= target,
            None => last_seen >= target,
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

        // Raise the target to the HIGHEST head any peer has advertised — never
        // lower it. Each connected peer's Hello/HelloAck drives one start_sync
        // with THAT peer's advertised applied tip. A peer wedged (or genuinely
        // lagging) at a low applied tip advertises a low head; if we let its
        // Hello overwrite `target_height`, the target collapses from the real
        // producer head (~73k) to that low value, `handle_blocks` then sees
        // `last_height >= target` and declares "Synchronization complete" at the
        // low height, and the drain stops — the fresh-node wedge-at-7 bug
        // (handoffs/NODE_FRESH_SYNC_WEDGE_2026-07-19.md). On a peer-to-peer
        // fleet this is self-reinforcing: nodes wedged at N advertise N to each
        // other and cap each other's targets. Taking the max keeps the target at
        // the best-known head so the drain continues to the real tip, and lets a
        // wedged node recover the moment any peer advertises a higher head.
        let target = (*self.target_height.read().await).max(peer_height);

        if target <= current {
            *self.state.write().await = SyncState::Synced;
            return Ok(());
        }

        *self.target_height.write().await = target;

        // Start with header download
        *self.state.write().await = SyncState::DownloadingHeaders {
            from: peer_hash,
            target_height: target,
            progress: 0.0,
        };

        info!("Starting sync from height {} to {}", current, target);
        // Requests are planned by the sync tick (`plan_ranges`).
        Ok(())
    }

    /// Raise the sync target to at least `height` (never lowers it), WITHOUT the
    /// side effects of `start_sync`.
    ///
    /// The 2s driver loop calls this every tick from the best peer's advertised
    /// head. `start_sync` cannot be used there: it resets the state to
    /// `DownloadingHeaders` and re-queues header downloads on every call, so
    /// driving it each tick leaves the node perpetually "starting" and it never
    /// settles into block download (observed: 0 blocks imported while `start_sync`
    /// fired 60+ times). The 2s loop already issues `request_headers` /
    /// `request_blocks` anchored on the applied tip, so all this needs to do is
    /// keep `target_height` at the real head — otherwise `handle_blocks` sees
    /// `last_height >= target` (target 0) and declares "Synchronization complete"
    /// after every batch, wedging a fresh node a few blocks in.
    pub async fn set_target(&self, height: u64) {
        let mut t = self.target_height.write().await;
        if height > *t {
            *t = height;
        }
    }

    /// Plan the next catch-up requests (see `sync_ranges.rs`). `peers` is in
    /// preference order. The caller sends what comes back, reports any send
    /// failure with [`Self::release_peer`], and penalises `expired` peers.
    pub fn plan_ranges(
        &self,
        now: Instant,
        applied: u64,
        applied_hash: Hash,
        peers: &[PeerSlot],
    ) -> Plan {
        match self.ranges.lock() {
            Ok(mut r) => r.plan(now, applied, applied_hash, peers),
            Err(_) => Plan::default(),
        }
    }

    /// Admission refused blocks `peer` delivered for `start..=end`: re-plan
    /// that range on someone else.
    pub fn range_rejected(&self, peer: &PeerId, start: u64, end: u64) {
        if let Ok(mut r) = self.ranges.lock() {
            r.on_rejected(peer, start, end);
        }
    }

    /// `peer` failed to take a request or went away: re-plan what it owed.
    pub fn release_peer(&self, peer: &PeerId) {
        if let Ok(mut r) = self.ranges.lock() {
            r.release_peer(peer);
        }
    }

    /// Range-scheduler counters (requests, retries, timeouts, duplicates).
    pub fn range_counters(&self) -> RangeCounters {
        self.ranges
            .lock()
            .map(|r| r.counters().clone())
            .unwrap_or_default()
    }

    /// Header anchors currently held (bounded by the scheduler's lookahead).
    pub fn anchor_count(&self) -> usize {
        self.ranges.lock().map(|r| r.anchor_count()).unwrap_or(0)
    }

    /// Height of the anchor on the most recent `GetBlocks` we sent (#156).
    pub fn last_block_anchor_height(&self) -> u64 {
        self.last_block_anchor_height.load(Ordering::Relaxed)
    }

    /// Process block download request.
    ///
    /// `from_height` is the height of `from`, recorded so a response can be
    /// judged against the anchor that produced it (#156).
    pub async fn request_blocks(
        &self,
        peer: &Peer,
        from: Hash,
        from_height: u64,
    ) -> Result<(), NetworkError> {
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
        self.last_block_anchor_height
            .store(from_height, Ordering::Relaxed);

        Ok(())
    }

    /// Handle received headers.
    ///
    /// WP-H.4: heights must be strictly increasing. A valid batch from the peer
    /// we asked feeds the range scheduler's anchors (bounded by its lookahead);
    /// headers nobody asked for, or from a peer we did not ask, are dropped.
    /// An empty batch answers our request too ("nothing above that anchor"),
    /// and only the responding peer's request is retired (CHAIN-B-A008).
    pub async fn handle_headers(
        &self,
        from_peer: &PeerId,
        headers: Vec<BlockHeader>,
    ) -> Result<(), NetworkError> {
        for window in headers.windows(2) {
            let [prev, next] = window else { continue };
            if next.height <= prev.height {
                warn!(
                    "SYNC_REJECT: non-monotonic header heights ({} -> {})",
                    prev.height, next.height
                );
                // Retire our request to this peer: it answered, badly.
                if let Ok(mut r) = self.ranges.lock() {
                    r.on_headers(from_peer, &[]);
                }
                return Err(NetworkError::ProtocolError(
                    "non-monotonic header heights in sync response".into(),
                ));
            }
        }
        let anchors: Vec<(u64, Hash)> = headers.iter().map(|h| (h.height, h.block_hash)).collect();
        if let Ok(mut r) = self.ranges.lock() {
            r.on_headers(from_peer, &anchors);
        }
        let (Some(first), Some(last)) = (headers.first(), headers.last()) else {
            return Ok(());
        };
        let (first_height, last_height, first_hash) = (first.height, last.height, first.block_hash);
        *self.last_header_hash.write().await = Some(last.block_hash);

        // Progress, saturating: a peer on a shorter branch can answer below us.
        let current = *self.current_height.read().await;
        let target = *self.target_height.read().await;
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
        debug!(
            "Downloaded {} headers (height {}-{}), progress: {:.1}%",
            headers.len(),
            first_height,
            last_height,
            progress
        );
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
    ///
    /// Returns how the response relates to the catch-up range it answers, so
    /// the caller can score the peer against what was actually asked.
    pub async fn handle_blocks(
        &self,
        from_peer: &PeerId,
        blocks: Vec<Block>,
    ) -> Result<BlocksMatch, NetworkError> {
        // Retire the RESPONDING peer's pending block requests up front — a
        // response answers our in-flight request to that peer regardless of
        // contents (empty batch, or a batch whose first block's selected-parent
        // differs from the requested `from` on a multi-producer DAG). See the
        // matching note in `handle_headers`; leaving a phantom pending entry is
        // what false-timed-out the sole block source and isolated the node.
        //
        // CHAIN-B-A008: keyed by peer (was a wholesale `clear()`), so one peer's
        // (or an attacker's) response can no longer retire another peer's
        // outstanding request and neuter `check_timeouts`.
        self.pending_blocks
            .write()
            .await
            .retain(|_, req| req.peer_id != *from_peer);
        let raw_first_height = blocks.first().map(|b| b.header.height);
        if blocks.is_empty() {
            return Ok(self.match_range(from_peer, None, &[]));
        }

        let total = blocks.len();
        // Safety: non-empty guaranteed by early return above
        let first_height = match blocks.first() {
            Some(b) => b.header.height,
            None => return Ok(self.match_range(from_peer, None, &[])),
        };
        // (Pending retirement already done unconditionally at the top of this
        // function — see the comment there.)
        let mut validated = Vec::with_capacity(total);
        let mut rejected = 0usize;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        for block in blocks {
            // 0. PBA-L1b-003: the same wall-clock future bound gossip applies.
            // This path (which also receives unsolicited `Blocks`) skipped it,
            // so a u64::MAX-timestamp block entered via sync. Local policy,
            // not a validity rule: a block rejected now is accepted once its
            // time arrives.
            if !citrate_consensus::hardening::within_future_drift(block.header.timestamp, now) {
                warn!(
                    "SYNC_REJECT: block height={} timestamp {} is beyond now+{}s",
                    block.header.height,
                    block.header.timestamp,
                    citrate_consensus::hardening::MAX_FUTURE_BLOCK_DRIFT_SECS
                );
                rejected = rejected.saturating_add(1);
                continue;
            }

            // 1. Verify canonical hash integrity
            if !block.verify_hash_for(self.pba_hardening) {
                warn!(
                    "SYNC_REJECT: block height={} hash mismatch (tampered commitment roots)",
                    block.header.height
                );
                rejected = rejected.saturating_add(1);
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
                    rejected = rejected.saturating_add(1);
                    continue;
                }
                Err(e) => {
                    warn!(
                        "SYNC_REJECT: block height={} signature error: {}",
                        block.header.height, e
                    );
                    rejected = rejected.saturating_add(1);
                    continue;
                }
            }

            // 3. Verify tx_root consistency. PBA-L1b-002: from the activation
            // height the root commits to every tx's full contents; below it
            // the legacy root (over the wire `tx.hash`) is kept byte-identical.
            let computed_tx_root = citrate_consensus::tx_auth::tx_root_for_height(
                self.pba_hardening,
                block.header.height,
                &block.transactions,
            );
            if block.tx_root != computed_tx_root {
                warn!(
                    "SYNC_REJECT: block height={} tx_root mismatch",
                    block.header.height
                );
                rejected = rejected.saturating_add(1);
                continue;
            }

            validated.push(block);
        }

        if rejected > 0 {
            warn!("Sync validation: {}/{} blocks rejected", rejected, total);
        }

        let links: Vec<BlockLink> = validated
            .iter()
            .map(|b| BlockLink {
                height: b.header.height,
                hash: b.header.block_hash,
                parent: b.header.selected_parent_hash,
            })
            .collect();
        let matched = self.match_range(from_peer, raw_first_height, &links);

        if validated.is_empty() {
            return Ok(matched);
        }

        let last_height = match validated.last() {
            Some(b) => b.header.height,
            None => return Ok(matched),
        };
        let accepted = validated.len();

        // Store only validated blocks
        self.downloaded_blocks.write().await.extend(validated);

        // Update progress.
        //
        // #146 — EVERY term here saturates, and the reason is not cosmetic. This
        // is a percentage for a log line, and an unguarded `last_height - current`
        // PANICKED the tokio task that owns the node's entire inbound message
        // loop (release builds set `overflow-checks = true`). That task is the one
        // serving GetBlocks/GetHeaders, admitting synced blocks, and driving the
        // applied tip, so one underflow here silently and permanently stopped the
        // node from processing any network message at all — while the process
        // stayed up, kept its peers, kept answering eth_syncing with a correct
        // "36k behind", and burned 0% CPU. No crash record, no restart loop:
        // exactly the "genuinely idle" cold-sync stall reported from the fleet.
        // A restart bought one more batch, until the next underflow.
        //
        // `current` is our APPLIED height (set below, and by #135), while
        // `last_height` is only the height of the last block a peer HANDED us, so
        // `last_height < current` is ordinary traffic, not an anomaly: a response
        // to a stale anchor, a sibling group on a shorter branch, or simply
        // `drive_drain` walking the applied tip past the batch in flight. The
        // identical guard already exists in `handle_headers` (added when this
        // very panic was seen there); it was never mirrored here.
        let current = *self.current_height.read().await;
        let target = *self.target_height.read().await;
        let span = target.saturating_sub(current);
        let done = last_height.saturating_sub(current);
        let progress = if span == 0 {
            100.0
        } else {
            (done as f32 / span as f32) * 100.0
        };

        *self.state.write().await = SyncState::DownloadingBlocks {
            from_height: current,
            to_height: target,
            progress,
        };

        // Advance progress against the node's OWN applied height when known —
        // `last_height` is only the height of the last block handed to us, and
        // recording it here is what let a node with a gap believe it was caught
        // up (wedge #85, see `sync_is_complete`).
        *self.current_height.write().await = self.applied_height().unwrap_or(last_height);

        debug!(
            "Validated and imported {}/{} blocks (height {}-{}), progress: {:.1}%",
            accepted, total, first_height, last_height, progress
        );

        // Check if sync complete — against our OWN chain, not the last block seen.
        if Self::sync_is_complete(self.applied_height(), last_height, target) {
            *self.state.write().await = SyncState::Synced;
            info!(
                "Synchronization complete at height {}",
                self.applied_height().unwrap_or(last_height)
            );
        }

        Ok(matched)
    }

    fn match_range(
        &self,
        peer: &PeerId,
        first: Option<u64>,
        validated: &[BlockLink],
    ) -> BlocksMatch {
        match self.ranges.lock() {
            Ok(mut r) => r.on_blocks(peer, first, validated),
            Err(_) => BlocksMatch::Unsolicited,
        }
    }

    /// Ancestry-recovery block requests that timed out (forward catch-up
    /// timeouts come back from [`Self::plan_ranges`] instead).
    pub async fn check_timeouts(&self) -> Vec<(Hash, PeerId)> {
        let mut timed_out: Vec<(Hash, PeerId)> = Vec::new();
        let now = Instant::now();

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

    /// Wedge regression: a later `start_sync` from a peer advertising a LOWER
    /// head must NOT lower the sync target below a higher peer's head. Pre-fix,
    /// `start_sync` overwrote `target_height` with the last caller's height, so a
    /// boot wedged at applied-tip 7 collapsed the target from the producer's ~73k
    /// to 7 and the drain declared "complete" at 7
    /// (handoffs/NODE_FRESH_SYNC_WEDGE_2026-07-19.md).
    #[tokio::test]
    async fn start_sync_target_only_rises_never_lowers() {
        let sync = SyncManager::new(SyncConfig::default());

        // Producer peer advertises the real head.
        sync.start_sync(73_400, Hash::new([1u8; 32])).await.unwrap();
        assert_eq!(*sync.target_height.read().await, 73_400);

        // A boot wedged at applied-tip 7 advertises 7 — must NOT lower the target.
        sync.start_sync(7, Hash::new([2u8; 32])).await.unwrap();
        assert_eq!(
            *sync.target_height.read().await,
            73_400,
            "a low-advertising peer must not lower the sync target"
        );
        // And we must still be draining (not prematurely Synced).
        assert!(
            !sync.is_synced().await,
            "must keep draining toward the real head"
        );

        // A peer advertising an even higher head DOES raise it.
        sync.start_sync(80_000, Hash::new([3u8; 32])).await.unwrap();
        assert_eq!(*sync.target_height.read().await, 80_000);
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

    fn slots(ids: &[&str], head: u64) -> Vec<PeerSlot> {
        ids.iter()
            .map(|i| PeerSlot::new(crate::PeerId(i.to_string()), head))
            .collect()
    }

    fn header_requests(plan: &Plan) -> Vec<String> {
        plan.requests
            .iter()
            .filter_map(|r| match r {
                crate::SyncRequest::Headers { peer, .. } => Some(peer.0.clone()),
                _ => None,
            })
            .collect()
    }

    /// Liveness regression: a completed headers response must RETIRE the
    /// request it answers. Pre-fix the entry was never removed, so the
    /// responding peer was later flagged as timed out — the chain of events
    /// that let a bootnode drop its only block source and split-brain the
    /// fleet. With the range scheduler the observable is: once the peer
    /// answers, the next round asks for the next headers instead of waiting
    /// out (and penalising) the old request.
    #[tokio::test]
    async fn handle_headers_retires_pending_request() {
        use citrate_consensus::types::{BlockBuilder, PublicKey};

        let sync = SyncManager::new(SyncConfig::default());
        let now = Instant::now();
        let peers = slots(&["peer-a"], 10_000);
        let first = sync.plan_ranges(now, 0, Hash::default(), &peers);
        assert_eq!(header_requests(&first), vec!["peer-a".to_string()]);
        // Still outstanding: nothing new is asked.
        let waiting = sync.plan_ranges(now, 0, Hash::default(), &peers);
        assert!(header_requests(&waiting).is_empty());

        let served: Vec<BlockHeader> = (1..=5u64)
            .map(|h| {
                let mut hd = BlockBuilder::new()
                    .parent(Hash::new([9u8; 32]))
                    .height(h)
                    .proposer(PublicKey::new([1; 32]))
                    .build_unhashed()
                    .header;
                hd.block_hash = Hash::new([h as u8; 32]);
                hd
            })
            .collect();
        sync.handle_headers(&crate::PeerId("peer-a".to_string()), served)
            .await
            .expect("handle_headers");
        let next = sync.plan_ranges(now, 0, Hash::default(), &peers);
        assert_eq!(
            header_requests(&next),
            vec!["peer-a".to_string()],
            "an answered header request must be retired so the next one goes out"
        );
        assert!(
            next.expired.is_empty(),
            "an answered request must never later count as a timeout"
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
        let _ = sync
            .handle_blocks(&PeerId("peer-b".to_string()), vec![served])
            .await;

        assert!(
            !sync.pending_blocks.read().await.contains_key(&anchor),
            "pending blocks request must be retired once the peer responds"
        );
    }

    /// Build a block that survives every check in `handle_blocks` — canonical
    /// hash, real ed25519 signature over that hash, and a tx_root consistent
    /// with an empty transaction list. A block that fails validation is dropped
    /// before the progress arithmetic, so the underflow tests below cannot use
    /// the unsigned builders the retirement tests use.
    fn signed_block_at(height: u64) -> Block {
        use citrate_consensus::types::{BlockBuilder, PublicKey};
        let key = crypto::generate_keypair();
        let pubkey = PublicKey::new(key.verifying_key().to_bytes());
        let mut block = BlockBuilder::new()
            .parent(Hash::new([7u8; 32]))
            .height(height)
            .proposer(pubkey)
            .build_unhashed();
        // tx_root over zero transactions, matching handle_blocks' recomputation.
        block.tx_root = citrate_consensus::tx_auth::tx_root_legacy(&[]);
        block.header.block_hash = block.compute_hash();
        block.signature = crypto::sign_block(&block.header.block_hash, &key);
        block
    }

    /// RED TEST — #146. The live cold-sync stall reproduced on this box: a
    /// follower at applied height 8,137 with the network tip at ~128,000
    /// received a batch of blocks BELOW its applied tip, and
    ///
    ///     ((last_height - current) as f32 / ...)
    ///
    /// underflowed. Release profile sets `overflow-checks = true`, so it did not
    /// wrap — it PANICKED, on the tokio task that owns the node's whole inbound
    /// message loop. From that instant the node processed no network message
    /// ever again: it stopped serving GetBlocks/GetHeaders, stopped admitting
    /// synced blocks, and its applied tip froze — while the process stayed up
    /// with its peers connected, 0% CPU, and a correct `eth_syncing` (the 2s
    /// tick task lives in a different spawn, and kept issuing requests nobody
    /// was left to answer).
    ///
    /// `last_height < current` is ORDINARY traffic, not corruption: a response
    /// to an anchor we have since walked past, a sibling group on a shorter
    /// branch, or `drive_drain` advancing the applied tip while the batch was in
    /// flight. Any of them was fatal.
    #[tokio::test]
    async fn a_batch_below_our_applied_height_must_not_panic_the_message_loop() {
        let sync = SyncManager::new(SyncConfig::default())
            .with_local_height(Arc::new(AtomicU64::new(8_137)));
        *sync.current_height.write().await = 8_137;
        sync.set_target(128_000).await;

        // The peer answers with a range entirely BELOW our applied tip.
        let batch = vec![signed_block_at(8_000), signed_block_at(8_001)];
        sync.handle_blocks(&crate::PeerId("p".into()), batch)
            .await
            .expect("a behind-us batch is normal traffic, not an error");

        // And the node is still usable afterwards: not wedged into Synced, and
        // still able to take the next batch.
        let ahead = vec![signed_block_at(8_200)];
        sync.handle_blocks(&crate::PeerId("p".into()), ahead)
            .await
            .expect("the manager keeps working after a behind-us batch");
    }

    /// The denominator half of the same guard: a peer at (or below) our own
    /// height makes `target == current`, which must report 100% rather than
    /// divide by zero. Pinned separately so a future edit cannot restore the
    /// numerator guard while dropping this one.
    #[tokio::test]
    async fn a_batch_at_our_target_reports_complete_without_dividing_by_zero() {
        let sync = SyncManager::new(SyncConfig::default())
            .with_local_height(Arc::new(AtomicU64::new(500)));
        *sync.current_height.write().await = 500;
        sync.set_target(500).await;

        sync.handle_blocks(&crate::PeerId("p".into()), vec![signed_block_at(500)])
            .await
            .expect("an at-tip batch is handled");
        assert!(
            sync.is_synced().await,
            "applied == target is genuinely synced"
        );
    }

    /// P1 regression: an EMPTY batch ("you are already at my tip") MUST still
    /// retire the pending request. Pre-fix the `is_empty()` early-return skipped
    /// retirement, so the entry lingered until `check_timeouts` FALSELY flagged
    /// the responding peer — a core driver of the sync-stall / peer-isolation
    /// storm (the node kept requesting from a peer that had nothing new, timed
    /// it out, and dropped its only block source).
    #[tokio::test]
    async fn empty_response_retires_pending() {
        use crate::PeerId;
        let sync = SyncManager::new(SyncConfig::default());
        let ba = Hash::new([8u8; 32]);
        let now = Instant::now();
        let peers = slots(&["p"], 10_000);
        assert_eq!(
            header_requests(&sync.plan_ranges(now, 0, Hash::default(), &peers)),
            vec!["p".to_string()]
        );
        sync.pending_blocks.write().await.insert(
            ba,
            BlockRequest {
                hash: ba,
                peer_id: PeerId("p".into()),
                requested_at: Instant::now(),
                retries: 0,
            },
        );
        sync.handle_headers(&PeerId("p".into()), vec![])
            .await
            .expect("handle empty headers");
        let _ = sync.handle_blocks(&PeerId("p".into()), vec![]).await;
        // An answer with nothing new backs header requests off briefly; past
        // the backoff the next one goes out, and nothing ever expired.
        let past_backoff = Instant::now() + RangeConfig::default().header_backoff;
        let after = sync.plan_ranges(past_backoff, 0, Hash::default(), &peers);
        assert!(
            after.expired.is_empty() && !header_requests(&after).is_empty(),
            "an empty header response must retire the pending request"
        );
        assert!(
            sync.pending_blocks.read().await.is_empty(),
            "an empty block response must retire the pending request"
        );
    }

    /// P1 regression: a batch whose first block's selected-parent does NOT equal
    /// the requested anchor (a multi-producer DAG sibling served via the
    /// height index) MUST still retire the pending request. The pre-fix keyed
    /// remove (`remove(first.selected_parent_hash)`) missed, so the entry
    /// lingered forever and false-timed-out the peer.
    #[tokio::test]
    async fn mismatched_first_block_retires_pending() {
        use crate::PeerId;
        use citrate_consensus::types::{BlockBuilder, PublicKey};
        let sync = SyncManager::new(SyncConfig::default());
        *sync.current_height.write().await = 0;
        *sync.target_height.write().await = 100;
        let anchor = Hash::new([3u8; 32]);
        sync.pending_blocks.write().await.insert(
            anchor,
            BlockRequest {
                hash: anchor,
                peer_id: PeerId("p".into()),
                requested_at: Instant::now(),
                retries: 0,
            },
        );
        // First served block's parent is a DIFFERENT hash than the requested
        // anchor — i.e. the height-index successor is a non-selected sibling.
        let served = BlockBuilder::new()
            .parent(Hash::new([99u8; 32]))
            .height(1)
            .proposer(PublicKey::new([1; 32]))
            .build_unhashed();
        let _ = sync.handle_blocks(&PeerId("p".into()), vec![served]).await;
        assert!(
            sync.pending_blocks.read().await.is_empty(),
            "a sibling-first-block response must still retire the pending request"
        );
    }

    /// CHAIN-B-A008 REGRESSION. A response from one peer must retire only THAT
    /// peer's pending requests, never another peer's. The pre-fix code did a
    /// wholesale `pending_*.clear()` on every inbound `Headers`/`Blocks`, so an
    /// attacker emitting empty responses retired honest peers' outstanding
    /// requests and `check_timeouts` could never observe a real timeout —
    /// disabling the whole sync-peer penalty/eviction escalation.
    #[tokio::test]
    async fn response_from_one_peer_does_not_retire_another_peers_request() {
        use crate::PeerId;

        let sync = SyncManager::new(SyncConfig::default());

        // Peer A and peer B each have one outstanding block request.
        let anchor_a = Hash::new([0xAA; 32]);
        let anchor_b = Hash::new([0xBB; 32]);
        sync.pending_blocks.write().await.insert(
            anchor_a,
            BlockRequest {
                hash: anchor_a,
                peer_id: PeerId("peer-a".into()),
                requested_at: Instant::now(),
                retries: 0,
            },
        );
        sync.pending_blocks.write().await.insert(
            anchor_b,
            BlockRequest {
                hash: anchor_b,
                peer_id: PeerId("peer-b".into()),
                requested_at: Instant::now(),
                retries: 0,
            },
        );

        // Peer B answers with an empty batch. This must retire only B's entry.
        let _ = sync.handle_blocks(&PeerId("peer-b".into()), vec![]).await;

        let pending = sync.pending_blocks.read().await;
        assert!(
            pending.contains_key(&anchor_a),
            "peer A's request MUST survive a response from peer B (pre-fix bug)"
        );
        assert!(
            !pending.contains_key(&anchor_b),
            "peer B's own request is retired by its response"
        );
    }

    /// REGRESSION — wedge #85, observed on chain 40204 on 2026-07-29.
    ///
    /// Three bootnodes sat at applied height 54,600 while the producer ran on to
    /// 56,128. They received the LIVE TIP by gossip, logged "Validated and
    /// imported 2/2 blocks (height 56127-56128) / Synchronization complete at
    /// height 56128", and stopped asking for the 54,601..56,127 they were
    /// missing. Verified on the live node: `eth_getBlockByNumber(0xdb40)`
    /// returned null — the very block they had just called imported was not in
    /// their chain store — while head stayed at 0xd548 (54,600), and they served
    /// "Sending 0 blocks" to their own peers.
    ///
    /// The height of the last block HANDED to us is not evidence of holding its
    /// ancestry. Completion must be judged against our own applied chain.
    #[test]
    fn sync_is_not_complete_while_our_own_chain_lags_the_target() {
        // Applied 54,600; a live tip block at 56,128 arrives; target 56,128.
        assert!(
            !SyncManager::sync_is_complete(Some(54_600), 56_128, 56_128),
            "a node holding only up to 54,600 must NOT call itself synced just \
             because it was handed the tip block at 56,128 — that is wedge #85"
        );
    }

    #[test]
    fn sync_is_complete_once_our_own_chain_reaches_the_target() {
        assert!(SyncManager::sync_is_complete(Some(56_128), 56_128, 56_128));
        assert!(SyncManager::sync_is_complete(Some(56_200), 56_128, 56_128));
    }

    #[test]
    fn sync_falls_back_to_last_seen_when_local_height_is_unwired() {
        // Back-compat: a SyncManager with no handle behaves exactly as before.
        assert!(SyncManager::sync_is_complete(None, 56_128, 56_128));
        assert!(!SyncManager::sync_is_complete(None, 54_600, 56_128));
    }

    #[tokio::test]
    async fn with_local_height_is_read_live_from_the_handle() {
        let handle = Arc::new(AtomicU64::new(54_600));
        let sync = SyncManager::new(SyncConfig::default()).with_local_height(handle.clone());
        assert_eq!(sync.applied_height(), Some(54_600));

        // The node applies forward; sync must observe it without rewiring.
        handle.store(56_128, Ordering::Relaxed);
        assert_eq!(sync.applied_height(), Some(56_128));
    }

    /// CHAIN-B-A004 tripwire: an unbounded flood of `Headers` messages must not
    /// grow what the sync manager retains. Pre-fix `handle_headers` did a bare
    /// `.extend(headers)` into a buffer nothing drained, so one peer could OOM
    /// the node; the later cap held it at 64 MiB. Headers now only feed the
    /// range scheduler's anchors, which are bounded by its lookahead and taken
    /// only from the peer that was asked. We assert the bound rather than
    /// exercising a true OOM, which would be unsafe.
    #[tokio::test]
    async fn downloaded_headers_stay_within_byte_cap_under_flood() {
        use citrate_consensus::types::{BlockBuilder, PublicKey};

        let sync = SyncManager::new(SyncConfig::default());
        let template = BlockBuilder::new()
            .parent(Hash::new([7u8; 32]))
            .height(1)
            .proposer(PublicKey::new([1; 32]))
            .build_unhashed()
            .header;
        let now = Instant::now();
        let peers = slots(&["p"], u64::MAX);

        // 400 batches x 1024 headers ≈ 409k headers, half of them solicited.
        let per_batch: u64 = 1024;
        for batch in 0..400u64 {
            if batch % 2 == 0 {
                sync.plan_ranges(now, 0, Hash::default(), &peers);
            }
            let mut headers = Vec::with_capacity(per_batch as usize);
            for i in 0..per_batch {
                let mut h = template.clone();
                h.height = batch * per_batch + i + 1; // strictly monotonic in-batch
                h.block_hash = Hash::new([(i % 251) as u8 + 1; 32]);
                headers.push(h);
            }
            sync.handle_headers(&crate::PeerId("p".into()), headers)
                .await
                .expect("handle_headers should accept a monotonic batch");
        }
        let lookahead = RangeConfig::default().lookahead as usize;
        assert!(
            sync.anchor_count() <= lookahead,
            "header anchors must stay within the lookahead ({lookahead}); got {}",
            sync.anchor_count()
        );
    }

    /// CHAIN-B-A008 for headers: a header response from one peer must not
    /// retire (or feed anchors into) a request made to another.
    #[tokio::test]
    async fn header_response_from_one_peer_does_not_retire_another_peers_request() {
        use citrate_consensus::types::{BlockBuilder, PublicKey};

        let sync = SyncManager::new(SyncConfig::default());
        let now = Instant::now();
        let peers = slots(&["peer-a", "peer-b"], 10_000);
        let first = sync.plan_ranges(now, 0, Hash::default(), &peers);
        assert_eq!(header_requests(&first), vec!["peer-a".to_string()]);
        let mut h = BlockBuilder::new()
            .parent(Hash::new([7u8; 32]))
            .height(1)
            .proposer(PublicKey::new([1; 32]))
            .build_unhashed()
            .header;
        h.block_hash = Hash::new([0x42; 32]);
        sync.handle_headers(&crate::PeerId("peer-b".into()), vec![h])
            .await
            .expect("headers");
        assert_eq!(
            sync.anchor_count(),
            0,
            "unsolicited headers must not become anchors"
        );
        let again = sync.plan_ranges(now, 0, Hash::default(), &peers);
        assert!(
            header_requests(&again).is_empty(),
            "peer A's request must survive a response from peer B"
        );
    }
}
