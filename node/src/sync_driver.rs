// citrate/node/src/sync_driver.rs
//
// The two halves of catch-up sync, out of main.rs so they can be tested:
//
//   - `SyncDriver::tick`: decide which `GetHeaders` / `GetBlocks` to send and
//     to whom, and retire requests that timed out;
//   - `SyncDriver::ingest_blocks`: take one `Blocks` response through
//     validation and admission (which executes and verifies each block), and
//     score the peer on what it actually delivered.
//
// main.rs owns the sockets, the peer manager, logging of peer changes and the
// drop-and-re-handshake escalation; everything that decides WHAT to ask for and
// HOW a response is taken in lives here, and the multi-peer sync test drives
// exactly this code.

// PANIC-S1 G2: block production / apply / sync path (T1); panic-free outside tests.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::string_slice
    )
)]

use crate::admission::{self, AdmitOutcome, BlockAdmission};
use crate::sync_peer::{self, ServeQuality, SyncCandidate, SyncPeerSelector};
use citrate_consensus::types::{Block, BlockHeader, Hash};
use citrate_network::peer::{Peer, PeerId};
use citrate_network::{BlocksMatch, NetworkMessage, PeerSlot, SyncManager, SyncRequest};
use citrate_storage::StorageManager;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Notify};

/// How often the request side runs when nothing wakes it. Every response
/// wakes it too (see [`SyncDriver::wake_handle`]), so a freed range slot is
/// refilled at once instead of on the next tick; the interval only bounds how
/// late a timeout is noticed.
pub const TICK_INTERVAL: Duration = Duration::from_millis(500);

/// A connected peer as the tick sees it.
#[derive(Clone)]
pub struct TickPeer {
    pub id: PeerId,
    pub head_height: u64,
    pub peer: Arc<Peer>,
}

/// What one tick did that main.rs must act on.
#[derive(Debug, Default)]
pub struct TickReport {
    /// The peer the selector preferred this tick (for the SYNCPEER log line).
    pub chosen: Option<String>,
    /// Peers whose request failed to send, with their new timeout count.
    pub send_failed: Vec<(PeerId, u32)>,
    /// Peers that let a request time out, with their new timeout count.
    pub timed_out: Vec<(PeerId, u32)>,
}

/// One validated `Blocks` response on its way from the network loop to the
/// sync admission worker.
#[derive(Debug)]
pub struct ReceivedBlocks {
    pub pid: PeerId,
    pub matched: BlocksMatch,
    pub validated: Vec<Block>,
}

/// How long the network loop waits for room in the admission queue before
/// it drops a response (and re-plans its range). Far below the receive-loop
/// stall detector's window, so a slow apply cannot stop the loop.
pub const ADMIT_HANDOFF_WAIT: Duration = Duration::from_secs(2);

/// What [`SyncDriver::hand_to_admission`] did with a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handoff {
    Queued,
    /// The queue stayed full: dropped, and its range (if any) re-planned.
    Dropped,
    /// The admission worker is gone.
    Closed,
}

/// Bound on validated responses waiting for admission. The scheduler's
/// lookahead (512 heights, 16 ranges) is the most that can legitimately be
/// waiting; the rest is headroom for unsolicited answers.
pub const ADMIT_QUEUE: usize = 64;

/// What one `Blocks` response did.
#[derive(Debug, Clone)]
pub struct IngestReport {
    pub newly_admitted: usize,
    pub quality: ServeQuality,
    pub score: i32,
    pub anchor: u64,
    pub applied_now: u64,
    pub gap: u64,
}

pub struct SyncDriver {
    sync: Arc<SyncManager>,
    selector: Arc<Mutex<SyncPeerSelector>>,
    rotate_idx: AtomicU64,
    wake: Arc<Notify>,
}

fn applied_tip(storage: &StorageManager) -> (Hash, u64) {
    storage
        .blocks
        .get_applied_tip()
        .ok()
        .flatten()
        .unwrap_or_else(|| (Hash::new([0u8; 32]), 0))
}

impl SyncDriver {
    pub fn new(sync: Arc<SyncManager>, selector: Arc<Mutex<SyncPeerSelector>>) -> Self {
        Self {
            sync,
            selector,
            rotate_idx: AtomicU64::new(0),
            wake: Arc::new(Notify::new()),
        }
    }

    /// Notified after every response; the tick loop waits on it alongside
    /// its interval.
    pub fn wake_handle(&self) -> Arc<Notify> {
        self.wake.clone()
    }

    #[cfg(test)]
    pub fn sync(&self) -> &Arc<SyncManager> {
        &self.sync
    }

    /// One round of the request side. `target` is the best known network
    /// height (already clamped by the caller).
    ///
    /// Every peer that can advance us is ranked (`SyncPeerSelector::rank`, the
    /// order `select` maximises) and the range scheduler spreads disjoint
    /// ranges over them, keyed by the next heights not yet requested. See
    /// core/network/src/sync_ranges.rs.
    pub async fn tick(
        &self,
        storage: &StorageManager,
        target: u64,
        peers: &[TickPeer],
    ) -> TickReport {
        let mut report = TickReport::default();
        let (applied_hash, applied_height) = applied_tip(storage);
        let candidates: Vec<SyncCandidate> = peers
            .iter()
            .map(|p| SyncCandidate {
                id: p.id.0.clone(),
                head_height: p.head_height,
            })
            .collect();
        // Best first; a peer in bad standing (de-preferred by timeouts, or a
        // negative usefulness score) may hold only one range at a time.
        let ranked: Vec<(String, usize)> = {
            let sel = self.selector.lock().await;
            sel.rank(&candidates, applied_height)
                .into_iter()
                .map(|c| {
                    let bad = sel.failures(&c.id) >= sync_peer::DEPREFER_AT_FAILURES
                        || sel.score(&c.id) < 0;
                    (c.id.clone(), usize::from(bad))
                })
                .collect()
        };
        report.chosen = ranked.first().map(|(id, _)| id.clone());
        let mut slots: Vec<PeerSlot> = ranked
            .iter()
            .filter_map(|(id, cap)| {
                peers.iter().find(|p| p.id.0 == *id).map(|p| PeerSlot {
                    id: p.id.clone(),
                    head_height: p.head_height,
                    max_in_flight: *cap,
                })
            })
            .collect();
        if slots.is_empty() && applied_height < target && !peers.is_empty() {
            // Evidence we are behind but nobody admits a head above ours
            // (stale advertisements): ask everyone, starting from a rotating
            // offset so one peer serving a side branch cannot pin us.
            let n = self.rotate_idx.fetch_add(1, Ordering::Relaxed) as usize;
            for k in 0..peers.len() {
                let i = n.wrapping_add(k).checked_rem(peers.len()).unwrap_or(0);
                if let Some(p) = peers.get(i) {
                    slots.push(PeerSlot::new(p.id.clone(), target));
                }
            }
        }

        let plan = self
            .sync
            .plan_ranges(Instant::now(), applied_height, applied_hash, &slots);
        // #151: a request that fails to send counts against the peer, and
        // whatever it was given is re-planned on someone else.
        let mut failed: Vec<PeerId> = Vec::new();
        for req in plan.requests {
            let (pid, msg) = match req {
                SyncRequest::Headers {
                    peer, from, count, ..
                } => (peer, NetworkMessage::GetHeaders { from, count }),
                SyncRequest::Blocks {
                    peer, from, count, ..
                } => (
                    peer,
                    NetworkMessage::GetBlocks {
                        from,
                        count,
                        step: 1,
                    },
                ),
            };
            if failed.contains(&pid) {
                continue;
            }
            let sent = match peers.iter().find(|p| p.id == pid) {
                Some(tp) => tp.peer.send(msg).await.is_ok(),
                None => false,
            };
            if !sent {
                self.sync.release_peer(&pid);
                failed.push(pid);
            }
        }
        let mut sel = self.selector.lock().await;
        for pid in failed {
            let fails = sel.record_timeout(&pid.0);
            report.send_failed.push((pid, fails));
        }
        // One timeout per peer per round, however many of its ranges expired
        // together: they are one slow connection, not several failures.
        let mut charged: Vec<PeerId> = Vec::new();
        // A peer whose header anchor a block answer proved wrong, or whose
        // delivered range was refused or never applied, is charged like a
        // timeout so it drops below the peers that serve.
        for pid in plan.misbehaved {
            let pf = sel.record_timeout(&pid.0);
            charged.push(pid.clone());
            report.timed_out.push((pid, pf));
        }
        for e in plan.expired {
            if charged.contains(&e.peer) {
                continue;
            }
            let pf = sel.record_timeout(&e.peer.0);
            charged.push(e.peer.clone());
            report.timed_out.push((e.peer, pf));
        }
        drop(sel);
        // Ancestry-recovery requests (SYNC-S3) keep their own timeouts.
        for (_h, pid) in self.sync.check_timeouts().await {
            if charged.contains(&pid) {
                continue;
            }
            let pf = self.selector.lock().await.record_timeout(&pid.0);
            charged.push(pid.clone());
            report.timed_out.push((pid, pf));
        }
        report
    }

    /// Take one `Headers` response in and wake the request side, which can
    /// now anchor more ranges.
    pub async fn ingest_headers(&self, pid: &PeerId, headers: Vec<BlockHeader>) {
        if let Err(e) = self.sync.handle_headers(pid, headers).await {
            tracing::debug!("headers from {}: {}", pid.0, e);
        }
        self.wake.notify_one();
    }

    /// Receive side of one `Blocks` response, run on the network loop:
    /// validate every block (WP-H.4) and record which range it answers, so
    /// the range's timer stops when the answer ARRIVES, not when admission
    /// gets to it. Admission is [`Self::admit_received`], on the sync
    /// admission worker, so a slow apply never holds up header answers, other
    /// peers' block answers, or serving peers.
    pub async fn receive_blocks(&self, pid: &PeerId, blocks: Vec<Block>) -> ReceivedBlocks {
        let matched = self
            .sync
            .handle_blocks(pid, blocks)
            .await
            .unwrap_or(BlocksMatch::Unsolicited);
        // Same task as handle_blocks, so this drains exactly its output.
        let validated = self.sync.drain_validated_blocks().await;
        self.wake.notify_one();
        ReceivedBlocks {
            pid: pid.clone(),
            matched,
            validated,
        }
    }

    /// Queue one received response for the admission worker, waiting at most
    /// `wait` for room. The network loop calls this, so it must not block
    /// for long: when the queue stays full the response is dropped and the
    /// range it delivered goes back to the scheduler, uncharged.
    pub async fn hand_to_admission(
        &self,
        tx: &tokio::sync::mpsc::Sender<ReceivedBlocks>,
        received: ReceivedBlocks,
        wait: Duration,
    ) -> Handoff {
        use tokio::sync::mpsc::error::SendTimeoutError;
        match tx.send_timeout(received, wait).await {
            Ok(()) => Handoff::Queued,
            Err(SendTimeoutError::Timeout(r)) => {
                if let BlocksMatch::Range {
                    start,
                    delivered_through,
                    ..
                } = r.matched
                {
                    if delivered_through >= start {
                        self.sync.range_dropped(&r.pid, start, delivered_through);
                    }
                }
                self.wake.notify_one();
                Handoff::Dropped
            }
            Err(SendTimeoutError::Closed(_)) => Handoff::Closed,
        }
    }

    /// Admission side of one `Blocks` response: admit in height order
    /// (deferring blocks whose parent is still on the way into `orphans`),
    /// and score the peer on what was new. `on_admitted` runs for every newly
    /// admitted block.
    pub async fn admit_received<F: FnMut(&Block)>(
        &self,
        admission: &BlockAdmission,
        storage: &StorageManager,
        orphans: &mut Vec<Block>,
        received: ReceivedBlocks,
        target: u64,
        mut on_admitted: F,
    ) -> IngestReport {
        let ReceivedBlocks {
            pid,
            matched,
            validated: mut pending,
        } = received;
        let pid = &pid;
        let fresh: HashSet<Hash> = pending.iter().map(|b| b.header.block_hash).collect();
        // CHAIN-B-A005: only re-scan the orphan buffer when this batch
        // actually delivered something new.
        let reprocessed_orphans = !pending.is_empty();
        if reprocessed_orphans {
            pending.append(orphans);
            pending = admission::bound_orphan_buffer(pending);
        }

        // Fixpoint: a block whose parent is not admitted yet is DEFERRED
        // (buffered), never dropped; a parent arriving later unblocks it.
        let mut newly_admitted: usize = 0;
        let mut highest_admitted: u64 = 0;
        let mut rejected_fresh: usize = 0;
        loop {
            let mut progressed = false;
            let mut deferred: Vec<Block> = Vec::new();
            for block in std::mem::take(&mut pending) {
                match admission.admit(&block).await {
                    AdmitOutcome::Admitted { completed_partial } => {
                        progressed = true;
                        newly_admitted = newly_admitted.saturating_add(1);
                        if block.header.height > highest_admitted {
                            highest_admitted = block.header.height;
                        }
                        on_admitted(&block);
                        if completed_partial {
                            tracing::debug!(
                                "Completed a partial admission of synced block {} @ {}",
                                hex::encode(
                                    block.header.block_hash.as_bytes().get(..8).unwrap_or(&[])
                                ),
                                block.header.height
                            );
                        }
                    }
                    AdmitOutcome::AlreadyAdmitted => {}
                    AdmitOutcome::Deferred { missing_parent } => {
                        tracing::debug!(
                            "Deferred synced block {} @ {}: missing parent {}",
                            hex::encode(block.header.block_hash.as_bytes().get(..8).unwrap_or(&[])),
                            block.header.height,
                            hex::encode(missing_parent.as_bytes().get(..8).unwrap_or(&[]))
                        );
                        deferred.push(block);
                    }
                    AdmitOutcome::Rejected(why) => {
                        if fresh.contains(&block.header.block_hash) {
                            rejected_fresh = rejected_fresh.saturating_add(1);
                        }
                        tracing::warn!(
                            "Rejected inconsistent synced block {} @ {}: {}",
                            hex::encode(block.header.block_hash.as_bytes().get(..8).unwrap_or(&[])),
                            block.header.height,
                            why
                        );
                    }
                }
            }
            pending = deferred;
            if !progressed {
                break;
            }
        }
        // Blocks from THIS response still waiting on a parent: a range that
        // arrived ahead of an earlier one. They count as service only inside
        // the run the scheduler accepted as linked to the range's anchor; a
        // block on a parent nobody can resolve is not service.
        let linked_run = match &matched {
            BlocksMatch::Range {
                start,
                delivered_through,
                ..
            } => Some((*start, *delivered_through)),
            BlocksMatch::Unsolicited => None,
        };
        let deferred_fresh = pending
            .iter()
            .filter(|b| fresh.contains(&b.header.block_hash))
            .filter(|b| {
                linked_run.is_some_and(|(s, t)| b.header.height >= s && b.header.height <= t)
            })
            .count();
        // Admission refused part of a delivered range: ask someone else.
        if rejected_fresh > 0 {
            if let Some((s, t)) = linked_run {
                if t >= s {
                    self.sync.range_rejected(pid, s, t);
                }
            }
        }
        if reprocessed_orphans {
            *orphans = admission::bound_orphan_buffer(std::mem::take(&mut pending));
        }
        self.wake.notify_one();

        // #153/#155/#156: credit the peer on what it delivered, relative to
        // what the range asked for and to the gap. A response that answers no
        // range of ours (ancestry recovery, or a late answer to a range
        // already reassigned) is our question, not the peer's failure: neutral
        // when it brings nothing.
        let (_, applied_now) = applied_tip(storage);
        let gap = target.saturating_sub(applied_now);
        let (anchor, batch, stale_anchor) = match matched {
            BlocksMatch::Range { start, end, .. } => (
                start,
                usize::try_from(end.saturating_sub(start).saturating_add(1)).unwrap_or(usize::MAX),
                false,
            ),
            BlocksMatch::Unsolicited => (self.sync.last_block_anchor_height(), 32, true),
        };
        let useful = newly_admitted.saturating_add(deferred_fresh);
        let mut sel = self.selector.lock().await;
        let quality = sel.record_serve(&pid.0, useful, highest_admitted, gap, batch, stale_anchor);
        IngestReport {
            newly_admitted: useful,
            quality,
            score: sel.score(&pid.0),
            anchor,
            applied_now,
            gap,
        }
    }
}

#[cfg(test)]
mod tests {
    //! Multi-peer catch-up sync on a local devnet.
    //!
    //! A chain of `N` signed blocks with real state roots (rewards plus
    //! periodic transfers) is built once and stored in a serving store. A fresh
    //! node, wired exactly like `start_node` wires one (storage-backed executor,
    //! canonical applicator with GhostDAG fork choice, block admission, sync
    //! manager), syncs it from three peers over in-memory channels using the
    //! same `SyncDriver::tick` / `SyncDriver::ingest_blocks` the network loop
    //! calls. Two peers are honest; the third answers block requests either
    //! with nothing or not at all, and answers header requests with nothing.
    //!
    //! Each peer runs the real `block_serve` handlers and records every request
    //! it receives, so duplicate requests are counted on the wire, independent
    //! of the driver's own bookkeeping.
    use super::*;
    use crate::block_serve;
    use crate::canonical_apply::{canonical_reward_config, CanonicalApplicator};
    use citrate_consensus::crypto;
    use citrate_consensus::dag_store::DagStore;
    use citrate_consensus::ghostdag::GhostDag;
    use citrate_consensus::hardening::PbaHardening;
    use citrate_consensus::types::{
        blue_work_for_score, BlockBuilder, GhostDagParams, PublicKey, Signature, Transaction,
        VrfProof,
    };
    use citrate_economics::rewards::RewardCalculator;
    use citrate_execution::revm_adapter::BlockContext;
    use citrate_execution::types::Address;
    use citrate_execution::{Executor, StateDB};
    use citrate_network::peer::{Direction, PeerInfo, PeerState};
    use citrate_network::{NetworkMessage, SyncConfig};
    use citrate_storage::pruning::PruningConfig;
    use primitive_types::U256;
    use std::collections::BTreeSet;
    use std::time::Instant;
    use tokio::sync::mpsc;

    const CB: [u8; 20] = [0x33; 20];
    const CHAIN_ID: u64 = 40204;
    /// Funded genesis accounts. World-state size drives per-block apply cost
    /// (state snapshots, state root), so the slow-apply scenario raises it.
    fn funded_count() -> usize {
        env_u64("CITRATE_SYNC_TEST_FUNDED", 64) as usize
    }
    const FUND: u128 = 1_000_000_000_000_000_000_000;

    fn funded(i: usize) -> [u8; 20] {
        let mut a = [0u8; 20];
        a[0] = 0xA0;
        a[12..20].copy_from_slice(&(i as u64).to_be_bytes());
        a
    }

    fn embedded(addr: [u8; 20]) -> PublicKey {
        let mut b = [0u8; 32];
        b[..20].copy_from_slice(&addr);
        PublicKey::new(b)
    }

    fn fund_genesis(exec: &Executor) {
        for i in 0..funded_count() {
            exec.set_balance(&Address(funded(i)), U256::from(FUND));
        }
    }

    struct Chain {
        genesis: Block,
        /// blocks[h - 1] is height h.
        blocks: Vec<Block>,
    }

    fn seal(
        key: &ed25519_dalek::SigningKey,
        height: u64,
        parent: Hash,
        root: Hash,
        txs: Vec<Transaction>,
    ) -> Block {
        let mut b = BlockBuilder::new()
            .version(2)
            .height(height)
            .parent(parent)
            .coinbase(CB)
            .timestamp(1_000 + height)
            .vrf_reveal(VrfProof {
                proof: vec![],
                output: Hash::new([0x5A; 32]),
            })
            .transactions(txs)
            .state_root(root)
            .blue_score(height)
            .blue_work(blue_work_for_score(height))
            .proposer(PublicKey::new(key.verifying_key().to_bytes()))
            .build_unhashed();
        b.tx_root = citrate_consensus::tx_auth::tx_root_for_height(
            PbaHardening::off(),
            height,
            &b.transactions,
        );
        b.header.block_hash = b.compute_hash();
        b.signature = crypto::sign_block(&b.header.block_hash, key);
        b
    }

    /// Build `n` blocks the way the producer does: block context, execute the
    /// transactions, credit the basic reward, seal over the resulting root.
    async fn build_chain(n: u64) -> Chain {
        let key = crypto::generate_keypair();
        let genesis = {
            let mut g = BlockBuilder::new()
                .version(2)
                .height(0)
                .parent(Hash::default())
                .coinbase(CB)
                .timestamp(1_000)
                .vrf_reveal(VrfProof {
                    proof: vec![],
                    output: Hash::new([0x5A; 32]),
                })
                .transactions(vec![])
                .state_root(Hash::default())
                .blue_score(0)
                .blue_work(blue_work_for_score(0))
                .build_unhashed();
            g.header.block_hash = g.compute_hash();
            g
        };
        let exec = Executor::new(Arc::new(StateDB::new()));
        fund_genesis(&exec);
        let rewards = RewardCalculator::new(canonical_reward_config());
        let treasury = canonical_reward_config().treasury_address;
        let accounts = funded_count();
        let mut nonces = vec![0u64; accounts];
        let mut parent = genesis.header.block_hash;
        let mut blocks = Vec::with_capacity(n as usize);
        for h in 1..=n {
            exec.set_block_context(BlockContext {
                coinbase: CB,
                prevrandao: [0x5A; 32],
                block_hashes: std::collections::HashMap::new(),
            });
            // A transfer every 4th block, rotating senders and recipients.
            let mut txs = Vec::new();
            if h % 4 == 0 {
                let i = (h as usize / 4) % accounts;
                let to = funded((i + 1) % accounts);
                txs.push(Transaction {
                    nonce: nonces[i],
                    from: embedded(funded(i)),
                    to: Some(embedded(to)),
                    value: 1_000 + u128::from(h),
                    gas_limit: 21_000,
                    gas_price: 1_000_000_000,
                    signature: Signature::new([1; 64]),
                    chain_id: Some(CHAIN_ID),
                    ..Default::default()
                });
                nonces[i] += 1;
            }
            let provisional = seal(&key, h, parent, Hash::default(), txs.clone());
            for tx in &txs {
                exec.execute_transaction(&provisional, tx)
                    .await
                    .expect("producer tx executes");
            }
            let r = rewards.calculate_reward(&provisional).expect("reward");
            for (addr, amt) in [
                (Address(CB), r.validator_reward),
                (treasury, r.treasury_reward),
            ] {
                if amt > U256::zero() {
                    let bal = exec.get_balance(&addr);
                    exec.set_balance(&addr, bal + amt);
                }
            }
            let root = exec.calculate_state_root();
            let b = seal(&key, h, parent, root, txs);
            parent = b.header.block_hash;
            blocks.push(b);
        }
        Chain { genesis, blocks }
    }

    fn store_with(chain: &Chain, dir: &std::path::Path) -> Arc<StorageManager> {
        let s = Arc::new(StorageManager::new(dir, PruningConfig::default()).expect("storage"));
        s.blocks.put_block(&chain.genesis).expect("genesis");
        for b in &chain.blocks {
            s.blocks.put_block(b).expect("put");
        }
        s
    }

    /// A fresh node, wired as `start_node` wires one.
    struct Follower {
        storage: Arc<StorageManager>,
        executor: Arc<Executor>,
        admission: Arc<BlockAdmission>,
        driver: Arc<SyncDriver>,
    }

    async fn follower(chain: &Chain, dir: &std::path::Path) -> Follower {
        let storage =
            Arc::new(StorageManager::new(dir, PruningConfig::default()).expect("storage"));
        let g = &chain.genesis;
        storage.blocks.put_block(g).expect("genesis");
        storage
            .blocks
            .put_applied_tip(&g.header.block_hash, 0)
            .expect("tip");
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        dag.set_configured_genesis(g.header.block_hash);
        dag.store_block(g.clone()).await.expect("genesis dag");
        let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag.clone()));
        ghostdag.add_block(g).await.expect("genesis ghostdag");
        let executor = Arc::new(Executor::with_storage_and_chain_id(
            Arc::new(StateDB::new()),
            Some(storage.state.clone()),
            CHAIN_ID,
        ));
        executor.set_pba_hardening(PbaHardening::off());
        fund_genesis(&executor);
        let app = Arc::new(
            CanonicalApplicator::new(executor.clone(), storage.clone())
                .with_fork_choice(ghostdag.clone()),
        );
        let admission = Arc::new(BlockAdmission::new(
            storage.clone(),
            dag,
            ghostdag,
            Some(app.clone()),
        ));
        let sync = Arc::new(
            SyncManager::new(SyncConfig::default())
                .with_local_height(app.applied_height_handle())
                .with_pba_hardening(PbaHardening::off()),
        );
        let driver = Arc::new(SyncDriver::new(
            sync,
            Arc::new(Mutex::new(SyncPeerSelector::new())),
        ));
        Follower {
            storage,
            executor,
            admission,
            driver,
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Behaviour {
        Honest,
        /// Block requests: alternately never answered and answered empty.
        /// Header requests: answered empty.
        EmptyOrSilent,
        /// Block requests: the right heights, but every block re-sealed under
        /// the peer's own key on a parent nobody holds (each passes the
        /// receive-side checks; none links to our chain). Header requests:
        /// answered honestly.
        Forger,
        /// Header requests: each header's hash replaced by the hash of the
        /// block 100 heights above it. Block requests: answered honestly.
        HeaderLiar,
    }

    /// `block` moved onto a parent nobody holds and re-signed by `key`.
    fn forge(block: &Block, key: &ed25519_dalek::SigningKey) -> Block {
        let mut b = block.clone();
        let mut fake = [0xEEu8; 32];
        fake[..8].copy_from_slice(&b.header.height.to_be_bytes());
        b.header.selected_parent_hash = Hash::new(fake);
        b.header.proposer_pubkey = PublicKey::new(key.verifying_key().to_bytes());
        b.header.block_hash = b.compute_hash();
        b.signature = crypto::sign_block(&b.header.block_hash, key);
        b
    }

    #[derive(Default, Debug)]
    struct Wire {
        get_blocks: u64,
        get_headers: u64,
        /// GetBlocks asking (beyond the anchor) for a height some peer had
        /// already sent the follower.
        duplicate_get_blocks: u64,
        faulty_get_blocks: u64,
        blocks_sent: u64,
        served: BTreeSet<u64>,
    }

    fn spawn_peer(
        name: &str,
        behaviour: Behaviour,
        head: u64,
        storage: Arc<StorageManager>,
        inbound: mpsc::Sender<(PeerId, NetworkMessage)>,
        wire: Arc<std::sync::Mutex<Wire>>,
    ) -> TickPeer {
        let id = PeerId(name.to_string());
        let (tx, mut rx) = mpsc::channel::<NetworkMessage>(1024);
        let (_unused_tx, unused_rx) = mpsc::channel::<NetworkMessage>(1);
        let mut info = PeerInfo::new(
            id.clone(),
            "127.0.0.1:1".parse().expect("addr"),
            Direction::Outbound,
        );
        info.state = PeerState::Connected;
        info.head_height = head;
        let peer = Arc::new(Peer::new(info, tx, unused_rx));
        let pid = id.clone();
        tokio::spawn(async move {
            let forger_key = crypto::generate_keypair();
            let mut k = 0u64;
            while let Some(msg) = rx.recv().await {
                match msg {
                    NetworkMessage::GetBlocks { from, count, .. } => {
                        let anchor = if from == Hash::new([0u8; 32]) {
                            0
                        } else {
                            storage
                                .blocks
                                .get_block(&from)
                                .ok()
                                .flatten()
                                .map(|b| b.header.height)
                                .unwrap_or(0)
                        };
                        {
                            let mut w = wire.lock().expect("wire");
                            w.get_blocks += 1;
                            let asked =
                                anchor.saturating_add(1)..anchor.saturating_add(u64::from(count));
                            if w.served.range(asked).next().is_some() {
                                w.duplicate_get_blocks += 1;
                            }
                            if behaviour != Behaviour::Honest {
                                w.faulty_get_blocks += 1;
                            }
                        }
                        // Serving cost of a real peer on a LAN.
                        tokio::time::sleep(Duration::from_millis(5)).await;
                        let blocks = match behaviour {
                            Behaviour::Honest => block_serve::serve_blocks(&storage, &from, count),
                            Behaviour::EmptyOrSilent => {
                                k += 1;
                                if k % 2 == 1 {
                                    continue; // never answered
                                }
                                Vec::new()
                            }
                            Behaviour::Forger => block_serve::serve_blocks(&storage, &from, count)
                                .iter()
                                .map(|b| forge(b, &forger_key))
                                .collect(),
                            Behaviour::HeaderLiar => {
                                block_serve::serve_blocks(&storage, &from, count)
                            }
                        };
                        {
                            let mut w = wire.lock().expect("wire");
                            w.blocks_sent += blocks.len() as u64;
                            for b in &blocks {
                                w.served.insert(b.header.height);
                            }
                        }
                        if inbound
                            .send((pid.clone(), NetworkMessage::Blocks { blocks }))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    NetworkMessage::GetHeaders { from, count } => {
                        wire.lock().expect("wire").get_headers += 1;
                        let headers = match behaviour {
                            Behaviour::Honest | Behaviour::Forger => {
                                block_serve::serve_headers(&storage, &from, count)
                            }
                            Behaviour::EmptyOrSilent => Vec::new(),
                            Behaviour::HeaderLiar => {
                                let mut hs = block_serve::serve_headers(&storage, &from, count);
                                for h in &mut hs {
                                    if let Ok(Some(other)) =
                                        storage.blocks.get_block_by_height(h.height + 100)
                                    {
                                        h.block_hash = other;
                                    }
                                }
                                hs
                            }
                        };
                        if inbound
                            .send((pid.clone(), NetworkMessage::Headers { headers }))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    _ => {}
                }
            }
        });
        TickPeer {
            id,
            head_height: head,
            peer,
        }
    }

    fn rss_kb() -> u64 {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("VmRSS:"))
                    .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
            })
            .unwrap_or(0)
    }

    struct Outcome {
        applied: u64,
        secs: f64,
        rss_start_kb: u64,
        rss_peak_kb: u64,
        received_blocks: u64,
        distinct_blocks: u64,
        /// Time spent validating responses (hash, signature, tx_root) on the
        /// receive side.
        validate_secs: f64,
    }

    /// Sync `follower` from `peers` until it reaches `n` or `deadline` passes.
    async fn run_sync(
        f: &Follower,
        peers: Vec<TickPeer>,
        mut inbound: mpsc::Receiver<(PeerId, NetworkMessage)>,
        n: u64,
        deadline: Duration,
    ) -> Outcome {
        let start = Instant::now();
        let rss_start_kb = rss_kb();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let peak = Arc::new(AtomicU64::new(rss_start_kb));
        let sampler = {
            let stop = stop.clone();
            let peak = peak.clone();
            tokio::spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    peak.fetch_max(rss_kb(), Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            })
        };
        // Request side: the tick, as the network loop runs it.
        let ticker = {
            let driver = f.driver.clone();
            let storage = f.storage.clone();
            let stop = stop.clone();
            let peers = peers.clone();
            let wake = driver.wake_handle();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(TICK_INTERVAL);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                while !stop.load(Ordering::Relaxed) {
                    tokio::select! {
                        _ = interval.tick() => {}
                        _ = wake.notified() => {}
                    }
                    let _ = driver.tick(&storage, n, &peers).await;
                }
            })
        };
        // Admission worker, like the node's.
        let (admit_tx, mut admit_rx) = mpsc::channel::<ReceivedBlocks>(ADMIT_QUEUE);
        let worker = {
            let driver = f.driver.clone();
            let admission = f.admission.clone();
            let storage = f.storage.clone();
            tokio::spawn(async move {
                let mut orphans: Vec<Block> = Vec::new();
                while let Some(r) = admit_rx.recv().await {
                    driver
                        .admit_received(&admission, &storage, &mut orphans, r, n, |_| {})
                        .await;
                }
            })
        };
        // Receive side: one task, like the network loop.
        let mut received_blocks = 0u64;
        let mut validate_secs = 0f64;
        let mut distinct: BTreeSet<Hash> = BTreeSet::new();
        let applied = || {
            f.storage
                .blocks
                .get_applied_tip()
                .ok()
                .flatten()
                .map(|(_, h)| h)
                .unwrap_or(0)
        };
        while applied() < n && start.elapsed() < deadline {
            let msg = tokio::time::timeout(Duration::from_millis(200), inbound.recv()).await;
            let Ok(Some((pid, msg))) = msg else { continue };
            match msg {
                NetworkMessage::Blocks { blocks } => {
                    received_blocks += blocks.len() as u64;
                    for b in &blocks {
                        distinct.insert(b.header.block_hash);
                    }
                    let t = Instant::now();
                    let r = f.driver.receive_blocks(&pid, blocks).await;
                    validate_secs += t.elapsed().as_secs_f64();
                    if admit_tx.send(r).await.is_err() {
                        break;
                    }
                }
                NetworkMessage::Headers { headers } => {
                    f.driver.ingest_headers(&pid, headers).await;
                }
                _ => {}
            }
        }
        let secs = start.elapsed().as_secs_f64();
        stop.store(true, Ordering::Relaxed);
        drop(admit_tx);
        let _ = worker.await;
        let _ = ticker.await;
        let _ = sampler.await;
        Outcome {
            applied: applied(),
            secs,
            rss_start_kb,
            rss_peak_kb: peak.load(Ordering::Relaxed),
            received_blocks,
            distinct_blocks: distinct.len() as u64,
            validate_secs,
        }
    }

    fn env_u64(name: &str, default: u64) -> u64 {
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    /// A full admission queue does not hold the caller: the response is
    /// dropped after the bounded wait and its range is asked again.
    #[tokio::test]
    async fn a_full_admission_queue_drops_the_response_and_re_plans_its_range() {
        let chain = build_chain(40).await;
        let serve_dir = tempfile::tempdir().expect("tempdir");
        let serving = store_with(&chain, serve_dir.path());
        let node_dir = tempfile::tempdir().expect("tempdir");
        let f = follower(&chain, node_dir.path()).await;
        let (in_tx, mut in_rx) = mpsc::channel::<(PeerId, NetworkMessage)>(16);
        let wire = Arc::new(std::sync::Mutex::new(Wire::default()));
        let peer = spawn_peer("p", Behaviour::Honest, 40, serving, in_tx, wire.clone());
        let peers = vec![peer];
        f.driver.tick(&f.storage, 40, &peers).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let get_blocks_before = wire.lock().expect("wire").get_blocks;
        assert_eq!(get_blocks_before, 1);
        // Take the Blocks answer (headers may come first).
        let blocks = loop {
            let (_, msg) = in_rx.recv().await.expect("answer");
            if let NetworkMessage::Blocks { blocks } = msg {
                break blocks;
            }
        };
        let r = f.driver.receive_blocks(&PeerId("p".into()), blocks).await;
        assert!(matches!(r.matched, BlocksMatch::Range { .. }));
        // A queue with no room.
        let (tx, _rx) = mpsc::channel::<ReceivedBlocks>(1);
        tx.try_send(ReceivedBlocks {
            pid: PeerId("x".into()),
            matched: BlocksMatch::Unsolicited,
            validated: Vec::new(),
        })
        .expect("fill");
        let t = Instant::now();
        let out = f
            .driver
            .hand_to_admission(&tx, r, Duration::from_millis(50))
            .await;
        assert_eq!(out, Handoff::Dropped);
        assert!(t.elapsed() < Duration::from_secs(2), "the caller was held");
        // The dropped range is requested again.
        f.driver.tick(&f.storage, 40, &peers).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            wire.lock().expect("wire").get_blocks,
            get_blocks_before + 1,
            "the dropped range was not asked again"
        );
        assert_eq!(f.driver.sync().range_counters().duplicate_requests, 0);
    }

    /// Catch-up floor, applied blocks per second. The old driver could not
    /// exceed one 32-block range per 2 s tick (~15.5 blocks/s) in any build.
    fn min_blocks_per_sec() -> f64 {
        if cfg!(debug_assertions) {
            20.0
        } else {
            200.0
        }
    }

    /// Always-on: 2,000 blocks (debug-build friendly).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fresh_node_syncs_from_three_peers_one_faulty_without_duplicate_requests() {
        multi_peer_catch_up(env_u64("CITRATE_SYNC_TEST_BLOCKS", 2_000)).await;
    }

    /// The full 20k-block run. Slow in a debug build; run it in release:
    /// `cargo test --release -p citrate-node --bin citrate catch_up_20k -- --ignored --nocapture`
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "20k blocks: run in release (see doc comment)"]
    async fn catch_up_20k_blocks_from_three_peers_one_faulty() {
        multi_peer_catch_up(env_u64("CITRATE_SYNC_TEST_BLOCKS", 20_000)).await;
    }

    /// One misbehaving peer, sorted first, and two honest peers. Catch-up
    /// must still complete, on the right tip and state, within the same
    /// throughput bound as the faulty-peer run.
    async fn adversarial_catch_up(n: u64, bad: Behaviour) {
        let chain = build_chain(n).await;
        let serve_dir = tempfile::tempdir().expect("tempdir");
        let serving = store_with(&chain, serve_dir.path());
        let node_dir = tempfile::tempdir().expect("tempdir");
        let f = follower(&chain, node_dir.path()).await;
        let (in_tx, in_rx) = mpsc::channel::<(PeerId, NetworkMessage)>(4096);
        let wire = Arc::new(std::sync::Mutex::new(Wire::default()));
        let peers = vec![
            spawn_peer(
                "peer-a",
                bad,
                n,
                serving.clone(),
                in_tx.clone(),
                wire.clone(),
            ),
            spawn_peer(
                "peer-b",
                Behaviour::Honest,
                n,
                serving.clone(),
                in_tx.clone(),
                wire.clone(),
            ),
            spawn_peer(
                "peer-c",
                Behaviour::Honest,
                n,
                serving.clone(),
                in_tx.clone(),
                wire.clone(),
            ),
        ];
        let floor = min_blocks_per_sec();
        let deadline = Duration::from_secs_f64(n as f64 / floor * 1.5 + 10.0);
        let out = run_sync(&f, peers, in_rx, n, deadline).await;
        let w = wire.lock().expect("wire");
        let c = f.driver.sync().range_counters();
        println!(
            "SYNCBENCH {bad:?} n={n} applied={} secs={:.1} get_blocks={} get_headers={} \
             faulty_get_blocks={} scheduler={c:?}",
            out.applied, out.secs, w.get_blocks, w.get_headers, w.faulty_get_blocks
        );
        assert_eq!(
            out.applied, n,
            "{bad:?}: follower stopped at {} of {n} after {:.0}s",
            out.applied, out.secs
        );
        let tip = chain.blocks.last().expect("non-empty chain");
        let (tip_hash, _) = f.storage.blocks.get_applied_tip().unwrap().unwrap();
        assert_eq!(tip_hash, tip.header.block_hash);
        assert_eq!(f.executor.calculate_state_root(), tip.state_root);
        // Header requests stay proportional to the chain, not to time.
        assert!(
            w.get_headers <= n,
            "{bad:?}: {} GetHeaders for {n} blocks",
            w.get_headers
        );
    }

    /// A peer that answers its ranges with blocks that do not link to our
    /// chain (right heights, own key, unknown parent) must not hold catch-up.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn catch_up_completes_with_a_peer_serving_non_linking_blocks() {
        adversarial_catch_up(
            env_u64("CITRATE_SYNC_TEST_ADV_BLOCKS", 1_500),
            Behaviour::Forger,
        )
        .await;
    }

    /// A header source whose hashes belong to other heights must not hold
    /// catch-up or drive a header-request storm.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn catch_up_completes_with_a_header_source_whose_hashes_are_for_other_heights() {
        adversarial_catch_up(
            env_u64("CITRATE_SYNC_TEST_ADV_BLOCKS", 1_500),
            Behaviour::HeaderLiar,
        )
        .await;
    }

    async fn multi_peer_catch_up(n: u64) {
        let chain = build_chain(n).await;
        let serve_dir = tempfile::tempdir().expect("tempdir");
        let serving = store_with(&chain, serve_dir.path());
        let node_dir = tempfile::tempdir().expect("tempdir");
        let f = follower(&chain, node_dir.path()).await;

        let (in_tx, in_rx) = mpsc::channel::<(PeerId, NetworkMessage)>(4096);
        let wire = Arc::new(std::sync::Mutex::new(Wire::default()));
        let peers = vec![
            // The faulty peer sorts first, so on equal standing it is the
            // preferred source until it proves otherwise: the worst case.
            spawn_peer(
                "peer-a",
                Behaviour::EmptyOrSilent,
                n,
                serving.clone(),
                in_tx.clone(),
                wire.clone(),
            ),
            spawn_peer(
                "peer-b",
                Behaviour::Honest,
                n,
                serving.clone(),
                in_tx.clone(),
                wire.clone(),
            ),
            spawn_peer(
                "peer-c",
                Behaviour::Honest,
                n,
                serving.clone(),
                in_tx.clone(),
                wire.clone(),
            ),
        ];
        // The deadline is what the throughput floor allows, plus slack.
        let floor = min_blocks_per_sec();
        let deadline = Duration::from_secs_f64(n as f64 / floor * 1.5 + 10.0);
        let out = run_sync(&f, peers, in_rx, n, deadline).await;
        let w = wire.lock().expect("wire");
        let c = f.driver.sync().range_counters();
        println!("SYNCBENCH scheduler {c:?}");
        let bps = out.applied as f64 / out.secs;
        println!(
            "SYNCBENCH n={n} applied={} secs={:.1} blocks_per_sec={:.1} rss_start_mb={:.0} \
             rss_peak_mb={:.0} get_blocks={} get_headers={} duplicate_get_blocks={} \
             faulty_get_blocks={} blocks_sent={} received={} distinct={} validate_secs={:.2}",
            out.applied,
            out.secs,
            bps,
            out.rss_start_kb as f64 / 1024.0,
            out.rss_peak_kb as f64 / 1024.0,
            w.get_blocks,
            w.get_headers,
            w.duplicate_get_blocks,
            w.faulty_get_blocks,
            w.blocks_sent,
            out.received_blocks,
            out.distinct_blocks,
            out.validate_secs,
        );

        // Reached the tip, on the right block, with the right state.
        assert_eq!(out.applied, n, "follower stopped at {} of {n}", out.applied);
        let tip = chain.blocks.last().expect("non-empty chain");
        let (tip_hash, _) = f.storage.blocks.get_applied_tip().unwrap().unwrap();
        assert_eq!(tip_hash, tip.header.block_hash);
        assert_eq!(f.executor.calculate_state_root(), tip.state_root);
        for b in &chain.blocks {
            assert_eq!(
                f.storage
                    .state
                    .get_state_root(&b.header.block_hash)
                    .unwrap(),
                Some(b.state_root),
                "persisted state root at height {}",
                b.header.height
            );
        }
        // Throughput floor.
        assert!(
            bps >= floor,
            "catch-up ran at {bps:.1} blocks/s, floor is {floor}"
        );
        // No request asked for data a peer had already sent.
        assert_eq!(w.duplicate_get_blocks, 0, "duplicate GetBlocks on the wire");
        assert_eq!(
            c.duplicate_requests, 0,
            "scheduler issued an overlapping range"
        );
        // The faulty peer was used and routed around: its ranges came back
        // empty or timed out and were served by someone else.
        assert!(w.faulty_get_blocks > 0, "faulty peer never asked");
        assert!(
            c.timeouts > 0 && c.empty_responses > 0,
            "faulty peer's failures not seen"
        );
        assert!(
            c.retries > 0,
            "faulty peer's ranges were never re-requested"
        );
    }
}
