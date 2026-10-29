// citrate/node/src/split_heal_tests.rs
//
// Producers on separate branches must merge back without operator action.
//
// THE FAILURE (r1006, 2026-10-29, height 86,473): the seven producers split
// into seven branches within seconds and each extended only its own from then
// on. Peers' new blocks waited on parents the node never fetched, sync rounds
// against equal-height peers asked nothing, and restarts did not help.
//
// This harness runs seven producers through the code the node runs:
// `BlockProducer::produce_block` (with the catch-up gate and the attested /
// deferred evidence wired as `start_node` wires them), `BlockAdmission::admit`
// for gossip, the `Blocks` handler's steps (`SyncManager::handle_blocks`,
// the fork-point tracker, `admit_to_fixpoint` with the orphan buffer, the
// missing-parent walk, the serve credit), the 2 s sync tick (peer selection,
// anchor, `request_blocks`), `block_serve::serve_blocks` for every answer,
// and the periodic drain. Requests and answers travel as real
// `NetworkMessage`s through each node's `Peer` handles; a message on a down
// link is lost, exactly like a dropped frame. Nothing is retried that the node
// would not retry itself.
//
// Post-activation: blocks are past the validator activation height, the DAG
// store judges stake-gated eligibility with a production VRF selector over the
// seven producers, the producers sign the equivocation-vote sidecar, and the
// executor settles with a reward policy. The rules that are process-wide (the
// block-validity hardening, active from block 1 on r1006) are switched on in a
// child process so no other test in this binary sees them. Checkpoint finality
// is not wired: its voting pin is off for every chain in this release.
//
// `main_loop_mirrors_the_harness` fails if main.rs stops making the calls the
// harness makes.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use citrate_consensus::crypto::Ed25519SigningKey;
use citrate_consensus::dag_store::DagStore;
use citrate_consensus::ghostdag::GhostDag;
use citrate_consensus::types::{Block, BlockBuilder, GhostDagParams, Hash, PublicKey, VrfProof};
use citrate_consensus::vrf::VrfProposerSelector;
use citrate_execution::{Executor, StateDB};
use citrate_network::peer::{Direction, Peer, PeerInfo, PeerState};
use citrate_network::sync::{SyncConfig, SyncManager};
use citrate_network::{NetworkMessage, PeerId};
use citrate_sequencer::mempool::{Mempool, MempoolConfig};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use primitive_types::U256;
use tempfile::TempDir;
use tokio::sync::mpsc;

use crate::admission::{self, AdmitOutcome, BlockAdmission};
use crate::block_serve;
use crate::canonical_apply::CanonicalApplicator;
use crate::producer::{AttestedNetworkHead, BlockProducer, EquivocationVoteConfig};
use crate::sync_peer;
use crate::sync_recovery;
use crate::sync_rejoin;

const CHAIN_ID: u64 = 40204;
/// Validator activation height (r1006: 1000). Every block after the warm-up
/// is past it; the code paths are the same at any height.
const ACT: u64 = 8;
const REG: [u8; 20] = [0x99; 20];
const MIN_STAKE: u128 = 32_000;
const STAKE: u128 = 40_000;
/// Messages processed per pump before the harness calls it a storm.
const PUMP_CAP: usize = 200_000;

fn key(i: usize) -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[0x60 + i as u8; 32])
}

fn proposer(i: usize) -> [u8; 32] {
    key(i).verifying_key().to_bytes()
}

fn coinbase(i: usize) -> [u8; 20] {
    [0x10 + i as u8; 20]
}

fn embedded(addr: [u8; 20]) -> PublicKey {
    let mut b = [0u8; 32];
    b[..20].copy_from_slice(&addr);
    PublicKey::new(b)
}

fn short(h: &Hash) -> String {
    hex::encode(&h.as_bytes()[..4])
}

/// What the run looks like.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Scenario {
    pub producers: usize,
    /// Slots before the partition (everyone connected).
    pub warmup: u64,
    /// Slots of the partition into singletons (one slot = one 2 s tick).
    pub partition: u64,
    /// Slots allowed after the heal for the fleet to agree.
    pub heal_rounds: u64,
    /// Before the partition, one gossip block per producer reaches nobody, and
    /// one `Blocks` answer carries a block whose parent no peer will ever serve:
    /// the state of a node that has been running for a while (its orphan
    /// buffer is never empty again).
    pub long_running: bool,
}

struct Node {
    name: String,
    storage: Arc<StorageManager>,
    app: Arc<CanonicalApplicator>,
    adm: Arc<BlockAdmission>,
    producer: BlockProducer,
    sync: SyncManager,
    rejoin: parking_lot::Mutex<sync_rejoin::RejoinTracker>,
    sel: sync_peer::SyncPeerSelector,
    walk: sync_recovery::ParentWalks,
    orphans: Vec<Block>,
    attested: AttestedNetworkHead,
    max_seen: AtomicU64,
    /// This node's handle on each remote (None for itself), with the queue of
    /// messages it sent that way.
    peers: Vec<Option<(Arc<Peer>, mpsc::Receiver<NetworkMessage>)>>,
    rotate_idx: u64,
    diverge_idx: u64,
    _dir: TempDir,
}

pub(crate) struct Fleet {
    nodes: Vec<Node>,
    /// links[i][j]: messages from i reach j.
    links: Vec<Vec<bool>>,
    genesis: Block,
    /// Messages lost on down links (diagnostics).
    pub lost: usize,
}

fn genesis_block(root: Hash) -> Block {
    let mut g = BlockBuilder::new()
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
        .state_root(root)
        .blue_score(0)
        .blue_work(citrate_consensus::types::blue_work_for_score(0))
        .build_unhashed();
    g.header.block_hash = g.compute_hash();
    g
}

fn policy(n: usize) -> citrate_execution::block_rewards::EpochRewardPolicy {
    let mut staker_of = HashMap::new();
    for i in 0..n {
        staker_of.insert(proposer(i), coinbase(i));
    }
    citrate_execution::block_rewards::EpochRewardPolicy {
        epoch: 1,
        snapshot_height: 0,
        activation_height: ACT,
        registry: REG,
        reward_minter: citrate_execution::block_rewards::REWARD_MINTER_ADDRESS,
        priority_fee_share_bps: 2500,
        block_subsidy: U256::zero(),
        staker_of,
    }
}

impl Fleet {
    pub(crate) async fn new(n: usize) -> Self {
        let empty_root = Executor::new(Arc::new(StateDB::new())).calculate_state_root();
        let genesis = genesis_block(empty_root);
        let mut nodes = Vec::new();
        for i in 0..n {
            let dir = TempDir::new().expect("tempdir");
            let storage = Arc::new(
                StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"),
            );
            let executor = Arc::new(Executor::with_storage_and_chain_id(
                Arc::new(StateDB::new()),
                Some(storage.state.clone()),
                CHAIN_ID,
            ));
            executor.set_validator_activation_height(ACT);
            *executor.reward_policy_handle().write() = Some(policy(n));
            // As start_node: the production selector, the activation height on
            // the DAG store, strict VRF.
            let selector = Arc::new(VrfProposerSelector::production());
            selector
                .sync_active_set(
                    (0..n)
                        .map(|j| (PublicKey::new(proposer(j)), STAKE))
                        .collect(),
                    MIN_STAKE,
                )
                .await;
            let dag = Arc::new(
                DagStore::with_strict_vrf(true)
                    .with_proposer_selector(selector)
                    .with_enforcement_activation_height(ACT),
            );
            let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag.clone()));
            storage.blocks.put_block(&genesis).expect("genesis");
            storage
                .blocks
                .put_applied_tip(&genesis.header.block_hash, 0)
                .expect("genesis tip");
            dag.set_configured_genesis(genesis.header.block_hash);
            dag.store_block(genesis.clone()).await.expect("genesis dag");
            ghostdag
                .add_block(&genesis)
                .await
                .expect("genesis ghostdag");
            let app = Arc::new(
                CanonicalApplicator::new(executor.clone(), storage.clone())
                    .with_fork_choice(ghostdag.clone()),
            );
            app.set_genesis(
                Executor::new(Arc::new(StateDB::new())).state_snapshot(),
                genesis.header.block_hash,
            );
            ghostdag.reconcile_tips_from_dag_store().await;
            let adm = Arc::new(BlockAdmission::new(
                storage.clone(),
                dag.clone(),
                ghostdag.clone(),
                Some(app.clone()),
            ));
            let mempool = Arc::new(Mempool::new(MempoolConfig {
                require_valid_signature: false,
                ..Default::default()
            }));
            let attested = AttestedNetworkHead::new();
            let producer = BlockProducer::with_shared_dag(
                storage.clone(),
                executor,
                mempool,
                None,
                embedded(coinbase(i)),
                key(i),
                2,
                Arc::new(citrate_economics::UnifiedEconomicsManager::new(
                    citrate_economics::UnifiedEconomicsConfig::default(),
                )),
                dag,
                ghostdag,
            )
            .await
            .with_v2_headers(true)
            .with_applied_tip_lock(app.advance_lock())
            .with_equivocation_vote_config(EquivocationVoteConfig {
                chain_id: CHAIN_ID,
                registry: REG,
                activation_height: ACT,
            })
            .with_produce_catchup_gate(&app)
            .with_network_height_gate(&attested);
            let sync = SyncManager::new(SyncConfig::default())
                .with_local_height(app.applied_height_handle());
            nodes.push(Node {
                name: format!("p{i}"),
                storage,
                app,
                adm,
                producer,
                sync,
                rejoin: parking_lot::Mutex::new(sync_rejoin::RejoinTracker::new()),
                sel: sync_peer::SyncPeerSelector::new(),
                walk: sync_recovery::ParentWalks::new(),
                orphans: Vec::new(),
                attested,
                max_seen: AtomicU64::new(0),
                peers: Vec::new(),
                rotate_idx: 0,
                diverge_idx: 0,
                _dir: dir,
            });
        }
        let names: Vec<String> = nodes.iter().map(|n| n.name.clone()).collect();
        for (i, node) in nodes.iter_mut().enumerate() {
            for (j, name) in names.iter().enumerate() {
                if i == j {
                    node.peers.push(None);
                    continue;
                }
                let (tx, rx) = mpsc::channel(1 << 16);
                let (_in_tx, in_rx) = mpsc::channel(1);
                let mut info = PeerInfo::new(
                    PeerId::new(name.clone()),
                    "127.0.0.1:1".parse().expect("addr"),
                    Direction::Outbound,
                );
                info.state = PeerState::Connected;
                node.peers
                    .push(Some((Arc::new(Peer::new(info, tx, in_rx)), rx)));
            }
        }
        let mut fleet = Self {
            links: Vec::new(),
            nodes,
            genesis,
            lost: 0,
        };
        fleet.links = vec![vec![false; n]; n];
        fleet.set_links(|_, _| true);
        fleet
    }

    pub(crate) fn set_links(&mut self, up: impl Fn(usize, usize) -> bool) {
        let n = self.nodes.len();
        for i in 0..n {
            for j in 0..n {
                self.links[i][j] = i != j && up(i, j);
            }
        }
    }

    fn index_of(&self, name: &str) -> usize {
        self.nodes
            .iter()
            .position(|n| n.name == name)
            .expect("known peer")
    }

    fn peer(&self, at: usize, remote: usize) -> Arc<Peer> {
        self.nodes[at].peers[remote]
            .as_ref()
            .map(|(p, _)| p.clone())
            .expect("peer handle")
    }

    /// Everything node `i` has sent, as (from, to, message); lost on down links.
    fn outbox(&mut self) -> Vec<(usize, usize, NetworkMessage)> {
        let mut out = Vec::new();
        for i in 0..self.nodes.len() {
            for j in 0..self.nodes.len() {
                let Some((_, rx)) = self.nodes[i].peers[j].as_mut() else {
                    continue;
                };
                while let Ok(m) = rx.try_recv() {
                    if self.links[i][j] {
                        out.push((i, j, m));
                    } else {
                        self.lost += 1;
                    }
                }
            }
        }
        out
    }

    /// Deliver messages until none are left in flight.
    async fn pump(&mut self) {
        let mut queue: VecDeque<(usize, usize, NetworkMessage)> = self.outbox().into();
        let mut handled = 0usize;
        while let Some((from, to, msg)) = queue.pop_front() {
            handled += 1;
            assert!(
                handled < PUMP_CAP,
                "message storm: {handled} messages in one pump"
            );
            self.receive(to, from, msg).await;
            queue.extend(self.outbox());
        }
    }

    /// One message, through the steps `start_node`'s receive loop runs for it.
    async fn receive(&mut self, at: usize, from: usize, msg: NetworkMessage) {
        let pid = PeerId::new(self.nodes[from].name.clone());
        let peer = self.peer(at, from);
        let node = &mut self.nodes[at];
        match msg {
            NetworkMessage::GetBlocks {
                from: anchor,
                count,
                ..
            } => {
                let blocks = block_serve::serve_blocks(&node.storage, &anchor, count);
                let _ = peer.send(NetworkMessage::Blocks { blocks }).await;
            }
            NetworkMessage::GetHeaders {
                from: anchor,
                count,
            } => {
                let headers = block_serve::serve_headers(&node.storage, &anchor, count);
                let _ = peer.send(NetworkMessage::Headers { headers }).await;
            }
            NetworkMessage::Headers { headers } => {
                let _ = node.sync.handle_headers(&pid, headers).await;
            }
            NetworkMessage::NewBlock { block } => node.on_new_block(&peer, block).await,
            NetworkMessage::Blocks { blocks } => node.on_blocks(&peer, &pid, blocks).await,
            _ => {}
        }
    }

    /// One slot: every producer tries to seal (random order), its block is
    /// gossiped, then each node runs its sync tick and its drain.
    pub(crate) async fn slot(&mut self, order: &[usize]) -> Vec<(usize, Block)> {
        let mut produced = Vec::new();
        for &i in order {
            let Ok(h) = self.nodes[i].producer.produce_block().await else {
                continue;
            };
            let b = self.nodes[i]
                .storage
                .blocks
                .get_block(&h)
                .expect("read produced")
                .expect("produced stored");
            for j in 0..self.nodes.len() {
                if j != i {
                    let _ = self
                        .peer(i, j)
                        .send(NetworkMessage::NewBlock { block: b.clone() })
                        .await;
                }
            }
            produced.push((i, b));
            self.pump().await;
        }
        for i in 0..self.nodes.len() {
            let linked: Vec<usize> = (0..self.nodes.len())
                .filter(|&j| self.links[i][j] && self.links[j][i])
                .collect();
            let peers: Vec<Arc<Peer>> = linked.iter().map(|&j| self.peer(i, j)).collect();
            self.nodes[i].tick(&peers).await;
            self.pump().await;
        }
        for n in &self.nodes {
            n.app.drive_drain().await;
        }
        produced
    }

    /// The selected chain from node `i`'s applied tip: height -> hash.
    pub(crate) async fn chain(&self, i: usize) -> HashMap<u64, Hash> {
        let n = &self.nodes[i];
        let mut chain = HashMap::new();
        let mut cur = n.app.applied_tip().await.hash;
        loop {
            let b = n
                .storage
                .blocks
                .get_block(&cur)
                .expect("read")
                .expect("selected chain block stored");
            chain.insert(b.header.height, cur);
            if b.header.height == 0 {
                break;
            }
            cur = b.header.selected_parent_hash;
        }
        chain
    }

    /// Every block in the past of node `i`'s applied tip (selected and merge
    /// parents), as proposer index -> count.
    pub(crate) async fn past_by_producer(&self, i: usize) -> HashMap<usize, usize> {
        let n = &self.nodes[i];
        let by_cb: HashMap<[u8; 20], usize> =
            (0..self.nodes.len()).map(|j| (coinbase(j), j)).collect();
        let mut seen: HashSet<Hash> = HashSet::new();
        let mut stack = vec![n.app.applied_tip().await.hash];
        let mut out: HashMap<usize, usize> = HashMap::new();
        while let Some(h) = stack.pop() {
            if !seen.insert(h) {
                continue;
            }
            let Some(b) = n.storage.blocks.get_block(&h).expect("read") else {
                continue;
            };
            if b.header.height == 0 {
                continue;
            }
            if let Some(&j) = by_cb.get(&b.header.coinbase) {
                *out.entry(j).or_default() += 1;
            }
            stack.push(b.header.selected_parent_hash);
            stack.extend(b.header.merge_parent_hashes.iter().copied());
        }
        out
    }

    /// Whether all nodes' selected chains agree at `height`.
    pub(crate) async fn agree_at(&self, height: u64) -> Option<Hash> {
        let first = self.chain(0).await.get(&height).copied()?;
        for i in 1..self.nodes.len() {
            if self.chain(i).await.get(&height) != Some(&first) {
                return None;
            }
        }
        Some(first)
    }

    pub(crate) async fn applied_heights(&self) -> Vec<u64> {
        let mut out = Vec::new();
        for n in &self.nodes {
            out.push(n.app.applied_tip().await.height);
        }
        out
    }

    pub(crate) async fn describe(&self) -> String {
        let mut s = String::new();
        for n in &self.nodes {
            let t = n.app.applied_tip().await;
            s.push_str(&format!(
                "{}: applied {}@{} orphans={} stored_tip={:?}; ",
                n.name,
                short(&t.hash),
                t.height,
                n.orphans.len(),
                n.storage.blocks.get_latest_height().ok()
            ));
        }
        s
    }
}

impl Node {
    fn applied(&self) -> (Hash, u64) {
        self.storage
            .blocks
            .get_applied_tip()
            .ok()
            .flatten()
            .unwrap_or((Hash::new([0u8; 32]), 0))
    }

    /// main.rs `NetworkMessage::NewBlock` arm (gossip validation and relay
    /// aside: the harness is a full mesh and its blocks are honest).
    async fn on_new_block(&mut self, peer: &Arc<Peer>, block: Block) {
        {
            let mut info = peer.info.write().await;
            if block.header.height > info.head_height {
                info.head_height = block.header.height;
                info.head_hash = block.header.block_hash;
            }
        }
        if self.adm.is_fully_admitted(&block.header.block_hash).await {
            return;
        }
        match self.adm.admit(&block).await {
            AdmitOutcome::Admitted { .. } => {
                sync_peer::record_verified_height(&self.max_seen, block.header.height);
                self.attested.observe(&self.storage, &block);
            }
            AdmitOutcome::AlreadyAdmitted => {}
            AdmitOutcome::Deferred { missing_parent } => {
                self.attested.observe_deferred(&block);
                let applied_now = self.applied().1;
                sync_peer::record_unverified_height(
                    &self.max_seen,
                    block.header.height,
                    applied_now,
                );
                if sync_peer::should_attempt_ancestry_recovery(block.header.height, applied_now) {
                    let _ = self
                        .sync
                        .request_blocks(peer, missing_parent, block.header.height.saturating_sub(1))
                        .await;
                }
            }
            AdmitOutcome::Rejected(why) => {
                panic!(
                    "{} rejected gossip block {} @ {}: {why}",
                    self.name,
                    short(&block.header.block_hash),
                    block.header.height
                );
            }
        }
    }

    /// main.rs `NetworkMessage::Blocks` arm.
    async fn on_blocks(&mut self, peer: &Arc<Peer>, pid: &PeerId, blocks: Vec<Block>) {
        let answer_hashes: Vec<Hash> = blocks.iter().map(|b| b.header.block_hash).collect();
        let _ = self.sync.handle_blocks(pid, blocks).await;
        let mut pending = self.sync.drain_validated_blocks().await;
        let verified: HashSet<Hash> = pending.iter().map(|b| b.header.block_hash).collect();
        let answers_rejoin = self
            .rejoin
            .lock()
            .take_answer(&pid.0, &answer_hashes, &verified);
        let reprocessed = !pending.is_empty();
        if reprocessed {
            pending.append(&mut self.orphans);
            pending = admission::bound_orphan_buffer(pending);
        }
        let storage = self.storage.clone();
        let attested = self.attested.clone();
        let fx = self
            .adm
            .admit_to_fixpoint(pending, |b, _| {
                attested.observe(&storage, b);
            })
            .await;
        let newly_admitted = fx.newly_admitted;
        let highest = fx.highest_admitted;
        let deferred_from_answer = fx
            .deferred
            .iter()
            .filter(|b| verified.contains(&b.header.block_hash))
            .count();
        let lowest_deferred = {
            let from_answer: Vec<&Block> = fx
                .deferred
                .iter()
                .filter(|b| verified.contains(&b.header.block_hash))
                .collect();
            sync_recovery::lowest_deferred(&self.storage, &from_answer)
        };
        if reprocessed {
            self.orphans = admission::bound_orphan_buffer(fx.deferred);
        }
        let applied_now = self.applied().1;
        let target = self.max_seen.load(Ordering::Relaxed);
        let gap = target.saturating_sub(applied_now);
        let stale_anchor = sync_recovery::answer_anchor_was_stale(
            self.sync.last_block_anchor_height(),
            applied_now,
            answer_hashes.len(),
        );
        if let Some((parent, parent_height)) = self.walk.next(
            &pid.0,
            lowest_deferred,
            !self.orphans.is_empty(),
            newly_admitted > 0,
            applied_now,
            std::time::Instant::now(),
        ) {
            let sent = self
                .sync
                .request_blocks(peer, parent, parent_height)
                .await
                .unwrap_or(false);
            if !sent {
                self.walk.unsent(&pid.0);
            }
        }
        let mut gave_up = false;
        if let Some(anchor_height) = answers_rejoin {
            let answer = sync_rejoin::classify(
                answer_hashes.is_empty(),
                newly_admitted,
                highest,
                deferred_from_answer,
            );
            let t = self.rejoin.lock().on_answer(answer, gap > 0, anchor_height);
            gave_up = matches!(t, Some(sync_rejoin::Transition::GaveUp { .. }));
        }
        self.sel.record_serve(
            &pid.0,
            newly_admitted,
            highest.map(|(_, h)| h).unwrap_or(0),
            gap,
            32,
            stale_anchor,
        );
        if gave_up {
            self.sel.record_give_up(&pid.0);
        }
    }

    /// main.rs periodic sync tick, over the peers this node is connected to.
    async fn tick(&mut self, connected: &[Arc<Peer>]) {
        let mut best_h = 0u64;
        let mut candidates = Vec::new();
        let mut heads = Vec::new();
        for p in connected {
            let info = p.info.read().await;
            best_h = best_h.max(info.head_height);
            candidates.push(sync_peer::SyncCandidate {
                id: info.id.0.clone(),
                head_height: info.head_height,
            });
            heads.push(sync_peer::HeadView {
                head_height: info.head_height,
                head_held: info.head_hash == Hash::default()
                    || self
                        .storage
                        .blocks
                        .has_block(&info.head_hash)
                        .unwrap_or(false),
            });
        }
        let seen = self.max_seen.load(Ordering::Relaxed);
        let applied_tip = self.applied();
        let applied_height = applied_tip.1;
        let target = best_h
            .max(seen)
            .min(applied_height.saturating_add(10_000_000));
        if target > 0 {
            self.sync.set_target(target).await;
        }
        let chosen = self
            .sel
            .select(&candidates, applied_height)
            .map(|c| c.id.clone());
        let mut diverged = false;
        let request_peer = if let Some(id) = chosen {
            connected
                .iter()
                .zip(candidates.iter())
                .find(|(_, c)| c.id == id)
                .map(|(p, _)| p.clone())
        } else if applied_height < target && !connected.is_empty() {
            let i = (self.rotate_idx as usize) % connected.len();
            self.rotate_idx = self.rotate_idx.wrapping_add(1);
            connected.get(i).cloned()
        } else if let Some(i) =
            sync_peer::diverged_source(&heads, applied_height, &mut self.diverge_idx)
        {
            diverged = true;
            connected.get(i).cloned()
        } else {
            None
        };
        if let Some(peer) = request_peer {
            self.rejoin.lock().note_sync_target(target, applied_tip.1);
            self.rejoin.lock().note_diverged(diverged);
            let (from, height) = self.rejoin.lock().anchor(applied_tip, |h| {
                sync_rejoin::anchor_at_height(&self.storage, h)
            });
            let (ph, pb) = self.sync.pending_counts().await;
            if ph < 8 {
                let _ = self.sync.request_headers(&peer, applied_tip.0).await;
            }
            if pb < 8 {
                if let Ok(true) = self.sync.request_blocks(&peer, from, height).await {
                    let pid = peer.info.read().await.id.clone();
                    let t = self.rejoin.lock().note_asked(&pid.0, (from, height));
                    if matches!(t, Some(sync_rejoin::Transition::GaveUp { .. })) {
                        self.sel.record_give_up(&pid.0);
                    }
                }
            }
        }
        for (_h, pid) in self.sync.check_timeouts().await {
            self.sel.record_timeout(&pid.0);
        }
    }
}

/// Fixed-seed xorshift for the production order.
pub(crate) struct Rng(u64);
impl Rng {
    pub(crate) fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub(crate) fn order(&mut self, n: usize) -> Vec<usize> {
        let mut o: Vec<usize> = (0..n).collect();
        for k in (1..n).rev() {
            o.swap(k, (self.next() % (k as u64 + 1)) as usize);
        }
        o
    }
}

/// What a run ended with.
#[derive(Debug)]
pub(crate) struct Outcome {
    /// Slots after the heal until the fleet agreed (None: never).
    pub agreed_after: Option<u64>,
    pub detail: String,
}

/// Warm up connected, partition into singletons, heal, and count the slots
/// until every node's selected chain agrees at a height above the partition
/// and every producer's partition blocks are in the agreed past.
pub(crate) async fn run(s: Scenario) -> Outcome {
    let mut fleet = Fleet::new(s.producers).await;
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..s.warmup {
        let o = rng.order(s.producers);
        fleet.slot(&o).await;
    }
    let warm = fleet.applied_heights().await;
    assert!(
        warm.iter().all(|h| *h > ACT),
        "warm-up must pass the activation height: {warm:?}"
    );
    let pre = *warm.iter().max().expect("nodes");
    if s.long_running {
        long_running_history(&mut fleet).await;
    }
    fleet.set_links(|_, _| false);
    let mut partition_blocks: HashMap<usize, HashSet<Hash>> = HashMap::new();
    for _ in 0..s.partition {
        let o = rng.order(s.producers);
        for (i, b) in fleet.slot(&o).await {
            partition_blocks
                .entry(i)
                .or_default()
                .insert(b.header.block_hash);
        }
    }
    let split_top = *fleet.applied_heights().await.iter().max().expect("nodes");
    fleet.set_links(|_, _| true);
    for round in 1..=s.heal_rounds {
        let o = rng.order(s.producers);
        fleet.slot(&o).await;
        let heights = fleet.applied_heights().await;
        let min_h = *heights.iter().min().expect("nodes");
        if min_h < split_top + 3 {
            continue;
        }
        let Some(_) = fleet.agree_at(min_h - 2).await else {
            continue;
        };
        let past = fleet.past_by_producer(0).await;
        let merged_all = (0..s.producers).all(|i| {
            partition_blocks
                .get(&i)
                .is_none_or(|own| !own.is_empty() && past.get(&i).copied().unwrap_or(0) > 0)
        });
        if merged_all {
            return Outcome {
                agreed_after: Some(round),
                detail: format!("pre={pre} split_top={split_top} {}", fleet.describe().await),
            };
        }
    }
    let mut detail = format!(
        "pre={pre} split_top={split_top} lost={} {}",
        fleet.lost,
        fleet.describe().await
    );
    for i in 0..s.producers {
        detail.push_str(&format!(
            "past[{i}]={:?}; ",
            fleet.past_by_producer(i).await
        ));
    }
    Outcome {
        agreed_after: None,
        detail,
    }
}

/// The ordinary history of a node that has been up for a while: one gossip
/// block per producer that reached nobody (healed by the next block), and one
/// `Blocks` answer carrying a block whose parent no peer holds any more.
async fn long_running_history(fleet: &mut Fleet) {
    let n = fleet.nodes.len();
    for i in 0..n {
        let Ok(h) = fleet.nodes[i].producer.produce_block().await else {
            continue;
        };
        let _ = h; // lost: never gossiped
        fleet.pump().await;
        let o: Vec<usize> = (0..n).collect();
        fleet.slot(&o).await;
    }
    // A block on a parent nobody will ever serve (a peer's discarded branch).
    let ghost_parent = genesis_block(Hash::new([0xEE; 32]));
    for i in 0..n {
        let from = (i + 1) % n;
        let mut b = BlockBuilder::new()
            .version(2)
            .height(fleet.nodes[i].applied().1)
            .parent(ghost_parent.header.block_hash)
            .coinbase(coinbase(from))
            .timestamp(chrono::Utc::now().timestamp().max(0) as u64)
            .vrf_reveal(VrfProof {
                proof: vec![],
                output: Hash::new([0x5B; 32]),
            })
            .transactions(vec![])
            .state_root(Hash::default())
            .blue_score(1)
            .blue_work(citrate_consensus::types::blue_work_for_score(1))
            .proposer(PublicKey::new(proposer(from)))
            .build_unhashed();
        b.tx_root = citrate_consensus::tx_auth::tx_root_for_height(
            citrate_consensus::hardening::PbaHardening::from_process(),
            b.header.height,
            &b.transactions,
        );
        b.header.block_hash = b.compute_hash();
        b.signature = citrate_consensus::crypto::sign_block(&b.header.block_hash, &key(from));
        let peer = fleet.peer(i, from);
        let pid = PeerId::new(fleet.nodes[from].name.clone());
        fleet.nodes[i].on_blocks(&peer, &pid, vec![b]).await;
        fleet.pump().await;
        assert!(
            !fleet.nodes[i].orphans.is_empty(),
            "the unservable block stays in the orphan buffer"
        );
    }
    let _ = fleet.genesis.header.height;
    let _ = fleet.index_of("p0");
}

/// Child-process switch: the block-validity hardening is process-wide, so the
/// post-activation runs execute in a child with it on (r1006: from block 1).
const CHILD_ENV: &str = "CITRATE_SPLIT_HEAL_CHILD";

fn run_in_child(test: &str) {
    let exe = std::env::current_exe().expect("exe");
    let out = std::process::Command::new(exe)
        .args([test, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, "1")
        .output()
        .expect("spawn child");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "child {test} failed:\n{stdout}\n{stderr}"
    );
}

fn in_child() -> bool {
    if std::env::var(CHILD_ENV).is_err() {
        return false;
    }
    citrate_consensus::hardening::set_pba_hardening_height(Some(0));
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seven_singletons() -> Scenario {
        Scenario {
            producers: 7,
            warmup: ACT + 4,
            partition: 30,
            heal_rounds: 40,
            long_running: false,
        }
    }

    /// (a) Seven producers past activation, a 60 s partition into seven
    /// singletons (30 slots of 2 s), then the links come back. Every node must
    /// agree on one selected chain within 40 slots, with every producer's
    /// partition blocks merged into its past. No operator action.
    #[tokio::test(flavor = "current_thread")]
    async fn seven_producers_partitioned_into_singletons_heal() {
        if !in_child() {
            return run_in_child(
                "split_heal_tests::tests::seven_producers_partitioned_into_singletons_heal",
            );
        }
        let out = run(seven_singletons()).await;
        assert!(
            out.agreed_after.is_some(),
            "seven producers did not re-merge after the partition: {}",
            out.detail
        );
    }

    /// Same, on nodes that have been up for a while (see `long_running`).
    #[tokio::test(flavor = "current_thread")]
    async fn seven_long_running_producers_partitioned_into_singletons_heal() {
        if !in_child() {
            return run_in_child(
                "split_heal_tests::tests::seven_long_running_producers_partitioned_into_singletons_heal",
            );
        }
        let out = run(Scenario {
            long_running: true,
            ..seven_singletons()
        })
        .await;
        assert!(
            out.agreed_after.is_some(),
            "long-running producers did not re-merge after the partition: {}",
            out.detail
        );
    }

    /// Tripwire: the harness mirrors main.rs's receive loop and sync tick. If
    /// main.rs stops making one of these calls, the harness no longer tests
    /// what the node runs.
    #[test]
    fn main_loop_mirrors_the_harness() {
        let main = include_str!("main.rs");
        for needle in [
            // Inbound routing: serve requests leave the receive loop.
            "serve_lane.route(",
            // NewBlock arm.
            "admission_for_net.admit(&block)",
            "attested_for_rx.observe_deferred(&block)",
            "sync_peer::should_attempt_ancestry_recovery(",
            // Blocks arm.
            "sync_for_rx.handle_blocks(&pid, blocks)",
            ".take_answer(",
            "admission::bound_orphan_buffer(",
            ".admit_to_fixpoint(pending,",
            "sync_recovery::lowest_deferred(",
            "parent_walks.next(",
            "parent_walks.unsent(&pid.0)",
            "sync_rejoin::classify(",
            "sel.record_serve(",
            // Sync tick.
            "sel.select(&candidates, applied_height)",
            "sync_peer::diverged_source(",
            ".note_diverged(",
            ".note_sync_target(target, applied_tip.1)",
            "rejoin_for_loop.lock().anchor(",
            ".note_asked(&pid.0, (block_from, block_height))",
        ] {
            assert!(
                main.contains(needle),
                "main.rs no longer contains `{needle}`"
            );
        }
    }

    /// (b) Two producers split at equal height, each with 10 blocks of its
    /// own: they converge.
    #[tokio::test(flavor = "current_thread")]
    async fn two_producers_equal_height_split_converge() {
        if !in_child() {
            return run_in_child(
                "split_heal_tests::tests::two_producers_equal_height_split_converge",
            );
        }
        let out = run(Scenario {
            producers: 2,
            warmup: ACT + 4,
            partition: 10,
            heal_rounds: 30,
            long_running: true,
        })
        .await;
        assert!(
            out.agreed_after.is_some(),
            "two producers did not converge: {}",
            out.detail
        );
    }
}
