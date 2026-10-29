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
#[derive(Clone, Debug)]
pub(crate) struct Scenario {
    pub producers: usize,
    /// Slots before the partition (everyone connected).
    pub warmup: u64,
    /// Before the partition, one gossip block per producer reaches nobody, and
    /// one `Blocks` answer carries a block whose parent no peer will ever serve:
    /// the state of a node that has been running for a while (its orphan
    /// buffer is never empty again).
    pub long_running: bool,
    /// The partition: groups that still reach each other (empty: singletons).
    pub groups: Vec<Vec<usize>>,
    /// Slots of the partition (one slot = one 2 s tick).
    pub partition: u64,
    /// Every producer restarts at the end of the partition.
    pub restart_all: bool,
    /// After the restart, only this producer comes up, for this many slots;
    /// the others then start (fresh processes) and every link is up.
    pub solo: Option<(usize, u64)>,
    /// After the heal, the producer with the lowest tip seals nothing (its seal
    /// gate holds it, or its gossip is shed), so nothing it sends announces its
    /// branch and no peer ever sees it ahead.
    pub quiet_after_heal: bool,
    /// The heal is a reconnect: the transport handshake gives each side the
    /// other's head, as `transport.rs` does on connect.
    pub reconnect: bool,
    /// Slots allowed after the heal.
    pub heal_rounds: u64,
    /// Every producer's partition blocks must end up in the agreed past.
    pub require_merged: bool,
    /// Every producer must be sealing again (a block in the last
    /// [`PRODUCING_WINDOW`] slots).
    pub require_producing: bool,
    /// Silent hostile peers per node: each connects to every node, answers
    /// nothing, and from the heal on gossips, every slot, a block it signed
    /// itself on a parent nobody holds (P1-1).
    pub sybils: usize,
}

/// See [`Scenario::require_producing`].
const PRODUCING_WINDOW: u64 = 3;

/// One slot of simulated time.
const SLOT: std::time::Duration = std::time::Duration::from_secs(2);

struct Node {
    name: String,
    storage: Arc<StorageManager>,
    executor: Arc<Executor>,
    app: Arc<CanonicalApplicator>,
    adm: Arc<BlockAdmission>,
    producer: BlockProducer,
    sync: SyncManager,
    rejoin: parking_lot::Mutex<sync_rejoin::RejoinTracker>,
    sel: sync_peer::SyncPeerSelector,
    walk: sync_recovery::ParentWalks,
    /// This process's peer table (the walk sends through it).
    pm: Arc<citrate_network::PeerManager>,
    orphans: Vec<Block>,
    attested: AttestedNetworkHead,
    max_seen: AtomicU64,
    /// The producer's initial-sync gate (`with_initial_sync_gate`).
    initial_sync: Arc<std::sync::atomic::AtomicBool>,
    /// Slot this process started at (the tick's `node_started_at`).
    started_slot: u64,
    /// Simulated monotonic time (one slot = [`SLOT`]), for every clock the
    /// recovery and pull paths read.
    clock: std::time::Instant,
    rotate_idx: u64,
    split_gate: sync_peer::SplitPullGate,
    /// Blocks this process has relayed (the gossip seen-cache).
    relayed: HashSet<Hash>,
    dir: TempDir,
}

/// A node's handle on a peer, and the queue of what it sent that peer.
type PeerLink = (Arc<Peer>, mpsc::Receiver<NetworkMessage>);

pub(crate) struct Fleet {
    nodes: Vec<Node>,
    /// peers[i][j]: node i's handle on node j, and the queue of what i sent j.
    peers: Vec<Vec<Option<PeerLink>>>,
    /// links[i][j]: messages from i reach j.
    links: Vec<Vec<bool>>,
    /// sybils[i]: node i's handles on the silent hostile peers, and what it
    /// sent them (dropped unanswered).
    sybils: Vec<Vec<PeerLink>>,
    /// Sybils gossip from now on.
    sybils_active: bool,
    /// Nodes not running.
    down: HashSet<usize>,
    /// Producers that seal nothing.
    quiet: HashSet<usize>,
    genesis: Block,
    /// Simulated time, in slots, from `epoch`.
    epoch: std::time::Instant,
    /// The same simulated time, in milliseconds, for the sync managers'
    /// request clocks (`SyncManager::with_clock_offset`).
    clock_ms: Arc<AtomicU64>,
    slot_no: u64,
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

impl Node {
    /// A node process as `start_node` wires one, on `storage` (fresh, or the
    /// store of a stopped process with its hydrated state `boot`).
    #[allow(clippy::too_many_arguments)]
    async fn start(
        i: usize,
        n: usize,
        genesis: &Block,
        storage: Arc<StorageManager>,
        dir: TempDir,
        boot: Option<citrate_execution::state::StateSnapshot>,
        slot_no: u64,
        clock: std::time::Instant,
        clock_ms: Arc<AtomicU64>,
    ) -> Self {
        if boot.is_none() {
            storage.blocks.put_block(genesis).expect("genesis");
            storage
                .blocks
                .put_applied_tip(&genesis.header.block_hash, 0)
                .expect("genesis tip");
        }
        let executor = Arc::new(Executor::with_storage_and_chain_id(
            Arc::new(StateDB::new()),
            Some(storage.state.clone()),
            CHAIN_ID,
        ));
        if let Some(state) = boot {
            executor.state_restore(state);
        }
        executor.set_validator_activation_height(ACT);
        *executor.reward_policy_handle().write() = Some(policy(n));
        // The production selector over the producers' stake, strict VRF, and
        // the activation height on a persistent DAG store.
        let selector = Arc::new(VrfProposerSelector::production());
        selector
            .sync_active_set(
                (0..n)
                    .map(|j| (PublicKey::new(proposer(j)), STAKE))
                    .collect(),
                MIN_STAKE,
            )
            .await;
        let kv = Arc::new(crate::persistent_dag::RocksDbKvStore::new(
            storage.db.clone(),
        ));
        let dag = Arc::new(
            DagStore::persistent_with_strict_vrf(kv, true)
                .expect("dag load")
                .with_proposer_selector(selector)
                .with_enforcement_activation_height(ACT),
        );
        dag.set_configured_genesis(genesis.header.block_hash);
        let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag.clone()));
        let app = Arc::new(
            CanonicalApplicator::new(executor.clone(), storage.clone())
                .with_fork_choice(ghostdag.clone())
                .with_dag_prune_floor(dag.clone()),
        );
        app.set_genesis(
            Executor::new(Arc::new(StateDB::new())).state_snapshot(),
            genesis.header.block_hash,
        );
        let adm = Arc::new(BlockAdmission::new(
            storage.clone(),
            dag.clone(),
            ghostdag.clone(),
            Some(app.clone()),
        ));
        adm.seed_genesis().await;
        let _ = adm.reconcile().await;
        ghostdag.reconcile_tips_from_dag_store().await;
        let mempool = Arc::new(Mempool::new(MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        }));
        let attested = AttestedNetworkHead::new();
        let initial_sync = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let producer = BlockProducer::with_shared_dag(
            storage.clone(),
            executor.clone(),
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
        .with_network_height_gate(&attested)
        .with_initial_sync_gate(initial_sync.clone());
        let sync = SyncManager::new(SyncConfig::default())
            .with_local_height(app.applied_height_handle())
            .with_clock_offset(clock_ms);
        Self {
            name: format!("p{i}"),
            storage,
            executor,
            app,
            adm,
            producer,
            sync,
            rejoin: parking_lot::Mutex::new(sync_rejoin::RejoinTracker::new()),
            sel: sync_peer::SyncPeerSelector::new(),
            walk: sync_recovery::ParentWalks::new(clock, SyncConfig::default().request_timeout),
            pm: Arc::new(citrate_network::PeerManager::new(
                citrate_network::PeerManagerConfig::default(),
            )),
            orphans: Vec::new(),
            attested,
            max_seen: AtomicU64::new(0),
            initial_sync,
            started_slot: slot_no,
            clock,
            rotate_idx: 0,
            split_gate: sync_peer::SplitPullGate::new(),
            relayed: HashSet::new(),
            dir,
        }
    }
}

impl Fleet {
    pub(crate) async fn new(n: usize) -> Self {
        let empty_root = Executor::new(Arc::new(StateDB::new())).calculate_state_root();
        let genesis = genesis_block(empty_root);
        let epoch = std::time::Instant::now();
        let clock_ms = Arc::new(AtomicU64::new(0));
        let mut nodes = Vec::new();
        for i in 0..n {
            let dir = TempDir::new().expect("tempdir");
            let storage = Arc::new(
                StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"),
            );
            nodes.push(
                Node::start(
                    i,
                    n,
                    &genesis,
                    storage,
                    dir,
                    None,
                    0,
                    epoch,
                    clock_ms.clone(),
                )
                .await,
            );
        }
        let mut peers = Vec::new();
        for i in 0..n {
            let mut row = Vec::new();
            for j in 0..n {
                if i == j {
                    row.push(None);
                    continue;
                }
                let (tx, rx) = mpsc::channel(1 << 16);
                let (_in_tx, in_rx) = mpsc::channel(1);
                let mut info = PeerInfo::new(
                    PeerId::new(format!("p{j}")),
                    "127.0.0.1:1".parse().expect("addr"),
                    Direction::Outbound,
                );
                info.state = PeerState::Connected;
                row.push(Some((Arc::new(Peer::new(info, tx, in_rx)), rx)));
            }
            peers.push(row);
        }
        let mut fleet = Self {
            nodes,
            peers,
            links: vec![vec![false; n]; n],
            sybils: (0..n).map(|_| Vec::new()).collect(),
            sybils_active: false,
            down: HashSet::new(),
            quiet: HashSet::new(),
            genesis,
            epoch,
            clock_ms,
            slot_no: 0,
            lost: 0,
        };
        fleet.set_links(|_, _| true);
        for i in 0..n {
            fleet.attach_peers(i).await;
        }
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

    fn now(&self) -> std::time::Instant {
        self.epoch + SLOT * u32::try_from(self.slot_no).expect("slots")
    }

    fn up(&self, i: usize, j: usize) -> bool {
        self.links[i][j] && !self.down.contains(&i) && !self.down.contains(&j)
    }

    fn peer(&self, at: usize, remote: usize) -> Arc<Peer> {
        self.peers[at][remote]
            .as_ref()
            .map(|(p, _)| p.clone())
            .expect("peer handle")
    }

    /// Node `i`'s peer table holds its handles on every other node.
    async fn attach_peers(&mut self, i: usize) {
        for j in 0..self.nodes.len() {
            if let Some((p, _)) = self.peers[i][j].as_ref() {
                self.nodes[i]
                    .pm
                    .add_peer(p.clone())
                    .await
                    .expect("add peer");
            }
        }
        for (p, _) in &self.sybils[i] {
            self.nodes[i]
                .pm
                .add_peer(p.clone())
                .await
                .expect("add sybil");
        }
    }

    /// Give every node `k` silent hostile peers.
    async fn add_sybils(&mut self, k: usize) {
        for i in 0..self.nodes.len() {
            for s in 0..k {
                let (tx, rx) = mpsc::channel(1 << 16);
                let (_in_tx, in_rx) = mpsc::channel(1);
                let mut info = PeerInfo::new(
                    PeerId::new(format!("sybil{s}")),
                    "127.0.0.1:1".parse().expect("addr"),
                    Direction::Inbound,
                );
                info.state = PeerState::Connected;
                self.sybils[i].push((Arc::new(Peer::new(info, tx, in_rx)), rx));
            }
            self.attach_peers(i).await;
        }
    }

    /// Each sybil gossips each node a block it signed itself, at the node's
    /// height plus two, on a parent nobody holds.
    async fn sybil_gossip(&mut self) {
        for i in 0..self.nodes.len() {
            if self.down.contains(&i) {
                continue;
            }
            for k in 0..self.sybils[i].len() {
                let key = Ed25519SigningKey::from_bytes(&[0xA0 ^ k as u8; 32]);
                let height = self.nodes[i].applied().1 + 2;
                let mut seed = [0u8; 32];
                seed[..8].copy_from_slice(&self.slot_no.to_le_bytes());
                seed[8] = k as u8;
                seed[9] = i as u8;
                let mut b = BlockBuilder::new()
                    .version(2)
                    .height(height)
                    .parent(Hash::new(seed))
                    .coinbase([0xBB; 20])
                    .timestamp(chrono::Utc::now().timestamp().max(0) as u64)
                    .vrf_reveal(VrfProof {
                        proof: vec![],
                        output: Hash::new([0x5C; 32]),
                    })
                    .transactions(vec![])
                    .state_root(Hash::default())
                    .blue_score(height)
                    .blue_work(citrate_consensus::types::blue_work_for_score(height))
                    .proposer(PublicKey::new(key.verifying_key().to_bytes()))
                    .build_unhashed();
                b.tx_root = citrate_consensus::tx_auth::tx_root_for_height(
                    citrate_consensus::hardening::PbaHardening::from_process(),
                    height,
                    &b.transactions,
                );
                b.header.block_hash = b.compute_hash();
                b.signature = citrate_consensus::crypto::sign_block(&b.header.block_hash, &key);
                let peer = self.sybils[i][k].0.clone();
                let pid = PeerId::new(format!("sybil{k}"));
                self.nodes[i].on_new_block(&peer, &pid, b).await;
            }
        }
        self.pump().await;
    }

    /// Stop node `i` and start a new process on its store. Messages in flight
    /// to or from it are lost.
    async fn restart(&mut self, i: usize) {
        self.pump().await;
        let n = self.nodes.len();
        let old = self.nodes.remove(i);
        let boot = old.executor.state_snapshot();
        let Node { storage, dir, .. } = old;
        let node = Node::start(
            i,
            n,
            &self.genesis,
            storage,
            dir,
            Some(boot),
            self.slot_no,
            self.now(),
            self.clock_ms.clone(),
        )
        .await;
        self.nodes.insert(i, node);
        self.attach_peers(i).await;
    }

    /// Every link reconnects: each node's view of each peer's head becomes that
    /// peer's applied tip, as the transport handshake sets it.
    async fn handshake(&mut self) {
        let n = self.nodes.len();
        for j in 0..n {
            let (hash, height) = self.nodes[j].applied();
            for i in (0..n).filter(|i| *i != j) {
                let peer = self.peer(i, j);
                let mut info = peer.info.write().await;
                info.head_height = height;
                info.head_hash = hash;
            }
        }
    }

    /// Everything sent so far, as (from, to, message); lost on down links.
    fn outbox(&mut self) -> Vec<(usize, usize, NetworkMessage)> {
        let mut out = Vec::new();
        let n = self.nodes.len();
        for i in 0..n {
            for j in 0..n {
                let up = self.up(i, j);
                let Some((_, rx)) = self.peers[i][j].as_mut() else {
                    continue;
                };
                while let Ok(m) = rx.try_recv() {
                    if up {
                        out.push((i, j, m));
                    } else {
                        self.lost += 1;
                    }
                }
            }
            for (_, rx) in &mut self.sybils[i] {
                while rx.try_recv().is_ok() {}
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
            NetworkMessage::NewBlock { block } => {
                // Gossip validation relays a block once to every other peer
                // (`GossipProtocol::handle_new_block`), before admission.
                let hash = block.header.block_hash;
                let relay = !node.adm.is_fully_admitted(&hash).await && node.relayed.insert(hash);
                node.on_new_block(&peer, &pid, block.clone()).await;
                if relay {
                    let n = self.nodes.len();
                    for j in (0..n).filter(|j| *j != at && *j != from) {
                        let _ = self
                            .peer(at, j)
                            .send(NetworkMessage::NewBlock {
                                block: block.clone(),
                            })
                            .await;
                    }
                }
            }
            NetworkMessage::Blocks { blocks } => node.on_blocks(&peer, &pid, blocks).await,
            _ => {}
        }
    }

    /// One slot: every running producer tries to seal (random order), its
    /// block is gossiped, then each running node runs its sync tick and drain.
    pub(crate) async fn slot(&mut self, order: &[usize]) -> Vec<(usize, Block)> {
        self.slot_no += 1;
        self.clock_ms.store(
            self.slot_no * u64::try_from(SLOT.as_millis()).expect("ms"),
            Ordering::Relaxed,
        );
        let now = self.now();
        for node in &mut self.nodes {
            node.clock = now;
        }
        if self.sybils_active {
            self.sybil_gossip().await;
        }
        let n = self.nodes.len();
        let mut produced = Vec::new();
        for &i in order {
            if self.quiet.contains(&i) || self.down.contains(&i) {
                continue;
            }
            let Ok(h) = self.nodes[i].producer.produce_block().await else {
                continue;
            };
            let b = self.nodes[i]
                .storage
                .blocks
                .get_block(&h)
                .expect("read produced")
                .expect("produced stored");
            for j in (0..n).filter(|j| *j != i) {
                let _ = self
                    .peer(i, j)
                    .send(NetworkMessage::NewBlock { block: b.clone() })
                    .await;
            }
            produced.push((i, b));
            self.pump().await;
        }
        let running: Vec<usize> = (0..n).filter(|i| !self.down.contains(i)).collect();
        for i in running.iter().copied() {
            let linked: Vec<usize> = (0..n).filter(|&j| self.up(i, j) && self.up(j, i)).collect();
            let mut peers: Vec<Arc<Peer>> = linked.iter().map(|&j| self.peer(i, j)).collect();
            peers.extend(self.sybils[i].iter().map(|(p, _)| p.clone()));
            let since =
                SLOT * u32::try_from(self.slot_no - self.nodes[i].started_slot).expect("slots");
            self.nodes[i].tick(&peers, since).await;
            self.pump().await;
        }
        for i in running {
            self.nodes[i].app.drive_drain().await;
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
    /// parents).
    pub(crate) async fn past(&self, i: usize) -> HashSet<Hash> {
        let n = &self.nodes[i];
        let mut seen: HashSet<Hash> = HashSet::new();
        let mut stack = vec![n.app.applied_tip().await.hash];
        while let Some(h) = stack.pop() {
            if seen.contains(&h) {
                continue;
            }
            let Some(b) = n.storage.blocks.get_block(&h).expect("read") else {
                continue;
            };
            seen.insert(h);
            stack.push(b.header.selected_parent_hash);
            stack.extend(b.header.merge_parent_hashes.iter().copied());
        }
        seen
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
                "{}: applied {}@{} orphans={} stored_tip={:?} initial_sync={} rejoin={:?}; ",
                n.name,
                short(&t.hash),
                t.height,
                n.orphans.len(),
                n.storage.blocks.get_latest_height().ok(),
                n.initial_sync.load(Ordering::Relaxed),
                n.rejoin.lock().mode(),
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
    async fn on_new_block(&mut self, peer: &Arc<Peer>, pid: &PeerId, block: Block) {
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
                    let now = self.clock;
                    let step = self.walk.begin(
                        &pid.0,
                        missing_parent,
                        block.header.height.saturating_sub(1),
                        applied_now,
                        now,
                    );
                    self.run_step(&pid.0, step, applied_now, now).await;
                }
                let _ = peer;
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

    /// `sync_recovery::run_step`, as both receive-loop call sites run it.
    async fn run_step(
        &mut self,
        peer: &str,
        step: sync_recovery::Step,
        applied_now: u64,
        now: std::time::Instant,
    ) {
        let storage = self.storage.clone();
        sync_recovery::run_step(
            &mut self.walk,
            &self.pm,
            &self.sync,
            peer,
            step,
            applied_now,
            |p| storage.blocks.has_block(p).unwrap_or(false),
            now,
        )
        .await;
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
            sync_recovery::lowest_deferred(&from_answer, &fx)
        };
        for b in fx
            .deferred
            .iter()
            .filter(|b| verified.contains(&b.header.block_hash))
        {
            if let Some((_, parent)) = fx.waiting_on.get(&b.header.block_hash) {
                self.walk.note_buffered(*parent, &pid.0, self.clock);
            }
        }
        let stuck_roots = if reprocessed {
            sync_recovery::deferred_roots(&fx)
        } else {
            Vec::new()
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
        {
            let now = self.clock;
            let step = self.walk.next(
                &pid.0,
                sync_recovery::WalkAnswer {
                    lowest_deferred,
                    admitted: newly_admitted,
                    orphans_remaining: !self.orphans.is_empty(),
                    applied: applied_now,
                },
                now,
            );
            self.walk.note_stuck(&stuck_roots, &pid.0, now);
            self.run_step(&pid.0, step, applied_now, now).await;
        }
        let _ = peer;
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

    /// main.rs periodic sync tick, over the peers this node is connected to;
    /// `since_start` is how long this process has run.
    async fn tick(&mut self, connected: &[Arc<Peer>], since_start: std::time::Duration) {
        let mut best_h = 0u64;
        let mut candidates = Vec::new();
        let mut split = Vec::new();
        for p in connected {
            let info = p.info.read().await;
            best_h = best_h.max(info.head_height);
            candidates.push(sync_peer::SyncCandidate {
                id: info.id.0.clone(),
                head_height: info.head_height,
            });
            split.push(sync_peer::SplitCandidate {
                id: info.id.0.clone(),
                head_height: info.head_height,
                head_hash: info.head_hash,
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
        if !self.initial_sync.load(Ordering::Relaxed)
            && sync_recovery::initial_sync_complete(
                applied_height,
                target,
                connected.len(),
                since_start,
            )
        {
            self.initial_sync.store(true, Ordering::Relaxed);
        }
        let held_heads: HashSet<Hash> = split
            .iter()
            .map(|c| c.head_hash)
            .filter(|h| self.storage.blocks.has_block(h).unwrap_or(true))
            .collect();
        let (source, _transition) = sync_rejoin::choose_source(
            &mut self.rejoin.lock(),
            &self.sel,
            &mut self.split_gate,
            &candidates,
            &split,
            applied_tip,
            |h| held_heads.contains(h),
            self.clock,
        );
        let chosen = source.peer().map(str::to_string);
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
        } else {
            None
        };
        if let Some(peer) = request_peer {
            self.rejoin.lock().note_sync_target(target, applied_tip.1);
            let (from, height) = self.rejoin.lock().anchor(applied_tip, |h| {
                sync_rejoin::anchor_at_height(&self.storage, h)
            });
            let (ph, pb) = self.sync.pending_counts().await;
            if ph < 8 {
                let _ = self.sync.request_headers(&peer, applied_tip.0).await;
            }
            if pb < sync_recovery::TICK_PENDING_GATE {
                let sent = self.sync.request_blocks(&peer, from, height).await;
                if matches!(sent, Ok(false)) {
                    let pid = peer.info.read().await.id.clone();
                    if self.rejoin.lock().note_unsent(&pid.0).is_some() {
                        self.sel.record_give_up(&pid.0);
                    }
                }
                if let Ok(true) = sent {
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
    /// Slots after the heal until the run's conditions held (None: never).
    pub healed_after: Option<u64>,
    pub detail: String,
}

/// Warm up connected, partition, optionally restart (and run one producer
/// alone), heal, and count the slots until every node's selected chain agrees
/// at a height above the split, plus the scenario's extra conditions.
pub(crate) async fn run(s: Scenario) -> Outcome {
    let n = s.producers;
    let mut fleet = Fleet::new(n).await;
    fleet.add_sybils(s.sybils).await;
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..s.warmup {
        let o = rng.order(n);
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
    let group_of = |i: usize| -> Option<usize> { s.groups.iter().position(|g| g.contains(&i)) };
    fleet.set_links(|i, j| group_of(i).is_some() && group_of(i) == group_of(j));
    let mut partition_blocks: HashMap<usize, HashSet<Hash>> = HashMap::new();
    for _ in 0..s.partition {
        let o = rng.order(n);
        for (i, b) in fleet.slot(&o).await {
            partition_blocks
                .entry(i)
                .or_default()
                .insert(b.header.block_hash);
        }
    }
    if s.restart_all {
        for i in 0..n {
            fleet.restart(i).await;
        }
    }
    if let Some((alone, slots)) = s.solo {
        fleet.down = (0..n).filter(|i| *i != alone).collect();
        for _ in 0..slots {
            let o = rng.order(n);
            for (i, b) in fleet.slot(&o).await {
                partition_blocks
                    .entry(i)
                    .or_default()
                    .insert(b.header.block_hash);
            }
        }
        // The others start now: fresh processes.
        let others: Vec<usize> = fleet.down.drain().collect();
        for i in others {
            fleet.restart(i).await;
        }
    }
    let split_top = *fleet.applied_heights().await.iter().max().expect("nodes");
    let split_heights = fleet.applied_heights().await;
    fleet.set_links(|_, _| true);
    if s.reconnect || s.restart_all || s.solo.is_some() {
        fleet.handshake().await;
    }
    if s.quiet_after_heal {
        // The lowest producer goes quiet, so no peer ever sees it ahead.
        let heights = fleet.applied_heights().await;
        let low = (0..n)
            .min_by_key(|i| (heights[*i], std::cmp::Reverse(*i)))
            .expect("producers");
        fleet.quiet.insert(low);
    }
    fleet.sybils_active = s.sybils > 0;
    let mut last_sealed: HashMap<usize, u64> = HashMap::new();
    for round in 1..=s.heal_rounds {
        let o = rng.order(n);
        for (i, _) in fleet.slot(&o).await {
            last_sealed.insert(i, round);
        }
        let heights = fleet.applied_heights().await;
        let min_h = *heights.iter().min().expect("nodes");
        if min_h < split_top + 3 {
            continue;
        }
        let Some(_) = fleet.agree_at(min_h - 2).await else {
            continue;
        };
        if s.require_merged {
            let past = fleet.past(0).await;
            let merged_all = (0..n).all(|i| {
                partition_blocks
                    .get(&i)
                    .is_some_and(|own| own.iter().any(|h| past.contains(h)))
            });
            if !merged_all {
                continue;
            }
        }
        if s.require_producing {
            let producing = (0..n).filter(|i| !fleet.quiet.contains(i)).all(|i| {
                last_sealed
                    .get(&i)
                    .is_some_and(|r| r + PRODUCING_WINDOW > round)
            });
            if !producing {
                continue;
            }
        }
        println!("SPLITHEAL {s:?}: healed {round} slot(s) after the heal");
        return Outcome {
            healed_after: Some(round),
            detail: format!(
                "pre={pre} split={split_heights:?} {}",
                fleet.describe().await
            ),
        };
    }
    let mut detail = format!(
        "pre={pre} split={split_heights:?} lost={} last_sealed={last_sealed:?} {}",
        fleet.lost,
        fleet.describe().await
    );
    for i in 0..n {
        let past = fleet.past(i).await;
        let merged: Vec<usize> = (0..n)
            .map(|j| {
                partition_blocks
                    .get(&j)
                    .map(|own| own.iter().filter(|h| past.contains(h)).count())
                    .unwrap_or(0)
            })
            .collect();
        detail.push_str(&format!(
            "node {i} holds partition blocks per producer {merged:?}; "
        ));
    }
    Outcome {
        healed_after: None,
        detail,
    }
}

/// The ordinary history of a node that has been up for a while: one gossip
/// block per producer that reached nobody (healed by the next block), and one
/// `Blocks` answer carrying a block whose parent no peer holds any more.
async fn long_running_history(fleet: &mut Fleet) {
    let n = fleet.nodes.len();
    for i in 0..n {
        // Sealed but never gossiped.
        let _ = fleet.nodes[i].producer.produce_block().await;
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

    fn base(producers: usize) -> Scenario {
        Scenario {
            producers,
            warmup: ACT + 4,
            long_running: false,
            groups: Vec::new(),
            partition: 30,
            restart_all: false,
            solo: None,
            quiet_after_heal: false,
            reconnect: false,
            heal_rounds: 40,
            require_merged: true,
            require_producing: true,
            sybils: 0,
        }
    }

    async fn assert_heals(name: &str, s: Scenario) {
        let out = run(s).await;
        assert!(
            out.healed_after.is_some(),
            "{name}: the fleet did not heal: {}",
            out.detail
        );
    }

    /// Control: seven fresh producers past activation, a 60 s partition into
    /// seven singletons (30 slots of 2 s), then the links come back. A fresh
    /// fleet healed before the fix too (as DGX's devnet phase 2).
    #[tokio::test(flavor = "current_thread")]
    async fn seven_producers_partitioned_into_singletons_heal() {
        if !in_child() {
            return run_in_child(
                "split_heal_tests::tests::seven_producers_partitioned_into_singletons_heal",
            );
        }
        assert_heals("seven fresh singletons", base(7)).await;
    }

    /// (a) The same on producers that have been running for a while (see
    /// `long_running`): every node agrees on one selected chain within 40
    /// slots, every producer's partition blocks are merged into its past, and
    /// every producer is sealing again. No operator action.
    #[tokio::test(flavor = "current_thread")]
    async fn seven_long_running_producers_partitioned_into_singletons_heal() {
        if !in_child() {
            return run_in_child(
                "split_heal_tests::tests::seven_long_running_producers_partitioned_into_singletons_heal",
            );
        }
        assert_heals(
            "seven long-running singletons",
            Scenario {
                long_running: true,
                ..base(7)
            },
        )
        .await;
    }

    /// DGX devnet phase 3: a 4v3 partition, every producer restarted during
    /// it, then one producer of the three running alone for about 2 minutes
    /// before the other six start. The four end up forked below their tip and
    /// far behind; they must rejoin and seal again.
    #[tokio::test(flavor = "current_thread")]
    async fn four_three_partition_with_restarts_and_a_lone_producer_heals() {
        if !in_child() {
            return run_in_child(
                "split_heal_tests::tests::four_three_partition_with_restarts_and_a_lone_producer_heals",
            );
        }
        assert_heals(
            "4v3 + restarts + lone producer",
            Scenario {
                groups: vec![vec![0, 1, 2, 3], vec![4, 5, 6]],
                partition: 9,
                restart_all: true,
                solo: Some((4, 60)),
                require_merged: false,
                ..base(7)
            },
        )
        .await;
    }

    /// P1-1 / P3: DGX's phase 3 with eight silent hostile peers on every node,
    /// each gossiping a self-signed block on an unknown parent every slot and
    /// answering nothing. Their walk requests sit pending for the sync
    /// manager's whole timeout; recovery and the sync tick must still bring
    /// the stuck side back and sealing.
    #[tokio::test(flavor = "current_thread")]
    async fn four_three_partition_heals_under_silent_sybils() {
        if !in_child() {
            return run_in_child(
                "split_heal_tests::tests::four_three_partition_heals_under_silent_sybils",
            );
        }
        assert_heals(
            "4v3 + restarts + lone producer + 8 silent sybils",
            Scenario {
                groups: vec![vec![0, 1, 2, 3], vec![4, 5, 6]],
                partition: 9,
                restart_all: true,
                solo: Some((4, 60)),
                require_merged: false,
                sybils: 8,
                ..base(7)
            },
        )
        .await;
    }

    /// The same with the lone producer running long enough that the four are
    /// forked below their tip and ~250 behind (DGX's stuck devnet): the
    /// missing-parent walk carries them back within one budget.
    #[tokio::test(flavor = "current_thread")]
    async fn four_three_partition_far_behind_heals() {
        if !in_child() {
            return run_in_child("split_heal_tests::tests::four_three_partition_far_behind_heals");
        }
        assert_heals(
            "4v3 + restarts + lone producer, far behind",
            Scenario {
                groups: vec![vec![0, 1, 2, 3], vec![4, 5, 6]],
                partition: 9,
                restart_all: true,
                solo: Some((4, 250)),
                require_merged: false,
                ..base(7)
            },
        )
        .await;
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
        assert_heals(
            "two producers",
            Scenario {
                long_running: true,
                partition: 10,
                heal_rounds: 30,
                ..base(2)
            },
        )
        .await;
    }

    /// A producer that stays quiet after a reconnect (nothing it sends
    /// announces its branch) still has its branch fetched: the peers see a
    /// head at their height that they do not hold and pull it.
    #[tokio::test(flavor = "current_thread")]
    async fn quiet_producer_branch_is_fetched_after_reconnect() {
        if !in_child() {
            return run_in_child(
                "split_heal_tests::tests::quiet_producer_branch_is_fetched_after_reconnect",
            );
        }
        assert_heals(
            "quiet producer",
            Scenario {
                long_running: true,
                partition: 10,
                heal_rounds: 30,
                quiet_after_heal: true,
                reconnect: true,
                ..base(2)
            },
        )
        .await;
    }
    /// Tripwire: the harness mirrors main.rs's receive loop and sync tick. If
    /// main.rs stops making one of these calls, the harness no longer tests
    /// what the node runs.
    #[test]
    fn main_loop_mirrors_the_harness() {
        let main = include_str!("main.rs");
        for needle in [
            // NewBlock arm.
            "gossip_for_rx.handle_new_block(block.clone(), &pid)",
            "admission_for_net.admit(&block)",
            "attested_for_rx.observe_deferred(&block)",
            "sync_peer::should_attempt_ancestry_recovery(",
            // Blocks arm.
            "sync_for_rx.handle_blocks(&pid, blocks)",
            ".take_answer(",
            "admission::bound_orphan_buffer(",
            ".admit_to_fixpoint(pending,",
            "sync_recovery::lowest_deferred(",
            "parent_walks.begin(",
            "parent_walks.next(",
            "sync_recovery::run_step(",
            "parent_walks.note_buffered(*parent, &pid.0, now)",
            "parent_walks.note_stuck(&stuck_roots, &pid.0, now)",
            "sync_recovery::deferred_roots(&fixpoint)",
            "rejoin_for_loop.lock().note_unsent(&pid.0)",
            "pb < sync_recovery::TICK_PENDING_GATE",
            "|h| held_heads.contains(h)",
            "sync_rejoin::classify(",
            "sel.record_serve(",
            // Sync tick.
            "sync_rejoin::choose_source(",
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
}
