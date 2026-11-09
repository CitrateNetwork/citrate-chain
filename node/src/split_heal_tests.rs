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
// anchor, `request_blocks`), the serving plane (`serve_plane::answer` over
// `block_serve`, under its `ServeQueue` budgets, ADR CV-6) for every answer,
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
// Every message a node receives first goes through its own
// `PeerManager::forward_incoming` (the production inbound admission), so a
// rule there that sheds a message the walk or sync needs fails these
// scenarios.
//
// `main_loop_mirrors_the_harness` fails if main.rs stops making the calls the
// harness makes.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
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
/// The DAG retain window the pruned scenarios prune to: harness scale, below
/// the node's floor (`dag_prune::MIN_RETAIN_BLOCKS` = the 10,000-height undo
/// window, S3-4), so a scenario reaches it in about a thousand slots. The
/// undo records still cover `canonical_apply::MAX_REORG_DEPTH`, so every fork
/// these scenarios build sits inside both the retained range and the window.
const HARNESS_PRUNE_RETAIN: u64 = 1_000;

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
    /// At every restart, the stopped node's DAG store is pruned to its last
    /// this many blocks (as `dag_prune` does on a node running with a retain
    /// window), so the restarted node runs with a prune floor.
    pub prune_retain: Option<u64>,
    /// Silent hostile peers per node: each connects to every node, answers
    /// nothing, and from the heal on gossips, every slot, a block it signed
    /// itself on a parent nobody holds (P1-1).
    pub sybils: usize,
    /// How a restarted node comes back (see [`RestartMode`]).
    pub restart_mode: RestartMode,
}

/// How [`Fleet::restart`] brings a stopped node back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RestartMode {
    /// The new process keeps the old one's open store and is handed the old
    /// executor's in-memory state snapshot.
    Snapshot,
    /// CV-9: the old process is dropped entirely (every handle on its RocksDB
    /// closed) and the new one reopens the data dir from disk as `start_node`
    /// does: the start-up hardening purge, world state hydrated and checked
    /// against the applied tip's committed root (`boot_state`), the DAG store,
    /// GhostDAG tips and the applicator's reorg window all reloaded from the
    /// store.
    Disk,
}

/// See [`Scenario::require_producing`].
const PRODUCING_WINDOW: u64 = 3;

/// One slot of simulated time.
const SLOT: std::time::Duration = std::time::Duration::from_secs(2);

struct Node {
    name: String,
    storage: Arc<StorageManager>,
    dag: Arc<DagStore>,
    executor: Arc<Executor>,
    app: Arc<CanonicalApplicator>,
    adm: Arc<BlockAdmission>,
    producer: BlockProducer,
    sync: SyncManager,
    rejoin: parking_lot::Mutex<sync_rejoin::RejoinTracker>,
    tip_reask: sync_recovery::TipReask,
    sel: sync_peer::SyncPeerSelector,
    walk: sync_recovery::ParentWalks,
    /// This process's peer table (the walk sends through it). Every message
    /// this node receives goes through its `forward_incoming` into `inbound`,
    /// the production admission path, so a message it sheds is lost here too.
    pm: Arc<citrate_network::PeerManager>,
    /// The node's inbound queue (main.rs: 512 slots).
    inbound: mpsc::Receiver<(PeerId, NetworkMessage)>,
    /// The serving lane (main.rs: `set_serve_sink`, ADR CV-6) and the
    /// serving plane's budgeted queue.
    serve_rx: mpsc::Receiver<(PeerId, NetworkMessage)>,
    serve_q: citrate_network::inbound::ServeQueue<NetworkMessage>,
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
    /// How far this node's wall clock (the producer's slot clock and the
    /// attested head's clock) runs ahead of the harness's simulated time, in
    /// ms (negative: behind). 0 unless a test skews it
    /// ([`Fleet::set_clock_skew`]); a restarted process starts at 0.
    skew_ms: Arc<AtomicI64>,
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
    /// serve_cut[i][j]: of what i sends j, only gossip (`NewBlock`) arrives;
    /// requests and answers are lost. The state of a producer whose serving
    /// is starved (H3): it hears its peers' new blocks but can never fetch
    /// the ancestry it lacks, so it cannot admit them.
    serve_cut: Vec<Vec<bool>>,
    /// The producers' deferred-evidence refuse window (`None`: the default).
    refuse_window: Option<std::time::Duration>,
    /// See [`Scenario::prune_retain`].
    prune_retain: Option<u64>,
    /// See [`Scenario::restart_mode`].
    restart_mode: RestartMode,
    genesis: Block,
    /// Simulated time, in slots, from `epoch`.
    epoch: std::time::Instant,
    /// The same simulated time, in milliseconds, for the sync managers'
    /// request clocks (`SyncManager::with_clock_offset`).
    clock_ms: Arc<AtomicU64>,
    slot_no: u64,
    /// Messages lost on down links (diagnostics).
    pub lost: usize,
    /// Messages a node's inbound admission shed (diagnostics).
    pub shed: usize,
    /// For the apply-cost bench: (slot, time) of every gossiped block a node
    /// had not admitted yet, through `on_new_block` (stored -> DAG ->
    /// applied: admission executes on receive).
    pub admit_cost: Vec<(u64, std::time::Duration)>,
}

fn genesis_block(root: Hash) -> Block {
    genesis_block_at(root, 1000)
}

/// [`genesis_block`] with header time `timestamp`.
fn genesis_block_at(root: Hash, timestamp: u64) -> Block {
    let mut g = BlockBuilder::new()
        .version(2)
        .height(0)
        .parent(Hash::default())
        .coinbase([0x33; 20])
        .timestamp(timestamp)
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

/// What a starting node process is handed.
enum Boot {
    /// A new data dir: genesis is written.
    Fresh,
    /// The stopped process's open store and in-memory state.
    Snapshot(citrate_execution::state::StateSnapshot),
    /// A store reopened from disk; state is hydrated from it.
    Disk,
}

impl Node {
    /// Stop the process: every handle it holds (on its store too) is
    /// dropped; only the data dir is kept.
    fn stop(self) -> TempDir {
        self.dir
    }

    /// A node process as `start_node` wires one, on `storage`: fresh, the
    /// still-open store of a stopped process with its state snapshot, or a
    /// store reopened from disk (see [`Boot`]).
    #[allow(clippy::too_many_arguments)]
    async fn start(
        i: usize,
        n: usize,
        genesis: &Block,
        storage: Arc<StorageManager>,
        dir: TempDir,
        boot: Boot,
        slot_no: u64,
        clock: std::time::Instant,
        clock_ms: Arc<AtomicU64>,
        refuse_window: Option<std::time::Duration>,
    ) -> Self {
        let state_db = Arc::new(StateDB::new());
        match &boot {
            Boot::Fresh => {
                storage.blocks.put_block(genesis).expect("genesis");
                storage
                    .blocks
                    .put_applied_tip(&genesis.header.block_hash, 0)
                    .expect("genesis tip");
            }
            Boot::Snapshot(_) => {}
            Boot::Disk => {
                // start_node's order: the start-up hardening purge before
                // anything loads, then the world state from the store.
                crate::hardening_rejoin::purge_invalid_post_activation(
                    &storage,
                    citrate_consensus::hardening::PbaHardening::from_process(),
                    CHAIN_ID,
                )
                .expect("start-up hardening check");
                crate::boot_state::hydrate_state_db(&storage, &state_db)
                    .expect("boot hydration from disk");
            }
        }
        let executor = Arc::new(Executor::with_storage_and_chain_id(
            state_db,
            Some(storage.state.clone()),
            CHAIN_ID,
        ));
        if let Boot::Snapshot(state) = boot {
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
        dag.set_slot_origin(&genesis.header)
            .expect("r1007 G9: bind the slot origin from genesis, as start_node does");
        let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag.clone()));
        let dag_handle = dag.clone();
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
        // r1007 G9: the producers below stamp the harness's simulated time, so
        // the deferred-evidence check judges header timestamps against it too
        // (before G9 the producer stamped the real clock).
        let skew_ms = Arc::new(AtomicI64::new(0));
        let sim_wall: crate::producer::SlotClock = {
            let base_ms = genesis
                .header
                .timestamp
                .saturating_add(citrate_consensus::slots::SLOT_DURATION_SECS)
                .saturating_mul(1_000);
            let sim = clock_ms.clone();
            let skew = skew_ms.clone();
            Arc::new(move || {
                base_ms
                    .saturating_add(sim.load(Ordering::Relaxed))
                    .saturating_add_signed(skew.load(Ordering::Relaxed))
            })
        };
        let attested = AttestedNetworkHead::new().with_wall_clock_for_test(sim_wall.clone());
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
        .with_initial_sync_gate(initial_sync.clone())
        // r1007 G9: producers read the harness's simulated time (one harness
        // slot = SLOT), starting one chain slot after genesis, so every
        // producer of a harness slot stamps the same chain slot and the next
        // harness slot is a later one, however fast the harness runs.
        .with_slot_clock(sim_wall);
        let producer = match refuse_window {
            Some(w) => producer.with_deferred_refuse_window(w),
            None => producer,
        };
        let sync = SyncManager::new(SyncConfig::default())
            .with_local_height(app.applied_height_handle())
            .with_clock_offset(clock_ms);
        let pm = Arc::new(citrate_network::PeerManager::new(
            citrate_network::PeerManagerConfig::default(),
        ));
        let (in_tx, inbound) = mpsc::channel(512);
        pm.set_incoming(in_tx).await;
        let (serve_tx, serve_rx) = mpsc::channel(citrate_network::inbound::SERVE_LANE_CAPACITY);
        pm.set_serve_sink(serve_tx).await;
        Self {
            name: format!("p{i}"),
            storage,
            dag: dag_handle,
            executor,
            app,
            adm,
            producer,
            sync,
            rejoin: parking_lot::Mutex::new(sync_rejoin::RejoinTracker::new()),
            tip_reask: sync_recovery::TipReask::new(),
            sel: sync_peer::SyncPeerSelector::new(),
            walk: sync_recovery::ParentWalks::new(clock, SyncConfig::default().request_timeout),
            pm,
            inbound,
            serve_rx,
            serve_q: crate::serve_plane::queue(),
            orphans: Vec::new(),
            attested,
            max_seen: AtomicU64::new(0),
            initial_sync,
            started_slot: slot_no,
            clock,
            skew_ms,
            rotate_idx: 0,
            split_gate: sync_peer::SplitPullGate::new(),
            relayed: HashSet::new(),
            dir,
        }
    }
}

impl Fleet {
    /// Node `i`'s data dir recorded for the differential replay harness
    /// (`tools/replay-ref`, S3-3c): opened read-only while the node runs, with
    /// the execution parameters this harness starts every node with.
    fn record(&self, i: usize) -> citrate_replay_ref::Recording {
        let mut cfg = citrate_replay_ref::ReplayConfig::from_process(CHAIN_ID);
        cfg.validator_activation_height = Some(ACT);
        cfg.reward_policy = Some(citrate_replay_ref::RecordedRewardPolicy::from_policy(
            &policy(self.nodes.len()),
        ));
        citrate_replay_ref::record_data_dir(self.nodes[i].dir.path(), cfg)
            .expect("record a node's data dir")
    }

    pub(crate) async fn new(n: usize) -> Self {
        Self::with_refuse_window(n, None).await
    }

    /// A fleet whose producers use `refuse_window` as their deferred-evidence
    /// refuse window (the harness runs in real time, so the 60 s default never
    /// elapses inside a run). With a window set, genesis carries the current wall
    /// time, so block headers carry it too: deferred evidence is judged against
    /// local wall time, and headers stamped at time 1000 would never count.
    pub(crate) async fn with_refuse_window(
        n: usize,
        refuse_window: Option<std::time::Duration>,
    ) -> Self {
        let empty_root = Executor::new(Arc::new(StateDB::new())).calculate_state_root();
        let genesis = match refuse_window {
            Some(_) => genesis_block_at(
                empty_root,
                u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(1000),
            ),
            None => genesis_block(empty_root),
        };
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
                    Boot::Fresh,
                    0,
                    epoch,
                    clock_ms.clone(),
                    refuse_window,
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
            serve_cut: vec![vec![false; n]; n],
            refuse_window,
            prune_retain: None,
            restart_mode: RestartMode::Snapshot,
            genesis,
            epoch,
            clock_ms,
            slot_no: 0,
            lost: 0,
            shed: 0,
            admit_cost: Vec::new(),
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
        if let Some(retain) = self.prune_retain {
            let tip = old.applied().1;
            if let Some(point) = tip.checked_sub(retain).filter(|p| *p > 0) {
                let at = old
                    .storage
                    .blocks
                    .get_canonical_block_by_height(point)
                    .expect("canonical read")
                    .expect("canonical block at the pruning point");
                old.dag
                    .update_pruning_point(at)
                    .await
                    .expect("pruning point");
                let dropped = old.dag.prune().await.expect("prune");
                // A node restarted again without moving past its previous
                // pruning point has nothing new to drop: the eager load no
                // longer puts pruned blocks back into the DAG store.
                assert!(
                    crate::dag_prune::pruned_below(&old.dag).await == point,
                    "fixture: {} pruned below {point} (dropped {dropped})",
                    old.name
                );
                assert!(
                    old.dag.get_blocks_at_height(point - 1).await.is_empty(),
                    "fixture: {} still holds blocks below {point}",
                    old.name
                );
            }
        }
        let (storage, dir, boot) = match self.restart_mode {
            RestartMode::Snapshot => {
                let boot = old.executor.state_snapshot();
                let Node { storage, dir, .. } = old;
                (storage, dir, Boot::Snapshot(boot))
            }
            RestartMode::Disk => {
                let dir = old.stop();
                let storage = Arc::new(
                    StorageManager::new(dir.path(), PruningConfig::default())
                        .expect("reopen the stopped node's store"),
                );
                (storage, dir, Boot::Disk)
            }
        };
        let node = Node::start(
            i,
            n,
            &self.genesis,
            storage,
            dir,
            boot,
            self.slot_no,
            self.now(),
            self.clock_ms.clone(),
            self.refuse_window,
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
                    let cut = self.serve_cut[i][j] && !matches!(m, NetworkMessage::NewBlock { .. });
                    if up && !cut {
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
        // Production admission (`PeerManager::forward_incoming`): anything it
        // sheds never reaches the handlers, exactly as on a node.
        let msg = {
            let node = &mut self.nodes[at];
            node.pm.forward_incoming(pid.clone(), msg).await;
            match node.inbound.try_recv() {
                Ok((_, msg)) => msg,
                Err(_) => match node.serve_rx.try_recv() {
                    // The serving lane: the plane's budgeted queue, answered
                    // now (the harness's serving task never lags).
                    Ok((sender, request)) => {
                        use citrate_network::inbound::ServeAdmit;
                        if node.serve_q.push(sender, request) != ServeAdmit::Queued {
                            self.shed += 1;
                            return;
                        }
                        let peer = self.peer(at, from);
                        let node = &mut self.nodes[at];
                        while let Some((asker, request)) = node.serve_q.take_next() {
                            if let Some(reply) = crate::serve_plane::answer(&node.storage, &request)
                            {
                                let _ = peer.send(reply).await;
                            }
                            node.serve_q.done(&asker);
                        }
                        return;
                    }
                    Err(_) => {
                        self.shed += 1;
                        return;
                    }
                },
            }
        };
        let peer = self.peer(at, from);
        let node = &mut self.nodes[at];
        match msg {
            NetworkMessage::Headers { headers } => {
                let _ = node.sync.handle_headers(&pid, headers).await;
            }
            NetworkMessage::NewBlock { block } => {
                // Gossip validation relays a block once to every other peer
                // (`GossipProtocol::handle_new_block`), before admission.
                let hash = block.header.block_hash;
                let fresh = !node.adm.is_fully_admitted(&hash).await;
                let relay = fresh && node.relayed.insert(hash);
                let t = std::time::Instant::now();
                node.on_new_block(&peer, &pid, block.clone()).await;
                let spent = t.elapsed();
                if fresh {
                    self.admit_cost.push((self.slot_no, spent));
                }
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

    /// One slot: every running producer tries to seal (random order), then
    /// the sealed blocks are gossiped (in that order), then each running node
    /// runs its sync tick and drain.
    ///
    /// r1007 G9 (#184): every producer seals at the slot boundary, on the
    /// slot grid, from what it held when the slot began; a block of slot s
    /// reaches a peer during slot s and is merged by slot s + 1. So the
    /// producers of one harness slot all seal before any of that slot's blocks
    /// is delivered. (Before G9 the harness delivered each block before the
    /// next producer sealed, and a later producer of the same round stacked a
    /// block on it. Under G9 that producer would see a selected parent in its
    /// own slot and skip, so one block per harness slot was sealed across the
    /// whole fleet and a larger side could never outweigh a smaller one.)
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
            produced.push((i, b));
        }
        for (i, b) in &produced {
            for j in (0..n).filter(|j| j != i) {
                let _ = self
                    .peer(*i, j)
                    .send(NetworkMessage::NewBlock { block: b.clone() })
                    .await;
            }
            self.pump().await;
        }
        self.end_slot().await;
        produced
    }

    /// The end of a slot: each running node runs its sync tick, then its
    /// drain.
    async fn end_slot(&mut self) {
        let n = self.nodes.len();
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
    }

    /// Node `i`'s wall clock runs `ms` ahead of the harness's time (negative:
    /// behind), as an unsynchronized host's would: its producer's slot clock
    /// and its attested-head clock read the skewed time.
    pub(crate) fn set_clock_skew(&mut self, i: usize, ms: i64) {
        self.nodes[i].skew_ms.store(ms, Ordering::Relaxed);
    }

    /// One slot in real-time order. `rounds` lists `(producer, at_ms)`: the
    /// producer's round fires when the harness's time is the slot boundary
    /// plus `at_ms` (negative: before the boundary). A producer with a clock
    /// skewed +200 ms ([`Self::set_clock_skew`]) fires at `at_ms = -200`, when
    /// its own clock reads the boundary; a round that fires early within
    /// `SLOT_TICK_EARLY_ALLOWANCE_MS` has a negative `at_ms` and no skew.
    ///
    /// Rounds fire in `at_ms` order (ties in list order). The blocks of the
    /// rounds that fire at one instant are gossiped and every running node
    /// drains before the next instant's rounds fire: the network delay is
    /// shorter than the gap between them, and a node drains continuously.
    /// Then each running node runs its sync tick and drain, as in
    /// [`Self::slot`]. With every `at_ms` equal this is [`Self::slot`].
    pub(crate) async fn slot_timed(&mut self, rounds: &[(usize, i64)]) -> Vec<(usize, Block)> {
        self.slot_no += 1;
        let slot_ms = u64::try_from(SLOT.as_millis()).expect("ms");
        let boundary_ms = self.slot_no * slot_ms;
        let now = self.now();
        for node in &mut self.nodes {
            node.clock = now;
        }
        if self.sybils_active {
            self.sybil_gossip().await;
        }
        let n = self.nodes.len();
        let mut order: Vec<(usize, i64)> = rounds.to_vec();
        order.sort_by_key(|&(_, at)| at);
        let mut produced = Vec::new();
        let mut k = 0;
        while k < order.len() {
            let at = order[k].1;
            self.clock_ms
                .store(boundary_ms.saturating_add_signed(at), Ordering::Relaxed);
            let mut sealed = Vec::new();
            while k < order.len() && order[k].1 == at {
                let i = order[k].0;
                k += 1;
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
                sealed.push((i, b));
            }
            for (i, b) in &sealed {
                for j in (0..n).filter(|j| j != i) {
                    let _ = self
                        .peer(*i, j)
                        .send(NetworkMessage::NewBlock { block: b.clone() })
                        .await;
                }
                self.pump().await;
            }
            for i in (0..n).filter(|i| !self.down.contains(i)) {
                self.nodes[i].app.drive_drain().await;
            }
            produced.extend(sealed);
        }
        self.clock_ms.store(
            boundary_ms.max(self.clock_ms.load(Ordering::Relaxed)),
            Ordering::Relaxed,
        );
        self.end_slot().await;
        produced
    }

    /// Of the blocks node `i` has accepted (its applied tip and that tip's
    /// past, genesis excluded), how many each of the fleet's producers
    /// sealed, by producer index. Every block in that past is accepted, so
    /// this is each producer's share of the accepted slots.
    pub(crate) async fn accepted_by_producer(&self, i: usize) -> Vec<usize> {
        let mut counts = vec![0usize; self.nodes.len()];
        let mut seen = self.past(i).await;
        seen.insert(self.nodes[i].app.applied_tip().await.hash);
        for h in seen {
            let Some(b) = self.nodes[i].storage.blocks.get_block(&h).expect("read") else {
                continue;
            };
            if b.header.height == 0 {
                continue;
            }
            if let Some(p) =
                (0..self.nodes.len()).find(|&p| b.header.proposer_pubkey.as_bytes() == &proposer(p))
            {
                counts[p] += 1;
            }
        }
        counts
    }

    /// Of node `i`'s selected chain (genesis excluded), how many chain blocks
    /// each producer sealed, by producer index. On this branch the block
    /// reward settles per applied chain block to its proposer's staker, so
    /// this is each producer's share of the rewards; under spec §3.8 (the
    /// emission split among a chain block's blue mergeset) the reward share
    /// follows [`Self::accepted_by_producer`] instead.
    pub(crate) async fn chain_by_producer(&self, i: usize) -> Vec<usize> {
        let mut counts = vec![0usize; self.nodes.len()];
        for (height, h) in self.chain(i).await {
            if height == 0 {
                continue;
            }
            let b = self.nodes[i]
                .storage
                .blocks
                .get_block(&h)
                .expect("read")
                .expect("chain block stored");
            if let Some(p) =
                (0..self.nodes.len()).find(|&p| b.header.proposer_pubkey.as_bytes() == &proposer(p))
            {
                counts[p] += 1;
            }
        }
        counts
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
        let answer_top = pending.iter().map(|b| b.header.height).max();
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
        let (applied_hash_now, applied_now) = self.applied();
        let target = self.max_seen.load(Ordering::Relaxed);
        let gap = target.saturating_sub(applied_now);
        let held_ahead = sync_recovery::answer_is_held_ahead(
            answer_top,
            newly_admitted,
            deferred_from_answer,
            applied_now,
        );
        self.tip_reask
            .note_answer(applied_hash_now, held_ahead, self.clock);
        let stale_anchor = sync_recovery::answer_anchor_was_stale(
            self.sync.last_block_anchor_height(),
            applied_now,
            answer_hashes.len(),
        ) || held_ahead;
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
        if self.attested.take_resync_request() {
            let _ = sync_rejoin::start_resync(&mut self.rejoin.lock(), &split, applied_tip, |h| {
                held_heads.contains(h)
            });
        }
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
            let held_tip = self.tip_reask.hold(from, applied_tip.0, self.clock);
            if pb < sync_recovery::TICK_PENDING_GATE && !held_tip {
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
    fleet.prune_retain = s.prune_retain;
    fleet.restart_mode = s.restart_mode;
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
        "pre={pre} split={split_heights:?} lost={} shed={} last_sealed={last_sealed:?} {}",
        fleet.lost,
        fleet.shed,
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
    let _ = child_output(test);
}

/// [`run_in_child`], returning the child's stdout and stderr.
fn child_output(test: &str) -> String {
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
    format!("{stdout}{stderr}")
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
            prune_retain: None,
            sybils: 0,
            restart_mode: RestartMode::Snapshot,
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

    /// DGX devnet C2/D1/D2: the 4v3 restart scenario past the DAG prune
    /// retention. The producers run with a 1000-block retain window (the
    /// devnet's, below today's 10,000 floor: `HARNESS_PRUNE_RETAIN`), the split and the restarts happen
    /// past height 1000, so the four restart forked below their tip on a
    /// pruned DAG store, where a replay from genesis is refused. They must
    /// switch by a bounded reorg, rejoin and seal again.
    #[tokio::test(flavor = "current_thread")]
    async fn four_three_partition_with_restarts_past_prune_retention_heals() {
        if !in_child() {
            return run_in_child(
                "split_heal_tests::tests::four_three_partition_with_restarts_past_prune_retention_heals",
            );
        }
        assert_heals(
            "4v3 + restarts + lone producer, pruned DAG stores",
            Scenario {
                warmup: ACT + 152,
                groups: vec![vec![0, 1, 2, 3], vec![4, 5, 6]],
                partition: 9,
                restart_all: true,
                solo: Some((4, 60)),
                require_merged: false,
                prune_retain: Some(HARNESS_PRUNE_RETAIN),
                ..base(7)
            },
        )
        .await;
    }

    // CV-9 (S1-5): every scenario above that restarts a node, again with the
    // restart dropping the process and reopening its data dir from RocksDB
    // (`RestartMode::Disk`). A scenario that heals from the in-memory snapshot
    // and not from disk is a restart the network cannot rely on.

    fn four_three_with_restarts() -> Scenario {
        Scenario {
            groups: vec![vec![0, 1, 2, 3], vec![4, 5, 6]],
            partition: 9,
            restart_all: true,
            solo: Some((4, 60)),
            require_merged: false,
            ..base(7)
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn four_three_partition_with_restarts_and_a_lone_producer_heals_from_disk() {
        if !in_child() {
            return run_in_child(
                "split_heal_tests::tests::four_three_partition_with_restarts_and_a_lone_producer_heals_from_disk",
            );
        }
        assert_heals(
            "4v3 + restarts from disk + lone producer",
            Scenario {
                restart_mode: RestartMode::Disk,
                ..four_three_with_restarts()
            },
        )
        .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn four_three_partition_heals_under_silent_sybils_from_disk() {
        if !in_child() {
            return run_in_child(
                "split_heal_tests::tests::four_three_partition_heals_under_silent_sybils_from_disk",
            );
        }
        assert_heals(
            "4v3 + restarts from disk + lone producer + 8 silent sybils",
            Scenario {
                sybils: 8,
                restart_mode: RestartMode::Disk,
                ..four_three_with_restarts()
            },
        )
        .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn four_three_partition_far_behind_heals_from_disk() {
        if !in_child() {
            return run_in_child(
                "split_heal_tests::tests::four_three_partition_far_behind_heals_from_disk",
            );
        }
        assert_heals(
            "4v3 + restarts from disk + lone producer, far behind",
            Scenario {
                solo: Some((4, 250)),
                restart_mode: RestartMode::Disk,
                ..four_three_with_restarts()
            },
        )
        .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn four_three_partition_with_restarts_past_prune_retention_heals_from_disk() {
        if !in_child() {
            return run_in_child(
                "split_heal_tests::tests::four_three_partition_with_restarts_past_prune_retention_heals_from_disk",
            );
        }
        assert_heals(
            "4v3 + restarts from disk + lone producer, pruned DAG stores",
            Scenario {
                warmup: ACT + 152,
                prune_retain: Some(HARNESS_PRUNE_RETAIN),
                restart_mode: RestartMode::Disk,
                ..four_three_with_restarts()
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

    /// r1007 G9 (#184), OPEN: a producer that already holds another
    /// producer's block of the current slot must still seal its own block for
    /// this slot, on the best blocks of earlier slots, and leave the same-slot
    /// block for the next slot to merge. Today it skips the slot ("the
    /// selected parent is in slot s, not before this slot"), because fork
    /// choice selects the same-slot block and the round may only seal on the
    /// applied tip (MP-S1). So whichever producer's block arrives first takes
    /// the slot from every producer that has not sealed yet: a producer whose
    /// clock runs ahead, or that seals early within the drift, wins slots
    /// alone. The fix has to choose parents from earlier slots and seal on
    /// their state, which crosses MP-S1, the drain and fork choice; it is
    /// left to a reviewed change. `Fleet::slot` seals every producer of a
    /// slot before delivering, the honest synchronized-clock case.
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "open (#184): a same-slot block received before the round makes the producer skip its slot"]
    async fn a_producer_seals_its_slot_after_receiving_a_same_slot_block() {
        let mut fleet = Fleet::new(2).await;
        for _ in 0..6 {
            fleet.slot(&[0, 1]).await;
        }
        // Slot 7: producer 0 seals and its block reaches producer 1 first.
        let produced = fleet.slot(&[0]).await;
        assert_eq!(produced.len(), 1, "producer 0 sealed slot 7");
        let r = fleet.nodes[1].producer.produce_block().await;
        assert!(
            r.is_ok(),
            "producer 1 must still seal slot 7 (on slot 6's blocks): {r:?}"
        );
    }

    /// Same-slot fairness (spec 06 G13.4, acceptance A1/A2): slots per run.
    const FAIR_SLOTS: usize = 60;
    /// Same-slot fairness: producers in the fleet.
    const FAIR_N: usize = 3;
    /// Same-slot fairness: how far a producer's share of the accepted blocks
    /// may sit from 1/FAIR_N. Every producer seals every slot when the rule
    /// holds, so the only slack is the harness's first slot (no producer
    /// seals in it: 59 blocks over 60 slots even for a lone producer) and the
    /// last slot's siblings, not merged yet: at most two blocks a producer.
    const FAIR_SLOT_TOLERANCE: f64 = 0.05;
    /// Same-slot fairness: slots of a run in which a producer may have no
    /// accepted block (the first and the last, see FAIR_SLOT_TOLERANCE).
    const FAIR_SLOT_SLACK: usize = 2;
    /// Same-slot fairness: the largest share of selected-chain blocks (the
    /// reward-bearing blocks on this branch) one producer may hold. Which
    /// sibling becomes the chain block is decided by Key (blue_work, then the
    /// slot-bound VRF output), a 1/FAIR_N draw per slot when the siblings
    /// merge the same past: Binomial(60, 1/3) exceeds 30 with probability
    /// about 0.3%. The keys are fixed, so the run is deterministic.
    const FAIR_CHAIN_MAX_SHARE: f64 = 0.5;

    /// Runs FAIR_SLOTS slots of FAIR_N producers with the given rounds per
    /// slot, then returns, for every node, the accepted blocks per producer
    /// and the chain blocks per producer.
    async fn fairness_run(
        skew: &[(usize, i64)],
        rounds: &[(usize, i64)],
    ) -> Vec<(Vec<usize>, Vec<usize>)> {
        let mut fleet = Fleet::new(FAIR_N).await;
        for &(i, ms) in skew {
            fleet.set_clock_skew(i, ms);
        }
        for _ in 0..FAIR_SLOTS {
            fleet.slot_timed(rounds).await;
        }
        let mut out = Vec::new();
        for i in 0..FAIR_N {
            out.push((
                fleet.accepted_by_producer(i).await,
                fleet.chain_by_producer(i).await,
            ));
        }
        println!("SAMESLOT skew={skew:?} rounds={rounds:?}: (accepted, chain) per node {out:?}");
        out
    }

    /// Acceptance A1: on every node, every producer's share of the accepted
    /// blocks is 1/FAIR_N within FAIR_SLOT_TOLERANCE, and every producer has a
    /// block accepted in all but FAIR_SLOT_SLACK slots.
    fn assert_fair_slot_share(run: &[(Vec<usize>, Vec<usize>)], what: &str) {
        for (node, (accepted, _)) in run.iter().enumerate() {
            let total: usize = accepted.iter().sum();
            for (p, &c) in accepted.iter().enumerate() {
                let share = c as f64 / total.max(1) as f64;
                assert!(
                    (share - 1.0 / FAIR_N as f64).abs() <= FAIR_SLOT_TOLERANCE
                        && c + FAIR_SLOT_SLACK >= FAIR_SLOTS,
                    "{what}: node {node} accepted {accepted:?} over {FAIR_SLOTS} slots; \
                     producer {p} has {c} ({share:.3}), fair is one per slot (1/{FAIR_N})"
                );
            }
        }
    }

    /// Acceptance A2 (reward proxy): on every node, no producer holds more
    /// than FAIR_CHAIN_MAX_SHARE of the selected-chain blocks.
    fn assert_fair_chain_share(run: &[(Vec<usize>, Vec<usize>)], what: &str) {
        for (node, (_, chain)) in run.iter().enumerate() {
            let total: usize = chain.iter().sum();
            for (p, &c) in chain.iter().enumerate() {
                let share = c as f64 / total.max(1) as f64;
                assert!(
                    share <= FAIR_CHAIN_MAX_SHARE,
                    "{what}: node {node} chain blocks {chain:?}; producer {p} holds {c} \
                     ({share:.3}), at most {FAIR_CHAIN_MAX_SHARE} allowed"
                );
            }
        }
    }

    /// Control for the same-slot fairness tests: with synchronized clocks
    /// every producer seals every slot (on the earlier slots' blocks) and the
    /// next slot merges the siblings, so the accepted blocks split evenly.
    /// Passes today; the skewed variants below must match it.
    #[tokio::test(flavor = "current_thread")]
    async fn same_slot_share_is_fair_with_synchronized_clocks() {
        let run = fairness_run(&[], &[(0, 0), (1, 0), (2, 0)]).await;
        assert_fair_slot_share(&run, "synchronized clocks");
        assert_fair_chain_share(&run, "synchronized clocks");
    }

    /// Same-slot fairness A1 (spec 06 G13), OPEN: a producer whose clock
    /// runs 200 ms ahead fires its round 200 ms before the others, and its
    /// block reaches them first. Each of them then skips the slot (G9: the
    /// selected parent is in this slot), so the fast producer seals every
    /// accepted block. Fixed when a producer seals its slot-s block on the
    /// view of slots before s (G13 rules SF1 to SF4).
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "open (#184, spec 06 G13): a producer whose clock runs 200 ms ahead takes every slot"]
    async fn same_slot_share_is_fair_with_a_fast_clock() {
        let run = fairness_run(&[(0, 200)], &[(0, -200), (1, 0), (2, 0)]).await;
        assert_fair_slot_share(&run, "producer 0 clock +200 ms");
    }

    /// Same-slot fairness A1, OPEN: the same, with synchronized clocks and a
    /// round that fires 240 ms early, inside SLOT_TICK_EARLY_ALLOWANCE_MS
    /// (250 ms), so it still stamps the coming slot.
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "open (#184, spec 06 G13): a round inside the 250 ms early-tick allowance takes every slot"]
    async fn same_slot_share_is_fair_with_an_early_round() {
        let run = fairness_run(&[], &[(0, -240), (1, 0), (2, 0)]).await;
        assert_fair_slot_share(&run, "producer 0 round 240 ms early");
    }

    /// Same-slot fairness A2 (reward proxy), OPEN: with a producer 200 ms
    /// ahead, it holds every selected-chain block, so on this branch it
    /// earns every block reward.
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "open (#184, spec 06 G13): a producer whose clock runs 200 ms ahead earns every block reward"]
    async fn same_slot_reward_share_is_fair_with_a_fast_clock() {
        let run = fairness_run(&[(0, 200)], &[(0, -200), (1, 0), (2, 0)]).await;
        assert_fair_chain_share(&run, "producer 0 clock +200 ms");
    }

    /// See `apply_cost_per_block_stays_within_budget`.
    const APPLY_GROWTH_MAX: f64 = 3.0;
    /// See `apply_cost_per_block_stays_within_budget`.
    const APPLY_BUDGET_MS: f64 = 250.0;

    /// Per-block apply cost (planset H7, ADR CV-6): two producers past
    /// activation through the node's code paths on RocksDB stores, 120 slots.
    /// Measured: the time each node spends admitting a peer's gossiped block
    /// (`on_new_block`: stored -> DAG -> applied, since admission executes on
    /// receive). This is the per-block cost that is ~3 s on r1006 and ~35 ms
    /// on the devnet. CI thresholds:
    ///
    /// * the median over the last 30 slots is at most [`APPLY_GROWTH_MAX`]
    ///   times the median over slots 10..40: a cost that grows with the store
    ///   (the H7 class: full scans, body reloads) fails;
    /// * the median over all blocks is at most `CITRATE_APPLY_BUDGET_MS`
    ///   (default [`APPLY_BUDGET_MS`], a debug build on a loaded CI runner).
    ///
    /// Prints an `APPLYCOST` line with the numbers. Blocks carry no
    /// transactions, so this is the consensus and storage cost per block, not
    /// execution.
    #[tokio::test(flavor = "current_thread")]
    async fn apply_cost_per_block_stays_within_budget() {
        if !in_child() {
            let out =
                child_output("split_heal_tests::tests::apply_cost_per_block_stays_within_budget");
            for line in out.lines().filter(|l| l.starts_with("APPLYCOST")) {
                eprintln!("{line}");
            }
            return;
        }
        // Simulated time runs ahead of the wall clock (one slot = 2 s), and
        // admission refuses blocks too far in the future: stay inside it.
        const SLOTS: u64 = 120;
        /// Slots of the early window (after warm-up and activation).
        const EARLY: (u64, u64) = (10, 40);
        let mut fleet = Fleet::new(2).await;
        let mut rng = Rng(0x00C0_FFEE_D00D_F00D);
        for _ in 0..SLOTS {
            let o = rng.order(2);
            fleet.slot(&o).await;
        }
        let heights = fleet.applied_heights().await;
        // r1007 G9: a chain gains at most one height per slot (every parent is
        // in an earlier slot), so SLOTS slots carry at most SLOTS heights; the
        // first slot seals nothing (the #126 initial-sync gate opens at the
        // first sync tick). Before G9 a producer stacked a second block on a
        // same-round block, and the bound was `>= SLOTS`.
        assert!(
            heights.iter().all(|h| *h >= SLOTS - 1 && *h <= SLOTS),
            "both nodes apply every slot after the first, one height per slot: {heights:?}"
        );
        // Every gossiped block a node admitted, by slot, in ms.
        let per_block: Vec<(u64, f64)> = fleet
            .admit_cost
            .iter()
            .map(|(slot, d)| (*slot, d.as_secs_f64() * 1e3))
            .collect();
        fn median(mut v: Vec<f64>) -> f64 {
            assert!(!v.is_empty(), "no samples");
            v.sort_by(|a, b| a.total_cmp(b));
            v[v.len() / 2]
        }
        let window = |lo: u64, hi: u64| {
            median(
                per_block
                    .iter()
                    .filter(|(slot, _)| (lo..hi).contains(slot))
                    .map(|(_, ms)| *ms)
                    .collect(),
            )
        };
        let early = window(EARLY.0, EARLY.1);
        let late = window(SLOTS - 30, SLOTS + 1);
        let all = median(per_block.iter().map(|(_, ms)| *ms).collect());
        let budget = std::env::var("CITRATE_APPLY_BUDGET_MS")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(APPLY_BUDGET_MS);
        eprintln!(
            "APPLYCOST blocks={} samples={} admit_apply_ms_per_block median={all:.2} \
             early={early:.2} late={late:.2} growth={:.2} budget_ms={budget}",
            heights.iter().max().copied().unwrap_or(0),
            per_block.len(),
            late / early
        );
        assert!(
            late <= early * APPLY_GROWTH_MAX,
            "apply cost grew with the store: {early:.2} ms/block early, {late:.2} ms/block late"
        );
        assert!(
            all <= budget,
            "apply cost {all:.2} ms/block over the {budget} ms budget"
        );
    }

    /// The highest applied height in each of `groups`.
    async fn group_tops(fleet: &Fleet, groups: &[Vec<usize>]) -> Vec<u64> {
        let heights = fleet.applied_heights().await;
        groups
            .iter()
            .map(|g| g.iter().map(|i| heights[*i]).max().unwrap_or(0))
            .collect()
    }

    /// CV-5 (H2): a 4v3 split, the three ahead, where both sides then hear
    /// each other's new blocks but can never fetch the ancestry they lack
    /// (serving between the sides is starved, H3), so neither can admit the
    /// other's branch. Past
    /// the refuse window at most one branch may keep growing: a producer that
    /// cannot reconcile with a branch fork choice would prefer stops sealing
    /// instead of extending its own, and the other side keeps the chain live.
    ///
    /// The harness runs in real time, so the producers' refuse window is set
    /// to zero: every slot of the cut is past it.
    #[tokio::test(flavor = "current_thread")]
    async fn no_two_branches_grow_while_producers_cannot_admit_each_other() {
        if !in_child() {
            return run_in_child(
                "split_heal_tests::tests::no_two_branches_grow_while_producers_cannot_admit_each_other",
            );
        }
        let n = 7;
        let groups = vec![vec![0, 1, 2, 3], vec![4, 5, 6]];
        let side = |i: usize| usize::from(i >= 4);
        let mut fleet = Fleet::with_refuse_window(n, Some(std::time::Duration::ZERO)).await;
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for _ in 0..ACT + 4 {
            let o = rng.order(n);
            fleet.slot(&o).await;
        }
        // Partition: the three build a branch of their own while the four are
        // held (a stall on their side), so the minority's branch leads. That is
        // the case the base's 60 s cap sealed through: a branch backed by three
        // of seven is evidence, but not a majority.
        fleet.set_links(|i, j| side(i) == side(j));
        fleet.quiet = groups[0].iter().copied().collect();
        for _ in 0..6 {
            let o = rng.order(n);
            fleet.slot(&o).await;
        }
        fleet.quiet.clear();
        // Gossip crosses again, requests and answers do not.
        fleet.set_links(|_, _| true);
        fleet.serve_cut = (0..n)
            .map(|i| (0..n).map(|j| side(i) != side(j)).collect())
            .collect();
        for _ in 0..5 {
            let o = rng.order(n);
            fleet.slot(&o).await;
        }
        let settled = group_tops(&fleet, &groups).await;
        for _ in 0..30 {
            let o = rng.order(n);
            fleet.slot(&o).await;
        }
        let end = group_tops(&fleet, &groups).await;
        let grew: Vec<bool> = settled.iter().zip(&end).map(|(a, b)| b > a).collect();
        assert!(
            !(grew[0] && grew[1]),
            "both branches kept growing while neither side could admit the other: \
             {settled:?} -> {end:?}; {}",
            fleet.describe().await
        );
        assert!(
            grew[0] || grew[1],
            "neither branch grew: the gate held both sides off ({settled:?} -> {end:?})"
        );
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
            "pb < sync_recovery::TICK_PENDING_GATE && !held_tip",
            "sync_recovery::answer_is_held_ahead(",
            "tip_reask_for_rx.lock().note_answer(",
            "tip_reask_for_loop.lock().hold(",
            "|h| held_heads.contains(h)",
            "sync_rejoin::classify(",
            "sel.record_serve(",
            // Serving plane (ADR CV-6).
            "peer_manager.set_serve_sink(serve_tx)",
            "serve_plane::spawn(storage.clone(), peer_manager.clone(), serve_rx)",
            // Sync tick.
            "attested_for_sync.take_resync_request()",
            "sync_rejoin::start_resync(",
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

    /// H1 (lead, from the CHAIN-SAFETY lane): a 4v3 split, then the sides hear
    /// each other's new blocks but serving between them is starved, and the
    /// three have stopped sealing (held quiet, as a producer that cannot
    /// reconcile does). When serving returns, the stopped side must rejoin the
    /// four's chain as a follower within 60 slots, without sealing first.
    #[tokio::test(flavor = "current_thread")]
    async fn stopped_side_rejoins_after_serving_returns() {
        if !in_child() {
            return run_in_child(
                "split_heal_tests::tests::stopped_side_rejoins_after_serving_returns",
            );
        }
        let n = 7;
        let side_a = [0usize, 1, 2, 3];
        let side_b = [4usize, 5, 6];
        let in_a = |i: usize| i < 4;
        let mut fleet = Fleet::new(n).await;
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for _ in 0..ACT + 4 {
            let o = rng.order(n);
            fleet.slot(&o).await;
        }
        // Partition: both sides build their own branch.
        fleet.set_links(|i, j| in_a(i) == in_a(j));
        for _ in 0..10 {
            let o = rng.order(n);
            fleet.slot(&o).await;
        }
        // Links back, but across the split only gossip arrives; the three stop
        // sealing.
        fleet.set_links(|_, _| true);
        for i in 0..n {
            for j in 0..n {
                fleet.serve_cut[i][j] = in_a(i) != in_a(j);
            }
        }
        fleet.quiet.extend(side_b);
        for _ in 0..30 {
            let o = rng.order(n);
            fleet.slot(&o).await;
        }
        // Serving returns. The three stay stopped: they must follow.
        fleet.serve_cut = vec![vec![false; n]; n];
        let heights = fleet.applied_heights().await;
        let (top_node, top) = side_a
            .iter()
            .map(|i| (*i, heights[*i]))
            .max_by_key(|(_, h)| *h)
            .expect("side a");
        let target = *fleet.chain(top_node).await.get(&top).expect("a's head");
        let mut rejoined_at = None;
        for slot in 1..=60u64 {
            let o = rng.order(n);
            fleet.slot(&o).await;
            let mut all = true;
            for i in side_b {
                if fleet.chain(i).await.get(&top) != Some(&target) {
                    all = false;
                    break;
                }
            }
            if all {
                rejoined_at = Some(slot);
                break;
            }
        }
        assert!(
            rejoined_at.is_some(),
            "the stopped side did not rejoin within 60 slots of serving returning \
             (target height {top}): {}",
            fleet.describe().await
        );
    }

    /// What one run of the stopped-side scenario ended with
    /// ([`stopped_side`]).
    struct StoppedSide {
        /// The three's tip height minus the highest height the two sides
        /// still agree on, when serving returns.
        fork_depth: u64,
        /// The three's highest applied height 5 slots into the cut and at its
        /// end.
        cut_tops: (u64, u64),
        /// Slots after serving returned until all three hold the four's chain
        /// at the four's height of that moment (None: not within 60).
        rejoined_at: Option<u64>,
        /// With `pruned`: for each of the three, its data dir replayed by the
        /// reference path (S3-3c) after the rejoin, and again with the block
        /// at the given height changed.
        replays: Vec<(
            String,
            citrate_replay_ref::Report,
            citrate_replay_ref::Report,
            u64,
        )>,
        detail: String,
    }

    /// H1 family (see `stopped_side_rejoins_after_serving_returns`): warm up,
    /// a 4v3 split for `partition` slots, then the links come back with only
    /// gossip crossing the split for `cut` slots, then serving returns and the
    /// three get 60 slots to follow the four. With `gate`, the three are not
    /// held quiet: they run the real producer gate (CV-5, refuse window zero
    /// as the harness runs in real time), which must stop them on its own;
    /// without it they are held quiet, as a follower or a producer whose
    /// operator stopped it. With `pruned`, the warm-up runs past the DAG
    /// prune retention and the three restart at the end of the partition with
    /// their stores pruned to it (a replay from genesis is then refused).
    async fn stopped_side(partition: u64, cut: u64, gate: bool, pruned: bool) -> StoppedSide {
        let n = 7;
        let side_a = [0usize, 1, 2, 3];
        let side_b = vec![4usize, 5, 6];
        let in_a = |i: usize| i < 4;
        let mut fleet = if gate {
            Fleet::with_refuse_window(n, Some(std::time::Duration::ZERO)).await
        } else {
            Fleet::new(n).await
        };
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let retain = HARNESS_PRUNE_RETAIN;
        loop {
            let o = rng.order(n);
            fleet.slot(&o).await;
            let low = *fleet.applied_heights().await.iter().min().expect("nodes");
            if fleet.slot_no >= ACT + 4 && (!pruned || low > retain + 50) {
                break;
            }
        }
        fleet.set_links(|i, j| in_a(i) == in_a(j));
        for _ in 0..partition {
            let o = rng.order(n);
            fleet.slot(&o).await;
        }
        if pruned {
            fleet.prune_retain = Some(retain);
            for i in side_b.iter().copied() {
                fleet.restart(i).await;
            }
            fleet.prune_retain = None;
        }
        fleet.set_links(|_, _| true);
        for i in 0..n {
            for j in 0..n {
                fleet.serve_cut[i][j] = in_a(i) != in_a(j);
            }
        }
        if !gate {
            fleet.quiet.extend(side_b.iter().copied());
        }
        let b = [side_b.clone()];
        let mut settled = 0;
        for k in 0..cut {
            if k == 5 {
                settled = group_tops(&fleet, &b).await[0];
            }
            let o = rng.order(n);
            fleet.slot(&o).await;
        }
        let cut_end = group_tops(&fleet, &b).await[0];
        fleet.serve_cut = vec![vec![false; n]; n];
        let heights = fleet.applied_heights().await;
        let (top_node, top) = side_a
            .iter()
            .map(|i| (*i, heights[*i]))
            .max_by_key(|(_, h)| *h)
            .expect("side a");
        let a_chain = fleet.chain(top_node).await;
        let target = *a_chain.get(&top).expect("a's head");
        let b_chain = fleet.chain(side_b[0]).await;
        let b_tip = heights[side_b[0]];
        let fork = (0..=b_tip)
            .rev()
            .find(|h| b_chain.contains_key(h) && b_chain.get(h) == a_chain.get(h))
            .unwrap_or(0);
        let mut rejoined_at = None;
        for slot in 1..=60u64 {
            let o = rng.order(n);
            fleet.slot(&o).await;
            let mut all = true;
            for i in side_b.iter().copied() {
                if fleet.chain(i).await.get(&top) != Some(&target) {
                    all = false;
                    break;
                }
            }
            if all {
                rejoined_at = Some(slot);
                break;
            }
        }
        let mut replays = Vec::new();
        if pruned && rejoined_at.is_some() {
            use citrate_replay_ref::{replay, SelectedChain};
            let k = fork + 10;
            for i in side_b.iter().copied() {
                let rec = fleet.record(i);
                // Optional: keep the recording for the `replay-diff` CLI
                // (tools/replay-ref), e.g. for a release-gate run. Off by default.
                if let Ok(out) = std::env::var("CITRATE_SPLIT_HEAL_RECORDING_DIR") {
                    let path = std::path::Path::new(&out).join(format!("stopped-side-node{i}.rec"));
                    rec.write_to(&path).expect("write the recording");
                }
                let clean = replay(&rec, &SelectedChain).await.expect("replay");
                let mut bad = rec.clone();
                if let Some(b) = bad.chain_block_mut(k) {
                    b.header.coinbase = [0xEE; 20];
                }
                let mutated = replay(&bad, &SelectedChain).await.expect("replay");
                replays.push((format!("node {i}"), clean, mutated, k));
            }
        }
        StoppedSide {
            fork_depth: b_tip.saturating_sub(fork),
            cut_tops: (settled, cut_end),
            rejoined_at,
            replays,
            detail: format!(
                "target {top}, fork at {fork}, three at {b_tip}: {}",
                fleet.describe().await
            ),
        }
    }

    /// H1, made independent of the wall clock: the same as
    /// `stopped_side_rejoins_after_serving_returns` with a 90-slot cut, long
    /// enough that every one of the four times out past the de-prefer
    /// threshold at the three even when the run takes no wall time (the
    /// 30-slot cut gets there only when slots take real time, as on a loaded
    /// CI runner). The three's siblings keep answering with nothing new and
    /// bottom out; the three must still ask the four again once serving
    /// returns.
    #[tokio::test(flavor = "current_thread")]
    async fn stopped_side_rejoins_after_a_long_serving_cut() {
        if !in_child() {
            return run_in_child(
                "split_heal_tests::tests::stopped_side_rejoins_after_a_long_serving_cut",
            );
        }
        let r = stopped_side(10, 90, false, false).await;
        assert!(
            r.rejoined_at.is_some(),
            "the stopped side did not rejoin within 60 slots of serving returning \
             after a 90-slot cut ({})",
            r.detail
        );
    }

    /// H1 against the real CV-5 producer gate instead of a held-quiet model:
    /// nobody is told to stop. While the three hear the four's heavier branch
    /// and cannot fetch it, their gate must stop them (cannot reconcile); when
    /// serving returns they must follow the four within 60 slots.
    #[tokio::test(flavor = "current_thread")]
    async fn gate_stopped_side_rejoins_after_serving_returns() {
        if !in_child() {
            return run_in_child(
                "split_heal_tests::tests::gate_stopped_side_rejoins_after_serving_returns",
            );
        }
        let r = stopped_side(10, 90, true, false).await;
        assert_eq!(
            r.cut_tops.0, r.cut_tops.1,
            "the three kept sealing on their branch while they could not admit \
             the four's heavier one (CV-5): {}",
            r.detail
        );
        assert!(
            r.rejoined_at.is_some(),
            "the gate-stopped side did not rejoin within 60 slots of serving \
             returning ({})",
            r.detail
        );
    }

    /// CV-7: the same, with the three's branch more than `SNAPSHOT_RING_DEPTH`
    /// (100, the in-memory reorg ring and the whole undo window before S3-4)
    /// blocks above the fork point when serving returns. The switch reverts
    /// from the undo records (`REORG_UNDO_DEPTH` = 10,000 since S3-4).
    #[tokio::test(flavor = "current_thread")]
    async fn stopped_side_forked_beyond_the_reorg_window_rejoins() {
        if !in_child() {
            return run_in_child(
                "split_heal_tests::tests::stopped_side_forked_beyond_the_reorg_window_rejoins",
            );
        }
        // r1007 G9: a branch gains at most one height per slot, so the
        // partition must be longer than the 100-block ring (it was 45 slots
        // when producers stacked several heights per round).
        let r = stopped_side(110, 30, false, false).await;
        assert!(
            r.fork_depth > crate::canonical_apply::SNAPSHOT_RING_DEPTH,
            "fixture: the three's branch is only {} deep ({})",
            r.fork_depth,
            r.detail
        );
        assert!(
            r.rejoined_at.is_some(),
            "a side forked {} deep did not rejoin within 60 slots of serving \
             returning ({})",
            r.fork_depth,
            r.detail
        );
    }

    /// CV-7 (H6) on a pruned store: the same >100-deep fork, with the three
    /// restarted at the end of the partition on stores pruned to
    /// `HARNESS_PRUNE_RETAIN`, so the rebuild from genesis is refused
    /// (`RebuildDecision::RefusePruned`) and the switch needs undo records
    /// for the whole depth. Red on r1007/candidate: the three fetch the four's
    /// whole chain (stored tip 1597) but the applied tip stays on their branch
    /// at 1192. S3-4 (undo window = prune retention, CV-7a) makes it green.
    #[tokio::test(flavor = "current_thread")]
    async fn pruned_stopped_side_forked_beyond_the_reorg_window_rejoins() {
        if !in_child() {
            return run_in_child(
                "split_heal_tests::tests::pruned_stopped_side_forked_beyond_the_reorg_window_rejoins",
            );
        }
        // r1007 G9: one height per slot; see the unpruned variant.
        let r = stopped_side(110, 30, false, true).await;
        assert!(
            r.fork_depth > crate::canonical_apply::SNAPSHOT_RING_DEPTH,
            "fixture: the three's branch is only {} deep ({})",
            r.fork_depth,
            r.detail
        );
        assert!(
            r.rejoined_at.is_some(),
            "a pruned side forked {} deep did not rejoin within 60 slots of \
             serving returning ({})",
            r.fork_depth,
            r.detail
        );
        // S3-3c: each of the three, after switching that fork from its undo
        // records, replays with zero divergence from genesis through the
        // independent reference path; one changed block is caught at its height.
        assert_eq!(r.replays.len(), 3, "{}", r.detail);
        for (name, clean, mutated, k) in &r.replays {
            assert_eq!(clean.divergence, None, "{name}: {clean:?}");
            assert_eq!(clean.matched, clean.tip_height, "{name}: {clean:?}");
            assert_eq!(
                mutated.divergence.as_ref().map(|d| d.height),
                Some(*k),
                "{name}: {mutated:?}"
            );
        }
    }
}
