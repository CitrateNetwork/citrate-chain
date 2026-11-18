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
// block-validity hardening, active from block 1 on r1006, and the r1007 MPT
// state root, CV-14) are switched on in a child process so no other test in
// this binary sees them. Checkpoint finality
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
    /// The producer's pool (the cold-sync runs feed it ~10 KB transactions).
    mempool: Arc<Mempool>,
    sync: SyncManager,
    rejoin: parking_lot::Mutex<sync_rejoin::RejoinTracker>,
    /// Header-first ancestor sync (`ancestor_sync`, protocol 1.3).
    ancestor: parking_lot::Mutex<crate::ancestor_sync::AncestorSync>,
    /// Deferred-gossip height claims per delivering peer (`sync_peer`).
    deferred_heights: sync_peer::DeferredHeights,
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
    /// Nodes that serve `GetBlocks` as a server built before #477 does (a
    /// 60 KiB reply budget; replies split as since #476).
    legacy_serve: HashSet<usize>,
    /// Nodes running a binary from before ancestor sync: they advertise
    /// protocol 1.2 in their handshake and run no ancestor-sync episode
    /// (a rolling upgrade's old half).
    legacy_protocol: HashSet<usize>,
    /// Accounts the genesis state funds.
    alloc: Vec<(citrate_execution::types::Address, U256)>,
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

/// The genesis state: `alloc` funded, nothing else.
fn genesis_state(
    alloc: &[(citrate_execution::types::Address, U256)],
) -> citrate_execution::state::StateSnapshot {
    let db = Arc::new(StateDB::new());
    for (addr, balance) in alloc {
        db.accounts.create_account_if_not_exists(*addr);
        db.accounts.set_balance(*addr, *balance);
    }
    Executor::new(db).state_snapshot()
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
    /// The stopped process's open store and in-memory state (boxed: a
    /// snapshot is larger than the other variants).
    Snapshot(Box<citrate_execution::state::StateSnapshot>),
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
        alloc: &[(citrate_execution::types::Address, U256)],
    ) -> Self {
        let state_db = Arc::new(StateDB::new());
        let fresh = matches!(boot, Boot::Fresh);
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
            executor.state_restore(*state);
        } else if fresh && !alloc.is_empty() {
            executor.state_restore(genesis_state(alloc));
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
        // The pool is the applicator's too, as `start_node` wires it: a reorg
        // gives the abandoned blocks' transactions back to it.
        let mempool = Arc::new(Mempool::new(MempoolConfig {
            require_valid_signature: false,
            ..Default::default()
        }));
        let app = Arc::new(
            CanonicalApplicator::new(executor.clone(), storage.clone())
                .with_fork_choice(ghostdag.clone())
                .with_dag_prune_floor(dag.clone())
                .with_mempool(mempool.clone()),
        );
        app.set_genesis(genesis_state(alloc), genesis.header.block_hash);
        let adm = Arc::new(BlockAdmission::new(
            storage.clone(),
            dag.clone(),
            ghostdag.clone(),
            Some(app.clone()),
        ));
        adm.seed_genesis().await;
        let _ = adm.reconcile().await;
        ghostdag.reconcile_tips_from_dag_store().await;
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
            mempool.clone(),
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
        .with_applicator(app.clone())
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
            mempool,
            sync,
            rejoin: parking_lot::Mutex::new(sync_rejoin::RejoinTracker::new()),
            ancestor: parking_lot::Mutex::new(crate::ancestor_sync::AncestorSync::new()),
            deferred_heights: sync_peer::DeferredHeights::new(),
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
        Self::with_genesis(n, refuse_window, Vec::new()).await
    }

    /// A fleet whose genesis state funds `alloc` (the cold-sync runs' senders).
    pub(crate) async fn with_genesis(
        n: usize,
        refuse_window: Option<std::time::Duration>,
        alloc: Vec<(citrate_execution::types::Address, U256)>,
    ) -> Self {
        let empty_root = {
            let e = Executor::new(Arc::new(StateDB::new()));
            e.state_restore(genesis_state(&alloc));
            e.calculate_state_root()
        };
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
                    &alloc,
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
                // What the transport handshake records (`transport.rs`).
                info.version = Some(citrate_network::ProtocolVersion::CURRENT);
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
            legacy_serve: HashSet::new(),
            legacy_protocol: HashSet::new(),
            alloc,
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
        // The transport handshake (Hello / HelloAck) gives each side the other's
        // head as it connects (`transport.rs`), so a node of a fresh network has
        // heard every peer's genesis head before its first sync tick. The
        // initial-sync condition counts only heard peers (R2 early seal).
        fleet.handshake().await;
        fleet
    }

    /// Node `j` runs a binary from before ancestor sync: every peer's handle
    /// on it records the 1.2 handshake it sends, and it runs no episode.
    pub(crate) async fn set_legacy_protocol(&mut self, j: usize) {
        self.legacy_protocol.insert(j);
        for i in 0..self.nodes.len() {
            if let Some((p, _)) = self.peers[i][j].as_ref() {
                p.info.write().await.version =
                    Some(citrate_network::ProtocolVersion::CHECKPOINT_CERT_SYNC);
            }
        }
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
                (storage, dir, Boot::Snapshot(Box::new(boot)))
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
            &self.alloc,
        )
        .await;
        self.nodes.insert(i, node);
        self.attach_peers(i).await;
    }

    /// Every link reconnects: each node's view of each peer's head becomes that
    /// peer's applied tip, as the transport handshake sets it.
    async fn handshake(&mut self) {
        let n = self.nodes.len();
        let now = self.now();
        for j in 0..n {
            let (hash, height) = self.nodes[j].applied();
            for i in (0..n).filter(|i| *i != j) {
                let peer = self.peer(i, j);
                let mut info = peer.info.write().await;
                info.head_height = height;
                info.reported_head_height = height;
                // The handshake's time on the harness's simulated clock.
                info.reported_at = now;
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
        // A node on the 1.2 binary cannot decode the 1.3 messages and would
        // drop the connection: none may ever reach it (`Peer::send` gates).
        assert!(
            !(self.legacy_protocol.contains(&at) && msg.is_ancestor_sync()),
            "a 1.2 node (p{at}) was sent {} by p{from}",
            msg.kind()
        );
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
                        let legacy = self.legacy_serve.contains(&at);
                        let node = &mut self.nodes[at];
                        while let Some((asker, request)) = node.serve_q.take_next() {
                            // The messages that go on the wire (a `Blocks`
                            // reply split under the Noise cap, #476).
                            let frames = if legacy {
                                legacy_answer_frames(&node.storage, &request)
                            } else {
                                crate::serve_plane::answer_frames(&node.storage, &request)
                            };
                            for reply in frames {
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
                let applied = node.applied();
                let round = node.sync.pipeline_on_answer(applied).await;
                for p in &round.timed_out {
                    node.sel.record_timeout(&p.0);
                }
            }
            NetworkMessage::NewBlock { block } => {
                // Gossip validation relays a block once to every other peer
                // (`GossipProtocol::handle_new_block`), before admission.
                let hash = block.header.block_hash;
                let fresh = !node.adm.is_fully_admitted(&hash).await;
                let relay = fresh && node.relayed.insert(hash);
                let t = std::time::Instant::now();
                node.on_new_block(&peer, &pid, block.clone()).await;
                // Admission's cost plus the apply it hands the drain task.
                node.run_woken_drain().await;
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
            NetworkMessage::Blocks { blocks } => {
                node.on_blocks(&peer, &pid, blocks).await;
                node.run_woken_drain().await;
            }
            // main.rs `NetworkMessage::Ancestor` arm.
            NetworkMessage::Ancestor {
                common,
                tip,
                tip_blue_work,
                headers,
            } => {
                let finalized = node.app.finalized_height_handle().load(Ordering::SeqCst);
                let _ = crate::ancestor_sync::on_reply(
                    &node.ancestor,
                    &node.storage,
                    finalized,
                    &pid.0,
                    common,
                    tip,
                    tip_blue_work,
                    &headers,
                    node.clock,
                );
            }
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
            let ancestor_on = !self.legacy_protocol.contains(&i);
            self.nodes[i].tick(&peers, since, ancestor_on).await;
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
        // main.rs: the head rises only for a block this node verified
        // (`sync_peer::gossip_raises_head`).
        if self.adm.is_fully_admitted(&block.header.block_hash).await {
            sync_peer::raise_gossip_head(Some(peer.clone()), &block).await;
            return;
        }
        match self.adm.admit(&block).await {
            AdmitOutcome::Admitted { .. } => {
                sync_peer::record_verified_height(&self.max_seen, block.header.height);
                sync_peer::raise_gossip_head(Some(peer.clone()), &block).await;
                self.attested.observe(&self.storage, &block);
            }
            AdmitOutcome::AlreadyAdmitted => {
                sync_peer::raise_gossip_head(Some(peer.clone()), &block).await;
            }
            AdmitOutcome::Deferred { missing_parent } => {
                self.attested.observe_deferred(&block);
                let applied_now = self.applied().1;
                let corroborated = self.deferred_heights.record(
                    &pid.0,
                    block.header.height,
                    self.pm.get_all_peers().len(),
                );
                if let Some(h) = corroborated {
                    sync_peer::record_unverified_height(&self.max_seen, h, applied_now);
                }
                if sync_peer::gossip_raises_head(false, block.header.height, corroborated) {
                    sync_peer::raise_gossip_head(Some(peer.clone()), &block).await;
                }
                self.ancestor.lock().note_deferred(self.clock);
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

    /// The node's drain task (`start_node`): admission never executes, it
    /// wakes this task (`CanonicalApplicator::request_drain`), which applies
    /// what was stored and follows fork choice. The harness runs it right
    /// after the message that woke it.
    async fn run_woken_drain(&self) {
        let wake = self.app.drain_wake();
        if tokio::time::timeout(std::time::Duration::ZERO, wake.notified())
            .await
            .is_ok()
        {
            self.app.drive_drain().await;
        }
    }

    /// main.rs `NetworkMessage::Blocks` arm.
    async fn on_blocks(&mut self, peer: &Arc<Peer>, pid: &PeerId, blocks: Vec<Block>) {
        let answer_hashes: Vec<Hash> = blocks.iter().map(|b| b.header.block_hash).collect();
        let receipt = self
            .sync
            .handle_blocks(pid, blocks)
            .await
            .unwrap_or_default();
        let mut pending = self.sync.drain_validated_blocks().await;
        let answer_top = pending.iter().map(|b| b.header.height).max();
        let answer_highest = pending
            .iter()
            .max_by_key(|b| b.header.height)
            .map(|b| (b.header.block_hash, b.header.height));
        let verified: HashSet<Hash> = pending.iter().map(|b| b.header.block_hash).collect();
        let answers_rejoin = if receipt.pipelined {
            None
        } else {
            self.rejoin
                .lock()
                .take_answer(&pid.0, &answer_hashes, &verified)
        };
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
        {
            let mut anc = self.ancestor.lock();
            if deferred_from_answer > 0 {
                anc.note_deferred(self.clock);
            }
            let storage = self.storage.clone();
            let _ = anc.on_blocks(&pid.0, &answer_hashes, self.clock, |h| {
                storage.blocks.has_block(h).unwrap_or(false)
            });
        }
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
        if !receipt.pipelined {
            self.tip_reask
                .note_answer(applied_hash_now, held_ahead, self.clock);
        }
        let stale_anchor = if receipt.pipelined {
            receipt.new_blocks == 0 && receipt.received > 0
        } else {
            sync_recovery::answer_anchor_was_stale(
                self.sync.last_block_anchor_height(),
                applied_now,
                answer_hashes.len(),
            ) || held_ahead
        };
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
            let answer = sync_rejoin::classify_answer(
                answer_hashes.is_empty(),
                newly_admitted,
                highest,
                deferred_from_answer,
                answer_highest,
            );
            let t = self.rejoin.lock().on_answer(answer, gap > 0, anchor_height);
            gave_up = matches!(t, Some(sync_rejoin::Transition::GaveUp { .. }));
        }
        let (served_new, batch) = if receipt.pipelined {
            (receipt.new_blocks, receipt.received.max(1))
        } else {
            (newly_admitted, 32)
        };
        self.sel.record_serve(
            &pid.0,
            served_new,
            highest.map(|(_, h)| h).unwrap_or(0),
            gap,
            batch,
            stale_anchor,
        );
        if gave_up {
            self.sel.record_give_up(&pid.0);
        }
        // #477: issue on answer.
        let round = self.sync.pipeline_on_answer(self.applied()).await;
        for p in &round.timed_out {
            self.sel.record_timeout(&p.0);
        }
    }

    /// main.rs periodic sync tick, over the peers this node is connected to;
    /// `since_start` is how long this process has run.
    async fn tick(
        &mut self,
        connected: &[Arc<Peer>],
        since_start: std::time::Duration,
        ancestor_on: bool,
    ) {
        let mut best_h = 0u64;
        let mut candidates = Vec::new();
        let mut split = Vec::new();
        let mut heard = 0usize;
        for p in connected {
            let info = p.info.read().await;
            if sync_recovery::peer_head_heard(&info.head_hash) {
                heard = heard.saturating_add(1);
            }
            // main.rs: the self-reported head , 0 = none, timed
            // when reported; the newest wins.
            if info.reported_head_height > 0 {
                self.sel.note_reported_head_at(
                    &info.id.0,
                    info.reported_head_height,
                    info.reported_at,
                );
            }
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
            && sync_recovery::initial_sync_complete(applied_height, target, heard, since_start)
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
        // #477: the pipelined download, as main.rs runs it.
        let pipeline_peers: Vec<(citrate_network::sync_pipeline::PipelinePeer, Arc<Peer>)> =
            connected
                .iter()
                .zip(candidates.iter())
                .map(|(p, c)| {
                    (
                        citrate_network::sync_pipeline::PipelinePeer {
                            id: PeerId::new(c.id.clone()),
                            head_height: c.head_height,
                            admissible: sync_peer::pipeline_peer_admissible(c, applied_height),
                        },
                        p.clone(),
                    )
                })
                .collect();
        // main.rs: ancestor sync, then the pipeline and the tick's own request
        // stand aside while an episode fetches a branch below our tip.
        let ancestor_owns = if ancestor_on {
            let storage = self.storage.clone();
            let cands = crate::ancestor_sync::candidates(connected, |h| {
                storage.blocks.has_block(h).unwrap_or(true)
            })
            .await;
            let finalized = self.app.finalized_height_handle().load(Ordering::SeqCst);
            let _ = crate::ancestor_sync::run_tick(
                &self.ancestor,
                &self.storage,
                &self.sync,
                &cands,
                finalized,
                applied_height < target,
                self.clock,
            )
            .await;
            self.ancestor.lock().owns_sync()
        } else {
            false
        };
        let following_tip = self.rejoin.lock().is_following_tip() && !ancestor_owns;
        let pipeline_round = self
            .sync
            .pipeline_tick(applied_tip, pipeline_peers, following_tip)
            .await;
        let pipelined = self.sync.pipeline_active();
        let request_peer = if ancestor_owns {
            None
        } else if let Some(id) = chosen {
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
            let (_ph, pb) = self.sync.pending_counts().await;
            let held_tip = self.tip_reask.hold(from, applied_tip.0, self.clock);
            if !pipelined && pb < sync_recovery::TICK_PENDING_GATE && !held_tip {
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
        for pid in &pipeline_round.timed_out {
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
    child_output_with(test, &[])
}

/// [`child_output`] with extra test-harness arguments (`--include-ignored`
/// for a measurement run).
fn child_output_with(test: &str, extra: &[&str]) -> String {
    let exe = std::env::current_exe().expect("exe");
    let out = std::process::Command::new(exe)
        .args([test, "--exact", "--nocapture", "--test-threads=1"])
        .args(extra)
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
    // CV-14 (an r1007 genesis rule): the post-activation runs root state with
    // the standard incremental MPT, as an r1007 node does.
    citrate_execution::mpt_state_root::set_mpt_state_root_height(Some(0));
    true
}

/// What a server built before #477 sends for `request`: `Blocks` replies
/// under the old 60 KiB budget, split as since #476.
fn legacy_answer_frames(storage: &StorageManager, request: &NetworkMessage) -> Vec<NetworkMessage> {
    match request {
        NetworkMessage::GetBlocks { from, count, .. } => {
            crate::block_serve::chunk_for_noise(crate::block_serve::serve_blocks_within(
                storage,
                from,
                *count,
                crate::block_serve::LEGACY_BLOCKS_RESPONSE_BYTES,
            ))
            .into_iter()
            .map(|blocks| NetworkMessage::Blocks { blocks })
            .collect()
        }
        other => crate::serve_plane::answer_frames(storage, other),
    }
}

/// #477: a cold node syncing a static DAG from a few servers, over a modelled
/// network.
///
/// Seven producers seal for `slots` slots (seven siblings per height, every
/// `fat_every`-th slot one of them carrying a ~10 KB transaction, the r1007
/// height-1553 shape), then stop. A fresh node, wired like every node here
/// (`Node::start`: storage-backed executor, applicator with fork choice,
/// admission, sync manager), connects to `servers` only and syncs through the
/// code the node runs: its sync tick every 2 s, the `Blocks` / `Headers`
/// handlers, and the servers' serving plane (`serve_plane::answer_frames`, or
/// a pre-#477 server's 60 KiB replies for `legacy`).
///
/// Time is simulated: a message from a server reaches the cold node one
/// `latency_ms` later, after every earlier message to it has, at
/// `downlink_mbit`. With `count_cpu`, the cold node's own processing time
/// (validation, admission, apply, measured on this host) and a server's answer
/// time are added to the clock, so the blocks/s reported are what the sync
/// logic, this host's CPU and that link allow together; without it (debug
/// builds) they are what the sync logic and the link allow.
#[derive(Clone, Debug)]
pub(crate) struct ColdSync {
    pub slots: u64,
    pub fat_every: Option<u64>,
    pub servers: Vec<usize>,
    pub latency_ms: u64,
    pub downlink_mbit: u64,
    pub count_cpu: bool,
    pub max_virtual_secs: u64,
}

/// What one cold sync did.
#[derive(Debug, Clone)]
pub(crate) struct ColdSyncReport {
    pub legacy: Vec<usize>,
    pub count_cpu: bool,
    pub tip: u64,
    pub dag_blocks: usize,
    pub dag_bytes: u64,
    pub max_siblings: usize,
    pub fat_blocks: usize,
    /// Simulated ms at which the cold node's applied tip reached `tip`.
    pub reached_ms: Option<u64>,
    pub applied: u64,
    pub virtual_ms: u64,
    pub wall: std::time::Duration,
    pub messages_to_cold: usize,
    pub bytes_to_cold: u64,
    pub requests_from_cold: usize,
}

impl ColdSyncReport {
    /// DAG blocks per simulated second until the tip was reached (or until
    /// the run stopped, counting what was applied).
    pub(crate) fn blocks_per_sec(&self) -> u64 {
        let ms = self.reached_ms.unwrap_or(self.virtual_ms).max(1);
        let blocks = if self.reached_ms.is_some() {
            self.dag_blocks as u64
        } else {
            (self.dag_blocks as u64)
                .saturating_mul(self.applied)
                .checked_div(self.tip.max(1))
                .unwrap_or(0)
        };
        blocks.saturating_mul(1000) / ms
    }

    pub(crate) fn line(&self) -> String {
        format!(
            "cold sync legacy={:?} cpu={}: tip={} dag_blocks={} dag_MiB={:.1} max_siblings={} \
             fat_blocks={} reached={} applied={} virtual={:.1}s blocks/s={} heights/s={:.1} \
             wall={:.1}s msgs_in={} MiB_in={:.1} requests_out={}",
            self.legacy,
            self.count_cpu,
            self.tip,
            self.dag_blocks,
            self.dag_bytes as f64 / (1024.0 * 1024.0),
            self.max_siblings,
            self.fat_blocks,
            self.reached_ms.is_some(),
            self.applied,
            self.reached_ms.unwrap_or(self.virtual_ms) as f64 / 1000.0,
            self.blocks_per_sec(),
            self.applied as f64 * 1000.0 / self.reached_ms.unwrap_or(self.virtual_ms).max(1) as f64,
            self.wall.as_secs_f64(),
            self.messages_to_cold,
            self.bytes_to_cold as f64 / (1024.0 * 1024.0),
            self.requests_from_cold
        )
    }
}

/// The key of the `seq`-th ~10 KB transaction's sender.
fn fat_sender(seq: u64) -> Ed25519SigningKey {
    let mut seed = [0x3Cu8; 32];
    seed[..8].copy_from_slice(&seq.to_be_bytes());
    Ed25519SigningKey::from_bytes(&seed)
}

/// A signed ~10 KB transaction from its own funded sender (nonce 0), so it is
/// valid in any block.
fn fat_tx(seq: u64) -> citrate_consensus::types::Transaction {
    let sk = fat_sender(seq);
    let data = vec![0xAB; 10_400];
    let mut tx = citrate_consensus::types::Transaction {
        nonce: 0,
        to: Some(PublicKey::new([0xB0; 32])),
        value: 0,
        gas_limit: 21_000 + 16 * data.len() as u64 + 10_000,
        gas_price: 1_000_000_000,
        data,
        chain_id: Some(CHAIN_ID),
        ..Default::default()
    };
    citrate_consensus::crypto::sign_transaction_v2(&mut tx, &sk).expect("sign");
    tx.hash = citrate_consensus::tx_auth::native_tx_id(&tx);
    tx
}

impl Fleet {
    /// A fleet of `producers` producers plus one cold node (the last index),
    /// down, after `slots` slots: the DAG [`ColdSync`] syncs.
    pub(crate) async fn cold_sync_dag(producers: usize, spec: &ColdSync) -> Self {
        let senders = spec
            .fat_every
            .map(|e| spec.slots / e.max(1) + 1)
            .unwrap_or(0);
        let alloc = (0..senders)
            .map(|i| {
                let pk = PublicKey::new(fat_sender(i).verifying_key().to_bytes());
                (
                    citrate_execution::address_utils::normalize_address(&pk),
                    U256::from(10u128.pow(21)),
                )
            })
            .collect();
        let mut fleet = Self::with_genesis(producers + 1, None, alloc).await;
        let cold = producers;
        fleet.down.insert(cold);
        let mut rng = Rng(0x4770_4770_4770_4770);
        let mut fat = 0u64;
        for slot in 0..spec.slots {
            if let Some(every) = spec.fat_every {
                if slot > ACT && slot % every == 0 {
                    let p = (fat as usize) % producers;
                    fleet.nodes[p]
                        .mempool
                        .add_transaction(fat_tx(fat), citrate_sequencer::mempool::TxClass::Standard)
                        .await
                        .expect("fixture: the pool takes the ~10 KB transaction");
                    fat += 1;
                }
            }
            let order = rng.order(producers);
            fleet.slot(&order).await;
        }
        fleet.pump().await;
        fleet.quiet = (0..producers).collect();
        fleet
    }

    /// Node `i` restarts as a fresh process on an empty data dir.
    async fn replace_with_fresh(&mut self, i: usize) {
        let n = self.nodes.len();
        let dir = TempDir::new().expect("tempdir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let node = Node::start(
            i,
            n,
            &self.genesis,
            storage,
            dir,
            Boot::Fresh,
            self.slot_no,
            self.now(),
            self.clock_ms.clone(),
            self.refuse_window,
            &self.alloc,
        )
        .await;
        self.nodes[i] = node;
        self.attach_peers(i).await;
    }

    /// Sync a fresh cold node (the last index) from `spec.servers`, of which
    /// `legacy` serve as pre-#477 servers. `tune` sets up the cold node's sync
    /// manager (its clock is the simulation's).
    pub(crate) async fn cold_sync(
        &mut self,
        spec: &ColdSync,
        legacy: &[usize],
        tune: impl FnOnce(SyncManager) -> SyncManager,
    ) -> ColdSyncReport {
        use std::cmp::Reverse;
        use std::collections::BinaryHeap;
        let cold = self.nodes.len() - 1;
        self.replace_with_fresh(cold).await;
        self.down.remove(&cold);
        let servers = spec.servers.clone();
        self.set_links(|i, j| {
            (i == cold && servers.contains(&j)) || (j == cold && servers.contains(&i))
        });
        self.legacy_serve = legacy.iter().copied().collect();
        let _ = self.outbox();
        self.handshake().await;

        let tip = self.nodes[servers[0]].applied().1;
        for &s in &servers {
            assert_eq!(
                self.nodes[s].applied().1,
                tip,
                "fixture: every server holds the whole DAG"
            );
        }
        let rows = self.nodes[servers[0]]
            .storage
            .blocks
            .hashes_in_height_range(1, tip)
            .expect("height range");
        let mut per_height: HashMap<u64, usize> = HashMap::new();
        let mut fat_blocks = 0usize;
        let mut dag_bytes = 0u64;
        for (h, hash) in &rows {
            *per_height.entry(*h).or_default() += 1;
            let b = self.nodes[servers[0]]
                .storage
                .blocks
                .get_block(hash)
                .expect("read")
                .expect("stored");
            let size = bincode::serialized_size(&b).expect("size");
            dag_bytes += size;
            if size > 10_000 {
                fat_blocks += 1;
            }
        }
        let max_siblings = per_height.values().copied().max().unwrap_or(0);

        // The cold node's clock is the simulation's.
        let origin = self.now();
        let vclock = Arc::new(AtomicU64::new(0));
        {
            let node = &mut self.nodes[cold];
            let sync = SyncManager::new(SyncConfig::default())
                .with_local_height(node.app.applied_height_handle())
                .with_virtual_clock(origin, vclock.clone());
            node.sync = tune(sync);
            node.walk =
                sync_recovery::ParentWalks::new(origin, SyncConfig::default().request_timeout);
        }

        let latency_us = spec.latency_ms * 1000;
        // Bytes per microsecond x 1e6 (Mbit/s -> bytes/s).
        let bytes_per_sec = spec.downlink_mbit.max(1) * 1_000_000 / 8;
        let mut heap: BinaryHeap<Reverse<(u64, u64)>> = BinaryHeap::new();
        let mut in_flight: HashMap<u64, (usize, usize, NetworkMessage)> = HashMap::new();
        let mut seq = 0u64;
        let mut downlink_free = 0u64;
        let mut server_free: HashMap<usize, u64> = HashMap::new();
        let mut report = ColdSyncReport {
            legacy: legacy.to_vec(),
            count_cpu: spec.count_cpu,
            tip,
            dag_blocks: rows.len(),
            dag_bytes,
            max_siblings,
            fat_blocks,
            reached_ms: None,
            applied: 0,
            virtual_ms: 0,
            wall: std::time::Duration::ZERO,
            messages_to_cold: 0,
            bytes_to_cold: 0,
            requests_from_cold: 0,
        };
        let mut schedule = |out: Vec<(usize, usize, NetworkMessage)>,
                            send_us: u64,
                            heap: &mut BinaryHeap<Reverse<(u64, u64)>>,
                            in_flight: &mut HashMap<u64, (usize, usize, NetworkMessage)>,
                            report: &mut ColdSyncReport| {
            for (from, to, msg) in out {
                let mut at = send_us + latency_us;
                if to == cold {
                    let size = bincode::serialized_size(&msg).expect("size");
                    let start = at.max(downlink_free);
                    at = start + (size * 1_000_000).div_ceil(bytes_per_sec);
                    downlink_free = at;
                    report.messages_to_cold += 1;
                    report.bytes_to_cold += size;
                } else if from == cold {
                    report.requests_from_cold += 1;
                }
                seq += 1;
                heap.push(Reverse((at, seq)));
                in_flight.insert(seq, (from, to, msg));
            }
        };
        let max_us = spec.max_virtual_secs * 1_000_000;
        let mut v = 0u64;
        let mut next_tick = 0u64;
        let wall = std::time::Instant::now();
        loop {
            let applied = self.nodes[cold].applied().1;
            if applied >= tip {
                report.reached_ms = Some(v / 1000);
                break;
            }
            if v > max_us {
                break;
            }
            let set_clock = |fleet: &mut Self, us: u64| {
                vclock.store(us / 1000, Ordering::Relaxed);
                fleet.nodes[cold].clock = origin + std::time::Duration::from_micros(us);
            };
            let next_event = heap.peek().map(|Reverse((t, _))| *t);
            if next_event.is_none_or(|t| t >= next_tick) {
                v = v.max(next_tick);
                set_clock(self, v);
                let peers: Vec<Arc<Peer>> = servers.iter().map(|&s| self.peer(cold, s)).collect();
                let t = std::time::Instant::now();
                self.nodes[cold]
                    .tick(&peers, std::time::Duration::from_secs(3600), true)
                    .await;
                self.nodes[cold].app.drive_drain().await;
                if spec.count_cpu {
                    v += t.elapsed().as_micros() as u64;
                }
                next_tick += 2_000_000;
                let out = self.outbox();
                schedule(out, v, &mut heap, &mut in_flight, &mut report);
                continue;
            }
            let Some(Reverse((t, id))) = heap.pop() else {
                continue;
            };
            let (from, to, msg) = in_flight.remove(&id).expect("scheduled message");
            let send = if to == cold {
                v = v.max(t);
                set_clock(self, v);
                let w = std::time::Instant::now();
                self.receive(to, from, msg).await;
                if spec.count_cpu {
                    v += w.elapsed().as_micros() as u64;
                }
                v
            } else {
                let free = server_free.entry(to).or_default();
                let start = t.max(*free);
                let w = std::time::Instant::now();
                self.receive(to, from, msg).await;
                let spent = if spec.count_cpu {
                    w.elapsed().as_micros() as u64
                } else {
                    0
                };
                let end = start + spent;
                *free = end;
                end
            };
            let out = self.outbox();
            schedule(out, send, &mut heap, &mut in_flight, &mut report);
        }
        report.applied = self.nodes[cold].applied().1;
        report.virtual_ms = v / 1000;
        report.wall = wall.elapsed();
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #477: the shape of the cold-sync runs. 40 ms one way and 50 Mbit/s down
    /// stand for a home connection to the fleet.
    fn cold_spec(slots: u64, count_cpu: bool) -> ColdSync {
        ColdSync {
            slots,
            fat_every: Some(5),
            servers: vec![0, 1, 2],
            latency_ms: 40,
            downlink_mbit: 50,
            count_cpu,
            max_virtual_secs: 6 * 3600,
        }
    }

    /// The cold node's sync manager for the always-on run, whose DAG is small
    /// (~50 heights): the pipeline at a scale that DAG exercises (it engages
    /// 8 heights behind, 8-height windows). The production tunables are
    /// measured by `cold_sync_throughput_on_an_r1007_shaped_dag`.
    fn cold_tune_small(sync: SyncManager) -> SyncManager {
        sync.with_pipeline_config(citrate_network::sync_pipeline::PipelineConfig {
            engage_gap: 8,
            window_heights: 8,
            lookahead_heights: 64,
            ..citrate_network::sync_pipeline::PipelineConfig::default()
        })
    }

    fn print_cold_lines(out: &str) {
        for l in out.lines().filter(|l| l.starts_with("cold sync")) {
            eprintln!("{l}");
        }
    }

    /// #477 (r1007 cold sync gaining ~0.1 heights/s). A fresh node syncs a
    /// seven-producer DAG (seven siblings per height, ~10 KB blocks among
    /// them) from three servers, through the code a node runs, on a modelled
    /// 40 ms / 50 Mbit link; once from three current servers and once from a
    /// mixed fleet where two of the three are pre-#477 (60 KiB replies). Both
    /// reach the tip, at a rate the 2 s, one-request-per-tick driver cannot:
    /// it gains three heights (21 blocks) per tick, ~10 blocks/s.
    #[tokio::test(flavor = "current_thread")]
    async fn a_cold_node_syncs_a_seven_producer_dag_from_three_servers() {
        if !in_child() {
            let out = child_output(
                "split_heal_tests::tests::a_cold_node_syncs_a_seven_producer_dag_from_three_servers",
            );
            print_cold_lines(&out);
            return;
        }
        let spec = cold_spec(ACT + 40, false);
        let mut fleet = Fleet::cold_sync_dag(7, &spec).await;
        for legacy in [vec![], vec![1, 2]] {
            let r = fleet.cold_sync(&spec, &legacy, cold_tune_small).await;
            println!("{}", r.line());
            assert!(
                r.max_siblings >= 6,
                "fixture: a seven-producer DAG ({})",
                r.line()
            );
            assert!(r.fat_blocks > 0, "fixture: ~10 KB blocks ({})", r.line());
            assert!(
                r.reached_ms.is_some(),
                "the cold node reaches the tip: {}",
                r.line()
            );
            assert!(
                r.blocks_per_sec() >= 100,
                "cold sync throughput {} blocks/s is the 2 s tick's: {}",
                r.blocks_per_sec(),
                r.line()
            );
        }
    }

    /// #477 measurement (release; numbers in the PR). `CITRATE_COLD_SYNC_SLOTS`
    /// sets the DAG's length (default 1,500 slots: ~10,500 blocks). Runs three
    /// servers all current, one current and two pre-#477, and all three
    /// pre-#477, with the cold node's processing time counted (this host's CPU
    /// and the link together), then the first two again on the link alone.
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "measurement (#477): run in release"]
    async fn cold_sync_throughput_on_an_r1007_shaped_dag() {
        if !in_child() {
            let out = child_output_with(
                "split_heal_tests::tests::cold_sync_throughput_on_an_r1007_shaped_dag",
                &["--include-ignored"],
            );
            print_cold_lines(&out);
            return;
        }
        let slots = std::env::var("CITRATE_COLD_SYNC_SLOTS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1_500);
        let spec = cold_spec(slots, true);
        let t = std::time::Instant::now();
        let mut fleet = Fleet::cold_sync_dag(7, &spec).await;
        println!(
            "cold sync fixture: {slots} slots in {:.1}s",
            t.elapsed().as_secs_f64()
        );
        let mut reports = Vec::new();
        for (legacy, cpu) in [
            (vec![], true),
            (vec![1, 2], true),
            (vec![0, 1, 2], true),
            (vec![], false),
            (vec![1, 2], false),
        ] {
            let run = ColdSync {
                count_cpu: cpu,
                ..spec.clone()
            };
            let r = fleet.cold_sync(&run, &legacy, |s| s).await;
            println!("{}", r.line());
            reports.push(r);
        }
        for r in &reports {
            assert!(r.reached_ms.is_some(), "{}", r.line());
        }
        assert!(
            reports[0].blocks_per_sec() >= 150,
            "#477 target: {}",
            reports[0].line()
        );
    }

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

    /// (r1007, 2026-11-14, fork at 93,015): four producers each
    /// ended up alone on their own branch while the other three kept one
    /// merged chain, for longer than the 100-block snapshot ring (~2,300
    /// heights live), with no restart. When the links came back the four
    /// never rejoined: their fork-point searches found the fork and then
    /// gave up, the parent walk stopped at the ring, and the producer gate
    /// held them. Here: the same shape at harness scale, 150 slots apart.
    #[tokio::test(flavor = "current_thread")]
    async fn four_lone_producers_forked_past_the_ring_rejoin_the_three() {
        if !in_child() {
            return run_in_child(
                "split_heal_tests::tests::four_lone_producers_forked_past_the_ring_rejoin_the_three",
            );
        }
        assert_heals(
            "4 singletons v 3, forked past the ring",
            Scenario {
                groups: vec![vec![0], vec![1], vec![2], vec![3], vec![4, 5, 6]],
                partition: 150,
                reconnect: true,
                heal_rounds: 150,
                require_merged: false,
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
            "sync_rejoin::classify_answer(",
            "sel.record_serve(",
            // The drain task applies what admission stored, woken by it.
            "let wake = app.drain_wake();",
            "_ = wake.notified() => {}",
            // The producer advances to fork choice's head under its lock (RC-6).
            "producer_instance.with_applicator(app.clone())",
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
            // #477 pipelined download.
            "sync_peer::pipeline_peer_admissible(c, applied_height)",
            "rejoin_for_loop.lock().is_following_tip()",
            ".pipeline_tick(applied_tip_now, pipeline_peers, following_tip)",
            "sync_for_loop.pipeline_active()",
            "!pipelined && pb < sync_recovery::TICK_PENDING_GATE && !held_tip",
            "if ancestor_owns {",
            // Ancestor sync and the evidence rules (r1007 fleet split).
            "ancestor_sync::candidates(&handles,",
            "ancestor_sync::run_tick(",
            "ancestor_for_loop.lock().owns_sync()",
            "rejoin_for_loop.lock().is_following_tip() && !ancestor_owns",
            "ancestor_sync::on_reply(",
            "anc.on_blocks(&pid.0, &answer_hashes, now,",
            "anc.note_deferred(now)",
            "deferred_heights.record(",
            "sync_peer::gossip_raises_head(",
            "sync_peer::raise_gossip_head(pm_for_rx.get_peer(&pid), &block)",
            "sync_for_rx.pipeline_on_answer(applied_tip)",
            "let answers_rejoin = if receipt.pipelined {",
            "receipt.new_blocks == 0 && receipt.received > 0",
        ] {
            assert!(
                main.contains(needle),
                "main.rs no longer contains `{needle}`"
            );
        }
    }

    /// R2 early seal (devnet fin-r2-k1000-1, p7, 2026-11-10). A producer restored from a
    /// snapshot ~23 blocks behind the network came up with one inbound peer whose head it had
    /// not heard yet, declared "Initial sync complete (applied=23271 target=23271 peers=1)"
    /// 0.4 s later and sealed two blocks on its stale tip before the F2 gate had any network
    /// height. A node that has heard nothing above its own applied tip has not shown that it
    /// is caught up: it must not seal until it has heard where the network is (or the solo
    /// grace runs out with no peer at all). Red at 6cc39b41: the sync tick counts the silent
    /// peer as "in sync" and the producer seals.
    #[tokio::test(flavor = "current_thread")]
    async fn a_restarted_producer_does_not_seal_before_it_hears_a_peer_head() {
        if !in_child() {
            return run_in_child(
                "split_heal_tests::tests::a_restarted_producer_does_not_seal_before_it_hears_a_peer_head",
            );
        }
        let n = 4;
        let late = 3usize;
        let mut fleet = Fleet::new(n).await;
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for _ in 0..ACT + 4 {
            let o = rng.order(n);
            fleet.slot(&o).await;
        }
        // The late node is down while the others go on (the R2 snapshot restore).
        fleet.down.insert(late);
        for _ in 0..20 {
            let o = rng.order(n);
            fleet.slot(&o).await;
        }
        fleet.down.remove(&late);
        fleet.restart(late).await;
        let heights = fleet.applied_heights().await;
        let net = heights
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != late)
            .map(|(_, h)| *h)
            .max()
            .expect("running nodes");
        assert!(
            net > heights[late] + crate::producer::CATCHUP_REFUSE_GAP,
            "fixture: the restarted node must be behind (net {net}, it {})",
            heights[late]
        );
        // Freshly connected: no Hello yet, so no peer head is known.
        let peers: Vec<Arc<Peer>> = (0..n)
            .filter(|j| *j != late)
            .map(|j| fleet.peer(late, j))
            .collect();
        for p in &peers {
            let mut info = p.info.write().await;
            info.head_height = 0;
            info.head_hash = Hash::default();
        }
        // The main loop's sync tick, 1 s into the process, then a production round.
        fleet.nodes[late]
            .tick(&peers, std::time::Duration::from_secs(1), true)
            .await;
        let sealed = fleet.nodes[late].producer.produce_block().await;
        assert!(
            sealed.is_err(),
            "a producer {} blocks behind that has heard no peer head sealed on its stale tip \
             (initial_sync={})",
            net - heights[late],
            fleet.nodes[late].initial_sync.load(Ordering::Relaxed)
        );
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
            citrate_mergeset_ref::Report,
            citrate_mergeset_ref::Report,
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
            // r1007 S3-3b: the independent mergeset reference
            // (`citrate-mergeset-ref`), which recomputes GHOSTDAG, every
            // accepted mergeset, settlement and the commitments from the
            // recorded blocks alone (`replay-diff --mode mergeset`).
            use citrate_replay_ref::replay_mergeset;
            let k = fork + 10;
            for i in side_b.iter().copied() {
                let rec = fleet.record(i);
                // Optional: keep the recording for the `replay-diff` CLI
                // (tools/replay-ref), e.g. for a release-gate run. Off by default.
                if let Ok(out) = std::env::var("CITRATE_SPLIT_HEAL_RECORDING_DIR") {
                    let path = std::path::Path::new(&out).join(format!("stopped-side-node{i}.rec"));
                    rec.write_to(&path).expect("write the recording");
                }
                let clean = replay_mergeset(&rec).expect("replay");
                let mut bad = rec.clone();
                if let Some(b) = bad.chain_block_mut(k) {
                    b.state_root = Hash::new([0xEE; 32]);
                }
                let mutated = replay_mergeset(&bad).expect("replay");
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
            assert!(
                clean.lists_compared == 0 || clean.executed > 0,
                "{name}: {clean:?}"
            );
            assert_eq!(
                mutated.divergence.as_ref().map(|d| d.height),
                Some(*k),
                "{name}: {mutated:?}"
            );
        }
    }

    // ---------------------------------------------------------------------
    // Ancestor sync (r1007 fleet split, 2026-11-15, fork at 105,012).
    //
    // After checkpoint 105,000 finalized, the fleet split into partitions
    // that each built only on their own blocks and never re-converged: a
    // node on a lighter branch kept receiving the heavier branch's blocks,
    // deferred every one (missing parent), and anchored every request at its
    // own applied height, which on the other branch is above the fork point.
    // The missing-parent walk gave up a few hundred heights down. These
    // scenarios fork two producer groups above a finalized checkpoint, run
    // the fork well past the walk's reach, reconnect them, and require the
    // fleet to re-converge on the heavier branch by itself.
    // ---------------------------------------------------------------------

    /// What [`deep_split`] found.
    struct DeepSplit {
        /// Highest height both groups' selected chains agreed on before the heal.
        fork: u64,
        /// The lighter group's applied height minus `fork` at the heal.
        light_depth: u64,
        /// How far the heavy group's tip was above the light group's.
        heavy_lead: u64,
        /// Slots after the heal until every node selected the heavier group's
        /// pre-heal chain (four below its tip) and every producer was sealing
        /// again.
        converged_at: Option<u64>,
        /// The finalized checkpoint registered before the split.
        checkpoint: u64,
        /// Every node's reorg floor at the end (never below `checkpoint`).
        floors: Vec<u64>,
        /// A checkpoint above the fork, registered after the heal, and every
        /// node's floor after it (empty: the nodes disagree at that height;
        /// `None`: no convergence to register on).
        finalized_after: Option<(u64, Vec<u64>)>,
        /// Per transaction (light-only, heavy-only): executed on node 0's
        /// converged chain, or waiting in some node's pool.
        txs: Vec<(&'static str, bool, bool)>,
        detail: String,
    }

    /// A 3v4 split above a finalized checkpoint, `partition` slots long, then
    /// every link back (a reconnect: the handshake gives each side the
    /// other's head), and up to `heal` slots to converge. One transaction is
    /// submitted to each side during the partition. During the partition the
    /// light group seals only every other slot, so the heavy branch is also
    /// ahead in height when the links come back, as on r1007 (HEAVY was 363
    /// heights above LIGHT): the light nodes are "behind", every peer's head
    /// is raised to the heavy tip by relayed gossip, and the heavy tip blocks
    /// they hear are too far above them for the missing-parent walk.
    async fn deep_split(partition: u64, heal: u64) -> DeepSplit {
        deep_split_with(partition, heal, &[]).await
    }

    /// [`deep_split`] with `legacy` nodes on the pre-1.3 binary (a rolling
    /// upgrade's old half).
    async fn deep_split_with(partition: u64, heal: u64, legacy: &[usize]) -> DeepSplit {
        let n = 7;
        let light: Vec<usize> = vec![0, 1, 2];
        let heavy: Vec<usize> = vec![3, 4, 5, 6];
        let in_light = |i: usize| i < 3;
        let alloc = (0..2u64)
            .map(|i| {
                let pk = PublicKey::new(fat_sender(i).verifying_key().to_bytes());
                (
                    citrate_execution::address_utils::normalize_address(&pk),
                    U256::from(10u128.pow(21)),
                )
            })
            .collect();
        let mut fleet = Fleet::with_genesis(n, None, alloc).await;
        for &j in legacy {
            fleet.set_legacy_protocol(j).await;
        }
        let mut rng = Rng(0x5EED_A11C_E570_0001);
        for _ in 0..ACT + 6 {
            let o = rng.order(n);
            fleet.slot(&o).await;
        }
        // A finalized checkpoint every node agrees on, two below the lowest
        // tip (r1007: 105,000, finalized 85 s before the split).
        let low = *fleet.applied_heights().await.iter().min().expect("nodes");
        let checkpoint = low - 2;
        let cp_hash = fleet
            .agree_at(checkpoint)
            .await
            .expect("fixture: the fleet agrees below its tips before the split");
        for node in &fleet.nodes {
            node.app.register_certified(checkpoint, cp_hash);
            assert_eq!(
                node.app.settle_registered_floor().await,
                checkpoint,
                "fixture: {} raises its reorg floor to the checkpoint",
                node.name
            );
        }
        fleet.set_links(|i, j| in_light(i) == in_light(j));
        let light_tx = fat_tx(0);
        let heavy_tx = fat_tx(1);
        for k in 0..partition {
            if k == 5 {
                fleet.nodes[light[0]]
                    .mempool
                    .add_transaction(
                        light_tx.clone(),
                        citrate_sequencer::mempool::TxClass::Standard,
                    )
                    .await
                    .expect("fixture: the light pool takes its transaction");
                fleet.nodes[heavy[0]]
                    .mempool
                    .add_transaction(
                        heavy_tx.clone(),
                        citrate_sequencer::mempool::TxClass::Standard,
                    )
                    .await
                    .expect("fixture: the heavy pool takes its transaction");
            }
            if k % 2 == 1 {
                fleet.quiet.extend(light.iter().copied());
            }
            let o = rng.order(n);
            fleet.slot(&o).await;
            fleet.quiet.clear();
        }
        let heights = fleet.applied_heights().await;
        let light_chain = fleet.chain(light[0]).await;
        let (heavy_top_node, heavy_top) = heavy
            .iter()
            .map(|i| (*i, heights[*i]))
            .max_by_key(|(_, h)| *h)
            .expect("heavy side");
        let heavy_chain = fleet.chain(heavy_top_node).await;
        // A few heights below the heavy group's tip: the block there is
        // settled on every heavy node (the topmost siblings are not yet).
        let heavy_mark = heavy_top - 4;
        let heavy_tip = *heavy_chain.get(&heavy_mark).expect("heavy mark");
        let light_top = light.iter().map(|i| heights[*i]).max().expect("light");
        let fork = (0..=light_top)
            .rev()
            .find(|h| light_chain.contains_key(h) && light_chain.get(h) == heavy_chain.get(h))
            .unwrap_or(0);
        fleet.set_links(|_, _| true);
        fleet.handshake().await;
        let mut last_sealed: HashMap<usize, u64> = HashMap::new();
        let mut converged_at = None;
        for slot in 1..=heal {
            let o = rng.order(n);
            for (i, _) in fleet.slot(&o).await {
                last_sealed.insert(i, slot);
            }
            let mut all = true;
            for i in 0..n {
                if fleet.chain(i).await.get(&heavy_mark) != Some(&heavy_tip) {
                    all = false;
                    break;
                }
            }
            let producing = (0..n).all(|i| {
                last_sealed
                    .get(&i)
                    .is_some_and(|r| r + PRODUCING_WINDOW > slot)
            });
            // One line per heal slot, shown only when the run fails.
            println!(
                "DEEPSLOT {slot} applied={:?} on_heavy={all} producing={producing}",
                fleet.applied_heights().await
            );
            if all && producing {
                converged_at = Some(slot);
                break;
            }
        }
        let mut floors = Vec::new();
        for node in &fleet.nodes {
            floors.push(node.app.finalized_height_handle().load(Ordering::SeqCst));
        }
        let finalized_after = if converged_at.is_some() {
            // Every node on one chain: a checkpoint above the fork can gather
            // every vote. Register it on every node; each floor must rise to it.
            let min_h = *fleet.applied_heights().await.iter().min().expect("nodes");
            let cp2 = min_h.saturating_sub(2).max(fork + 1);
            match fleet.agree_at(cp2).await {
                Some(h2) => {
                    let mut out = Vec::new();
                    for node in &fleet.nodes {
                        node.app.register_certified(cp2, h2);
                        out.push(node.app.settle_registered_floor().await);
                    }
                    Some((cp2, out))
                }
                None => Some((cp2, Vec::new())),
            }
        } else {
            None
        };
        println!(
            "DEEPSPLIT fork={fork} light_depth={} heavy_lead={} converged_at={converged_at:?} \
             lost={} shed={}",
            light_top.saturating_sub(fork),
            heavy_top.saturating_sub(light_top),
            fleet.lost,
            fleet.shed
        );
        let past = fleet.past(0).await;
        let mut txs = Vec::new();
        for (name, tx) in [("light-only", &light_tx), ("heavy-only", &heavy_tx)] {
            let executed = fleet.nodes[0]
                .storage
                .transactions
                .get_receipt(&tx.hash)
                .expect("read receipt")
                .is_some_and(|r| {
                    past.contains(&r.block_hash) || fleet_tip_is(&fleet, &r.block_hash)
                });
            let mut pooled = false;
            for node in &fleet.nodes {
                if node.mempool.contains(&tx.hash).await {
                    pooled = true;
                }
            }
            txs.push((name, executed, pooled));
        }
        DeepSplit {
            fork,
            light_depth: light_top.saturating_sub(fork),
            heavy_lead: heavy_top.saturating_sub(light_top),
            converged_at,
            checkpoint,
            floors,
            finalized_after,
            txs,
            detail: format!(
                "fork {fork}, light at {light_top}, heavy at {heavy_top} ({}): {}",
                short(&heavy_tip),
                fleet.describe().await
            ),
        }
    }

    /// Whether `h` is node 0's applied tip (its past excludes it).
    fn fleet_tip_is(fleet: &Fleet, h: &Hash) -> bool {
        fleet.nodes[0].applied().0 == *h
    }

    /// The r1007 split at harness scale: two producer groups fork above a
    /// finalized checkpoint and run 1,100 slots apart (the heavy branch one
    /// height per slot, the light one every other slot: both are more than
    /// the 512-height missing-parent walk above the fork, and the heavy tip is
    /// more than that above the light one), then reconnect. Within 60 slots
    /// (two minutes of chain time) every node must be on the heavier
    /// (four-producer) branch and every producer sealing again, without
    /// operator action; the
    /// reorg must stay above the checkpoint; a checkpoint above the fork must
    /// then finalize on every node; and neither side's transaction may be
    /// lost (executed on the converged chain, or back in a pool).
    #[tokio::test(flavor = "current_thread")]
    async fn two_groups_forked_past_the_walk_reconverge_on_the_heavier_branch() {
        if !in_child() {
            return run_in_child(
                "split_heal_tests::tests::two_groups_forked_past_the_walk_reconverge_on_the_heavier_branch",
            );
        }
        let r = deep_split(1_100, 60).await;
        assert!(
            r.light_depth > crate::sync_peer::ANCESTRY_RECOVERY_WINDOW
                && r.heavy_lead > crate::sync_peer::ANCESTRY_RECOVERY_WINDOW,
            "fixture: the lighter branch is {} deep and {} behind ({})",
            r.light_depth,
            r.heavy_lead,
            r.detail
        );
        assert!(
            r.fork > r.checkpoint,
            "fixture: the fork is above the checkpoint ({})",
            r.detail
        );
        assert!(
            r.converged_at.is_some(),
            "a {}-deep split did not re-converge on the heavier branch within 60 slots \
             of the reconnect ({})",
            r.light_depth,
            r.detail
        );
        assert!(
            r.floors.iter().all(|f| *f >= r.checkpoint),
            "a reorg floor fell below the finalized checkpoint {}: {:?}",
            r.checkpoint,
            r.floors
        );
        let (cp2, floors) = r.finalized_after.clone().expect("converged");
        assert!(
            floors.len() == 7 && floors.iter().all(|f| *f == cp2),
            "checkpoint {cp2} above the fork did not finalize on every node: {floors:?} ({})",
            r.detail
        );
        for (name, executed, pooled) in &r.txs {
            assert!(
                *executed || *pooled,
                "the {name} transaction was lost: not executed on the converged chain and \
                 in no pool ({})",
                r.detail
            );
        }
    }

    /// A block `key` signed at `height` on a parent nobody holds: what a
    /// relay of another branch's tip, or a forger, gossips. It passes gossip
    /// validation (self-consistent, self-signed) and defers on admission.
    fn unconnected_block(key: &Ed25519SigningKey, height: u64, salt: u8) -> Block {
        let mut parent = [0xD7u8; 32];
        parent[0] = salt;
        let mut b = BlockBuilder::new()
            .version(2)
            .height(height)
            .parent(Hash::new(parent))
            .coinbase([0xBC; 20])
            .timestamp(chrono::Utc::now().timestamp().max(0) as u64)
            .vrf_reveal(VrfProof {
                proof: vec![],
                output: Hash::new([0x5D; 32]),
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
        b.signature = citrate_consensus::crypto::sign_block(&b.header.block_hash, key);
        b
    }

    /// Evidence poisoning (r1007 fleet split): one peer gossips a signed block
    /// a million heights above the network on a parent nobody holds. It
    /// defers. Neither the node's network-height evidence (`max_seen_height`,
    /// the sync target and `eth_syncing.highestBlock`) nor that peer's
    /// advertised head may move: nothing verified it, and no second peer
    /// corroborates it. Red at f4a0e600: the head was raised before
    /// validation and the deferred path recorded the claim.
    #[tokio::test(flavor = "current_thread")]
    async fn a_lone_peers_far_ahead_gossip_moves_neither_the_target_nor_its_head() {
        if !in_child() {
            return run_in_child(
                "split_heal_tests::tests::a_lone_peers_far_ahead_gossip_moves_neither_the_target_nor_its_head",
            );
        }
        let n = 3;
        let mut fleet = Fleet::new(n).await;
        fleet.add_sybils(1).await;
        let mut rng = Rng(0x0BAD_5EED_0000_0001);
        for _ in 0..ACT + 4 {
            let o = rng.order(n);
            fleet.slot(&o).await;
        }
        let verified = *fleet.applied_heights().await.iter().max().expect("nodes");
        let before = fleet.nodes[0].max_seen.load(Ordering::Relaxed);
        assert!(before <= verified, "fixture: {before} > {verified}");
        let key = Ed25519SigningKey::from_bytes(&[0xF1; 32]);
        let claim = verified + 1_000_000;
        let peer = fleet.sybils[0][0].0.clone();
        let pid = PeerId::new("sybil0".to_string());
        for k in 0..4u8 {
            let b = unconnected_block(&key, claim + u64::from(k), k);
            fleet.nodes[0].on_new_block(&peer, &pid, b).await;
        }
        fleet.pump().await;
        let seen = fleet.nodes[0].max_seen.load(Ordering::Relaxed);
        assert!(
            seen <= verified,
            "one peer's unverified claim of {claim} moved the network height to {seen} \
             (verified {verified})"
        );
        let head = peer.info.read().await.head_height;
        assert!(
            head <= verified,
            "the peer's advertised head was raised to {head} by a block nothing verified"
        );
    }

    /// Rolling upgrade: the same deep split with two of the four heavy
    /// producers still on the 1.2 binary. No message reaches them that they
    /// cannot decode (nothing is lost on their links for that), the upgraded
    /// light group re-converges through the upgraded heavy peers, and the
    /// old nodes stay on the heavy branch they never left.
    #[tokio::test(flavor = "current_thread")]
    async fn a_mixed_version_fleet_reconverges_through_its_upgraded_peers() {
        if !in_child() {
            return run_in_child(
                "split_heal_tests::tests::a_mixed_version_fleet_reconverges_through_its_upgraded_peers",
            );
        }
        let r = deep_split_with(1_100, 60, &[5, 6]).await;
        assert!(
            r.light_depth > crate::sync_peer::ANCESTRY_RECOVERY_WINDOW,
            "fixture: {} deep ({})",
            r.light_depth,
            r.detail
        );
        assert!(
            r.converged_at.is_some(),
            "a mixed fleet did not re-converge on the heavier branch ({})",
            r.detail
        );
        for (name, executed, pooled) in &r.txs {
            assert!(
                *executed || *pooled,
                "the {name} transaction was lost ({})",
                r.detail
            );
        }
    }
}
