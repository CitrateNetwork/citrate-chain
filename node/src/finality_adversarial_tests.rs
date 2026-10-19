// node/src/finality_adversarial_tests.rs
//
// WP-S.3 Stage 2 — checkpoint-finality integration + adversarial suite A1–A8
// (docs/consensus/CHECKPOINT_FINALITY_WIRING.md §8.2, §8.3).
//
// Test-only. Every scenario runs several in-process nodes, each with the
// production pieces a node wires in `main.rs`, over its own on-disk store:
//
//   * `CanonicalApplicator` over a RocksDB `StorageManager` (applied chain,
//     executed and state-root verified; owns the reorg floor);
//   * `CheckpointManager::with_persistence` over the same RocksDB
//     (`RocksDbKvStore`, certificates + the durable signed-vote record);
//   * `FinalityGadget` (producer path; compiled switch forced ON here — every
//     release pin is OFF) with an epoch-snapshot `VrfProposerSelector`;
//   * the finality DRIVER pass (`finality_driver::run_pass` + `gate_outbound`,
//     exactly what `finality_driver::spawn` runs each second, walking the
//     node's own stored headers);
//   * the floor VERIFIER (`FloorVerifier`, Enforced mode — both switches ON,
//     which no release ships yet), sharing the gadget's safety stop and
//     installed as the manager's finalization guard, as `main.rs` does.
//
// Votes travel through an in-process gossip queue standing in for
// `NetworkMessage::CheckpointVote` broadcast + the inbound handler's relay.
// Blocks are reward-only v2 blocks with correct cumulative state roots, so
// every applied block really executes. Byzantine validators are keys with no
// node: the test signs their votes and injects them.
//
// The TLA+ action each step corresponds to (specs/tla/consensus/
// CheckpointFinalitySafety.tla) is named in the comments: Propose/SignVote
// (driver pass), Finalize (gossip reaching quorum), VerifyFloor (verifier
// tick), Reorg (`reorg_to`), Restart (rebuild the node over its store).
// Finalize includes the floor check the guard runs before the finalization is
// visible (the TLA+ Finalize action raises the floor or halts in the same step).
//
// Late-joiner certificate sync (C3-S1b, spec §11.10) runs over the same
// pieces: each node has a `CertificateSync` (Enforced, installed only with the
// finalization guard in place, as main.rs), and `Net::sync_cert` runs one
// GetCheckpoint / CheckpointCertificate exchange over the real wire codec
// (TLA+ SyncCert). The open S1 finding across sibling committees is
// `#[ignore = "bug: ..."]`; it is not a pass today.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use citrate_api::finalized_tag::FinalizedAnchor;
use citrate_consensus::checkpoint::{
    derived_quorum, sign_checkpoint_vote, Checkpoint, CheckpointConfig, CheckpointError,
    CheckpointManager, CheckpointStatus, CheckpointVote, CommitteeSelector,
};
use citrate_consensus::checkpoint_gadget::{
    finalize_retry_delay, FinalityGadget, InboundOutcome, SkipReason, FINALIZE_RETRY_BASE,
    FINALIZE_RETRY_CAP,
};
use citrate_consensus::crypto::Ed25519SigningKey;
use citrate_consensus::dag_store::{cf, DagStore, KvStore};
use citrate_consensus::types::{Block, Hash, PublicKey};
use citrate_consensus::vrf::VrfProposerSelector;
use citrate_execution::Executor;
use citrate_network::NetworkMessage;
use citrate_storage::StorageManager;

use crate::canonical_apply::tests::{fresh, mk_block_vrf, persist, roots};
use crate::canonical_apply::{ApplyOutcome, CanonicalApplicator, ReorgOutcome};
use crate::finality_driver::{gate_outbound, retry_finalizations, run_pass, OwnVoteRetries};
use crate::finality_floor::{
    CertificateCommittees, FloorMode, FloorTick, FloorVerifier, HaltReason,
};
use crate::finality_sync::{CertificateSync, SyncOutcome};
use crate::persistent_dag::RocksDbKvStore;

const CHAIN: u64 = 40204;
const FOREIGN_CHAIN: u64 = 1337;

/// VRF tag of the main branch (A) and of competing branches.
const VRF_A: [u8; 32] = [0x5A; 32];
const VRF_B: [u8; 32] = [0xB0; 32];
const VRF_C: [u8; 32] = [0xC0; 32];

/// Highest block height any scenario builds (state roots are precomputed).
const MAX_HEIGHT: u64 = 84;

/// Spec §3 parameters at the scale of a test: interval 2, depth 3.
fn config(committee_size: usize) -> CheckpointConfig {
    CheckpointConfig {
        interval: 2,
        committee_size,
        quorum_threshold: 67,
        chain_id: CHAIN,
        vote_depth: 3,
    }
}

fn key(i: u8) -> Ed25519SigningKey {
    let mut seed = [0u8; 32];
    seed[0] = i;
    seed[1] = 0xF1;
    seed[31] = 0xA7;
    Ed25519SigningKey::from_bytes(&seed)
}

fn pk(k: &Ed25519SigningKey) -> PublicKey {
    PublicKey::new(k.verifying_key().to_bytes())
}

// ---------------------------------------------------------------------------
// Chains
// ---------------------------------------------------------------------------

/// Block-tree builder. All branches share the cumulative reward-only state
/// roots (reward-only blocks with one coinbase produce the same state at the
/// same height), so any branch applies and executes.
struct Chains {
    roots: Vec<Hash>,
}

impl Chains {
    fn new() -> Self {
        Self {
            roots: roots(MAX_HEIGHT),
        }
    }

    fn root(&self, height: u64) -> Hash {
        let i = usize::try_from(height.saturating_sub(1)).expect("height fits");
        *self.roots.get(i).expect("height within MAX_HEIGHT")
    }

    /// A branch of blocks `1..=len`: `base` up to `fork_at - 1`, then new
    /// blocks tagged `vrf` from `fork_at` (a sibling of `base[fork_at]`).
    /// Index `h - 1` holds height `h`.
    fn branch(&self, base: &[Block], fork_at: u64, len: u64, vrf: [u8; 32]) -> Vec<Block> {
        let mut out: Vec<Block> = base
            .iter()
            .take(usize::try_from(fork_at.saturating_sub(1)).expect("fits"))
            .cloned()
            .collect();
        let mut parent = out.last().map_or(Hash::default(), |b| b.header.block_hash);
        for h in fork_at..=len {
            let mut tag = vrf;
            // Distinct hash per height even when the parent repeats a tag.
            tag[1] = u8::try_from(h).expect("height fits a byte");
            let b = mk_block_vrf(h, parent, self.root(h), tag);
            parent = b.header.block_hash;
            out.push(b);
        }
        out
    }

    fn main(&self, len: u64) -> Vec<Block> {
        self.branch(&[], 1, len, VRF_A)
    }
}

fn at(branch: &[Block], height: u64) -> &Block {
    branch
        .get(usize::try_from(height.saturating_sub(1)).expect("fits"))
        .expect("height on branch")
}

fn hash_at(branch: &[Block], height: u64) -> Hash {
    at(branch, height).header.block_hash
}

// ---------------------------------------------------------------------------
// Nodes
// ---------------------------------------------------------------------------

/// The validator set every node's epoch snapshot S(1) holds.
#[derive(Clone)]
struct Validators {
    set: Vec<(PublicKey, u128)>,
    /// Extra snapshots `(S(E), set)` recorded on every node (A7).
    later: Vec<(u64, Vec<(PublicKey, u128)>)>,
    /// Epoch schedule (EPOCH, LAG): S(E) = E * EPOCH - LAG.
    schedule: (u64, u64),
}

impl Validators {
    fn equal_stake(keys: &[Ed25519SigningKey]) -> Self {
        Self {
            set: keys.iter().map(|k| (pk(k), 32_000u128)).collect(),
            later: Vec::new(),
            schedule: (20, 19),
        }
    }
}

struct TestNode {
    exec: Arc<Executor>,
    storage: Arc<StorageManager>,
    _dir: tempfile::TempDir,
    app: Arc<CanonicalApplicator>,
    dag: Arc<DagStore>,
    gadget: Arc<FinalityGadget>,
    verifier: Arc<FloorVerifier>,
    sync: Arc<CertificateSync>,
    key: Ed25519SigningKey,
    cursor: u64,
    retries: OwnVoteRetries,
    /// Every block this node has stored (re-hydrated into a fresh DAG on restart).
    known: Vec<Block>,
    /// The applicator's fork-choice head (`None`: nothing to follow, as with no
    /// fork choice). Set by a test to drive the spine-rebuild recovery path.
    head: Arc<parking_lot::Mutex<Option<Hash>>>,
}

/// Build the finality stack over `storage` the way `main.rs` does, then run
/// the verifier's boot check BEFORE any block is admitted (Restart / boot).
#[allow(clippy::too_many_arguments)]
async fn assemble(
    exec: Arc<Executor>,
    storage: Arc<StorageManager>,
    dir: tempfile::TempDir,
    key: Ed25519SigningKey,
    vals: &Validators,
    cfg: CheckpointConfig,
    known: Vec<Block>,
) -> (TestNode, FloorTick) {
    let kv: Arc<dyn KvStore> = Arc::new(RocksDbKvStore::new(storage.db.clone()));
    assemble_with(exec, storage, dir, key, vals, cfg, known, kv).await
}

/// [`assemble`] with the manager's persistent store given explicitly (a fault
/// seam over the node's RocksDB, see [`FaultyCertKv`]).
#[allow(clippy::too_many_arguments)]
async fn assemble_with(
    exec: Arc<Executor>,
    storage: Arc<StorageManager>,
    dir: tempfile::TempDir,
    key: Ed25519SigningKey,
    vals: &Validators,
    cfg: CheckpointConfig,
    known: Vec<Block>,
    kv: Arc<dyn KvStore>,
) -> (TestNode, FloorTick) {
    let head = Arc::new(parking_lot::Mutex::new(None));
    let app = Arc::new(
        CanonicalApplicator::new(exec.clone(), storage.clone()).with_fork_choice_cell(head.clone()),
    );
    let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
    for b in &known {
        let _ = dag.store_block(b.clone()).await;
    }
    let sel = VrfProposerSelector::new().with_snapshot_schedule(vals.schedule.0, vals.schedule.1);
    sel.sync_active_set_at(1, vals.set.clone(), 1).await;
    for (snap, set) in &vals.later {
        sel.sync_active_set_at(*snap, set.clone(), 1).await;
    }
    let mgr = Arc::new(CheckpointManager::with_persistence(cfg, dag.clone(), kv));
    let gadget = Arc::new(FinalityGadget::with_switch(
        mgr.clone(),
        Some(Arc::new(sel)),
        true,
    ));
    let verifier = Arc::new(FloorVerifier::new(
        FloorMode::Enforced,
        mgr,
        app.clone(),
        gadget.safety_stop(),
        Arc::new(AtomicU64::new(0)),
        CertificateCommittees::new(gadget.clone(), storage.clone()),
    ));
    assert!(verifier.install_finalization_guard(), "Enforced installs");
    let boot = verifier.boot_check().await;
    // Stage 1b: late-joiner certificate sync over the same pieces (main.rs).
    let sync = Arc::new(
        CertificateSync::new(gadget.clone(), app.clone(), verifier.clone())
            .expect("Enforced with the guard installed"),
    );
    (
        TestNode {
            exec,
            storage,
            _dir: dir,
            app,
            dag,
            gadget,
            verifier,
            sync,
            key,
            cursor: 0,
            retries: OwnVoteRetries::default(),
            known,
            head,
        },
        boot,
    )
}

impl TestNode {
    async fn boot(key: Ed25519SigningKey, vals: &Validators, cfg: CheckpointConfig) -> Self {
        let (exec, storage, dir) = fresh();
        let (node, tick) = assemble(exec, storage, dir, key, vals, cfg, Vec::new()).await;
        assert_eq!(tick, FloorTick::NoCertificate, "fresh node boot");
        node
    }

    /// Process restart over the same data directory: pending checkpoints,
    /// buffers, the driver cursor, the verifier state and the (in-memory)
    /// reorg floor are lost; blocks, certificates and the signed-vote record
    /// persist. World state is carried over (state persistence is covered by
    /// the SRP restart tests, not here). Returns the boot check's verdict.
    async fn restart(self, vals: &Validators, cfg: CheckpointConfig) -> (Self, FloorTick) {
        let TestNode {
            exec,
            storage,
            _dir,
            known,
            key,
            ..
        } = self;
        assemble(exec, storage, _dir, key, vals, cfg, known).await
    }

    fn me(&self) -> PublicKey {
        pk(&self.key)
    }

    fn mgr(&self) -> &Arc<CheckpointManager> {
        self.gadget.manager()
    }

    /// Store a block as the receive path does (chain store + DAG).
    async fn import(&mut self, b: &Block) {
        if self
            .known
            .iter()
            .any(|k| k.header.block_hash == b.header.block_hash)
        {
            return;
        }
        persist(&self.storage, b);
        let _ = self.dag.store_block(b.clone()).await;
        self.known.push(b.clone());
    }

    /// Import and apply every block of `branch` above the applied tip (linear
    /// extension of the applied chain).
    async fn follow(&mut self, branch: &[Block]) {
        let tip = self.app.applied_tip().await;
        for b in branch {
            self.import(b).await;
            if b.header.height <= tip.height {
                continue;
            }
            match self.app.apply_received(b).await {
                ApplyOutcome::Applied { .. } => {}
                other => panic!("block {} not applied: {other:?}", b.header.height),
            }
        }
    }

    /// Fork choice moves this node to `branch`'s tip (TLA+ Reorg).
    async fn reorg_onto(&mut self, branch: &[Block]) -> ReorgOutcome {
        for b in branch {
            self.import(b).await;
        }
        let tip = branch.last().expect("non-empty branch").header.block_hash;
        let lock = self.app.advance_lock();
        let mut state = lock.lock().await;
        self.app.reorg_to(&mut state, tip).await
    }

    /// One driver pass (TLA+ Propose + SignVote), exactly as
    /// `finality_driver::spawn` runs it: walk this node's stored headers from
    /// the applied tip, report buried boundaries, gate the outbound votes.
    async fn drive(&mut self) -> Vec<CheckpointVote> {
        let tip = self.app.applied_tip().await;
        self.gadget.observe_tip(tip.height).await;
        let storage = self.storage.clone();
        let lookup = move |h: &Hash| {
            storage
                .blocks
                .get_header(h)
                .map(|o| o.map(|hd| (hd.height, hd.selected_parent_hash, hd.vrf_reveal.output)))
                .map_err(|e| e.to_string())
        };
        let out = run_pass(
            &self.gadget,
            Some(&self.key),
            &mut self.cursor,
            &mut self.retries,
            tip.hash,
            tip.height,
            &lookup,
        )
        .await;
        gate_outbound(&self.gadget, Some(&self.key), &mut self.retries, out)
    }

    /// One floor-verifier pass (TLA+ VerifyFloor).
    async fn tick(&self) -> FloorTick {
        self.verifier.tick().await
    }

    fn floor(&self) -> u64 {
        self.app.finalized_height_handle().load(Ordering::SeqCst)
    }

    fn rpc_finalized(&self) -> FinalizedAnchor {
        self.verifier.rpc_finalized_handle().resolve(&self.storage)
    }

    async fn finalized(&self) -> u64 {
        self.mgr().latest_finalized_height().await
    }

    async fn finalized_hash(&self, height: u64) -> Option<Hash> {
        let cp = self.mgr().get_checkpoint(height).await?;
        (cp.status == CheckpointStatus::Finalized).then_some(cp.block_hash)
    }
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

/// In-process gossip: a queue of `(sender, vote)`; delivery to every online
/// node except the sender; a vote a node accepted for the first time is
/// relayed once (`InboundOutcome::relay`), as the inbound handler does.
struct Net {
    nodes: Vec<TestNode>,
    online: Vec<bool>,
    queue: VecDeque<(Option<usize>, CheckpointVote)>,
    /// Every `(receiver, vote, outcome)` delivered, for assertions.
    log: Vec<(usize, CheckpointVote, String)>,
}

impl Net {
    fn new(nodes: Vec<TestNode>) -> Self {
        let online = vec![true; nodes.len()];
        Self {
            nodes,
            online,
            queue: VecDeque::new(),
            log: Vec::new(),
        }
    }

    fn node(&self, i: usize) -> &TestNode {
        self.nodes.get(i).expect("node index")
    }

    fn node_mut(&mut self, i: usize) -> &mut TestNode {
        self.nodes.get_mut(i).expect("node index")
    }

    async fn follow_all(&mut self, branch: &[Block]) {
        for n in &mut self.nodes {
            n.follow(branch).await;
        }
    }

    /// Driver pass on node `i`; its outbound votes enter the gossip queue.
    async fn drive(&mut self, i: usize) -> Vec<CheckpointVote> {
        let out = self.node_mut(i).drive().await;
        for v in &out {
            self.queue.push_back((Some(i), v.clone()));
        }
        out
    }

    /// Deliver one vote to node `to` (a Byzantine or targeted send). Accepted
    /// votes are relayed into the queue like any other.
    async fn send_to(&mut self, to: usize, vote: CheckpointVote) -> InboundOutcome {
        let out = self.node(to).gadget.on_inbound_vote(vote.clone()).await;
        self.log.push((to, vote, format!("{out:?}")));
        if let Some(relay) = out.relay() {
            self.queue.push_back((Some(to), relay.clone()));
        }
        out
    }

    /// Inject a vote from a validator with no node (Byzantine actor) to all.
    fn inject(&mut self, vote: CheckpointVote) {
        self.queue.push_back((None, vote));
    }

    /// Run gossip to quiescence among the online nodes.
    async fn gossip(&mut self) {
        let mut steps = 0usize;
        while let Some((from, vote)) = self.queue.pop_front() {
            for i in 0..self.nodes.len() {
                if Some(i) == from || !*self.online.get(i).expect("online flag") {
                    continue;
                }
                let _ = self.send_to(i, vote.clone()).await;
                steps = steps.saturating_add(1);
            }
            assert!(steps < 200_000, "gossip must terminate (relay dedupe)");
        }
    }

    /// Driver pass on every online node, then gossip, then a verifier pass on
    /// every online node.
    async fn round(&mut self) -> Vec<FloorTick> {
        for i in 0..self.nodes.len() {
            if *self.online.get(i).expect("online flag") {
                self.drive(i).await;
            }
        }
        self.gossip().await;
        self.tick_all().await
    }

    /// Stage 1b certificate sync, one exchange (spec §11.10): node `to` asks
    /// node `from` (`GetCheckpoint`), `from` serves its highest certificate in
    /// range (`CheckpointCertificate`), `to` verifies and installs it, all over
    /// the real wire codec. `None`: nothing was requested (nothing to ask for)
    /// or nothing was served.
    async fn sync_cert(&mut self, to: usize, from: usize) -> Option<SyncOutcome> {
        let to_id = format!("node-{to}");
        let from_id = format!("node-{from}");
        // In-process time does not advance: lift the request / serve spacing
        // (covered by finality_sync's own tests) for this exchange.
        self.node(to).sync.reset_rate_limits_for_tests().await;
        self.node(from).sync.reset_rate_limits_for_tests().await;
        let (peer, req) = self
            .node(to)
            .sync
            .request(std::slice::from_ref(&from_id))
            .await?;
        assert_eq!(peer, from_id);
        let req = over_the_wire(&req);
        let NetworkMessage::GetCheckpoint { above, at_or_below } = req else {
            panic!("expected GetCheckpoint, got {req:?}");
        };
        let resp = self.node(from).sync.serve(&to_id, above, at_or_below).await;
        let resp = resp?;
        let NetworkMessage::CheckpointCertificate {
            height,
            block_hash,
            signatures,
        } = over_the_wire(&resp)
        else {
            panic!("expected CheckpointCertificate");
        };
        assert!(self.node(to).sync.accept_response(&from_id).await);
        Some(
            self.node(to)
                .sync
                .process(&from_id, height, block_hash, signatures)
                .await,
        )
    }

    async fn tick_all(&mut self) -> Vec<FloorTick> {
        let mut ticks = Vec::new();
        for (i, n) in self.nodes.iter().enumerate() {
            if *self.online.get(i).expect("online flag") {
                ticks.push(n.tick().await);
            }
        }
        ticks
    }

    /// S1 across the whole network: at every height, at most one hash is
    /// finalized by any node. Returns the finalized hash per checked height.
    async fn assert_no_conflicting_finality(&self, heights: &[u64]) {
        for &h in heights {
            let mut seen: Option<Hash> = None;
            for (i, n) in self.nodes.iter().enumerate() {
                if let Some(x) = n.finalized_hash(h).await {
                    match seen {
                        None => seen = Some(x),
                        Some(y) => assert_eq!(x, y, "S1 violated at height {h} on node {i}"),
                    }
                }
            }
        }
    }

    /// No honest node's own key ever emitted two different hashes at a height.
    fn assert_honest_no_equivocation(&self) {
        let honest: Vec<PublicKey> = self.nodes.iter().map(TestNode::me).collect();
        for (_, v, _) in &self.log {
            if !honest.contains(&v.voter) {
                continue;
            }
            for (_, w, _) in &self.log {
                if w.voter == v.voter && w.height == v.height {
                    assert_eq!(
                        w.block_hash, v.block_hash,
                        "honest key equivocated at height {}",
                        v.height
                    );
                }
            }
        }
    }
}

async fn network(n: u8, vals: &Validators, cfg: CheckpointConfig) -> Net {
    let mut nodes = Vec::new();
    for i in 0..n {
        nodes.push(TestNode::boot(key(i), vals, cfg.clone()).await);
    }
    Net::new(nodes)
}

fn verified(height: u64) -> FloorTick {
    FloorTick::Verified {
        height,
        floor_raised: true,
        recovered: false,
    }
}

/// Through the real wire codec (bincode out, bounded `decode_inbound` in).
fn over_the_wire(msg: &NetworkMessage) -> NetworkMessage {
    let bytes = bincode::serialize(msg).expect("encode");
    NetworkMessage::decode_inbound(&bytes).expect("decode_inbound")
}

/// A finalized certificate for `(height, hash)` with `committee` and the votes
/// of `signers`, each signed over `chain_id`.
fn certificate(
    height: u64,
    hash: Hash,
    committee: &[PublicKey],
    signers: &[&Ed25519SigningKey],
    chain_id: u64,
) -> Checkpoint {
    let mut votes = std::collections::HashMap::new();
    for k in signers {
        let v = sign_checkpoint_vote(chain_id, height, hash, k);
        votes.insert(v.voter, v.signature);
    }
    Checkpoint {
        height,
        block_hash: hash,
        committee: committee.to_vec(),
        votes,
        status: CheckpointStatus::Finalized,
    }
}

/// Write `cert` where `CheckpointManager::finalize_checkpoint` persists it
/// (`DAG_METADATA` `checkpoint:{height}`, bincode) — a damaged or tampered
/// record, or one written by a certificate source this node trusts.
fn write_certificate(storage: &StorageManager, cert: &Checkpoint) {
    RocksDbKvStore::new(storage.db.clone())
        .kv_put(
            cf::DAG_METADATA,
            format!("checkpoint:{}", cert.height).as_bytes(),
            &bincode::serialize(cert).expect("serialize certificate"),
        )
        .expect("write certificate");
}

fn delete_certificate(storage: &StorageManager, height: u64) {
    RocksDbKvStore::new(storage.db.clone())
        .kv_delete(cf::DAG_METADATA, format!("checkpoint:{height}").as_bytes())
        .expect("delete certificate");
}

// ---------------------------------------------------------------------------
// §8.2 integration: happy path end to end
// ---------------------------------------------------------------------------

/// Four validators on one chain: driver -> votes -> quorum -> certificate ->
/// verifier raises the floor (Enforced) on every node -> the RPC tags name the
/// certified block -> a reorg with its fork point below the floor is rejected.
#[tokio::test]
async fn integration_four_nodes_finalize_raise_floor_and_reject_deep_reorg() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let vals = Validators::equal_stake(&keys);
    let mut net = network(4, &vals, config(100)).await;
    let a = chains.main(8);
    net.follow_all(&a).await;
    // Before anything finalized the tags resolve to genesis.
    assert_eq!(net.node(0).rpc_finalized(), FinalizedAnchor::GENESIS);

    let ticks = net.round().await;
    assert!(ticks.iter().all(|t| *t == verified(4)), "{ticks:?}");
    for n in &net.nodes {
        assert_eq!(n.finalized().await, 4);
        assert_eq!(n.floor(), 4);
        assert_eq!(
            n.rpc_finalized(),
            FinalizedAnchor {
                height: 4,
                hash: Some(hash_at(&a, 4))
            }
        );
    }
    net.assert_no_conflicting_finality(&[2, 4]).await;

    // A heavier branch forking below the floor (sibling of A3) is refused.
    let b = chains.branch(&a, 3, 12, VRF_B);
    match net.node_mut(0).reorg_onto(&b).await {
        ReorgOutcome::Rejected(why) => assert!(why.contains("below finalized"), "{why}"),
        other => panic!("reorg below the floor must be rejected, got {other:?}"),
    }
    assert_eq!(net.node(0).app.applied_tip().await.hash, hash_at(&a, 8));
    assert_eq!(net.node(0).tick().await, verified(4));

    // Finality keeps advancing as the chain grows.
    let a = chains.main(12);
    net.follow_all(&a).await;
    let ticks = net.round().await;
    assert!(ticks.iter().all(|t| *t == verified(8)), "{ticks:?}");
    net.assert_honest_no_equivocation();
}

// ---------------------------------------------------------------------------
// A1 — equivocation
// ---------------------------------------------------------------------------

/// A1: a committee member double-votes two sibling hashes at H — A to the
/// nodes on branch A, B to the node on branch B. At most one hash finalizes
/// anywhere (A, on the nodes that hold 3 of 4 votes for it); B never does; the
/// conflicting second vote is rejected and never relayed.
#[tokio::test]
async fn a1_equivocating_voter_cannot_finalize_two_hashes() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let byz = keys.get(3).expect("byzantine key");
    let vals = Validators::equal_stake(&keys);
    let mut net = network(3, &vals, config(100)).await;
    let a = chains.main(8);
    let b = chains.branch(&a, 4, 8, VRF_B); // sibling AT the checkpoint height 4
    net.node_mut(0).follow(&a).await;
    net.node_mut(1).follow(&a).await;
    net.node_mut(2).follow(&b).await;

    for i in 0..3 {
        net.drive(i).await;
    }
    // The Byzantine member signs BOTH siblings at 4 (and the shared block 2).
    net.inject(sign_checkpoint_vote(CHAIN, 2, hash_at(&a, 2), byz));
    let vote_a = sign_checkpoint_vote(CHAIN, 4, hash_at(&a, 4), byz);
    let vote_b = sign_checkpoint_vote(CHAIN, 4, hash_at(&b, 4), byz);
    net.send_to(0, vote_a.clone()).await;
    net.send_to(1, vote_a).await;
    net.send_to(2, vote_b.clone()).await;
    net.gossip().await;

    // Nodes 0, 1: {0, 1, byz} = quorum 3 for A@4. Node 2: {2, byz} for B@4.
    for i in [0usize, 1] {
        assert_eq!(net.node(i).finalized_hash(4).await, Some(hash_at(&a, 4)));
    }
    assert_eq!(net.node(2).finalized_hash(4).await, None, "B@4 never final");
    assert_eq!(net.node(2).finalized().await, 2, "shared block 2 finalized");
    net.assert_no_conflicting_finality(&[2, 4]).await;
    net.assert_honest_no_equivocation();

    // The conflicting vote is rejected everywhere it lands on A, never relayed.
    let out = net.send_to(0, vote_b.clone()).await;
    assert!(matches!(out, InboundOutcome::Rejected(_)), "{out:?}");
    assert!(out.relay().is_none());
    // Node 2 rejected the A votes for its pending B (hash mismatch).
    assert!(net
        .log
        .iter()
        .filter(|(to, v, _)| *to == 2 && v.height == 4 && v.block_hash == hash_at(&a, 4))
        .all(|(_, _, o)| o.starts_with("Rejected")));

    let ticks = net.tick_all().await;
    assert_eq!(ticks, vec![verified(4), verified(4), verified(2)]);
    assert!(
        !net.node(2).gadget.halted(),
        "no certificate for B: no stop"
    );

    // Fork choice later moves node 2 onto A (fork point 3 >= its floor 2):
    // allowed. Without certificate sync node 2 cannot learn the A@4
    // certificate (its pending checkpoint at 4 names B and the votes for A
    // were already gossiped) — see the C3-S1b test below.
    match net.node_mut(2).reorg_onto(&a).await {
        ReorgOutcome::Reorged { .. } => {}
        other => panic!("reorg above the floor must proceed, got {other:?}"),
    }
    assert_eq!(net.node(2).finalized().await, 2);
    assert_eq!(net.node(2).tick().await, verified(2));
}

/// A1 follow-up: a node that sat on the losing sibling at a checkpoint and is
/// then moved onto the finalized branch by fork choice reaches the same
/// finalized height as its peers through certificate sync (C3-S1b). While it
/// is on the sibling and does not hold the finalized block, the peer's
/// certificate cannot be checked against its committee: refused, no halt.
#[tokio::test]
async fn a1_node_on_losing_sibling_catches_up_after_reorg() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let byz = keys.get(3).expect("byzantine key");
    let vals = Validators::equal_stake(&keys);
    let mut net = network(3, &vals, config(100)).await;
    let a = chains.main(8);
    let b = chains.branch(&a, 4, 8, VRF_B);
    net.node_mut(0).follow(&a).await;
    net.node_mut(1).follow(&a).await;
    net.node_mut(2).follow(&b).await;
    for i in 0..3 {
        net.drive(i).await;
    }
    net.send_to(0, sign_checkpoint_vote(CHAIN, 4, hash_at(&a, 4), byz))
        .await;
    net.gossip().await;
    assert_eq!(net.node(0).finalized_hash(4).await, Some(hash_at(&a, 4)));
    // On B, without A4's header: refused with a log only.
    let out = net.sync_cert(2, 0).await;
    assert!(
        matches!(&out, Some(SyncOutcome::NotOnThisChain { height: 4, .. })),
        "{out:?}"
    );
    assert!(!net.node(2).gadget.halted());
    assert_eq!(net.node(2).finalized_hash(4).await, None);

    let _ = net.node_mut(2).reorg_onto(&a).await;
    let _ = net.round().await;
    let out = net.sync_cert(2, 0).await;
    assert!(
        matches!(&out, Some(SyncOutcome::Installed { height: 4, .. })),
        "{out:?}"
    );
    assert_eq!(net.node(2).finalized_hash(4).await, Some(hash_at(&a, 4)));
    assert_eq!(net.node(2).floor(), 4);
    assert_eq!(net.node(2).tick().await, verified(4));
    net.assert_no_conflicting_finality(&[2, 4]).await;
}

/// Owner Q1 on #332 (MAC recommendation): a node on the losing sibling that
/// HOLDS the finalized block (stored, not applied) is offered the peers'
/// certificate. It verifies against the committee this node derives itself —
/// a quorum of its own committee finalized a block it is not on — so the node
/// enters the mismatch safety stop and alarms, exactly as for a stored
/// certificate that does not match. Nothing is installed, the floor is not
/// raised, and the stop clears once fork choice moves the node onto the
/// finalized block; the certificate is then installed normally.
#[tokio::test]
async fn a1_verified_sibling_certificate_halts_then_recovers() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let byz = keys.get(3).expect("byzantine key");
    let vals = Validators::equal_stake(&keys);
    let mut net = network(3, &vals, config(100)).await;
    let a = chains.main(8);
    let b = chains.branch(&a, 4, 8, VRF_B);
    net.node_mut(0).follow(&a).await;
    net.node_mut(1).follow(&a).await;
    net.node_mut(2).follow(&b).await;
    for i in 0..3 {
        net.drive(i).await;
    }
    net.send_to(0, sign_checkpoint_vote(CHAIN, 4, hash_at(&a, 4), byz))
        .await;
    net.gossip().await;
    // Node 2 receives A's blocks but fork choice keeps it on B.
    for blk in &a {
        net.node_mut(2).import(blk).await;
    }
    let floor_before = net.node(2).floor();
    let out = net.sync_cert(2, 0).await;
    match &out {
        Some(SyncOutcome::ConflictingFinality {
            height: 4,
            certified,
            canonical,
            floor: FloorTick::Halted(HaltReason::Mismatch { height: 4, .. }),
        }) => {
            assert_eq!(*certified, hash_at(&a, 4));
            assert_eq!(*canonical, Some(hash_at(&b, 4)));
        }
        other => panic!("verified sibling must halt: {other:?}"),
    }
    assert!(net.node(2).gadget.halted(), "safety stop engaged");
    assert_eq!(net.node(2).finalized_hash(4).await, None, "not installed");
    assert_eq!(net.node(2).floor(), floor_before, "floor not raised");
    assert!(net.node_mut(2).drive().await.is_empty(), "signs nothing");
    // The poll keeps the stop while B is canonical here.
    assert!(matches!(
        net.node(2).tick().await,
        FloorTick::Halted(HaltReason::Mismatch { height: 4, .. })
    ));
    // Fork choice moves node 2 onto A: the poll clears the stop, then the
    // certificate installs normally.
    let _ = net.node_mut(2).reorg_onto(&a).await;
    assert!(matches!(
        net.node(2).tick().await,
        FloorTick::Verified {
            recovered: true,
            ..
        }
    ));
    assert!(!net.node(2).gadget.halted());
    let out = net.sync_cert(2, 0).await;
    assert!(
        matches!(&out, Some(SyncOutcome::Installed { height: 4, .. })),
        "{out:?}"
    );
    assert_eq!(net.node(2).finalized_hash(4).await, Some(hash_at(&a, 4)));
    assert_eq!(net.node(2).floor(), 4);
}

/// Owner Q1, the other half: a sibling certificate that does NOT verify
/// against the committee this node derives (signed by outsiders, or below
/// quorum) is unauthenticated peer input — refused with a log only, never a
/// halt.
#[tokio::test]
async fn a1_unverified_sibling_certificate_is_refused_without_halting() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let vals = Validators::equal_stake(&keys);
    let mut net = network(2, &vals, config(100)).await;
    let a = chains.main(8);
    let b = chains.branch(&a, 4, 8, VRF_B);
    net.node_mut(0).follow(&b).await;
    net.node_mut(1).follow(&a).await;
    // Node 1 (on A) holds B's blocks too. Node 0 claims B4 is final with a
    // forged certificate: stored where node 0 serves it from.
    for blk in &b {
        net.node_mut(1).import(blk).await;
    }
    let outsiders: Vec<Ed25519SigningKey> = (40..44).map(key).collect();
    let o: Vec<&Ed25519SigningKey> = outsiders.iter().collect();
    let k: Vec<&Ed25519SigningKey> = keys.iter().collect();
    let committee: Vec<PublicKey> = keys.iter().map(pk).collect();
    let b4 = hash_at(&b, 4);
    for forged in [
        certificate(
            4,
            b4,
            &outsiders.iter().map(pk).collect::<Vec<_>>(),
            &o,
            CHAIN,
        ),
        certificate(4, b4, &committee, &k[..2], CHAIN),
    ] {
        let mut src = net.nodes.remove(0);
        write_certificate(&src.storage, &forged);
        // Rebuilt over the store so the serving manager loads the record (its
        // own boot check halts on it — irrelevant: only node 1 is under test).
        let (n, _) = src.restart(&vals, config(100)).await;
        src = n;
        net.nodes.insert(0, src);
        let out = net.sync_cert(1, 0).await;
        assert!(
            matches!(&out, Some(SyncOutcome::NotOnThisChain { height: 4, .. })),
            "{out:?}"
        );
        assert!(!net.node(1).gadget.halted(), "a forged sibling never halts");
        assert_eq!(net.node(1).finalized().await, 0);
        delete_certificate(&net.node(0).storage, 4);
    }
}

// ---------------------------------------------------------------------------
// A2 — vote withholding / censorship
// ---------------------------------------------------------------------------

/// A2: 1 of 4 withholding (f = 1) does not stall finality.
#[tokio::test]
async fn a2_one_withholder_of_four_does_not_stall() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let vals = Validators::equal_stake(&keys);
    let mut net = network(4, &vals, config(100)).await;
    let a = chains.main(8);
    net.follow_all(&a).await;
    for i in 0..3 {
        net.drive(i).await; // node 3 withholds its votes
    }
    net.gossip().await;
    let ticks = net.tick_all().await;
    assert_eq!(
        ticks,
        vec![
            verified(4),
            verified(4),
            verified(4),
            // The withholder never proposed: the votes it received wait in its
            // early-vote buffer.
            FloorTick::NoCertificate
        ]
    );
    // When the withholder runs its own pass it finalizes from that buffer.
    net.drive(3).await;
    net.gossip().await;
    assert_eq!(net.node(3).tick().await, verified(4));
    net.assert_no_conflicting_finality(&[2, 4]).await;
}

/// A2 / L2: 2 of 4 withhold (above f): finality stalls at the last finalized
/// height on every node, blocks keep being applied, nothing halts, and when the
/// withholders return every stalled boundary finalizes and every floor rises.
#[tokio::test]
async fn a2_withheld_quorum_stalls_safely_then_resumes() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let vals = Validators::equal_stake(&keys);
    let mut net = network(4, &vals, config(100)).await;
    let a = chains.main(8);
    net.follow_all(&a).await;
    // Nodes 2 and 3 are online (they receive) but withhold their votes.
    net.drive(0).await;
    net.drive(1).await;
    net.gossip().await;
    for t in net.tick_all().await {
        assert_eq!(t, FloorTick::NoCertificate);
    }
    // The chain keeps growing under the stall; still nothing finalizes.
    let a = chains.main(12);
    net.follow_all(&a).await;
    net.drive(0).await;
    net.drive(1).await;
    net.gossip().await;
    for (i, n) in net.nodes.iter().enumerate() {
        assert_eq!(n.app.applied_tip().await.height, 12, "node {i} applies");
        assert_eq!(n.finalized().await, 0, "node {i} stalled");
        assert_eq!(n.tick().await, FloorTick::NoCertificate);
        assert_eq!(n.floor(), 0);
        assert!(!n.gadget.halted(), "a stall is not a safety stop");
    }
    // Node 2 returns: its first pass votes 2..8 and replays the early votes it
    // buffered from 0 and 1 -> quorum on 0, 1, 2. Node 3 returns after.
    net.drive(2).await;
    net.gossip().await;
    for i in 0..3 {
        assert_eq!(net.node(i).finalized().await, 8, "node {i}");
    }
    net.drive(3).await;
    net.gossip().await;
    let ticks = net.tick_all().await;
    assert!(ticks.iter().all(|t| *t == verified(8)), "{ticks:?}");
    for n in &net.nodes {
        assert_eq!(n.floor(), 8);
    }
    net.assert_no_conflicting_finality(&[2, 4, 6, 8]).await;
    net.assert_honest_no_equivocation();
}

// ---------------------------------------------------------------------------
// A3 — Byzantine 1/3
// ---------------------------------------------------------------------------

/// A3 / S1: n = 7, f = floor((n-1)/3) = 2 Byzantine, quorum 5. Four honest
/// nodes sit on A, one honest node on the sibling B at checkpoint 4. The two
/// Byzantine members first push only B (A stalls at 4 honest votes, B reaches 3
/// on the B node: nothing finalizes at 4 anywhere), then equivocate and also
/// sign A (A finalizes on the A nodes). B never finalizes.
#[tokio::test]
async fn a3_one_third_byzantine_cannot_force_conflicting_finality() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..7).map(key).collect();
    assert_eq!(derived_quorum(7), 5);
    let byz: Vec<&Ed25519SigningKey> = keys.iter().skip(5).collect();
    let vals = Validators::equal_stake(&keys);
    let mut net = network(5, &vals, config(100)).await;
    let a = chains.main(8);
    let b = chains.branch(&a, 4, 8, VRF_B);
    for i in 0..4 {
        net.node_mut(i).follow(&a).await;
    }
    net.node_mut(4).follow(&b).await;
    for i in 0..5 {
        net.drive(i).await;
    }
    for z in &byz {
        net.inject(sign_checkpoint_vote(CHAIN, 4, hash_at(&b, 4), z));
    }
    net.gossip().await;
    // Height 2 (shared) finalized by the 5 honest votes alone; nothing at 4.
    for (i, n) in net.nodes.iter().enumerate() {
        assert_eq!(n.finalized().await, 2, "node {i}");
        assert_eq!(n.finalized_hash(4).await, None, "node {i}");
    }
    assert_eq!(net.node(4).mgr().pending_vote_count(4).await, Some(3));

    // Byzantine members equivocate: also sign A@4.
    for z in &byz {
        net.inject(sign_checkpoint_vote(CHAIN, 4, hash_at(&a, 4), z));
    }
    net.gossip().await;
    for i in 0..4 {
        assert_eq!(net.node(i).finalized_hash(4).await, Some(hash_at(&a, 4)));
    }
    assert_eq!(net.node(4).finalized_hash(4).await, None, "B never final");
    net.assert_no_conflicting_finality(&[2, 4]).await;
    net.assert_honest_no_equivocation();
    let ticks = net.tick_all().await;
    assert_eq!(
        ticks,
        vec![
            verified(4),
            verified(4),
            verified(4),
            verified(4),
            verified(2)
        ]
    );
}

// ---------------------------------------------------------------------------
// A4 — cross-chain replay; forged certificates
// ---------------------------------------------------------------------------

/// A4 / S3: votes signed for another chain id by the REAL committee are
/// rejected (all four of them: no finality from them, nothing relayed); the
/// honest votes then finalize normally.
#[tokio::test]
async fn a4_cross_chain_votes_are_rejected() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let vals = Validators::equal_stake(&keys);
    let mut net = network(4, &vals, config(100)).await;
    let a = chains.main(8);
    net.follow_all(&a).await;
    let _ = net.node_mut(0).drive().await; // node 0 proposes 2, 4 (own vote kept local)
    for k in &keys {
        for h in [2u64, 4] {
            let out = net
                .send_to(0, sign_checkpoint_vote(FOREIGN_CHAIN, h, hash_at(&a, h), k))
                .await;
            assert!(
                matches!(out, InboundOutcome::Rejected(_)),
                "foreign vote at {h}: {out:?}"
            );
            assert!(out.relay().is_none());
        }
    }
    assert!(net.queue.is_empty(), "nothing relayed");
    assert_eq!(net.node(0).finalized().await, 0);
    assert_eq!(net.node(0).mgr().pending_vote_count(4).await, Some(1));

    let ticks = net.round().await;
    assert!(ticks.iter().all(|t| *t == verified(4)), "{ticks:?}");
}

/// A4 / stale-or-forged certificates: each tampered certificate record, found
/// at boot, halts finality BEFORE any block is admitted — floor never raised
/// from the forged record (only restored to the earlier VALID certificate at 6,
/// whose block is canonical here: boot floor restore, review of #335 @
/// 5236d2b), RPC tags at genesis, gadget proposes nothing — and the stop never
/// clears by itself.
#[tokio::test]
async fn a4_forged_certificates_halt_at_boot_and_never_clear() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let committee: Vec<PublicKey> = keys.iter().map(pk).collect();
    let vals = Validators::equal_stake(&keys);
    let cfg = config(100);
    let mut net = network(4, &vals, cfg.clone()).await;
    let a = chains.main(10);
    net.follow_all(&a).await;
    let ticks = net.round().await;
    assert!(ticks.iter().all(|t| *t == verified(6)), "{ticks:?}");

    let outsiders: Vec<Ed25519SigningKey> = (40..44).map(key).collect();
    let h8 = hash_at(&a, 8);
    let k: Vec<&Ed25519SigningKey> = keys.iter().collect();
    let o: Vec<&Ed25519SigningKey> = outsiders.iter().collect();
    let mut pending_status = certificate(8, h8, &committee, &k, CHAIN);
    pending_status.status = CheckpointStatus::Pending;
    let mut swapped_hash = certificate(8, hash_at(&a, 6), &committee, &k, CHAIN);
    swapped_hash.block_hash = h8; // signatures are over a different block
    let forgeries: Vec<(&str, Checkpoint)> = vec![
        (
            "below quorum",
            certificate(8, h8, &committee, &k[..2], CHAIN),
        ),
        (
            "foreign-chain signatures",
            certificate(8, h8, &committee, &k, FOREIGN_CHAIN),
        ),
        ("signatures over another block", swapped_hash),
        (
            "outsider voters",
            certificate(8, h8, &committee, &[k[0], k[1], o[0]], CHAIN),
        ),
        (
            "committee below the minimum",
            certificate(8, h8, &committee[..3], &k[..3], CHAIN),
        ),
    ];
    let mut node = net.nodes.pop().expect("node 3");
    for (what, forged) in forgeries {
        assert!(
            forged.verify_certificate(CHAIN).is_err(),
            "{what}: must not verify"
        );
        write_certificate(&node.storage, &forged);
        let (n, boot) = node.restart(&vals, cfg.clone()).await;
        node = n;
        assert!(
            matches!(
                boot,
                FloorTick::Halted(HaltReason::InvalidCertificate { height: 8, .. })
            ),
            "{what}: {boot:?}"
        );
        assert!(node.gadget.halted(), "{what}");
        assert_eq!(
            node.floor(),
            6,
            "{what}: not raised from the forged record; restored to the valid A6"
        );
        assert_eq!(node.rpc_finalized(), FinalizedAnchor::GENESIS, "{what}");
        let out = node.drive().await;
        assert!(out.is_empty(), "{what}: nothing signed while halted");
        // Never clears by itself, even if something clears the gadget flag.
        node.gadget.safety_stop().clear().await;
        assert!(matches!(node.tick().await, FloorTick::Halted(_)), "{what}");
        assert!(node.gadget.halted(), "{what}");
        delete_certificate(&node.storage, 8);
    }
    // A record whose status is not Finalized is never loaded as a certificate:
    // the boot check verifies the real one at 6 (nothing is raised from it).
    assert!(pending_status.verify_certificate(CHAIN).is_err());
    write_certificate(&node.storage, &pending_status);
    let (node, boot) = node.restart(&vals, cfg.clone()).await;
    assert_eq!(boot, verified(6));
    assert_eq!(node.mgr().latest_finalized_height().await, 6);
    delete_certificate(&node.storage, 8);
    // Record removed: the next boot verifies the real certificate again.
    let (node, boot) = node.restart(&vals, cfg).await;
    assert_eq!(boot, verified(6));
    assert_eq!(node.floor(), 6);
}

/// A4 follow-up: a STORED certificate whose committee is NOT the committee the
/// epoch snapshot yields for that height (here: four outsider keys, every
/// signature valid — internally consistent) is rejected at boot. The boot
/// check re-derives the committee for every stored certificate (governing
/// epoch snapshot + the certified block's VRF beacon) and verifies against
/// it, never against the record's own committee (review of #332 @ 354908b).
#[tokio::test]
async fn a4_certificate_with_a_foreign_committee_is_rejected() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let vals = Validators::equal_stake(&keys);
    let cfg = config(100);
    let mut node = TestNode::boot(key(0), &vals, cfg.clone()).await;
    let a = chains.main(10);
    node.follow(&a).await;
    let outsiders: Vec<Ed25519SigningKey> = (40..44).map(key).collect();
    let committee: Vec<PublicKey> = outsiders.iter().map(pk).collect();
    let o: Vec<&Ed25519SigningKey> = outsiders.iter().collect();
    write_certificate(
        &node.storage,
        &certificate(6, hash_at(&a, 6), &committee, &o, CHAIN),
    );
    let (node, boot) = node.restart(&vals, cfg).await;
    assert!(
        matches!(
            boot,
            FloorTick::Halted(HaltReason::InvalidCertificate { .. })
        ),
        "{boot:?}"
    );
    assert_eq!(node.floor(), 0);
}

// ---------------------------------------------------------------------------
// A5 — cross-height replay; stale votes
// ---------------------------------------------------------------------------

/// A5 / S3: a valid vote for H relabelled to H' is rejected; a correctly
/// signed vote for (H', hash at H) is rejected (wrong block for H'); a vote for
/// an already-finalized height is rejected, not buffered, not relayed.
#[tokio::test]
async fn a5_cross_height_and_stale_votes_are_rejected() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let vals = Validators::equal_stake(&keys);
    let mut net = network(4, &vals, config(100)).await;
    let a = chains.main(8);
    net.follow_all(&a).await;
    let _ = net.node_mut(0).drive().await; // pending 2, 4 on node 0
    let k1 = keys.get(1).expect("key 1");
    let v2 = sign_checkpoint_vote(CHAIN, 2, hash_at(&a, 2), k1);

    let mut relabelled = v2.clone();
    relabelled.height = 4;
    relabelled.block_hash = hash_at(&a, 4);
    let out = net.send_to(0, relabelled).await;
    assert!(
        matches!(
            out,
            InboundOutcome::Rejected(CheckpointError::InvalidSignature(_))
        ),
        "{out:?}"
    );
    let wrong_block = sign_checkpoint_vote(CHAIN, 4, hash_at(&a, 2), k1);
    let out = net.send_to(0, wrong_block).await;
    assert!(matches!(out, InboundOutcome::Rejected(_)), "{out:?}");
    assert_eq!(net.node(0).mgr().pending_vote_count(4).await, Some(1));
    // A non-boundary height is refused outright.
    let odd = sign_checkpoint_vote(CHAIN, 5, hash_at(&a, 5), k1);
    let out = net.send_to(1, odd).await;
    assert!(
        matches!(
            out,
            InboundOutcome::Rejected(CheckpointError::NotCheckpointBoundary)
        ),
        "{out:?}"
    );
    net.queue.clear();

    let _ = net.round().await;
    for n in &net.nodes {
        assert_eq!(n.finalized().await, 4);
    }
    // Stale: a vote for a finalized height, arriving after finality.
    let late = sign_checkpoint_vote(CHAIN, 2, hash_at(&a, 2), keys.get(3).expect("k3"));
    for i in 0..4 {
        let out = net.send_to(i, late.clone()).await;
        assert!(matches!(out, InboundOutcome::Rejected(_)), "{out:?}");
        assert!(out.relay().is_none());
        assert_eq!(net.node(i).gadget.early_vote_count().await, 0);
    }
}

// ---------------------------------------------------------------------------
// A6 — reorg below finality; safety stop and resume
// ---------------------------------------------------------------------------

/// A6 / S2: after the floor is raised, a reorg with its fork point below it is
/// rejected, including a heavier branch with a sibling AT the checkpoint; a
/// reorg whose fork point is at/above the floor proceeds and the certificate
/// stays verified.
#[tokio::test]
async fn a6_reorg_below_finality_is_rejected_above_is_allowed() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let vals = Validators::equal_stake(&keys);
    let mut net = network(4, &vals, config(100)).await;
    let a = chains.main(8);
    net.follow_all(&a).await;
    let _ = net.round().await;
    assert_eq!(net.node(0).floor(), 4);

    for fork_at in [2u64, 4] {
        let b = chains.branch(&a, fork_at, 14, VRF_B);
        match net.node_mut(0).reorg_onto(&b).await {
            ReorgOutcome::Rejected(why) => {
                assert!(why.contains("below finalized"), "fork at {fork_at}: {why}")
            }
            other => panic!("fork at {fork_at}: expected Rejected, got {other:?}"),
        }
        assert_eq!(net.node(0).app.applied_tip().await.hash, hash_at(&a, 8));
    }
    // Fork point exactly at the floor (sibling of A5): allowed.
    let c = chains.branch(&a, 5, 10, VRF_C);
    match net.node_mut(0).reorg_onto(&c).await {
        ReorgOutcome::Reorged { .. } => {}
        other => panic!("fork point at the floor must reorg, got {other:?}"),
    }
    assert_eq!(net.node(0).tick().await, verified(4));
    assert!(!net.node(0).gadget.halted());
}

/// Safety stop and resume, end to end (spec §4.5). Node 3 proposes and signs
/// A2 / A4, then fork choice moves it onto a sibling branch B (forking at 3)
/// BEFORE the votes for A4 reach it — allowed, nothing above 0 is final yet.
/// When A4 then finalizes on node 3, the finalization-time check finds B4 at
/// height 4 and halts finality before the finalization is visible: no
/// proposal, no signature, floor and RPC tags at the last verified pair (A2),
/// while the other nodes keep finalizing. When fork choice brings the node
/// back onto the certified branch the stop clears, the boundaries skipped
/// during the stop are revisited on the canonical chain, and the node votes
/// and finalizes with the others again.
#[tokio::test]
async fn safety_stop_on_mismatch_then_resume_after_fork_choice() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let vals = Validators::equal_stake(&keys);
    let mut net = network(4, &vals, config(100)).await;
    let a = chains.main(8);
    net.follow_all(&a).await;
    for i in 0..4 {
        net.drive(i).await;
    }
    // Node 3 is moved onto a heavier sibling branch forking at 3 before any
    // vote is delivered: allowed (its floor is 0).
    let b = chains.branch(&a, 4, 12, VRF_B);
    match net.node_mut(3).reorg_onto(&b).await {
        ReorgOutcome::Reorged { .. } => {}
        other => panic!("expected the reorg to proceed, got {other:?}"),
    }
    net.gossip().await; // Finalize 2, 4 everywhere.
    let halted = HaltReason::Mismatch {
        height: 4,
        certified: hash_at(&a, 4),
        canonical: Some(hash_at(&b, 4)),
    };
    for i in 0..3 {
        assert_eq!(net.node(i).finalized().await, 4);
        assert_eq!(net.node(i).floor(), 4, "floor raised at finalization");
    }
    // Node 3 holds the certificate for A4 but halted when it finalized; the
    // floor protects A2 (shared by both branches), not A4.
    assert_eq!(net.node(3).finalized().await, 4);
    assert!(net.node(3).gadget.halted(), "halted at finalization");
    assert_eq!(net.node(3).floor(), 2);
    assert_eq!(
        net.node(3).rpc_finalized(),
        FinalizedAnchor {
            height: 2,
            hash: Some(hash_at(&a, 2))
        }
    );
    assert_eq!(net.node(3).tick().await, FloorTick::Halted(halted.clone()));

    // The others advance to 12 and keep finalizing (quorum 3 without node 3);
    // node 3 runs its driver on B: nothing is proposed or signed, nothing sent.
    let a = chains.main(12);
    for i in 0..3 {
        net.node_mut(i).follow(&a).await;
    }
    let out = net.drive(3).await;
    assert!(out.is_empty());
    for h in [6u64, 8] {
        assert_eq!(net.node(3).gadget.signed_vote_at(h), None, "nothing signed");
        assert_eq!(net.node(3).mgr().pending_hash(h).await, None);
    }
    for i in 0..3 {
        net.drive(i).await;
    }
    net.gossip().await;
    for i in 0..3 {
        assert_eq!(net.node(i).finalized().await, 8);
        assert_eq!(net.node(i).tick().await, verified(8));
    }
    assert_eq!(net.node(3).tick().await, FloorTick::Halted(halted));

    // Fork choice: A is heavier again; node 3 reorgs back (fork point 3 >=
    // floor 2). The next poll clears the stop and raises the floor.
    let a = chains.main(14);
    for i in 0..3 {
        net.node_mut(i).follow(&a).await;
    }
    match net.node_mut(3).reorg_onto(&a).await {
        ReorgOutcome::Reorged { .. } => {}
        other => panic!("expected the reorg back onto A, got {other:?}"),
    }
    let t = net.node(3).tick().await;
    assert!(
        matches!(
            t,
            FloorTick::Verified {
                recovered: true,
                ..
            }
        ),
        "{t:?}"
    );
    assert!(!net.node(3).gadget.halted());
    // Node 3's next pass revisits 6 and 8 (skipped during the stop) on A —
    // proposing them replays the votes it buffered meanwhile -> finalized — and
    // votes the new boundary 10 with the others.
    let mut node3_out = Vec::new();
    for i in 0..4 {
        let out = net.drive(i).await;
        if i == 3 {
            node3_out = out;
        }
    }
    net.gossip().await;
    let own: Vec<(u64, Hash)> = node3_out
        .iter()
        .filter(|v| v.voter == net.node(3).me())
        .map(|v| (v.height, v.block_hash))
        .collect();
    assert_eq!(
        own,
        vec![
            (10, hash_at(&a, 10)),
            (6, hash_at(&a, 6)),
            (8, hash_at(&a, 8))
        ],
        "new boundary first, then the revisits — all on A"
    );
    let ticks = net.tick_all().await;
    assert!(ticks.iter().all(|t| *t == verified(10)), "{ticks:?}");
    net.assert_no_conflicting_finality(&[2, 4, 6, 8, 10]).await;
    net.assert_honest_no_equivocation();
}

/// §5 S2 (strict): "committed state is never reverted below
/// `latest_finalized_height()`". The reorg floor is raised when the checkpoint
/// finalizes — before the finalized height is visible — not at the next
/// floor-verifier poll, so a reorg right after finalization, with no poll in
/// between, is rejected. (Formerly an open finding: the floor followed only at
/// the 5 s poll.) TLA+: CheckpointFinalitySafety_strict.cfg.
#[tokio::test]
async fn s2_strict_reorg_below_fresh_certificate_is_rejected() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let vals = Validators::equal_stake(&keys);
    let mut net = network(4, &vals, config(100)).await;
    let a = chains.main(8);
    net.follow_all(&a).await;
    for i in 0..4 {
        net.drive(i).await;
    }
    net.gossip().await;
    for n in &net.nodes {
        assert_eq!(n.finalized().await, 4);
        assert_eq!(n.floor(), 4, "floor raised at finalization, no poll needed");
        assert_eq!(
            n.rpc_finalized(),
            FinalizedAnchor {
                height: 4,
                hash: Some(hash_at(&a, 4))
            }
        );
        assert!(!n.gadget.halted());
    }
    let b = chains.branch(&a, 4, 12, VRF_B);
    match net.node_mut(3).reorg_onto(&b).await {
        ReorgOutcome::Rejected(why) => assert!(why.contains("below finalized"), "{why}"),
        other => panic!("S2: reorg below the finalized height 4 proceeded: {other:?}"),
    }
    assert_eq!(net.node(3).app.applied_tip().await.hash, hash_at(&a, 8));
    // The poll (backstop) agrees and changes nothing.
    assert_eq!(net.node(3).tick().await, verified(4));
    assert_eq!(net.node(3).floor(), 4);
    // The losing branch is never proposed or signed: the driver keeps walking A.
    let a = chains.main(12);
    net.follow_all(&a).await;
    let ticks = net.round().await;
    assert!(ticks.iter().all(|t| *t == verified(8)), "{ticks:?}");
    for n in &net.nodes {
        for h in [6u64, 8] {
            if let Some(signed) = n.gadget.signed_vote_at(h) {
                assert_eq!(signed, hash_at(&a, h), "signed only on A");
            }
        }
    }
    net.assert_no_conflicting_finality(&[2, 4, 6, 8]).await;
    net.assert_honest_no_equivocation();
}

/// S2, certified block not yet on this node's applied chain when it finalizes
/// (fork choice moved node 3 to a SHORTER branch after it proposed A4): the
/// finalization-time check cannot confirm A4, so finality is paused
/// (`Unconfirmed`) before the finalization is visible. The certificate is
/// registered with the applicator: once fork choice brings A4 back, the very
/// next reorg attempt raises the floor to 4 under the advance lock and is
/// refused if it would revert A4 — no poll needed. The poll then clears the
/// stop.
#[tokio::test]
async fn s2_certificate_not_yet_applied_pauses_then_protects_on_return() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let vals = Validators::equal_stake(&keys);
    let mut net = network(4, &vals, config(100)).await;
    let a = chains.main(8);
    net.follow_all(&a).await;
    for i in 0..4 {
        net.drive(i).await;
    }
    // A shorter sibling branch: A1, A2, then B3 (tip height 3 < 4).
    let short = chains.branch(&a, 3, 3, VRF_B);
    match net.node_mut(3).reorg_onto(&short).await {
        ReorgOutcome::Reorged { height: 3, .. } => {}
        other => panic!("expected the reorg to the short branch, got {other:?}"),
    }
    net.gossip().await;
    assert_eq!(net.node(3).finalized().await, 4);
    assert!(net.node(3).gadget.halted(), "paused at finalization");
    assert_eq!(net.node(3).floor(), 2, "A2 is shared and protected");
    let t = net.node(3).tick().await;
    assert!(
        matches!(
            &t,
            FloorTick::Halted(HaltReason::Unconfirmed { height: 4, certified, .. })
                if *certified == hash_at(&a, 4)
        ),
        "{t:?}"
    );
    assert_eq!(
        net.node(3).app.certified_pending(),
        vec![(4, hash_at(&a, 4))]
    );
    // Fork choice brings A back (fork point 2 >= floor 2: allowed).
    match net.node_mut(3).reorg_onto(&a).await {
        ReorgOutcome::Reorged { .. } => {}
        other => panic!("expected the reorg back onto A, got {other:?}"),
    }
    // Before any poll: a reorg that would revert A4 is refused, and the floor
    // is raised to 4 by that check.
    let c = chains.branch(&a, 4, 12, VRF_C);
    match net.node_mut(3).reorg_onto(&c).await {
        ReorgOutcome::Rejected(why) => assert!(why.contains("below finalized height 4"), "{why}"),
        other => panic!("A4 is canonical and certified; reorg must be refused: {other:?}"),
    }
    assert_eq!(net.node(3).floor(), 4);
    assert!(net.node(3).app.certified_pending().is_empty());
    let t = net.node(3).tick().await;
    assert!(
        matches!(
            t,
            FloorTick::Verified {
                height: 4,
                recovered: true,
                ..
            }
        ),
        "{t:?}"
    );
    assert!(!net.node(3).gadget.halted());
}

/// S2 publication (review of #335 @ db243a1): the verifier's hooks publish the
/// finalized/safe RPC pair only once the certificate is in the persistent
/// store, whatever their caller did — a block reported finalized without a
/// stored certificate could be reorged out after a restart. (Since #362
/// `finalize_checkpoint` writes the certificate durably before it runs the
/// guard, and finalizes nothing if that write fails —
/// `s2_certificate_write_failure_raises_no_floor_and_publishes_nothing`; this
/// test drives the hooks directly to pin the publication check itself.) After
/// publication a restart restores the floor from the certificate and refuses
/// the same reorg.
#[tokio::test]
async fn s2_rpc_finalized_is_published_only_after_the_certificate_is_persisted() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let vals = Validators::equal_stake(&keys);
    let committee: Vec<PublicKey> = keys.iter().map(pk).collect();
    let signers: Vec<&Ed25519SigningKey> = keys.iter().take(3).collect();
    let cfg = config(100);
    let mut node = TestNode::boot(key(0), &vals, cfg.clone()).await;
    let genesis_state = node.exec.state_snapshot();
    let a = chains.main(8);
    node.follow(&a).await;
    let b = chains.branch(&a, 3, 10, VRF_B);
    for blk in &b {
        node.import(blk).await;
    }
    let cert = certificate(4, hash_at(&a, 4), &committee, &signers, CHAIN);

    // The guard (CheckpointManager::finalize_checkpoint's pre-finalization
    // hook) runs: floor raised, nothing published.
    assert_eq!(node.verifier.on_finalize(&cert).await, Some(verified(4)));
    assert_eq!(node.floor(), 4, "floor raised at finalization");
    assert_eq!(
        node.rpc_finalized(),
        FinalizedAnchor::GENESIS,
        "nothing published before the certificate is persisted"
    );
    // The certificate write did not happen (or failed): the post-finalization
    // hook and the poll still publish nothing.
    assert!(!node.mgr().is_certificate_persisted(4, &hash_at(&a, 4)));
    assert_eq!(node.verifier.after_finalize(&cert).await, Some(verified(4)));
    assert_eq!(node.rpc_finalized(), FinalizedAnchor::GENESIS);
    assert_eq!(node.tick().await, FloorTick::NoCertificate);
    assert_eq!(node.rpc_finalized(), FinalizedAnchor::GENESIS);

    // Crash in that interval: the restart has neither the certificate nor the
    // floor, so a rebuild abandoning A4 proceeds — and no block it abandons was
    // ever reported finalized.
    let (node, boot) = node.restart(&vals, cfg.clone()).await;
    assert_eq!(boot, FloorTick::NoCertificate);
    assert_eq!(node.floor(), 0);
    assert_eq!(node.rpc_finalized(), FinalizedAnchor::GENESIS);
    *node.head.lock() = Some(hash_at(&b, 10));
    assert!(
        node.app
            .recover_to_head(genesis_state.clone(), Hash::default())
            .await
            .expect("recovery call returns"),
        "nothing finalized here after the restart: the rebuild proceeds"
    );
    assert_eq!(node.app.applied_tip().await.hash, hash_at(&b, 10));
    *node.head.lock() = Some(hash_at(&a, 8));
    assert!(
        node.app
            .recover_to_head(genesis_state.clone(), Hash::default())
            .await
            .expect("recovery call returns"),
        "back onto A"
    );
    assert_eq!(node.app.applied_tip().await.hash, hash_at(&a, 8));

    // The certificate is persisted (as finalize_checkpoint does before the
    // post-finalization hook): now, and only now, the pair is published.
    assert_eq!(node.verifier.on_finalize(&cert).await, Some(verified(4)));
    assert_eq!(node.rpc_finalized(), FinalizedAnchor::GENESIS);
    write_certificate(&node.storage, &cert);
    assert!(node.mgr().is_certificate_persisted(4, &hash_at(&a, 4)));
    assert_eq!(node.verifier.after_finalize(&cert).await, Some(verified(4)));
    assert_eq!(
        node.rpc_finalized(),
        FinalizedAnchor {
            height: 4,
            hash: Some(hash_at(&a, 4))
        }
    );

    // A crash after publication: the restart restores the floor from the stored
    // certificate before anything else, so the same rebuild is refused.
    let (node, boot) = node.restart(&vals, cfg).await;
    assert_eq!(boot, verified(4));
    assert_eq!(node.floor(), 4);
    assert_eq!(
        node.rpc_finalized(),
        FinalizedAnchor {
            height: 4,
            hash: Some(hash_at(&a, 4))
        }
    );
    *node.head.lock() = Some(hash_at(&b, 10));
    assert!(
        !node
            .app
            .recover_to_head(genesis_state, Hash::default())
            .await
            .expect("recovery call returns"),
        "S2: a block published as finalized must not be abandoned after a restart"
    );
    assert_eq!(node.app.applied_tip().await.hash, hash_at(&a, 8));
    assert_eq!(node.floor(), 4);
}

/// S2 publication, recovery variant: an `Unconfirmed` stop entered at
/// finalization (certified block above the applied tip) clears on the poll once
/// the block is applied — the floor is raised then — but the pair is still not
/// published while its certificate is not persisted. A safety stop in force
/// also blocks the post-finalization publication.
#[tokio::test]
async fn s2_cleared_stop_does_not_publish_an_unpersisted_certificate() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let vals = Validators::equal_stake(&keys);
    let committee: Vec<PublicKey> = keys.iter().map(pk).collect();
    let signers: Vec<&Ed25519SigningKey> = keys.iter().take(3).collect();
    let mut node = TestNode::boot(key(0), &vals, config(100)).await;
    let a = chains.main(8);
    node.follow(a.get(..3).expect("A1..A3")).await;
    let cert = certificate(4, hash_at(&a, 4), &committee, &signers, CHAIN);
    let t = node.verifier.on_finalize(&cert).await;
    assert!(
        matches!(
            &t,
            Some(FloorTick::Halted(HaltReason::Unconfirmed { height: 4, .. }))
        ),
        "{t:?}"
    );
    // A stop is in force: the post-finalization hook publishes nothing.
    assert!(matches!(
        node.verifier.after_finalize(&cert).await,
        Some(FloorTick::Halted(_))
    ));
    assert_eq!(node.rpc_finalized(), FinalizedAnchor::GENESIS);
    node.follow(&a).await;
    let t = node.tick().await;
    assert!(matches!(t, FloorTick::NoCertificate), "{t:?}");
    assert!(!node.gadget.halted(), "stop cleared: A4 is canonical");
    assert_eq!(node.floor(), 4, "floor raised when the stop cleared");
    assert_eq!(
        node.rpc_finalized(),
        FinalizedAnchor::GENESIS,
        "not published: the certificate is not persisted"
    );
    write_certificate(&node.storage, &cert);
    assert_eq!(node.verifier.after_finalize(&cert).await, Some(verified(4)));
    assert_eq!(
        node.rpc_finalized(),
        FinalizedAnchor {
            height: 4,
            hash: Some(hash_at(&a, 4))
        }
    );
}

/// S2 atomicity, guard state change <-> certificate (review of #335 @ fa6595a1).
/// The finalization-time guard raises the floor; the certificate it ran on must
/// then be the one finalized and persisted, even if the pending checkpoint is
/// pruned and RE-PROPOSED for the same block hash (with no votes) while the
/// guard runs, and while a second finalization of the same height is started.
///
/// Deterministic interleaving on the real wiring (manager + installed verifier
/// guard + applicator): the test holds the applicator's advance lock, so the
/// guard parks inside its floor check after registering the certificate; the
/// prune, the re-proposal attempt (refused since #362: the certificate is
/// already durable when the guard runs) and the concurrent finalization happen
/// there; then the lock is released. Afterwards the floor, the persisted
/// certificate and the published RPC pair agree, and a restart that reloads
/// everything from disk restores the same floor and refuses a rebuild below
/// it. (A failed certificate write raises no floor at all:
/// `s2_certificate_write_failure_raises_no_floor_and_publishes_nothing`.)
#[tokio::test]
async fn s2_guarded_certificate_survives_a_same_hash_re_proposal_and_a_restart() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let vals = Validators::equal_stake(&keys);
    let committee: Vec<PublicKey> = keys.iter().map(pk).collect();
    let cfg = config(100);
    let mut node = TestNode::boot(key(0), &vals, cfg.clone()).await;
    let genesis_state = node.exec.state_snapshot();
    let a = chains.main(8);
    node.follow(&a).await;
    let b = chains.branch(&a, 3, 10, VRF_B);
    for blk in &b {
        node.import(blk).await;
    }
    let h4 = hash_at(&a, 4);
    let mgr = node.mgr().clone();
    assert_eq!(
        mgr.ensure_proposed(4, h4, committee.clone())
            .await
            .expect("propose"),
        citrate_consensus::checkpoint::ProposeOutcome::Proposed
    );
    for k in keys.iter().take(3) {
        mgr.submit_vote(sign_checkpoint_vote(CHAIN, 4, h4, k))
            .await
            .expect("vote");
    }

    // Park the guard inside its floor check.
    let advance = node.app.advance_lock();
    let held = advance.lock().await;
    let first = tokio::spawn({
        let mgr = mgr.clone();
        async move { mgr.finalize_checkpoint(4).await }
    });
    let mut spins = 0u32;
    while !node.app.certified_pending().contains(&(4, h4)) {
        spins += 1;
        assert!(spins < 100_000, "guard never reached its floor check");
        tokio::task::yield_now().await;
    }
    // Inside the guard: pruned, a same-hash re-proposal attempted, and a
    // concurrent finalization of the same height queued. The certificate is
    // already durable when the guard runs (#362), so the height cannot be
    // re-opened: the re-proposal is refused and nothing is pending there.
    let second = tokio::spawn({
        let mgr = mgr.clone();
        async move { mgr.finalize_checkpoint(4).await }
    });
    mgr.prune_at_or_below(4).await;
    assert_eq!(
        mgr.ensure_proposed(4, h4, committee.clone())
            .await
            .expect("re-propose"),
        citrate_consensus::checkpoint::ProposeOutcome::AlreadyFinalized,
        "a height whose certificate is on disk is never re-opened"
    );
    assert_eq!(mgr.pending_vote_count(4).await, None);
    assert_eq!(node.floor(), 0, "the guard has not raised the floor yet");
    drop(held);

    let first = first.await.expect("first finalization task");
    assert!(
        first.is_ok(),
        "the certificate the guard ran on must finalize, got {first:?}"
    );
    let cp = first.expect("checked above");
    assert_eq!((cp.height, cp.block_hash, cp.votes.len()), (4, h4, 3));
    let second = second.await.expect("second finalization task");
    assert!(
        matches!(second, Err(CheckpointError::BlockNotFound(_))),
        "{second:?}"
    );
    // The guard's state change and the certificate agree.
    assert_eq!(node.floor(), 4, "floor raised by the guard");
    assert!(!node.gadget.halted());
    assert!(
        mgr.is_certificate_persisted(4, &h4),
        "the guarded certificate is persisted"
    );
    assert_eq!(mgr.latest_finalized_height().await, 4);
    assert_eq!(
        node.rpc_finalized(),
        FinalizedAnchor {
            height: 4,
            hash: Some(h4)
        }
    );
    assert_eq!(node.tick().await, verified(4));

    // Crash and restart from disk: floor, certificate and RPC pair come back
    // together, and a rebuild abandoning A4 is refused.
    let (node, boot) = node.restart(&vals, cfg).await;
    assert_eq!(boot, verified(4));
    assert_eq!(node.floor(), 4);
    assert_eq!(node.mgr().latest_finalized_height().await, 4);
    let stored = node.mgr().get_checkpoint(4).await.expect("reloaded");
    assert_eq!((stored.block_hash, stored.votes.len()), (h4, 3));
    assert!(stored.verify_certificate(CHAIN).is_ok());
    assert_eq!(
        node.rpc_finalized(),
        FinalizedAnchor {
            height: 4,
            hash: Some(h4)
        }
    );
    *node.head.lock() = Some(hash_at(&b, 10));
    assert!(
        !node
            .app
            .recover_to_head(genesis_state, Hash::default())
            .await
            .expect("recovery call returns"),
        "S2: the finalized block must not be abandoned after a restart"
    );
    assert_eq!(node.app.applied_tip().await.hash, hash_at(&a, 8));
}

// ---------------------------------------------------------------------------
// S2 certificate durability (follow-up to #335): the certificate is written
// with a synced write BEFORE the guard raises the floor and before anything is
// published; a failed write raises no floor and publishes nothing.
// ---------------------------------------------------------------------------

/// Fault seam over the node's real RocksDB store: every write of a certificate
/// record (`DAG_METADATA` `checkpoint:{height}`) fails while `failing` is set,
/// as a failed write or a failed fsync would; every other record (blocks, the
/// signed-vote record, ...) goes straight to RocksDB.
struct FaultyCertKv {
    inner: RocksDbKvStore,
    failing: std::sync::atomic::AtomicBool,
    failed: AtomicU64,
}

impl FaultyCertKv {
    fn new(storage: &StorageManager, failing: bool) -> Arc<Self> {
        Arc::new(Self {
            inner: RocksDbKvStore::new(storage.db.clone()),
            failing: std::sync::atomic::AtomicBool::new(failing),
            failed: AtomicU64::new(0),
        })
    }

    fn heal(&self) {
        self.failing.store(false, Ordering::SeqCst);
    }

    fn check(&self, cf_name: &str, key: &[u8]) -> Result<(), String> {
        if cf_name == cf::DAG_METADATA
            && key.starts_with(b"checkpoint:")
            && self.failing.load(Ordering::SeqCst)
        {
            self.failed.fetch_add(1, Ordering::SeqCst);
            return Err("injected: fsync failed (EIO)".to_string());
        }
        Ok(())
    }
}

impl KvStore for FaultyCertKv {
    fn kv_get(&self, cf_name: &str, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        self.inner.kv_get(cf_name, key)
    }
    fn kv_put(&self, cf_name: &str, key: &[u8], value: &[u8]) -> Result<(), String> {
        self.check(cf_name, key)?;
        self.inner.kv_put(cf_name, key, value)
    }
    fn kv_put_durable(&self, cf_name: &str, key: &[u8], value: &[u8]) -> Result<(), String> {
        self.check(cf_name, key)?;
        self.inner.kv_put_durable(cf_name, key, value)
    }
    fn kv_delete(&self, cf_name: &str, key: &[u8]) -> Result<(), String> {
        self.inner.kv_delete(cf_name, key)
    }
    fn kv_exists(&self, cf_name: &str, key: &[u8]) -> Result<bool, String> {
        self.inner.kv_exists(cf_name, key)
    }
    fn kv_iter_cf(&self, cf_name: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
        self.inner.kv_iter_cf(cf_name)
    }
    fn kv_write_batch(&self, ops: &[citrate_consensus::dag_store::KvOp]) -> Result<(), String> {
        for op in ops {
            if let citrate_consensus::dag_store::KvOp::Put { cf, key, .. } = op {
                self.check(cf, key)?;
            }
        }
        self.inner.kv_write_batch(ops)
    }
}

/// S2 durability, fault injection (TLA+ Finalize does not fire when its
/// certificate cannot be persisted). Real wiring: the Enforced verifier is the
/// manager's guard, over the node's RocksDB with the certificate writes failing.
/// The quorum vote arrives through the gadget's inbound path; the failed write
/// surfaces there as `FinalizeFailed`, and NOTHING advances: no floor, no
/// finalized/safe RPC pair, no latest finalized height, no certificate on disk,
/// no safety stop, and the poll finds nothing either. A restart in that state
/// boots with nothing finalized. Once the store recovers, the retry finalizes
/// the same certificate and the floor, the RPC pair and a restart all agree.
#[tokio::test]
async fn s2_certificate_write_failure_raises_no_floor_and_publishes_nothing() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let vals = Validators::equal_stake(&keys);
    let committee: Vec<PublicKey> = keys.iter().map(pk).collect();
    let cfg = config(100);
    let (exec, storage, dir) = fresh();
    let fault = FaultyCertKv::new(&storage, true);
    let (mut node, boot) = assemble_with(
        exec,
        storage,
        dir,
        key(0),
        &vals,
        cfg.clone(),
        Vec::new(),
        fault.clone(),
    )
    .await;
    assert_eq!(boot, FloorTick::NoCertificate);
    let a = chains.main(8);
    node.follow(&a).await;
    let h4 = hash_at(&a, 4);
    let mgr = node.mgr().clone();
    mgr.ensure_proposed(4, h4, committee.clone())
        .await
        .expect("propose");
    for k in keys.iter().take(2) {
        mgr.submit_vote(sign_checkpoint_vote(CHAIN, 4, h4, k))
            .await
            .expect("vote");
    }
    let third = keys.get(2).expect("key 2");
    let out = node
        .gadget
        .on_inbound_vote(sign_checkpoint_vote(CHAIN, 4, h4, third))
        .await;
    assert!(
        matches!(
            &out,
            InboundOutcome::FinalizeFailed {
                height: 4,
                error: CheckpointError::StorageError(_),
                ..
            }
        ),
        "the failed certificate write must surface (fail-closed), got {out:?}"
    );
    assert!(fault.failed.load(Ordering::SeqCst) >= 1);
    assert_eq!(
        node.floor(),
        0,
        "the floor must not move without a durable certificate"
    );
    assert_eq!(node.rpc_finalized(), FinalizedAnchor::GENESIS);
    assert_eq!(node.finalized().await, 0);
    assert!(!mgr.is_certificate_persisted(4, &h4));
    assert!(
        !node.gadget.halted(),
        "a storage fault is not a safety stop"
    );
    assert_eq!(node.tick().await, FloorTick::NoCertificate);
    assert_eq!(node.floor(), 0);
    assert_eq!(node.rpc_finalized(), FinalizedAnchor::GENESIS);
    assert_eq!(mgr.pending_vote_count(4).await, Some(3), "votes kept");

    // The store recovers; the retry finalizes the same certificate.
    fault.heal();
    let cp = mgr.finalize_checkpoint(4).await.expect("retry finalizes");
    assert_eq!((cp.height, cp.block_hash, cp.votes.len()), (4, h4, 3));
    assert!(mgr.is_certificate_persisted(4, &h4));
    assert_eq!(node.floor(), 4);
    assert_eq!(
        node.rpc_finalized(),
        FinalizedAnchor {
            height: 4,
            hash: Some(h4)
        }
    );
    let (node, boot) = node.restart(&vals, cfg).await;
    assert_eq!(boot, verified(4));
    assert_eq!(node.floor(), 4);
}

/// S2 durability, ordering: when the guard raises the floor, the certificate is
/// ALREADY on disk through a synced write. The guard is parked inside its floor
/// check (the test holds the applicator's advance lock); at that instant the
/// floor has not moved, nothing is published, the certificate record is in
/// RocksDB and the store's synced-write counter has advanced.
#[tokio::test]
async fn s2_certificate_is_synced_to_disk_before_the_guard_raises_the_floor() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let vals = Validators::equal_stake(&keys);
    let committee: Vec<PublicKey> = keys.iter().map(pk).collect();
    let mut node = TestNode::boot(key(0), &vals, config(100)).await;
    let a = chains.main(8);
    node.follow(&a).await;
    let h4 = hash_at(&a, 4);
    let mgr = node.mgr().clone();
    mgr.ensure_proposed(4, h4, committee)
        .await
        .expect("propose");
    for k in keys.iter().take(3) {
        mgr.submit_vote(sign_checkpoint_vote(CHAIN, 4, h4, k))
            .await
            .expect("vote");
    }
    let synced_before = node.storage.db.write_batch_sync_count();

    let advance = node.app.advance_lock();
    let held = advance.lock().await;
    let task = tokio::spawn({
        let mgr = mgr.clone();
        async move { mgr.finalize_checkpoint(4).await }
    });
    let mut spins = 0u32;
    while !node.app.certified_pending().contains(&(4, h4)) {
        spins += 1;
        assert!(spins < 100_000, "guard never reached its floor check");
        tokio::task::yield_now().await;
    }
    // Inside the guard, before the floor is raised.
    assert_eq!(node.floor(), 0);
    assert_eq!(node.rpc_finalized(), FinalizedAnchor::GENESIS);
    assert!(
        mgr.is_certificate_persisted(4, &h4),
        "the certificate must be on disk before the floor is raised"
    );
    assert!(
        node.storage.db.write_batch_sync_count() > synced_before,
        "the certificate write must be synced (fsync), not a plain buffered put"
    );
    drop(held);
    let cp = task.await.expect("task").expect("finalize");
    assert_eq!((cp.height, cp.block_hash), (4, h4));
    assert_eq!(node.floor(), 4);
    assert_eq!(
        node.rpc_finalized(),
        FinalizedAnchor {
            height: 4,
            hash: Some(h4)
        }
    );
}

// ---------------------------------------------------------------------------
// S2 durability across a process kill (TLA+ Restart after Finalize). A CHILD
// process (this test binary re-invoked) finalizes A4 over a RocksDB directory
// through the real wiring, waits until the finalized/safe pair names A4, prints
// a marker and blocks; the parent SIGKILLs it (no destructors, no flush, no
// RocksDB close) and reopens the directory: the certificate is on disk, the
// boot check restores the floor from it, the RPC pair names A4, and a rebuild
// abandoning A4 is refused. Run process-kill tests under
// `unshare --user --map-root-user --pid --fork --mount-proc`.
// ---------------------------------------------------------------------------

const C362_PARENT: &str = "C362_CHILD_PARENT";
const C362_MARK: &str = "C362_PUBLISHED dir=";

/// Child entry point (a no-op unless `C362_CHILD_PARENT` is set).
#[tokio::test]
async fn s2_cert_kill_child() {
    let Ok(parent) = std::env::var(C362_PARENT) else {
        return;
    };
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let vals = Validators::equal_stake(&keys);
    let committee: Vec<PublicKey> = keys.iter().map(pk).collect();
    // The data directory lives under the parent's temp dir; the parent removes
    // it (this process is killed, so its own TempDir is never dropped).
    let dir = tempfile::Builder::new()
        .prefix("node-")
        .tempdir_in(&parent)
        .expect("child data dir");
    let storage = Arc::new(
        StorageManager::new(
            dir.path(),
            citrate_storage::pruning::PruningConfig::default(),
        )
        .expect("storage"),
    );
    let exec = Arc::new(Executor::new(Arc::new(citrate_execution::StateDB::new())));
    let path = dir.path().to_path_buf();
    let (mut node, boot) =
        assemble(exec, storage, dir, key(0), &vals, config(100), Vec::new()).await;
    assert_eq!(boot, FloorTick::NoCertificate);
    let a = chains.main(8);
    node.follow(&a).await;
    for blk in &chains.branch(&a, 3, 10, VRF_B) {
        node.import(blk).await;
    }
    let h4 = hash_at(&a, 4);
    let mgr = node.mgr().clone();
    mgr.ensure_proposed(4, h4, committee)
        .await
        .expect("propose");
    for k in keys.iter().take(3) {
        mgr.submit_vote(sign_checkpoint_vote(CHAIN, 4, h4, k))
            .await
            .expect("vote");
    }
    mgr.finalize_checkpoint(4).await.expect("finalize");
    assert_eq!(
        node.rpc_finalized(),
        FinalizedAnchor {
            height: 4,
            hash: Some(h4)
        },
        "published"
    );
    {
        use std::io::Write as _;
        let mut out = std::io::stdout().lock();
        writeln!(out, "{C362_MARK}{}", path.display()).expect("marker");
        out.flush().expect("flush");
    }
    // Wait to be killed; never return (a return would drop the store cleanly).
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

#[tokio::test]
async fn s2_certificate_survives_a_kill_after_publication() {
    if std::env::var(C362_PARENT).is_ok() {
        return;
    }
    use std::io::BufRead as _;
    let parent = tempfile::tempdir().expect("parent dir");
    let exe = std::env::current_exe().expect("exe");
    let mut child = std::process::Command::new(exe)
        .args([
            "finality_adversarial_tests::s2_cert_kill_child",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(C362_PARENT, parent.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn child");
    let stdout = child.stdout.take().expect("child stdout");
    let mut data_dir = None;
    for line in std::io::BufReader::new(stdout).lines() {
        let line = line.expect("child stdout line");
        if let Some(p) = line.split(C362_MARK).nth(1) {
            data_dir = Some(std::path::PathBuf::from(p.trim()));
            break;
        }
    }
    let Some(data_dir) = data_dir else {
        let out = child.wait_with_output().expect("child output");
        panic!(
            "child never published: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    child.kill().expect("SIGKILL the child");
    let status = child.wait().expect("reap child");
    assert!(
        !status.success(),
        "the child was killed, not exited: {status}"
    );

    // Reopen the killed node's directory as a restart does.
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let vals = Validators::equal_stake(&keys);
    let a = chains.main(8);
    let b = chains.branch(&a, 3, 10, VRF_B);
    let h4 = hash_at(&a, 4);
    let storage = Arc::new(
        StorageManager::new(
            &data_dir,
            citrate_storage::pruning::PruningConfig::default(),
        )
        .expect("reopen storage"),
    );
    let exec = Arc::new(Executor::new(Arc::new(citrate_execution::StateDB::new())));
    let genesis_state = exec.state_snapshot();
    let placeholder = tempfile::tempdir().expect("placeholder dir");
    let (node, boot) = assemble(
        exec,
        storage,
        placeholder,
        key(0),
        &vals,
        config(100),
        Vec::new(),
    )
    .await;
    assert!(
        node.mgr().is_certificate_persisted(4, &h4),
        "the certificate published before the kill must be on disk"
    );
    let stored = node.mgr().get_checkpoint(4).await.expect("reloaded");
    assert!(stored.verify_certificate(CHAIN).is_ok());
    assert_eq!(boot, verified(4), "boot restores the floor from it");
    assert_eq!(node.floor(), 4);
    assert_eq!(
        node.rpc_finalized(),
        FinalizedAnchor {
            height: 4,
            hash: Some(h4)
        }
    );
    *node.head.lock() = Some(hash_at(&b, 10));
    assert!(
        !node
            .app
            .recover_to_head(genesis_state, Hash::default())
            .await
            .expect("recovery call returns"),
        "S2: a block published as finalized before the kill must not be abandoned"
    );
    assert_eq!(node.app.applied_tip().await.hash, hash_at(&a, 8));
}

// ---------------------------------------------------------------------------
// S2 certificate write retry (follow-up to #368): a checkpoint that reached
// quorum but whose certificate could not be written is retried on the driver
// tick (`finality_driver::retry_finalizations`), with capped backoff, so it
// finalizes once the store recovers even if no further vote ever arrives. A
// store that never recovers never raises the floor.
// ---------------------------------------------------------------------------

/// Quorum (3 of 4) for A4 reaches the node through the gadget's inbound path
/// while every certificate write fails: the finalization failed, nothing moved.
async fn quorum_with_failing_certificate_store(
    node: &TestNode,
    fault: &FaultyCertKv,
    keys: &[Ed25519SigningKey],
    h4: Hash,
) {
    let committee: Vec<PublicKey> = keys.iter().map(pk).collect();
    let mgr = node.mgr().clone();
    mgr.ensure_proposed(4, h4, committee)
        .await
        .expect("propose");
    for k in keys.iter().take(2) {
        mgr.submit_vote(sign_checkpoint_vote(CHAIN, 4, h4, k))
            .await
            .expect("vote");
    }
    let third = keys.get(2).expect("key 2");
    let out = node
        .gadget
        .on_inbound_vote(sign_checkpoint_vote(CHAIN, 4, h4, third))
        .await;
    assert!(
        matches!(
            &out,
            InboundOutcome::FinalizeFailed {
                height: 4,
                error: CheckpointError::StorageError(_),
                ..
            }
        ),
        "the failed certificate write must surface, got {out:?}"
    );
    assert!(fault.failed.load(Ordering::SeqCst) >= 1);
    assert_eq!(node.floor(), 0);
    assert_eq!(node.rpc_finalized(), FinalizedAnchor::GENESIS);
    assert!(!mgr.is_certificate_persisted(4, &h4));
}

/// The store recovers and NO further vote arrives: the driver's retry step
/// finalizes A4 within one backoff window — certificate on disk, floor raised,
/// finalized/safe pair published — and a restart restores the same floor. A
/// tick before the window does nothing; ticks after it never publish again.
#[tokio::test]
async fn s2_certificate_write_failure_is_retried_on_the_tick_without_further_votes() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let vals = Validators::equal_stake(&keys);
    let cfg = config(100);
    let (exec, storage, dir) = fresh();
    let fault = FaultyCertKv::new(&storage, true);
    let (mut node, boot) = assemble_with(
        exec,
        storage,
        dir,
        key(0),
        &vals,
        cfg.clone(),
        Vec::new(),
        fault.clone(),
    )
    .await;
    assert_eq!(boot, FloorTick::NoCertificate);
    let a = chains.main(8);
    node.follow(&a).await;
    let h4 = hash_at(&a, 4);
    quorum_with_failing_certificate_store(&node, &fault, &keys, h4).await;

    fault.heal();
    let start = std::time::Instant::now();
    let early = retry_finalizations(&node.gadget, start).await;
    assert!(early.finalized.is_empty(), "{early:?}");
    assert_eq!(node.floor(), 0, "not due before the backoff window");

    let out = retry_finalizations(&node.gadget, start + FINALIZE_RETRY_BASE).await;
    assert_eq!(out.finalized, vec![4], "{out:?}");
    assert!(node.mgr().is_certificate_persisted(4, &h4));
    assert_eq!(node.finalized().await, 4);
    assert_eq!(node.floor(), 4, "the floor follows the durable certificate");
    let anchor4 = FinalizedAnchor {
        height: 4,
        hash: Some(h4),
    };
    assert_eq!(node.rpc_finalized(), anchor4);
    assert_eq!(node.tick().await, verified(4));

    // Idempotent: no second finalization, the published pair is unchanged.
    let again = retry_finalizations(&node.gadget, start + FINALIZE_RETRY_CAP * 4).await;
    assert!(again.finalized.is_empty() && again.failed.is_empty() && again.pending == 0);
    assert_eq!(node.gadget.finalize_retry_stats().recovered, 1);
    assert_eq!(node.rpc_finalized(), anchor4);

    let (node, boot) = node.restart(&vals, cfg).await;
    assert_eq!(boot, verified(4));
    assert_eq!(node.floor(), 4);
}

/// The store never recovers: every retry fails, the floor never moves, nothing
/// is published, no safety stop engages, and the retries respect the capped
/// backoff (one certificate write per due tick, none in between).
#[tokio::test]
async fn s2_permanent_certificate_write_failure_never_raises_the_floor() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let vals = Validators::equal_stake(&keys);
    let cfg = config(100);
    let (exec, storage, dir) = fresh();
    let fault = FaultyCertKv::new(&storage, true);
    let (mut node, _boot) = assemble_with(
        exec,
        storage,
        dir,
        key(0),
        &vals,
        cfg.clone(),
        Vec::new(),
        fault.clone(),
    )
    .await;
    let a = chains.main(8);
    node.follow(&a).await;
    let h4 = hash_at(&a, 4);
    quorum_with_failing_certificate_store(&node, &fault, &keys, h4).await;

    let mut now = std::time::Instant::now() + FINALIZE_RETRY_BASE;
    let mut failures: u32 = 1;
    for round in 0..10 {
        let before = fault.failed.load(Ordering::SeqCst);
        if round > 0 {
            let idle =
                retry_finalizations(&node.gadget, now - std::time::Duration::from_millis(1)).await;
            assert!(idle.failed.is_empty() && idle.finalized.is_empty());
            assert_eq!(
                fault.failed.load(Ordering::SeqCst),
                before,
                "backoff respected"
            );
        }
        let out = retry_finalizations(&node.gadget, now).await;
        assert_eq!(out.failed, vec![4], "{out:?}");
        assert_eq!(fault.failed.load(Ordering::SeqCst), before + 1);
        assert_eq!(node.floor(), 0, "no durable certificate, no floor");
        assert_eq!(node.rpc_finalized(), FinalizedAnchor::GENESIS);
        assert_eq!(node.finalized().await, 0);
        assert!(
            !node.gadget.halted(),
            "a storage fault is not a safety stop"
        );
        assert_eq!(node.tick().await, FloorTick::NoCertificate);
        failures += 1;
        now += finalize_retry_delay(failures);
    }
    assert_eq!(finalize_retry_delay(failures), FINALIZE_RETRY_CAP);
    assert!(!node.mgr().is_certificate_persisted(4, &h4));
    let (node, boot) = node.restart(&vals, cfg).await;
    assert_eq!(boot, FloorTick::NoCertificate, "nothing finalized survives");
    assert_eq!(node.floor(), 0);
    assert_eq!(node.rpc_finalized(), FinalizedAnchor::GENESIS);
}

// Crash/restart variants (TLA+ Restart around a retried Finalize): a CHILD
// process reaches quorum with the certificate writes failing, then either
// heals the store and lets the retry tick finalize ("heal") or keeps failing
// through several retries ("permanent"); it prints a marker and blocks; the
// parent SIGKILLs it and reopens the directory. "heal": the certificate the
// retry wrote is on disk and the boot check restores the floor. "permanent":
// nothing is on disk, the boot check finds no certificate and the floor and
// the RPC pair stay at genesis. Run under
// `unshare --user --map-root-user --pid --fork --mount-proc`.

const RETRY_PARENT: &str = "C368R_CHILD_PARENT";
const RETRY_MODE: &str = "C368R_CHILD_MODE";
const RETRY_MARK: &str = "C368R_READY dir=";

/// Child entry point (a no-op unless `C368R_CHILD_PARENT` is set).
#[tokio::test]
async fn s2_cert_retry_kill_child() {
    let Ok(parent) = std::env::var(RETRY_PARENT) else {
        return;
    };
    let heal = std::env::var(RETRY_MODE).as_deref() == Ok("heal");
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let vals = Validators::equal_stake(&keys);
    let dir = tempfile::Builder::new()
        .prefix("node-")
        .tempdir_in(&parent)
        .expect("child data dir");
    let storage = Arc::new(
        StorageManager::new(
            dir.path(),
            citrate_storage::pruning::PruningConfig::default(),
        )
        .expect("storage"),
    );
    let exec = Arc::new(Executor::new(Arc::new(citrate_execution::StateDB::new())));
    let path = dir.path().to_path_buf();
    let fault = FaultyCertKv::new(&storage, true);
    let (mut node, boot) = assemble_with(
        exec,
        storage,
        dir,
        key(0),
        &vals,
        config(100),
        Vec::new(),
        fault.clone(),
    )
    .await;
    assert_eq!(boot, FloorTick::NoCertificate);
    let a = chains.main(8);
    node.follow(&a).await;
    let h4 = hash_at(&a, 4);
    quorum_with_failing_certificate_store(&node, &fault, &keys, h4).await;
    let mut now = std::time::Instant::now() + FINALIZE_RETRY_BASE;
    if heal {
        fault.heal();
        let out = retry_finalizations(&node.gadget, now).await;
        assert_eq!(out.finalized, vec![4], "{out:?}");
        assert_eq!(
            node.rpc_finalized(),
            FinalizedAnchor {
                height: 4,
                hash: Some(h4)
            },
            "published"
        );
    } else {
        for failures in 2..6u32 {
            let out = retry_finalizations(&node.gadget, now).await;
            assert_eq!(out.failed, vec![4], "{out:?}");
            now += finalize_retry_delay(failures);
        }
        assert_eq!(node.floor(), 0);
        assert_eq!(node.rpc_finalized(), FinalizedAnchor::GENESIS);
    }
    {
        use std::io::Write as _;
        let mut out = std::io::stdout().lock();
        writeln!(out, "{RETRY_MARK}{}", path.display()).expect("marker");
        out.flush().expect("flush");
    }
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

/// Run the retry child in `mode`, SIGKILL it at its marker, and return the
/// parent temp dir (keeps the data alive) and the killed node's data dir.
fn kill_retry_child(mode: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    use std::io::BufRead as _;
    let parent = tempfile::tempdir().expect("parent dir");
    let exe = std::env::current_exe().expect("exe");
    let mut child = std::process::Command::new(exe)
        .args([
            "finality_adversarial_tests::s2_cert_retry_kill_child",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(RETRY_PARENT, parent.path())
        .env(RETRY_MODE, mode)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn child");
    let stdout = child.stdout.take().expect("child stdout");
    let mut data_dir = None;
    for line in std::io::BufReader::new(stdout).lines() {
        let line = line.expect("child stdout line");
        if let Some(p) = line.split(RETRY_MARK).nth(1) {
            data_dir = Some(std::path::PathBuf::from(p.trim()));
            break;
        }
    }
    let Some(data_dir) = data_dir else {
        let out = child.wait_with_output().expect("child output");
        panic!(
            "child ({mode}) never reached its marker: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    child.kill().expect("SIGKILL the child");
    let status = child.wait().expect("reap child");
    assert!(!status.success(), "the child was killed: {status}");
    (parent, data_dir)
}

async fn reopen_killed(data_dir: &std::path::Path) -> (TestNode, FloorTick) {
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let vals = Validators::equal_stake(&keys);
    let storage = Arc::new(
        StorageManager::new(data_dir, citrate_storage::pruning::PruningConfig::default())
            .expect("reopen storage"),
    );
    let exec = Arc::new(Executor::new(Arc::new(citrate_execution::StateDB::new())));
    let placeholder = tempfile::tempdir().expect("placeholder dir");
    assemble(
        exec,
        storage,
        placeholder,
        key(0),
        &vals,
        config(100),
        Vec::new(),
    )
    .await
}

#[tokio::test]
async fn s2_retried_certificate_survives_a_kill_after_publication() {
    if std::env::var(RETRY_PARENT).is_ok() {
        return;
    }
    let (_parent, data_dir) = kill_retry_child("heal");
    let chains = Chains::new();
    let h4 = hash_at(&chains.main(8), 4);
    let (node, boot) = reopen_killed(&data_dir).await;
    assert!(
        node.mgr().is_certificate_persisted(4, &h4),
        "the certificate the retry wrote must be on disk after the kill"
    );
    let stored = node.mgr().get_checkpoint(4).await.expect("reloaded");
    assert!(stored.verify_certificate(CHAIN).is_ok());
    assert_eq!(boot, verified(4), "boot restores the floor from it");
    assert_eq!(node.floor(), 4);
    assert_eq!(
        node.rpc_finalized(),
        FinalizedAnchor {
            height: 4,
            hash: Some(h4)
        }
    );
}

#[tokio::test]
async fn s2_kill_during_permanent_certificate_failure_finalizes_nothing() {
    if std::env::var(RETRY_PARENT).is_ok() {
        return;
    }
    let (_parent, data_dir) = kill_retry_child("permanent");
    let chains = Chains::new();
    let h4 = hash_at(&chains.main(8), 4);
    let (node, boot) = reopen_killed(&data_dir).await;
    assert!(!node.mgr().is_certificate_persisted(4, &h4));
    assert_eq!(boot, FloorTick::NoCertificate);
    assert_eq!(node.floor(), 0);
    assert_eq!(node.finalized().await, 0);
    assert_eq!(node.rpc_finalized(), FinalizedAnchor::GENESIS);
}

/// An `Unconfirmed` stop becomes a mismatch (with the alarm) once the node's
/// chain is found to hold another block at the certified height.
#[tokio::test]
async fn s2_unconfirmed_becomes_mismatch_when_another_block_is_applied() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let vals = Validators::equal_stake(&keys);
    let mut net = network(4, &vals, config(100)).await;
    let a = chains.main(8);
    net.follow_all(&a).await;
    for i in 0..4 {
        net.drive(i).await;
    }
    let short = chains.branch(&a, 3, 3, VRF_B);
    let _ = net.node_mut(3).reorg_onto(&short).await;
    net.gossip().await;
    assert!(net.node(3).gadget.halted());
    // Node 3 extends its own branch past height 4.
    let longer = chains.branch(&a, 3, 6, VRF_B);
    net.node_mut(3).follow(&longer).await;
    assert_eq!(
        net.node(3).tick().await,
        FloorTick::Halted(HaltReason::Mismatch {
            height: 4,
            certified: hash_at(&a, 4),
            canonical: Some(hash_at(&longer, 4)),
        })
    );
    assert!(net.node(3).gadget.halted());
    assert_eq!(net.node(3).floor(), 2);
}

// ---------------------------------------------------------------------------
// A7 — committee grinding
// ---------------------------------------------------------------------------

/// A7 / S4: with 10 validators and committee size 4, every node derives the
/// identical committee from (governing snapshot, H, the checkpoint block's
/// committed VRF output); a validator outside that committee — e.g. one that
/// would be selected under a different (ground) seed — cannot vote; stake
/// registered after the snapshot does not move the committee for heights that
/// snapshot governs.
#[tokio::test]
async fn a7_committee_is_fixed_by_snapshot_height_and_block_seed() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..10).map(key).collect();
    let mut vals = Validators::equal_stake(&keys);
    // Snapshot S(2) = 21 (schedule 20/19): an attacker key with huge stake
    // registers after S(1). It governs heights 22.. only.
    let attacker = key(77);
    let mut grown = vals.set.clone();
    grown.push((pk(&attacker), u128::from(u64::MAX)));
    vals.later.push((21, grown));
    let cfg = config(4);
    let mut net = network(3, &vals, cfg.clone()).await;
    let a = chains.main(8);
    net.follow_all(&a).await;
    for i in 0..3 {
        net.drive(i).await;
    }
    let h = 4u64;
    let seed = at(&a, h).header.vrf_reveal.output;
    let expected = CommitteeSelector::select(&vals.set, h, &seed, 4);
    assert_eq!(expected.len(), 4);
    for (i, n) in net.nodes.iter().enumerate() {
        let c = n.gadget.committee_for(h, &seed).await.expect("committee");
        assert_eq!(c, expected, "node {i} derives the same committee");
        assert!(
            !c.contains(&pk(&attacker)),
            "post-snapshot stake is ignored"
        );
    }
    // A validator in the set but outside this committee, which a ground seed
    // would select: its vote is refused.
    let outsider = keys
        .iter()
        .find(|k| !expected.contains(&pk(k)))
        .expect("an outsider");
    let ground = (0u8..=255)
        .map(|b| Hash::new([b; 32]))
        .find(|s| CommitteeSelector::select(&vals.set, h, s, 4).contains(&pk(outsider)))
        .expect("some seed selects the outsider");
    assert_ne!(ground, seed);
    let out = net
        .send_to(0, sign_checkpoint_vote(CHAIN, h, hash_at(&a, h), outsider))
        .await;
    assert!(
        matches!(
            out,
            InboundOutcome::Rejected(CheckpointError::NotInCommittee(_))
        ),
        "{out:?}"
    );
    let out = net
        .send_to(0, sign_checkpoint_vote(CHAIN, h, hash_at(&a, h), &attacker))
        .await;
    assert!(matches!(out, InboundOutcome::Rejected(_)), "{out:?}");

    // The real committee's votes finalize H on every node (quorum 3 of 4).
    for k in keys.iter().filter(|k| expected.contains(&pk(k))).take(3) {
        net.inject(sign_checkpoint_vote(CHAIN, h, hash_at(&a, h), k));
    }
    net.gossip().await;
    for (i, n) in net.nodes.iter().enumerate() {
        let cp = n.mgr().get_checkpoint(h).await.expect("certificate");
        assert_eq!(cp.status, CheckpointStatus::Finalized, "node {i}");
        assert_eq!(cp.committee, expected, "node {i}");
    }
    // Heights governed by S(2) do see the new set (deterministically).
    let late = net.node(0).gadget.committee_for(22, &seed).await;
    let grown_set = vals.later.first().expect("S(2)").1.clone();
    assert_eq!(
        late,
        Some(CommitteeSelector::select(&grown_set, 22, &seed, 4))
    );
}

/// A7 follow-up, S1 across sibling candidates. The committee for a checkpoint
/// is drawn from the governing snapshot with the CANDIDATE block's own VRF
/// output as seed (`FinalityGadget::committee_for`), so two siblings at the
/// same height get different committees once the validator set is larger than
/// `committee_size`. Eight equal-stake validators, committee size 4 (quorum 3):
/// a sibling B4 whose committee shares at most one member with A4's is found
/// deterministically. The network splits along the fork: A4's committee
/// members follow A, the rest of B4's committee follows B. No key signs two
/// hashes, no one is Byzantine, and each side still collects 3 of its own 4.
/// Returns both sides after one round each.
struct SiblingSplit {
    side_a: Net,
    side_b: Net,
    a: Vec<Block>,
    b: Vec<Block>,
    committee_a: Vec<PublicKey>,
    committee_b: Vec<PublicKey>,
}

const SPLIT_HEIGHT: u64 = 4;

async fn sibling_committee_split() -> SiblingSplit {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..8).map(key).collect();
    let vals = Validators::equal_stake(&keys);
    let cfg = config(4);
    let h = SPLIT_HEIGHT;
    let committee = |branch: &[Block]| {
        CommitteeSelector::select(&vals.set, h, &at(branch, h).header.vrf_reveal.output, 4)
    };
    let a = chains.main(8);
    let committee_a = committee(&a);
    let (b, committee_b) = (0u8..=255)
        .filter(|t| *t != VRF_A[0])
        .find_map(|t| {
            let b = chains.branch(&a, h, 8, [t; 32]);
            let cb = committee(&b);
            let shared = cb.iter().filter(|k| committee_a.contains(k)).count();
            (shared <= 1).then_some((b, cb))
        })
        .expect("a sibling seed whose committee overlaps A4's in at most one member");
    assert_eq!((committee_a.len(), committee_b.len()), (4, 4));
    let mut nodes_a = Vec::new();
    let mut nodes_b = Vec::new();
    for k in &keys {
        let me = pk(k);
        if committee_a.contains(&me) {
            nodes_a.push(TestNode::boot(k.clone(), &vals, cfg.clone()).await);
        } else if committee_b.contains(&me) {
            nodes_b.push(TestNode::boot(k.clone(), &vals, cfg.clone()).await);
        }
    }
    let mut side_a = Net::new(nodes_a);
    let mut side_b = Net::new(nodes_b);
    side_a.follow_all(&a).await;
    side_b.follow_all(&b).await;
    let _ = side_a.round().await;
    let _ = side_b.round().await;
    SiblingSplit {
        side_a,
        side_b,
        a,
        b,
        committee_a,
        committee_b,
    }
}

/// Pins the counterexample (review of #333 @ 0286eff, P2): with per-candidate
/// committees, sibling blocks A4 and B4 BOTH finalize, on disjoint honest
/// signers, with no equivocation and no Byzantine key. Expected to start
/// failing once the protocol fixes the committee independently of the
/// candidate (or otherwise prevents this); then update this test and
/// un-ignore `s1_sibling_committees_never_finalize_conflicting_blocks`.
/// TLA+: CheckpointFinalitySafety_committees.cfg.
#[tokio::test]
async fn open_finding_sibling_committees_finalize_conflicting_blocks() {
    let split = sibling_committee_split().await;
    let h = SPLIT_HEIGHT;
    assert_ne!(
        split.committee_a, split.committee_b,
        "committee follows the candidate"
    );
    for n in &split.side_a.nodes {
        assert_eq!(n.finalized_hash(h).await, Some(hash_at(&split.a, h)));
    }
    for n in &split.side_b.nodes {
        assert_eq!(n.finalized_hash(h).await, Some(hash_at(&split.b, h)));
    }
    split.side_a.assert_honest_no_equivocation();
    split.side_b.assert_honest_no_equivocation();
}

/// S1 as specified (§5): at most one block finalizes per height network-wide,
/// whatever the candidate. Fails today with per-candidate committees (see the
/// test above).
#[tokio::test]
#[ignore = "bug: S1 — sibling candidates draw their committees from their own VRF seeds; disjoint committees can both finalize"]
async fn s1_sibling_committees_never_finalize_conflicting_blocks() {
    let split = sibling_committee_split().await;
    let h = SPLIT_HEIGHT;
    let mut seen: Option<Hash> = None;
    for n in split.side_a.nodes.iter().chain(split.side_b.nodes.iter()) {
        if let Some(x) = n.finalized_hash(h).await {
            match seen {
                None => seen = Some(x),
                Some(y) => assert_eq!(x, y, "S1 violated at height {h}"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// A8 — long-range / posterior corruption
// ---------------------------------------------------------------------------

/// A8: after A@4 is finalized, the ENTIRE old committee (posterior corruption
/// of every key) signs the sibling B@4. Those votes are refused by every node,
/// no node re-opens the height, and a fully-signed B@4 certificate written into
/// a node's store halts that node at boot (mismatch with its canonical A@4)
/// instead of moving its floor or RPC tags onto B. Finality never moves
/// backwards or sideways.
#[tokio::test]
async fn a8_old_committee_cannot_refinalize_a_competing_history() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let committee: Vec<PublicKey> = keys.iter().map(pk).collect();
    let vals = Validators::equal_stake(&keys);
    let cfg = config(100);
    let mut net = network(4, &vals, cfg.clone()).await;
    let a = chains.main(8);
    let b = chains.branch(&a, 4, 12, VRF_B);
    net.follow_all(&a).await;
    let _ = net.round().await;
    for k in &keys {
        net.inject(sign_checkpoint_vote(CHAIN, 4, hash_at(&b, 4), k));
    }
    net.gossip().await;
    assert!(net
        .log
        .iter()
        .filter(|(_, v, _)| v.block_hash == hash_at(&b, 4))
        .all(|(_, _, o)| o.starts_with("Rejected")));
    for n in &mut net.nodes {
        for blk in &b {
            n.import(blk).await;
        }
        let out = n
            .gadget
            .on_buried_checkpoint(4, hash_at(&b, 4), &Hash::new([1; 32]), Some(&n.key))
            .await;
        assert_eq!(out.skipped, Some(SkipReason::AlreadyFinalized));
        assert!(out.outbound.is_empty());
        assert_eq!(n.finalized_hash(4).await, Some(hash_at(&a, 4)));
        assert_eq!(n.floor(), 4);
    }

    // A complete, validly signed B@4 certificate lands in node 0's store.
    let k: Vec<&Ed25519SigningKey> = keys.iter().collect();
    let posterior = certificate(4, hash_at(&b, 4), &committee, &k, CHAIN);
    assert!(posterior.verify_certificate(CHAIN).is_ok());
    let node = net.nodes.remove(0);
    write_certificate(&node.storage, &posterior);
    let (node, boot) = node.restart(&vals, cfg).await;
    assert_eq!(
        boot,
        FloorTick::Halted(HaltReason::Mismatch {
            height: 4,
            certified: hash_at(&b, 4),
            canonical: Some(hash_at(&a, 4)),
        })
    );
    assert!(node.gadget.halted());
    assert_eq!(
        node.floor(),
        2,
        "floor not raised onto B; restored to the stored A2 certificate at boot"
    );
    assert_eq!(node.rpc_finalized(), FinalizedAnchor::GENESIS);
}

// ---------------------------------------------------------------------------
// Restart mid-epoch
// ---------------------------------------------------------------------------

/// Restart mid-epoch: node 3 signs its votes (durable record) and dies before
/// they leave the process; node 2 is down. Nodes 0 and 1 stall at 2 votes. On
/// restart node 3's driver starts from cursor 0, re-signs the SAME votes
/// (identical bytes: deterministic ed25519 over the recorded hash) and
/// broadcasts them: 0 and 1 finalize. Later checkpoints finalize with node 3
/// too, and a further restart re-raises the floor at boot, before any block
/// is admitted.
#[tokio::test]
async fn restart_mid_epoch_resends_recorded_votes_and_restores_floor_at_boot() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let vals = Validators::equal_stake(&keys);
    let cfg = config(100);
    let mut net = network(4, &vals, cfg.clone()).await;
    let a = chains.main(8);
    net.follow_all(&a).await;
    *net.online.get_mut(2).expect("flag") = false; // node 2 is down throughout
    *net.online.get_mut(3).expect("flag") = false;
    let lost = net.node_mut(3).drive().await; // signed, never broadcast (crash)
    assert_eq!(lost.len(), 2);
    assert_eq!(net.node(3).gadget.signed_vote_at(4), Some(hash_at(&a, 4)));
    net.drive(0).await;
    net.drive(1).await;
    net.gossip().await;
    assert_eq!(net.node(0).finalized().await, 0, "2 of 4: stalled");

    // Restart node 3 mid-epoch (schedule 20/19: S(1) governs 2..=21).
    let n3 = net.nodes.pop().expect("node 3");
    let (n3, boot) = n3.restart(&vals, cfg.clone()).await;
    assert_eq!(boot, FloorTick::NoCertificate);
    net.nodes.push(n3);
    *net.online.get_mut(3).expect("flag") = true;
    let resent = net.drive(3).await;
    let bytes = |v: &CheckpointVote| (v.height, v.block_hash, v.signature.as_bytes().to_vec());
    assert_eq!(
        resent.iter().map(bytes).collect::<Vec<_>>(),
        lost.iter().map(bytes).collect::<Vec<_>>(),
        "the recorded votes, re-signed identically"
    );
    net.gossip().await;
    for i in [0usize, 1] {
        assert_eq!(net.node(i).finalized().await, 4, "node {i}");
        assert_eq!(net.node(i).tick().await, verified(4));
    }
    // Node 3 restarted after 0 and 1 gossiped: it holds only its own vote.
    // Catching it up on 2 and 4 is certificate sync (C3-S1b, test below).
    assert_eq!(net.node(3).finalized().await, 0);

    // The chain moves on; 0, 1, 3 finalize 6 and 8 together.
    let a = chains.main(12);
    for i in [0usize, 1, 3] {
        net.node_mut(i).follow(&a).await;
    }
    let _ = net.round().await;
    for i in [0usize, 1, 3] {
        assert_eq!(net.node(i).finalized().await, 8, "node {i}");
        assert_eq!(net.node(i).floor(), 8, "node {i}");
    }
    // A further restart: the floor is back at 8 from the boot check alone.
    let n3 = net.nodes.pop().expect("node 3");
    let (n3, boot) = n3.restart(&vals, cfg).await;
    assert_eq!(boot, verified(8));
    assert_eq!(n3.floor(), 8);
    assert_eq!(
        n3.rpc_finalized(),
        FinalizedAnchor {
            height: 8,
            hash: Some(hash_at(&a, 8))
        }
    );
    net.nodes.push(n3);
    net.assert_no_conflicting_finality(&[2, 4, 6, 8]).await;
}

/// S2 across a restart with many stored certificates the floor does not cover
/// (review of #335 @ 5236d2b). The network finalized A10 and then, on branch
/// B (forking at 11), every height 11..=80 — 70 certificates, more than the
/// 64 the boot check used to register. This node is still on A (A80), so the
/// latest certificate is a mismatch and the gadget halts. On restart the
/// boot check must still find A10 — the highest stored certificate whose
/// block is on this node's applied chain, below all 70 — and raise the floor
/// to it before any reorg is judged. After a restart the snapshot ring holds
/// only the tip, so a reorg below it goes through the from-genesis spine
/// rebuild (`recover_to_head`, the recovery path): fork choice towards a
/// branch C forking below 10 is refused; towards the certified branch B
/// (fork point 10) it proceeds, and the safety stop then clears. None of the
/// 70 uncovered certificates is dropped. TLA+: CheckpointFinalitySafety_
/// restart.cfg (holds) / _bootlimit.cfg (a truncated boot check reverts the
/// older finalized block).
#[tokio::test]
async fn s2_restart_restores_the_floor_below_many_uncovered_certificates() {
    const TIP: u64 = 80;
    const CERTIFIED: u64 = 10;
    let uncovered = TIP - CERTIFIED;
    assert!(uncovered > 64, "more than the former registration bound");
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let mut vals = Validators::equal_stake(&keys);
    // Every epoch up to the tip has its snapshot (S(2..4) = 21, 41, 61 under
    // schedule 20/19), as registry_sync records on a live node: the boot check
    // derives each stored certificate's committee from its governing snapshot.
    for snap in [21u64, 41, 61] {
        vals.later.push((snap, vals.set.clone()));
    }
    let committee: Vec<PublicKey> = keys.iter().map(pk).collect();
    let signers: Vec<&Ed25519SigningKey> = keys.iter().take(3).collect();
    let cfg = config(100);
    let mut node = TestNode::boot(key(0), &vals, cfg.clone()).await;
    let genesis_state = node.exec.state_snapshot();
    let a = chains.main(TIP);
    node.follow(&a).await;
    let b = chains.branch(&a, CERTIFIED + 1, TIP, VRF_B);
    let c = chains.branch(&a, 5, TIP + 2, VRF_C);
    for blk in b.iter().chain(c.iter()) {
        node.import(blk).await;
    }
    write_certificate(
        &node.storage,
        &certificate(
            CERTIFIED,
            hash_at(&a, CERTIFIED),
            &committee,
            &signers,
            CHAIN,
        ),
    );
    for h in (CERTIFIED + 1)..=TIP {
        write_certificate(
            &node.storage,
            &certificate(h, hash_at(&b, h), &committee, &signers, CHAIN),
        );
    }

    // TLA+ Restart, then the boot check (VerifyFloor while booting).
    let (node, boot) = node.restart(&vals, cfg).await;
    assert_eq!(
        boot,
        FloorTick::Halted(HaltReason::Mismatch {
            height: TIP,
            certified: hash_at(&b, TIP),
            canonical: Some(hash_at(&a, TIP)),
        })
    );
    assert!(node.gadget.halted());
    assert_eq!(
        node.floor(),
        CERTIFIED,
        "boot restores the floor to the highest stored certificate on this chain"
    );
    let pending = node.app.certified_pending();
    assert_eq!(
        pending.len(),
        usize::try_from(uncovered).expect("fits"),
        "every certificate above the floor stays registered"
    );
    assert_eq!(
        pending.first(),
        Some(&(CERTIFIED + 1, hash_at(&b, CERTIFIED + 1)))
    );

    // TLA+ Reorg below the certified height, via the recovery path: refused.
    *node.head.lock() = Some(hash_at(&c, TIP + 2));
    let rebuilt = node
        .app
        .recover_to_head(genesis_state.clone(), Hash::default())
        .await
        .expect("recovery call returns");
    assert!(
        !rebuilt,
        "S2: a rebuild abandoning the finalized A10 must be refused after restart"
    );
    assert_eq!(node.app.applied_tip().await.hash, hash_at(&a, TIP));
    assert_eq!(node.floor(), CERTIFIED);

    // Fork choice onto the certified branch (fork point 10): proceeds, and the
    // stop clears on the next pass.
    *node.head.lock() = Some(hash_at(&b, TIP));
    let rebuilt = node
        .app
        .recover_to_head(genesis_state, Hash::default())
        .await
        .expect("recovery call returns");
    assert!(
        rebuilt,
        "the rebuild onto the certified branch must proceed"
    );
    assert_eq!(node.app.applied_tip().await.hash, hash_at(&b, TIP));
    assert_eq!(
        node.tick().await,
        FloorTick::Verified {
            height: TIP,
            floor_raised: true,
            recovered: true,
        }
    );
    assert_eq!(node.floor(), TIP);
    assert!(node.app.certified_pending().is_empty());
    assert!(!node.gadget.halted());
}

/// Restart follow-up: a node that missed the votes for a checkpoint while it
/// was down obtains that checkpoint's certificate from a peer (C3-S1b).
#[tokio::test]
async fn restarted_node_fetches_missed_certificates() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let vals = Validators::equal_stake(&keys);
    let cfg = config(100);
    let mut net = network(4, &vals, cfg.clone()).await;
    let a = chains.main(8);
    net.follow_all(&a).await;
    *net.online.get_mut(3).expect("flag") = false;
    for i in 0..3 {
        net.drive(i).await;
    }
    net.gossip().await;
    let n3 = net.nodes.pop().expect("node 3");
    let (n3, _) = n3.restart(&vals, cfg).await;
    net.nodes.push(n3);
    *net.online.get_mut(3).expect("flag") = true;
    let _ = net.round().await;
    let out = net.sync_cert(3, 0).await;
    assert!(
        matches!(&out, Some(SyncOutcome::Installed { height: 4, .. })),
        "{out:?}"
    );
    assert_eq!(net.node(3).finalized().await, 4);
    assert_eq!(net.node(3).floor(), 4);
    assert_eq!(net.node(3).tick().await, verified(4));
    // Persisted like a local certificate: verified again at the next boot.
    let n3 = net.nodes.pop().expect("node 3");
    let (n3, boot) = n3.restart(&vals, config(100)).await;
    assert_eq!(boot, verified(4));
    assert_eq!(n3.floor(), 4);
}

/// Review of #332 @ 354908b (blocking 1): a synced certificate becomes visible
/// only through the finalization guard. `process()` (sync install) races a
/// reorg below the certified block; whichever wins, the node is never left
/// with the certificate visible and the certified block reverted while
/// finality runs: either the floor covers A4 (the reorg is refused) or the
/// node is in the safety stop (reorg first: the certificate is a verified
/// sibling, or the guard found the mismatch). TLA+ SyncCert.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s2_synced_install_races_a_reorg_below_it() {
    let chains = Chains::new();
    let keys: Vec<Ed25519SigningKey> = (0..4).map(key).collect();
    let vals = Validators::equal_stake(&keys);
    let a = chains.main(8);
    let c = chains.branch(&a, 4, 12, VRF_C);
    let a4 = hash_at(&a, 4);
    let mut seen = std::collections::BTreeSet::new();
    for round in 0..9u32 {
        let mut net = network(4, &vals, config(100)).await;
        net.follow_all(&a).await;
        *net.online.get_mut(3).expect("flag") = false;
        for i in 0..3 {
            net.drive(i).await;
        }
        net.gossip().await;
        assert_eq!(net.node(0).finalized().await, 4);
        assert_eq!(net.node(3).finalized().await, 0);
        for blk in &c {
            net.node_mut(3).import(blk).await;
        }
        // The exchange up to the install, then race install vs reorg.
        net.node(3).sync.reset_rate_limits_for_tests().await;
        net.node(0).sync.reset_rate_limits_for_tests().await;
        let (_, req) = net
            .node(3)
            .sync
            .request(&["node-0".to_string()])
            .await
            .expect("due");
        let NetworkMessage::GetCheckpoint { above, at_or_below } = req else {
            panic!("expected GetCheckpoint");
        };
        let resp = net
            .node(0)
            .sync
            .serve("node-3", above, at_or_below)
            .await
            .expect("served");
        let NetworkMessage::CheckpointCertificate {
            height,
            block_hash,
            signatures,
        } = resp
        else {
            panic!("expected CheckpointCertificate");
        };
        assert!(net.node(3).sync.accept_response("node-0").await);
        let n3 = net.node(3);
        let sync = n3.sync.clone();
        let app = n3.app.clone();
        let c_tip = c.last().expect("tip").header.block_hash;
        let install = async move { sync.process("node-0", height, block_hash, signatures).await };
        let reorg = async move {
            let lock = app.advance_lock();
            let mut st = lock.lock().await;
            app.reorg_to(&mut st, c_tip).await
        };
        // Every third round runs them in order (install, then reorg) so that
        // interleaving is always covered; the others race on worker threads.
        let (out, reorged) = if round % 3 == 0 {
            let out = install.await;
            (out, reorg.await)
        } else {
            let install = tokio::spawn(install);
            let reorg = tokio::spawn(reorg);
            (
                install.await.expect("install task"),
                reorg.await.expect("reorg task"),
            )
        };
        let n3 = net.node(3);
        let tip = n3.app.applied_tip().await;
        let here = n3.app.walk_applied(tip).hash_at(4).expect("walk");
        let visible = n3.finalized_hash(4).await == Some(a4);
        let halted = n3.gadget.halted();
        let label = match (&out, &reorged) {
            (SyncOutcome::Installed { .. }, ReorgOutcome::Rejected(_)) => "install-first",
            (SyncOutcome::ConflictingFinality { .. }, _) => "reorg-first",
            (SyncOutcome::Installed { .. }, _) => "reorg-between",
            _ => "other",
        };
        seen.insert(label);
        if here == Some(a4) {
            assert!(!halted, "{label}: {out:?} / {reorged:?}");
            assert!(visible, "{label}: installed");
            assert_eq!(n3.floor(), 4, "{label}: floor covers the certified block");
        } else {
            assert!(
                halted,
                "{label}: A4 reverted while finality runs: {out:?} / {reorged:?}"
            );
        }
    }
    assert!(!seen.contains("other"), "{seen:?}");
    assert!(seen.contains("install-first"), "{seen:?}");
}
