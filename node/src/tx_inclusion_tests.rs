// citrate/node/src/tx_inclusion_tests.rs
//
// A valid transaction must keep being offered to the producer, and keep being
// included, for as long as it is valid against the state the producer builds
// on (the selected parent's post-state).
//
// THE FAILURE (r1007 devnet on the 56cc2bc8 baseline, 2026-11-04, and live
// r1006, chain#405 "txs take ~1 h to land"): under load each sending account
// got a few transactions in and then stuck at one nonce. The stuck transaction
// sat in every producer's pool, the pool handed the producer a candidate every
// slot, and the producer admitted none of them. Nothing on the selected chain
// carried a transaction after height ~1016.
//
// Two producers, wired as `start_node` wires one (shared DAG, execute-on-receive
// applicator with fork choice, admission, the applied-tip lock, and a mempool
// with the committed nonce and balance readers), exchange blocks in process.
// The sender is funded at genesis. Nothing here is mocked: blocks are produced
// by `BlockProducer::produce_block`, admitted by `BlockAdmission::admit` and
// applied (or reorged to) by the applicator's drain.

use std::sync::Arc;

use citrate_consensus::crypto::Ed25519SigningKey;
use citrate_consensus::dag_store::DagStore;
use citrate_consensus::ghostdag::GhostDag;
use citrate_consensus::types::{
    Block, BlockBuilder, GhostDagParams, Hash, PublicKey, Signature, Transaction, VrfProof,
};
use citrate_execution::types::Address;
use citrate_execution::{Executor, StateDB};
use citrate_sequencer::mempool::{Mempool, MempoolConfig, TxClass};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use primitive_types::U256;
use tempfile::TempDir;

use crate::admission::{AdmitOutcome, BlockAdmission};
use crate::canonical_apply::CanonicalApplicator;
use crate::producer::BlockProducer;

const CHAIN_ID: u64 = 40204;
const SENDER: Address = Address([0x5E; 20]);
const RECIPIENT: Address = Address([0x7A; 20]);
const GAS_PRICE: u64 = 1_000_000_000;

fn embedded(addr: Address) -> PublicKey {
    let mut b = [0u8; 32];
    b[..20].copy_from_slice(&addr.0);
    PublicKey::new(b)
}

/// A decoder-verified EVM-shaped transfer (signature checks are off in these
/// pools; the subject is inclusion, not authentication).
fn transfer(nonce: u64) -> Transaction {
    let mut hash = [0xC0u8; 32];
    hash[..8].copy_from_slice(&nonce.to_be_bytes());
    Transaction {
        hash: Hash::new(hash),
        nonce,
        from: embedded(SENDER),
        to: Some(embedded(RECIPIENT)),
        value: 1,
        gas_limit: 21_000,
        gas_price: GAS_PRICE,
        data: vec![],
        signature: Signature::new([1; 64]),
        tx_type: None,
        chain_id: Some(CHAIN_ID),
        ecdsa_verified: true,
        ..Default::default()
    }
}

/// The funded genesis state every node starts from.
fn genesis_state() -> citrate_execution::state::StateSnapshot {
    let db = Arc::new(StateDB::new());
    db.accounts.create_account_if_not_exists(SENDER);
    db.accounts.set_balance(SENDER, U256::from(10u128.pow(24)));
    Executor::new(db).state_snapshot()
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

pub(crate) struct TxNode {
    pub storage: Arc<StorageManager>,
    pub executor: Arc<Executor>,
    pub app: Arc<CanonicalApplicator>,
    pub adm: Arc<BlockAdmission>,
    pub mempool: Arc<Mempool>,
    pub producer: BlockProducer,
    _dir: TempDir,
}

impl TxNode {
    async fn start(i: u8, genesis: &Block) -> Self {
        let dir = TempDir::new().expect("tempdir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        storage.blocks.put_block(genesis).expect("genesis");
        storage
            .blocks
            .put_applied_tip(&genesis.header.block_hash, 0)
            .expect("genesis tip");
        let executor = Arc::new(Executor::with_storage_and_chain_id(
            Arc::new(StateDB::new()),
            Some(storage.state.clone()),
            CHAIN_ID,
        ));
        executor.state_restore(genesis_state());
        let kv = Arc::new(crate::persistent_dag::RocksDbKvStore::new(
            storage.db.clone(),
        ));
        let dag = Arc::new(DagStore::persistent_with_strict_vrf(kv, true).expect("dag load"));
        dag.set_configured_genesis(genesis.header.block_hash);
        dag.set_slot_origin(&genesis.header)
            .expect("r1007 G9: bind the slot origin from genesis, as start_node does");
        let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag.clone()));
        // The mempool exactly as `start_node` builds it: committed nonce and
        // balance readers over the executor.
        let mempool = Arc::new(
            Mempool::new(MempoolConfig {
                require_valid_signature: false,
                chain_id: CHAIN_ID,
                ..Default::default()
            })
            .with_state_nonce_reader({
                let exec = executor.clone();
                Arc::new(move |pk: &PublicKey| {
                    exec.get_nonce(&citrate_execution::address_utils::normalize_address(pk))
                })
            })
            .with_state_balance_reader({
                let exec = executor.clone();
                Arc::new(move |pk: &PublicKey| {
                    let bal =
                        exec.get_balance(&citrate_execution::address_utils::normalize_address(pk));
                    let cap = U256::from(u128::MAX);
                    (if bal > cap { cap } else { bal }).low_u128()
                })
            }),
        );
        let app = Arc::new(
            CanonicalApplicator::new(executor.clone(), storage.clone())
                .with_fork_choice(ghostdag.clone())
                .with_mempool(mempool.clone()),
        );
        app.set_genesis(genesis_state(), genesis.header.block_hash);
        let adm = Arc::new(BlockAdmission::new(
            storage.clone(),
            dag.clone(),
            ghostdag.clone(),
            Some(app.clone()),
        ));
        adm.seed_genesis().await;
        let _ = adm.reconcile().await;
        ghostdag.reconcile_tips_from_dag_store().await;
        let producer = BlockProducer::with_shared_dag(
            storage.clone(),
            executor.clone(),
            mempool.clone(),
            None,
            embedded(Address([0x10 + i; 20])),
            Ed25519SigningKey::from_bytes(&[0x60 + i; 32]),
            2,
            Arc::new(citrate_economics::UnifiedEconomicsManager::new(
                citrate_economics::UnifiedEconomicsConfig::default(),
            )),
            dag,
            ghostdag,
        )
        .await
        .with_v2_headers(true)
        .with_applied_tip_lock(app.advance_lock());
        Self {
            storage,
            executor,
            app,
            adm,
            mempool,
            producer,
            _dir: dir,
        }
    }

    /// Seal one block; returns it.
    async fn produce(&self) -> Block {
        let h = self.producer.produce_block().await.expect("produce");
        self.storage
            .blocks
            .get_block(&h)
            .expect("read produced")
            .expect("produced stored")
    }

    /// Gossip receive: admit, then the periodic drain.
    async fn receive(&self, block: &Block) {
        match self.adm.admit(block).await {
            AdmitOutcome::Admitted { .. } | AdmitOutcome::AlreadyAdmitted => {}
            other => panic!(
                "block {} @ {} not admitted: {other:?}",
                block.header.block_hash, block.header.height
            ),
        }
        self.app.drive_drain().await;
    }

    /// Gossip/RPC ingress for a transaction.
    async fn submit(&self, tx: &Transaction) {
        self.mempool
            .add_transaction(tx.clone(), TxClass::Standard)
            .await
            .expect("valid tx admitted");
    }

    fn sender_nonce(&self) -> u64 {
        self.executor.get_nonce(&SENDER)
    }

    async fn applied_height(&self) -> u64 {
        self.app.applied_tip().await.height
    }
}

async fn fleet() -> (TxNode, TxNode) {
    let root = Executor::new(Arc::new(StateDB::new()));
    root.state_restore(genesis_state());
    let genesis = genesis_block(root.calculate_state_root());
    (
        TxNode::start(0, &genesis).await,
        TxNode::start(1, &genesis).await,
    )
}

/// The devnet wedge. The pool on producer A holds the sender's nonce-0 tx when
/// B's block executing it arrives, so A's pooled copy is stale; A then includes
/// nonce 1 itself. When nonce 2 arrives, A's pool is {0 (stale), 2}. Selection
/// must start at the sender's nonce in the state A builds on (2), not at the
/// lowest pooled nonce (0), or the producer is offered only the stale tx and
/// skips it every slot: the sender is stuck until the stale copy expires
/// (3,600 s), which is the "~1 h" of chain#405.
#[tokio::test]
async fn sender_is_not_wedged_by_a_stale_pooled_nonce_after_a_peer_block() {
    let (a, b) = fleet().await;
    let t0 = transfer(0);
    let t1 = transfer(1);
    let t2 = transfer(2);

    // Slot 1: both pools receive nonce 0; only B seals, and its block carries it.
    a.submit(&t0).await;
    b.submit(&t0).await;
    let b1 = b.produce().await;
    assert!(b1.transactions.iter().any(|t| t.hash == t0.hash));
    a.receive(&b1).await;
    assert_eq!(a.sender_nonce(), 1, "A applied B's block");

    // Slot 2: nonce 1 reaches A only; A seals it, B receives the block.
    a.submit(&t1).await;
    let a2 = a.produce().await;
    assert!(
        a2.transactions.iter().any(|t| t.hash == t1.hash),
        "A includes nonce 1 on top of B's block"
    );
    b.receive(&a2).await;
    assert_eq!(b.sender_nonce(), 2);

    // Slots 3..: nonce 2 reaches every pool; A seals.
    a.submit(&t2).await;
    b.submit(&t2).await;
    for _ in 0..5 {
        let blk = a.produce().await;
        b.receive(&blk).await;
    }
    assert_eq!(
        a.sender_nonce(),
        3,
        "nonce 2 is valid against A's state and sits in A's pool, so A must include it \
         (A's pool still holds the executed nonce-0 copy: {} pooled)",
        a.mempool.stats().await.total_transactions
    );
    assert_eq!(b.sender_nonce(), 3);
}

/// Register H8 red test. A's block carrying the sender's tx loses the slot: B's
/// branch is heavier, B never held the tx, and merged blocks are not executed.
/// A reorgs onto B's chain. The tx is still valid there, so it must go back into
/// A's pool and be included on the selected chain.
#[tokio::test]
async fn no_valid_tx_lost_when_its_block_loses_the_slot() {
    let (a, b) = fleet().await;
    let t0 = transfer(0);

    // Slot 1: the tx reaches A only. Both seal siblings at height 1; A's carries it.
    a.submit(&t0).await;
    let a1 = a.produce().await;
    assert!(a1.transactions.iter().any(|t| t.hash == t0.hash));
    let b1 = b.produce().await;
    assert!(b1.transactions.is_empty());
    // Slot 2: only B seals, on its own block: B's branch is now heavier.
    let b2 = b.produce().await;
    assert_eq!(b2.header.height, 2);

    // The partition heals: A reorgs onto B's chain, B learns A's sibling.
    a.receive(&b1).await;
    a.receive(&b2).await;
    b.receive(&a1).await;
    assert_eq!(a.applied_height().await, 2);
    assert_eq!(
        a.app.applied_tip().await.hash,
        b2.header.block_hash,
        "A follows the heavier branch"
    );
    assert_eq!(
        a.sender_nonce(),
        0,
        "the tx is not executed on the selected chain"
    );

    // Slots 3..: A and B alternate. The tx must land on the selected chain.
    for slot in 0..6 {
        let (p, q) = if slot % 2 == 0 { (&a, &b) } else { (&b, &a) };
        let blk = p.produce().await;
        q.receive(&blk).await;
    }
    assert_eq!(
        a.sender_nonce(),
        1,
        "the tx from A's losing block was valid on the selected chain and must be included"
    );
    assert_eq!(b.sender_nonce(), 1);
}

/// The devnet sequence on p2 (fed `ops/r1007-devnet` evidence/tx-inclusion,
/// 03:12-03:23Z): (1) the producer executes a tx-carrying candidate; (2) that
/// block loses the slot; (3) every later slot selects 0 txs, although the
/// wallet keeps resending and sends the next nonce; (4) only a restart clears
/// it. The producer's executor is NOT left ahead: after the reorg it holds the
/// selected chain's state, which this test checks. The tx is lost from the
/// pool instead, and the pool refuses the resends.
#[tokio::test]
async fn producer_keeps_including_after_its_tx_block_loses_the_slot() {
    let (a, b) = fleet().await;
    let t0 = transfer(0);
    let t1 = transfer(1);

    // (1) A executes a candidate carrying the sender's nonce 0.
    a.submit(&t0).await;
    let a1 = a.produce().await;
    assert!(a1.transactions.iter().any(|t| t.hash == t0.hash));
    assert_eq!(a.sender_nonce(), 1, "A applied its own block");

    // (2) It loses the slot: B's branch (which never held the tx) is heavier.
    let b1 = b.produce().await;
    let b2 = b.produce().await;
    a.receive(&b1).await;
    a.receive(&b2).await;
    b.receive(&a1).await;
    assert_eq!(a.app.applied_tip().await.hash, b2.header.block_hash);
    assert_eq!(
        a.sender_nonce(),
        0,
        "A's executor holds the selected chain's state after the reorg (not left advanced)"
    );

    // The wallet resends nonce 0 (the load loop resent every 30 s) and sends nonce 1.
    let resend = a
        .mempool
        .add_transaction(t0.clone(), TxClass::Standard)
        .await;
    a.submit(&t1).await;
    assert!(
        a.mempool.contains(&t0.hash).await,
        "the nonce-0 tx is valid on the selected chain and must be in A's pool (resend: {resend:?})"
    );

    // (3) The next slots: A must include nonce 0 and then nonce 1.
    let mut carried = Vec::new();
    for _ in 0..4 {
        let blk = a.produce().await;
        carried.push(blk.transactions.len());
        b.receive(&blk).await;
    }
    assert_eq!(
        a.sender_nonce(),
        2,
        "A must include the sender's txs after its block lost the slot (txs per slot: {carried:?})"
    );
    assert_eq!(b.sender_nonce(), 2);
}

/// The info line for a produced block must report the block's height and its
/// transaction count. It printed a per-process counter and a literal 0, so a
/// 1-tx block at height 2801 logged `Produced block #25 … txs=0`, and the
/// devnet lane read "no block carries a tx".
#[test]
fn produced_block_log_reports_height_and_tx_count() {
    let src = include_str!("producer.rs");
    let start = src
        .find("RoundOutcome::Produced(block_hash) => {")
        .expect("produced arm");
    let arm = &src[start..start + 800];
    assert!(
        !arm.contains("0, // We'll get tx count from block"),
        "the produced-block log must not print a constant tx count"
    );
}

/// `start_node` must wire the mempool into the applicator the way the harness
/// above does, or a reorg never re-injects anything.
#[test]
fn start_node_wires_the_mempool_into_the_applicator() {
    let main = include_str!("main.rs");
    let start = main
        .find("canonical_apply::CanonicalApplicator::new(executor.clone(), storage.clone())")
        .expect("applicator construction in start_node");
    let builder = &main[start..start + 900];
    assert!(
        builder.contains(".with_mempool(mempool.clone())"),
        "start_node must attach the mempool to the applicator"
    );
}

#[test]
fn produced_block_line_reports_the_stored_blocks_height_and_tx_count() {
    let mut blk = genesis_block(Hash::default());
    blk.header.height = 2801;
    blk.transactions = vec![transfer(7)];
    let line = crate::producer::produced_block_line(&blk.header.block_hash, Some(&blk), 25);
    assert!(line.contains("height=2801"), "{line}");
    assert!(line.contains("txs=1"), "{line}");
    let missing = crate::producer::produced_block_line(&blk.header.block_hash, None, 25);
    assert!(!missing.contains("txs="), "no guessed count: {missing}");
}

/// A partition long enough that the losing side's abandoned run is deeper than
/// the in-memory snapshot ring (`SNAPSHOT_RING_DEPTH`, 100). `shared` blocks are
/// sealed by A and received by B first (the fork point is at that height); then
/// A seals `a_run` blocks alone, the first one carrying the sender's nonce-0 tx,
/// and B seals `b_run` blocks alone (B's branch is the heavier one). A then
/// receives B's branch. Returns the tx and B's tip.
async fn deep_partition(
    a: &TxNode,
    b: &TxNode,
    shared: usize,
    a_run: usize,
    b_run: usize,
) -> (Transaction, Block) {
    for _ in 0..shared {
        let blk = a.produce().await;
        b.receive(&blk).await;
    }
    let t0 = transfer(0);
    a.submit(&t0).await;
    let a1 = a.produce().await;
    assert!(a1.transactions.iter().any(|t| t.hash == t0.hash));
    for _ in 1..a_run {
        a.produce().await;
    }
    assert_eq!(a.sender_nonce(), 1, "A executed its own block");
    let mut b_branch = Vec::new();
    for _ in 0..b_run {
        b_branch.push(b.produce().await);
    }
    for blk in &b_branch {
        a.receive(blk).await;
    }
    let tip = b_branch.last().expect("B's branch").clone();
    assert_eq!(
        a.app.applied_tip().await.hash,
        tip.header.block_hash,
        "A follows B's heavier branch"
    );
    assert_eq!(a.sender_nonce(), 0, "the tx is not executed on B's branch");
    (t0, tip)
}

/// S3-4 x tx-inclusion: a fork point below the snapshot ring is switched in
/// place from the undo records on disk (`revert_from_undo`), and the abandoned
/// blocks' still-valid txs return to the pool exactly as on a shallow reorg.
#[tokio::test]
async fn deep_reorg_below_the_ring_reinjects_the_abandoned_txs() {
    let (a, b) = fleet().await;
    let depth = crate::canonical_apply::SNAPSHOT_RING_DEPTH as usize + 10;
    let (t0, _) = deep_partition(&a, &b, 2, depth, depth + 2).await;
    assert!(
        a.mempool.contains(&t0.hash).await,
        "the deep reorg ({depth} blocks abandoned) did not return the tx to A's pool"
    );
    let blk = a.produce().await;
    assert!(
        blk.transactions.iter().any(|t| t.hash == t0.hash),
        "A includes the re-injected tx in its next block"
    );
    b.receive(&blk).await;
    assert_eq!(a.sender_nonce(), 1);
    assert_eq!(b.sender_nonce(), 1);
}

/// The from-genesis rebuild (`recover_automatic`, the drain's fallback when the
/// fork point has no ring snapshot and no undo walk applies: here the fork point
/// is genesis itself, below the ring) switches branches too, so it must return
/// the abandoned blocks' still-valid txs to the pool like `reorg_to` does. The
/// tx-inclusion lane recorded that it did not (07: "the deep-reorg path does
/// not re-inject").
#[tokio::test]
async fn from_genesis_rebuild_reinjects_the_abandoned_txs() {
    let (a, b) = fleet().await;
    let depth = crate::canonical_apply::SNAPSHOT_RING_DEPTH as usize + 10;
    let (t0, _) = deep_partition(&a, &b, 0, depth, depth + 2).await;
    assert!(
        a.mempool.contains(&t0.hash).await,
        "the rebuild ({depth} blocks abandoned) did not return the tx to A's pool"
    );
    let blk = a.produce().await;
    assert!(
        blk.transactions.iter().any(|t| t.hash == t0.hash),
        "A includes the re-injected tx in its next block"
    );
    b.receive(&blk).await;
    assert_eq!(a.sender_nonce(), 1);
    assert_eq!(b.sender_nonce(), 1);
}
