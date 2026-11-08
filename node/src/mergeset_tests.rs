// citrate/node/src/mergeset_tests.rs
//
// r1007 S3-3b (ADR CV-4a, planset 05 WP S3-3b / S3-3c, spec 06 §3 and §8):
// mergeset execution, end to end through the production paths.
//
// Producers are `BlockProducer::produce_block`, blocks reach peers through
// `BlockAdmission::admit` and the applicator's drain (execute-on-receive, with
// fork choice and reorgs), exactly as `start_node` wires a node (the harness is
// the one `tx_inclusion_tests` uses, with several senders, a configurable
// GHOSTDAG K, and an optional §R' policy whose registry records each vest).
// Nothing is mocked. Receipts are read from the node's receipt store and its
// JSON-RPC (`eth_getTransactionReceipt`).
//
// The rule under test (spec 06 §3.1): a chain block C executes the
// transactions of Mergeset(C) = {SP(C)} ∪ Mergeset*(C), SP first, then the
// rest ascending by key, on post(SP(C)); a duplicate or a nonce/balance
// conflict is skipped with no fee, no nonce bump and no receipt; red blocks'
// transactions run too; receipts name the accepting block and carry the
// including block.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicU64;
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
const GAS_PRICE: u64 = 1_000_000_000;
const FUND: u128 = 1_000_000_000_000_000_000_000_000; // 1e24 wei
const VALUE: u128 = 1_000;
/// The §R' registry the policy fleets vest into. Its code records every
/// vest: `sstore(pubkey, sload(pubkey) + callvalue)` with the pubkey the
/// first calldata word after the selector (`creditReward(bytes32,uint256)`).
const REG: [u8; 20] = [0x99; 20];
const REG_CODE: [u8; 11] = [
    0x34, 0x60, 0x04, 0x35, 0x54, 0x01, 0x60, 0x04, 0x35, 0x55, 0x00,
];
/// A contract whose every call reverts (`revert(0, 0)`): a call to it is
/// executed and fails, and is charged its whole gas limit.
const REVERTER: [u8; 20] = [0xEF; 20];
const REVERTER_CODE: [u8; 5] = [0x60, 0x00, 0x60, 0x00, 0xfd];
/// A contract that stores BLOCKHASH(NUMBER - 1) at slot 0 and
/// BLOCKHASH(NUMBER - 2) at slot 1 on every call.
const PROBE: [u8; 20] = [0xBB; 20];
const PROBE_CODE: [u8; 19] = [
    0x43, 0x60, 0x01, 0x90, 0x03, 0x40, 0x60, 0x00, 0x55, // sstore(0, blockhash(number - 1))
    0x43, 0x60, 0x02, 0x90, 0x03, 0x40, 0x60, 0x01, 0x55, // sstore(1, blockhash(number - 2))
    0x00,
];

fn sender(i: u8) -> Address {
    Address([0x50 + i; 20])
}

fn recipient(i: u8) -> Address {
    Address([0x70 + i; 20])
}

fn embedded(addr: Address) -> PublicKey {
    let mut b = [0u8; 32];
    b[..20].copy_from_slice(&addr.0);
    PublicKey::new(b)
}

fn signing_key(i: u8) -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[0x60 + i; 32])
}

fn proposer_of(i: u8) -> [u8; 32] {
    signing_key(i).verifying_key().to_bytes()
}

fn coinbase_of(i: u8) -> Address {
    Address([0x20 + i; 20])
}

/// A decoder-verified EVM-shaped transfer (pool signature checks are off; the
/// subject is execution, not authentication). The hash binds every field
/// that differs between the transfers a test builds.
fn transfer(from: u8, nonce: u64, to: Address, value: u128, gas_price: u64) -> Transaction {
    let mut hash = [0u8; 32];
    hash[0] = 0xC0;
    hash[1] = from;
    hash[2..10].copy_from_slice(&nonce.to_be_bytes());
    hash[10..30].copy_from_slice(&to.0);
    hash[30] = (value % 251) as u8;
    hash[31] = (gas_price % 253) as u8;
    Transaction {
        hash: Hash::new(hash),
        nonce,
        from: embedded(sender(from)),
        to: Some(embedded(to)),
        value,
        gas_limit: 21_000,
        gas_price,
        data: vec![],
        signature: Signature::new([1; 64]),
        tx_type: None,
        chain_id: Some(CHAIN_ID),
        ecdsa_verified: true,
        ..Default::default()
    }
}

/// A call to [`REVERTER`] declaring `gas` (executed, fails, charged `gas`).
fn reverting_call(from: u8, nonce: u64, gas: u64) -> Transaction {
    let mut tx = transfer(from, nonce, Address(REVERTER), 0, GAS_PRICE);
    tx.data = vec![0x01];
    tx.gas_limit = gas;
    tx.hash = Hash::new({
        let mut h = *tx.hash.as_bytes();
        h[0] = 0xCA;
        h
    });
    tx
}

#[derive(Clone)]
struct FleetSpec {
    producers: u8,
    senders: u8,
    k: u32,
    /// §R' policy active from height 1, with [`REG`] recording vests.
    policy: bool,
    /// [`REVERTER`] deployed at genesis.
    reverter: bool,
    /// [`PROBE`] deployed at genesis.
    blockhash_probe: bool,
}

impl FleetSpec {
    fn new(producers: u8) -> Self {
        Self {
            producers,
            senders: 4,
            k: GhostDagParams::default().k,
            policy: false,
            reverter: false,
            blockhash_probe: false,
        }
    }
}

fn genesis_state(spec: &FleetSpec) -> citrate_execution::state::StateSnapshot {
    let db = Arc::new(StateDB::new());
    for i in 0..spec.senders {
        db.accounts.create_account_if_not_exists(sender(i));
        db.accounts.set_balance(sender(i), U256::from(FUND));
    }
    Executor::new(db).state_snapshot()
}

/// The genesis world state on `exec`: the funded senders, and the contracts
/// the spec asks for (through `Executor::set_code`, so the code is held where
/// execution reads it).
fn seed_genesis(exec: &Executor, spec: &FleetSpec) {
    exec.state_restore(genesis_state(spec));
    if spec.reverter {
        exec.set_code(&Address(REVERTER), REVERTER_CODE.to_vec());
    }
    if spec.policy {
        exec.set_code(&Address(REG), REG_CODE.to_vec());
    }
    if spec.blockhash_probe {
        exec.set_code(&Address(PROBE), PROBE_CODE.to_vec());
    }
}

fn policy(spec: &FleetSpec) -> citrate_execution::block_rewards::EpochRewardPolicy {
    citrate_execution::block_rewards::EpochRewardPolicy {
        epoch: 0,
        snapshot_height: 0,
        activation_height: 1,
        registry: REG,
        reward_minter: citrate_execution::block_rewards::REWARD_MINTER_ADDRESS,
        priority_fee_share_bps: 5_000,
        block_subsidy: U256::zero(),
        staker_of: (0..spec.producers)
            .map(|i| (proposer_of(i), coinbase_of(i).0))
            .collect(),
    }
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

struct MNode {
    storage: Arc<StorageManager>,
    executor: Arc<Executor>,
    app: Arc<CanonicalApplicator>,
    adm: Arc<BlockAdmission>,
    mempool: Arc<Mempool>,
    producer: BlockProducer,
    ghostdag: Arc<GhostDag>,
    _dir: TempDir,
}

impl MNode {
    async fn start(i: u8, spec: &FleetSpec, genesis: &Block) -> Self {
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
        seed_genesis(&executor, spec);
        if spec.policy {
            executor.set_validator_activation_height(1);
            *executor.reward_policy_handle().write() = Some(policy(spec));
        }
        let kv = Arc::new(crate::persistent_dag::RocksDbKvStore::new(
            storage.db.clone(),
        ));
        let dag = Arc::new(DagStore::persistent_with_strict_vrf(kv, true).expect("dag load"));
        dag.set_configured_genesis(genesis.header.block_hash);
        let ghostdag = Arc::new(GhostDag::new(
            GhostDagParams {
                k: spec.k,
                ..GhostDagParams::default()
            },
            dag.clone(),
        ));
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
        app.set_genesis(executor.state_snapshot(), genesis.header.block_hash);
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
            embedded(coinbase_of(i)),
            signing_key(i),
            2,
            Arc::new(citrate_economics::UnifiedEconomicsManager::new(
                citrate_economics::UnifiedEconomicsConfig::default(),
            )),
            dag,
            ghostdag.clone(),
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
            ghostdag,
            _dir: dir,
        }
    }

    async fn produce(&self) -> Block {
        let h = self.producer.produce_block().await.expect("produce");
        self.storage
            .blocks
            .get_block(&h)
            .expect("read produced")
            .expect("produced stored")
    }

    /// Admit (deferred blocks are retried by the caller), then drain.
    async fn offer(&self, block: &Block) -> bool {
        let ok = matches!(
            self.adm.admit(block).await,
            AdmitOutcome::Admitted { .. } | AdmitOutcome::AlreadyAdmitted
        );
        self.app.drive_drain().await;
        ok
    }

    async fn receive(&self, block: &Block) {
        assert!(
            self.offer(block).await,
            "block {} @ {} not admitted",
            block.header.block_hash,
            block.header.height
        );
    }

    async fn submit(&self, tx: &Transaction) -> bool {
        self.mempool
            .add_transaction(tx.clone(), TxClass::Standard)
            .await
            .is_ok()
    }

    fn nonce(&self, a: Address) -> u64 {
        self.executor.get_nonce(&a)
    }

    fn balance(&self, a: Address) -> U256 {
        self.executor.get_balance(&a)
    }

    async fn tip(&self) -> (Hash, u64) {
        let t = self.app.applied_tip().await;
        (t.hash, t.height)
    }

    fn receipt_json(&self, tx: &Hash) -> Option<serde_json::Value> {
        self.storage
            .transactions
            .get_receipt(tx)
            .expect("receipt read")
            .map(|r| serde_json::to_value(r).expect("receipt json"))
    }

    /// The node's applied chain, genesis first.
    async fn chain(&self) -> Vec<Hash> {
        let (mut cursor, _) = self.tip().await;
        let mut out = Vec::new();
        loop {
            out.push(cursor);
            let b = self
                .storage
                .blocks
                .get_block(&cursor)
                .expect("read")
                .expect("chain block stored");
            if b.header.height == 0 {
                break;
            }
            cursor = b.header.selected_parent_hash;
        }
        out.reverse();
        out
    }

    /// Every stored block in past(applied tip), the tip excluded.
    async fn past_of_tip(&self) -> Vec<Block> {
        let (tip, _) = self.tip().await;
        let mut seen: HashSet<Hash> = HashSet::new();
        let mut out = Vec::new();
        let mut stack = vec![tip];
        while let Some(h) = stack.pop() {
            let b = self
                .storage
                .blocks
                .get_block(&h)
                .expect("read")
                .expect("past block stored");
            for p in b.parents() {
                if p != Hash::default() && seen.insert(p) {
                    stack.push(p);
                }
            }
            if h != tip {
                out.push(b);
            }
        }
        out
    }

    /// The txs the node indexed under chain block `c`, in execution order:
    /// (tx hash, including block, status), from receipt JSON.
    fn accepted_list(&self, c: &Hash) -> Vec<(Hash, Hash, bool)> {
        let mut rows = Vec::new();
        for tx in self
            .storage
            .transactions
            .get_block_transactions(c)
            .expect("index")
        {
            let Some(j) = self.receipt_json(&tx) else {
                continue;
            };
            if j["block_hash"] != serde_json::to_value(c).expect("hash json") {
                continue;
            }
            let acc = &j["acceptance"];
            assert!(
                acc.is_object(),
                "receipt of {tx} under chain block {c} carries no acceptance record: {j}"
            );
            let including: Hash =
                serde_json::from_value(acc["including_block_hash"].clone()).expect("including");
            let pos = acc["transaction_index"].as_u64().expect("index");
            rows.push((pos, (tx, including, j["status"].as_bool().expect("status"))));
        }
        rows.sort_by_key(|(p, _)| *p);
        rows.into_iter().map(|(_, r)| r).collect()
    }

    fn rpc(&self) -> Arc<jsonrpc_core::IoHandler> {
        std::env::set_var("CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT", "1");
        let mut io = jsonrpc_core::IoHandler::new();
        citrate_api::eth_rpc::register_eth_methods_with_finality(
            &mut io,
            self.storage.clone(),
            self.mempool.clone(),
            self.executor.clone(),
            CHAIN_ID,
            Arc::new(citrate_api::FilterRegistry::new()),
            None,
            Arc::new(AtomicU64::new(0)),
        );
        Arc::new(io)
    }
}

async fn rpc_call(
    io: &Arc<jsonrpc_core::IoHandler>,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    let io = io.clone();
    let req =
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
    let resp = tokio::task::spawn_blocking(move || io.handle_request_sync(&req))
        .await
        .expect("rpc task")
        .expect("rpc response");
    let v: serde_json::Value = serde_json::from_str(&resp).expect("rpc json");
    v["result"].clone()
}

fn hex32(h: &Hash) -> String {
    format!("0x{}", hex::encode(h.as_bytes()))
}

struct Fleet {
    spec: FleetSpec,
    genesis: Block,
    nodes: Vec<MNode>,
}

impl Fleet {
    async fn new(spec: FleetSpec) -> Self {
        let root = Executor::new(Arc::new(StateDB::new()));
        seed_genesis(&root, &spec);
        let genesis = genesis_block(root.calculate_state_root());
        let mut nodes = Vec::new();
        for i in 0..spec.producers {
            nodes.push(MNode::start(i, &spec, &genesis).await);
        }
        Self {
            spec,
            genesis,
            nodes,
        }
    }

    /// Offer `blocks` to node `i` until every one is admitted (a block whose
    /// parent is not admitted yet is retried after the others).
    async fn deliver(&self, i: usize, blocks: &[Block]) {
        let mut pending: Vec<Block> = blocks.to_vec();
        for _ in 0..=blocks.len() {
            let mut next = Vec::new();
            for b in pending {
                if !self.nodes[i].offer(&b).await {
                    next.push(b);
                }
            }
            pending = next;
            if pending.is_empty() {
                return;
            }
        }
        panic!("node {i}: {} block(s) never admitted", pending.len());
    }
}

/// splitmix64.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = self.below(i as u64 + 1) as usize;
            v.swap(i, j);
        }
    }
}

/// A randomized multi-producer run: each slot, every sender's next txs reach
/// one or two random pools, a random non-empty subset of producers seals
/// (siblings), and the new blocks reach every node in a random order. Then
/// one producer at a time seals, with full delivery, for at least `settle`
/// slots and until three blocks in a row carry nothing (every pool is
/// drained: each skipped occurrence was re-offered and re-included), so every
/// block is merged and accepted. Returns every tx submitted.
async fn random_run(fleet: &Fleet, rng: &mut Rng, slots: u64, settle: u64) -> Vec<Transaction> {
    let n = fleet.nodes.len();
    let mut next_nonce: HashMap<u8, u64> = HashMap::new();
    let mut all = Vec::new();
    for _ in 0..slots {
        for s in 0..fleet.spec.senders {
            for _ in 0..(1 + rng.below(2)) {
                let nonce = *next_nonce.entry(s).or_insert(0);
                let tx = transfer(s, nonce, recipient(s), VALUE, GAS_PRICE);
                let mut took = false;
                for _ in 0..(1 + rng.below(2)) {
                    let i = rng.below(n as u64) as usize;
                    took |= fleet.nodes[i].submit(&tx).await;
                }
                if took {
                    next_nonce.insert(s, nonce + 1);
                    all.push(tx);
                }
            }
        }
        let mut sealers: Vec<usize> = (0..n).filter(|_| rng.below(2) == 0).collect();
        if sealers.is_empty() {
            sealers.push(rng.below(n as u64) as usize);
        }
        let mut new = Vec::new();
        for i in sealers {
            if let Ok(h) = fleet.nodes[i].producer.produce_block().await {
                if let Some(b) = fleet.nodes[i].storage.blocks.get_block(&h).expect("read") {
                    new.push(b);
                }
            }
        }
        for i in 0..n {
            let mut order = new.clone();
            rng.shuffle(&mut order);
            fleet.deliver(i, &order).await;
        }
    }
    let mut empty_run = 0u64;
    for s in 0..(settle + 40) {
        if s >= settle && empty_run >= 3 {
            break;
        }
        let i = (s as usize) % n;
        if let Ok(h) = fleet.nodes[i].producer.produce_block().await {
            let b = fleet.nodes[i]
                .storage
                .blocks
                .get_block(&h)
                .expect("read")
                .expect("stored");
            empty_run = if b.transactions.is_empty() {
                empty_run + 1
            } else {
                0
            };
            for j in 0..n {
                fleet.deliver(j, std::slice::from_ref(&b)).await;
            }
        }
    }
    all
}

/// S3-3b planset (I2 + I3, spec 06 §8.1): over randomized multi-producer DAGs
/// with siblings, merges, re-inclusions and nonce gaps, every transaction that
/// appears in a block of past(applied tip) is executed exactly once: one
/// receipt, naming a chain block as its accepting block and a block of
/// past(tip) that carries it as its including block, and the sender's nonce
/// and balance account for each of its transactions once (value and the
/// 21,000-gas fee, nothing for any skipped duplicate).
#[tokio::test]
async fn every_valid_tx_in_an_accepted_block_executes_exactly_once() {
    for seed in 1..=6u64 {
        let fleet = Fleet::new(FleetSpec::new(3)).await;
        let mut rng = Rng(seed);
        let submitted = random_run(&fleet, &mut rng, 6, 6).await;
        for (ni, node) in fleet.nodes.iter().enumerate() {
            let past = node.past_of_tip().await;
            let chain: HashSet<Hash> = node.chain().await.into_iter().collect();
            let past_hashes: HashSet<Hash> = past.iter().map(|b| b.header.block_hash).collect();
            let mut carried: HashMap<Hash, Vec<Hash>> = HashMap::new();
            for b in &past {
                for t in &b.transactions {
                    carried.entry(t.hash).or_default().push(b.header.block_hash);
                }
            }
            for (tx, blocks) in &carried {
                let j = node.receipt_json(tx).unwrap_or_else(|| {
                    panic!("seed {seed} node {ni}: tx {tx} is in accepted block(s) {blocks:?} but never executed")
                });
                let accepting: Hash =
                    serde_json::from_value(j["block_hash"].clone()).expect("block hash");
                assert!(
                    chain.contains(&accepting),
                    "seed {seed} node {ni}: tx {tx}'s receipt names {accepting}, not a chain block"
                );
                let acc = &j["acceptance"];
                assert!(
                    acc.is_object(),
                    "seed {seed} node {ni}: tx {tx}'s receipt has no acceptance record: {j}"
                );
                let including: Hash =
                    serde_json::from_value(acc["including_block_hash"].clone()).expect("incl");
                assert!(
                    past_hashes.contains(&including) && blocks.contains(&including),
                    "seed {seed} node {ni}: tx {tx} executed from {including}, which is not one \
                     of its accepted blocks {blocks:?}"
                );
            }
            // Each sender's txs that reached an accepted block executed once
            // each, in nonce order: nonce == count, balance == FUND - Σ(value +
            // fee) exactly (a fee charged for a skipped duplicate shows here).
            for s in 0..fleet.spec.senders {
                let mine: Vec<&Transaction> = submitted
                    .iter()
                    .filter(|t| t.from == embedded(sender(s)) && carried.contains_key(&t.hash))
                    .collect();
                let count = mine.len() as u64;
                assert_eq!(
                    node.nonce(sender(s)),
                    count,
                    "seed {seed} node {ni}: sender {s} executed a different number of txs than \
                     reached accepted blocks"
                );
                let spent = U256::from(count) * U256::from(VALUE + 21_000u128 * GAS_PRICE as u128);
                assert_eq!(
                    node.balance(sender(s)),
                    U256::from(FUND) - spent,
                    "seed {seed} node {ni}: sender {s} paid for something other than its txs once each"
                );
            }
        }
        // Every node agrees on the result.
        let roots: HashSet<Hash> = fleet
            .nodes
            .iter()
            .map(|n| n.executor.calculate_state_root())
            .collect();
        assert_eq!(roots.len(), 1, "seed {seed}: nodes disagree on the state");
    }
}

/// S3-3b planset (I4, property): nodes holding the same DAG compute the same
/// chain, the same accepted list per chain block and the same state, whatever
/// order the blocks arrived in; a fresh GHOSTDAG engine over a node's store
/// (a restart's reload) orders every mergeset identically.
#[tokio::test]
async fn total_order_identical_across_nodes() {
    for seed in 11..=14u64 {
        let spec = FleetSpec::new(3);
        let fleet = Fleet::new(spec.clone()).await;
        let mut rng = Rng(seed);
        random_run(&fleet, &mut rng, 6, 3).await;
        // Every stored block of node 0, delivered to two fresh followers in
        // two random arrival orders.
        let mut blocks: Vec<Block> = fleet.nodes[0].past_of_tip().await;
        let (tip, _) = fleet.nodes[0].tip().await;
        blocks.push(
            fleet.nodes[0]
                .storage
                .blocks
                .get_block(&tip)
                .expect("read")
                .expect("tip"),
        );
        let mut views = Vec::new();
        for f in 0..2u8 {
            let follower = MNode::start(10 + f, &spec, &fleet.genesis).await;
            let mut order = blocks.clone();
            rng.shuffle(&mut order);
            let mut pending = order;
            for _ in 0..=blocks.len() {
                let mut next = Vec::new();
                for b in pending {
                    if !follower.offer(&b).await {
                        next.push(b);
                    }
                }
                pending = next;
                if pending.is_empty() {
                    break;
                }
            }
            assert!(
                pending.is_empty(),
                "seed {seed}: follower {f} did not admit the DAG"
            );
            views.push(follower);
        }
        let reference = &fleet.nodes[0];
        let chain = reference.chain().await;
        for (fi, v) in views.iter().enumerate() {
            assert_eq!(
                v.chain().await,
                chain,
                "seed {seed} follower {fi}: chain differs"
            );
            assert_eq!(
                v.executor.calculate_state_root(),
                reference.executor.calculate_state_root(),
                "seed {seed} follower {fi}: state differs"
            );
            for c in chain.iter().skip(1) {
                assert_eq!(
                    v.accepted_list(c),
                    reference.accepted_list(c),
                    "seed {seed} follower {fi}: accepted list of {c} differs"
                );
            }
        }
        // Partition (I1): every tx in past(tip) is in exactly one chain
        // block's accepted list, or was skipped there.
        let mut executed: HashMap<Hash, usize> = HashMap::new();
        for c in chain.iter().skip(1) {
            for (t, _, _) in reference.accepted_list(c) {
                *executed.entry(t).or_default() += 1;
            }
        }
        assert!(
            executed.values().all(|n| *n == 1),
            "seed {seed}: a tx executed twice"
        );
        let carried: HashSet<Hash> = reference
            .past_of_tip()
            .await
            .iter()
            .flat_map(|b| b.transactions.iter().map(|t| t.hash))
            .collect();
        assert!(
            carried.iter().all(|t| executed.contains_key(t)),
            "seed {seed}: a tx in an accepted block is in no chain block's accepted list"
        );
        // A restart's reload: a fresh engine over the same store gives the
        // same records, so the same mergesets.
        let kv = Arc::new(crate::persistent_dag::RocksDbKvStore::new(
            reference.storage.db.clone(),
        ));
        let dag = Arc::new(DagStore::persistent_with_strict_vrf(kv, true).expect("reload"));
        let fresh = GhostDag::new(
            GhostDagParams {
                k: spec.k,
                ..GhostDagParams::default()
            },
            dag,
        );
        for c in chain.iter().skip(1) {
            let a = reference.ghostdag.ghostdag_data(c).await.expect("record");
            let b = fresh.ghostdag_data(c).await.expect("reloaded record");
            assert_eq!(
                a.as_ref(),
                b.as_ref(),
                "seed {seed}: record of {c} differs after reload"
            );
        }
    }
}

/// Two producers both include the same tx in sibling blocks; the block that
/// merges them executes it once (from the first in order, its selected
/// parent) and skips the other copy with no fee and no nonce bump.
#[tokio::test]
async fn duplicate_tx_in_sibling_skipped_without_fee() {
    let fleet = Fleet::new(FleetSpec::new(2)).await;
    let (a, b) = (&fleet.nodes[0], &fleet.nodes[1]);
    let t = transfer(0, 0, recipient(0), VALUE, GAS_PRICE);
    assert!(a.submit(&t).await && b.submit(&t).await);
    let a1 = a.produce().await;
    let b1 = b.produce().await;
    assert!(a1.transactions.iter().any(|x| x.hash == t.hash));
    assert!(b1.transactions.iter().any(|x| x.hash == t.hash));
    a.receive(&b1).await;
    b.receive(&a1).await;
    let m = a.produce().await;
    b.receive(&m).await;
    assert_eq!(
        m.header.merge_parent_hashes.len(),
        1,
        "m merges the sibling"
    );
    let sp = m.header.selected_parent_hash;
    for (name, node) in [("A", a), ("B", b)] {
        assert_eq!(node.nonce(sender(0)), 1, "{name}: executed exactly once");
        assert_eq!(
            node.balance(sender(0)),
            U256::from(FUND) - U256::from(VALUE + 21_000u128 * GAS_PRICE as u128),
            "{name}: one fee and one value, nothing for the skipped copy"
        );
        assert_eq!(node.balance(recipient(0)), U256::from(VALUE));
        let j = node.receipt_json(&t.hash).expect("executed");
        assert_eq!(
            j["block_hash"],
            serde_json::to_value(m.header.block_hash).expect("json"),
            "{name}: the receipt names the accepting block"
        );
        assert_eq!(
            j["acceptance"]["including_block_hash"],
            serde_json::to_value(sp).expect("json"),
            "{name}: the first occurrence in order (the selected parent's) executed"
        );
        assert_eq!(
            node.accepted_list(&m.header.block_hash),
            vec![(t.hash, sp, true)],
            "{name}: m executed one occurrence"
        );
    }
}

/// Two different txs spend the same (sender, nonce) in sibling blocks. The
/// merging block executes the one in its selected parent and skips the other
/// deterministically: no fee, no receipt, its recipient never paid. A third
/// node fed the blocks in another order reaches the same result.
#[tokio::test]
async fn nonce_conflict_skipped_deterministically() {
    let mut spec = FleetSpec::new(3);
    spec.senders = 1;
    let fleet = Fleet::new(spec).await;
    let (a, b, c) = (&fleet.nodes[0], &fleet.nodes[1], &fleet.nodes[2]);
    let t1 = transfer(0, 0, recipient(1), VALUE, GAS_PRICE);
    let t2 = transfer(0, 0, recipient(2), VALUE, GAS_PRICE);
    assert!(a.submit(&t1).await && b.submit(&t2).await);
    let a1 = a.produce().await;
    let b1 = b.produce().await;
    a.receive(&b1).await;
    let m = a.produce().await;
    let sp = m.header.selected_parent_hash;
    let (winner, loser, w_to, l_to) = if sp == a1.header.block_hash {
        (&t1, &t2, recipient(1), recipient(2))
    } else {
        (&t2, &t1, recipient(2), recipient(1))
    };
    // C receives the merge block's parents in the other order.
    c.receive(&b1).await;
    c.receive(&a1).await;
    c.receive(&m).await;
    for (name, node) in [("A", a), ("C", c)] {
        assert_eq!(node.nonce(sender(0)), 1, "{name}");
        assert_eq!(
            node.balance(w_to),
            U256::from(VALUE),
            "{name}: the winner paid"
        );
        assert_eq!(
            node.balance(l_to),
            U256::zero(),
            "{name}: the loser never ran"
        );
        assert_eq!(
            node.balance(sender(0)),
            U256::from(FUND) - U256::from(VALUE + 21_000u128 * GAS_PRICE as u128),
            "{name}: one fee"
        );
        assert!(
            node.receipt_json(&loser.hash).is_none(),
            "{name}: no receipt for the skip"
        );
        assert_eq!(
            node.accepted_list(&m.header.block_hash),
            vec![(winner.hash, sp, true)],
            "{name}"
        );
    }
    assert_eq!(
        a.executor.calculate_state_root(),
        c.executor.calculate_state_root()
    );
}

/// K = 0: every block of `Mergeset*` is red. A red block's tx is executed
/// (spec 06 §3.3, D7) when the block that merges it is applied, and its
/// receipt reports the red color.
#[tokio::test]
async fn red_block_txs_execute_per_spec() {
    let mut spec = FleetSpec::new(2);
    spec.k = 0;
    let fleet = Fleet::new(spec).await;
    let (a, b) = (&fleet.nodes[0], &fleet.nodes[1]);
    let t = transfer(0, 0, recipient(0), VALUE, GAS_PRICE);
    assert!(b.submit(&t).await);
    let _a1 = a.produce().await;
    let a2 = a.produce().await;
    let b1 = b.produce().await;
    assert!(b1.transactions.iter().any(|x| x.hash == t.hash));
    a.receive(&b1).await;
    let m = a.produce().await;
    assert_eq!(m.header.selected_parent_hash, a2.header.block_hash);
    assert_eq!(m.header.merge_parent_hashes, vec![b1.header.block_hash]);
    let rec = a
        .ghostdag
        .ghostdag_data(&m.header.block_hash)
        .await
        .expect("record");
    assert_eq!(
        rec.mergeset_reds,
        vec![b1.header.block_hash],
        "b1 is red at K = 0"
    );
    assert_eq!(a.nonce(sender(0)), 1, "the red block's tx executed");
    assert_eq!(a.balance(recipient(0)), U256::from(VALUE));
    let j = a.receipt_json(&t.hash).expect("receipt");
    assert_eq!(
        j["block_hash"],
        serde_json::to_value(m.header.block_hash).expect("json")
    );
    assert_eq!(j["acceptance"]["inclusion_color"], "Red");
    assert_eq!(
        j["acceptance"]["including_block_hash"],
        serde_json::to_value(b1.header.block_hash).expect("json")
    );
    // The independent reference colors b1 red at K = 0 too and reproduces
    // m's commitments (red block executed, no emission share for it).
    let mut cfg = citrate_replay_ref::ReplayConfig::from_process(CHAIN_ID);
    cfg.ghostdag_k = 0;
    cfg.genesis_alloc = (0..fleet.spec.senders)
        .map(|s| {
            let mut be = [0u8; 32];
            U256::from(FUND).to_big_endian(&mut be);
            (sender(s).0, be)
        })
        .collect();
    let rec = citrate_replay_ref::record_db(&a.storage.db, cfg, "A".into()).expect("record");
    let report = citrate_replay_ref::replay_mergeset(&rec).expect("replay");
    assert_eq!(report.divergence, None, "{report:?}");
    assert_eq!(report.matched, 3);
}

/// Spec 06 §3.8 (O3, O4 defaults): R(h) of the accepting block goes to its
/// blue blocks only (here its selected parent), never to a red one; the
/// priority fees of a red block's txs vest to the ACCEPTING block's proposer.
#[tokio::test]
async fn rewards_to_blue_only_and_red_fees_to_acceptor() {
    let mut spec = FleetSpec::new(2);
    spec.k = 0;
    spec.policy = true;
    let fleet = Fleet::new(spec).await;
    let (a, b) = (&fleet.nodes[0], &fleet.nodes[1]);
    // Priority 1 gwei per gas over the 1 gwei base fee.
    let t = transfer(0, 0, recipient(0), VALUE, 2 * GAS_PRICE);
    assert!(b.submit(&t).await);
    let _a1 = a.produce().await;
    let _a2 = a.produce().await;
    let b1 = b.produce().await;
    a.receive(&b1).await;
    let cb_a = a.balance(coinbase_of(0));
    let cb_b = a.balance(coinbase_of(1));
    let vested = |node: &MNode, i: u8| {
        node.executor
            .state_db()
            .get_storage(&Address(REG), &proposer_of(i))
            .map(|v| U256::from_big_endian(&v))
            .unwrap_or_default()
    };
    let (va, vb) = (vested(a, 0), vested(a, 1));
    let m = a.produce().await;
    let r =
        crate::canonical_apply::canonical_block_reward(
            &citrate_economics::RewardCalculator::new(
                crate::canonical_apply::canonical_reward_config(),
            ),
            &BlockBuilder::new().height(m.header.height).build_unhashed(),
            &[],
        )
        .expect("reward");
    assert_eq!(
        a.balance(coinbase_of(0)) - cb_a,
        r.validator_reward,
        "the blue selected parent's coinbase earns R(h)"
    );
    assert_eq!(
        a.balance(coinbase_of(1)),
        cb_b,
        "the red block's coinbase earns nothing"
    );
    let pool = U256::from(21_000u64) * U256::from(GAS_PRICE);
    assert_eq!(
        vested(a, 0) - va,
        pool / 2,
        "the red block's priority fees vest to the accepting block's proposer"
    );
    assert_eq!(
        vested(a, 1),
        vb,
        "nothing vests to the red block's proposer"
    );
}

/// Spec 06 §3.6 (O5): one accepting block executes at most ACCEPT_GAS_LIMIT.
/// Three siblings each declare 30M (three failing 10M calls each, each charged
/// its whole limit); the block that accepts all three runs six (60M) and
/// skips the last three, with no fee, and commits gas_used = 60M under the
/// header gas_limit ACCEPT_GAS_LIMIT.
#[tokio::test]
async fn gas_limit_per_accepting_block_enforced() {
    let mut spec = FleetSpec::new(3);
    spec.senders = 9;
    spec.reverter = true;
    let fleet = Fleet::new(spec).await;
    let mut calls = Vec::new();
    for s in 0..9u8 {
        let tx = reverting_call(s, 0, 10_000_000);
        assert!(fleet.nodes[(s / 3) as usize].submit(&tx).await);
        calls.push(tx);
    }
    let mut sibs = Vec::new();
    for i in 0..3 {
        let blk = fleet.nodes[i].produce().await;
        assert_eq!(
            blk.transactions.len(),
            3,
            "node {i} includes its three calls"
        );
        sibs.push(blk);
    }
    let a = &fleet.nodes[0];
    fleet.deliver(0, &sibs[1..]).await;
    let m = a.produce().await;
    assert_eq!(m.header.merge_parent_hashes.len(), 2);
    let header = serde_json::to_value(&m.header).expect("header json");
    assert_eq!(
        header["gas_limit"].as_u64(),
        Some(60_000_000),
        "the header gas limit is ACCEPT_GAS_LIMIT"
    );
    assert_eq!(header["gas_used"].as_u64(), Some(60_000_000));
    let executed: Vec<&Transaction> = calls
        .iter()
        .filter(|t| a.receipt_json(&t.hash).is_some())
        .collect();
    assert_eq!(executed.len(), 6, "six calls fit the budget");
    for t in &calls {
        let s = (0..9u8)
            .find(|s| t.from == embedded(sender(*s)))
            .expect("sender");
        match a.receipt_json(&t.hash) {
            Some(j) => {
                assert_eq!(
                    j["block_hash"],
                    serde_json::to_value(m.header.block_hash).expect("j")
                );
                assert_eq!(j["status"], false);
                assert_eq!(a.nonce(sender(s)), 1);
                assert_eq!(
                    a.balance(sender(s)),
                    U256::from(FUND) - U256::from(10_000_000u128 * GAS_PRICE as u128)
                );
            }
            None => {
                assert_eq!(a.nonce(sender(s)), 0, "a skipped call bumps no nonce");
                assert_eq!(a.balance(sender(s)), U256::from(FUND), "and pays no fee");
            }
        }
    }
}

/// A selected-chain reorg undoes the accepted mergeset of every abandoned
/// chain block: receipts naming it leave, state equals a node that only ever
/// applied the winning chain, and the abandoned txs execute again once a
/// later block merges their blocks.
#[tokio::test]
async fn reorg_rolls_back_accepted_mergeset() {
    let fleet = Fleet::new(FleetSpec::new(2)).await;
    let (a, b) = (&fleet.nodes[0], &fleet.nodes[1]);
    let ta = transfer(0, 0, recipient(0), VALUE, GAS_PRICE);
    let tb = transfer(1, 0, recipient(1), VALUE, GAS_PRICE);
    assert!(a.submit(&ta).await && b.submit(&tb).await);
    let a1 = a.produce().await;
    let b1 = b.produce().await;
    a.receive(&b1).await;
    let m = a.produce().await;
    for t in [&ta, &tb] {
        let j = a.receipt_json(&t.hash).expect("executed by m");
        assert_eq!(
            j["block_hash"],
            serde_json::to_value(m.header.block_hash).expect("j"),
            "before the reorg, m accepts both siblings"
        );
    }
    // B never sees a1 or m and grows a heavier chain on b1.
    let mut bs = Vec::new();
    for _ in 0..3 {
        bs.push(b.produce().await);
    }
    for blk in &bs {
        a.receive(blk).await;
    }
    let (tip, _) = a.tip().await;
    assert_eq!(
        tip, bs[2].header.block_hash,
        "A reorged onto B's heavier chain"
    );
    assert_eq!(
        a.executor.calculate_state_root(),
        b.executor.calculate_state_root(),
        "A's state is exactly B's (I7)"
    );
    let mj = serde_json::to_value(m.header.block_hash).expect("j");
    for t in [&ta, &tb] {
        if let Some(j) = a.receipt_json(&t.hash) {
            assert_ne!(j["block_hash"], mj, "no receipt names the abandoned m");
        }
    }
    assert!(
        a.receipt_json(&ta.hash).is_none(),
        "a1 is not accepted on B's chain"
    );
    let jb = a.receipt_json(&tb.hash).expect("tb executed on B's chain");
    assert_eq!(
        jb["block_hash"],
        serde_json::to_value(bs[0].header.block_hash).expect("j")
    );
    // A's next block merges a1 and m: ta executes again.
    let n = a.produce().await;
    let ja = a.receipt_json(&ta.hash).expect("ta executed again");
    assert_eq!(
        ja["block_hash"],
        serde_json::to_value(n.header.block_hash).expect("j")
    );
    assert_eq!(
        ja["acceptance"]["including_block_hash"],
        serde_json::to_value(a1.header.block_hash).expect("j")
    );
    b.receive(&a1).await;
    b.receive(&m).await;
    b.receive(&n).await;
    assert_eq!(
        a.executor.calculate_state_root(),
        b.executor.calculate_state_root()
    );
}

/// Spec 06 §3.11 / §5.1: a tx included in block X and executed by chain block
/// C has its receipt under C (blockHash, blockNumber, transactionIndex and
/// cumulativeGasUsed within C) and names X as its including block, in the
/// store and over `eth_getTransactionReceipt`; before C exists it has no
/// receipt; `eth_getBlockByNumber(height(C))` lists it.
#[tokio::test]
async fn receipt_reports_accepting_and_including_block() {
    let fleet = Fleet::new(FleetSpec::new(1)).await;
    let a = &fleet.nodes[0];
    let t = transfer(0, 0, recipient(0), VALUE, GAS_PRICE);
    assert!(a.submit(&t).await);
    let x = a.produce().await;
    assert!(x.transactions.iter().any(|y| y.hash == t.hash));
    assert!(
        a.receipt_json(&t.hash).is_none(),
        "included, not executed yet: no receipt"
    );
    let c = a.produce().await;
    let io = a.rpc();
    let r = rpc_call(
        &io,
        "eth_getTransactionReceipt",
        serde_json::json!([hex32(&t.hash)]),
    )
    .await;
    assert_eq!(r["blockHash"], hex32(&c.header.block_hash));
    assert_eq!(r["blockNumber"], format!("0x{:x}", c.header.height));
    assert_eq!(r["transactionIndex"], "0x0");
    assert_eq!(r["cumulativeGasUsed"], format!("0x{:x}", 21_000));
    assert_eq!(r["includingBlockHash"], hex32(&x.header.block_hash));
    assert_eq!(
        r["includingBlockHeight"],
        format!("0x{:x}", x.header.height)
    );
    assert_eq!(r["inclusionColor"], "selected_parent");
    let blk = rpc_call(
        &io,
        "eth_getBlockByNumber",
        serde_json::json!([format!("0x{:x}", c.header.height), false]),
    )
    .await;
    assert_eq!(blk["hash"], hex32(&c.header.block_hash));
    assert_eq!(
        blk["transactions"],
        serde_json::json!([hex32(&t.hash)]),
        "block n lists the tx whose receipt says n"
    );
}

/// Spec 06 §9.4: a transaction skipped by its accepting block for a reason
/// that can clear later (here B3, the ACCEPT gas budget) goes back to the
/// accepting node's pool, is included again, and executes exactly once when
/// a later block accepts the re-including block. Its sender pays once.
#[tokio::test]
async fn skipped_merged_block_txs_are_reinjected_and_execute_once() {
    let mut spec = FleetSpec::new(3);
    spec.senders = 9;
    spec.reverter = true;
    let fleet = Fleet::new(spec).await;
    let mut calls = Vec::new();
    for s in 0..9u8 {
        let tx = reverting_call(s, 0, 10_000_000);
        assert!(fleet.nodes[(s / 3) as usize].submit(&tx).await);
        calls.push(tx);
    }
    let mut sibs = Vec::new();
    for i in 0..3 {
        sibs.push(fleet.nodes[i].produce().await);
    }
    let a = &fleet.nodes[0];
    fleet.deliver(0, &sibs[1..]).await;
    let m = a.produce().await;
    let skipped: Vec<&Transaction> = calls
        .iter()
        .filter(|t| a.receipt_json(&t.hash).is_none())
        .collect();
    assert_eq!(skipped.len(), 3, "the budget leaves three calls skipped");
    assert!(
        m.transactions
            .iter()
            .all(|t| !skipped.iter().any(|s| s.hash == t.hash)),
        "m was sealed before the skips were known to the pool"
    );
    // The accepting node re-offered them: its next block includes them all.
    let r = a.produce().await;
    for t in &skipped {
        assert!(
            r.transactions.iter().any(|x| x.hash == t.hash),
            "skipped tx {} was re-included",
            t.hash
        );
    }
    let acc = a.produce().await;
    for t in &calls {
        let s = (0..9u8)
            .find(|s| t.from == embedded(sender(*s)))
            .expect("sender");
        assert!(a.receipt_json(&t.hash).is_some(), "every call executed");
        assert_eq!(a.nonce(sender(s)), 1, "once");
        assert_eq!(
            a.balance(sender(s)),
            U256::from(FUND) - U256::from(10_000_000u128 * GAS_PRICE as u128),
            "one fee"
        );
    }
    for t in &skipped {
        let j = a.receipt_json(&t.hash).expect("receipt");
        assert_eq!(
            j["block_hash"],
            serde_json::to_value(acc.header.block_hash).expect("j")
        );
        assert_eq!(
            j["acceptance"]["including_block_hash"],
            serde_json::to_value(r.header.block_hash).expect("j"),
            "it executed from the block that re-included it"
        );
    }
}

/// Spec 06 §9.4 (CHAIN-TXINCL finding): a producer never re-includes a
/// transaction that a block in past(SP) already carries. The block's own
/// list is selected against post(B), after B executed its mergeset, so a tx
/// in SP's list has bumped its sender's nonce by then; B's own included txs
/// stay pooled (they are not executed yet) but are not offered again by its
/// child.
#[tokio::test]
async fn producer_does_not_reinclude_txs_included_in_past_of_sp() {
    let fleet = Fleet::new(FleetSpec::new(2)).await;
    let (a, b) = (&fleet.nodes[0], &fleet.nodes[1]);
    let t = transfer(0, 0, recipient(0), VALUE, GAS_PRICE);
    let u = transfer(1, 0, recipient(1), VALUE, GAS_PRICE);
    assert!(a.submit(&t).await && b.submit(&t).await && a.submit(&u).await);
    // B includes t; A receives B's block and seals on it.
    let b1 = b.produce().await;
    assert!(b1.transactions.iter().any(|x| x.hash == t.hash));
    a.receive(&b1).await;
    let a2 = a.produce().await;
    assert_eq!(a2.header.selected_parent_hash, b1.header.block_hash);
    assert!(
        !a2.transactions.iter().any(|x| x.hash == t.hash),
        "t is in past(SP) and must not be included again"
    );
    assert!(a2.transactions.iter().any(|x| x.hash == u.hash));
    // A's own block a2 carries u; its child a3 does not carry u again.
    let a3 = a.produce().await;
    assert_eq!(a3.header.selected_parent_hash, a2.header.block_hash);
    assert!(!a3.transactions.iter().any(|x| x.hash == u.hash));
    assert_eq!(a.nonce(sender(0)), 1);
    assert_eq!(a.nonce(sender(1)), 1);
}

/// Spec 06 §3.7: inside the transactions chain block C accepts, BLOCKHASH(n)
/// is the hash of C's selected-chain ancestor at height n, for the 256
/// heights below height(C). A contract stores BLOCKHASH(NUMBER - 1) and
/// BLOCKHASH(NUMBER - 2); after C executes the call they are SP(C) and
/// SP(SP(C)).
#[tokio::test]
async fn blockhash_opcode_returns_selected_chain_ancestors() {
    let mut spec = FleetSpec::new(1);
    spec.blockhash_probe = true;
    let fleet = Fleet::new(spec).await;
    let a = &fleet.nodes[0];
    let _a1 = a.produce().await;
    let mut call = transfer(0, 0, Address(PROBE), 0, GAS_PRICE);
    call.data = vec![0x01];
    call.gas_limit = 200_000;
    assert!(a.submit(&call).await);
    let x = a.produce().await;
    assert!(x.transactions.iter().any(|t| t.hash == call.hash));
    let c = a.produce().await;
    let j = a.receipt_json(&call.hash).expect("executed");
    assert_eq!(j["status"], true, "{j}");
    assert_eq!(
        j["block_hash"],
        serde_json::to_value(c.header.block_hash).expect("j")
    );
    let slot = |i: u8| {
        let mut k = [0u8; 32];
        k[31] = i;
        a.executor
            .state_db()
            .get_storage(&Address(PROBE), &k)
            .map(|v| {
                let mut out = [0u8; 32];
                out.copy_from_slice(&v[..32]);
                out
            })
            .unwrap_or([0u8; 32])
    };
    let sp = c.header.selected_parent_hash;
    let sp_parent = x.header.selected_parent_hash;
    assert_eq!(sp, x.header.block_hash);
    assert_eq!(slot(0), *sp.as_bytes(), "BLOCKHASH(height(C) - 1) = SP(C)");
    assert_eq!(
        slot(1),
        *sp_parent.as_bytes(),
        "BLOCKHASH(height(C) - 2) = SP(SP(C))"
    );
}

/// S3-3c (spec 06 §8.3, I6): the node's chain, recorded from its data dir,
/// replays through the INDEPENDENT reference (`citrate-mergeset-ref`, which
/// shares no execution code with the node) with no divergence in GHOSTDAG,
/// state root, receipt root, accepted root, gas used or accepted list, over
/// randomized multi-producer DAGs, and over the split-heal recordings when
/// `CITRATE_SPLIT_HEAL_RECORDING_DIR` names them; and a corrupted header root
/// is caught at its height.
#[tokio::test]
async fn replay_parity_mergeset() {
    for seed in 21..=24u64 {
        let spec = FleetSpec::new(3);
        let fleet = Fleet::new(spec.clone()).await;
        let mut rng = Rng(seed);
        random_run(&fleet, &mut rng, 6, 3).await;
        for (ni, node) in fleet.nodes.iter().enumerate() {
            let mut cfg = citrate_replay_ref::ReplayConfig::from_process(CHAIN_ID);
            cfg.ghostdag_k = spec.k;
            cfg.genesis_alloc = (0..spec.senders)
                .map(|s| {
                    let mut be = [0u8; 32];
                    U256::from(FUND).to_big_endian(&mut be);
                    (sender(s).0, be)
                })
                .collect();
            let rec = citrate_replay_ref::record_db(&node.storage.db, cfg, format!("node {ni}"))
                .expect("record");
            let report = citrate_replay_ref::replay_mergeset(&rec).expect("replay");
            assert_eq!(
                report.divergence, None,
                "seed {seed} node {ni}: node and reference diverge"
            );
            assert_eq!(
                report.matched,
                rec.chain.len() as u64 - 1,
                "seed {seed} node {ni}"
            );
            assert!(
                report.executed > 0,
                "seed {seed} node {ni}: nothing executed"
            );
            assert!(
                report.lists_compared > 0,
                "seed {seed} node {ni}: no list compared"
            );
            // Sensitivity: a wrong root at height 3 is the first divergence.
            let mut bad = rec.clone();
            if let Some(b) = bad.chain_block_mut(3) {
                b.state_root = Hash::new([0xAB; 32]);
                let bad_report = citrate_replay_ref::replay_mergeset(&bad).expect("replay");
                let d = bad_report.divergence.expect("caught");
                assert_eq!(d.height, 3, "seed {seed} node {ni}");
                assert_eq!(d.field, citrate_mergeset_ref::Field::StateRoot);
            }
        }
    }
    // The split-heal fleet's stopped-side recordings, when a split_heal run
    // kept them (`CITRATE_SPLIT_HEAL_RECORDING_DIR`, written by
    // `split_heal_tests`): each replays through the reference with no
    // divergence.
    if let Ok(dir) = std::env::var("CITRATE_SPLIT_HEAL_RECORDING_DIR") {
        let mut replayed = 0usize;
        let entries = std::fs::read_dir(&dir).expect("the recording dir is readable");
        for e in entries {
            let path = e.expect("dir entry").path();
            if path.extension().and_then(|x| x.to_str()) != Some("rec") {
                continue;
            }
            let rec = citrate_replay_ref::Recording::read_from(&path).expect("read recording");
            let report = citrate_replay_ref::replay_mergeset(&rec).expect("replay");
            assert_eq!(
                report.divergence,
                None,
                "{}: node and reference diverge",
                path.display()
            );
            assert_eq!(report.matched, report.tip_height, "{}", path.display());
            println!(
                "replay_parity_mergeset: {} matched {} chain blocks ({} executed, {} skipped)",
                path.display(),
                report.matched,
                report.executed,
                report.skipped
            );
            replayed += 1;
        }
        assert!(replayed > 0, "no split-heal recording in {dir}");
    }
}
