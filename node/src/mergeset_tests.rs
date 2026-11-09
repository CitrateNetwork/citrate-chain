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
/// A contract that stores GASLIMIT at slot 0 on every call.
const GASLIMIT_PROBE: [u8; 20] = [0xBC; 20];
const GASLIMIT_PROBE_CODE: [u8; 5] = [0x45, 0x60, 0x00, 0x55, 0x00];
/// A contract that stores BLOCKHASH(NUMBER - 1) at slot 0 and
/// BLOCKHASH(NUMBER - 2) at slot 1 on every call.
const PROBE: [u8; 20] = [0xBB; 20];
const PROBE_CODE: [u8; 19] = [
    0x43, 0x60, 0x01, 0x90, 0x03, 0x40, 0x60, 0x00, 0x55, // sstore(0, blockhash(number - 1))
    0x43, 0x60, 0x02, 0x90, 0x03, 0x40, 0x60, 0x01, 0x55, // sstore(1, blockhash(number - 2))
    0x00,
];

/// S3-3c differential contracts. COUNTER: `v = sload(0) + 1; sstore(0, v);
/// sstore(1, caller); log1(v, topic 0xAA)`, so its storage, its logs and the
/// receipts' log data depend on the execution order of the calls to it.
const COUNTER: [u8; 20] = [0xC1; 20];
const COUNTER_CODE: [u8; 25] = [
    0x60, 0x00, 0x54, 0x60, 0x01, 0x01, 0x80, 0x60, 0x00,
    0x55, // v = sload(0)+1; sstore(0, v)
    0x60, 0x00, 0x52, // mstore(0, v)
    0x33, 0x60, 0x01, 0x55, // sstore(1, caller)
    0x60, 0xAA, 0x60, 0x20, 0x60, 0x00, 0xA1, // log1(0, 32, 0xAA)
    0x00,
];
/// FORWARDER: `call(gas, 0x7F7F..7F, callvalue, 0, 0, 0, 0)`, an internal
/// value transfer (REVM's balance changes are what land it).
const FORWARDER: [u8; 20] = [0xF1; 20];
const FORWARDER_CODE: [u8; 34] = [
    0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x34, 0x73, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F,
    0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x5A, 0xF1,
    0x50, 0x00,
];
/// FACTORY: every call CREATEs a contract whose runtime code is `0x00`
/// (internal CREATE: the factory's nonce and the created code are stored by
/// the commit rules).
const FACTORY: [u8; 20] = [0xFA; 20];
const FACTORY_CODE: [u8; 23] = [
    0x69, 0x60, 0x00, 0x60, 0x00, 0x53, 0x60, 0x01, 0x60, 0x00, 0xF3, // push10 init
    0x60, 0x00, 0x52, // mstore(0, init)
    0x60, 0x0A, 0x60, 0x16, 0x60, 0x00, 0xF0, // create(0, 22, 10)
    0x50, 0x00,
];
/// SLOT_WRITER: `for i in 0..1300 { sstore(base + i, 1) }`, base = the first
/// calldata word. 1,300 fresh slots per call, about 28.8M gas: two calls fill
/// an accepting block to ~96% of ACCEPT_GAS_LIMIT.
const SLOT_WRITER: [u8; 20] = [0x5A; 20];
const SLOT_WRITER_CODE: [u8; 29] = [
    0x60, 0x00, 0x35, 0x60, 0x00, // base = calldata[0]; i = 0
    0x5B, // loop:
    0x61, 0x05, 0x14, 0x81, 0x10, 0x15, 0x60, 0x1B, 0x57, // if !(i < 1300) goto end
    0x60, 0x01, 0x82, 0x82, 0x01, 0x55, // sstore(base + i, 1)
    0x60, 0x01, 0x01, 0x60, 0x05, 0x56, // i += 1; goto loop
    0x5B, 0x00, // end: stop
];
const SLOTS_PER_CALL: usize = 1300;

/// Init code deploying a 10-byte counter (`sstore(0, sload(0) + 1)`).
const DEPLOY_INIT: [u8; 22] = [
    0x60, 0x0A, 0x60, 0x0C, 0x60, 0x00, 0x39, 0x60, 0x0A, 0x60, 0x00,
    0xF3, // codecopy; return
    0x60, 0x00, 0x54, 0x60, 0x01, 0x01, 0x60, 0x00, 0x55, 0x00,
];
/// Init code that reverts: a failed deployment.
const DEPLOY_INIT_REVERTS: [u8; 5] = [0x60, 0x00, 0x60, 0x00, 0xFD];

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
    /// [`GASLIMIT_PROBE`] deployed at genesis.
    gaslimit_probe: bool,
    /// [`COUNTER`], [`FORWARDER`] and [`FACTORY`] deployed at genesis.
    contracts: bool,
    /// [`SLOT_WRITER`] deployed at genesis.
    slot_writer: bool,
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
            gaslimit_probe: false,
            contracts: false,
            slot_writer: false,
        }
    }

    /// The contract code genesis seeds for this spec: (address, code).
    fn genesis_code(&self) -> Vec<([u8; 20], Vec<u8>)> {
        let mut out = Vec::new();
        if self.reverter {
            out.push((REVERTER, REVERTER_CODE.to_vec()));
        }
        if self.policy {
            out.push((REG, REG_CODE.to_vec()));
        }
        if self.blockhash_probe {
            out.push((PROBE, PROBE_CODE.to_vec()));
        }
        if self.gaslimit_probe {
            out.push((GASLIMIT_PROBE, GASLIMIT_PROBE_CODE.to_vec()));
        }
        if self.slot_writer {
            out.push((SLOT_WRITER, SLOT_WRITER_CODE.to_vec()));
        }
        if self.contracts {
            out.push((COUNTER, COUNTER_CODE.to_vec()));
            out.push((FORWARDER, FORWARDER_CODE.to_vec()));
            out.push((FACTORY, FACTORY_CODE.to_vec()));
        }
        out
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
    for (addr, code) in spec.genesis_code() {
        exec.set_code(&Address(addr), code);
    }
}

/// The genesis world state on a node's executor, as `start_node` lays it
/// down (`genesis::initialize_genesis_state_with_profile`): written through
/// the executor to its state store, then committed, so the store holds the
/// allocation before block 1 and block 1's undo record holds only what block
/// 1 changed.
fn seed_genesis_persisted(exec: &Executor, spec: &FleetSpec) {
    for i in 0..spec.senders {
        exec.set_balance(&sender(i), U256::from(FUND));
    }
    for (addr, code) in spec.genesis_code() {
        exec.set_code(&Address(addr), code);
    }
    exec.state_db().commit();
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
        seed_genesis_persisted(&executor, spec);
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
            .with_included_nonce_reader(crate::mergeset::included_nonce_reader(storage.clone()))
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

/// Spec 06 §3.7: inside the transactions chain block C accepts, GASLIMIT is
/// ACCEPT_GAS_LIMIT, the budget C executes them under.
#[tokio::test]
async fn gaslimit_opcode_is_the_accept_gas_limit() {
    let mut spec = FleetSpec::new(1);
    spec.gaslimit_probe = true;
    let fleet = Fleet::new(spec).await;
    let a = &fleet.nodes[0];
    let mut call = transfer(0, 0, Address(GASLIMIT_PROBE), 0, GAS_PRICE);
    call.data = vec![0x01];
    call.gas_limit = 100_000;
    assert!(a.submit(&call).await);
    let x = a.produce().await;
    assert!(x.transactions.iter().any(|t| t.hash == call.hash));
    let _c = a.produce().await;
    let j = a.receipt_json(&call.hash).expect("executed");
    assert_eq!(j["status"], true, "{j}");
    let stored = a
        .executor
        .state_db()
        .get_storage(&Address(GASLIMIT_PROBE), &[0u8; 32])
        .map(|v| U256::from_big_endian(&v))
        .unwrap_or_default();
    assert_eq!(
        stored,
        U256::from(citrate_consensus::acceptance::ACCEPT_GAS_LIMIT),
        "GASLIMIT inside an accepted mergeset"
    );
}

// ---------------------------------------------------------------------------
// S3-3c differential (spec 06 §8.3, I6): the production executor against the
// INDEPENDENT reference, on adversarial DAGs carrying contract transactions.
// ---------------------------------------------------------------------------

/// A contract-path transaction (call when `to` is set, deployment otherwise).
/// `salt` keeps two transactions that share (sender, nonce, to) distinct.
#[allow(clippy::too_many_arguments)]
fn evm_tx(
    from: u8,
    nonce: u64,
    to: Option<[u8; 20]>,
    value: u128,
    data: Vec<u8>,
    gas: u64,
    gas_price: u64,
    salt: u8,
) -> Transaction {
    let mut tx = transfer(
        from,
        nonce,
        Address(to.unwrap_or([0; 20])),
        value,
        gas_price,
    );
    tx.to = to.map(|a| embedded(Address(a)));
    tx.data = data;
    tx.gas_limit = gas;
    let mut h = *tx.hash.as_bytes();
    h[0] = 0xD0;
    h[30] = salt;
    tx.hash = Hash::new(h);
    tx
}

/// One random transaction of the differential mix, from `from` at `nonce`.
/// Every kind the production executor routes through REVM is here: calls
/// that write storage and log (order-dependent), an internal value transfer,
/// an internal CREATE, deployments that succeed and that revert, a call that
/// reverts, a call that runs out of gas; and plain transfers. Half pay a
/// priority fee (so §R' vests run through the registry's code).
fn mixed_tx(rng: &mut Rng, from: u8, nonce: u64) -> Transaction {
    let price = if rng.below(2) == 0 {
        GAS_PRICE
    } else {
        2 * GAS_PRICE
    };
    let kind = rng.below(9) as u8;
    let salt = 0x10 + kind;
    match kind {
        0 => evm_tx(
            from,
            nonce,
            Some(recipient(from).0),
            VALUE,
            vec![],
            21_000,
            price,
            salt,
        ),
        1 | 2 => evm_tx(
            from,
            nonce,
            Some(COUNTER),
            0,
            vec![0x01],
            120_000,
            price,
            salt,
        ),
        3 => evm_tx(
            from,
            nonce,
            Some(FORWARDER),
            VALUE,
            vec![0x02],
            120_000,
            price,
            salt,
        ),
        4 => evm_tx(
            from,
            nonce,
            Some(REVERTER),
            0,
            vec![0x03],
            60_000,
            price,
            salt,
        ),
        5 => evm_tx(
            from,
            nonce,
            Some(FACTORY),
            0,
            vec![0x04],
            200_000,
            price,
            salt,
        ),
        6 => evm_tx(
            from,
            nonce,
            None,
            0,
            DEPLOY_INIT.to_vec(),
            200_000,
            price,
            salt,
        ),
        7 => evm_tx(
            from,
            nonce,
            None,
            0,
            DEPLOY_INIT_REVERTS.to_vec(),
            120_000,
            price,
            salt,
        ),
        // Out of gas: 700 + intrinsic leaves no gas for the SLOAD.
        _ => evm_tx(
            from,
            nonce,
            Some(COUNTER),
            0,
            vec![0x05],
            21_800,
            price,
            salt,
        ),
    }
}

/// Rotate producers with full delivery until `min` slots passed and three
/// blocks in a row carry nothing (every pool drained), bounded.
async fn settle_fleet(fleet: &Fleet, min: u64) {
    let n = fleet.nodes.len();
    let mut empty_run = 0u64;
    for s in 0..(min + 60) {
        if s >= min && empty_run >= 3 {
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
}

/// The differential fleet's senders: 0..=3 random traffic, 4 and 5 the heavy
/// senders, 6 the double spender.
const DIFF_TRAFFIC: u8 = 4;
const HEAVY_A: u8 = 4;
const HEAVY_B: u8 = 5;
const DOUBLE_SPENDER: u8 = 6;
/// Two heavy reverting calls nearly fill ACCEPT_GAS_LIMIT (60M): the txs after
/// them in the acceptance order are skipped for gas (B3), and a sender's later
/// nonces then skip as gaps (B1) until both are re-included.
const HEAVY_GAS: u64 = 29_990_000;

/// An adversarial run for the differential (spec 06 §8.3 generator): random
/// connected slots with the mixed transactions sent to one or two pools
/// (duplicates across siblings), then a partition in which every producer
/// seals `depth` blocks alone, with a cross-partition double spend (a large
/// spend on one side, a small spend plus a follow-up on the other: the
/// follow-up then fails B2 where the large spend wins) and two heavy calls on
/// two sides; then the heal (every block to every node, shuffled: the next
/// block's mergeset holds every other side's blocks, mostly red at small K)
/// and the settle. Twice.
async fn adversarial_run(fleet: &Fleet, rng: &mut Rng, depth: u64) {
    let n = fleet.nodes.len();
    let mut next_nonce: HashMap<u8, u64> = HashMap::new();
    for round in 0..2u8 {
        // Connected slots.
        for _ in 0..3 {
            for s in 0..DIFF_TRAFFIC {
                for _ in 0..(1 + rng.below(2)) {
                    let nonce = *next_nonce.entry(s).or_insert(0);
                    let tx = mixed_tx(rng, s, nonce);
                    let mut took = false;
                    for _ in 0..(1 + rng.below(2)) {
                        let i = rng.below(n as u64) as usize;
                        took |= fleet.nodes[i].submit(&tx).await;
                    }
                    if took {
                        next_nonce.insert(s, nonce + 1);
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
        // Partition. The conflict set is placed on separate sides.
        let d = fleet.nodes[0].nonce(sender(DOUBLE_SPENDER));
        let salt = 0x40 + round;
        // Sized from the current balance (round 0's winner spent part of it).
        let bal = fleet.nodes[0].balance(sender(DOUBLE_SPENDER)).low_u128();
        let big = evm_tx(
            DOUBLE_SPENDER,
            d,
            Some(recipient(1).0),
            bal / 10 * 9,
            vec![],
            21_000,
            GAS_PRICE,
            salt,
        );
        let small = evm_tx(
            DOUBLE_SPENDER,
            d,
            Some(recipient(2).0),
            1,
            vec![],
            21_000,
            GAS_PRICE,
            salt,
        );
        let follow = evm_tx(
            DOUBLE_SPENDER,
            d + 1,
            Some(recipient(3).0),
            bal / 2,
            vec![],
            21_000,
            GAS_PRICE,
            salt,
        );
        for (i, t, what) in [
            (0, &big, "large spend"),
            (1 % n, &small, "small spend"),
            (1 % n, &follow, "follow-up"),
        ] {
            if let Err(e) = fleet.nodes[i]
                .mempool
                .add_transaction(t.clone(), TxClass::Standard)
                .await
            {
                panic!("the {what} is not pooled: {e:?}");
            }
        }
        for (i, s) in [(2 % n, HEAVY_A), (3 % n, HEAVY_B)] {
            let nonce = fleet.nodes[0].nonce(sender(s));
            assert!(
                fleet.nodes[i]
                    .submit(&reverting_call(s, nonce, HEAVY_GAS))
                    .await,
                "the heavy call of sender {s} is pooled"
            );
        }
        let mut partitioned = Vec::new();
        for _ in 0..depth {
            for (i, node) in fleet.nodes.iter().enumerate() {
                let s = (i as u8) % DIFF_TRAFFIC;
                let nonce = *next_nonce.entry(s).or_insert(0);
                let tx = mixed_tx(rng, s, nonce);
                if node.submit(&tx).await {
                    next_nonce.insert(s, nonce + 1);
                }
                if let Ok(h) = node.producer.produce_block().await {
                    if let Some(b) = node.storage.blocks.get_block(&h).expect("read") {
                        partitioned.push(b);
                    }
                }
            }
        }
        // Heal.
        for i in 0..n {
            let mut order = partitioned.clone();
            rng.shuffle(&mut order);
            fleet.deliver(i, &order).await;
        }
        settle_fleet(fleet, 4).await;
        // Traffic senders whose txs were dropped from every pool would leave
        // a permanent gap; resume from the agreed state nonce.
        for s in 0..DIFF_TRAFFIC {
            next_nonce.insert(s, fleet.nodes[0].nonce(sender(s)));
        }
    }
}

/// S3-3c (spec 06 §8.3, I6), the differential the replay parity test cannot
/// reach: the production executor (the node, end to end) and the independent
/// reference (`citrate-mergeset-ref`, its own EVM driver over revm, its own
/// GHOSTDAG, ordering, outcome classes, settlement and commitments) produce the
/// same per-chain-block state root, receipt root (status, cumulative gas, gas
/// used, logs), accepted root, gas used and accepted list, over adversarial
/// DAGs with: contract calls that write order-dependent storage and logs,
/// reverted calls and deployments, out-of-gas calls, internal value transfers
/// and CREATEs, duplicates across siblings, a cross-partition double spend,
/// balance conflicts, ACCEPT-budget overflow with the nonce gaps it opens,
/// red blocks, §R' vests into a registry with code, and deep mergesets after a
/// partition heals. The coverage of each class is asserted, so a generator
/// that stops producing one fails here.
#[tokio::test]
async fn reference_executor_matches_production_on_adversarial_dags() {
    let mut total = citrate_mergeset_ref::Report {
        matched: 0,
        lists_compared: 0,
        executed: 0,
        skipped: 0,
        skipped_nonce: 0,
        skipped_balance: 0,
        skipped_gas: 0,
        failed: 0,
        created: 0,
        logs: 0,
        max_mergeset: 0,
        reds: 0,
        tip_height: 0,
        divergence: None,
    };
    // CITRATE_NODE_DIFF_SEEDS widens the run (default 3 seeds; each is a
    // 4-node fleet, about 20 s).
    let seeds: u64 = std::env::var("CITRATE_NODE_DIFF_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    for seed in 31..31 + seeds {
        let mut spec = FleetSpec::new(4);
        spec.senders = 7;
        spec.k = 1;
        spec.policy = true;
        spec.reverter = true;
        spec.contracts = true;
        let fleet = Fleet::new(spec.clone()).await;
        let mut rng = Rng(seed);
        adversarial_run(&fleet, &mut rng, 4).await;
        let roots: HashSet<Hash> = fleet
            .nodes
            .iter()
            .map(|n| n.executor.calculate_state_root())
            .collect();
        assert_eq!(
            roots.len(),
            1,
            "seed {seed}: the nodes disagree on the state"
        );
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
            cfg.genesis_code = spec.genesis_code();
            cfg.validator_activation_height = Some(1);
            cfg.reward_policy = Some(citrate_replay_ref::RecordedRewardPolicy::from_policy(
                &policy(&spec),
            ));
            let rec = citrate_replay_ref::record_db(&node.storage.db, cfg, format!("node {ni}"))
                .expect("record");
            let report = citrate_replay_ref::replay_mergeset(&rec).expect("replay");
            assert_eq!(
                report.divergence, None,
                "seed {seed} node {ni}: the production executor and the reference diverge"
            );
            assert_eq!(
                report.matched,
                rec.chain.len() as u64 - 1,
                "seed {seed} node {ni}: every chain block compared"
            );
            // A chain block that executed nothing indexes no list; every
            // other one is compared entry by entry.
            assert!(
                report.lists_compared > 0,
                "seed {seed} node {ni}: no accepted list compared"
            );
            println!("seed {seed} node {ni}: {report:?}");
            total.matched += report.matched;
            total.executed += report.executed;
            total.skipped += report.skipped;
            total.skipped_nonce += report.skipped_nonce;
            total.skipped_balance += report.skipped_balance;
            total.skipped_gas += report.skipped_gas;
            total.failed += report.failed;
            total.created += report.created;
            total.logs += report.logs;
            total.reds += report.reds;
            total.max_mergeset = total.max_mergeset.max(report.max_mergeset);
        }
    }
    // Coverage: every adversarial class reached the comparison.
    println!("differential totals: {total:?}");
    assert!(
        total.failed > 0,
        "no reverted / failed tx compared: {total:?}"
    );
    assert!(
        total.created > 0,
        "no contract creation compared: {total:?}"
    );
    assert!(total.logs > 0, "no log compared: {total:?}");
    assert!(total.reds > 0, "no red block accepted: {total:?}");
    assert!(
        total.skipped_nonce > 0,
        "no duplicate / double spend / gap skip: {total:?}"
    );
    assert!(
        total.skipped_balance > 0,
        "no balance-conflict skip: {total:?}"
    );
    assert!(total.skipped_gas > 0, "no ACCEPT-budget skip: {total:?}");
    assert!(total.max_mergeset >= 8, "no deep mergeset: {total:?}");
}

// ---------------------------------------------------------------------------
// S3-3b: disqualified from chain (spec 06 §3.10, D11).
// ---------------------------------------------------------------------------

/// `b` re-sealed by producer `i` after `edit`: hash recomputed, signature
/// remade. A block whose own commitments lie, or one built on such a block,
/// as a dishonest producer would send it.
fn resealed(b: &Block, i: u8, edit: impl FnOnce(&mut Block)) -> Block {
    let mut x = b.clone();
    edit(&mut x);
    x.header.block_hash = x.compute_hash();
    x.signature = citrate_consensus::crypto::sign_block(&x.header.block_hash, &signing_key(i));
    x
}

fn with_wrong_state_root(b: &Block, i: u8) -> Block {
    resealed(b, i, |x| x.state_root = Hash::new([0xBA; 32]))
}

/// A chain block whose state root is wrong is admitted to the DAG (admission
/// never executes) and is disqualified when the applied chain reaches it:
/// the mark is persisted, the node stays on its last valid chain block and
/// keeps sealing on it, and the bad block is still a DAG block: once the
/// node's chain outweighs it, a block merges it and executes its own txs.
#[tokio::test]
async fn wrong_state_root_disqualifies_from_chain_not_from_dag() {
    let fleet = Fleet::new(FleetSpec::new(2)).await;
    let (a, b) = (&fleet.nodes[0], &fleet.nodes[1]);
    let t = transfer(0, 0, recipient(0), VALUE, GAS_PRICE);
    assert!(a.submit(&t).await);
    let a1 = a.produce().await;
    b.receive(&a1).await;
    let u = transfer(1, 0, recipient(1), VALUE, GAS_PRICE);
    assert!(a.submit(&u).await);
    let a2 = a.produce().await;
    assert!(a2.transactions.iter().any(|x| x.hash == u.hash));
    let x = with_wrong_state_root(&a2, 0);
    let xh = x.header.block_hash;
    assert!(b.offer(&x).await, "admission never executes: x is admitted");
    assert_eq!(b.tip().await.0, a1.header.block_hash, "x is never applied");
    assert!(
        b.ghostdag.is_disqualified(&xh),
        "x is disqualified from chain"
    );
    assert!(
        b.storage.blocks.get_block(&xh).expect("read").is_some(),
        "x stays a DAG block"
    );
    // Persisted: a reload of the DAG store sees the mark.
    let kv = Arc::new(crate::persistent_dag::RocksDbKvStore::new(
        b.storage.db.clone(),
    ));
    let reloaded = DagStore::persistent_with_strict_vrf(kv, true).expect("reload");
    assert!(reloaded.is_disqualified(&xh), "the mark survives a restart");
    // B keeps sealing on its applied tip. x can be merged only by a block
    // whose selected parent outweighs it (G3), so once B's own chain is
    // heavier one of its blocks merges x and executes x's own tx.
    let m = b.produce().await;
    assert_eq!(m.header.selected_parent_hash, a1.header.block_hash);
    assert!(!b.ghostdag.is_disqualified(&m.header.block_hash));
    let mut merger = None;
    for _ in 0..3 {
        let next = b.produce().await;
        assert_eq!(
            b.tip().await.0,
            next.header.block_hash,
            "B extends its own chain"
        );
        if next.header.merge_parent_hashes.contains(&xh) {
            merger = Some(next);
            break;
        }
    }
    let merger = merger.expect("x is merged once B's chain outweighs it");
    let j = b
        .receipt_json(&u.hash)
        .expect("x's tx is executed once x is merged");
    assert_eq!(
        j["acceptance"]["including_block_hash"],
        serde_json::to_value(xh).expect("j"),
        "included by x"
    );
    assert_eq!(
        j["block_hash"],
        serde_json::to_value(merger.header.block_hash).expect("j"),
        "accepted by the block that merges x"
    );
}

/// Fork choice never names a disqualified block: a lone disqualified tip
/// yields its last valid selected-chain ancestor (no reorg attempt that can
/// only fail), and with a valid sibling the sibling wins and is applied.
#[tokio::test]
async fn disqualified_tip_is_skipped_by_fork_choice() {
    let fleet = Fleet::new(FleetSpec::new(3)).await;
    let (a, b, c) = (&fleet.nodes[0], &fleet.nodes[1], &fleet.nodes[2]);
    let a1 = a.produce().await;
    b.receive(&a1).await;
    c.receive(&a1).await;
    let x = with_wrong_state_root(&a.produce().await, 0);
    b.receive(&x).await;
    assert_eq!(
        b.ghostdag.select_tip().await.expect("a head"),
        a1.header.block_hash,
        "a lone disqualified tip yields its last valid ancestor"
    );
    let c2 = c.produce().await;
    assert_eq!(c2.header.selected_parent_hash, a1.header.block_hash);
    b.receive(&c2).await;
    assert_eq!(
        b.ghostdag.select_tip().await.expect("a head"),
        c2.header.block_hash,
        "the valid sibling wins"
    );
    assert_eq!(b.tip().await.0, c2.header.block_hash, "and is applied");
}

/// A block whose selected parent is disqualified is disqualified too: it is
/// admitted (a DAG block) and inherits the mark, and fork choice and the
/// producer stay on the last valid chain block.
#[tokio::test]
async fn child_of_disqualified_sp_is_disqualified() {
    let fleet = Fleet::new(FleetSpec::new(2)).await;
    let (a, b) = (&fleet.nodes[0], &fleet.nodes[1]);
    let a1 = a.produce().await;
    b.receive(&a1).await;
    let a2 = a.produce().await;
    let x = with_wrong_state_root(&a2, 0);
    let a3 = a.produce().await;
    assert_eq!(a3.header.selected_parent_hash, a2.header.block_hash);
    let y = resealed(&a3, 0, |y| {
        y.header.selected_parent_hash = x.header.block_hash
    });
    // After the mark.
    b.receive(&x).await;
    assert!(b.ghostdag.is_disqualified(&x.header.block_hash));
    assert!(b.offer(&y).await, "y is admitted");
    assert!(
        b.ghostdag.is_disqualified(&y.header.block_hash),
        "y inherits the mark at admission"
    );
    assert_eq!(b.tip().await.0, a1.header.block_hash);
    // Fork choice never returns to the marked branch, and B seals on a1.
    assert_eq!(
        b.ghostdag.select_tip().await.expect("a head"),
        a1.header.block_hash
    );
    let m = b.produce().await;
    assert_eq!(m.header.selected_parent_hash, a1.header.block_hash);
    // Propagation to descendants held BEFORE the mark is covered by the
    // consensus test `disqualify_propagates_to_selected_parent_descendants`
    // (admission applies on receipt here, so x is always marked before y can
    // be admitted).
}

// ---------------------------------------------------------------------------
// S3-3b: undo records at ACCEPT_GAS_LIMIT, and reorg reversibility (I7).
// ---------------------------------------------------------------------------

/// A call to [`SLOT_WRITER`] writing slots `base..base + 1300`.
fn slot_writer_call(from: u8, nonce: u64, base: u64) -> Transaction {
    let mut tx = transfer(from, nonce, Address(SLOT_WRITER), 0, GAS_PRICE);
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&base.to_be_bytes());
    tx.data = word.to_vec();
    tx.gas_limit = 29_990_000;
    tx.hash = Hash::new({
        let mut h = *tx.hash.as_bytes();
        h[0] = 0x5A;
        h
    });
    tx
}

/// Spec 06 §4.2 (S3-4, reviewer R9): an accepting block that executes close
/// to ACCEPT_GAS_LIMIT of fresh storage writes keeps its undo record, whole:
/// one storage pre-image per slot it wrote and the senders' account
/// pre-images. The record is never dropped for its size (H6). A reorg off the
/// block then gives exactly the winning chain's state.
#[tokio::test]
async fn undo_record_never_dropped_at_accept_gas_limit() {
    let mut spec = FleetSpec::new(3);
    spec.slot_writer = true;
    let fleet = Fleet::new(spec).await;
    let (a, b, c) = (&fleet.nodes[0], &fleet.nodes[1], &fleet.nodes[2]);
    assert!(a.submit(&slot_writer_call(0, 0, 0)).await);
    assert!(b.submit(&slot_writer_call(1, 0, 10_000)).await);
    let a1 = a.produce().await;
    let b1 = b.produce().await;
    assert_eq!(a1.transactions.len(), 1);
    assert_eq!(b1.transactions.len(), 1);
    a.receive(&b1).await;
    let m = a.produce().await;
    let accept = citrate_consensus::acceptance::ACCEPT_GAS_LIMIT;
    assert!(
        m.header.gas_used > accept / 10 * 9 && m.header.gas_used <= accept,
        "m executes close to ACCEPT_GAS_LIMIT: {}",
        m.header.gas_used
    );
    let rec = a
        .storage
        .state
        .get_reorg_undo(m.header.height)
        .expect("read")
        .expect("the record of a block at ACCEPT_GAS_LIMIT is kept");
    assert_eq!(rec.hash, m.header.block_hash);
    assert_eq!(
        rec.storage.len(),
        2 * SLOTS_PER_CALL,
        "one pre-image per slot written"
    );
    assert!(
        rec.storage
            .iter()
            .all(|(addr, _, pre)| *addr == Address(SLOT_WRITER) && pre.is_none()),
        "fresh slots: no pre-value"
    );
    for s in [sender(0), sender(1)] {
        assert!(
            rec.accounts.iter().any(|p| p.0 == s),
            "the sender {s} has an account pre-image"
        );
    }
    // A heavier chain that never saw a1, b1 or m: A reorgs off m.
    let mut cs = Vec::new();
    for _ in 0..4 {
        cs.push(c.produce().await);
    }
    for blk in &cs {
        a.receive(blk).await;
    }
    assert_eq!(a.tip().await.0, cs[3].header.block_hash, "A reorged off m");
    assert_eq!(
        a.executor.calculate_state_root(),
        c.executor.calculate_state_root(),
        "m's writes are undone exactly"
    );
}

/// Spec 06 §8.1 I7: applying chain A, reorging to B, then back to A gives
/// exactly what a fresh apply of A gives: the state, the receipts and
/// accepted lists, and the undo records of every height.
#[tokio::test]
async fn reorg_round_trip_equals_fresh_apply() {
    let spec = FleetSpec::new(2);
    let fleet = Fleet::new(spec.clone()).await;
    let (a, b) = (&fleet.nodes[0], &fleet.nodes[1]);
    // A's branch carries sender 0's txs, B's branch sender 1's.
    let mut a_blocks = Vec::new();
    let mut b_blocks = Vec::new();
    for n in 0..2u64 {
        assert!(
            a.submit(&transfer(0, n, recipient(0), VALUE, GAS_PRICE))
                .await
        );
        a_blocks.push(a.produce().await);
    }
    for n in 0..3u64 {
        assert!(
            b.submit(&transfer(1, n, recipient(1), VALUE, GAS_PRICE))
                .await
        );
        b_blocks.push(b.produce().await);
    }
    for n in 2..5u64 {
        assert!(
            a.submit(&transfer(0, n, recipient(0), VALUE, GAS_PRICE))
                .await
        );
        a_blocks.push(a.produce().await);
    }
    // The round trip: A's first two, then B's heavier three, then A's five.
    let r = MNode::start(7, &spec, &fleet.genesis).await;
    for blk in &a_blocks[..2] {
        r.receive(blk).await;
    }
    assert_eq!(r.tip().await.0, a_blocks[1].header.block_hash);
    for blk in &b_blocks {
        r.receive(blk).await;
    }
    assert_eq!(r.tip().await.0, b_blocks[2].header.block_hash, "A -> B");
    for blk in &a_blocks[2..] {
        r.receive(blk).await;
    }
    assert_eq!(r.tip().await.0, a_blocks[4].header.block_hash, "B -> A");
    // A fresh node that only ever saw A's chain.
    let f = MNode::start(8, &spec, &fleet.genesis).await;
    for blk in &a_blocks {
        f.receive(blk).await;
    }
    assert_eq!(f.chain().await, r.chain().await);
    assert_eq!(
        r.executor.calculate_state_root(),
        f.executor.calculate_state_root(),
        "state"
    );
    for blk in &a_blocks {
        assert_eq!(
            r.accepted_list(&blk.header.block_hash),
            f.accepted_list(&blk.header.block_hash),
            "accepted list of {}",
            blk.header.block_hash
        );
        for t in &blk.transactions {
            assert_eq!(
                r.receipt_json(&t.hash),
                f.receipt_json(&t.hash),
                "receipt of {}",
                t.hash
            );
        }
        let h = blk.header.height;
        assert_eq!(
            r.storage.state.get_reorg_undo(h).expect("read"),
            f.storage.state.get_reorg_undo(h).expect("read"),
            "undo record at {h}"
        );
    }
    for blk in &b_blocks {
        for t in &blk.transactions {
            assert!(
                r.receipt_json(&t.hash).is_none(),
                "B's tx {} is not executed on A's chain",
                t.hash
            );
        }
    }
    assert_eq!(r.nonce(sender(1)), 0, "B's sender is untouched");
    assert_eq!(r.nonce(sender(0)), f.nonce(sender(0)));
}

// ---------------------------------------------------------------------------
// Mempool nonce window under mergeset execution (lead decision 2026-11-09).
// The 16-ahead window counts from the sender's highest INCLUDED nonce on the
// applied chain (contiguous from its committed nonce), not from the committed
// nonce alone, which lags inclusion by one block under spec 06 D6.
// ---------------------------------------------------------------------------

/// The Rule 6 pattern that the committed-nonce window refused (64 signers at
/// about 4.7 tx/s each, so about 10 new txs per sender per block): every
/// submission is admitted while earlier ones wait in an included,
/// not-yet-accepted block, and all of them execute.
#[tokio::test]
async fn high_rate_sender_is_not_refused_while_its_txs_await_acceptance() {
    let fleet = Fleet::new(FleetSpec::new(1)).await;
    let a = &fleet.nodes[0];
    const PER_BLOCK: u64 = 10;
    const SLOTS: u64 = 6;
    for slot in 0..SLOTS {
        for k in 0..PER_BLOCK {
            let n = slot * PER_BLOCK + k;
            let tx = transfer(0, n, recipient(0), VALUE, GAS_PRICE);
            if let Err(e) = a.mempool.add_transaction(tx, TxClass::Standard).await {
                panic!(
                    "slot {slot}: nonce {n} refused (committed {}): {e:?}",
                    a.nonce(sender(0))
                );
            }
        }
        let blk = a.produce().await;
        assert_eq!(
            blk.transactions.len() as u64,
            PER_BLOCK,
            "slot {slot}: the block includes the sender's next ten"
        );
    }
    for _ in 0..2 {
        a.produce().await;
    }
    assert_eq!(
        a.nonce(sender(0)),
        SLOTS * PER_BLOCK,
        "every tx executed once"
    );
}

/// The window keeps its anti-spam bound (at most 16 beyond what the applied
/// chain includes) and follows a reorg: when the block that included a
/// sender's txs leaves the applied chain, the window falls back to the
/// committed nonce.
#[tokio::test]
async fn nonce_window_is_bounded_by_the_included_run_and_follows_reorgs() {
    let fleet = Fleet::new(FleetSpec::new(2)).await;
    let (a, b) = (&fleet.nodes[0], &fleet.nodes[1]);
    let submit = |n: u64| async move {
        a.mempool
            .add_transaction(
                transfer(0, n, recipient(0), VALUE, GAS_PRICE),
                TxClass::Standard,
            )
            .await
    };
    for n in 0..10 {
        submit(n).await.expect("within the committed window");
    }
    let a1 = a.produce().await;
    assert_eq!(a1.transactions.len(), 10);
    assert_eq!(a.nonce(sender(0)), 0, "included, not yet accepted");
    // Included run 0..=9: the window is 10..=26.
    assert!(
        submit(27).await.is_err(),
        "17 beyond the included run is refused"
    );
    submit(20).await.expect("within 16 of the included run");
    // B never saw a1 and outgrows it; A reorgs and a1 leaves its chain.
    let b1 = b.produce().await;
    let b2 = b.produce().await;
    a.receive(&b1).await;
    a.receive(&b2).await;
    assert_eq!(a.tip().await.0, b2.header.block_hash, "A reorged onto B");
    assert_eq!(a.nonce(sender(0)), 0);
    // Nothing of sender 0 is included on the applied chain now.
    assert!(
        submit(18).await.is_err(),
        "the window is the committed nonce again: 18 is 18 ahead of 0"
    );
    submit(16).await.expect("16 ahead of the committed nonce");
}
