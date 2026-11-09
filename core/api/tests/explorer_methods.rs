// citrate/core/api/tests/explorer_methods.rs
//
// S3-7 (CNV-RPC) conformance tests for the read-only RPC the explorer needs
// (planset 02 §3, spec 06 §5). Two fixtures:
//
// * `executed_chain()`: a real chain of four blocks executed by a real
//   `Executor` over a real `StorageManager` (state, undo records, receipts,
//   canonical index all written by `apply_block`). Block 1 deploys a factory,
//   block 2 sends value and calls the factory (an internal CREATE), block 3
//   sends value again. Used for historical state, receipts, the accepting
//   block, the tracers and the creator lookup.
// * `dag_fixture()`: stored headers only, with siblings, a side branch and
//   persisted GHOSTDAG records, for the DAG methods.

use citrate_api::eth_rpc::register_eth_methods_with_finality;
use citrate_api::state_tag::HISTORICAL_STATE_CODE;
use citrate_api::FilterRegistry;
use citrate_consensus::checkpoint::{Checkpoint, CheckpointStatus};
use citrate_consensus::hardening::PbaHardening;
use citrate_consensus::types::{
    Block, BlockBuilder, GhostdagData, Hash, PublicKey, Signature, Transaction, VrfProof,
};
use citrate_execution::executor::fixed_reward;
use citrate_execution::{address_utils, Executor, StateDB};
use citrate_sequencer::mempool::{Mempool, MempoolConfig};
use citrate_storage::db::column_families::{CF_DAG_GHOSTDAG, CF_DAG_METADATA, CF_METADATA};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use primitive_types::U256;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tempfile::TempDir;

const CHAIN: u64 = 40204;
const A: [u8; 20] = [0xAA; 20];
const B: [u8; 20] = [0xBB; 20];
const COINBASE: [u8; 20] = [0x77; 20];

// Child init code: returns the 1-byte runtime 0x00 (STOP).
//   PUSH1 1 PUSH1 0x0c PUSH1 0 CODECOPY PUSH1 1 PUSH1 0 RETURN | 00
const CHILD_INIT: &str = "6001600c60003960016000f300";

/// Factory runtime: with 32 bytes of calldata, return slot 0; otherwise
/// CREATE a child (CHILD_INIT) and store its address in slot 0.
fn factory_runtime() -> Vec<u8> {
    // CALLDATASIZE PUSH1 0x20 EQ PUSH1 0x23 JUMPI
    let mut c = vec![0x36, 0x60, 0x20, 0x14, 0x60, 0x23, 0x57];
    // PUSH13 <child init> PUSH1 0 MSTORE
    c.push(0x6c);
    c.extend_from_slice(&hex::decode(CHILD_INIT).expect("child init hex"));
    c.extend_from_slice(&[0x60, 0x00, 0x52]);
    // PUSH1 13 (size) PUSH1 19 (offset) PUSH1 0 (value) CREATE
    c.extend_from_slice(&[0x60, 0x0d, 0x60, 0x13, 0x60, 0x00, 0xf0]);
    // PUSH1 0 SSTORE STOP
    c.extend_from_slice(&[0x60, 0x00, 0x55, 0x00]);
    assert_eq!(c.len(), 0x23, "the read branch starts at 0x23");
    // JUMPDEST PUSH1 0 SLOAD PUSH1 0 MSTORE PUSH1 32 PUSH1 0 RETURN
    c.extend_from_slice(&[
        0x5b, 0x60, 0x00, 0x54, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
    ]);
    c
}

fn factory_init() -> Vec<u8> {
    let rt = factory_runtime();
    let len = u8::try_from(rt.len()).expect("short runtime");
    // PUSH1 len PUSH1 0x0c PUSH1 0 CODECOPY PUSH1 len PUSH1 0 RETURN
    let mut c = vec![
        0x60, len, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, len, 0x60, 0x00, 0xf3,
    ];
    c.extend_from_slice(&rt);
    c
}

fn embedded(addr: [u8; 20]) -> PublicKey {
    let mut b = [0u8; 32];
    b[..20].copy_from_slice(&addr);
    PublicKey::new(b)
}

fn hx(h: &Hash) -> String {
    format!("0x{}", hex::encode(h.as_bytes()))
}

fn ax(a: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(a))
}

fn tx(tag: u8, nonce: u64, to: Option<[u8; 20]>, value: u128, data: Vec<u8>) -> Transaction {
    Transaction {
        hash: Hash::new([tag; 32]),
        nonce,
        from: embedded(A),
        to: to.map(embedded),
        value,
        gas_limit: 1_000_000,
        gas_price: 1_000_000_000,
        data,
        signature: Signature::new([0u8; 64]),
        chain_id: Some(CHAIN),
        ..Default::default()
    }
}

fn template(height: u64, parent: Hash, txs: Vec<Transaction>, root: Hash) -> Block {
    let mut b = BlockBuilder::new()
        .version(2)
        .height(height)
        .parent(parent)
        .coinbase(COINBASE)
        .timestamp(1_700_000_000 + height)
        .vrf_reveal(VrfProof {
            proof: vec![1],
            output: Hash::new([0x50 + height as u8; 32]),
        })
        .transactions(txs)
        .state_root(root)
        .build_unhashed();
    b.header.block_hash = b.compute_hash();
    b
}

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime")
    })
}

struct Chain {
    storage: Arc<StorageManager>,
    executor: Arc<Executor>,
    io: jsonrpc_core::IoHandler,
    blocks: Vec<Block>,
    factory: [u8; 20],
    child: [u8; 20],
    deploy_tx: Hash,
    create_tx: Hash,
    _tmp: TempDir,
}

/// Execute `txs` on the producer, seal the block with its root, store it,
/// and apply it on the node's executor (state, undo record, receipts, tip).
async fn produce(
    producer: &Executor,
    node: &Executor,
    storage: &StorageManager,
    height: u64,
    parent: Hash,
    txs: Vec<Transaction>,
) -> Block {
    let draft = template(height, parent, txs.clone(), Hash::default());
    producer.set_block_context(citrate_execution::revm_adapter::BlockContext {
        coinbase: COINBASE,
        prevrandao: *draft.header.vrf_reveal.output.as_bytes(),
        block_hashes: HashMap::new(),
    });
    let mut receipts = Vec::new();
    for t in &draft.transactions {
        receipts.push(
            producer
                .execute_transaction(&draft, t)
                .await
                .expect("executes"),
        );
    }
    producer
        .settle_block_rewards(
            height,
            COINBASE,
            *draft.header.proposer_pubkey.as_bytes(),
            draft.header.base_fee_per_gas,
            &draft.transactions,
            &receipts,
            &[],
        )
        .await
        .expect("settle");
    let block = template(height, parent, txs, producer.calculate_state_root());
    storage.blocks.put_block(&block).expect("store block");
    node.apply_block(&block, COINBASE, &fixed_reward(&[]))
        .await
        .expect("the node applies the block");
    block
}

fn executed_chain() -> Chain {
    std::env::set_var("CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT", "1");
    let tmp = TempDir::new().expect("tempdir");
    let storage =
        Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).expect("storage"));
    let node = Arc::new(Executor::with_storage_and_chain_id(
        Arc::new(StateDB::new()),
        Some(storage.state.clone()),
        CHAIN,
    ));
    let producer = Executor::with_chain_id(Arc::new(StateDB::new()), CHAIN);
    for e in [&*node, &producer] {
        e.set_pba_hardening(PbaHardening::off());
        e.set_balance(
            &address_utils::normalize_address(&embedded(A)),
            U256::from(1_000_000_000_000_000_000_000u128),
        );
    }
    let genesis = template(0, Hash::default(), vec![], producer.calculate_state_root());
    storage.blocks.put_block(&genesis).expect("genesis");
    storage
        .blocks
        .put_applied_tip(&genesis.header.block_hash, 0)
        .expect("genesis tip");

    let rt = runtime();
    let deploy = tx(0x11, 0, None, 0, factory_init());
    let b1 = rt.block_on(produce(
        &producer,
        &node,
        &storage,
        1,
        genesis.header.block_hash,
        vec![deploy.clone()],
    ));
    let receipt = storage
        .transactions
        .get_receipt(&deploy.hash)
        .expect("read")
        .expect("deploy receipt");
    assert!(receipt.status, "the factory deploys");
    let factory: [u8; 20] = receipt
        .output
        .as_slice()
        .try_into()
        .expect("20-byte address");

    let send = tx(0x21, 1, Some(B), 5, vec![]);
    let create = tx(0x22, 2, Some(factory), 0, vec![0x01]);
    let b2 = rt.block_on(produce(
        &producer,
        &node,
        &storage,
        2,
        b1.header.block_hash,
        vec![send, create.clone()],
    ));
    let send2 = tx(0x31, 3, Some(B), 7, vec![]);
    let b3 = rt.block_on(produce(
        &producer,
        &node,
        &storage,
        3,
        b2.header.block_hash,
        vec![send2],
    ));

    let slot0 = storage
        .state
        .get_storage(&citrate_execution::types::Address(factory), &[0u8; 32])
        .expect("read")
        .expect("the factory stored the child");
    let mut child = [0u8; 20];
    child.copy_from_slice(&slot0[slot0.len() - 20..]);

    let mut io = jsonrpc_core::IoHandler::new();
    register_eth_methods_with_finality(
        &mut io,
        storage.clone(),
        Arc::new(Mempool::new(MempoolConfig::default())),
        node.clone(),
        CHAIN,
        Arc::new(FilterRegistry::new()),
        None,
        Arc::new(AtomicU64::new(0)),
    );
    Chain {
        storage,
        executor: node,
        io,
        blocks: vec![genesis, b1, b2, b3],
        factory,
        child,
        deploy_tx: deploy.hash,
        create_tx: create.hash,
        _tmp: tmp,
    }
}

fn call(io: &jsonrpc_core::IoHandler, method: &str, params: Value) -> Value {
    let _rt = runtime().enter();
    let req = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
    let resp = io.handle_request_sync(&req).expect("response");
    serde_json::from_str(&resp).expect("json")
}

fn result(io: &jsonrpc_core::IoHandler, method: &str, params: Value) -> Value {
    let v = call(io, method, params.clone());
    assert!(v.get("error").is_none(), "{method} {params}: {v}");
    v["result"].clone()
}

fn word(addr: &[u8; 20]) -> String {
    format!("0x{}{}", "0".repeat(24), hex::encode(addr))
}

// ── 8. historical state ──────────────────────────────────────────────────

#[test]
fn historical_balance_nonce_code_and_storage_at_past_blocks() {
    let c = executed_chain();
    let bal = |n: &str| result(&c.io, "eth_getBalance", json!([ax(&B), n]));
    assert_eq!(bal("0x0"), "0x0");
    assert_eq!(bal("0x1"), "0x0");
    assert_eq!(bal("0x2"), "0x5");
    assert_eq!(bal("0x3"), "0xc");
    assert_eq!(bal("latest"), "0xc");
    // By hash, and as an EIP-1898 object.
    assert_eq!(
        result(
            &c.io,
            "eth_getBalance",
            json!([ax(&B), hx(&c.blocks[2].header.block_hash)])
        ),
        "0x5"
    );
    assert_eq!(
        result(
            &c.io,
            "eth_getBalance",
            json!([ax(&B), {"blockHash": hx(&c.blocks[1].header.block_hash)}])
        ),
        "0x0"
    );
    let nonce = |n: &str| result(&c.io, "eth_getTransactionCount", json!([ax(&A), n]));
    assert_eq!(nonce("0x0"), "0x0");
    assert_eq!(nonce("0x1"), "0x1");
    assert_eq!(nonce("0x2"), "0x3");
    let code = |a: &[u8; 20], n: &str| result(&c.io, "eth_getCode", json!([ax(a), n]));
    assert_eq!(code(&c.factory, "0x0"), "0x");
    assert_eq!(
        code(&c.factory, "0x1"),
        format!("0x{}", hex::encode(factory_runtime()))
    );
    assert_eq!(code(&c.child, "0x1"), "0x");
    // The child's code as the chain stores it (the code store's encoding),
    // the same bytes the head serves.
    let child_now = code(&c.child, "latest");
    assert_ne!(child_now, "0x");
    assert_eq!(code(&c.child, "0x2"), child_now);
    let slot = |n: &str| result(&c.io, "eth_getStorageAt", json!([ax(&c.factory), "0x0", n]));
    assert_eq!(slot("0x1"), format!("0x{}", "0".repeat(64)));
    assert_eq!(slot("0x2"), word(&c.child));
}

#[test]
fn historical_eth_call_runs_on_the_named_blocks_state() {
    let c = executed_chain();
    let read =
        json!({"from": ax(&A), "to": ax(&c.factory), "data": format!("0x{}", "00".repeat(32))});
    assert_eq!(
        result(&c.io, "eth_call", json!([read.clone(), "0x1"])),
        format!("0x{}", "0".repeat(64)),
        "before block 2 the factory has created nothing"
    );
    assert_eq!(
        result(&c.io, "eth_call", json!([read.clone(), "0x2"])),
        word(&c.child)
    );
    assert_eq!(
        result(&c.io, "eth_call", json!([read, "latest"])),
        word(&c.child)
    );
}

#[test]
fn historical_reads_fail_closed_without_an_undo_record() {
    let c = executed_chain();
    let mut key = b"reorg_undo:".to_vec();
    key.extend_from_slice(&2u64.to_be_bytes());
    c.storage
        .db
        .delete_cf(CF_METADATA, &key)
        .expect("drop record 2");
    for (m, p) in [
        ("eth_getBalance", json!([ax(&B), "0x1"])),
        ("eth_getStorageAt", json!([ax(&c.factory), "0x0", "0x1"])),
        (
            "eth_call",
            json!([{"from": ax(&A), "to": ax(&c.factory), "data": format!("0x{}", "00".repeat(32))}, "0x1"]),
        ),
    ] {
        let v = call(&c.io, m, p);
        assert_eq!(v["error"]["code"], HISTORICAL_STATE_CODE, "{m}: {v}");
        assert!(
            v["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("undo record"),
            "{m} says why: {v}"
        );
    }
    // Above the dropped record the state is still served.
    assert_eq!(
        result(&c.io, "eth_getBalance", json!([ax(&B), "0x2"])),
        "0x5"
    );
}

// ── 7. eth_getBlockReceipts ──────────────────────────────────────────────

#[test]
fn block_receipts_have_running_cumulative_gas_and_indices() {
    let c = executed_chain();
    let r = result(&c.io, "eth_getBlockReceipts", json!(["0x2"]));
    let arr = r.as_array().expect("array");
    assert_eq!(arr.len(), 2);
    let g0 = u64::from_str_radix(arr[0]["gasUsed"].as_str().expect("gas")[2..].as_ref(), 16)
        .expect("hex");
    let g1 = u64::from_str_radix(arr[1]["gasUsed"].as_str().expect("gas")[2..].as_ref(), 16)
        .expect("hex");
    assert_eq!(arr[0]["cumulativeGasUsed"], format!("0x{g0:x}"));
    assert_eq!(arr[1]["cumulativeGasUsed"], format!("0x{:x}", g0 + g1));
    assert_eq!(arr[0]["transactionIndex"], "0x0");
    assert_eq!(arr[1]["transactionIndex"], "0x1");
    assert_eq!(arr[1]["transactionHash"], hx(&c.create_tx));
    assert_eq!(arr[0]["blockHash"], hx(&c.blocks[2].header.block_hash));
    assert_eq!(arr[0]["logsBloom"].as_str().expect("bloom").len(), 2 + 512);
    // By hash; latest; a deploy carries its contract address.
    let by_hash = result(
        &c.io,
        "eth_getBlockReceipts",
        json!([hx(&c.blocks[2].header.block_hash)]),
    );
    assert_eq!(by_hash, r);
    assert_eq!(
        result(&c.io, "eth_getBlockReceipts", json!(["latest"]))
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    let b1 = result(&c.io, "eth_getBlockReceipts", json!(["0x1"]));
    assert_eq!(b1[0]["contractAddress"], ax(&c.factory));
    // Above the head: null.
    assert!(result(&c.io, "eth_getBlockReceipts", json!(["0x9"])).is_null());
}

// ── 4. citrate_getAcceptingBlock ─────────────────────────────────────────

#[test]
fn accepting_block_names_the_executing_chain_block() {
    let c = executed_chain();
    let r = result(
        &c.io,
        "citrate_getAcceptingBlock",
        json!([hx(&c.create_tx)]),
    );
    assert_eq!(r["acceptingBlockHash"], hx(&c.blocks[2].header.block_hash));
    assert_eq!(r["acceptingHeight"], "0x2");
    assert_eq!(r["semantics"], "including-chain-block");
    assert_eq!(r["inclusions"][0]["outcome"], "executed");
    // Spec 06 §5.4 colour: before S3-3b the including block is the chain
    // block itself, which the explorer renders as a chain block.
    assert_eq!(r["inclusions"][0]["color"], "selected_parent", "{r}");
    assert_eq!(r["inclusionsComplete"], false);
    let none = result(
        &c.io,
        "citrate_getAcceptingBlock",
        json!([hx(&Hash::new([0xEE; 32]))]),
    );
    assert!(none["acceptingBlockHash"].is_null());
    assert_eq!(none["inclusions"], json!([]));
}

// ── 9. tracers and the creator lookup ────────────────────────────────────

#[test]
fn call_tracer_shows_the_factory_create() {
    let c = executed_chain();
    let t = result(
        &c.io,
        "debug_traceTransaction",
        json!([hx(&c.create_tx), {"tracer": "callTracer"}]),
    );
    assert_eq!(t["type"], "CALL", "{t}");
    assert_eq!(t["from"], ax(&A));
    assert_eq!(t["to"], ax(&c.factory));
    assert_eq!(
        t["calls"].as_array().map(Vec::len),
        Some(1),
        "one subcall, from the committed attempt only: {t}"
    );
    let inner = &t["calls"][0];
    assert_eq!(inner["type"], "CREATE", "{t}");
    assert_eq!(inner["from"], ax(&c.factory));
    assert_eq!(inner["to"], ax(&c.child));
    assert_eq!(inner["input"], format!("0x{CHILD_INIT}"));
    assert_eq!(inner["output"], "0x00");
    // onlyTopCall drops the subcalls.
    let top = result(
        &c.io,
        "debug_traceTransaction",
        json!([hx(&c.create_tx), {"tracer": "callTracer", "tracerConfig": {"onlyTopCall": true}}]),
    );
    assert!(top.get("calls").is_none(), "{top}");
    // A native transfer is one CALL frame with the value.
    let send = result(
        &c.io,
        "debug_traceTransaction",
        json!([hx(&Hash::new([0x21; 32])), {"tracer": "callTracer"}]),
    );
    assert_eq!(send["type"], "CALL");
    assert_eq!(send["value"], "0x5");
    assert_eq!(send["to"], ax(&B));
    // The deploy is a CREATE frame naming the factory.
    let dep = result(
        &c.io,
        "debug_traceTransaction",
        json!([hx(&c.deploy_tx), {"tracer": "callTracer"}]),
    );
    assert_eq!(dep["type"], "CREATE", "{dep}");
    assert_eq!(dep["to"], ax(&c.factory));
}

#[test]
fn prestate_tracer_reports_the_state_before_the_transaction() {
    let c = executed_chain();
    let p = result(
        &c.io,
        "debug_traceTransaction",
        json!([hx(&c.create_tx), {"tracer": "prestateTracer"}]),
    );
    let f = &p[ax(&c.factory)];
    assert_eq!(
        f["code"],
        format!("0x{}", hex::encode(factory_runtime())),
        "{p}"
    );
    assert_eq!(
        f["storage"][format!("0x{}", "0".repeat(64))],
        format!("0x{}", "0".repeat(64)),
        "slot 0 was empty before the create: {p}"
    );
    // The sender had already sent tx 0x21 (nonce 1) in the same block.
    assert_eq!(p[ax(&A)]["nonce"], 2, "{p}");
}

#[test]
fn trace_call_simulates_on_the_named_block() {
    let c = executed_chain();
    let t = result(
        &c.io,
        "debug_traceCall",
        json!([{"from": ax(&A), "to": ax(&c.factory), "data": "0x01"}, "0x1", {"tracer": "callTracer"}]),
    );
    assert_eq!(t["calls"][0]["type"], "CREATE", "{t}");
    let unsupported = call(
        &c.io,
        "debug_traceCall",
        json!([{"from": ax(&A), "to": ax(&c.factory)}, "latest", {"tracer": "4byteTracer"}]),
    );
    assert_eq!(unsupported["error"]["code"], -32602, "{unsupported}");
}

#[test]
fn contract_creator_finds_eoa_deploys_and_factory_creates() {
    let c = executed_chain();
    let f = result(&c.io, "ots_getContractCreator", json!([ax(&c.factory)]));
    assert_eq!(f["hash"], hx(&c.deploy_tx), "{f}");
    assert_eq!(f["creator"], ax(&A));
    let ch = result(&c.io, "ots_getContractCreator", json!([ax(&c.child)]));
    assert_eq!(ch["hash"], hx(&c.create_tx), "{ch}");
    assert_eq!(ch["creator"], ax(&c.factory));
    assert!(result(&c.io, "ots_getContractCreator", json!([ax(&B)])).is_null());
}

#[test]
fn tracing_changes_no_state() {
    let c = executed_chain();
    let root = c.executor.state_root_readonly();
    let tip = c.storage.blocks.get_applied_tip().expect("tip");
    let count = c.storage.blocks.stored_block_count().expect("count");
    let undo = c.storage.state.reorg_undo_heights().expect("undo");
    for _ in 0..2 {
        result(
            &c.io,
            "debug_traceTransaction",
            json!([hx(&c.create_tx), {"tracer": "callTracer"}]),
        );
        result(
            &c.io,
            "debug_traceTransaction",
            json!([hx(&c.create_tx), {"tracer": "prestateTracer"}]),
        );
        result(
            &c.io,
            "debug_traceCall",
            json!([{"from": ax(&A), "to": ax(&c.factory), "data": "0x01"}, "latest", {"tracer": "callTracer"}]),
        );
        result(&c.io, "ots_getContractCreator", json!([ax(&c.child)]));
        result(
            &c.io,
            "eth_call",
            json!([{"from": ax(&A), "to": ax(&c.factory), "data": "0x01"}, "0x1"]),
        );
    }
    assert_eq!(
        c.executor.state_root_readonly(),
        root,
        "the node's state root moved"
    );
    assert_eq!(c.executor.state_root_readonly(), c.blocks[3].state_root);
    assert_eq!(c.storage.blocks.get_applied_tip().expect("tip"), tip);
    assert_eq!(c.storage.blocks.stored_block_count().expect("count"), count);
    assert_eq!(c.storage.state.reorg_undo_heights().expect("undo"), undo);
    // The flat store still holds the head's state.
    assert_eq!(
        result(&c.io, "eth_getBalance", json!([ax(&B), "latest"])),
        "0xc"
    );
    assert_eq!(
        result(&c.io, "eth_getTransactionCount", json!([ax(&A), "latest"])),
        "0x4"
    );
}

#[test]
fn heavy_methods_carry_a_method_budget_cost() {
    use citrate_api::rpc_limits::heavy_method_cost;
    assert_eq!(
        heavy_method_cost("debug_traceTransaction"),
        citrate_api::trace_rpc::TRACE_COST
    );
    assert_eq!(
        heavy_method_cost("debug_traceCall"),
        citrate_api::trace_rpc::TRACE_COST
    );
    assert_eq!(
        heavy_method_cost("ots_getContractCreator"),
        citrate_api::trace_rpc::CREATOR_LOOKUP_COST
    );
    assert!(citrate_api::trace_rpc::TRACE_COST > 0);
    assert!(citrate_api::historical_state::HISTORICAL_POINT_READ_COST > 0);
    assert!(
        citrate_api::historical_state::HISTORICAL_FULL_STATE_COST
            > citrate_api::historical_state::HISTORICAL_POINT_READ_COST
    );
}

// ── DAG fixture: 1, 2, 3, 5, 6 ───────────────────────────────────────────

fn h(tag: u8, n: u64) -> Hash {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&n.to_be_bytes());
    b[31] = tag;
    Hash::new(b)
}

fn put(storage: &StorageManager, hash: Hash, height: u64, sp: Hash, merge: Vec<Hash>) -> Block {
    let b = BlockBuilder::new()
        .hash(hash)
        .parent(sp)
        .merge_parents(merge)
        .height(height)
        .blue_score(height)
        .timestamp(1_000_000 + height)
        .build_unhashed();
    storage.blocks.put_block(&b).expect("block");
    b
}

fn record(storage: &StorageManager, hash: Hash, data: &GhostdagData) {
    let v = citrate_consensus::dag_store::encode_ghostdag_record(&hash, data).expect("encode");
    storage
        .db
        .put_cf(CF_DAG_GHOSTDAG, hash.as_bytes(), &v)
        .expect("put record");
}

struct Dag {
    storage: Arc<StorageManager>,
    io: jsonrpc_core::IoHandler,
    _tmp: TempDir,
}

/// a0 - a1 - a2 - a3 (applied chain, tip a3); b2, c2 siblings of a2 (parent
/// a1); b3 on b2. a3 merges b2 (blue) and c2 (red). a1 has no record (pruned).
fn dag_fixture() -> Dag {
    std::env::set_var("CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT", "1");
    let tmp = TempDir::new().expect("tempdir");
    let storage =
        Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).expect("storage"));
    let a0 = h(0xA0, 0);
    let a1 = h(0xA0, 1);
    let a2 = h(0xA0, 2);
    let b2 = h(0xB0, 2);
    let c2 = h(0xC0, 2);
    let a3 = h(0xA0, 3);
    let b3 = h(0xB0, 3);
    put(&storage, a0, 0, Hash::default(), vec![]);
    put(&storage, a1, 1, a0, vec![]);
    put(&storage, a2, 2, a1, vec![]);
    put(&storage, b2, 2, a1, vec![]);
    put(&storage, c2, 2, a1, vec![]);
    put(&storage, a3, 3, a2, vec![b2, c2]);
    put(&storage, b3, 3, b2, vec![]);
    storage.blocks.put_applied_tip(&a3, 3).expect("tip");
    let gd = |sp: Hash, score: u64, blues: Vec<Hash>, reds: Vec<Hash>, sizes: &[(Hash, u32)]| {
        GhostdagData {
            selected_parent: sp,
            blue_score: score,
            blue_work: u128::from(score) * 10,
            mergeset_blues: blues,
            mergeset_reds: reds,
            blues_anticone_sizes: sizes.iter().copied().collect::<BTreeMap<_, _>>(),
            merge_depth_root: a0,
        }
    };
    record(&storage, a0, &GhostdagData::genesis());
    record(&storage, a2, &gd(a1, 2, vec![a1], vec![], &[(a1, 0)]));
    record(&storage, b2, &gd(a1, 2, vec![a1], vec![], &[(a1, 0)]));
    record(&storage, c2, &gd(a1, 2, vec![a1], vec![], &[(a1, 0)]));
    record(
        &storage,
        a3,
        &gd(a2, 4, vec![a2, b2], vec![c2], &[(a2, 0), (b2, 1)]),
    );
    // A finalized checkpoint certificate at height 2, as CheckpointManager
    // persists it.
    let committee: Vec<PublicKey> = (1..=4u8).map(|i| PublicKey::new([i; 32])).collect();
    let votes = committee
        .iter()
        .take(3)
        .map(|k| (*k, Signature::new([7u8; 64])))
        .collect();
    let cp = Checkpoint {
        height: 2,
        block_hash: a2,
        committee,
        votes,
        status: CheckpointStatus::Finalized,
    };
    storage
        .db
        .put_cf(
            CF_DAG_METADATA,
            b"checkpoint:2",
            &bincode::serialize(&cp).expect("encode"),
        )
        .expect("put certificate");

    let executor = Arc::new(Executor::new(Arc::new(StateDB::new())));
    let mut io = jsonrpc_core::IoHandler::new();
    register_eth_methods_with_finality(
        &mut io,
        storage.clone(),
        Arc::new(Mempool::new(MempoolConfig::default())),
        executor,
        CHAIN,
        Arc::new(FilterRegistry::new()),
        None,
        Arc::new(AtomicU64::new(0)),
    );
    citrate_api::node_rpc::register_node_methods(&mut io, storage.clone(), CHAIN, None);
    Dag {
        storage,
        io,
        _tmp: tmp,
    }
}

// ── 1. citrate_getBlocksAtHeight ─────────────────────────────────────────

#[test]
fn blocks_at_height_lists_every_sibling() {
    let d = dag_fixture();
    let r = result(&d.io, "citrate_getBlocksAtHeight", json!(["0x2"]));
    let blocks = r["blocks"].as_array().expect("blocks");
    let mut want = vec![hx(&h(0xA0, 2)), hx(&h(0xB0, 2)), hx(&h(0xC0, 2))];
    want.sort();
    let got: Vec<String> = blocks
        .iter()
        .map(|b| b["hash"].as_str().expect("hash").to_string())
        .collect();
    assert_eq!(got, want, "{r}");
    for b in blocks {
        let chain = b["hash"] == hx(&h(0xA0, 2));
        assert_eq!(b["isSelectedChain"], chain, "{b}");
        assert_eq!(b["selectedParent"], hx(&h(0xA0, 1)));
        assert_eq!(b["hasGhostdagRecord"], true);
    }
    // The legacy height index names one of them only.
    let legacy = d.storage.blocks.get_block_by_height(2).expect("read");
    assert!(legacy.is_some());
    assert_eq!(
        result(&d.io, "citrate_getBlocksAtHeight", json!([9]))["blocks"],
        json!([])
    );
}

// ── 2. citrate_getGhostdagData ───────────────────────────────────────────

#[test]
fn ghostdag_data_reads_the_persisted_record_and_colours() {
    let d = dag_fixture();
    let a3 = result(&d.io, "citrate_getGhostdagData", json!([hx(&h(0xA0, 3))]));
    assert_eq!(a3["recordAvailable"], true);
    assert_eq!(a3["selectedParent"], hx(&h(0xA0, 2)));
    assert_eq!(a3["blueScore"], "0x4");
    assert_eq!(
        a3["mergesetBlues"],
        json!([hx(&h(0xA0, 2)), hx(&h(0xB0, 2))])
    );
    assert_eq!(a3["mergesetReds"], json!([hx(&h(0xC0, 2))]));
    assert_eq!(a3["isSelectedChain"], true);

    let b2 = result(&d.io, "citrate_getGhostdagData", json!([hx(&h(0xB0, 2))]));
    assert_eq!(b2["color"], "blue", "{b2}");
    assert_eq!(b2["mergingChainBlock"], hx(&h(0xA0, 3)));
    assert_eq!(b2["blueAnticoneSize"], 1);
    assert_eq!(b2["isSelectedChain"], false);

    let c2 = result(&d.io, "citrate_getGhostdagData", json!([hx(&h(0xC0, 2))]));
    assert_eq!(c2["color"], "red", "{c2}");
    assert_eq!(c2["mergingChainBlock"], hx(&h(0xA0, 3)));

    // a1's record is gone (pruned): its record fields are null, honestly.
    let a1 = result(&d.io, "citrate_getGhostdagData", json!([hx(&h(0xA0, 1))]));
    assert_eq!(a1["recordAvailable"], false, "{a1}");
    assert!(a1["mergesetBlues"].is_null());
    assert!(a1["blueScore"].is_null());
    assert_eq!(a1["header"]["blueScore"], "0x1");

    assert!(result(
        &d.io,
        "citrate_getGhostdagData",
        json!([hx(&Hash::new([9; 32]))])
    )
    .is_null());
}

// ── 3. citrate_getSelectedChainChanges ───────────────────────────────────

#[test]
fn selected_chain_changes_report_removed_and_added_blocks() {
    let d = dag_fixture();
    let r = result(
        &d.io,
        "citrate_getSelectedChainChanges",
        json!([hx(&h(0xB0, 3))]),
    );
    assert_eq!(
        r["removedChainBlockHashes"],
        json!([hx(&h(0xB0, 3)), hx(&h(0xB0, 2))]),
        "{r}"
    );
    assert_eq!(r["commonAncestor"]["hash"], hx(&h(0xA0, 1)));
    assert_eq!(
        r["addedChainBlocks"],
        json!([
            {"hash": hx(&h(0xA0, 2)), "height": "0x2"},
            {"hash": hx(&h(0xA0, 3)), "height": "0x3"},
        ])
    );
    assert_eq!(r["more"], false);
    // The hash-only list the explorer's chain-change feed reads (Kaspa's
    // `addedChainBlockHashes`), in the same order as `addedChainBlocks`.
    assert_eq!(
        r["addedChainBlockHashes"],
        json!([hx(&h(0xA0, 2)), hx(&h(0xA0, 3))]),
        "{r}"
    );

    let on_chain = result(
        &d.io,
        "citrate_getSelectedChainChanges",
        json!([hx(&h(0xA0, 1)), 1]),
    );
    assert_eq!(on_chain["removedChainBlockHashes"], json!([]));
    assert_eq!(
        on_chain["addedChainBlocks"],
        json!([{"hash": hx(&h(0xA0, 2)), "height": "0x2"}])
    );
    assert_eq!(on_chain["more"], true);

    let unknown = call(
        &d.io,
        "citrate_getSelectedChainChanges",
        json!([hx(&Hash::new([9; 32]))]),
    );
    assert_eq!(unknown["error"]["code"], -32602, "{unknown}");
}

// ── 5. citrate_getFinalityStatus ─────────────────────────────────────────

#[test]
fn finality_status_reports_the_stored_certificate_not_depth() {
    let d = dag_fixture();
    let r = result(&d.io, "citrate_getFinalityStatus", json!([]));
    assert_eq!(r["enforcement"], false, "{r}");
    assert_eq!(r["finalizedSource"], "height-handle");
    assert_eq!(
        r["finalized"]["height"], "0x0",
        "no finality raised: genesis"
    );
    assert_eq!(r["finalized"]["hash"], hx(&h(0xA0, 0)));
    assert_eq!(r["latestCertificate"]["height"], "0x2");
    assert_eq!(r["latestCertificate"]["blockHash"], hx(&h(0xA0, 2)));
    assert_eq!(r["latestCertificate"]["committeeSize"], 4);
    assert_eq!(r["latestCertificate"]["voters"], 3);
    assert!(
        r["latestCertificate"]["stateRoot"].is_null(),
        "finality-lane field: {r}"
    );
    let pending: Vec<&str> = r["pendingFinalityLane"]
        .as_array()
        .expect("list")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        pending.contains(&"stateRoot") && pending.contains(&"votedStake"),
        "{r}"
    );
    assert_eq!(r["votingPinned"], false);

    // The keys the explorer (citrate-explorer#51, src/lib/citrate/r1007.ts)
    // and the finality lane's handler share: a view is always available from
    // storage, so `published` is true; `finalized.blockHash` names the anchor.
    assert_eq!(r["published"], true, "{r}");
    assert_eq!(r["voting"], false, "{r}");
    assert_eq!(r["finalized"]["blockHash"], hx(&h(0xA0, 0)), "{r}");
    assert!(r["quorumRule"].is_string(), "{r}");
    assert!(r["dataSource"].is_string(), "{r}");
    assert!(r.get("mode").is_some(), "{r}");
}

// ── 6. citrate_getDagStats ───────────────────────────────────────────────

#[test]
fn dag_stats_counts_are_maintained_not_estimated() {
    let d = dag_fixture();
    let r = result(&d.io, "citrate_getDagStats", json!([]));
    assert_eq!(r["totalBlocks"], 7, "{r}");
    assert!(
        r.get("blueBlocks").is_none() && r.get("redBlocks").is_none(),
        "{r}"
    );
    assert_eq!(r["selectedTip"]["hash"], hx(&h(0xA0, 3)));
    assert_eq!(r["selectedTip"]["blueScore"], 4);
    let doomed = [h(0xB0, 3)].into_iter().collect();
    d.storage.blocks.purge_blocks(&doomed).expect("purge");
    assert_eq!(
        result(&d.io, "citrate_getDagStats", json!([]))["totalBlocks"],
        6
    );
}
