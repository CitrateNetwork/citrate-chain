// citrate/core/api/tests/state_tag_fail_closed.rs
//
// chain#425: the account-state reads hold only the executed head's state, so a
// block tag naming any other block is refused, never answered from the head's
// state. Before the fix every one of these methods accepted a past block number
// or hash and silently answered with latest state.

use citrate_api::eth_rpc::register_eth_methods_with_finality;
use citrate_api::state_tag::{HISTORICAL_STATE_CODE, HISTORICAL_STATE_MESSAGE};
use citrate_api::FilterRegistry;
use citrate_consensus::types::{Block, BlockBuilder, Hash};
use citrate_execution::executor::Executor;
use citrate_sequencer::mempool::{Mempool, MempoolConfig};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use serde_json::{json, Value};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tempfile::TempDir;

const ADDR: &str = "0x00000000000000000000000000000000deadbeef";
const FROM: &str = "0x00000000000000000000000000000000000000aa";

fn hash_of(tag: u8, n: u64) -> Hash {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&n.to_be_bytes());
    h[31] = tag;
    Hash::new(h)
}

fn hx(h: &Hash) -> String {
    format!("0x{}", hex::encode(h.as_bytes()))
}

struct Fx {
    storage: Arc<StorageManager>,
    io: jsonrpc_core::IoHandler,
    a: Vec<Block>,
    sibling: Block,
    _tmp: TempDir,
}

fn put(storage: &StorageManager, tag: u8, height: u64, parent: Hash) -> Block {
    let b = BlockBuilder::new()
        .hash(hash_of(tag, height))
        .parent(parent)
        .height(height)
        .timestamp(1_000_000 + height)
        .gas_limit(30_000_000)
        .build_unhashed();
    storage.blocks.put_block(&b).expect("block");
    b
}

/// a0..=a6 stored, the executed head at a5, a sibling of a5 stored.
fn fixture() -> Fx {
    std::env::set_var("CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT", "1");
    let tmp = TempDir::new().expect("tempdir");
    let storage =
        Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).expect("storage"));
    let mut a = Vec::new();
    let mut parent = Hash::default();
    for h in 0..=6 {
        let b = put(&storage, 0xA0, h, parent);
        parent = b.hash();
        a.push(b);
    }
    let sibling = put(&storage, 0xC0, 5, a[4].hash());
    storage
        .blocks
        .put_applied_tip(&a[5].hash(), 5)
        .expect("applied tip");
    let executor = Arc::new(Executor::new(Arc::new(citrate_execution::StateDB::new())));
    let mut io = jsonrpc_core::IoHandler::new();
    register_eth_methods_with_finality(
        &mut io,
        storage.clone(),
        Arc::new(Mempool::new(MempoolConfig::default())),
        executor,
        40204,
        Arc::new(FilterRegistry::new()),
        None,
        Arc::new(AtomicU64::new(0)),
    );
    Fx {
        storage,
        io,
        a,
        sibling,
        _tmp: tmp,
    }
}

/// The six state reads, each with `tag` in its block-tag position (`None` =
/// the tag omitted).
fn requests(tag: Option<Value>) -> Vec<(&'static str, Value)> {
    let with = |mut p: Vec<Value>| {
        if let Some(t) = &tag {
            p.push(t.clone());
        }
        Value::Array(p)
    };
    vec![
        ("eth_getBalance", with(vec![json!(ADDR)])),
        ("eth_getCode", with(vec![json!(ADDR)])),
        ("eth_getTransactionCount", with(vec![json!(ADDR)])),
        ("eth_getStorageAt", with(vec![json!(ADDR), json!("0x0")])),
        (
            "eth_call",
            with(vec![json!({"from": FROM, "to": ADDR, "data": "0x"})]),
        ),
        (
            "eth_estimateGas",
            with(vec![json!({"from": FROM, "to": ADDR, "data": "0x"})]),
        ),
    ]
}

/// eth_call / eth_estimateGas bound their simulation with a tokio timer, so
/// requests are handled inside a runtime context (as the RPC server does).
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

fn call(io: &jsonrpc_core::IoHandler, method: &str, params: &Value) -> Value {
    let _rt = runtime().enter();
    let req = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
    let resp = io.handle_request_sync(&req).expect("response");
    serde_json::from_str(&resp).expect("json")
}

fn assert_served(io: &jsonrpc_core::IoHandler, tag: Option<Value>, why: &str) {
    for (m, p) in requests(tag) {
        let v = call(io, m, &p);
        assert!(
            v.get("error").is_none() && v.get("result").is_some(),
            "{m} {p}: {why} must be served, got {v}"
        );
    }
}

fn assert_refused(io: &jsonrpc_core::IoHandler, tag: Value, why: &str) {
    for (m, p) in requests(Some(tag)) {
        let v = call(io, m, &p);
        assert!(
            v.get("result").is_none(),
            "{m} {p}: {why} must be refused, not answered from latest state: {v}"
        );
        assert_eq!(
            v["error"]["code"],
            json!(HISTORICAL_STATE_CODE),
            "{m} {p}: {v}"
        );
        let msg = v["error"]["message"].as_str().unwrap_or_default();
        assert!(msg.starts_with(HISTORICAL_STATE_MESSAGE), "{m}: {msg}");
        assert_eq!(
            v["error"]["data"]["executedHead"]["number"],
            json!("0x5"),
            "{m}: {v}"
        );
    }
}

#[test]
fn a_block_number_below_the_executed_head_is_refused_by_every_state_read() {
    let f = fixture();
    for n in ["0x4", "0x3", "0x1", "0x0", "earliest"] {
        assert_refused(&f.io, json!(n), &format!("tag {n} (below the head)"));
    }
    assert_refused(
        &f.io,
        json!({"blockNumber": "0x2"}),
        "EIP-1898 blockNumber below the head",
    );
}

#[test]
fn a_block_hash_other_than_the_executed_head_is_refused() {
    let f = fixture();
    assert_refused(&f.io, json!(hx(&f.a[3].hash())), "an ancestor's hash");
    assert_refused(
        &f.io,
        json!({"blockHash": hx(&f.a[2].hash())}),
        "EIP-1898 ancestor hash",
    );
    assert_refused(&f.io, json!(hx(&f.sibling.hash())), "a sibling of the head");
    assert_refused(&f.io, json!(hx(&hash_of(0xEE, 99))), "an unknown hash");
}

#[test]
fn a_block_above_the_executed_head_is_refused() {
    let f = fixture();
    assert_refused(&f.io, json!("0x6"), "a stored block not executed yet");
    assert_refused(&f.io, json!("0x100"), "a future height");
    assert_refused(
        &f.io,
        json!(hx(&f.a[6].hash())),
        "the hash of a stored, unexecuted block",
    );
}

#[test]
fn latest_pending_absent_and_the_executed_head_itself_are_served() {
    let f = fixture();
    assert_served(&f.io, None, "an omitted tag");
    assert_served(&f.io, Some(json!("latest")), "latest");
    assert_served(&f.io, Some(json!("pending")), "pending");
    assert_served(&f.io, Some(json!("0x5")), "the head's number");
    assert_served(&f.io, Some(json!(hx(&f.a[5].hash()))), "the head's hash");
    assert_served(
        &f.io,
        Some(json!({"blockHash": hx(&f.a[5].hash())})),
        "EIP-1898 head hash",
    );
    assert_served(
        &f.io,
        Some(json!({"blockNumber": "0x5"})),
        "EIP-1898 head number",
    );
}

#[test]
fn the_accepted_number_follows_the_executed_head() {
    let f = fixture();
    f.storage
        .blocks
        .put_applied_tip(&f.a[6].hash(), 6)
        .expect("advance");
    assert_served(&f.io, Some(json!("0x6")), "the new head");
    for (m, p) in requests(Some(json!("0x5"))) {
        let v = call(&f.io, m, &p);
        assert_eq!(
            v["error"]["code"],
            json!(HISTORICAL_STATE_CODE),
            "{m}: old head now below: {v}"
        );
    }
}

#[test]
fn a_malformed_tag_is_invalid_params_not_latest() {
    let f = fixture();
    for tag in [json!("blah"), json!(7), json!({"foo": 1}), json!("0xnope")] {
        for (m, p) in requests(Some(tag.clone())) {
            let v = call(&f.io, m, &p);
            assert_eq!(v["error"]["code"], json!(-32602), "{m} {p}: {v}");
        }
    }
}
