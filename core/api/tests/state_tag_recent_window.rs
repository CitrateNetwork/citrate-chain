// citrate/core/api/tests/state_tag_recent_window.rs
//
// chain#425 operator opt-out (`[rpc] serve_recent_state_tags = N`). Foundry's
// fork mode (`forge script`, `anvil --fork-url`) reads `eth_getBlockByNumber
// ("latest")` once and then pins every balance / nonce / code / storage read to
// that block's hash, so a strict node refuses the script as soon as one more
// block executes. With N > 0 a tag naming a canonical block at most N blocks
// from the executed head is answered from the head's state; anything further,
// off the canonical chain, unknown, or finality-related still fails closed.
// The default (N = 0) is strict: tests/state_tag_fail_closed.rs.

use citrate_api::eth_rpc::{register_eth_methods_with_options, EthRpcOptions};
use citrate_api::state_tag::{
    StateTagPolicy, HISTORICAL_STATE_CODE, HISTORICAL_STATE_MESSAGE, MAX_RECENT_STATE_TAGS,
};
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
const HEAD: u64 = 100;
const WINDOW: u64 = 64;

fn hash_of(tag: u8, n: u64) -> Hash {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&n.to_be_bytes());
    h[31] = tag;
    Hash::new(h)
}

fn hx(h: &Hash) -> String {
    format!("0x{}", hex::encode(h.as_bytes()))
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

struct Fx {
    storage: Arc<StorageManager>,
    io: jsonrpc_core::IoHandler,
    /// a0..=a102; the executed head is a100, a101 and a102 are stored above it.
    a: Vec<Block>,
    /// A sibling of a95 (parent a94) and a sibling of the head (parent a99).
    side95: Block,
    side100: Block,
    _tmp: TempDir,
}

fn fixture(window: u64) -> Fx {
    std::env::set_var("CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT", "1");
    let tmp = TempDir::new().expect("tempdir");
    let storage =
        Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).expect("storage"));
    let mut a = Vec::new();
    let mut parent = Hash::default();
    for h in 0..=HEAD + 2 {
        let b = put(&storage, 0xA0, h, parent);
        parent = b.hash();
        a.push(b);
    }
    let side95 = put(&storage, 0xC0, 95, a[94].hash());
    let side100 = put(&storage, 0xC0, 100, a[99].hash());
    storage
        .blocks
        .put_applied_tip(&a[HEAD as usize].hash(), HEAD)
        .expect("tip");
    let io = io_with(&storage, window);
    Fx {
        storage,
        io,
        a,
        side95,
        side100,
        _tmp: tmp,
    }
}

fn io_with(storage: &Arc<StorageManager>, window: u64) -> jsonrpc_core::IoHandler {
    let executor = Arc::new(Executor::new(Arc::new(citrate_execution::StateDB::new())));
    let mut io = jsonrpc_core::IoHandler::new();
    register_eth_methods_with_options(
        &mut io,
        storage.clone(),
        Arc::new(Mempool::new(MempoolConfig::default())),
        executor,
        40204,
        Arc::new(FilterRegistry::new()),
        None,
        Arc::new(AtomicU64::new(0)),
        EthRpcOptions {
            state_tags: StateTagPolicy::from_config(window),
        },
    );
    io
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

fn call(io: &jsonrpc_core::IoHandler, method: &str, params: &Value) -> Value {
    let _rt = runtime().enter();
    let req = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
    let resp = io.handle_request_sync(&req).expect("response");
    serde_json::from_str(&resp).expect("json")
}

fn requests(tag: Value) -> Vec<(&'static str, Value)> {
    let call_obj = json!({"from": FROM, "to": ADDR, "data": "0x"});
    vec![
        ("eth_getBalance", json!([ADDR, tag])),
        ("eth_getCode", json!([ADDR, tag])),
        ("eth_getTransactionCount", json!([ADDR, tag])),
        ("eth_getStorageAt", json!([ADDR, "0x0", tag])),
        ("eth_call", json!([call_obj, tag])),
        ("eth_estimateGas", json!([call_obj, tag])),
    ]
}

fn served(io: &jsonrpc_core::IoHandler, tag: Value, why: &str) {
    for (m, p) in requests(tag) {
        let v = call(io, m, &p);
        assert!(
            v.get("error").is_none() && v.get("result").is_some(),
            "{m} {p}: {why} must be served, got {v}"
        );
    }
}

fn refused(io: &jsonrpc_core::IoHandler, tag: Value, why: &str) {
    for (m, p) in requests(tag) {
        let v = call(io, m, &p);
        assert!(
            v.get("result").is_none(),
            "{m} {p}: {why} must be refused: {v}"
        );
        assert_eq!(
            v["error"]["code"],
            json!(HISTORICAL_STATE_CODE),
            "{m} {p}: {v}"
        );
        let msg = v["error"]["message"].as_str().unwrap_or_default();
        assert!(msg.starts_with(HISTORICAL_STATE_MESSAGE), "{m}: {msg}");
    }
}

#[test]
fn window_serves_a_pinned_recent_canonical_block() {
    let f = fixture(WINDOW);
    let edge = &f.a[(HEAD - WINDOW) as usize]; // exactly WINDOW below the head
    for b in [&f.a[99], &f.a[90], edge] {
        served(&f.io, json!(hx(&b.hash())), "a recent canonical hash");
        served(
            &f.io,
            json!({"blockHash": hx(&b.hash()), "requireCanonical": false}),
            "Foundry's EIP-1898 pinned hash",
        );
        served(
            &f.io,
            json!(format!("0x{:x}", b.header.height)),
            "a recent number",
        );
    }
    // Stored above the head, on a chain that descends from it (what
    // eth_getBlockByNumber("latest") names while the head is catching up).
    served(
        &f.io,
        json!(hx(&f.a[101].hash())),
        "a stored child of the head",
    );
    served(
        &f.io,
        json!(hx(&f.a[102].hash())),
        "a stored grandchild of the head",
    );
    served(&f.io, json!("0x66"), "a stored height above the head");
}

#[test]
fn window_still_refuses_old_off_chain_unknown_and_unstored_tags() {
    let f = fixture(WINDOW);
    let old = &f.a[(HEAD - WINDOW - 1) as usize];
    refused(
        &f.io,
        json!(hx(&old.hash())),
        "a canonical hash past the window",
    );
    refused(
        &f.io,
        json!(format!("0x{:x}", old.header.height)),
        "a number past the window",
    );
    refused(&f.io, json!("earliest"), "genesis, past the window");
    refused(
        &f.io,
        json!(hx(&f.side95.hash())),
        "a sibling inside the window",
    );
    refused(
        &f.io,
        json!({"blockHash": hx(&f.side95.hash()), "requireCanonical": false}),
        "a pinned sibling",
    );
    refused(&f.io, json!(hx(&f.side100.hash())), "a sibling of the head");
    refused(&f.io, json!(hx(&hash_of(0xEE, 7))), "an unknown hash");
    refused(
        &f.io,
        json!("0x67"),
        "a height above the head that is not stored",
    );
}

#[test]
fn window_never_relaxes_finality_tags() {
    let f = fixture(WINDOW);
    for tag in [
        json!("finalized"),
        json!("safe"),
        json!({"blockNumber": "finalized"}),
        json!({"blockNumber": "safe"}),
    ] {
        for (m, p) in requests(tag.clone()) {
            let v = call(&f.io, m, &p);
            assert!(
                v.get("result").is_none(),
                "{m} {p}: finality tag served: {v}"
            );
        }
    }
}

#[test]
fn default_policy_is_strict() {
    let f = fixture(0);
    refused(
        &f.io,
        json!(hx(&f.a[99].hash())),
        "one block below the head, strict",
    );
    refused(
        &f.io,
        json!(hx(&f.a[101].hash())),
        "one stored block above the head, strict",
    );
    served(
        &f.io,
        json!(hx(&f.a[HEAD as usize].hash())),
        "the head itself",
    );
    assert_eq!(StateTagPolicy::default(), StateTagPolicy::from_config(0));
    assert_eq!(
        StateTagPolicy::from_config(u64::MAX).recent_window,
        MAX_RECENT_STATE_TAGS,
        "clamped"
    );
}

/// The request sequence `forge script --rpc-url` sends (recorded with Foundry
/// 1.8.3 against a loopback recorder): one `eth_getBlockByNumber("latest")`,
/// then balance / nonce / code reads pinned to that block's hash, bare and as
/// `{"blockHash", "requireCanonical": false}`, while the chain keeps executing.
fn replay_forge_session(f: &Fx, io: &jsonrpc_core::IoHandler) -> Vec<Value> {
    let latest = call(io, "eth_getBlockByNumber", &json!(["latest", false]));
    let pinned = latest["result"]["hash"]
        .as_str()
        .expect("latest hash")
        .to_string();
    let pinned_obj = json!({"blockHash": pinned, "requireCanonical": false});
    let reads = |io: &jsonrpc_core::IoHandler| -> Vec<Value> {
        vec![
            call(io, "eth_getBalance", &json!([FROM, pinned])),
            call(io, "eth_getTransactionCount", &json!([FROM, pinned_obj])),
            call(io, "eth_getCode", &json!([ADDR, pinned])),
            call(io, "eth_getStorageAt", &json!([ADDR, "0x0", pinned_obj])),
            call(io, "eth_getBalance", &json!([ADDR, pinned_obj])),
        ]
    };
    let mut out = reads(io);
    // Three more blocks execute while the script runs.
    let mut parent = f.a.last().expect("a").hash();
    for h in HEAD + 3..=HEAD + 5 {
        parent = put(&f.storage, 0xA0, h, parent).hash();
    }
    f.storage
        .blocks
        .put_applied_tip(&parent, HEAD + 5)
        .expect("advance");
    out.extend(reads(io));
    out
}

#[test]
fn forge_script_session_replay_is_served_with_the_window() {
    let f = fixture(WINDOW);
    for v in replay_forge_session(&f, &f.io) {
        assert!(v.get("error").is_none(), "pinned fork read refused: {v}");
    }
}

#[test]
fn forge_script_session_replay_is_refused_when_strict() {
    let f = fixture(0);
    let out = replay_forge_session(&f, &f.io);
    assert!(
        out.iter()
            .all(|v| v["error"]["code"] == json!(HISTORICAL_STATE_CODE)),
        "strict: latest names a stored block above the executed head, then the head moves: {out:?}"
    );
}
