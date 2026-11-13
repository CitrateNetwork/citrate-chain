// Account-state reads refuse the `finalized` / `safe` tags while the finalized
// height is behind the tip, pinned at each state-reading method.
//
// The state store holds only the latest committed state, so a read under a
// finality tag can only be served once finality has caught up with the tip.
// The existing test covers eth_getBalance and eth_getTransactionCount; this
// covers eth_getCode, eth_getStorageAt, eth_call and eth_estimateGas, with a
// control showing each is served once finalized == latest.
//
// In-process only: drives the registered IoHandler; storage is a temp dir.

use citrate_api::eth_rpc::register_eth_methods_with_finality;
use citrate_api::FilterRegistry;
use citrate_consensus::types::{BlockBuilder, Hash};
use citrate_execution::executor::Executor;
use citrate_sequencer::mempool::{Mempool, MempoolConfig};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use serde_json::{json, Value};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tempfile::TempDir;

const TIP: u64 = 5;
const ADDR: &str = "0x4242424242424242424242424242424242424242";

fn chain() -> (Arc<StorageManager>, TempDir) {
    let tmp = TempDir::new().expect("tempdir");
    let storage =
        Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).expect("storage"));
    let genesis = BlockBuilder::new()
        .hash(Hash::new([0xEE; 32]))
        .parent(Hash::default())
        .height(0)
        .build_unhashed();
    storage.blocks.put_block(&genesis).expect("genesis");
    let mut parent = genesis.hash();
    for h in 1..=TIP {
        let mut hb = [0u8; 32];
        hb[..8].copy_from_slice(&h.to_be_bytes());
        hb[31] = 0xAB;
        let b = BlockBuilder::new()
            .hash(Hash::new(hb))
            .parent(parent)
            .height(h)
            .timestamp(1_000_000 + h)
            .gas_limit(30_000_000)
            .base_fee_per_gas(1_000_000_000)
            .build_unhashed();
        storage.blocks.put_block(&b).expect("block");
        parent = b.hash();
    }
    (storage, tmp)
}

fn io(finalized: u64) -> (jsonrpc_core::IoHandler, TempDir) {
    std::env::set_var("CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT", "1");
    let (storage, tmp) = chain();
    let executor = Arc::new(Executor::new(Arc::new(citrate_execution::StateDB::new())));
    let mut io = jsonrpc_core::IoHandler::new();
    register_eth_methods_with_finality(
        &mut io,
        storage,
        Arc::new(Mempool::new(MempoolConfig::default())),
        executor,
        40204,
        Arc::new(FilterRegistry::new()),
        None,
        Arc::new(AtomicU64::new(finalized)),
    );
    (io, tmp)
}

fn call(io: &jsonrpc_core::IoHandler, method: &str, params: Value) -> Value {
    let req = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
    // eth_call / eth_estimateGas simulate on the runtime, so run inside it.
    let resp = tokio::task::block_in_place(|| io.handle_request_sync(&req)).expect("response");
    serde_json::from_str(&resp).expect("json")
}

/// True if the reply is the "state at this tag is not available" refusal.
fn refused_for_tag(v: &Value) -> bool {
    v.get("error")
        .map(|e| {
            e.get("code").and_then(Value::as_i64) == Some(-32000)
                && e.get("message")
                    .and_then(Value::as_str)
                    .is_some_and(|m| m.contains("is not available"))
        })
        .unwrap_or(false)
}

fn requests(tag: &str) -> Vec<(&'static str, Value)> {
    let call_obj = json!({ "to": ADDR, "data": "0x" });
    vec![
        ("eth_getCode", json!([ADDR, tag])),
        ("eth_getStorageAt", json!([ADDR, "0x0", tag])),
        ("eth_call", json!([call_obj.clone(), tag])),
        ("eth_estimateGas", json!([call_obj, tag])),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn state_reads_refuse_finality_tags_while_finality_lags_the_tip() {
    let (io, _tmp) = io(1);
    let mut served = Vec::new();
    for tag in ["finalized", "safe"] {
        for (method, params) in requests(tag) {
            let v = call(&io, method, params);
            if !refused_for_tag(&v) {
                served.push(format!("{method}({tag}) -> {v}"));
            }
        }
    }
    assert!(
        served.is_empty(),
        "latest state must not be served under a finality tag while finalized (1) < tip ({TIP}): {served:#?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn state_reads_serve_finality_tags_once_finality_reaches_the_tip() {
    // Control: the refusal is about the lag, not the tag. With finalized ==
    // tip, latest state is the finalized state and the reads go through.
    let (io, _tmp) = io(TIP);
    for tag in ["finalized", "safe"] {
        for (method, params) in requests(tag) {
            let v = call(&io, method, params);
            assert!(
                !refused_for_tag(&v),
                "{method}({tag}) must be served once finalized == tip: {v}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn latest_tag_is_never_refused() {
    let (io, _tmp) = io(1);
    for (method, params) in requests("latest") {
        let v = call(&io, method, params);
        assert!(!refused_for_tag(&v), "{method}(latest): {v}");
    }
}
