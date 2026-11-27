// Pins the RPC gas cap at the two simulation entry points that apply it:
// `eth_call` and `eth_estimateGas`. The cap helper has its own unit test, but
// removing either call site left every existing test green, because nothing
// drove the registered methods with an over-cap gas limit. Each test here goes
// through the registered IoHandler, so it fails if the call site stops calling
// the check. Local only: in-process handler, temp-dir storage, no network.

use citrate_api::eth_rpc::RPC_GAS_CAP;
use citrate_api::FilterRegistry;
use citrate_consensus::types::{BlockBuilder, Hash};
use citrate_execution::executor::Executor;
use citrate_sequencer::mempool::{Mempool, MempoolConfig};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use std::sync::Arc;
use tempfile::TempDir;

fn storage_with_genesis() -> (Arc<StorageManager>, TempDir) {
    let tmp = TempDir::new().expect("tempdir");
    let storage =
        Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).expect("storage"));
    let genesis = BlockBuilder::new()
        .hash(Hash::new([0xEE; 32]))
        .parent(Hash::default())
        .height(0)
        .build_unhashed();
    storage.blocks.put_block(&genesis).expect("genesis");
    (storage, tmp)
}

fn eth_io(storage: Arc<StorageManager>) -> jsonrpc_core::IoHandler {
    // Method budgets are process-global; let anonymous in-process calls through.
    std::env::set_var("CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT", "1");
    let executor = Arc::new(Executor::new(Arc::new(citrate_execution::StateDB::new())));
    let mut io = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(
        &mut io,
        storage,
        Arc::new(Mempool::new(MempoolConfig::default())),
        executor,
        40204,
        Arc::new(FilterRegistry::new()),
        None,
    );
    io
}

fn call(io: &jsonrpc_core::IoHandler, method: &str, gas: u64) -> serde_json::Value {
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": [{
            "from": "0x1111111111111111111111111111111111111111",
            "to": "0x2222222222222222222222222222222222222222",
            "gas": format!("0x{gas:x}"),
            "data": "0x"
        }, "latest"]
    });
    let resp = io
        .handle_request_sync(&req.to_string())
        .expect("a response");
    serde_json::from_str(&resp).expect("json response")
}

fn is_gas_cap_refusal(v: &serde_json::Value) -> bool {
    let Some(err) = v.get("error") else {
        return false;
    };
    err.get("code").and_then(|c| c.as_i64()) == Some(-32602)
        && err
            .get("message")
            .and_then(|m| m.as_str())
            .is_some_and(|m| m.contains("RPC gas cap"))
}

fn assert_cap_enforced(method: &str) {
    // The simulation path applies a tokio timeout, so the handler needs a
    // runtime context, as it has inside the node.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("runtime");
    let _ctx = rt.enter();
    let (storage, _tmp) = storage_with_genesis();
    let io = eth_io(storage);

    // Exactly at the cap: the call is simulated, not refused by the cap.
    let at_cap = call(&io, method, RPC_GAS_CAP);
    assert!(
        !is_gas_cap_refusal(&at_cap),
        "{method} with gas == RPC_GAS_CAP must not be refused by the cap: {at_cap}"
    );

    // One above the cap, and the u64 maximum, are both refused before execution.
    for gas in [RPC_GAS_CAP + 1, u64::MAX] {
        let over = call(&io, method, gas);
        assert!(
            is_gas_cap_refusal(&over),
            "{method} with gas {gas} must be refused by the RPC gas cap, got {over}"
        );
        assert!(
            over.get("result").is_none(),
            "{method} with gas {gas} must not return a result: {over}"
        );
    }
}

#[test]
fn eth_call_refuses_a_gas_limit_above_the_rpc_cap() {
    assert_cap_enforced("eth_call");
}

#[test]
fn eth_estimate_gas_refuses_a_gas_limit_above_the_rpc_cap() {
    assert_cap_enforced("eth_estimateGas");
}
