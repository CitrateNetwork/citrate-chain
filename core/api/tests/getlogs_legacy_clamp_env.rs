// The operator switch `CITRATE_RPC_GETLOGS_CLAMP_RANGE` as the registered
// eth_getLogs handler reads it. Its own test binary: the variable is process
// global and read when the handler is built, so it must not race other tests.

use citrate_api::canonical_logs::{legacy_clamp_from_env, LEGACY_CLAMP_ENV, MAX_LOG_BLOCK_RANGE};
use citrate_api::eth_rpc::register_eth_methods_with_finality;
use citrate_api::FilterRegistry;
use citrate_consensus::types::{BlockBuilder, Hash};
use citrate_execution::executor::Executor;
use citrate_sequencer::mempool::{Mempool, MempoolConfig};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use serde_json::Value;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

fn over_limit_call(storage: Arc<StorageManager>) -> Value {
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
        Arc::new(AtomicU64::new(0)),
    );
    let to = format!("0x{:x}", MAX_LOG_BLOCK_RANGE + 1);
    let req = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "eth_getLogs",
        "params": [{"fromBlock": "0x0", "toBlock": to}],
    })
    .to_string();
    serde_json::from_str(&io.handle_request_sync(&req).expect("response")).expect("json")
}

#[test]
fn legacy_clamp_env_values_as_the_handler_reads_them() {
    std::env::set_var("CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT", "1");
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let storage = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).expect("storage"));
    let g = BlockBuilder::new()
        .hash(Hash::new([0xEE; 32]))
        .parent(Hash::default())
        .height(0)
        .build_unhashed();
    storage.blocks.put_block(&g).expect("g");
    storage.blocks.put_applied_tip(&g.hash(), 0).expect("tip");

    let clamps = ["1", "true", "TRUE", " True ", " 1\n"];
    let errors = ["0", "", "yes", "on", "2", "false", "1 1"];
    for v in clamps {
        std::env::set_var(LEGACY_CLAMP_ENV, v);
        assert!(legacy_clamp_from_env(), "{v:?} enables the clamp");
        let r = over_limit_call(storage.clone());
        assert!(r.get("error").is_none(), "{v:?}: clamped, not an error: {r}");
        assert!(r["result"].is_array(), "{v:?}: {r}");
    }
    for v in errors {
        std::env::set_var(LEGACY_CLAMP_ENV, v);
        assert!(!legacy_clamp_from_env(), "{v:?} leaves the limit on");
        let r = over_limit_call(storage.clone());
        assert_eq!(r["error"]["code"], -32005, "{v:?}: {r}");
    }
    std::env::remove_var(LEGACY_CLAMP_ENV);
    assert!(!legacy_clamp_from_env(), "unset leaves the limit on");
    assert_eq!(over_limit_call(storage)["error"]["code"], -32005);
}
