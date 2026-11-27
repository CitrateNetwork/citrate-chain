//! `citrate_registerSchoolNode` validates its input but has no registry to
//! write to. Its response must say so: a caller must never read a confirmed
//! registration out of a call that persisted nothing. Driven through the
//! registered IoHandler; no network.

use citrate_api::FilterRegistry;
use citrate_execution::executor::Executor;
use citrate_sequencer::mempool::{Mempool, MempoolConfig};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tempfile::TempDir;

fn io() -> (jsonrpc_core::IoHandler, TempDir) {
    let tmp = TempDir::new().expect("tempdir");
    let storage =
        Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).expect("storage"));
    let executor = Arc::new(Executor::new(Arc::new(citrate_execution::StateDB::new())));
    let mut io = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(
        &mut io,
        storage,
        Arc::new(Mempool::new(MempoolConfig::default())),
        executor,
        40204,
        Arc::new(FilterRegistry::new()),
        // The operator method group (which carries this method) is registered
        // only on a node that wires the pause flag, as the node binary does.
        Some(Arc::new(AtomicBool::new(false))),
    );
    (io, tmp)
}

fn call(io: &jsonrpc_core::IoHandler, params: &str) -> serde_json::Value {
    std::env::set_var("CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT", "1");
    let req = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"citrate_registerSchoolNode","params":{params}}}"#
    );
    let resp = io.handle_request_sync(&req).expect("response");
    serde_json::from_str(&resp).expect("json")
}

#[test]
fn valid_request_is_reported_as_not_persisted() {
    let (io, _tmp) = io();
    let v = call(
        &io,
        r#"["Example School","ops@example.org","0x1111111111111111111111111111111111111111"]"#,
    );
    let r = v
        .get("result")
        .unwrap_or_else(|| panic!("expected a result, got {v}"));
    assert_eq!(r["status"], "not_persisted", "{r}");
    assert_eq!(r["persisted"], false, "{r}");
    assert_ne!(r["status"], "registered");
    assert!(
        r.get("isActive").is_none(),
        "no activation state for an unpersisted request: {r}"
    );
    assert!(
        r.get("registeredAt").is_none(),
        "no registration timestamp: {r}"
    );
    assert_eq!(
        r["operatorAddress"],
        "0x1111111111111111111111111111111111111111"
    );
}

#[test]
fn malformed_operator_address_is_rejected() {
    let (io, _tmp) = io();
    let v = call(&io, r#"["Example School","ops@example.org","0x1234"]"#);
    assert!(
        v.get("error").is_some(),
        "short address must be an error: {v}"
    );
}
