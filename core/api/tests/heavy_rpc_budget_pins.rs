// Every heavy compute RPC is charged against the per-client method budget,
// pinned through the real HTTP server.
//
// The existing test sends 11 `citrate_runInference` calls and expects the 11th
// to be refused. This covers the other heavy methods. Each test first spends
// the 1000-unit window with 10 `citrate_runInference` calls (100 units each),
// then sends ONE call of the method under test with empty params. If that
// method is charged, the budget error (-32005) comes back before its handler
// runs; if it were free, the handler would run and reject the empty params
// instead (-32602). The empty params also mean no handler does any work.
//
// Local only: the server binds 127.0.0.1 inside this process.

use citrate_api::rate_limit::RateLimitConfig;
use citrate_consensus::types::{BlockBuilder, Hash};
use citrate_execution::executor::Executor;
use citrate_sequencer::mempool::{Mempool, MempoolConfig};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use serde_json::Value;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;

/// The method budget is process-global; run these one at a time, each in a
/// fresh one-second window.
static LOCK: Mutex<()> = Mutex::new(());

fn storage() -> (Arc<StorageManager>, TempDir) {
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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

fn spawn_rpc(storage: Arc<StorageManager>) -> (u16, citrate_api::RpcCloseHandle) {
    let port = free_port();
    let cfg = citrate_api::RpcConfig {
        listen_addr: format!("127.0.0.1:{port}").parse().expect("addr"),
        rate_limit: RateLimitConfig::default(),
        ..Default::default()
    };
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let executor = Arc::new(Executor::new(Arc::new(citrate_execution::StateDB::new())));
    let pm = Arc::new(citrate_network::peer::PeerManager::new(
        citrate_network::peer::PeerManagerConfig::default(),
    ));
    let rpc = citrate_api::RpcServer::new(cfg, storage, mempool, pm, executor, 40204);
    let (close, _jh) = rpc.spawn().expect("spawn rpc");
    (port, close)
}

fn http_post(port: u16, body: &str) -> String {
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(30)))
        .expect("timeout");
    let req = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    s.write_all(req.as_bytes()).expect("write");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// JSON-RPC error code of the response with `id`, from a batch response.
fn error_code_for(resp: &str, id: u64) -> Option<i64> {
    let body = resp.split("\r\n\r\n").nth(1)?;
    let v: Value = serde_json::from_str(body).ok()?;
    v.as_array()?
        .iter()
        .find(|r| r.get("id").and_then(Value::as_u64) == Some(id))?
        .get("error")?
        .get("code")?
        .as_i64()
}

/// Spend the budget window with 10 `citrate_runInference` calls, then call
/// `method` once (id 99) with empty params; return that call's error code.
fn code_after_spent_budget(method: &str) -> Option<i64> {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::thread::sleep(Duration::from_millis(1100)); // fresh window
    let (storage, _tmp) = storage();
    let (port, close) = spawn_rpc(storage);
    let mut calls: Vec<String> = (0..10)
        .map(|i| {
            format!(
                r#"{{"jsonrpc":"2.0","id":{i},"method":"citrate_runInference","params":[{{"model_id":"0x{}","input":"0x00","max_gas":1000}}]}}"#,
                "11".repeat(32)
            )
        })
        .collect();
    calls.push(format!(
        r#"{{"jsonrpc":"2.0","id":99,"method":"{method}","params":[]}}"#
    ));
    let resp = http_post(port, &format!("[{}]", calls.join(",")));
    close.close();
    error_code_for(&resp, 99)
}

fn assert_charged(method: &str) {
    assert_eq!(
        code_after_spent_budget(method),
        Some(-32005),
        "{method} must be charged against the method budget (refused once the window is spent)"
    );
}

#[test]
fn request_inference_is_charged_against_the_method_budget() {
    assert_charged("citrate_requestInference");
}

#[test]
fn chat_completion_is_charged_against_the_method_budget() {
    assert_charged("citrate_chatCompletion");
}

#[test]
fn text_embedding_is_charged_against_the_method_budget() {
    assert_charged("citrate_getTextEmbedding");
}

#[test]
fn semantic_search_is_charged_against_the_method_budget() {
    assert_charged("citrate_semanticSearch");
}

#[test]
fn pin_artifact_is_charged_against_the_method_budget() {
    assert_charged("citrate_pinArtifact");
}

#[test]
fn a_cheap_method_is_not_refused_by_a_spent_heavy_budget() {
    // Control: a method with no heavy cost is still served after the heavy
    // budget is spent, so the tests above are not passing because every call
    // after the 10th is refused.
    assert_ne!(code_after_spent_budget("eth_chainId"), Some(-32005));
}
