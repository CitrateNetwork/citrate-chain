// Regression pins for input and access guards on the node's RPC surface.
//
// Each test drives the real entry point: the HTTP JSON-RPC server spawned by
// `RpcServer::spawn`, the registered eth IoHandler, the WebSocket subscription
// server the node binds, or the method object a handler delegates to. It then
// asserts that the guard holds. Each guard was checked by removing only that
// guard and confirming its test fails on an assertion.
//
// Local only: every server binds 127.0.0.1 inside this process. Script and
// file side effects stay in per-test temp dirs, and process-wide environment
// changes are made under `LOCK` and restored afterwards.

use citrate_api::rate_limit::RateLimitConfig;
use citrate_api::FilterRegistry;
use citrate_consensus::types::{Hash, PublicKey, Signature, Transaction};
use citrate_execution::executor::Executor;
use citrate_sequencer::mempool::{Mempool, MempoolConfig};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;

/// The HTTP tests share the process-global method budget and environment; run
/// them one at a time.
static LOCK: Mutex<()> = Mutex::new(());

fn lock() -> std::sync::MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Set an environment variable for the life of the guard, then restore it.
struct EnvGuard {
    key: &'static str,
    old: Option<std::ffi::OsString>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let old = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, old }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.old.take() {
            Some(v) => std::env::set_var(self.key, v),
            None => std::env::remove_var(self.key),
        }
    }
}

fn storage() -> (Arc<StorageManager>, TempDir) {
    let tmp = TempDir::new().expect("tempdir");
    let s = Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).expect("storage"));
    (s, tmp)
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

struct Rpc {
    port: u16,
    close: citrate_api::RpcCloseHandle,
    _tmp: TempDir,
}

impl Drop for Rpc {
    fn drop(&mut self) {
        self.close.clone().close();
    }
}

fn spawn_rpc() -> Rpc {
    std::env::set_var("CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT", "1");
    let (storage, tmp) = storage();
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
    Rpc {
        port,
        close,
        _tmp: tmp,
    }
}

/// POST one JSON-RPC call and return the parsed response body.
fn rpc_call(rpc: &Rpc, method: &str, params: serde_json::Value) -> serde_json::Value {
    let body =
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
    let mut s = std::net::TcpStream::connect(("127.0.0.1", rpc.port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(60)))
        .expect("timeout");
    let req = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        rpc.port,
        body.len(),
        body
    );
    s.write_all(req.as_bytes()).expect("write");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    let json = out.split("\r\n\r\n").nth(1).unwrap_or("");
    serde_json::from_str(json).unwrap_or_else(|e| panic!("bad response ({e}): {out}"))
}

fn error_code(v: &serde_json::Value) -> Option<i64> {
    v.get("error")
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_i64())
}

const UNAUTHORIZED: i64 = -32001;

// ---------------------------------------------------------------------------
// Contract-verification index: writes and deletes need the operator token.
// ---------------------------------------------------------------------------

fn verify_payload(extra: serde_json::Value) -> serde_json::Value {
    let mut p = serde_json::json!({
        "address": format!("0x{}", "ab".repeat(20)),
        "runtime_bytecode": "0x6000",
    });
    if let (Some(p), Some(extra)) = (p.as_object_mut(), extra.as_object()) {
        for (k, v) in extra {
            p.insert(k.clone(), v.clone());
        }
    }
    p
}

#[test]
fn verify_contract_requires_the_operator_token() {
    let _g = lock();
    let _tok = EnvGuard::set("CITRATE_OPERATOR_TOKEN", "operator-secret");
    let rpc = spawn_rpc();
    let none = rpc_call(
        &rpc,
        "citrate_verifyContract",
        verify_payload(serde_json::json!({})),
    );
    assert_eq!(error_code(&none), Some(UNAUTHORIZED), "no token: {none}");
    let wrong = rpc_call(
        &rpc,
        "citrate_verifyContract",
        verify_payload(serde_json::json!({"operator_token": "guess"})),
    );
    assert_eq!(
        error_code(&wrong),
        Some(UNAUTHORIZED),
        "wrong token: {wrong}"
    );
    // Control: the right token reaches the handler body (the address has no
    // code, so it reports unverified rather than an auth error).
    let ok = rpc_call(
        &rpc,
        "citrate_verifyContract",
        verify_payload(serde_json::json!({"operator_token": "operator-secret"})),
    );
    assert_eq!(error_code(&ok), None, "right token: {ok}");
    assert_eq!(ok["result"]["verified"], false, "{ok}");
}

#[test]
fn prune_verifications_requires_the_operator_token() {
    let _g = lock();
    let _tok = EnvGuard::set("CITRATE_OPERATOR_TOKEN", "operator-secret");
    let rpc = spawn_rpc();
    let none = rpc_call(
        &rpc,
        "citrate_pruneVerifications",
        serde_json::json!({"max_records": 0}),
    );
    assert_eq!(error_code(&none), Some(UNAUTHORIZED), "no token: {none}");
    let wrong = rpc_call(
        &rpc,
        "citrate_pruneVerifications",
        serde_json::json!({"max_records": 0, "operator_token": "guess"}),
    );
    assert_eq!(
        error_code(&wrong),
        Some(UNAUTHORIZED),
        "wrong token: {wrong}"
    );
    let ok = rpc_call(
        &rpc,
        "citrate_pruneVerifications",
        serde_json::json!({"max_records": 0, "operator_token": "operator-secret"}),
    );
    assert_eq!(error_code(&ok), None, "right token: {ok}");
}

// ---------------------------------------------------------------------------
// Contract verification: source handed to the compiler is size-bounded.
// ---------------------------------------------------------------------------

#[test]
fn verify_contract_refuses_oversized_source_before_compiling() {
    let _g = lock();
    let _tok = EnvGuard::set("CITRATE_OPERATOR_TOKEN", "operator-secret");
    let rpc = spawn_rpc();
    let big = "a".repeat(1_048_577);
    let v = rpc_call(
        &rpc,
        "citrate_verifyContract",
        serde_json::json!({
            "address": format!("0x{}", "ab".repeat(20)),
            "source_code": big,
            "operator_token": "operator-secret",
        }),
    );
    let reason = v["result"]["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("source too large"),
        "oversized source must be refused by the size bound: {reason}"
    );
}

#[test]
fn verify_contract_refuses_oversized_standard_json_before_compiling() {
    let _g = lock();
    let _tok = EnvGuard::set("CITRATE_OPERATOR_TOKEN", "operator-secret");
    let rpc = spawn_rpc();
    let big = "a".repeat(1_048_577);
    let v = rpc_call(
        &rpc,
        "citrate_verifyContract",
        serde_json::json!({
            "address": format!("0x{}", "ab".repeat(20)),
            "standard_json": big,
            "operator_token": "operator-secret",
        }),
    );
    let reason = v["result"]["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("standard_json too large"),
        "oversized standard-json must be refused by the size bound: {reason}"
    );
}

// ---------------------------------------------------------------------------
// Chat completion: the model name is an allowlist, never a path.
// ---------------------------------------------------------------------------

#[test]
fn chat_completion_rejects_model_names_outside_the_allowlist() {
    let _g = lock();
    // Point every home-relative model directory at an empty temp dir so no
    // real model on the host is ever reachable from this test.
    let home = TempDir::new().expect("home");
    let _home = EnvGuard::set("HOME", home.path().to_str().expect("utf8"));
    let rpc = spawn_rpc();
    let absent = home.path().join("nothing-here").join("model.gguf");
    for name in [
        absent.to_str().expect("utf8"),
        "../../outside",
        "unlisted-model",
    ] {
        let v = rpc_call(
            &rpc,
            "citrate_chatCompletion",
            serde_json::json!([{"model": name, "messages": [{"role":"user","content":"hi"}]}]),
        );
        let msg = v["error"]["message"].as_str().unwrap_or_default();
        assert!(
            msg.contains("unknown model"),
            "model {name:?} must be refused as unknown, not resolved: {v}"
        );
    }
}

// ---------------------------------------------------------------------------
// AI status: the inference-binary probe runs once per process, not per call.
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn ai_status_probes_the_inference_binary_once() {
    use std::os::unix::fs::PermissionsExt;
    let _g = lock();
    let dir = TempDir::new().expect("bin dir");
    let count = dir.path().join("calls");
    let probe = dir.path().join("llama-cli");
    std::fs::write(
        &probe,
        format!("#!/bin/sh\necho call >> '{}'\nexit 0\n", count.display()),
    )
    .expect("write probe");
    std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let path = format!(
        "{}:{}",
        dir.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let _path = EnvGuard::set("PATH", &path);
    let rpc = spawn_rpc();
    for _ in 0..3 {
        let v = rpc_call(&rpc, "citrate_getAIStatus", serde_json::json!([]));
        assert_eq!(v["result"]["gguf_engine_available"], true, "{v}");
    }
    let calls = std::fs::read_to_string(&count).unwrap_or_default();
    assert_eq!(
        calls.lines().count(),
        1,
        "three status calls must spawn the probe once, not per call"
    );
}

// ---------------------------------------------------------------------------
// Artifact pinning: the CID is sent as one encoded query parameter.
// ---------------------------------------------------------------------------

/// A one-shot HTTP endpoint standing in for the local IPFS API. It records the
/// request target and answers 200.
fn fake_ipfs() -> (String, std::thread::JoinHandle<String>) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let base = format!("http://{}", l.local_addr().expect("addr"));
    let jh = std::thread::spawn(move || {
        let (s, _) = l.accept().expect("accept");
        s.set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let mut r = BufReader::new(s.try_clone().expect("clone"));
        let mut line = String::new();
        r.read_line(&mut line).expect("request line");
        loop {
            let mut h = String::new();
            if r.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                break;
            }
        }
        let mut s = s;
        let _ = s.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        );
        line.split_whitespace().nth(1).unwrap_or("").to_string()
    });
    (base, jh)
}

fn query_pairs(target: &str) -> Vec<(String, String)> {
    let url = reqwest::Url::parse(&format!("http://h{target}")).expect("target");
    url.query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

const HOSTILE_CID: &str = "QmTest&recursive=false&progress=true#rest";

#[test]
fn pin_artifact_sends_the_cid_as_one_encoded_parameter() {
    let _g = lock();
    let (base, jh) = fake_ipfs();
    let _ipfs = EnvGuard::set("CITRATE_IPFS_PROVIDERS", &base);
    let rpc = spawn_rpc();
    let v = rpc_call(
        &rpc,
        "citrate_pinArtifact",
        serde_json::json!([HOSTILE_CID, 1]),
    );
    assert_eq!(v["result"]["status"], "ok", "{v}");
    let target = jh.join().expect("fake ipfs");
    assert!(target.starts_with("/api/v0/pin/add?"), "{target}");
    let pairs = query_pairs(&target);
    let args: Vec<&str> = pairs
        .iter()
        .filter(|(k, _)| k == "arg")
        .map(|(_, v)| v.as_str())
        .collect();
    assert_eq!(
        args,
        vec![HOSTILE_CID],
        "the whole CID is one value: {target}"
    );
    assert!(
        !pairs
            .iter()
            .any(|(k, _)| k == "recursive" || k == "progress"),
        "no caller-chosen parameter may reach the IPFS API: {target}"
    );
}

#[test]
fn artifact_status_sends_the_cid_as_one_encoded_parameter() {
    let _g = lock();
    let (base, jh) = fake_ipfs();
    let _ipfs = EnvGuard::set("CITRATE_IPFS_PROVIDERS", &base);
    let rpc = spawn_rpc();
    let _ = rpc_call(
        &rpc,
        "citrate_getArtifactStatus",
        serde_json::json!([HOSTILE_CID]),
    );
    let target = jh.join().expect("fake ipfs");
    assert!(target.starts_with("/api/v0/pin/ls?"), "{target}");
    let pairs = query_pairs(&target);
    assert_eq!(
        pairs,
        vec![("arg".to_string(), HOSTILE_CID.to_string())],
        "the whole CID is the only parameter: {target}"
    );
}

// ---------------------------------------------------------------------------
// Filters: IDs cannot be enumerated to remove another client's filter.
// ---------------------------------------------------------------------------

fn eth_io(storage: Arc<StorageManager>) -> jsonrpc_core::IoHandler {
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

fn io_call(
    io: &jsonrpc_core::IoHandler,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    let req =
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
    serde_json::from_str(&io.handle_request_sync(&req).expect("response")).expect("json")
}

#[test]
fn filter_ids_cannot_be_enumerated_to_uninstall_another_clients_filter() {
    let (storage, _tmp) = storage();
    let io = eth_io(storage);
    let mut victims = Vec::new();
    for _ in 0..4 {
        let v = io_call(&io, "eth_newBlockFilter", serde_json::json!([]));
        victims.push(v["result"].as_str().expect("filter id").to_string());
    }
    // Another client sweeps the low ID space.
    let mut removed = 0;
    for id in 1u64..=4096 {
        let v = io_call(
            &io,
            "eth_uninstallFilter",
            serde_json::json!([format!("0x{id:x}")]),
        );
        if v["result"] == true {
            removed += 1;
        }
    }
    assert_eq!(
        removed, 0,
        "a sweep of 0x1..0x1000 must not hit any live filter"
    );
    for id in &victims {
        let v = io_call(&io, "eth_getFilterChanges", serde_json::json!([id]));
        assert!(
            v.get("error").is_none(),
            "victim filter {id} must survive: {v}"
        );
    }
}

// ---------------------------------------------------------------------------
// Raw transaction submission: the wire `ecdsa_verified` flag is not trusted.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_raw_transaction_does_not_trust_a_wire_verified_flag() {
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let executor = Arc::new(Executor::new(Arc::new(citrate_execution::StateDB::new())));
    let api = citrate_api::methods::TransactionApi::new(mempool.clone(), executor, 40204);
    // An EVM-shaped sender (20-byte address, 12 zero bytes) with a signature
    // that recovers to nobody, claiming on the wire to be already verified.
    let mut from = [0u8; 32];
    from[..20].copy_from_slice(&[0xAB; 20]);
    let tx = Transaction {
        hash: Hash::new([0x5A; 32]),
        nonce: 0,
        from: PublicKey::new(from),
        to: Some(PublicKey::new([0x22; 32])),
        value: 1,
        gas_limit: 21_000,
        gas_price: 2_000_000_000,
        data: vec![],
        signature: Signature::new([0x07; 64]),
        chain_id: Some(40204),
        ecdsa_verified: true,
        ..Default::default()
    };
    let raw = bincode::serialize(&tx).expect("serialize");
    let res = api.send_raw_transaction(raw).await;
    assert!(
        res.is_err(),
        "a forged EVM-shaped transaction must be refused, not admitted on its wire flag"
    );
    assert_eq!(
        mempool.stats().await.total_transactions,
        0,
        "nothing admitted"
    );
}

// ---------------------------------------------------------------------------
// WebSocket subscriptions: per-connection and per-message caps.
// ---------------------------------------------------------------------------

async fn spawn_ws() -> (std::net::SocketAddr, TempDir) {
    let (storage, tmp) = storage();
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", free_port()).parse().expect("addr");
    let srv = Arc::new(citrate_api::EthSubscriptionServer::new(
        addr, storage, mempool,
    ));
    tokio::spawn(srv.start());
    tokio::time::sleep(Duration::from_millis(300)).await;
    (addr, tmp)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_subscriptions_per_connection_are_capped() {
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let (addr, _tmp) = spawn_ws().await;
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}"))
        .await
        .expect("ws connect");
    let mut results = Vec::new();
    for i in 0..65u32 {
        let req = serde_json::json!({"jsonrpc":"2.0","id":i,"method":"eth_subscribe","params":["newHeads"]});
        ws.send(Message::Text(req.to_string())).await.expect("send");
        let reply = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("reply in time")
            .expect("open")
            .expect("frame");
        let v: serde_json::Value =
            serde_json::from_str(reply.to_text().expect("text")).expect("json");
        results.push(v);
    }
    let accepted = results.iter().filter(|v| v.get("result").is_some()).count();
    assert_eq!(accepted, 64, "the first 64 subscriptions are accepted");
    assert_eq!(
        error_code(&results[64]),
        Some(-32005),
        "the 65th subscription on one connection must be refused: {}",
        results[64]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_oversized_message_closes_the_connection() {
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let (addr, _tmp) = spawn_ws().await;
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}"))
        .await
        .expect("ws connect");
    // 2 MiB text message: over the 1 MiB cap, far under the library default.
    let _ = ws.send(Message::Text("x".repeat(2 * 1024 * 1024))).await;
    // Then a valid request. A server that took the big message keeps the
    // connection and answers this one.
    let req =
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":"eth_subscribe","params":["newHeads"]});
    let _ = ws.send(Message::Text(req.to_string())).await;
    let answered = loop {
        match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
            Err(_) => break false,
            Ok(None) | Ok(Some(Err(_))) => break false,
            // The reply to the valid request; any other text (an error reply to
            // the big message) is skipped.
            Ok(Some(Ok(Message::Text(t)))) if t.contains("\"result\"") => break true,
            Ok(Some(Ok(Message::Close(_)))) => break false,
            Ok(Some(Ok(_))) => continue,
        }
    };
    assert!(
        !answered,
        "an over-cap message must close the connection, not be accepted"
    );
}

// ---------------------------------------------------------------------------
// REST API key: compared in constant time.
// ---------------------------------------------------------------------------

/// Source tripwire. Timing is not observable in a unit test, so this checks the
/// compare itself, like the existing tripwires for the operator token and the
/// RPC API key. The REST middleware must use `constant_time_eq` and must not
/// compare the bearer token with `==`.
#[test]
fn rest_api_key_compare_is_constant_time_source_tripwire() {
    let src = include_str!("../src/openai_api.rs");
    let start = src
        .find("async fn require_rest_api_key")
        .expect("REST auth middleware present");
    let body = &src[start..];
    let end = body.find("\n}\n").map(|i| i + 2).unwrap_or(body.len());
    let body = &body[..end];
    assert!(
        body.contains("constant_time_eq(token.as_bytes(), expected_key.as_bytes())"),
        "the REST bearer token must be compared with constant_time_eq"
    );
    let code: String = body
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code.contains("== expected_key") && !code.contains("expected_key =="),
        "no short-circuiting == on the REST key"
    );
}
