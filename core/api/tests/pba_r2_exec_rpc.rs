// PBA-R2 (lane CHAIN-EXEC) regression tests for the chain node's external RPC
// surface. Each test is the audit PoC (citrate-security
// audits/2026-09-24-prebounty-adversarial-audit/lanes/L1a-chain-execution-rpc/
// evidence/l1a_poc.rs) turned around: it drives the REAL entry point (the
// registered IoHandler, or the spawned HTTP / WebSocket server) and asserts the
// bound holds. Local only: every server binds 127.0.0.1 inside this process.

use citrate_api::rate_limit::RateLimitConfig;
use citrate_api::FilterRegistry;
use citrate_consensus::types::{BlockBuilder, Hash, PublicKey, Signature, Transaction};
use citrate_execution::executor::Executor;
use citrate_sequencer::mempool::{Mempool, MempoolConfig, TxClass};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;

/// HTTP tests share the process-global method budget; run them one at a time.
static HTTP_LOCK: Mutex<()> = Mutex::new(());

fn allow_anon_budget() {
    std::env::set_var("CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT", "1");
}

fn tx(n: u64) -> Transaction {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&n.to_be_bytes());
    Transaction {
        hash: Hash::new(h),
        nonce: n,
        from: PublicKey::new([1u8; 32]),
        to: Some(PublicKey::new([2u8; 32])),
        value: 0,
        gas_limit: 21_000,
        gas_price: 2_000_000_000,
        data: vec![],
        signature: Signature::new([7u8; 64]),
        chain_id: Some(40204),
        ..Default::default()
    }
}

/// Seed `n` blocks at heights 1..=n, each carrying one transaction.
fn storage_with_tx_blocks(n: u64) -> (Arc<StorageManager>, TempDir) {
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
    for h in 1..=n {
        let mut hb = [0u8; 32];
        hb[..8].copy_from_slice(&h.to_be_bytes());
        hb[31] = 0xAA;
        let b = BlockBuilder::new()
            .hash(Hash::new(hb))
            .parent(parent)
            .height(h)
            .timestamp(1_000_000 + h)
            .gas_limit(30_000_000)
            .gas_used(21_000)
            .base_fee_per_gas(1_000_000_000)
            .transactions(vec![tx(h)])
            .build_unhashed();
        storage.blocks.put_block(&b).expect("block");
        parent = b.hash();
    }
    (storage, tmp)
}

fn eth_io_with(storage: Arc<StorageManager>, mempool: Arc<Mempool>) -> jsonrpc_core::IoHandler {
    let executor = Arc::new(Executor::new(Arc::new(citrate_execution::StateDB::new())));
    let mut io = jsonrpc_core::IoHandler::new();
    citrate_api::eth_rpc::register_eth_methods(
        &mut io,
        storage,
        mempool,
        executor,
        40204,
        Arc::new(FilterRegistry::new()),
        None,
    );
    io
}

fn eth_io(storage: Arc<StorageManager>) -> jsonrpc_core::IoHandler {
    eth_io_with(storage, Arc::new(Mempool::new(MempoolConfig::default())))
}

fn call(io: &jsonrpc_core::IoHandler, req: &str) -> serde_json::Value {
    let resp = io.handle_request_sync(req).expect("response");
    serde_json::from_str(&resp).expect("json response")
}

fn error_code(v: &serde_json::Value) -> Option<i64> {
    v.get("error")
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_i64())
}

// ---------------------------------------------------------------------------
// PBA-L1a-002 (HIGH): eth_feeHistory rewardPercentiles amplification.
// ---------------------------------------------------------------------------

fn fee_history_req(block_count: &str, n_percentiles: usize) -> String {
    let list = vec!["50"; n_percentiles].join(",");
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"eth_feeHistory","params":["{block_count}","latest",[{list}]]}}"#
    )
}

#[test]
fn pba_l1a_002_fee_history_rejects_more_than_100_percentiles() {
    allow_anon_budget();
    let (storage, _tmp) = storage_with_tx_blocks(8);
    let io = eth_io(storage);
    let v = call(&io, &fee_history_req("0x400", 101));
    assert_eq!(
        error_code(&v),
        Some(-32602),
        "101 percentiles must be invalid params: {v}"
    );
    // The audit PoC's 50,000-entry list is refused before any block is read.
    let v = call(&io, &fee_history_req("0x400", 50_000));
    assert_eq!(
        error_code(&v),
        Some(-32602),
        "50k percentiles must be refused: {v}"
    );
}

#[test]
fn pba_l1a_002_fee_history_response_is_bounded() {
    allow_anon_budget();
    let (storage, _tmp) = storage_with_tx_blocks(64);
    let io = eth_io(storage);
    let v = call(&io, &fee_history_req("0x400", 100));
    let reward = v["result"]["reward"].as_array().expect("reward array");
    let total: usize = reward
        .iter()
        .map(|r| r.as_array().map_or(0, |a| a.len()))
        .sum();
    // 64 tx-bearing blocks x 100 percentiles, plus the empty genesis block's
    // single placeholder entry (heights 0..=64 are in the window).
    assert!(
        total <= 65 * 100,
        "response must be bounded by blocks x 100: {total}"
    );
    assert_eq!(
        total,
        64 * 100 + 1,
        "100 percentiles over 64 tx-bearing blocks are all served"
    );
}

#[test]
fn pba_l1a_002_fee_history_validates_percentile_values() {
    allow_anon_budget();
    let (storage, _tmp) = storage_with_tx_blocks(2);
    let io = eth_io(storage);
    for bad in ["[101]", "[-1]", "[50,10]", "[\"x\"]", "\"50\""] {
        let req = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"eth_feeHistory","params":["0x2","latest",{bad}]}}"#
        );
        let v = call(&io, &req);
        assert_eq!(
            error_code(&v),
            Some(-32602),
            "percentiles {bad} must be rejected: {v}"
        );
    }
    let ok = r#"{"jsonrpc":"2.0","id":1,"method":"eth_feeHistory","params":["0x2","latest",[0,25,25,100]]}"#;
    let v = call(&io, ok);
    assert!(
        v.get("result").is_some(),
        "monotonic 0..=100 list is accepted: {v}"
    );
}

// ---------------------------------------------------------------------------
// PBA-L1a-020 (LOW): blockCount 0x0 underflow panic.
// ---------------------------------------------------------------------------

#[test]
fn pba_l1a_020_fee_history_zero_block_count_does_not_panic() {
    allow_anon_budget();
    let (storage, _tmp) = storage_with_tx_blocks(2);
    let io = eth_io(storage);
    let req = r#"{"jsonrpc":"2.0","id":1,"method":"eth_feeHistory","params":["0x0","latest",[]]}"#;
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| call(&io, req)));
    let v = r.expect("eth_feeHistory(0x0) must not panic the handler");
    assert_eq!(v["result"]["reward"], serde_json::json!([]), "{v}");
}

// ---------------------------------------------------------------------------
// PBA-L1a-010 (MEDIUM): unbounded filter criteria.
// ---------------------------------------------------------------------------

#[test]
fn pba_l1a_010_filter_criteria_are_bounded() {
    allow_anon_budget();
    let (storage, _tmp) = storage_with_tx_blocks(1);
    let io = eth_io(storage);
    // The audit PoC: 1,000,000 null topic positions.
    let topics = vec!["null"; 1_000_000].join(",");
    for method in ["eth_newFilter", "eth_getLogs"] {
        let req = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":[{{"fromBlock":"latest","topics":[{topics}]}}]}}"#
        );
        let v = call(&io, &req);
        assert_eq!(
            error_code(&v),
            Some(-32602),
            "{method}: 1M topic positions: {v}"
        );
    }
    let many_addrs = vec!["\"0x0000000000000000000000000000000000000001\""; 33].join(",");
    let req = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"eth_newFilter","params":[{{"address":[{many_addrs}]}}]}}"#
    );
    assert_eq!(error_code(&call(&io, &req)), Some(-32602), "33 addresses");
    let h = "\"0x0000000000000000000000000000000000000000000000000000000000000001\"";
    let alts = vec![h; 33].join(",");
    let req = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"eth_newFilter","params":[{{"topics":[[{alts}]]}}]}}"#
    );
    assert_eq!(
        error_code(&call(&io, &req)),
        Some(-32602),
        "33 topic alternatives"
    );
    // Exactly at the caps is accepted.
    let addrs32 = vec!["\"0x0000000000000000000000000000000000000001\""; 32].join(",");
    let req = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"eth_newFilter","params":[{{"address":[{addrs32}]}}]}}"#
    );
    assert!(
        call(&io, &req)["result"].is_string(),
        "32 addresses accepted"
    );
    let alts32 = vec![h; 32].join(",");
    let req = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"eth_newFilter","params":[{{"topics":[[{alts32}]]}}]}}"#
    );
    assert!(
        call(&io, &req)["result"].is_string(),
        "32 alternatives accepted"
    );
    // Normal-shaped criteria still work.
    let req = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"eth_newFilter","params":[{{"topics":[{h},null,[{h},{h}],null]}}]}}"#
    );
    let v = call(&io, &req);
    assert!(
        v["result"].is_string(),
        "4 positions / 2 alternatives accepted: {v}"
    );
}

// ---------------------------------------------------------------------------
// PBA-L1a-021 (LOW): eth_getTransactionCount(pending) with a u64::MAX nonce.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pba_l1a_021_pending_nonce_max_does_not_panic() {
    allow_anon_budget();
    let (storage, _tmp) = storage_with_tx_blocks(1);
    let mempool = Arc::new(Mempool::new(MempoolConfig {
        require_valid_signature: false,
        max_nonce_gap: u64::MAX,
        ..Default::default()
    }));
    // A native (non-EVM-shaped) sender so the EVM recovery gate does not apply.
    let from = PublicKey::new([0x5A; 32]);
    let mut t = tx(u64::MAX);
    t.from = from;
    t.nonce = u64::MAX;
    t.hash = Hash::new([0x77; 32]);
    if mempool.add_transaction(t, TxClass::Standard).await.is_err() {
        // Once admission rejects u64::MAX nonces (PBA-L1a-001, consensus lane)
        // this RPC path cannot see one; the overflow-safety of the lookup itself
        // is pinned by the sequencer unit test
        // `pba_l1a_021_pending_nonce_matching_is_overflow_safe`.
        return;
    }
    let addr = citrate_execution::address_utils::normalize_address(&from);
    let io = eth_io_with(storage, mempool);
    let req = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionCount","params":["0x{}","pending"]}}"#,
        hex::encode(addr.0)
    );
    let io = Arc::new(io);
    let v = tokio::task::spawn_blocking(move || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| call(&io, &req)))
    })
    .await
    .expect("join")
    .expect("pending nonce lookup must not panic on a u64::MAX pending nonce");
    assert!(v.get("result").is_some(), "{v}");
}

// ---------------------------------------------------------------------------
// HTTP server helpers
// ---------------------------------------------------------------------------

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

fn http_post_host(port: u16, host: &str, body: &str) -> String {
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(30)))
        .expect("timeout");
    let req = format!(
        "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    s.write_all(req.as_bytes()).expect("write");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn http_post(port: u16, body: &str) -> String {
    http_post_host(port, &format!("127.0.0.1:{port}"), body)
}

fn spawn_rpc(
    storage: Arc<StorageManager>,
    rate_limit: RateLimitConfig,
) -> (u16, citrate_api::RpcCloseHandle) {
    let port = free_port();
    let cfg = citrate_api::RpcConfig {
        listen_addr: format!("127.0.0.1:{port}").parse().expect("addr"),
        rate_limit,
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

fn body_of(resp: &str) -> &str {
    resp.split("\r\n\r\n").nth(1).unwrap_or("")
}

// ---------------------------------------------------------------------------
// PBA-L1a-009 (MEDIUM) + PBA-L1a-002 remediation "cap JSON-RPC batch size".
// ---------------------------------------------------------------------------

#[test]
fn pba_l1a_009_batch_over_cap_is_refused() {
    let _g = HTTP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    allow_anon_budget();
    let (storage, _tmp) = storage_with_tx_blocks(2);
    let (port, close) = spawn_rpc(storage, RateLimitConfig::default());
    let batch = |n: usize| {
        let calls: Vec<String> = (0..n)
            .map(|i| {
                format!(r#"{{"jsonrpc":"2.0","id":{i},"method":"eth_blockNumber","params":[]}}"#)
            })
            .collect();
        format!("[{}]", calls.join(","))
    };
    let resp = http_post(port, &batch(101));
    let v: serde_json::Value = serde_json::from_str(body_of(&resp)).expect("json body");
    assert_eq!(
        error_code(&v),
        Some(-32600),
        "101-call batch must be refused: {resp}"
    );
    let resp = http_post(port, &batch(100));
    let v: serde_json::Value = serde_json::from_str(body_of(&resp)).expect("json body");
    assert_eq!(
        v.as_array().map(|a| a.len()),
        Some(100),
        "100-call batch is served"
    );
    close.close();
}

#[test]
fn pba_l1a_009_batch_elements_are_charged_as_requests() {
    let _g = HTTP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    allow_anon_budget();
    let (storage, _tmp) = storage_with_tx_blocks(2);
    // The audit PoC shape: a 3-request window.
    let (port, close) = spawn_rpc(
        storage,
        RateLimitConfig {
            max_requests: 3,
            window_secs: 60,
            ..Default::default()
        },
    );
    let calls: Vec<String> = (0..50)
        .map(|i| format!(r#"{{"jsonrpc":"2.0","id":{i},"method":"eth_blockNumber","params":[]}}"#))
        .collect();
    let resp = http_post(port, &format!("[{}]", calls.join(",")));
    let body = body_of(&resp);
    let executed = body.matches("\"result\"").count();
    assert_eq!(
        executed, 0,
        "a 50-call batch must not run under a 3-request limit: {resp}"
    );
    assert!(body.contains("-32099"), "rate-limit error expected: {resp}");
    close.close();
}

// ---------------------------------------------------------------------------
// PBA-L1a-016 (MEDIUM): heavy compute RPCs cost 1.
// ---------------------------------------------------------------------------

#[test]
fn pba_l1a_016_heavy_methods_consume_the_method_budget() {
    let _g = HTTP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::thread::sleep(Duration::from_millis(1100)); // fresh 1 s budget window
    let (storage, _tmp) = storage_with_tx_blocks(1);
    let (port, close) = spawn_rpc(storage, RateLimitConfig::default());
    // 11 inference calls in ONE request: at cost 100 each the 1000-unit budget
    // admits 10; the 11th must be refused with the budget error (-32005).
    let calls: Vec<String> = (0..11)
        .map(|i| {
            format!(
                r#"{{"jsonrpc":"2.0","id":{i},"method":"citrate_runInference","params":[{{"model_id":"0x{}","input":"0x00","max_gas":1000}}]}}"#,
                "11".repeat(32)
            )
        })
        .collect();
    let resp = http_post(port, &format!("[{}]", calls.join(",")));
    assert!(
        body_of(&resp).contains("-32005"),
        "the 11th heavy call must exceed the method budget: {resp}"
    );
    close.close();
}

// ---------------------------------------------------------------------------
// PBA-L1a-023 (LOW): no Host allowlist on a loopback RPC (DNS rebinding).
// ---------------------------------------------------------------------------

#[test]
fn pba_l1a_023_loopback_rpc_rejects_foreign_host_header() {
    let _g = HTTP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    allow_anon_budget();
    let (storage, _tmp) = storage_with_tx_blocks(1);
    let (port, close) = spawn_rpc(storage, RateLimitConfig::default());
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}"#;
    let evil = http_post_host(port, "rebind.attacker.example", body);
    assert!(
        evil.starts_with("HTTP/1.1 403"),
        "a rebinding Host must be refused: {}",
        evil.lines().next().unwrap_or("")
    );
    for host in [format!("127.0.0.1:{port}"), format!("localhost:{port}")] {
        let ok = http_post_host(port, &host, body);
        assert!(
            ok.starts_with("HTTP/1.1 200"),
            "{host}: {}",
            ok.lines().next().unwrap_or("")
        );
    }
    close.close();
}

#[test]
fn pba_l1a_023_host_policy_table() {
    use citrate_api::server::rpc_host_allowlist;
    let lo: std::net::SocketAddr = "127.0.0.1:8545".parse().expect("addr");
    let public: std::net::SocketAddr = "0.0.0.0:8545".parse().expect("addr");
    assert!(
        rpc_host_allowlist(&lo, &[], false).is_some(),
        "loopback, unproxied: restricted"
    );
    assert!(
        rpc_host_allowlist(&lo, &[], true).is_none(),
        "proxied: proxy forwards public Host"
    );
    assert!(
        rpc_host_allowlist(&public, &[], false).is_none(),
        "public bind: unchanged"
    );
    let explicit = rpc_host_allowlist(&public, &["rpc.example.org".to_string()], false)
        .expect("explicit allowlist applies to any bind");
    assert!(explicit.iter().any(|h| h == "rpc.example.org"));
}

// ---------------------------------------------------------------------------
// PBA-L1a-005 (MEDIUM): WebSocket pre-handshake sockets.
// ---------------------------------------------------------------------------

async fn spawn_ws() -> (
    std::net::SocketAddr,
    TempDir,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let tmp = TempDir::new().expect("tempdir");
    let storage =
        Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).expect("storage"));
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", free_port()).parse().expect("addr");
    let srv = Arc::new(citrate_api::EthSubscriptionServer::new(
        addr, storage, mempool,
    ));
    let task = tokio::spawn(srv.start());
    tokio::time::sleep(Duration::from_millis(300)).await;
    (addr, tmp, task)
}

/// true once the server has closed this (never-upgraded) socket.
fn closed_by_server(s: &mut std::net::TcpStream, wait: Duration) -> bool {
    s.set_read_timeout(Some(wait)).expect("timeout");
    let mut b = [0u8; 1];
    match s.read(&mut b) {
        Ok(0) => true,
        Ok(_) => false,
        Err(e) => matches!(
            e.kind(),
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
        ),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pba_l1a_005_ws_pre_handshake_sockets_are_capped_per_ip() {
    let (addr, _tmp, task) = spawn_ws().await;
    let mut socks = Vec::new();
    for _ in 0..40 {
        socks.push(std::net::TcpStream::connect(addr).expect("connect"));
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let extra: Vec<std::net::TcpStream> = socks.split_off(32);
    let refused = tokio::task::spawn_blocking(move || {
        let mut extra = extra;
        extra
            .iter_mut()
            .map(|s| closed_by_server(s, Duration::from_secs(2)))
            .filter(|closed| *closed)
            .count()
    })
    .await
    .expect("join");
    assert_eq!(
        refused, 8,
        "sockets past the 32-per-IP cap must be dropped before the handshake"
    );
    assert!(!task.is_finished(), "server keeps running");
    drop(socks);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pba_l1a_005_ws_handshake_times_out() {
    let (addr, _tmp, task) = spawn_ws().await;
    let s = std::net::TcpStream::connect(addr).expect("connect");
    // Never send the HTTP upgrade. The server must drop us after the 10 s
    // handshake window instead of holding the fd forever.
    let closed = tokio::task::spawn_blocking(move || {
        let mut s = s;
        closed_by_server(&mut s, Duration::from_secs(20))
    })
    .await
    .expect("join");
    assert!(
        closed,
        "an un-upgraded socket must be closed by the handshake timeout"
    );
    assert!(!task.is_finished());
}

// ---------------------------------------------------------------------------
// PBA-L1a-018 (MEDIUM): RLP re-encoding malleability.
// ---------------------------------------------------------------------------

fn be_trim(b: &[u8]) -> Vec<u8> {
    let first = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    b[first..].to_vec()
}

/// A validly signed EIP-155 legacy tx; `mutate` may tamper with the RLP
/// encoding of the final (signed) list.
fn signed_legacy(extra_item: bool, r_leading_zero: bool) -> Vec<u8> {
    use secp256k1::{Message, Secp256k1, SecretKey};
    use sha3::{Digest, Keccak256};
    let chain_id = 40204u64;
    let to = [0x22u8; 20];
    let mut unsigned = rlp::RlpStream::new_list(9);
    unsigned.append(&3u64);
    unsigned.append(&1_000_000_000u64);
    unsigned.append(&21_000u64);
    unsigned.append(&to.as_slice());
    unsigned.append(&5u64);
    unsigned.append_empty_data();
    unsigned.append(&chain_id);
    unsigned.append(&0u8);
    unsigned.append(&0u8);
    let sighash = Keccak256::digest(unsigned.out());
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[7u8; 32]).expect("key");
    let sig = secp.sign_ecdsa_recoverable(&Message::from_slice(&sighash).expect("msg"), &sk);
    let (recid, rs) = sig.serialize_compact();
    let v = chain_id * 2 + 35 + recid.to_i32() as u64;
    let mut r = be_trim(&rs[..32]);
    if r_leading_zero {
        r.insert(0, 0);
    }
    let s = be_trim(&rs[32..]);
    let mut signed = rlp::RlpStream::new_list(if extra_item { 10 } else { 9 });
    signed.append(&3u64);
    signed.append(&1_000_000_000u64);
    signed.append(&21_000u64);
    signed.append(&to.as_slice());
    signed.append(&5u64);
    signed.append_empty_data();
    signed.append(&v);
    signed.append(&r.as_slice());
    signed.append(&s.as_slice());
    if extra_item {
        signed.append(&0xdeadu64);
    }
    signed.out().to_vec()
}

#[test]
fn pba_l1a_018_legacy_tx_has_one_encoding() {
    use citrate_api::eth_tx_decoder::decode_eth_transaction;
    let raw = signed_legacy(false, false);
    let tx = decode_eth_transaction(&raw).expect("canonical signed tx decodes");
    assert_eq!(tx.nonce, 3);

    // (a) extra list item: same signer/nonce, different raw bytes => new hash
    let extra = signed_legacy(true, false);
    assert!(
        decode_eth_transaction(&extra).is_err(),
        "an extra RLP list item must be rejected (re-hash malleability)"
    );
    // (b) trailing bytes after the list
    let mut trailing = raw.clone();
    trailing.push(0x80);
    assert!(
        decode_eth_transaction(&trailing).is_err(),
        "trailing bytes must be rejected"
    );
    // (c) r with a leading zero byte (non-canonical integer)
    let padded = signed_legacy(false, true);
    assert!(
        decode_eth_transaction(&padded).is_err(),
        "zero-padded r must be rejected"
    );
}

#[test]
fn pba_l1a_018_typed_tx_y_parity_and_trailing_bytes() {
    use citrate_api::eth_tx_decoder::decode_eth_transaction;
    use secp256k1::{Message, Secp256k1, SecretKey};
    use sha3::{Digest, Keccak256};
    let chain_id = 40204u64;
    let to = [0x22u8; 20];
    let body = |s: &mut rlp::RlpStream| {
        s.append(&chain_id);
        s.append(&1u64);
        s.append(&1_000_000_000u64);
        s.append(&2_000_000_000u64);
        s.append(&21_000u64);
        s.append(&to.as_slice());
        s.append(&0u64);
        s.append_empty_data();
        s.begin_list(0);
    };
    let mut unsigned = rlp::RlpStream::new_list(9);
    body(&mut unsigned);
    let mut pre = vec![0x02u8];
    pre.extend_from_slice(&unsigned.out());
    let sighash = Keccak256::digest(&pre);
    let sig = Secp256k1::new().sign_ecdsa_recoverable(
        &Message::from_slice(&sighash).expect("msg"),
        &SecretKey::from_slice(&[9u8; 32]).expect("key"),
    );
    let (recid, rs) = sig.serialize_compact();
    let encode = |y: u64, trailing: bool| {
        let mut s = rlp::RlpStream::new_list(12);
        body(&mut s);
        s.append(&y);
        s.append(&be_trim(&rs[..32]).as_slice());
        s.append(&be_trim(&rs[32..]).as_slice());
        let mut out = vec![0x02u8];
        out.extend_from_slice(&s.out());
        if trailing {
            out.push(0x80);
        }
        out
    };
    let y = recid.to_i32() as u64;
    decode_eth_transaction(&encode(y, false)).expect("canonical EIP-1559 tx decodes");
    // yParity 2/3 used to be masked to 0/1: same signer, new hash.
    assert!(
        decode_eth_transaction(&encode(y + 2, false)).is_err(),
        "yParity > 1 must be rejected"
    );
    assert!(
        decode_eth_transaction(&encode(y, true)).is_err(),
        "trailing bytes must be rejected"
    );
}

// ---------------------------------------------------------------------------
// PBA-L1a-002: feeHistory is budget-priced and batch responses are bounded.
// ---------------------------------------------------------------------------

#[test]
fn fee_history_cost_scales_with_response() {
    use citrate_api::eth_rpc::fee_history_cost;
    assert_eq!(fee_history_cost(1, 0), 11);
    assert_eq!(fee_history_cost(1024, 100), 10 + 101);
    assert!(fee_history_cost(1024, 100) > fee_history_cost(512, 100));
    assert_eq!(fee_history_cost(u64::MAX, usize::MAX), u32::MAX);
}

#[test]
fn batch_response_cap_replaces_oversized_result() {
    use citrate_api::rpc_limits::{cap_batch_response, MAX_BATCH_RESPONSE_BYTES};
    use jsonrpc_core::{Id, Output, Response, Success, Value, Version};
    let big = Value::String("x".repeat(MAX_BATCH_RESPONSE_BYTES));
    let r = Response::Batch(vec![Output::Success(Success {
        jsonrpc: Some(Version::V2),
        result: big,
        id: Id::Num(1),
    })]);
    let capped = cap_batch_response(Some(r)).expect("response");
    let s = serde_json::to_string(&capped).expect("json");
    assert!(
        s.len() < 1024 && s.contains("-32003"),
        "{}",
        &s[..s.len().min(200)]
    );
    let small = Response::Batch(vec![Output::Success(Success {
        jsonrpc: Some(Version::V2),
        result: Value::Bool(true),
        id: Id::Num(1),
    })]);
    let kept = cap_batch_response(Some(small.clone())).expect("response");
    assert_eq!(
        serde_json::to_string(&kept).expect("json"),
        serde_json::to_string(&small).expect("json")
    );
    assert!(cap_batch_response(None).is_none());
}

#[test]
fn fee_history_batch_response_is_bounded() {
    let _g = HTTP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::thread::sleep(Duration::from_millis(1100)); // fresh budget window
    let (storage, _tmp) = storage_with_tx_blocks(300);
    let (port, close) = spawn_rpc(storage, RateLimitConfig::default());
    let pcts = vec!["50"; 100].join(",");
    let calls: Vec<String> = (0..100)
        .map(|i| {
            format!(
                r#"{{"jsonrpc":"2.0","id":{i},"method":"eth_feeHistory","params":["0x400","latest",[{pcts}]]}}"#
            )
        })
        .collect();
    let resp = http_post(port, &format!("[{}]", calls.join(",")));
    let body = body_of(&resp);
    assert!(
        body.len() < citrate_api::rpc_limits::MAX_BATCH_RESPONSE_BYTES,
        "batch response {} bytes",
        body.len()
    );
    assert!(
        body.contains("-32005"),
        "later calls exceed the method budget"
    );
    close.close();
}
