// WebSocket server admission limits, pinned through the real listener.
//
// 1. The global socket cap is taken at accept(), before the upgrade, so
//    sockets that never upgrade count against it too. The existing tests pin
//    the per-IP cap and the handshake timeout; this pins the global cap (set
//    below the per-IP cap so it is the one that binds).
// 2. `eth_subscribe("logs", filter)` keeps its filter for the connection's
//    lifetime, so the filter is bounded exactly like `eth_newFilter`.
// 3. The accept loop retries after an accept error instead of returning.
//
// Local only: the server binds 127.0.0.1 inside this process.

use citrate_api::eth_subscriptions::WsLimits;
use citrate_api::EthSubscriptionServer;
use citrate_sequencer::mempool::{Mempool, MempoolConfig};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

async fn spawn_ws(limits: Option<WsLimits>) -> (std::net::SocketAddr, TempDir) {
    let tmp = TempDir::new().expect("tempdir");
    let storage =
        Arc::new(StorageManager::new(tmp.path(), PruningConfig::default()).expect("storage"));
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", free_port()).parse().expect("addr");
    let mut srv = EthSubscriptionServer::new(addr, storage, mempool);
    if let Some(l) = limits {
        srv = srv.with_limits(l);
    }
    tokio::spawn(Arc::new(srv).start());
    tokio::time::sleep(Duration::from_millis(300)).await;
    (addr, tmp)
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
async fn sockets_past_the_global_cap_are_dropped_before_the_handshake() {
    const GLOBAL: usize = 4;
    let (addr, _tmp) = spawn_ws(Some(WsLimits {
        max_sockets: GLOBAL,
        max_per_ip: 100,
        handshake_timeout: Duration::from_secs(60),
    }))
    .await;
    let mut socks = Vec::new();
    for _ in 0..GLOBAL + 3 {
        socks.push(std::net::TcpStream::connect(addr).expect("connect"));
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let extra = socks.split_off(GLOBAL);
    let (refused, first_open) = tokio::task::spawn_blocking(move || {
        let mut extra = extra;
        let refused = extra
            .iter_mut()
            .map(|s| closed_by_server(s, Duration::from_secs(2)))
            .filter(|closed| *closed)
            .count();
        let first = socks.first_mut().expect("one admitted socket");
        let first_open = !closed_by_server(first, Duration::from_secs(1));
        (refused, first_open)
    })
    .await
    .expect("join");
    assert_eq!(
        refused, 3,
        "sockets past the global cap must be dropped before the handshake"
    );
    assert!(first_open, "a socket inside the cap waits for its upgrade");
}

fn subscribe_logs(filter: serde_json::Value, id: u32) -> String {
    serde_json::json!({
        "jsonrpc": "2.0", "id": id, "method": "eth_subscribe", "params": ["logs", filter]
    })
    .to_string()
}

async fn round_trip<S>(ws: &mut S, msg: String) -> serde_json::Value
where
    S: futures::Sink<tokio_tungstenite::tungstenite::Message>
        + futures::Stream<
            Item = Result<
                tokio_tungstenite::tungstenite::Message,
                tokio_tungstenite::tungstenite::Error,
            >,
        > + Unpin,
    <S as futures::Sink<tokio_tungstenite::tungstenite::Message>>::Error: std::fmt::Debug,
{
    use futures::{SinkExt, StreamExt};
    ws.send(tokio_tungstenite::tungstenite::Message::Text(msg))
        .await
        .expect("send");
    let frame = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("reply in time")
        .expect("open")
        .expect("frame");
    serde_json::from_str(frame.to_text().expect("text")).expect("json")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logs_subscription_filter_is_bounded() {
    let (addr, _tmp) = spawn_ws(None).await;
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}"))
        .await
        .expect("ws connect");

    let addrs: Vec<String> = (0..33).map(|i| format!("0x{:040x}", i + 1)).collect();
    let over = subscribe_logs(serde_json::json!({ "address": addrs }), 1);
    let within = subscribe_logs(serde_json::json!({ "address": addrs[..32] }), 2);
    let r_over = round_trip(&mut ws, over).await;
    assert_eq!(
        r_over["error"]["code"].as_i64(),
        Some(-32602),
        "a logs subscription with 33 addresses must be refused: {r_over}"
    );
    let r_within = round_trip(&mut ws, within).await;
    assert!(
        r_within.get("result").is_some(),
        "a logs subscription at the 32-address limit is accepted: {r_within}"
    );
}

#[tokio::test]
async fn the_accept_loop_survives_accept_errors() {
    // The server's accept loop must log and retry an accept error (EMFILE and
    // the like), not return. Drive it with an accept source that fails three
    // times and then hands over a real connection.
    use citrate_api::eth_subscriptions::run_accept_loop;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let listener = Arc::new(
        tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind"),
    );
    let addr = listener.local_addr().expect("addr");
    let calls = Arc::new(AtomicUsize::new(0));
    let (handled_tx, mut handled_rx) =
        tokio::sync::mpsc::unbounded_channel::<std::net::SocketAddr>();

    let accept = {
        let listener = listener.clone();
        let calls = calls.clone();
        move || {
            let listener = listener.clone();
            let n = calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if n < 3 {
                    Err(std::io::Error::from_raw_os_error(24)) // EMFILE
                } else {
                    listener.accept().await
                }
            })
                as std::pin::Pin<
                    Box<
                        dyn std::future::Future<
                                Output = std::io::Result<(
                                    tokio::net::TcpStream,
                                    std::net::SocketAddr,
                                )>,
                            > + Send,
                    >,
                >
        }
    };
    let loop_task = tokio::spawn(run_accept_loop(accept, move |_stream, peer| {
        let _ = handled_tx.send(peer);
    }));

    let _client = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let handled = tokio::time::timeout(Duration::from_secs(5), handled_rx.recv()).await;
    assert!(
        matches!(handled, Ok(Some(_))),
        "a connection after three accept errors must still be handled"
    );
    assert!(calls.load(Ordering::SeqCst) >= 4);
    assert!(!loop_task.is_finished(), "the accept loop keeps running");
    loop_task.abort();
}
