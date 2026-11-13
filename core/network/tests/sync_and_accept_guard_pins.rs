// Sync-response scoping and inbound accept rate, pinned at their entry points.
//
// 1. `SyncManager::handle_headers` / `handle_blocks` retire only the pending
//    requests of the peer that answered. A response from one peer must leave
//    another peer's outstanding request in place, so that `check_timeouts`
//    still reports it once it expires. Driven through the public
//    `request_*` -> `handle_*` -> `check_timeouts` path the node uses.
// 2. The Noise listener limits how many inbound connections one source IP may
//    open within the accept window. Connections over the limit are closed
//    before the handshake starts; connections under it are kept open waiting
//    for the client's first handshake message.
//
// Local only: listeners bind 127.0.0.1 inside this process; no files are
// written.

use citrate_consensus::types::Hash;
use citrate_network::noise::NoiseKeypair;
use citrate_network::peer::{Direction, PeerManagerConfig};
use citrate_network::transport::HandshakeParams;
use citrate_network::{
    NetworkMessage, NetworkTransport, Peer, PeerId, PeerInfo, PeerManager, SyncConfig, SyncManager,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Sync: a response retires only the responding peer's requests.
// ---------------------------------------------------------------------------

const SHORT_TIMEOUT: Duration = Duration::from_millis(50);

fn sync_manager() -> SyncManager {
    SyncManager::new(SyncConfig {
        request_timeout: SHORT_TIMEOUT,
        ..SyncConfig::default()
    })
}

/// A connected peer whose outbound queue is drained by the returned receiver
/// (kept alive so `send` succeeds).
fn peer(id: &str, port: u16) -> (Peer, mpsc::Receiver<NetworkMessage>) {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
    let info = PeerInfo::new(PeerId::new(id.into()), addr, Direction::Outbound);
    let (send_tx, send_rx) = mpsc::channel(16);
    let (_recv_tx, recv_rx) = mpsc::channel(16);
    (Peer::new(info, send_tx, recv_rx), send_rx)
}

async fn timed_out_peers(sync: &SyncManager) -> Vec<(Hash, String)> {
    tokio::time::sleep(SHORT_TIMEOUT * 3).await;
    sync.check_timeouts()
        .await
        .into_iter()
        .map(|(h, p)| (h, p.0))
        .collect()
}

#[tokio::test]
async fn headers_from_one_peer_leave_another_peers_request_to_time_out() {
    let sync = sync_manager();
    let (a, _a_rx) = peer("peer-a", 30001);
    let (b, _b_rx) = peer("peer-b", 30002);
    let from_a = Hash::new([0xA1; 32]);
    let from_b = Hash::new([0xB1; 32]);
    sync.request_headers(&a, from_a).await.expect("request a");
    sync.request_headers(&b, from_b).await.expect("request b");
    assert_eq!(sync.pending_counts().await.0, 2);

    // Peer B answers with an empty batch.
    let _ = sync
        .handle_headers(&PeerId::new("peer-b".into()), vec![])
        .await;

    let timed_out = timed_out_peers(&sync).await;
    assert!(
        timed_out.contains(&(from_a, "peer-a".to_string())),
        "peer A's header request must still time out after peer B answers: {timed_out:?}"
    );
    assert!(
        !timed_out.iter().any(|(_, p)| p == "peer-b"),
        "peer B's own request is retired by its response: {timed_out:?}"
    );
}

#[tokio::test]
async fn blocks_from_one_peer_leave_another_peers_request_to_time_out() {
    let sync = sync_manager();
    let (a, _a_rx) = peer("peer-a", 30003);
    let (b, _b_rx) = peer("peer-b", 30004);
    let from_a = Hash::new([0xA2; 32]);
    let from_b = Hash::new([0xB2; 32]);
    sync.request_blocks(&a, from_a, 10)
        .await
        .expect("request a");
    sync.request_blocks(&b, from_b, 10)
        .await
        .expect("request b");
    assert_eq!(sync.pending_counts().await.1, 2);

    let _ = sync
        .handle_blocks(&PeerId::new("peer-b".into()), vec![])
        .await;

    let timed_out = timed_out_peers(&sync).await;
    assert!(
        timed_out.contains(&(from_a, "peer-a".to_string())),
        "peer A's block request must still time out after peer B answers: {timed_out:?}"
    );
    assert!(
        !timed_out.iter().any(|(_, p)| p == "peer-b"),
        "peer B's own request is retired by its response: {timed_out:?}"
    );
}

#[tokio::test]
async fn an_unanswered_request_times_out() {
    // Control: with no response at all, both requests time out. Without this,
    // the tests above could pass on a manager that never times anything out.
    let sync = sync_manager();
    let (a, _a_rx) = peer("peer-a", 30005);
    let from_a = Hash::new([0xA3; 32]);
    sync.request_headers(&a, from_a)
        .await
        .expect("request headers");
    sync.request_blocks(&a, Hash::new([0xA4; 32]), 1)
        .await
        .expect("request blocks");
    let timed_out = timed_out_peers(&sync).await;
    assert_eq!(timed_out.len(), 2, "{timed_out:?}");
}

// ---------------------------------------------------------------------------
// Inbound accept rate per source IP (Noise listener).
// ---------------------------------------------------------------------------

/// Accepts one source IP may make within the window before it is refused.
const ACCEPTS_PER_IP: usize = 10;
const DEADLINE: Duration = Duration::from_secs(2);

fn free_addr() -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    l.local_addr().expect("addr")
}

async fn spawn_noise_listener() -> (SocketAddr, NetworkTransport) {
    // A large peer table, so the at-capacity check never fires first.
    let pm = Arc::new(PeerManager::new(PeerManagerConfig {
        max_peers: 1_000,
        max_inbound: 1_000,
        ..PeerManagerConfig::default()
    }));
    let params = HandshakeParams {
        network_id: 40204,
        genesis_hash: Hash::new([0x11; 32]),
        head: Arc::new(tokio::sync::RwLock::new((0, Hash::new([0x11; 32])))),
    };
    let kp = NoiseKeypair::generate().expect("noise keypair");
    let transport =
        NetworkTransport::new(pm, PeerId::new("listener".into()), params).with_noise(kp);
    let addr = free_addr();
    transport.start_listener(addr).await.expect("listen");
    (addr, transport)
}

async fn connect(addr: SocketAddr) -> TcpStream {
    for _ in 0..50 {
        if let Ok(s) = TcpStream::connect(addr).await {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("listener at {addr} never came up");
}

/// True if the server closes the stream (EOF or reset) within `DEADLINE`.
async fn closed_by_server(stream: &mut TcpStream) -> bool {
    let mut buf = [0u8; 256];
    match tokio::time::timeout(DEADLINE, stream.read(&mut buf)).await {
        Err(_) => false,
        Ok(Ok(0)) => true,
        Ok(Ok(_)) => false,
        Ok(Err(e)) => matches!(
            e.kind(),
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
        ),
    }
}

#[tokio::test]
async fn inbound_connections_over_the_per_ip_accept_rate_are_closed_before_the_handshake() {
    let (addr, _t) = spawn_noise_listener().await;

    // The first ACCEPTS_PER_IP connections are admitted: the server keeps them
    // open, waiting for the client's first Noise message.
    let mut admitted = Vec::new();
    for _ in 0..ACCEPTS_PER_IP {
        admitted.push(connect(addr).await);
    }
    // Give the accept loop time to process them in order.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The next one from the same IP, inside the window, is closed at once.
    let mut over = connect(addr).await;
    assert!(
        closed_by_server(&mut over).await,
        "connection {} from one IP inside the accept window must be closed",
        ACCEPTS_PER_IP + 1
    );

    // Control: an admitted connection is still open (the limiter did not just
    // close everything).
    let first = admitted.first_mut().expect("one admitted");
    assert!(
        !closed_by_server(first).await,
        "a connection inside the per-IP accept rate must stay open for the handshake"
    );
}
