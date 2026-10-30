// Frame-size limits at the real handshake entry points.
//
// The decoder-level test in `protocol.rs` pins `NetworkMessage::decode_inbound`.
// These tests drive the listeners the node actually opens and check that an
// inbound length prefix above the cap is refused as soon as the prefix is read:
// the server must drop the connection without waiting for (or reserving room
// for) a body it was told is coming. A listener that honours the declared
// length instead sits waiting for the body, which these tests observe as a
// connection that is still open after the deadline.
//
// Local only: every listener binds 127.0.0.1 inside this process, and no test
// writes outside its own sockets.

use citrate_consensus::types::Hash;
use citrate_network::noise::{self, NoiseKeypair};
use citrate_network::peer::{PeerId, PeerManager, PeerManagerConfig};
use citrate_network::transport::HandshakeParams;
use citrate_network::NetworkTransport;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Frame cap of both the plaintext and the Noise transport (1 MiB).
const FRAME_CAP: u32 = 1024 * 1024;
/// Cap on a single Noise handshake message.
const NOISE_MSG_CAP: u32 = 65_535;
/// How long the server gets to drop an over-cap connection.
const DEADLINE: Duration = Duration::from_secs(3);

fn free_addr() -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    l.local_addr().expect("addr")
}

/// Wait up to `DEADLINE` for the server to close the stream. Returns true if it
/// closed (EOF or reset), false if it was still open at the deadline. Any bytes
/// the server sends first (a Disconnect frame, say) are drained.
async fn closed_by_server(stream: &mut TcpStream) -> bool {
    let mut buf = [0u8; 4096];
    let started = tokio::time::Instant::now();
    loop {
        let left = match DEADLINE.checked_sub(started.elapsed()) {
            Some(d) => d,
            None => return false,
        };
        match tokio::time::timeout(left, stream.read(&mut buf)).await {
            Err(_) => return false,
            Ok(Ok(0)) => return true,
            Ok(Ok(_)) => continue,
            Ok(Err(e)) => {
                return matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                )
            }
        }
    }
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

/// Noise transport listener (the production P2P path).
async fn spawn_noise_listener() -> (SocketAddr, NetworkTransport) {
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
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

// ---------------------------------------------------------------------------
// Noise transport: the handshake message length prefix.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn noise_handshake_drops_an_over_cap_message_length() {
    let (addr, _t) = spawn_noise_listener().await;
    let mut s = connect(addr).await;
    // The first Noise message is a bare 4-byte big-endian length. Declare one
    // byte more than the cap and send nothing else.
    s.write_all(&(NOISE_MSG_CAP + 1).to_be_bytes())
        .await
        .expect("write prefix");
    assert!(
        closed_by_server(&mut s).await,
        "an over-cap Noise handshake length must close the connection immediately"
    );
}

#[tokio::test]
async fn noise_handshake_waits_for_an_in_cap_message_body() {
    // Control: a prefix at the cap is legal, so the server must keep waiting for
    // the body. Without this the over-cap test could pass on a server that drops
    // every connection.
    let (addr, _t) = spawn_noise_listener().await;
    let mut s = connect(addr).await;
    s.write_all(&NOISE_MSG_CAP.to_be_bytes())
        .await
        .expect("write prefix");
    assert!(
        !closed_by_server(&mut s).await,
        "an in-cap Noise handshake length must not be refused"
    );
}

// ---------------------------------------------------------------------------
// Noise transport: the first framed message after the handshake (Hello).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn noise_transport_drops_an_over_cap_hello_frame() {
    let (addr, _t) = spawn_noise_listener().await;
    let mut s = connect(addr).await;
    let kp = NoiseKeypair::generate().expect("client keypair");
    let _session = noise::handshake_initiator(&mut s, &kp)
        .await
        .expect("noise handshake");
    // Post-handshake frames are length-delimited (4-byte big-endian prefix).
    s.write_all(&(FRAME_CAP + 1).to_be_bytes())
        .await
        .expect("write prefix");
    assert!(
        closed_by_server(&mut s).await,
        "an over-cap Hello frame length must close the connection immediately"
    );
}

#[tokio::test]
async fn noise_transport_waits_for_an_in_cap_hello_frame() {
    let (addr, _t) = spawn_noise_listener().await;
    let mut s = connect(addr).await;
    let kp = NoiseKeypair::generate().expect("client keypair");
    let _session = noise::handshake_initiator(&mut s, &kp)
        .await
        .expect("noise handshake");
    s.write_all(&FRAME_CAP.to_be_bytes())
        .await
        .expect("write prefix");
    assert!(
        !closed_by_server(&mut s).await,
        "an in-cap Hello frame length must not be refused"
    );
}

// ---------------------------------------------------------------------------
// Legacy plaintext listener (`PeerManager::start_listener`).
// ---------------------------------------------------------------------------

async fn spawn_plaintext_listener() -> SocketAddr {
    // The plaintext path is fail-closed behind this switch outside unit tests.
    std::env::set_var("CITRATE_ALLOW_PLAINTEXT_P2P", "1");
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    let addr = free_addr();
    pm.start_listener(addr, 40204, Hash::new([0x22; 32]), 0, Hash::new([0x22; 32]))
        .await
        .expect("plaintext listener");
    addr
}

#[tokio::test]
async fn plaintext_handshake_drops_an_over_cap_hello_frame() {
    let addr = spawn_plaintext_listener().await;
    let mut s = connect(addr).await;
    s.write_all(&(FRAME_CAP + 1).to_be_bytes())
        .await
        .expect("write prefix");
    assert!(
        closed_by_server(&mut s).await,
        "an over-cap Hello frame length must close the plaintext connection immediately"
    );
}

#[tokio::test]
async fn plaintext_handshake_waits_for_an_in_cap_hello_frame() {
    let addr = spawn_plaintext_listener().await;
    let mut s = connect(addr).await;
    s.write_all(&FRAME_CAP.to_be_bytes())
        .await
        .expect("write prefix");
    assert!(
        !closed_by_server(&mut s).await,
        "an in-cap Hello frame length must not be refused"
    );
}
