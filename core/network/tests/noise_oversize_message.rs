// citrate/core/network/tests/noise_oversize_message.rs
//
// r1007 cold-sync wedge at height 1552 (2026-11-14): one message over the
// Noise per-message cap took down the whole connection.
//
// Noise encrypts each transport message with one `write_message`, which
// refuses a plaintext over 65,535 - 16 bytes. The writer task used to treat
// that refusal like a dead socket and `break`, so the peer was dropped, the
// requester saw `Broken pipe` on its next write, and every message queued
// behind the oversized one was lost with it. Live, boot1/2/3 logged
// "encrypt failed: noise encrypt: input error" + "Removed peer" for the Mac's
// node every ~30 s for over 24 h.
//
// An oversized message can never be sent as one Noise message, so it is
// dropped; the connection and the messages after it must survive.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use citrate_consensus::types::Hash;
use citrate_network::transport::HandshakeParams;
use citrate_network::PeerManagerConfig;
use citrate_network::{NetworkMessage, NetworkTransport, NoiseKeypair, PeerId, PeerManager};
use tokio::sync::mpsc;

struct Node {
    pm: Arc<PeerManager>,
    transport: NetworkTransport,
    id: PeerId,
    incoming: mpsc::Receiver<(PeerId, NetworkMessage)>,
}

async fn node() -> Node {
    let keypair = NoiseKeypair::generate().expect("noise keypair");
    let id = keypair.derive_peer_id();
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    let (tx, incoming) = mpsc::channel(1024);
    pm.set_incoming(tx).await;
    let params = HandshakeParams {
        network_id: 40204,
        genesis_hash: Hash::new([0x42; 32]),
        head: Arc::new(tokio::sync::RwLock::new((0, Hash::new([0x42; 32])))),
    };
    let transport = NetworkTransport::new(pm.clone(), id.clone(), params).with_noise(keypair);
    Node {
        pm,
        transport,
        id,
        incoming,
    }
}

fn free_local_addr() -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    l.local_addr().expect("local addr")
}

/// Both ends registered each other (the handshake finished on both sides).
async fn connect(a: &Node, b: &Node) {
    let addr = free_local_addr();
    a.transport.start_listener(addr).await.expect("listen");
    b.transport.connect_to(addr).await.expect("dial");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while a.pm.get_peer(&b.id).is_none() || b.pm.get_peer(&a.id).is_none() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "Noise handshake did not complete"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// RED before the fix: the oversized message made the writer `break`, so the
/// marker sent after it never arrived and the peer was removed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_oversized_message_is_dropped_and_the_connection_survives() {
    let a = node().await;
    let mut b = node().await;
    connect(&a, &b).await;

    // 2,200 hashes serialize to ~70 KB: over the 65,519-byte Noise plaintext
    // cap and under the 1 MiB frame cap, the same shape as the 74,543-byte
    // height-1553 reply.
    let oversized = NetworkMessage::GetTransactions {
        hashes: vec![Hash::new([9; 32]); 2_200],
    };
    assert!(
        bincode::serialized_size(&oversized).expect("size") > 65_535 - 16,
        "the test message must exceed the Noise plaintext cap"
    );
    let marker = NetworkMessage::GetTransactions {
        hashes: vec![Hash::new([1; 32])],
    };
    let to_b = a.pm.get_peer(&b.id).expect("b connected to a");
    to_b.send(oversized).await.expect("queue oversized");
    to_b.send(marker).await.expect("queue marker");

    let got = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some((from, msg)) = b.incoming.recv().await {
            if let NetworkMessage::GetTransactions { hashes } = msg {
                return Some((from, hashes));
            }
        }
        None
    })
    .await
    .expect("the message after the oversized one never arrived: the connection was torn down")
    .expect("incoming channel open");

    assert_eq!(got.0, a.id, "delivered from a");
    assert_eq!(
        got.1,
        vec![Hash::new([1; 32])],
        "only the marker arrives; the oversized message is dropped, not split"
    );
    assert!(
        a.pm.get_peer(&b.id).is_some(),
        "a must keep b connected after dropping one oversized message"
    );
}
