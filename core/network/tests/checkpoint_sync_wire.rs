// WP-S.3 Stage 1b: checkpoint certificate sync on the wire
// (docs/consensus/CHECKPOINT_FINALITY_WIRING.md §11.10).
//
// `GetCheckpoint` / `CheckpointCertificate` are new message variants. A node
// from before them fails to decode an unknown variant and drops the
// connection, so they are sent only to peers whose handshake advertised
// `ProtocolVersion::CHECKPOINT_CERT_SYNC` (1.2) or later. Every existing
// variant keeps its wire discriminant (the new ones are appended last).

use citrate_consensus::types::{Hash, PublicKey, Signature};
use citrate_network::peer::{Direction, Peer, PeerInfo};
use citrate_network::protocol::{CheckpointSignature, NetworkMessage, ProtocolVersion};
use citrate_network::{PeerId, PeerManager, PeerManagerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

const V1_0: ProtocolVersion = ProtocolVersion {
    major: 1,
    minor: 0,
    patch: 0,
};
const V1_1: ProtocolVersion = ProtocolVersion {
    major: 1,
    minor: 1,
    patch: 0,
};

async fn peer(
    pm: &PeerManager,
    n: u8,
    version: Option<ProtocolVersion>,
) -> (Arc<Peer>, mpsc::Receiver<NetworkMessage>) {
    let addr: SocketAddr = format!("10.0.1.{n}:30303").parse().unwrap();
    let mut info = PeerInfo::new(PeerId(format!("peer-{n}")), addr, Direction::Outbound);
    info.version = version;
    let (to_wire, from_node) = mpsc::channel(64);
    let (_unused, inbound) = mpsc::channel(1);
    let p = Arc::new(Peer::new(info, to_wire, inbound));
    pm.add_peer(p.clone()).await.expect("peer added");
    (p, from_node)
}

fn drain(rx: &mut mpsc::Receiver<NetworkMessage>) -> Vec<NetworkMessage> {
    let mut out = Vec::new();
    while let Ok(m) = rx.try_recv() {
        out.push(m);
    }
    out
}

fn certificate() -> NetworkMessage {
    NetworkMessage::CheckpointCertificate {
        height: 40,
        block_hash: Hash::new([4; 32]),
        signatures: vec![CheckpointSignature {
            voter: PublicKey::new([1; 32]),
            signature: Signature::new([2; 64]),
        }],
    }
}

#[tokio::test]
async fn sync_messages_reach_only_peers_that_decode_them() {
    let pm = PeerManager::new(PeerManagerConfig::default());
    let (_, mut old) = peer(&pm, 1, Some(V1_0)).await;
    let (_, mut v11) = peer(&pm, 2, Some(V1_1)).await;
    let (_, mut unknown) = peer(&pm, 3, None).await;
    let (_, mut new) = peer(&pm, 4, Some(ProtocolVersion::CURRENT)).await;

    let req = NetworkMessage::GetCheckpoint {
        above: 0,
        at_or_below: 100,
    };
    pm.broadcast(&req).await.unwrap();
    pm.broadcast(&certificate()).await.unwrap();
    // Ordinary traffic is unaffected.
    pm.broadcast(&NetworkMessage::Ping { nonce: 7 })
        .await
        .unwrap();

    for rx in [&mut old, &mut v11, &mut unknown] {
        let got = drain(rx);
        assert_eq!(got.len(), 1, "only the ping: {got:?}");
        assert!(matches!(
            got.first(),
            Some(NetworkMessage::Ping { nonce: 7 })
        ));
    }
    let got = drain(&mut new);
    assert_eq!(got.len(), 3, "a 1.2 peer gets all three: {got:?}");
    assert!(matches!(
        got.first(),
        Some(NetworkMessage::GetCheckpoint { .. })
    ));
    assert!(matches!(
        got.get(1),
        Some(NetworkMessage::CheckpointCertificate { .. })
    ));
}

#[test]
fn version_bump_is_backward_compatible() {
    let cur = ProtocolVersion::CURRENT;
    assert_eq!(cur, ProtocolVersion::CHECKPOINT_CERT_SYNC);
    assert!(V1_0.is_compatible(&cur) && cur.is_compatible(&V1_0));
    assert!(V1_1.is_compatible(&cur) && cur.is_compatible(&V1_1));
    assert!(cur.understands_checkpoint_sync());
    assert!(cur.verifies_native_v2(), "1.2 still verifies V2 native txs");
    assert!(!V1_1.understands_checkpoint_sync());
    assert!(!V1_0.understands_checkpoint_sync());
    let later = ProtocolVersion {
        major: 1,
        minor: 9,
        patch: 0,
    };
    assert!(later.understands_checkpoint_sync());
    let other_major = ProtocolVersion {
        major: 2,
        minor: 5,
        patch: 0,
    };
    assert!(!other_major.understands_checkpoint_sync());
}

/// The new variants are appended: existing discriminants do not move (a 1.1
/// node still decodes everything a 1.2 node sends it), and the new messages
/// round-trip through the bounded inbound decoder.
#[test]
fn wire_discriminants_are_stable_and_new_variants_round_trip() {
    let disc = |m: &NetworkMessage| {
        let b = bincode::serialize(m).expect("serialize");
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    };
    assert_eq!(disc(&NetworkMessage::Ping { nonce: 0 }), 3);
    let vote = NetworkMessage::CheckpointVote {
        height: 2,
        block_hash: Hash::default(),
        voter_pubkey: vec![],
        signature: vec![],
    };
    let vote_d = disc(&vote);
    let get_d = disc(&NetworkMessage::GetCheckpoint {
        above: 0,
        at_or_below: 0,
    });
    let cert_d = disc(&certificate());
    assert!(
        get_d > vote_d && cert_d == get_d + 1,
        "appended after every existing variant"
    );

    for m in [
        NetworkMessage::GetCheckpoint {
            above: 5,
            at_or_below: 9,
        },
        certificate(),
    ] {
        let bytes = bincode::serialize(&m).expect("serialize");
        let back = NetworkMessage::decode_inbound(&bytes).expect("decode_inbound");
        assert_eq!(
            bincode::serialize(&back).expect("re-serialize"),
            bytes,
            "round trip"
        );
    }
}
