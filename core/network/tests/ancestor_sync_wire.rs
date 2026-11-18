// Ancestor sync on the wire (ADR-2026-11-17, protocol 1.3).
//
// `GetAncestor` / `Ancestor` are new message variants. A node from before them
// fails to decode an unknown variant and drops the connection, so during a
// rolling upgrade they are sent only to peers whose handshake advertised
// `ProtocolVersion::ANCESTOR_SYNC` (1.3) or later. Every existing variant keeps
// its wire discriminant (the new ones are appended last), so the two halves
// of a mixed fleet still exchange every other message unchanged.

use citrate_consensus::types::{BlockHeader, Hash, PublicKey, VrfProof};
use citrate_network::peer::{Direction, Peer, PeerInfo};
use citrate_network::protocol::{
    NetworkMessage, ProtocolVersion, MAX_ANCESTOR_HEADERS, MAX_LOCATOR_HASHES,
};
use citrate_network::{PeerId, PeerManager, PeerManagerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

const V1_0: ProtocolVersion = ProtocolVersion {
    major: 1,
    minor: 0,
    patch: 0,
};
const V1_2: ProtocolVersion = ProtocolVersion::CHECKPOINT_CERT_SYNC;

async fn peer(
    pm: &PeerManager,
    n: u8,
    version: Option<ProtocolVersion>,
) -> (Arc<Peer>, mpsc::Receiver<NetworkMessage>) {
    let addr: SocketAddr = format!("10.0.2.{n}:30303").parse().expect("addr");
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

fn header(height: u64) -> BlockHeader {
    BlockHeader {
        version: 2,
        block_hash: Hash::new([height as u8; 32]),
        selected_parent_hash: Hash::new([0x11; 32]),
        merge_parent_hashes: vec![],
        timestamp: 1_000,
        height,
        blue_score: height,
        blue_work: citrate_consensus::types::blue_work_for_score(height),
        pruning_point: Hash::default(),
        proposer_pubkey: PublicKey::new([1; 32]),
        vrf_reveal: VrfProof {
            proof: vec![],
            output: Hash::default(),
        },
        base_fee_per_gas: 0,
        gas_used: 0,
        gas_limit: 30_000_000,
        coinbase: [0; 20],
    }
}

fn reply() -> NetworkMessage {
    NetworkMessage::Ancestor {
        common: Some((Hash::new([3; 32]), 9)),
        tip: (Hash::new([4; 32]), 12),
        tip_blue_work: 77,
        headers: vec![header(10), header(11)],
    }
}

/// Mixed fleet: a 1.0, a 1.2 (the r1007 fleet binary) and an unknown-version
/// peer get neither ancestor message, and still get ordinary traffic; a 1.3
/// peer gets both.
#[tokio::test]
async fn ancestor_messages_reach_only_peers_that_decode_them() {
    let pm = PeerManager::new(PeerManagerConfig::default());
    let (_, mut old) = peer(&pm, 1, Some(V1_0)).await;
    let (_, mut v12) = peer(&pm, 2, Some(V1_2)).await;
    let (_, mut unknown) = peer(&pm, 3, None).await;
    let (new_peer, mut new) = peer(&pm, 4, Some(ProtocolVersion::CURRENT)).await;

    let req = NetworkMessage::GetAncestor {
        locator: vec![Hash::new([1; 32]), Hash::new([2; 32])],
    };
    pm.broadcast(&req).await.expect("broadcast");
    pm.broadcast(&reply()).await.expect("broadcast");
    pm.broadcast(&NetworkMessage::Ping { nonce: 9 })
        .await
        .expect("broadcast");

    for rx in [&mut old, &mut v12, &mut unknown] {
        let got = drain(rx);
        assert_eq!(got.len(), 1, "only the ping: {got:?}");
        assert!(matches!(
            got.first(),
            Some(NetworkMessage::Ping { nonce: 9 })
        ));
    }
    let got = drain(&mut new);
    assert_eq!(got.len(), 3, "a 1.3 peer gets all three: {got:?}");
    assert!(matches!(
        got.first(),
        Some(NetworkMessage::GetAncestor { .. })
    ));
    assert!(matches!(got.get(1), Some(NetworkMessage::Ancestor { .. })));
    assert!(new_peer.speaks_ancestor_sync().await);
}

/// A direct send to an old peer is withheld, not an error: the caller (the
/// ancestor-sync driver) never picks such a peer, and a slip must not cost the
/// connection.
#[tokio::test]
async fn a_direct_send_to_a_1_2_peer_is_withheld_without_error() {
    let pm = PeerManager::new(PeerManagerConfig::default());
    let (p, mut rx) = peer(&pm, 5, Some(V1_2)).await;
    assert!(!p.speaks_ancestor_sync().await);
    p.send(NetworkMessage::GetAncestor { locator: vec![] })
        .await
        .expect("withheld, not failed");
    assert!(drain(&mut rx).is_empty());
}

#[test]
fn version_bump_is_backward_compatible() {
    let cur = ProtocolVersion::CURRENT;
    assert_eq!(cur, ProtocolVersion::ANCESTOR_SYNC);
    assert!(V1_0.is_compatible(&cur) && cur.is_compatible(&V1_0));
    assert!(V1_2.is_compatible(&cur) && cur.is_compatible(&V1_2));
    assert!(cur.understands_ancestor_sync());
    assert!(
        cur.understands_checkpoint_sync(),
        "1.3 still speaks 1.2's messages"
    );
    assert!(cur.verifies_native_v2());
    assert!(!V1_2.understands_ancestor_sync());
    assert!(!V1_0.understands_ancestor_sync());
    let later = ProtocolVersion {
        major: 1,
        minor: 9,
        patch: 0,
    };
    assert!(later.understands_ancestor_sync());
    let other_major = ProtocolVersion {
        major: 2,
        minor: 5,
        patch: 0,
    };
    assert!(!other_major.understands_ancestor_sync());
}

/// The new variants are appended: every existing variant keeps its bincode
/// tag (a 1.2 node decodes everything a 1.3 node sends it), and the new ones
/// take the next two.
#[test]
fn existing_wire_discriminants_are_unchanged() {
    fn tag(m: &NetworkMessage) -> u32 {
        let bytes = bincode::serialize(m).expect("serialize");
        u32::from_le_bytes(bytes[..4].try_into().expect("tag"))
    }
    assert_eq!(tag(&NetworkMessage::Ping { nonce: 1 }), 3);
    assert_eq!(
        tag(&NetworkMessage::GetBlocks {
            from: Hash::default(),
            count: 1,
            step: 1
        }),
        6
    );
    assert_eq!(
        tag(&NetworkMessage::GetCheckpoint {
            above: 0,
            at_or_below: 1
        }),
        42
    );
    assert_eq!(tag(&NetworkMessage::GetAncestor { locator: vec![] }), 44);
    assert_eq!(tag(&reply()), 45);
}

#[test]
fn ancestor_messages_round_trip_and_are_labelled() {
    let req = NetworkMessage::GetAncestor {
        locator: vec![Hash::new([7; 32]); MAX_LOCATOR_HASHES],
    };
    let back: NetworkMessage =
        bincode::deserialize(&bincode::serialize(&req).expect("ser")).expect("de");
    assert!(
        matches!(back, NetworkMessage::GetAncestor { ref locator } if locator.len() == MAX_LOCATOR_HASHES)
    );
    let back: NetworkMessage =
        bincode::deserialize(&bincode::serialize(&reply()).expect("ser")).expect("de");
    match back {
        NetworkMessage::Ancestor {
            common,
            tip,
            tip_blue_work,
            headers,
        } => {
            assert_eq!(common, Some((Hash::new([3; 32]), 9)));
            assert_eq!(tip, (Hash::new([4; 32]), 12));
            assert_eq!(tip_blue_work, 77);
            assert_eq!(headers.len(), 2);
        }
        other => panic!("expected Ancestor, got {other:?}"),
    }
    assert_eq!(req.kind(), "GetAncestor");
    assert_eq!(reply().kind(), "Ancestor");
    assert!(req.requires_response());
    assert!(req.is_ancestor_sync() && reply().is_ancestor_sync());
    assert!(!NetworkMessage::Ping { nonce: 0 }.is_ancestor_sync());
    // GetAncestor is a serve request (the serving plane answers it, ADR CV-6);
    // its answer may use the reserved part of the inbound queue.
    assert!(citrate_network::inbound::serve_request(&req));
    assert!(citrate_network::inbound::reserved_lane(&reply()));
}

/// A full reply fits one Noise message: the server stops at the header
/// count cap, and 128 headers stay under the 64 KiB Noise limit.
#[test]
fn a_full_reply_fits_one_noise_message() {
    let full = NetworkMessage::Ancestor {
        common: Some((Hash::new([3; 32]), 9)),
        tip: (Hash::new([4; 32]), 9 + u64::from(MAX_ANCESTOR_HEADERS)),
        tip_blue_work: u128::MAX,
        headers: (0..u64::from(MAX_ANCESTOR_HEADERS))
            .map(|k| header(10 + k))
            .collect(),
    };
    let size = bincode::serialized_size(&full).expect("size");
    assert!(
        size < citrate_network::noise::MAX_NOISE_PLAINTEXT_LEN as u64,
        "{size} bytes"
    );
}
