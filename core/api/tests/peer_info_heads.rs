// citrate/core/api/tests/peer_info_heads.rs
//
// S3-7 / core#605 (0.5.3 sync-truth check): `net_peerInfo` reports, for each
// peer, the last-known head height and tip hash the node's sync scoring reads
// (`PeerInfo.head_height` / `head_hash`: seeded at the Hello/HelloAck
// handshake, raised by every gossiped block from that peer), next to the
// fields it already returned (id, addr, direction).

use citrate_api::methods::NetworkApi;
use citrate_consensus::types::Hash;
use citrate_network::peer::{
    Direction, Peer, PeerId, PeerInfo, PeerManager, PeerManagerConfig, PeerState,
};
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

async fn add(pm: &PeerManager, id: &str, addr: &str, state: PeerState, height: u64, hash: Hash) {
    let (tx, _to_wire) = mpsc::channel(8);
    let (_unused, rx) = mpsc::channel(1);
    let addr: SocketAddr = addr.parse().expect("addr");
    let mut info = PeerInfo::new(PeerId::new(id.to_string()), addr, Direction::Outbound);
    info.state = state;
    info.head_height = height;
    info.head_hash = hash;
    pm.add_peer(Arc::new(Peer::new(info, tx, rx)))
        .await
        .expect("add peer");
}

#[tokio::test]
async fn peer_info_reports_each_peers_last_known_head() {
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    add(
        &pm,
        "peer_a",
        "10.0.0.1:30303",
        PeerState::Connected,
        1_234,
        Hash::new([0xAB; 32]),
    )
    .await;
    add(
        &pm,
        "peer_b",
        "10.0.0.2:30303",
        PeerState::Connected,
        99,
        Hash::new([0xCD; 32]),
    )
    .await;

    let api = NetworkApi::new(pm.clone(), 40204);
    let peers = api.get_peer_info().await.expect("peer info");
    assert_eq!(peers.len(), 2);
    let by_id = |id: &str| -> Value {
        peers
            .iter()
            .find(|p| p["id"] == id)
            .cloned()
            .unwrap_or_else(|| panic!("{id} listed"))
    };
    let a = by_id("peer_a");
    assert_eq!(a["addr"], "10.0.0.1:30303");
    assert_eq!(a["direction"], "outbound");
    assert_eq!(a["state"], "connected");
    assert_eq!(a["headHeight"], "0x4d2", "{a}");
    assert_eq!(a["headHash"], format!("0x{}", "ab".repeat(32)));
    assert_eq!(a["headSource"], "advertised");
    assert!(a["lastSeenSecsAgo"].is_u64(), "{a}");
    let b = by_id("peer_b");
    assert_eq!(b["headHeight"], "0x63");
    assert_eq!(b["headHash"], format!("0x{}", "cd".repeat(32)));

    // Gossip raises a peer's head (node/src/main.rs, block gossip arm); the
    // RPC reads the current value, not the handshake one.
    let p = pm
        .get_peer(&PeerId::new("peer_b".to_string()))
        .expect("peer_b");
    {
        let mut info = p.info.write().await;
        info.head_height = 100;
        info.head_hash = Hash::new([0xEE; 32]);
    }
    let again = api.get_peer_info().await.expect("peer info");
    let b = again.iter().find(|p| p["id"] == "peer_b").expect("peer_b");
    assert_eq!(b["headHeight"], "0x64");
    assert_eq!(b["headHash"], format!("0x{}", "ee".repeat(32)));
}

#[tokio::test]
async fn a_peer_that_never_advertised_a_head_reports_null_not_zero() {
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    // Still handshaking: no Hello seen yet, so no head is known.
    add(
        &pm,
        "fresh",
        "10.0.0.3:30303",
        PeerState::Handshaking,
        0,
        Hash::default(),
    )
    .await;
    let peers = NetworkApi::new(pm, 40204)
        .get_peer_info()
        .await
        .expect("peer info");
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0]["state"], "handshaking");
    assert!(peers[0]["headHeight"].is_null(), "{}", peers[0]);
    assert!(peers[0]["headHash"].is_null(), "{}", peers[0]);
}

/// CV-3 one blue-score unit: next to `headHeight` (block height,
/// `header.height`, the unit of `eth_blockNumber` and
/// `citrate_nodeIdentity.syncState.appliedHeight`) each peer reports the
/// GHOSTDAG blue score of its head (`header.blue_score`, header-committed and
/// validated at admission). Hello/HelloAck carry no blue score, so it is
/// `null` until a gossiped block from that peer raises the head; the head
/// height, hash and blue score always describe the same block.
#[tokio::test]
async fn peer_info_reports_the_heads_blue_score_once_gossip_names_it() {
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    add(
        &pm,
        "peer_c",
        "10.0.0.4:30303",
        PeerState::Connected,
        50,
        Hash::new([0x11; 32]),
    )
    .await;
    let api = NetworkApi::new(pm.clone(), 40204);
    let peers = api.get_peer_info().await.expect("peer info");
    let c = &peers[0];
    assert_eq!(c["heightUnit"], "header.height", "{c}");
    assert_eq!(c["blueScoreUnit"], "ghostdag.blue_score", "{c}");
    assert!(
        c["headBlueScore"].is_null(),
        "the handshake names no blue score: {c}"
    );
    assert!(c["headBlueScoreSource"].is_null(), "{c}");

    let p = pm
        .get_peer(&PeerId::new("peer_c".to_string()))
        .expect("peer_c");
    // A gossiped block above the head raises all three together.
    assert!(p
        .info
        .write()
        .await
        .observe_gossiped_head(51, Hash::new([0x22; 32]), 77));
    // A gossiped block at or below the head changes nothing.
    assert!(!p
        .info
        .write()
        .await
        .observe_gossiped_head(51, Hash::new([0x33; 32]), 99));
    let again = api.get_peer_info().await.expect("peer info");
    let c = &again[0];
    assert_eq!(c["headHeight"], "0x33", "{c}");
    assert_eq!(c["headHash"], format!("0x{}", "22".repeat(32)));
    assert_eq!(c["headBlueScore"], "0x4d", "{c}");
    assert_eq!(c["headBlueScoreSource"], "gossip", "{c}");
}
