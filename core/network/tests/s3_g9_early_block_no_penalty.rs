// r1007 G9 ingress (#184, spec G9 "hold, rather than reject"; reviewer R12).
//
// Written against the existing gossip API only, so it fails on its assertion
// (not on compilation) before the hold lands: an honest peer whose block is
// 30 s early, and otherwise valid, must not be charged SCORE_INVALID_BLOCK.
// Four such blocks used to ban it (-25 each, ban at -100).
// The full hold/release behaviour is in `s3_g9_ingress_hold.rs`.

use citrate_consensus::crypto;
use citrate_consensus::hardening::PbaHardening;
use citrate_consensus::types::{BlockBuilder, Hash, PublicKey, VrfProof};
use citrate_network::peer::{Direction, Peer, PeerInfo, PeerState};
use citrate_network::{GossipConfig, GossipProtocol, PeerId, PeerManager, PeerManagerConfig};
use std::sync::Arc;

#[tokio::test]
async fn early_but_valid_blocks_never_ban_an_honest_peer() {
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    let gossip = GossipProtocol::new(GossipConfig::default(), pm.clone())
        .with_pba_hardening(PbaHardening::off());
    let id = PeerId::new("skewed-honest".to_string());
    let (send_tx, _send_rx) = tokio::sync::mpsc::channel(16);
    let (_recv_tx, recv_rx) = tokio::sync::mpsc::channel(1);
    let mut info = PeerInfo::new(
        id.clone(),
        "10.9.0.1:9000".parse().expect("addr"),
        Direction::Inbound,
    );
    info.state = PeerState::Connected;
    let peer = Arc::new(Peer::new(info, send_tx, recv_rx));
    pm.add_peer(peer.clone()).await.expect("add peer");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let key = crypto::Ed25519SigningKey::from_bytes(&[0x42; 32]);
    for i in 0..4u8 {
        let mut b = BlockBuilder::new()
            .version(2)
            .height(1)
            .parent(Hash::new([i.wrapping_add(1); 32]))
            .coinbase([0x77; 20])
            .timestamp(now + 30)
            .vrf_reveal(VrfProof {
                proof: vec![1],
                output: Hash::new([0x5A; 32]),
            })
            .transactions(vec![])
            .state_root(Hash::default())
            .blue_score(1)
            .blue_work(citrate_consensus::types::blue_work_for_score(1))
            .build_unhashed();
        b.header.proposer_pubkey = PublicKey::new(key.verifying_key().to_bytes());
        b.tx_root = citrate_consensus::tx_auth::tx_root_legacy(&[]);
        b.header.block_hash = b.compute_hash();
        b.signature = crypto::sign_block(&b.header.block_hash, &key);
        assert!(
            gossip.handle_new_block(b, &id).await.is_ok(),
            "block {i}: 30 s early is not invalid"
        );
    }
    assert_eq!(
        peer.info.read().await.score,
        0,
        "an honest peer with a 30 s fast clock is never penalized"
    );
}
