// PBA-L1a-006 (gossip half) / NET-H3 regression.
//
// Gossip deduplicated and relayed transactions by the claimed `tx.hash` and
// never checked signatures. An attacker's own signed tx carrying a victim's
// hash was relayed and cached as "seen+propagated", so the victim's genuine tx
// was then dropped as a duplicate and never relayed. Now every gossiped tx is
// authenticated from its contents and keyed on its canonical id.

use citrate_consensus::crypto::{sign_transaction, Ed25519SigningKey};
use citrate_consensus::types::{Hash, PublicKey, Signature, Transaction};
use citrate_network::{GossipConfig, GossipProtocol, PeerId, PeerManager, PeerManagerConfig};
use std::sync::Arc;

fn signed(seed: u8, claimed: u8) -> Transaction {
    let sk = Ed25519SigningKey::from_bytes(&[seed; 32]);
    let mut tx = Transaction {
        hash: Hash::new([claimed; 32]),
        nonce: 0,
        to: Some(PublicKey::new([9; 32])),
        value: 1,
        gas_limit: 21_000,
        gas_price: 1_000_000_000,
        chain_id: Some(40204),
        ..Default::default()
    };
    sign_transaction(&mut tx, &sk).unwrap();
    tx
}

fn gossip() -> GossipProtocol {
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    GossipProtocol::new(GossipConfig::default(), pm)
}

#[tokio::test]
async fn pba_l1a_006_claimed_hash_cannot_shadow_a_victims_tx_in_gossip() {
    let g = gossip();
    let peer = PeerId("p".into());
    g.handle_new_transaction(signed(2, 0x42), &peer).await.unwrap(); // attacker, victim's hash
    g.handle_new_transaction(signed(1, 0x42), &peer).await.unwrap(); // victim
    let (_, _, received, _, dups, _, _, _) = g.get_stats().await;
    assert_eq!(received, 2, "PBA-L1a-006: the victim's tx must be processed, not dropped");
    assert_eq!(dups, 0);
}

#[tokio::test]
async fn pba_l1a_006_unauthenticated_tx_is_rejected_and_not_cached() {
    let g = gossip();
    let peer = PeerId("p".into());
    let mut forged = signed(1, 0x42);
    forged.value = 999; // body no longer matches the signature
    assert!(g.handle_new_transaction(forged, &peer).await.is_err());
    let mut unsigned = signed(1, 0x43);
    unsigned.signature = Signature::new([0xAA; 64]);
    assert!(g.handle_new_transaction(unsigned, &peer).await.is_err());
    // The genuine tx still goes through afterwards.
    g.handle_new_transaction(signed(1, 0x42), &peer).await.unwrap();
    let (_, _, received, _, _, _, _, _) = g.get_stats().await;
    assert_eq!(received, 1);
}

/// PBA-L1b-007: the pre-filter for unsolicited `Transactions` batches rejects
/// what the gossip arm rejects and normalizes the id, without relaying.
#[tokio::test]
async fn pba_l1b_007_prevalidate_matches_gossip_rules() {
    let g = gossip();
    let peer = PeerId("p".into());
    let ok = g.prevalidate_transaction(signed(1, 0x42), &peer).await.unwrap();
    assert_eq!(ok.hash, citrate_consensus::tx_auth::authenticate(&ok).unwrap());
    let mut zero_gas = signed(1, 0x42);
    zero_gas.gas_price = 0;
    assert!(g.prevalidate_transaction(zero_gas, &peer).await.is_err());
    let mut forged = signed(1, 0x42);
    forged.value = 7;
    assert!(g.prevalidate_transaction(forged, &peer).await.is_err());
    let (_, _, _, propagated, _, _, _, _) = g.get_stats().await;
    assert_eq!(propagated, 0, "prevalidation never relays");
}

/// Tripwire: the node's `Transactions` arm goes through the pre-filter.
#[test]
fn pba_l1b_007_tripwire_transactions_arm_is_prefiltered() {
    let src = include_str!("../../../node/src/main.rs");
    let arm = src
        .find("NetworkMessage::Transactions { transactions } =>")
        .expect("Transactions arm");
    assert!(src[arm..arm + 1_200].contains("gossip_for_rx.prevalidate_transaction("));
}
