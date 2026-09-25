// PBA-L1b-002 (CRITICAL) regression — from the audit PoCs
// `lanes/L1b-chain-consensus-p2p/evidence/pba_l1b_poc.rs::poc_002_*`.
//
// `tx_root` was Sha3 over each transaction's wire `hash` field, never
// recomputed from contents. A relaying peer could rewrite a transaction inside
// an honest, validly signed block (new recipient/value, `hash` untouched):
// block hash, proposer signature and tx_root all still verified. Followers
// stored the rewritten body under the real hash, failed it on state root, and
// dropped the genuine copy as a duplicate: permanently wedged.
//
// Fix: after the PBA-R2 activation height, `tx_root` commits to every
// transaction's full contents (`tx_auth::tx_root_v2`) on every path — the
// producer builds it, sync/gossip/admission/import check it.

use citrate_consensus::crypto;
use citrate_consensus::hardening::PbaHardening;
use citrate_consensus::tx_auth::{native_tx_id, tx_root_for_height, tx_root_legacy};
use citrate_consensus::types::{Block, BlockBuilder, Hash, PublicKey, Transaction, VrfProof};
use citrate_network::{
    GossipConfig, GossipProtocol, PeerId, PeerManager, PeerManagerConfig, SyncConfig, SyncManager,
};
use std::sync::Arc;

fn signed_native(seed: u8, nonce: u64, to: [u8; 32], value: u128) -> Transaction {
    let sk = crypto::Ed25519SigningKey::from_bytes(&[seed; 32]);
    let mut tx = Transaction {
        nonce,
        to: Some(PublicKey::new(to)),
        value,
        gas_limit: 21_000,
        gas_price: 1_000_000_000,
        chain_id: Some(40204),
        ..Default::default()
    };
    crypto::sign_transaction(&mut tx, &sk).unwrap();
    tx.hash = native_tx_id(&tx);
    tx
}

/// An honest block as the producer builds it under `hardening`.
fn honest_signed_block(hardening: PbaHardening) -> Block {
    let key = crypto::generate_keypair();
    let proposer = PublicKey::new(key.verifying_key().to_bytes());
    let txs = vec![signed_native(1, 0, [0xB0; 32], 1_000)];
    let mut b = BlockBuilder::new()
        .version(2)
        .height(5)
        .parent(Hash::new([7u8; 32]))
        .blue_score(5)
        .proposer(proposer)
        .coinbase([0x77; 20])
        .timestamp(1_700_000_000)
        .vrf_reveal(VrfProof {
            proof: vec![1, 2, 3],
            output: Hash::new([0x5A; 32]),
        })
        .transactions(txs)
        .state_root(Hash::new([0x33; 32]))
        .build_unhashed();
    b.tx_root = tx_root_for_height(hardening, 5, &b.transactions);
    b.header.block_hash = b.compute_hash();
    b.signature = crypto::sign_block(&b.header.block_hash, &key);
    b
}

/// The relay attack: rewrite the body, keep `tx.hash`, header, signature.
fn tamper(b: &Block) -> Block {
    let mut t = b.clone();
    t.transactions[0].to = Some(PublicKey::new([0xBB; 32]));
    t.transactions[0].value = 999_999_999;
    t
}

#[test]
fn pba_l1b_002_v2_root_detects_the_rewrite_legacy_does_not() {
    let honest = honest_signed_block(PbaHardening::at(0));
    let forged = tamper(&honest);
    assert_eq!(forged.header.block_hash, honest.header.block_hash);
    assert!(forged.verify_hash(), "header is untouched");
    assert!(crypto::verify_block_signature(&forged).unwrap());
    // Legacy rule: blind to the rewrite (the vulnerability, kept below activation).
    assert_eq!(tx_root_legacy(&forged.transactions), tx_root_legacy(&honest.transactions));
    // v2 rule: the rewrite no longer matches the committed root.
    assert_ne!(
        tx_root_for_height(PbaHardening::at(0), 5, &forged.transactions),
        forged.tx_root
    );
}

#[tokio::test]
async fn pba_l1b_002_sync_rejects_rewritten_body_accepts_honest() {
    let hardening = PbaHardening::at(0);
    let honest = honest_signed_block(hardening);
    let forged = tamper(&honest);
    let sync = SyncManager::new(SyncConfig::default()).with_pba_hardening(hardening);
    sync.handle_blocks(&PeerId("attacker".into()), vec![forged])
        .await
        .unwrap();
    assert_eq!(
        sync.drain_validated_blocks().await.len(),
        0,
        "PBA-L1b-002: sync must reject a rewritten body"
    );
    sync.handle_blocks(&PeerId("honest".into()), vec![honest.clone()])
        .await
        .unwrap();
    let got = sync.drain_validated_blocks().await;
    assert_eq!(got.len(), 1, "the honest copy is accepted");
    assert_eq!(got[0].transactions[0].value, 1_000);
}

#[tokio::test]
async fn pba_l1b_002_gossip_rejects_rewritten_body_then_accepts_honest() {
    let hardening = PbaHardening::at(0);
    let honest = honest_signed_block(hardening);
    let forged = tamper(&honest);
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    let gossip = GossipProtocol::new(GossipConfig::default(), pm).with_pba_hardening(hardening);
    assert!(
        gossip
            .handle_new_block(forged, &PeerId("attacker".into()))
            .await
            .is_err(),
        "PBA-L1b-002: gossip must reject a rewritten body (and not relay it)"
    );
    gossip
        .handle_new_block(honest, &PeerId("honest".into()))
        .await
        .expect("the honest copy is validated, not dropped as a duplicate");
}

/// Below the activation height the legacy rule is unchanged: honest legacy
/// blocks keep validating (no fork before the scheduled height).
#[tokio::test]
async fn pba_l1b_002_before_activation_legacy_blocks_still_validate() {
    let hardening = PbaHardening::at(1_000);
    let honest = honest_signed_block(hardening); // height 5 < 1000: legacy root
    assert_eq!(honest.tx_root, tx_root_legacy(&honest.transactions));
    let sync = SyncManager::new(SyncConfig::default()).with_pba_hardening(hardening);
    sync.handle_blocks(&PeerId("p".into()), vec![honest]).await.unwrap();
    assert_eq!(sync.drain_validated_blocks().await.len(), 1);
}

/// Tripwire (class-level): no block path may compute a tx root by hand. Every
/// producer/validator goes through `tx_auth::tx_root_for_height`.
#[test]
fn pba_l1b_002_tripwire_no_hand_rolled_tx_root() {
    for (file, src) in [
        ("sync.rs", include_str!("../src/sync.rs")),
        ("gossip.rs", include_str!("../src/gossip.rs")),
    ] {
        assert!(
            src.contains("tx_auth::tx_root_for_height("),
            "{file}: tx_root must be checked with tx_auth::tx_root_for_height"
        );
        assert!(
            !src.contains("hasher.update(tx.hash.as_bytes())"),
            "{file}: hand-rolled tx_root over the wire tx.hash (PBA-L1b-002)"
        );
    }
}
