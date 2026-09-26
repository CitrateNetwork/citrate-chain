// PBA-L1b-003 (CRITICAL) regression — from the audit PoC
// `lanes/L1b-chain-consensus-p2p/evidence/pba_l1b_poc.rs::poc_003_*`.
//
// Consensus required only `child.ts >= selected_parent.ts`, with no upper
// bound; gossip checked `ts <= now + 900` but the sync path (`handle_blocks`,
// which also serves unsolicited `Blocks`) did not; and the producer stamped
// `now`. One block with `timestamp = u64::MAX` became the fork-choice tip and
// every honest child was then rejected as "precedes selected parent": a
// permanent halt of honest block production.
//
// Fix (three layers):
//   * validity (behind the PBA-R2 activation height): a block may not run more
//     than MAX_BLOCK_TIMESTAMP_ADVANCE_SECS past its selected parent;
//   * ingress policy (always on): sync rejects `ts > now + 900` like gossip;
//   * producer (always on): stamps clamp(now, parent.ts, parent.ts + MAX).

use citrate_consensus::crypto;
use citrate_consensus::dag_store::DagStore;
use citrate_consensus::ghostdag::GhostDag;
use citrate_consensus::hardening::{
    producer_timestamp, PbaHardening, MAX_BLOCK_TIMESTAMP_ADVANCE_SECS,
};
use citrate_consensus::types::{Block, BlockBuilder, GhostDagParams, Hash, PublicKey, VrfProof};
use citrate_network::{PeerId, SyncConfig, SyncManager};
use std::sync::Arc;

const COINBASE: [u8; 20] = [0x77; 20];

fn mk_linked(height: u64, parent: Hash, ts: u64) -> Block {
    let mut b = BlockBuilder::new()
        .version(2)
        .height(height)
        .parent(parent)
        .coinbase(COINBASE)
        .timestamp(ts)
        .vrf_reveal(VrfProof {
            proof: vec![],
            output: Hash::new([0x5A; 32]),
        })
        .transactions(vec![])
        .state_root(Hash::default())
        .blue_score(height)
        .blue_work(citrate_consensus::types::blue_work_for_score(height))
        .build_unhashed();
    b.header.block_hash = b.compute_hash();
    b
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn dag_with_genesis(hardening: PbaHardening) -> (Arc<DagStore>, GhostDag, Block) {
    let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let gd = GhostDag::new(GhostDagParams::default(), dag.clone()).with_pba_hardening(hardening);
    let genesis = mk_linked(0, Hash::default(), now() - 60);
    dag.store_block(genesis.clone()).await.unwrap();
    gd.add_block(&genesis).await.unwrap();
    (dag, gd, genesis)
}

/// After activation: the poison block itself is invalid on the consensus path
/// every ingress funnels through (admission runs validate_block_consistency).
#[tokio::test]
async fn pba_l1b_003_far_future_block_rejected_by_consensus_after_activation() {
    let (_dag, gd, genesis) = dag_with_genesis(PbaHardening::at(0)).await;
    let poison = mk_linked(1, genesis.header.block_hash, u64::MAX);
    let r = gd.validate_block_consistency(&poison).await;
    assert!(
        r.is_err(),
        "PBA-L1b-003: a u64::MAX-timestamp block must be invalid after activation"
    );

    // Exactly at the bound is valid; one past it is not.
    let at_bound = mk_linked(
        1,
        genesis.header.block_hash,
        genesis.header.timestamp + MAX_BLOCK_TIMESTAMP_ADVANCE_SECS,
    );
    gd.validate_block_consistency(&at_bound)
        .await
        .expect("parent.ts + MAX is valid");
    let past_bound = mk_linked(
        1,
        genesis.header.block_hash,
        genesis.header.timestamp + MAX_BLOCK_TIMESTAMP_ADVANCE_SECS + 1,
    );
    assert!(gd.validate_block_consistency(&past_bound).await.is_err());
}

/// Before activation the legacy rule stands (history must not be re-judged),
/// but the sync ingress still refuses a far-future block and the producer can
/// always build a valid child, so there is no halt either way.
#[tokio::test]
async fn pba_l1b_003_before_activation_legacy_rule_but_no_halt() {
    let (dag, gd, genesis) = dag_with_genesis(PbaHardening::off()).await;
    let poison = mk_linked(1, genesis.header.block_hash, u64::MAX);
    gd.validate_block_consistency(&poison)
        .await
        .expect("pre-activation: legacy validity (no upper bound) is unchanged");
    dag.store_block(poison.clone()).await.unwrap();
    gd.add_block(&poison).await.unwrap();
    assert_eq!(gd.select_tip().await.unwrap(), poison.header.block_hash);

    // Producer: stamps max(now, parent.ts) — the child is valid.
    let child_ts = producer_timestamp(now(), poison.header.timestamp);
    let child = mk_linked(2, poison.header.block_hash, child_ts);
    gd.validate_block_consistency(&child)
        .await
        .expect("PBA-L1b-003: the honest child of a future-dated tip must be valid");
}

/// The producer's stamp is always valid under the post-activation rule, even
/// after an outage longer than the bound.
#[tokio::test]
async fn pba_l1b_003_producer_stamp_valid_after_long_outage() {
    let (_dag, gd, genesis) = dag_with_genesis(PbaHardening::at(0)).await;
    let ts = producer_timestamp(now() + 30 * 86_400, genesis.header.timestamp);
    let child = mk_linked(1, genesis.header.block_hash, ts);
    gd.validate_block_consistency(&child)
        .await
        .expect("clamped producer stamp is valid");
}

/// Sync ingress (the unsolicited-`Blocks` path that bypassed gossip's check)
/// rejects a far-future block regardless of activation.
#[tokio::test]
async fn pba_l1b_003_sync_rejects_far_future_block() {
    for hardening in [PbaHardening::off(), PbaHardening::at(0)] {
        let key = crypto::generate_keypair();
        let mut b = mk_linked(1, Hash::new([1; 32]), u64::MAX);
        b.header.proposer_pubkey = PublicKey::new(key.verifying_key().to_bytes());
        b.tx_root = citrate_consensus::tx_auth::tx_root_for_height(hardening, 1, &[]);
        b.header.block_hash = b.compute_hash();
        b.signature = crypto::sign_block(&b.header.block_hash, &key);
        let sync = SyncManager::new(SyncConfig::default()).with_pba_hardening(hardening);
        sync.handle_blocks(&PeerId("attacker".into()), vec![b])
            .await
            .unwrap();
        assert_eq!(
            sync.drain_validated_blocks().await.len(),
            0,
            "PBA-L1b-003: sync must reject ts=u64::MAX ({hardening:?})"
        );
    }
}

/// Gossip keeps rejecting it too (the check it always had, now shared).
#[tokio::test]
async fn pba_l1b_003_gossip_rejects_far_future_block() {
    use citrate_network::{GossipConfig, GossipProtocol, PeerManager, PeerManagerConfig};
    let key = crypto::generate_keypair();
    let mut b = mk_linked(1, Hash::new([1; 32]), u64::MAX);
    b.header.vrf_reveal.proof = vec![1];
    b.header.proposer_pubkey = PublicKey::new(key.verifying_key().to_bytes());
    b.tx_root = citrate_consensus::tx_auth::tx_root_legacy(&[]);
    b.header.block_hash = b.compute_hash();
    b.signature = crypto::sign_block(&b.header.block_hash, &key);
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    let gossip =
        GossipProtocol::new(GossipConfig::default(), pm).with_pba_hardening(PbaHardening::off());
    assert!(gossip
        .handle_new_block(b, &PeerId("attacker".into()))
        .await
        .is_err());
}

/// Tripwire (class-level): every block ingress in the network crate applies
/// the shared wall-clock bound. A new ingress path that forgets it fails here.
#[test]
fn pba_l1b_003_tripwire_every_block_ingress_checks_future_drift() {
    for (file, src) in [
        ("sync.rs", include_str!("../src/sync.rs")),
        ("gossip.rs", include_str!("../src/gossip.rs")),
    ] {
        let verifies = src.matches("verify_hash").count();
        let drift = src.matches("hardening::within_future_drift(").count();
        assert!(
            drift >= 1 && verifies >= 1,
            "{file}: a block ingress that verifies hashes must also apply \
             hardening::within_future_drift (PBA-L1b-003)"
        );
        assert!(
            !src.contains("now + 900"),
            "{file}: use hardening::within_future_drift, not an inline bound"
        );
    }
}
