// r1007 G9 ingress policy (planset 2026-11-03-r1007-v060, 06_CONSENSUS_SPEC.md
// §2 G9, reviewer item R12; issue #184).
//
// The spec: "hold, rather than reject, a block whose slot > now_slot + 15".
// r1007 cut the future drift from 900 s to 15 s
// (`hardening::MAX_FUTURE_BLOCK_DRIFT_SECS`). Gossip still REJECTED a block
// past it: it dropped the block and charged the sender SCORE_INVALID_BLOCK
// (-25; a peer is banned at -100). So an honest producer whose clock runs a
// little more than 15 s fast lost every block it gossiped, and after four of
// them it was banned, although nothing about its blocks is invalid. The block
// is only early: once its slot arrives it is valid.
//
// What these tests pin:
//   * an early block (past the drift, within the hold horizon) that passes
//     every other gossip check is HELD: no penalty, no relay, not admitted;
//   * it is released once its slot is inside the drift, and the release goes
//     through the same gossip validation (relayed, peer rewarded);
//   * a block past the hold horizon is still rejected and penalized, as is an
//     early block that fails any other check (no free storage for junk);
//   * the hold is bounded per peer and in total, and a re-sent held block is
//     held once.

use citrate_consensus::crypto;
use citrate_consensus::hardening::{PbaHardening, MAX_FUTURE_BLOCK_DRIFT_SECS};
use citrate_consensus::slots::HELD_FUTURE_HORIZON_SECS;
use citrate_consensus::types::{Block, BlockBuilder, Hash, PublicKey, VrfProof};
use citrate_network::gossip::{BlockGossip, MAX_HELD_BLOCKS, MAX_HELD_BLOCKS_PER_PEER};
use citrate_network::peer::{Direction, Peer, PeerInfo, PeerState};
use citrate_network::{GossipConfig, GossipProtocol, PeerId, PeerManager, PeerManagerConfig};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

fn wall_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
}

/// A block that passes every gossip check except, possibly, the time window:
/// self-consistent hash, legacy tx root (hardening off), a VRF proof, a
/// non-zero blue score, and a real ed25519 signature.
fn signed_block(tag: u8, timestamp: u64) -> Block {
    let key = crypto::Ed25519SigningKey::from_bytes(&[tag.wrapping_add(1); 32]);
    let mut b = BlockBuilder::new()
        .version(2)
        .height(1)
        .parent(Hash::new([tag; 32]))
        .coinbase([0x77; 20])
        .timestamp(timestamp)
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
    b
}

struct Net {
    gossip: GossipProtocol,
    pm: Arc<PeerManager>,
    /// Milliseconds added to the gossip wall clock.
    clock_ms: Arc<AtomicU64>,
}

fn net() -> Net {
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    let clock_ms = Arc::new(AtomicU64::new(0));
    let gossip = GossipProtocol::new(GossipConfig::default(), pm.clone())
        .with_pba_hardening(PbaHardening::off())
        .with_clock_offset(clock_ms.clone());
    Net {
        gossip,
        pm,
        clock_ms,
    }
}

impl Net {
    async fn peer(
        &self,
        n: u8,
    ) -> (
        PeerId,
        Arc<Peer>,
        tokio::sync::mpsc::Receiver<citrate_network::NetworkMessage>,
    ) {
        let id = PeerId::new(format!("peer-{n}"));
        let (send_tx, send_rx) = tokio::sync::mpsc::channel(256);
        let (_recv_tx, recv_rx) = tokio::sync::mpsc::channel(1);
        let addr = format!("10.{n}.0.1:9000").parse().expect("addr");
        let mut info = PeerInfo::new(id.clone(), addr, Direction::Inbound);
        info.state = PeerState::Connected;
        let peer = Arc::new(Peer::new(info, send_tx, recv_rx));
        self.pm.add_peer(peer.clone()).await.expect("add peer");
        (id, peer, send_rx)
    }

    fn advance_secs(&self, secs: u64) {
        self.clock_ms.fetch_add(secs * 1_000, Ordering::Relaxed);
    }
}

async fn score(peer: &Arc<Peer>) -> i32 {
    peer.info.read().await.score
}

/// The constants the policy rests on: the hold band starts where the 15 s
/// drift ends and is bounded well below the parent-relative bound. (Constant
/// assertions on purpose: they pin the policy constants this file relies on.)
#[test]
#[allow(clippy::assertions_on_constants)]
fn hold_band_is_past_the_drift_and_bounded() {
    assert_eq!(MAX_FUTURE_BLOCK_DRIFT_SECS, 15);
    assert!(HELD_FUTURE_HORIZON_SECS > MAX_FUTURE_BLOCK_DRIFT_SECS);
    assert!(
        HELD_FUTURE_HORIZON_SECS <= 900,
        "never hold further ahead than the pre-r1007 drift"
    );
    assert!(MAX_HELD_BLOCKS_PER_PEER >= 1 && MAX_HELD_BLOCKS_PER_PEER < MAX_HELD_BLOCKS);
}

/// The core case: a block 30 s early is held, not penalized and not relayed;
/// once its slot is inside the drift it is released, and the released block
/// is relayed and rewarded like any valid block.
#[tokio::test]
async fn early_block_is_held_not_penalized_and_released_when_its_slot_arrives() {
    let n = net();
    let (sender, sender_peer, _s_rx) = n.peer(1).await;
    let (_other, _o_peer, mut other_rx) = n.peer(2).await;
    let block = signed_block(0x10, wall_now() + 30);

    let out = n
        .gossip
        .handle_new_block(block.clone(), &sender)
        .await
        .expect("an early block is not an invalid block");
    assert_eq!(out, BlockGossip::Held);
    assert_eq!(
        score(&sender_peer).await,
        0,
        "no penalty for an early block"
    );
    assert!(other_rx.try_recv().is_err(), "a held block is not relayed");
    assert_eq!(n.gossip.held_block_count(), 1);
    assert!(
        n.gossip.take_due_held_blocks().is_empty(),
        "not due while its slot is past the drift"
    );

    // 20 s later its timestamp is within the 15 s drift.
    n.advance_secs(20);
    let due = n.gossip.take_due_held_blocks();
    assert_eq!(due.len(), 1, "released once its slot arrives");
    assert_eq!(due[0].0, sender, "released as from the peer that sent it");
    assert_eq!(due[0].1.header.block_hash, block.header.block_hash);
    assert_eq!(n.gossip.held_block_count(), 0);

    // The release goes through gossip validation again, now valid.
    let out = n
        .gossip
        .handle_new_block(due[0].1.clone(), &due[0].0)
        .await
        .expect("valid once its slot arrived");
    assert_eq!(out, BlockGossip::Relayed);
    assert!(score(&sender_peer).await > 0, "rewarded as a valid relay");
    assert!(other_rx.try_recv().is_ok(), "relayed to the other peer");
}

/// The edges of the hold band: at the horizon the block is held; one second
/// past it the block is rejected and penalized as before (an hour ahead is
/// still rejected, `adversarial_tests::test_future_timestamp_block_rejected`).
#[tokio::test]
async fn hold_horizon_edges() {
    let n = net();
    let (p, peer, _rx) = n.peer(3).await;
    // Pin the clock so the edge does not move under the test.
    let base = wall_now();
    let at = signed_block(0x20, base + HELD_FUTURE_HORIZON_SECS);
    let past = signed_block(0x21, base + HELD_FUTURE_HORIZON_SECS + 2);
    assert_eq!(
        n.gossip.handle_new_block(at, &p).await.expect("held"),
        BlockGossip::Held
    );
    assert_eq!(score(&peer).await, 0);
    assert!(n.gossip.handle_new_block(past, &p).await.is_err());
    assert_eq!(score(&peer).await, -25, "past the horizon is still invalid");
    assert_eq!(n.gossip.held_block_count(), 1);
}

/// An early block that fails any other check is rejected and penalized, never
/// held: the hold stores only blocks that are valid but for the time.
#[tokio::test]
async fn early_block_with_a_bad_signature_is_rejected_not_held() {
    let n = net();
    let (p, peer, _rx) = n.peer(4).await;
    let mut b = signed_block(0x30, wall_now() + 30);
    b.signature = crypto::sign_block(
        &b.header.block_hash,
        &crypto::Ed25519SigningKey::from_bytes(&[0xEE; 32]),
    );
    assert!(n.gossip.handle_new_block(b, &p).await.is_err());
    assert_eq!(score(&peer).await, -25);
    assert_eq!(n.gossip.held_block_count(), 0);
}

/// A held block re-sent (by the same or another peer) is held once.
#[tokio::test]
async fn a_resent_held_block_is_held_once() {
    let n = net();
    let (a, _pa, _ra) = n.peer(5).await;
    let (b, pb, _rb) = n.peer(6).await;
    let block = signed_block(0x40, wall_now() + 30);
    for from in [&a, &a, &b] {
        assert_eq!(
            n.gossip
                .handle_new_block(block.clone(), from)
                .await
                .expect("held"),
            BlockGossip::Held
        );
    }
    assert_eq!(n.gossip.held_block_count(), 1);
    assert_eq!(score(&pb).await, 0);
    n.advance_secs(20);
    assert_eq!(n.gossip.take_due_held_blocks().len(), 1, "released once");
}

/// One peer can hold at most MAX_HELD_BLOCKS_PER_PEER blocks; past that its
/// early blocks are refused without a penalty (they can be fetched by sync
/// once due) and take no space.
#[tokio::test]
async fn hold_is_bounded_per_peer_without_penalty() {
    let n = net();
    let (p, peer, _rx) = n.peer(7).await;
    let t = wall_now() + 30;
    for i in 0..MAX_HELD_BLOCKS_PER_PEER {
        let b = signed_block(0x50u8.wrapping_add(i as u8), t);
        assert_eq!(
            n.gossip.handle_new_block(b, &p).await.expect("held"),
            BlockGossip::Held
        );
    }
    let extra = signed_block(0xF0, t);
    assert_eq!(
        n.gossip
            .handle_new_block(extra, &p)
            .await
            .expect("not invalid"),
        BlockGossip::HoldFull
    );
    assert_eq!(n.gossip.held_block_count(), MAX_HELD_BLOCKS_PER_PEER);
    assert_eq!(
        score(&peer).await,
        0,
        "a full hold is not the sender's fault"
    );
}

/// The hold is bounded in total: many peers cannot grow it past
/// MAX_HELD_BLOCKS.
#[tokio::test]
async fn hold_is_bounded_in_total() {
    let n = net();
    let t = wall_now() + 30;
    let peers = MAX_HELD_BLOCKS / MAX_HELD_BLOCKS_PER_PEER + 2;
    let mut tag: u8 = 0;
    let mut full = 0usize;
    for i in 0..peers {
        let (p, _peer, _rx) = n.peer(100u8.wrapping_add(i as u8)).await;
        for _ in 0..MAX_HELD_BLOCKS_PER_PEER {
            tag = tag.wrapping_add(1);
            let b = signed_block(tag, t);
            match n.gossip.handle_new_block(b, &p).await.expect("not invalid") {
                BlockGossip::Held => {}
                BlockGossip::HoldFull => full += 1,
                other => panic!("unexpected {other:?}"),
            }
        }
    }
    assert_eq!(n.gossip.held_block_count(), MAX_HELD_BLOCKS);
    assert_eq!(full, peers * MAX_HELD_BLOCKS_PER_PEER - MAX_HELD_BLOCKS);
}

/// A block within the drift is relayed as before (the hold never delays a
/// timely block).
#[tokio::test]
async fn timely_block_is_relayed_not_held() {
    let n = net();
    let (p, _peer, _rx) = n.peer(8).await;
    let b = signed_block(0x60, wall_now() + MAX_FUTURE_BLOCK_DRIFT_SECS - 2);
    assert_eq!(
        n.gossip.handle_new_block(b, &p).await.expect("valid"),
        BlockGossip::Relayed
    );
    assert_eq!(n.gossip.held_block_count(), 0);
}
