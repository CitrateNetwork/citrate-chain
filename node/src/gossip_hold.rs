//! r1007 G9 ingress, "hold, rather than reject" (planset 2026-11-03-r1007-v060,
//! `06_CONSENSUS_SPEC.md` G9, reviewer R12; #184).
//!
//! Gossip holds a block that is valid except that it is early: stamped past
//! the 15 s future drift (`hardening::MAX_FUTURE_BLOCK_DRIFT_SECS`) and within
//! `slots::HELD_FUTURE_HORIZON_SECS` (`GossipProtocol::handle_new_block`
//! returns `BlockGossip::Held`). This task hands each held block back to the
//! node's inbound message queue, as a `NewBlock` from the peer that sent it,
//! once its slot is inside the drift. The NewBlock arm in `main.rs` then runs
//! the same gossip validation and admission as for any gossiped block.
//!
//! Data source: the held blocks are `GossipProtocol::take_due_held_blocks`
//! (gossip's bounded in-memory hold); the sink is the inbound queue that the
//! peer manager feeds (`PeerManager::set_incoming`).

use citrate_network::{GossipProtocol, NetworkMessage, PeerId};
use std::sync::Arc;
use tokio::sync::mpsc::{error::TrySendError, Sender, WeakSender};

/// Hand every due held block to `tx` as a `NewBlock` from its sender. A block
/// that does not fit (queue full) goes back into the hold for the next pass.
/// Returns how many were handed over.
pub(crate) fn release_due(gossip: &GossipProtocol, tx: &Sender<(PeerId, NetworkMessage)>) -> usize {
    let mut sent = 0usize;
    for (from, block) in gossip.take_due_held_blocks() {
        match tx.try_send((from, NetworkMessage::NewBlock { block })) {
            Ok(()) => sent = sent.saturating_add(1),
            Err(TrySendError::Full((from, msg))) | Err(TrySendError::Closed((from, msg))) => {
                if let NetworkMessage::NewBlock { block } = msg {
                    let size = bincode::serialize(&block).map(|b| b.len()).unwrap_or(0);
                    let _ = gossip.hold_early_block(&from, block, size);
                }
            }
        }
    }
    sent
}

/// Run [`release_due`] once per slot for the life of the node. Holds only a
/// weak handle on the queue, so the queue still closes (and the message loop
/// still reports it) when the peer manager drops its sender.
pub(crate) fn spawn_release(
    gossip: Arc<GossipProtocol>,
    tx: WeakSender<(PeerId, NetworkMessage)>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut timer = crate::timing::cadence_interval(std::time::Duration::from_secs(
            citrate_consensus::slots::SLOT_DURATION_SECS,
        ));
        loop {
            timer.tick().await;
            let Some(tx) = tx.upgrade() else {
                return;
            };
            let n = release_due(&gossip, &tx);
            if n > 0 {
                tracing::debug!("G9 ingress: released {n} held early block(s) to admission");
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_consensus::crypto;
    use citrate_consensus::hardening::PbaHardening;
    use citrate_consensus::types::{Block, BlockBuilder, Hash, PublicKey, VrfProof};
    use citrate_network::{BlockGossip, GossipConfig, PeerManager, PeerManagerConfig};
    use std::sync::atomic::{AtomicU64, Ordering};

    fn early_block(tag: u8, secs_ahead: u64) -> Block {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        let key = crypto::Ed25519SigningKey::from_bytes(&[tag; 32]);
        let mut b = BlockBuilder::new()
            .version(2)
            .height(1)
            .parent(Hash::new([tag; 32]))
            .coinbase([0x77; 20])
            .timestamp(now + secs_ahead)
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

    fn gossip() -> (GossipProtocol, Arc<AtomicU64>) {
        let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
        let clock = Arc::new(AtomicU64::new(0));
        let g = GossipProtocol::new(GossipConfig::default(), pm)
            .with_pba_hardening(PbaHardening::off())
            .with_clock_offset(clock.clone());
        (g, clock)
    }

    /// A held block reaches the inbound queue once its slot is due, as a
    /// NewBlock from the peer that sent it, and not before.
    #[tokio::test]
    async fn a_held_block_is_handed_to_the_inbound_queue_when_due() {
        let (g, clock) = gossip();
        let from = PeerId::new("skewed".to_string());
        let b = early_block(0x31, 30);
        assert_eq!(
            g.handle_new_block(b.clone(), &from)
                .await
                .expect("early, not invalid"),
            BlockGossip::Held
        );
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        assert_eq!(release_due(&g, &tx), 0, "not due yet");
        assert!(rx.try_recv().is_err());

        clock.fetch_add(20_000, Ordering::Relaxed);
        assert_eq!(release_due(&g, &tx), 1);
        let (pid, msg) = rx.try_recv().expect("released");
        assert_eq!(pid, from);
        match msg {
            NetworkMessage::NewBlock { block } => {
                assert_eq!(block.header.block_hash, b.header.block_hash)
            }
            other => panic!("expected NewBlock, got {other:?}"),
        }
        assert_eq!(g.held_block_count(), 0);
    }

    /// A due block that does not fit in a full queue stays held and is handed
    /// over on a later pass: the release never loses a block.
    #[tokio::test]
    async fn a_full_queue_keeps_the_block_held() {
        let (g, clock) = gossip();
        let from = PeerId::new("skewed".to_string());
        let b = early_block(0x32, 30);
        g.handle_new_block(b, &from).await.expect("held");
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        tx.try_send((from.clone(), NetworkMessage::Ping { nonce: 0 }))
            .expect("fill the queue");
        clock.fetch_add(20_000, Ordering::Relaxed);
        assert_eq!(release_due(&g, &tx), 0, "queue full");
        assert_eq!(g.held_block_count(), 1, "still held");
        let _ = rx.try_recv();
        assert_eq!(release_due(&g, &tx), 1, "handed over once there is room");
    }

    /// The release task stops when the queue's last strong sender is gone.
    #[tokio::test]
    async fn the_release_task_ends_with_the_queue() {
        let (g, _clock) = gossip();
        let (tx, _rx) = tokio::sync::mpsc::channel::<(PeerId, NetworkMessage)>(1);
        let task = spawn_release(Arc::new(g), tx.downgrade());
        drop(tx);
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("ends within a few slots")
            .expect("no panic");
    }

    /// Tripwire: main.rs runs the release and keeps held blocks out of
    /// admission. If either call goes, early blocks are lost or admitted early.
    #[test]
    fn main_wires_the_hold() {
        let main = include_str!("main.rs");
        assert!(main.contains("gossip_hold::spawn_release(gossip.clone(), held_release_tx)"));
        assert!(main.contains("citrate_network::BlockGossip::Held"));
        assert!(
            !main.contains("match gossip_for_rx.handle_new_block(block.clone(), &pid).await {\n                                Ok(_) =>"),
            "an `Ok(_)` arm would admit held blocks"
        );
    }
}
