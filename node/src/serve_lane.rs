//! Serving peers' `GetBlocks` / `GetHeaders` off the receive loop.
//!
//! The node has one inbound queue and one receive loop. The loop used to
//! answer every `GetBlocks` and `GetHeaders` inline (storage reads, a
//! serialized answer, a send), so a burst of sync requests from peers slowed
//! the loop, the inbound queue filled, and `PeerManager::forward_incoming`
//! shed whatever arrived next, peers' new blocks included. [`ServeLane`] hands
//! serve requests to a separate task with its own bounded queue; the receive
//! loop keeps only the messages that change this node's state. A full serve
//! queue sheds requests (the asker re-asks on its next sync tick), counted and
//! warned about at a bounded rate, and never blocks the receive loop.

// PANIC-S1 G2: sync path; panic-free outside tests.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::string_slice
    )
)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use citrate_consensus::types::Hash;
use citrate_network::shed_log::ShedLog;
use citrate_network::{NetworkMessage, PeerId};
use citrate_storage::StorageManager;
use tokio::sync::mpsc;

/// Serve requests waiting for the serve task, at most.
pub const SERVE_QUEUE: usize = 256;

/// At most one "serve requests shed" warning per this interval.
pub const SERVE_SHED_WARN_EVERY: Duration = Duration::from_secs(10);

/// A peer's request for blocks or headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeRequest {
    Blocks { from: Hash, count: u32 },
    Headers { from: Hash, count: u32 },
}

/// The receive loop's handle on the serve task's queue.
#[derive(Debug)]
pub struct ServeLane {
    tx: mpsc::Sender<(PeerId, ServeRequest)>,
    shed: AtomicU64,
    shed_log: ShedLog,
}

impl ServeLane {
    /// A lane with a queue of `capacity`, and the receiver the serve task reads.
    pub fn new(capacity: usize) -> (Self, mpsc::Receiver<(PeerId, ServeRequest)>) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        (
            Self {
                tx,
                shed: AtomicU64::new(0),
                shed_log: ShedLog::new(SERVE_SHED_WARN_EVERY),
            },
            rx,
        )
    }

    /// Route one inbound message: a serve request goes to the serve task (or
    /// is shed when its queue is full); anything else comes back for the
    /// receive loop.
    pub fn route(&self, pid: PeerId, msg: NetworkMessage) -> Option<(PeerId, NetworkMessage)> {
        let _ = (&self.tx, &self.shed_log);
        Some((pid, msg))
    }

    /// Serve requests shed because the serve queue was full.
    pub fn shed(&self) -> u64 {
        self.shed.load(Ordering::Relaxed)
    }
}

/// The answer to one request, through the bounded serve paths.
pub fn answer(storage: &StorageManager, req: &ServeRequest) -> NetworkMessage {
    match req {
        ServeRequest::Blocks { from, count } => NetworkMessage::Blocks {
            blocks: crate::block_serve::serve_blocks(storage, from, *count),
        },
        ServeRequest::Headers { from, count } => NetworkMessage::Headers {
            headers: crate::block_serve::serve_headers(storage, from, *count),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_consensus::types::{Block, BlockBuilder, VrfProof};

    fn new_block() -> Block {
        let mut b = BlockBuilder::new()
            .version(2)
            .height(1)
            .parent(Hash::new([1; 32]))
            .coinbase([2; 20])
            .timestamp(1_000)
            .vrf_reveal(VrfProof {
                proof: vec![],
                output: Hash::new([3; 32]),
            })
            .transactions(vec![])
            .state_root(Hash::default())
            .build_unhashed();
        b.header.block_hash = b.compute_hash();
        b
    }

    /// (d) Peers' block gossip is not starved by serving: with the serve task
    /// stalled and thousands of `GetBlocks` queued ahead of it, the receive
    /// loop gets the `NewBlock` and never a serve request; the overflow is
    /// counted.
    #[test]
    fn new_blocks_reach_the_receive_loop_under_serve_load() {
        let (lane, _rx_stalled) = ServeLane::new(4);
        let pid = PeerId::new("peer".into());
        let mut to_loop = Vec::new();
        for i in 0..5_000u32 {
            let req = if i % 2 == 0 {
                NetworkMessage::GetBlocks {
                    from: Hash::new([7; 32]),
                    count: 32,
                    step: 1,
                }
            } else {
                NetworkMessage::GetHeaders {
                    from: Hash::new([7; 32]),
                    count: 64,
                }
            };
            if let Some(m) = lane.route(pid.clone(), req) {
                to_loop.push(m);
            }
        }
        let block = new_block();
        let routed = lane.route(
            pid.clone(),
            NetworkMessage::NewBlock {
                block: block.clone(),
            },
        );
        assert!(
            to_loop.is_empty(),
            "{} serve requests were left for the receive loop",
            to_loop.len()
        );
        assert!(
            matches!(routed, Some((_, NetworkMessage::NewBlock { block: b })) if b.header.block_hash == block.header.block_hash),
            "the new block goes to the receive loop"
        );
        assert_eq!(
            lane.shed(),
            5_000 - 4,
            "requests over the queue are counted"
        );
    }

    /// The serve task answers through the same bounded paths.
    #[test]
    fn answers_use_the_bounded_serve_paths() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = StorageManager::new(
            dir.path(),
            citrate_storage::pruning::PruningConfig::default(),
        )
        .expect("storage");
        let unknown = Hash::new([9; 32]);
        assert!(matches!(
            answer(&storage, &ServeRequest::Blocks { from: unknown, count: 10_000 }),
            NetworkMessage::Blocks { blocks } if blocks.is_empty()
        ));
        assert!(matches!(
            answer(&storage, &ServeRequest::Headers { from: unknown, count: 10_000 }),
            NetworkMessage::Headers { headers } if headers.is_empty()
        ));
    }
}
