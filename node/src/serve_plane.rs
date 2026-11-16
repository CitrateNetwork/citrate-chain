// citrate/node/src/serve_plane.rs

//! The history-serving plane (ADR CV-6, planset H3).
//!
//! Peers' `GetBlocks` / `GetHeaders` used to share the node's one inbound
//! queue with block gossip and were answered from storage on the consensus
//! loop itself. Under catch-up load (r1006, 2026-11-01) that loop spent its
//! time reading history while the producers' `NewBlock`s waited behind it or
//! were shed, and producers sealed on their own branches without ever looking
//! "behind".
//!
//! Now `PeerManager::forward_incoming` routes serve requests to their own
//! bounded lane, and this task answers them:
//!
//! * **Off the consensus loop.** Answers are read on blocking worker threads
//!   from storage only (`block_serve::serve_blocks` / `serve_headers` over the
//!   `StorageManager` column families). No consensus, admission or
//!   applied-tip lock is taken, so serving never waits on block admission and
//!   admission never waits on serving.
//! * **Budgets that answer, not vanish.** A peer has at most one request being
//!   answered at a time and at most [`SERVE_PENDING_PER_PEER`] waiting; peers
//!   are served round-robin; at most [`SERVE_WORKERS`] answers are built at
//!   once and [`SERVE_PENDING_GLOBAL`] wait across all peers. A request over
//!   budget waits its turn; only one past the waiting caps is shed (counted
//!   under `PeerManager::serve_drops_by_kind`). The caps sit far above what an
//!   honest requester has outstanding (the sync tick keeps
//!   `sync_recovery::TICK_PENDING_GATE` requests in flight, the missing-parent
//!   walk `MAX_WALKS_IN_FLIGHT`), because a request shed without an answer
//!   stalls the requester's answer-paced walk for the 30 s request timeout:
//!   the per-peer token bucket of 5aff3633 did exactly that and kept 6 of 8
//!   split-heal scenarios from healing (removed in d3562a36).
//! * **Never blocks gossip.** The serve lane is a separate queue; when it is
//!   full, `forward_incoming` sheds the serve request and returns. Nothing on
//!   this path awaits the consensus queue.

// PANIC-S1 G2: sync path (T1); panic-free outside tests.
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

use std::collections::HashMap;
use std::sync::Arc;

use citrate_network::inbound::{
    ServeAdmit, ServeQueue, SERVE_PENDING_GLOBAL, SERVE_PENDING_PER_PEER,
};
use citrate_network::{NetworkMessage, PeerId, PeerManager};
use citrate_storage::StorageManager;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::block_serve;

/// Answers built at once (blocking storage readers).
pub const SERVE_WORKERS: usize = 2;

/// The answer to one serve request, or `None` for a message that is not one.
///
/// Source: `block_serve::serve_blocks` / `block_serve::serve_headers`, which
/// read the node's `StorageManager` (CF_METADATA height index, CF_BLOCKS)
/// under their NET-1/NET-2 clamps. Reads only; takes no consensus lock.
pub fn answer(storage: &StorageManager, request: &NetworkMessage) -> Option<NetworkMessage> {
    match request {
        NetworkMessage::GetBlocks { from, count, .. } => Some(NetworkMessage::Blocks {
            blocks: block_serve::serve_blocks(storage, from, *count),
        }),
        NetworkMessage::GetHeaders { from, count } => Some(NetworkMessage::Headers {
            headers: block_serve::serve_headers(storage, from, *count),
        }),
        _ => None,
    }
}

/// [`answer`], as the messages that go on the wire: a `Blocks` reply is split
/// by [`block_serve::chunk_for_noise`] so no message exceeds the Noise
/// per-message cap (the r1007 height-1553 wedge); anything else is one message.
pub fn answer_frames(storage: &StorageManager, request: &NetworkMessage) -> Vec<NetworkMessage> {
    match answer(storage, request) {
        Some(NetworkMessage::Blocks { blocks }) => block_serve::chunk_for_noise(blocks)
            .into_iter()
            .map(|blocks| NetworkMessage::Blocks { blocks })
            .collect(),
        Some(other) => vec![other],
        None => Vec::new(),
    }
}

/// The serving queue with this plane's budgets.
pub fn queue() -> ServeQueue<NetworkMessage> {
    ServeQueue::new(SERVE_PENDING_PER_PEER, SERVE_PENDING_GLOBAL)
}

/// Spawn the serving task over the serve lane `rx` (the receiver of the sink
/// given to `PeerManager::set_serve_sink`). It ends only when that lane
/// closes, which `start_node` treats as fatal.
pub fn spawn(
    storage: Arc<StorageManager>,
    pm: Arc<PeerManager>,
    rx: mpsc::Receiver<(PeerId, NetworkMessage)>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run(storage, pm, rx, SERVE_WORKERS))
}

async fn run(
    storage: Arc<StorageManager>,
    pm: Arc<PeerManager>,
    mut rx: mpsc::Receiver<(PeerId, NetworkMessage)>,
    workers: usize,
) {
    let mut queue = queue();
    let mut jobs: JoinSet<()> = JoinSet::new();
    let mut job_peer: HashMap<tokio::task::Id, PeerId> = HashMap::new();
    let mut open = true;
    loop {
        while jobs.len() < workers.max(1) {
            let Some((pid, request)) = queue.take_next() else {
                break;
            };
            let storage = storage.clone();
            let pm = pm.clone();
            let to = pid.clone();
            let handle = jobs.spawn(async move {
                let kind = request.kind();
                let built = tokio::task::spawn_blocking(move || {
                    // the anchor of a peer's own sync request is
                    // its current self-report.
                    let anchor = match &request {
                        NetworkMessage::GetBlocks { from, .. }
                        | NetworkMessage::GetHeaders { from, .. } => {
                            block_serve::anchor_height(&storage, from)
                        }
                        _ => None,
                    };
                    (answer_frames(&storage, &request), anchor)
                })
                .await;
                match built {
                    Ok((frames, anchor)) => {
                        // Only ever RAISES the report: a peer probing below
                        // its own tip (a fork-point search) is not behind.
                        // Only a handshake sets it lower.
                        if let (Some(h), Some(p)) = (anchor, pm.get_peer(&to)) {
                            let mut info = p.info.write().await;
                            if h > info.reported_head_height {
                                info.reported_head_height = h;
                                info.reported_at = std::time::Instant::now();
                            }
                        }
                        let blocks: usize = frames
                            .iter()
                            .map(|f| match f {
                                NetworkMessage::Blocks { blocks } => blocks.len(),
                                _ => 0,
                            })
                            .sum();
                        match frames.first() {
                            Some(NetworkMessage::Blocks { .. }) if frames.len() > 1 => info!(
                                "Sending {} blocks to peer {} in {} messages",
                                blocks,
                                to.0,
                                frames.len()
                            ),
                            Some(NetworkMessage::Blocks { .. }) => {
                                info!("Sending {} blocks to peer {}", blocks, to.0)
                            }
                            Some(NetworkMessage::Headers { headers }) => {
                                debug!("Sending {} headers to peer {}", headers.len(), to.0)
                            }
                            _ => {}
                        }
                        // In order, one after another, on the peer's one queue.
                        for frame in &frames {
                            if pm
                                .send_to_peers(std::slice::from_ref(&to), frame)
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                    Err(e) => warn!("serve plane: {} from {} not answered: {}", kind, to.0, e),
                }
            });
            job_peer.insert(handle.id(), pid);
        }
        if !open && jobs.is_empty() && queue.pending() == 0 {
            return;
        }
        tokio::select! {
            biased;
            done = jobs.join_next_with_id(), if !jobs.is_empty() => {
                let id = match done {
                    Some(Ok((id, ()))) => Some(id),
                    Some(Err(e)) => {
                        warn!("serve plane: an answer task failed: {}", e);
                        Some(e.id())
                    }
                    None => None,
                };
                if let Some(pid) = id.and_then(|id| job_peer.remove(&id)) {
                    queue.done(&pid);
                }
            }
            got = rx.recv(), if open && !queue.is_full() => match got {
                Some((pid, request)) => {
                    let kind = request.kind();
                    match queue.push(pid.clone(), request) {
                        ServeAdmit::Queued => {}
                        ServeAdmit::PeerFull | ServeAdmit::GlobalFull => {
                            pm.record_serve_drop(kind, &pid);
                        }
                    }
                }
                None => open = false,
            },
            // Unreachable while the loop invariants hold (no job running and
            // nothing to receive means nothing waits either, handled above);
            // ending lets `start_node`'s watchdog say so rather than spin.
            else => return,
        }
    }
}
