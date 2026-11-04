// citrate/node/src/serve_plane_tests.rs
//
// CV-6 / planset H3: history serving must not delay block admission.
//
// THE FAILURE (r1006, 2026-11-01): one node serving catch-up to six peers had
// their GetBlocks in the same queue as block gossip, and answered each one
// from storage on the consensus loop (`main.rs`, the inbound message loop).
// A gossiped NewBlock waited behind every serve request queued ahead of it,
// so the producers heard each other's blocks late or not at all without ever
// looking "behind".
//
// The loop modelled here does what main.rs's inbound loop does with what
// reaches it: messages are taken off the node's inbound queue in order, and a
// serve request that reaches it is answered from storage there and then
// (`block_serve::serve_blocks` / `serve_headers`), as the loop did before CV-6.
// What is measured is how long a gossiped block waits in front of admission:
// from `forward_incoming` until the loop takes it off the queue.

use std::sync::Arc;
use std::time::{Duration, Instant};

use citrate_consensus::types::{Block, BlockBuilder, Hash, PublicKey};
use citrate_network::peer::{Direction, Peer, PeerInfo, PeerState};
use citrate_network::{NetworkMessage, PeerId, PeerManager, PeerManagerConfig};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use tempfile::TempDir;
use tokio::sync::mpsc;

use crate::block_serve;

/// Catching-up peers.
const PEERS: usize = 8;
/// Serve requests per peer, all sent before the gossiped block.
const REQUESTS_PER_PEER: usize = 60;
/// Stored chain the requests are served from.
const CHAIN: u64 = 600;
/// The bound on how long a gossiped block may wait for admission while the
/// node serves history. One 2 s slot is the producer's whole budget; a block
/// that waits a tenth of it is already late.
const ADMISSION_WAIT_BOUND: Duration = Duration::from_millis(200);

fn hash_at(tag: u8, height: u64) -> Hash {
    let mut bytes = [tag; 32];
    bytes[..8].copy_from_slice(&height.to_be_bytes());
    Hash::new(bytes)
}

fn block(tag: u8, height: u64, parent: Hash) -> Block {
    BlockBuilder::new()
        .hash(hash_at(tag, height))
        .parent(parent)
        .height(height)
        .timestamp(1_000_000 + height)
        .blue_score(height)
        .blue_work(u128::from(height))
        .proposer(PublicKey::new([1; 32]))
        .build_unhashed()
}

fn chain_of(n: u64) -> (TempDir, Arc<StorageManager>, Hash) {
    let dir = TempDir::new().expect("tempdir");
    let storage =
        Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
    let mut parent = Hash::default();
    for h in 0..n {
        let b = block(7, h, parent);
        parent = b.hash();
        storage.blocks.put_block(&b).expect("put_block");
    }
    (dir, storage, parent)
}

/// A connected peer whose outbound queue this test holds (what the node sends
/// it lands there).
fn peer(name: &str) -> (Arc<Peer>, mpsc::Receiver<NetworkMessage>) {
    let (tx, rx) = mpsc::channel(1 << 16);
    let (_in_tx, in_rx) = mpsc::channel(1);
    let mut info = PeerInfo::new(
        PeerId::new(name.to_string()),
        "127.0.0.1:1".parse().expect("addr"),
        Direction::Outbound,
    );
    info.state = PeerState::Connected;
    (Arc::new(Peer::new(info, tx, in_rx)), rx)
}

/// RED. While the node serves large GetBlocks ranges to catching-up peers, a
/// gossiped block reaches admission within [`ADMISSION_WAIT_BOUND`].
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn serve_does_not_block_admission() {
    let (_dir, storage, tip) = chain_of(CHAIN);
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    // main.rs: the 512-slot inbound queue.
    let (in_tx, mut in_rx) = mpsc::channel::<(PeerId, NetworkMessage)>(512);
    pm.set_incoming(in_tx).await;
    let mut outboxes = Vec::new();
    for p in 0..PEERS {
        let (peer, rx) = peer(&format!("catchup-{p}"));
        pm.add_peer(peer).await.expect("add peer");
        outboxes.push(rx);
    }

    // The consensus loop: takes messages in order; answers a serve request
    // that reaches it inline from storage, as main.rs's loop did.
    let (seen_tx, mut seen_rx) = mpsc::unbounded_channel::<Instant>();
    let loop_storage = storage.clone();
    let loop_pm = pm.clone();
    let consensus_loop = tokio::spawn(async move {
        while let Some((pid, msg)) = in_rx.recv().await {
            match msg {
                NetworkMessage::GetBlocks { from, count, .. } => {
                    let blocks = block_serve::serve_blocks(&loop_storage, &from, count);
                    let _ = loop_pm
                        .send_to_peers(
                            std::slice::from_ref(&pid),
                            &NetworkMessage::Blocks { blocks },
                        )
                        .await;
                }
                NetworkMessage::GetHeaders { from, count } => {
                    let headers = block_serve::serve_headers(&loop_storage, &from, count);
                    let _ = loop_pm
                        .send_to_peers(
                            std::slice::from_ref(&pid),
                            &NetworkMessage::Headers { headers },
                        )
                        .await;
                }
                NetworkMessage::NewBlock { .. } => {
                    let _ = seen_tx.send(Instant::now());
                }
                _ => {}
            }
        }
    });

    // History load: every peer asks for the whole chain from genesis.
    for _ in 0..REQUESTS_PER_PEER {
        for p in 0..PEERS {
            pm.forward_incoming(
                PeerId::new(format!("catchup-{p}")),
                NetworkMessage::GetBlocks {
                    from: Hash::default(),
                    count: block_serve::MAX_BLOCKS_PER_REQUEST,
                    step: 1,
                },
            )
            .await;
        }
    }
    // A producer's block arrives while that load is queued.
    let sent = Instant::now();
    pm.forward_incoming(
        PeerId::new("producer".to_string()),
        NetworkMessage::NewBlock {
            block: block(9, CHAIN, tip),
        },
    )
    .await;
    let seen = tokio::time::timeout(Duration::from_secs(120), seen_rx.recv())
        .await
        .expect("the gossiped block never reached admission")
        .expect("loop alive");
    let waited = seen.saturating_duration_since(sent);
    eprintln!("SERVEPLANE gossiped block waited {waited:?} for admission");
    assert!(
        waited <= ADMISSION_WAIT_BOUND,
        "a gossiped block waited {waited:?} for admission behind history serving \
         (bound {ADMISSION_WAIT_BOUND:?})"
    );
    consensus_loop.abort();
    drop(outboxes);
}
