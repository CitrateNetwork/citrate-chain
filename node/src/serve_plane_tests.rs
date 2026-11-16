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
//
// With ADR CV-6 the node also sets a serving lane (`set_serve_sink`) and runs
// `serve_plane::spawn` on it, as `start_node` does: serve requests then never
// reach the loop, and every one of them must still be answered.

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
    // start_node: the serving lane and its task.
    let (serve_tx, serve_rx) = mpsc::channel(citrate_network::inbound::SERVE_LANE_CAPACITY);
    pm.set_serve_sink(serve_tx).await;
    let serving = crate::serve_plane::spawn(storage.clone(), pm.clone(), serve_rx);
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

    // Serving was moved, not dropped: every request is answered with blocks.
    let started = Instant::now();
    for (p, outbox) in outboxes.iter_mut().enumerate() {
        let mut answered = 0usize;
        while answered < REQUESTS_PER_PEER {
            let msg = tokio::time::timeout(Duration::from_secs(120), outbox.recv())
                .await
                .unwrap_or_else(|_| panic!("catchup-{p}: only {answered} answers"))
                .expect("outbox open");
            if let NetworkMessage::Blocks { blocks } = msg {
                assert!(!blocks.is_empty(), "catchup-{p}: an empty answer");
                answered += 1;
            }
        }
    }
    eprintln!(
        "SERVEPLANE all {} requests answered {:?} after the block was admitted",
        PEERS * REQUESTS_PER_PEER,
        started.elapsed()
    );
    assert_eq!(pm.serve_drops(), 0, "a serve request was shed");
    assert_eq!(pm.inbound_drops(), 0, "a consensus-queue message was shed");
    consensus_loop.abort();
    serving.abort();
}

// ---------------------------------------------------------------------------
// r1007 cold-sync wedge at height 1552 (2026-11-14).
//
// Every fresh node stalled at applied height 1552 while the network ran on past
// 96,000. Seven producers sealed at both 1552 and 1553; each height-1553 block
// carries one transaction, and the height-1553 group serializes to 74,543
// bytes. `serve_blocks` always emits the first height-group above the anchor
// (the SYNC-S2 forward-progress guarantee), so boot1/2/3 each built a 14-block
// reply (the 1552 group plus the 1553 group), and Noise refused to encrypt it:
//
//   block-serve: height-1553 group is 74543 bytes, over the 61440-byte soft budget
//   Sending 14 blocks to peer noise_26cee14b...
//   encrypt failed: Transport error: noise encrypt: input error
//   Removed peer: noise_26cee14b...
//
// The fixture below is that shape, served over a real Noise connection.
// ---------------------------------------------------------------------------

/// Producers sealing at each height on r1007 around 1552/1553.
const SIBLINGS: u8 = 7;
/// One height-1553 block: 74,543 / 7 bytes, rounded up.
const FAT_BLOCK_BYTES: u64 = 10_650;

/// A block padded with one transaction to serialize to `target_bytes`.
fn fat_block(id: u8, height: u64, selected: Hash, merges: Vec<Hash>, target_bytes: u64) -> Block {
    use citrate_consensus::types::{Signature, Transaction};
    let mk = |data: Vec<u8>| {
        let tx = Transaction {
            hash: Hash::new([id; 32]),
            nonce: 0,
            from: PublicKey::new([2; 32]),
            to: None,
            value: 0,
            gas_limit: 3_000_000,
            gas_price: 1_000_000_000,
            data,
            signature: Signature::new([1; 64]),
            tx_type: None,
            chain_id: Some(40204),
            ..Default::default()
        };
        BlockBuilder::new()
            .hash(hash_at(id, height))
            .parent(selected)
            .merge_parents(merges.clone())
            .height(height)
            .timestamp(1_000_000 + height)
            .blue_score(height)
            .blue_work(u128::from(height))
            .proposer(PublicKey::new([1; 32]))
            .transactions(vec![tx])
            .build_unhashed()
    };
    let base = bincode::serialized_size(&mk(Vec::new())).expect("size");
    mk(vec![0xAB; target_bytes.saturating_sub(base) as usize])
}

/// Genesis, seven empty siblings at height 1 (r1007's 1552) and seven
/// one-transaction siblings at height 2 (r1007's 1553). Returns the storage
/// and the requester's anchor: the canonical height-1 block.
fn wedge_1553_store() -> (TempDir, Arc<StorageManager>, Hash) {
    let dir = TempDir::new().expect("tempdir");
    let storage =
        Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
    let genesis = block(1, 0, Hash::default());
    storage.blocks.put_block(&genesis).expect("put genesis");
    let mut h1 = Vec::new();
    for id in 0..SIBLINGS {
        let b = block(0x10 + id, 1, genesis.hash());
        storage.blocks.put_block(&b).expect("put h1");
        h1.push(b.hash());
    }
    let anchor = storage
        .blocks
        .get_block_by_height(1)
        .expect("read")
        .expect("height 1 indexed");
    let merges: Vec<Hash> = h1.iter().copied().filter(|h| *h != anchor).collect();
    for id in 0..SIBLINGS {
        let b = fat_block(0x20 + id, 2, anchor, merges.clone(), FAT_BLOCK_BYTES);
        storage.blocks.put_block(&b).expect("put h2");
    }
    (dir, storage, anchor)
}

struct WireNode {
    pm: Arc<PeerManager>,
    transport: citrate_network::NetworkTransport,
    id: PeerId,
    incoming: mpsc::Receiver<(PeerId, NetworkMessage)>,
}

async fn wire_node() -> WireNode {
    let keypair = citrate_network::NoiseKeypair::generate().expect("noise keypair");
    let id = keypair.derive_peer_id();
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    let (tx, incoming) = mpsc::channel(1024);
    pm.set_incoming(tx).await;
    let params = citrate_network::transport::HandshakeParams {
        network_id: 40204,
        genesis_hash: Hash::new([0x42; 32]),
        head: Arc::new(tokio::sync::RwLock::new((0, Hash::new([0x42; 32])))),
    };
    let transport =
        citrate_network::NetworkTransport::new(pm.clone(), id.clone(), params).with_noise(keypair);
    WireNode {
        pm,
        transport,
        id,
        incoming,
    }
}

async fn wire_connect(server: &WireNode, client: &WireNode) {
    let addr = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr");
    server.transport.start_listener(addr).await.expect("listen");
    client.transport.connect_to(addr).await.expect("dial");
    let deadline = Instant::now() + Duration::from_secs(10);
    while server.pm.get_peer(&client.id).is_none() || client.pm.get_peer(&server.id).is_none() {
        assert!(
            Instant::now() < deadline,
            "Noise handshake did not complete"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// RED on main: the reply is one 14-block message over the Noise cap, so the
/// requester receives nothing and the server drops it. GREEN: the reply goes
/// out as several messages, every block arrives, and the connection stays up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_height_group_over_the_noise_cap_is_delivered_whole() {
    let (_dir, storage, anchor) = wedge_1553_store();
    let server = wire_node().await;
    let mut client = wire_node().await;
    let (serve_tx, serve_rx) = mpsc::channel(citrate_network::inbound::SERVE_LANE_CAPACITY);
    server.pm.set_serve_sink(serve_tx).await;
    let serving = crate::serve_plane::spawn(storage.clone(), server.pm.clone(), serve_rx);
    wire_connect(&server, &client).await;

    let expected = block_serve::serve_blocks(&storage, &anchor, 32);
    assert_eq!(
        expected.len(),
        usize::from(SIBLINGS) * 2,
        "the anchor's height-group plus the whole fat group above it"
    );
    let reply_bytes = bincode::serialized_size(&NetworkMessage::Blocks {
        blocks: expected.clone(),
    })
    .expect("size");
    assert!(
        reply_bytes > citrate_network::noise::MAX_NOISE_PLAINTEXT_LEN as u64,
        "fixture must reproduce an over-cap reply (got {reply_bytes} bytes)"
    );

    client
        .pm
        .get_peer(&server.id)
        .expect("server connected")
        .send(NetworkMessage::GetBlocks {
            from: anchor,
            count: 32,
            step: 1,
        })
        .await
        .expect("send GetBlocks");

    let mut got: Vec<Hash> = Vec::new();
    let mut frames = 0usize;
    let deadline = Instant::now() + Duration::from_secs(15);
    while got.len() < expected.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        let Ok(Some((from, msg))) = tokio::time::timeout(left, client.incoming.recv()).await else {
            panic!(
                "received {} of {} blocks in {frames} message(s): the over-cap reply was lost",
                got.len(),
                expected.len()
            );
        };
        if let NetworkMessage::Blocks { blocks } = msg {
            assert_eq!(from, server.id);
            frames += 1;
            got.extend(blocks.iter().map(|b| b.header.block_hash));
        }
    }
    let want: Vec<Hash> = expected.iter().map(|b| b.header.block_hash).collect();
    assert_eq!(got, want, "every block, once, in serve order");
    assert!(frames > 1, "the reply must have been split");
    assert!(
        server.pm.get_peer(&client.id).is_some(),
        "the server must keep the requester connected"
    );
    serving.abort();
}

/// Every message `answer_frames` puts on the wire for the height-1553 shape
/// fits one Noise message, and together they are exactly `serve_blocks`.
#[test]
fn answer_frames_fit_the_noise_cap() {
    let (_dir, storage, anchor) = wedge_1553_store();
    let request = NetworkMessage::GetBlocks {
        from: anchor,
        count: 32,
        step: 1,
    };
    let frames = crate::serve_plane::answer_frames(&storage, &request);
    assert!(frames.len() > 1, "the over-cap reply is split");
    let cap = citrate_network::noise::MAX_NOISE_PLAINTEXT_LEN;
    let mut served = Vec::new();
    for f in &frames {
        let wire = bincode::serialize(f).expect("encode");
        assert!(
            wire.len() <= cap,
            "a {}-byte message is over {cap}",
            wire.len()
        );
        let NetworkMessage::Blocks { blocks } = f else {
            panic!("a GetBlocks answer must be Blocks");
        };
        served.extend(blocks.iter().map(|b| b.header.block_hash));
    }
    let want: Vec<Hash> = block_serve::serve_blocks(&storage, &anchor, 32)
        .iter()
        .map(|b| b.header.block_hash)
        .collect();
    assert_eq!(served, want);

    // Headers answers are unchanged: one message.
    let headers = crate::serve_plane::answer_frames(
        &storage,
        &NetworkMessage::GetHeaders {
            from: anchor,
            count: 64,
        },
    );
    assert_eq!(headers.len(), 1);
}

/// a peer's own sync requests are its current
/// self-report. A `GetBlocks` (or `GetHeaders`) anchored at a block we hold at
/// height h refreshes that peer's reported head to h, so a long-lived
/// connection keeps an up-to-date report without a new handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peers_sync_request_refreshes_its_reported_head() {
    let (_dir, storage, _tip) = chain_of(40);
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    let (serve_tx, serve_rx) = mpsc::channel(citrate_network::inbound::SERVE_LANE_CAPACITY);
    pm.set_serve_sink(serve_tx).await;
    let serving = crate::serve_plane::spawn(storage.clone(), pm.clone(), serve_rx);
    let (p, mut outbox) = peer("member");
    p.info.write().await.reported_head_height = 3;
    pm.add_peer(p.clone()).await.expect("add peer");
    let anchor = storage
        .blocks
        .get_block_by_height(25)
        .expect("read")
        .expect("height 25");
    pm.forward_incoming(
        PeerId::new("member".to_string()),
        NetworkMessage::GetBlocks {
            from: anchor,
            count: 8,
            step: 1,
        },
    )
    .await;
    let _ = tokio::time::timeout(Duration::from_secs(10), outbox.recv())
        .await
        .expect("answered");
    assert_eq!(p.info.read().await.reported_head_height, 25);
    serving.abort();
}

/// A request anchor only RAISES a peer's reported head. A peer probing below
/// its own tip (a fork-point search) must not look far behind; only a new
/// handshake may lower the report.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lower_request_anchor_never_lowers_the_reported_head() {
    let (_dir, storage, _tip) = chain_of(40);
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    let (serve_tx, serve_rx) = mpsc::channel(citrate_network::inbound::SERVE_LANE_CAPACITY);
    pm.set_serve_sink(serve_tx).await;
    let serving = crate::serve_plane::spawn(storage.clone(), pm.clone(), serve_rx);
    let (p, mut outbox) = peer("prober");
    p.info.write().await.reported_head_height = 30;
    pm.add_peer(p.clone()).await.expect("add peer");
    let anchor = storage
        .blocks
        .get_block_by_height(12)
        .expect("read")
        .expect("height 12");
    pm.forward_incoming(
        PeerId::new("prober".to_string()),
        NetworkMessage::GetBlocks {
            from: anchor,
            count: 8,
            step: 1,
        },
    )
    .await;
    let _ = tokio::time::timeout(Duration::from_secs(10), outbox.recv())
        .await
        .expect("answered");
    assert_eq!(
        p.info.read().await.reported_head_height,
        30,
        "a lower anchor lowered the report"
    );
    serving.abort();
}
