// citrate/core/network/src/lib.rs

// Network module for peer-to-peer communication
//
// LOCK ORDERING — acquire in this order to prevent deadlocks:
//
//   Level 1 (outermost — acquire first):
//     peer.rs          PeerManager.stats          (Arc<RwLock<PeerStats>>)
//     peer.rs          Peer.info                  (Arc<RwLock<PeerInfo>>)
//     discovery.rs     Discovery.connected_peers  (Arc<RwLock<HashSet<String>>>)
//
//   Level 2:
//     sync.rs          SyncManager.state              (Arc<RwLock<SyncState>>)
//     sync.rs          SyncManager.current_height     (Arc<RwLock<u64>>)
//     sync.rs          SyncManager.target_height      (Arc<RwLock<u64>>)
//     sync.rs          SyncManager.downloaded_headers (Arc<RwLock<Vec>>)
//     sync.rs          SyncManager.downloaded_blocks  (Arc<RwLock<Vec>>)
//     sync.rs          SyncManager.block_queue        (Arc<RwLock<VecDeque>>)
//     sync.rs          SyncManager.header_queue       (Arc<RwLock<VecDeque>>)
//     sync.rs          SyncManager.pending_headers    (Arc<RwLock<HashMap>>)
//     sync.rs          SyncManager.pending_blocks     (Arc<RwLock<HashMap>>)
//     sync.rs          SyncManager.last_header_hash   (Arc<RwLock<Option<Hash>>>)
//     sync.rs          SyncManager.last_requested_header (Arc<RwLock<Option<Hash>>>)
//
//   Level 3:
//     block_propagation.rs  BlockPropagation.block_sources     (Arc<RwLock<HashMap>>)
//     block_propagation.rs  BlockPropagation.recent_broadcasts (Arc<RwLock<HashSet>>)
//     block_propagation.rs  BlockPropagation.downloading       (Arc<RwLock<HashSet>>)
//     block_propagation.rs  BlockPropagation.header_cache      (Arc<RwLock<HashMap>>)
//     transaction_gossip.rs TransactionGossip.seen_txs         (Arc<RwLock<HashMap>>)
//     transaction_gossip.rs TransactionGossip.pending_ai_txs   (Arc<RwLock<Vec>>)
//     transaction_gossip.rs TransactionGossip.peer_inventory   (Arc<RwLock<HashMap>>)
//     gossip.rs             GossipProtocol.stats               (Arc<RwLock<GossipStats>>)
//     relay.rs              RelayService.sessions              (RwLock<HashMap>)
//
//   Level 4 (innermost — acquire last):
//     ai_handler.rs  AINetworkHandler.pending_inferences (Arc<RwLock<HashMap>>)
//     ai_handler.rs  AINetworkHandler.active_training    (Arc<RwLock<HashMap>>)
//     ai_handler.rs  AINetworkHandler.model_cache        (Arc<RwLock<HashMap>>)
//     noise.rs       NoiseSession.transport              (Arc<parking_lot::Mutex<TransportState>>)
//
//   Lock-free (DashMap, no ordering constraint):
//     peer.rs              PeerManager.peers        (Arc<DashMap>)
//     peer.rs              PeerManager.banned_peers  (Arc<DashMap>)
//     discovery.rs         Discovery.known_peers     (Arc<DashMap>)
//     gossip.rs            GossipProtocol.seen_blocks/seen_transactions (Arc<DashMap>)
//
//   Notes:
//   - Most functions acquire a single lock, drop it, then acquire the next (sequential).
//   - peer.rs remove_peer holds Peer.info.read() + stats.write() simultaneously — safe
//     because info is Level 1 and stats is Level 1 (same level, but info is read-only
//     and always acquired before stats in every path).
//   - sync.rs start_block_download holds downloaded_headers.read() + block_queue.write()
//     simultaneously — safe because no reverse ordering exists.
//   - discovery.rs find_peers holds connected_peers.read() while calling
//     peer_manager.get_peer_counts() which acquires stats.read() — safe (Level 1 read-read).
pub mod ai_handler;
pub mod block_propagation;
pub mod bootnode;
pub mod discovery;
pub mod gossip;
pub mod learning_messages;
pub mod nat;
pub mod noise;
pub mod peer;
pub mod protocol;
pub mod relay;
pub mod sync;
pub mod transaction_gossip;
pub mod transport;
pub mod types;

pub use ai_handler::{AINetworkHandler, NetworkInferenceExecutor, NetworkInferenceResult};
pub use block_propagation::BlockPropagation;
pub use bootnode::{resolve_bootnode, split_bootnode};
pub use discovery::{Discovery, DiscoveryConfig};
pub use gossip::{CheckpointLearningData, GossipConfig, GossipProtocol, LearningDedup};
pub use learning_messages::{
    AdapterOffer, BelnapConfidence, LearningEmbedding, LearningMessage, PerformanceProfile,
};
pub use nat::{NatInfo, NatType};
pub use peer::{Peer, PeerId, PeerInfo, PeerManager, PeerManagerConfig};
pub use protocol::{ModelMetadata, NetworkMessage, Protocol, ProtocolVersion};
pub use relay::{RelayError, RelayService};
pub use sync::{SyncConfig, SyncManager, SyncState};
pub use transaction_gossip::{GossipConfig as TxGossipConfig, TransactionGossip};
pub use transport::NetworkTransport;
pub use types::{NetworkConfig, NetworkError};
pub use noise::NoiseKeypair;
