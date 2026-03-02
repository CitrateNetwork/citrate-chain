// citrate/core/network/src/lib.rs

// Network module for peer-to-peer communication
pub mod ai_handler;
pub mod block_propagation;
pub mod discovery;
pub mod gossip;
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
pub use discovery::{Discovery, DiscoveryConfig};
pub use gossip::{GossipConfig, GossipProtocol};
pub use nat::{NatInfo, NatType};
pub use peer::{Peer, PeerId, PeerInfo, PeerManager, PeerManagerConfig};
pub use protocol::{ModelMetadata, NetworkMessage, Protocol, ProtocolVersion};
pub use relay::{RelayError, RelayService};
pub use sync::{SyncConfig, SyncManager, SyncState};
pub use transaction_gossip::{GossipConfig as TxGossipConfig, TransactionGossip};
pub use transport::NetworkTransport;
pub use types::{NetworkConfig, NetworkError};
pub use noise::NoiseKeypair;
