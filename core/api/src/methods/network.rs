// citrate/core/api/src/methods/network.rs
use crate::types::{error::ApiError, response::NodeInfo};
use citrate_consensus::types::Hash;
use citrate_network::peer::PeerManager;
use std::sync::Arc;

/// Network-related API methods
pub struct NetworkApi {
    peer_manager: Arc<PeerManager>,
    chain_id: u64,
}

impl NetworkApi {
    pub fn new(peer_manager: Arc<PeerManager>, chain_id: u64) -> Self {
        Self {
            peer_manager,
            chain_id,
        }
    }

    /// Get network version
    pub async fn get_version(&self) -> Result<String, ApiError> {
        Ok(self.chain_id.to_string())
    }

    /// Get peer count
    pub async fn get_peer_count(&self) -> Result<usize, ApiError> {
        let (total, _, _) = self.peer_manager.get_peer_counts().await;
        Ok(total)
    }

    /// Check if node is listening for connections
    pub async fn is_listening(&self) -> Result<bool, ApiError> {
        // Check if we can accept more peers
        let (total, _, _) = self.peer_manager.get_peer_counts().await;
        Ok(total < self.peer_manager.max_peers())
    }

    /// Get node information
    pub async fn get_node_info(&self) -> Result<NodeInfo, ApiError> {
        let (peer_count, _, _) = self.peer_manager.get_peer_counts().await;

        Ok(NodeInfo {
            version: "citrate/v0.1.0".to_string(),
            network_id: 1,
            chain_id: self.chain_id,
            genesis_hash: Hash::default(),
            head_hash: Hash::default(),
            head_height: 0,
            peer_count,
        })
    }

    /// `net_peerInfo` (S3-7, core#605): every peer the peer manager holds,
    /// with the head the node's sync scoring reads for it.
    ///
    /// Data source: `PeerManager::get_all_peers()` → each `PeerInfo`
    /// (`core/network/src/peer.rs`). `headHeight` / `headHash` are
    /// `PeerInfo.head_height` / `head_hash`: seeded from the peer's
    /// Hello/HelloAck at the handshake (`transport.rs`) and raised by every
    /// gossiped block from that peer (`node/src/main.rs`, block gossip arm),
    /// the values the 2 s sync tick selects on (`node/src/sync_peer.rs`).
    /// They are ADVERTISED, not proven held (`sync_peer.rs` invariant I4), so
    /// `headSource` is `"advertised"`. Before the handshake completes
    /// (`Connecting` / `Handshaking`) no head is known and both are `null`.
    pub async fn get_peer_info(&self) -> Result<Vec<serde_json::Value>, ApiError> {
        use citrate_network::peer::{Direction, PeerState};
        let mut out = Vec::new();
        for peer in self.peer_manager.get_all_peers() {
            let info = peer.info.read().await;
            let direction = match info.direction {
                Direction::Inbound => "inbound",
                Direction::Outbound => "outbound",
            };
            let state = match info.state {
                PeerState::Connecting => "connecting",
                PeerState::Handshaking => "handshaking",
                PeerState::Connected => "connected",
                PeerState::Disconnecting => "disconnecting",
                PeerState::Disconnected => "disconnected",
            };
            let head_known = !matches!(info.state, PeerState::Connecting | PeerState::Handshaking);
            out.push(serde_json::json!({
                "id": info.id.to_string(),
                "addr": info.addr.to_string(),
                "direction": direction,
                "state": state,
                "headHeight": head_known.then(|| format!("0x{:x}", info.head_height)),
                "headHash": head_known
                    .then(|| format!("0x{}", hex::encode(info.head_hash.as_bytes()))),
                "headSource": "advertised",
                "lastSeenSecsAgo": info.last_seen.elapsed().as_secs(),
                "connectedSecs": info.connected_at.elapsed().as_secs(),
                "score": info.score,
            }));
        }
        Ok(out)
    }

    /// Get connected peers
    pub async fn get_peers(&self) -> Result<Vec<String>, ApiError> {
        let peers = self.peer_manager.get_all_peers();
        let mut peer_ids = Vec::new();

        for peer in peers {
            let info = peer.info.read().await;
            peer_ids.push(info.id.to_string());
        }

        Ok(peer_ids)
    }
}
