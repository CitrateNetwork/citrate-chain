// citrate/core/network/src/relay.rs
//
// WP-S.4: Relay protocol for NAT-bound peers.
// Bootstrap nodes act as relays, forwarding encrypted Noise frames
// between peers that cannot establish direct connections.

use crate::peer::{PeerId, PeerManager};
use crate::protocol::NetworkMessage;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Maximum relay payload size (1 MB).
const MAX_RELAY_PAYLOAD: usize = 1_048_576;

/// Relay session TTL — sessions expire after 10 minutes of inactivity.
const SESSION_TTL: Duration = Duration::from_secs(600);

/// Maximum concurrent relay sessions.
const MAX_SESSIONS: usize = 1000;

/// A relay session between two peers.
#[derive(Debug)]
#[allow(dead_code)]
struct RelaySession {
    /// The peer requesting relay service.
    requester: PeerId,

    /// The target peer being relayed to.
    target: PeerId,

    /// When the session was last active.
    last_active: Instant,

    /// Total bytes relayed in this session.
    bytes_relayed: u64,
}

/// Relay node service — handles relay requests from NAT-bound peers.
pub struct RelayService {
    peer_manager: Arc<PeerManager>,

    /// Active relay sessions, keyed by requester peer ID.
    sessions: RwLock<HashMap<PeerId, RelaySession>>,

    /// Whether this node is acting as a relay.
    enabled: bool,
}

impl RelayService {
    pub fn new(peer_manager: Arc<PeerManager>, enabled: bool) -> Self {
        Self {
            peer_manager,
            sessions: RwLock::new(HashMap::new()),
            enabled,
        }
    }

    /// Whether relay service is enabled on this node.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Handle an incoming relay request from a peer.
    ///
    /// Forwards the payload to the target peer as a `RelayData` message.
    pub async fn handle_relay_request(
        &self,
        from: &PeerId,
        target_peer_id: &str,
        payload: Vec<u8>,
    ) -> Result<(), RelayError> {
        if !self.enabled {
            return Err(RelayError::NotEnabled);
        }

        if payload.len() > MAX_RELAY_PAYLOAD {
            return Err(RelayError::PayloadTooLarge(payload.len()));
        }

        let target = PeerId::new(target_peer_id.to_string());

        // Check that target peer is connected
        let target_peer = self
            .peer_manager
            .get_peer(&target)
            .ok_or_else(|| RelayError::TargetNotFound(target_peer_id.to_string()))?;

        // Create or update session
        {
            let mut sessions = self.sessions.write().await;

            // Enforce max sessions
            if !sessions.contains_key(from) && sessions.len() >= MAX_SESSIONS {
                // Evict oldest session
                let oldest = sessions
                    .iter()
                    .min_by_key(|(_, s)| s.last_active)
                    .map(|(k, _)| k.clone());
                if let Some(key) = oldest {
                    sessions.remove(&key);
                }
            }

            sessions
                .entry(from.clone())
                .and_modify(|s| {
                    s.last_active = Instant::now();
                    s.bytes_relayed += payload.len() as u64;
                })
                .or_insert(RelaySession {
                    requester: from.clone(),
                    target: target.clone(),
                    last_active: Instant::now(),
                    bytes_relayed: payload.len() as u64,
                });
        }

        // Forward as RelayData to target
        let payload_len = payload.len();
        let relay_msg = NetworkMessage::RelayData {
            source_peer_id: from.0.clone(),
            payload,
        };

        target_peer
            .send(relay_msg)
            .await
            .map_err(|e| RelayError::ForwardFailed(e.to_string()))?;

        debug!(
            "Relayed {} bytes from {} to {}",
            payload_len,
            from.0,
            target_peer_id
        );

        Ok(())
    }

    /// Handle a hole punch request — notify the target peer.
    pub async fn handle_hole_punch_request(
        &self,
        from: &PeerId,
        target_peer_id: &str,
        external_addr: &str,
    ) -> Result<(), RelayError> {
        if !self.enabled {
            return Err(RelayError::NotEnabled);
        }

        let target = PeerId::new(target_peer_id.to_string());

        let target_peer = self
            .peer_manager
            .get_peer(&target)
            .ok_or_else(|| RelayError::TargetNotFound(target_peer_id.to_string()))?;

        // Send hole punch notification to target
        let notify_msg = NetworkMessage::HolePunchNotify {
            peer_id: from.0.clone(),
            external_addr: external_addr.to_string(),
        };

        target_peer
            .send(notify_msg)
            .await
            .map_err(|e| RelayError::ForwardFailed(e.to_string()))?;

        info!(
            "Sent hole punch notification: {} wants to connect to {} (external: {})",
            from.0, target_peer_id, external_addr
        );

        Ok(())
    }

    /// Clean up expired relay sessions.
    pub async fn cleanup_expired_sessions(&self) -> usize {
        let mut sessions = self.sessions.write().await;
        let before = sessions.len();
        sessions.retain(|_, s| s.last_active.elapsed() < SESSION_TTL);
        let removed = before - sessions.len();
        if removed > 0 {
            debug!("Cleaned up {} expired relay sessions", removed);
        }
        removed
    }

    /// Get the number of active relay sessions.
    pub async fn active_session_count(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Get total bytes relayed.
    pub async fn total_bytes_relayed(&self) -> u64 {
        self.sessions
            .read()
            .await
            .values()
            .map(|s| s.bytes_relayed)
            .sum()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("relay service not enabled")]
    NotEnabled,

    #[error("target peer not found: {0}")]
    TargetNotFound(String),

    #[error("payload too large: {0} bytes (max {MAX_RELAY_PAYLOAD})")]
    PayloadTooLarge(usize),

    #[error("failed to forward message: {0}")]
    ForwardFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerManagerConfig;

    #[tokio::test]
    async fn test_relay_service_disabled() {
        let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
        let relay = RelayService::new(pm, false);

        assert!(!relay.is_enabled());

        let from = PeerId::new("peer_1".to_string());
        let result = relay
            .handle_relay_request(&from, "peer_2", vec![1, 2, 3])
            .await;

        assert!(matches!(result, Err(RelayError::NotEnabled)));
    }

    #[tokio::test]
    async fn test_relay_payload_too_large() {
        let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
        let relay = RelayService::new(pm, true);

        let from = PeerId::new("peer_1".to_string());
        let payload = vec![0u8; MAX_RELAY_PAYLOAD + 1];
        let result = relay.handle_relay_request(&from, "peer_2", payload).await;

        assert!(matches!(result, Err(RelayError::PayloadTooLarge(_))));
    }

    #[tokio::test]
    async fn test_relay_target_not_found() {
        let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
        let relay = RelayService::new(pm, true);

        let from = PeerId::new("peer_1".to_string());
        let result = relay
            .handle_relay_request(&from, "nonexistent_peer", vec![1, 2, 3])
            .await;

        assert!(matches!(result, Err(RelayError::TargetNotFound(_))));
    }
}
