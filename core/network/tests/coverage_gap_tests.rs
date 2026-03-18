// coverage_gap_tests.rs — tests targeting uncovered lines in citrate-network
//
// Covers: peer management edge cases, message construction/serialization,
// config validation, direction tracking, gossip config, discovery config.

use citrate_network::peer::{Direction, Peer, PeerId, PeerInfo, PeerManager, PeerManagerConfig};
use citrate_network::protocol::{
    DagBlockInfo, MessagePriority, NetworkMessage, PeerAddress, ProtocolVersion,
};
use citrate_network::types::{NetworkConfig, NetworkStats};
use citrate_network::{DiscoveryConfig, GossipConfig};

use citrate_consensus::types::Hash;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// PeerInfo stale detection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_peer_info_stale_detection() {
    let peer_id = PeerId::new("stale_test".into());
    let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
    let info = PeerInfo::new(peer_id, addr, Direction::Inbound);

    // With a zero timeout, the peer should immediately be stale
    assert!(info.is_stale(Duration::from_secs(0)));

    // With a long timeout, the peer should not be stale
    assert!(!info.is_stale(Duration::from_secs(3600)));
}

#[tokio::test]
async fn test_peer_info_update_last_seen() {
    let peer_id = PeerId::new("update_test".into());
    let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
    let mut info = PeerInfo::new(peer_id, addr, Direction::Outbound);

    // After creation, should not be stale with reasonable timeout
    assert!(!info.is_stale(Duration::from_secs(60)));

    // Update last_seen and verify still not stale
    info.update_last_seen();
    assert!(!info.is_stale(Duration::from_secs(60)));
}

// ---------------------------------------------------------------------------
// PeerManager ban and check
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_peer_manager_ban_and_check() {
    let config = PeerManagerConfig {
        ban_duration: Duration::from_secs(3600),
        ..Default::default()
    };
    let manager = PeerManager::new(config);

    let addr: SocketAddr = "10.0.0.1:30303".parse().unwrap();

    // Not banned initially
    assert!(!manager.is_banned(&addr).await);

    // Ban the address
    manager.ban_peer(addr).await;

    // Should now be banned
    assert!(manager.is_banned(&addr).await);
}

#[tokio::test]
async fn test_peer_manager_ban_expiry() {
    let config = PeerManagerConfig {
        // Very short ban duration so it expires quickly
        ban_duration: Duration::from_millis(1),
        ..Default::default()
    };
    let manager = PeerManager::new(config);

    let addr: SocketAddr = "10.0.0.2:30303".parse().unwrap();
    manager.ban_peer(addr).await;

    // Wait for ban to expire
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Ban should have expired
    assert!(!manager.is_banned(&addr).await);
}

#[tokio::test]
async fn test_peer_manager_cleanup_expired_bans() {
    let config = PeerManagerConfig {
        ban_duration: Duration::from_millis(1),
        ..Default::default()
    };
    let manager = PeerManager::new(config);

    let addr1: SocketAddr = "10.0.0.3:30303".parse().unwrap();
    let addr2: SocketAddr = "10.0.0.4:30303".parse().unwrap();

    manager.ban_peer(addr1).await;
    manager.ban_peer(addr2).await;

    // Wait for bans to expire
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Cleanup should remove expired bans
    manager.cleanup_expired_bans();

    assert!(!manager.is_banned(&addr1).await);
    assert!(!manager.is_banned(&addr2).await);
}

// ---------------------------------------------------------------------------
// NetworkMessage serialization roundtrip
// ---------------------------------------------------------------------------

#[test]
fn test_network_message_serialization_roundtrip_hello() {
    let msg = NetworkMessage::Hello {
        version: ProtocolVersion::CURRENT,
        network_id: 42,
        genesis_hash: Hash::new([0xAA; 32]),
        head_height: 100,
        head_hash: Hash::new([0xBB; 32]),
        peer_id: "peer_hello".into(),
    };
    let bytes = bincode::serialize(&msg).expect("serialize Hello");
    let recovered: NetworkMessage = bincode::deserialize(&bytes).expect("deserialize Hello");
    match recovered {
        NetworkMessage::Hello {
            network_id,
            head_height,
            peer_id,
            ..
        } => {
            assert_eq!(network_id, 42);
            assert_eq!(head_height, 100);
            assert_eq!(peer_id, "peer_hello");
        }
        other => panic!("Expected Hello, got {:?}", other),
    }
}

#[test]
fn test_network_message_serialization_roundtrip_hello_ack() {
    let msg = NetworkMessage::HelloAck {
        version: ProtocolVersion::CURRENT,
        head_height: 200,
        head_hash: Hash::new([0xCC; 32]),
        peer_id: "ack_peer".into(),
    };
    let bytes = bincode::serialize(&msg).expect("serialize HelloAck");
    let recovered: NetworkMessage = bincode::deserialize(&bytes).expect("deserialize HelloAck");
    match recovered {
        NetworkMessage::HelloAck {
            head_height,
            peer_id,
            ..
        } => {
            assert_eq!(head_height, 200);
            assert_eq!(peer_id, "ack_peer");
        }
        other => panic!("Expected HelloAck, got {:?}", other),
    }
}

#[test]
fn test_network_message_serialization_roundtrip_disconnect() {
    let msg = NetworkMessage::Disconnect {
        reason: "test disconnect".into(),
    };
    let bytes = bincode::serialize(&msg).unwrap();
    let recovered: NetworkMessage = bincode::deserialize(&bytes).unwrap();
    match recovered {
        NetworkMessage::Disconnect { reason } => assert_eq!(reason, "test disconnect"),
        other => panic!("Expected Disconnect, got {:?}", other),
    }
}

#[test]
fn test_network_message_serialization_roundtrip_get_blocks() {
    let msg = NetworkMessage::GetBlocks {
        from: Hash::new([1; 32]),
        count: 50,
        step: 2,
    };
    let bytes = bincode::serialize(&msg).unwrap();
    let recovered: NetworkMessage = bincode::deserialize(&bytes).unwrap();
    match recovered {
        NetworkMessage::GetBlocks { count, step, .. } => {
            assert_eq!(count, 50);
            assert_eq!(step, 2);
        }
        other => panic!("Expected GetBlocks, got {:?}", other),
    }
}

#[test]
fn test_network_message_serialization_roundtrip_get_peers() {
    let msg = NetworkMessage::GetPeers;
    let bytes = bincode::serialize(&msg).unwrap();
    let recovered: NetworkMessage = bincode::deserialize(&bytes).unwrap();
    assert!(matches!(recovered, NetworkMessage::GetPeers));
}

#[test]
fn test_network_message_serialization_roundtrip_peers() {
    let msg = NetworkMessage::Peers {
        peers: vec![PeerAddress {
            id: "remote_peer".into(),
            addr: "192.168.1.1:30303".into(),
            last_seen: 12345,
            score: 50,
        }],
    };
    let bytes = bincode::serialize(&msg).unwrap();
    let recovered: NetworkMessage = bincode::deserialize(&bytes).unwrap();
    match recovered {
        NetworkMessage::Peers { peers } => {
            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].id, "remote_peer");
            assert_eq!(peers[0].score, 50);
        }
        other => panic!("Expected Peers, got {:?}", other),
    }
}

#[test]
fn test_network_message_serialization_roundtrip_get_mempool() {
    let msg = NetworkMessage::GetMempool;
    let bytes = bincode::serialize(&msg).unwrap();
    let recovered: NetworkMessage = bincode::deserialize(&bytes).unwrap();
    assert!(matches!(recovered, NetworkMessage::GetMempool));
}

#[test]
fn test_network_message_serialization_roundtrip_mempool() {
    let msg = NetworkMessage::Mempool {
        tx_hashes: vec![Hash::new([10; 32]), Hash::new([20; 32])],
    };
    let bytes = bincode::serialize(&msg).unwrap();
    let recovered: NetworkMessage = bincode::deserialize(&bytes).unwrap();
    match recovered {
        NetworkMessage::Mempool { tx_hashes } => {
            assert_eq!(tx_hashes.len(), 2);
        }
        other => panic!("Expected Mempool, got {:?}", other),
    }
}

#[test]
fn test_network_message_serialization_roundtrip_checkpoint_vote() {
    let msg = NetworkMessage::CheckpointVote {
        height: 500,
        block_hash: Hash::new([0xFF; 32]),
        voter_pubkey: vec![1, 2, 3],
        signature: vec![4, 5, 6],
    };
    let bytes = bincode::serialize(&msg).unwrap();
    let recovered: NetworkMessage = bincode::deserialize(&bytes).unwrap();
    match recovered {
        NetworkMessage::CheckpointVote {
            height,
            voter_pubkey,
            signature,
            ..
        } => {
            assert_eq!(height, 500);
            assert_eq!(voter_pubkey, vec![1, 2, 3]);
            assert_eq!(signature, vec![4, 5, 6]);
        }
        other => panic!("Expected CheckpointVote, got {:?}", other),
    }
}

#[test]
fn test_network_message_serialization_roundtrip_relay_request() {
    let msg = NetworkMessage::RelayRequest {
        target_peer_id: "target".into(),
        payload: vec![0xDE, 0xAD],
    };
    let bytes = bincode::serialize(&msg).unwrap();
    let recovered: NetworkMessage = bincode::deserialize(&bytes).unwrap();
    match recovered {
        NetworkMessage::RelayRequest {
            target_peer_id,
            payload,
        } => {
            assert_eq!(target_peer_id, "target");
            assert_eq!(payload, vec![0xDE, 0xAD]);
        }
        other => panic!("Expected RelayRequest, got {:?}", other),
    }
}

#[test]
fn test_network_message_serialization_roundtrip_relay_data() {
    let msg = NetworkMessage::RelayData {
        source_peer_id: "source".into(),
        payload: vec![0xBE, 0xEF],
    };
    let bytes = bincode::serialize(&msg).unwrap();
    let recovered: NetworkMessage = bincode::deserialize(&bytes).unwrap();
    match recovered {
        NetworkMessage::RelayData {
            source_peer_id,
            payload,
        } => {
            assert_eq!(source_peer_id, "source");
            assert_eq!(payload, vec![0xBE, 0xEF]);
        }
        other => panic!("Expected RelayData, got {:?}", other),
    }
}

#[test]
fn test_network_message_serialization_roundtrip_hole_punch() {
    let msg = NetworkMessage::HolePunchRequest {
        target_peer_id: "target_hp".into(),
        external_addr: "1.2.3.4:5678".into(),
    };
    let bytes = bincode::serialize(&msg).unwrap();
    let recovered: NetworkMessage = bincode::deserialize(&bytes).unwrap();
    match recovered {
        NetworkMessage::HolePunchRequest {
            target_peer_id,
            external_addr,
        } => {
            assert_eq!(target_peer_id, "target_hp");
            assert_eq!(external_addr, "1.2.3.4:5678");
        }
        other => panic!("Expected HolePunchRequest, got {:?}", other),
    }
}

#[test]
fn test_network_message_serialization_roundtrip_hole_punch_notify() {
    let msg = NetworkMessage::HolePunchNotify {
        peer_id: "notified_peer".into(),
        external_addr: "5.6.7.8:9012".into(),
    };
    let bytes = bincode::serialize(&msg).unwrap();
    let recovered: NetworkMessage = bincode::deserialize(&bytes).unwrap();
    match recovered {
        NetworkMessage::HolePunchNotify {
            peer_id,
            external_addr,
        } => {
            assert_eq!(peer_id, "notified_peer");
            assert_eq!(external_addr, "5.6.7.8:9012");
        }
        other => panic!("Expected HolePunchNotify, got {:?}", other),
    }
}

#[test]
fn test_network_message_serialization_roundtrip_model_announce() {
    let msg = NetworkMessage::ModelAnnounce {
        model_id: Hash::new([0x11; 32]),
        model_hash: Hash::new([0x22; 32]),
        owner: vec![1, 2, 3, 4],
        metadata: citrate_network::ModelMetadata {
            name: "test-model".into(),
            version: "1.0".into(),
            description: "desc".into(),
            framework: "pytorch".into(),
            input_shape: vec![1, 3, 224, 224],
            output_shape: vec![1, 1000],
            size_bytes: 100_000,
            created_at: 0,
        },
        weight_cid: "QmTest123".into(),
    };
    let bytes = bincode::serialize(&msg).unwrap();
    let recovered: NetworkMessage = bincode::deserialize(&bytes).unwrap();
    match recovered {
        NetworkMessage::ModelAnnounce {
            weight_cid,
            metadata,
            ..
        } => {
            assert_eq!(weight_cid, "QmTest123");
            assert_eq!(metadata.name, "test-model");
        }
        other => panic!("Expected ModelAnnounce, got {:?}", other),
    }
}

#[test]
fn test_network_message_serialization_roundtrip_inference_request() {
    let msg = NetworkMessage::InferenceRequest {
        request_id: Hash::new([0x33; 32]),
        model_id: Hash::new([0x44; 32]),
        input_hash: Hash::new([0x55; 32]),
        requester: vec![5, 6, 7],
        max_fee: 1_000_000,
    };
    let bytes = bincode::serialize(&msg).unwrap();
    let recovered: NetworkMessage = bincode::deserialize(&bytes).unwrap();
    match recovered {
        NetworkMessage::InferenceRequest {
            max_fee,
            requester,
            ..
        } => {
            assert_eq!(max_fee, 1_000_000);
            assert_eq!(requester, vec![5, 6, 7]);
        }
        other => panic!("Expected InferenceRequest, got {:?}", other),
    }
}

#[test]
fn test_network_message_serialization_roundtrip_training_job() {
    let msg = NetworkMessage::TrainingJobAnnounce {
        job_id: Hash::new([0x66; 32]),
        model_id: Hash::new([0x77; 32]),
        dataset_hash: Hash::new([0x88; 32]),
        participants_needed: 10,
        reward_per_gradient: 5000,
        owner: [0xAA; 20],
    };
    let bytes = bincode::serialize(&msg).unwrap();
    let recovered: NetworkMessage = bincode::deserialize(&bytes).unwrap();
    match recovered {
        NetworkMessage::TrainingJobAnnounce {
            participants_needed,
            reward_per_gradient,
            owner,
            ..
        } => {
            assert_eq!(participants_needed, 10);
            assert_eq!(reward_per_gradient, 5000);
            assert_eq!(owner, [0xAA; 20]);
        }
        other => panic!("Expected TrainingJobAnnounce, got {:?}", other),
    }
}

#[test]
fn test_network_message_serialization_roundtrip_dag_info() {
    let msg = NetworkMessage::DagInfo {
        info: vec![DagBlockInfo {
            hash: Hash::new([1; 32]),
            selected_parent: Hash::new([2; 32]),
            merge_parents: vec![Hash::new([3; 32])],
            blue_score: 42,
            is_blue: true,
        }],
    };
    let bytes = bincode::serialize(&msg).unwrap();
    let recovered: NetworkMessage = bincode::deserialize(&bytes).unwrap();
    match recovered {
        NetworkMessage::DagInfo { info } => {
            assert_eq!(info.len(), 1);
            assert_eq!(info[0].blue_score, 42);
            assert!(info[0].is_blue);
        }
        other => panic!("Expected DagInfo, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// NetworkConfig defaults
// ---------------------------------------------------------------------------

#[test]
fn test_network_config_defaults() {
    let config = NetworkConfig::default();

    assert_eq!(config.max_peers, 50);
    assert_eq!(config.max_inbound, 30);
    assert_eq!(config.max_outbound, 20);
    assert!(config.enable_discovery);
    assert_eq!(config.gossip_interval, Duration::from_secs(1));
    assert_eq!(config.connection_timeout, Duration::from_secs(10));
    assert_eq!(config.handshake_timeout, Duration::from_secs(5));
    assert_eq!(config.request_timeout, Duration::from_secs(30));
    assert_eq!(config.ping_interval, Duration::from_secs(30));
    assert_eq!(config.network_id, 1);
    assert_eq!(
        config.listen_addr,
        "0.0.0.0:30303".parse::<SocketAddr>().unwrap()
    );
    assert!(config.bootstrap_nodes.is_empty());
}

#[test]
fn test_network_config_serialization_roundtrip() {
    let config = NetworkConfig::default();
    let json = serde_json::to_string(&config).expect("serialize NetworkConfig");
    let recovered: NetworkConfig = serde_json::from_str(&json).expect("deserialize NetworkConfig");
    assert_eq!(recovered.max_peers, config.max_peers);
    assert_eq!(recovered.network_id, config.network_id);
}

// ---------------------------------------------------------------------------
// Peer direction tracking
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_peer_direction_tracking() {
    let config = PeerManagerConfig {
        max_peers: 10,
        max_inbound: 5,
        max_outbound: 5,
        ..Default::default()
    };
    let manager = PeerManager::new(config);

    // Add 2 inbound, 3 outbound
    for i in 0..2u16 {
        let (tx, rx) = mpsc::channel(10);
        let addr: SocketAddr = format!("127.0.0.1:{}", 9100 + i).parse().unwrap();
        let peer = Arc::new(Peer::new(
            PeerInfo::new(PeerId::new(format!("in_{}", i)), addr, Direction::Inbound),
            tx,
            rx,
        ));
        manager.add_peer(peer).await.unwrap();
    }

    for i in 0..3u16 {
        let (tx, rx) = mpsc::channel(10);
        let addr: SocketAddr = format!("127.0.0.2:{}", 9200 + i).parse().unwrap();
        let peer = Arc::new(Peer::new(
            PeerInfo::new(PeerId::new(format!("out_{}", i)), addr, Direction::Outbound),
            tx,
            rx,
        ));
        manager.add_peer(peer).await.unwrap();
    }

    let (total, inbound, outbound) = manager.get_peer_counts().await;
    assert_eq!(total, 5);
    assert_eq!(inbound, 2);
    assert_eq!(outbound, 3);
}

// ---------------------------------------------------------------------------
// Peer disconnect removes from list
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_peer_disconnect_removes_from_list() {
    let manager = PeerManager::new(PeerManagerConfig::default());

    let peer_id = PeerId::new("removable".into());
    let addr: SocketAddr = "127.0.0.1:9300".parse().unwrap();
    let (tx, rx) = mpsc::channel(10);
    let peer = Arc::new(Peer::new(
        PeerInfo::new(peer_id.clone(), addr, Direction::Inbound),
        tx,
        rx,
    ));

    manager.add_peer(peer).await.unwrap();
    assert!(manager.get_peer(&peer_id).is_some());

    // Remove
    let removed = manager.remove_peer(&peer_id).await;
    assert!(removed.is_some());
    assert!(manager.get_peer(&peer_id).is_none());

    let (total, inbound, _) = manager.get_peer_counts().await;
    assert_eq!(total, 0);
    assert_eq!(inbound, 0);
}

#[tokio::test]
async fn test_remove_nonexistent_peer() {
    let manager = PeerManager::new(PeerManagerConfig::default());
    let peer_id = PeerId::new("nonexistent".into());
    let removed = manager.remove_peer(&peer_id).await;
    assert!(removed.is_none());
}

// ---------------------------------------------------------------------------
// GossipConfig defaults
// ---------------------------------------------------------------------------

#[test]
fn test_gossip_config_defaults() {
    let config = GossipConfig::default();

    assert_eq!(config.max_seen_cache, 10000);
    assert_eq!(config.seen_cache_ttl, Duration::from_secs(600));
    assert_eq!(config.fanout, 8);
    assert_eq!(config.max_message_size, 1024 * 1024); // 1MB
    assert_eq!(config.validation_timeout, Duration::from_millis(100));
}

// ---------------------------------------------------------------------------
// DiscoveryConfig defaults
// ---------------------------------------------------------------------------

#[test]
fn test_discovery_config_defaults() {
    let config = DiscoveryConfig::default();

    assert!(config.bootstrap_nodes.is_empty());
    assert_eq!(config.max_peers, 100);
    assert_eq!(config.discovery_interval, Duration::from_secs(30));
    assert_eq!(config.peer_exchange_size, 10);
    assert_eq!(config.peer_expiry, Duration::from_secs(3600));
}

// ---------------------------------------------------------------------------
// PeerManagerConfig defaults
// ---------------------------------------------------------------------------

#[test]
fn test_peer_manager_config_defaults() {
    let config = PeerManagerConfig::default();

    assert_eq!(config.max_peers, 50);
    assert_eq!(config.max_inbound, 30);
    assert_eq!(config.max_outbound, 20);
    assert_eq!(config.peer_timeout, Duration::from_secs(120));
    assert_eq!(config.ban_duration, Duration::from_secs(3600));
    assert_eq!(config.score_threshold, -100);
}

// ---------------------------------------------------------------------------
// PeerId operations
// ---------------------------------------------------------------------------

#[test]
fn test_peer_id_new_and_display() {
    let id = PeerId::new("my_peer_123".into());
    assert_eq!(id.0, "my_peer_123");
    assert_eq!(format!("{}", id), "my_peer_123");
}

#[test]
fn test_peer_id_random_unique() {
    let id1 = PeerId::random();
    let id2 = PeerId::random();
    assert_ne!(id1, id2);
}

#[test]
fn test_peer_id_equality() {
    let id1 = PeerId::new("same".into());
    let id2 = PeerId::new("same".into());
    let id3 = PeerId::new("different".into());
    assert_eq!(id1, id2);
    assert_ne!(id1, id3);
}

#[test]
fn test_peer_id_hash_trait() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(PeerId::new("a".into()));
    set.insert(PeerId::new("b".into()));
    set.insert(PeerId::new("a".into())); // duplicate
    assert_eq!(set.len(), 2);
}

// ---------------------------------------------------------------------------
// PeerInfo initial values
// ---------------------------------------------------------------------------

#[test]
fn test_peer_info_initial_values() {
    let id = PeerId::new("init_test".into());
    let addr: SocketAddr = "127.0.0.1:30303".parse().unwrap();
    let info = PeerInfo::new(id.clone(), addr, Direction::Outbound);

    assert_eq!(info.id, id);
    assert_eq!(info.addr, addr);
    assert_eq!(info.state, citrate_network::peer::PeerState::Connecting);
    assert_eq!(info.direction, Direction::Outbound);
    assert!(info.version.is_none());
    assert_eq!(info.head_height, 0);
    assert_eq!(info.messages_sent, 0);
    assert_eq!(info.messages_received, 0);
    assert_eq!(info.bytes_sent, 0);
    assert_eq!(info.bytes_received, 0);
    assert_eq!(info.score, 0);
}

// ---------------------------------------------------------------------------
// ProtocolVersion compatibility
// ---------------------------------------------------------------------------

#[test]
fn test_protocol_version_compatible_same_major() {
    let v1 = ProtocolVersion { major: 1, minor: 0, patch: 0 };
    let v2 = ProtocolVersion { major: 1, minor: 5, patch: 3 };
    assert!(v1.is_compatible(&v2));
    assert!(v2.is_compatible(&v1));
}

#[test]
fn test_protocol_version_incompatible_different_major() {
    let v1 = ProtocolVersion { major: 1, minor: 0, patch: 0 };
    let v2 = ProtocolVersion { major: 2, minor: 0, patch: 0 };
    assert!(!v1.is_compatible(&v2));
}

#[test]
fn test_protocol_version_display() {
    let v = ProtocolVersion { major: 1, minor: 2, patch: 3 };
    assert_eq!(format!("{}", v), "1.2.3");
}

#[test]
fn test_protocol_version_current() {
    let current = ProtocolVersion::CURRENT;
    assert_eq!(current.major, 1);
    assert!(current.is_compatible(&current));
}

// ---------------------------------------------------------------------------
// MessagePriority and requires_response coverage
// ---------------------------------------------------------------------------

#[test]
fn test_message_priority_all_variants() {
    // Critical
    assert_eq!(
        NetworkMessage::GetHeaders { from: Hash::default(), count: 1 }.priority(),
        MessagePriority::Critical
    );

    // High
    // (NewBlock tested in existing tests)

    // Normal
    assert_eq!(
        NetworkMessage::GetTransactions { hashes: vec![] }.priority(),
        MessagePriority::Normal
    );
    assert_eq!(
        NetworkMessage::Transactions { transactions: vec![] }.priority(),
        MessagePriority::Normal
    );

    // Low
    assert_eq!(
        NetworkMessage::Ping { nonce: 0 }.priority(),
        MessagePriority::Low
    );
    assert_eq!(
        NetworkMessage::Pong { nonce: 0 }.priority(),
        MessagePriority::Low
    );

    // Default Normal (for variants not explicitly matched)
    assert_eq!(
        NetworkMessage::Disconnect { reason: "bye".into() }.priority(),
        MessagePriority::Normal
    );
    assert_eq!(
        NetworkMessage::Blocks { blocks: vec![] }.priority(),
        MessagePriority::Normal
    );
    assert_eq!(
        NetworkMessage::Headers { headers: vec![] }.priority(),
        MessagePriority::Normal
    );
}

#[test]
fn test_message_requires_response_comprehensive() {
    // Messages that require responses
    assert!(NetworkMessage::Ping { nonce: 0 }.requires_response());
    assert!(NetworkMessage::GetBlocks { from: Hash::default(), count: 1, step: 1 }.requires_response());
    assert!(NetworkMessage::GetHeaders { from: Hash::default(), count: 1 }.requires_response());
    assert!(NetworkMessage::GetTransactions { hashes: vec![] }.requires_response());
    assert!(NetworkMessage::GetMempool.requires_response());
    assert!(NetworkMessage::GetPeers.requires_response());
    assert!(NetworkMessage::GetBlueSet { block: Hash::default() }.requires_response());
    assert!(NetworkMessage::GetDagInfo { blocks: vec![] }.requires_response());
    assert!(NetworkMessage::GetState { root: Hash::default(), keys: vec![] }.requires_response());
    assert!(NetworkMessage::GetBlocksByHeight { from_height: 0, count: 1 }.requires_response());

    // Messages that do NOT require responses
    assert!(!NetworkMessage::Pong { nonce: 0 }.requires_response());
    assert!(!NetworkMessage::Disconnect { reason: "x".into() }.requires_response());
    assert!(!NetworkMessage::Blocks { blocks: vec![] }.requires_response());
    assert!(!NetworkMessage::Headers { headers: vec![] }.requires_response());
    assert!(!NetworkMessage::Peers { peers: vec![] }.requires_response());
    assert!(NetworkMessage::GetPeers.requires_response()); // GetPeers does require response
}

// ---------------------------------------------------------------------------
// NetworkStats defaults
// ---------------------------------------------------------------------------

#[test]
fn test_network_stats_defaults() {
    let stats = NetworkStats::default();
    assert_eq!(stats.peers_connected, 0);
    assert_eq!(stats.peers_inbound, 0);
    assert_eq!(stats.peers_outbound, 0);
    assert_eq!(stats.messages_sent, 0);
    assert_eq!(stats.messages_received, 0);
    assert_eq!(stats.bytes_sent, 0);
    assert_eq!(stats.bytes_received, 0);
}

// ---------------------------------------------------------------------------
// PeerManager max_peers accessor
// ---------------------------------------------------------------------------

#[test]
fn test_peer_manager_max_peers() {
    let config = PeerManagerConfig {
        max_peers: 42,
        ..Default::default()
    };
    let manager = PeerManager::new(config);
    assert_eq!(manager.max_peers(), 42);
}

// ---------------------------------------------------------------------------
// PeerManager get_all_peers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_peer_manager_get_all_peers() {
    let manager = PeerManager::new(PeerManagerConfig::default());

    // Initially empty
    assert!(manager.get_all_peers().is_empty());

    // Add peers
    for i in 0..3u16 {
        let (tx, rx) = mpsc::channel(10);
        let addr: SocketAddr = format!("127.0.0.1:{}", 9400 + i).parse().unwrap();
        let peer = Arc::new(Peer::new(
            PeerInfo::new(PeerId::new(format!("all_{}", i)), addr, Direction::Inbound),
            tx,
            rx,
        ));
        manager.add_peer(peer).await.unwrap();
    }

    assert_eq!(manager.get_all_peers().len(), 3);
}

// ---------------------------------------------------------------------------
// PeerManager set_incoming and forward_incoming
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_peer_manager_set_and_forward_incoming() {
    let manager = PeerManager::new(PeerManagerConfig::default());
    let (tx, mut rx) = mpsc::channel(10);

    manager.set_incoming(tx).await;

    // Forward a message
    let peer_id = PeerId::new("fwd_test".into());
    let msg = NetworkMessage::Ping { nonce: 42 };
    manager.forward_incoming(peer_id.clone(), msg).await;

    // Should receive it
    let (recv_id, recv_msg) = rx.recv().await.expect("should receive forwarded message");
    assert_eq!(recv_id, peer_id);
    match recv_msg {
        NetworkMessage::Ping { nonce } => assert_eq!(nonce, 42),
        other => panic!("Expected Ping, got {:?}", other),
    }
}

#[tokio::test]
async fn test_peer_manager_forward_incoming_no_sink() {
    // When no incoming sink is set, forward should silently drop
    let manager = PeerManager::new(PeerManagerConfig::default());
    let peer_id = PeerId::new("no_sink".into());
    let msg = NetworkMessage::Ping { nonce: 1 };
    // Should not panic
    manager.forward_incoming(peer_id, msg).await;
}

// ---------------------------------------------------------------------------
// PeerManager connect_to_peer — banned peer check
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_connect_to_banned_peer_fails() {
    let config = PeerManagerConfig {
        ban_duration: Duration::from_secs(3600),
        ..Default::default()
    };
    let manager = PeerManager::new(config);

    let addr: SocketAddr = "10.0.0.5:30303".parse().unwrap();
    manager.ban_peer(addr).await;

    let result = manager
        .connect_to_peer(PeerId::new("banned_peer".into()), addr)
        .await;
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("banned"));
}

// ---------------------------------------------------------------------------
// PeerManager connect_to_peer — already connected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_connect_to_already_connected_peer() {
    let manager = PeerManager::new(PeerManagerConfig::default());

    let peer_id = PeerId::new("already_connected".into());
    let addr: SocketAddr = "127.0.0.1:9500".parse().unwrap();

    // First connect succeeds
    let (tx, rx) = mpsc::channel(10);
    let peer = Arc::new(Peer::new(
        PeerInfo::new(peer_id.clone(), addr, Direction::Outbound),
        tx,
        rx,
    ));
    manager.add_peer(peer).await.unwrap();

    // Second connect returns Ok (already connected)
    let result = manager.connect_to_peer(peer_id, addr).await;
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// PeerManager max inbound/outbound limits
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_peer_manager_max_inbound_limit() {
    let config = PeerManagerConfig {
        max_peers: 10,
        max_inbound: 1,
        max_outbound: 9,
        ..Default::default()
    };
    let manager = PeerManager::new(config);

    // First inbound succeeds
    let (tx1, rx1) = mpsc::channel(10);
    let p1 = Arc::new(Peer::new(
        PeerInfo::new(PeerId::new("in_1".into()), "127.0.0.1:9600".parse().unwrap(), Direction::Inbound),
        tx1,
        rx1,
    ));
    assert!(manager.add_peer(p1).await.is_ok());

    // Second inbound fails
    let (tx2, rx2) = mpsc::channel(10);
    let p2 = Arc::new(Peer::new(
        PeerInfo::new(PeerId::new("in_2".into()), "127.0.0.1:9601".parse().unwrap(), Direction::Inbound),
        tx2,
        rx2,
    ));
    let result = manager.add_peer(p2).await;
    assert!(result.is_err());
    assert!(format!("{}", result.unwrap_err()).contains("Max inbound"));
}

#[tokio::test]
async fn test_peer_manager_max_outbound_limit() {
    let config = PeerManagerConfig {
        max_peers: 10,
        max_inbound: 9,
        max_outbound: 1,
        ..Default::default()
    };
    let manager = PeerManager::new(config);

    // First outbound succeeds
    let (tx1, rx1) = mpsc::channel(10);
    let p1 = Arc::new(Peer::new(
        PeerInfo::new(PeerId::new("out_1".into()), "127.0.0.1:9700".parse().unwrap(), Direction::Outbound),
        tx1,
        rx1,
    ));
    assert!(manager.add_peer(p1).await.is_ok());

    // Second outbound fails
    let (tx2, rx2) = mpsc::channel(10);
    let p2 = Arc::new(Peer::new(
        PeerInfo::new(PeerId::new("out_2".into()), "127.0.0.1:9701".parse().unwrap(), Direction::Outbound),
        tx2,
        rx2,
    ));
    let result = manager.add_peer(p2).await;
    assert!(result.is_err());
    assert!(format!("{}", result.unwrap_err()).contains("Max outbound"));
}

// ---------------------------------------------------------------------------
// PeerManager broadcast
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_peer_manager_broadcast_empty() {
    let manager = PeerManager::new(PeerManagerConfig::default());
    let msg = NetworkMessage::Ping { nonce: 99 };
    // Broadcast to zero peers should succeed
    let result = manager.broadcast(&msg).await;
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// PeerManager update_peer_score
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_update_peer_score_positive() {
    let manager = PeerManager::new(PeerManagerConfig::default());

    let peer_id = PeerId::new("score_test".into());
    let (tx, rx) = mpsc::channel(10);
    let peer = Arc::new(Peer::new(
        PeerInfo::new(peer_id.clone(), "127.0.0.1:9800".parse().unwrap(), Direction::Inbound),
        tx,
        rx,
    ));
    manager.add_peer(peer.clone()).await.unwrap();

    manager.update_peer_score(&peer_id, 10).await;

    let p = manager.get_peer(&peer_id).unwrap();
    let info = p.info.read().await;
    assert_eq!(info.score, 10);
}

#[tokio::test]
async fn test_update_peer_score_nonexistent() {
    let manager = PeerManager::new(PeerManagerConfig::default());
    // Should not panic
    manager.update_peer_score(&PeerId::new("ghost".into()), -5).await;
}

// ---------------------------------------------------------------------------
// NetworkError variants
// ---------------------------------------------------------------------------

#[test]
fn test_network_error_display() {
    let err = citrate_network::types::NetworkError::ConnectionFailed("timeout".into());
    assert!(format!("{}", err).contains("timeout"));

    let err2 = citrate_network::types::NetworkError::Shutdown;
    assert!(format!("{}", err2).contains("shutting down"));

    let err3 = citrate_network::types::NetworkError::DecodeError("bad data".into());
    assert!(format!("{}", err3).contains("bad data"));

    let err4 = citrate_network::types::NetworkError::PeerNotFound("missing".into());
    assert!(format!("{}", err4).contains("missing"));

    let err5 = citrate_network::types::NetworkError::Timeout("rpc".into());
    assert!(format!("{}", err5).contains("rpc"));

    let err6 = citrate_network::types::NetworkError::InvalidMessage("corrupt".into());
    assert!(format!("{}", err6).contains("corrupt"));

    let err7 = citrate_network::types::NetworkError::TransportError("tls".into());
    assert!(format!("{}", err7).contains("tls"));
}

// ---------------------------------------------------------------------------
// PeerState equality
// ---------------------------------------------------------------------------

#[test]
fn test_peer_state_equality() {
    use citrate_network::peer::PeerState;
    assert_eq!(PeerState::Connecting, PeerState::Connecting);
    assert_ne!(PeerState::Connecting, PeerState::Connected);
    assert_eq!(PeerState::Disconnected, PeerState::Disconnected);
}

// ---------------------------------------------------------------------------
// Direction equality
// ---------------------------------------------------------------------------

#[test]
fn test_direction_equality() {
    assert_eq!(Direction::Inbound, Direction::Inbound);
    assert_eq!(Direction::Outbound, Direction::Outbound);
    assert_ne!(Direction::Inbound, Direction::Outbound);
}
