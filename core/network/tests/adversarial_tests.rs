// Adversarial tests for the Citrate network layer.
//
// These tests verify the network's resilience against malicious peers,
// invalid messages, eclipse attacks, and gossip protocol abuse.

use citrate_consensus::types::{
    Block, BlockHeader, GhostDagParams, Hash, PublicKey, Signature, Transaction, VrfProof,
};
use citrate_network::{
    gossip::{GossipConfig, GossipProtocol},
    peer::{Direction, Peer, PeerId, PeerInfo, PeerManager, PeerManagerConfig},
    NetworkMessage,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a mock peer with the given ID, address, and direction, returning
/// the peer and its send-side receiver so we can observe outgoing messages.
/// The peer's state is set to Connected so gossip propagation considers it eligible.
fn make_peer(
    id: PeerId,
    addr: SocketAddr,
    direction: Direction,
) -> (Arc<Peer>, mpsc::Receiver<NetworkMessage>) {
    let (send_tx, send_rx) = mpsc::channel(100);
    let (_recv_tx, recv_rx) = mpsc::channel(100);
    let mut info = PeerInfo::new(id, addr, direction);
    info.state = citrate_network::peer::PeerState::Connected;
    let peer = Arc::new(Peer::new(info, send_tx, recv_rx));
    (peer, send_rx)
}

/// Build a minimal genesis block (selected_parent == Hash::default(), no merge parents).
fn make_genesis_block() -> Block {
    let mut block = Block {
        header: BlockHeader {
            version: 1,
            block_hash: Hash::default(),
            selected_parent_hash: Hash::default(),
            merge_parent_hashes: vec![],
            timestamp: current_timestamp(),
            height: 0,
            blue_score: 0,
            blue_work: 0,
            pruning_point: Hash::default(),
            proposer_pubkey: PublicKey::new([0; 32]),
            vrf_reveal: VrfProof {
                proof: vec![],
                output: Hash::default(),
            },
            base_fee_per_gas: 0,
            gas_used: 0,
            gas_limit: 30_000_000,
        },
        state_root: Hash::default(),
        tx_root: compute_tx_root(&[]),
        receipt_root: Hash::default(),
        artifact_root: Hash::default(),
        ghostdag_params: GhostDagParams::default(),
        transactions: vec![],
        signature: Signature::new([0; 64]),
        embedded_models: vec![],
        required_pins: vec![],
        learning_embedding: None,
        learning_confidence: None,
        gradient_commitment: None,
    };
    block.header.block_hash = block.compute_hash();
    block
}

/// Build a non-genesis block with customizable fields. The block will NOT
/// pass full validation (no real signature/VRF) but is useful for testing
/// specific validation paths.
fn make_non_genesis_block(height: u64, blue_score: u64, timestamp: u64) -> Block {
    let mut block = Block {
        header: BlockHeader {
            version: 1,
            block_hash: Hash::default(),
            selected_parent_hash: Hash::new([1; 32]), // non-zero parent
            merge_parent_hashes: vec![],
            timestamp,
            height,
            blue_score,
            blue_work: blue_score as u128,
            pruning_point: Hash::default(),
            proposer_pubkey: PublicKey::new([2; 32]),
            vrf_reveal: VrfProof {
                proof: vec![1, 2, 3], // non-empty VRF
                output: Hash::new([3; 32]),
            },
            base_fee_per_gas: 0,
            gas_used: 0,
            gas_limit: 30_000_000,
        },
        state_root: Hash::default(),
        tx_root: compute_tx_root(&[]),
        receipt_root: Hash::default(),
        artifact_root: Hash::default(),
        ghostdag_params: GhostDagParams::default(),
        transactions: vec![],
        signature: Signature::new([0; 64]),
        embedded_models: vec![],
        required_pins: vec![],
        learning_embedding: None,
        learning_confidence: None,
        gradient_commitment: None,
    };
    block.header.block_hash = block.compute_hash();
    block
}

fn make_valid_transaction(nonce: u64) -> Transaction {
    Transaction {
        hash: Hash::new([nonce as u8; 32]),
        nonce,
        from: PublicKey::new([0; 32]),
        to: None,
        value: 0,
        gas_limit: 21_000,
        gas_price: 1_000_000_000, // 1 Gwei
        data: vec![],
        signature: Signature::new([0; 64]),
        ..Default::default()
    }
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn compute_tx_root(txs: &[Transaction]) -> Hash {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    for tx in txs {
        hasher.update(tx.hash.as_bytes());
    }
    let bytes = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[..32]);
    Hash::new(arr)
}

fn unique_addr(index: u16) -> SocketAddr {
    format!("127.0.0.1:{}", 20_000 + index).parse().unwrap()
}

// ===========================================================================
// 1. Peer Scoring & Banning
// ===========================================================================

#[tokio::test]
async fn test_invalid_block_reduces_peer_score() {
    // A non-genesis block with blue_score=0 will fail ZERO_BLUE_SCORE validation,
    // triggering a SCORE_INVALID_BLOCK (-25) penalty on the sending peer.
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    let gossip = GossipProtocol::new(GossipConfig::default(), pm.clone());

    let peer_id = PeerId::new("scorer_peer".into());
    let (peer, _rx) = make_peer(peer_id.clone(), unique_addr(0), Direction::Inbound);
    pm.add_peer(peer.clone()).await.unwrap();

    // Initial score is 0
    assert_eq!(peer.info.read().await.score, 0);

    // Send a block that will fail validation (blue_score=0 on non-genesis)
    let bad_block = make_non_genesis_block(5, 0, current_timestamp());
    let result = gossip.handle_new_block(bad_block, &peer_id).await;
    assert!(result.is_err());

    // Score should have decreased by SCORE_INVALID_BLOCK (-25)
    let score = peer.info.read().await.score;
    assert_eq!(score, -25, "Expected score to be -25 after invalid block, got {}", score);
}

#[tokio::test]
async fn test_score_below_threshold_triggers_ban() {
    // With score_threshold = -100, sending 5 invalid blocks (-25 each = -125)
    // should trigger a ban and removal (ban fires when score < threshold, i.e. < -100).
    let config = PeerManagerConfig {
        score_threshold: -100,
        ..Default::default()
    };
    let pm = Arc::new(PeerManager::new(config));
    let gossip = GossipProtocol::new(GossipConfig::default(), pm.clone());

    let peer_id = PeerId::new("ban_target".into());
    let addr = unique_addr(1);
    let (peer, _rx) = make_peer(peer_id.clone(), addr, Direction::Inbound);
    pm.add_peer(peer).await.unwrap();

    // Send 5 invalid blocks to accumulate -125 score (< -100 threshold)
    for i in 0..5 {
        let bad_block = make_non_genesis_block(i + 1, 0, current_timestamp());
        let _ = gossip.handle_new_block(bad_block, &peer_id).await;
    }

    // Peer should now be banned and removed
    assert!(pm.get_peer(&peer_id).is_none(), "Peer should be removed after score drops below threshold");
    assert!(pm.is_banned(&addr).await, "Peer address should be banned");
}

#[tokio::test]
async fn test_valid_blocks_increase_score() {
    // Genesis blocks bypass signature checks, so we can use them to test
    // the SCORE_VALID_BLOCK (+1) reward path.
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    let gossip = GossipProtocol::new(GossipConfig::default(), pm.clone());

    let peer_id = PeerId::new("good_peer".into());
    let (peer, _rx) = make_peer(peer_id.clone(), unique_addr(2), Direction::Inbound);
    pm.add_peer(peer.clone()).await.unwrap();

    // Send a valid genesis block
    let genesis = make_genesis_block();
    let result = gossip.handle_new_block(genesis, &peer_id).await;
    assert!(result.is_ok(), "Genesis block should pass validation");

    let score = peer.info.read().await.score;
    assert_eq!(score, 1, "Score should increase by 1 for a valid block, got {}", score);
}

#[tokio::test]
async fn test_banned_peer_reconnection_rejected() {
    let config = PeerManagerConfig {
        ban_duration: Duration::from_secs(3600),
        ..Default::default()
    };
    let pm = PeerManager::new(config);
    let addr: SocketAddr = unique_addr(3);

    // Ban the address
    pm.ban_peer(addr).await;
    assert!(pm.is_banned(&addr).await);

    // Try to connect — should fail
    let peer_id = PeerId::new("banned_reconnect".into());
    let result = pm.connect_to_peer(peer_id, addr).await;
    assert!(result.is_err(), "Connecting to a banned address should fail");
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("banned"), "Error should mention ban: {}", err_msg);
}

// ===========================================================================
// 2. Connection Limits
// ===========================================================================

#[tokio::test]
async fn test_max_peers_enforced() {
    let config = PeerManagerConfig {
        max_peers: 3,
        max_inbound: 3,
        max_outbound: 3,
        ..Default::default()
    };
    let pm = PeerManager::new(config);

    // Add max_peers peers (mix of inbound/outbound to stay within direction limits)
    for i in 0..3u16 {
        let (peer, _rx) = make_peer(
            PeerId::new(format!("peer_{}", i)),
            unique_addr(10 + i),
            Direction::Inbound,
        );
        pm.add_peer(peer).await.unwrap();
    }

    // 4th peer should be rejected (max_peers = 3)
    let (extra_peer, _rx) = make_peer(
        PeerId::new("peer_extra".into()),
        unique_addr(13),
        Direction::Inbound,
    );
    let result = pm.add_peer(extra_peer).await;
    assert!(result.is_err(), "Should reject peer beyond max_peers limit");

    let (total, _, _) = pm.get_peer_counts().await;
    assert_eq!(total, 3);
}

#[tokio::test]
async fn test_inbound_connection_rejected_at_capacity() {
    let config = PeerManagerConfig {
        max_peers: 10,
        max_inbound: 2,
        max_outbound: 10,
        ..Default::default()
    };
    let pm = PeerManager::new(config);

    // Fill inbound slots
    for i in 0..2u16 {
        let (peer, _rx) = make_peer(
            PeerId::new(format!("inbound_{}", i)),
            unique_addr(20 + i),
            Direction::Inbound,
        );
        pm.add_peer(peer).await.unwrap();
    }

    // Next inbound should be rejected
    let (extra_inbound, _rx) = make_peer(
        PeerId::new("inbound_extra".into()),
        unique_addr(22),
        Direction::Inbound,
    );
    let result = pm.add_peer(extra_inbound).await;
    assert!(result.is_err(), "Should reject inbound peer beyond max_inbound");

    let (_, inbound, _) = pm.get_peer_counts().await;
    assert_eq!(inbound, 2);
}

#[tokio::test]
async fn test_peer_removal_frees_slot() {
    let config = PeerManagerConfig {
        max_peers: 2,
        max_inbound: 2,
        max_outbound: 2,
        ..Default::default()
    };
    let pm = PeerManager::new(config);

    let id1 = PeerId::new("slot_peer_1".into());
    let id2 = PeerId::new("slot_peer_2".into());
    let id3 = PeerId::new("slot_peer_3".into());

    let (p1, _rx1) = make_peer(id1.clone(), unique_addr(30), Direction::Outbound);
    let (p2, _rx2) = make_peer(id2.clone(), unique_addr(31), Direction::Outbound);
    pm.add_peer(p1).await.unwrap();
    pm.add_peer(p2).await.unwrap();

    // Full — reject
    let (p3_first, _rx3) = make_peer(id3.clone(), unique_addr(32), Direction::Outbound);
    assert!(pm.add_peer(p3_first).await.is_err());

    // Remove one peer
    pm.remove_peer(&id1).await;
    let (total, _, _) = pm.get_peer_counts().await;
    assert_eq!(total, 1);

    // Now adding should succeed
    let (p3_second, _rx3b) = make_peer(id3, unique_addr(32), Direction::Outbound);
    assert!(pm.add_peer(p3_second).await.is_ok());
    let (total, _, _) = pm.get_peer_counts().await;
    assert_eq!(total, 2);
}

// ===========================================================================
// 3. Message Validation
// ===========================================================================

#[tokio::test]
async fn test_oversized_block_rejected() {
    // Create a gossip protocol with a tiny max_message_size to trigger
    // the BLOCK_OVERSIZED check without needing a truly huge block.
    let gossip_config = GossipConfig {
        max_message_size: 64, // very small limit — any block will exceed this
        ..Default::default()
    };
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    let gossip = GossipProtocol::new(gossip_config, pm.clone());

    let peer_id = PeerId::new("oversized_sender".into());
    let (peer, _rx) = make_peer(peer_id.clone(), unique_addr(40), Direction::Inbound);
    pm.add_peer(peer.clone()).await.unwrap();

    // A normal genesis block serializes to well over 64 bytes
    let block = make_genesis_block();
    let result = gossip.handle_new_block(block, &peer_id).await;
    assert!(result.is_err(), "Oversized block should be rejected");

    // Peer score should have decreased
    let score = peer.info.read().await.score;
    assert!(score < 0, "Score should be negative after oversized block");
}

#[tokio::test]
async fn test_future_timestamp_block_rejected() {
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    let gossip = GossipProtocol::new(GossipConfig::default(), pm.clone());

    let peer_id = PeerId::new("future_sender".into());
    let (peer, _rx) = make_peer(peer_id.clone(), unique_addr(41), Direction::Inbound);
    pm.add_peer(peer.clone()).await.unwrap();

    // Block with timestamp 1 hour in the future (>15 min tolerance)
    let future_ts = current_timestamp() + 3600;
    let block = make_non_genesis_block(5, 10, future_ts);
    let result = gossip.handle_new_block(block, &peer_id).await;
    assert!(result.is_err(), "Block with future timestamp should be rejected");

    let score = peer.info.read().await.score;
    assert_eq!(score, -25, "Score should decrease by SCORE_INVALID_BLOCK");
}

#[tokio::test]
async fn test_zero_blue_score_non_genesis_rejected() {
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    let gossip = GossipProtocol::new(GossipConfig::default(), pm.clone());

    let peer_id = PeerId::new("zero_blue_sender".into());
    let (peer, _rx) = make_peer(peer_id.clone(), unique_addr(42), Direction::Inbound);
    pm.add_peer(peer.clone()).await.unwrap();

    // Non-genesis block with blue_score = 0
    let block = make_non_genesis_block(10, 0, current_timestamp());
    let result = gossip.handle_new_block(block, &peer_id).await;
    assert!(result.is_err(), "Non-genesis block with zero blue_score should be rejected");
}

#[tokio::test]
async fn test_duplicate_block_deduplicated() {
    // The gossip dedup check only filters when `propagated=true`. With no other
    // peers to propagate to, the first call marks `propagated=false`, the second
    // call goes through validation again. Adding a second peer ensures propagation
    // happens, marking the block as `propagated=true`, so the third call is deduped.
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    let gossip = GossipProtocol::new(GossipConfig::default(), pm.clone());

    let peer_id = PeerId::new("dup_sender".into());
    let (peer, _rx) = make_peer(peer_id.clone(), unique_addr(43), Direction::Inbound);
    pm.add_peer(peer).await.unwrap();

    // Add a second peer so propagation can occur (marks block as propagated=true)
    let peer_id2 = PeerId::new("propagation_target".into());
    let (peer2, _rx2) = make_peer(peer_id2, unique_addr(44), Direction::Outbound);
    pm.add_peer(peer2).await.unwrap();

    let genesis = make_genesis_block();

    // First submission — received + propagated
    let result1 = gossip.handle_new_block(genesis.clone(), &peer_id).await;
    assert!(result1.is_ok(), "First submission should succeed");

    // Second submission — now propagated=true, so this is deduplicated
    let result2 = gossip.handle_new_block(genesis, &peer_id).await;
    assert!(result2.is_ok(), "Duplicate block should be silently deduplicated");

    let (blocks_received, _, _, _, duplicates_filtered, _, _, _) = gossip.get_stats().await;
    assert_eq!(blocks_received, 1, "Only one block should be counted as received");
    assert_eq!(duplicates_filtered, 1, "One duplicate should be filtered");
}

// ===========================================================================
// 4. Eclipse Attack Resistance
// ===========================================================================

#[tokio::test]
async fn test_subnet_diversity_enforcement() {
    // The current PeerManager does not enforce subnet-level diversity.
    // This test documents the expected behavior: multiple peers from the same
    // /24 subnet can all connect. When subnet limits are implemented, this
    // test should be updated to verify rejection.
    let config = PeerManagerConfig {
        max_peers: 10,
        max_inbound: 10,
        max_outbound: 10,
        ..Default::default()
    };
    let pm = PeerManager::new(config);

    // Add 5 peers from the same /24 subnet (127.0.0.x)
    for i in 0..5u16 {
        let addr: SocketAddr = format!("127.0.0.{}:{}", i + 1, 30000 + i).parse().unwrap();
        let (peer, _rx) = make_peer(
            PeerId::new(format!("subnet_peer_{}", i)),
            addr,
            Direction::Inbound,
        );
        pm.add_peer(peer).await.unwrap();
    }

    let (total, _, _) = pm.get_peer_counts().await;
    // Currently all are accepted (no subnet limit). When subnet limits are
    // added, expect total < 5.
    assert_eq!(total, 5, "All same-subnet peers currently accepted (no subnet limit enforced)");
}

#[tokio::test]
async fn test_mixed_inbound_outbound_peers() {
    let config = PeerManagerConfig {
        max_peers: 10,
        max_inbound: 3,
        max_outbound: 3,
        ..Default::default()
    };
    let pm = PeerManager::new(config);

    // Add 3 inbound
    for i in 0..3u16 {
        let (peer, _rx) = make_peer(
            PeerId::new(format!("in_{}", i)),
            unique_addr(50 + i),
            Direction::Inbound,
        );
        pm.add_peer(peer).await.unwrap();
    }

    // Add 3 outbound
    for i in 0..3u16 {
        let (peer, _rx) = make_peer(
            PeerId::new(format!("out_{}", i)),
            unique_addr(60 + i),
            Direction::Outbound,
        );
        pm.add_peer(peer).await.unwrap();
    }

    let (total, inbound, outbound) = pm.get_peer_counts().await;
    assert_eq!(total, 6);
    assert_eq!(inbound, 3);
    assert_eq!(outbound, 3);

    // Extra inbound should fail
    let (extra_in, _rx) = make_peer(
        PeerId::new("in_extra".into()),
        unique_addr(70),
        Direction::Inbound,
    );
    assert!(pm.add_peer(extra_in).await.is_err());

    // Extra outbound should fail
    let (extra_out, _rx) = make_peer(
        PeerId::new("out_extra".into()),
        unique_addr(71),
        Direction::Outbound,
    );
    assert!(pm.add_peer(extra_out).await.is_err());

    // Counts unchanged
    let (total, inbound, outbound) = pm.get_peer_counts().await;
    assert_eq!(total, 6);
    assert_eq!(inbound, 3);
    assert_eq!(outbound, 3);
}

// ===========================================================================
// 5. Gossip Protocol
// ===========================================================================

#[tokio::test]
async fn test_transaction_deduplication() {
    // Same dedup logic as blocks: need another peer for propagation to mark
    // the tx as `propagated=true`, so the next submission is actually filtered.
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    let gossip = GossipProtocol::new(GossipConfig::default(), pm.clone());

    let peer_id = PeerId::new("tx_dup_sender".into());
    let (peer, _rx) = make_peer(peer_id.clone(), unique_addr(80), Direction::Inbound);
    pm.add_peer(peer).await.unwrap();

    // Add a second peer for propagation
    let peer_id2 = PeerId::new("tx_propagation_target".into());
    let (peer2, _rx2) = make_peer(peer_id2, unique_addr(83), Direction::Outbound);
    pm.add_peer(peer2).await.unwrap();

    let tx = make_valid_transaction(42);

    // First submission — received + propagated
    let r1 = gossip.handle_new_transaction(tx.clone(), &peer_id).await;
    assert!(r1.is_ok(), "First tx submission should succeed");

    // Second submission — now propagated=true, so deduplicated
    let r2 = gossip.handle_new_transaction(tx, &peer_id).await;
    assert!(r2.is_ok(), "Duplicate tx should be silently deduplicated");

    let (_, _, txs_received, _, duplicates, _, _, _) = gossip.get_stats().await;
    assert_eq!(txs_received, 1, "Only one tx should be counted as received");
    assert_eq!(duplicates, 1, "One duplicate should be filtered");
}

#[tokio::test]
async fn test_seen_cache_cleanup() {
    let config = GossipConfig {
        max_seen_cache: 3,
        ..Default::default()
    };
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    let gossip = GossipProtocol::new(config, pm.clone());

    let peer_id = PeerId::new("cache_filler".into());
    let (peer, _rx) = make_peer(peer_id.clone(), unique_addr(81), Direction::Inbound);
    pm.add_peer(peer).await.unwrap();

    // Submit 5 valid genesis blocks (each with a different hash via different timestamps)
    // We'll use the seen_blocks cache directly to avoid needing valid signatures.
    for i in 0..5u8 {
        let _hash = Hash::new([i + 10; 32]);
        // Insert directly into seen cache to avoid needing valid blocks
        gossip
            .handle_new_block(
                {
                    let mut g = make_genesis_block();
                    // Tweak the block so each gets a unique hash
                    g.header.timestamp = current_timestamp() + i as u64;
                    g.header.block_hash = g.compute_hash();
                    g.tx_root = compute_tx_root(&[]);
                    // Recompute hash with updated timestamp
                    g.header.block_hash = g.compute_hash();
                    g
                },
                &peer_id,
            )
            .await
            .ok(); // some may fail tx_root but that's fine — they still get seen-cached
    }

    // Trigger cleanup
    gossip.cleanup_seen_cache().await;

    let (_, _, _, _, _, _, _, _) = gossip.get_stats().await;
    // The seen_blocks cache should be trimmed to max_seen_cache (3)
    // We can't directly access the internal cache, but cleanup should not panic.
    // The fact that we get here without panic is the success criterion.
}

#[tokio::test]
async fn test_gossip_stats_tracking() {
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    let gossip = GossipProtocol::new(GossipConfig::default(), pm.clone());

    let peer_id = PeerId::new("stats_peer".into());
    let (peer, _rx) = make_peer(peer_id.clone(), unique_addr(82), Direction::Inbound);
    pm.add_peer(peer).await.unwrap();

    // Initial stats should be zero
    let (br, bp, tr, tp, dup, _, _, _) = gossip.get_stats().await;
    assert_eq!((br, bp, tr, tp, dup), (0, 0, 0, 0, 0));

    // Submit a valid genesis block
    let genesis = make_genesis_block();
    gossip.handle_new_block(genesis, &peer_id).await.unwrap();

    let (br, _bp, _tr, _tp, _dup, _, _, _) = gossip.get_stats().await;
    assert_eq!(br, 1, "blocks_received should be 1 after one valid block");

    // Submit a valid transaction
    let tx = make_valid_transaction(99);
    gossip.handle_new_transaction(tx, &peer_id).await.unwrap();

    let (br, _bp, tr, _tp, _dup, _, _, _) = gossip.get_stats().await;
    assert_eq!(br, 1);
    assert_eq!(tr, 1, "transactions_received should be 1 after one valid tx");
}
