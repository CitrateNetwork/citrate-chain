// Stress tests for the Citrate network layer.
//
// These tests verify that core network components remain stable under high
// concurrency, rapid state changes, and sustained load.

use citrate_network::{
    peer::{Direction, Peer, PeerId, PeerInfo, PeerManager, PeerManagerConfig},
    NetworkMessage,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_peer_simple(
    id: PeerId,
    addr: SocketAddr,
    direction: Direction,
) -> Arc<Peer> {
    let (send_tx, recv_rx) = mpsc::channel(100);
    let info = PeerInfo::new(id, addr, direction);
    Arc::new(Peer::new(info, send_tx, recv_rx))
}

fn unique_addr(index: u16) -> SocketAddr {
    format!("127.0.0.1:{}", 40_000 + index).parse().unwrap()
}

// ===========================================================================
// 6. Stress Tests
// ===========================================================================

#[tokio::test]
async fn test_rapid_peer_connect_disconnect_100_cycles() {
    let config = PeerManagerConfig {
        max_peers: 5,
        max_inbound: 5,
        max_outbound: 5,
        ..Default::default()
    };
    let pm = PeerManager::new(config);

    for cycle in 0..100u16 {
        let peer_id = PeerId::new(format!("cycle_peer_{}", cycle));
        let addr = unique_addr(cycle);
        let peer = make_peer_simple(peer_id.clone(), addr, Direction::Outbound);

        let add_result = pm.add_peer(peer).await;
        assert!(add_result.is_ok(), "Cycle {}: add_peer should succeed", cycle);

        pm.remove_peer(&peer_id).await;

        let (total, _, _) = pm.get_peer_counts().await;
        assert_eq!(total, 0, "Cycle {}: peer count should be 0 after removal", cycle);
    }

    // Final sanity check
    let peers = pm.get_all_peers();
    assert!(peers.is_empty(), "No peers should remain after 100 connect/disconnect cycles");
}

#[tokio::test]
async fn test_concurrent_message_handling() {
    let config = PeerManagerConfig::default();
    let pm = Arc::new(PeerManager::new(config));

    // Add 10 peers
    let mut peer_ids = Vec::new();
    for i in 0..10u16 {
        let peer_id = PeerId::new(format!("msg_peer_{}", i));
        let addr = unique_addr(200 + i);
        let peer = make_peer_simple(peer_id.clone(), addr, Direction::Outbound);
        pm.add_peer(peer).await.unwrap();
        peer_ids.push(peer_id);
    }

    // Spawn 100 concurrent tasks each sending a message to a random peer
    let mut handles = Vec::new();
    for i in 0..100u32 {
        let pm_clone = pm.clone();
        let peer_id = peer_ids[i as usize % peer_ids.len()].clone();
        let handle = tokio::spawn(async move {
            let msg = NetworkMessage::Ping { nonce: i as u64 };
            if let Some(peer) = pm_clone.get_peer(&peer_id) {
                // Send may fail if channel is full, but should not panic
                let _ = peer.send(msg).await;
            }
        });
        handles.push(handle);
    }

    // All tasks should complete without panic
    for handle in handles {
        handle.await.expect("Task should not panic");
    }

    // Peers should still be connected
    let (total, _, _) = pm.get_peer_counts().await;
    assert_eq!(total, 10, "All 10 peers should still be connected");
}

#[tokio::test]
async fn test_peer_manager_under_load() {
    let config = PeerManagerConfig {
        max_peers: 50,
        max_inbound: 30,
        max_outbound: 20,
        ..Default::default()
    };
    let pm = Arc::new(PeerManager::new(config));

    // Spawn multiple tasks that add and remove peers rapidly
    let mut handles = Vec::new();

    // 10 adder tasks, each adding 5 peers
    for task_id in 0..10u16 {
        let pm_clone = pm.clone();
        let handle = tokio::spawn(async move {
            let mut added_ids = Vec::new();
            for i in 0..5u16 {
                let idx = task_id * 100 + i;
                let peer_id = PeerId::new(format!("load_peer_{}", idx));
                let addr = unique_addr(300 + idx);
                let peer = make_peer_simple(peer_id.clone(), addr, Direction::Outbound);
                if pm_clone.add_peer(peer).await.is_ok() {
                    added_ids.push(peer_id);
                }
            }
            added_ids
        });
        handles.push(handle);
    }

    // Collect all added peer IDs
    let mut all_added: Vec<PeerId> = Vec::new();
    for handle in handles {
        let ids = handle.await.expect("Adder task should not panic");
        all_added.extend(ids);
    }

    let (total_after_add, _, _) = pm.get_peer_counts().await;
    assert!(total_after_add > 0, "Should have added some peers");
    assert!(total_after_add <= 50, "Should not exceed max_peers");

    // Now spawn remover tasks
    let mut remove_handles = Vec::new();
    for peer_id in all_added.clone() {
        let pm_clone = pm.clone();
        let handle = tokio::spawn(async move {
            pm_clone.remove_peer(&peer_id).await;
        });
        remove_handles.push(handle);
    }

    for handle in remove_handles {
        handle.await.expect("Remover task should not panic");
    }

    let (total_after_remove, inbound, outbound) = pm.get_peer_counts().await;
    assert_eq!(total_after_remove, 0, "All peers should be removed");
    assert_eq!(inbound, 0);
    assert_eq!(outbound, 0);
}
