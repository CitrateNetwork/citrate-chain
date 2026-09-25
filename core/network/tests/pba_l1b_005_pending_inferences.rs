// PBA-L1b-005 (MEDIUM) regression, handler half.
//
// A P2P `InferenceRequest` stored a pending entry per request id with no cap
// and no expiry, so any peer could grow `pending_inferences` without bound.
// (The other half — inference no longer runs on the node's single inbound
// message loop — is `node/src/network_inference.rs::InferenceDispatcher`.)

use citrate_consensus::types::Hash;
use citrate_network::ai_handler::AINetworkHandler;
use citrate_network::protocol::NetworkMessage;
use citrate_network::{PeerId, PeerManager, PeerManagerConfig};
use citrate_storage::db::RocksDB;
use citrate_storage::state_manager::StateManager;
use std::sync::Arc;

fn req(i: u32) -> NetworkMessage {
    let mut id = [0u8; 32];
    id[..4].copy_from_slice(&i.to_le_bytes());
    NetworkMessage::InferenceRequest {
        request_id: Hash::new(id),
        model_id: Hash::new([9; 32]),
        input_hash: Hash::new([1; 32]),
        requester: vec![0xAB; 20],
        max_fee: 0,
    }
}

#[tokio::test]
async fn pba_l1b_005_pending_inferences_are_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let sm = Arc::new(StateManager::new(Arc::new(RocksDB::open(dir.path()).unwrap())));
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    let h = AINetworkHandler::new(sm, pm);
    for i in 0..5_000u32 {
        h.handle_message(&PeerId(format!("p{}", i % 50)), &req(i)).await.unwrap();
    }
    let n = h.pending_inference_count().await;
    assert!(
        n <= 256,
        "PBA-L1b-005: pending inference requests must be capped, have {n}"
    );
    // One peer cannot take the whole table.
    let dir2 = tempfile::tempdir().unwrap();
    let h2 = AINetworkHandler::new(
        Arc::new(StateManager::new(Arc::new(RocksDB::open(dir2.path()).unwrap()))),
        Arc::new(PeerManager::new(PeerManagerConfig::default())),
    );
    for i in 0..1_000u32 {
        h2.handle_message(&PeerId("one".into()), &req(i)).await.unwrap();
    }
    assert!(h2.pending_inference_count().await <= 16);
}
