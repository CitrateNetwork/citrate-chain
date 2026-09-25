// PBA-L1b-004 (HIGH) regression — from the audit PoC
// `lanes/L1b-chain-consensus-p2p/evidence/pba_l1b_poc.rs::poc_004_*`.
//
// Any peer could send `ModelAnnounce`; each fresh model id became a permanent
// RocksDB record (with an attacker-sized description) via
// `StateManager::register_model`, with no size cap, no quota and no expiry.
// One connection at the 200 msg/s cap grew the DB by ~222 MiB per second, and
// the growth survived restarts: disk exhaustion halts the node.
//
// Fix: peer announcements are advisory. They live only in a bounded,
// expiring in-memory cache (global cap + per-peer quota + metadata size cap),
// never in persistent state. The same rule is applied to the sibling
// unauthenticated P2P writes (TrainingJobAnnounce, GradientSubmission,
// WeightSync, InferenceResponse).

use citrate_consensus::types::Hash;
use citrate_network::ai_handler::AINetworkHandler;
use citrate_network::protocol::{ModelMetadata, NetworkMessage};
use citrate_network::{PeerId, PeerManager, PeerManagerConfig};
use citrate_storage::db::RocksDB;
use citrate_storage::state_manager::StateManager;
use std::sync::Arc;

fn dir_size(p: &std::path::Path) -> u64 {
    std::fs::read_dir(p)
        .unwrap()
        .flatten()
        .map(|e| {
            let m = e.metadata().unwrap();
            if m.is_dir() {
                dir_size(&e.path())
            } else {
                m.len()
            }
        })
        .sum()
}

fn announce(i: u32, description: String) -> NetworkMessage {
    let mut id = [0u8; 32];
    id[..4].copy_from_slice(&i.to_le_bytes());
    NetworkMessage::ModelAnnounce {
        model_id: Hash::new(id),
        model_hash: Hash::new([1; 32]),
        owner: vec![0xAB; 20],
        metadata: ModelMetadata {
            name: format!("m{i}"),
            version: "1".into(),
            description,
            framework: "x".into(),
            input_shape: vec![],
            output_shape: vec![],
            size_bytes: 0,
            created_at: 0,
        },
        weight_cid: "bafy".into(),
    }
}

fn model_id(i: u32) -> Hash {
    let mut id = [0u8; 32];
    id[..4].copy_from_slice(&i.to_le_bytes());
    Hash::new(id)
}

#[tokio::test]
async fn pba_l1b_004_model_announce_flood_does_not_grow_persistent_state() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(RocksDB::open(dir.path()).unwrap());
    let sm = Arc::new(StateManager::new(db.clone()));
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    let h = AINetworkHandler::new(sm.clone(), pm);
    let attacker = PeerId("attacker".into());
    let before = dir_size(dir.path());

    // Incompressible-ish descriptions, as in the PoC (scaled down: 64 x 256 KiB).
    const N: u32 = 64;
    let blob: String = (0..256 * 1024u32)
        .map(|i| {
            let x = i.wrapping_mul(2654435761).rotate_left(7) ^ (i >> 3);
            (b'a' + (x % 26) as u8) as char
        })
        .collect();
    for i in 0..N {
        let _ = h.handle_message(&attacker, &announce(i, blob.clone())).await;
    }
    db.flush().ok();
    let persisted = (0..N)
        .filter(|i| sm.get_model(&citrate_execution::ModelId(model_id(*i))).is_some())
        .count();
    let grown = dir_size(dir.path()).saturating_sub(before);
    assert_eq!(persisted, 0, "PBA-L1b-004: peer announcements must never reach persistent state");
    assert!(
        grown < 1024 * 1024,
        "PBA-L1b-004: persistent growth from one peer's flood must stay bounded, grew {grown} bytes"
    );
}
