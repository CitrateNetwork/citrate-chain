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
use citrate_network::ai_handler::{
    AINetworkHandler, MAX_ANNOUNCE_METADATA_BYTES, MAX_CACHED_MODELS, MAX_MODELS_PER_PEER,
};
use citrate_network::protocol::{ModelMetadata, NetworkMessage};
use citrate_network::{PeerId, PeerManager, PeerManagerConfig};
use citrate_storage::db::RocksDB;
use citrate_storage::state_manager::StateManager;
use std::sync::Arc;

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
async fn pba_l1b_004_cache_is_bounded_per_peer_and_globally() {
    let dir = tempfile::tempdir().unwrap();
    let sm = Arc::new(StateManager::new(Arc::new(RocksDB::open(dir.path()).unwrap())));
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    let h = AINetworkHandler::new(sm, pm);

    // Per-peer quota.
    let attacker = PeerId("attacker".into());
    for i in 0..(MAX_MODELS_PER_PEER as u32 * 3) {
        h.handle_message(&attacker, &announce(i, "d".into())).await.unwrap();
    }
    assert_eq!(h.cached_model_count().await, MAX_MODELS_PER_PEER);

    // Oversized metadata is refused outright.
    let big = "x".repeat(MAX_ANNOUNCE_METADATA_BYTES + 1);
    h.handle_message(&PeerId("other".into()), &announce(1_000_000, big))
        .await
        .unwrap();
    assert!(!h.has_cached_model(&model_id(1_000_000)).await);

    // Global cap across many peers.
    for p in 0..(MAX_CACHED_MODELS / MAX_MODELS_PER_PEER + 4) {
        let peer = PeerId(format!("peer-{p}"));
        for j in 0..MAX_MODELS_PER_PEER as u32 {
            let i = 2_000_000 + (p as u32) * 1_000 + j;
            h.handle_message(&peer, &announce(i, "d".into())).await.unwrap();
        }
    }
    assert!(h.cached_model_count().await <= MAX_CACHED_MODELS);
}

/// Sibling unauthenticated writes (variant sweep): a flood of
/// TrainingJobAnnounce must not reach persistent state either.
#[tokio::test]
async fn pba_l1b_004_training_announce_flood_not_persisted() {
    let dir = tempfile::tempdir().unwrap();
    let sm = Arc::new(StateManager::new(Arc::new(RocksDB::open(dir.path()).unwrap())));
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    let h = AINetworkHandler::new(sm.clone(), pm);
    for i in 0..500u32 {
        let msg = NetworkMessage::TrainingJobAnnounce {
            job_id: model_id(i),
            model_id: model_id(i),
            dataset_hash: Hash::new([2; 32]),
            participants_needed: 1,
            reward_per_gradient: 1,
            owner: [0xAB; 20],
        };
        h.handle_message(&PeerId("attacker".into()), &msg).await.unwrap();
    }
    assert!(sm.get_training_job(&citrate_execution::JobId(model_id(0))).is_none());
    assert!(h.active_training_count().await <= citrate_network::ai_handler::MAX_TRAINING_JOBS);
}

/// Tripwire (class-level): no P2P AI handler writes persistent state. Every
/// message here is an unauthenticated peer claim.
#[test]
fn pba_l1b_004_tripwire_ai_handler_never_persists_peer_claims() {
    let src = include_str!("../src/ai_handler.rs");
    let prod = &src[..src.find("#[cfg(test)]").expect("test module")];
    for write in [
        "state_manager.register_model(",
        "state_manager.add_training_job(",
        "state_manager.update_model_weights(",
        "state_manager.cache_inference_result(",
        "state_manager\n                .register_model(",
        ".add_lora_adapter(",
    ] {
        assert!(
            !prod.contains(write),
            "PBA-L1b-004: ai_handler must not persist peer claims ({write})"
        );
    }
}
