//! WP-F.2: LearningGossip integration tests.
//!
//! Tests deduplication, rate limiting, validation rejection, per-checkpoint
//! storage, pruning, and serialization round-trips of learning messages
//! through the gossip protocol layer.

use std::sync::Arc;

use citrate_consensus::types::{Hash, PublicKey, Signature};
use citrate_network::{
    learning_messages::{
        AdapterOffer, BelnapConfidence, LearningEmbedding, LearningMessage, PerformanceProfile,
    },
    GossipConfig, GossipProtocol, PeerId, PeerManager, PeerManagerConfig,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_gossip() -> (GossipProtocol, Arc<PeerManager>) {
    let pm = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    let gossip = GossipProtocol::new(GossipConfig::default(), pm.clone());
    (gossip, pm)
}

/// Register a dummy peer so the PeerManager recognizes the PeerId.
async fn register_peer(pm: &Arc<PeerManager>, id: &PeerId) {
    use citrate_network::peer::{Direction, Peer, PeerInfo};
    use tokio::sync::mpsc;
    let (send_tx, recv_rx) = mpsc::channel(10);
    let addr = "127.0.0.1:9999".parse().unwrap();
    let info = PeerInfo::new(id.clone(), addr, Direction::Inbound);
    let peer = Arc::new(Peer::new(info, send_tx, recv_rx));
    pm.add_peer(peer).await.unwrap();
}

fn make_valid_embedding(checkpoint: u64, participant_id: u8) -> LearningEmbedding {
    LearningEmbedding {
        checkpoint_height: checkpoint,
        participant: PublicKey::new([participant_id; 32]),
        embedding: vec![0.1, 0.2, 0.3, 0.4],
        confidence: vec![
            BelnapConfidence::True,
            BelnapConfidence::Neither,
            BelnapConfidence::False,
            BelnapConfidence::Both,
        ],
        profile: PerformanceProfile {
            accuracy: 0.95,
            latency_ms: 42,
            domains: vec!["nlp".to_string()],
            uptime: 0.99,
            adapter_count: 3,
        },
        signature: Signature::default(),
    }
}

fn make_valid_adapter_offer(checkpoint: u64, mentor_id: u8, mentee_id: u8) -> AdapterOffer {
    AdapterOffer {
        checkpoint_height: checkpoint,
        mentor: PublicKey::new([mentor_id; 32]),
        mentee: PublicKey::new([mentee_id; 32]),
        adapter_cid: "QmTestCid123456789".to_string(),
        adapter_hash: Hash::new([0xAA; 32]),
        provenance: vec![],
        signature: Signature::default(),
    }
}

// ---------------------------------------------------------------------------
// Embedding validation tests
// ---------------------------------------------------------------------------

#[test]
fn test_learning_embedding_validation_valid() {
    let emb = make_valid_embedding(100, 1);
    assert!(emb.validate().is_ok());
}

#[test]
fn test_learning_embedding_validation_empty() {
    let mut emb = make_valid_embedding(100, 1);
    emb.embedding = vec![];
    emb.confidence = vec![];
    let err = emb.validate().unwrap_err();
    assert!(err.contains("Empty embedding vector"), "got: {err}");
}

#[test]
fn test_learning_embedding_validation_dimension_mismatch() {
    let mut emb = make_valid_embedding(100, 1);
    emb.confidence.pop();
    let err = emb.validate().unwrap_err();
    assert!(err.contains("Confidence length"), "got: {err}");
}

#[test]
fn test_learning_embedding_validation_nan() {
    let mut emb = make_valid_embedding(100, 1);
    emb.embedding[2] = f32::NAN;
    let err = emb.validate().unwrap_err();
    assert!(err.contains("Non-finite value at index 2"), "got: {err}");
}

#[test]
fn test_learning_embedding_validation_accuracy_bounds() {
    let mut emb = make_valid_embedding(100, 1);
    emb.profile.accuracy = 1.5;
    assert!(emb.validate().is_err());

    emb.profile.accuracy = -0.1;
    assert!(emb.validate().is_err());

    emb.profile.accuracy = 0.0;
    assert!(emb.validate().is_ok());

    emb.profile.accuracy = 1.0;
    assert!(emb.validate().is_ok());
}

// ---------------------------------------------------------------------------
// AdapterOffer validation tests
// ---------------------------------------------------------------------------

#[test]
fn test_adapter_offer_validation_valid() {
    let offer = make_valid_adapter_offer(100, 1, 2);
    assert!(offer.validate().is_ok());
}

#[test]
fn test_adapter_offer_validation_self_mentor() {
    let mut offer = make_valid_adapter_offer(100, 1, 2);
    offer.mentee = offer.mentor;
    let err = offer.validate().unwrap_err();
    assert!(err.contains("Mentor cannot be own mentee"), "got: {err}");
}

#[test]
fn test_adapter_offer_validation_empty_cid() {
    let mut offer = make_valid_adapter_offer(100, 1, 2);
    offer.adapter_cid = String::new();
    let err = offer.validate().unwrap_err();
    assert!(err.contains("Empty adapter CID"), "got: {err}");
}

// ---------------------------------------------------------------------------
// Serialization round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_learning_message_serialization_roundtrip() {
    // Test embedding round-trip
    let emb = make_valid_embedding(100, 1);
    let msg = LearningMessage::Embedding(emb.clone());
    let bytes = bincode::serialize(&msg).expect("serialize");
    let recovered: LearningMessage = bincode::deserialize(&bytes).expect("deserialize");
    match recovered {
        LearningMessage::Embedding(e) => {
            assert_eq!(e.checkpoint_height, emb.checkpoint_height);
            assert_eq!(e.participant, emb.participant);
            assert_eq!(e.embedding, emb.embedding);
            assert_eq!(e.confidence, emb.confidence);
        }
        _ => panic!("Expected LearningMessage::Embedding"),
    }

    // Test adapter round-trip
    let offer = make_valid_adapter_offer(200, 3, 4);
    let msg = LearningMessage::Adapter(offer.clone());
    let bytes = bincode::serialize(&msg).expect("serialize");
    let recovered: LearningMessage = bincode::deserialize(&bytes).expect("deserialize");
    match recovered {
        LearningMessage::Adapter(a) => {
            assert_eq!(a.checkpoint_height, offer.checkpoint_height);
            assert_eq!(a.mentor, offer.mentor);
            assert_eq!(a.mentee, offer.mentee);
            assert_eq!(a.adapter_cid, offer.adapter_cid);
        }
        _ => panic!("Expected LearningMessage::Adapter"),
    }
}

// ---------------------------------------------------------------------------
// Gossip handler: deduplication
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_learning_embedding_deduplication() {
    let (gossip, pm) = make_gossip();
    let peer_id = PeerId::new("learning-peer-1".to_string());
    register_peer(&pm, &peer_id).await;

    let emb = make_valid_embedding(100, 1);

    // First submission should succeed and increment learning_received
    let msg1 = LearningMessage::Embedding(emb.clone());
    let result1 = gossip.handle_learning_message(msg1, &peer_id).await;
    assert!(result1.is_ok(), "First embedding submission should succeed");

    let (_, _, _, _, _, lr1, _, ld1) = gossip.get_stats().await;
    assert_eq!(lr1, 1, "learning_received should be 1");
    assert_eq!(ld1, 0, "No duplicates yet");

    // Second submission of same (checkpoint_height, participant) should be deduped
    let msg2 = LearningMessage::Embedding(emb.clone());
    let result2 = gossip.handle_learning_message(msg2, &peer_id).await;
    assert!(result2.is_ok(), "Duplicate should be silently dropped");

    let (_, _, _, _, _, lr2, _, ld2) = gossip.get_stats().await;
    assert_eq!(lr2, 1, "learning_received should still be 1 (deduped)");
    assert_eq!(ld2, 1, "One duplicate should be filtered");
}

/// Different participants at the same checkpoint should NOT be deduped.
#[tokio::test]
async fn test_learning_different_participants_not_deduped() {
    let (gossip, pm) = make_gossip();
    let peer_id = PeerId::new("learning-peer-2".to_string());
    register_peer(&pm, &peer_id).await;

    let emb1 = make_valid_embedding(100, 1);
    let emb2 = make_valid_embedding(100, 2); // different participant

    let r1 = gossip
        .handle_learning_message(LearningMessage::Embedding(emb1), &peer_id)
        .await;
    assert!(r1.is_ok());

    let r2 = gossip
        .handle_learning_message(LearningMessage::Embedding(emb2), &peer_id)
        .await;
    assert!(r2.is_ok());

    let (_, _, _, _, _, lr, _, ld) = gossip.get_stats().await;
    assert_eq!(lr, 2, "Both embeddings should be received (different participants)");
    assert_eq!(ld, 0, "No duplicates");
}

/// Same participant at different checkpoints should NOT be deduped.
#[tokio::test]
async fn test_learning_different_checkpoints_not_deduped() {
    let (gossip, pm) = make_gossip();
    let peer_id = PeerId::new("learning-peer-3".to_string());
    register_peer(&pm, &peer_id).await;

    let emb1 = make_valid_embedding(100, 1);
    let emb2 = make_valid_embedding(150, 1); // same participant, different checkpoint

    let r1 = gossip
        .handle_learning_message(LearningMessage::Embedding(emb1), &peer_id)
        .await;
    assert!(r1.is_ok());

    let r2 = gossip
        .handle_learning_message(LearningMessage::Embedding(emb2), &peer_id)
        .await;
    assert!(r2.is_ok());

    let (_, _, _, _, _, lr, _, _) = gossip.get_stats().await;
    assert_eq!(lr, 2, "Both embeddings should be accepted (different checkpoints)");
}

// ---------------------------------------------------------------------------
// Gossip handler: invalid message rejection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_learning_invalid_message_rejected() {
    let (gossip, pm) = make_gossip();
    let peer_id = PeerId::new("learning-peer-bad".to_string());
    register_peer(&pm, &peer_id).await;

    // Invalid: empty embedding
    let mut emb = make_valid_embedding(100, 1);
    emb.embedding = vec![];
    emb.confidence = vec![];
    let msg = LearningMessage::Embedding(emb);

    let result = gossip.handle_learning_message(msg, &peer_id).await;
    assert!(result.is_err(), "Invalid learning message should be rejected");

    let (_, _, _, _, _, lr, _, _) = gossip.get_stats().await;
    assert_eq!(lr, 0, "Invalid messages should not count as received");
}

#[tokio::test]
async fn test_learning_self_mentor_rejected() {
    let (gossip, pm) = make_gossip();
    let peer_id = PeerId::new("learning-peer-self".to_string());
    register_peer(&pm, &peer_id).await;

    let mut offer = make_valid_adapter_offer(100, 1, 2);
    offer.mentee = offer.mentor; // self-mentoring
    let msg = LearningMessage::Adapter(offer);

    let result = gossip.handle_learning_message(msg, &peer_id).await;
    assert!(result.is_err(), "Self-mentoring adapter offer should be rejected");
}

// ---------------------------------------------------------------------------
// Per-checkpoint data collection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_learning_data_stored_per_checkpoint() {
    let (gossip, pm) = make_gossip();
    let peer_id = PeerId::new("learning-peer-store".to_string());
    register_peer(&pm, &peer_id).await;

    // Submit embeddings at checkpoint 100 and 200
    let emb100 = make_valid_embedding(100, 1);
    let emb200 = make_valid_embedding(200, 2);
    let adapter100 = make_valid_adapter_offer(100, 3, 4);

    gossip
        .handle_learning_message(LearningMessage::Embedding(emb100), &peer_id)
        .await
        .unwrap();
    gossip
        .handle_learning_message(LearningMessage::Embedding(emb200), &peer_id)
        .await
        .unwrap();
    gossip
        .handle_learning_message(LearningMessage::Adapter(adapter100), &peer_id)
        .await
        .unwrap();

    // Check checkpoint 100 data
    let data100 = gossip.get_learning_data(100).await;
    assert!(data100.is_some(), "Checkpoint 100 should have data");
    let data100 = data100.unwrap();
    assert_eq!(data100.embeddings.len(), 1, "One embedding at cp 100");
    assert_eq!(data100.adapters.len(), 1, "One adapter at cp 100");

    // Check checkpoint 200 data
    let data200 = gossip.get_learning_data(200).await;
    assert!(data200.is_some(), "Checkpoint 200 should have data");
    let data200 = data200.unwrap();
    assert_eq!(data200.embeddings.len(), 1, "One embedding at cp 200");
    assert_eq!(data200.adapters.len(), 0, "No adapters at cp 200");

    // Check non-existent checkpoint
    let data300 = gossip.get_learning_data(300).await;
    assert!(data300.is_none(), "Checkpoint 300 should have no data");
}

// ---------------------------------------------------------------------------
// Pruning
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_learning_data_pruning() {
    let (gossip, pm) = make_gossip();
    let peer_id = PeerId::new("learning-peer-prune".to_string());
    register_peer(&pm, &peer_id).await;

    // Submit data at checkpoints 50, 100, 150
    for (cp, pid) in [(50u64, 1u8), (100, 2), (150, 3)] {
        let emb = make_valid_embedding(cp, pid);
        gossip
            .handle_learning_message(LearningMessage::Embedding(emb), &peer_id)
            .await
            .unwrap();
    }

    // Prune everything at or below checkpoint 100
    gossip.prune_learning_data(100).await;

    // Checkpoint 50 and 100 should be gone
    assert!(gossip.get_learning_data(50).await.is_none());
    assert!(gossip.get_learning_data(100).await.is_none());

    // Checkpoint 150 should still be present
    assert!(gossip.get_learning_data(150).await.is_some());
}

// ---------------------------------------------------------------------------
// Adapter offer gossip through handler
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_adapter_offer_gossip_handler() {
    let (gossip, pm) = make_gossip();
    let peer_id = PeerId::new("adapter-peer".to_string());
    register_peer(&pm, &peer_id).await;

    let offer = make_valid_adapter_offer(100, 1, 2);
    let msg = LearningMessage::Adapter(offer);

    let result = gossip.handle_learning_message(msg, &peer_id).await;
    assert!(result.is_ok());

    let (_, _, _, _, _, lr, _, _) = gossip.get_stats().await;
    assert_eq!(lr, 1, "Adapter offer should be counted as learning_received");

    let data = gossip.get_learning_data(100).await.unwrap();
    assert_eq!(data.adapters.len(), 1);
    assert_eq!(data.embeddings.len(), 0);
}

// ---------------------------------------------------------------------------
// Multiple embeddings at same checkpoint (different participants)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_multiple_embeddings_same_checkpoint() {
    let (gossip, pm) = make_gossip();
    let peer_id = PeerId::new("multi-emb-peer".to_string());
    register_peer(&pm, &peer_id).await;

    // 5 different participants at the same checkpoint
    for pid in 1..=5u8 {
        let emb = make_valid_embedding(100, pid);
        gossip
            .handle_learning_message(LearningMessage::Embedding(emb), &peer_id)
            .await
            .unwrap();
    }

    let data = gossip.get_learning_data(100).await.unwrap();
    assert_eq!(
        data.embeddings.len(),
        5,
        "All 5 embeddings from different participants should be stored"
    );
}
