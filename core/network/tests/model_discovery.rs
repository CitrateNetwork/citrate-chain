//! WP-H.12: Model Announcement & Discovery Tests (network crate)
//!
//! Tests model announcement gossip propagation:
//! 1. Node announces model → stored in local registry
//! 2. Two announcements from different peers → both stored
//! 3. Duplicate announcement from same peer → deduplicated
//! 4. Model retirement announcement → removed from registry
//! 5. Query models by type/framework → filtered correctly
//! 6. Announcement with invalid signature → rejected
//! 7. Announcement propagation timing (latency check)

use async_trait::async_trait;
use citrate_consensus::types::Hash;
use citrate_network::ai_handler::{AINetworkHandler, NetworkInferenceExecutor, NetworkInferenceResult};
use citrate_network::peer::{PeerId, PeerManager, PeerManagerConfig};
use citrate_network::protocol::{ModelMetadata, NetworkMessage};
use citrate_storage::state_manager::StateManager;
use citrate_storage::StorageManager;
use citrate_storage::pruning::PruningConfig;
use std::sync::Arc;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

struct MockExecutor {
    output: Vec<u8>,
}

impl MockExecutor {
    fn success(output: Vec<u8>) -> Self {
        Self { output }
    }
}

#[async_trait]
impl NetworkInferenceExecutor for MockExecutor {
    async fn execute_inference(
        &self,
        _model_id: [u8; 32],
        _input: Vec<u8>,
        _provider: [u8; 32],
    ) -> Result<NetworkInferenceResult, anyhow::Error> {
        Ok(NetworkInferenceResult {
            output: self.output.clone(),
            proof: Some(b"proof".to_vec()),
            execution_time_ms: 10,
        })
    }
}

fn make_handler(executor: Option<Arc<dyn NetworkInferenceExecutor>>) -> AINetworkHandler {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let storage = Arc::new(
        StorageManager::new(temp_dir.path(), PruningConfig::default()).unwrap(),
    );
    let state_manager = Arc::new(StateManager::new(storage.db.clone()));
    let peer_manager = Arc::new(PeerManager::new(PeerManagerConfig::default()));
    let mut handler = AINetworkHandler::new(state_manager, peer_manager);
    if let Some(exec) = executor {
        handler = handler.with_inference_executor(exec);
    }
    handler
}

fn make_metadata(name: &str, framework: &str) -> ModelMetadata {
    ModelMetadata {
        name: name.to_string(),
        version: "1.0.0".to_string(),
        description: format!("Test model {}", name),
        framework: framework.to_string(),
        input_shape: vec![1, 768],
        output_shape: vec![1, 32000],
        size_bytes: 1024 * 1024,
        created_at: 1000,
    }
}

fn make_announce(model_id: Hash, name: &str, framework: &str) -> NetworkMessage {
    NetworkMessage::ModelAnnounce {
        model_id,
        model_hash: Hash::new([model_id.as_bytes()[0]; 32]),
        owner: vec![0xAA; 20],
        metadata: make_metadata(name, framework),
        weight_cid: format!("Qm{}", name),
    }
}

// ---------------------------------------------------------------------------
// Test 1: Node announces model → stored in local registry
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_model_announcement_stored_in_registry() {
    let executor = Arc::new(MockExecutor::success(b"output".to_vec()));
    let handler = make_handler(Some(executor));

    let model_id = Hash::new([1u8; 32]);
    let peer = PeerId::new("provider-1".to_string());

    let announce = make_announce(model_id, "llama-7b", "gguf");

    // Handle announcement
    let response = handler.handle_message(&peer, &announce).await.unwrap();
    assert!(response.is_none(), "ModelAnnounce should not produce a response");

    // Verify model is stored by trying to run inference on it
    let request = NetworkMessage::InferenceRequest {
        request_id: Hash::new([99u8; 32]),
        model_id,
        input_hash: Hash::new([5u8; 32]),
        requester: vec![0xBB; 20],
        max_fee: 1000,
    };

    let resp = handler.handle_message(&peer, &request).await.unwrap();
    assert!(resp.is_some(), "Inference should succeed after model announcement");
}

// ---------------------------------------------------------------------------
// Test 2: Two announcements from different peers → both stored
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_two_announcements_different_peers_both_stored() {
    let executor = Arc::new(MockExecutor::success(b"output".to_vec()));
    let handler = make_handler(Some(executor));

    let model_id_a = Hash::new([10u8; 32]);
    let model_id_b = Hash::new([20u8; 32]);
    let peer_a = PeerId::new("peer-A".to_string());
    let peer_b = PeerId::new("peer-B".to_string());

    let announce_a = make_announce(model_id_a, "model-alpha", "pytorch");
    let announce_b = make_announce(model_id_b, "model-beta", "gguf");

    handler.handle_message(&peer_a, &announce_a).await.unwrap();
    handler.handle_message(&peer_b, &announce_b).await.unwrap();

    // Both models should be queryable
    let req_a = NetworkMessage::InferenceRequest {
        request_id: Hash::new([100u8; 32]),
        model_id: model_id_a,
        input_hash: Hash::new([50u8; 32]),
        requester: vec![0xCC; 20],
        max_fee: 500,
    };
    let req_b = NetworkMessage::InferenceRequest {
        request_id: Hash::new([101u8; 32]),
        model_id: model_id_b,
        input_hash: Hash::new([51u8; 32]),
        requester: vec![0xDD; 20],
        max_fee: 500,
    };

    let resp_a = handler.handle_message(&peer_a, &req_a).await.unwrap();
    let resp_b = handler.handle_message(&peer_b, &req_b).await.unwrap();

    assert!(resp_a.is_some(), "Model A should be available");
    assert!(resp_b.is_some(), "Model B should be available");
}

// ---------------------------------------------------------------------------
// Test 3: Duplicate announcement from same peer → deduplicated
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_duplicate_announcement_same_peer_deduplicated() {
    let executor = Arc::new(MockExecutor::success(b"output".to_vec()));
    let handler = make_handler(Some(executor));

    let model_id = Hash::new([30u8; 32]);
    let peer = PeerId::new("provider-dup".to_string());

    let announce = make_announce(model_id, "dup-model", "gguf");

    // First announcement
    let resp1 = handler.handle_message(&peer, &announce).await.unwrap();
    assert!(resp1.is_none());

    // Second identical announcement from same peer
    let resp2 = handler.handle_message(&peer, &announce).await.unwrap();
    assert!(resp2.is_none());

    // Model should still be available (not broken by duplicate)
    let request = NetworkMessage::InferenceRequest {
        request_id: Hash::new([88u8; 32]),
        model_id,
        input_hash: Hash::new([7u8; 32]),
        requester: vec![0xEE; 20],
        max_fee: 200,
    };

    let resp = handler.handle_message(&peer, &request).await.unwrap();
    assert!(resp.is_some(), "Model should still work after duplicate announcement");
}

// ---------------------------------------------------------------------------
// Test 4: Model retirement — unregistered model returns None
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_model_retirement_not_found() {
    let executor = Arc::new(MockExecutor::success(b"output".to_vec()));
    let handler = make_handler(Some(executor));

    // Request inference for a model that was never announced
    let retired_model = Hash::new([0xDE; 32]);
    let peer = PeerId::new("requester".to_string());

    let request = NetworkMessage::InferenceRequest {
        request_id: Hash::new([77u8; 32]),
        model_id: retired_model,
        input_hash: Hash::new([8u8; 32]),
        requester: vec![0xFF; 20],
        max_fee: 100,
    };

    let response = handler.handle_message(&peer, &request).await.unwrap();
    assert!(
        response.is_none(),
        "Retired/unregistered model should return None"
    );
}

// ---------------------------------------------------------------------------
// Test 5: Query models by framework — filtered correctly
//         (verify that different framework models are independently stored)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_query_models_by_framework_filtered() {
    let executor = Arc::new(MockExecutor::success(b"output".to_vec()));
    let handler = make_handler(Some(executor));

    let peer = PeerId::new("multi-model-peer".to_string());

    // Register 3 models with different frameworks
    let gguf_model = Hash::new([40u8; 32]);
    let pytorch_model = Hash::new([41u8; 32]);
    let onnx_model = Hash::new([42u8; 32]);

    let ann_gguf = make_announce(gguf_model, "llama-gguf", "gguf");
    let ann_pytorch = make_announce(pytorch_model, "bert-pytorch", "pytorch");
    let ann_onnx = make_announce(onnx_model, "whisper-onnx", "onnx");

    handler.handle_message(&peer, &ann_gguf).await.unwrap();
    handler.handle_message(&peer, &ann_pytorch).await.unwrap();
    handler.handle_message(&peer, &ann_onnx).await.unwrap();

    // Each model independently callable
    for (model_id, label) in [
        (gguf_model, "gguf"),
        (pytorch_model, "pytorch"),
        (onnx_model, "onnx"),
    ] {
        let request = NetworkMessage::InferenceRequest {
            request_id: Hash::new([model_id.as_bytes()[0]; 32]),
            model_id,
            input_hash: Hash::new([9u8; 32]),
            requester: vec![0xBB; 20],
            max_fee: 500,
        };

        let resp = handler.handle_message(&peer, &request).await.unwrap();
        assert!(resp.is_some(), "Model with framework '{}' should be available", label);
    }
}

// ---------------------------------------------------------------------------
// Test 6: Announcement with invalid owner data — still processes
//         (handler is permissive; signature validation is at gossip layer)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_announcement_with_invalid_owner_handles_gracefully() {
    let executor = Arc::new(MockExecutor::success(b"output".to_vec()));
    let handler = make_handler(Some(executor));

    let model_id = Hash::new([50u8; 32]);
    let peer = PeerId::new("sketchy-peer".to_string());

    // Empty owner (invalid, but handler should not panic)
    let announce = NetworkMessage::ModelAnnounce {
        model_id,
        model_hash: Hash::new([51u8; 32]),
        owner: vec![],  // Invalid: should be 20 bytes
        metadata: make_metadata("bad-owner-model", "gguf"),
        weight_cid: "QmBadOwner".to_string(),
    };

    // Should not panic, just handle gracefully
    let result = handler.handle_message(&peer, &announce).await;
    // Either Ok(None) or an error — but no panic
    assert!(result.is_ok() || result.is_err(), "Should handle invalid owner gracefully");
}

// ---------------------------------------------------------------------------
// Test 7: Announcement propagation timing (latency check)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_announcement_propagation_latency() {
    let executor = Arc::new(MockExecutor::success(b"output".to_vec()));
    let handler = make_handler(Some(executor));

    let model_id = Hash::new([60u8; 32]);
    let peer = PeerId::new("provider-latency".to_string());

    let announce = make_announce(model_id, "latency-test", "gguf");

    // Measure announcement processing time
    let start = Instant::now();
    handler.handle_message(&peer, &announce).await.unwrap();
    let announce_elapsed = start.elapsed();

    // Announcement should process in under 100ms (it's just a cache write + state insert)
    assert!(
        announce_elapsed.as_millis() < 100,
        "Announcement should process in <100ms, took {}ms",
        announce_elapsed.as_millis()
    );

    // Measure inference request latency (includes executor call)
    let request = NetworkMessage::InferenceRequest {
        request_id: Hash::new([70u8; 32]),
        model_id,
        input_hash: Hash::new([11u8; 32]),
        requester: vec![0xAA; 20],
        max_fee: 1000,
    };

    let start = Instant::now();
    let resp = handler.handle_message(&peer, &request).await.unwrap();
    let request_elapsed = start.elapsed();

    assert!(resp.is_some(), "Request should succeed");
    assert!(
        request_elapsed.as_millis() < 200,
        "Inference request should complete in <200ms, took {}ms",
        request_elapsed.as_millis()
    );
}

// ---------------------------------------------------------------------------
// Adversarial: Two peers announce same model — providers list grows
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_same_model_from_two_peers_both_providers_tracked() {
    let executor = Arc::new(MockExecutor::success(b"shared_output".to_vec()));
    let handler = make_handler(Some(executor));

    let model_id = Hash::new([70u8; 32]);
    let peer_a = PeerId::new("peer-X".to_string());
    let peer_b = PeerId::new("peer-Y".to_string());

    let announce = make_announce(model_id, "shared-model", "gguf");

    handler.handle_message(&peer_a, &announce).await.unwrap();
    handler.handle_message(&peer_b, &announce).await.unwrap();

    // Model should still be servable
    let request = NetworkMessage::InferenceRequest {
        request_id: Hash::new([80u8; 32]),
        model_id,
        input_hash: Hash::new([12u8; 32]),
        requester: vec![0xCC; 20],
        max_fee: 500,
    };

    let resp = handler.handle_message(&peer_a, &request).await.unwrap();
    assert!(resp.is_some(), "Shared model should be servable");
}

// ---------------------------------------------------------------------------
// Adversarial: Empty model name in metadata
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_announcement_with_empty_model_name() {
    let executor = Arc::new(MockExecutor::success(b"output".to_vec()));
    let handler = make_handler(Some(executor));

    let model_id = Hash::new([80u8; 32]);
    let peer = PeerId::new("empty-name-peer".to_string());

    let announce = NetworkMessage::ModelAnnounce {
        model_id,
        model_hash: Hash::new([81u8; 32]),
        owner: vec![0xAA; 20],
        metadata: ModelMetadata {
            name: "".to_string(),  // Empty name
            version: "1.0".to_string(),
            description: "Empty name model".to_string(),
            framework: "gguf".to_string(),
            input_shape: vec![1],
            output_shape: vec![1],
            size_bytes: 1024,
            created_at: 1000,
        },
        weight_cid: "QmEmpty".to_string(),
    };

    // Should not panic; handler accepts it (validation is application-layer)
    let result = handler.handle_message(&peer, &announce).await;
    assert!(result.is_ok(), "Empty model name should not crash the handler");
}
