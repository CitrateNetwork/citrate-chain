//! WP-H.10: Multi-Node Inference Routing Tests (network crate portion)
//!
//! Tests model announcement, inference request routing, model-not-found errors,
//! provider timeout fallback, proof-of-computation in responses, cache hit behavior,
//! and multi-provider routing for the AINetworkHandler.

use async_trait::async_trait;
use citrate_consensus::types::Hash;
use citrate_network::ai_handler::{AINetworkHandler, NetworkInferenceExecutor, NetworkInferenceResult};
use citrate_network::peer::{PeerId, PeerManager, PeerManagerConfig};
use citrate_network::protocol::{ModelMetadata, NetworkMessage};
use citrate_storage::state_manager::StateManager;
use citrate_storage::StorageManager;
use citrate_storage::pruning::PruningConfig;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A mock inference executor that returns a configurable result.
struct MockExecutor {
    output: Vec<u8>,
    proof: Option<Vec<u8>>,
    execution_time_ms: u64,
    should_fail: bool,
}

impl MockExecutor {
    fn success(output: Vec<u8>) -> Self {
        Self {
            output,
            proof: Some(b"proof_of_computation".to_vec()),
            execution_time_ms: 50,
            should_fail: false,
        }
    }

    fn failing() -> Self {
        Self {
            output: vec![],
            proof: None,
            execution_time_ms: 0,
            should_fail: true,
        }
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
        if self.should_fail {
            return Err(anyhow::anyhow!("executor timeout / failure"));
        }
        Ok(NetworkInferenceResult {
            output: self.output.clone(),
            proof: self.proof.clone(),
            execution_time_ms: self.execution_time_ms,
        })
    }
}

/// Build an AINetworkHandler backed by in-memory storage.
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

fn make_model_metadata(name: &str) -> ModelMetadata {
    ModelMetadata {
        name: name.to_string(),
        version: "1.0.0".to_string(),
        description: format!("Test model {}", name),
        framework: "gguf".to_string(),
        input_shape: vec![1, 768],
        output_shape: vec![1, 32000],
        size_bytes: 1024 * 1024,
        created_at: 1000,
    }
}

// Model registration is done through handle_model_announce (ModelAnnounce message)
// rather than direct state_manager access, which is encapsulated in the handler.

// ---------------------------------------------------------------------------
// Test 1: Model announcement creates entry in local registry
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_model_announcement_creates_registry_entry() {
    let executor = Arc::new(MockExecutor::success(b"test_output".to_vec()));
    let handler = make_handler(Some(executor));

    let model_id = Hash::new([1u8; 32]);
    let model_hash = Hash::new([2u8; 32]);
    let peer = PeerId::new("provider-A".to_string());
    let metadata = make_model_metadata("llama-7b");

    let announce = NetworkMessage::ModelAnnounce {
        model_id,
        model_hash,
        owner: vec![0xAA; 20],
        metadata: metadata.clone(),
        weight_cid: "QmTestModelCID".to_string(),
    };

    // Handle the announcement
    let response = handler.handle_message(&peer, &announce).await.unwrap();
    assert!(
        response.is_none(),
        "ModelAnnounce should not produce a response"
    );

    // Now an inference request for this model should succeed
    let request = NetworkMessage::InferenceRequest {
        request_id: Hash::new([99u8; 32]),
        model_id,
        input_hash: Hash::new([5u8; 32]),
        requester: vec![0xBB; 20],
        max_fee: 1000,
    };

    let response = handler.handle_message(&peer, &request).await.unwrap();
    assert!(
        response.is_some(),
        "Inference request should succeed after model announcement"
    );
}

// ---------------------------------------------------------------------------
// Test 2: Inference request routes to correct provider by model_id
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_inference_routes_to_correct_model() {
    let executor = Arc::new(MockExecutor::success(b"model_output".to_vec()));
    let handler = make_handler(Some(executor));

    let model_id_a = Hash::new([10u8; 32]);
    let model_id_b = Hash::new([20u8; 32]);
    let peer = PeerId::new("provider".to_string());

    // Register Model A
    let announce_a = NetworkMessage::ModelAnnounce {
        model_id: model_id_a,
        model_hash: Hash::new([11u8; 32]),
        owner: vec![0xAA; 20],
        metadata: make_model_metadata("model-a"),
        weight_cid: "QmModelA".to_string(),
    };
    handler.handle_message(&peer, &announce_a).await.unwrap();

    // Register Model B
    let announce_b = NetworkMessage::ModelAnnounce {
        model_id: model_id_b,
        model_hash: Hash::new([22u8; 32]),
        owner: vec![0xBB; 20],
        metadata: make_model_metadata("model-b"),
        weight_cid: "QmModelB".to_string(),
    };
    handler.handle_message(&peer, &announce_b).await.unwrap();

    // Request inference for Model A
    let request_a = NetworkMessage::InferenceRequest {
        request_id: Hash::new([100u8; 32]),
        model_id: model_id_a,
        input_hash: Hash::new([50u8; 32]),
        requester: vec![0xCC; 20],
        max_fee: 500,
    };

    let resp = handler.handle_message(&peer, &request_a).await.unwrap();
    assert!(
        resp.is_some(),
        "Should route inference to model A"
    );
    match resp.unwrap() {
        NetworkMessage::InferenceResponse { request_id, .. } => {
            assert_eq!(request_id, Hash::new([100u8; 32]));
        }
        other => panic!("Expected InferenceResponse, got {:?}", other),
    }

    // Request inference for Model B
    let request_b = NetworkMessage::InferenceRequest {
        request_id: Hash::new([101u8; 32]),
        model_id: model_id_b,
        input_hash: Hash::new([51u8; 32]),
        requester: vec![0xDD; 20],
        max_fee: 500,
    };

    let resp = handler.handle_message(&peer, &request_b).await.unwrap();
    assert!(
        resp.is_some(),
        "Should route inference to model B"
    );
    match resp.unwrap() {
        NetworkMessage::InferenceResponse { request_id, .. } => {
            assert_eq!(request_id, Hash::new([101u8; 32]));
        }
        other => panic!("Expected InferenceResponse, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Test 3: Model not found returns None (no error, graceful handling)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_model_not_found_graceful() {
    let executor = Arc::new(MockExecutor::success(b"output".to_vec()));
    let handler = make_handler(Some(executor));

    let unknown_model = Hash::new([0xFF; 32]);
    let peer = PeerId::new("requester".to_string());

    let request = NetworkMessage::InferenceRequest {
        request_id: Hash::new([77u8; 32]),
        model_id: unknown_model,
        input_hash: Hash::new([8u8; 32]),
        requester: vec![0xEE; 20],
        max_fee: 100,
    };

    // Model not registered → should return None (no response)
    let response = handler.handle_message(&peer, &request).await.unwrap();
    assert!(
        response.is_none(),
        "Unregistered model should return None (no provider found)"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Provider timeout → falls back gracefully (returns None)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_provider_timeout_graceful_fallback() {
    let executor = Arc::new(MockExecutor::failing());
    let handler = make_handler(Some(executor));

    let model_id = Hash::new([30u8; 32]);
    let peer = PeerId::new("provider-timeout".to_string());

    // Register model
    let announce = NetworkMessage::ModelAnnounce {
        model_id,
        model_hash: Hash::new([31u8; 32]),
        owner: vec![0xAA; 20],
        metadata: make_model_metadata("slow-model"),
        weight_cid: "QmSlowModel".to_string(),
    };
    handler.handle_message(&peer, &announce).await.unwrap();

    // Request inference — executor fails (simulating timeout)
    let request = NetworkMessage::InferenceRequest {
        request_id: Hash::new([88u8; 32]),
        model_id,
        input_hash: Hash::new([9u8; 32]),
        requester: vec![0xCC; 20],
        max_fee: 200,
    };

    let response = handler.handle_message(&peer, &request).await.unwrap();
    assert!(
        response.is_none(),
        "Failed executor should gracefully return None"
    );
}

// ---------------------------------------------------------------------------
// Test 5: Response includes proof-of-computation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_response_includes_proof_of_computation() {
    let executor = Arc::new(MockExecutor::success(b"inference_result".to_vec()));
    let handler = make_handler(Some(executor));

    let model_id = Hash::new([40u8; 32]);
    let peer = PeerId::new("provider-proof".to_string());

    // Register model
    let announce = NetworkMessage::ModelAnnounce {
        model_id,
        model_hash: Hash::new([41u8; 32]),
        owner: vec![0xAA; 20],
        metadata: make_model_metadata("proof-model"),
        weight_cid: "QmProofModel".to_string(),
    };
    handler.handle_message(&peer, &announce).await.unwrap();

    // Request inference
    let request = NetworkMessage::InferenceRequest {
        request_id: Hash::new([55u8; 32]),
        model_id,
        input_hash: Hash::new([6u8; 32]),
        requester: vec![0xDD; 20],
        max_fee: 300,
    };

    let response = handler.handle_message(&peer, &request).await.unwrap();
    assert!(response.is_some());

    match response.unwrap() {
        NetworkMessage::InferenceResponse {
            request_id,
            output_hash,
            proof,
            provider,
        } => {
            assert_eq!(request_id, Hash::new([55u8; 32]));
            // Proof should be non-empty (mock returns b"proof_of_computation")
            assert!(
                !proof.is_empty(),
                "Response should include proof-of-computation"
            );
            // Output hash should be non-zero (hash of actual output)
            assert_ne!(
                output_hash,
                Hash::default(),
                "Output hash should be non-default"
            );
            // Provider should be non-empty
            assert!(
                !provider.is_empty(),
                "Provider field should be populated"
            );
        }
        other => panic!("Expected InferenceResponse, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Test 6: No executor configured → returns None (no crash)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_no_executor_returns_none() {
    // Handler without an executor
    let handler = make_handler(None);

    let model_id = Hash::new([50u8; 32]);
    let peer = PeerId::new("provider-no-exec".to_string());

    // Register model
    let announce = NetworkMessage::ModelAnnounce {
        model_id,
        model_hash: Hash::new([51u8; 32]),
        owner: vec![0xAA; 20],
        metadata: make_model_metadata("no-exec-model"),
        weight_cid: "QmNoExecModel".to_string(),
    };
    handler.handle_message(&peer, &announce).await.unwrap();

    // Request inference — no executor → should return None gracefully
    let request = NetworkMessage::InferenceRequest {
        request_id: Hash::new([66u8; 32]),
        model_id,
        input_hash: Hash::new([7u8; 32]),
        requester: vec![0xEE; 20],
        max_fee: 100,
    };

    let response = handler.handle_message(&peer, &request).await.unwrap();
    assert!(
        response.is_none(),
        "Without executor, should return None"
    );
}

// ---------------------------------------------------------------------------
// Test 7: Two providers announce same model → both registered, routes to one
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_two_providers_same_model() {
    let executor = Arc::new(MockExecutor::success(b"multi_provider_output".to_vec()));
    let handler = make_handler(Some(executor));

    let model_id = Hash::new([60u8; 32]);
    let metadata = make_model_metadata("shared-model");

    // Provider A announces
    let peer_a = PeerId::new("provider-A".to_string());
    let announce_a = NetworkMessage::ModelAnnounce {
        model_id,
        model_hash: Hash::new([61u8; 32]),
        owner: vec![0xAA; 20],
        metadata: metadata.clone(),
        weight_cid: "QmSharedModel".to_string(),
    };
    handler.handle_message(&peer_a, &announce_a).await.unwrap();

    // Provider B announces the same model
    let peer_b = PeerId::new("provider-B".to_string());
    let announce_b = NetworkMessage::ModelAnnounce {
        model_id,
        model_hash: Hash::new([61u8; 32]),
        owner: vec![0xBB; 20],
        metadata,
        weight_cid: "QmSharedModel".to_string(),
    };
    handler.handle_message(&peer_b, &announce_b).await.unwrap();

    // Request inference — should succeed (routes to one of the providers)
    let request = NetworkMessage::InferenceRequest {
        request_id: Hash::new([70u8; 32]),
        model_id,
        input_hash: Hash::new([10u8; 32]),
        requester: vec![0xCC; 20],
        max_fee: 500,
    };

    let response = handler.handle_message(&peer_a, &request).await.unwrap();
    assert!(
        response.is_some(),
        "Should route to one of the registered providers"
    );
}
