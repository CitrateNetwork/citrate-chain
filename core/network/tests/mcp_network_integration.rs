// MCP → Network inference integration test
//
// Validates the full pipeline:
// 1. Create AINetworkHandler with a mock NetworkInferenceExecutor
// 2. Register a model in the handler's state manager
// 3. Simulate an InferenceRequest network message
// 4. Verify the InferenceResponse contains output bytes and serialised proof

use async_trait::async_trait;
use citrate_consensus::types::*;
use citrate_execution::{AccessPolicy, Address, ModelId, ModelState, UsageStats};
use citrate_network::ai_handler::{
    AINetworkHandler, NetworkInferenceExecutor, NetworkInferenceResult,
};
use citrate_network::peer::{PeerId, PeerManager, PeerManagerConfig};
use citrate_network::protocol::NetworkMessage;
use citrate_storage::pruning::PruningConfig;
use citrate_storage::state_manager::StateManager;
use citrate_storage::StorageManager;
use std::sync::Arc;
use tempfile::TempDir;

/// Mock executor that returns deterministic output + JSON proof.
struct MockMCPExecutor {
    output: Vec<u8>,
}

impl MockMCPExecutor {
    fn new(output: Vec<u8>) -> Self {
        Self { output }
    }
}

#[async_trait]
impl NetworkInferenceExecutor for MockMCPExecutor {
    async fn execute_inference(
        &self,
        model_id: [u8; 32],
        _input: Vec<u8>,
        _provider: [u8; 32],
    ) -> Result<NetworkInferenceResult, anyhow::Error> {
        // Build a deterministic proof matching the structure produced by
        // NodeNetworkInferenceExecutor (JSON with model_hash, input_hash, etc.)
        let proof = serde_json::to_vec(&serde_json::json!({
            "model_hash": hex::encode(model_id),
            "input_hash": hex::encode([0xAAu8; 32]),
            "output_hash": hex::encode([0xBBu8; 32]),
            "io_commitment": hex::encode([0xCCu8; 32]),
            "provider": hex::encode([0u8; 20]),
            "timestamp": 1700000000u64,
        }))
        .unwrap();

        Ok(NetworkInferenceResult {
            output: self.output.clone(),
            proof: Some(proof),
            execution_time_ms: 100,
        })
    }
}

/// Build a minimal handler backed by temp storage + a mock executor.
fn build_handler(executor: Arc<dyn NetworkInferenceExecutor>) -> (AINetworkHandler, Arc<StateManager>) {
    let temp_dir = TempDir::new().unwrap();
    // Leak TempDir so it lives for the test duration (we don't care about cleanup in tests)
    let temp_path = temp_dir.path().to_path_buf();
    std::mem::forget(temp_dir);

    let storage = Arc::new(
        StorageManager::new(&temp_path, PruningConfig::default()).unwrap(),
    );
    let state_manager = Arc::new(StateManager::new(storage.db.clone()));
    let peer_manager = Arc::new(PeerManager::new(PeerManagerConfig::default()));

    let handler = AINetworkHandler::new(state_manager.clone(), peer_manager)
        .with_inference_executor(executor);

    (handler, state_manager)
}

/// Register a model in the state manager so the handler can find it.
fn register_model(state_manager: &StateManager, model_hash: Hash) {
    let exec_meta = citrate_execution::ModelMetadata {
        name: "integration-test-model".to_string(),
        version: "1.0.0".to_string(),
        description: "E2E integration test model".to_string(),
        framework: "gguf".to_string(),
        input_shape: vec![1],
        output_shape: vec![1],
        size_bytes: 1024,
        created_at: 0,
    };

    let model_state = ModelState {
        owner: Address([0u8; 20]),
        model_hash: Hash::default(),
        version: 1,
        metadata: exec_meta,
        access_policy: AccessPolicy::Public,
        usage_stats: UsageStats::default(),
    };

    state_manager
        .register_model(ModelId(model_hash), model_state, "QmTestCID".to_string())
        .unwrap();
}

#[cfg(test)]
mod mcp_network_integration {
    use super::*;

    #[tokio::test]
    async fn test_full_inference_pipeline() {
        // 1. Set up handler with mock executor
        let expected_output = b"Hello from the GGUF engine!".to_vec();
        let executor = Arc::new(MockMCPExecutor::new(expected_output.clone()));
        let (handler, state_manager) = build_handler(executor);

        // 2. Register model
        let model_id = Hash::new([42u8; 32]);
        register_model(&state_manager, model_id);

        // 3. Simulate an InferenceRequest arriving over the network
        let peer = PeerId::new("remote-peer".to_string());
        let request_id = Hash::new([99u8; 32]);
        let request = NetworkMessage::InferenceRequest {
            request_id,
            model_id,
            input_hash: Hash::new([0xAAu8; 32]),
            requester: vec![0x11; 20],
            max_fee: 5000,
        };

        let response = handler
            .handle_message(&peer, &request)
            .await
            .expect("handle_message should not return Err");

        // 4. Should produce an InferenceResponse
        assert!(response.is_some(), "Executor is configured — must get a response");
        let response = response.unwrap();

        match response {
            NetworkMessage::InferenceResponse {
                request_id: resp_id,
                output_hash: _,
                proof,
                provider: _,
            } => {
                // Request ID should round-trip
                assert_eq!(resp_id, request_id);

                // Proof should be non-empty JSON with expected fields
                assert!(!proof.is_empty(), "Proof should not be empty");

                let proof_json: serde_json::Value =
                    serde_json::from_slice(&proof).expect("Proof should be valid JSON");
                assert!(
                    proof_json.get("model_hash").is_some(),
                    "Proof should contain model_hash"
                );
                assert!(
                    proof_json.get("input_hash").is_some(),
                    "Proof should contain input_hash"
                );
                assert!(
                    proof_json.get("output_hash").is_some(),
                    "Proof should contain output_hash"
                );
                assert!(
                    proof_json.get("timestamp").is_some(),
                    "Proof should contain timestamp"
                );
            }
            other => panic!("Expected InferenceResponse, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_inference_without_registered_model_returns_none() {
        let executor = Arc::new(MockMCPExecutor::new(vec![1, 2, 3]));
        let (handler, _state_manager) = build_handler(executor);

        // Don't register any model — request should return None
        let peer = PeerId::new("peer-x".to_string());
        let request = NetworkMessage::InferenceRequest {
            request_id: Hash::new([88u8; 32]),
            model_id: Hash::new([0xFFu8; 32]), // non-existent
            input_hash: Hash::new([0xAAu8; 32]),
            requester: vec![0x22; 20],
            max_fee: 1000,
        };

        let response = handler.handle_message(&peer, &request).await.unwrap();
        assert!(
            response.is_none(),
            "Model not registered — should return None"
        );
    }
}
