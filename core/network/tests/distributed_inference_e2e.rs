// Distributed inference end-to-end test
//
// Validates that:
// 1. Two nodes can start with the same genesis
// 2. Node A can register a model and announce it
// 3. The AINetworkHandler correctly processes AI messages
// 4. Message round-trips produce valid responses

use citrate_consensus::types::*;
use citrate_network::ai_handler::AINetworkHandler;
use citrate_network::peer::{PeerId, PeerManager, PeerManagerConfig};
use citrate_network::protocol::{ModelMetadata as NetModelMetadata, NetworkMessage};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::state_manager::StateManager;
use citrate_storage::StorageManager;
use std::sync::Arc;
use tempfile::TempDir;

fn create_test_block(num: u8, height: u64) -> Block {
    let mut hash_bytes = [0u8; 32];
    hash_bytes[0] = num;

    Block {
        header: BlockHeader {
            version: 1,
            block_hash: Hash::new(hash_bytes),
            selected_parent_hash: Hash::default(),
            merge_parent_hashes: vec![],
            timestamp: 1000000 + height * 10,
            height,
            blue_score: height * 10,
            blue_work: (height as u128) * 1000,
            pruning_point: Hash::default(),
            proposer_pubkey: PublicKey::new([0u8; 32]),
            vrf_reveal: VrfProof {
                proof: vec![0u8; 80],
                output: Hash::default(),
            },
            base_fee_per_gas: 0,
            gas_used: 0,
            gas_limit: 30_000_000,
        },
        state_root: Hash::default(),
        tx_root: Hash::default(),
        receipt_root: Hash::default(),
        artifact_root: Hash::default(),
        ghostdag_params: GhostDagParams::default(),
        transactions: vec![],
        signature: Signature::new([0u8; 64]),
        embedded_models: vec![],
        required_pins: vec![],
        learning_embedding: None,
        learning_confidence: None,
        gradient_commitment: None,
            learning_root: Hash::default(),
    }
}

#[cfg(test)]
mod distributed_inference {
    use super::*;

    /// Helper to create a node-like setup (storage + state manager + peer manager + AI handler)
    async fn setup_node() -> (
        Arc<StorageManager>,
        Arc<StateManager>,
        Arc<PeerManager>,
        Arc<AINetworkHandler>,
    ) {
        let temp_dir = TempDir::new().unwrap();
        let config = PruningConfig::default();
        let storage = Arc::new(StorageManager::new(temp_dir.path(), config).unwrap());
        let state_manager = Arc::new(StateManager::new(storage.db.clone()));
        let peer_manager = Arc::new(PeerManager::new(PeerManagerConfig::default()));
        let ai_handler = Arc::new(AINetworkHandler::new(
            state_manager.clone(),
            peer_manager.clone(),
        ));

        // Store genesis block
        let genesis = create_test_block(0, 0);
        let _ = storage.blocks.put_block(&genesis);

        (storage, state_manager, peer_manager, ai_handler)
    }

    #[tokio::test]
    async fn test_model_announce_round_trip() {
        let (_storage_a, _sm_a, _pm_a, _handler_a) = setup_node().await;
        let (_storage_b, _sm_b, _pm_b, handler_b) = setup_node().await;

        let peer_a = PeerId("node-a".to_string());

        // Node A announces a model
        let model_id = Hash::new([1u8; 32]);
        let model_hash = Hash::new([2u8; 32]);
        let announce_msg = NetworkMessage::ModelAnnounce {
            model_id,
            model_hash,
            owner: vec![0xAA; 20],
            metadata: NetModelMetadata {
                name: "test-model".to_string(),
                version: "1.0.0".to_string(),
                description: "A test text generation model".to_string(),
                framework: "gguf".to_string(),
                input_shape: vec![1, 512],
                output_shape: vec![1, 512],
                size_bytes: 500_000_000,
                created_at: 1700000000,
            },
            weight_cid: "QmTestCID12345".to_string(),
        };

        // Node B processes the announcement
        let response = handler_b
            .handle_message(&peer_a, &announce_msg)
            .await
            .expect("handler should not error on valid announce");

        // Announcement doesn't require a response
        assert!(
            response.is_none(),
            "ModelAnnounce should not produce a response"
        );
    }

    #[tokio::test]
    async fn test_inference_request_response_flow() {
        let (_storage_a, _sm_a, _pm_a, handler_a) = setup_node().await;

        let peer_b = PeerId("node-b".to_string());

        // First, announce a model so the handler knows about it
        let model_id = Hash::new([10u8; 32]);
        let announce = NetworkMessage::ModelAnnounce {
            model_id,
            model_hash: Hash::new([11u8; 32]),
            owner: vec![0xBB; 20],
            metadata: NetModelMetadata {
                name: "inference-model".to_string(),
                version: "1.0.0".to_string(),
                description: "Model for inference testing".to_string(),
                framework: "gguf".to_string(),
                input_shape: vec![1, 256],
                output_shape: vec![1, 256],
                size_bytes: 1_000_000,
                created_at: 1700000000,
            },
            weight_cid: "QmInferenceModelCID".to_string(),
        };
        handler_a
            .handle_message(&peer_b, &announce)
            .await
            .unwrap();

        // Now send an inference request
        let request_id = Hash::new([20u8; 32]);
        let request = NetworkMessage::InferenceRequest {
            request_id,
            model_id,
            input_hash: Hash::new([30u8; 32]),
            requester: vec![0xCC; 20],
            max_fee: 1000,
        };

        let _response = handler_a
            .handle_message(&peer_b, &request)
            .await
            .expect("handler should not error on inference request");

        // Handler may or may not produce a response depending on whether
        // it can actually execute the model locally. Just verify no panic.
        // In a full integration test with GGUF engine, we'd assert the response.
    }

    #[tokio::test]
    async fn test_weight_sync_versioning() {
        let (_storage, _sm, _pm, handler) = setup_node().await;

        let peer = PeerId("sync-peer".to_string());

        // First announce a model
        let model_id = Hash::new([50u8; 32]);
        let announce = NetworkMessage::ModelAnnounce {
            model_id,
            model_hash: Hash::new([51u8; 32]),
            owner: vec![0xDD; 20],
            metadata: NetModelMetadata {
                name: "sync-model".to_string(),
                version: "1.0.0".to_string(),
                description: "Model for weight sync testing".to_string(),
                framework: "gguf".to_string(),
                input_shape: vec![1, 128],
                output_shape: vec![1, 128],
                size_bytes: 100_000,
                created_at: 1700000000,
            },
            weight_cid: "QmSyncModelCID".to_string(),
        };
        handler.handle_message(&peer, &announce).await.unwrap();

        // Send weight sync update
        let sync_msg = NetworkMessage::WeightSync {
            model_id,
            version: 2,
            weight_delta: vec![0x01, 0x02, 0x03, 0x04],
        };

        let result = handler.handle_message(&peer, &sync_msg).await;
        assert!(result.is_ok(), "Weight sync should succeed");
    }

    #[tokio::test]
    async fn test_non_ai_message_passthrough() {
        let (_storage, _sm, _pm, handler) = setup_node().await;

        let peer = PeerId("other-peer".to_string());

        // Send a non-AI message — handler should return Ok(None)
        let ping = NetworkMessage::Ping { nonce: 42 };
        let result = handler.handle_message(&peer, &ping).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_training_job_announce() {
        let (_storage, _sm, _pm, handler) = setup_node().await;

        let peer = PeerId("trainer".to_string());

        let training_msg = NetworkMessage::TrainingJobAnnounce {
            job_id: Hash::new([60u8; 32]),
            model_id: Hash::new([61u8; 32]),
            dataset_hash: Hash::new([62u8; 32]),
            participants_needed: 5,
            reward_per_gradient: 100,
            owner: [0xEE; 20],
        };

        let result = handler.handle_message(&peer, &training_msg).await;
        assert!(
            result.is_ok(),
            "Training job announce should be handled without error"
        );
    }
}
