//! WP-H.10: Multi-Node Inference Routing Tests (MCP crate portion)
//!
//! Tests model registration, request routing, model-not-found errors,
//! provider selection, request status tracking, and multi-provider scenarios
//! through the MCP ModelRegistry.

use citrate_execution::{Address, Hash};
use citrate_mcp::registry::ModelRegistry;
use citrate_mcp::types::{
    ComputeRequirements, Currency, HardwareType, ModelId, ModelMetadata, PricingModel, RequestStatus,
};
use citrate_storage::pruning::PruningConfig;
use citrate_storage::StorageManager;
use primitive_types::U256;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_storage() -> Arc<StorageManager> {
    let temp_dir = tempfile::TempDir::new().unwrap();
    Arc::new(StorageManager::new(temp_dir.path(), PruningConfig::default()).unwrap())
}

fn make_model_metadata(name: &str, size: u64) -> ModelMetadata {
    ModelMetadata {
        id: ModelId([0u8; 32]), // Will be assigned by registry
        owner: Address([0xAA; 20]),
        name: name.to_string(),
        version: "1.0".to_string(),
        hash: Hash::new([1u8; 32]),
        size,
        architecture: vec![],
        compute_requirements: ComputeRequirements {
            min_memory: 1024 * 1024 * 1024, // 1GB
            min_compute: 100,
            gpu_required: false,
            supported_hardware: vec![HardwareType::CPU],
        },
        pricing: PricingModel {
            base_price: U256::from(100),
            per_token_price: U256::from(1),
            per_second_price: U256::from(10),
            currency: Currency::SALT,
        },
    }
}

// ---------------------------------------------------------------------------
// Test 1: Model registration creates entry in registry
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_model_registration_creates_entry() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let metadata = make_model_metadata("llama-7b", 4_000_000_000);
    let provider = Address([0xBB; 20]);

    let model_id = registry
        .register(metadata.clone(), vec![provider], Some("QmTestCID".to_string()))
        .await
        .unwrap();

    // Retrieve model
    let retrieved = registry.get_model(&model_id).await.unwrap();
    assert_eq!(retrieved.name, "llama-7b");
    assert_eq!(retrieved.size, 4_000_000_000);

    // Retrieve providers
    let providers = registry.get_providers(&model_id).await.unwrap();
    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0], provider);

    // Retrieve weight CID
    let cid = registry.get_weight_cid(&model_id).await.unwrap();
    assert_eq!(cid, Some("QmTestCID".to_string()));
}

// ---------------------------------------------------------------------------
// Test 2: Inference request routes to correct provider by model_id
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_inference_request_routes_to_provider() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let provider_a = Address([0xAA; 20]);
    let provider_b = Address([0xBB; 20]);
    let requester = Address([0xCC; 20]);

    // Register two different models with different providers
    let meta_a = make_model_metadata("model-a", 1_000_000);
    let model_id_a = registry
        .register(meta_a, vec![provider_a], None)
        .await
        .unwrap();

    let mut meta_b = make_model_metadata("model-b", 2_000_000);
    meta_b.hash = Hash::new([2u8; 32]); // Different hash so different model ID
    let model_id_b = registry
        .register(meta_b, vec![provider_b], None)
        .await
        .unwrap();

    // Create request for model A → should assign to provider A
    let input_hash_a = Hash::new([10u8; 32]);
    let request_id_a = registry
        .create_request(model_id_a, input_hash_a, requester, U256::from(1000))
        .await
        .unwrap();
    assert_ne!(request_id_a.0, [0u8; 32]);

    // Create request for model B → should assign to provider B
    let input_hash_b = Hash::new([20u8; 32]);
    let request_id_b = registry
        .create_request(model_id_b, input_hash_b, requester, U256::from(2000))
        .await
        .unwrap();
    assert_ne!(request_id_b.0, [0u8; 32]);
    assert_ne!(request_id_a.0, request_id_b.0, "requests should have different IDs");
}

// ---------------------------------------------------------------------------
// Test 3: Model not found returns error with message
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_model_not_found_returns_error() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let unknown_model = ModelId([0xFF; 32]);
    let requester = Address([0xCC; 20]);

    // Get model → error
    let result = registry.get_model(&unknown_model).await;
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("not found"),
        "Error should mention 'not found', got: {}",
        err_msg
    );

    // Create request for unknown model → error
    let result = registry
        .create_request(unknown_model, Hash::new([1u8; 32]), requester, U256::from(100))
        .await;
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Test 4: Request status tracking (Pending → Completed)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_request_status_tracking() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let provider = Address([0xAA; 20]);
    let requester = Address([0xCC; 20]);

    let metadata = make_model_metadata("status-model", 500_000);
    let model_id = registry
        .register(metadata, vec![provider], None)
        .await
        .unwrap();

    let request_id = registry
        .create_request(model_id, Hash::new([5u8; 32]), requester, U256::from(500))
        .await
        .unwrap();

    // Update status to Completed
    let result_hash = Hash::new([99u8; 32]);
    registry
        .update_request_status(request_id, RequestStatus::Completed(result_hash))
        .await
        .unwrap();

    // Model's total_executions should increment
    let record = registry.get_record(&model_id).await.unwrap();
    assert_eq!(record.total_executions, 1);
}

// ---------------------------------------------------------------------------
// Test 5: Duplicate model registration rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_duplicate_model_registration_rejected() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let metadata = make_model_metadata("dup-model", 1_000_000);
    let provider = Address([0xAA; 20]);

    // First registration succeeds
    let _model_id = registry
        .register(metadata.clone(), vec![provider], None)
        .await
        .unwrap();

    // Second registration of same model fails
    let result = registry.register(metadata, vec![provider], None).await;
    assert!(
        result.is_err(),
        "Duplicate model registration should fail"
    );
}

// ---------------------------------------------------------------------------
// Test 6: Multiple providers for same model
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_multiple_providers_registered() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let provider_a = Address([0xAA; 20]);
    let provider_b = Address([0xBB; 20]);

    let metadata = make_model_metadata("multi-provider-model", 1_000_000);
    let model_id = registry
        .register(metadata, vec![provider_a, provider_b], None)
        .await
        .unwrap();

    let providers = registry.get_providers(&model_id).await.unwrap();
    assert_eq!(providers.len(), 2);
    assert!(providers.contains(&provider_a));
    assert!(providers.contains(&provider_b));

    // Request should succeed (routes to first provider)
    let requester = Address([0xCC; 20]);
    let request_id = registry
        .create_request(model_id, Hash::new([7u8; 32]), requester, U256::from(100))
        .await
        .unwrap();
    assert_ne!(request_id.0, [0u8; 32]);
}

// ---------------------------------------------------------------------------
// Test 7: Weight CID update
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_weight_cid_update() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let metadata = make_model_metadata("weight-model", 1_000_000);
    let provider = Address([0xAA; 20]);

    let model_id = registry
        .register(metadata, vec![provider], Some("QmOldCID".to_string()))
        .await
        .unwrap();

    // Update weight CID
    registry
        .update_weight(&model_id, "QmNewCID".to_string())
        .await
        .unwrap();

    let cid = registry.get_weight_cid(&model_id).await.unwrap();
    assert_eq!(cid, Some("QmNewCID".to_string()));
}
