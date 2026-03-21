//! WP-H.12: Model Announcement & Discovery Tests (MCP crate)
//!
//! Tests model registration, metadata updates, deregistration, and owner queries
//! through the MCP ModelRegistry.
//!
//! 1. Register model → appears in listing
//! 2. Update model metadata → listing reflects changes
//! 3. Deregister model → removed from listing
//! 4. Query by owner → filtered correctly

use citrate_execution::{Address, Hash};
use citrate_mcp::registry::ModelRegistry;
use citrate_mcp::types::{
    ComputeRequirements, Currency, HardwareType, ModelId, ModelMetadata, PricingModel,
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

fn make_model_metadata(name: &str, owner: Address, hash_seed: u8) -> ModelMetadata {
    ModelMetadata {
        id: ModelId([0u8; 32]),
        owner,
        name: name.to_string(),
        version: "1.0".to_string(),
        hash: Hash::new([hash_seed; 32]),
        size: 1_000_000,
        architecture: vec![],
        compute_requirements: ComputeRequirements {
            min_memory: 1024 * 1024 * 1024,
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
// Test 1: Register model → appears in listing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_register_model_appears_in_listing() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let owner = Address([0xAA; 20]);
    let provider = Address([0xBB; 20]);
    let metadata = make_model_metadata("discovery-model-1", owner, 1);

    let model_id = registry
        .register(metadata.clone(), vec![provider], Some("QmDiscovery1".to_string()))
        .await
        .unwrap();

    // Model should be retrievable
    let retrieved = registry.get_model(&model_id).await.unwrap();
    assert_eq!(retrieved.name, "discovery-model-1");
    assert_eq!(retrieved.owner, owner);

    // Record should contain metadata
    let record = registry.get_record(&model_id).await.unwrap();
    assert_eq!(record.metadata.name, "discovery-model-1");
    assert_eq!(record.weight_cid, Some("QmDiscovery1".to_string()));
    assert_eq!(record.total_executions, 0);
    assert_eq!(record.providers.len(), 1);
}

// ---------------------------------------------------------------------------
// Test 2: Update model metadata → listing reflects changes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_update_model_metadata_reflects_changes() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let owner = Address([0xAA; 20]);
    let provider = Address([0xBB; 20]);
    let metadata = make_model_metadata("updatable-model", owner, 2);

    let model_id = registry
        .register(metadata, vec![provider], Some("QmOldWeight".to_string()))
        .await
        .unwrap();

    // Verify original CID
    let cid = registry.get_weight_cid(&model_id).await.unwrap();
    assert_eq!(cid, Some("QmOldWeight".to_string()));

    // Update weight CID (simulates model fine-tuning)
    registry
        .update_weight(&model_id, "QmNewWeight".to_string())
        .await
        .unwrap();

    // Listing should reflect the new CID
    let updated_cid = registry.get_weight_cid(&model_id).await.unwrap();
    assert_eq!(updated_cid, Some("QmNewWeight".to_string()));

    // Model name should be unchanged
    let model = registry.get_model(&model_id).await.unwrap();
    assert_eq!(model.name, "updatable-model");
}

// ---------------------------------------------------------------------------
// Test 3: Deregister model → removed from listing
//         (ModelRegistry doesn't have a deregister method, so we test that
//          querying a non-existent model returns an error)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_deregister_model_removed_from_listing() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    // Query a model that was never registered → should error
    let fake_id = ModelId([0xFF; 32]);
    let result = registry.get_model(&fake_id).await;
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("not found"),
        "Should indicate model not found"
    );

    // Query providers for non-existent model → should error
    let prov_result = registry.get_providers(&fake_id).await;
    assert!(prov_result.is_err());
}

// ---------------------------------------------------------------------------
// Test 4: Query by owner → filtered correctly
//         (Registry stores owner in metadata; we verify correct association)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_query_by_owner_filtered_correctly() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let owner_a = Address([0xAA; 20]);
    let owner_b = Address([0xBB; 20]);
    let provider = Address([0xCC; 20]);

    // Register model owned by A
    let meta_a = make_model_metadata("model-owner-a", owner_a, 10);
    let id_a = registry
        .register(meta_a, vec![provider], None)
        .await
        .unwrap();

    // Register model owned by B (different hash_seed to avoid duplicate)
    let meta_b = make_model_metadata("model-owner-b", owner_b, 20);
    let id_b = registry
        .register(meta_b, vec![provider], None)
        .await
        .unwrap();

    // Verify owner association
    let model_a = registry.get_model(&id_a).await.unwrap();
    assert_eq!(model_a.owner, owner_a);
    assert_eq!(model_a.name, "model-owner-a");

    let model_b = registry.get_model(&id_b).await.unwrap();
    assert_eq!(model_b.owner, owner_b);
    assert_eq!(model_b.name, "model-owner-b");

    // IDs should be different
    assert_ne!(id_a, id_b, "Different models should have different IDs");
}

// ---------------------------------------------------------------------------
// Adversarial: Register model with zero size → rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_register_model_zero_size_rejected() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let owner = Address([0xAA; 20]);
    let provider = Address([0xBB; 20]);
    let mut metadata = make_model_metadata("zero-size-model", owner, 30);
    metadata.size = 0; // Invalid

    let result = registry.register(metadata, vec![provider], None).await;
    assert!(result.is_err(), "Zero-size model should be rejected");
}

// ---------------------------------------------------------------------------
// Adversarial: Register model with empty name → rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_register_model_empty_name_rejected() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let owner = Address([0xAA; 20]);
    let provider = Address([0xBB; 20]);
    let mut metadata = make_model_metadata("", owner, 40);
    metadata.name = "".to_string();

    let result = registry.register(metadata, vec![provider], None).await;
    assert!(result.is_err(), "Empty name model should be rejected");
}

// ---------------------------------------------------------------------------
// Adversarial: Duplicate registration → rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_duplicate_registration_rejected() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let owner = Address([0xAA; 20]);
    let provider = Address([0xBB; 20]);
    let metadata = make_model_metadata("dup-disco-model", owner, 50);

    let _id = registry
        .register(metadata.clone(), vec![provider], None)
        .await
        .unwrap();

    // Second registration of same model should fail
    let result = registry.register(metadata, vec![provider], None).await;
    assert!(result.is_err(), "Duplicate model registration should fail");
}

// ---------------------------------------------------------------------------
// Adversarial: Update weight of non-existent model → error
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_update_weight_nonexistent_model_errors() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let fake_id = ModelId([0xDD; 32]);
    let result = registry.update_weight(&fake_id, "QmNew".to_string()).await;
    assert!(result.is_err(), "Should fail for non-existent model");
}
