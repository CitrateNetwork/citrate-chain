// coverage_98.rs — WP-RR.9: Comprehensive integration tests targeting 98% coverage
//
// Focus areas:
//   1. Model registration, lookup, and update (ModelRegistry with StorageManager)
//   2. Execution request creation and status updates
//   3. GGUF engine: config, model path, embedding parse, chat prompt, cosine similarity
//   4. Verification edge cases: nonce boundaries, standalone proof, IO commitment
//   5. Cache: eviction ordering, preload overflow, stats accuracy
//   6. Execution types: Model, TrainingMetrics, gas estimation
//   7. ModelMetadata architecture field default deserialization

use citrate_mcp::cache::ModelCache;
use citrate_mcp::execution::{Model, TrainingMetrics};
use citrate_mcp::gguf_engine::{
    cosine_similarity, ChatMessage, GGUFEngine, GGUFEngineConfig, ModelType,
};
use citrate_mcp::provider::ProviderRegistry;
use citrate_mcp::registry::ModelRegistry;
use citrate_mcp::types::{
    ComputeCapacity, ComputeRequirements, Currency, ExecutionProof, ExecutionRequest,
    HardwareType, ModelId, ModelMetadata, PricingModel, ProviderInfo, RequestId, RequestStatus,
};
use citrate_mcp::verification::ExecutionVerifier;

use citrate_execution::{Address, Hash};
use primitive_types::U256;
use sha3::{Digest, Sha3_256};
use std::sync::Arc;

// =============================================================================
// Helpers
// =============================================================================

fn make_storage() -> Arc<citrate_storage::StorageManager> {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let pruning = citrate_storage::pruning::PruningConfig::default();
    Arc::new(
        citrate_storage::StorageManager::new(tmp.path(), pruning)
            .expect("create StorageManager"),
    )
}

fn make_model_metadata(name: &str, size: u64, hash_byte: u8) -> ModelMetadata {
    ModelMetadata {
        id: ModelId([0u8; 32]),
        owner: Address([1u8; 20]),
        name: name.to_string(),
        version: "1.0.0".to_string(),
        hash: Hash::new([hash_byte; 32]),
        size,
        architecture: vec![0x47, 0x47, 0x55, 0x46],
        compute_requirements: ComputeRequirements {
            min_memory: 1024,
            min_compute: 10,
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

fn make_model(id_byte: u8) -> Model {
    Model {
        id: ModelId([id_byte; 32]),
        architecture: vec![0x47, 0x47, 0x55, 0x46],
        weights: vec![1, 2, 3, 4, 5],
        metadata: b"{}".to_vec(),
    }
}

fn make_provider_info(id: u8, memory_gb: u64, compute: u64) -> ProviderInfo {
    let mut addr = [0u8; 20];
    addr[0] = id;
    ProviderInfo {
        address: Address(addr),
        name: format!("Provider {}", id),
        endpoint: format!("http://p{}.test", id),
        capacity: ComputeCapacity {
            total_memory: memory_gb * 1024 * 1024 * 1024,
            available_memory: memory_gb * 1024 * 1024 * 1024 / 2,
            total_compute: compute,
            available_compute: compute / 2,
            hardware: vec![HardwareType::CPU],
        },
        reputation: 100,
        total_executions: 0,
    }
}

/// Build a valid legacy commitment proof for a given model, input, output.
fn build_valid_proof(model: &Model, input: &[u8], output: &[u8]) -> ExecutionProof {
    let model_hash = {
        let mut h = Sha3_256::new();
        h.update(&model.architecture);
        h.update(&model.weights);
        h.update(&model.metadata);
        Hash::new(h.finalize().into())
    };
    let input_hash = {
        let mut h = Sha3_256::new();
        h.update(input);
        Hash::new(h.finalize().into())
    };
    let output_hash = {
        let mut h = Sha3_256::new();
        h.update(output);
        Hash::new(h.finalize().into())
    };
    let io_commitment = {
        let mut h = Sha3_256::new();
        h.update(input_hash.as_bytes());
        h.update(output_hash.as_bytes());
        Hash::new(h.finalize().into())
    };

    let statement = b"test statement".to_vec();
    let response = [0x42u8; 32];
    let commitment = {
        let mut h = Sha3_256::new();
        h.update(&statement);
        h.update(response);
        h.finalize()
    };

    let mut proof_data = commitment.to_vec();
    proof_data.extend_from_slice(&response);

    ExecutionProof {
        model_hash,
        input_hash,
        output_hash,
        io_commitment,
        statement,
        proof_data,
        timestamp: chrono::Utc::now().timestamp() as u64,
        provider: Address([0u8; 20]),
    }
}

// =============================================================================
// 1. ModelRegistry — registration, lookup, update, requests
// =============================================================================

#[tokio::test]
async fn test_registry_register_and_get_model() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let meta = make_model_metadata("test-model-1", 5000, 0xAA);
    let providers = vec![Address([10u8; 20])];

    let model_id = registry
        .register(meta.clone(), providers, Some("QmTest123".into()))
        .await
        .unwrap();

    // get_model returns metadata
    let retrieved = registry.get_model(&model_id).await.unwrap();
    assert_eq!(retrieved.name, "test-model-1");
    assert_eq!(retrieved.size, 5000);
}

#[tokio::test]
async fn test_registry_get_record_includes_weight_cid() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let meta = make_model_metadata("model-cid", 1000, 0xBB);
    let providers = vec![Address([20u8; 20])];
    let model_id = registry
        .register(meta, providers, Some("QmWeightCid".into()))
        .await
        .unwrap();

    let record = registry.get_record(&model_id).await.unwrap();
    assert_eq!(record.weight_cid, Some("QmWeightCid".into()));
    assert_eq!(record.total_executions, 0);
    assert_eq!(record.success_rate, 100.0);
}

#[tokio::test]
async fn test_registry_register_duplicate_fails() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let meta = make_model_metadata("dup-model", 1000, 0xCC);
    let providers = vec![Address([30u8; 20])];

    // First registration succeeds
    registry
        .register(meta.clone(), providers.clone(), None)
        .await
        .unwrap();

    // Second registration with same hash should fail
    let result = registry.register(meta, providers, None).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("already registered"));
}

#[tokio::test]
async fn test_registry_validate_empty_name() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let mut meta = make_model_metadata("", 1000, 0xDD);
    meta.name = String::new();

    let result = registry.register(meta, vec![], None).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("name cannot be empty"));
}

#[tokio::test]
async fn test_registry_validate_zero_size() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let meta = make_model_metadata("zero-size", 0, 0xEE);

    let result = registry.register(meta, vec![], None).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("size cannot be zero"));
}

#[tokio::test]
async fn test_registry_validate_zero_min_memory() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let mut meta = make_model_metadata("no-mem", 1000, 0x11);
    meta.compute_requirements.min_memory = 0;

    let result = registry.register(meta, vec![], None).await;
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Minimum memory requirement cannot be zero"));
}

#[tokio::test]
async fn test_registry_update_weight() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let meta = make_model_metadata("update-weight", 1000, 0x22);
    let model_id = registry
        .register(meta, vec![Address([40u8; 20])], None)
        .await
        .unwrap();

    // Initially no weight CID
    let cid = registry.get_weight_cid(&model_id).await.unwrap();
    assert!(cid.is_none());

    // Update weight
    registry
        .update_weight(&model_id, "QmNewWeight".into())
        .await
        .unwrap();

    let cid = registry.get_weight_cid(&model_id).await.unwrap();
    assert_eq!(cid, Some("QmNewWeight".into()));
}

#[tokio::test]
async fn test_registry_update_weight_nonexistent_model() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let result = registry
        .update_weight(&ModelId([0xFF; 32]), "QmTest".into())
        .await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Model not found"));
}

#[tokio::test]
async fn test_registry_get_model_not_found() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let result = registry.get_model(&ModelId([0xFF; 32])).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Model not found"));
}

#[tokio::test]
async fn test_registry_get_providers() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let provider1 = Address([50u8; 20]);
    let provider2 = Address([51u8; 20]);
    let meta = make_model_metadata("multi-provider", 1000, 0x33);
    let model_id = registry
        .register(meta, vec![provider1, provider2], None)
        .await
        .unwrap();

    let providers = registry.get_providers(&model_id).await.unwrap();
    assert_eq!(providers.len(), 2);
    assert!(providers.contains(&provider1));
    assert!(providers.contains(&provider2));
}

#[tokio::test]
async fn test_registry_get_providers_not_found() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let result = registry.get_providers(&ModelId([0xAA; 32])).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("No providers"));
}

// =============================================================================
// 2. Execution requests
// =============================================================================

#[tokio::test]
async fn test_registry_create_request() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let provider = Address([60u8; 20]);
    let meta = make_model_metadata("request-model", 1000, 0x44);
    let model_id = registry
        .register(meta, vec![provider], None)
        .await
        .unwrap();

    let requester = Address([70u8; 20]);
    let input_hash = Hash::new([0xBB; 32]);
    let request_id = registry
        .create_request(model_id, input_hash, requester, U256::from(1000))
        .await
        .unwrap();

    // Request ID should be a valid 32-byte identifier
    assert_ne!(request_id.0, [0u8; 32]);
}

#[tokio::test]
async fn test_registry_create_request_model_not_found() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let result = registry
        .create_request(
            ModelId([0xFF; 32]),
            Hash::new([1u8; 32]),
            Address([2u8; 20]),
            U256::from(100),
        )
        .await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Model not found"));
}

#[tokio::test]
async fn test_registry_create_request_no_providers() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    // Register model with empty providers list
    let meta = make_model_metadata("no-provider-model", 1000, 0x55);
    let model_id = registry.register(meta, vec![], None).await.unwrap();

    let result = registry
        .create_request(
            model_id,
            Hash::new([1u8; 32]),
            Address([2u8; 20]),
            U256::from(100),
        )
        .await;
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("No providers available"));
}

#[tokio::test]
async fn test_registry_update_request_status_completed() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let provider = Address([80u8; 20]);
    let meta = make_model_metadata("status-model", 1000, 0x66);
    let model_id = registry
        .register(meta, vec![provider], None)
        .await
        .unwrap();

    let request_id = registry
        .create_request(
            model_id,
            Hash::new([1u8; 32]),
            Address([2u8; 20]),
            U256::from(100),
        )
        .await
        .unwrap();

    // Check initial execution count is 0
    let record_before = registry.get_record(&model_id).await.unwrap();
    assert_eq!(record_before.total_executions, 0);

    // Update to Completed
    let result_hash = Hash::new([0xCC; 32]);
    registry
        .update_request_status(request_id, RequestStatus::Completed(result_hash))
        .await
        .unwrap();

    // total_executions should increment
    let record_after = registry.get_record(&model_id).await.unwrap();
    assert_eq!(record_after.total_executions, 1);
}

#[tokio::test]
async fn test_registry_update_request_status_failed() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let meta = make_model_metadata("fail-model", 1000, 0x77);
    let model_id = registry
        .register(meta, vec![Address([90u8; 20])], None)
        .await
        .unwrap();

    let request_id = registry
        .create_request(
            model_id,
            Hash::new([1u8; 32]),
            Address([2u8; 20]),
            U256::from(100),
        )
        .await
        .unwrap();

    // Update to Failed — should NOT increment total_executions
    registry
        .update_request_status(request_id, RequestStatus::Failed("timeout".into()))
        .await
        .unwrap();

    let record = registry.get_record(&model_id).await.unwrap();
    assert_eq!(record.total_executions, 0);
}

#[tokio::test]
async fn test_registry_update_request_status_not_found() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let result = registry
        .update_request_status(RequestId([0xFF; 32]), RequestStatus::Cancelled)
        .await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Request not found"));
}

// =============================================================================
// 3. GGUF Engine
// =============================================================================

#[test]
fn test_gguf_config_default() {
    let config = GGUFEngineConfig::default();
    assert!(config.context_size > 0);
    assert!(config.threads > 0);
    assert!(config.models_dir.to_str().unwrap().contains(".citrate/models"));
}

#[test]
fn test_gguf_engine_new_with_tempdir() {
    let tmp = tempfile::tempdir().unwrap();
    let config = GGUFEngineConfig {
        llama_cpp_path: tmp.path().to_path_buf(),
        models_dir: tmp.path().join("models"),
        threads: 4,
        context_size: 2048,
    };

    // Should succeed (creates models dir)
    let engine = GGUFEngine::new(config).unwrap();
    assert!(tmp.path().join("models").exists());

    // Test get_ipfs_model_path
    let path = engine.get_ipfs_model_path("abc123");
    assert!(path.to_str().unwrap().contains("abc123.gguf"));
}

#[tokio::test]
async fn test_gguf_load_model_from_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let config = GGUFEngineConfig {
        llama_cpp_path: tmp.path().to_path_buf(),
        models_dir: tmp.path().join("models"),
        threads: 2,
        context_size: 1024,
    };
    let engine = GGUFEngine::new(config).unwrap();

    let model_bytes = b"GGUF fake model data for testing";
    let path = engine
        .load_model_from_bytes("test_model", model_bytes)
        .await
        .unwrap();

    assert!(path.exists());
    assert!(path.to_str().unwrap().contains("test_model.gguf"));

    // Loading again with same size should return cached path
    let path2 = engine
        .load_model_from_bytes("test_model", model_bytes)
        .await
        .unwrap();
    assert_eq!(path, path2);
}

#[tokio::test]
async fn test_gguf_load_model_different_size_overwrites() {
    let tmp = tempfile::tempdir().unwrap();
    let config = GGUFEngineConfig {
        llama_cpp_path: tmp.path().to_path_buf(),
        models_dir: tmp.path().join("models"),
        threads: 2,
        context_size: 1024,
    };
    let engine = GGUFEngine::new(config).unwrap();

    let model_v1 = b"version 1 data";
    let path1 = engine
        .load_model_from_bytes("evolving_model", model_v1)
        .await
        .unwrap();
    assert!(path1.exists());

    // Different size should overwrite
    let model_v2 = b"version 2 data with more content";
    let path2 = engine
        .load_model_from_bytes("evolving_model", model_v2)
        .await
        .unwrap();
    assert_eq!(path1, path2); // Same path, different content

    let content = tokio::fs::read(&path2).await.unwrap();
    assert_eq!(content, model_v2);
}

#[test]
fn test_gguf_find_llama_binary_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let config = GGUFEngineConfig {
        llama_cpp_path: tmp.path().to_path_buf(),
        models_dir: tmp.path().join("models"),
        threads: 2,
        context_size: 1024,
    };
    let engine = GGUFEngine::new(config).unwrap();

    // generate_text/generate_embeddings would fail trying to find binary
    // We test this by checking the error message pattern
    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(engine.generate_text(
        std::path::Path::new("/nonexistent/model.gguf"),
        "test",
        10,
        0.7,
    ));
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));
}

#[test]
fn test_gguf_model_type_variants() {
    // Verify ModelType enum values
    assert_eq!(ModelType::Embedding, ModelType::Embedding);
    assert_eq!(ModelType::TextGeneration, ModelType::TextGeneration);
    assert_ne!(ModelType::Embedding, ModelType::TextGeneration);

    // Debug formatting
    assert!(format!("{:?}", ModelType::Embedding).contains("Embedding"));
    assert!(format!("{:?}", ModelType::TextGeneration).contains("TextGeneration"));
}

#[test]
fn test_chat_message_serialization() {
    let msg = ChatMessage {
        role: "user".to_string(),
        content: "Hello, world!".to_string(),
    };

    let json = serde_json::to_string(&msg).unwrap();
    let recovered: ChatMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(recovered.role, "user");
    assert_eq!(recovered.content, "Hello, world!");
}

#[test]
fn test_chat_message_all_roles_serialization() {
    // Test chat messages for all roles serialize correctly
    // (format_chat_prompt is private; tested via unit tests in gguf_engine.rs)
    for role in ["system", "user", "assistant", "custom_role"] {
        let msg = ChatMessage {
            role: role.to_string(),
            content: format!("Content for {}", role),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let recovered: ChatMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.role, role);
        assert!(recovered.content.contains(role));
    }
}

#[tokio::test]
async fn test_chat_completion_fails_without_binary() {
    // chat_completion exercises format_chat_prompt internally, then calls generate_text
    // which fails because no llama.cpp binary exists
    let tmp = tempfile::tempdir().unwrap();
    let config = GGUFEngineConfig {
        llama_cpp_path: tmp.path().to_path_buf(),
        models_dir: tmp.path().join("models"),
        threads: 2,
        context_size: 1024,
    };
    let engine = GGUFEngine::new(config).unwrap();

    let messages = vec![
        ChatMessage {
            role: "system".to_string(),
            content: "You are helpful".to_string(),
        },
        ChatMessage {
            role: "user".to_string(),
            content: "Hello".to_string(),
        },
    ];

    let result = engine
        .chat_completion(std::path::Path::new("/fake/model.gguf"), &messages, 10, 0.7)
        .await;
    assert!(result.is_err());
    // The error comes from find_llama_binary failing
    assert!(result.unwrap_err().to_string().contains("not found"));
}

// =============================================================================
// 4. Cosine similarity edge cases
// =============================================================================

#[test]
fn test_cosine_similarity_identical_vectors() {
    let a = vec![1.0, 2.0, 3.0];
    let sim = cosine_similarity(&a, &a);
    assert!((sim - 1.0).abs() < 1e-6);
}

#[test]
fn test_cosine_similarity_orthogonal_vectors() {
    let a = vec![1.0, 0.0];
    let b = vec![0.0, 1.0];
    let sim = cosine_similarity(&a, &b);
    assert!(sim.abs() < 1e-6);
}

#[test]
fn test_cosine_similarity_opposite_vectors() {
    let a = vec![1.0, 2.0, 3.0];
    let b = vec![-1.0, -2.0, -3.0];
    let sim = cosine_similarity(&a, &b);
    assert!((sim + 1.0).abs() < 1e-6);
}

#[test]
fn test_cosine_similarity_different_lengths() {
    let a = vec![1.0, 2.0];
    let b = vec![1.0, 2.0, 3.0];
    let sim = cosine_similarity(&a, &b);
    assert_eq!(sim, 0.0);
}

#[test]
fn test_cosine_similarity_zero_vector() {
    let a = vec![0.0, 0.0, 0.0];
    let b = vec![1.0, 2.0, 3.0];
    let sim = cosine_similarity(&a, &b);
    assert_eq!(sim, 0.0);
}

#[test]
fn test_cosine_similarity_both_zero() {
    let a = vec![0.0, 0.0];
    let b = vec![0.0, 0.0];
    let sim = cosine_similarity(&a, &b);
    assert_eq!(sim, 0.0);
}

#[test]
fn test_cosine_similarity_empty_vectors() {
    let a: Vec<f32> = vec![];
    let b: Vec<f32> = vec![];
    let sim = cosine_similarity(&a, &b);
    // Both empty, same length (0), dot product = 0, magnitudes = 0 => returns 0.0
    assert_eq!(sim, 0.0);
}

#[test]
fn test_cosine_similarity_single_element() {
    let a = vec![5.0];
    let b = vec![3.0];
    let sim = cosine_similarity(&a, &b);
    assert!((sim - 1.0).abs() < 1e-6); // Same direction
}

// =============================================================================
// 5. Verification edge cases
// =============================================================================

#[test]
fn test_verify_model_valid_with_architecture() {
    let verifier = ExecutionVerifier::new();
    let model = Model {
        id: ModelId([1u8; 32]),
        architecture: vec![0x47, 0x47, 0x55, 0x46],
        weights: vec![1, 2, 3],
        metadata: b"{}".to_vec(),
    };
    assert!(verifier.verify_model(&model).is_ok());
}

#[test]
fn test_verify_model_max_size_boundary() {
    // Set a very specific max size and test boundary
    std::env::set_var("CITRATE_MAX_MODEL_SIZE", "100");
    let verifier = ExecutionVerifier::new();

    // Exactly at limit — should pass
    let model_at_limit = Model {
        id: ModelId([1u8; 32]),
        architecture: vec![1],
        weights: vec![0u8; 100],
        metadata: b"m".to_vec(),
    };
    assert!(verifier.verify_model(&model_at_limit).is_ok());

    // One byte over limit — should fail
    let model_over = Model {
        id: ModelId([1u8; 32]),
        architecture: vec![1],
        weights: vec![0u8; 101],
        metadata: b"m".to_vec(),
    };
    let result = verifier.verify_model(&model_over);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("too large"));

    std::env::remove_var("CITRATE_MAX_MODEL_SIZE");
}

#[test]
fn test_verify_execution_io_commitment_mismatch() {
    let verifier = ExecutionVerifier::new();
    let model = make_model(1);
    let input = b"input";
    let output = b"output";
    let mut proof = build_valid_proof(&model, input, output);

    // Corrupt the IO commitment
    proof.io_commitment = Hash::new([0xFF; 32]);

    let result = verifier
        .verify_execution(&model, input, output, &proof)
        .unwrap();
    assert!(!result, "IO commitment mismatch should fail");
}

#[test]
fn test_verify_batch_all_valid() {
    let verifier = ExecutionVerifier::new();
    let model = make_model(1);

    let proof1 = build_valid_proof(&model, b"in1", b"out1");
    let proof2 = build_valid_proof(&model, b"in2", b"out2");

    let results = verifier.verify_batch(&[proof1, proof2]).unwrap();
    assert_eq!(results.len(), 2);
    assert!(results[0]);
    assert!(results[1]);
}

#[test]
fn test_verify_batch_single_invalid() {
    let verifier = ExecutionVerifier::new();

    let invalid_proof = ExecutionProof {
        model_hash: Hash::default(), // zero — fails standalone
        input_hash: Hash::new([1u8; 32]),
        output_hash: Hash::new([2u8; 32]),
        io_commitment: Hash::default(),
        statement: vec![],
        proof_data: vec![],
        timestamp: chrono::Utc::now().timestamp() as u64,
        provider: Address([0u8; 20]),
    };

    let results = verifier.verify_batch(&[invalid_proof]).unwrap();
    assert_eq!(results.len(), 1);
    assert!(!results[0]);
}

#[test]
fn test_verify_proof_standalone_zero_input_hash() {
    let verifier = ExecutionVerifier::new();

    let proof = ExecutionProof {
        model_hash: Hash::new([1u8; 32]),
        input_hash: Hash::default(), // zero
        output_hash: Hash::new([2u8; 32]),
        io_commitment: Hash::default(),
        statement: vec![],
        proof_data: vec![],
        timestamp: chrono::Utc::now().timestamp() as u64,
        provider: Address([0u8; 20]),
    };

    let results = verifier.verify_batch(&[proof]).unwrap();
    assert!(!results[0], "Zero input hash should fail standalone");
}

#[test]
fn test_verify_proof_standalone_zero_output_hash() {
    let verifier = ExecutionVerifier::new();

    let proof = ExecutionProof {
        model_hash: Hash::new([1u8; 32]),
        input_hash: Hash::new([2u8; 32]),
        output_hash: Hash::default(), // zero
        io_commitment: Hash::default(),
        statement: vec![],
        proof_data: vec![],
        timestamp: chrono::Utc::now().timestamp() as u64,
        provider: Address([0u8; 20]),
    };

    let results = verifier.verify_batch(&[proof]).unwrap();
    assert!(!results[0], "Zero output hash should fail standalone");
}

#[test]
fn test_verify_proof_standalone_io_commitment_mismatch() {
    let verifier = ExecutionVerifier::new();

    let input_hash = Hash::new([1u8; 32]);
    let output_hash = Hash::new([2u8; 32]);
    // Incorrect IO commitment (should be H(input_hash || output_hash))
    let wrong_commitment = Hash::new([99u8; 32]);

    let proof = ExecutionProof {
        model_hash: Hash::new([3u8; 32]),
        input_hash,
        output_hash,
        io_commitment: wrong_commitment,
        statement: vec![],
        proof_data: vec![],
        timestamp: chrono::Utc::now().timestamp() as u64,
        provider: Address([0u8; 20]),
    };

    let results = verifier.verify_batch(&[proof]).unwrap();
    assert!(!results[0], "Wrong IO commitment should fail standalone");
}

#[test]
fn test_verification_key_data_length() {
    let verifier = ExecutionVerifier::new();
    let model = make_model(1);

    let vk = verifier.generate_verification_key(&model).unwrap();

    // Key data should be exactly 64 bytes (base_key 32 + final_key 32)
    assert_eq!(vk.key_data.len(), 64);
    assert_ne!(vk.model_hash, Hash::default());
    assert!(vk.created_at > 0);
}

#[test]
fn test_verification_key_model_hash_consistency() {
    let verifier = ExecutionVerifier::new();
    let model = make_model(5);

    let vk1 = verifier.generate_verification_key(&model).unwrap();
    let vk2 = verifier.generate_verification_key(&model).unwrap();

    // Deterministic
    assert_eq!(vk1.model_hash, vk2.model_hash);
    assert_eq!(vk1.key_data, vk2.key_data);
}

// =============================================================================
// 6. Nonce-enhanced commitment proof boundary tests
// =============================================================================

/// Build a complete ExecutionProof with nonce-enhanced proof_data
/// that will pass model/input/output hash checks so we can test the
/// commitment verification path via the public verify_execution API.
fn build_execution_proof_with_nonce(
    model: &Model,
    input: &[u8],
    output: &[u8],
    nonce_ts: u64,
) -> ExecutionProof {
    let model_hash = {
        let mut h = Sha3_256::new();
        h.update(&model.architecture);
        h.update(&model.weights);
        h.update(&model.metadata);
        Hash::new(h.finalize().into())
    };
    let input_hash = {
        let mut h = Sha3_256::new();
        h.update(input);
        Hash::new(h.finalize().into())
    };
    let output_hash = {
        let mut h = Sha3_256::new();
        h.update(output);
        Hash::new(h.finalize().into())
    };
    let io_commitment = {
        let mut h = Sha3_256::new();
        h.update(input_hash.as_bytes());
        h.update(output_hash.as_bytes());
        Hash::new(h.finalize().into())
    };

    let statement = b"nonce test statement".to_vec();
    let response = [0xAA; 32];
    let nonce_bytes = nonce_ts.to_le_bytes();

    // commitment = H(statement || response || nonce)
    let commitment = {
        let mut h = Sha3_256::new();
        h.update(&statement);
        h.update(&response);
        h.update(&nonce_bytes);
        h.finalize()
    };

    let mut proof_data = Vec::with_capacity(72);
    proof_data.extend_from_slice(&commitment);
    proof_data.extend_from_slice(&response);
    proof_data.extend_from_slice(&nonce_bytes);

    ExecutionProof {
        model_hash,
        input_hash,
        output_hash,
        io_commitment,
        statement,
        proof_data,
        timestamp: chrono::Utc::now().timestamp() as u64,
        provider: Address([0u8; 20]),
    }
}

#[test]
fn test_nonce_proof_at_5min_boundary() {
    let verifier = ExecutionVerifier::new();
    let model = make_model(1);
    let input = b"boundary input";
    let output = b"boundary output";
    // Just within 5-minute window (299 seconds ago)
    let ts = chrono::Utc::now().timestamp() as u64 - 299;
    let proof = build_execution_proof_with_nonce(&model, input, output, ts);

    let result = verifier.verify_execution(&model, input, output, &proof);
    assert!(result.unwrap(), "Nonce at 299s old should still be valid");
}

#[test]
fn test_nonce_proof_just_within_future_tolerance() {
    let verifier = ExecutionVerifier::new();
    let model = make_model(2);
    let input = b"future input";
    let output = b"future output";
    // 59 seconds in the future (within 60s tolerance)
    let ts = chrono::Utc::now().timestamp() as u64 + 59;
    let proof = build_execution_proof_with_nonce(&model, input, output, ts);

    let result = verifier.verify_execution(&model, input, output, &proof);
    assert!(
        result.unwrap(),
        "Nonce 59s in future should be within tolerance"
    );
}

#[test]
fn test_nonce_proof_exactly_at_future_limit() {
    let verifier = ExecutionVerifier::new();
    let model = make_model(3);
    let input = b"limit input";
    let output = b"limit output";
    // 62 seconds in the future (beyond 60s tolerance)
    let ts = chrono::Utc::now().timestamp() as u64 + 62;
    let proof = build_execution_proof_with_nonce(&model, input, output, ts);

    let result = verifier.verify_execution(&model, input, output, &proof);
    assert!(
        !result.unwrap(),
        "Nonce 62s in future should exceed tolerance"
    );
}

#[test]
fn test_nonce_proof_with_extra_bytes_beyond_72() {
    let verifier = ExecutionVerifier::new();
    let model = make_model(4);
    let input = b"extra input";
    let output = b"extra output";
    let ts = chrono::Utc::now().timestamp() as u64;
    let mut proof = build_execution_proof_with_nonce(&model, input, output, ts);
    // Append extra bytes beyond 72 — nonce-enhanced path uses first 72 only
    proof.proof_data.extend_from_slice(&[0xFF; 100]);

    let result = verifier.verify_execution(&model, input, output, &proof);
    assert!(result.unwrap(), "Extra bytes beyond 72 should not affect verification");
}

// =============================================================================
// 7. Cache — eviction ordering and stats
// =============================================================================

#[tokio::test]
async fn test_cache_eviction_preserves_recently_accessed() {
    // Each make_model produces: arch(4) + weights(5) + metadata(2) + id(32) = 43 bytes
    // Cache that can hold exactly 2 models (86 bytes) but not 3 (129 bytes)
    let cache = ModelCache::new(90);

    let m1 = make_model(1);
    let m2 = make_model(2);
    let m3 = make_model(3);

    cache.put(ModelId([1u8; 32]), m1).await.unwrap();
    cache.put(ModelId([2u8; 32]), m2).await.unwrap();

    // Access m1 to make it recently used (moves to front of LRU)
    cache.get(&ModelId([1u8; 32])).await;

    // Adding m3 should evict m2 (LRU = least recently used), not m1
    cache.put(ModelId([3u8; 32]), m3).await.unwrap();

    assert!(
        cache.get(&ModelId([1u8; 32])).await.is_some(),
        "Recently accessed m1 should survive eviction"
    );
    assert!(
        cache.get(&ModelId([2u8; 32])).await.is_none(),
        "LRU m2 should be evicted"
    );
    assert!(cache.get(&ModelId([3u8; 32])).await.is_some());
}

#[tokio::test]
async fn test_cache_stats_after_operations() {
    let cache = ModelCache::new(100_000);

    let stats = cache.stats().await;
    assert_eq!(stats.total_models, 0);
    assert_eq!(stats.current_size, 0);
    assert_eq!(stats.utilization, 0.0);
    assert_eq!(stats.total_accesses, 0);

    let m1 = make_model(1);
    cache.put(ModelId([1u8; 32]), m1).await.unwrap();

    // Access 3 times
    cache.get(&ModelId([1u8; 32])).await;
    cache.get(&ModelId([1u8; 32])).await;
    cache.get(&ModelId([1u8; 32])).await;

    let stats = cache.stats().await;
    assert_eq!(stats.total_models, 1);
    assert!(stats.current_size > 0);
    assert!(stats.utilization > 0.0);
    assert!(stats.utilization < 100.0);
    // 1 from put + 3 gets = 4 total accesses
    assert!(stats.total_accesses >= 4);
}

#[tokio::test]
async fn test_cache_preload_multiple_models() {
    let cache = ModelCache::new(100_000);

    let models: Vec<(ModelId, Model)> = (10..15u8)
        .map(|i| (ModelId([i; 32]), make_model(i)))
        .collect();

    cache.preload(models).await.unwrap();

    let stats = cache.stats().await;
    assert_eq!(stats.total_models, 5);

    for i in 10..15u8 {
        assert!(cache.get(&ModelId([i; 32])).await.is_some());
    }
}

#[tokio::test]
async fn test_cache_preload_model_too_large() {
    let cache = ModelCache::new(10); // Tiny cache

    let large_model = Model {
        id: ModelId([1u8; 32]),
        architecture: vec![0; 100],
        weights: vec![0; 100],
        metadata: vec![0; 100],
    };

    let result = cache.preload(vec![(ModelId([1u8; 32]), large_model)]).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_cache_remove_updates_size() {
    let cache = ModelCache::new(100_000);

    let m = make_model(1);
    cache.put(ModelId([1u8; 32]), m).await.unwrap();

    let stats_before = cache.stats().await;
    assert!(stats_before.current_size > 0);

    cache.remove(&ModelId([1u8; 32])).await;

    let stats_after = cache.stats().await;
    assert_eq!(stats_after.current_size, 0);
    assert_eq!(stats_after.total_models, 0);
}

#[tokio::test]
async fn test_cache_clear_resets_everything() {
    let cache = ModelCache::new(100_000);

    for i in 0..5u8 {
        cache.put(ModelId([i; 32]), make_model(i)).await.unwrap();
    }

    cache.clear().await;

    let stats = cache.stats().await;
    assert_eq!(stats.total_models, 0);
    assert_eq!(stats.current_size, 0);

    for i in 0..5u8 {
        assert!(cache.get(&ModelId([i; 32])).await.is_none());
    }
}

// =============================================================================
// 8. Execution types
// =============================================================================

#[test]
fn test_model_clone_and_debug() {
    let model = make_model(1);
    let cloned = model.clone();
    assert_eq!(cloned.id, model.id);
    assert_eq!(cloned.weights, model.weights);
    assert_eq!(cloned.architecture, model.architecture);

    let debug = format!("{:?}", model);
    assert!(debug.contains("Model"));
}

#[test]
fn test_training_metrics_debug() {
    let metrics = TrainingMetrics {
        loss: 0.05,
        accuracy: 0.95,
        epoch: 10,
    };
    let debug = format!("{:?}", metrics);
    assert!(debug.contains("0.05"));
    assert!(debug.contains("0.95"));
    assert!(debug.contains("10"));

    let cloned = metrics.clone();
    assert_eq!(cloned.loss, 0.05);
    assert_eq!(cloned.accuracy, 0.95);
    assert_eq!(cloned.epoch, 10);
}

#[test]
fn test_inference_result_debug() {
    use citrate_mcp::execution::InferenceResult;

    let proof = build_valid_proof(&make_model(1), b"in", b"out");
    let result = InferenceResult {
        output: vec![1, 2, 3],
        proof,
        gas_used: 100_000,
        latency_ms: 42,
        provider: Address([0xAA; 20]),
    };

    let debug = format!("{:?}", result);
    assert!(debug.contains("InferenceResult"));
    assert!(debug.contains("100000"));

    let cloned = result.clone();
    assert_eq!(cloned.gas_used, 100_000);
    assert_eq!(cloned.latency_ms, 42);
}

// =============================================================================
// 9. ModelMetadata architecture default deserialization
// =============================================================================

#[test]
fn test_model_metadata_architecture_default_on_missing_field() {
    // When deserializing JSON without the "architecture" field, it should
    // default to empty vec due to #[serde(default)]
    let json = r#"{
        "id": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        "owner": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
        "name": "test",
        "version": "1.0",
        "hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        "size": 100,
        "compute_requirements": {
            "min_memory": 1024,
            "min_compute": 10,
            "gpu_required": false,
            "supported_hardware": ["CPU"]
        },
        "pricing": {
            "base_price": "0x64",
            "per_token_price": "0x1",
            "per_second_price": "0xa",
            "currency": "SALT"
        }
    }"#;

    let meta: ModelMetadata = serde_json::from_str(json).unwrap();
    assert!(
        meta.architecture.is_empty(),
        "Missing architecture field should default to empty"
    );
    assert_eq!(meta.name, "test");
}

#[test]
fn test_model_metadata_with_architecture_field() {
    let meta = make_model_metadata("with-arch", 1000, 0x01);
    let json = serde_json::to_string(&meta).unwrap();
    let recovered: ModelMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(recovered.architecture, vec![0x47, 0x47, 0x55, 0x46]);
}

// =============================================================================
// 10. ModelRecord serialization (via bincode roundtrip)
// =============================================================================

#[test]
fn test_model_record_bincode_roundtrip() {
    use citrate_mcp::registry::ModelRecord;

    let meta = make_model_metadata("record-test", 2000, 0x88);
    let record = ModelRecord {
        metadata: meta,
        providers: vec![Address([1u8; 20]), Address([2u8; 20])],
        created_at: 1700000000,
        total_executions: 42,
        average_latency: 150,
        success_rate: 98.5,
        weight_cid: Some("QmTestCid123".into()),
    };

    let bytes = bincode::serialize(&record).unwrap();
    let recovered: ModelRecord = bincode::deserialize(&bytes).unwrap();

    assert_eq!(recovered.metadata.name, "record-test");
    assert_eq!(recovered.providers.len(), 2);
    assert_eq!(recovered.total_executions, 42);
    assert_eq!(recovered.average_latency, 150);
    assert_eq!(recovered.success_rate, 98.5);
    assert_eq!(recovered.weight_cid, Some("QmTestCid123".into()));
}

// =============================================================================
// 11. GGUF embeddings (exercises generate_embeddings path which uses
//     parse_embedding_output internally) and additional public API tests
// =============================================================================

#[tokio::test]
async fn test_generate_embeddings_fails_without_binary() {
    let tmp = tempfile::tempdir().unwrap();
    let config = GGUFEngineConfig {
        llama_cpp_path: tmp.path().to_path_buf(),
        models_dir: tmp.path().join("models"),
        threads: 2,
        context_size: 1024,
    };
    let engine = GGUFEngine::new(config).unwrap();

    let texts = vec!["Hello world".to_string()];
    let result = engine
        .generate_embeddings(std::path::Path::new("/fake/model.gguf"), &texts)
        .await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));
}

#[test]
fn test_gguf_engine_config_clone() {
    let config = GGUFEngineConfig::default();
    let cloned = config.clone();
    assert_eq!(cloned.context_size, config.context_size);
    assert_eq!(cloned.threads, config.threads);
    assert_eq!(cloned.models_dir, config.models_dir);
    assert_eq!(cloned.llama_cpp_path, config.llama_cpp_path);
}

#[test]
fn test_gguf_engine_config_debug() {
    let config = GGUFEngineConfig::default();
    let debug = format!("{:?}", config);
    assert!(debug.contains("GGUFEngineConfig"));
    assert!(debug.contains("context_size"));
}

#[test]
fn test_gguf_get_ipfs_model_path_various_ids() {
    let tmp = tempfile::tempdir().unwrap();
    let config = GGUFEngineConfig {
        llama_cpp_path: tmp.path().to_path_buf(),
        models_dir: tmp.path().join("models"),
        threads: 2,
        context_size: 1024,
    };
    let engine = GGUFEngine::new(config).unwrap();

    let path1 = engine.get_ipfs_model_path("model_abc");
    assert!(path1.to_str().unwrap().ends_with("model_abc.gguf"));

    let path2 = engine.get_ipfs_model_path("Qm123456");
    assert!(path2.to_str().unwrap().ends_with("Qm123456.gguf"));

    // Different model IDs produce different paths
    assert_ne!(path1, path2);
}

// =============================================================================
// 12. Execution type edge cases
// =============================================================================

#[test]
fn test_execution_request_status_all_variants_debug() {
    // Ensures all RequestStatus variants format without panic
    let statuses: Vec<RequestStatus> = vec![
        RequestStatus::Pending,
        RequestStatus::Assigned(Address([1u8; 20])),
        RequestStatus::Executing,
        RequestStatus::Completed(Hash::new([2u8; 32])),
        RequestStatus::Failed("something went wrong".into()),
        RequestStatus::Cancelled,
    ];

    for s in &statuses {
        let debug = format!("{:?}", s);
        assert!(!debug.is_empty());
    }
}

#[test]
fn test_execution_request_serialization_all_statuses() {
    let base = ExecutionRequest {
        id: RequestId([1u8; 32]),
        model_id: ModelId([2u8; 32]),
        input_hash: Hash::new([3u8; 32]),
        requester: Address([4u8; 20]),
        provider: Address([5u8; 20]),
        max_price: U256::from(999),
        status: RequestStatus::Pending,
        created_at: 100,
    };

    // Test serialization for each status variant
    for status in [
        RequestStatus::Pending,
        RequestStatus::Assigned(Address([6u8; 20])),
        RequestStatus::Executing,
        RequestStatus::Completed(Hash::new([7u8; 32])),
        RequestStatus::Failed("err".into()),
        RequestStatus::Cancelled,
    ] {
        let mut req = base.clone();
        req.status = status;
        let json = serde_json::to_string(&req).unwrap();
        let recovered: ExecutionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.created_at, 100);
    }
}

// =============================================================================
// 13. Provider score calculation edge cases
// =============================================================================

#[tokio::test]
async fn test_provider_score_new_provider_default() {
    let registry = ProviderRegistry::new();
    let model_id = ModelId([20u8; 32]);

    // Provider with no jobs
    let p = make_provider_info(1, 16, 100);
    registry.register_provider(p.clone()).await.unwrap();
    registry
        .register_model_provider(p.address, model_id)
        .await
        .unwrap();

    let requirements = ComputeRequirements {
        min_memory: 100,
        min_compute: 1,
        gpu_required: false,
        supported_hardware: vec![HardwareType::CPU],
    };

    // New provider should still be selectable
    let selected = registry.select_provider(&model_id, &requirements).await;
    assert!(selected.is_ok());
    assert_eq!(selected.unwrap(), p.address);
}

#[tokio::test]
async fn test_provider_latency_affects_score() {
    let registry = ProviderRegistry::new();
    let model_id = ModelId([21u8; 32]);

    // Fast provider
    let p_fast = make_provider_info(1, 16, 100);
    registry.register_provider(p_fast.clone()).await.unwrap();
    registry
        .register_model_provider(p_fast.address, model_id)
        .await
        .unwrap();
    // Low latency
    registry
        .update_reputation(p_fast.address, true, 10)
        .await
        .unwrap();

    // Slow provider (same capacity but higher latency)
    let p_slow = make_provider_info(2, 16, 100);
    registry.register_provider(p_slow.clone()).await.unwrap();
    registry
        .register_model_provider(p_slow.address, model_id)
        .await
        .unwrap();
    // High latency
    registry
        .update_reputation(p_slow.address, true, 10000)
        .await
        .unwrap();

    let requirements = ComputeRequirements {
        min_memory: 100,
        min_compute: 1,
        gpu_required: false,
        supported_hardware: vec![HardwareType::CPU],
    };

    let selected = registry.select_provider(&model_id, &requirements).await.unwrap();
    // Fast provider should win due to lower latency (higher latency score)
    assert_eq!(selected, p_fast.address);
}

// =============================================================================
// 14. Verification key derivation edge cases
// =============================================================================

#[test]
fn test_verification_key_large_model() {
    let verifier = ExecutionVerifier::new();
    let model = Model {
        id: ModelId([1u8; 32]),
        architecture: vec![0xAB; 1024],
        weights: vec![0xCD; 10_000],
        metadata: vec![0xEF; 500],
    };

    let vk = verifier.generate_verification_key(&model).unwrap();
    assert_eq!(vk.key_data.len(), 64);
    assert_ne!(vk.model_hash, Hash::default());
}

#[test]
fn test_verification_key_minimal_model() {
    let verifier = ExecutionVerifier::new();
    let model = Model {
        id: ModelId([1u8; 32]),
        architecture: vec![1],
        weights: vec![2],
        metadata: vec![3],
    };

    let vk = verifier.generate_verification_key(&model).unwrap();
    assert_eq!(vk.key_data.len(), 64);
}

#[test]
fn test_verifier_default_trait() {
    let v1 = ExecutionVerifier::new();
    let v2 = ExecutionVerifier::default();
    // Both should produce same verification for same model
    let model = make_model(1);
    let vk1 = v1.generate_verification_key(&model).unwrap();
    let vk2 = v2.generate_verification_key(&model).unwrap();
    assert_eq!(vk1.model_hash, vk2.model_hash);
    assert_eq!(vk1.key_data, vk2.key_data);
}

// =============================================================================
// 15. Registry persist/retrieve integration
// =============================================================================

#[tokio::test]
async fn test_registry_persist_and_retrieve_multiple() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    // Register multiple models
    let mut ids = Vec::new();
    for i in 0..5u8 {
        let meta = make_model_metadata(&format!("model-{}", i), 1000 + i as u64, i + 100);
        let model_id = registry
            .register(meta, vec![Address([i + 50; 20])], Some(format!("QmCid{}", i)))
            .await
            .unwrap();
        ids.push(model_id);
    }

    // Retrieve all and verify
    for (idx, id) in ids.iter().enumerate() {
        let meta = registry.get_model(id).await.unwrap();
        assert_eq!(meta.name, format!("model-{}", idx));
        assert_eq!(meta.size, 1000 + idx as u64);

        let cid = registry.get_weight_cid(id).await.unwrap();
        assert_eq!(cid, Some(format!("QmCid{}", idx)));
    }
}

#[tokio::test]
async fn test_registry_weight_cid_none_initially() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let meta = make_model_metadata("no-cid", 1000, 0x99);
    let model_id = registry.register(meta, vec![], None).await.unwrap();

    let cid = registry.get_weight_cid(&model_id).await.unwrap();
    assert!(cid.is_none());
}

#[tokio::test]
async fn test_registry_get_weight_cid_not_found() {
    let storage = make_storage();
    let registry = ModelRegistry::new(storage);

    let cid = registry.get_weight_cid(&ModelId([0xFF; 32])).await.unwrap();
    // Non-existent model returns None (not an error, just absence)
    assert!(cid.is_none());
}
