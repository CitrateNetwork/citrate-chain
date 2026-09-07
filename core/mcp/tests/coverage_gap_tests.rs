// coverage_gap_tests.rs — tests targeting uncovered lines in citrate-mcp
//
// Covers: provider management, model verification, execution proof generation/verification,
// model metadata serialization, type edge cases, and cache operations.

use citrate_mcp::execution::Model;
use citrate_mcp::provider::ProviderRegistry;
use citrate_mcp::types::{
    ComputeCapacity, ComputeRequirements, Currency, ExecutionProof, ExecutionRequest,
    HardwareType, ModelId, ModelMetadata, PricingModel, ProviderInfo, RequestId, RequestStatus,
};
use citrate_mcp::verification::ExecutionVerifier;

use citrate_execution::{Address, Hash};
use primitive_types::U256;
use sha3::{Digest, Sha3_256};

// ---------------------------------------------------------------------------
// Helper constructors
// ---------------------------------------------------------------------------

fn make_model_metadata(name: &str, size: u64) -> ModelMetadata {
    ModelMetadata {
        id: ModelId([0u8; 32]),
        owner: Address([1u8; 20]),
        name: name.to_string(),
        version: "1.0.0".to_string(),
        hash: Hash::new([42u8; 32]),
        size,
        architecture: vec![0x47, 0x47, 0x55, 0x46], // GGUF magic
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

fn make_provider(id: u8, memory_gb: u64, compute: u64) -> ProviderInfo {
    let mut addr = [0u8; 20];
    addr[0] = id;
    ProviderInfo {
        address: Address(addr),
        name: format!("Provider {}", id),
        endpoint: format!("http://provider{}.example.com", id),
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

fn make_provider_with_gpu(id: u8, memory_gb: u64, compute: u64) -> ProviderInfo {
    let mut info = make_provider(id, memory_gb, compute);
    info.capacity.hardware = vec![
        HardwareType::CPU,
        HardwareType::GPU("NVIDIA A100".to_string()),
    ];
    info
}

fn make_test_model(id: u8) -> Model {
    Model {
        id: ModelId([id; 32]),
        architecture: vec![0x47, 0x47, 0x55, 0x46],
        weights: vec![1, 2, 3, 4, 5],
        metadata: b"{}".to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Provider registration and lookup
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_provider_registration() {
    let registry = ProviderRegistry::new();
    let provider = make_provider_with_gpu(1, 32, 200);

    registry.register_provider(provider.clone()).await.unwrap();

    let retrieved = registry.get_provider(&provider.address).await.unwrap();
    assert_eq!(retrieved.name, "Provider 1");
    assert_eq!(retrieved.endpoint, "http://provider1.example.com");

    // GPU should be in capabilities
    let has_gpu = retrieved
        .capacity
        .hardware
        .iter()
        .any(|h| matches!(h, HardwareType::GPU(_)));
    assert!(has_gpu);
}

// ---------------------------------------------------------------------------
// Provider selection by score — highest score selected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_provider_selection_by_score() {
    let registry = ProviderRegistry::new();
    let model_id = ModelId([1u8; 32]);

    // Register low-capacity provider
    let p1 = make_provider(1, 8, 50);
    registry.register_provider(p1.clone()).await.unwrap();
    registry
        .register_model_provider(p1.address, model_id)
        .await
        .unwrap();

    // Register high-capacity provider
    let p2 = make_provider(2, 64, 500);
    registry.register_provider(p2.clone()).await.unwrap();
    registry
        .register_model_provider(p2.address, model_id)
        .await
        .unwrap();

    // Give p2 successful jobs (improves reputation score)
    for _ in 0..5 {
        registry.update_reputation(p2.address, true, 50).await.unwrap();
    }

    let requirements = ComputeRequirements {
        min_memory: 1000,
        min_compute: 10,
        gpu_required: false,
        supported_hardware: vec![HardwareType::CPU],
    };

    let selected = registry.select_provider(&model_id, &requirements).await.unwrap();
    // Provider 2 should win due to higher capacity and better reputation
    assert_eq!(selected, p2.address);
}

// ---------------------------------------------------------------------------
// Provider deactivation (no providers for model after memory requirement filter)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_provider_deactivation_via_requirements() {
    let registry = ProviderRegistry::new();
    let model_id = ModelId([2u8; 32]);

    // Register a small provider
    let p = make_provider(1, 4, 50); // 4GB total, 2GB available
    registry.register_provider(p.clone()).await.unwrap();
    registry
        .register_model_provider(p.address, model_id)
        .await
        .unwrap();

    // Require more memory than available
    let requirements = ComputeRequirements {
        min_memory: 100 * 1024 * 1024 * 1024, // 100GB
        min_compute: 10,
        gpu_required: false,
        supported_hardware: vec![HardwareType::CPU],
    };

    let result = registry.select_provider(&model_id, &requirements).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("No suitable providers"));
}

// ---------------------------------------------------------------------------
// Execution proof generation and verification (via ExecutionVerifier)
// ---------------------------------------------------------------------------

#[test]
fn test_execution_proof_generation_and_verification() {
    let verifier = ExecutionVerifier::new();
    let model = make_test_model(1);
    let input = b"test input data";
    let output = b"test output data";

    // Generate proof components manually (mimicking ModelExecutor::generate_proof)
    // Note: hash_model in verification.rs hashes architecture + weights + metadata
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

    // Build statement
    let mut statement = Vec::new();
    statement.extend_from_slice(b"CITRATE_EXECUTION_V1");
    statement.extend_from_slice(model_hash.as_bytes());
    statement.extend_from_slice(input_hash.as_bytes());
    statement.extend_from_slice(output_hash.as_bytes());
    statement.extend_from_slice(io_commitment.as_bytes());

    let provider = Address([0xAA; 20]);

    // Generate response
    let response = {
        let mut h = Sha3_256::new();
        h.update(b"CITRATE_RESPONSE_V1");
        h.update(&statement);
        h.update(provider.0);
        h.update(0i64.to_le_bytes()); // fixed timestamp for determinism
        h.finalize()
    };

    // Compute commitment = H(statement || response) — legacy format
    let commitment = {
        let mut h = Sha3_256::new();
        h.update(&statement);
        h.update(response);
        h.finalize()
    };

    let mut proof_data = Vec::with_capacity(64);
    proof_data.extend_from_slice(&commitment);
    proof_data.extend_from_slice(&response);

    let proof = ExecutionProof {
        model_hash,
        input_hash,
        output_hash,
        io_commitment,
        statement,
        proof_data,
        timestamp: chrono::Utc::now().timestamp() as u64,
        provider,
    };

    // A hash commitment is not a real execution proof; verification fails closed.
    let result = verifier.verify_execution(&model, input, output, &proof).unwrap();
    assert!(!result, "legacy commitment must not verify as a real proof");
}

// ---------------------------------------------------------------------------
// Execution proof verification — invalid (tampered output)
// ---------------------------------------------------------------------------

#[test]
fn test_execution_proof_verification_invalid_output() {
    let verifier = ExecutionVerifier::new();
    let model = make_test_model(1);
    let input = b"test input";
    let output = b"real output";
    let tampered_output = b"tampered output";

    // Build a valid proof for the real output
    let model_hash = {
        let mut h = Sha3_256::new();
        h.update(&model.architecture);
        h.update(&model.weights);
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

    let mut statement = Vec::new();
    statement.extend_from_slice(b"CITRATE_EXECUTION_V1");
    statement.extend_from_slice(model_hash.as_bytes());
    statement.extend_from_slice(input_hash.as_bytes());
    statement.extend_from_slice(output_hash.as_bytes());
    statement.extend_from_slice(io_commitment.as_bytes());

    let response = {
        let mut h = Sha3_256::new();
        h.update(b"CITRATE_RESPONSE_V1");
        h.update(&statement);
        h.update([0u8; 20]);
        h.update(0i64.to_le_bytes());
        h.finalize()
    };
    let commitment = {
        let mut h = Sha3_256::new();
        h.update(&statement);
        h.update(response);
        h.finalize()
    };

    let mut proof_data = Vec::with_capacity(64);
    proof_data.extend_from_slice(&commitment);
    proof_data.extend_from_slice(&response);

    let proof = ExecutionProof {
        model_hash,
        input_hash,
        output_hash,
        io_commitment,
        statement,
        proof_data,
        timestamp: chrono::Utc::now().timestamp() as u64,
        provider: Address([0u8; 20]),
    };

    // Verify with tampered output — should fail
    let result = verifier
        .verify_execution(&model, input, tampered_output, &proof)
        .unwrap();
    assert!(!result, "Tampered output should fail verification");
}

// ---------------------------------------------------------------------------
// Model verification — empty weights rejected
// ---------------------------------------------------------------------------

#[test]
fn test_model_with_empty_weights_rejected() {
    let verifier = ExecutionVerifier::new();
    let model = Model {
        id: ModelId([1u8; 32]),
        architecture: vec![1, 2, 3],
        weights: vec![], // empty weights
        metadata: b"{}".to_vec(),
    };

    let result = verifier.verify_model(&model);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("weights are empty"));
}

// ---------------------------------------------------------------------------
// Model verification — empty metadata rejected
// ---------------------------------------------------------------------------

#[test]
fn test_model_with_empty_metadata_rejected() {
    let verifier = ExecutionVerifier::new();
    let model = Model {
        id: ModelId([1u8; 32]),
        architecture: vec![1, 2, 3],
        weights: vec![4, 5, 6],
        metadata: vec![], // empty
    };

    let result = verifier.verify_model(&model);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("metadata is empty"));
}

// ---------------------------------------------------------------------------
// Model with empty architecture + weights present => warning but ok
// ---------------------------------------------------------------------------

#[test]
fn test_model_with_empty_architecture_and_weights_present() {
    let verifier = ExecutionVerifier::new();
    let model = Model {
        id: ModelId([1u8; 32]),
        architecture: vec![], // empty architecture
        weights: vec![1, 2, 3, 4],
        metadata: b"{}".to_vec(),
    };

    // Should succeed with a warning (no error)
    let result = verifier.verify_model(&model);
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// Model with empty architecture AND empty weights => rejected
// ---------------------------------------------------------------------------

#[test]
fn test_model_with_no_architecture_and_no_weights_rejected() {
    let verifier = ExecutionVerifier::new();
    let model = Model {
        id: ModelId([1u8; 32]),
        architecture: vec![],
        weights: vec![],
        metadata: b"{}".to_vec(),
    };

    let result = verifier.verify_model(&model);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("neither architecture nor weights"));
}

// ---------------------------------------------------------------------------
// Model verification — valid model passes
// ---------------------------------------------------------------------------

#[test]
fn test_model_verification_valid() {
    let verifier = ExecutionVerifier::new();
    let model = make_test_model(1);

    let result = verifier.verify_model(&model);
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// Model metadata serialization roundtrip
// ---------------------------------------------------------------------------

#[test]
fn test_model_metadata_serialization_roundtrip() {
    let metadata = make_model_metadata("roundtrip-model", 5000);

    let json = serde_json::to_string(&metadata).expect("serialize ModelMetadata");
    let recovered: ModelMetadata = serde_json::from_str(&json).expect("deserialize ModelMetadata");

    assert_eq!(recovered.name, "roundtrip-model");
    assert_eq!(recovered.version, "1.0.0");
    assert_eq!(recovered.size, 5000);
    assert_eq!(recovered.compute_requirements.min_memory, 1024);
    assert_eq!(recovered.pricing.base_price, U256::from(100));
}

#[test]
fn test_model_metadata_bincode_roundtrip() {
    let metadata = make_model_metadata("bincode-test", 1000);

    let bytes = bincode::serialize(&metadata).expect("bincode serialize ModelMetadata");
    let recovered: ModelMetadata =
        bincode::deserialize(&bytes).expect("bincode deserialize ModelMetadata");

    assert_eq!(recovered.name, "bincode-test");
    assert_eq!(recovered.size, 1000);
}

// ---------------------------------------------------------------------------
// ExecutionProof serialization roundtrip
// ---------------------------------------------------------------------------

#[test]
fn test_execution_proof_serialization_roundtrip() {
    let proof = ExecutionProof {
        model_hash: Hash::new([1u8; 32]),
        input_hash: Hash::new([2u8; 32]),
        output_hash: Hash::new([3u8; 32]),
        io_commitment: Hash::new([4u8; 32]),
        statement: vec![5, 6, 7],
        proof_data: vec![8, 9, 10],
        timestamp: 1234567890,
        provider: Address([0xAA; 20]),
    };

    let json = serde_json::to_string(&proof).unwrap();
    let recovered: ExecutionProof = serde_json::from_str(&json).unwrap();

    assert_eq!(recovered.model_hash, proof.model_hash);
    assert_eq!(recovered.timestamp, 1234567890);
    assert_eq!(recovered.statement, vec![5, 6, 7]);
    assert_eq!(recovered.proof_data, vec![8, 9, 10]);
}

// ---------------------------------------------------------------------------
// Provider reputation tracking
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_provider_reputation_multiple_jobs() {
    let registry = ProviderRegistry::new();
    let provider = make_provider(1, 16, 100);
    let address = provider.address;

    registry.register_provider(provider).await.unwrap();

    // 3 successes, 1 failure
    registry.update_reputation(address, true, 100).await.unwrap();
    registry.update_reputation(address, true, 200).await.unwrap();
    registry.update_reputation(address, true, 150).await.unwrap();
    registry.update_reputation(address, false, 500).await.unwrap();

    let info = registry.get_provider(&address).await.unwrap();
    assert_eq!(info.total_executions, 4);
    assert_eq!(info.reputation, 75); // 3/4 = 75%
}

// ---------------------------------------------------------------------------
// Provider model provider — unregistered provider
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_register_model_provider_for_unregistered_provider() {
    let registry = ProviderRegistry::new();
    let address = Address([99u8; 20]);
    let model_id = ModelId([1u8; 32]);

    let result = registry.register_model_provider(address, model_id).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not registered"));
}

// ---------------------------------------------------------------------------
// Multiple providers for same model
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_multiple_providers_for_same_model() {
    let registry = ProviderRegistry::new();
    let model_id = ModelId([5u8; 32]);

    // Register 3 providers for same model
    for i in 1..=3u8 {
        let p = make_provider(i, 16, 100);
        registry.register_provider(p.clone()).await.unwrap();
        registry
            .register_model_provider(p.address, model_id)
            .await
            .unwrap();
    }

    let requirements = ComputeRequirements {
        min_memory: 1000,
        min_compute: 10,
        gpu_required: false,
        supported_hardware: vec![HardwareType::CPU],
    };

    // Should select one of them
    let selected = registry.select_provider(&model_id, &requirements).await;
    assert!(selected.is_ok());
}

// ---------------------------------------------------------------------------
// GPU requirement filter
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_gpu_requirement_filters_cpu_only() {
    let registry = ProviderRegistry::new();
    let model_id = ModelId([6u8; 32]);

    // Only CPU provider registered
    let p = make_provider(1, 32, 200);
    registry.register_provider(p.clone()).await.unwrap();
    registry
        .register_model_provider(p.address, model_id)
        .await
        .unwrap();

    let requirements = ComputeRequirements {
        min_memory: 1000,
        min_compute: 10,
        gpu_required: true,
        supported_hardware: vec![HardwareType::GPU("any".to_string())],
    };

    let result = registry.select_provider(&model_id, &requirements).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_gpu_requirement_selects_gpu_provider() {
    let registry = ProviderRegistry::new();
    let model_id = ModelId([7u8; 32]);

    // CPU provider
    let p1 = make_provider(1, 32, 200);
    registry.register_provider(p1.clone()).await.unwrap();
    registry
        .register_model_provider(p1.address, model_id)
        .await
        .unwrap();

    // GPU provider
    let p2 = make_provider_with_gpu(2, 32, 200);
    registry.register_provider(p2.clone()).await.unwrap();
    registry
        .register_model_provider(p2.address, model_id)
        .await
        .unwrap();

    let requirements = ComputeRequirements {
        min_memory: 1000,
        min_compute: 10,
        gpu_required: true,
        supported_hardware: vec![HardwareType::GPU("any".to_string())],
    };

    let selected = registry.select_provider(&model_id, &requirements).await.unwrap();
    assert_eq!(selected, p2.address);
}

// ---------------------------------------------------------------------------
// Verify batch proofs
// ---------------------------------------------------------------------------

#[test]
fn test_verify_batch_proofs() {
    let verifier = ExecutionVerifier::new();

    // Create two valid standalone proofs
    let input_hash1 = Hash::new([1u8; 32]);
    let output_hash1 = Hash::new([2u8; 32]);
    let io_commitment1 = {
        let mut h = Sha3_256::new();
        h.update(input_hash1.as_bytes());
        h.update(output_hash1.as_bytes());
        Hash::new(h.finalize().into())
    };

    let statement1 = b"test statement 1".to_vec();
    let response1 = {
        let mut h = Sha3_256::new();
        h.update(&statement1);
        h.finalize()
    };
    let commitment1 = {
        let mut h = Sha3_256::new();
        h.update(&statement1);
        h.update(response1);
        h.finalize()
    };
    let mut proof_data1 = Vec::new();
    proof_data1.extend_from_slice(&commitment1);
    proof_data1.extend_from_slice(&response1);

    let proof1 = ExecutionProof {
        model_hash: Hash::new([10u8; 32]),
        input_hash: input_hash1,
        output_hash: output_hash1,
        io_commitment: io_commitment1,
        statement: statement1,
        proof_data: proof_data1,
        timestamp: chrono::Utc::now().timestamp() as u64,
        provider: Address([0u8; 20]),
    };

    // Invalid proof (zero hashes)
    let proof2 = ExecutionProof {
        model_hash: Hash::default(), // zero hash
        input_hash: Hash::default(),
        output_hash: Hash::default(),
        io_commitment: Hash::default(),
        statement: vec![],
        proof_data: vec![],
        timestamp: chrono::Utc::now().timestamp() as u64,
        provider: Address([0u8; 20]),
    };

    let results = verifier.verify_batch(&[proof1, proof2]).unwrap();
    assert_eq!(results.len(), 2);
    assert!(results[0]); // valid proof
    assert!(!results[1]); // invalid (zero model hash)
}

// ---------------------------------------------------------------------------
// Commitment proof verification — empty statement rejected
// ---------------------------------------------------------------------------

#[test]
fn test_verify_execution_empty_statement_proof() {
    let verifier = ExecutionVerifier::new();
    let model = make_test_model(1);
    let input = b"test";
    let output = b"result";

    // Create proof with empty statement
    let model_hash = {
        let mut h = Sha3_256::new();
        h.update(&model.architecture);
        h.update(&model.weights);
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

    let proof = ExecutionProof {
        model_hash,
        input_hash,
        output_hash,
        io_commitment,
        statement: vec![], // empty
        proof_data: vec![0u8; 64],
        timestamp: chrono::Utc::now().timestamp() as u64,
        provider: Address([0u8; 20]),
    };

    let result = verifier.verify_execution(&model, input, output, &proof).unwrap();
    // Should fail because empty statement fails ZK verification
    assert!(!result);
}

// ---------------------------------------------------------------------------
// Commitment proof verification — proof too short
// ---------------------------------------------------------------------------

#[test]
fn test_verify_execution_proof_too_short() {
    let verifier = ExecutionVerifier::new();
    let model = make_test_model(1);
    let input = b"input";
    let output = b"output";

    let model_hash = {
        let mut h = Sha3_256::new();
        h.update(&model.architecture);
        h.update(&model.weights);
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

    let proof = ExecutionProof {
        model_hash,
        input_hash,
        output_hash,
        io_commitment,
        statement: vec![1, 2, 3],
        proof_data: vec![0u8; 10], // too short (< 64)
        timestamp: chrono::Utc::now().timestamp() as u64,
        provider: Address([0u8; 20]),
    };

    let result = verifier.verify_execution(&model, input, output, &proof).unwrap();
    assert!(!result, "Short proof_data should fail verification");
}

// ---------------------------------------------------------------------------
// Commitment proof verification — model hash mismatch
// ---------------------------------------------------------------------------

#[test]
fn test_verify_execution_model_hash_mismatch() {
    let verifier = ExecutionVerifier::new();
    let model = make_test_model(1);
    let input = b"input";
    let output = b"output";

    // Wrong model hash
    let proof = ExecutionProof {
        model_hash: Hash::new([0xFF; 32]), // doesn't match actual model
        input_hash: Hash::new([0u8; 32]),
        output_hash: Hash::new([0u8; 32]),
        io_commitment: Hash::new([0u8; 32]),
        statement: vec![1, 2, 3],
        proof_data: vec![0u8; 64],
        timestamp: chrono::Utc::now().timestamp() as u64,
        provider: Address([0u8; 20]),
    };

    let result = verifier.verify_execution(&model, input, output, &proof).unwrap();
    assert!(!result, "Model hash mismatch should fail verification");
}

// ---------------------------------------------------------------------------
// Provider list
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_list_providers_empty() {
    let registry = ProviderRegistry::new();
    let providers = registry.list_providers().await;
    assert!(providers.is_empty());
}

#[tokio::test]
async fn test_list_providers_multiple() {
    let registry = ProviderRegistry::new();
    for i in 1..=4u8 {
        let p = make_provider(i, 16, 100);
        registry.register_provider(p).await.unwrap();
    }
    let providers = registry.list_providers().await;
    assert_eq!(providers.len(), 4);
}

// ---------------------------------------------------------------------------
// ProviderRegistry default
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_provider_registry_default() {
    let registry = ProviderRegistry::default();
    assert!(registry.list_providers().await.is_empty());
}

// ---------------------------------------------------------------------------
// ModelId operations
// ---------------------------------------------------------------------------

#[test]
fn test_model_id_from_hash() {
    let hash = Hash::new([0xAB; 32]);
    let model_id = ModelId::from_hash(&hash);
    assert_eq!(model_id.0, [0xAB; 32]);
}

#[test]
fn test_model_id_as_bytes() {
    let model_id = ModelId([0xCD; 32]);
    assert_eq!(model_id.as_bytes(), &[0xCD; 32]);
}

// ---------------------------------------------------------------------------
// RequestId and RequestStatus
// ---------------------------------------------------------------------------

#[test]
fn test_request_id_equality_and_hash() {
    use std::collections::HashMap;
    let id1 = RequestId([1u8; 32]);
    let id2 = RequestId([1u8; 32]);
    let id3 = RequestId([2u8; 32]);

    assert_eq!(id1, id2);
    assert_ne!(id1, id3);

    let mut map = HashMap::new();
    map.insert(id1, "first");
    map.insert(id3, "third");
    assert_eq!(map.get(&id2), Some(&"first"));
}

#[test]
fn test_request_status_serialization_roundtrip() {
    let statuses = vec![
        RequestStatus::Pending,
        RequestStatus::Assigned(Address([1u8; 20])),
        RequestStatus::Executing,
        RequestStatus::Completed(Hash::new([2u8; 32])),
        RequestStatus::Failed("test error".into()),
        RequestStatus::Cancelled,
    ];

    for status in statuses {
        let json = serde_json::to_string(&status).unwrap();
        let recovered: RequestStatus = serde_json::from_str(&json).unwrap();
        // Just verify it roundtrips without panic
        let _ = format!("{:?}", recovered);
    }
}

// ---------------------------------------------------------------------------
// ComputeCapacity serialization
// ---------------------------------------------------------------------------

#[test]
fn test_compute_capacity_serialization() {
    let cap = ComputeCapacity {
        total_memory: 32 * 1024 * 1024 * 1024,
        available_memory: 16 * 1024 * 1024 * 1024,
        total_compute: 1000,
        available_compute: 500,
        hardware: vec![
            HardwareType::CPU,
            HardwareType::GPU("RTX 4090".into()),
            HardwareType::TPU("v4".into()),
            HardwareType::Custom("FPGA".into()),
        ],
    };

    let json = serde_json::to_string(&cap).unwrap();
    let recovered: ComputeCapacity = serde_json::from_str(&json).unwrap();
    assert_eq!(recovered.total_compute, 1000);
    assert_eq!(recovered.hardware.len(), 4);
}

// ---------------------------------------------------------------------------
// ProviderInfo serialization
// ---------------------------------------------------------------------------

#[test]
fn test_provider_info_serialization() {
    let info = make_provider(1, 16, 100);

    let json = serde_json::to_string(&info).unwrap();
    let recovered: ProviderInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(recovered.name, "Provider 1");
    assert_eq!(recovered.reputation, 100);
}

// ---------------------------------------------------------------------------
// ExecutionRequest serialization
// ---------------------------------------------------------------------------

#[test]
fn test_execution_request_serialization() {
    let req = ExecutionRequest {
        id: RequestId([1u8; 32]),
        model_id: ModelId([2u8; 32]),
        input_hash: Hash::new([3u8; 32]),
        requester: Address([4u8; 20]),
        provider: Address([5u8; 20]),
        max_price: U256::from(1_000_000),
        status: RequestStatus::Pending,
        created_at: 1234567890,
    };

    let json = serde_json::to_string(&req).unwrap();
    let recovered: ExecutionRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(recovered.created_at, 1234567890);
}

// ---------------------------------------------------------------------------
// Compute requirements edge cases
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_compute_requirement_not_enough_compute() {
    let registry = ProviderRegistry::new();
    let model_id = ModelId([10u8; 32]);

    let p = make_provider(1, 16, 50); // 50 compute units total, 25 available
    registry.register_provider(p.clone()).await.unwrap();
    registry
        .register_model_provider(p.address, model_id)
        .await
        .unwrap();

    let requirements = ComputeRequirements {
        min_memory: 1000,
        min_compute: 100, // requires more than available (25)
        gpu_required: false,
        supported_hardware: vec![HardwareType::CPU],
    };

    let result = registry.select_provider(&model_id, &requirements).await;
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Currency variants
// ---------------------------------------------------------------------------

#[test]
fn test_currency_serialization() {
    for currency in [Currency::SALT, Currency::ETH, Currency::USDC] {
        let json = serde_json::to_string(&currency).unwrap();
        let recovered: Currency = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{:?}", currency), format!("{:?}", recovered));
    }
}

// ---------------------------------------------------------------------------
// PricingModel with different currencies
// ---------------------------------------------------------------------------

#[test]
fn test_pricing_model_all_currencies() {
    for currency in [Currency::SALT, Currency::ETH, Currency::USDC] {
        let pricing = PricingModel {
            base_price: U256::from(100),
            per_token_price: U256::from(1),
            per_second_price: U256::from(10),
            currency,
        };

        let json = serde_json::to_string(&pricing).unwrap();
        let _: PricingModel = serde_json::from_str(&json).unwrap();
    }
}

// ---------------------------------------------------------------------------
// ModelCache basic operations
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_model_cache_put_and_get() {
    let cache = citrate_mcp::cache::ModelCache::new(1024 * 1024); // 1MB
    let model_id = ModelId([1u8; 32]);
    let model = make_test_model(1);

    // Initially not in cache
    assert!(cache.get(&model_id).await.is_none());

    // Put model
    cache.put(model_id, model.clone()).await.unwrap();

    // Now in cache
    let retrieved = cache.get(&model_id).await;
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.id, model_id);
    assert_eq!(retrieved.weights, model.weights);
}

#[tokio::test]
async fn test_model_cache_miss() {
    let cache = citrate_mcp::cache::ModelCache::new(1024 * 1024);
    let model_id = ModelId([99u8; 32]);

    assert!(cache.get(&model_id).await.is_none());
}
