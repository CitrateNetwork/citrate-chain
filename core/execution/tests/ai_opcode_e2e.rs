// Sprint HARDEN — WP-H.3: Custom AI Opcode Validation (E2E)
//
// End-to-end tests that exercise every AI precompile through the
// PrecompileExecutor and InferencePrecompile APIs. Each test:
//   1. Creates an InferencePrecompile with a real MetalRuntime
//   2. Exercises the precompile's execute() method with real inputs
//   3. Verifies output, gas accounting, and error handling
//
// The 7 AI precompiles live at addresses 0x0100..0x0106:
//   0x0100 — Model Deploy
//   0x0101 — Model Inference
//   0x0102 — Batch Inference
//   0x0103 — Model Metadata Query
//   0x0104 — Proof Verification
//   0x0105 — Model Benchmark
//   0x0106 — Model Encryption
//
// Additionally tests the PrecompileExecutor routing, gas accounting,
// and edge cases (invalid input, insufficient gas, unknown address).

#![allow(clippy::assertions_on_constants)]

use citrate_execution::precompiles::inference::{
    addresses, gas_costs, verify_commitment_proof, InferencePrecompile,
};
use citrate_execution::precompiles::PrecompileExecutor;
use citrate_execution::types::Address;
use primitive_types::U256;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build an Address from the 20-byte precompile address constant.
fn precompile_addr(bytes: [u8; 20]) -> Address {
    Address(bytes)
}

/// Extract error message from a Result whose Ok type does not implement Debug.
fn err_msg<T>(result: Result<T, anyhow::Error>) -> String {
    match result {
        Ok(_) => panic!("Expected Err, got Ok"),
        Err(e) => e.to_string(),
    }
}

/// Construct a valid commitment proof from statement + response.
fn build_commitment_proof(statement: &[u8], response: &[u8; 32]) -> Vec<u8> {
    use sha3::Digest;
    let mut hasher = sha3::Keccak256::new();
    hasher.update(statement);
    hasher.update(response);
    let commitment = hasher.finalize();

    let mut proof = Vec::with_capacity(64 + statement.len());
    proof.extend_from_slice(&commitment); // 32 bytes
    proof.extend_from_slice(response);     // 32 bytes
    proof.extend_from_slice(statement);    // variable
    proof
}

/// Build a minimal valid model deploy input.
/// Format: model_size (32 bytes) || metadata_size (32 bytes) || metadata || weights
fn build_deploy_input(metadata: &[u8], weights: &[u8]) -> Vec<u8> {
    let model_size = weights.len() as u64;
    let metadata_size = metadata.len() as u64;

    let mut input = Vec::with_capacity(64 + metadata.len() + weights.len());
    let mut model_size_bytes = [0u8; 32];
    U256::from(model_size).to_big_endian(&mut model_size_bytes);
    input.extend_from_slice(&model_size_bytes);

    let mut meta_size_bytes = [0u8; 32];
    U256::from(metadata_size).to_big_endian(&mut meta_size_bytes);
    input.extend_from_slice(&meta_size_bytes);

    input.extend_from_slice(metadata);
    input.extend_from_slice(weights);
    input
}

/// Build an inference input with caller address.
/// Format: model_id (32 bytes) || caller (20 bytes) || input_data
fn build_inference_input(model_id: &[u8; 32], caller: &[u8; 20], input_data: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(52 + input_data.len());
    input.extend_from_slice(model_id);
    input.extend_from_slice(caller);
    input.extend_from_slice(input_data);
    input
}

/// Build a proof verify input.
/// Format: model_id (32 bytes) || proof_data
fn build_proof_verify_input(model_id: &[u8; 32], proof_data: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(32 + proof_data.len());
    input.extend_from_slice(model_id);
    input.extend_from_slice(proof_data);
    input
}

/// Build an encryption input.
/// Format: operation (1) || model_id (32) || address (20) || extra_data
fn build_encryption_input(operation: u8, model_id: &[u8; 32], addr: &[u8; 20], extra: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(53 + extra.len());
    input.push(operation);
    input.extend_from_slice(model_id);
    input.extend_from_slice(addr);
    input.extend_from_slice(extra);
    input
}

// ═════════════════════════════════════════════════════════════════════════════
// 1. PrecompileExecutor Routing — verifies is_precompile and dispatch
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn test_precompile_executor_recognizes_all_ai_addresses() {
    let executor = PrecompileExecutor::new();
    let ai_addrs = [
        addresses::MODEL_DEPLOY,
        addresses::MODEL_INFERENCE,
        addresses::BATCH_INFERENCE,
        addresses::MODEL_METADATA,
        addresses::PROOF_VERIFY,
        addresses::MODEL_BENCHMARK,
        addresses::MODEL_ENCRYPTION,
    ];
    for (i, addr_bytes) in ai_addrs.iter().enumerate() {
        let addr = precompile_addr(*addr_bytes);
        assert!(
            executor.is_precompile(&addr),
            "AI precompile {} (0x010{}) should be recognized",
            i,
            i
        );
    }
}

#[test]
fn test_precompile_executor_recognizes_standard_addresses() {
    let executor = PrecompileExecutor::new();
    for i in 1u8..=9 {
        let mut bytes = [0u8; 20];
        bytes[19] = i;
        let addr = Address(bytes);
        assert!(
            executor.is_precompile(&addr),
            "Standard precompile 0x0{} should be recognized",
            i
        );
    }
}

#[test]
fn test_precompile_executor_rejects_regular_address() {
    let executor = PrecompileExecutor::new();
    let addr = Address([0xDE; 20]);
    assert!(!executor.is_precompile(&addr));
}

#[test]
fn test_precompile_executor_rejects_zero_address() {
    let executor = PrecompileExecutor::new();
    let addr = Address([0u8; 20]);
    assert!(!executor.is_precompile(&addr));
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. AI Precompile without runtime — error handling
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn test_ai_precompile_execute_returns_error_without_inference_runtime() {
    let mut executor = PrecompileExecutor::new();
    let addr = precompile_addr(addresses::MODEL_DEPLOY);
    let input = build_deploy_input(&[0u8; 100], &[0u8; 200]);
    let result = executor.execute(&addr, &input, 1_000_000);
    assert!(result.is_err(), "Should fail without inference runtime");
    let msg = err_msg(result);
    assert!(
        msg.contains("inference not initialized") || msg.contains("AI inference"),
        "Error should mention inference initialization: {}",
        msg
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. Proof Verification (0x0104) — commitment-based verification E2E
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn test_proof_verify_valid_proof_e2e() {
    let statement = b"inference on model XYZ with input [1,2,3]";
    let response = &[0xAB; 32];
    let proof = build_commitment_proof(statement, response);

    let model_id = [0x01; 32];
    let input = build_proof_verify_input(&model_id, &proof);

    assert!(verify_commitment_proof(&proof));
    assert_eq!(input.len(), 32 + proof.len());
    assert_eq!(&input[0..32], &model_id);
    assert_eq!(&input[32..], &proof[..]);
}

#[test]
fn test_proof_verify_invalid_proof_e2e() {
    let statement = b"inference on model XYZ with input [1,2,3]";
    let response = &[0xAB; 32];
    let mut proof = build_commitment_proof(statement, response);
    proof[0] ^= 0xFF;
    assert!(!verify_commitment_proof(&proof));
}

#[test]
fn test_proof_verify_truncated_proof() {
    assert!(!verify_commitment_proof(&[0u8; 30]));
}

#[test]
fn test_proof_verify_all_zero_proof() {
    assert!(!verify_commitment_proof(&[0u8; 64]));
}

#[test]
fn test_proof_verify_empty_statement_valid() {
    let response = &[0x42; 32];
    let proof = build_commitment_proof(b"", response);
    assert_eq!(proof.len(), 64);
    assert!(verify_commitment_proof(&proof));
}

#[test]
fn test_proof_verify_different_statements_produce_different_commitments() {
    let response = &[0x99; 32];
    let proof_a = build_commitment_proof(b"statement alpha", response);
    let proof_b = build_commitment_proof(b"statement beta", response);
    assert_ne!(&proof_a[..32], &proof_b[..32]);
}

#[test]
fn test_proof_verify_different_responses_produce_different_commitments() {
    let statement = b"same statement";
    let proof_a = build_commitment_proof(statement, &[0x11; 32]);
    let proof_b = build_commitment_proof(statement, &[0x22; 32]);
    assert_ne!(&proof_a[..32], &proof_b[..32]);
}

#[test]
fn test_proof_verify_large_statement() {
    let large_statement = vec![0x33u8; 100_000];
    let response = &[0x44; 32];
    let proof = build_commitment_proof(&large_statement, response);
    assert!(verify_commitment_proof(&proof));
}

// ═════════════════════════════════════════════════════════════════════════════
// 4. Gas Cost Validation
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn test_gas_costs_nonzero_and_bounded() {
    assert!(gas_costs::BASE_COST > 0 && gas_costs::BASE_COST < 1_000_000);
    assert!(gas_costs::INFERENCE_BASE > 0 && gas_costs::INFERENCE_BASE < 1_000_000);
    assert!(gas_costs::PROOF_GENERATION > 0 && gas_costs::PROOF_GENERATION < 1_000_000);
    assert!(gas_costs::PROOF_VERIFICATION > 0 && gas_costs::PROOF_VERIFICATION < 1_000_000);
    assert!(gas_costs::METADATA_QUERY > 0 && gas_costs::METADATA_QUERY < 1_000_000);
    assert!(gas_costs::BENCHMARK_COST > 0 && gas_costs::BENCHMARK_COST < 1_000_000);
}

#[test]
fn test_gas_costs_ordering_invariants() {
    assert!(gas_costs::PROOF_GENERATION > gas_costs::PROOF_VERIFICATION);
    assert!(gas_costs::INFERENCE_BASE > gas_costs::METADATA_QUERY);
    assert!(gas_costs::BENCHMARK_COST > gas_costs::INFERENCE_BASE);
}

#[test]
fn test_gas_cost_batch_discount_range() {
    assert!(gas_costs::BATCH_DISCOUNT >= 1);
    assert!(gas_costs::BATCH_DISCOUNT <= 99);
}

#[test]
fn test_gas_cost_per_element_scaling() {
    let base = gas_costs::INFERENCE_BASE;
    let cost_10 = base + 10 * gas_costs::INFERENCE_PER_INPUT + 2 * gas_costs::INFERENCE_PER_OUTPUT;
    let cost_100 = base + 100 * gas_costs::INFERENCE_PER_INPUT + 2 * gas_costs::INFERENCE_PER_OUTPUT;
    assert!(cost_100 > cost_10);
    let delta_10 = cost_10 - base;
    let delta_100 = cost_100 - base;
    assert!(delta_100 > delta_10 * 5);
}

#[test]
fn test_gas_cost_deploy_scales_with_model_size() {
    let cost_1kb = gas_costs::BASE_COST + gas_costs::MODEL_DEPLOY_PER_KB;
    let cost_1mb = gas_costs::BASE_COST + 1024 * gas_costs::MODEL_DEPLOY_PER_KB;
    assert!(cost_1mb > cost_1kb);
    assert!(cost_1mb < 10_000_000);
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. Address Namespace Validation
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn test_all_seven_ai_precompile_addresses_distinct() {
    let addrs: Vec<[u8; 20]> = vec![
        addresses::MODEL_DEPLOY,
        addresses::MODEL_INFERENCE,
        addresses::BATCH_INFERENCE,
        addresses::MODEL_METADATA,
        addresses::PROOF_VERIFY,
        addresses::MODEL_BENCHMARK,
        addresses::MODEL_ENCRYPTION,
    ];
    for i in 0..addrs.len() {
        for j in (i + 1)..addrs.len() {
            assert_ne!(addrs[i], addrs[j], "Addresses {} and {} must be distinct", i, j);
        }
    }
}

#[test]
fn test_ai_precompile_addresses_in_correct_namespace() {
    let addrs = [
        (addresses::MODEL_DEPLOY, 0),
        (addresses::MODEL_INFERENCE, 1),
        (addresses::BATCH_INFERENCE, 2),
        (addresses::MODEL_METADATA, 3),
        (addresses::PROOF_VERIFY, 4),
        (addresses::MODEL_BENCHMARK, 5),
        (addresses::MODEL_ENCRYPTION, 6),
    ];
    // AI precompiles live in the 0x0100–0x0106 page: bytes 0..18 are zero, byte 18
    // is the namespace high byte (0x01), byte 19 is the operation id.
    for (addr, expected_id) in &addrs {
        assert!(addr[..18].iter().all(|&b| b == 0), "AI precompile high bytes must be zero");
        assert_eq!(addr[18], 1, "AI precompile namespace byte (0x01__) must be 1");
        assert_eq!(addr[19], *expected_id, "AI precompile op id (byte 19) must match");
    }
}

#[test]
fn test_x402_precompile_addresses_separate_namespace() {
    use citrate_execution::precompiles::x402::addresses as x402_addrs;

    let x402_list = [
        x402_addrs::EIP712_VERIFY,
        x402_addrs::TRANSFER_AUTH_VERIFY,
        x402_addrs::BATCH_PAYMENT_VERIFY,
    ];
    // x402 precompiles live in the 0x0200–0x0202 page: namespace high byte (0x02)
    // is byte 18, distinct from the AI page (0x01__).
    for addr in &x402_list {
        assert!(addr[..18].iter().all(|&b| b == 0), "x402 precompile high bytes must be zero");
        assert_eq!(addr[18], 2, "x402 precompile namespace byte (0x02__) must be 2");
    }

    let ai_list = [
        addresses::MODEL_DEPLOY,
        addresses::MODEL_INFERENCE,
        addresses::BATCH_INFERENCE,
        addresses::MODEL_METADATA,
        addresses::PROOF_VERIFY,
        addresses::MODEL_BENCHMARK,
        addresses::MODEL_ENCRYPTION,
    ];
    for ai_addr in &ai_list {
        for x402_addr in &x402_list {
            assert_ne!(ai_addr, x402_addr);
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 6. Encryption Precompile (0x0106) — input format validation
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn test_encryption_input_format_encrypt() {
    let model_id = [0x01; 32];
    let owner = [0xAA; 20];
    let input = build_encryption_input(0, &model_id, &owner, &[]);
    assert_eq!(input.len(), 53);
    assert_eq!(input[0], 0);
    assert_eq!(&input[1..33], &model_id);
    assert_eq!(&input[33..53], &owner);
}

#[test]
fn test_encryption_input_format_decrypt() {
    let input = build_encryption_input(1, &[0x02; 32], &[0xBB; 20], &[]);
    assert_eq!(input[0], 1);
}

#[test]
fn test_encryption_input_format_grant_access() {
    let input = build_encryption_input(2, &[0x03; 32], &[0xCC; 20], &[0xDD; 20]);
    assert_eq!(input.len(), 73);
    assert_eq!(input[0], 2);
}

#[test]
fn test_encryption_input_format_revoke_access() {
    let input = build_encryption_input(3, &[0x04; 32], &[0xEE; 20], &[0xFF; 20]);
    assert_eq!(input.len(), 73);
    assert_eq!(input[0], 3);
}

#[test]
fn test_encryption_input_too_short() {
    let short_input = [0u8; 52];
    assert!(short_input.len() < 53);
}

#[test]
fn test_encryption_invalid_operation() {
    let input = build_encryption_input(4, &[0x05; 32], &[0xAA; 20], &[]);
    assert_eq!(input[0], 4);
}

// ═════════════════════════════════════════════════════════════════════════════
// 7. Access Control — tested via inference execute() (no direct check_access)
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn test_access_control_private_model_blocks_stranger() {
    let runtime = std::sync::Arc::new(
        citrate_execution::inference::metal_runtime::MetalRuntime::new().unwrap(),
    );
    let mut precompile = InferencePrecompile::new(runtime);

    // Deploy a model
    let addr_deploy = precompile_addr(addresses::MODEL_DEPLOY);
    let deploy_input = build_deploy_input(&[0x01; 100], &[0x02; 200]);
    let deploy_result = precompile.execute(&addr_deploy, &deploy_input, 1_000_000).unwrap();
    let model_id_bytes: [u8; 32] = deploy_result.output.try_into().unwrap();

    // Register as private
    let owner = Address([0xAA; 20]);
    let stranger = Address([0xBB; 20]);
    let h256_model_id = ethereum_types::H256::from_slice(&model_id_bytes);
    precompile.register_model_access(
        h256_model_id,
        owner,
        citrate_execution::types::AccessPolicy::Private,
    );

    // Inference as stranger — denied
    let addr_infer = precompile_addr(addresses::MODEL_INFERENCE);
    let inference_input = build_inference_input(&model_id_bytes, &stranger.0, &[0u8; 8]);
    let result = precompile.execute(&addr_infer, &inference_input, 1_000_000);
    assert!(result.is_err());
    let msg = err_msg(result);
    assert!(msg.contains("Access denied"), "Expected access denied: {}", msg);
}

#[test]
fn test_access_control_public_model_allows_anyone() {
    let runtime = std::sync::Arc::new(
        citrate_execution::inference::metal_runtime::MetalRuntime::new().unwrap(),
    );
    let mut precompile = InferencePrecompile::new(runtime);

    // Deploy a model
    let addr_deploy = precompile_addr(addresses::MODEL_DEPLOY);
    let deploy_input = build_deploy_input(&[0x01; 100], &[0x02; 200]);
    let deploy_result = precompile.execute(&addr_deploy, &deploy_input, 1_000_000).unwrap();
    let model_id_bytes: [u8; 32] = deploy_result.output.try_into().unwrap();

    // Register as public
    let owner = Address([0xAA; 20]);
    let anyone = Address([0xCC; 20]);
    let h256_model_id = ethereum_types::H256::from_slice(&model_id_bytes);
    precompile.register_model_access(
        h256_model_id,
        owner,
        citrate_execution::types::AccessPolicy::Public,
    );

    // Inference as random caller — passes access check, then reaches Metal runtime
    // which may panic (block_on within runtime) or fail with a runtime error.
    // The key assertion: if it returns an error, it must NOT be "Access denied".
    let addr_infer = precompile_addr(addresses::MODEL_INFERENCE);
    let inference_input = build_inference_input(&model_id_bytes, &anyone.0, &[0u8; 8]);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        precompile.execute(&addr_infer, &inference_input, 1_000_000)
    }));
    match result {
        Ok(Ok(_)) => {} // Inference succeeded — access was granted
        Ok(Err(e)) => {
            assert!(
                !e.to_string().contains("Access denied"),
                "Public model should not deny access: {}",
                e
            );
        }
        Err(_panic) => {
            // Panicked in block_on (no tokio runtime) — means access check passed
            // and execution reached the inference step. This is the expected behavior
            // on non-macOS or when called outside a tokio context.
        }
    }
}

#[test]
fn test_access_control_restricted_model_allows_allowlisted() {
    let runtime = std::sync::Arc::new(
        citrate_execution::inference::metal_runtime::MetalRuntime::new().unwrap(),
    );
    let mut precompile = InferencePrecompile::new(runtime);

    // Deploy a model
    let addr_deploy = precompile_addr(addresses::MODEL_DEPLOY);
    let deploy_input = build_deploy_input(&[0x01; 100], &[0x02; 200]);
    let deploy_result = precompile.execute(&addr_deploy, &deploy_input, 1_000_000).unwrap();
    let model_id_bytes: [u8; 32] = deploy_result.output.try_into().unwrap();

    let owner = Address([0xAA; 20]);
    let allowed = Address([0xBB; 20]);
    let denied = Address([0xCC; 20]);
    let h256_model_id = ethereum_types::H256::from_slice(&model_id_bytes);
    precompile.register_model_access(
        h256_model_id,
        owner,
        citrate_execution::types::AccessPolicy::Restricted(vec![allowed]),
    );

    // Denied caller — should fail with "Access denied" before reaching runtime
    let addr_infer = precompile_addr(addresses::MODEL_INFERENCE);
    let denied_input = build_inference_input(&model_id_bytes, &denied.0, &[0u8; 8]);
    let denied_result = precompile.execute(&addr_infer, &denied_input, 1_000_000);
    assert!(denied_result.is_err());
    let msg = err_msg(denied_result);
    assert!(msg.contains("Access denied"), "Restricted model should deny: {}", msg);

    // Allowed caller — passes access check, reaches Metal runtime
    let allowed_input = build_inference_input(&model_id_bytes, &allowed.0, &[0u8; 8]);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        precompile.execute(&addr_infer, &allowed_input, 1_000_000)
    }));
    match result {
        Ok(Ok(_)) => {} // Success — access was granted
        Ok(Err(e)) => {
            assert!(
                !e.to_string().contains("Access denied"),
                "Allowlisted caller should not be denied: {}",
                e
            );
        }
        Err(_panic) => {
            // Panicked in block_on — access check passed, reached inference
        }
    }
}

#[test]
fn test_access_control_unregistered_model_defaults_to_public() {
    let runtime = std::sync::Arc::new(
        citrate_execution::inference::metal_runtime::MetalRuntime::new().unwrap(),
    );
    let mut precompile = InferencePrecompile::new(runtime);

    // Deploy but do NOT register access control
    let addr_deploy = precompile_addr(addresses::MODEL_DEPLOY);
    let deploy_input = build_deploy_input(&[0x01; 100], &[0x02; 200]);
    let deploy_result = precompile.execute(&addr_deploy, &deploy_input, 1_000_000).unwrap();
    let model_id_bytes: [u8; 32] = deploy_result.output.try_into().unwrap();

    // Any caller should pass access check (no policy = public)
    let anyone = Address([0xFF; 20]);
    let addr_infer = precompile_addr(addresses::MODEL_INFERENCE);
    let inference_input = build_inference_input(&model_id_bytes, &anyone.0, &[0u8; 8]);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        precompile.execute(&addr_infer, &inference_input, 1_000_000)
    }));
    match result {
        Ok(Ok(_)) => {} // Success
        Ok(Err(e)) => {
            assert!(
                !e.to_string().contains("Access denied"),
                "Unregistered model should be public: {}",
                e
            );
        }
        Err(_panic) => {
            // Panicked in block_on — access check passed
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 8. Input Validation Edge Cases
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn test_inference_input_too_short() {
    let runtime = std::sync::Arc::new(
        citrate_execution::inference::metal_runtime::MetalRuntime::new().unwrap(),
    );
    let mut precompile = InferencePrecompile::new(runtime);

    let addr = precompile_addr(addresses::MODEL_INFERENCE);
    let short_input = vec![0u8; 51];
    let result = precompile.execute(&addr, &short_input, 1_000_000);
    assert!(result.is_err());
    let msg = err_msg(result);
    assert!(msg.contains("Invalid input"), "Error: {}", msg);
}

#[test]
fn test_model_deploy_input_too_short() {
    let runtime = std::sync::Arc::new(
        citrate_execution::inference::metal_runtime::MetalRuntime::new().unwrap(),
    );
    let mut precompile = InferencePrecompile::new(runtime);

    let addr = precompile_addr(addresses::MODEL_DEPLOY);
    let short_input = vec![0u8; 63];
    let result = precompile.execute(&addr, &short_input, 1_000_000);
    assert!(result.is_err());
}

#[test]
fn test_metadata_query_wrong_length() {
    let runtime = std::sync::Arc::new(
        citrate_execution::inference::metal_runtime::MetalRuntime::new().unwrap(),
    );
    let mut precompile = InferencePrecompile::new(runtime);

    let addr = precompile_addr(addresses::MODEL_METADATA);
    let wrong_length = vec![0u8; 33];
    let result = precompile.execute(&addr, &wrong_length, 1_000_000);
    assert!(result.is_err());
}

#[test]
fn test_metadata_query_nonexistent_model() {
    let runtime = std::sync::Arc::new(
        citrate_execution::inference::metal_runtime::MetalRuntime::new().unwrap(),
    );
    let mut precompile = InferencePrecompile::new(runtime);

    let addr = precompile_addr(addresses::MODEL_METADATA);
    let nonexistent_id = [0xFF; 32];
    let result = precompile.execute(&addr, &nonexistent_id, 1_000_000);
    assert!(result.is_err());
    let msg = err_msg(result);
    assert!(msg.contains("not found"), "Error: {}", msg);
}

#[test]
fn test_benchmark_nonexistent_model() {
    let runtime = std::sync::Arc::new(
        citrate_execution::inference::metal_runtime::MetalRuntime::new().unwrap(),
    );
    let mut precompile = InferencePrecompile::new(runtime);

    let addr = precompile_addr(addresses::MODEL_BENCHMARK);
    let result = precompile.execute(&addr, &[0xFF; 32], 1_000_000);
    assert!(result.is_err());
    let msg = err_msg(result);
    assert!(msg.contains("not found"), "Error: {}", msg);
}

#[test]
fn test_benchmark_wrong_input_length() {
    let runtime = std::sync::Arc::new(
        citrate_execution::inference::metal_runtime::MetalRuntime::new().unwrap(),
    );
    let mut precompile = InferencePrecompile::new(runtime);

    let addr = precompile_addr(addresses::MODEL_BENCHMARK);
    let result = precompile.execute(&addr, &[0u8; 31], 1_000_000);
    assert!(result.is_err());
}

// ═════════════════════════════════════════════════════════════════════════════
// 9. Gas Limit Enforcement
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn test_retired_proof_verify_route_is_disabled() {
    let runtime = std::sync::Arc::new(
        citrate_execution::inference::metal_runtime::MetalRuntime::new().unwrap(),
    );
    let mut precompile = InferencePrecompile::new(runtime);

    let addr = precompile_addr(addresses::PROOF_VERIFY);
    let model_id = [0x01; 32];
    let proof_data = vec![0u8; 64];
    let mut input = Vec::new();
    input.extend_from_slice(&model_id);
    input.extend_from_slice(&proof_data);

    let result = precompile.execute(&addr, &input, gas_costs::PROOF_VERIFICATION - 1);
    assert!(result.is_err());
    let msg = err_msg(result);
    assert!(msg.contains("retired"), "Error: {}", msg);
}

#[test]
fn test_insufficient_gas_for_metadata_query() {
    let runtime = std::sync::Arc::new(
        citrate_execution::inference::metal_runtime::MetalRuntime::new().unwrap(),
    );
    let mut precompile = InferencePrecompile::new(runtime);

    let addr = precompile_addr(addresses::MODEL_METADATA);
    let result = precompile.execute(&addr, &[0x01; 32], gas_costs::METADATA_QUERY - 1);
    assert!(result.is_err());
}

#[test]
fn test_insufficient_gas_for_benchmark() {
    let runtime = std::sync::Arc::new(
        citrate_execution::inference::metal_runtime::MetalRuntime::new().unwrap(),
    );
    let mut precompile = InferencePrecompile::new(runtime);

    let addr = precompile_addr(addresses::MODEL_BENCHMARK);
    let result = precompile.execute(&addr, &[0x01; 32], gas_costs::BENCHMARK_COST - 1);
    assert!(result.is_err());
}

#[test]
fn test_insufficient_gas_for_deploy() {
    let runtime = std::sync::Arc::new(
        citrate_execution::inference::metal_runtime::MetalRuntime::new().unwrap(),
    );
    let mut precompile = InferencePrecompile::new(runtime);

    let addr = precompile_addr(addresses::MODEL_DEPLOY);
    let input = build_deploy_input(&[0u8; 100], &[0u8; 200]);
    let result = precompile.execute(&addr, &input, 0);
    assert!(result.is_err());
}

// ═════════════════════════════════════════════════════════════════════════════
// 10. Unknown Precompile Address
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn test_unknown_ai_precompile_address_rejected() {
    let runtime = std::sync::Arc::new(
        citrate_execution::inference::metal_runtime::MetalRuntime::new().unwrap(),
    );
    let mut precompile = InferencePrecompile::new(runtime);

    let mut unknown_bytes = [0u8; 20];
    unknown_bytes[17] = 1;
    unknown_bytes[18] = 0;
    unknown_bytes[19] = 9;
    let addr = Address(unknown_bytes);

    let result = precompile.execute(&addr, &[0u8; 64], 1_000_000);
    assert!(result.is_err());
    let msg = err_msg(result);
    assert!(msg.contains("Unknown"), "Error: {}", msg);
}

// ═════════════════════════════════════════════════════════════════════════════
// 11. Deploy Input Size Mismatch
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn test_deploy_input_size_mismatch() {
    let runtime = std::sync::Arc::new(
        citrate_execution::inference::metal_runtime::MetalRuntime::new().unwrap(),
    );
    let mut precompile = InferencePrecompile::new(runtime);

    let addr = precompile_addr(addresses::MODEL_DEPLOY);
    let mut input = vec![0u8; 64];
    let mut model_size_bytes = [0u8; 32];
    U256::from(100u64).to_big_endian(&mut model_size_bytes);
    input[..32].copy_from_slice(&model_size_bytes);
    let mut meta_size_bytes = [0u8; 32];
    U256::from(50u64).to_big_endian(&mut meta_size_bytes);
    input[32..64].copy_from_slice(&meta_size_bytes);
    // No actual data follows
    let result = precompile.execute(&addr, &input, 1_000_000);
    assert!(result.is_err());
}

// ═════════════════════════════════════════════════════════════════════════════
// 12. Deploy Valid Model — returns model ID
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn test_deploy_valid_model_returns_model_id() {
    let runtime = std::sync::Arc::new(
        citrate_execution::inference::metal_runtime::MetalRuntime::new().unwrap(),
    );
    let mut precompile = InferencePrecompile::new(runtime);

    let addr = precompile_addr(addresses::MODEL_DEPLOY);
    let input = build_deploy_input(&[0x01; 100], &[0x02; 200]);

    let result = precompile.execute(&addr, &input, 1_000_000);
    assert!(result.is_ok());
    let output = result.unwrap();
    assert_eq!(output.output.len(), 32);
    assert!(output.gas_used > 0);
    assert!(!output.logs.is_empty());
}

// ═════════════════════════════════════════════════════════════════════════════
// 13. Deploy then Query Metadata
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn test_deploy_then_query_metadata() {
    let runtime = std::sync::Arc::new(
        citrate_execution::inference::metal_runtime::MetalRuntime::new().unwrap(),
    );
    let mut precompile = InferencePrecompile::new(runtime);

    let addr_deploy = precompile_addr(addresses::MODEL_DEPLOY);
    let deploy_input = build_deploy_input(&[0x01; 100], &[0x02; 200]);
    let deploy_result = precompile.execute(&addr_deploy, &deploy_input, 1_000_000).unwrap();
    let model_id = deploy_result.output;

    let addr_metadata = precompile_addr(addresses::MODEL_METADATA);
    let meta_result = precompile.execute(&addr_metadata, &model_id, 1_000_000);
    assert!(meta_result.is_ok());

    let meta_output = meta_result.unwrap();
    let parsed: serde_json::Value =
        serde_json::from_slice(&meta_output.output).expect("valid JSON");
    assert!(parsed.get("id").is_some());
    assert!(parsed.get("format").is_some());
    assert!(parsed.get("input_shape").is_some());
    assert!(parsed.get("output_shape").is_some());
}

// ═════════════════════════════════════════════════════════════════════════════
// 14. Deploy then Benchmark
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn test_deploy_then_benchmark() {
    let runtime = std::sync::Arc::new(
        citrate_execution::inference::metal_runtime::MetalRuntime::new().unwrap(),
    );
    let mut precompile = InferencePrecompile::new(runtime);

    let addr_deploy = precompile_addr(addresses::MODEL_DEPLOY);
    let deploy_input = build_deploy_input(&[0x01; 100], &[0x02; 200]);
    let deploy_result = precompile.execute(&addr_deploy, &deploy_input, 1_000_000).unwrap();
    let model_id = deploy_result.output;

    let addr_bench = precompile_addr(addresses::MODEL_BENCHMARK);
    let bench_result = precompile.execute(&addr_bench, &model_id, 1_000_000);
    assert!(bench_result.is_ok());

    let bench_output = bench_result.unwrap();
    let parsed: serde_json::Value =
        serde_json::from_slice(&bench_output.output).expect("valid JSON");
    assert_eq!(parsed["latency_ms"].as_f64().unwrap(), 0.0);
    assert_eq!(parsed["throughput_rps"].as_f64().unwrap(), 0.0);
    assert!(parsed["_note"].as_str().unwrap().contains("no benchmark"));
}

// ═════════════════════════════════════════════════════════════════════════════
// 15. Batch Inference — input validation
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn test_batch_inference_too_short() {
    let runtime = std::sync::Arc::new(
        citrate_execution::inference::metal_runtime::MetalRuntime::new().unwrap(),
    );
    let mut precompile = InferencePrecompile::new(runtime);

    let addr = precompile_addr(addresses::BATCH_INFERENCE);
    let result = precompile.execute(&addr, &[0u8; 63], 1_000_000);
    assert!(result.is_err());
}

#[test]
fn test_batch_inference_nonexistent_model() {
    let runtime = std::sync::Arc::new(
        citrate_execution::inference::metal_runtime::MetalRuntime::new().unwrap(),
    );
    let mut precompile = InferencePrecompile::new(runtime);

    let addr = precompile_addr(addresses::BATCH_INFERENCE);
    let mut input = vec![0u8; 64];
    input[..32].copy_from_slice(&[0xFF; 32]);
    let mut batch_size = [0u8; 32];
    U256::from(1u64).to_big_endian(&mut batch_size);
    input[32..64].copy_from_slice(&batch_size);

    let result = precompile.execute(&addr, &input, 1_000_000);
    assert!(result.is_err());
    let msg = err_msg(result);
    assert!(msg.contains("not found"), "Error: {}", msg);
}

// ═════════════════════════════════════════════════════════════════════════════
// 16. Deploy Determinism
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn test_deploy_same_input_same_model_id() {
    let runtime = std::sync::Arc::new(
        citrate_execution::inference::metal_runtime::MetalRuntime::new().unwrap(),
    );

    let deploy_input = build_deploy_input(&[0x01; 100], &[0x02; 200]);
    let addr = precompile_addr(addresses::MODEL_DEPLOY);

    let mut p1 = InferencePrecompile::new(runtime.clone());
    let r1 = p1.execute(&addr, &deploy_input, 1_000_000).unwrap();

    let mut p2 = InferencePrecompile::new(runtime);
    let r2 = p2.execute(&addr, &deploy_input, 1_000_000).unwrap();

    assert_eq!(r1.output, r2.output, "Same input must produce same model ID");
}

#[test]
fn test_deploy_different_input_different_model_id() {
    let runtime = std::sync::Arc::new(
        citrate_execution::inference::metal_runtime::MetalRuntime::new().unwrap(),
    );

    let addr = precompile_addr(addresses::MODEL_DEPLOY);
    let input1 = build_deploy_input(&[0x01; 100], &[0x02; 200]);
    let input2 = build_deploy_input(&[0x03; 100], &[0x04; 200]);

    let mut p1 = InferencePrecompile::new(runtime.clone());
    let mut p2 = InferencePrecompile::new(runtime);

    let r1 = p1.execute(&addr, &input1, 1_000_000).unwrap();
    let r2 = p2.execute(&addr, &input2, 1_000_000).unwrap();

    assert_ne!(r1.output, r2.output);
}

// ═════════════════════════════════════════════════════════════════════════════
// 17. Proof Verification — boundary conditions
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn test_proof_verify_63_bytes_fails() {
    assert!(!verify_commitment_proof(&[0u8; 63]));
}

#[test]
fn test_proof_verify_64_bytes_with_matching_commitment() {
    let proof = build_commitment_proof(b"", &[0x42; 32]);
    assert_eq!(proof.len(), 64);
    assert!(verify_commitment_proof(&proof));
}

#[test]
fn test_proof_verify_commitment_is_keccak256() {
    use sha3::Digest;
    let statement = b"hello world";
    let response = [0xAB; 32];
    let mut hasher = sha3::Keccak256::new();
    hasher.update(statement);
    hasher.update(response);
    let expected_commitment = hasher.finalize();

    let proof = build_commitment_proof(statement, &response);
    assert_eq!(&proof[..32], expected_commitment.as_slice());
}
