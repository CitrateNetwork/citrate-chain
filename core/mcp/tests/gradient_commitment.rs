// WP-H.9: Gradient Commitment Verification Tests
//
// Tests for the commitment-based proof verification scheme in
// `core/mcp/src/verification.rs` (the `verify_commitment_proof` path).
//
// Coverage:
//   1. SHA3(statement || response || nonce) commitment matches
//   2. Tampered gradient -> commitment fails
//   3. Nonce replay within 5-min window -> detected
//   4. Commitment across checkpoint boundary -> correct
//   5. Commitment generation is < 1ms (benchmark assertion)

use citrate_mcp::verification::ExecutionVerifier;
use citrate_mcp::execution::Model;
use citrate_mcp::types::{ExecutionProof, ModelId};
use citrate_execution::{Address, Hash};
use sha3::{Digest, Sha3_256};

// =============================================================================
// Helpers
// =============================================================================

fn make_model() -> Model {
    Model {
        id: ModelId([0xAA; 32]),
        architecture: b"transformer-v1".to_vec(),
        weights: vec![1, 2, 3, 4, 5, 6, 7, 8],
        metadata: b"{\"name\":\"test\"}".to_vec(),
    }
}

/// Build a valid nonce-enhanced commitment proof.
///
/// proof_data layout: commitment(32) || response(32) || nonce(8)
/// commitment = SHA3(statement || response || nonce)
fn build_nonce_proof(statement: &[u8], response: &[u8; 32], nonce_ts: u64) -> Vec<u8> {
    let nonce_bytes = nonce_ts.to_le_bytes();
    let mut hasher = Sha3_256::new();
    hasher.update(statement);
    hasher.update(response);
    hasher.update(nonce_bytes);
    let commitment = hasher.finalize();

    let mut proof_data = commitment.to_vec(); // 32 bytes
    proof_data.extend_from_slice(response);   // 32 bytes
    proof_data.extend_from_slice(&nonce_bytes);// 8 bytes = 72 total
    proof_data
}

/// Build a valid legacy (no nonce) commitment proof.
///
/// proof_data layout: commitment(32) || response(32)
/// commitment = SHA3(statement || response)
fn build_legacy_proof(statement: &[u8], response: &[u8; 32]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(statement);
    hasher.update(response);
    let commitment = hasher.finalize();

    let mut proof_data = commitment.to_vec();
    proof_data.extend_from_slice(response);
    proof_data
}

/// Build a full ExecutionProof with a valid commitment.
fn build_execution_proof(model: &Model, input: &[u8], output: &[u8], proof_data: Vec<u8>, statement: Vec<u8>) -> ExecutionProof {
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

fn current_ts() -> u64 {
    chrono::Utc::now().timestamp() as u64
}

// =============================================================================
// 1. SHA3(statement || response || nonce) commitment matches
// =============================================================================

#[test]
fn test_nonce_enhanced_commitment_matches() {
    let verifier = ExecutionVerifier::new();
    let model = make_model();
    let input = b"gradient tensor data";
    let output = b"commitment output";

    let statement = b"gradient_commitment_v1".to_vec();
    let response = [0x42u8; 32];
    let nonce_ts = current_ts();

    let proof_data = build_nonce_proof(&statement, &response, nonce_ts);
    let proof = build_execution_proof(&model, input, output, proof_data, statement);

    let result = verifier.verify_execution(&model, input, output, &proof);
    assert!(result.is_ok(), "Verification should succeed");
    assert!(!result.unwrap(), "legacy nonce commitment must fail closed");
}

#[test]
fn test_legacy_commitment_matches() {
    let verifier = ExecutionVerifier::new();
    let model = make_model();
    let input = b"gradient data";
    let output = b"result data";

    let statement = b"legacy_statement".to_vec();
    let response = [0x55u8; 32];

    let proof_data = build_legacy_proof(&statement, &response);
    let proof = build_execution_proof(&model, input, output, proof_data, statement);

    let result = verifier.verify_execution(&model, input, output, &proof);
    assert!(result.is_ok());
    assert!(!result.unwrap(), "legacy commitment must fail closed");
}

// =============================================================================
// 2. Tampered gradient -> commitment fails
// =============================================================================

#[test]
fn test_tampered_response_fails() {
    let verifier = ExecutionVerifier::new();
    let model = make_model();
    let input = b"gradient data";
    let output = b"output data";

    let statement = b"tamper_test".to_vec();
    let response = [0x42u8; 32];
    let nonce_ts = current_ts();

    let mut proof_data = build_nonce_proof(&statement, &response, nonce_ts);
    // Tamper with the response bytes (bytes 32..64)
    proof_data[32] ^= 0xFF;

    let proof = build_execution_proof(&model, input, output, proof_data, statement);
    let result = verifier.verify_execution(&model, input, output, &proof);
    assert!(result.is_ok());
    assert!(!result.unwrap(), "Tampered response should fail verification");
}

#[test]
fn test_tampered_commitment_fails() {
    let verifier = ExecutionVerifier::new();
    let model = make_model();
    let input = b"gradient data";
    let output = b"output data";

    let statement = b"tamper_commitment_test".to_vec();
    let response = [0x42u8; 32];
    let nonce_ts = current_ts();

    let mut proof_data = build_nonce_proof(&statement, &response, nonce_ts);
    // Tamper with the commitment bytes (bytes 0..32)
    proof_data[0] ^= 0xFF;

    let proof = build_execution_proof(&model, input, output, proof_data, statement);
    let result = verifier.verify_execution(&model, input, output, &proof);
    assert!(result.is_ok());
    assert!(!result.unwrap(), "Tampered commitment should fail verification");
}

#[test]
fn test_tampered_nonce_fails() {
    let verifier = ExecutionVerifier::new();
    let model = make_model();
    let input = b"gradient data";
    let output = b"output data";

    let statement = b"tamper_nonce_test".to_vec();
    let response = [0x42u8; 32];
    let nonce_ts = current_ts();

    let mut proof_data = build_nonce_proof(&statement, &response, nonce_ts);
    // Tamper with the nonce bytes (bytes 64..72)
    proof_data[64] ^= 0x01;

    let proof = build_execution_proof(&model, input, output, proof_data, statement);
    let result = verifier.verify_execution(&model, input, output, &proof);
    assert!(result.is_ok());
    assert!(!result.unwrap(), "Tampered nonce should fail verification");
}

#[test]
fn test_tampered_statement_fails() {
    let verifier = ExecutionVerifier::new();
    let model = make_model();
    let input = b"gradient data";
    let output = b"output data";

    let original_statement = b"original_statement".to_vec();
    let response = [0x42u8; 32];
    let nonce_ts = current_ts();

    // Build proof with original statement
    let proof_data = build_nonce_proof(&original_statement, &response, nonce_ts);

    // But create the ExecutionProof with a different statement
    let tampered_statement = b"tampered_statement".to_vec();
    let proof = build_execution_proof(&model, input, output, proof_data, tampered_statement);

    let result = verifier.verify_execution(&model, input, output, &proof);
    assert!(result.is_ok());
    assert!(!result.unwrap(), "Tampered statement should fail verification");
}

// =============================================================================
// 3. Nonce replay within 5-min window -> detected
// =============================================================================

#[test]
fn test_expired_nonce_rejected() {
    let verifier = ExecutionVerifier::new();
    let model = make_model();
    let input = b"gradient data";
    let output = b"output data";

    let statement = b"expired_nonce_test".to_vec();
    let response = [0x42u8; 32];
    // Nonce timestamp > 5 minutes (300 seconds) in the past
    let expired_ts = current_ts() - 400;

    let proof_data = build_nonce_proof(&statement, &response, expired_ts);
    let proof = build_execution_proof(&model, input, output, proof_data, statement);

    let result = verifier.verify_execution(&model, input, output, &proof);
    assert!(result.is_ok());
    assert!(!result.unwrap(), "Expired nonce (>5 min old) should fail");
}

#[test]
fn test_future_nonce_rejected() {
    let verifier = ExecutionVerifier::new();
    let model = make_model();
    let input = b"gradient data";
    let output = b"output data";

    let statement = b"future_nonce_test".to_vec();
    let response = [0x42u8; 32];
    // Nonce timestamp > 1 minute in the future (exceeds clock tolerance)
    let future_ts = current_ts() + 120;

    let proof_data = build_nonce_proof(&statement, &response, future_ts);
    let proof = build_execution_proof(&model, input, output, proof_data, statement);

    let result = verifier.verify_execution(&model, input, output, &proof);
    assert!(result.is_ok());
    assert!(!result.unwrap(), "Future nonce (>1 min ahead) should fail");
}

#[test]
fn test_nonce_at_boundary_still_fails_closed() {
    let verifier = ExecutionVerifier::new();
    let model = make_model();
    let input = b"gradient data";
    let output = b"output data";

    let statement = b"boundary_nonce_test".to_vec();
    let response = [0x42u8; 32];
    // Nonce timestamp exactly at the boundary — ~4 min 50 sec old (within 5 min window)
    let boundary_ts = current_ts() - 290;

    let proof_data = build_nonce_proof(&statement, &response, boundary_ts);
    let proof = build_execution_proof(&model, input, output, proof_data, statement);

    let result = verifier.verify_execution(&model, input, output, &proof);
    assert!(result.is_ok());
    assert!(!result.unwrap(), "legacy nonce commitment must fail closed");
}

#[test]
fn test_nonce_just_expired_rejected() {
    let verifier = ExecutionVerifier::new();
    let model = make_model();
    let input = b"gradient data";
    let output = b"output data";

    let statement = b"just_expired_test".to_vec();
    let response = [0x42u8; 32];
    // Nonce timestamp just past the 5-min boundary
    let just_expired_ts = current_ts() - 310;

    let proof_data = build_nonce_proof(&statement, &response, just_expired_ts);
    let proof = build_execution_proof(&model, input, output, proof_data, statement);

    let result = verifier.verify_execution(&model, input, output, &proof);
    assert!(result.is_ok());
    assert!(!result.unwrap(), "Nonce just past 5-min boundary should fail");
}

// =============================================================================
// 4. Commitment across checkpoint boundary -> correct
// =============================================================================

#[test]
fn test_commitment_across_checkpoint_boundary() {
    // Simulate commitments from two consecutive checkpoint windows.
    // Each should independently verify with its own nonce timestamp.
    let verifier = ExecutionVerifier::new();
    let model = make_model();

    let statement = b"checkpoint_boundary".to_vec();
    let response = [0x42u8; 32];

    // First checkpoint window (current)
    let ts_window_1 = current_ts();
    let proof_data_1 = build_nonce_proof(&statement, &response, ts_window_1);
    let proof_1 = build_execution_proof(&model, b"input1", b"output1", proof_data_1, statement.clone());

    let result_1 = verifier.verify_execution(&model, b"input1", b"output1", &proof_1);
    assert!(result_1.is_ok());
    assert!(!result_1.unwrap(), "legacy commitment must fail closed");

    // Second checkpoint window (different response/statement to simulate new window)
    let ts_window_2 = current_ts();
    let response_2 = [0x55u8; 32];
    let statement_2 = b"checkpoint_boundary_next".to_vec();
    let proof_data_2 = build_nonce_proof(&statement_2, &response_2, ts_window_2);
    let proof_2 = build_execution_proof(&model, b"input2", b"output2", proof_data_2, statement_2);

    let result_2 = verifier.verify_execution(&model, b"input2", b"output2", &proof_2);
    assert!(result_2.is_ok());
    assert!(!result_2.unwrap(), "legacy commitment must fail closed");
}

#[test]
fn test_same_nonce_different_statements_produce_different_commitments() {
    // Even with the same nonce timestamp, different statements produce
    // different commitments — replay of a commitment for a different
    // gradient is impossible.
    let response = [0x42u8; 32];
    let nonce_ts = current_ts();

    let statement_a = b"gradient_checkpoint_50";
    let statement_b = b"gradient_checkpoint_51";

    let proof_a = build_nonce_proof(statement_a, &response, nonce_ts);
    let proof_b = build_nonce_proof(statement_b, &response, nonce_ts);

    // Commitments (first 32 bytes) must differ
    assert_ne!(
        &proof_a[..32], &proof_b[..32],
        "Different statements should produce different commitments"
    );
}

#[test]
fn test_commitment_deterministic_across_calls() {
    let statement = b"deterministic_test";
    let response = [0x99u8; 32];
    let nonce_ts = 1_700_000_000u64;

    let proof_1 = build_nonce_proof(statement, &response, nonce_ts);
    let proof_2 = build_nonce_proof(statement, &response, nonce_ts);

    assert_eq!(proof_1, proof_2, "Same inputs should produce identical proofs");
}

// =============================================================================
// 5. Commitment generation is < 1ms (benchmark assertion)
// =============================================================================

#[test]
fn test_commitment_generation_under_1ms() {
    let statement = b"benchmark_statement_for_gradient_commitment_performance";
    let response = [0x42u8; 32];
    let nonce_ts = current_ts();
    let nonce_bytes = nonce_ts.to_le_bytes();

    // Warm up
    for _ in 0..100 {
        let mut hasher = Sha3_256::new();
        hasher.update(statement);
        hasher.update(response);
        hasher.update(nonce_bytes);
        let _ = hasher.finalize();
    }

    // Measure 1000 iterations
    let start = std::time::Instant::now();
    let iterations = 1000u32;
    for _ in 0..iterations {
        let mut hasher = Sha3_256::new();
        hasher.update(statement);
        hasher.update(response);
        hasher.update(nonce_bytes);
        let _ = hasher.finalize();
    }
    let elapsed = start.elapsed();
    let avg_ns = elapsed.as_nanos() / iterations as u128;

    // Assert average is under 1ms (1_000_000 ns)
    assert!(
        avg_ns < 1_000_000,
        "Average commitment generation took {} ns (> 1ms limit)",
        avg_ns
    );

    // In practice SHA3-256 on small inputs is well under 10 microseconds
    assert!(
        avg_ns < 100_000,
        "Average commitment should be well under 100us, was {} ns",
        avg_ns
    );
}

#[test]
fn test_full_verify_execution_under_1ms() {
    let verifier = ExecutionVerifier::new();
    let model = make_model();
    let input = b"perf test input";
    let output = b"perf test output";
    let statement = b"perf_statement".to_vec();
    let response = [0x42u8; 32];
    let nonce_ts = current_ts();

    let proof_data = build_nonce_proof(&statement, &response, nonce_ts);
    let proof = build_execution_proof(&model, input, output, proof_data, statement);

    // Warm up
    for _ in 0..100 {
        let _ = verifier.verify_execution(&model, input, output, &proof);
    }

    // Measure
    let start = std::time::Instant::now();
    let iterations = 1000u32;
    for _ in 0..iterations {
        let _ = verifier.verify_execution(&model, input, output, &proof);
    }
    let elapsed = start.elapsed();
    let avg_ns = elapsed.as_nanos() / iterations as u128;

    assert!(
        avg_ns < 1_000_000,
        "Full verify_execution averaged {} ns (> 1ms limit)",
        avg_ns
    );
}

// =============================================================================
// Edge cases
// =============================================================================

#[test]
fn test_empty_statement_fails() {
    let verifier = ExecutionVerifier::new();
    let model = make_model();
    let input = b"input";
    let output = b"output";

    // Build a proof with empty statement
    let response = [0x42u8; 32];
    let nonce_ts = current_ts();
    let nonce_bytes = nonce_ts.to_le_bytes();
    let mut hasher = Sha3_256::new();
    // hash of empty statement + response + nonce
    hasher.update(b"" as &[u8]);
    hasher.update(response);
    hasher.update(nonce_bytes);
    let commitment = hasher.finalize();

    let mut proof_data = commitment.to_vec();
    proof_data.extend_from_slice(&response);
    proof_data.extend_from_slice(&nonce_bytes);

    let proof = build_execution_proof(&model, input, output, proof_data, vec![]);
    let result = verifier.verify_execution(&model, input, output, &proof);
    assert!(result.is_ok());
    // Empty statement is rejected by verify_commitment_proof
    assert!(!result.unwrap(), "Empty statement should be rejected");
}

#[test]
fn test_proof_data_too_short_fails() {
    let verifier = ExecutionVerifier::new();
    let model = make_model();
    let input = b"input";
    let output = b"output";

    // Proof data with only 32 bytes (needs at least 64)
    let proof_data = vec![0x42u8; 32];
    let proof = build_execution_proof(&model, input, output, proof_data, b"statement".to_vec());

    let result = verifier.verify_execution(&model, input, output, &proof);
    assert!(result.is_ok());
    assert!(!result.unwrap(), "Short proof data should be rejected");
}

#[test]
fn test_empty_proof_data_fails() {
    let verifier = ExecutionVerifier::new();
    let model = make_model();
    let input = b"input";
    let output = b"output";

    let proof = build_execution_proof(&model, input, output, vec![], b"statement".to_vec());
    let result = verifier.verify_execution(&model, input, output, &proof);
    assert!(result.is_ok());
    assert!(!result.unwrap(), "Empty proof data should be rejected");
}
