// Sprint HARDEN — WP-H.3: Custom AI Opcode Validation
//
// Tests AI precompile infrastructure: addresses, gas costs, proof verification,
// access control, and input validation. Full execute() tests require MetalRuntime
// (GPU hardware) and are covered in the inline module tests.
#![allow(clippy::assertions_on_constants)]

use citrate_execution::precompiles::inference::{
    addresses, gas_costs, verify_commitment_proof,
};

// ─────────────────────────────────────────────────────────────────────
// 1. Address Validation — all 7 addresses are correct and distinct
// ─────────────────────────────────────────────────────────────────────

#[test]
fn test_all_precompile_addresses_are_distinct() {
    let addrs = [
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
fn test_precompile_address_namespace() {
    // All AI precompiles in 0x0001xx namespace (bytes 16-17 = 0x0001)
    let addrs = [
        addresses::MODEL_DEPLOY,
        addresses::MODEL_INFERENCE,
        addresses::BATCH_INFERENCE,
        addresses::MODEL_METADATA,
        addresses::PROOF_VERIFY,
        addresses::MODEL_BENCHMARK,
        addresses::MODEL_ENCRYPTION,
    ];
    for (i, addr) in addrs.iter().enumerate() {
        assert_eq!(addr[17], 1, "Precompile {} should be in 0x0001xx namespace", i);
        assert_eq!(addr[18], 0, "Precompile {} byte 18 should be 0", i);
    }
}

#[test]
fn test_precompile_addresses_sequential() {
    assert_eq!(addresses::MODEL_DEPLOY[19], 0);
    assert_eq!(addresses::MODEL_INFERENCE[19], 1);
    assert_eq!(addresses::BATCH_INFERENCE[19], 2);
    assert_eq!(addresses::MODEL_METADATA[19], 3);
    assert_eq!(addresses::PROOF_VERIFY[19], 4);
    assert_eq!(addresses::MODEL_BENCHMARK[19], 5);
    assert_eq!(addresses::MODEL_ENCRYPTION[19], 6);
}

// ─────────────────────────────────────────────────────────────────────
// 2. Gas Cost Validation — constants are reasonable and ordered
// ─────────────────────────────────────────────────────────────────────

#[test]
fn test_gas_cost_base_positive() {
    assert!(gas_costs::BASE_COST > 0);
    assert!(gas_costs::INFERENCE_BASE > 0);
    assert!(gas_costs::PROOF_GENERATION > 0);
}

#[test]
fn test_gas_cost_ordering() {
    // Inference should cost more than base
    assert!(gas_costs::INFERENCE_BASE > gas_costs::BASE_COST);
    // Proof generation should cost more than inference
    assert!(gas_costs::PROOF_GENERATION > gas_costs::INFERENCE_BASE);
}

#[test]
fn test_gas_cost_batch_discount_valid() {
    assert!(gas_costs::BATCH_DISCOUNT > 0, "Discount must be positive");
    assert!(gas_costs::BATCH_DISCOUNT < 100, "Discount must be less than 100%");
}

#[test]
fn test_gas_cost_scaling() {
    // Verify per-element costs are non-zero
    assert!(gas_costs::INFERENCE_PER_INPUT > 0);
    assert!(gas_costs::INFERENCE_PER_OUTPUT > 0);
    assert!(gas_costs::MODEL_DEPLOY_PER_KB > 0);
}

#[test]
fn test_gas_cost_inference_calculation() {
    // For 100 input elements and 10 output elements
    let input_elements = 100u64;
    let output_elements = 10u64;
    let expected_cost = gas_costs::INFERENCE_BASE
        + (input_elements * gas_costs::INFERENCE_PER_INPUT)
        + (output_elements * gas_costs::INFERENCE_PER_OUTPUT);

    // 5000 + 1000 + 100 = 6100
    assert_eq!(expected_cost, 6100);
    assert!(expected_cost < 1_000_000, "Cost should be reasonable");
}

#[test]
fn test_gas_cost_model_deploy_calculation() {
    // For a 1MB model
    let model_size_kb = 1024u64;
    let expected_cost = gas_costs::BASE_COST + model_size_kb * gas_costs::MODEL_DEPLOY_PER_KB;

    assert!(expected_cost > gas_costs::BASE_COST);
    assert!(expected_cost < 10_000_000, "1MB model deploy should cost < 10M gas");
}

// ─────────────────────────────────────────────────────────────────────
// 3. Commitment Proof Verification — the core proof scheme
// ─────────────────────────────────────────────────────────────────────

fn build_commitment_proof(statement: &[u8], response: &[u8; 32]) -> Vec<u8> {
    use sha3::Digest;
    let mut hasher = sha3::Keccak256::new();
    hasher.update(statement);
    hasher.update(response);
    let commitment = hasher.finalize();

    let mut proof = Vec::with_capacity(64 + statement.len());
    proof.extend_from_slice(&commitment);
    proof.extend_from_slice(response);
    proof.extend_from_slice(statement);
    proof
}

#[test]
fn test_commitment_proof_valid() {
    let statement = b"inference on model_abc with input [1,2,3]";
    let response = &[0xAB; 32];
    let proof = build_commitment_proof(statement, response);
    assert!(verify_commitment_proof(&proof), "Valid proof should verify");
}

#[test]
fn test_commitment_proof_invalid_commitment() {
    let statement = b"test statement";
    let response = &[0xCD; 32];
    let mut proof = build_commitment_proof(statement, response);
    proof[0] ^= 0xFF; // Corrupt commitment
    assert!(!verify_commitment_proof(&proof), "Corrupted commitment should fail");
}

#[test]
fn test_commitment_proof_invalid_response() {
    let statement = b"test statement";
    let response = &[0xEF; 32];
    let mut proof = build_commitment_proof(statement, response);
    proof[32] ^= 0xFF; // Corrupt response
    assert!(!verify_commitment_proof(&proof), "Corrupted response should fail");
}

#[test]
fn test_commitment_proof_invalid_statement() {
    let statement = b"test statement";
    let response = &[0x11; 32];
    let mut proof = build_commitment_proof(statement, response);
    if proof.len() > 64 {
        proof[64] ^= 0xFF; // Corrupt statement
    }
    assert!(!verify_commitment_proof(&proof), "Corrupted statement should fail");
}

#[test]
fn test_commitment_proof_too_short() {
    let proof = vec![0u8; 32]; // Need at least 64 bytes
    assert!(!verify_commitment_proof(&proof));
}

#[test]
fn test_commitment_proof_empty() {
    assert!(!verify_commitment_proof(&[]));
}

#[test]
fn test_commitment_proof_exact_64_bytes() {
    // Exactly 64 bytes = commitment (32) + response (32) + empty statement
    let statement = b"";
    let response = &[0x22; 32];
    let proof = build_commitment_proof(statement, response);
    assert_eq!(proof.len(), 64);
    assert!(verify_commitment_proof(&proof), "64-byte proof with empty statement should verify");
}

#[test]
fn test_commitment_proof_large_statement() {
    let statement = vec![0x33u8; 10_000]; // 10KB statement
    let response = &[0x44; 32];
    let proof = build_commitment_proof(&statement, response);
    assert!(verify_commitment_proof(&proof));
}

#[test]
fn test_commitment_proof_deterministic() {
    let statement = b"determinism test";
    let response = &[0x55; 32];
    let proof1 = build_commitment_proof(statement, response);
    let proof2 = build_commitment_proof(statement, response);
    assert_eq!(proof1, proof2, "Same inputs must produce same proof");
}

#[test]
fn test_commitment_proof_different_statements_different_proofs() {
    let response = &[0x66; 32];
    let proof1 = build_commitment_proof(b"statement A", response);
    let proof2 = build_commitment_proof(b"statement B", response);
    assert_ne!(proof1[..32], proof2[..32], "Different statements must produce different commitments");
}

#[test]
fn test_commitment_proof_different_responses_different_proofs() {
    let statement = b"same statement";
    let proof1 = build_commitment_proof(statement, &[0x77; 32]);
    let proof2 = build_commitment_proof(statement, &[0x88; 32]);
    assert_ne!(proof1[..32], proof2[..32], "Different responses must produce different commitments");
}
