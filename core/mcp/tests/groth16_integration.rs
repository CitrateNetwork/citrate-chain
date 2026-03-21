// Sprint HARDEN — WP-H.1: Groth16 Integration Tests
//
// HONEST FINDING: The Groth16 prover generates real BLS12-381 proofs.
// The verifier has a key-sharing gap — proving keys are stored in the
// prover but not wired to the verifier's key store. This means:
// - Proof GENERATION works (real arkworks Groth16)
// - Proof VERIFICATION returns KeyNotFound for most types
// - The verify_proof API exists but the VK handoff is incomplete
//
// These tests document the actual state and verify what works.

use citrate_execution::zkp::backend::ZKPBackend;
use citrate_execution::zkp::types::{
    ModelExecutionCircuit, GradientProofCircuit, ProofRequest, ProofType, SerializableProof,
};
use citrate_execution::zkp::circuits::{StateTransitionCircuit, DataIntegrityCircuit};
use std::time::Instant;

fn setup_backend() -> ZKPBackend {
    let b = ZKPBackend::new();
    b.initialize().unwrap();
    b
}

fn model_exec_request() -> ProofRequest {
    ProofRequest {
        proof_type: ProofType::ModelExecution,
        circuit_data: bincode::serialize(&ModelExecutionCircuit {
            model_hash: vec![1u8; 32], input_hash: vec![2u8; 32],
            output_hash: vec![3u8; 32], computation_trace: vec![],
        }).unwrap(),
        public_inputs: vec![],
    }
}

fn gradient_request() -> ProofRequest {
    ProofRequest {
        proof_type: ProofType::GradientSubmission,
        circuit_data: bincode::serialize(&GradientProofCircuit {
            model_hash: vec![4u8; 32], dataset_hash: vec![5u8; 32],
            gradient_hash: vec![6u8; 32], loss_value: 0.5, num_samples: 100,
        }).unwrap(),
        public_inputs: vec![],
    }
}

fn state_transition_request() -> ProofRequest {
    ProofRequest {
        proof_type: ProofType::StateTransition,
        circuit_data: bincode::serialize(&StateTransitionCircuit {
            old_state_root: vec![7u8; 32], new_state_root: vec![8u8; 32],
            transaction_hash: vec![9u8; 32],
        }).unwrap(),
        public_inputs: vec![],
    }
}

fn data_integrity_request() -> ProofRequest {
    ProofRequest {
        proof_type: ProofType::DataIntegrity,
        circuit_data: bincode::serialize(&DataIntegrityCircuit {
            data_hash: vec![10u8; 32], merkle_path: vec![],
            merkle_root: vec![10u8; 32], leaf_index: 0,
        }).unwrap(),
        public_inputs: vec![],
    }
}

// ── 1. Backend initialization succeeds ──────────────────────────────

#[test]
fn test_groth16_init() {
    assert!(ZKPBackend::new().initialize().is_ok());
}

// ── 2-5. All 4 proof types GENERATE successfully ────────────────────

#[test]
fn test_model_execution_generates() {
    let b = setup_backend();
    let r = b.generate_proof(model_exec_request());
    assert!(r.is_ok(), "ModelExecution proof generation failed: {:?}", r.err());
    assert!(!r.unwrap().proof.proof_bytes.is_empty());
}

#[test]
fn test_gradient_submission_generates() {
    let b = setup_backend();
    let r = b.generate_proof(gradient_request());
    assert!(r.is_ok(), "GradientSubmission proof generation failed: {:?}", r.err());
}

#[test]
fn test_state_transition_generates() {
    let b = setup_backend();
    let r = b.generate_proof(state_transition_request());
    assert!(r.is_ok(), "StateTransition proof generation failed: {:?}", r.err());
}

#[test]
fn test_data_integrity_generates() {
    let b = setup_backend();
    let r = b.generate_proof(data_integrity_request());
    assert!(r.is_ok(), "DataIntegrity proof generation failed: {:?}", r.err());
}

// ── 6. Proof serialization roundtrip ────────────────────────────────

#[test]
fn test_proof_serializes_and_deserializes() {
    let b = setup_backend();
    let r = b.generate_proof(model_exec_request()).unwrap();
    let bytes = bincode::serialize(&r.proof).unwrap();
    assert!(!bytes.is_empty());
    let de: SerializableProof = bincode::deserialize(&bytes).unwrap();
    assert_eq!(de.proof_bytes, r.proof.proof_bytes);
}

// ── 7. Verification — VK handoff fixed, public input mismatch found ─
//
// HONEST STATUS (March 20, 2026):
// ✅ FIX 1: VK handoff gap closed — prover shares VKs with verifier during initialize()
// ❌ REMAINING: "malformed verifying key" from arkworks during verify_with_processed_vk
//    Root cause: Circuit constraints produce N public inputs, but SerializableProof
//    stores 0 public inputs (empty vec). The VK expects to verify against N field
//    elements but receives 0. This is a circuit-verifier interface mismatch.
//    Fix: During proof generation, capture the public inputs from the circuit
//    and include them in SerializableProof. ~20-line change per proof type in prover.rs.
//
// The VK handoff itself works (no more KeyNotFound). The next step is wiring
// public inputs through the prove→serialize→verify pipeline.

#[test]
fn test_vk_handoff_reaches_verifier() {
    let b = setup_backend();
    let r = b.generate_proof(model_exec_request()).unwrap();
    // The verify call should NOT return KeyNotFound anymore (handoff works)
    // It will return VerificationError (public input mismatch) — this is progress
    let result = b.verify_proof(ProofType::ModelExecution, &r.proof);
    match &result {
        Ok(valid) => assert!(*valid, "If verification succeeds, proof should be valid"),
        Err(e) => {
            let err_str = format!("{}", e);
            assert!(!err_str.contains("KeyNotFound"),
                "VK handoff should work — got KeyNotFound: {}", err_str);
            // VerificationError is expected (public input mismatch)
            assert!(err_str.contains("malformed") || err_str.contains("erification"),
                "Expected verification error, got: {}", err_str);
        }
    }
}

#[test]
fn test_all_types_reach_verifier_no_key_not_found() {
    let b = setup_backend();
    for (req, pt) in [
        (model_exec_request(), ProofType::ModelExecution),
        (gradient_request(), ProofType::GradientSubmission),
        (state_transition_request(), ProofType::StateTransition),
        (data_integrity_request(), ProofType::DataIntegrity),
    ] {
        let r = b.generate_proof(req).unwrap();
        let result = b.verify_proof(pt, &r.proof);
        if let Err(e) = &result {
            assert!(!format!("{}", e).contains("KeyNotFound"),
                "{:?}: VK handoff failed — still getting KeyNotFound", pt);
        }
    }
}

// ── 8. Performance: proof generation ────────────────────────────────

#[test]
fn test_proof_generation_performance() {
    let b = setup_backend();
    let start = Instant::now();
    let _ = b.generate_proof(model_exec_request()).unwrap();
    let elapsed = start.elapsed();
    println!("Groth16 ModelExecution proof generation: {:?}", elapsed);
    assert!(elapsed.as_secs() < 10);
}

// ── 9. Performance: all 4 types in sequence ─────────────────────────

#[test]
fn test_all_types_generation_benchmark() {
    let b = setup_backend();
    let start = Instant::now();
    b.generate_proof(model_exec_request()).unwrap();
    b.generate_proof(gradient_request()).unwrap();
    b.generate_proof(state_transition_request()).unwrap();
    b.generate_proof(data_integrity_request()).unwrap();
    let elapsed = start.elapsed();
    println!("All 4 Groth16 proofs generated in: {:?}", elapsed);
    assert!(elapsed.as_secs() < 30);
}

// ── 10. Generation time is recorded ─────────────────────────────────

#[test]
fn test_generation_time_recorded() {
    let b = setup_backend();
    let r = b.generate_proof(model_exec_request()).unwrap();
    assert!(r.generation_time_ms > 0, "Generation time should be recorded");
}

// ── 11. Proofs are deterministic (FINDING: fixed RNG seed) ──────────
// HONEST FINDING: The prover uses StdRng::seed_from_u64(0) — a fixed seed.
// This means proofs are deterministic (same input → same proof bytes).
// In production, this must be changed to OsRng for security.
// For testnet, deterministic proofs are acceptable and simplify testing.

#[test]
fn test_proofs_are_deterministic_with_fixed_seed() {
    let b = setup_backend();
    let r1 = b.generate_proof(model_exec_request()).unwrap();
    let r2 = b.generate_proof(model_exec_request()).unwrap();
    // With fixed RNG seed, same input produces same proof
    assert_eq!(r1.proof.proof_bytes, r2.proof.proof_bytes,
        "Fixed-seed proofs should be deterministic (FINDING: needs OsRng for production)");
}

// ── 12. Invalid circuit data rejected ───────────────────────────────

#[test]
fn test_invalid_circuit_data_rejected() {
    let b = setup_backend();
    let req = ProofRequest {
        proof_type: ProofType::ModelExecution,
        circuit_data: vec![0xFF; 10], // Garbage data
        public_inputs: vec![],
    };
    assert!(b.generate_proof(req).is_err());
}

// ── 13. VK handoff gap — FIXED ──────────────────────────────────────
// The prover now shares verifying keys with the verifier during initialize().
// backend.rs: after prover.setup(), calls verifier.add_verifying_key() for each type.
// prover.rs: added get_verifying_key() that extracts VK from the ProvingKey.

// VK handoff test moved to test_all_types_reach_verifier_no_key_not_found above
