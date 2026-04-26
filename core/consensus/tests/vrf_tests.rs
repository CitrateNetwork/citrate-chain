// Sprint NN: VRF and ECVRF consensus tests.
//
// These tests verify the VRF (Verifiable Random Function) subsystem that
// underpins proposer election. Tests cover:
// - Proof generation produces non-empty output
// - Determinism (same inputs => same output)
// - Different slots and different keys produce different outputs
//
// Uses both the high-level VrfProposerSelector API and the low-level
// ecvrf::prove/verify functions.

use citrate_consensus::types::*;
use citrate_consensus::vrf::VrfProposerSelector;

// ============================================================================
// 1. test_generate_block_vrf_produces_nonempty_proof
//    Call generate_vrf_proof and verify proof is non-empty and output != zero.
// ============================================================================
#[test]
fn test_generate_block_vrf_produces_nonempty_proof() {
    let selector = VrfProposerSelector::new();
    let secret_key = [42u8; 32];
    let proposer = PublicKey::new([1; 32]);
    let previous_vrf = Hash::new([0xAA; 32]);
    let slot = 100;

    let proof = selector
        .generate_vrf_proof(&secret_key, &proposer, &previous_vrf, slot)
        .expect("VRF proof generation must succeed");

    // ECVRF proofs are 114 bytes (pk_p256=33 + Gamma=33 + c=16 + s=32)
    assert_eq!(
        proof.proof.len(),
        114,
        "ECVRF proof must be 114 bytes, got {}",
        proof.proof.len()
    );
    assert_ne!(
        proof.output,
        Hash::default(),
        "VRF output must not be zero"
    );

    // Proof bytes must not be all-zero
    assert!(
        !proof.proof.iter().all(|&b| b == 0),
        "VRF proof bytes must not be all zeros"
    );
}

// ============================================================================
// 2. test_vrf_deterministic
//    Same inputs must produce the same VRF output.
// ============================================================================
#[test]
fn test_vrf_deterministic() {
    let selector = VrfProposerSelector::new();
    let secret_key = [42u8; 32];
    let proposer = PublicKey::new([1; 32]);
    let previous_vrf = Hash::new([0xBB; 32]);
    let slot = 200;

    let proof1 = selector
        .generate_vrf_proof(&secret_key, &proposer, &previous_vrf, slot)
        .unwrap();
    let proof2 = selector
        .generate_vrf_proof(&secret_key, &proposer, &previous_vrf, slot)
        .unwrap();

    assert_eq!(
        proof1.output, proof2.output,
        "Same inputs must produce the same VRF output"
    );
    assert_eq!(
        proof1.proof, proof2.proof,
        "Same inputs must produce the same VRF proof bytes"
    );
}

// ============================================================================
// 3. test_vrf_different_slot_different_output
//    Different slot numbers must produce different VRF outputs.
// ============================================================================
#[test]
fn test_vrf_different_slot_different_output() {
    let selector = VrfProposerSelector::new();
    let secret_key = [42u8; 32];
    let proposer = PublicKey::new([1; 32]);
    let previous_vrf = Hash::new([0xCC; 32]);

    let proof_slot_1 = selector
        .generate_vrf_proof(&secret_key, &proposer, &previous_vrf, 1)
        .unwrap();
    let proof_slot_2 = selector
        .generate_vrf_proof(&secret_key, &proposer, &previous_vrf, 2)
        .unwrap();

    assert_ne!(
        proof_slot_1.output, proof_slot_2.output,
        "Different slots must produce different VRF outputs"
    );
}

// ============================================================================
// 4. test_vrf_different_key_different_output
//    Different signing keys must produce different VRF outputs.
// ============================================================================
#[test]
fn test_vrf_different_key_different_output() {
    let selector = VrfProposerSelector::new();
    let proposer = PublicKey::new([1; 32]);
    let previous_vrf = Hash::new([0xDD; 32]);
    let slot = 100;

    let secret_key_a = [42u8; 32];
    let secret_key_b = [99u8; 32];

    let proof_a = selector
        .generate_vrf_proof(&secret_key_a, &proposer, &previous_vrf, slot)
        .unwrap();
    let proof_b = selector
        .generate_vrf_proof(&secret_key_b, &proposer, &previous_vrf, slot)
        .unwrap();

    assert_ne!(
        proof_a.output, proof_b.output,
        "Different keys must produce different VRF outputs"
    );
}

// ============================================================================
// 5. test_vrf_proof_verifies_roundtrip
//    Generate a proof and verify it roundtrips correctly.
// ============================================================================
#[test]
fn test_vrf_proof_verifies_roundtrip() {
    let selector = VrfProposerSelector::new();
    let secret_key = [42u8; 32];
    let proposer = PublicKey::new([1; 32]);
    let previous_vrf = Hash::new([0xEE; 32]);
    let slot = 500;

    let proof = selector
        .generate_vrf_proof(&secret_key, &proposer, &previous_vrf, slot)
        .unwrap();

    // Verify the proof against the same parameters
    let verified = selector
        .verify_vrf_math_only(&proposer, &proof, &previous_vrf, slot)
        .expect("Verification must not error");

    assert!(verified, "Generated proof must verify successfully");
}

// ============================================================================
// 6. test_vrf_proof_fails_wrong_slot
//    A proof generated for slot N must not verify for slot M (N != M).
// ============================================================================
#[test]
fn test_vrf_proof_fails_wrong_slot() {
    let selector = VrfProposerSelector::new();
    let secret_key = [42u8; 32];
    let proposer = PublicKey::new([1; 32]);
    let previous_vrf = Hash::new([0xEE; 32]);

    let proof = selector
        .generate_vrf_proof(&secret_key, &proposer, &previous_vrf, 100)
        .unwrap();

    // Verify against a DIFFERENT slot
    let verified = selector
        .verify_vrf_math_only(&proposer, &proof, &previous_vrf, 999)
        .expect("Verification must not error");

    assert!(
        !verified,
        "Proof generated for slot 100 must not verify for slot 999"
    );
}

// ============================================================================
// 7. test_ecvrf_low_level_prove_verify
//    Directly test the ecvrf::prove and ecvrf::verify functions.
// ============================================================================
#[test]
fn test_ecvrf_low_level_prove_verify() {
    let secret = [77u8; 32];
    let alpha = b"test alpha for consensus hardening";

    let (proof, beta) =
        citrate_consensus::ecvrf::prove(&secret, alpha).expect("ecvrf::prove must succeed");

    let verified_beta =
        citrate_consensus::ecvrf::verify(alpha, &proof).expect("ecvrf::verify must succeed");

    assert_eq!(
        beta, verified_beta,
        "Verified beta must match original beta"
    );
}

// ============================================================================
// 8. test_ecvrf_tampered_proof_rejects
//    Tampering with the proof challenge must cause verification to fail.
// ============================================================================
#[test]
fn test_ecvrf_tampered_proof_rejects() {
    let secret = [77u8; 32];
    let alpha = b"tamper test alpha";

    let (mut proof, _) = citrate_consensus::ecvrf::prove(&secret, alpha).unwrap();

    // Tamper with the challenge bytes
    proof.c[0] ^= 0xFF;

    let result = citrate_consensus::ecvrf::verify(alpha, &proof);
    assert!(
        result.is_err(),
        "Tampered proof must fail verification"
    );
}
