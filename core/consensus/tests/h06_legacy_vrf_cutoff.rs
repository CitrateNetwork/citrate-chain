// Audit finding H-06 regression: previously the VRF verifier
// accepted both 114-byte ECVRF proofs and 32-byte SHA3 proofs
// indefinitely. The 32-byte path is unauthenticated — anyone
// computing `proof.proof = X` and `output = SHA3(X || pubkey ||
// prev_vrf || slot)` produces a "proof" the verifier accepts. An
// attacker mining blocks with such a forged 32-byte VRF could
// claim to be any validator.
//
// Fix (WP-B2.3): legacy 32-byte proofs are now rejected at or
// above `DEFAULT_LEGACY_VRF_CUTOFF_HEIGHT` (default 100_000).
// Below the cutoff, both ECVRF and legacy are accepted (necessary
// for replaying genesis-era chain history that pre-dates ECVRF).
//
// Sister doc: `docs/security/ECVRF_DEPRECATION_PLAN.md`.

use citrate_consensus::types::{Hash, PublicKey, VrfProof};
use citrate_consensus::vrf::{
    VrfProposerSelector, DEFAULT_LEGACY_VRF_CUTOFF_HEIGHT,
};
use sha3::{Digest, Sha3_256};

fn legacy_forged_proof(proposer: &PublicKey, prev_vrf: &Hash, slot: u64) -> VrfProof {
    // Attacker constructs:
    //   proof.proof = arbitrary 32 bytes
    //   proof.output = SHA3(proof || alpha)
    // where alpha = SHA3(proposer || prev_vrf || slot.to_le_bytes())
    let proof_bytes: Vec<u8> = (0..32u8).map(|i| 0xAA ^ i).collect();

    let mut alpha_hasher = Sha3_256::new();
    alpha_hasher.update(proposer.as_bytes());
    alpha_hasher.update(prev_vrf.as_bytes());
    alpha_hasher.update(slot.to_le_bytes());
    let alpha = alpha_hasher.finalize();

    let mut output_hasher = Sha3_256::new();
    output_hasher.update(&proof_bytes);
    output_hasher.update(alpha);
    let output = Hash::from_bytes(&output_hasher.finalize());

    VrfProof {
        proof: proof_bytes,
        output,
    }
}

/// H-06.1: a forged legacy proof at a slot WAY below the cutoff
/// is accepted (backward compat for sync-replay of historical
/// blocks). This pins the dual-path semantics.
#[test]
fn h06_legacy_proof_accepted_below_cutoff() {
    let selector = VrfProposerSelector::new();
    let proposer = PublicKey::new([0x42; 32]);
    let prev_vrf = Hash::new([0xCD; 32]);
    let slot = 42; // way below default cutoff (100_000)

    let proof = legacy_forged_proof(&proposer, &prev_vrf, slot);
    let result = selector
        .verify_vrf_proof(&proposer, &proof, &prev_vrf, slot)
        .expect("verify");
    assert!(
        result,
        "H-06: forged legacy proof must STILL be accepted below cutoff (sync-replay window)"
    );
}

/// H-06.2: the same forged legacy proof at slot >= cutoff MUST be
/// rejected. This is the load-bearing fix.
#[test]
fn h06_legacy_proof_rejected_at_or_above_cutoff() {
    let selector = VrfProposerSelector::new();
    let proposer = PublicKey::new([0x42; 32]);
    let prev_vrf = Hash::new([0xCD; 32]);

    // Exactly at cutoff: rejected.
    let slot_at = DEFAULT_LEGACY_VRF_CUTOFF_HEIGHT;
    let proof_at = legacy_forged_proof(&proposer, &prev_vrf, slot_at);
    let result_at = selector
        .verify_vrf_proof(&proposer, &proof_at, &prev_vrf, slot_at)
        .expect("verify");
    assert!(
        !result_at,
        "H-06: legacy proof at cutoff height MUST be rejected"
    );

    // Far above cutoff: rejected.
    let slot_above = DEFAULT_LEGACY_VRF_CUTOFF_HEIGHT + 50_000;
    let proof_above = legacy_forged_proof(&proposer, &prev_vrf, slot_above);
    let result_above = selector
        .verify_vrf_proof(&proposer, &proof_above, &prev_vrf, slot_above)
        .expect("verify");
    assert!(
        !result_above,
        "H-06: legacy proof above cutoff MUST be rejected"
    );
}

/// H-06.3: the cutoff is configurable via `with_legacy_cutoff_height`
/// — useful for devnets / tests that want the old behavior. We
/// shift it to 0 (== always-reject) and verify even slot=0 fails
/// for legacy proofs.
#[test]
fn h06_with_zero_cutoff_rejects_all_legacy_proofs() {
    let selector = VrfProposerSelector::new().with_legacy_cutoff_height(0);
    let proposer = PublicKey::new([0x42; 32]);
    let prev_vrf = Hash::new([0xCD; 32]);

    let proof = legacy_forged_proof(&proposer, &prev_vrf, 0);
    let result = selector
        .verify_vrf_proof(&proposer, &proof, &prev_vrf, 0)
        .expect("verify");
    assert!(
        !result,
        "H-06: zero-cutoff means all legacy proofs rejected (genesis-era too)"
    );
}

/// H-06.4: ECVRF proofs (114 bytes) are unaffected by the cutoff
/// — they're always accepted regardless of height because the
/// crypto verification is sound. This pins the fix as targeting
/// only the legacy path, not the well-formed ECVRF path.
#[test]
fn h06_ecvrf_proofs_accepted_at_any_height() {
    let selector = VrfProposerSelector::new();

    // Use the real ECVRF prove pipeline so we have a valid proof.
    let mut secret = [0u8; 32];
    secret[0] = 0x77;
    secret[31] = 0x55;
    let proposer = PublicKey::new([0x33; 32]);
    let prev_vrf = Hash::new([0xEE; 32]);

    let slots = [
        0u64,
        DEFAULT_LEGACY_VRF_CUTOFF_HEIGHT.saturating_sub(1),
        DEFAULT_LEGACY_VRF_CUTOFF_HEIGHT,
        DEFAULT_LEGACY_VRF_CUTOFF_HEIGHT + 1_000_000,
    ];

    for slot in slots {
        let proof = selector
            .generate_vrf_proof(&secret, &proposer, &prev_vrf, slot)
            .expect("ECVRF prove");
        assert_eq!(
            proof.proof.len(),
            114,
            "ECVRF proof must be 114 bytes"
        );
        let ok = selector
            .verify_vrf_proof(&proposer, &proof, &prev_vrf, slot)
            .expect("verify");
        assert!(ok, "H-06: ECVRF proof at slot {slot} must be accepted");
    }
}
