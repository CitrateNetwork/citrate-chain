use citrate_commd_fold::commd_fixed_fold::prove_fixed_compressed;
use citrate_commd_verify::{scalar_to_be_bytes, verify_fold_proof, VerifyError};

#[test]
fn cry_c2_forged_initial_state_is_rejected() {
    let proof = prove_fixed_compressed(b"CRY-C2 tripwire").expect("proof");
    let mut z0 = proof
        .z0
        .iter()
        .copied()
        .map(scalar_to_be_bytes)
        .collect::<Vec<_>>();
    z0[0] = [1u8; 32];

    assert_eq!(
        verify_fold_proof(
            &proof.vk_bytes,
            &proof.proof_bytes,
            proof.num_steps,
            proof.depth,
            &z0,
        ),
        Err(VerifyError::NonCanonicalInitialState)
    );
}
