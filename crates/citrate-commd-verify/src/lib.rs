//! citrate-commd-verify (citrate-chain#170, M3) — the in-node verifier kernel for the recursive
//! CommD fold proof. Wraps Nova's `CompressedSNARK::verify` for the `CommDBindFoldStep` circuit and
//! returns the proof's bound public `(commD, dataCommit)`. This is the pure function the `0x0130`
//! precompile will call once wired into consensus (feature-gated / NOT yet activated).
//!
//! ## Dep-link result (validated)
//! Nova (`halo2curves` 0.9) links into the workspace ALONGSIDE the pinned PSE-halo2 stack
//! (`halo2curves` 0.7) — both coexist in the lock and `citrate-execution --features halo2-substrate`
//! builds with Nova present. So the verifier can live in the node binary; only the PROVER stays
//! isolated (it needs the insecure `test-utils` SRS). The `CommDBindFoldStep` circuit type comes from
//! the prover crate by path.
//!
//! ## Fixed-arity circuit ⇒ ONE baked VK (resolved)
//! The verifier is parameterized by [`FixedCommDFoldStep`], whose arity is a constant
//! (`MAX_DEPTH + 7`) — its R1CS shape, and thus the Nova verifier key, do NOT depend on the file.
//! A single VK (generated once, `fixed_public_params` → `CompressedSNARK::setup`) verifies proofs for
//! every file size, so the precompile can bake ONE key. `commD`/`dataCommit` sit at the FIXED public
//! slots `COMMD_INDEX`/`DATACOMMIT_INDEX`. Production still owes the trusted-setup `.ptau` swap (drop
//! Nova `test-utils`) and the consensus wiring of `0x0130`.

use citrate_commd_fold::commd_fixed_fold::{
    canonical_initial_state, FixedCommDFoldStep, COMMD_INDEX, DATACOMMIT_INDEX, MAX_DEPTH,
};
use citrate_commd_fold::{Scalar, E1, E2};
use ff::PrimeField;
use nova_snark::nova::{CompressedSNARK, VerifierKey};

type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;

type Vk = VerifierKey<E1, E2, FixedCommDFoldStep, S1, S2>;
type Snark = CompressedSNARK<E1, E2, FixedCommDFoldStep, S1, S2>;

/// Why a fold-proof verification failed. `Display` is safe to surface (no secret material).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The verifier key or proof bytes did not deserialize.
    Decode,
    /// A public-input word was not a canonical field element (>= the BN254 scalar modulus).
    NonCanonicalInput,
    /// The proof did not verify against the key + public inputs.
    Invalid,
    /// `depth` is inconsistent with the public-state arity (`z` too short for commD/dataCommit).
    BadArity,
    /// The supplied initial state is not the canonical state for the leaf count/depth.
    NonCanonicalInitialState,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            VerifyError::Decode => "fold proof/vk failed to decode",
            VerifyError::NonCanonicalInput => "public input is not a canonical field element",
            VerifyError::Invalid => "fold proof did not verify",
            VerifyError::BadArity => "depth inconsistent with public-state arity",
            VerifyError::NonCanonicalInitialState => "initial fold state is not canonical",
        };
        f.write_str(s)
    }
}

impl std::error::Error for VerifyError {}

/// A canonical 32-byte big-endian `bytes32` -> BN254 scalar. Errors if `>= r`.
pub fn be_bytes_to_scalar(be: [u8; 32]) -> Result<Scalar, VerifyError> {
    let mut le = be;
    le.reverse();
    Option::from(Scalar::from_repr(le.into())).ok_or(VerifyError::NonCanonicalInput)
}

/// A BN254 scalar -> canonical 32-byte big-endian (`bytes32` / `compute_comm_d` encoding).
pub fn scalar_to_be_bytes(s: Scalar) -> [u8; 32] {
    let repr = s.to_repr();
    let le = repr.as_ref();
    let mut be = [0u8; 32];
    for i in 0..32 {
        be[i] = le[31 - i];
    }
    be
}

/// Verify a serialized recursive-fold CommD proof against a serialized verifier key and the public
/// inputs, returning the proof's bound `(commD, dataCommit)` as 32-byte big-endian. This is the exact
/// relation the `0x0130` precompile enforces; `IPFSIncentivesV3.challengeWrongCommD` then slashes iff
/// `dataCommit == reg.dataCommit` and `trueCommD != reg.commD`.
///
/// `z0_be` is the initial public state (each word big-endian; it carries the file's `depth` at a fixed
/// slot); `num_steps` is the leaf count. With the fixed-arity circuit, commD/dataCommit sit at the
/// CONSTANT slots `COMMD_INDEX`/`DATACOMMIT_INDEX` regardless of file size.
pub fn verify_fold_proof(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    num_steps: usize,
    depth: usize,
    z0_be: &[[u8; 32]],
) -> Result<([u8; 32], [u8; 32]), VerifyError> {
    if z0_be.len() != MAX_DEPTH + 7 {
        return Err(VerifyError::BadArity);
    }

    let z0: Vec<Scalar> = z0_be
        .iter()
        .map(|b| be_bytes_to_scalar(*b))
        .collect::<Result<_, _>>()?;
    let canonical_z0 = canonical_initial_state(num_steps, depth)
        .map_err(|_| VerifyError::NonCanonicalInitialState)?;
    if z0 != canonical_z0 {
        return Err(VerifyError::NonCanonicalInitialState);
    }

    let vk: Vk = bincode::deserialize(vk_bytes).map_err(|_| VerifyError::Decode)?;
    let snark: Snark = bincode::deserialize(proof_bytes).map_err(|_| VerifyError::Decode)?;

    let zn = snark
        .verify(&vk, num_steps, &canonical_z0)
        .map_err(|_| VerifyError::Invalid)?;

    if zn.len() <= DATACOMMIT_INDEX {
        return Err(VerifyError::BadArity);
    }
    let comm_d = scalar_to_be_bytes(zn[COMMD_INDEX]);
    let data_commit = scalar_to_be_bytes(zn[DATACOMMIT_INDEX]);
    Ok((comm_d, data_commit))
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_commd_fold::commd_fixed_fold::prove_fixed_compressed;

    /// M3 kernel acceptance: a REAL fixed-arity compressed proof (produced by the prover crate)
    /// verifies in this node-linkable verifier, and its bound public output equals the canonical
    /// `(compute_comm_d, compute_data_commit)`. A tampered proof is rejected.
    #[test]
    fn verifies_a_real_fold_proof_and_rejects_tampering() {
        let data: Vec<u8> = (0..200u32).map(|i| (i * 13 + 5) as u8).collect();
        let p = prove_fixed_compressed(&data).expect("prove compressed");

        let z0_be: Vec<[u8; 32]> = p.z0.iter().copied().map(scalar_to_be_bytes).collect();

        let (comm_d, data_commit) =
            verify_fold_proof(&p.vk_bytes, &p.proof_bytes, p.num_steps, p.depth, &z0_be)
                .expect("valid proof must verify");
        assert_eq!(
            comm_d,
            citrate_commd::compute_comm_d(&data),
            "verified commD != canonical"
        );
        assert_eq!(
            data_commit,
            citrate_commd::compute_data_commit(&data),
            "verified dataCommit != canonical"
        );

        // Tamper with a load-bearing proof byte → verification must fail (decode or invalid).
        let mut bad = p.proof_bytes.clone();
        bad[64] ^= 0x01;
        assert!(
            verify_fold_proof(&p.vk_bytes, &bad, p.num_steps, p.depth, &z0_be).is_err(),
            "a tampered proof must not verify"
        );
    }

    #[test]
    fn non_canonical_public_input_is_rejected() {
        // 0xFF..FF is >= the BN254 scalar modulus → not a canonical field element.
        let all_ff = [0xFFu8; 32];
        assert_eq!(
            be_bytes_to_scalar(all_ff),
            Err(VerifyError::NonCanonicalInput)
        );
    }

    #[test]
    fn non_canonical_initial_state_is_rejected_before_proof_decode() {
        let z0 = vec![[0u8; 32]; MAX_DEPTH + 7];
        assert_eq!(
            verify_fold_proof(&[], &[], 1, 0, &z0),
            Err(VerifyError::NonCanonicalInitialState)
        );
    }
}
