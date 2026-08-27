//! Compressed binding proof (citrate-chain#170, M2c) — wrap the (linear-size) `RecursiveSNARK` into a
//! SUCCINCT `CompressedSNARK` (Spartan over HyperKZG on the primary curve, IPA on the secondary), the
//! artifact an on-chain verifier (M3) will check. The compressed proof is a fixed, small size
//! independent of the file's leaf count, and its verification reproduces the SAME public
//! `(commD, dataCommit)` the recursive proof carried — so the succinct proof still binds both
//! commitments to one file.
//!
//! This module proves the full prover pipeline end-to-end: fold -> compress -> verify, plus a
//! serialize -> deserialize -> verify round-trip (the proof and verifier key both derive serde), so
//! the wire artifact M3 consumes is exercised here. `test-utils` still supplies the insecure
//! deterministic SRS; **production (M3/M4) MUST switch to a trusted-setup `.ptau`** (see the crate
//! docs and `PublicParams::setup_with_ptau_dir`).

use nova_snark::nova::{CompressedSNARK, VerifierKey};

use crate::commd_bind_fold::{build_bound_fold, CommDBindFoldStep};
use crate::merkle_fold::scalar_to_be_bytes;
use crate::{Scalar, E1, E2};

type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;

/// The full compressed-proof artifact for a file: the public `(commD, dataCommit)` it binds, the
/// serialized proof and verifier key (what ships to / is baked into the on-chain verifier), and the
/// public inputs the verifier needs (`num_steps`, `z0`, and the `depth` that locates the commitments
/// in the public state).
pub struct CompressedCommDProof {
    pub comm_d: [u8; 32],
    pub data_commit: [u8; 32],
    pub num_steps: usize,
    pub depth: usize,
    pub z0: Vec<Scalar>,
    /// bincode(`CompressedSNARK`) — the succinct proof.
    pub proof_bytes: Vec<u8>,
    /// bincode(`VerifierKey`) — baked into the verifier; carried here for the round-trip test.
    pub vk_bytes: Vec<u8>,
}

/// Fold `data`, compress the recursive proof, verify the compressed proof, and package the artifact.
/// Returns iff the compressed proof verifies and its public output carries `(commD, dataCommit)`.
pub fn prove_commd_compressed(
    data: &[u8],
) -> Result<CompressedCommDProof, Box<dyn std::error::Error>> {
    let built = build_bound_fold(data)?;
    let (pk, vk) = CompressedSNARK::<E1, E2, CommDBindFoldStep, S1, S2>::setup(&built.pp)?;
    let snark =
        CompressedSNARK::<E1, E2, CommDBindFoldStep, S1, S2>::prove(&built.pp, &pk, &built.rs)?;

    // Verify here to (a) prove the compressed proof is valid and (b) extract the public state it binds.
    let zn = snark.verify(&vk, built.num_steps, &built.z0)?;
    let comm_d = scalar_to_be_bytes(zn[built.commd_index()]);
    let data_commit = scalar_to_be_bytes(zn[built.datacommit_index()]);

    let proof_bytes = bincode::serialize(&snark)?;
    let vk_bytes = bincode::serialize(&vk)?;

    Ok(CompressedCommDProof {
        comm_d,
        data_commit,
        num_steps: built.num_steps,
        depth: built.depth,
        z0: built.z0,
        proof_bytes,
        vk_bytes,
    })
}

/// The off-chain analogue of the M3 on-chain verifier: deserialize the verifier key and proof, verify
/// the compressed proof against the public inputs, and return the `(commD, dataCommit)` it carries.
/// The on-chain path checks the SAME relation, then slashes iff `trueCommD != reg.commD` while
/// requiring `dataCommit == reg.dataCommit`.
pub fn verify_commd_compressed(
    proof_bytes: &[u8],
    vk_bytes: &[u8],
    num_steps: usize,
    depth: usize,
    z0: &[Scalar],
) -> Result<([u8; 32], [u8; 32]), Box<dyn std::error::Error>> {
    let vk: VerifierKey<E1, E2, CommDBindFoldStep, S1, S2> = bincode::deserialize(vk_bytes)?;
    let snark: CompressedSNARK<E1, E2, CommDBindFoldStep, S1, S2> =
        bincode::deserialize(proof_bytes)?;
    let zn = snark.verify(&vk, num_steps, z0)?;
    let comm_d = scalar_to_be_bytes(zn[depth + 1]);
    let data_commit = scalar_to_be_bytes(zn[depth + 3]);
    Ok((comm_d, data_commit))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// M2c acceptance: fold -> compress -> verify yields a succinct proof whose public output equals
    /// the canonical `(compute_comm_d, compute_data_commit)`, AND the serialized proof round-trips
    /// through bincode and re-verifies to the same commitments. This is the artifact M3 verifies
    /// on-chain.
    #[test]
    fn compressed_proof_verifies_and_round_trips() {
        // One representative size (compression setup + prove is heavy; correctness of the fold itself
        // is covered across sizes in commd_bind_fold).
        let data: Vec<u8> = (0..200u32).map(|i| (i * 13 + 5) as u8).collect();

        let proof = prove_commd_compressed(&data).expect("compressed prove + verify");
        assert_eq!(
            proof.comm_d,
            citrate_commd::compute_comm_d(&data),
            "compressed commD != reference"
        );
        assert_eq!(
            proof.data_commit,
            citrate_commd::compute_data_commit(&data),
            "compressed dataCommit != reference"
        );

        // Serialize -> deserialize -> verify: the wire artifact the on-chain verifier consumes.
        let (rt_commd, rt_dc) = verify_commd_compressed(
            &proof.proof_bytes,
            &proof.vk_bytes,
            proof.num_steps,
            proof.depth,
            &proof.z0,
        )
        .expect("round-trip verify");
        assert_eq!(rt_commd, proof.comm_d, "round-trip commD mismatch");
        assert_eq!(rt_dc, proof.data_commit, "round-trip dataCommit mismatch");

        // The compressed proof is succinct — a few KB regardless of file size, unlike the recursive
        // proof. (Sanity bound, not a tight target; the exact size feeds the M3 calldata budget.)
        assert!(
            proof.proof_bytes.len() < 50_000,
            "compressed proof unexpectedly large: {} bytes",
            proof.proof_bytes.len()
        );
        eprintln!(
            "M2c: compressed proof = {} bytes, vk = {} bytes",
            proof.proof_bytes.len(),
            proof.vk_bytes.len()
        );
    }

    /// A proof for one file must not verify against another file's public inputs: swapping `z0`/steps
    /// for a different file makes verification fail (the public output is bound into the proof).
    #[test]
    fn compressed_proof_is_bound_to_its_public_inputs() {
        let data_a: Vec<u8> = (0..200u32).map(|i| (i * 13 + 5) as u8).collect();
        let data_b: Vec<u8> = (0..100u32).map(|i| (i * 7 + 1) as u8).collect();
        let pa = prove_commd_compressed(&data_a).expect("prove a");
        let pb = prove_commd_compressed(&data_b).expect("prove b");
        // Verify A's proof against B's public inputs (different num_steps/z0/depth) — must error.
        let wrong = verify_commd_compressed(
            &pa.proof_bytes,
            &pa.vk_bytes,
            pb.num_steps,
            pb.depth,
            &pb.z0,
        );
        assert!(
            wrong.is_err(),
            "a proof must not verify against a different file's public inputs"
        );
    }
}
