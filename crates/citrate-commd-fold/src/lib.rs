//! citrate-commd-fold — Nova/folding prover for the recursive CommD proof (citrate-chain#170, M2).
//!
//! ISOLATED workspace: Nova's dep tree (nova-snark / bellpepper / its halo2curves pin) never unifies
//! with the pinned PSE-halo2/ark-0.4 stack in the parent workspace. This prover runs out-of-process
//! (like the citrate-sealer sidecar); the chain verifies only the final wrapped proof.
//!
//! **M2a (`SumFoldStep`, retained baseline):** de-risked the Nova pipeline over the BN254/Grumpkin
//! cycle with a minimal folded step (a running sum), proving setup → N × prove_step → verify works
//! in-repo. Kept as the smallest end-to-end pipeline witness.
//!
//! **M2b (`poseidon_gadget` + `merkle_fold`, DONE):** the real fold. A bellpepper Poseidon-BN254
//! gadget bit-identical to `citrate-commd::poseidon_hash` (`gadget_hash_matches_native`), driving an
//! incremental-Merkle fold step (`MerkleFoldStep`) that mirrors `IncrementalMerkle`. `fold_commd`
//! recursively proves the canonical `compute_comm_d` in-circuit and VERIFIES the recursive proof
//! (`fold_commd_matches_reference`). Nova's built-in Poseidon uses different constants, so the bespoke
//! gadget is required. **Next (M2b-cont):** fold the `dataCommit` sponge as a second public output to
//! bind the leaves to the registered file identity. **M2c:** compress (Spartan/HyperKZG) and wrap for
//! on-chain verify. **M3/M4:** verifier precompile + contract rewrite.

pub mod commd_bind_fold;
pub mod commd_compressed;
pub mod merkle_fold;
pub mod poseidon_gadget;

use ff::Field;
use nova_snark::{
    frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError},
    nova::{PublicParams, RecursiveSNARK},
    provider::{Bn256EngineKZG, GrumpkinEngine},
    traits::{circuit::StepCircuit, snark::RelaxedR1CSSNARKTrait, Engine},
};

/// Primary engine — BN254 with KZG (our curve).
pub type E1 = Bn256EngineKZG;
/// Secondary engine — Grumpkin (the cycle partner).
pub type E2 = GrumpkinEngine;
/// The BN254 scalar field the fold runs over (== citrate-commd's Fr).
pub type Scalar = <E1 as Engine>::Scalar;

type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;

/// A minimal fold step: `z_out[0] = z_in[0] + x`, with `x` a per-step private witness. The M2a
/// pipeline baseline (superseded for real work by [`merkle_fold::MerkleFoldStep`]); retained as the
/// smallest end-to-end witness that Nova setup → prove_step → verify works in-repo.
#[derive(Clone)]
pub struct SumFoldStep {
    pub x: Scalar,
}

impl StepCircuit<Scalar> for SumFoldStep {
    fn arity(&self) -> usize {
        1
    }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let z0 = &z[0];
        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(self.x))?;
        let out = AllocatedNum::alloc(cs.namespace(|| "out"), || {
            Ok(z0.get_value().ok_or(SynthesisError::AssignmentMissing)? + self.x)
        })?;
        // Enforce out = z0 + x.
        cs.enforce(
            || "out = z0 + x",
            |lc| lc + z0.get_variable() + x.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + out.get_variable(),
        );
        Ok(vec![out])
    }
}

/// Fold `xs` into a running sum via a Nova RecursiveSNARK, then verify the recursive proof. Returns
/// the verified final `z` (the accumulated sum). Proves the Nova pipeline end-to-end.
pub fn fold_sum(xs: &[Scalar]) -> Result<Vec<Scalar>, Box<dyn std::error::Error>> {
    assert!(!xs.is_empty(), "need at least one step");
    let c0 = SumFoldStep { x: xs[0] };
    let pp = PublicParams::<E1, E2, SumFoldStep>::setup(&c0, &*S1::ck_floor(), &*S2::ck_floor())?;

    let z0 = [Scalar::ZERO];
    let mut rs = RecursiveSNARK::<E1, E2, SumFoldStep>::new(&pp, &c0, &z0)?;
    for &x in xs {
        rs.prove_step(&pp, &SumFoldStep { x })?;
    }
    let out = rs.verify(&pp, xs.len(), &z0)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nova_fold_pipeline_verifies() {
        // M2a acceptance: Nova setup + N prove_steps + verify succeed in-repo over BN254/Grumpkin.
        let xs: Vec<Scalar> = (1..=5u64).map(Scalar::from).collect();
        // M2a acceptance: the recursive proof VERIFIES (fold_sum returns Ok iff verify passed), and
        // the folded output is correct — N prove_steps over z0=0 accumulate the plain sum.
        let out = fold_sum(&xs).expect("nova fold + verify must succeed");
        assert_eq!(out.len(), 1, "arity-1 output");
        let sum: Scalar = xs.iter().copied().fold(Scalar::ZERO, |a, b| a + b);
        assert_eq!(
            out[0], sum,
            "folded output must equal the running sum (== 15)"
        );
    }
}
