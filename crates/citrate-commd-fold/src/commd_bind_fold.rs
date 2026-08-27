//! Binding fold step (citrate-chain#170, M2b-cont) — the fold that proves BOTH public commitments of
//! a file from the SAME in-circuit leaf stream: the Merkle `commD` (as in [`crate::merkle_fold`]) AND
//! the `dataCommit` sponge. Exposing both, derived from one shared set of leaf witnesses, is what
//! makes the wrong-CommD challenge SOUND: a proof cannot pair a `commD` for one file with a
//! `dataCommit` for another, so the contract can slash iff `trueCommD != reg.commD` while requiring
//! the public `dataCommit == reg.dataCommit` (ADR-2026-08-27). This closes the leaf↔identity binding
//! that `merkle_fold` alone left open.
//!
//! ## IVC state `z` (arity = depth + 6)
//!   `z[0..depth]` = Merkle `filled[h]`   ·  `z[depth]` = `index`  ·  `z[depth+1]` = `commD` (root)
//!   `z[depth+2..depth+5]` = sponge lanes `[s0, s1, s2]`  ·  `z[depth+5]` = `pos` (rate lane 0/1)
//!
//! The sponge is seeded (in `z0`) with `citrate-commd::data_commit_preamble_state` — the state after
//! absorbing `[domain, len]` and one permutation — then each step absorbs its leaf into the current
//! rate lane, permuting when a pair completes; the LAST step (a witnessed `is_last` flag) applies the
//! final squeeze permutation iff a half-pair is pending. This mirrors `compute_data_commit_streaming`
//! exactly, which is proven byte-equal to the batch `compute_data_commit`.

use std::sync::Arc;

use ff::Field as _;
use nova_snark::frontend::{
    num::AllocatedNum, AllocatedBit, Boolean, ConstraintSystem, SynthesisError,
};
use nova_snark::nova::{PublicParams, RecursiveSNARK};
use nova_snark::traits::{circuit::StepCircuit, snark::RelaxedR1CSSNARKTrait};

use crate::merkle_fold::{alloc_const, conditionally_select, scalar_low_u64, scalar_to_be_bytes};
use crate::poseidon_gadget::{add_const, ark_fr_to_scalar, PoseidonBn254Gadget};
use crate::{Scalar, E1, E2};

type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;

/// One fold step that advances BOTH the Merkle `commD` and the `dataCommit` sponge over one leaf.
#[derive(Clone)]
pub struct CommDBindFoldStep {
    depth: usize,
    leaf: Scalar,
    is_last: bool,
    zeros: Vec<Scalar>, // Merkle zero-subtree roots, zeros[0..=depth]
    gadget: Arc<PoseidonBn254Gadget>,
}

impl StepCircuit<Scalar> for CommDBindFoldStep {
    fn arity(&self) -> usize {
        self.depth + 6
    }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let depth = self.depth;

        // Shared leaf witness for this step, plus the is_last flag (drives the squeeze).
        let leaf = AllocatedNum::alloc(cs.namespace(|| "leaf"), || Ok(self.leaf))?;
        let is_last = Boolean::from(AllocatedBit::alloc(
            cs.namespace(|| "is_last"),
            Some(self.is_last),
        )?);

        // ============================ Merkle commD fold ============================
        let mut filled: Vec<AllocatedNum<Scalar>> = z[0..depth].to_vec();
        let index = z[depth].clone();

        let index_u64 = index.get_value().map(scalar_low_u64);
        let mut bits: Vec<AllocatedBit> = Vec::with_capacity(depth);
        for h in 0..depth {
            bits.push(AllocatedBit::alloc(
                cs.namespace(|| format!("index bit {h}")),
                index_u64.map(|v| (v >> h) & 1 == 1),
            )?);
        }
        {
            let bit_vars: Vec<_> = bits.iter().map(|b| b.get_variable()).collect();
            cs.enforce(
                || "index bit recomposition",
                |mut lc| {
                    for (h, v) in bit_vars.iter().enumerate() {
                        lc = lc + (Scalar::from(1u64 << h), *v);
                    }
                    lc
                },
                |lc| lc + CS::one(),
                |lc| lc + index.get_variable(),
            );
        }
        let mut cur = leaf.clone();
        for h in 0..depth {
            let bit = Boolean::from(bits[h].clone());
            let zero_h = alloc_const(cs.namespace(|| format!("zeros {h}")), self.zeros[h])?;
            let left =
                conditionally_select(cs.namespace(|| format!("left {h}")), &filled[h], &cur, &bit)?;
            let right =
                conditionally_select(cs.namespace(|| format!("right {h}")), &cur, &zero_h, &bit)?;
            filled[h] = left.clone();
            cur = self
                .gadget
                .hash2(cs.namespace(|| format!("node {h}")), &left, &right)?;
        }
        let new_index = add_const(cs.namespace(|| "index += 1"), &index, Scalar::ONE)?;

        // ============================ dataCommit sponge fold ============================
        let s0 = z[depth + 2].clone();
        let s1 = z[depth + 3].clone();
        let s2 = z[depth + 4].clone();
        let pos = z[depth + 5].clone();
        // Constrain `pos` to a bit and mirror it as a Boolean for the lane selects.
        let pos_bit = AllocatedBit::alloc(
            cs.namespace(|| "pos bit"),
            pos.get_value().map(|v| v == Scalar::ONE),
        )?;
        cs.enforce(
            || "pos == pos_bit",
            |lc| lc + pos.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + pos_bit.get_variable(),
        );
        let pos_bool = Boolean::from(pos_bit.clone());

        // Absorb: add `leaf` into the current rate lane. lp = leaf·pos (leaf when pos==1, else 0).
        let lp = leaf.mul(cs.namespace(|| "leaf*pos"), &pos)?;
        // s1' = s1 + (leaf - lp)  [adds leaf when pos==0];  s2' = s2 + lp  [adds leaf when pos==1].
        let s1p = AllocatedNum::alloc(cs.namespace(|| "s1'"), || {
            let v = s1.get_value().ok_or(SynthesisError::AssignmentMissing)?
                + leaf.get_value().ok_or(SynthesisError::AssignmentMissing)?
                - lp.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            Ok(v)
        })?;
        cs.enforce(
            || "s1' = s1 + leaf - lp",
            |lc| lc + s1.get_variable() + leaf.get_variable() - lp.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + s1p.get_variable(),
        );
        let s2p = AllocatedNum::alloc(cs.namespace(|| "s2'"), || {
            let v = s2.get_value().ok_or(SynthesisError::AssignmentMissing)?
                + lp.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            Ok(v)
        })?;
        cs.enforce(
            || "s2' = s2 + lp",
            |lc| lc + s2.get_variable() + lp.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + s2p.get_variable(),
        );

        // permute the absorbed state; select it iff a pair just completed (pos==1).
        let raw = [s0.clone(), s1p.clone(), s2p.clone()];
        let permuted = self
            .gadget
            .permute3(cs.namespace(|| "pair permute"), raw.clone())?;
        let after0 =
            conditionally_select(cs.namespace(|| "after0"), &permuted[0], &raw[0], &pos_bool)?;
        let after1 =
            conditionally_select(cs.namespace(|| "after1"), &permuted[1], &raw[1], &pos_bool)?;
        let after2 =
            conditionally_select(cs.namespace(|| "after2"), &permuted[2], &raw[2], &pos_bool)?;
        // new_pos = 1 - pos.
        let new_pos = AllocatedNum::alloc(cs.namespace(|| "new pos"), || {
            Ok(Scalar::ONE - pos.get_value().ok_or(SynthesisError::AssignmentMissing)?)
        })?;
        cs.enforce(
            || "new_pos = 1 - pos",
            |lc| lc + CS::one() - pos.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + new_pos.get_variable(),
        );

        // Squeeze: on the LAST step, if a half-pair is pending (new_pos==1, i.e. pos==0), permute once
        // more. do_squeeze = is_last AND (NOT pos).
        let do_squeeze = Boolean::and(cs.namespace(|| "do_squeeze"), &is_last, &pos_bool.not())?;
        let after = [after0, after1, after2];
        let squeezed = self
            .gadget
            .permute3(cs.namespace(|| "squeeze permute"), after.clone())?;
        let final0 = conditionally_select(
            cs.namespace(|| "final0"),
            &squeezed[0],
            &after[0],
            &do_squeeze,
        )?;
        let final1 = conditionally_select(
            cs.namespace(|| "final1"),
            &squeezed[1],
            &after[1],
            &do_squeeze,
        )?;
        let final2 = conditionally_select(
            cs.namespace(|| "final2"),
            &squeezed[2],
            &after[2],
            &do_squeeze,
        )?;

        // ============================ assemble z' ============================
        let mut out = filled;
        out.push(new_index);
        out.push(cur); // commD (root)
        out.push(final0);
        out.push(final1); // dataCommit at the last step
        out.push(final2);
        out.push(new_pos);
        Ok(out)
    }
}

/// The built recursive-fold pipeline for a file: the public parameters, the fully-folded
/// `RecursiveSNARK`, the initial public state `z0`, the Merkle `depth`, and the step count `n`.
/// Shared by the recursive-verify path ([`fold_commd_bound`]) and the compressed path
/// ([`crate::commd_compressed`]) so the (expensive) fold is written once.
pub struct BuiltFold {
    pub pp: PublicParams<E1, E2, CommDBindFoldStep>,
    pub rs: RecursiveSNARK<E1, E2, CommDBindFoldStep>,
    pub z0: Vec<Scalar>,
    pub depth: usize,
    pub num_steps: usize,
}

impl BuiltFold {
    /// `(commD, dataCommit)` indices within the public state `z`.
    pub fn commd_index(&self) -> usize {
        self.depth + 1
    }
    pub fn datacommit_index(&self) -> usize {
        self.depth + 3
    }
}

/// Build `pp`, run the full binding fold over `data`, and return the pipeline (NOT yet verified).
pub fn build_bound_fold(data: &[u8]) -> Result<BuiltFold, Box<dyn std::error::Error>> {
    let leaves: Vec<Scalar> = citrate_commd::pack_bytes(data)
        .into_iter()
        .map(ark_fr_to_scalar)
        .collect();
    let n = leaves.len();
    let depth = if n <= 1 {
        0
    } else {
        n.next_power_of_two().trailing_zeros() as usize
    };

    // Merkle zero-subtree roots.
    let mut zeros: Vec<Scalar> = vec![Scalar::ZERO];
    let mut zeros_ark = vec![ark_bn254::Fr::from(0u64)];
    for h in 1..=depth {
        let za = citrate_commd::poseidon_hash(&[zeros_ark[h - 1], zeros_ark[h - 1]]);
        zeros_ark.push(za);
        zeros.push(ark_fr_to_scalar(za));
    }
    // dataCommit sponge preamble (after [domain, len] + one permutation), from the canonical source.
    let pre = citrate_commd::data_commit_preamble_state(n);
    let (ps0, ps1, ps2) = (
        ark_fr_to_scalar(pre[0]),
        ark_fr_to_scalar(pre[1]),
        ark_fr_to_scalar(pre[2]),
    );

    let gadget = Arc::new(PoseidonBn254Gadget::from_citrate_commd());
    let mk = |leaf: Scalar, is_last: bool| CommDBindFoldStep {
        depth,
        leaf,
        is_last,
        zeros: zeros.clone(),
        gadget: gadget.clone(),
    };

    // z0 = [filled=zeros[0..depth], index=0, root=zeros[depth], s0,s1,s2 = preamble, pos=0].
    let mut z0: Vec<Scalar> = zeros[0..depth].to_vec();
    z0.push(Scalar::ZERO);
    z0.push(zeros[depth]);
    z0.push(ps0);
    z0.push(ps1);
    z0.push(ps2);
    z0.push(Scalar::ZERO);

    let c0 = mk(leaves[0], n == 1);
    let pp =
        PublicParams::<E1, E2, CommDBindFoldStep>::setup(&c0, &*S1::ck_floor(), &*S2::ck_floor())?;

    let mut rs = RecursiveSNARK::<E1, E2, CommDBindFoldStep>::new(&pp, &c0, &z0)?;
    for (i, &leaf) in leaves.iter().enumerate() {
        rs.prove_step(&pp, &mk(leaf, i + 1 == n))?;
    }
    Ok(BuiltFold {
        pp,
        rs,
        z0,
        depth,
        num_steps: n,
    })
}

/// Fold `data` through a Nova `RecursiveSNARK`, verify, and return `(commD, dataCommit)` — both 32
/// big-endian bytes — proven from ONE in-circuit leaf stream. Returns them iff the recursive proof
/// verifies. This is the M2b-cont binding proof.
pub fn fold_commd_bound(data: &[u8]) -> Result<([u8; 32], [u8; 32]), Box<dyn std::error::Error>> {
    let built = build_bound_fold(data)?;
    let out = built.rs.verify(&built.pp, built.num_steps, &built.z0)?;
    let comm_d = scalar_to_be_bytes(out[built.commd_index()]);
    let data_commit = scalar_to_be_bytes(out[built.datacommit_index()]);
    Ok((comm_d, data_commit))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// M2b-cont acceptance: the recursively-folded `(commD, dataCommit)` — both derived from ONE
    /// in-circuit leaf stream — equal the canonical `compute_comm_d` AND `compute_data_commit`, across
    /// single-leaf, exact-boundary, and odd/even leaf counts. This is the binding property the sound
    /// challenge relies on.
    #[test]
    fn fold_binds_commd_and_datacommit_to_reference() {
        for &n_bytes in &[1usize, 31, 32, 62, 100, 200] {
            let data: Vec<u8> = (0..n_bytes).map(|i| (i * 13 + 5) as u8).collect();
            let (commd, datacommit) =
                fold_commd_bound(&data).expect("bound fold + verify must succeed");
            assert_eq!(
                commd,
                citrate_commd::compute_comm_d(&data),
                "folded commD != reference at {n_bytes}B"
            );
            assert_eq!(
                datacommit,
                citrate_commd::compute_data_commit(&data),
                "folded dataCommit != reference at {n_bytes}B"
            );
        }
    }

    /// The two commitments are genuinely both bound to the bytes: flipping one byte changes BOTH the
    /// proven commD and the proven dataCommit (so a challenger cannot swap the file behind either).
    #[test]
    fn both_commitments_are_byte_sensitive() {
        let a: Vec<u8> = (0..100u32).map(|i| i as u8).collect();
        let mut b = a.clone();
        b[63] ^= 1;
        let (ca, da) = fold_commd_bound(&a).expect("fold a");
        let (cb, db) = fold_commd_bound(&b).expect("fold b");
        assert_ne!(ca, cb, "commD must change");
        assert_ne!(da, db, "dataCommit must change");
    }
}
