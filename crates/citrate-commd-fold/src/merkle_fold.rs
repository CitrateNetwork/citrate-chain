//! Incremental-Merkle fold step (citrate-chain#170, M2b) — the REAL Nova step circuit that replaces
//! the M2a `SumFoldStep` placeholder. One step folds ONE leaf into an append-only Poseidon-BN254
//! Merkle accumulator, exactly mirroring `citrate-commd::IncrementalMerkle::insert_returning_siblings`.
//! After folding all `N` leaves of a file, the recursive proof's public output root equals
//! `citrate-commd::compute_comm_d(data)` — the canonical CommD — recomputed entirely in-circuit
//! without ever materializing the whole `O(N)` tree in one circuit. This is what makes a sound,
//! size-agnostic wrong-CommD challenge feasible (ADR-2026-08-27).
//!
//! ## IVC state `z` (arity = depth + 2)
//!   `z[0..depth]`  = `filled[h]`  — the cached left sibling at each height for the current path
//!   `z[depth]`     = `index`      — number of leaves folded so far
//!   `z[depth+1]`   = `root`       — running Merkle root of `leaves[0..index]` with the rest zero
//!
//! ## One step (native reference — `insert_returning_siblings`)
//! ```text
//! cur = leaf
//! for h in 0..depth:
//!     bit = (index >> h) & 1
//!     left  = bit ? filled[h] : cur        // cur is the LEFT child when bit==0
//!     right = bit ? cur       : zeros[h]    // zeros[h] = zero-subtree root at height h
//!     filled[h] = left                      // (== cur when bit==0; unchanged when bit==1)
//!     cur = H(left, right)                  // H = the byte-exact PoseidonBn254Gadget
//! root = cur ; index += 1
//! ```
//! `zeros[h]` are public constants (`H` of the zero subtree); `leaf` and the `index` bits are the
//! per-step private witness. **Scope of THIS increment:** the fold proves `root == poseidon_merkle(leaves)`
//! *given* the leaves. Binding those leaves to the registered file identity (the `dataCommit` sponge of
//! ADR-2026-08-27) is folded in the NEXT increment as a second public output; here the leaves are the
//! prover's asserted input, and the test pins the root against the canonical reference.

use std::sync::Arc;

use ff::{Field as _, PrimeField as _};
use nova_snark::frontend::{
    num::AllocatedNum, AllocatedBit, Boolean, ConstraintSystem, SynthesisError,
};
use nova_snark::nova::{PublicParams, RecursiveSNARK};
use nova_snark::traits::{circuit::StepCircuit, snark::RelaxedR1CSSNARKTrait};

use crate::poseidon_gadget::{add_const, ark_fr_to_scalar, PoseidonBn254Gadget};
use crate::{Scalar, E1, E2};

type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;

/// One incremental-Merkle insert as a Nova step circuit. `depth`, `zeros`, and `gadget` are shared
/// across every step of a fold (they define the arity and the constant substrate); only `leaf` is the
/// per-step witness.
#[derive(Clone)]
pub struct MerkleFoldStep {
    depth: usize,
    leaf: Scalar,
    zeros: Vec<Scalar>, // zeros[0..=depth]
    gadget: Arc<PoseidonBn254Gadget>,
}

impl StepCircuit<Scalar> for MerkleFoldStep {
    fn arity(&self) -> usize {
        self.depth + 2
    }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let depth = self.depth;
        // Unpack the IVC state.
        let mut filled: Vec<AllocatedNum<Scalar>> = z[0..depth].to_vec();
        let index = z[depth].clone();

        // The leaf folded this step (private witness).
        let leaf = AllocatedNum::alloc(cs.namespace(|| "leaf"), || Ok(self.leaf))?;

        // Decompose `index` into its `depth` low bits (index < 2^depth for a valid fold). The bits are
        // witnessed and then constrained to recompose `index`, so a malicious prover cannot pick a path
        // that disagrees with the running index.
        let index_u64 = index.get_value().map(scalar_low_u64);
        let mut bits: Vec<AllocatedBit> = Vec::with_capacity(depth);
        for h in 0..depth {
            let b = AllocatedBit::alloc(
                cs.namespace(|| format!("index bit {h}")),
                index_u64.map(|v| (v >> h) & 1 == 1),
            )?;
            bits.push(b);
        }
        // Enforce Σ bit_h · 2^h == index.
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

        // Walk the path from the leaf to the root, updating `filled` as we go.
        let mut cur = leaf;
        for h in 0..depth {
            let bit = Boolean::from(bits[h].clone());
            let zero_h = alloc_const(cs.namespace(|| format!("zeros {h}")), self.zeros[h])?;

            // left  = bit ? filled[h] : cur ; right = bit ? cur : zeros[h]
            let left =
                conditionally_select(cs.namespace(|| format!("left {h}")), &filled[h], &cur, &bit)?;
            let right =
                conditionally_select(cs.namespace(|| format!("right {h}")), &cur, &zero_h, &bit)?;
            // filled[h] becomes the left child (== cur when bit==0; unchanged when bit==1).
            filled[h] = left.clone();
            cur = self
                .gadget
                .hash2(cs.namespace(|| format!("node {h}")), &left, &right)?;
        }

        // index += 1 ; new root = cur.
        let new_index = add_const(cs.namespace(|| "index += 1"), &index, Scalar::ONE)?;

        let mut out = filled;
        out.push(new_index);
        out.push(cur);
        Ok(out)
    }
}

/// Fold every 31-byte leaf of `data` through a Nova `RecursiveSNARK`, verify the recursive proof, and
/// return the folded CommD as 32 big-endian bytes. This is the M2b end-to-end proof that the canonical
/// `citrate-commd::compute_comm_d` is reproducible in-circuit via recursion. Returns the CommD iff the
/// recursive proof verifies.
pub fn fold_commd(data: &[u8]) -> Result<[u8; 32], Box<dyn std::error::Error>> {
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

    // Zero-subtree roots, computed natively (== the gadget's H by construction): zeros[0]=0,
    // zeros[h]=H(zeros[h-1], zeros[h-1]). Shared as circuit constants and as the z0 initial state.
    let mut zeros: Vec<Scalar> = vec![Scalar::ZERO];
    let mut zeros_ark = vec![ark_bn254::Fr::from(0u64)];
    for h in 1..=depth {
        let za = citrate_commd::poseidon_hash(&[zeros_ark[h - 1], zeros_ark[h - 1]]);
        zeros_ark.push(za);
        zeros.push(ark_fr_to_scalar(za));
    }

    let gadget = Arc::new(PoseidonBn254Gadget::from_citrate_commd());
    let mk = |leaf: Scalar| MerkleFoldStep {
        depth,
        leaf,
        zeros: zeros.clone(),
        gadget: gadget.clone(),
    };

    // z0 = [filled = zeros[0..depth], index = 0, root = zeros[depth]] (the all-empty tree).
    let mut z0: Vec<Scalar> = zeros[0..depth].to_vec();
    z0.push(Scalar::ZERO);
    z0.push(zeros[depth]);

    let c0 = mk(leaves[0]);
    let pp =
        PublicParams::<E1, E2, MerkleFoldStep>::setup(&c0, &*S1::ck_floor(), &*S2::ck_floor())?;

    let mut rs = RecursiveSNARK::<E1, E2, MerkleFoldStep>::new(&pp, &c0, &z0)?;
    for &leaf in &leaves {
        rs.prove_step(&pp, &mk(leaf))?;
    }
    let out = rs.verify(&pp, leaves.len(), &z0)?;

    // Final root = z[depth+1].
    let root = out[depth + 1];
    Ok(scalar_to_be_bytes(root))
}

/// Low 64 bits of a scalar (little-endian). The fold's `index` is always `< 2^depth <= 2^63`, so the
/// low word carries the full value.
pub(crate) fn scalar_low_u64(s: Scalar) -> u64 {
    let repr = s.to_repr();
    let le = repr.as_ref();
    let mut v = 0u64;
    for (i, b) in le.iter().take(8).enumerate() {
        v |= (*b as u64) << (8 * i);
    }
    v
}

/// Scalar -> 32-byte big-endian (matches `citrate-commd::fr_to_be_bytes` / on-chain `bytes32`).
pub(crate) fn scalar_to_be_bytes(s: Scalar) -> [u8; 32] {
    let repr = s.to_repr();
    let le = repr.as_ref();
    let mut be = [0u8; 32];
    for i in 0..32 {
        be[i] = le[31 - i];
    }
    be
}

/// Allocate a wire constrained to the constant `c` (one linear row `x·1 = c`).
pub(crate) fn alloc_const<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    c: Scalar,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    let x = AllocatedNum::alloc(cs.namespace(|| "const"), || Ok(c))?;
    cs.enforce(
        || "x == c",
        |lc| lc + x.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + (c, CS::one()),
    );
    Ok(x)
}

/// `out = cond ? a : b`. One R1CS row: `(a - b)·cond = out - b`.
pub(crate) fn conditionally_select<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    a: &AllocatedNum<Scalar>,
    b: &AllocatedNum<Scalar>,
    cond: &Boolean,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    let out = AllocatedNum::alloc(cs.namespace(|| "selected"), || {
        let pick = cond.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        if pick {
            a.get_value().ok_or(SynthesisError::AssignmentMissing)
        } else {
            b.get_value().ok_or(SynthesisError::AssignmentMissing)
        }
    })?;
    cs.enforce(
        || "conditional select",
        |lc| lc + a.get_variable() - b.get_variable(),
        |_lc| cond.lc(CS::one(), Scalar::ONE),
        |lc| lc + out.get_variable() - b.get_variable(),
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// M2b end-to-end: the recursively-folded CommD equals the canonical `citrate-commd::compute_comm_d`
    /// for a range of file sizes (spanning a single leaf, exact-leaf boundaries, and non-power-of-two
    /// leaf counts). Sizes are kept modest because each case runs a full Nova setup + N prove_steps.
    #[test]
    fn fold_commd_matches_reference() {
        // (bytes, resulting leaf count / depth): 1->1/0, 31->1/0, 32->2/1, 100->4/2, 200->7/3.
        for &n_bytes in &[1usize, 31, 32, 100, 200] {
            let data: Vec<u8> = (0..n_bytes).map(|i| (i * 13 + 5) as u8).collect();
            let got = fold_commd(&data).expect("recursive fold + verify must succeed");
            assert_eq!(
                got,
                citrate_commd::compute_comm_d(&data),
                "folded CommD != canonical reference at {n_bytes} bytes"
            );
        }
    }

    /// Sanity: the fold is byte-collision-sensitive end-to-end — a one-byte change in a deep leaf
    /// yields a different proven root (the property the bond ultimately relies on).
    #[test]
    fn fold_commd_is_collision_sensitive() {
        let a: Vec<u8> = (0..100u32).map(|i| i as u8).collect();
        let mut b = a.clone();
        b[80] ^= 1;
        assert_ne!(
            fold_commd(&a).expect("fold a"),
            fold_commd(&b).expect("fold b"),
            "a one-byte change must change the folded CommD"
        );
    }
}
