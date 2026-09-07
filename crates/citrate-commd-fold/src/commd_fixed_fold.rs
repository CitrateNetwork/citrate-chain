//! Fixed-arity binding fold (citrate-chain#170, M3) — the SINGLE-VK circuit the `0x0130` precompile
//! verifies. Identical in meaning to [`crate::commd_bind_fold`] (proves `commD` AND `dataCommit` from
//! one leaf stream) but with a CONSTANT arity: the Merkle walk always spans [`MAX_DEPTH`] levels and
//! MASKS every level `h >= depth` (the file's actual depth, a public input) — passing the running node
//! through unchanged. A masked walk to `depth` levels maintains exactly the depth-`depth` incremental
//! root, so the output `commD` equals `citrate-commd::compute_comm_d` (next-power-of-two semantics
//! preserved — NOT re-versioned). Because the R1CS shape no longer depends on the file, ONE Nova
//! verifier key covers every file size — which is what makes a single baked-VK on-chain precompile
//! possible. De-risked natively by `citrate-commd::compute_comm_d_fixed_depth`.
//!
//! ## IVC state `z` (arity = MAX_DEPTH + 7)
//!   `z[0..MAX_DEPTH]` = Merkle `filled[h]`  ·  `z[MAX_DEPTH]` = `index`  ·  `z[MAX_DEPTH+1]` = `commD`
//!   `z[MAX_DEPTH+2..MAX_DEPTH+5]` = sponge `[s0,s1,s2]`  ·  `z[MAX_DEPTH+5]` = `pos`
//!   `z[MAX_DEPTH+6]` = `depth` (public, threaded unchanged — the mask is derived from it each step)

use std::sync::Arc;

use ff::Field as _;
use nova_snark::frontend::{
    num::AllocatedNum, AllocatedBit, Boolean, ConstraintSystem, SynthesisError,
};
use nova_snark::nova::{CompressedSNARK, PublicParams, RecursiveSNARK};
use nova_snark::traits::{circuit::StepCircuit, snark::RelaxedR1CSSNARKTrait};

use crate::merkle_fold::{alloc_const, conditionally_select, scalar_low_u64, scalar_to_be_bytes};
use crate::poseidon_gadget::{add_const, ark_fr_to_scalar, PoseidonBn254Gadget};
use crate::{Scalar, E1, E2};

type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;

/// The fixed Merkle depth the single-VK circuit always walks. `2^MAX_DEPTH` leaves × 31 bytes ≈ 34 TB
/// — far above any model. A file's actual depth ≤ MAX_DEPTH; deeper levels are masked out per step.
pub const MAX_DEPTH: usize = 40;

/// One fixed-arity fold step: advances the masked Merkle `commD` and the `dataCommit` sponge over one
/// leaf. `depth`, `zeros`, `gadget` are shared across every step; `leaf`/`is_last` are per-step.
#[derive(Clone)]
pub struct FixedCommDFoldStep {
    // NB: the file's `depth` is NOT a circuit field — it is carried in the IVC public state
    // `z[MAX_DEPTH+6]` (so it is bound consistent + public), and the level mask is derived from it.
    leaf: Scalar,
    is_last: bool,
    zeros: Vec<Scalar>, // zeros[0..=MAX_DEPTH]
    gadget: Arc<PoseidonBn254Gadget>,
}

impl StepCircuit<Scalar> for FixedCommDFoldStep {
    fn arity(&self) -> usize {
        MAX_DEPTH + 7
    }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let leaf = AllocatedNum::alloc(cs.namespace(|| "leaf"), || Ok(self.leaf))?;
        let is_last = Boolean::from(AllocatedBit::alloc(
            cs.namespace(|| "is_last"),
            Some(self.is_last),
        )?);

        let mut filled: Vec<AllocatedNum<Scalar>> = z[0..MAX_DEPTH].to_vec();
        let index = z[MAX_DEPTH].clone();
        let depth = z[MAX_DEPTH + 6].clone();

        // ── level-activity mask: active[h] = (h < depth). Witnessed booleans, constrained to be a
        //    length-`depth` prefix: monotone non-increasing + Σ active == depth. ──
        let depth_u64 = depth.get_value().map(scalar_low_u64);
        let mut active: Vec<AllocatedBit> = Vec::with_capacity(MAX_DEPTH);
        for h in 0..MAX_DEPTH {
            active.push(AllocatedBit::alloc(
                cs.namespace(|| format!("active {h}")),
                depth_u64.map(|d| (h as u64) < d),
            )?);
        }
        // Σ active[h] == depth.
        {
            let vars: Vec<_> = active.iter().map(|b| b.get_variable()).collect();
            cs.enforce(
                || "sum(active) == depth",
                |mut lc| {
                    for v in &vars {
                        lc = lc + *v;
                    }
                    lc
                },
                |lc| lc + CS::one(),
                |lc| lc + depth.get_variable(),
            );
        }
        // Monotone: active[h+1] * (1 - active[h]) == 0  (a 1 cannot follow a 0).
        for h in 0..MAX_DEPTH - 1 {
            cs.enforce(
                || format!("monotone {h}"),
                |lc| lc + active[h + 1].get_variable(),
                |lc| lc + CS::one() - active[h].get_variable(),
                |lc| lc,
            );
        }

        // ── index bit-decomposition over MAX_DEPTH bits (index < 2^depth ≤ 2^MAX_DEPTH). ──
        let index_u64 = index.get_value().map(scalar_low_u64);
        let mut bits: Vec<AllocatedBit> = Vec::with_capacity(MAX_DEPTH);
        for h in 0..MAX_DEPTH {
            bits.push(AllocatedBit::alloc(
                cs.namespace(|| format!("index bit {h}")),
                index_u64.map(|v| (v >> h) & 1 == 1),
            )?);
        }
        {
            let vars: Vec<_> = bits.iter().map(|b| b.get_variable()).collect();
            cs.enforce(
                || "index recomposition",
                |mut lc| {
                    for (h, v) in vars.iter().enumerate() {
                        // 2^h fits in u64 for h < 64; MAX_DEPTH ≤ 40.
                        lc = lc + (Scalar::from(1u64 << h), *v);
                    }
                    lc
                },
                |lc| lc + CS::one(),
                |lc| lc + index.get_variable(),
            );
        }

        // ── masked Merkle walk: at each level do the insert, but only ADOPT the result when active. ──
        let mut cur = leaf.clone();
        for h in 0..MAX_DEPTH {
            let act = Boolean::from(active[h].clone());
            let bit = Boolean::from(bits[h].clone());
            let zero_h = alloc_const(cs.namespace(|| format!("zeros {h}")), self.zeros[h])?;

            // left = bit ? filled[h] : cur ; right = bit ? cur : zeros[h]
            let left =
                conditionally_select(cs.namespace(|| format!("left {h}")), &filled[h], &cur, &bit)?;
            let right =
                conditionally_select(cs.namespace(|| format!("right {h}")), &cur, &zero_h, &bit)?;
            let hashed = self
                .gadget
                .hash2(cs.namespace(|| format!("node {h}")), &left, &right)?;

            // Adopt only when this level is active; otherwise cur and filled[h] pass through.
            cur = conditionally_select(cs.namespace(|| format!("cur {h}")), &hashed, &cur, &act)?;
            filled[h] = conditionally_select(
                cs.namespace(|| format!("filled {h}")),
                &left,
                &filled[h],
                &act,
            )?;
        }
        let new_index = add_const(cs.namespace(|| "index += 1"), &index, Scalar::ONE)?;

        // ── dataCommit sponge fold (depth-independent; identical to commd_bind_fold). ──
        let s0 = z[MAX_DEPTH + 2].clone();
        let s1 = z[MAX_DEPTH + 3].clone();
        let s2 = z[MAX_DEPTH + 4].clone();
        let pos = z[MAX_DEPTH + 5].clone();
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

        let lp = leaf.mul(cs.namespace(|| "leaf*pos"), &pos)?;
        let s1p = AllocatedNum::alloc(cs.namespace(|| "s1'"), || {
            Ok(s1.get_value().ok_or(SynthesisError::AssignmentMissing)?
                + leaf.get_value().ok_or(SynthesisError::AssignmentMissing)?
                - lp.get_value().ok_or(SynthesisError::AssignmentMissing)?)
        })?;
        cs.enforce(
            || "s1' = s1 + leaf - lp",
            |lc| lc + s1.get_variable() + leaf.get_variable() - lp.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + s1p.get_variable(),
        );
        let s2p = AllocatedNum::alloc(cs.namespace(|| "s2'"), || {
            Ok(s2.get_value().ok_or(SynthesisError::AssignmentMissing)?
                + lp.get_value().ok_or(SynthesisError::AssignmentMissing)?)
        })?;
        cs.enforce(
            || "s2' = s2 + lp",
            |lc| lc + s2.get_variable() + lp.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + s2p.get_variable(),
        );

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
        let new_pos = AllocatedNum::alloc(cs.namespace(|| "new pos"), || {
            Ok(Scalar::ONE - pos.get_value().ok_or(SynthesisError::AssignmentMissing)?)
        })?;
        cs.enforce(
            || "new_pos = 1 - pos",
            |lc| lc + CS::one() - pos.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + new_pos.get_variable(),
        );

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

        // ── assemble z' (fixed layout; commD at MAX_DEPTH+1, depth threaded unchanged). ──
        let mut out = filled;
        out.push(new_index);
        out.push(cur); // commD (masked root at level `depth`)
        out.push(final0);
        out.push(final1); // dataCommit at the last step
        out.push(final2);
        out.push(new_pos);
        out.push(depth); // unchanged
        Ok(out)
    }
}

/// The built fixed-arity fold pipeline: `pp`, the folded `rs`, `z0`, and `num_steps`. `depth` lives in
/// `z0[MAX_DEPTH+6]`; `commD`/`dataCommit` are read at the FIXED slots `MAX_DEPTH+1` / `MAX_DEPTH+3`.
pub struct BuiltFixedFold {
    pub pp: PublicParams<E1, E2, FixedCommDFoldStep>,
    pub rs: RecursiveSNARK<E1, E2, FixedCommDFoldStep>,
    pub z0: Vec<Scalar>,
    pub num_steps: usize,
}

/// The Merkle zero-subtree roots `zeros[0..=MAX_DEPTH]`, as Nova scalars.
fn zeros_scalars() -> Vec<Scalar> {
    let mut zeros: Vec<Scalar> = vec![Scalar::ZERO];
    let mut zeros_ark = vec![ark_bn254::Fr::from(0u64)];
    for h in 1..=MAX_DEPTH {
        let za = citrate_commd::poseidon_hash(&[zeros_ark[h - 1], zeros_ark[h - 1]]);
        zeros_ark.push(za);
        zeros.push(ark_fr_to_scalar(za));
    }
    zeros
}

/// Construct the only valid initial public state for a fixed fold.
///
/// The precompile receives `z0` over the wire for ABI compatibility, but all of
/// its load-bearing fields are derived here from the public leaf count and
/// depth. This prevents an attacker from supplying forged `filled`, sponge,
/// position, or depth state to a sound Nova step circuit.
pub fn canonical_initial_state(
    num_steps: usize,
    depth: usize,
) -> Result<Vec<Scalar>, Box<dyn std::error::Error>> {
    if num_steps == 0 {
        return Err("fold must contain at least one leaf".into());
    }

    let max_leaves = 1u64 << MAX_DEPTH;
    if num_steps as u64 > max_leaves {
        return Err(format!("leaf count exceeds MAX_DEPTH {MAX_DEPTH}").into());
    }

    let expected_depth = if num_steps <= 1 {
        0
    } else {
        num_steps.next_power_of_two().trailing_zeros() as usize
    };
    if depth != expected_depth || depth > MAX_DEPTH {
        return Err(format!(
            "depth {depth} does not match leaf count {num_steps} (expected {expected_depth})"
        )
        .into());
    }

    let zeros = zeros_scalars();
    let pre = citrate_commd::data_commit_preamble_state(num_steps);
    let mut z0: Vec<Scalar> = zeros[0..MAX_DEPTH].to_vec();
    z0.push(Scalar::ZERO); // index
    z0.push(Scalar::ZERO); // commD (overwritten by the first step)
    z0.push(ark_fr_to_scalar(pre[0]));
    z0.push(ark_fr_to_scalar(pre[1]));
    z0.push(ark_fr_to_scalar(pre[2]));
    z0.push(Scalar::ZERO); // pos
    z0.push(Scalar::from(depth as u64));
    Ok(z0)
}

/// The file-INDEPENDENT public parameters for the fixed-arity circuit. Because the R1CS shape is fixed
/// (MAX_DEPTH), one `pp` (and thus one `CompressedSNARK` verifier key) covers EVERY file — this is the
/// whole point of the fixed-arity rework. Derived from a canonical empty-file sample circuit.
pub fn fixed_public_params(
) -> Result<PublicParams<E1, E2, FixedCommDFoldStep>, Box<dyn std::error::Error>> {
    let c0 = FixedCommDFoldStep {
        leaf: Scalar::ZERO,
        is_last: true,
        zeros: zeros_scalars(),
        gadget: Arc::new(PoseidonBn254Gadget::from_citrate_commd()),
    };
    Ok(PublicParams::setup(
        &c0,
        &*S1::ck_floor(),
        &*S2::ck_floor(),
    )?)
}

/// A folded fixed-arity pipeline WITHOUT its `pp` (the caller shares one `pp`/`vk` across files).
pub struct FoldedFixed {
    pub rs: RecursiveSNARK<E1, E2, FixedCommDFoldStep>,
    pub z0: Vec<Scalar>,
    pub num_steps: usize,
    pub depth: usize,
}

/// PRODUCTION public parameters: same fixed-arity circuit, but the commitment key comes from a
/// trusted-setup `.ptau` directory (Nova auto-selects the right-sized file) instead of the insecure
/// `test-utils` deterministic SRS. This is what the VK-bake tool uses for the baked precompile key.
/// The circuit (and thus the VK) is identical regardless of SRS source — only the toxic-waste
/// provenance differs.
pub fn fixed_public_params_ptau(
    ptau_dir: &std::path::Path,
) -> Result<PublicParams<E1, E2, FixedCommDFoldStep>, Box<dyn std::error::Error>> {
    let c0 = FixedCommDFoldStep {
        leaf: Scalar::ZERO,
        is_last: true,
        zeros: zeros_scalars(),
        gadget: Arc::new(PoseidonBn254Gadget::from_citrate_commd()),
    };
    Ok(PublicParams::setup_with_ptau_dir(
        &c0,
        &*S1::ck_floor(),
        &*S2::ck_floor(),
        ptau_dir,
    )?)
}

/// Run the fixed-arity binding fold over `data` against a SHARED `pp` (borrowed, so one `pp`/`vk`
/// serves every file). NOT yet verified.
pub fn fold_fixed_with_pp(
    data: &[u8],
    pp: &PublicParams<E1, E2, FixedCommDFoldStep>,
) -> Result<FoldedFixed, Box<dyn std::error::Error>> {
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
    if depth > MAX_DEPTH {
        return Err(format!("file needs depth {depth} > MAX_DEPTH {MAX_DEPTH}").into());
    }

    let zeros = zeros_scalars();
    let gadget = Arc::new(PoseidonBn254Gadget::from_citrate_commd());
    let mk = |leaf: Scalar, is_last: bool| FixedCommDFoldStep {
        leaf,
        is_last,
        zeros: zeros.clone(),
        gadget: gadget.clone(),
    };

    // z0 is derived from the public leaf count/depth, never caller-supplied.
    let z0 = canonical_initial_state(n, depth)?;

    let mut rs =
        RecursiveSNARK::<E1, E2, FixedCommDFoldStep>::new(pp, &mk(leaves[0], n == 1), &z0)?;
    for (i, &leaf) in leaves.iter().enumerate() {
        rs.prove_step(pp, &mk(leaf, i + 1 == n))?;
    }
    Ok(FoldedFixed {
        rs,
        z0,
        num_steps: n,
        depth,
    })
}

/// Build `pp` and run the fixed-arity binding fold over `data` (NOT yet verified). Convenience wrapper
/// that generates a fresh `pp`; use [`fold_fixed_with_pp`] to share one across files.
pub fn build_fixed_fold(data: &[u8]) -> Result<BuiltFixedFold, Box<dyn std::error::Error>> {
    let pp = fixed_public_params()?;
    let f = fold_fixed_with_pp(data, &pp)?;
    Ok(BuiltFixedFold {
        pp,
        rs: f.rs,
        z0: f.z0,
        num_steps: f.num_steps,
    })
}

/// commD / dataCommit slots in the fixed public state.
pub const COMMD_INDEX: usize = MAX_DEPTH + 1;
pub const DATACOMMIT_INDEX: usize = MAX_DEPTH + 3;

/// The serialized `CompressedSNARK` verifier key for `pp` — the artifact the `0x0130` precompile
/// bakes (via `include_bytes!`). One key covers every file (fixed arity). Bincode-encoded, matching
/// `citrate-commd-verify`'s deserialization.
pub fn compressed_verifier_key(
    pp: &PublicParams<E1, E2, FixedCommDFoldStep>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let (_pk, vk) = CompressedSNARK::<E1, E2, FixedCommDFoldStep, S1, S2>::setup(pp)?;
    Ok(bincode::serialize(&vk)?)
}

/// A compressed fixed-arity proof + everything the verifier needs. `vk_bytes` is the SAME for every
/// file (the single baked key); `proof_bytes` is ~a few KB. This is the artifact the `0x0130`
/// precompile consumes (proof + z0 from calldata; the vk baked in).
pub struct FixedCompressedProof {
    pub comm_d: [u8; 32],
    pub data_commit: [u8; 32],
    pub num_steps: usize,
    pub depth: usize,
    pub z0: Vec<Scalar>,
    pub proof_bytes: Vec<u8>,
    pub vk_bytes: Vec<u8>,
}

/// Fold `data` on the fixed-arity circuit, compress, verify, and package the artifact (proof + shared
/// vk + public inputs). Returns iff the compressed proof verifies.
pub fn prove_fixed_compressed(
    data: &[u8],
) -> Result<FixedCompressedProof, Box<dyn std::error::Error>> {
    let pp = fixed_public_params()?;
    let (pk, vk) = CompressedSNARK::<E1, E2, FixedCommDFoldStep, S1, S2>::setup(&pp)?;
    let folded = fold_fixed_with_pp(data, &pp)?;
    let snark = CompressedSNARK::<E1, E2, FixedCommDFoldStep, S1, S2>::prove(&pp, &pk, &folded.rs)?;
    let zn = snark.verify(&vk, folded.num_steps, &folded.z0)?;
    Ok(FixedCompressedProof {
        comm_d: scalar_to_be_bytes(zn[COMMD_INDEX]),
        data_commit: scalar_to_be_bytes(zn[DATACOMMIT_INDEX]),
        num_steps: folded.num_steps,
        depth: folded.depth,
        z0: folded.z0,
        proof_bytes: bincode::serialize(&snark)?,
        vk_bytes: bincode::serialize(&vk)?,
    })
}

/// Fold + recursively verify; return `(commD, dataCommit)`.
pub fn fold_commd_fixed(data: &[u8]) -> Result<([u8; 32], [u8; 32]), Box<dyn std::error::Error>> {
    let built = build_fixed_fold(data)?;
    let out = built.rs.verify(&built.pp, built.num_steps, &built.z0)?;
    Ok((
        scalar_to_be_bytes(out[COMMD_INDEX]),
        scalar_to_be_bytes(out[DATACOMMIT_INDEX]),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_snark::nova::CompressedSNARK;

    /// M3 fixed-arity acceptance: ONE circuit (MAX_DEPTH) proves the canonical `(commD, dataCommit)`
    /// for DIFFERENT file sizes — the property that lets a single baked VK cover every file.
    #[test]
    fn fixed_fold_matches_reference_across_sizes() {
        for &n_bytes in &[1usize, 31, 32, 100, 200] {
            let data: Vec<u8> = (0..n_bytes).map(|i| (i * 13 + 5) as u8).collect();
            let (commd, datacommit) =
                fold_commd_fixed(&data).expect("fixed fold + verify must succeed");
            assert_eq!(
                commd,
                citrate_commd::compute_comm_d(&data),
                "fixed commD != reference at {n_bytes}B"
            );
            assert_eq!(
                datacommit,
                citrate_commd::compute_data_commit(&data),
                "fixed dataCommit != reference at {n_bytes}B"
            );
        }
    }

    /// ★ THE M3 PAYOFF: a SINGLE (pp, verifier key) — generated once, file-independent — verifies
    /// compressed proofs for files of DIFFERENT depths. This is exactly what the precompile bakes: one
    /// VK for all files. Each verified proof still binds the canonical `(commD, dataCommit)`.
    #[test]
    fn one_verifier_key_covers_different_file_sizes() {
        let pp = fixed_public_params().expect("pp");
        let (pk, vk) =
            CompressedSNARK::<E1, E2, FixedCommDFoldStep, S1, S2>::setup(&pp).expect("vk");

        // Two files with DIFFERENT depths (32 B → 2 leaves → depth 1; 200 B → 7 leaves → depth 3).
        for &n_bytes in &[32usize, 200] {
            let data: Vec<u8> = (0..n_bytes).map(|i| (i * 9 + 2) as u8).collect();
            let folded = fold_fixed_with_pp(&data, &pp).expect("fold");
            let snark =
                CompressedSNARK::<E1, E2, FixedCommDFoldStep, S1, S2>::prove(&pp, &pk, &folded.rs)
                    .expect("compress");
            let zn = snark
                .verify(&vk, folded.num_steps, &folded.z0)
                .expect("verify against the SHARED vk");
            assert_eq!(
                scalar_to_be_bytes(zn[COMMD_INDEX]),
                citrate_commd::compute_comm_d(&data),
                "shared-vk commD != reference at {n_bytes}B"
            );
            assert_eq!(
                scalar_to_be_bytes(zn[DATACOMMIT_INDEX]),
                citrate_commd::compute_data_commit(&data),
                "shared-vk dataCommit != reference at {n_bytes}B"
            );
        }
    }
}
