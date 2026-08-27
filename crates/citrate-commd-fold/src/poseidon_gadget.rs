//! In-circuit Poseidon-BN254 (citrate-chain#170, M2b) — a bellpepper/Nova gadget that computes the
//! SAME 2-input Poseidon compression as `citrate-commd::poseidon_hash(&[a, b])`, byte-for-byte.
//!
//! This is the crux of the recursive CommD proof: the fold step recomputes the incremental-Merkle
//! root in-circuit, and every node is `H(left, right)` under THIS gadget. If the gadget disagrees
//! with the native hash by a single bit, the folded `commD` diverges from `citrate-commd::compute_comm_d`
//! and the whole proof is worthless. So the gadget is not "a Poseidon" — it is a bit-exact re-execution
//! of ark-crypto-primitives' `PoseidonSponge` permutation over the frozen 0x0108 constants.
//!
//! Nova's built-in Poseidon (`neptune`/`SpongeCircuit`) uses DIFFERENT round constants and cannot be
//! reused; hence this bespoke gadget. Its constants are loaded from the one canonical source —
//! `citrate-commd::poseidon_config()` (the ark `PoseidonConfig`) — and converted into Nova's scalar
//! field; there are no hand-copied numbers to drift. Correctness is pinned by `gadget_hash_matches_native`.
//!
//! Reduction (proven natively in `citrate-commd`, ark `PoseidonSponge`, rate 2 / capacity 1):
//!   `poseidon_hash([a, b]) == permute([0, a, b])[1]`
//! i.e. the capacity lane starts at 0, `a`/`b` are absorbed into the two rate lanes, one permutation
//! runs, and the first rate lane is squeezed. The permutation is
//!   round r: state += ARK[r];  S-box (x^5: all lanes if full round, lane 0 only if partial);  state = MDS·state
//! with full rounds on `r ∈ [0, half) ∪ [half+partial, total)` and partial rounds in between.

use ark_ff::{BigInteger, PrimeField as _};
use ff::{Field as _, PrimeField as _};
use nova_snark::frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError};

use crate::Scalar;

/// Convert an ark BN254 `Fr` to Nova's scalar (`halo2curves` bn256 `Fr`). Both are the SAME field
/// (the BN254 scalar field r); the canonical little-endian representative maps 1:1. Infallible for a
/// valid field element — the `.expect` fires only if the two crates disagree on the field modulus,
/// which would be a build-level impossibility we want to surface loudly rather than mask.
pub fn ark_fr_to_scalar(f: ark_bn254::Fr) -> Scalar {
    let le = f.into_bigint().to_bytes_le(); // <= 32 bytes, little-endian, canonical (< r)
    let mut repr = [0u8; 32];
    repr[..le.len()].copy_from_slice(&le);
    Option::from(Scalar::from_repr(repr.into()))
        .expect("ark BN254 Fr is a canonical element of the shared scalar field")
}

/// Poseidon-BN254 constants for the in-circuit gadget, converted once from `citrate-commd`'s frozen
/// ark `PoseidonConfig` into Nova's scalar field. Shape mirrors ark: `ark[round][lane]`, `mds[i][j]`,
/// `width = rate + capacity`.
#[derive(Clone)]
pub struct PoseidonBn254Gadget {
    full_rounds: usize,
    partial_rounds: usize,
    width: usize,
    ark: Vec<Vec<Scalar>>,
    mds: Vec<Vec<Scalar>>,
}

impl PoseidonBn254Gadget {
    /// Load the constants from the single canonical source (`citrate-commd`) and convert to Nova's
    /// field. This is the ONLY place constants enter the gadget — keeping it differentially bound to
    /// the native hash used by the contract, sealer, and client.
    pub fn from_citrate_commd() -> Self {
        let cfg = citrate_commd::poseidon_config();
        let conv = |m: &Vec<Vec<ark_bn254::Fr>>| -> Vec<Vec<Scalar>> {
            m.iter()
                .map(|row| row.iter().copied().map(ark_fr_to_scalar).collect())
                .collect()
        };
        Self {
            full_rounds: cfg.full_rounds,
            partial_rounds: cfg.partial_rounds,
            width: cfg.rate + cfg.capacity,
            ark: conv(&cfg.ark),
            mds: conv(&cfg.mds),
        }
    }

    /// The 2-input compression `H(a, b)` used at every Merkle node — bit-identical to
    /// `citrate-commd::poseidon_hash(&[a, b])`. Allocates a capacity lane constrained to 0, absorbs
    /// `a`/`b` into the rate lanes, runs one permutation, and returns the first rate lane.
    pub fn hash2<CS: ConstraintSystem<Scalar>>(
        &self,
        mut cs: CS,
        a: &AllocatedNum<Scalar>,
        b: &AllocatedNum<Scalar>,
    ) -> Result<AllocatedNum<Scalar>, SynthesisError> {
        // Capacity lane = 0. Allocate AND constrain it to zero (a free variable here would be a
        // soundness hole: a malicious prover could set the capacity to forge the root).
        let cap = AllocatedNum::alloc(cs.namespace(|| "capacity"), || Ok(Scalar::ZERO))?;
        cs.enforce(
            || "capacity == 0",
            |lc| lc + cap.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc, // C-side is the zero linear combination
        );
        let mut state = vec![cap, a.clone(), b.clone()];
        debug_assert_eq!(
            self.width,
            state.len(),
            "width must be rate(2)+capacity(1)=3"
        );
        self.permute(cs.namespace(|| "permute"), &mut state)?;
        Ok(state[1].clone())
    }

    /// One full Poseidon permutation over a 3-lane state, returned functionally — the sponge fold
    /// (`dataCommit`) permutes `[capacity, rate0, rate1]` whenever a rate-pair completes and once more
    /// at squeeze. Bit-identical to `citrate-commd::poseidon_permute` (asserted by the fold's
    /// differential test against `compute_data_commit`).
    pub fn permute3<CS: ConstraintSystem<Scalar>>(
        &self,
        mut cs: CS,
        state: [AllocatedNum<Scalar>; 3],
    ) -> Result<[AllocatedNum<Scalar>; 3], SynthesisError> {
        let mut v = state.to_vec();
        self.permute(cs.namespace(|| "permute3"), &mut v)?;
        Ok([v[0].clone(), v[1].clone(), v[2].clone()])
    }

    /// One full Poseidon permutation over `state` (length `width`), in place. Mirrors ark's
    /// `PoseidonSponge::permute` exactly: ARK → S-box → MDS, with the full/partial round schedule.
    // The lane index reads parallel arrays (`state[i]` and the constant `ark[r][i]`), so an explicit
    // index loop is clearer than zipping — mirrors ark's own `apply_ark`.
    #[allow(clippy::needless_range_loop)]
    fn permute<CS: ConstraintSystem<Scalar>>(
        &self,
        mut cs: CS,
        state: &mut [AllocatedNum<Scalar>],
    ) -> Result<(), SynthesisError> {
        let half = self.full_rounds / 2;
        let total = self.full_rounds + self.partial_rounds;
        for r in 0..total {
            let is_full = r < half || r >= half + self.partial_rounds;
            // --- ARK: state[i] += ark[r][i] ---
            for i in 0..self.width {
                state[i] = add_const(
                    cs.namespace(|| format!("ark r{r} lane{i}")),
                    &state[i],
                    self.ark[r][i],
                )?;
            }
            // --- S-box (x^5): all lanes on full rounds, lane 0 only on partial rounds ---
            if is_full {
                for i in 0..self.width {
                    state[i] = pow5(cs.namespace(|| format!("sbox r{r} lane{i}")), &state[i])?;
                }
            } else {
                state[0] = pow5(cs.namespace(|| format!("sbox r{r} lane0")), &state[0])?;
            }
            // --- MDS: state = M · state ---
            let mixed = self.apply_mds(cs.namespace(|| format!("mds r{r}")), state)?;
            state.clone_from_slice(&mixed);
        }
        Ok(())
    }

    /// `out[i] = Σ_j mds[i][j] · state[j]` — the linear MDS mix. Each output lane is one allocated
    /// wire constrained by a single linear R1CS row (the mix is affine, so no multiplication gates).
    // Index loop: `i`/`j` index the constant `mds[i][j]` matrix against `state[j]` — the matmul reads
    // clearest as a double index loop, matching ark's `apply_mds`.
    #[allow(clippy::needless_range_loop)]
    fn apply_mds<CS: ConstraintSystem<Scalar>>(
        &self,
        mut cs: CS,
        state: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let mut out = Vec::with_capacity(self.width);
        for i in 0..self.width {
            let value = || -> Option<Scalar> {
                let mut acc = Scalar::ZERO;
                for j in 0..self.width {
                    acc += self.mds[i][j] * state[j].get_value()?;
                }
                Some(acc)
            };
            let out_i = AllocatedNum::alloc(cs.namespace(|| format!("mds out{i}")), || {
                value().ok_or(SynthesisError::AssignmentMissing)
            })?;
            // Enforce (Σ mds[i][j]·state[j]) · 1 = out_i.
            let row = self.mds[i].clone();
            let state_vars: Vec<_> = state.iter().map(|s| s.get_variable()).collect();
            cs.enforce(
                || format!("mds row {i}"),
                |mut lc| {
                    for j in 0..row.len() {
                        lc = lc + (row[j], state_vars[j]);
                    }
                    lc
                },
                |lc| lc + CS::one(),
                |lc| lc + out_i.get_variable(),
            );
            out.push(out_i);
        }
        Ok(out)
    }
}

/// `y = x + c` for a field constant `c`. One linear R1CS row `(x + c)·1 = y`. Shared with the fold
/// step (the running index is incremented via `add_const(index, 1)`).
pub(crate) fn add_const<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    x: &AllocatedNum<Scalar>,
    c: Scalar,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    let y = AllocatedNum::alloc(cs.namespace(|| "sum"), || {
        Ok(x.get_value().ok_or(SynthesisError::AssignmentMissing)? + c)
    })?;
    cs.enforce(
        || "y = x + c",
        |lc| lc + x.get_variable() + (c, CS::one()),
        |lc| lc + CS::one(),
        |lc| lc + y.get_variable(),
    );
    Ok(y)
}

/// `y = x^5` (the Poseidon S-box, alpha = 5). Three multiplication gates: x² , x⁴ , x⁵ = x⁴·x.
fn pow5<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    x: &AllocatedNum<Scalar>,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    let x2 = x.square(cs.namespace(|| "x2"))?;
    let x4 = x2.square(cs.namespace(|| "x4"))?;
    x4.mul(cs.namespace(|| "x5"), x)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr as ArkFr;
    use nova_snark::frontend::test_cs::TestConstraintSystem;

    /// THE M2b crux test: the in-circuit gadget's `H(a, b)` equals the native
    /// `citrate-commd::poseidon_hash(&[a, b])` for every probe — and the circuit is satisfied.
    /// If this passes, the recursive fold can recompute the exact canonical CommD in-circuit.
    #[test]
    fn gadget_hash_matches_native() {
        let g = PoseidonBn254Gadget::from_citrate_commd();
        // Probes: zeros (the Merkle zero-subtree case), equal lanes (H(z,z)), small, and large values.
        let probes: &[(u64, u64)] = &[
            (0, 0),
            (1, 0),
            (0, 1),
            (1, 2),
            (7, 7),
            (255, 256),
            (123_456_789, 987_654_321),
            (u64::MAX, 1),
        ];
        for &(av, bv) in probes {
            let a_ark = ArkFr::from(av);
            let b_ark = ArkFr::from(bv);
            let native = citrate_commd::poseidon_hash(&[a_ark, b_ark]);
            let expected = ark_fr_to_scalar(native);

            let mut cs = TestConstraintSystem::<Scalar>::new();
            let a = AllocatedNum::alloc(cs.namespace(|| "a"), || Ok(ark_fr_to_scalar(a_ark)))
                .expect("alloc a");
            let b = AllocatedNum::alloc(cs.namespace(|| "b"), || Ok(ark_fr_to_scalar(b_ark)))
                .expect("alloc b");
            let out = g.hash2(cs.namespace(|| "hash"), &a, &b).expect("hash2");

            assert!(cs.is_satisfied(), "gadget CS unsatisfied at ({av},{bv})");
            assert_eq!(
                out.get_value().expect("out value"),
                expected,
                "in-circuit H({av},{bv}) != native poseidon_hash"
            );
        }
    }

    /// The capacity constraint is load-bearing: without `capacity == 0` a prover could pick any
    /// capacity. Here we just assert the honest path constrains it (a full negative soundness test
    /// belongs in the fold-level R1CS check). The gadget must produce a fully-satisfied system with a
    /// non-trivial constraint count (it is a real 64-round permutation, not a shortcut).
    #[test]
    fn gadget_emits_real_constraints() {
        let g = PoseidonBn254Gadget::from_citrate_commd();
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let a = AllocatedNum::alloc(cs.namespace(|| "a"), || Ok(Scalar::from(3u64))).expect("a");
        let b = AllocatedNum::alloc(cs.namespace(|| "b"), || Ok(Scalar::from(4u64))).expect("b");
        let _ = g.hash2(cs.namespace(|| "hash"), &a, &b).expect("hash2");
        assert!(cs.is_satisfied(), "honest hash must satisfy");
        // 64 rounds; every round has an MDS (3 lanes) + ARK (3 lanes); full rounds add 3 S-boxes (×3
        // gates), partial rounds 1 S-box. Far more than a trivial handful — guards against a gadget
        // that silently degenerates to an identity.
        assert!(
            cs.num_constraints() > 200,
            "expected a real permutation, got {} constraints",
            cs.num_constraints()
        );
    }
}
