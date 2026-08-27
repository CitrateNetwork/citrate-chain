// crates/citrate-commd/src/poseidon.rs
//
// Poseidon-BN254 — byte-identical to `citrate-execution`'s
// `core/execution/src/zkp/poseidon_bn254.rs` (the RM-M1b 0x0107/0x0108 commitment
// substrate and the in-circuit `PoseidonChip`). This crate carries its own copy so
// that `compute_comm_d` is available to lean consumers (the CX-S2.2 desktop client)
// WITHOUT pulling the halo2 proving stack. Drift between the two copies is caught by
// the differential test in `citrate-execution` (`poseidon_commd_parity`), which asserts
// this `poseidon_hash` equals the frozen one for the same inputs — do NOT change the
// parameters below to make a test pass; they are the frozen commitment constants.
//
// Parameters (Grain-LFSR-derived, deterministic over the BN254 field):
//   rate = 2, capacity = 1, full_rounds = 8, partial_rounds = 56, alpha = 5, skip = 0.

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::traits::find_poseidon_ark_and_mds;
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ff::PrimeField;
use once_cell::sync::Lazy;

static POSEIDON_CONFIG_BN254: Lazy<PoseidonConfig<Fr>> = Lazy::new(|| {
    let rate = 2usize;
    let capacity = 1usize;
    let full_rounds = 8usize;
    let partial_rounds = 56usize;
    let alpha = 5u64;
    let skip_matrices = 0u64;

    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
        Fr::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds as u64,
        partial_rounds as u64,
        skip_matrices,
    );

    PoseidonConfig::new(full_rounds, partial_rounds, alpha, mds, ark, rate, capacity)
});

/// Native Poseidon hash over a slice of BN254 field elements. Absorb all inputs,
/// squeeze one field element. Empty input maps to field zero (absent-commitment
/// sentinel) — same convention as the frozen `poseidon_bn254::poseidon_hash`.
pub fn poseidon_hash(inputs: &[Fr]) -> Fr {
    if inputs.is_empty() {
        return Fr::from(0u64);
    }
    let config = &*POSEIDON_CONFIG_BN254;
    let mut sponge = PoseidonSponge::<Fr>::new(config);
    sponge.absorb(&inputs.to_vec());
    let result = sponge.squeeze_native_field_elements(1);
    result[0]
}

/// The shared Poseidon config, so an in-circuit chip can load the SAME ARK + MDS.
pub fn poseidon_config() -> &'static PoseidonConfig<Fr> {
    &POSEIDON_CONFIG_BN254
}

/// The raw Poseidon-BN254 permutation over a full-width state (`rate + capacity = 3` lanes),
/// exactly as `ark_crypto_primitives`' `PoseidonSponge::permute`: for each round, `ARK` (add the
/// round constants), the S-box (`x^alpha` on every lane in full rounds, on lane 0 only in partial
/// rounds), then the `MDS` mix. Full rounds are the first and last `full_rounds/2`; the
/// `partial_rounds` sit in the middle.
///
/// Exposed so the recursive fold prover (`citrate-commd-fold`) can (a) seed the `dataCommit` sponge
/// with the post-preamble state and (b) differentially test its in-circuit permutation gadget against
/// this native one, lane-for-lane — a strictly stronger check than `poseidon_hash` alone. It is the
/// single canonical source of the permutation; `permute([0, a, b])[1] == poseidon_hash(&[a, b])` is
/// asserted in the tests below.
pub fn poseidon_permute(state_in: &[Fr]) -> Vec<Fr> {
    use ark_ff::{Field as _, Zero as _};
    let cfg = &*POSEIDON_CONFIG_BN254;
    let width = state_in.len();
    let mut state = state_in.to_vec();
    let half = cfg.full_rounds / 2;
    let total = cfg.full_rounds + cfg.partial_rounds;
    for r in 0..total {
        let is_full = r < half || r >= half + cfg.partial_rounds;
        // ARK.
        for (i, s) in state.iter_mut().enumerate() {
            *s += cfg.ark[r][i];
        }
        // S-box (x^alpha).
        if is_full {
            for s in state.iter_mut() {
                *s = s.pow([cfg.alpha]);
            }
        } else {
            state[0] = state[0].pow([cfg.alpha]);
        }
        // MDS mix.
        let mut mixed = vec![Fr::zero(); width];
        for (i, m) in mixed.iter_mut().enumerate() {
            let mut acc = Fr::zero();
            for (j, s) in state.iter().enumerate() {
                acc += cfg.mds[i][j] * s;
            }
            *m = acc;
        }
        state = mixed;
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero as _;

    #[test]
    fn permute_matches_hash_for_two_inputs() {
        // The 2-input compression the Merkle tree uses IS `permute([0, a, b])[1]` (rate 2 / capacity
        // 1, one absorb of the rate lanes, one permutation, squeeze the first rate lane). This ties
        // the raw permutation to the frozen `poseidon_hash`.
        for (a, b) in [(1u64, 2u64), (7, 7), (0, 0), (123456789, 987654321)] {
            let a = Fr::from(a);
            let b = Fr::from(b);
            let out = poseidon_permute(&[Fr::zero(), a, b]);
            assert_eq!(out[1], poseidon_hash(&[a, b]), "permute[1] != hash(a,b)");
        }
    }
}
