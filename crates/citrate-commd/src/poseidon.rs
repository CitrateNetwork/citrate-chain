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
