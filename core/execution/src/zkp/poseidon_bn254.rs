// citrate/core/execution/src/zkp/poseidon_bn254.rs
//
// Poseidon hash over BN254 Fr — RM-M1b commitment substrate.
//
// Parallel to `zkp/poseidon.rs` which operates on BLS12-381 Fr.
// The BN254 variant is what RM-M1b's 0x0108 verifier uses
// in-circuit, so the off-chain primitive at 0x0107 must use the
// SAME field for proof composability.
//
// Parameters (identical to the BLS12-381 variant; only the field
// differs):
//   - rate = 2 (absorb 2 field elements per permutation)
//   - capacity = 1
//   - full_rounds = 8 (4 before + 4 after partial)
//   - partial_rounds = 56
//   - alpha = 5 (S-box exponent x^5)
//   - ARK + MDS via Grain LFSR (regenerated per field; the BN254
//     constants will differ from BLS12-381 because the LFSR
//     output depends on the field modulus)
//
// **Versioning:** the byte output of `poseidon_hash` here is
// FROZEN against the test vectors in `poseidon_bn254_frozen_v1.rs`.
// Drift in the underlying constants (e.g. an
// `ark-crypto-primitives` bump that changes
// `find_poseidon_ark_and_mds`'s LFSR) silently invalidates every
// 0x0107 commitment ever made on BN254. The frozen-vectors test
// is the canary; do NOT regenerate to make it pass — see the
// procedure block at the top of `poseidon_bn254_frozen_v1.rs`.

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::traits::find_poseidon_ark_and_mds;
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::{
    CryptographicSponge, FieldBasedCryptographicSponge,
};
use ark_ff::PrimeField;
use once_cell::sync::Lazy;

/// Poseidon parameters for BN254 Fr.
///
/// Standard Poseidon-2 with the same shape as the BLS12-381
/// variant in `zkp::poseidon`. Constants are derived
/// deterministically by the Grain LFSR over the BN254 field
/// modulus — they are NOT copies of the BLS12-381 constants.
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

    PoseidonConfig::new(
        full_rounds,
        partial_rounds,
        alpha,
        mds,
        ark,
        rate,
        capacity,
    )
});

/// Native Poseidon hash over a slice of BN254 field elements.
/// Matches the byte output the RM-M1b in-circuit Poseidon chip
/// produces (load-bearing soundness invariant per ADR-RM-M1b-1).
///
/// Sponge construction: absorb all inputs, squeeze one field
/// element as the digest. Empty input maps to field zero (sentinel
/// for absent commitment) — same convention as `zkp::poseidon`.
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

/// Get a reference to the Poseidon configuration. Used by the
/// halo2 chip in `zkp/halo2/chips.rs` to load the same ARK + MDS
/// constants into fixed columns. Single source of truth: the
/// chip and the off-chain hash MUST consume the same config.
pub fn poseidon_config() -> &'static PoseidonConfig<Fr> {
    &POSEIDON_CONFIG_BN254
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

    #[test]
    fn poseidon_hash_deterministic() {
        let data = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let h1 = poseidon_hash(&data);
        let h2 = poseidon_hash(&data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn poseidon_hash_collision_resistance_smoke() {
        let a = vec![Fr::from(1u64), Fr::from(2u64)];
        let b = vec![Fr::from(1u64), Fr::from(3u64)];
        assert_ne!(poseidon_hash(&a), poseidon_hash(&b));
    }

    #[test]
    fn poseidon_hash_empty_is_zero() {
        let h = poseidon_hash(&[]);
        assert_eq!(h, Fr::from(0u64));
    }

    #[test]
    fn poseidon_hash_order_matters() {
        let a = vec![Fr::from(1u64), Fr::from(2u64)];
        let b = vec![Fr::from(2u64), Fr::from(1u64)];
        assert_ne!(poseidon_hash(&a), poseidon_hash(&b));
    }

    #[test]
    fn poseidon_hash_differs_from_bls12_381_variant() {
        // poseidon_hash([1,2,3]) under BN254 must NOT equal the
        // BLS12-381 variant's output — they're different fields,
        // different ARK constants, different output. If they ever
        // matched, something is wrong with the field-tagging.
        use crate::zkp::poseidon::poseidon_hash as poseidon_bls;
        use ark_bls12_381::Fr as BlsFr;
        use ark_ff::{BigInteger, PrimeField};

        let bls_inputs = vec![BlsFr::from(1u64), BlsFr::from(2u64), BlsFr::from(3u64)];
        let bls_out = poseidon_bls(&bls_inputs);

        let bn_inputs = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let bn_out = poseidon_hash(&bn_inputs);

        // Compare via raw bigint bytes since the field types differ.
        let bls_bytes = bls_out.into_bigint().to_bytes_be();
        let bn_bytes = bn_out.into_bigint().to_bytes_be();
        assert_ne!(
            bls_bytes, bn_bytes,
            "BLS12-381 and BN254 Poseidon must produce different outputs"
        );

        // Sanity: neither is zero (which would be a different bug).
        assert!(!bls_out.is_zero());
        assert!(!bn_out.is_zero());
    }
}
