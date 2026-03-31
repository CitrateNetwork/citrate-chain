// citrate/core/execution/src/zkp/poseidon.rs
//
// Poseidon hash function for ZK-SNARK circuits.
//
// Poseidon uses significantly fewer R1CS constraints per hash than MiMC
// (~213-320 constraints vs MiMC's ~660+ per element), making it the preferred
// commitment scheme for new circuits.
//
// Parameters (BLS12-381 scalar field):
//   - width = 3 (rate = 2, capacity = 1)
//   - full rounds = 8 (4 + 4)
//   - partial rounds = 56
//   - S-box exponent = 5 (x^5)
//   - MDS and round constants generated via Grain LFSR (standard Poseidon)
//
// This module wraps the `ark-crypto-primitives` sponge-based Poseidon
// implementation, providing simple hash interfaces that mirror mimc.rs.

use ark_bls12_381::Fr;
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::poseidon::traits::find_poseidon_ark_and_mds;
use ark_crypto_primitives::sponge::{
    CryptographicSponge, FieldBasedCryptographicSponge,
};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use once_cell::sync::Lazy;

use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;

/// Poseidon parameters for BLS12-381 Fr.
///
/// Standard Poseidon with:
///   - rate = 2 (absorb 2 field elements per permutation)
///   - capacity = 1
///   - full_rounds = 8 (4 before + 4 after partial rounds)
///   - partial_rounds = 56
///   - alpha (S-box exponent) = 5
///
/// Round constants and MDS matrix are generated deterministically via the
/// Poseidon Grain LFSR, the same method used by the reference implementation.
static POSEIDON_CONFIG: Lazy<PoseidonConfig<Fr>> = Lazy::new(|| {
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

// ---------------------------------------------------------------------------
// Native (out-of-circuit) functions
// ---------------------------------------------------------------------------

/// Native Poseidon hash over a slice of field elements.
///
/// Uses a sponge construction: absorbs all inputs, then squeezes one
/// field element as the hash digest.
pub fn poseidon_hash(inputs: &[Fr]) -> Fr {
    if inputs.is_empty() {
        return Fr::from(0u64);
    }
    let config = &*POSEIDON_CONFIG;
    let mut sponge = PoseidonSponge::<Fr>::new(config);
    sponge.absorb(&inputs.to_vec());
    let result = sponge.squeeze_native_field_elements(1);
    result[0]
}

// ---------------------------------------------------------------------------
// In-circuit functions
// ---------------------------------------------------------------------------

/// In-circuit Poseidon hash over a slice of FpVar field elements.
///
/// Mirrors the native `poseidon_hash` but generates R1CS constraints.
/// Uses the PoseidonSpongeVar gadget from ark-crypto-primitives.
pub fn poseidon_hash_circuit(
    cs: ConstraintSystemRef<Fr>,
    inputs: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    if inputs.is_empty() {
        return FpVar::new_constant(cs, Fr::from(0u64));
    }
    let config = &*POSEIDON_CONFIG;
    let mut sponge = PoseidonSpongeVar::<Fr>::new(cs, config);
    sponge.absorb(&inputs.to_vec())?;
    let result = sponge.squeeze_field_elements(1)?;
    Ok(result[0].clone())
}

/// Get a reference to the Poseidon configuration (for testing / external use).
pub fn poseidon_config() -> &'static PoseidonConfig<Fr> {
    &POSEIDON_CONFIG
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_poseidon_hash_deterministic() {
        let data = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let h1 = poseidon_hash(&data);
        let h2 = poseidon_hash(&data);
        assert_eq!(h1, h2, "Poseidon hash must be deterministic");
    }

    #[test]
    fn test_poseidon_hash_collision_resistance() {
        let a = vec![Fr::from(1u64), Fr::from(2u64)];
        let b = vec![Fr::from(1u64), Fr::from(3u64)];
        assert_ne!(
            poseidon_hash(&a),
            poseidon_hash(&b),
            "Different inputs must produce different hashes"
        );
    }

    #[test]
    fn test_poseidon_hash_empty() {
        let h = poseidon_hash(&[]);
        assert_eq!(h, Fr::from(0u64), "Hash of empty input should be zero");
    }

    #[test]
    fn test_poseidon_hash_single_element() {
        let h = poseidon_hash(&[Fr::from(42u64)]);
        assert!(!h.is_zero(), "Hash of [42] must be non-zero");
    }

    #[test]
    fn test_poseidon_hash_order_matters() {
        let a = vec![Fr::from(1u64), Fr::from(2u64)];
        let b = vec![Fr::from(2u64), Fr::from(1u64)];
        assert_ne!(
            poseidon_hash(&a),
            poseidon_hash(&b),
            "[1,2] and [2,1] must hash differently"
        );
    }

    #[test]
    fn test_poseidon_hash_different_lengths() {
        let a = vec![Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)];
        let b = vec![Fr::from(0u64), Fr::from(0u64)];
        assert_ne!(
            poseidon_hash(&a),
            poseidon_hash(&b),
            "Hash of [0,0,0] must differ from hash of [0,0]"
        );
    }

    #[test]
    fn test_poseidon_circuit_matches_native() {
        let data = vec![Fr::from(10u64), Fr::from(20u64), Fr::from(30u64)];
        let native_hash = poseidon_hash(&data);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let data_vars: Vec<FpVar<Fr>> = data
            .iter()
            .map(|d| FpVar::new_witness(cs.clone(), || Ok(*d)).unwrap())
            .collect();

        let circuit_hash = poseidon_hash_circuit(cs.clone(), &data_vars).unwrap();
        let circuit_val = circuit_hash.value().unwrap();

        assert_eq!(
            native_hash, circuit_val,
            "Circuit hash must match native hash"
        );
        assert!(cs.is_satisfied().unwrap(), "Constraints must be satisfied");
    }

    #[test]
    fn test_poseidon_circuit_single_element() {
        let data = vec![Fr::from(99u64)];
        let native_hash = poseidon_hash(&data);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let data_vars: Vec<FpVar<Fr>> = data
            .iter()
            .map(|d| FpVar::new_witness(cs.clone(), || Ok(*d)).unwrap())
            .collect();

        let circuit_hash = poseidon_hash_circuit(cs.clone(), &data_vars).unwrap();
        let circuit_val = circuit_hash.value().unwrap();

        assert_eq!(
            native_hash, circuit_val,
            "Single-element circuit hash must match native"
        );
        assert!(cs.is_satisfied().unwrap(), "Constraints must be satisfied");
    }

    #[test]
    fn test_poseidon_circuit_empty() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit_hash = poseidon_hash_circuit(cs.clone(), &[]).unwrap();
        let circuit_val = circuit_hash.value().unwrap();
        assert_eq!(circuit_val, Fr::from(0u64), "Empty circuit hash must be zero");
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_poseidon_fewer_constraints_than_mimc() {
        let data: Vec<Fr> = (0..10).map(|i| Fr::from(i as u64)).collect();

        // MiMC constraints
        let cs_mimc = ConstraintSystem::<Fr>::new_ref();
        let vars_mimc: Vec<_> = data
            .iter()
            .map(|d| FpVar::new_witness(cs_mimc.clone(), || Ok(*d)).unwrap())
            .collect();
        let _ = super::super::mimc::mimc_hash_circuit(cs_mimc.clone(), &vars_mimc).unwrap();
        let mimc_constraints = cs_mimc.num_constraints();

        // Poseidon constraints
        let cs_pos = ConstraintSystem::<Fr>::new_ref();
        let vars_pos: Vec<_> = data
            .iter()
            .map(|d| FpVar::new_witness(cs_pos.clone(), || Ok(*d)).unwrap())
            .collect();
        let _ = poseidon_hash_circuit(cs_pos.clone(), &vars_pos).unwrap();
        let pos_constraints = cs_pos.num_constraints();

        eprintln!(
            "MiMC: {} constraints, Poseidon: {} constraints ({}x reduction)",
            mimc_constraints,
            pos_constraints,
            mimc_constraints as f64 / pos_constraints as f64
        );
        assert!(
            pos_constraints < mimc_constraints,
            "Poseidon ({}) should have fewer constraints than MiMC ({})",
            pos_constraints,
            mimc_constraints
        );
    }

    #[test]
    fn test_poseidon_large_input() {
        // Hash of 100 elements should complete without panic
        let data: Vec<Fr> = (0..100).map(|i| Fr::from(i as u64)).collect();
        let h = poseidon_hash(&data);
        assert!(!h.is_zero(), "Hash of 100 elements must be non-zero");
    }

    #[test]
    fn test_poseidon_config_valid() {
        let config = poseidon_config();
        assert_eq!(config.full_rounds, 8);
        assert_eq!(config.partial_rounds, 56);
        assert_eq!(config.alpha, 5);
        assert_eq!(config.rate, 2);
        assert_eq!(config.capacity, 1);
        // MDS should be 3x3 (rate + capacity = 3)
        assert_eq!(config.mds.len(), 3);
        for row in &config.mds {
            assert_eq!(row.len(), 3);
        }
        // ARK should have full_rounds + partial_rounds entries
        assert_eq!(config.ark.len(), 64); // 8 + 56
        for entry in &config.ark {
            assert_eq!(entry.len(), 3); // width = rate + capacity = 3
        }
    }
}
