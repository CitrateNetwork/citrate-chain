// citrate/core/execution/src/zkp/mimc.rs
//
// MiMC hash function for ZK-SNARK circuits.
//
// MiMC is a block cipher / hash designed for efficient arithmetic circuit
// evaluation.  It uses only field additions and cubings, so it maps directly
// to R1CS constraints without bit-decomposition overhead.
//
// Core operation (one round):
//     round(x, k, c_i) = (x + k + c_i)^3
//
// Full encryption (220 rounds for BLS12-381 security):
//     MiMC(x, k) = round_n(...round_1(x, k, c_0)..., k, c_{n-1}) + k
//
// Hash mode: Miyaguchi-Preneel sponge
//     H([x_0, ..., x_n]) = fold each x_i into running state via:
//         state = MiMC_encrypt(x_i, state) + x_i + state

use ark_bls12_381::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use once_cell::sync::Lazy;
use sha3::{Digest, Sha3_256};

/// Number of MiMC rounds (standard security parameter for BLS12-381).
const MIMC_ROUNDS: usize = 220;

/// Deterministically generate round constants from a domain separator.
/// Each constant is SHA3("citrate_mimc_round_" || i_le_bytes) mapped to Fr.
fn generate_round_constants() -> Vec<Fr> {
    let mut constants = Vec::with_capacity(MIMC_ROUNDS);
    for i in 0..MIMC_ROUNDS {
        let mut hasher = Sha3_256::new();
        hasher.update(b"citrate_mimc_round_");
        hasher.update(i.to_le_bytes());
        let hash = hasher.finalize();
        // Use first 31 bytes to avoid modular bias (BLS12-381 scalar field
        // is ~255 bits; 31 bytes = 248 bits < field modulus).
        let mut bytes = [0u8; 32];
        bytes[..31].copy_from_slice(&hash[..31]);
        constants.push(Fr::from_le_bytes_mod_order(&bytes));
    }
    constants
}

/// Lazily-initialized round constants (computed once, reused forever).
static ROUND_CONSTANTS: Lazy<Vec<Fr>> = Lazy::new(generate_round_constants);

// ---------------------------------------------------------------------------
// Native (out-of-circuit) functions
// ---------------------------------------------------------------------------

/// Native MiMC encryption: encrypts `x` under key `k`.
pub fn mimc_encrypt(x: Fr, k: Fr) -> Fr {
    let constants = &*ROUND_CONSTANTS;
    let mut state = x;
    for c in constants {
        let t = state + k + c;
        state = t * t * t; // t^3
    }
    state + k // final key addition
}

/// Native MiMC hash (Miyaguchi-Preneel sponge):
///   H([x_0, ..., x_n]) = fold(state, x_i) where
///       fold(s, x) = MiMC_encrypt(x, s) + x + s
pub fn mimc_hash(inputs: &[Fr]) -> Fr {
    let mut state = Fr::from(0u64);
    for &x in inputs {
        state = mimc_encrypt(x, state) + x + state;
    }
    state
}

/// Convert an Fr element to a 32-byte little-endian array suitable for H256.
pub fn fr_to_bytes_le(f: &Fr) -> [u8; 32] {
    let bigint = f.into_bigint();
    let limb_bytes = bigint.to_bytes_le();
    let mut out = [0u8; 32];
    let len = limb_bytes.len().min(32);
    out[..len].copy_from_slice(&limb_bytes[..len]);
    out
}

// ---------------------------------------------------------------------------
// In-circuit functions
// ---------------------------------------------------------------------------

/// In-circuit MiMC encryption.
pub fn mimc_encrypt_circuit(
    cs: ConstraintSystemRef<Fr>,
    x: &FpVar<Fr>,
    k: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let constants = &*ROUND_CONSTANTS;
    let mut state = x.clone();
    for c in constants {
        let c_var = FpVar::new_constant(cs.clone(), *c)?;
        let t = &state + k + &c_var;
        state = &t * &t * &t; // t^3
    }
    Ok(&state + k)
}

/// In-circuit MiMC hash (Miyaguchi-Preneel sponge).
pub fn mimc_hash_circuit(
    cs: ConstraintSystemRef<Fr>,
    inputs: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut state = FpVar::new_constant(cs.clone(), Fr::from(0u64))?;
    for x in inputs {
        let encrypted = mimc_encrypt_circuit(cs.clone(), x, &state)?;
        state = &encrypted + x + &state;
    }
    Ok(state)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

    #[test]
    fn test_round_constants_deterministic() {
        let a = generate_round_constants();
        let b = generate_round_constants();
        assert_eq!(a.len(), MIMC_ROUNDS);
        assert_eq!(a, b, "Round constants must be deterministic");
    }

    #[test]
    fn test_round_constants_nonzero() {
        let constants = &*ROUND_CONSTANTS;
        for (i, c) in constants.iter().enumerate() {
            assert!(!c.is_zero(), "Round constant {} should not be zero", i);
        }
    }

    #[test]
    fn test_mimc_hash_determinism() {
        let data = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let h1 = mimc_hash(&data);
        let h2 = mimc_hash(&data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_mimc_hash_collision_resistance() {
        let a = vec![Fr::from(1u64), Fr::from(2u64)];
        let b = vec![Fr::from(1u64), Fr::from(3u64)];
        assert_ne!(mimc_hash(&a), mimc_hash(&b));
    }

    #[test]
    fn test_mimc_hash_empty() {
        let h = mimc_hash(&[]);
        assert_eq!(h, Fr::from(0u64), "Hash of empty input should be zero state");
    }

    #[test]
    fn test_mimc_encrypt_differs_from_identity() {
        let x = Fr::from(42u64);
        let k = Fr::from(7u64);
        let enc = mimc_encrypt(x, k);
        assert_ne!(enc, x);
        assert_ne!(enc, k);
    }

    #[test]
    fn test_mimc_circuit_matches_native() {
        use ark_relations::r1cs::ConstraintSystem;

        let data = vec![Fr::from(10u64), Fr::from(20u64), Fr::from(30u64)];
        let native_hash = mimc_hash(&data);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let data_vars: Vec<FpVar<Fr>> = data
            .iter()
            .map(|d| FpVar::new_witness(cs.clone(), || Ok(*d)).unwrap())
            .collect();

        let circuit_hash = mimc_hash_circuit(cs.clone(), &data_vars).unwrap();
        let circuit_val = circuit_hash.value().unwrap();

        assert_eq!(native_hash, circuit_val, "Circuit hash must match native hash");
        assert!(cs.is_satisfied().unwrap(), "Constraints must be satisfied");
    }

    #[test]
    fn test_fr_to_bytes_roundtrip() {
        let original = Fr::from(123456789u64);
        let bytes = fr_to_bytes_le(&original);
        let recovered = Fr::from_le_bytes_mod_order(&bytes);
        assert_eq!(original, recovered);
    }
}
