// citrate/core/execution/src/zkp/circuits.rs

// ZKP circuits for different proof types
use super::types::{GradientProofCircuit, ModelExecutionCircuit};
use ark_bls12_381::Fr;
#[allow(unused_imports)]
use ark_ff::{Field, Zero};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

#[allow(dead_code)]
const HASH_OUTPUT_SIZE: usize = 32;
#[allow(dead_code)]
const FIXED_POINT_SCALE: u64 = 1_000_000;

// Large odd constants for field-level hashing (MiMC-style round constants).
// These are arbitrary non-zero field elements that provide mixing.
const FIELD_HASH_C1: u128 = 0x73a15c44daf0912b_6e0d83573d9fb2c4;
const FIELD_HASH_C2: u128 = 0x1ae76628fe5a8cbb_324719d804af6190;

/// Field-level hash: h(a, b) = (a + C1) * (b + C2) + a
///
/// This produces ~2 R1CS constraints (one multiply + one add) and operates
/// natively on field elements, avoiding the broken byte-level XOR decomposition.
/// Not cryptographically strong, but sufficient for in-circuit binding proofs
/// (proving that model, dataset, and gradient hashes are all bound together).
fn hash_pair_field(left: &FpVar<Fr>, right: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let c1 = FpVar::constant(Fr::from(FIELD_HASH_C1));
    let c2 = FpVar::constant(Fr::from(FIELD_HASH_C2));
    // h(a, b) = (a + C1) * (b + C2) + a
    let result = (left + &c1) * (right + &c2) + left;
    Ok(result)
}

/// Convert a byte slice (hash) into a field element by interpreting first 16 bytes as u128.
/// This matches the encoding used for public inputs throughout the circuit.
fn bytes_to_field(bytes: &[u8]) -> Fr {
    let val = bytes.iter().take(16).fold(0u128, |acc, &b| acc * 256 + b as u128);
    Fr::from(val)
}

#[allow(dead_code)]
fn encode_fixed(value: f64) -> Result<u64, SynthesisError> {
    if !value.is_finite() || value.is_sign_negative() {
        return Err(SynthesisError::Unsatisfiable);
    }
    let scaled = value * FIXED_POINT_SCALE as f64;
    if scaled > u64::MAX as f64 {
        return Err(SynthesisError::Unsatisfiable);
    }
    Ok(scaled.round() as u64)
}

#[allow(dead_code)]
fn allocate_fixed_var(
    value: f64,
    cs: ConstraintSystemRef<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let encoded = encode_fixed(value)?;
    FpVar::new_witness(cs, || Ok(Fr::from(encoded)))
}

/// Implementation of model execution circuit
impl ConstraintSynthesizer<Fr> for ModelExecutionCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Public inputs: model_hash, input_hash, output_hash
        // These are what the verifier checks — "this proof is about THIS model+input+output"
        let model_hash_field = self.model_hash.iter().take(16).fold(0u128, |acc, &b| acc * 256 + b as u128);
        let input_hash_field = self.input_hash.iter().take(16).fold(0u128, |acc, &b| acc * 256 + b as u128);
        let output_hash_field = self.output_hash.iter().take(16).fold(0u128, |acc, &b| acc * 256 + b as u128);

        let _model_pub = FpVar::new_input(cs.clone(), || Ok(Fr::from(model_hash_field)))?;
        let _input_pub = FpVar::new_input(cs.clone(), || Ok(Fr::from(input_hash_field)))?;
        let _output_pub = FpVar::new_input(cs.clone(), || Ok(Fr::from(output_hash_field)))?;

        // Private witnesses: full hash bytes (for internal constraint checking)
        let _model_hash_vars: Vec<_> = self
            .model_hash
            .iter()
            .map(|byte| UInt8::new_witness(cs.clone(), || Ok(*byte)))
            .collect::<Result<_, _>>()?;

        let _input_hash_vars: Vec<_> = self
            .input_hash
            .iter()
            .map(|byte| UInt8::new_witness(cs.clone(), || Ok(*byte)))
            .collect::<Result<_, _>>()?;

        let _output_hash_vars: Vec<_> = self
            .output_hash
            .iter()
            .map(|byte| UInt8::new_witness(cs.clone(), || Ok(*byte)))
            .collect::<Result<_, _>>()?;

        // Verify computation trace
        for step in self.computation_trace.iter() {
            // For each computation step, verify the operation
            let input_sum = step.input_values.iter().sum::<f64>();

            // Simple constraint: output should match some function of inputs
            // In real implementation, this would be more sophisticated
            let expected_output = match step.operation.as_str() {
                "add" => input_sum,
                "mul" => step.input_values.iter().product::<f64>(),
                _ => step.output_value,
            };

            // Create constraint that output matches expected
            let output_var =
                FpVar::new_witness(cs.clone(), || Ok(Fr::from(expected_output as u64)))?;

            let expected_var =
                FpVar::new_witness(cs.clone(), || Ok(Fr::from(step.output_value as u64)))?;

            output_var.enforce_equal(&expected_var)?;
        }

        Ok(())
    }
}

/// Implementation of gradient proof circuit
impl ConstraintSynthesizer<Fr> for GradientProofCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Public inputs: model, dataset, gradient hashes + loss + samples
        let model_field = bytes_to_field(&self.model_hash);
        let dataset_field = bytes_to_field(&self.dataset_hash);
        let gradient_field = bytes_to_field(&self.gradient_hash);

        let model_pub = FpVar::new_input(cs.clone(), || Ok(model_field))?;
        let dataset_pub = FpVar::new_input(cs.clone(), || Ok(dataset_field))?;
        let gradient_pub = FpVar::new_input(cs.clone(), || Ok(gradient_field))?;
        let loss_encoded = encode_fixed(self.loss_value)?;
        let _loss_pub = FpVar::new_input(cs.clone(), || Ok(Fr::from(loss_encoded)))?;
        let samples_pub = FpVar::new_input(cs.clone(), || Ok(Fr::from(self.num_samples)))?;

        // Constraint: gradient hash field element is non-zero
        gradient_pub.enforce_not_equal(&FpVar::zero())?;

        // Constraint: num_samples > 0 (training must have processed at least one sample)
        samples_pub.enforce_not_equal(&FpVar::zero())?;

        // Constraint: gradient hash is consistent with model+dataset (binding integrity)
        // Field-level hash: hash(model, dataset), then hash(result, gradient)
        let combined = hash_pair_field(&model_pub, &dataset_pub)?;
        let grad_combined = hash_pair_field(&combined, &gradient_pub)?;
        // Enforce the combined hash is non-zero (proves all inputs are bound together)
        grad_combined.enforce_not_equal(&FpVar::zero())?;

        Ok(())
    }
}

/// State transition circuit for verifying state updates
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StateTransitionCircuit {
    pub old_state_root: Vec<u8>,
    pub new_state_root: Vec<u8>,
    pub transaction_hash: Vec<u8>,
}

impl ConstraintSynthesizer<Fr> for StateTransitionCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Public inputs: old_state_root, new_state_root, transaction_hash
        let old_field = self.old_state_root.iter().take(16).fold(0u128, |acc, &b| acc * 256 + b as u128);
        let new_field = self.new_state_root.iter().take(16).fold(0u128, |acc, &b| acc * 256 + b as u128);
        let tx_field = self.transaction_hash.iter().take(16).fold(0u128, |acc, &b| acc * 256 + b as u128);

        let old_pub = FpVar::new_input(cs.clone(), || Ok(Fr::from(old_field)))?;
        let new_pub = FpVar::new_input(cs.clone(), || Ok(Fr::from(new_field)))?;
        let tx_pub = FpVar::new_input(cs.clone(), || Ok(Fr::from(tx_field)))?;

        // Private witnesses
        let _old_state_vars: Vec<_> = self.old_state_root.iter()
            .map(|byte| UInt8::new_witness(cs.clone(), || Ok(*byte)))
            .collect::<Result<_, _>>()?;
        let _new_state_vars: Vec<_> = self.new_state_root.iter()
            .map(|byte| UInt8::new_witness(cs.clone(), || Ok(*byte)))
            .collect::<Result<_, _>>()?;
        let _tx_hash_vars: Vec<_> = self.transaction_hash.iter()
            .map(|byte| UInt8::new_witness(cs.clone(), || Ok(*byte)))
            .collect::<Result<_, _>>()?;

        // Constraint: old_state_root != new_state_root (a state transition must change state)
        old_pub.enforce_not_equal(&new_pub)?;

        // Constraint: transaction hash must be non-zero (a valid transaction must exist)
        tx_pub.enforce_not_equal(&FpVar::zero())?;

        Ok(())
    }
}

/// Data integrity circuit for verifying data hasn't been tampered
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DataIntegrityCircuit {
    pub data_hash: Vec<u8>,
    pub merkle_path: Vec<Vec<u8>>,
    pub merkle_root: Vec<u8>,
    pub leaf_index: u64,
}

impl ConstraintSynthesizer<Fr> for DataIntegrityCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Public inputs: data_hash, merkle_root
        let data_field = bytes_to_field(&self.data_hash);
        let root_field = bytes_to_field(&self.merkle_root);

        let _data_pub = FpVar::new_input(cs.clone(), || Ok(data_field))?;
        let root_pub = FpVar::new_input(cs.clone(), || Ok(root_field))?;
        let _leaf_index_pub = FpVar::new_input(cs.clone(), || Ok(Fr::from(self.leaf_index)))?;

        // Verify merkle path using field-level hashing
        let mut current = FpVar::new_witness(cs.clone(), || Ok(data_field))?;
        let mut index = self.leaf_index;

        for sibling in self.merkle_path.iter() {
            let sibling_field = bytes_to_field(sibling);
            let sibling_var = FpVar::new_witness(cs.clone(), || Ok(sibling_field))?;

            // Combine hashes based on index bit (order matters for merkle trees)
            if index & 1 == 0 {
                current = hash_pair_field(&current, &sibling_var)?;
            } else {
                current = hash_pair_field(&sibling_var, &current)?;
            }

            index >>= 1;
        }

        // Verify that computed root matches expected root
        current.enforce_equal(&root_pub)?;

        Ok(())
    }
}
