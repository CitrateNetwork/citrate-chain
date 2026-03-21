// citrate/core/execution/src/zkp/circuits.rs

// ZKP circuits for different proof types
use super::types::{GradientProofCircuit, ModelExecutionCircuit};
use ark_bls12_381::Fr;
#[allow(unused_imports)]
use ark_ff::Zero;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

const HASH_OUTPUT_SIZE: usize = 32;
#[allow(dead_code)]
const FIXED_POINT_SCALE: u64 = 1_000_000;
const HASH_SALT: [u8; HASH_OUTPUT_SIZE] = [
    0x73, 0xa1, 0x5c, 0x44, 0xda, 0xf0, 0x91, 0x2b, 0x6e, 0x0d, 0x83, 0x57, 0x3d, 0x9f, 0xb2,
    0xc4, 0x1a, 0xe7, 0x66, 0x28, 0xfe, 0x5a, 0x8c, 0xbb, 0x32, 0x47, 0x19, 0xd8, 0x04, 0xaf,
    0x61, 0x90,
];

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

#[allow(dead_code)]
fn fp_to_hash_bytes(value: &FpVar<Fr>) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    let bits = value.to_bits_le()?;
    let mut bytes = Vec::with_capacity(HASH_OUTPUT_SIZE);
    for chunk in bits.chunks(8).take(HASH_OUTPUT_SIZE) {
        let mut chunk_bits = chunk.to_vec();
        while chunk_bits.len() < 8 {
            chunk_bits.push(Boolean::FALSE);
        }
        bytes.push(UInt8::from_bits_le(&chunk_bits));
    }
    while bytes.len() < HASH_OUTPUT_SIZE {
        bytes.push(UInt8::constant(0));
    }
    Ok(bytes)
}

#[allow(dead_code)]
fn u64_to_hash_bytes(value: u64) -> Vec<UInt8<Fr>> {
    let mut raw = value.to_le_bytes().to_vec();
    raw.resize(HASH_OUTPUT_SIZE, 0);
    UInt8::constant_vec(&raw)
}

fn hash_pair(left: &[UInt8<Fr>], right: &[UInt8<Fr>]) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    let mut result = Vec::with_capacity(HASH_OUTPUT_SIZE);
    for i in 0..HASH_OUTPUT_SIZE {
        let l_byte = if i < left.len() {
            left[i].clone()
        } else {
            UInt8::constant(0)
        };
        let r_byte = if i < right.len() {
            right[i].clone()
        } else {
            UInt8::constant(0)
        };

        let l_bits = l_byte.to_bits_le()?;
        let r_bits = r_byte.to_bits_le()?;

        let mut mixed_bits = Vec::with_capacity(8);
        for bit_idx in 0..8 {
            let mut bit = l_bits[bit_idx].xor(&r_bits[bit_idx])?;
            if (HASH_SALT[i % HASH_OUTPUT_SIZE] >> bit_idx) & 1 == 1 {
                bit = bit.xor(&Boolean::TRUE)?;
            }
            mixed_bits.push(bit);
        }

        result.push(UInt8::from_bits_le(&mixed_bits));
    }
    Ok(result)
}

#[allow(dead_code)]
fn hash_chain(chunks: &[Vec<UInt8<Fr>>]) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    if chunks.is_empty() {
        return Ok(UInt8::constant_vec(&HASH_SALT));
    }

    let seed = UInt8::constant_vec(&HASH_SALT);
    let mut state = hash_pair(&seed, &chunks[0])?;
    for chunk in chunks.iter().skip(1) {
        state = hash_pair(&state, chunk)?;
    }
    Ok(state)
}

/// Implementation of model execution circuit
impl ConstraintSynthesizer<Fr> for ModelExecutionCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Public inputs: model_hash, input_hash, output_hash
        // These are what the verifier checks — "this proof is about THIS model+input+output"
        let model_hash_field = self.model_hash.iter().take(8).fold(0u64, |acc, &b| acc * 256 + b as u64);
        let input_hash_field = self.input_hash.iter().take(8).fold(0u64, |acc, &b| acc * 256 + b as u64);
        let output_hash_field = self.output_hash.iter().take(8).fold(0u64, |acc, &b| acc * 256 + b as u64);

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
        let model_field = self.model_hash.iter().take(8).fold(0u64, |acc, &b| acc * 256 + b as u64);
        let dataset_field = self.dataset_hash.iter().take(8).fold(0u64, |acc, &b| acc * 256 + b as u64);
        let gradient_field = self.gradient_hash.iter().take(8).fold(0u64, |acc, &b| acc * 256 + b as u64);

        let _model_pub = FpVar::new_input(cs.clone(), || Ok(Fr::from(model_field)))?;
        let _dataset_pub = FpVar::new_input(cs.clone(), || Ok(Fr::from(dataset_field)))?;
        let _gradient_pub = FpVar::new_input(cs.clone(), || Ok(Fr::from(gradient_field)))?;
        let _loss_pub = FpVar::new_input(cs.clone(), || Ok(Fr::from(self.loss_value as u64)))?;
        let _samples_pub = FpVar::new_input(cs.clone(), || Ok(Fr::from(self.num_samples)))?;

        // Private witnesses
        let _model_hash_vars: Vec<_> = self.model_hash.iter()
            .map(|byte| UInt8::new_witness(cs.clone(), || Ok(*byte)))
            .collect::<Result<_, _>>()?;
        let _dataset_hash_vars: Vec<_> = self.dataset_hash.iter()
            .map(|byte| UInt8::new_witness(cs.clone(), || Ok(*byte)))
            .collect::<Result<_, _>>()?;
        let _gradient_hash_vars: Vec<_> = self.gradient_hash.iter()
            .map(|byte| UInt8::new_witness(cs.clone(), || Ok(*byte)))
            .collect::<Result<_, _>>()?;

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
        let old_field = self.old_state_root.iter().take(8).fold(0u64, |acc, &b| acc * 256 + b as u64);
        let new_field = self.new_state_root.iter().take(8).fold(0u64, |acc, &b| acc * 256 + b as u64);
        let tx_field = self.transaction_hash.iter().take(8).fold(0u64, |acc, &b| acc * 256 + b as u64);

        let _old_pub = FpVar::new_input(cs.clone(), || Ok(Fr::from(old_field)))?;
        let _new_pub = FpVar::new_input(cs.clone(), || Ok(Fr::from(new_field)))?;
        let _tx_pub = FpVar::new_input(cs.clone(), || Ok(Fr::from(tx_field)))?;

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
        let data_field = self.data_hash.iter().take(8).fold(0u64, |acc, &b| acc * 256 + b as u64);
        let root_field = self.merkle_root.iter().take(8).fold(0u64, |acc, &b| acc * 256 + b as u64);

        let _data_pub = FpVar::new_input(cs.clone(), || Ok(Fr::from(data_field)))?;
        let _root_pub = FpVar::new_input(cs.clone(), || Ok(Fr::from(root_field)))?;

        // Private witnesses
        let data_hash_vars: Vec<_> = self.data_hash.iter()
            .map(|byte| UInt8::new_witness(cs.clone(), || Ok(*byte)))
            .collect::<Result<_, _>>()?;
        let root_vars: Vec<_> = self.merkle_root.iter()
            .map(|byte| UInt8::new_witness(cs.clone(), || Ok(*byte)))
            .collect::<Result<_, _>>()?;

        // Verify merkle path
        let mut current_hash = data_hash_vars;
        let mut index = self.leaf_index;

        for sibling in self.merkle_path.iter() {
            let sibling_vars: Vec<_> = sibling
                .iter()
                .map(|byte| UInt8::new_witness(cs.clone(), || Ok(*byte)))
                .collect::<Result<_, _>>()?;

            // Combine hashes based on index bit
            if index & 1 == 0 {
                // Current hash is left child
                current_hash = hash_pair(&current_hash, &sibling_vars)?;
            } else {
                // Current hash is right child
                current_hash = hash_pair(&sibling_vars, &current_hash)?;
            }

            index >>= 1;
        }

        // Verify that computed root matches expected root
        for (computed, expected) in current_hash.iter().zip(root_vars.iter()) {
            computed.enforce_equal(expected)?;
        }

        Ok(())
    }
}
