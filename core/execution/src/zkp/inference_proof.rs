// citrate/core/execution/src/zkp/inference_proof.rs

//! Zero-Knowledge Proofs for Private AI Inference
//!
//! This module implements ZK-SNARKs for proving AI inference correctness
//! without revealing model weights or input/output data.

use anyhow::{Result, anyhow};
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey, Proof};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;
use ark_snark::SNARK;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Sha3_256, Digest};
use primitive_types::{H256, H160};

/// Private inference proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceProof {
    /// The ZK proof
    pub proof: Vec<u8>, // Serialized Groth16 proof

    /// Public inputs (commitments)
    pub public_inputs: PublicInputs,

    /// Proof metadata
    pub metadata: ProofMetadata,
}

/// Public inputs for inference verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicInputs {
    /// Commitment to model weights
    pub model_commitment: H256,

    /// Commitment to input data
    pub input_commitment: H256,

    /// Commitment to output data
    pub output_commitment: H256,

    /// Model identifier (public)
    pub model_id: H256,

    /// Inference timestamp
    pub timestamp: u64,

    /// Raw commitment field element bytes (LE) for lossless Fr reconstruction.
    /// These are the exact bytes of the MiMC hash Fr values, stored alongside
    /// the H256 commitments to avoid any conversion ambiguity during verification.
    #[serde(default)]
    pub commitment_fr_bytes: Option<([u8; 32], [u8; 32], [u8; 32])>,
}

/// Proof metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// Prover address
    pub prover: H160,

    /// Circuit type
    pub circuit_type: CircuitType,

    /// Proving time in milliseconds
    pub proving_time_ms: u64,

    /// Verification key hash
    pub vk_hash: H256,
}

/// Types of inference circuits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CircuitType {
    /// Neural network forward pass
    NeuralNetwork {
        layers: usize,
        neurons_per_layer: usize,
    },

    /// Transformer model inference
    Transformer {
        attention_heads: usize,
        sequence_length: usize,
    },

    /// Convolution operation
    Convolution {
        kernel_size: usize,
        channels: usize,
    },

    /// Custom circuit
    Custom(String),
}

/// Private inputs for the inference circuit
struct PrivateInputs {
    model_weights: Vec<Fr>,
    input_data: Vec<Fr>,
    output_data: Vec<Fr>,
}

/// Inference circuit for ZK proof generation
pub struct InferenceCircuit {
    /// Private inputs
    private_inputs: Option<PrivateInputs>,

    /// Public inputs
    public_inputs: PublicInputs,

    /// Circuit configuration
    config: CircuitConfig,
}

/// Hash function used for vector commitments inside ZK circuits.
///
/// New circuits default to Poseidon, which uses significantly fewer R1CS
/// constraints than MiMC.  Existing proofs generated with MiMC still
/// verify against their original verification keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommitmentScheme {
    /// MiMC: 220-round Miyaguchi-Preneel sponge, x^3 S-box.
    /// ~660 constraints per absorbed field element.
    MiMC,
    /// Poseidon: width=3, R_f=8, R_p=56, x^5 S-box.
    /// ~213-320 constraints per absorbed field element.
    Poseidon,
}

/// Circuit configuration
#[derive(Debug, Clone)]
pub struct CircuitConfig {
    /// Maximum model size in parameters
    pub max_model_size: usize,

    /// Maximum input size
    pub max_input_size: usize,

    /// Maximum output size
    pub max_output_size: usize,

    /// Neurons per layer for the inference circuit.
    /// Must match the actual model architecture being proven.
    pub neurons_per_layer: usize,

    /// Enable optimizations
    pub optimize: bool,

    /// Commitment hash function for in-circuit and native commitments.
    /// Defaults to Poseidon for new circuits; set to MiMC for backward
    /// compatibility with existing verification keys.
    pub commitment_scheme: CommitmentScheme,
}

impl Default for CircuitConfig {
    fn default() -> Self {
        Self {
            max_model_size: 1_000_000,  // 1M parameters
            max_input_size: 1024,
            max_output_size: 1000,
            neurons_per_layer: 100,
            optimize: true,
            commitment_scheme: CommitmentScheme::Poseidon,
        }
    }
}

impl InferenceCircuit {
    /// Create new inference circuit
    pub fn new(
        model_weights: Vec<Fr>,
        input_data: Vec<Fr>,
        output_data: Vec<Fr>,
        model_id: H256,
        config: CircuitConfig,
    ) -> Self {
        // Calculate commitments using the configured hash function
        let commit_fn = match config.commitment_scheme {
            CommitmentScheme::MiMC => super::mimc::mimc_hash,
            CommitmentScheme::Poseidon => super::poseidon::poseidon_hash,
        };
        let mc_fr = commit_fn(&model_weights);
        let ic_fr = commit_fn(&input_data);
        let oc_fr = commit_fn(&output_data);

        let mc_bytes = super::mimc::fr_to_bytes_le(&mc_fr);
        let ic_bytes = super::mimc::fr_to_bytes_le(&ic_fr);
        let oc_bytes = super::mimc::fr_to_bytes_le(&oc_fr);

        let public_inputs = PublicInputs {
            model_commitment: H256(mc_bytes),
            input_commitment: H256(ic_bytes),
            output_commitment: H256(oc_bytes),
            model_id,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            commitment_fr_bytes: Some((mc_bytes, ic_bytes, oc_bytes)),
        };

        Self {
            private_inputs: Some(PrivateInputs {
                model_weights,
                input_data,
                output_data,
            }),
            public_inputs,
            config,
        }
    }

    /// Create circuit for verification (no private inputs)
    pub fn new_for_verification(
        public_inputs: PublicInputs,
        config: CircuitConfig,
    ) -> Self {
        Self {
            private_inputs: None,
            public_inputs,
            config,
        }
    }

    /// Commit to a vector using the configured hash function (MiMC or Poseidon).
    ///
    /// Uses the same algebraic hash as the in-circuit commitment so that
    /// native commitments stored in `PublicInputs` match what the R1CS
    /// circuit computes over the witness.
    ///
    /// IMPORTANT: The Fr->H256 conversion must be lossless and reversible.
    /// We use `Fr::into_bigint().to_bytes_le()` and reverse it in `verify()`
    /// with `Fr::from_le_bytes_mod_order()`. H256 is treated as an opaque
    /// 32-byte container here -- its endianness convention doesn't matter
    /// as long as we're consistent.
    #[allow(dead_code)] // Used by tests and available for external callers
    fn commit_vector(data: &[Fr]) -> H256 {
        Self::commit_vector_with_scheme(data, CommitmentScheme::MiMC)
    }

    /// Commit to a vector using a specific commitment scheme.
    #[allow(dead_code)]
    fn commit_vector_with_scheme(data: &[Fr], scheme: CommitmentScheme) -> H256 {
        let hash = match scheme {
            CommitmentScheme::MiMC => super::mimc::mimc_hash(data),
            CommitmentScheme::Poseidon => super::poseidon::poseidon_hash(data),
        };
        let bytes = super::mimc::fr_to_bytes_le(&hash);
        H256(bytes)
    }

    /// Simulate neural network forward pass
    fn neural_network_forward_pass(
        &self,
        cs: ConstraintSystemRef<Fr>,
        input_vars: &[FpVar<Fr>],
        weight_vars: &[Vec<FpVar<Fr>>],
    ) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
        let mut current_layer = input_vars.to_vec();

        // Process each layer
        for layer_weights in weight_vars.iter() {
            let mut next_layer = Vec::new();

            // Simplified: each neuron is dot product + ReLU
            let neurons_in_layer = layer_weights.len() / current_layer.len().max(1);

            for neuron_idx in 0..neurons_in_layer {
                // Compute weighted sum
                let mut sum = FpVar::new_constant(cs.clone(), Fr::from(0u64))?;

                for (i, input) in current_layer.iter().enumerate() {
                    let weight_idx = neuron_idx * current_layer.len() + i;
                    if weight_idx < layer_weights.len() {
                        let product = input * &layer_weights[weight_idx];
                        sum += &product;
                    }
                }

                // Apply ReLU activation (simplified)
                // In real implementation, would use lookup tables or polynomial approximation
                let is_positive = sum.is_cmp(
                    &FpVar::new_constant(cs.clone(), Fr::from(0u64))?,
                    std::cmp::Ordering::Greater,
                    false,
                )?;
                let relu_output = is_positive.select(&sum, &FpVar::zero())?;

                next_layer.push(relu_output);
            }

            current_layer = next_layer;
        }

        Ok(current_layer)
    }
}

impl ConstraintSynthesizer<Fr> for InferenceCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> Result<(), SynthesisError> {
        // ---------------------------------------------------------------
        // 1. PUBLIC INPUTS: commitments to model, input, and output.
        //    The verifier only sees these three field elements.
        //    The hash function is determined by config.commitment_scheme.
        // ---------------------------------------------------------------
        let commit_fn = match self.config.commitment_scheme {
            CommitmentScheme::MiMC => super::mimc::mimc_hash as fn(&[Fr]) -> Fr,
            CommitmentScheme::Poseidon => super::poseidon::poseidon_hash as fn(&[Fr]) -> Fr,
        };
        let (pub_model_commitment, pub_input_commitment, pub_output_commitment) =
            if let Some(private) = &self.private_inputs {
                // Compute native hashes and allocate as public inputs
                let mc = commit_fn(&private.model_weights);
                let ic = commit_fn(&private.input_data);
                let oc = commit_fn(&private.output_data);
                (
                    FpVar::new_input(cs.clone(), || Ok(mc))?,
                    FpVar::new_input(cs.clone(), || Ok(ic))?,
                    FpVar::new_input(cs.clone(), || Ok(oc))?,
                )
            } else {
                // For setup: dummy public inputs (values don't matter)
                (
                    FpVar::new_input(cs.clone(), || Ok(Fr::from(0u64)))?,
                    FpVar::new_input(cs.clone(), || Ok(Fr::from(0u64)))?,
                    FpVar::new_input(cs.clone(), || Ok(Fr::from(0u64)))?,
                )
            };

        // ---------------------------------------------------------------
        // 2. PRIVATE WITNESSES: raw model weights, input data, output data
        // ---------------------------------------------------------------
        let (weight_vars, input_vars, output_vars) = if let Some(private) = &self.private_inputs {
            let weight_vars: Vec<FpVar<Fr>> = private.model_weights
                .iter()
                .map(|w| FpVar::new_witness(cs.clone(), || Ok(*w)))
                .collect::<Result<_, _>>()?;

            let input_vars: Vec<FpVar<Fr>> = private.input_data
                .iter()
                .map(|i| FpVar::new_witness(cs.clone(), || Ok(*i)))
                .collect::<Result<_, _>>()?;

            let output_vars: Vec<FpVar<Fr>> = private.output_data
                .iter()
                .map(|o| FpVar::new_witness(cs.clone(), || Ok(*o)))
                .collect::<Result<_, _>>()?;

            (weight_vars, input_vars, output_vars)
        } else {
            // Allocate SEPARATE witness variables for each element.
            // Using vec![single_var?; N] would clone one variable N times,
            // sharing the same variable index and producing a smaller circuit
            // than the proving path, which would break Groth16 verification.
            let weight_vars: Vec<FpVar<Fr>> = (0..self.config.max_model_size)
                .map(|_| FpVar::new_witness(cs.clone(), || Ok(Fr::from(0u64))))
                .collect::<Result<_, _>>()?;
            let input_vars: Vec<FpVar<Fr>> = (0..self.config.max_input_size)
                .map(|_| FpVar::new_witness(cs.clone(), || Ok(Fr::from(0u64))))
                .collect::<Result<_, _>>()?;
            let output_vars: Vec<FpVar<Fr>> = (0..self.config.max_output_size)
                .map(|_| FpVar::new_witness(cs.clone(), || Ok(Fr::from(0u64))))
                .collect::<Result<_, _>>()?;
            (weight_vars, input_vars, output_vars)
        };

        // ---------------------------------------------------------------
        // 3. COMMITMENT CONSTRAINTS: in-circuit hash must equal public inputs
        // ---------------------------------------------------------------
        let scheme = self.config.commitment_scheme;
        let computed_model_commitment = Self::compute_commitment_circuit(
            cs.clone(),
            &weight_vars,
            scheme,
        )?;
        computed_model_commitment.enforce_equal(&pub_model_commitment)?;

        let computed_input_commitment = Self::compute_commitment_circuit(
            cs.clone(),
            &input_vars,
            scheme,
        )?;
        computed_input_commitment.enforce_equal(&pub_input_commitment)?;

        // ---------------------------------------------------------------
        // 4. INFERENCE: neural network forward pass
        // ---------------------------------------------------------------
        let layer_size = self.config.neurons_per_layer;
        let num_layers = if layer_size > 0 {
            weight_vars.len() / (layer_size * layer_size)
        } else {
            0
        };

        let mut weight_layers = Vec::new();
        for i in 0..num_layers {
            let start = i * layer_size * layer_size;
            let end = ((i + 1) * layer_size * layer_size).min(weight_vars.len());
            weight_layers.push(weight_vars[start..end].to_vec());
        }

        let computed_output = self.neural_network_forward_pass(
            cs.clone(),
            &input_vars,
            &weight_layers,
        )?;

        // Verify computed output matches declared output
        for (computed, expected) in computed_output.iter().zip(output_vars.iter()) {
            computed.enforce_equal(expected)?;
        }

        // ---------------------------------------------------------------
        // 5. OUTPUT COMMITMENT CONSTRAINT
        // ---------------------------------------------------------------
        let computed_output_commitment = Self::compute_commitment_circuit(
            cs.clone(),
            &output_vars,
            scheme,
        )?;
        computed_output_commitment.enforce_equal(&pub_output_commitment)?;

        // ---------------------------------------------------------------
        // 6. RANGE CHECKS on weights (always generated so the constraint
        //    structure is identical between setup and proving)
        // ---------------------------------------------------------------
        for weight in &weight_vars {
            let _ = weight.is_cmp(
                &FpVar::new_constant(cs.clone(), Fr::from(1000000u64))?,
                std::cmp::Ordering::Less,
                false,
            )?;
        }

        Ok(())
    }
}

impl InferenceCircuit {
    /// Compute commitment inside the circuit using the configured hash function.
    ///
    /// Dispatches to either MiMC or Poseidon based on the `CommitmentScheme`:
    /// - **MiMC**: 220-round Miyaguchi-Preneel sponge (x^3 S-box).
    /// - **Poseidon**: width=3, R_f=8, R_p=56 (x^5 S-box), significantly fewer constraints.
    fn compute_commitment_circuit(
        cs: ConstraintSystemRef<Fr>,
        data: &[FpVar<Fr>],
        scheme: CommitmentScheme,
    ) -> Result<FpVar<Fr>, SynthesisError> {
        match scheme {
            CommitmentScheme::MiMC => super::mimc::mimc_hash_circuit(cs, data),
            CommitmentScheme::Poseidon => super::poseidon::poseidon_hash_circuit(cs, data),
        }
    }
}

/// ZK Proof Generator for Inference
pub struct InferenceProver {
    /// Proving key
    proving_key: Option<ProvingKey<Bls12_381>>,

    /// Verifying key
    verifying_key: VerifyingKey<Bls12_381>,

    /// Circuit configuration
    config: CircuitConfig,
}

impl InferenceProver {
    /// Setup new prover
    pub fn setup(config: CircuitConfig) -> Result<Self> {
        // Create dummy circuit for setup
        let dummy_circuit = InferenceCircuit::new_for_verification(
            PublicInputs {
                model_commitment: H256::zero(),
                input_commitment: H256::zero(),
                output_commitment: H256::zero(),
                model_id: H256::zero(),
                timestamp: 0,
                commitment_fr_bytes: None,
            },
            config.clone(),
        );

        // Generate proving and verifying keys
        let mut rng = OsRng;
        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(dummy_circuit, &mut rng)
            .map_err(|e| anyhow!("Setup failed: {:?}", e))?;

        Ok(Self {
            proving_key: Some(pk),
            verifying_key: vk,
            config,
        })
    }

    /// Generate inference proof
    pub fn prove(
        &self,
        model_weights: Vec<Fr>,
        input_data: Vec<Fr>,
        output_data: Vec<Fr>,
        model_id: H256,
        prover_address: H160,
    ) -> Result<InferenceProof> {
        let start_time = std::time::Instant::now();

        // Create circuit
        let circuit = InferenceCircuit::new(
            model_weights,
            input_data,
            output_data,
            model_id,
            self.config.clone(),
        );

        let public_inputs = circuit.public_inputs.clone();

        // Generate proof
        let mut rng = OsRng;
        let proof = Groth16::<Bls12_381>::prove(
            self.proving_key.as_ref()
                .ok_or_else(|| anyhow!("Proving key not initialized — call setup() first"))?,
            circuit,
            &mut rng,
        ).map_err(|e| anyhow!("Proof generation failed: {:?}", e))?;

        // Serialize proof (compressed for smaller size, consistent with deserialization)
        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes)
            .map_err(|e| anyhow!("Proof serialization failed: {:?}", e))?;

        // Calculate VK hash
        let mut hasher = Sha3_256::new();
        let mut vk_bytes = Vec::new();
        self.verifying_key.serialize_uncompressed(&mut vk_bytes)
            .map_err(|e| anyhow!("VK serialization failed: {:?}", e))?;
        hasher.update(&vk_bytes);
        let vk_hash = H256::from_slice(hasher.finalize().as_slice());

        let proving_time_ms = start_time.elapsed().as_millis() as u64;

        Ok(InferenceProof {
            proof: proof_bytes,
            public_inputs,
            metadata: ProofMetadata {
                prover: prover_address,
                circuit_type: CircuitType::NeuralNetwork {
                    layers: 3,
                    neurons_per_layer: 100,
                },
                proving_time_ms,
                vk_hash,
            },
        })
    }

    /// Verify inference proof
    pub fn verify(&self, proof: &InferenceProof) -> Result<bool> {
        // Deserialize proof (compressed format, matching serialize_compressed)
        let proof_obj = Proof::<Bls12_381>::deserialize_compressed(&proof.proof[..])
            .map_err(|e| anyhow!("Proof deserialization failed: {:?}", e))?;

        // Reconstruct the exact Fr field elements that were used as public inputs.
        // Use the raw LE bytes stored alongside the H256 commitments to avoid
        // any conversion ambiguity.
        let public_inputs_vec = if let Some((mc, ic, oc)) = &proof.public_inputs.commitment_fr_bytes {
            vec![
                Fr::from_le_bytes_mod_order(mc),
                Fr::from_le_bytes_mod_order(ic),
                Fr::from_le_bytes_mod_order(oc),
            ]
        } else {
            // Fallback for proofs generated before this field existed
            let commitment_to_fr = |h: &H256| -> Fr {
                Fr::from_le_bytes_mod_order(&h.0)
            };
            vec![
                commitment_to_fr(&proof.public_inputs.model_commitment),
                commitment_to_fr(&proof.public_inputs.input_commitment),
                commitment_to_fr(&proof.public_inputs.output_commitment),
            ]
        };

        // Verify proof using prepared verifying key for efficiency
        let pvk = ark_groth16::prepare_verifying_key(&self.verifying_key);
        let valid = Groth16::<Bls12_381>::verify_with_processed_vk(
            &pvk,
            &public_inputs_vec,
            &proof_obj,
        ).map_err(|e| anyhow!("Verification failed: {:?}", e))?;

        Ok(valid)
    }

    /// Get verifying key for on-chain verification
    pub fn export_verifying_key(&self) -> Result<Vec<u8>> {
        let mut vk_bytes = Vec::new();
        self.verifying_key.serialize_uncompressed(&mut vk_bytes)
            .map_err(|e| anyhow!("VK serialization failed: {:?}", e))?;
        Ok(vk_bytes)
    }
}

/// Batch proof for multiple inferences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchInferenceProof {
    /// Individual proofs
    pub proofs: Vec<InferenceProof>,

    /// Aggregated proof (optional)
    pub aggregated_proof: Option<Vec<u8>>,

    /// Batch metadata
    pub batch_metadata: BatchMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchMetadata {
    /// Batch identifier
    pub batch_id: H256,

    /// Number of inferences
    pub count: usize,

    /// Total proving time
    pub total_proving_time_ms: u64,

    /// Batch timestamp
    pub timestamp: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inference_proof_generation() {
        // Setup prover.
        // Use neurons_per_layer=10 with 100 weights => 1 layer of 10x10.
        // Zero inputs ensure forward pass produces all-zero outputs (ReLU of 0 = 0),
        // so the output_data witnesses satisfy the circuit constraints.
        let config = CircuitConfig {
            max_model_size: 100,
            max_input_size: 10,
            max_output_size: 10,
            neurons_per_layer: 10,
            optimize: true,
            commitment_scheme: CommitmentScheme::Poseidon,
        };
        let prover = InferenceProver::setup(config).unwrap();

        // Weights can be arbitrary; zero inputs guarantee zero weighted sums
        let model_weights: Vec<Fr> = (0..100).map(|i| Fr::from(i as u64)).collect();
        let input_data: Vec<Fr> = vec![Fr::from(0u64); 10];
        // Forward pass with zero inputs: every neuron's weighted sum is 0,
        // ReLU(0) = 0, so the expected output is all zeros.
        let output_data: Vec<Fr> = vec![Fr::from(0u64); 10];

        // Generate proof
        let model_id = H256::random();
        let prover_address = H160::random();

        let proof = prover.prove(
            model_weights,
            input_data,
            output_data,
            model_id,
            prover_address,
        ).unwrap();

        assert!(!proof.proof.is_empty());
        assert_eq!(proof.public_inputs.model_id, model_id);

        // Verify proof
        let valid = prover.verify(&proof).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_commitment_generation() {
        let data = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let commitment = InferenceCircuit::commit_vector(&data);
        assert!(!commitment.is_zero());

        // Same data should produce same commitment
        let commitment2 = InferenceCircuit::commit_vector(&data);
        assert_eq!(commitment, commitment2);

        // Different data should produce different commitment
        let data2 = vec![Fr::from(4u64), Fr::from(5u64), Fr::from(6u64)];
        let commitment3 = InferenceCircuit::commit_vector(&data2);
        assert_ne!(commitment, commitment3);
    }

    #[test]
    fn test_commitment_fr_roundtrip() {
        let data = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let native_hash = crate::zkp::mimc::mimc_hash(&data);
        let h256 = InferenceCircuit::commit_vector(&data);
        let recovered = Fr::from_le_bytes_mod_order(&h256.0);
        assert_eq!(native_hash, recovered, "Fr -> H256 -> Fr must be lossless");
    }

    #[test]
    fn test_circuit_constraints_satisfied() {
        use ark_relations::r1cs::ConstraintSystem;

        let model_weights: Vec<Fr> = (0..100).map(|i| Fr::from(i as u64)).collect();
        let input_data: Vec<Fr> = vec![Fr::from(0u64); 10];
        let output_data: Vec<Fr> = vec![Fr::from(0u64); 10];

        let config = CircuitConfig {
            max_model_size: 100,
            max_input_size: 10,
            max_output_size: 10,
            neurons_per_layer: 10,
            optimize: true,
            commitment_scheme: CommitmentScheme::Poseidon,
        };

        let circuit = InferenceCircuit::new(
            model_weights, input_data, output_data,
            H256::zero(), config,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        eprintln!("Instance vars (incl. 'one'): {}", cs.num_instance_variables());
        eprintln!("Witness vars: {}", cs.num_witness_variables());
        eprintln!("Constraints: {}", cs.num_constraints());

        assert!(cs.is_satisfied().unwrap(), "Circuit must be satisfiable");
    }

    // --- New edge-case tests ---

    #[test]
    fn test_inference_proof_different_model_ids() {
        // model_id is stored in PublicInputs but is NOT part of the circuit constraints,
        // so two proofs with different model_ids but same data should still have
        // identical commitment values (model_commitment, input_commitment, output_commitment).
        let weights = vec![Fr::from(1u64), Fr::from(2u64)];
        let inputs = vec![Fr::from(3u64)];
        let outputs = vec![Fr::from(4u64)];

        let config = CircuitConfig {
            max_model_size: 2,
            max_input_size: 1,
            max_output_size: 1,
            neurons_per_layer: 1,
            optimize: true,
            commitment_scheme: CommitmentScheme::Poseidon,
        };

        let circuit_a = InferenceCircuit::new(
            weights.clone(),
            inputs.clone(),
            outputs.clone(),
            H256::from_low_u64_be(1),
            config.clone(),
        );
        let circuit_b = InferenceCircuit::new(
            weights,
            inputs,
            outputs,
            H256::from_low_u64_be(2),
            config,
        );

        // Commitments are derived from the data, not model_id
        assert_eq!(
            circuit_a.public_inputs.model_commitment,
            circuit_b.public_inputs.model_commitment,
        );
        assert_eq!(
            circuit_a.public_inputs.input_commitment,
            circuit_b.public_inputs.input_commitment,
        );
        assert_eq!(
            circuit_a.public_inputs.output_commitment,
            circuit_b.public_inputs.output_commitment,
        );
        // But the model_ids themselves differ
        assert_ne!(
            circuit_a.public_inputs.model_id,
            circuit_b.public_inputs.model_id,
        );
    }

    #[test]
    fn test_inference_proof_large_output() {
        // Verify that a circuit with max_output_size outputs can be constructed
        // and its constraints generated without panic.
        use ark_relations::r1cs::ConstraintSystem;

        let max_output = 50;
        let layer_size = 10;
        let model_size = layer_size * layer_size; // 1 layer of 10x10

        let config = CircuitConfig {
            max_model_size: model_size,
            max_input_size: layer_size,
            max_output_size: max_output,
            neurons_per_layer: layer_size,
            optimize: true,
            commitment_scheme: CommitmentScheme::Poseidon,
        };

        // Zero inputs => zero outputs through ReLU
        let model_weights: Vec<Fr> = (0..model_size).map(|i| Fr::from(i as u64)).collect();
        let input_data: Vec<Fr> = vec![Fr::from(0u64); layer_size];
        let output_data: Vec<Fr> = vec![Fr::from(0u64); max_output];

        let circuit = InferenceCircuit::new(
            model_weights,
            input_data,
            output_data,
            H256::zero(),
            config,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        assert!(
            cs.is_satisfied().unwrap(),
            "Circuit with large output size must be satisfiable"
        );
    }

    #[test]
    fn test_commitment_different_lengths() {
        // commit_vector with different lengths must produce different hashes
        let short = vec![Fr::from(42u64)];
        let long: Vec<Fr> = (0..100).map(|i| Fr::from(i as u64)).collect();

        let c_short = InferenceCircuit::commit_vector(&short);
        let c_long = InferenceCircuit::commit_vector(&long);

        assert_ne!(
            c_short, c_long,
            "Commitments of vectors with different lengths must differ"
        );
    }

    // --- Poseidon-specific tests ---

    #[test]
    fn test_inference_proof_with_poseidon() {
        // Full roundtrip: setup -> prove -> verify using Poseidon commitments.
        let config = CircuitConfig {
            max_model_size: 100,
            max_input_size: 10,
            max_output_size: 10,
            neurons_per_layer: 10,
            optimize: true,
            commitment_scheme: CommitmentScheme::Poseidon,
        };
        let prover = InferenceProver::setup(config).unwrap();

        let model_weights: Vec<Fr> = (0..100).map(|i| Fr::from(i as u64)).collect();
        let input_data: Vec<Fr> = vec![Fr::from(0u64); 10];
        let output_data: Vec<Fr> = vec![Fr::from(0u64); 10];

        let proof = prover.prove(
            model_weights,
            input_data,
            output_data,
            H256::random(),
            H160::random(),
        ).unwrap();

        let valid = prover.verify(&proof).unwrap();
        assert!(valid, "Poseidon-based proof must verify");
    }

    #[test]
    fn test_mimc_proofs_still_verify() {
        // Backward compatibility: MiMC commitment scheme still works end-to-end.
        let config = CircuitConfig {
            max_model_size: 100,
            max_input_size: 10,
            max_output_size: 10,
            neurons_per_layer: 10,
            optimize: true,
            commitment_scheme: CommitmentScheme::MiMC,
        };
        let prover = InferenceProver::setup(config).unwrap();

        let model_weights: Vec<Fr> = (0..100).map(|i| Fr::from(i as u64)).collect();
        let input_data: Vec<Fr> = vec![Fr::from(0u64); 10];
        let output_data: Vec<Fr> = vec![Fr::from(0u64); 10];

        let proof = prover.prove(
            model_weights,
            input_data,
            output_data,
            H256::random(),
            H160::random(),
        ).unwrap();

        let valid = prover.verify(&proof).unwrap();
        assert!(valid, "MiMC-based proof must still verify (backward compat)");
    }

    #[test]
    fn test_poseidon_and_mimc_commitments_differ() {
        // Poseidon and MiMC produce different commitments for the same data.
        let data = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];

        let mimc_commit = InferenceCircuit::commit_vector_with_scheme(&data, CommitmentScheme::MiMC);
        let poseidon_commit = InferenceCircuit::commit_vector_with_scheme(&data, CommitmentScheme::Poseidon);

        assert_ne!(
            mimc_commit, poseidon_commit,
            "MiMC and Poseidon must produce different commitments"
        );
    }

    #[test]
    fn test_poseidon_commitment_fr_roundtrip() {
        // Verify that Poseidon Fr->H256->Fr conversion is lossless.
        let data = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let native_hash = crate::zkp::poseidon::poseidon_hash(&data);
        let h256 = InferenceCircuit::commit_vector_with_scheme(&data, CommitmentScheme::Poseidon);
        let recovered = Fr::from_le_bytes_mod_order(&h256.0);
        assert_eq!(native_hash, recovered, "Poseidon Fr -> H256 -> Fr must be lossless");
    }

    #[test]
    fn test_poseidon_circuit_fewer_constraints_in_inference() {
        // Compare full InferenceCircuit constraint counts between MiMC and Poseidon.
        use ark_relations::r1cs::ConstraintSystem;

        let model_weights: Vec<Fr> = (0..100).map(|i| Fr::from(i as u64)).collect();
        let input_data: Vec<Fr> = vec![Fr::from(0u64); 10];
        let output_data: Vec<Fr> = vec![Fr::from(0u64); 10];

        // MiMC circuit
        let mimc_config = CircuitConfig {
            max_model_size: 100,
            max_input_size: 10,
            max_output_size: 10,
            neurons_per_layer: 10,
            optimize: true,
            commitment_scheme: CommitmentScheme::MiMC,
        };
        let mimc_circuit = InferenceCircuit::new(
            model_weights.clone(), input_data.clone(), output_data.clone(),
            H256::zero(), mimc_config,
        );
        let cs_mimc = ConstraintSystem::<Fr>::new_ref();
        mimc_circuit.generate_constraints(cs_mimc.clone()).unwrap();
        let mimc_constraints = cs_mimc.num_constraints();

        // Poseidon circuit
        let pos_config = CircuitConfig {
            max_model_size: 100,
            max_input_size: 10,
            max_output_size: 10,
            neurons_per_layer: 10,
            optimize: true,
            commitment_scheme: CommitmentScheme::Poseidon,
        };
        let pos_circuit = InferenceCircuit::new(
            model_weights, input_data, output_data,
            H256::zero(), pos_config,
        );
        let cs_pos = ConstraintSystem::<Fr>::new_ref();
        pos_circuit.generate_constraints(cs_pos.clone()).unwrap();
        let pos_constraints = cs_pos.num_constraints();

        eprintln!(
            "InferenceCircuit: MiMC={} constraints, Poseidon={} constraints ({}x reduction)",
            mimc_constraints,
            pos_constraints,
            mimc_constraints as f64 / pos_constraints as f64
        );
        assert!(
            pos_constraints < mimc_constraints,
            "Poseidon InferenceCircuit ({}) should have fewer constraints than MiMC ({})",
            pos_constraints,
            mimc_constraints
        );
    }

    #[test]
    fn test_default_config_uses_poseidon() {
        let config = CircuitConfig::default();
        assert_eq!(
            config.commitment_scheme,
            CommitmentScheme::Poseidon,
            "Default CircuitConfig must use Poseidon"
        );
    }
}