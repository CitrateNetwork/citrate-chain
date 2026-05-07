// citrate/core/execution/src/zkp/prover.rs

// Proof generator for ZKP operations
use super::circuits::{DataIntegrityCircuit, StateTransitionCircuit};
use super::types::{ProofType, ProvingKey, SerializableProof, ZKPError};
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_snark::SNARK;
use parking_lot::RwLock;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::Arc;

/// Pre-flight: synthesize the circuit into a fresh ConstraintSystem and verify
/// that all constraints are satisfied by the provided witness BEFORE invoking
/// `Groth16::prove`.
///
/// arkworks' Groth16::prove produces a non-verifying proof from unsatisfiable
/// constraints rather than returning Err — a known footgun. Without this
/// pre-flight check, a caller doing `let proof = backend.generate_proof(req)?;`
/// receives `Ok(proof)` even when their inputs violate circuit invariants;
/// the failure only surfaces later during verification (or never, if the
/// caller never verifies).
///
/// This helper closes that gap: any witness inconsistency surfaces as a
/// `ZKPError::SynthesisError` from `generate_proof`, with the same diagnostic
/// shape as a literal synthesis error from arkworks. WP-P4-16(a) closure
/// (CIF-16a in 2026-03-26 audit closure record).
///
/// Performance: synthesizes the circuit twice (here + Groth16::prove). The
/// constraint count for current ZKP circuits (model exec, gradient, state
/// transition, data integrity) is small relative to the prover's MSM cost,
/// so the overhead is well under 5%.
fn check_circuit_satisfied<C>(circuit: C) -> Result<(), ZKPError>
where
    C: ConstraintSynthesizer<Fr>,
{
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit
        .generate_constraints(cs.clone())
        .map_err(|e| ZKPError::SynthesisError(e.to_string()))?;
    cs.finalize();
    let satisfied = cs
        .is_satisfied()
        .map_err(|e| ZKPError::SynthesisError(e.to_string()))?;
    if !satisfied {
        return Err(ZKPError::SynthesisError(
            "circuit constraints not satisfied: witness is inconsistent with public inputs"
                .to_string(),
        ));
    }
    Ok(())
}

/// Proof generator for ZKP operations
pub struct Prover {
    proving_keys: Arc<RwLock<HashMap<ProofType, ProvingKey>>>,
    prepared_vks: Arc<RwLock<HashMap<ProofType, PreparedVerifyingKey<Bls12_381>>>>,
}

impl Prover {
    pub fn new() -> Self {
        Self {
            proving_keys: Arc::new(RwLock::new(HashMap::new())),
            prepared_vks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Setup proving and verifying keys for a circuit type
    pub fn setup(&self, proof_type: ProofType) -> Result<(), ZKPError> {
        let mut rng = OsRng;

        let (pk, vk) = match proof_type {
            ProofType::ModelExecution => {
                let circuit = super::types::ModelExecutionCircuit {
                    model_hash: vec![0; 32],
                    input_hash: vec![0; 32],
                    output_hash: vec![0; 32],
                    computation_trace: vec![],
                };

                Groth16::<Bls12_381>::circuit_specific_setup(circuit, &mut rng)
                    .map_err(|e| ZKPError::SetupError(e.to_string()))?
            }
            ProofType::GradientSubmission => {
                // Dummy values must satisfy constraints: gradient non-zero, num_samples non-zero
                let circuit = super::types::GradientProofCircuit {
                    model_hash: vec![1; 32],
                    dataset_hash: vec![1; 32],
                    gradient_hash: vec![1; 32],
                    loss_value: 1.0,
                    num_samples: 1,
                };

                Groth16::<Bls12_381>::circuit_specific_setup(circuit, &mut rng)
                    .map_err(|e| ZKPError::SetupError(e.to_string()))?
            }
            ProofType::StateTransition => {
                let circuit = StateTransitionCircuit {
                    old_state_root: vec![0; 32],
                    new_state_root: vec![0; 32],
                    transaction_hash: vec![0; 32],
                };

                Groth16::<Bls12_381>::circuit_specific_setup(circuit, &mut rng)
                    .map_err(|e| ZKPError::SetupError(e.to_string()))?
            }
            ProofType::DataIntegrity => {
                // Dummy values for R1CS shape discovery — must be valid witnesses
                let circuit = DataIntegrityCircuit {
                    data_hash: vec![1; 32],
                    merkle_path: vec![],
                    merkle_root: vec![1; 32],
                    leaf_index: 0,
                };

                Groth16::<Bls12_381>::circuit_specific_setup(circuit, &mut rng)
                    .map_err(|e| ZKPError::SetupError(e.to_string()))?
            }
        };

        // Store proving key
        self.proving_keys.write().insert(proof_type, pk);

        // Prepare and store verifying key
        let prepared_vk = prepare_verifying_key(&vk);
        self.prepared_vks.write().insert(proof_type, prepared_vk);

        Ok(())
    }

    /// Get the verifying key for a proof type (for sharing with the Verifier).
    /// Returns None if setup() hasn't been called for this type.
    pub fn get_verifying_key(&self, proof_type: ProofType) -> Option<super::types::VerifyingKey> {
        // The prepared VK contains the original VK — but we need the raw VK.
        // During setup, we stored the prepared VK. We need to also store the raw VK.
        // For now, return None and fix in the setup() to also store raw VKs.
        //
        // WORKAROUND: Re-extract from the proving key, which contains the VK.
        self.proving_keys.read().get(&proof_type).map(|pk| pk.vk.clone())
    }

    /// Generate proof for model execution
    pub fn prove_model_execution(
        &self,
        model_hash: Vec<u8>,
        input_hash: Vec<u8>,
        output_hash: Vec<u8>,
        computation_trace: Vec<super::types::ComputationStep>,
    ) -> Result<SerializableProof, ZKPError> {
        let circuit = super::types::ModelExecutionCircuit {
            model_hash: model_hash.clone(),
            input_hash: input_hash.clone(),
            output_hash: output_hash.clone(),
            computation_trace,
        };

        // WP-P4-16(a): pre-flight constraint-satisfaction check before Groth16::prove
        check_circuit_satisfied(circuit.clone())?;

        let pk = self
            .proving_keys
            .read()
            .get(&ProofType::ModelExecution)
            .ok_or_else(|| ZKPError::KeyNotFound("ModelExecution".to_string()))?
            .clone();

        let mut rng = OsRng;

        let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng)
            .map_err(|e| ZKPError::ProvingError(e.to_string()))?;

        // Public inputs must match what the circuit allocates via new_input().
        // The circuit truncates each hash to the first 16 bytes interpreted as u128.
        let to_field_str = |hash: &[u8]| -> String {
            let val = hash.iter().take(16).fold(0u128, |acc, &b| acc * 256 + b as u128);
            val.to_string()
        };

        let public_inputs = vec![
            to_field_str(&model_hash),
            to_field_str(&input_hash),
            to_field_str(&output_hash),
        ];

        SerializableProof::from_proof(&proof, public_inputs)
    }

    /// Generate proof for gradient submission
    pub fn prove_gradient_submission(
        &self,
        model_hash: Vec<u8>,
        dataset_hash: Vec<u8>,
        gradient_hash: Vec<u8>,
        loss_value: f64,
        num_samples: u64,
    ) -> Result<SerializableProof, ZKPError> {
        let circuit = super::types::GradientProofCircuit {
            model_hash: model_hash.clone(),
            dataset_hash: dataset_hash.clone(),
            gradient_hash: gradient_hash.clone(),
            loss_value,
            num_samples,
        };

        // WP-P4-16(a): pre-flight constraint-satisfaction check before Groth16::prove
        check_circuit_satisfied(circuit.clone())?;

        let pk = self
            .proving_keys
            .read()
            .get(&ProofType::GradientSubmission)
            .ok_or_else(|| ZKPError::KeyNotFound("GradientSubmission".to_string()))?
            .clone();

        let mut rng = OsRng;

        let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng)
            .map_err(|e| ZKPError::ProvingError(e.to_string()))?;

        // Public inputs must match circuit's new_input() allocations
        let to_field_str = |hash: &[u8]| -> String {
            hash.iter().take(16).fold(0u128, |acc, &b| acc * 256 + b as u128).to_string()
        };

        let public_inputs = vec![
            to_field_str(&model_hash),
            to_field_str(&dataset_hash),
            to_field_str(&gradient_hash),
            ((loss_value * 1_000_000.0).round() as u64).to_string(),
            num_samples.to_string(),
        ];

        SerializableProof::from_proof(&proof, public_inputs)
    }

    /// Generate proof for state transition
    pub fn prove_state_transition(
        &self,
        old_state_root: Vec<u8>,
        new_state_root: Vec<u8>,
        transaction_hash: Vec<u8>,
    ) -> Result<SerializableProof, ZKPError> {
        let circuit = StateTransitionCircuit {
            old_state_root: old_state_root.clone(),
            new_state_root: new_state_root.clone(),
            transaction_hash: transaction_hash.clone(),
        };

        // WP-P4-16(a): pre-flight constraint-satisfaction check before Groth16::prove
        check_circuit_satisfied(circuit.clone())?;

        let pk = self
            .proving_keys
            .read()
            .get(&ProofType::StateTransition)
            .ok_or_else(|| ZKPError::KeyNotFound("StateTransition".to_string()))?
            .clone();

        let mut rng = OsRng;

        let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng)
            .map_err(|e| ZKPError::ProvingError(e.to_string()))?;

        let to_field_str = |hash: &[u8]| -> String {
            hash.iter().take(16).fold(0u128, |acc, &b| acc * 256 + b as u128).to_string()
        };

        let public_inputs = vec![
            to_field_str(&old_state_root),
            to_field_str(&new_state_root),
            to_field_str(&transaction_hash),
        ];

        SerializableProof::from_proof(&proof, public_inputs)
    }

    /// Generate proof for data integrity
    pub fn prove_data_integrity(
        &self,
        data_hash: Vec<u8>,
        merkle_path: Vec<Vec<u8>>,
        merkle_root: Vec<u8>,
        leaf_index: u64,
    ) -> Result<SerializableProof, ZKPError> {
        let circuit = DataIntegrityCircuit {
            data_hash: data_hash.clone(),
            merkle_path: merkle_path.clone(),
            merkle_root: merkle_root.clone(),
            leaf_index,
        };

        // WP-P4-16(a): pre-flight constraint-satisfaction check before Groth16::prove.
        // This is the case the audit specifically flagged: a wrong merkle_root
        // would silently produce a non-verifying proof here. Now it returns Err.
        check_circuit_satisfied(circuit.clone())?;

        let pk = self
            .proving_keys
            .read()
            .get(&ProofType::DataIntegrity)
            .ok_or_else(|| ZKPError::KeyNotFound("DataIntegrity".to_string()))?
            .clone();

        let mut rng = OsRng;

        let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng)
            .map_err(|e| ZKPError::ProvingError(e.to_string()))?;

        let to_field_str = |hash: &[u8]| -> String {
            hash.iter().take(16).fold(0u128, |acc, &b| acc * 256 + b as u128).to_string()
        };

        let public_inputs = vec![
            to_field_str(&data_hash),
            to_field_str(&merkle_root),
            leaf_index.to_string(),
        ];

        SerializableProof::from_proof(&proof, public_inputs)
    }

    /// Batch prove multiple circuits of the same type.
    ///
    /// `public_inputs_per_circuit` must have the same length as `circuits`.
    /// Each entry contains the public input strings for the corresponding circuit,
    /// matching what the circuit allocates via `new_input()`.
    pub fn batch_prove<C>(
        &self,
        proof_type: ProofType,
        circuits: Vec<C>,
        public_inputs_per_circuit: Vec<Vec<String>>,
    ) -> Result<Vec<SerializableProof>, ZKPError>
    where
        C: ark_relations::r1cs::ConstraintSynthesizer<Fr> + Clone,
    {
        if circuits.len() != public_inputs_per_circuit.len() {
            return Err(ZKPError::InvalidPublicInputs);
        }

        let pk = self
            .proving_keys
            .read()
            .get(&proof_type)
            .ok_or_else(|| ZKPError::KeyNotFound(format!("{:?}", proof_type)))?
            .clone();

        let mut rng = OsRng;

        let mut proofs = Vec::new();

        for (circuit, public_inputs) in circuits.into_iter().zip(public_inputs_per_circuit) {
            // WP-P4-16(a): pre-flight constraint-satisfaction check before Groth16::prove
            check_circuit_satisfied(circuit.clone())?;
            let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng)
                .map_err(|e| ZKPError::ProvingError(e.to_string()))?;

            let serializable = SerializableProof::from_proof(&proof, public_inputs)?;
            proofs.push(serializable);
        }

        Ok(proofs)
    }
}

impl Default for Prover {
    fn default() -> Self {
        Self::new()
    }
}
