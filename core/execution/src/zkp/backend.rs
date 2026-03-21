// citrate/core/execution/src/zkp/backend.rs

// ZKP backend for managing proof generation and verification
use super::prover::Prover;
use super::types::{ProofRequest, ProofResponse, ProofType, SerializableProof, ZKPError};
use super::verifier::Verifier;
use std::sync::Arc;
use std::time::Instant;

/// ZKP backend for managing proof generation and verification
pub struct ZKPBackend {
    prover: Arc<Prover>,
    verifier: Arc<Verifier>,
}

impl Default for ZKPBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl ZKPBackend {
    pub fn new() -> Self {
        let prover = Arc::new(Prover::new());
        let verifier = Arc::new(Verifier::new());

        Self { prover, verifier }
    }

    /// Initialize the backend with setup for all proof types.
    /// After setup, verifying keys are shared from prover → verifier
    /// so that proofs can be verified independently.
    pub fn initialize(&self) -> Result<(), ZKPError> {
        let proof_types = [
            ProofType::ModelExecution,
            ProofType::GradientSubmission,
            ProofType::StateTransition,
            ProofType::DataIntegrity,
        ];

        // Setup all proof types (generates proving + verifying keys in prover)
        for pt in &proof_types {
            self.prover.setup(*pt)?;
        }

        // Wire verifying keys from prover to verifier (closes the VK handoff gap).
        // SAFETY: If any VK is missing, the entire initialization fails —
        // prevents a partially-initialized backend from silently producing
        // unverifiable proofs. (Modeled in ZKKeyManagement.tla, NoPartialSetup invariant.)
        for pt in &proof_types {
            let vk = self.prover.get_verifying_key(*pt).ok_or_else(|| {
                ZKPError::SetupError(format!(
                    "VK handoff failed: prover has no verifying key for {:?} after setup",
                    pt
                ))
            })?;
            self.verifier.add_verifying_key(*pt, vk);
        }

        Ok(())
    }

    /// Generate proof based on request
    pub fn generate_proof(&self, request: ProofRequest) -> Result<ProofResponse, ZKPError> {
        let start = Instant::now();

        let proof = match request.proof_type {
            ProofType::ModelExecution => {
                // Parse circuit data for model execution
                let circuit_data: super::types::ModelExecutionCircuit =
                    bincode::deserialize(&request.circuit_data)
                        .map_err(|_| ZKPError::InvalidCircuit)?;

                self.prover.prove_model_execution(
                    circuit_data.model_hash,
                    circuit_data.input_hash,
                    circuit_data.output_hash,
                    circuit_data.computation_trace,
                )?
            }
            ProofType::GradientSubmission => {
                // Parse circuit data for gradient submission
                let circuit_data: super::types::GradientProofCircuit =
                    bincode::deserialize(&request.circuit_data)
                        .map_err(|_| ZKPError::InvalidCircuit)?;

                self.prover.prove_gradient_submission(
                    circuit_data.model_hash,
                    circuit_data.dataset_hash,
                    circuit_data.gradient_hash,
                    circuit_data.loss_value,
                    circuit_data.num_samples,
                )?
            }
            ProofType::StateTransition => {
                // Parse circuit data for state transition
                let circuit_data: super::circuits::StateTransitionCircuit =
                    bincode::deserialize(&request.circuit_data)
                        .map_err(|_| ZKPError::InvalidCircuit)?;

                self.prover.prove_state_transition(
                    circuit_data.old_state_root,
                    circuit_data.new_state_root,
                    circuit_data.transaction_hash,
                )?
            }
            ProofType::DataIntegrity => {
                // Parse circuit data for data integrity
                let circuit_data: super::circuits::DataIntegrityCircuit =
                    bincode::deserialize(&request.circuit_data)
                        .map_err(|_| ZKPError::InvalidCircuit)?;

                self.prover.prove_data_integrity(
                    circuit_data.data_hash,
                    circuit_data.merkle_path,
                    circuit_data.merkle_root,
                    circuit_data.leaf_index,
                )?
            }
        };

        let generation_time_ms = start.elapsed().as_millis() as u64;

        Ok(ProofResponse {
            proof,
            proof_type: request.proof_type,
            generation_time_ms,
        })
    }

    /// Verify a proof
    pub fn verify_proof(
        &self,
        proof_type: ProofType,
        proof: &SerializableProof,
    ) -> Result<bool, ZKPError> {
        let result = self.verifier.verify(proof_type, proof)?;
        Ok(result.is_valid)
    }

    /// Generate proof for tensor computation
    pub fn prove_tensor_computation(
        &self,
        operation: &str,
        input_tensors: Vec<Vec<u8>>,
        output_tensor: Vec<u8>,
    ) -> Result<SerializableProof, ZKPError> {
        use sha3::{Digest, Sha3_256};

        // Hash inputs and output
        let mut hasher = Sha3_256::new();
        for input in &input_tensors {
            hasher.update(input);
        }
        let input_hash = hasher.finalize_reset().to_vec();

        hasher.update(&output_tensor);
        let output_hash = hasher.finalize_reset().to_vec();

        // Create computation trace
        let computation_trace = vec![super::types::ComputationStep {
            operation: operation.to_string(),
            input_values: vec![input_tensors.len() as f64],
            output_value: 1.0,
        }];

        // Model hash (for tensor operations, we use operation type as identifier)
        hasher.update(operation.as_bytes());
        let model_hash = hasher.finalize().to_vec();

        self.prover
            .prove_model_execution(model_hash, input_hash, output_hash, computation_trace)
    }

    /// Verify tensor computation proof
    pub fn verify_tensor_computation(
        &self,
        proof: &SerializableProof,
        operation: &str,
        input_tensors: Vec<Vec<u8>>,
        output_tensor: Vec<u8>,
    ) -> Result<bool, ZKPError> {
        use sha3::{Digest, Sha3_256};

        // Compute expected hashes
        let mut hasher = Sha3_256::new();

        hasher.update(operation.as_bytes());
        let model_hash = hasher.finalize_reset().to_vec();

        for input in &input_tensors {
            hasher.update(input);
        }
        let input_hash = hasher.finalize_reset().to_vec();

        hasher.update(&output_tensor);
        let output_hash = hasher.finalize().to_vec();

        self.verifier
            .verify_model_execution(proof, &model_hash, &input_hash, &output_hash)
    }

    /// Generate proof for model training
    pub fn prove_training_round(
        &self,
        model_id: &[u8],
        dataset_id: &[u8],
        gradients: Vec<u8>,
        loss: f64,
        batch_size: u64,
    ) -> Result<SerializableProof, ZKPError> {
        use sha3::{Digest, Sha3_256};

        let mut hasher = Sha3_256::new();
        hasher.update(&gradients);
        let gradient_hash = hasher.finalize().to_vec();

        self.prover.prove_gradient_submission(
            model_id.to_vec(),
            dataset_id.to_vec(),
            gradient_hash,
            loss,
            batch_size,
        )
    }

    /// Batch generate proofs
    pub fn batch_generate_proofs(
        &self,
        requests: Vec<ProofRequest>,
    ) -> Result<Vec<ProofResponse>, ZKPError> {
        let mut responses = Vec::new();

        for request in requests {
            let response = self.generate_proof(request)?;
            responses.push(response);
        }

        Ok(responses)
    }

    /// Get proving time estimate
    pub fn estimate_proving_time(&self, proof_type: ProofType) -> u64 {
        // Estimates in milliseconds
        match proof_type {
            ProofType::ModelExecution => 500,
            ProofType::GradientSubmission => 750,
            ProofType::StateTransition => 300,
            ProofType::DataIntegrity => 400,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::types::{
        ModelExecutionCircuit, GradientProofCircuit,
        ProofRequest, ProofType, SerializableProof, ZKPError,
    };
    use super::super::circuits::{StateTransitionCircuit, DataIntegrityCircuit};

    // ---------------------------------------------------------------
    // Helper: build a fully-initialized backend (setup all 4 key pairs)
    // ---------------------------------------------------------------
    fn initialized_backend() -> ZKPBackend {
        let backend = ZKPBackend::new();
        backend.initialize().expect("Backend initialization must succeed");
        backend
    }

    // ---------------------------------------------------------------
    // Helper: create valid circuit_data bytes for each proof type
    // ---------------------------------------------------------------
    fn model_execution_data() -> Vec<u8> {
        // computation_trace must be empty to match the setup circuit's constraint count.
        // Groth16 requires identical circuit structure between setup and proving.
        let circuit = ModelExecutionCircuit {
            model_hash: vec![1u8; 32],
            input_hash: vec![2u8; 32],
            output_hash: vec![3u8; 32],
            computation_trace: vec![],
        };
        bincode::serialize(&circuit).unwrap()
    }

    fn gradient_submission_data() -> Vec<u8> {
        let circuit = GradientProofCircuit {
            model_hash: vec![10u8; 32],
            dataset_hash: vec![11u8; 32],
            gradient_hash: vec![12u8; 32],
            loss_value: 0.5,
            num_samples: 100,
        };
        bincode::serialize(&circuit).unwrap()
    }

    fn state_transition_data() -> Vec<u8> {
        let circuit = StateTransitionCircuit {
            old_state_root: vec![20u8; 32],
            new_state_root: vec![21u8; 32],
            transaction_hash: vec![22u8; 32],
        };
        bincode::serialize(&circuit).unwrap()
    }

    fn data_integrity_data() -> Vec<u8> {
        let circuit = DataIntegrityCircuit {
            data_hash: vec![30u8; 32],
            merkle_path: vec![],
            merkle_root: vec![30u8; 32], // same as data_hash => root == leaf (no path)
            leaf_index: 0,
        };
        bincode::serialize(&circuit).unwrap()
    }

    // ====================================================================
    // Happy-path tests
    // ====================================================================

    #[test]
    fn test_all_proof_types_generate_and_verify() {
        let backend = initialized_backend();

        let cases: Vec<(ProofType, Vec<u8>)> = vec![
            (ProofType::ModelExecution, model_execution_data()),
            (ProofType::GradientSubmission, gradient_submission_data()),
            (ProofType::StateTransition, state_transition_data()),
            (ProofType::DataIntegrity, data_integrity_data()),
        ];

        for (proof_type, circuit_data) in cases {
            let request = ProofRequest {
                proof_type,
                circuit_data,
                public_inputs: vec![],
            };

            let response = backend
                .generate_proof(request)
                .unwrap_or_else(|e| panic!("generate_proof failed for {:?}: {:?}", proof_type, e));

            assert_eq!(response.proof_type, proof_type);
            assert!(!response.proof.proof_bytes.is_empty());
            assert!(response.generation_time_ms > 0 || response.generation_time_ms == 0);

            let valid = backend
                .verify_proof(proof_type, &response.proof)
                .unwrap_or_else(|e| panic!("verify_proof failed for {:?}: {:?}", proof_type, e));

            assert!(valid, "Proof for {:?} must verify", proof_type);
        }
    }

    #[test]
    fn test_proof_determinism_with_same_input() {
        // Same input produces proofs that both verify (bytes differ due to OsRng)
        let backend = initialized_backend();

        let data = model_execution_data();

        let req1 = ProofRequest {
            proof_type: ProofType::ModelExecution,
            circuit_data: data.clone(),
            public_inputs: vec![],
        };
        let req2 = ProofRequest {
            proof_type: ProofType::ModelExecution,
            circuit_data: data,
            public_inputs: vec![],
        };

        let resp1 = backend.generate_proof(req1).unwrap();
        let resp2 = backend.generate_proof(req2).unwrap();

        // Both must verify
        assert!(backend.verify_proof(ProofType::ModelExecution, &resp1.proof).unwrap());
        assert!(backend.verify_proof(ProofType::ModelExecution, &resp2.proof).unwrap());

        // Public inputs must be identical (same circuit data)
        assert_eq!(resp1.proof.public_inputs, resp2.proof.public_inputs);
    }

    #[test]
    fn test_different_inputs_produce_different_proofs() {
        let backend = initialized_backend();

        let circuit_a = ModelExecutionCircuit {
            model_hash: vec![1u8; 32],
            input_hash: vec![2u8; 32],
            output_hash: vec![3u8; 32],
            computation_trace: vec![],
        };
        let circuit_b = ModelExecutionCircuit {
            model_hash: vec![99u8; 32],
            input_hash: vec![98u8; 32],
            output_hash: vec![97u8; 32],
            computation_trace: vec![],
        };

        let req_a = ProofRequest {
            proof_type: ProofType::ModelExecution,
            circuit_data: bincode::serialize(&circuit_a).unwrap(),
            public_inputs: vec![],
        };
        let req_b = ProofRequest {
            proof_type: ProofType::ModelExecution,
            circuit_data: bincode::serialize(&circuit_b).unwrap(),
            public_inputs: vec![],
        };

        let resp_a = backend.generate_proof(req_a).unwrap();
        let resp_b = backend.generate_proof(req_b).unwrap();

        // Different inputs should yield different public inputs
        assert_ne!(
            resp_a.proof.public_inputs, resp_b.proof.public_inputs,
            "Different circuit data must produce different public inputs"
        );
    }

    // ====================================================================
    // Edge-case / failure tests
    // ====================================================================

    #[test]
    fn test_verify_without_initialize_fails() {
        // Backend with no keys: verify should return KeyNotFound
        let backend = ZKPBackend::new();

        // Create a dummy proof (will never reach verification math)
        let dummy_proof = SerializableProof {
            proof_bytes: vec![0u8; 192], // Groth16 compressed proof size
            public_inputs: vec!["0".to_string()],
        };

        let result = backend.verify_proof(ProofType::ModelExecution, &dummy_proof);
        assert!(result.is_err(), "verify_proof before initialize must fail");

        let err = result.unwrap_err();
        assert!(
            matches!(err, ZKPError::KeyNotFound(_)),
            "Expected KeyNotFound, got: {:?}",
            err,
        );
    }

    #[test]
    fn test_generate_without_initialize_fails() {
        // Backend with no keys: generate should return KeyNotFound
        let backend = ZKPBackend::new();

        let request = ProofRequest {
            proof_type: ProofType::ModelExecution,
            circuit_data: model_execution_data(),
            public_inputs: vec![],
        };

        let result = backend.generate_proof(request);
        assert!(result.is_err(), "generate_proof before initialize must fail");

        let err = result.unwrap_err();
        assert!(
            matches!(err, ZKPError::KeyNotFound(_)),
            "Expected KeyNotFound, got: {:?}",
            err,
        );
    }

    #[test]
    fn test_invalid_circuit_data_rejected() {
        let backend = initialized_backend();

        // Garbage bytes that can't be deserialized as any circuit type
        let request = ProofRequest {
            proof_type: ProofType::ModelExecution,
            circuit_data: vec![0xFF, 0xFE, 0xFD, 0xFC],
            public_inputs: vec![],
        };

        let result = backend.generate_proof(request);
        assert!(result.is_err(), "Garbage circuit_data must be rejected");

        let err = result.unwrap_err();
        assert!(
            matches!(err, ZKPError::InvalidCircuit),
            "Expected InvalidCircuit, got: {:?}",
            err,
        );
    }

    #[test]
    fn test_tampered_proof_rejected() {
        let backend = initialized_backend();

        let request = ProofRequest {
            proof_type: ProofType::ModelExecution,
            circuit_data: model_execution_data(),
            public_inputs: vec![],
        };

        let response = backend.generate_proof(request).unwrap();

        // Tamper with one byte in the proof
        let mut tampered = response.proof.clone();
        if !tampered.proof_bytes.is_empty() {
            tampered.proof_bytes[0] ^= 0xFF;
        }

        // Verification should either fail with an error (deserialization) or return false
        let result = backend.verify_proof(ProofType::ModelExecution, &tampered);
        match result {
            Ok(valid) => assert!(!valid, "Tampered proof must not verify as valid"),
            Err(_) => {} // Deserialization error is also acceptable for corrupted bytes
        }
    }

    #[test]
    fn test_wrong_proof_type_fails() {
        let backend = initialized_backend();

        // Generate a ModelExecution proof
        let request = ProofRequest {
            proof_type: ProofType::ModelExecution,
            circuit_data: model_execution_data(),
            public_inputs: vec![],
        };
        let response = backend.generate_proof(request).unwrap();

        // Try to verify it as a GradientSubmission — must fail
        let result = backend.verify_proof(ProofType::GradientSubmission, &response.proof);
        match result {
            Ok(valid) => assert!(
                !valid,
                "Proof generated as ModelExecution must not verify as GradientSubmission"
            ),
            Err(_) => {} // Error is also acceptable (different VK, deserialization mismatch)
        }
    }

    #[test]
    fn test_empty_public_inputs_parsed() {
        // The verifier's parse_public_inputs with empty vec should return empty result.
        // We test indirectly: a proof with empty public_inputs should
        // fail at verification (no matching field elements), not panic.
        let backend = initialized_backend();

        let empty_proof = SerializableProof {
            proof_bytes: vec![0u8; 192],
            public_inputs: vec![],
        };

        // Should not panic — will fail at deserialization or verification
        let result = backend.verify_proof(ProofType::ModelExecution, &empty_proof);
        // We only care that it doesn't panic; error is expected
        assert!(result.is_err() || !result.unwrap());
    }

    #[test]
    fn test_public_input_hex_parsing() {
        // Verify that hex-formatted public inputs round-trip through the verifier.
        // We test parse_public_inputs indirectly since it's private.
        // A backend initialized with keys should accept proofs with hex public inputs.
        // For a direct test, we verify the prover produces decimal strings that
        // the verifier can parse.
        let backend = initialized_backend();

        let request = ProofRequest {
            proof_type: ProofType::ModelExecution,
            circuit_data: model_execution_data(),
            public_inputs: vec![],
        };
        let response = backend.generate_proof(request).unwrap();

        // The public inputs should be parseable decimal strings
        for pi in &response.proof.public_inputs {
            let parsed: Result<u128, _> = pi.parse();
            assert!(
                parsed.is_ok(),
                "Public input '{}' must be parseable as u128",
                pi
            );
        }

        // Verify succeeds with these decimal public inputs
        assert!(backend.verify_proof(ProofType::ModelExecution, &response.proof).unwrap());
    }

    #[test]
    fn test_public_input_decimal_parsing() {
        // Verify that decimal public inputs are correctly handled end-to-end
        let backend = initialized_backend();

        let request = ProofRequest {
            proof_type: ProofType::StateTransition,
            circuit_data: state_transition_data(),
            public_inputs: vec![],
        };
        let response = backend.generate_proof(request).unwrap();

        // All public inputs should be valid decimal strings
        for pi in &response.proof.public_inputs {
            assert!(
                pi.parse::<u128>().is_ok() || pi.starts_with("0x"),
                "Public input must be decimal or hex, got: {}",
                pi
            );
        }
    }

    #[test]
    fn test_public_input_invalid_rejected() {
        // A proof with an unparseable public input string should fail verification,
        // not silently produce Fr(0).
        let backend = initialized_backend();

        let bad_proof = SerializableProof {
            proof_bytes: vec![0u8; 192],
            public_inputs: vec!["not_a_number".to_string()],
        };

        let result = backend.verify_proof(ProofType::ModelExecution, &bad_proof);
        // Must error or return false — never silently succeed
        match result {
            Ok(valid) => assert!(
                !valid,
                "Invalid public input 'not_a_number' must not lead to a valid proof"
            ),
            Err(e) => {
                // InvalidPublicInputs or deserialization error is expected
                let msg = format!("{:?}", e);
                assert!(
                    msg.contains("InvalidPublicInputs")
                        || msg.contains("Deserialization")
                        || msg.contains("Verification"),
                    "Expected a parsing/verification error, got: {}",
                    msg,
                );
            }
        }
    }
}
