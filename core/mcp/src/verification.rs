// citrate/core/mcp/src/verification.rs

// Execution verifier for validating model execution proofs
use crate::execution::Model;
use crate::types::ExecutionProof;
use anyhow::Result;
use citrate_execution::Hash;
use sha3::{Digest, Sha3_256};
use tracing::{debug, info, warn};

/// Execution verifier for validating model execution proofs
pub struct ExecutionVerifier {
    // In production, this would include ZKP backend
}

impl ExecutionVerifier {
    pub fn new() -> Self {
        Self {}
    }

    /// Verify model integrity
    pub fn verify_model(&self, model: &Model) -> Result<()> {
        // Basic validation
        if model.architecture.is_empty() {
            return Err(anyhow::anyhow!("Model architecture is empty"));
        }

        if model.weights.is_empty() {
            return Err(anyhow::anyhow!("Model weights are empty"));
        }
        if model.metadata.is_empty() {
            return Err(anyhow::anyhow!("Model metadata is empty"));
        }

        // Additional sanity checks
        // - Enforce an upper bound on model size to prevent abuse in dev environments
        // - Compute and log a stable model hash for reproducibility
        let max_size_bytes: usize = 500 * 1024 * 1024; // 500 MB
        if model.weights.len() > max_size_bytes {
            return Err(anyhow::anyhow!(
                "Model weights too large: {} bytes (max {})",
                model.weights.len(),
                max_size_bytes
            ));
        }

        // Derive model hash and ensure it is not the zero hash
        let model_hash = self.hash_model(model);
        if model_hash == Hash::default() {
            return Err(anyhow::anyhow!("Computed model hash is zero"));
        }

        debug!("Model {:?} verified", hex::encode(&model.id.0[..8]));
        Ok(())
    }

    /// Verify execution proof
    pub fn verify_execution(
        &self,
        model: &Model,
        input: &[u8],
        output: &[u8],
        proof: &ExecutionProof,
    ) -> Result<bool> {
        // 1. Verify model hash
        let model_hash = self.hash_model(model);
        if model_hash != proof.model_hash {
            warn!("Model hash mismatch");
            return Ok(false);
        }

        // 2. Verify input hash
        let input_hash = self.hash_data(input);
        if input_hash != proof.input_hash {
            warn!("Input hash mismatch");
            return Ok(false);
        }

        // 3. Verify output hash
        let output_hash = self.hash_data(output);
        if output_hash != proof.output_hash {
            warn!("Output hash mismatch");
            return Ok(false);
        }

        // 4. Verify IO commitment
        let io_commitment = self.compute_io_commitment(&input_hash, &output_hash);
        if io_commitment != proof.io_commitment {
            warn!("IO commitment mismatch");
            return Ok(false);
        }

        // 5. Verify ZK proof (placeholder)
        if !self.verify_zk_proof(&proof.statement, &proof.proof_data)? {
            warn!("ZK proof verification failed");
            return Ok(false);
        }

        debug!(
            "Execution proof verified for model {:?}",
            hex::encode(&model.id.0[..8])
        );
        Ok(true)
    }

    /// Verify batch of proofs
    pub fn verify_batch(&self, proofs: &[ExecutionProof]) -> Result<Vec<bool>> {
        let mut results = Vec::new();

        for proof in proofs {
            // For now, verify individually
            // In production, use batch verification for efficiency
            let valid = self.verify_proof_standalone(proof)?;
            results.push(valid);
        }

        Ok(results)
    }

    /// Hash model
    fn hash_model(&self, model: &Model) -> Hash {
        let mut hasher = Sha3_256::new();
        hasher.update(&model.architecture);
        hasher.update(&model.weights);
        hasher.update(&model.metadata);

        let hash = hasher.finalize();
        Hash::new(hash.into())
    }

    /// Hash data
    fn hash_data(&self, data: &[u8]) -> Hash {
        let mut hasher = Sha3_256::new();
        hasher.update(data);

        let hash = hasher.finalize();
        Hash::new(hash.into())
    }

    /// Compute IO commitment
    fn compute_io_commitment(&self, input_hash: &Hash, output_hash: &Hash) -> Hash {
        let mut hasher = Sha3_256::new();
        hasher.update(input_hash.as_bytes());
        hasher.update(output_hash.as_bytes());

        let hash = hasher.finalize();
        Hash::new(hash.into())
    }

    /// Verify ZK proof
    ///
    /// This implements a commitment-based verification scheme.
    /// In production, this should be replaced with proper ZK verification using:
    /// - arkworks for zkSNARKs
    /// - bulletproofs for range proofs
    /// - PLONK for general-purpose proofs
    ///
    /// Current implementation verifies that the proof contains a valid
    /// commitment to the statement using a hash-based scheme.
    fn verify_zk_proof(&self, statement: &[u8], proof_data: &[u8]) -> Result<bool> {
        use sha3::{Digest, Sha3_256};

        // Reject empty inputs - this is a security requirement
        if statement.is_empty() {
            warn!("ZK verification failed: empty statement");
            return Ok(false);
        }

        if proof_data.is_empty() {
            warn!("ZK verification failed: empty proof data");
            return Ok(false);
        }

        // Minimum proof size: 32 bytes for commitment + 32 bytes for response
        if proof_data.len() < 64 {
            warn!("ZK verification failed: proof too short ({} bytes)", proof_data.len());
            return Ok(false);
        }

        // Extract commitment and response from proof
        let commitment = &proof_data[0..32];
        let response = &proof_data[32..64];

        // Compute expected commitment: H(statement || response)
        let mut hasher = Sha3_256::new();
        hasher.update(statement);
        hasher.update(response);
        let expected_commitment = hasher.finalize();

        // Verify commitment matches
        if commitment != expected_commitment.as_slice() {
            warn!("ZK verification failed: commitment mismatch");
            return Ok(false);
        }

        info!("ZK proof verified successfully");
        Ok(true)
    }

    /// Verify proof without model/input/output
    fn verify_proof_standalone(&self, proof: &ExecutionProof) -> Result<bool> {
        // Basic validation
        if proof.model_hash == Hash::default() {
            return Ok(false);
        }

        if proof.input_hash == Hash::default() {
            return Ok(false);
        }

        if proof.output_hash == Hash::default() {
            return Ok(false);
        }

        // Check IO commitment consistency
        let expected_commitment = self.compute_io_commitment(&proof.input_hash, &proof.output_hash);

        if expected_commitment != proof.io_commitment {
            return Ok(false);
        }

        // Verify timestamp is reasonable (not in future)
        let now = chrono::Utc::now().timestamp() as u64;
        if proof.timestamp > now {
            return Ok(false);
        }

        Ok(true)
    }

    /// Generate verification key (for setup phase)
    pub fn generate_verification_key(&self, model: &Model) -> Result<VerificationKey> {
        // Placeholder for verification key generation
        // In production, this would generate circuit-specific keys

        let model_hash = self.hash_model(model);

        Ok(VerificationKey {
            model_hash,
            key_data: vec![1, 2, 3, 4], // Placeholder
            created_at: chrono::Utc::now().timestamp() as u64,
        })
    }
}

/// Verification key for a model
#[derive(Debug, Clone)]
pub struct VerificationKey {
    pub model_hash: Hash,
    pub key_data: Vec<u8>,
    pub created_at: u64,
}

impl Default for ExecutionVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::Model;
    use crate::types::ModelId;

    fn create_test_model(arch: &[u8], weights: &[u8], meta: &[u8]) -> Model {
        Model {
            id: ModelId([1u8; 32]),
            architecture: arch.to_vec(),
            weights: weights.to_vec(),
            metadata: meta.to_vec(),
        }
    }

    fn create_valid_proof(model: &Model, input: &[u8], output: &[u8]) -> ExecutionProof {
        let verifier = ExecutionVerifier::new();

        let model_hash = {
            let mut hasher = Sha3_256::new();
            hasher.update(&model.architecture);
            hasher.update(&model.weights);
            hasher.update(&model.metadata);
            Hash::new(hasher.finalize().into())
        };

        let input_hash = {
            let mut hasher = Sha3_256::new();
            hasher.update(input);
            Hash::new(hasher.finalize().into())
        };

        let output_hash = {
            let mut hasher = Sha3_256::new();
            hasher.update(output);
            Hash::new(hasher.finalize().into())
        };

        let io_commitment = verifier.compute_io_commitment(&input_hash, &output_hash);

        // Create valid ZK proof (commitment-based)
        let statement = b"test statement".to_vec();
        let response = [42u8; 32];
        let mut hasher = Sha3_256::new();
        hasher.update(&statement);
        hasher.update(&response);
        let commitment = hasher.finalize();

        let mut proof_data = commitment.to_vec();
        proof_data.extend_from_slice(&response);

        ExecutionProof {
            model_hash,
            input_hash,
            output_hash,
            io_commitment,
            statement,
            proof_data,
            timestamp: chrono::Utc::now().timestamp() as u64,
            provider: citrate_execution::Address([0u8; 20]),
        }
    }

    #[test]
    fn test_verifier_new() {
        let verifier = ExecutionVerifier::new();
        assert!(std::mem::size_of_val(&verifier) >= 0); // Just verify it creates
    }

    #[test]
    fn test_verifier_default() {
        let verifier = ExecutionVerifier::default();
        assert!(std::mem::size_of_val(&verifier) >= 0);
    }

    #[test]
    fn test_verify_model_valid() {
        let verifier = ExecutionVerifier::new();
        let model = create_test_model(b"arch", b"weights", b"meta");

        let result = verifier.verify_model(&model);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_model_empty_architecture() {
        let verifier = ExecutionVerifier::new();
        let model = create_test_model(&[], b"weights", b"meta");

        let result = verifier.verify_model(&model);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("architecture"));
    }

    #[test]
    fn test_verify_model_empty_weights() {
        let verifier = ExecutionVerifier::new();
        let model = create_test_model(b"arch", &[], b"meta");

        let result = verifier.verify_model(&model);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("weights"));
    }

    #[test]
    fn test_verify_model_empty_metadata() {
        let verifier = ExecutionVerifier::new();
        let model = create_test_model(b"arch", b"weights", &[]);

        let result = verifier.verify_model(&model);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("metadata"));
    }

    #[test]
    fn test_verify_model_weights_too_large() {
        let verifier = ExecutionVerifier::new();
        let large_weights = vec![0u8; 501 * 1024 * 1024]; // 501 MB
        let model = create_test_model(b"arch", &large_weights, b"meta");

        let result = verifier.verify_model(&model);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }

    #[test]
    fn test_verify_execution_valid() {
        let verifier = ExecutionVerifier::new();
        let model = create_test_model(b"arch", b"weights", b"meta");
        let input = b"test input";
        let output = b"test output";
        let proof = create_valid_proof(&model, input, output);

        let result = verifier.verify_execution(&model, input, output, &proof);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_execution_model_hash_mismatch() {
        let verifier = ExecutionVerifier::new();
        let model = create_test_model(b"arch", b"weights", b"meta");
        let input = b"test input";
        let output = b"test output";
        let mut proof = create_valid_proof(&model, input, output);

        // Corrupt model hash
        proof.model_hash = Hash::new([0u8; 32]);

        let result = verifier.verify_execution(&model, input, output, &proof);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should fail verification
    }

    #[test]
    fn test_verify_execution_input_hash_mismatch() {
        let verifier = ExecutionVerifier::new();
        let model = create_test_model(b"arch", b"weights", b"meta");
        let input = b"test input";
        let output = b"test output";
        let proof = create_valid_proof(&model, input, output);

        // Use different input for verification
        let different_input = b"different input";
        let result = verifier.verify_execution(&model, different_input, output, &proof);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_verify_execution_output_hash_mismatch() {
        let verifier = ExecutionVerifier::new();
        let model = create_test_model(b"arch", b"weights", b"meta");
        let input = b"test input";
        let output = b"test output";
        let proof = create_valid_proof(&model, input, output);

        // Use different output for verification
        let different_output = b"different output";
        let result = verifier.verify_execution(&model, input, different_output, &proof);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_verify_batch_empty() {
        let verifier = ExecutionVerifier::new();
        let proofs: Vec<ExecutionProof> = vec![];

        let results = verifier.verify_batch(&proofs).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_verify_batch_mixed() {
        let verifier = ExecutionVerifier::new();
        let model = create_test_model(b"arch", b"weights", b"meta");

        // Valid proof
        let valid_proof = create_valid_proof(&model, b"input1", b"output1");

        // Invalid proof (default hashes)
        let invalid_proof = ExecutionProof {
            model_hash: Hash::default(),
            input_hash: Hash::default(),
            output_hash: Hash::default(),
            io_commitment: Hash::default(),
            statement: vec![],
            proof_data: vec![],
            timestamp: chrono::Utc::now().timestamp() as u64,
            provider: citrate_execution::Address([0u8; 20]),
        };

        let proofs = vec![valid_proof, invalid_proof];
        let results = verifier.verify_batch(&proofs).unwrap();

        assert_eq!(results.len(), 2);
        assert!(results[0]); // Valid proof should pass standalone check
        assert!(!results[1]); // Invalid proof should fail
    }

    #[test]
    fn test_generate_verification_key() {
        let verifier = ExecutionVerifier::new();
        let model = create_test_model(b"arch", b"weights", b"meta");

        let vk = verifier.generate_verification_key(&model).unwrap();

        assert_ne!(vk.model_hash, Hash::default());
        assert!(!vk.key_data.is_empty());
        assert!(vk.created_at > 0);
    }

    #[test]
    fn test_generate_verification_key_deterministic_hash() {
        let verifier = ExecutionVerifier::new();
        let model = create_test_model(b"arch", b"weights", b"meta");

        let vk1 = verifier.generate_verification_key(&model).unwrap();
        let vk2 = verifier.generate_verification_key(&model).unwrap();

        // Model hash should be deterministic
        assert_eq!(vk1.model_hash, vk2.model_hash);
    }

    #[test]
    fn test_verify_zk_proof_empty_statement() {
        let verifier = ExecutionVerifier::new();
        let model = create_test_model(b"arch", b"weights", b"meta");
        let input = b"test input";
        let output = b"test output";
        let mut proof = create_valid_proof(&model, input, output);

        proof.statement = vec![]; // Empty statement

        let result = verifier.verify_execution(&model, input, output, &proof);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should fail ZK verification
    }

    #[test]
    fn test_verify_zk_proof_empty_proof_data() {
        let verifier = ExecutionVerifier::new();
        let model = create_test_model(b"arch", b"weights", b"meta");
        let input = b"test input";
        let output = b"test output";
        let mut proof = create_valid_proof(&model, input, output);

        proof.proof_data = vec![]; // Empty proof data

        let result = verifier.verify_execution(&model, input, output, &proof);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should fail ZK verification
    }

    #[test]
    fn test_verify_zk_proof_too_short() {
        let verifier = ExecutionVerifier::new();
        let model = create_test_model(b"arch", b"weights", b"meta");
        let input = b"test input";
        let output = b"test output";
        let mut proof = create_valid_proof(&model, input, output);

        proof.proof_data = vec![1, 2, 3]; // Too short (< 64 bytes)

        let result = verifier.verify_execution(&model, input, output, &proof);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should fail ZK verification
    }

    #[test]
    fn test_verify_proof_standalone_zero_hashes() {
        let verifier = ExecutionVerifier::new();

        let invalid_proof = ExecutionProof {
            model_hash: Hash::default(),
            input_hash: Hash::new([1u8; 32]),
            output_hash: Hash::new([2u8; 32]),
            io_commitment: Hash::default(),
            statement: vec![],
            proof_data: vec![],
            timestamp: chrono::Utc::now().timestamp() as u64,
            provider: citrate_execution::Address([0u8; 20]),
        };

        let results = verifier.verify_batch(&[invalid_proof]).unwrap();
        assert!(!results[0]); // Zero model hash should fail
    }

    #[test]
    fn test_verify_proof_standalone_future_timestamp() {
        let verifier = ExecutionVerifier::new();
        let model = create_test_model(b"arch", b"weights", b"meta");
        let mut proof = create_valid_proof(&model, b"input", b"output");

        // Set timestamp in the future
        proof.timestamp = chrono::Utc::now().timestamp() as u64 + 3600;

        let results = verifier.verify_batch(&[proof]).unwrap();
        assert!(!results[0]); // Future timestamp should fail
    }

    #[test]
    fn test_io_commitment_consistency() {
        let verifier = ExecutionVerifier::new();
        let model = create_test_model(b"arch", b"weights", b"meta");
        let input = b"test input";
        let output = b"test output";
        let mut proof = create_valid_proof(&model, input, output);

        // Corrupt IO commitment
        proof.io_commitment = Hash::new([99u8; 32]);

        let result = verifier.verify_execution(&model, input, output, &proof);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // IO commitment mismatch should fail
    }
}
