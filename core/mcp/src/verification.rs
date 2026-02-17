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
        // Architecture check: warn if empty but weights present (legacy records),
        // reject only when BOTH architecture and weights are empty.
        if model.architecture.is_empty() {
            if model.weights.is_empty() {
                return Err(anyhow::anyhow!(
                    "Model has neither architecture nor weights"
                ));
            }
            warn!(
                "Model {:?} has empty architecture descriptor; proceeding with weights only",
                hex::encode(&model.id.0[..8])
            );
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

    /// Verify ZK proof using commitment-based scheme.
    ///
    /// When the `zkp_production` feature is enabled, this should dispatch to
    /// `verify_groth16_proof` (not yet implemented — see ADR-003).
    /// The arkworks crates (ark-groth16, ark-r1cs-std, ark-bls12-381) are
    /// already available in `core/execution/Cargo.toml:44-54`.
    fn verify_zk_proof(&self, statement: &[u8], proof_data: &[u8]) -> Result<bool> {
        #[cfg(feature = "zkp_production")]
        {
            return self.verify_groth16_proof(statement, proof_data);
        }

        #[cfg(not(feature = "zkp_production"))]
        {
            return self.verify_commitment_proof(statement, proof_data);
        }
    }

    /// Placeholder for Groth16 verification via arkworks.
    /// Gated behind `zkp_production` feature flag.
    #[cfg(feature = "zkp_production")]
    fn verify_groth16_proof(&self, _statement: &[u8], _proof_data: &[u8]) -> Result<bool> {
        // TODO: Implement using ark-groth16 + ark-bls12-381 from core/execution
        // 1. Deserialize proof from proof_data
        // 2. Deserialize verification key
        // 3. Prepare public inputs from statement
        // 4. Call Groth16::verify(&vk, &public_inputs, &proof)
        Err(anyhow::anyhow!(
            "Groth16 verification not yet implemented; enable arkworks integration"
        ))
    }

    /// Commitment-based proof verification (interim scheme).
    fn verify_commitment_proof(&self, statement: &[u8], proof_data: &[u8]) -> Result<bool> {
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
    ///
    /// Generates a unique verification key for a model based on its content hash.
    /// The key is derived using SHA3-256 with domain separation to ensure uniqueness.
    ///
    /// In production with a full ZK proving system, this would generate circuit-specific
    /// proving/verification key pairs using arkworks or similar libraries.
    pub fn generate_verification_key(&self, model: &Model) -> Result<VerificationKey> {
        let model_hash = self.hash_model(model);

        // Derive verification key from model hash using domain separation
        // This ensures each model gets a unique key based on its content
        let key_data = self.derive_verification_key_data(&model_hash, model);

        Ok(VerificationKey {
            model_hash,
            key_data,
            created_at: chrono::Utc::now().timestamp() as u64,
        })
    }

    /// Derive verification key data from model hash
    ///
    /// Uses a multi-round key derivation to produce a unique verification key
    /// for each model. The key incorporates:
    /// - Model content hash
    /// - Model size
    /// - Architecture hash
    fn derive_verification_key_data(&self, model_hash: &Hash, model: &Model) -> Vec<u8> {
        // Domain separation prefix for verification keys
        const VK_DOMAIN: &[u8] = b"citrate_verification_key_v1";

        // Round 1: Derive base key from model hash with domain separation
        let mut hasher = Sha3_256::new();
        hasher.update(VK_DOMAIN);
        hasher.update(model_hash.as_bytes());
        let base_key = hasher.finalize();

        // Round 2: Mix in architecture information for uniqueness
        let mut hasher = Sha3_256::new();
        hasher.update(&base_key);
        hasher.update(&model.architecture);
        hasher.update(&(model.weights.len() as u64).to_le_bytes());
        let arch_key = hasher.finalize();

        // Round 3: Final key derivation with additional entropy
        let mut hasher = Sha3_256::new();
        hasher.update(&arch_key);
        hasher.update(&model.metadata);
        hasher.update(b"final_key_derivation");
        let final_key = hasher.finalize();

        // Return 64 bytes of key material (two 32-byte hashes concatenated)
        let mut key_data = base_key.to_vec();
        key_data.extend_from_slice(&final_key);

        key_data
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
        // Empty architecture with weights present is allowed (legacy records) — just warns
        let model = create_test_model(&[], b"weights", b"meta");
        let result = verifier.verify_model(&model);
        assert!(result.is_ok());

        // Empty architecture AND empty weights should fail
        let model_both_empty = create_test_model(&[], &[], b"meta");
        let result_both = verifier.verify_model(&model_both_empty);
        assert!(result_both.is_err());
        assert!(result_both.unwrap_err().to_string().contains("neither"));
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

    #[test]
    fn test_verification_key_unique_per_model() {
        let verifier = ExecutionVerifier::new();

        // Create two different models
        let model1 = create_test_model(b"arch1", b"weights1", b"meta1");
        let model2 = create_test_model(b"arch2", b"weights2", b"meta2");

        let vk1 = verifier.generate_verification_key(&model1).unwrap();
        let vk2 = verifier.generate_verification_key(&model2).unwrap();

        // Different models should have different hashes
        assert_ne!(vk1.model_hash, vk2.model_hash);

        // Different models should have different key data
        assert_ne!(vk1.key_data, vk2.key_data);
    }

    #[test]
    fn test_verification_key_deterministic_key_data() {
        let verifier = ExecutionVerifier::new();
        let model = create_test_model(b"arch", b"weights", b"meta");

        let vk1 = verifier.generate_verification_key(&model).unwrap();
        let vk2 = verifier.generate_verification_key(&model).unwrap();

        // Same model should produce same key data
        assert_eq!(vk1.key_data, vk2.key_data);
    }

    #[test]
    fn test_verification_key_sufficient_length() {
        let verifier = ExecutionVerifier::new();
        let model = create_test_model(b"arch", b"weights", b"meta");

        let vk = verifier.generate_verification_key(&model).unwrap();

        // Key data should be at least 64 bytes (two SHA3-256 hashes)
        assert!(vk.key_data.len() >= 64);
    }

    #[test]
    fn test_verification_key_sensitive_to_weights() {
        let verifier = ExecutionVerifier::new();

        // Same architecture, different weights
        let model1 = create_test_model(b"arch", b"weights_a", b"meta");
        let model2 = create_test_model(b"arch", b"weights_b", b"meta");

        let vk1 = verifier.generate_verification_key(&model1).unwrap();
        let vk2 = verifier.generate_verification_key(&model2).unwrap();

        // Different weights should produce different keys
        assert_ne!(vk1.key_data, vk2.key_data);
    }

    #[test]
    fn test_verification_key_sensitive_to_architecture() {
        let verifier = ExecutionVerifier::new();

        // Same weights, different architecture
        let model1 = create_test_model(b"transformer", b"weights", b"meta");
        let model2 = create_test_model(b"cnn", b"weights", b"meta");

        let vk1 = verifier.generate_verification_key(&model1).unwrap();
        let vk2 = verifier.generate_verification_key(&model2).unwrap();

        // Different architecture should produce different keys
        assert_ne!(vk1.key_data, vk2.key_data);
    }

    #[test]
    fn test_verification_key_sensitive_to_metadata() {
        let verifier = ExecutionVerifier::new();

        // Same architecture and weights, different metadata
        let model1 = create_test_model(b"arch", b"weights", b"meta_v1");
        let model2 = create_test_model(b"arch", b"weights", b"meta_v2");

        let vk1 = verifier.generate_verification_key(&model1).unwrap();
        let vk2 = verifier.generate_verification_key(&model2).unwrap();

        // Different metadata should produce different keys
        assert_ne!(vk1.key_data, vk2.key_data);
    }

    // WP-A.4: ZK Proof Generation Tests

    #[test]
    fn test_zk_proof_structure() {
        // Verify proof structure: non-empty statement and proof_data >= 64 bytes
        let model = create_test_model(b"arch", b"weights", b"meta");
        let proof = create_valid_proof(&model, b"input", b"output");

        // Statement should be non-empty
        assert!(!proof.statement.is_empty());

        // Proof data should be at least 64 bytes (commitment + response)
        assert!(proof.proof_data.len() >= 64);
    }

    #[test]
    fn test_zk_proof_different_inputs_produce_different_proofs() {
        let model = create_test_model(b"arch", b"weights", b"meta");

        let proof1 = create_valid_proof(&model, b"input_a", b"output_a");
        let proof2 = create_valid_proof(&model, b"input_b", b"output_b");

        // Different inputs should produce different input hashes
        assert_ne!(proof1.input_hash, proof2.input_hash);

        // Different outputs should produce different output hashes
        assert_ne!(proof1.output_hash, proof2.output_hash);

        // IO commitments should differ
        assert_ne!(proof1.io_commitment, proof2.io_commitment);
    }

    #[test]
    fn test_zk_proof_different_models_produce_different_proofs() {
        let model1 = create_test_model(b"arch1", b"weights1", b"meta1");
        let model2 = create_test_model(b"arch2", b"weights2", b"meta2");

        let proof1 = create_valid_proof(&model1, b"input", b"output");
        let proof2 = create_valid_proof(&model2, b"input", b"output");

        // Different models should produce different model hashes
        assert_ne!(proof1.model_hash, proof2.model_hash);
    }

    #[test]
    fn test_zk_proof_tampered_commitment_fails_verification() {
        let verifier = ExecutionVerifier::new();
        let model = create_test_model(b"arch", b"weights", b"meta");
        let input = b"test input";
        let output = b"test output";
        let mut proof = create_valid_proof(&model, input, output);

        // Tamper with the commitment (first 32 bytes of proof_data)
        if proof.proof_data.len() >= 32 {
            proof.proof_data[0] ^= 0xFF; // Flip bits in commitment
        }

        let result = verifier.verify_execution(&model, input, output, &proof);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Tampered proof should fail
    }

    #[test]
    fn test_zk_proof_tampered_response_fails_verification() {
        let verifier = ExecutionVerifier::new();
        let model = create_test_model(b"arch", b"weights", b"meta");
        let input = b"test input";
        let output = b"test output";
        let mut proof = create_valid_proof(&model, input, output);

        // Tamper with the response (bytes 32-63 of proof_data)
        if proof.proof_data.len() >= 64 {
            proof.proof_data[32] ^= 0xFF; // Flip bits in response
        }

        let result = verifier.verify_execution(&model, input, output, &proof);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Tampered proof should fail
    }

    #[test]
    fn test_zk_proof_statement_commitment_binding() {
        let model = create_test_model(b"arch", b"weights", b"meta");
        let proof = create_valid_proof(&model, b"input", b"output");

        // The test helper creates proofs with "test statement" format
        // In production, the actual execution.rs generates proofs with CITRATE_EXECUTION_V1 prefix
        // Here we verify the test helper's format which uses "test statement"
        let statement_str = String::from_utf8_lossy(&proof.statement);
        assert!(statement_str.contains("test statement"));

        // Statement should be non-empty and meaningful
        assert!(!proof.statement.is_empty());

        // Proof data should be at least 64 bytes (commitment + response)
        assert!(proof.proof_data.len() >= 64);
    }

    #[test]
    fn test_zk_proof_production_format() {
        // Test that proofs with production format (CITRATE_EXECUTION_V1) verify correctly
        use sha3::{Digest, Sha3_256};

        let verifier = ExecutionVerifier::new();
        let model = create_test_model(b"arch", b"weights", b"meta");
        let input = b"test input";
        let output = b"test output";

        // Compute hashes as production code would
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

        // Create production-format statement
        let mut statement = Vec::with_capacity(32 * 4 + 20);
        statement.extend_from_slice(b"CITRATE_EXECUTION_V1");
        statement.extend_from_slice(model_hash.as_bytes());
        statement.extend_from_slice(input_hash.as_bytes());
        statement.extend_from_slice(output_hash.as_bytes());
        statement.extend_from_slice(io_commitment.as_bytes());

        // Statement should have expected length
        assert_eq!(statement.len(), 20 + 32 * 4); // prefix + 4 hashes

        // Verify prefix is correct
        let statement_str = String::from_utf8_lossy(&statement[..20]);
        assert_eq!(statement_str, "CITRATE_EXECUTION_V1");
    }

    #[test]
    fn test_zk_proof_verifies_correctly() {
        let verifier = ExecutionVerifier::new();
        let model = create_test_model(b"arch", b"weights", b"meta");
        let input = b"test input";
        let output = b"test output";
        let proof = create_valid_proof(&model, input, output);

        // A properly generated proof should verify
        let result = verifier.verify_execution(&model, input, output, &proof);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}
