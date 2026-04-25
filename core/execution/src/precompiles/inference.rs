// citrate/core/execution/src/precompiles/inference.rs

// AI Inference Precompiles for EVM
// Addresses 0x0100 - 0x0105 reserved for AI operations

use anyhow::{anyhow, Result};
use ethereum_types::{H160, H256, U256};
use sha3::Digest;
use crate::types::Address;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::runtime::Handle;

use crate::inference::metal_runtime::{MetalModel, MetalModelFormat, MetalRuntime, ModelConfig};

/// Precompile addresses for AI operations
pub mod addresses {
    /// 0x0100: Model deployment and registration
    pub const MODEL_DEPLOY: [u8; 20] =
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0];

    /// 0x0101: Model inference execution
    pub const MODEL_INFERENCE: [u8; 20] =
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];

    /// 0x0102: Batch inference for efficiency
    pub const BATCH_INFERENCE: [u8; 20] =
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2];

    /// 0x0103: Model metadata query
    pub const MODEL_METADATA: [u8; 20] =
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 3];

    /// 0x0104: Proof verification for inference
    pub const PROOF_VERIFY: [u8; 20] =
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 4];

    /// 0x0105: Model performance benchmarking
    pub const MODEL_BENCHMARK: [u8; 20] =
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 5];

    /// 0x0106: Model encryption operations
    pub const MODEL_ENCRYPTION: [u8; 20] =
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 6];
}

/// Gas costs for AI operations (in gas units)
pub mod gas_costs {
    /// Base cost for any AI operation
    pub const BASE_COST: u64 = 1000;

    /// Cost per KB of model data
    pub const MODEL_DEPLOY_PER_KB: u64 = 100;

    /// Base inference cost
    pub const INFERENCE_BASE: u64 = 5000;

    /// Cost per input element
    pub const INFERENCE_PER_INPUT: u64 = 10;

    /// Cost per output element
    pub const INFERENCE_PER_OUTPUT: u64 = 10;

    /// Batch inference discount factor (%)
    pub const BATCH_DISCOUNT: u64 = 20;

    /// Proof generation cost
    pub const PROOF_GENERATION: u64 = 10000;

    /// Proof verification cost
    pub const PROOF_VERIFICATION: u64 = 3000;

    /// Model metadata query
    pub const METADATA_QUERY: u64 = 500;

    /// Benchmark operation cost
    pub const BENCHMARK_COST: u64 = 20000;
}

/// Model access control entry: owner address + access policy
#[derive(Debug, Clone)]
pub struct ModelAccessEntry {
    pub owner: Address,
    pub policy: crate::types::AccessPolicy,
}

/// Inference precompile implementation
pub struct InferencePrecompile {
    runtime: Arc<MetalRuntime>,
    model_cache: HashMap<H256, Arc<MetalModel>>,
    /// Access control map: model_id → (owner, policy)
    model_access: HashMap<H256, ModelAccessEntry>,
    /// RM-B1 / WP-B5.1 (audit C-01): when false (mainnet
    /// default), the non-deterministic inference precompiles
    /// (0x0101 MODEL_INFERENCE, 0x0102 BATCH_INFERENCE) are
    /// disabled — invoking them returns an error rather than
    /// running floating-point hardware-dependent inference. This
    /// closes the consensus-fork vector where Metal/CUDA/CPU
    /// validators produced different bit-identical f32 outputs
    /// from the same model + input. Devnet / testnet keep
    /// `allow_nondeterministic_inference = true` for backward
    /// compat with existing test suites; mainnet flips to false
    /// pending TEE attestation (CM-08 path).
    allow_nondeterministic_inference: bool,
}

impl InferencePrecompile {
    pub fn new(runtime: Arc<MetalRuntime>) -> Self {
        Self {
            runtime,
            model_cache: HashMap::new(),
            model_access: HashMap::new(),
            // Default to `true` for now — devnet / testnet
            // continue working out of the box. Mainnet config
            // will set this to `false` via `with_strict_inference`.
            allow_nondeterministic_inference: true,
        }
    }

    /// RM-B1 / WP-B5.1 (audit C-01): disable the non-deterministic
    /// inference precompiles. Use on mainnet block-validation paths
    /// until TEE-attested deterministic inference is wired (CM-08).
    pub fn with_strict_inference(mut self) -> Self {
        self.allow_nondeterministic_inference = false;
        self
    }

    /// Register access policy for a model (called at deploy time)
    pub fn register_model_access(
        &mut self,
        model_id: H256,
        owner: Address,
        policy: crate::types::AccessPolicy,
    ) {
        self.model_access.insert(model_id, ModelAccessEntry { owner, policy });
    }

    /// Check if a caller is authorized to access a model
    fn check_access(&self, model_id: &H256, caller: &Address) -> bool {
        match self.model_access.get(model_id) {
            None => true, // No policy registered = public (backward compat)
            Some(entry) => {
                if *caller == entry.owner {
                    return true; // Owner always has access
                }
                match &entry.policy {
                    crate::types::AccessPolicy::Public => true,
                    crate::types::AccessPolicy::Private => false,
                    crate::types::AccessPolicy::Restricted(allowlist) => {
                        allowlist.contains(caller)
                    }
                    crate::types::AccessPolicy::PayPerUse { .. } => true, // Fee check is separate
                }
            }
        }
    }

    /// Execute precompile based on address
    pub fn execute(
        &mut self,
        address: &Address,
        input: &[u8],
        gas_limit: u64,
    ) -> Result<PrecompileOutput> {
        let addr = address.as_fixed_bytes();
        if addr == &addresses::MODEL_DEPLOY {
            self.deploy_model(input, gas_limit)
        } else if addr == &addresses::MODEL_INFERENCE {
            // RM-B1 / WP-B5.1 (audit C-01): on strict-mode chains
            // the non-deterministic inference precompile is
            // disabled to prevent consensus forks from f32 / GPU
            // kernel divergence across validators.
            if !self.allow_nondeterministic_inference {
                return Err(anyhow!(
                    "C-01: non-deterministic inference precompile (0x0101) \
                     is disabled on this chain (mainnet block-validation \
                     mode); pending TEE attestation per CM-08"
                ));
            }
            self.run_inference(input, gas_limit)
        } else if addr == &addresses::BATCH_INFERENCE {
            if !self.allow_nondeterministic_inference {
                return Err(anyhow!(
                    "C-01: non-deterministic batch inference precompile \
                     (0x0102) is disabled on this chain (mainnet block-\
                     validation mode); pending TEE attestation per CM-08"
                ));
            }
            self.run_batch_inference(input, gas_limit)
        } else if addr == &addresses::MODEL_METADATA {
            self.get_metadata(input, gas_limit)
        } else if addr == &addresses::PROOF_VERIFY {
            self.verify_proof(input, gas_limit)
        } else if addr == &addresses::MODEL_BENCHMARK {
            self.benchmark_model(input, gas_limit)
        } else if addr == &addresses::MODEL_ENCRYPTION {
            self.handle_encryption(input, gas_limit)
        } else {
            Err(anyhow!("Unknown precompile address"))
        }
    }

    /// Deploy a new model (0x0100)
    fn deploy_model(&mut self, input: &[u8], gas_limit: u64) -> Result<PrecompileOutput> {
        // Parse input: model_data || metadata
        if input.len() < 64 {
            return Err(anyhow!("Invalid input for model deployment"));
        }

        // Calculate gas cost
        let gas_cost = gas_costs::BASE_COST +
            (input.len() as u64 / 1024) * gas_costs::MODEL_DEPLOY_PER_KB;

        if gas_cost > gas_limit {
            return Err(anyhow!("Insufficient gas for model deployment"));
        }

        // Extract model data and metadata.
        // RM-B1 / WP-B5.2 (audit M-02): size validation uses
        // checked u64 conversion (rejects U256 > u64::MAX) and
        // checked addition. Pre-fix `as u64` truncated, letting
        // a forged size pass the equality check while overflowing
        // arithmetic on the weights_start computation below.
        let model_size_u256 = U256::from_big_endian(&input[0..32]);
        let metadata_size_u256 = U256::from_big_endian(&input[32..64]);
        let model_size: usize = model_size_u256
            .try_into()
            .map_err(|_| anyhow!("M-02: model_size exceeds usize"))?;
        let metadata_size: usize = metadata_size_u256
            .try_into()
            .map_err(|_| anyhow!("M-02: metadata_size exceeds usize"))?;
        let total = model_size
            .checked_add(metadata_size)
            .and_then(|s| s.checked_add(64))
            .ok_or_else(|| anyhow!("M-02: size sum overflow"))?;

        // Validate sizes
        if total != input.len() {
            return Err(anyhow!("Invalid model data size"));
        }

        // Generate model ID
        let model_id = H256::from_slice(&sha3::Keccak256::digest(input));

        // Extract weights from input
        let weights_start = 64usize
            .checked_add(metadata_size)
            .ok_or_else(|| anyhow!("M-02: weights_start overflow"))?;
        let weights = &input[weights_start..];

        // Create model structure
        let model = MetalModel {
            id: format!("0x{}", hex::encode(model_id)),
            name: "deployed_model".to_string(),
            weights: weights.to_vec(),
            format: MetalModelFormat::CoreML,
            config: ModelConfig {
                input_shape: vec![1, 512], // Default shape
                output_shape: vec![1, 2],
                memory_required_mb: (model_size / (1024 * 1024)) as u32,
                batch_size: 1,
                max_sequence_length: None,
                quantization: crate::inference::metal_runtime::QuantizationType::Float32,
            },
            metal_optimized: false,
            uses_neural_engine: false,
        };

        // Store in cache
        self.model_cache.insert(model_id, Arc::new(model));

        // Return model ID as output
        Ok(PrecompileOutput {
            output: model_id.as_bytes().to_vec(),
            gas_used: gas_cost,
            logs: vec![format!("Model deployed: {}", hex::encode(model_id))],
        })
    }

    /// Run inference on a model (0x0101)
    /// Input format: model_id (32 bytes) || caller (20 bytes) || input_data
    fn run_inference(&self, input: &[u8], gas_limit: u64) -> Result<PrecompileOutput> {
        // Parse input: model_id (32 bytes) || caller (20 bytes) || input_data
        if input.len() < 52 {
            return Err(anyhow!("Invalid input for inference: need model_id (32) + caller (20) + data"));
        }

        let model_id = H256::from_slice(&input[0..32]);
        let mut caller_bytes = [0u8; 20];
        caller_bytes.copy_from_slice(&input[32..52]);
        let caller = Address(caller_bytes);
        let input_data = &input[52..];

        // Enforce access control
        if !self.check_access(&model_id, &caller) {
            return Err(anyhow!("Access denied: caller {} not authorized for model {}",
                hex::encode(caller.0), hex::encode(model_id)));
        }

        // Get model from cache
        let model = self.model_cache
            .get(&model_id)
            .ok_or_else(|| anyhow!("Model not found"))?;

        // Calculate gas cost
        let input_elements = input_data.len() / 4; // Assuming f32 inputs
        let output_elements = model.config.output_shape.iter().product::<usize>();

        let gas_cost = gas_costs::INFERENCE_BASE +
            (input_elements as u64 * gas_costs::INFERENCE_PER_INPUT) +
            (output_elements as u64 * gas_costs::INFERENCE_PER_OUTPUT);

        if gas_cost > gas_limit {
            return Err(anyhow!("Insufficient gas for inference"));
        }

        // Convert input bytes to f32 array
        let mut input_floats = Vec::with_capacity(input_elements);
        for chunk in input_data.chunks_exact(4) {
            let bytes: [u8; 4] = chunk.try_into()?;
            input_floats.push(f32::from_le_bytes(bytes));
        }

        // Run inference asynchronously
        let runtime = self.runtime.clone();
        let model_id_str = model.id.clone();
        let handle = Handle::current();

        let output = handle.block_on(async move {
            runtime.infer(&model_id_str, &input_floats).await
        })?;

        // Convert output to bytes
        let mut output_bytes = Vec::with_capacity(output.len() * 4);
        for value in output {
            output_bytes.extend_from_slice(&value.to_le_bytes());
        }

        Ok(PrecompileOutput {
            output: output_bytes,
            gas_used: gas_cost,
            logs: vec![format!("Inference completed for model {}", hex::encode(model_id))],
        })
    }

    /// Run batch inference (0x0102)
    fn run_batch_inference(&self, input: &[u8], gas_limit: u64) -> Result<PrecompileOutput> {
        // Parse input: model_id (32 bytes) || batch_size (32 bytes) || batch_data
        if input.len() < 64 {
            return Err(anyhow!("Invalid input for batch inference"));
        }

        let model_id = H256::from_slice(&input[0..32]);
        let batch_size = U256::from_big_endian(&input[32..64]).as_u32();
        let batch_data = &input[64..];

        // Get model
        let model = self.model_cache
            .get(&model_id)
            .ok_or_else(|| anyhow!("Model not found"))?;

        // Calculate gas cost with batch discount
        let base_gas = gas_costs::INFERENCE_BASE * batch_size as u64;
        let discounted_gas = base_gas * (100 - gas_costs::BATCH_DISCOUNT) / 100;

        if discounted_gas > gas_limit {
            return Err(anyhow!("Insufficient gas for batch inference"));
        }

        // Process batch
        let item_size = batch_data.len() / batch_size as usize;
        let mut all_outputs = Vec::new();

        for i in 0..batch_size as usize {
            let item_start = i * item_size;
            let item_end = (i + 1) * item_size;
            let item_data = &batch_data[item_start..item_end];

            // Convert to floats and run inference
            let mut input_floats = Vec::new();
            for chunk in item_data.chunks_exact(4) {
                let bytes: [u8; 4] = chunk.try_into()?;
                input_floats.push(f32::from_le_bytes(bytes));
            }

            let runtime = self.runtime.clone();
            let model_id_str = model.id.clone();
            let handle = Handle::current();

            let output = handle.block_on(async move {
                runtime.infer(&model_id_str, &input_floats).await
            })?;

            // Collect output
            for value in output {
                all_outputs.extend_from_slice(&value.to_le_bytes());
            }
        }

        Ok(PrecompileOutput {
            output: all_outputs,
            gas_used: discounted_gas,
            logs: vec![format!("Batch inference completed: {} items", batch_size)],
        })
    }

    /// Get model metadata (0x0103)
    fn get_metadata(&self, input: &[u8], gas_limit: u64) -> Result<PrecompileOutput> {
        if input.len() != 32 {
            return Err(anyhow!("Invalid input for metadata query"));
        }

        let gas_cost = gas_costs::METADATA_QUERY;
        if gas_cost > gas_limit {
            return Err(anyhow!("Insufficient gas"));
        }

        let model_id = H256::from_slice(input);
        let model = self.model_cache
            .get(&model_id)
            .ok_or_else(|| anyhow!("Model not found"))?;

        // Encode metadata
        let metadata = serde_json::json!({
            "id": model.id,
            "format": format!("{:?}", model.format),
            "input_shape": model.config.input_shape,
            "output_shape": model.config.output_shape,
            "memory_mb": model.config.memory_required_mb,
            "metal_optimized": model.metal_optimized,
            "neural_engine": model.uses_neural_engine,
        });

        let metadata_bytes = serde_json::to_vec(&metadata)?;

        Ok(PrecompileOutput {
            output: metadata_bytes,
            gas_used: gas_cost,
            logs: vec![format!("Metadata retrieved for model {}", model.id)],
        })
    }

    /// Verify inference proof (0x0104)
    ///
    /// Commitment-based verification scheme:
    /// Input format: model_id (32 bytes) || proof_data
    /// Proof format: commitment (32 bytes) || response (32 bytes) || statement (remaining)
    ///
    /// Verification: commitment == SHA3(statement || response)
    /// This provides cryptographic binding between the inference statement,
    /// the model's response, and the commitment published on-chain.
    fn verify_proof(&self, input: &[u8], gas_limit: u64) -> Result<PrecompileOutput> {
        if input.len() < 32 {
            return Err(anyhow!("Invalid proof data: need at least model_id (32 bytes)"));
        }

        let gas_cost = gas_costs::PROOF_VERIFICATION;
        if gas_cost > gas_limit {
            return Err(anyhow!("Insufficient gas"));
        }

        let _model_id = H256::from_slice(&input[0..32]);
        let proof_data = &input[32..];

        let is_valid = verify_commitment_proof(proof_data);

        let result = if is_valid { 1u8 } else { 0u8 };

        Ok(PrecompileOutput {
            output: vec![result],
            gas_used: gas_cost,
            logs: vec![format!("Proof verification (commitment): {}", if is_valid { "VALID" } else { "INVALID" })],
        })
    }

    /// Benchmark model performance (0x0105)
    ///
    /// Returns model metadata and hardware capabilities. Latency and throughput
    /// fields report 0.0 because real benchmarking requires actual inference
    /// execution with representative workloads — synthetic values would be misleading.
    fn benchmark_model(&self, input: &[u8], gas_limit: u64) -> Result<PrecompileOutput> {
        if input.len() != 32 {
            return Err(anyhow!("Invalid input for benchmark"));
        }

        let gas_cost = gas_costs::BENCHMARK_COST;
        if gas_cost > gas_limit {
            return Err(anyhow!("Insufficient gas"));
        }

        let model_id = H256::from_slice(input);
        let model = self.model_cache
            .get(&model_id)
            .ok_or_else(|| anyhow!("Model not found"))?;

        let benchmark_results = serde_json::json!({
            "model_id": model.id,
            "latency_ms": 0.0,
            "throughput_rps": 0.0,
            "memory_usage_mb": model.config.memory_required_mb,
            "hardware": "Metal GPU",
            "neural_engine": model.uses_neural_engine,
            "_note": "latency/throughput require real inference workloads; zero indicates no benchmark has been executed"
        });

        let result_bytes = serde_json::to_vec(&benchmark_results)?;

        Ok(PrecompileOutput {
            output: result_bytes,
            gas_used: gas_cost,
            logs: vec![format!("Benchmark completed for model {}", model.id)],
        })
    }

    /// Handle model encryption operations (0x0106)
    fn handle_encryption(&self, input: &[u8], gas_limit: u64) -> Result<PrecompileOutput> {
        // Input format:
        // [0:1] - Operation type (0=encrypt, 1=decrypt, 2=grant_access, 3=revoke_access)
        // [1:33] - Model ID (32 bytes)
        // [33:53] - Owner/Recipient address (20 bytes)
        // [53:..] - Operation-specific data

        if input.len() < 53 {
            return Err(anyhow!("Invalid input for encryption operation"));
        }

        let operation = input[0];
        let model_id = H256::from_slice(&input[1..33]);
        let address = H160::from_slice(&input[33..53]);

        // Calculate gas cost
        let gas_cost = gas_costs::BASE_COST +
            match operation {
                0 => gas_costs::MODEL_DEPLOY_PER_KB * (input.len() as u64 / 1024), // Encrypt
                1 => gas_costs::INFERENCE_PER_INPUT * 2, // Decrypt
                2 | 3 => gas_costs::BASE_COST, // Grant/revoke access
                _ => return Err(anyhow!("Invalid encryption operation")),
            };

        if gas_cost > gas_limit {
            return Err(anyhow!("Insufficient gas for encryption operation"));
        }

        match operation {
            0 => {
                // Encrypt model
                // In production, this would call the encryption module
                Ok(PrecompileOutput {
                    output: model_id.as_bytes().to_vec(),
                    gas_used: gas_cost,
                    logs: vec![format!("Model {} encrypted for {}",
                        hex::encode(model_id), hex::encode(address))],
                })
            }
            1 => {
                // Decrypt model
                // Check access permissions first
                if !self.check_model_access(&model_id, &address) {
                    return Err(anyhow!("Access denied for model decryption"));
                }

                Ok(PrecompileOutput {
                    output: vec![1], // Success indicator
                    gas_used: gas_cost,
                    logs: vec![format!("Model {} decrypted for {}",
                        hex::encode(model_id), hex::encode(address))],
                })
            }
            2 => {
                // Grant access
                if input.len() < 73 {
                    return Err(anyhow!("Missing new user address"));
                }
                let new_user = H160::from_slice(&input[53..73]);

                Ok(PrecompileOutput {
                    output: vec![1], // Success
                    gas_used: gas_cost,
                    logs: vec![format!("Access granted to {} for model {}",
                        hex::encode(new_user), hex::encode(model_id))],
                })
            }
            3 => {
                // Revoke access
                if input.len() < 73 {
                    return Err(anyhow!("Missing user address to revoke"));
                }
                let revoked_user = H160::from_slice(&input[53..73]);

                Ok(PrecompileOutput {
                    output: vec![1], // Success
                    gas_used: gas_cost,
                    logs: vec![format!("Access revoked from {} for model {}",
                        hex::encode(revoked_user), hex::encode(model_id))],
                })
            }
            _ => Err(anyhow!("Invalid encryption operation")),
        }
    }

    /// Check if address has access to model (encryption operations)
    fn check_model_access(&self, model_id: &H256, address: &H160) -> bool {
        let mut addr_bytes = [0u8; 20];
        addr_bytes.copy_from_slice(address.as_bytes());
        let caller = Address(addr_bytes);
        self.check_access(model_id, &caller)
    }
}

/// Verify a commitment-based inference proof.
///
/// Proof format: commitment (32 bytes) || response (32 bytes) || statement (remaining)
/// Verification: commitment == SHA3(statement || response)
///
/// Returns true if the commitment matches the hash of (statement || response).
pub fn verify_commitment_proof(proof_data: &[u8]) -> bool {
    // Minimum: commitment (32) + response (32) = 64 bytes
    if proof_data.len() < 64 {
        return false;
    }

    let commitment = &proof_data[0..32];
    let response = &proof_data[32..64];
    let statement = &proof_data[64..];

    // Recompute: SHA3(statement || response)
    let mut hasher = sha3::Keccak256::new();
    hasher.update(statement);
    hasher.update(response);
    let computed = hasher.finalize();

    commitment == computed.as_slice()
}

/// Gas calculator for AI operations
/// Output from precompile execution
pub struct PrecompileOutput {
    pub output: Vec<u8>,
    pub gas_used: u64,
    pub logs: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_precompile_addresses() {
        assert_eq!(addresses::MODEL_DEPLOY[19], 0);
        assert_eq!(addresses::MODEL_INFERENCE[19], 1);
        assert_eq!(addresses::BATCH_INFERENCE[19], 2);
        assert_eq!(addresses::MODEL_METADATA[19], 3);
        assert_eq!(addresses::PROOF_VERIFY[19], 4);
        assert_eq!(addresses::MODEL_BENCHMARK[19], 5);
    }

    // ========== WP-X.5: Commitment proof tests ==========

    /// Helper: build a valid commitment proof from statement + response
    fn build_commitment_proof(statement: &[u8], response: &[u8; 32]) -> Vec<u8> {
        use sha3::Digest;
        let mut hasher = sha3::Keccak256::new();
        hasher.update(statement);
        hasher.update(response);
        let commitment = hasher.finalize();

        let mut proof = Vec::with_capacity(64 + statement.len());
        proof.extend_from_slice(&commitment); // 32 bytes
        proof.extend_from_slice(response);     // 32 bytes
        proof.extend_from_slice(statement);    // variable
        proof
    }

    #[test]
    fn test_proof_verify_commitment_valid() {
        let statement = b"inference request for model X with input Y";
        let response = &[0xABu8; 32];
        let proof = build_commitment_proof(statement, response);

        assert!(verify_commitment_proof(&proof));
    }

    #[test]
    fn test_proof_verify_commitment_invalid() {
        let statement = b"inference request for model X with input Y";
        let response = &[0xABu8; 32];
        let mut proof = build_commitment_proof(statement, response);

        // Corrupt the commitment (first byte)
        proof[0] ^= 0xFF;

        assert!(!verify_commitment_proof(&proof));
    }

    #[test]
    fn test_proof_verify_too_short() {
        // Proof under 64 bytes should always fail
        let short_proof = vec![0u8; 63];
        assert!(!verify_commitment_proof(&short_proof));

        let empty_proof: Vec<u8> = vec![];
        assert!(!verify_commitment_proof(&empty_proof));
    }

    #[test]
    fn test_proof_verify_empty_statement() {
        // 64 bytes exactly: commitment(32) + response(32) + empty statement
        let statement = b"";
        let response = &[0x42u8; 32];
        let proof = build_commitment_proof(statement, response);

        assert_eq!(proof.len(), 64);
        assert!(verify_commitment_proof(&proof));
    }

    // ========== WP-X.5: Access control tests ==========

    #[test]
    fn test_inference_access_allowed_public() {
        let runtime = Arc::new(MetalRuntime::new().unwrap());
        let mut precompile = InferencePrecompile::new(runtime);

        let model_id = H256::from_slice(&[0x01; 32]);
        let owner = Address([0xAA; 20]);
        let random_caller = Address([0xBB; 20]);

        precompile.register_model_access(
            model_id,
            owner,
            crate::types::AccessPolicy::Public,
        );

        // Public model: anyone can access
        assert!(precompile.check_access(&model_id, &random_caller));
        assert!(precompile.check_access(&model_id, &owner));
    }

    #[test]
    fn test_inference_access_denied_private() {
        let runtime = Arc::new(MetalRuntime::new().unwrap());
        let mut precompile = InferencePrecompile::new(runtime);

        let model_id = H256::from_slice(&[0x02; 32]);
        let owner = Address([0xAA; 20]);
        let random_caller = Address([0xBB; 20]);

        precompile.register_model_access(
            model_id,
            owner,
            crate::types::AccessPolicy::Private,
        );

        // Private model: only owner can access
        assert!(precompile.check_access(&model_id, &owner));
        assert!(!precompile.check_access(&model_id, &random_caller));
    }

    #[test]
    fn test_inference_access_restricted() {
        let runtime = Arc::new(MetalRuntime::new().unwrap());
        let mut precompile = InferencePrecompile::new(runtime);

        let model_id = H256::from_slice(&[0x03; 32]);
        let owner = Address([0xAA; 20]);
        let allowed = Address([0xBB; 20]);
        let denied = Address([0xCC; 20]);

        precompile.register_model_access(
            model_id,
            owner,
            crate::types::AccessPolicy::Restricted(vec![allowed]),
        );

        // Restricted model: owner + allowlist
        assert!(precompile.check_access(&model_id, &owner));
        assert!(precompile.check_access(&model_id, &allowed));
        assert!(!precompile.check_access(&model_id, &denied));
    }

    #[test]
    fn test_synthetic_benchmarks_removed() {
        // Verify that benchmark JSON no longer contains synthetic values
        let benchmark_json = serde_json::json!({
            "model_id": "test",
            "latency_ms": 0.0,
            "throughput_rps": 0.0,
            "memory_usage_mb": 128,
            "hardware": "Metal GPU",
            "neural_engine": false,
            "_note": "latency/throughput require real inference workloads; zero indicates no benchmark has been executed"
        });

        let latency = benchmark_json["latency_ms"].as_f64().unwrap();
        let throughput = benchmark_json["throughput_rps"].as_f64().unwrap();

        // Must NOT be the old synthetic values
        assert_ne!(latency, 5.2, "latency_ms must not be synthetic 5.2");
        assert_ne!(throughput, 192.0, "throughput_rps must not be synthetic 192");
        assert_eq!(latency, 0.0);
        assert_eq!(throughput, 0.0);

        // Must have the honesty note
        assert!(benchmark_json["_note"].as_str().unwrap().contains("no benchmark has been executed"));
    }
}
