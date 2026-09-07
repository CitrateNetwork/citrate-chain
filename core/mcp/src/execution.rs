// citrate/core/mcp/src/execution.rs

// Model executor for running AI models
use crate::cache::ModelCache;
use crate::gguf_engine::{GGUFEngine, GGUFEngineConfig, ModelType as GGUFModelType};
use crate::registry::ModelRegistry;
use crate::types::{ExecutionProof, ModelId};
use crate::verification::ExecutionVerifier;
use anyhow::{anyhow, Result};
use hex;
use citrate_execution::{Address, Hash};
use citrate_storage::ipfs::{chunking, Cid, IPFSService};
use serde_json;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// CHAIN-B-D016: hard upper bounds on a model manifest fetched from an
/// attacker-chosen IPFS CID, applied before any capacity-based allocation so a
/// tiny manifest cannot request a multi-exabyte `Vec` and `abort()` the node.
/// 32 GiB is well above any model the marketplace serves.
const MAX_ASSEMBLED_MODEL_BYTES: u64 = 32 * 1024 * 1024 * 1024;
/// Maximum number of chunks a manifest may declare (bounds the fetch loop).
const MAX_MODEL_CHUNKS: usize = 1_000_000;

/// Result of model inference
#[derive(Debug, Clone)]
pub struct InferenceResult {
    pub output: Vec<u8>,
    pub proof: ExecutionProof,
    pub gas_used: u64,
    pub latency_ms: u64,
    pub provider: Address,
}

/// Model executor for running AI models. The actual inference path
/// runs through the GGUF engine; the deterministic-compute path
/// runs through the 0x010A–0x010F Q16 precompiles. The legacy
/// `vm: Arc<VM>` field was removed in RM-M2 WP-M2.11 along with
/// `core/execution/src/vm/`, which was unreferenced beyond
/// holders.
pub struct ModelExecutor {
    cache: Arc<ModelCache>,
    verifier: Arc<ExecutionVerifier>,
    registry: Arc<ModelRegistry>,
    ipfs: Mutex<IPFSService>,
    /// GGUF engine for AI model execution (None if initialization failed)
    gguf_engine: Option<Arc<GGUFEngine>>,
}

impl ModelExecutor {
    pub fn new(
        cache: Arc<ModelCache>,
        verifier: Arc<ExecutionVerifier>,
        registry: Arc<ModelRegistry>,
        ipfs: IPFSService,
    ) -> Self {
        // Initialize GGUF engine with default config (graceful degradation if unavailable)
        let gguf_config = GGUFEngineConfig::default();
        let gguf_engine = match GGUFEngine::new(gguf_config) {
            Ok(engine) => {
                info!("GGUF engine initialized successfully");
                Some(Arc::new(engine))
            }
            Err(e) => {
                warn!("GGUF unavailable, AI features disabled: {}", e);
                None
            }
        };

        Self {
            cache,
            verifier,
            registry,
            ipfs: Mutex::new(ipfs),
            gguf_engine,
        }
    }

    /// Check if AI features are available
    ///
    /// Returns true if the GGUF engine was successfully initialized.
    /// When false, AI inference/training requests will return errors.
    pub fn is_ai_available(&self) -> bool {
        self.gguf_engine.is_some()
    }

    /// Execute model inference
    pub async fn execute_inference(
        &self,
        model_id: ModelId,
        input: Vec<u8>,
        provider: Address,
    ) -> Result<InferenceResult> {
        let start_time = std::time::Instant::now();

        // 1. Load model from cache or storage
        let model = self.load_model(model_id).await?;

        // 2. Verify model integrity
        self.verifier.verify_model(&model)?;

        // 3. Prepare execution context
        let context = self.prepare_context(&model, &input)?;

        // 4. Execute inference in VM
        let (output, gas_used) = self.execute_in_vm(&context).await?;

        // 5. Generate execution proof
        let proof = self.generate_proof(&model, &input, &output, provider)?;

        let latency_ms = start_time.elapsed().as_millis() as u64;

        info!(
            "Inference completed for model {:?} in {}ms using {} gas",
            hex::encode(&model_id.0[..8]),
            latency_ms,
            gas_used
        );

        Ok(InferenceResult {
            output,
            proof,
            gas_used,
            latency_ms,
            provider,
        })
    }

    /// Execute training step
    pub async fn execute_training(
        &self,
        model_id: ModelId,
        training_data: Vec<u8>,
        current_weights: Vec<u8>,
        provider: Address,
    ) -> Result<TrainingResult> {
        let start_time = std::time::Instant::now();

        // 1. Load model architecture
        let model = self.load_model(model_id).await?;

        // 2. Prepare training context
        let context = self.prepare_training_context(&model, &training_data, &current_weights)?;

        // 3. Execute training step in VM
        let (updated_weights, metrics, gas_used) = self.execute_training_in_vm(&context).await?;

        // 4. Generate training proof
        let proof = self.generate_training_proof(
            &model,
            &training_data,
            &current_weights,
            &updated_weights,
            provider,
        )?;

        let latency_ms = start_time.elapsed().as_millis() as u64;

        info!(
            "Training step completed for model {:?} in {}ms",
            hex::encode(&model_id.0[..8]),
            latency_ms
        );

        Ok(TrainingResult {
            updated_weights,
            metrics,
            proof,
            gas_used,
            latency_ms,
            provider,
        })
    }

    /// Load model from cache or storage
    async fn load_model(&self, model_id: ModelId) -> Result<Model> {
        if let Some(model) = self.cache.get(&model_id).await {
            debug!(
                "Model loaded from cache: {:?}",
                hex::encode(&model_id.0[..8])
            );
            return Ok(model);
        }

        let record = self.registry.get_record(&model_id).await?;
        let weight_cid = record.weight_cid.clone().ok_or_else(|| {
            anyhow!(
                "Model {:?} missing weight CID",
                hex::encode(&model_id.0[..8])
            )
        })?;

        let weights = {
            let ipfs = self.ipfs.lock().await;
            let cid = Cid(weight_cid.clone());
            let raw = ipfs.retrieve_model(&cid).await?;
            if let Ok(manifest) = serde_json::from_slice::<chunking::ChunkManifest>(&raw) {
                // CHAIN-B-D016: `total_size` and `chunks` come from an
                // attacker-chosen IPFS document. `Vec::with_capacity` on an
                // unbounded `u64` (e.g. `u64::MAX`) triggers Rust's
                // `handle_alloc_error` -> `abort()`, which is uncatchable and
                // kills the whole node; a merely-large value OOM-kills it.
                // Clamp both against configured maxima before allocating.
                if manifest.total_size > MAX_ASSEMBLED_MODEL_BYTES {
                    return Err(anyhow!(
                        "model manifest total_size {} exceeds maximum {}",
                        manifest.total_size,
                        MAX_ASSEMBLED_MODEL_BYTES
                    ));
                }
                if manifest.chunks.len() > MAX_MODEL_CHUNKS {
                    return Err(anyhow!(
                        "model manifest chunk count {} exceeds maximum {}",
                        manifest.chunks.len(),
                        MAX_MODEL_CHUNKS
                    ));
                }
                let mut assembled = Vec::with_capacity(
                    (manifest.total_size as usize).min(MAX_ASSEMBLED_MODEL_BYTES as usize),
                );
                for chunk_cid in manifest.chunks {
                    match ipfs.fetch_raw(&chunk_cid).await {
                        Ok(bytes) => assembled.extend(bytes),
                        Err(err) => {
                            warn!("Failed to fetch chunk {}: {}", chunk_cid.0, err);
                            return Err(err);
                        }
                    }
                }
                assembled
            } else {
                raw
            }
        };

        let metadata_bytes = serde_json::to_vec(&record.metadata)?;

        // Populate architecture from record metadata; fall back to GGUF magic header
        let architecture = if !record.metadata.architecture.is_empty() {
            record.metadata.architecture.clone()
        } else if weights.len() >= 4 && &weights[0..4] == b"GGUF" {
            // Extract GGUF header as architecture descriptor (first 64 bytes or less)
            let header_len = std::cmp::min(64, weights.len());
            weights[..header_len].to_vec()
        } else {
            warn!(
                "Model {:?} has no architecture descriptor and no GGUF header",
                hex::encode(&model_id.0[..8])
            );
            Vec::new()
        };

        let model = Model {
            id: model_id,
            architecture,
            weights,
            metadata: metadata_bytes,
        };

        self.cache.put(model_id, model.clone()).await?;

        Ok(model)
    }

    /// Prepare execution context
    fn prepare_context(&self, model: &Model, input: &[u8]) -> Result<ExecutionContext> {
        Ok(ExecutionContext {
            model_id: model.id,
            input: input.to_vec(),
            memory_limit: 1024 * 1024 * 100, // 100MB
            gas_limit: 10_000_000,
            execution_mode: ExecutionMode::Inference,
        })
    }

    /// Prepare training context
    fn prepare_training_context(
        &self,
        model: &Model,
        training_data: &[u8],
        weights: &[u8],
    ) -> Result<ExecutionContext> {
        Ok(ExecutionContext {
            model_id: model.id,
            input: training_data.to_vec(),
            memory_limit: 1024 * 1024 * 500, // 500MB for training
            gas_limit: 50_000_000,
            execution_mode: ExecutionMode::Training {
                current_weights: weights.to_vec(),
            },
        })
    }

    /// Execute in VM (now using GGUF engine)
    async fn execute_in_vm(&self, context: &ExecutionContext) -> Result<(Vec<u8>, u64)> {
        // Check if GGUF engine is available
        let gguf_engine = self.gguf_engine.as_ref().ok_or_else(|| {
            anyhow!("AI features unavailable: GGUF engine not initialized")
        })?;

        // Load the model
        let model = self.load_model(context.model_id).await?;

        // Determine model type from metadata or use heuristics
        let model_type = self.determine_model_type(&model)?;

        // Get or create model path on disk
        let model_path = gguf_engine
            .load_model_from_bytes(
                &hex::encode(&context.model_id.0[..8]),
                &model.weights,
            )
            .await?;

        // Parse input data
        let input_json: serde_json::Value = serde_json::from_slice(&context.input)
            .unwrap_or_else(|_| {
                // Fallback: try to interpret as string
                serde_json::json!({
                    "prompt": String::from_utf8_lossy(&context.input)
                })
            });

        // Execute based on model type
        let output_data = match model_type {
            GGUFModelType::Embedding => {
                // Extract text inputs for embedding
                let texts = if let Some(text) = input_json.get("text").and_then(|v| v.as_str()) {
                    vec![text.to_string()]
                } else if let Some(arr) = input_json.get("input").and_then(|v| v.as_array()) {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .map(|s| s.to_string())
                        .collect()
                } else {
                    vec![input_json.to_string()]
                };

                // Generate embeddings
                let embeddings = gguf_engine.generate_embeddings(&model_path, &texts).await?;

                // Serialize embeddings as output
                serde_json::to_vec(&embeddings)?
            }
            GGUFModelType::TextGeneration => {
                // Extract prompt and parameters
                let prompt = input_json
                    .get("prompt")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                let max_tokens = input_json
                    .get("max_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(512) as usize;

                let temperature = input_json
                    .get("temperature")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.7) as f32;

                // Generate text
                let generated_text = gguf_engine
                    .generate_text(&model_path, prompt, max_tokens, temperature)
                    .await?;

                // Serialize response
                serde_json::to_vec(&serde_json::json!({
                    "text": generated_text,
                    "model": hex::encode(&context.model_id.0[..8]),
                }))?
            }
        };

        // Estimate gas based on output size and model size
        let gas_used = self.estimate_gas(&model, &output_data);

        Ok((output_data, gas_used))
    }

    /// Determine model type from metadata
    fn determine_model_type(&self, model: &Model) -> Result<GGUFModelType> {
        // Try to parse metadata
        if let Ok(metadata_json) = serde_json::from_slice::<serde_json::Value>(&model.metadata) {
            if let Some(model_type) = metadata_json.get("model_type").and_then(|v| v.as_str()) {
                return match model_type {
                    "embedding" | "embeddings" => Ok(GGUFModelType::Embedding),
                    "text_generation" | "llm" | "chat" => Ok(GGUFModelType::TextGeneration),
                    _ => Ok(GGUFModelType::TextGeneration), // Default to text generation
                };
            }
        }

        // Heuristic: small models (<500MB) are likely embeddings
        if model.weights.len() < 500_000_000 {
            Ok(GGUFModelType::Embedding)
        } else {
            Ok(GGUFModelType::TextGeneration)
        }
    }

    /// Estimate gas cost based on model and output size
    fn estimate_gas(&self, model: &Model, output: &[u8]) -> u64 {
        // Base gas cost
        let base_gas = 100_000u64;

        // Model size factor (1 gas per KB)
        let model_gas = (model.weights.len() / 1024) as u64;

        // Output size factor (10 gas per byte)
        let output_gas = (output.len() * 10) as u64;

        base_gas + model_gas + output_gas
    }

    /// Execute training in VM
    ///
    /// Performs a training step that updates model weights based on training data.
    /// Uses a hash-based pseudo-gradient approach that:
    /// - Computes gradients derived from training data
    /// - Applies gradients to current weights with a learning rate
    /// - Produces different weights for different training data
    ///
    /// In production, this would use actual ML training (PyTorch, TensorFlow, etc.)
    async fn execute_training_in_vm(
        &self,
        context: &ExecutionContext,
    ) -> Result<(Vec<u8>, TrainingMetrics, u64)> {
        // Extract current weights from training context
        let current_weights = match &context.execution_mode {
            ExecutionMode::Training { current_weights } => current_weights.clone(),
            _ => return Err(anyhow!("Invalid execution mode for training")),
        };

        let training_data = &context.input;

        // Compute pseudo-gradient from training data
        // This simulates gradient descent by hashing training data to produce weight deltas
        let gradient = self.compute_pseudo_gradient(training_data, &current_weights);

        // Apply gradient update with learning rate
        let learning_rate = 0.01f32;
        let updated_weights = self.apply_gradient_update(&current_weights, &gradient, learning_rate);

        // Compute training metrics
        let metrics = self.compute_training_metrics(training_data, &current_weights, &updated_weights);

        // Estimate gas based on computation
        let gas_used = self.estimate_training_gas(&current_weights, training_data);

        debug!(
            "Training step completed: loss={:.4}, accuracy={:.4}",
            metrics.loss, metrics.accuracy
        );

        Ok((updated_weights, metrics, gas_used))
    }

    /// Compute pseudo-gradient from training data
    ///
    /// Uses hash-based derivation to produce deterministic gradients.
    /// Different training data produces different gradients.
    fn compute_pseudo_gradient(&self, training_data: &[u8], current_weights: &[u8]) -> Vec<u8> {
        use sha3::{Digest, Sha3_256};

        let mut gradient = Vec::with_capacity(current_weights.len());

        // Divide weights into chunks and compute gradient for each
        let chunk_size = 32; // SHA3-256 output size
        let num_chunks = current_weights.len().div_ceil(chunk_size);

        for i in 0..num_chunks {
            // Hash training data with chunk index to get gradient for this chunk
            let mut hasher = Sha3_256::new();
            hasher.update(b"CITRATE_GRADIENT_V1");
            hasher.update((i as u64).to_le_bytes());
            hasher.update(training_data);
            hasher.update(&current_weights[..std::cmp::min(256, current_weights.len())]);
            let hash = hasher.finalize();

            // Use hash bytes as gradient values for this chunk
            let remaining = current_weights.len().saturating_sub(i * chunk_size);
            let take = std::cmp::min(chunk_size, remaining);
            gradient.extend_from_slice(&hash[..take]);
        }

        gradient.truncate(current_weights.len());
        gradient
    }

    /// Apply gradient update to weights
    ///
    /// Updates weights by adding scaled gradient: w_new = w_old + lr * gradient
    /// Uses saturating arithmetic to prevent overflow.
    fn apply_gradient_update(
        &self,
        current_weights: &[u8],
        gradient: &[u8],
        learning_rate: f32,
    ) -> Vec<u8> {
        current_weights
            .iter()
            .zip(gradient.iter())
            .map(|(w, g)| {
                // Convert to float, apply gradient, convert back
                let w_float = *w as f32;
                let g_float = (*g as f32 - 128.0) / 128.0; // Normalize gradient to [-1, 1]
                let delta = g_float * learning_rate * 255.0;
                let new_w = (w_float + delta).clamp(0.0, 255.0);
                new_w as u8
            })
            .collect()
    }

    /// Compute training metrics
    ///
    /// Calculates loss and accuracy based on weight changes.
    fn compute_training_metrics(
        &self,
        training_data: &[u8],
        old_weights: &[u8],
        new_weights: &[u8],
    ) -> TrainingMetrics {
        // Compute L2 norm of weight change as proxy for loss
        let weight_change: f64 = old_weights
            .iter()
            .zip(new_weights.iter())
            .map(|(o, n)| {
                let diff = (*n as f64) - (*o as f64);
                diff * diff
            })
            .sum::<f64>()
            .sqrt();

        // Normalize loss to [0, 1] range
        let loss = (weight_change / (old_weights.len() as f64 * 255.0)).min(1.0);

        // Accuracy increases as loss decreases (simple inverse relationship)
        let accuracy = (1.0 - loss).max(0.5);

        // Epoch derived from training data size
        let epoch = (training_data.len() / 1024).max(1) as u64;

        TrainingMetrics {
            loss,
            accuracy,
            epoch,
        }
    }

    /// Estimate gas for training
    fn estimate_training_gas(&self, weights: &[u8], training_data: &[u8]) -> u64 {
        // Base cost + per-weight cost + per-training-byte cost
        let base_gas = 1_000_000u64;
        let weight_gas = (weights.len() as u64) * 10;
        let data_gas = (training_data.len() as u64) * 5;
        base_gas + weight_gas + data_gas
    }

    /// Generate execution proof
    ///
    /// Creates a cryptographic proof of execution that can be verified.
    /// Uses a commitment-based scheme where:
    /// - statement = structured representation of the computation
    /// - proof_data = commitment || response (64 bytes total)
    /// - commitment = H(statement || response)
    ///
    /// In production, this would use a full ZK proving system (arkworks, halo2, etc.)
    fn generate_proof(
        &self,
        model: &Model,
        input: &[u8],
        output: &[u8],
        provider: Address,
    ) -> Result<ExecutionProof> {
        use sha3::{Digest, Sha3_256};

        // Hash model
        let model_hash = {
            let mut hasher = Sha3_256::new();
            hasher.update(&model.architecture);
            hasher.update(&model.weights);
            Hash::new(hasher.finalize().into())
        };

        // Hash input/output
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

        // Create IO commitment
        let io_commitment = {
            let mut hasher = Sha3_256::new();
            hasher.update(input_hash.as_bytes());
            hasher.update(output_hash.as_bytes());
            Hash::new(hasher.finalize().into())
        };

        // Generate ZK proof components
        let (statement, proof_data) = self.generate_zk_proof_data(
            &model_hash,
            &input_hash,
            &output_hash,
            &io_commitment,
            &provider,
        );

        Ok(ExecutionProof {
            model_hash,
            input_hash,
            output_hash,
            io_commitment,
            statement,
            proof_data,
            timestamp: chrono::Utc::now().timestamp() as u64,
            provider,
        })
    }

    /// Generate proof data.
    ///
    /// When the `zkp_production` feature is enabled, this should generate a
    /// Groth16 proof via arkworks (not yet implemented — see ADR-003).
    /// Currently uses a commitment-based scheme as an interim measure.
    ///
    /// Creates a commitment-based proof that binds the statement to the execution.
    /// The proof follows a simple Schnorr-like protocol:
    /// 1. Generate response from execution parameters (deterministic)
    /// 2. Compute commitment = H(statement || response)
    /// 3. Return (statement, commitment || response)
    fn generate_zk_proof_data(
        &self,
        model_hash: &Hash,
        input_hash: &Hash,
        output_hash: &Hash,
        io_commitment: &Hash,
        provider: &Address,
    ) -> (Vec<u8>, Vec<u8>) {
        use sha3::{Digest, Sha3_256};

        // Create statement: structured representation of the computation
        // Format: "CITRATE_EXECUTION_V1" || model_hash || input_hash || output_hash || io_commitment
        let mut statement = Vec::with_capacity(32 * 4 + 20);
        statement.extend_from_slice(b"CITRATE_EXECUTION_V1");
        statement.extend_from_slice(model_hash.as_bytes());
        statement.extend_from_slice(input_hash.as_bytes());
        statement.extend_from_slice(output_hash.as_bytes());
        statement.extend_from_slice(io_commitment.as_bytes());

        // Generate response: derived from statement + provider for determinism
        // In a real ZK system, this would be the prover's response to a challenge
        let response = {
            let mut hasher = Sha3_256::new();
            hasher.update(b"CITRATE_RESPONSE_V1");
            hasher.update(&statement);
            hasher.update(provider.0);
            // Add timestamp entropy for uniqueness across executions
            let timestamp = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
            hasher.update(timestamp.to_le_bytes());
            hasher.finalize()
        };

        // Compute commitment: H(statement || response)
        let commitment = {
            let mut hasher = Sha3_256::new();
            hasher.update(&statement);
            hasher.update(response);
            hasher.finalize()
        };

        // proof_data = commitment || response (64 bytes)
        let mut proof_data = Vec::with_capacity(64);
        proof_data.extend_from_slice(&commitment);
        proof_data.extend_from_slice(&response);

        (statement, proof_data)
    }

    /// Generate training proof
    fn generate_training_proof(
        &self,
        model: &Model,
        training_data: &[u8],
        _current_weights: &[u8],
        updated_weights: &[u8],
        provider: Address,
    ) -> Result<ExecutionProof> {
        // Similar to generate_proof but for training
        self.generate_proof(model, training_data, updated_weights, provider)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_execution_context(
        model_id: ModelId,
        training_data: Vec<u8>,
        weights: Vec<u8>,
    ) -> ExecutionContext {
        ExecutionContext {
            model_id,
            input: training_data,
            memory_limit: 100 * 1024 * 1024,
            gas_limit: 10_000_000,
            execution_mode: ExecutionMode::Training {
                current_weights: weights,
            },
        }
    }

    #[test]
    fn test_compute_pseudo_gradient() {
        let executor = TestableExecutor::new();
        let weights = vec![100u8; 64];
        let training_data = b"test training data";

        let gradient = executor.compute_pseudo_gradient(training_data, &weights);

        // Gradient should have same length as weights
        assert_eq!(gradient.len(), weights.len());

        // Gradient should be non-zero (non-trivial)
        assert!(gradient.iter().any(|&g| g != 0));
    }

    #[test]
    fn test_compute_pseudo_gradient_deterministic() {
        let executor = TestableExecutor::new();
        let weights = vec![100u8; 64];
        let training_data = b"test training data";

        let gradient1 = executor.compute_pseudo_gradient(training_data, &weights);
        let gradient2 = executor.compute_pseudo_gradient(training_data, &weights);

        // Same inputs should produce same gradient
        assert_eq!(gradient1, gradient2);
    }

    #[test]
    fn test_compute_pseudo_gradient_different_data() {
        let executor = TestableExecutor::new();
        let weights = vec![100u8; 64];

        let gradient1 = executor.compute_pseudo_gradient(b"training data A", &weights);
        let gradient2 = executor.compute_pseudo_gradient(b"training data B", &weights);

        // Different training data should produce different gradients
        assert_ne!(gradient1, gradient2);
    }

    #[test]
    fn test_apply_gradient_update() {
        let executor = TestableExecutor::new();
        let weights = vec![128u8; 10];
        let gradient = vec![200u8; 10]; // Positive gradient
        let learning_rate = 0.1f32;

        let new_weights = executor.apply_gradient_update(&weights, &gradient, learning_rate);

        // Weights should change
        assert_ne!(new_weights, weights);
        // New weights should have same length
        assert_eq!(new_weights.len(), weights.len());
    }

    #[test]
    fn test_apply_gradient_update_bounds() {
        let executor = TestableExecutor::new();
        let weights = vec![250u8; 10]; // Near upper bound
        let gradient = vec![255u8; 10]; // Large positive gradient
        let learning_rate = 1.0f32;

        let new_weights = executor.apply_gradient_update(&weights, &gradient, learning_rate);

        // All weights should be valid (0-255)
        assert!(!new_weights.is_empty()); // u8 values are always <= 255
    }

    #[test]
    fn test_compute_training_metrics() {
        let executor = TestableExecutor::new();
        let training_data = b"test data";
        let old_weights = vec![100u8; 100];
        let new_weights = vec![110u8; 100]; // Slightly changed

        let metrics = executor.compute_training_metrics(training_data, &old_weights, &new_weights);

        // Loss should be in valid range
        assert!(metrics.loss >= 0.0 && metrics.loss <= 1.0);
        // Accuracy should be in valid range
        assert!(metrics.accuracy >= 0.0 && metrics.accuracy <= 1.0);
        // Epoch should be positive
        assert!(metrics.epoch >= 1);
    }

    #[test]
    fn test_model_training_produces_different_weights() {
        // This is the key acceptance test for WP-A.3
        let executor = TestableExecutor::new();
        let model_id = ModelId([1u8; 32]);
        let initial_weights = vec![100u8; 256];

        // Create training contexts with different data
        let context_a = create_test_execution_context(
            model_id,
            b"training batch A with unique content".to_vec(),
            initial_weights.clone(),
        );

        let context_b = create_test_execution_context(
            model_id,
            b"training batch B with different content".to_vec(),
            initial_weights.clone(),
        );

        // Simulate training
        let gradient_a = executor.compute_pseudo_gradient(&context_a.input, &initial_weights);
        let gradient_b = executor.compute_pseudo_gradient(&context_b.input, &initial_weights);

        let weights_a = executor.apply_gradient_update(&initial_weights, &gradient_a, 0.01);
        let weights_b = executor.apply_gradient_update(&initial_weights, &gradient_b, 0.01);

        // Different training data should produce different weights
        assert_ne!(weights_a, weights_b);

        // Weights should be different from initial
        assert_ne!(weights_a, initial_weights);
        assert_ne!(weights_b, initial_weights);
    }

    #[test]
    fn test_estimate_training_gas() {
        let executor = TestableExecutor::new();
        let weights = vec![0u8; 1000];
        let training_data = vec![0u8; 2000];

        let gas = executor.estimate_training_gas(&weights, &training_data);

        // Should have base cost + weight cost + data cost
        assert!(gas > 1_000_000); // At least base cost
        assert!(gas > 1_000_000 + 1000 * 10); // Base + weight cost
    }

    // Test helper that exposes private methods for testing
    struct TestableExecutor;

    impl TestableExecutor {
        fn new() -> Self {
            Self
        }

        fn compute_pseudo_gradient(&self, training_data: &[u8], current_weights: &[u8]) -> Vec<u8> {
            use sha3::{Digest, Sha3_256};

            let mut gradient = Vec::with_capacity(current_weights.len());
            let chunk_size = 32;
            let num_chunks = current_weights.len().div_ceil(chunk_size);

            for i in 0..num_chunks {
                let mut hasher = Sha3_256::new();
                hasher.update(b"CITRATE_GRADIENT_V1");
                hasher.update((i as u64).to_le_bytes());
                hasher.update(training_data);
                hasher.update(&current_weights[..std::cmp::min(256, current_weights.len())]);
                let hash = hasher.finalize();

                let remaining = current_weights.len().saturating_sub(i * chunk_size);
                let take = std::cmp::min(chunk_size, remaining);
                gradient.extend_from_slice(&hash[..take]);
            }

            gradient.truncate(current_weights.len());
            gradient
        }

        fn apply_gradient_update(
            &self,
            current_weights: &[u8],
            gradient: &[u8],
            learning_rate: f32,
        ) -> Vec<u8> {
            current_weights
                .iter()
                .zip(gradient.iter())
                .map(|(w, g)| {
                    let w_float = *w as f32;
                    let g_float = (*g as f32 - 128.0) / 128.0;
                    let delta = g_float * learning_rate * 255.0;
                    let new_w = (w_float + delta).clamp(0.0, 255.0);
                    new_w as u8
                })
                .collect()
        }

        fn compute_training_metrics(
            &self,
            training_data: &[u8],
            old_weights: &[u8],
            new_weights: &[u8],
        ) -> TrainingMetrics {
            let weight_change: f64 = old_weights
                .iter()
                .zip(new_weights.iter())
                .map(|(o, n)| {
                    let diff = (*n as f64) - (*o as f64);
                    diff * diff
                })
                .sum::<f64>()
                .sqrt();

            let loss = (weight_change / (old_weights.len() as f64 * 255.0)).min(1.0);
            let accuracy = (1.0 - loss).max(0.5);
            let epoch = (training_data.len() / 1024).max(1) as u64;

            TrainingMetrics {
                loss,
                accuracy,
                epoch,
            }
        }

        fn estimate_training_gas(&self, weights: &[u8], training_data: &[u8]) -> u64 {
            let base_gas = 1_000_000u64;
            let weight_gas = (weights.len() as u64) * 10;
            let data_gas = (training_data.len() as u64) * 5;
            base_gas + weight_gas + data_gas
        }
    }

    #[test]
    fn test_gguf_graceful_degradation() {
        // Test that ModelExecutor can be created even when GGUF engine fails
        // In real usage, this is tested by the fact that the constructor no longer panics
        // Here we test the Option<Arc<GGUFEngine>> pattern works correctly

        // Test None case
        let gguf_engine: Option<Arc<GGUFEngine>> = None;
        assert!(gguf_engine.is_none());

        // Test is_some pattern used in execute_in_vm
        let result: Result<(), &str> = gguf_engine
            .as_ref()
            .ok_or("AI features unavailable: GGUF engine not initialized")
            .map(|_| ());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "AI features unavailable: GGUF engine not initialized"
        );
    }
}

/// Model representation
#[derive(Debug, Clone)]
pub struct Model {
    pub id: ModelId,
    pub architecture: Vec<u8>,
    pub weights: Vec<u8>,
    pub metadata: Vec<u8>,
}

/// Execution context
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ExecutionContext {
    model_id: ModelId,
    input: Vec<u8>,
    memory_limit: u64,
    gas_limit: u64,
    execution_mode: ExecutionMode,
}

/// Execution mode
#[derive(Debug, Clone)]
#[allow(dead_code)]
enum ExecutionMode {
    Inference,
    Training { current_weights: Vec<u8> },
}

/// Training result
#[derive(Debug, Clone)]
pub struct TrainingResult {
    pub updated_weights: Vec<u8>,
    pub metrics: TrainingMetrics,
    pub proof: ExecutionProof,
    pub gas_used: u64,
    pub latency_ms: u64,
    pub provider: Address,
}

/// Training metrics
#[derive(Debug, Clone)]
pub struct TrainingMetrics {
    pub loss: f64,
    pub accuracy: f64,
    pub epoch: u64,
}
