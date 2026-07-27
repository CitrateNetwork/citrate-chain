// citrate/core/api/src/methods/ai.rs

use crate::types::error::ApiError;
use citrate_consensus::types::{Hash, PublicKey, Signature, Transaction};
use citrate_execution::executor::Executor;
use citrate_execution::types::{
    AccessPolicy, Address, JobId, ModelId, ModelMetadata, ModelState, TrainingJob,
};
use citrate_sequencer::{Mempool, TxClass};
use citrate_storage::StorageManager;
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::sync::Arc;

/// SECREM-01 Phase-8 (NET-1 variant): per-request caps on attacker-driven
/// batch sizes for the inference RPC surface — each entry spawns model
/// work, so an unbounded array is an inference-cost DoS.
const MAX_EMBEDDING_INPUTS: usize = 256;
const MAX_CHAT_MESSAGES: usize = 256;

/// OpenAI-compatible chat completion request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub n: Option<u32>,
    pub stop: Option<Vec<String>>,
    pub stream: Option<bool>,
}

/// Chat message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String, // "system", "user", "assistant"
    pub content: String,
}

/// Chat completion response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatCompletionResponse {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<ChatChoice>,
    pub usage: TokenUsage,
}

/// Chat choice
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatChoice {
    pub index: u32,
    pub message: ChatMessage,
    pub finish_reason: String,
}

/// Token usage stats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// Embeddings request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingsRequest {
    pub model: String,
    pub input: Vec<String>,
    pub encoding_format: Option<String>,
}

/// Embeddings response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingsResponse {
    pub object: String,
    pub data: Vec<EmbeddingData>,
    pub model: String,
    pub usage: TokenUsage,
    /// Citrate metadata: signals when embeddings are deterministic pseudo-vectors
    /// rather than real model output, so consumers can distinguish the two.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub _citrate_meta: Option<CitrateMeta>,
}

/// Citrate-specific metadata for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CitrateMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

/// Embedding data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingData {
    pub object: String,
    pub embedding: Vec<f32>,
    pub index: u32,
}

/// Model deployment request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployModelRequest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub framework: String,
    pub model_data: Vec<u8>,
    pub metadata: ModelMetadata,
    pub access_policy: AccessPolicy,
}

/// Inference request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceRequest {
    pub model_id: String,
    pub input_data: Vec<u8>,
    pub max_gas: u64,
    pub callback_url: Option<String>,
}

/// Inference result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceResult {
    pub request_id: String,
    pub model_id: String,
    pub output_data: Vec<u8>,
    pub gas_used: u64,
    pub execution_time_ms: u64,
    pub status: String,
    pub error: Option<String>,
}

/// Training job request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTrainingJobRequest {
    pub model_id: String,
    pub dataset_hash: String,
    pub participants: Vec<String>,
    pub reward_pool: String, // U256 as string
    pub gradient_requirements: u32,
}

/// LoRA adapter request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateLoRARequest {
    pub base_model_id: String,
    pub adapter_data: Vec<u8>,
    pub rank: u32,
    pub alpha: f32,
    pub description: String,
}

/// LoRA adapter info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoRAInfo {
    pub adapter_id: String,
    pub base_model_id: String,
    pub owner: String,
    pub rank: u32,
    pub alpha: f32,
    pub description: String,
    pub size_bytes: u64,
    pub created_at: u64,
}

/// Model statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelStats {
    pub model_id: String,
    pub total_inferences: u64,
    pub total_gas_used: u64,
    pub total_fees_earned: String, // U256 as string
    pub average_execution_time_ms: f64,
    pub success_rate: f64,
    pub last_used: u64,
}

/// AI/ML-related API methods
#[derive(Clone)]
pub struct AiApi {
    storage: Arc<StorageManager>,
    mempool: Arc<Mempool>,
    executor: Arc<Executor>,
}

impl AiApi {
    pub fn new(
        storage: Arc<StorageManager>,
        mempool: Arc<Mempool>,
        executor: Arc<Executor>,
    ) -> Self {
        Self {
            storage,
            mempool,
            executor,
        }
    }

    // ========== Model Management ==========

    /// Deploy a new model to the network
    pub async fn deploy_model(
        &self,
        request: DeployModelRequest,
        from: Address,
        gas_limit: u64,
        gas_price: u64,
    ) -> Result<Hash, ApiError> {
        // Calculate model hash
        let mut hasher = Sha3_256::new();
        hasher.update(&request.model_data);
        let model_hash_bytes = hasher.finalize();
        let mut model_hash_array = [0u8; 32];
        model_hash_array.copy_from_slice(&model_hash_bytes[..32]);
        let _model_hash = Hash::new(model_hash_array);

        // We'll encode the model registration data in the transaction data field

        // Get current nonce (get_nonce returns u64 directly, not Result)
        let nonce = self.executor.get_canonical_account(&from).nonce; // SRP-S4 WP-2.2: non-warming committed read

        // Create transaction (Transaction doesn't have a new() constructor, build directly)
        // Convert Address to PublicKey for the from field
        let mut from_pk_bytes = [0u8; 32];
        from_pk_bytes[..20].copy_from_slice(&from.0);
        let from_pk = PublicKey::new(from_pk_bytes);

        // Calculate transaction hash
        let mut hasher = Sha3_256::new();
        hasher.update(nonce.to_le_bytes());
        hasher.update(from.0);
        hasher.update(gas_price.to_le_bytes());
        let hash_bytes = hasher.finalize();
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hash_bytes);

        let tx = Transaction {
            hash: Hash::new(hash_array),
            nonce,
            from: from_pk,
            to: None, // Contract creation for model registration
            value: 0,
            gas_limit,
            gas_price,
            data: vec![], // Serialized transaction type would go here
            signature: Signature::new([0u8; 64]), // Placeholder - needs proper signing
            tx_type: None, // Will be determined from data
            ..Default::default()
        };

        // Clone tx hash before moving tx to mempool
        let tx_hash = tx.hash;

        // Submit to mempool (add_transaction is async and takes ownership)
        self.mempool
            .add_transaction(tx, TxClass::ModelUpdate)
            .await
            .map_err(|e| ApiError::InternalError(e.to_string()))?;

        Ok(tx_hash)
    }

    /// Update an existing model
    pub async fn update_model(
        &self,
        model_id: ModelId,
        _new_version_hash: Hash,
        _changelog: String,
        from: Address,
        gas_limit: u64,
        gas_price: u64,
    ) -> Result<Hash, ApiError> {
        // We'll encode the model update data in the transaction data field

        let nonce = self.executor.get_canonical_account(&from).nonce; // SRP-S4 WP-2.2: non-warming committed read

        // Convert Address to PublicKey
        let mut from_pk_bytes = [0u8; 32];
        from_pk_bytes[..20].copy_from_slice(&from.0);
        let from_pk = PublicKey::new(from_pk_bytes);

        // Calculate transaction hash
        let mut hasher = Sha3_256::new();
        hasher.update(nonce.to_le_bytes());
        hasher.update(from.0);
        hasher.update(model_id.0.as_bytes());
        let hash_bytes = hasher.finalize();
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hash_bytes);

        let tx = Transaction {
            hash: Hash::new(hash_array),
            nonce,
            from: from_pk,
            to: None,
            value: 0,
            gas_limit,
            gas_price,
            data: vec![],
            signature: Signature::new([0u8; 64]),
            tx_type: None, // Will be determined from data
            ..Default::default()
        };

        // Clone tx hash before moving tx to mempool
        let tx_hash = tx.hash;

        self.mempool
            .add_transaction(tx, TxClass::ModelUpdate)
            .await
            .map_err(|e| ApiError::InternalError(e.to_string()))?;

        Ok(tx_hash)
    }

    /// Get model information
    pub async fn get_model(&self, model_id: ModelId) -> Result<ModelState, ApiError> {
        self.storage
            .state
            .get_model(&model_id)
            .map_err(|e| ApiError::InternalError(e.to_string()))?
            .ok_or_else(|| ApiError::ModelNotFound(format!("{:?}", model_id)))
    }

    /// List registered models with optional filtering
    pub async fn list_models(
        &self,
        owner: Option<Address>,
        limit: Option<usize>,
    ) -> Result<Vec<ModelId>, ApiError> {
        if let Some(addr) = owner {
            self.storage
                .state
                .get_models_by_owner(&addr)
                .map_err(|e| ApiError::InternalError(e.to_string()))
        } else {
            // Get all models (placeholder implementation)
            // In real implementation, would iterate through state storage
            let mut model_ids = Vec::new();

            if let Some(limit) = limit {
                model_ids.truncate(limit);
            }

            Ok(model_ids)
        }
    }

    /// Get model statistics
    pub async fn get_model_stats(&self, model_id: ModelId) -> Result<ModelStats, ApiError> {
        let model = self.get_model(model_id).await?;

        Ok(ModelStats {
            model_id: hex::encode(model_id.0.as_bytes()),
            total_inferences: model.usage_stats.total_inferences,
            total_gas_used: model.usage_stats.total_gas_used,
            total_fees_earned: model.usage_stats.total_fees_earned.to_string(),
            average_execution_time_ms: if model.usage_stats.total_inferences > 0 {
                model.usage_stats.total_gas_used as f64 / model.usage_stats.total_inferences as f64
            } else {
                0.0
            },
            success_rate: 0.95, // Placeholder - would be calculated from actual data
            last_used: model.usage_stats.last_used,
        })
    }

    // ========== Inference Management ==========

    /// Request model inference
    pub async fn request_inference(
        &self,
        request: InferenceRequest,
        from: Address,
        gas_price: u64,
    ) -> Result<Hash, ApiError> {
        // Parse model ID
        let model_id_bytes = hex::decode(&request.model_id)
            .map_err(|_| ApiError::InvalidParams("Invalid model ID format".to_string()))?;

        if model_id_bytes.len() != 32 {
            return Err(ApiError::InvalidParams(
                "Model ID must be 32 bytes".to_string(),
            ));
        }

        let mut model_id_array = [0u8; 32];
        model_id_array.copy_from_slice(&model_id_bytes);
        let model_id = ModelId(Hash::new(model_id_array));

        // Check if model exists
        self.get_model(model_id).await?;

        // We'll encode the inference request data in the transaction data field

        let nonce = self.executor.get_canonical_account(&from).nonce; // SRP-S4 WP-2.2: non-warming committed read

        // Convert Address to PublicKey
        let mut from_pk_bytes = [0u8; 32];
        from_pk_bytes[..20].copy_from_slice(&from.0);
        let from_pk = PublicKey::new(from_pk_bytes);

        // Calculate transaction hash
        let mut hasher = Sha3_256::new();
        hasher.update(nonce.to_le_bytes());
        hasher.update(from.0);
        hasher.update(request.model_id.as_bytes());
        let hash_bytes = hasher.finalize();
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hash_bytes);

        let tx = Transaction {
            hash: Hash::new(hash_array),
            nonce,
            from: from_pk,
            to: None,
            value: 0,
            gas_limit: request.max_gas,
            gas_price,
            data: vec![],
            signature: Signature::new([0u8; 64]),
            tx_type: None,
            ..Default::default()
        };

        // Clone tx hash before moving tx to mempool
        let tx_hash = tx.hash;

        self.mempool
            .add_transaction(tx, TxClass::Inference)
            .await
            .map_err(|e| ApiError::InternalError(e.to_string()))?;

        Ok(tx_hash)
    }

    /// Get inference result
    pub async fn get_inference_result(
        &self,
        request_id: Hash,
    ) -> Result<InferenceResult, ApiError> {
        // Get transaction receipt from transaction store
        let receipt = self
            .storage
            .transactions
            .get_receipt(&request_id)
            .map_err(|e| ApiError::InternalError(e.to_string()))?
            .ok_or_else(|| ApiError::TransactionNotFound(format!("{:?}", request_id)))?;

        // Extract inference data from receipt
        Ok(InferenceResult {
            request_id: hex::encode(request_id.as_bytes()),
            model_id: "unknown".to_string(), // Would extract from transaction
            output_data: receipt.output,
            gas_used: receipt.gas_used,
            execution_time_ms: 100, // Placeholder
            status: if receipt.status {
                "completed".to_string()
            } else {
                "failed".to_string()
            },
            error: if !receipt.status {
                Some("Execution failed".to_string())
            } else {
                None
            },
        })
    }

    // ========== Training Job Management ==========

    /// Create a new training job
    pub async fn create_training_job(
        &self,
        request: CreateTrainingJobRequest,
        from: Address,
        _gas_limit: u64,
        _gas_price: u64,
    ) -> Result<Hash, ApiError> {
        // Parse model ID
        let model_id_bytes = hex::decode(&request.model_id)
            .map_err(|_| ApiError::InvalidParams("Invalid model ID format".to_string()))?;

        let mut model_id_array = [0u8; 32];
        model_id_array.copy_from_slice(&model_id_bytes);
        let model_id = ModelId(Hash::new(model_id_array));

        // Parse dataset hash
        let dataset_hash_bytes = hex::decode(&request.dataset_hash)
            .map_err(|_| ApiError::InvalidParams("Invalid dataset hash format".to_string()))?;

        let mut dataset_hash_array = [0u8; 32];
        dataset_hash_array.copy_from_slice(&dataset_hash_bytes);
        let dataset_hash = Hash::new(dataset_hash_array);

        // Parse participants
        let participants: Result<Vec<Address>, ApiError> = request
            .participants
            .iter()
            .map(|p| {
                let addr_bytes = hex::decode(p.trim_start_matches("0x")).map_err(|_| {
                    ApiError::InvalidParams("Invalid participant address".to_string())
                })?;

                if addr_bytes.len() != 20 {
                    return Err(ApiError::InvalidParams(
                        "Address must be 20 bytes".to_string(),
                    ));
                }

                let mut addr_array = [0u8; 20];
                addr_array.copy_from_slice(&addr_bytes);
                Ok(Address(addr_array))
            })
            .collect();

        let participants = participants?;

        // Parse reward pool
        let reward_pool = U256::from_dec_str(&request.reward_pool)
            .map_err(|_| ApiError::InvalidParams("Invalid reward pool amount".to_string()))?;

        // Generate job ID
        let mut hasher = Sha3_256::new();
        hasher.update(model_id.0.as_bytes());
        hasher.update(dataset_hash.as_bytes());
        hasher.update(from.0);
        hasher.update(chrono::Utc::now().timestamp().to_le_bytes());

        let job_id_bytes = hasher.finalize();
        let mut job_id_array = [0u8; 32];
        job_id_array.copy_from_slice(&job_id_bytes[..32]);
        let job_id = JobId(Hash::new(job_id_array));

        // Create training job
        let training_job = TrainingJob {
            id: job_id,
            owner: from,
            model_id,
            dataset_hash,
            participants,
            gradients_submitted: 0,
            gradients_required: request.gradient_requirements,
            reward_pool,
            status: citrate_execution::types::JobStatus::Pending,
            created_at: chrono::Utc::now().timestamp() as u64,
            completed_at: None,
        };

        // Store training job
        self.storage
            .state
            .put_training_job(&training_job)
            .map_err(|e| ApiError::InternalError(e.to_string()))?;

        Ok(Hash::new(*job_id.0.as_bytes()))
    }

    /// Get training job status
    pub async fn get_training_job(&self, job_id: JobId) -> Result<TrainingJob, ApiError> {
        self.storage
            .state
            .get_training_job(&job_id)
            .map_err(|e| ApiError::InternalError(e.to_string()))?
            .ok_or_else(|| ApiError::InternalError(format!("Training job {:?} not found", job_id)))
    }

    /// List training jobs
    pub async fn list_training_jobs(
        &self,
        _model_id: Option<ModelId>,
        _owner: Option<Address>,
        _status: Option<String>,
        _limit: Option<usize>,
    ) -> Result<Vec<JobId>, ApiError> {
        // For production, we need to implement proper indexing for training jobs
        // Currently returning empty list as a placeholder
        // NOTE: Training job listing requires a storage indexer (not yet implemented).
        // Returns empty list rather than error to maintain API compatibility.
        let filtered_jobs: Vec<JobId> = Vec::new();

        // The code below would apply filters in production:
        /*
        let mut filtered_jobs: Vec<JobId> = all_jobs
            .into_iter()
            .filter(|(_, job)| {
                if let Some(model_filter) = model_id {
                    if job.model_id != model_filter {
                        return false;
                    }
                }

                if let Some(owner_filter) = owner {
                    if job.owner != owner_filter {
                        return false;
                    }
                }

                if let Some(status_filter) = &status {
                    let job_status_str = match job.status {
                        citrate_execution::types::JobStatus::Pending => "pending",
                        citrate_execution::types::JobStatus::Active => "active",
                        citrate_execution::types::JobStatus::Completed => "completed",
                        citrate_execution::types::JobStatus::Failed => "failed",
                        citrate_execution::types::JobStatus::Cancelled => "cancelled",
                    };

                    if job_status_str != status_filter {
                        return false;
                    }
                }

                true
            })
            .map(|(job_id, _)| job_id)
            .collect();
        */

        // In production implementation would truncate here
        // if let Some(limit) = limit {
        //     filtered_jobs.truncate(limit);
        // }

        Ok(filtered_jobs)
    }

    // ========== LoRA Adapter Management ==========

    /// Create a new LoRA adapter
    pub async fn create_lora(
        &self,
        request: CreateLoRARequest,
        from: Address,
    ) -> Result<Hash, ApiError> {
        // Parse base model ID
        let model_id_bytes = hex::decode(&request.base_model_id)
            .map_err(|_| ApiError::InvalidParams("Invalid base model ID format".to_string()))?;

        let mut model_id_array = [0u8; 32];
        model_id_array.copy_from_slice(&model_id_bytes);
        let base_model_id = ModelId(Hash::new(model_id_array));

        // Verify base model exists
        self.get_model(base_model_id).await?;

        // Generate adapter ID
        let mut hasher = Sha3_256::new();
        hasher.update(base_model_id.0.as_bytes());
        hasher.update(from.0);
        hasher.update(&request.adapter_data);
        hasher.update(chrono::Utc::now().timestamp().to_le_bytes());

        let adapter_id_bytes = hasher.finalize();
        let mut adapter_id_array = [0u8; 32];
        adapter_id_array.copy_from_slice(&adapter_id_bytes[..32]);
        let adapter_id = Hash::new(adapter_id_array);

        // Create LoRA adapter record
        let _lora_info = LoRAInfo {
            adapter_id: hex::encode(adapter_id.as_bytes()),
            base_model_id: request.base_model_id,
            owner: hex::encode(from.0),
            rank: request.rank,
            alpha: request.alpha,
            description: request.description,
            size_bytes: request.adapter_data.len() as u64,
            created_at: chrono::Utc::now().timestamp() as u64,
        };

        // Store LoRA adapter (simplified - would use proper storage)
        // In real implementation, would store adapter_data to IPFS/Arweave
        // and store metadata in state

        Ok(adapter_id)
    }

    /// Get LoRA adapter information
    pub async fn get_lora(&self, _adapter_id: Hash) -> Result<LoRAInfo, ApiError> {
        // Placeholder implementation
        // Would retrieve from storage
        Err(ApiError::InternalError(
            "LoRA retrieval not yet implemented".to_string(),
        ))
    }

    /// List LoRA adapters for a base model
    pub async fn list_loras(
        &self,
        _base_model_id: Option<ModelId>,
        _owner: Option<Address>,
        _limit: Option<usize>,
    ) -> Result<Vec<LoRAInfo>, ApiError> {
        // Placeholder implementation
        // Would retrieve from storage with filtering
        Ok(Vec::new())
    }

    // ========== OpenAI/Anthropic Compatible Endpoints ==========

    /// OpenAI-compatible chat completions
    pub async fn chat_completions(
        &self,
        request: ChatCompletionRequest,
        _from: Option<Address>,
    ) -> Result<ChatCompletionResponse, ApiError> {
        // SECREM-01 Phase-8 (NET-1 variant): cap the message count so an
        // unbounded `messages` array can't drive unbounded prompt-build +
        // inference work.
        if request.messages.len() > MAX_CHAT_MESSAGES {
            return Err(ApiError::InvalidParams(format!(
                "too many messages: {} (max {MAX_CHAT_MESSAGES})",
                request.messages.len()
            )));
        }
        // For streaming responses, we'd need WebSocket support
        if request.stream.unwrap_or(false) {
            return Err(ApiError::InternalError(
                "Streaming not yet implemented".to_string(),
            ));
        }

        // Use Mistral 7B model from IPFS (well-known model ID)
        // In production, would look up model by name from request.model
        let _llm_model_id = ModelId(Hash::new([0x02; 32])); // Placeholder for Mistral 7B

        // Format messages into a single prompt
        let mut prompt = String::new();
        for msg in &request.messages {
            match msg.role.as_str() {
                "system" => prompt.push_str(&format!("### System:\n{}\n\n", msg.content)),
                "user" => prompt.push_str(&format!("### User:\n{}\n\n", msg.content)),
                "assistant" => prompt.push_str(&format!("### Assistant:\n{}\n\n", msg.content)),
                _ => prompt.push_str(&format!("### {}:\n{}\n\n", msg.role, msg.content)),
            }
        }
        prompt.push_str("### Assistant:\n");

        // Prepare input data with parameters
        let _input_data = serde_json::to_vec(&serde_json::json!({
            "prompt": prompt,
            "max_tokens": request.max_tokens.unwrap_or(512),
            "temperature": request.temperature.unwrap_or(0.7),
            "top_p": request.top_p.unwrap_or(1.0),
        }))
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

        // For chat completions, we can attempt synchronous execution for better UX
        // This bypasses the mempool for faster responses
        // In production, this would need rate limiting and access control

        // Estimate token counts from messages
        let prompt_tokens: u32 = request.messages.iter()
            .map(|m| (m.content.len() / 4) as u32)
            .sum();

        // Generate a temporary response ID
        let response_id = format!("chatcmpl-{}", chrono::Utc::now().timestamp_millis());

        // Execute actual inference using GGUF engine directly
        use citrate_mcp::gguf_engine::{GGUFEngine, GGUFEngineConfig};
        use std::path::PathBuf;

        // Resolve model name to filename
        let model_filename = match request.model.as_str() {
            "mistral-7b-instruct-v0.3" | "mistral-7b" => "Mistral-7B-Instruct-v0.3-Q4_K_M.gguf",
            "bge-m3" => "bge-m3-fp16.gguf",
            "qwen2-0.5b" | "qwen" | "qwen2.5" | "qwen2.5-1.5b" => "qwen2.5-1.5b-instruct-q4_0.gguf",
            other => other,
        };

        // Search for model in multiple locations
        let home_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let model_dirs = [
            PathBuf::from("./models"),
            PathBuf::from("../../../models"),
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../models"),
            home_dir.join("Models"),
            home_dir.join(".citrate/models"),
            home_dir.join(".ipfs/models"),
        ];

        // First try exact filename match
        let mut model_path: Option<PathBuf> = model_dirs.iter()
            .map(|dir| dir.join(model_filename))
            .find(|p| p.exists());

        // If not found, scan directories for any .gguf file (auto-detect)
        if model_path.is_none() {
            for dir in &model_dirs {
                if let Ok(entries) = std::fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.extension().is_some_and(|ext| ext == "gguf") {
                            tracing::info!("Auto-detected model: {:?}", path);
                            model_path = Some(path);
                            break;
                        }
                    }
                    if model_path.is_some() { break; }
                }
            }
        }

        let model_path = model_path.ok_or_else(|| {
            let searched = model_dirs.iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            ApiError::InternalError(format!(
                "No GGUF model found. Searched directories: {}. Download one with: Settings > AI Configuration > Download",
                searched
            ))
        })?;

        // Create GGUF engine for inference
        let gguf_config = GGUFEngineConfig {
            llama_cpp_path: PathBuf::from(
                std::env::var("LLAMA_CPP_PATH")
                    .unwrap_or_else(|_| {
                        dirs::home_dir()
                            .unwrap_or_else(|| PathBuf::from("."))
                            .join("llama.cpp")
                            .to_string_lossy()
                            .to_string()
                    })
            ),
            models_dir: PathBuf::from(".citrate/models"),
            context_size: 4096,
            threads: 4,
        };
        let gguf_engine = GGUFEngine::new(gguf_config)
            .map_err(|e| ApiError::InternalError(format!("Failed to initialize GGUF engine: {}", e)))?;

        // Generate text using llama.cpp
        let generated_text = gguf_engine
            .generate_text(
                &model_path,
                &prompt,
                request.max_tokens.unwrap_or(512) as usize,
                request.temperature.unwrap_or(0.7),
            )
            .await
            .map_err(|e| ApiError::InternalError(format!("GGUF inference failed: {}", e)))?;

        // Estimate actual token counts from the response
        let completion_tokens = (generated_text.len() / 4) as u32;

        Ok(ChatCompletionResponse {
            id: response_id,
            object: "chat.completion".to_string(),
            created: chrono::Utc::now().timestamp() as u64,
            model: request.model,
            choices: vec![ChatChoice {
                index: 0,
                message: ChatMessage {
                    role: "assistant".to_string(),
                    content: generated_text,
                },
                finish_reason: "stop".to_string(),
            }],
            usage: TokenUsage {
                prompt_tokens,
                completion_tokens,
                total_tokens: prompt_tokens + completion_tokens,
            },
        })
    }

    /// OpenAI-compatible embeddings
    pub async fn embeddings(
        &self,
        request: EmbeddingsRequest,
        _from: Option<Address>,
    ) -> Result<EmbeddingsResponse, ApiError> {
        // SECREM-01 Phase-8 (NET-1 variant): cap the input batch size so an
        // unbounded `input` array can't drive unbounded embedding work.
        if request.input.len() > MAX_EMBEDDING_INPUTS {
            return Err(ApiError::InvalidParams(format!(
                "too many inputs: {} (max {MAX_EMBEDDING_INPUTS})",
                request.input.len()
            )));
        }
        // For now, use genesis embedding model (BGE-M3) by default
        // In production, would look up model by name from request.model

        // For genesis models, we'd use a well-known ID
        // This will be used when full inference pipeline is connected
        let _embedding_model_id = ModelId(Hash::new([0x01; 32])); // Placeholder for genesis BGE-M3

        // Try to get embeddings from executor state
        // If the model exists and is cached, this will work
        // Otherwise, fall back to deterministic placeholder

        let embeddings_result: Result<Vec<Vec<f32>>, ApiError> = {
            // This would ideally call executor.execute_inference directly
            // For now, return structured placeholder that matches expected dimensions

            // BGE-M3 produces 1024-dimensional embeddings
            let embedding_dim = 1024;

            Ok(request
                .input
                .iter()
                .map(|text| {
                    // Generate deterministic pseudo-embeddings based on text hash
                    // In production, this would be real embeddings from the model
                    use sha3::{Digest, Sha3_256};
                    let mut hasher = Sha3_256::new();
                    hasher.update(text.as_bytes());
                    let hash = hasher.finalize();

                    // Convert hash to normalized embedding vector
                    (0..embedding_dim)
                        .map(|i| {
                            let byte_idx = i % hash.len();
                            let value = hash[byte_idx] as f32 / 255.0;
                            (value - 0.5) * 2.0 // Normalize to [-1, 1]
                        })
                        .collect()
                })
                .collect())
        };

        let embeddings = embeddings_result?;

        // Prepare embeddings data
        let embeddings_data: Vec<EmbeddingData> = embeddings
            .into_iter()
            .enumerate()
            .map(|(i, embedding)| EmbeddingData {
                object: "embedding".to_string(),
                embedding,
                index: i as u32,
            })
            .collect();

        Ok(EmbeddingsResponse {
            object: "list".to_string(),
            data: embeddings_data,
            model: request.model,
            usage: TokenUsage {
                prompt_tokens: request.input.iter().map(|s| s.len() as u32 / 4).sum(),
                completion_tokens: 0,
                total_tokens: request.input.iter().map(|s| s.len() as u32 / 4).sum(),
            },
            _citrate_meta: Some(CitrateMeta {
                warning: Some(
                    "Embeddings are deterministic pseudo-vectors derived from SHA3 hashing, \
                     not real model output. Deploy a GGUF/CoreML embedding model for production use."
                        .to_string(),
                ),
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_chat_message_serialization() {
        let msg = ChatMessage {
            role: "user".to_string(),
            content: "Hello, world!".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: ChatMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.role, "user");
        assert_eq!(deserialized.content, "Hello, world!");
    }

    #[test]
    fn test_chat_completion_request_defaults() {
        let req = ChatCompletionRequest {
            model: "gpt-4".to_string(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: "Hi".to_string(),
            }],
            max_tokens: None,
            temperature: None,
            top_p: None,
            n: None,
            stop: None,
            stream: None,
        };
        assert_eq!(req.model, "gpt-4");
        assert_eq!(req.messages.len(), 1);
        assert!(req.max_tokens.is_none());
        assert!(req.temperature.is_none());
        assert!(req.top_p.is_none());
        assert!(req.n.is_none());
        assert!(req.stop.is_none());
        assert!(req.stream.is_none());
    }

    #[test]
    fn test_embeddings_request_serialization() {
        let req = EmbeddingsRequest {
            model: "text-embedding-ada-002".to_string(),
            input: vec!["hello".to_string(), "world".to_string()],
            encoding_format: Some("float".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: EmbeddingsRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.model, "text-embedding-ada-002");
        assert_eq!(deserialized.input.len(), 2);
        assert_eq!(deserialized.input[0], "hello");
        assert_eq!(deserialized.input[1], "world");
        assert_eq!(deserialized.encoding_format, Some("float".to_string()));
    }

    #[test]
    fn test_token_usage_total() {
        let usage = TokenUsage {
            prompt_tokens: 100,
            completion_tokens: 50,
            total_tokens: 150,
        };
        assert_eq!(usage.prompt_tokens, 100);
        assert_eq!(usage.completion_tokens, 50);
        assert_eq!(usage.total_tokens, 150);
        assert_eq!(usage.total_tokens, usage.prompt_tokens + usage.completion_tokens);
    }

    #[test]
    fn test_deploy_model_request_serialization() {
        let req = DeployModelRequest {
            name: "my-model".to_string(),
            version: "1.0.0".to_string(),
            description: "A test model".to_string(),
            framework: "pytorch".to_string(),
            model_data: vec![1, 2, 3, 4],
            metadata: ModelMetadata {
                name: "my-model".to_string(),
                version: "1.0.0".to_string(),
                description: "A test model".to_string(),
                framework: "pytorch".to_string(),
                input_shape: vec![1, 3, 224, 224],
                output_shape: vec![1, 1000],
                size_bytes: 4,
                created_at: 1700000000,
            },
            access_policy: AccessPolicy::Public,
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: DeployModelRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "my-model");
        assert_eq!(deserialized.version, "1.0.0");
        assert_eq!(deserialized.description, "A test model");
        assert_eq!(deserialized.framework, "pytorch");
        assert_eq!(deserialized.model_data, vec![1, 2, 3, 4]);
        assert_eq!(deserialized.metadata.name, "my-model");
        assert_eq!(deserialized.metadata.input_shape, vec![1, 3, 224, 224]);
    }

    #[test]
    fn test_lora_info_serialization() {
        let info = LoRAInfo {
            adapter_id: "lora-001".to_string(),
            base_model_id: "base-model-001".to_string(),
            owner: "0xabcdef".to_string(),
            rank: 8,
            alpha: 16.0,
            description: "Fine-tuned adapter".to_string(),
            size_bytes: 1048576,
            created_at: 1700000000,
        };
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: LoRAInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.adapter_id, "lora-001");
        assert_eq!(deserialized.base_model_id, "base-model-001");
        assert_eq!(deserialized.owner, "0xabcdef");
        assert_eq!(deserialized.rank, 8);
        assert!((deserialized.alpha - 16.0).abs() < f32::EPSILON);
        assert_eq!(deserialized.description, "Fine-tuned adapter");
        assert_eq!(deserialized.size_bytes, 1048576);
        assert_eq!(deserialized.created_at, 1700000000);
    }

    #[test]
    fn test_model_stats_serialization() {
        let stats = ModelStats {
            model_id: "model-abc".to_string(),
            total_inferences: 5000,
            total_gas_used: 1000000,
            total_fees_earned: "500000000000000000".to_string(),
            average_execution_time_ms: 42.5,
            success_rate: 0.995,
            last_used: 1700000000,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: ModelStats = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.model_id, "model-abc");
        assert_eq!(deserialized.total_inferences, 5000);
        assert_eq!(deserialized.total_gas_used, 1000000);
        assert_eq!(deserialized.total_fees_earned, "500000000000000000");
        assert!((deserialized.average_execution_time_ms - 42.5).abs() < f64::EPSILON);
        assert!((deserialized.success_rate - 0.995).abs() < f64::EPSILON);
        assert_eq!(deserialized.last_used, 1700000000);
    }

    #[test]
    fn test_inference_result_success_and_error() {
        let success = InferenceResult {
            request_id: "req-001".to_string(),
            model_id: "model-001".to_string(),
            output_data: vec![10, 20, 30],
            gas_used: 21000,
            execution_time_ms: 150,
            status: "success".to_string(),
            error: None,
        };
        assert_eq!(success.status, "success");
        assert!(success.error.is_none());
        assert_eq!(success.output_data, vec![10, 20, 30]);

        let failure = InferenceResult {
            request_id: "req-002".to_string(),
            model_id: "model-001".to_string(),
            output_data: vec![],
            gas_used: 5000,
            execution_time_ms: 10,
            status: "error".to_string(),
            error: Some("Model not found".to_string()),
        };
        assert_eq!(failure.status, "error");
        assert_eq!(failure.error, Some("Model not found".to_string()));
        assert!(failure.output_data.is_empty());
    }
}
