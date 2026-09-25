// citrate/core/network/src/ai_handler.rs

// AI-specific network message handler
use crate::peer::{PeerId, PeerManager};
use crate::protocol::{ModelMetadata, NetworkMessage};
use anyhow::Result;
use async_trait::async_trait;
use chrono;
use citrate_consensus::types::Hash;
use citrate_execution::ModelId;
use citrate_storage::state_manager::StateManager;
use tracing::{debug, info, warn};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// ─────────────────────────────────────────────────────────────────────────────
// PBA-L1b-004: peer AI gossip is ADVISORY and BOUNDED.
//
// Every message handled here comes from an unauthenticated peer. Before this
// fix each fresh `ModelAnnounce` model id (and each `TrainingJobAnnounce` job
// id, `WeightSync`, `InferenceResponse`) became a permanent RocksDB record with
// attacker-sized fields: ~222 MiB/s of disk growth from one connection, kept
// across restarts. Peer claims now live only in bounded, expiring in-memory
// maps and never reach persistent state.
// ─────────────────────────────────────────────────────────────────────────────

/// Upper bound on an announcement's variable-size fields, in bytes.
pub const MAX_ANNOUNCE_METADATA_BYTES: usize = 4 * 1024;
/// Upper bound on cached peer model announcements (all peers).
pub const MAX_CACHED_MODELS: usize = 1024;
/// Upper bound on cached announcements originated by one peer.
pub const MAX_MODELS_PER_PEER: usize = 32;
/// Upper bound on providers recorded for one model.
pub const MAX_PROVIDERS_PER_MODEL: usize = 16;
/// How long a peer announcement is remembered.
pub const MODEL_ANNOUNCE_TTL: std::time::Duration = std::time::Duration::from_secs(3_600);
/// Upper bound on tracked peer training-job announcements (all peers).
pub const MAX_TRAINING_JOBS: usize = 256;
/// Upper bound on tracked training-job announcements originated by one peer.
pub const MAX_TRAINING_JOBS_PER_PEER: usize = 8;
/// PBA-L1b-005: upper bound on pending peer inference requests (all peers).
pub const MAX_PENDING_INFERENCES: usize = 256;
/// PBA-L1b-005: upper bound on pending inference requests from one peer.
pub const MAX_PENDING_INFERENCES_PER_PEER: usize = 16;
/// PBA-L1b-005: a pending request no response has retired expires after this.
pub const PENDING_INFERENCE_TTL_SECS: u64 = 60;
/// Peer score penalty for an oversized AI announcement.
const SCORE_OVERSIZED_AI_ANNOUNCE: i32 = -5;

/// Result of a network inference execution.
#[derive(Debug, Clone)]
pub struct NetworkInferenceResult {
    pub output: Vec<u8>,
    pub proof: Option<Vec<u8>>,
    pub execution_time_ms: u64,
}

/// Trait for executing AI inference, implemented by the node crate to avoid
/// a network -> mcp circular dependency.
#[async_trait]
pub trait NetworkInferenceExecutor: Send + Sync {
    async fn execute_inference(
        &self,
        model_id: [u8; 32],
        input: Vec<u8>,
        provider: [u8; 32],
    ) -> Result<NetworkInferenceResult, anyhow::Error>;
}

/// Handler for AI-specific network messages
pub struct AINetworkHandler {
    /// State manager for AI state
    state_manager: Arc<StateManager>,

    /// Peer manager
    peer_manager: Arc<PeerManager>,

    /// Pending inference requests
    pending_inferences: Arc<RwLock<HashMap<Hash, InferenceRequest>>>,

    /// Active training jobs
    active_training: Arc<RwLock<HashMap<Hash, TrainingJob>>>,

    /// Model cache for quick lookups
    model_cache: Arc<RwLock<HashMap<Hash, ModelInfo>>>,

    /// Optional inference executor for running models via MCP/GGUF
    inference_executor: Option<Arc<dyn NetworkInferenceExecutor>>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct InferenceRequest {
    request_id: Hash,
    model_id: Hash,
    input_hash: Hash,
    requester: Vec<u8>,
    max_fee: u128,
    timestamp: u64,
    /// PBA-L1b-005: the peer that sent it (per-peer cap).
    from_peer: PeerId,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct TrainingJob {
    job_id: Hash,
    model_id: Hash,
    dataset_hash: Hash,
    participants: Vec<PeerId>,
    gradients_received: u32,
    gradients_required: u32,
    reward_per_gradient: u128,
    /// PBA-L1b-004: who announced it (per-peer quota) and when (expiry).
    announcer: PeerId,
    announced_at: std::time::Instant,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct ModelInfo {
    model_id: Hash,
    weight_cid: String,
    metadata: ModelMetadata,
    version: u32,
    providers: Vec<PeerId>,
    /// PBA-L1b-004: who announced it (per-peer quota) and when (expiry).
    announcer: PeerId,
    announced_at: std::time::Instant,
}

/// Bytes an announcement asks us to hold, for the size cap.
fn announcement_bytes(owner: &[u8], metadata: &ModelMetadata, weight_cid: &str) -> usize {
    owner.len()
        + metadata.name.len()
        + metadata.version.len()
        + metadata.description.len()
        + metadata.framework.len()
        + (metadata.input_shape.len() + metadata.output_shape.len()) * 8
        + weight_cid.len()
}

impl AINetworkHandler {
    pub fn new(state_manager: Arc<StateManager>, peer_manager: Arc<PeerManager>) -> Self {
        Self {
            state_manager,
            peer_manager,
            pending_inferences: Arc::new(RwLock::new(HashMap::new())),
            active_training: Arc::new(RwLock::new(HashMap::new())),
            model_cache: Arc::new(RwLock::new(HashMap::new())),
            inference_executor: None,
        }
    }

    /// Attach an inference executor for handling inference requests via MCP/GGUF.
    pub fn with_inference_executor(mut self, executor: Arc<dyn NetworkInferenceExecutor>) -> Self {
        self.inference_executor = Some(executor);
        self
    }

    /// Number of peer model announcements currently cached (PBA-L1b-004).
    pub async fn cached_model_count(&self) -> usize {
        self.model_cache.read().await.len()
    }

    /// Whether a (non-expired) peer announcement for `model_id` is cached.
    pub async fn has_cached_model(&self, model_id: &Hash) -> bool {
        self.model_cache
            .read()
            .await
            .get(model_id)
            .is_some_and(|m| m.announced_at.elapsed() < MODEL_ANNOUNCE_TTL)
    }

    /// Number of inference requests currently pending (PBA-L1b-005).
    pub async fn pending_inference_count(&self) -> usize {
        self.pending_inferences.read().await.len()
    }

    /// Number of peer training-job announcements currently tracked.
    pub async fn active_training_count(&self) -> usize {
        self.active_training.read().await.len()
    }

    /// Handle incoming AI network message
    pub async fn handle_message(
        &self,
        peer_id: &PeerId,
        message: &NetworkMessage,
    ) -> Result<Option<NetworkMessage>> {
        match message {
            NetworkMessage::ModelAnnounce {
                model_id,
                model_hash,
                owner,
                metadata,
                weight_cid,
            } => {
                self.handle_model_announce(
                    peer_id,
                    *model_id,
                    *model_hash,
                    owner,
                    metadata.clone(),
                    weight_cid.clone(),
                )
                .await
            }

            NetworkMessage::InferenceRequest {
                request_id,
                model_id,
                input_hash,
                requester,
                max_fee,
            } => {
                self.handle_inference_request(
                    peer_id,
                    *request_id,
                    *model_id,
                    *input_hash,
                    requester.clone(),
                    *max_fee,
                )
                .await
            }

            NetworkMessage::InferenceResponse {
                request_id,
                output_hash,
                proof,
                provider,
            } => {
                self.handle_inference_response(
                    peer_id,
                    *request_id,
                    *output_hash,
                    proof.clone(),
                    provider.clone(),
                )
                .await
            }

            NetworkMessage::TrainingJobAnnounce {
                job_id,
                model_id,
                dataset_hash,
                participants_needed,
                reward_per_gradient,
                owner,
            } => {
                self.handle_training_announce(
                    peer_id,
                    *job_id,
                    *model_id,
                    *dataset_hash,
                    *participants_needed,
                    *reward_per_gradient,
                    *owner,
                )
                .await
            }

            NetworkMessage::GradientSubmission {
                job_id,
                gradient_hash,
                epoch,
                participant,
            } => {
                self.handle_gradient_submission(
                    peer_id,
                    *job_id,
                    *gradient_hash,
                    *epoch,
                    participant.clone(),
                )
                .await
            }

            NetworkMessage::WeightSync {
                model_id,
                version,
                weight_delta,
            } => {
                self.handle_weight_sync(peer_id, *model_id, *version, weight_delta.clone())
                    .await
            }

            _ => Ok(None), // Not an AI message
        }
    }

    /// Handle model announcement
    async fn handle_model_announce(
        &self,
        peer_id: &PeerId,
        model_id: Hash,
        model_hash: Hash,
        owner: &[u8],
        metadata: ModelMetadata,
        weight_cid: String,
    ) -> Result<Option<NetworkMessage>> {
        debug!(
            "Received model announcement from peer {}: model_id={:?}",
            peer_id, model_id
        );

        // PBA-L1b-004: size cap first — never hold attacker-sized fields.
        let bytes = announcement_bytes(owner, &metadata, &weight_cid);
        if bytes > MAX_ANNOUNCE_METADATA_BYTES {
            warn!(
                "PBA-L1b-004: dropping oversized ModelAnnounce from {} ({} bytes > {})",
                peer_id, bytes, MAX_ANNOUNCE_METADATA_BYTES
            );
            self.peer_manager
                .update_peer_score(peer_id, SCORE_OVERSIZED_AI_ANNOUNCE)
                .await;
            return Ok(None);
        }
        let _ = (owner, model_hash); // advisory only: never persisted as a model record

        let now = std::time::Instant::now();
        let mut cache = self.model_cache.write().await;
        cache.retain(|_, m| now.duration_since(m.announced_at) < MODEL_ANNOUNCE_TTL);

        // Known model: record this peer as a provider (bounded).
        if let Some(existing) = cache.get_mut(&model_id) {
            if !existing.providers.contains(peer_id)
                && existing.providers.len() < MAX_PROVIDERS_PER_MODEL
            {
                existing.providers.push(peer_id.clone());
            }
            return Ok(None);
        }

        // New model: per-peer quota, then the global cap (oldest evicted).
        let from_peer = cache.values().filter(|m| &m.announcer == peer_id).count();
        if from_peer >= MAX_MODELS_PER_PEER {
            debug!(
                "PBA-L1b-004: {} is at its announcement quota ({}); dropping {}",
                peer_id, MAX_MODELS_PER_PEER, model_id
            );
            return Ok(None);
        }
        if cache.len() >= MAX_CACHED_MODELS {
            if let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, m)| m.announced_at)
                .map(|(k, _)| *k)
            {
                cache.remove(&oldest);
            }
        }
        cache.insert(
            model_id,
            ModelInfo {
                model_id,
                weight_cid,
                metadata,
                version: 1,
                providers: vec![peer_id.clone()],
                announcer: peer_id.clone(),
                announced_at: now,
            },
        );
        debug!("Cached peer model announcement {} from {}", model_id, peer_id);

        Ok(None)
    }

    /// Handle inference request
    async fn handle_inference_request(
        &self,
        peer_id: &PeerId,
        request_id: Hash,
        model_id: Hash,
        input_hash: Hash,
        requester: Vec<u8>,
        max_fee: u128,
    ) -> Result<Option<NetworkMessage>> {
        debug!(
            "Received inference request {} for model {} from peer {}",
            request_id, model_id, peer_id
        );

        // Store pending request — PBA-L1b-005: bounded (global + per-peer
        // caps) and expiring; this map used to grow without limit.
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        {
            let mut pending = self.pending_inferences.write().await;
            pending.retain(|_, r| now.saturating_sub(r.timestamp) < PENDING_INFERENCE_TTL_SECS);
            if !pending.contains_key(&request_id) {
                let from_peer = pending.values().filter(|r| &r.from_peer == peer_id).count();
                if from_peer >= MAX_PENDING_INFERENCES_PER_PEER {
                    debug!(
                        "PBA-L1b-005: {} has {} pending inference requests; dropping {}",
                        peer_id, from_peer, request_id
                    );
                    return Ok(None);
                }
                if pending.len() >= MAX_PENDING_INFERENCES {
                    if let Some(oldest) = pending
                        .iter()
                        .min_by_key(|(_, r)| r.timestamp)
                        .map(|(k, _)| *k)
                    {
                        pending.remove(&oldest);
                    }
                }
            }
            pending.insert(
                request_id,
                InferenceRequest {
                    request_id,
                    model_id,
                    input_hash,
                    requester: requester.clone(),
                    max_fee,
                    timestamp: now,
                    from_peer: peer_id.clone(),
                },
            );
        }

        // Check if we can serve this inference: a locally registered model, or
        // a live (bounded, expiring) peer announcement (PBA-L1b-004: peer
        // announcements are no longer persisted as model records).
        if self.state_manager.get_model(&ModelId(model_id)).is_some()
            || self.has_cached_model(&model_id).await
        {
            debug!("Running inference for model {}", model_id);

            // Use the pluggable inference executor (MCP/GGUF backed)
            if let Some(ref executor) = self.inference_executor {
                // Build a provider key from the input hash (32 bytes)
                let provider_key = *input_hash.as_bytes();

                match executor
                    .execute_inference(*model_id.as_bytes(), input_hash.as_bytes().to_vec(), provider_key)
                    .await
                {
                    Ok(result) => {
                        info!(
                            "Inference completed for request {} in {}ms",
                            request_id, result.execution_time_ms
                        );

                        // Hash the output to produce a fixed-size 32-byte identifier
                        let output_hash = {
                            use sha3::{Digest, Sha3_256};
                            let mut hasher = Sha3_256::new();
                            hasher.update(&result.output);
                            Hash::new(hasher.finalize().into())
                        };

                        let proof = result.proof.unwrap_or_default();
                        let provider = model_id.as_bytes().to_vec();

                        return Ok(Some(NetworkMessage::InferenceResponse {
                            request_id,
                            output_hash,
                            proof,
                            provider,
                        }));
                    }
                    Err(e) => {
                        warn!("Inference execution failed for request {}: {}", request_id, e);
                    }
                }
            } else {
                debug!("No inference executor configured, skipping inference request for model {}", model_id);
            }
        }

        Ok(None)
    }

    /// Handle inference response
    async fn handle_inference_response(
        &self,
        peer_id: &PeerId,
        request_id: Hash,
        _output_hash: Hash,
        proof: Vec<u8>,
        _provider: Vec<u8>,
    ) -> Result<Option<NetworkMessage>> {
        debug!(
            "Received inference response {} from peer {}",
            request_id, peer_id
        );

        // Check if we have this pending request
        let mut pending = self.pending_inferences.write().await;
        if let Some(request) = pending.remove(&request_id) {
            // PBA-L1b-004 variant: a peer's response is an unauthenticated
            // claim (an attacker can pair its own request + response ids). It
            // retires the pending entry; it is never persisted.
            debug!(
                "Inference response {} for model {} from {} ({} proof bytes); not persisted",
                request_id,
                request.model_id,
                peer_id,
                proof.len()
            );
        }

        Ok(None)
    }

    /// Handle training job announcement
    #[allow(clippy::too_many_arguments)]
    async fn handle_training_announce(
        &self,
        peer_id: &PeerId,
        job_id: Hash,
        model_id: Hash,
        dataset_hash: Hash,
        participants_needed: u32,
        reward_per_gradient: u128,
        owner: [u8; 20],
    ) -> Result<Option<NetworkMessage>> {
        debug!(
            "Received training job {} announcement from peer {} with owner {:02x?}",
            job_id, peer_id, owner
        );

        // PBA-L1b-004 variant: bounded, expiring, in memory only — the
        // unauthenticated announcement (with a peer-chosen `owner`) used to be
        // written to persistent state per fresh job id.
        let _ = owner;
        let now = std::time::Instant::now();
        let mut training = self.active_training.write().await;
        training.retain(|_, j| now.duration_since(j.announced_at) < MODEL_ANNOUNCE_TTL);
        if training.contains_key(&job_id) {
            return Ok(None);
        }
        let from_peer = training.values().filter(|j| &j.announcer == peer_id).count();
        if from_peer >= MAX_TRAINING_JOBS_PER_PEER {
            debug!("PBA-L1b-004: {} is at its training-announce quota", peer_id);
            return Ok(None);
        }
        if training.len() >= MAX_TRAINING_JOBS {
            if let Some(oldest) = training
                .iter()
                .min_by_key(|(_, j)| j.announced_at)
                .map(|(k, _)| *k)
            {
                training.remove(&oldest);
            }
        }
        training.insert(
            job_id,
            TrainingJob {
                job_id,
                model_id,
                dataset_hash,
                participants: vec![peer_id.clone()],
                gradients_received: 0,
                gradients_required: participants_needed,
                reward_per_gradient,
                announcer: peer_id.clone(),
                announced_at: now,
            },
        );

        Ok(None)
    }

    /// Handle gradient submission
    async fn handle_gradient_submission(
        &self,
        peer_id: &PeerId,
        job_id: Hash,
        gradient_hash: Hash,
        epoch: u32,
        participant: Vec<u8>,
    ) -> Result<Option<NetworkMessage>> {
        debug!(
            "Received gradient submission for job {} epoch {} from peer {}",
            job_id, epoch, peer_id
        );

        let _ = participant;
        // PBA-L1b-004 variant: in-memory bookkeeping on a bounded, expiring
        // announcement only; a peer's gradient claim is never persisted.
        let known = {
            let mut training = self.active_training.write().await;
            match training.get_mut(&job_id) {
                Some(job) => {
                    job.gradients_received = job.gradients_received.saturating_add(1);
                    if !job.participants.contains(peer_id)
                        && job.participants.len() < MAX_PROVIDERS_PER_MODEL
                    {
                        job.participants.push(peer_id.clone());
                    }
                    debug!(
                        "Job {} now has {}/{} gradients from {} participants",
                        job_id,
                        job.gradients_received,
                        job.gradients_required,
                        job.participants.len()
                    );
                    true
                }
                None => false,
            }
        };
        if known {
            self.store_gradient_reference(job_id, gradient_hash, epoch).await?;
        }

        Ok(None)
    }

    /// Store gradient reference for later aggregation
    async fn store_gradient_reference(
        &self,
        job_id: Hash,
        gradient_hash: Hash,
        epoch: u32,
    ) -> Result<()> {
        // Gradients are stored off-chain (IPFS) and referenced by hash
        // Here we track which gradients we've received for a job
        debug!(
            "Stored gradient reference {} for job {} epoch {}",
            gradient_hash, job_id, epoch
        );
        Ok(())
    }

    /// Handle weight synchronization
    async fn handle_weight_sync(
        &self,
        peer_id: &PeerId,
        model_id: Hash,
        version: u32,
        weight_delta: Vec<u8>,
    ) -> Result<Option<NetworkMessage>> {
        debug!(
            "Received weight sync for model {} version {} ({} bytes) from peer {}",
            model_id, version, weight_delta.len(), peer_id
        );

        // Check if we should accept this update
        let should_update = {
            let cache = self.model_cache.read().await;
            if let Some(model_info) = cache.get(&model_id) {
                version > model_info.version
            } else {
                // Unknown model, accept if we have it registered in state
                self.state_manager.get_model(&ModelId(model_id)).is_some()
            }
        };

        if !should_update {
            debug!(
                "Ignoring weight sync for model {} - not newer than current version",
                model_id
            );
            return Ok(None);
        }

        // Compute new weight CID by hashing the delta
        // In production, this would involve applying the delta to get new weights
        // and storing them on IPFS to get the actual CID
        let new_weight_cid = self.compute_new_weight_cid(&model_id, &weight_delta, version);

        // PBA-L1b-004 variant: an unauthenticated peer's weight update is
        // never written to persistent state (it used to overwrite the weight
        // CID of any locally registered model). It only refreshes the bounded
        // in-memory announcement cache below.

        // Update local cache
        let mut cache = self.model_cache.write().await;
        if let Some(model_info) = cache.get_mut(&model_id) {
            model_info.version = version;
            model_info.weight_cid = new_weight_cid.clone();
            debug!(
                "Updated model {} to version {} with new CID {}",
                model_id, version, new_weight_cid
            );
        }

        // Note: We don't automatically re-broadcast weight updates to prevent
        // infinite propagation loops. The original sender is responsible for
        // broadcasting to all necessary peers. If we need to propagate, we should
        // implement a proper gossip protocol with TTL or seen-message tracking.

        debug!(
            "Successfully applied weight sync for model {} to version {}",
            model_id, version
        );

        Ok(None)
    }

    /// Compute new weight CID from delta
    fn compute_new_weight_cid(&self, model_id: &Hash, weight_delta: &[u8], version: u32) -> String {
        // In production, this would:
        // 1. Retrieve current model weights from storage
        // 2. Apply the delta (e.g., federated averaging, gradient update)
        // 3. Store updated weights on IPFS
        // 4. Return the new CID

        // For now, create a deterministic CID from the inputs
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash as StdHash, Hasher};

        let mut hasher = DefaultHasher::new();
        model_id.as_bytes().hash(&mut hasher);
        weight_delta.hash(&mut hasher);
        version.hash(&mut hasher);

        format!("Qm{:x}{:08x}", hasher.finish(), version)
    }

    /// Broadcast weight synchronization to peers
    /// Note: Currently unused but kept for future gossip protocol implementation
    #[allow(dead_code)]
    async fn broadcast_weight_sync(
        &self,
        model_id: Hash,
        version: u32,
        weight_delta: Vec<u8>,
    ) -> Result<()> {
        let message = NetworkMessage::WeightSync {
            model_id,
            version,
            weight_delta,
        };

        self.peer_manager.broadcast(&message).await?;
        debug!(
            "Broadcasted weight sync for model {} version {}",
            model_id, version
        );

        Ok(())
    }

    /// Broadcast model announcement to peers
    pub async fn broadcast_model(
        &self,
        model_id: Hash,
        model_hash: Hash,
        owner: Vec<u8>,
        metadata: ModelMetadata,
        weight_cid: String,
    ) -> Result<()> {
        let message = NetworkMessage::ModelAnnounce {
            model_id,
            model_hash,
            owner,
            metadata,
            weight_cid,
        };

        self.peer_manager.broadcast(&message).await?;
        info!("Broadcasted model {} announcement", model_id);

        Ok(())
    }

    /// Request inference from network
    pub async fn request_inference(
        &self,
        model_id: Hash,
        input_hash: Hash,
        requester: Vec<u8>,
        max_fee: u128,
    ) -> Result<Hash> {
        let request_id = Hash::new(rand::random());

        let message = NetworkMessage::InferenceRequest {
            request_id,
            model_id,
            input_hash,
            requester,
            max_fee,
        };

        self.peer_manager.broadcast(&message).await?;
        info!(
            "Broadcasted inference request {} for model {}",
            request_id, model_id
        );

        Ok(request_id)
    }

    /// Retrieve input data for inference from off-chain storage
    #[allow(dead_code)]
    async fn retrieve_input_data(&self, input_hash: &Hash) -> Result<Vec<f32>> {
        // In production, this would:
        // 1. Look up the input data location by hash (IPFS CID, Arweave TX, etc.)
        // 2. Fetch the data from distributed storage
        // 3. Deserialize and validate the input format
        // 4. Apply any necessary preprocessing

        // For now, simulate retrieving data based on hash
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash as StdHash, Hasher};

        let mut hasher = DefaultHasher::new();
        input_hash.as_bytes().hash(&mut hasher);
        let hash_value = hasher.finish();

        // Generate deterministic "input data" based on hash
        // This simulates actual data retrieval from off-chain storage
        let data_size = (hash_value % 1000 + 100) as usize; // 100-1099 elements
        let mut input_data = Vec::with_capacity(data_size);

        for i in 0..data_size {
            // Generate deterministic but varied input values
            let val = ((hash_value.wrapping_add(i as u64) % 1000) as f32) / 1000.0;
            input_data.push(val);
        }

        debug!("Retrieved {} input values for hash {:?}", data_size, input_hash);
        Ok(input_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_execution::{AccessPolicy, Address, ModelState, UsageStats};
    use citrate_network_test_helpers::*;

    // ---- test helpers inlined to avoid extra crate ----
    mod citrate_network_test_helpers {
        use super::*;

        /// A mock inference executor that returns a predetermined result.
        pub struct MockInferenceExecutor {
            pub output: Vec<u8>,
            pub proof: Option<Vec<u8>>,
            pub execution_time_ms: u64,
            pub should_fail: bool,
        }

        impl MockInferenceExecutor {
            pub fn success(output: Vec<u8>) -> Self {
                Self {
                    output,
                    proof: Some(b"mock_proof".to_vec()),
                    execution_time_ms: 42,
                    should_fail: false,
                }
            }

            pub fn failing() -> Self {
                Self {
                    output: vec![],
                    proof: None,
                    execution_time_ms: 0,
                    should_fail: true,
                }
            }
        }

        #[async_trait]
        impl NetworkInferenceExecutor for MockInferenceExecutor {
            async fn execute_inference(
                &self,
                _model_id: [u8; 32],
                _input: Vec<u8>,
                _provider: [u8; 32],
            ) -> Result<NetworkInferenceResult, anyhow::Error> {
                if self.should_fail {
                    return Err(anyhow::anyhow!("mock executor failure"));
                }
                Ok(NetworkInferenceResult {
                    output: self.output.clone(),
                    proof: self.proof.clone(),
                    execution_time_ms: self.execution_time_ms,
                })
            }
        }

        /// Build a minimal AINetworkHandler backed by in-memory stores.
        pub fn make_handler(
            executor: Option<Arc<dyn NetworkInferenceExecutor>>,
        ) -> AINetworkHandler {
            let storage = Arc::new(
                citrate_storage::StorageManager::new(
                    tempfile::TempDir::new().unwrap().path(),
                    citrate_storage::pruning::PruningConfig::default(),
                )
                .unwrap(),
            );
            let state_manager = Arc::new(StateManager::new(storage.db.clone()));
            let peer_manager = Arc::new(PeerManager::new(
                crate::peer::PeerManagerConfig::default(),
            ));
            let mut handler = AINetworkHandler::new(state_manager, peer_manager);
            if let Some(exec) = executor {
                handler.inference_executor = Some(exec);
            }
            handler
        }

        /// Register a model in the state_manager so inference requests can find it.
        pub fn register_model_in_handler(handler: &AINetworkHandler, model_id: Hash) {
            let exec_meta = citrate_execution::ModelMetadata {
                name: "test-model".to_string(),
                version: "1.0.0".to_string(),
                description: "unit test model".to_string(),
                framework: "gguf".to_string(),
                input_shape: vec![1],
                output_shape: vec![1],
                size_bytes: 1024,
                created_at: 0,
            };
            let model_state = ModelState {
                owner: Address([0u8; 20]),
                model_hash: Hash::default(),
                version: 1,
                metadata: exec_meta,
                access_policy: AccessPolicy::Public,
                usage_stats: UsageStats::default(),
            };
            handler
                .state_manager
                .register_model(
                    ModelId(model_id),
                    model_state,
                    "QmTestCID".to_string(),
                )
                .unwrap();
        }
    }

    #[tokio::test]
    async fn test_inference_with_executor() {
        let expected_output = b"hello inference".to_vec();
        let executor = Arc::new(MockInferenceExecutor::success(expected_output.clone()));
        let handler = make_handler(Some(executor));

        let model_id = Hash::new([1u8; 32]);
        register_model_in_handler(&handler, model_id);

        let peer = PeerId::new("peer-a".to_string());
        let request = NetworkMessage::InferenceRequest {
            request_id: Hash::new([99u8; 32]),
            model_id,
            input_hash: Hash::new([5u8; 32]),
            requester: vec![0xAA; 20],
            max_fee: 1000,
        };

        let response = handler.handle_message(&peer, &request).await.unwrap();
        assert!(response.is_some(), "Should produce an InferenceResponse");

        match response.unwrap() {
            NetworkMessage::InferenceResponse {
                request_id,
                proof,
                ..
            } => {
                assert_eq!(request_id, Hash::new([99u8; 32]));
                assert_eq!(proof, b"mock_proof".to_vec());
            }
            other => panic!("Expected InferenceResponse, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_inference_without_executor() {
        let handler = make_handler(None);

        let model_id = Hash::new([2u8; 32]);
        register_model_in_handler(&handler, model_id);

        let peer = PeerId::new("peer-b".to_string());
        let request = NetworkMessage::InferenceRequest {
            request_id: Hash::new([88u8; 32]),
            model_id,
            input_hash: Hash::new([6u8; 32]),
            requester: vec![0xBB; 20],
            max_fee: 500,
        };

        let response = handler.handle_message(&peer, &request).await.unwrap();
        assert!(
            response.is_none(),
            "Without executor, should return Ok(None)"
        );
    }

    #[tokio::test]
    async fn test_inference_executor_error() {
        let executor = Arc::new(MockInferenceExecutor::failing());
        let handler = make_handler(Some(executor));

        let model_id = Hash::new([3u8; 32]);
        register_model_in_handler(&handler, model_id);

        let peer = PeerId::new("peer-c".to_string());
        let request = NetworkMessage::InferenceRequest {
            request_id: Hash::new([77u8; 32]),
            model_id,
            input_hash: Hash::new([7u8; 32]),
            requester: vec![0xCC; 20],
            max_fee: 200,
        };

        let response = handler.handle_message(&peer, &request).await.unwrap();
        assert!(
            response.is_none(),
            "Executor error should gracefully return Ok(None)"
        );
    }
}
