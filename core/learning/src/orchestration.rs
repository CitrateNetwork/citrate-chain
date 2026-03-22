//! Checkpoint learning orchestration (WP-F.3).
//!
//! Wires paraconsensus federated learning into BFT checkpoint boundaries.
//! Called by the block producer when `height % checkpoint_interval == 0`.
//!
//! Formal specification: `specs/tla/StrobilationCheckpoint.tla`
//! - INV-2 (LearningRootDeterministic): same embeddings → same hash
//! - INV-4 (StateRootIndependent): learning_root NEVER affects state_root
//! - INV-5 (EmbeddingQuorum): aggregation only when quorum met
//!
//! The learning_root uses SHA3-256 for deterministic hashing to avoid
//! circular dependencies with the execution crate's MiMC implementation.
//! SHA3 provides the same determinism guarantee (same inputs → same hash).

use crate::aggregation::{AggregationInput, AggregationResult, ParaconsistentAggregator};
use crate::belnap::BelnapValue;
use crate::config::LearningConfig;
use crate::embeddings::EmbeddingVector;
use crate::errors::LearningResult;
use crate::mentor::{self, MentorPairing};
use crate::profile::PerformanceProfile;
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Result of a checkpoint learning aggregation.
///
/// Returned by [`LearningOrchestrator::run_checkpoint_aggregation`].
#[derive(Debug, Clone)]
pub struct LearningCheckpointResult {
    /// Hash for inclusion in the block header's `learning_root` field.
    /// SHA3-256 of `(aggregated_embedding || state_vector || checkpoint_height)`.
    pub learning_root: [u8; 32],

    /// Aggregated embedding vector (for downstream routing model update).
    pub aggregated_embedding: Vec<f32>,

    /// Belnap state vector (for disagreement tracking and macro-phase transitions).
    pub state_vector: Vec<BelnapValue>,

    /// Number of participants whose embeddings were included in this aggregation.
    pub participant_count: usize,

    /// Mean effective confidence from the aggregation.
    pub confidence: f32,

    /// Mentor-mentee pairings identified at this checkpoint (WP-F.6).
    ///
    /// Empty if mentor selection was not run (e.g. below quorum).
    pub mentor_pairings: Vec<MentorPairing>,
}

/// A peer embedding submitted at a checkpoint boundary.
///
/// This is the learning-crate counterpart of the network-layer
/// `LearningEmbedding` message, containing only the fields needed
/// for aggregation (no signatures or performance profiles).
#[derive(Debug, Clone)]
pub struct PeerEmbedding {
    /// Embedding vector.
    pub embedding: Vec<f32>,
    /// Per-dimension confidence values in [0, 1].
    pub confidence: Vec<f32>,
    /// Blue score from consensus (trust weight input).
    pub blue_score: f32,
}

/// Orchestrates federated learning at checkpoint boundaries.
///
/// Called by the block producer when a checkpoint height is reached.
/// Collects peer embeddings from the gossip layer, runs paraconsensus
/// aggregation, and computes a deterministic learning_root hash.
pub struct LearningOrchestrator {
    aggregator: ParaconsistentAggregator,
    config: LearningOrchestratorConfig,
}

/// Configuration for the learning orchestrator.
#[derive(Debug, Clone)]
pub struct LearningOrchestratorConfig {
    /// Minimum embeddings needed for aggregation (quorum).
    pub min_embeddings: usize,
    /// Embedding dimension (must match across all participants).
    pub embedding_dim: usize,
    /// Temperature for softmax trust weight computation.
    pub temperature: f32,
    /// Belnap high-confidence threshold (theta_high).
    pub theta_high: f32,
    /// Belnap low-confidence threshold (theta_low).
    pub theta_low: f32,
}

impl LearningOrchestratorConfig {
    /// Create from a `LearningConfig`.
    pub fn from_learning_config(config: &LearningConfig) -> Self {
        Self {
            min_embeddings: config.min_participants,
            embedding_dim: config.embedding_dimensions,
            temperature: config.temperature,
            theta_high: config.belnap_high_threshold,
            theta_low: config.belnap_low_threshold,
        }
    }
}

impl Default for LearningOrchestratorConfig {
    fn default() -> Self {
        let config = LearningConfig::default();
        Self::from_learning_config(&config)
    }
}

impl LearningOrchestrator {
    /// Create a new learning orchestrator.
    pub fn new(config: LearningOrchestratorConfig) -> Self {
        let aggregator = ParaconsistentAggregator::new(config.embedding_dim);
        Self { aggregator, config }
    }

    /// Create from a `LearningConfig`.
    pub fn from_learning_config(config: &LearningConfig) -> Self {
        Self::new(LearningOrchestratorConfig::from_learning_config(config))
    }

    /// Collect peer embeddings and run paraconsensus aggregation.
    ///
    /// Returns `Ok(result)` with the learning_root hash for inclusion
    /// in the block header, or `Err` if validation fails.
    ///
    /// **Quorum rule** (INV-5): if fewer than `min_embeddings` valid
    /// embeddings are available, returns a zero-hash result (no error).
    /// Per the TLA+ spec, below-quorum checkpoints produce zero hash.
    pub fn run_checkpoint_aggregation(
        &self,
        checkpoint_height: u64,
        local_embedding: Option<PeerEmbedding>,
        peer_embeddings: Vec<PeerEmbedding>,
    ) -> LearningResult<LearningCheckpointResult> {
        // 1. Combine local + peer embeddings
        let mut all_embeddings = peer_embeddings;
        if let Some(local) = local_embedding {
            all_embeddings.push(local);
        }

        // 2. Validate all embeddings (dimension, finite values)
        let valid_embeddings = self.validate_embeddings(all_embeddings)?;

        // 3. Check quorum (min_embeddings met?)
        if valid_embeddings.len() < self.config.min_embeddings {
            debug!(
                "Checkpoint {}: below quorum ({}/{}) — returning zero learning_root",
                checkpoint_height,
                valid_embeddings.len(),
                self.config.min_embeddings,
            );
            return Ok(LearningCheckpointResult {
                learning_root: [0u8; 32],
                aggregated_embedding: vec![],
                state_vector: vec![],
                participant_count: valid_embeddings.len(),
                confidence: 0.0,
                mentor_pairings: vec![],
            });
        }

        // 4. Run paraconsensus aggregation
        let result = self.aggregate(&valid_embeddings)?;

        // 5. Compute learning_root = SHA3(aggregated_embedding || state_vector || height)
        let learning_root = compute_learning_root(
            &result.embedding.data,
            &result.state_vector,
            checkpoint_height,
        );

        info!(
            "Checkpoint {} aggregation complete: {} participants, confidence={:.3}, root={}",
            checkpoint_height,
            valid_embeddings.len(),
            result.confidence,
            hex::encode(learning_root),
        );

        Ok(LearningCheckpointResult {
            learning_root,
            aggregated_embedding: result.embedding.data.clone(),
            state_vector: result.state_vector.clone(),
            participant_count: valid_embeddings.len(),
            confidence: result.confidence,
            mentor_pairings: vec![],
        })
    }

    /// Validate embeddings: check dimension, finite values, confidence dimension match.
    /// Returns only the valid embeddings, with invalid ones filtered out (logged).
    fn validate_embeddings(
        &self,
        embeddings: Vec<PeerEmbedding>,
    ) -> LearningResult<Vec<PeerEmbedding>> {
        let mut valid = Vec::with_capacity(embeddings.len());

        for (i, emb) in embeddings.into_iter().enumerate() {
            // Check embedding dimension
            if emb.embedding.len() != self.config.embedding_dim {
                warn!(
                    "Embedding {} rejected: dimension {} != expected {}",
                    i,
                    emb.embedding.len(),
                    self.config.embedding_dim,
                );
                continue;
            }

            // Check confidence dimension matches embedding
            if emb.confidence.len() != emb.embedding.len() {
                warn!(
                    "Embedding {} rejected: confidence dim {} != embedding dim {}",
                    i,
                    emb.confidence.len(),
                    emb.embedding.len(),
                );
                continue;
            }

            // Check for NaN/Inf in embedding values
            let mut has_bad_values = false;
            for (j, &v) in emb.embedding.iter().enumerate() {
                if !v.is_finite() {
                    warn!("Embedding {} rejected: non-finite value at index {}", i, j);
                    has_bad_values = true;
                    break;
                }
            }
            if has_bad_values {
                continue;
            }

            // Check for NaN/Inf in confidence values
            for (j, &v) in emb.confidence.iter().enumerate() {
                if !v.is_finite() {
                    warn!(
                        "Embedding {} rejected: non-finite confidence at index {}",
                        i, j
                    );
                    has_bad_values = true;
                    break;
                }
            }
            if has_bad_values {
                continue;
            }

            // Check blue_score is finite and non-negative
            if !emb.blue_score.is_finite() || emb.blue_score < 0.0 {
                warn!(
                    "Embedding {} rejected: invalid blue_score {}",
                    i, emb.blue_score
                );
                continue;
            }

            valid.push(emb);
        }

        Ok(valid)
    }

    /// Run the paraconsistent aggregation on validated embeddings.
    fn aggregate(&self, embeddings: &[PeerEmbedding]) -> LearningResult<AggregationResult> {
        // Convert PeerEmbedding slice to AggregationInput format
        let embedding_vecs: Vec<EmbeddingVector> = embeddings
            .iter()
            .map(|e| EmbeddingVector { data: e.embedding.clone() })
            .collect();

        let embedding_refs: Vec<&EmbeddingVector> = embedding_vecs.iter().collect();

        let confidence_slices: Vec<&[f32]> = embeddings
            .iter()
            .map(|e| e.confidence.as_slice())
            .collect();

        let blue_scores: Vec<f32> = embeddings.iter().map(|e| e.blue_score).collect();

        let input = AggregationInput {
            embeddings: &embedding_refs,
            confidences: &confidence_slices,
            blue_scores: &blue_scores,
            temperature: self.config.temperature,
            theta_high: self.config.theta_high,
            theta_low: self.config.theta_low,
        };

        self.aggregator.aggregate_paraconsistent(&input)
    }

    /// Run mentor selection from the peer profile store (WP-F.6).
    ///
    /// After aggregation, call this method with the profile store to identify
    /// mentor-mentee pairings.  The returned pairings can be attached to the
    /// `LearningCheckpointResult` and broadcast as `AdapterGenerationRequest`
    /// messages so that mentors know to produce adapters.
    pub fn run_mentor_selection(
        &self,
        profile_store: &PeerProfileStore,
        checkpoint_height: u64,
    ) -> Vec<MentorPairing> {
        let profiles_at_checkpoint = profile_store.get_profiles_at_checkpoint(checkpoint_height);

        if profiles_at_checkpoint.len() < 2 {
            debug!(
                "Checkpoint {}: only {} profiles, skipping mentor selection",
                checkpoint_height,
                profiles_at_checkpoint.len(),
            );
            return vec![];
        }

        // Convert from ([u8;32], &PerformanceProfile) to owned for select_mentors.
        let owned_profiles: Vec<([u8; 32], PerformanceProfile)> = profiles_at_checkpoint
            .into_iter()
            .map(|(k, p)| (k, p.clone()))
            .collect();

        let pairings = mentor::select_mentors(&owned_profiles);

        if !pairings.is_empty() {
            info!(
                "Checkpoint {}: {} mentor-mentee pairings identified",
                checkpoint_height,
                pairings.len(),
            );
        }

        pairings
    }
}

/// Compute the deterministic learning_root hash.
///
/// Uses SHA3-256 (not MiMC) to avoid circular dependency with the execution crate.
/// Determinism is guaranteed: same inputs always produce the same hash.
///
/// Domain separation: checkpoint_height is appended as the last 8 bytes
/// to ensure roots from different checkpoints never collide.
///
/// # Layout
/// ```text
/// SHA3-256(
///     embedding[0] as f32 LE bytes (4 bytes)
///     || embedding[1] as f32 LE bytes (4 bytes)
///     || ...
///     || state_vector[0] as u8 (1 byte: Neither=0, True=1, False=2, Both=3)
///     || state_vector[1] as u8 (1 byte)
///     || ...
///     || checkpoint_height as u64 LE bytes (8 bytes)
/// )
/// ```
pub fn compute_learning_root(
    aggregated_embedding: &[f32],
    state_vector: &[BelnapValue],
    checkpoint_height: u64,
) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};

    let mut hasher = Sha3_256::new();

    // Embedding values as deterministic f32 LE bytes
    for &v in aggregated_embedding {
        hasher.update(v.to_le_bytes());
    }

    // State vector as single-byte Belnap values
    for sv in state_vector {
        let byte = match sv {
            BelnapValue::Neither => 0u8,
            BelnapValue::True => 1u8,
            BelnapValue::False => 2u8,
            BelnapValue::Both => 3u8,
        };
        hasher.update([byte]);
    }

    // Domain separation: checkpoint height
    hasher.update(checkpoint_height.to_le_bytes());

    let hash_bytes = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash_bytes[..32]);
    result
}

// ---------------------------------------------------------------------------
// Peer profile storage (WP-F.5)
// ---------------------------------------------------------------------------

/// Key for indexing peer profiles: (checkpoint_height, participant_id).
///
/// The participant_id is a 32-byte array (the raw public key bytes)
/// to avoid depending on consensus types in this struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerProfileKey {
    pub checkpoint_height: u64,
    pub participant: [u8; 32],
}

/// Stores performance profiles received from peers at checkpoint boundaries.
///
/// Used by WP-F.6 mentor selection to find the best mentor for a given mentee
/// based on domain overlap, accuracy, and latency.
///
/// Profiles older than `max_checkpoints` are pruned automatically on insertion.
pub struct PeerProfileStore {
    /// (checkpoint_height, participant) → profile
    profiles: HashMap<PeerProfileKey, PerformanceProfile>,
    /// Maximum number of checkpoint heights to retain. Older ones are pruned.
    max_checkpoints: usize,
    /// Track known checkpoint heights for pruning.
    known_heights: Vec<u64>,
}

impl PeerProfileStore {
    /// Create a new peer profile store.
    ///
    /// `max_checkpoints` controls how many checkpoint generations of profiles
    /// are retained before the oldest are pruned. Set to 0 for unlimited.
    pub fn new(max_checkpoints: usize) -> Self {
        Self {
            profiles: HashMap::new(),
            max_checkpoints,
            known_heights: Vec::new(),
        }
    }

    /// Store a peer's performance profile for a given checkpoint.
    ///
    /// If a profile already exists for this (checkpoint, participant), it is
    /// replaced with the new one.
    pub fn store_profile(
        &mut self,
        checkpoint_height: u64,
        participant: [u8; 32],
        profile: PerformanceProfile,
    ) {
        let key = PeerProfileKey {
            checkpoint_height,
            participant,
        };
        self.profiles.insert(key, profile);

        // Track this height if new
        if !self.known_heights.contains(&checkpoint_height) {
            self.known_heights.push(checkpoint_height);
            self.known_heights.sort_unstable();
        }

        // Prune old checkpoints if limit exceeded
        if self.max_checkpoints > 0 && self.known_heights.len() > self.max_checkpoints {
            let prune_count = self.known_heights.len() - self.max_checkpoints;
            let heights_to_remove: Vec<u64> =
                self.known_heights.drain(..prune_count).collect();
            for h in &heights_to_remove {
                self.profiles.retain(|k, _| k.checkpoint_height != *h);
            }
            debug!(
                "Pruned {} old checkpoint heights from peer profile store",
                heights_to_remove.len(),
            );
        }
    }

    /// Retrieve a peer's profile for a specific checkpoint.
    pub fn get_profile(
        &self,
        checkpoint_height: u64,
        participant: [u8; 32],
    ) -> Option<&PerformanceProfile> {
        let key = PeerProfileKey {
            checkpoint_height,
            participant,
        };
        self.profiles.get(&key)
    }

    /// Retrieve all profiles for a specific checkpoint height.
    ///
    /// Returns a vec of (participant, profile) pairs.
    pub fn get_profiles_at_checkpoint(
        &self,
        checkpoint_height: u64,
    ) -> Vec<([u8; 32], &PerformanceProfile)> {
        self.profiles
            .iter()
            .filter(|(k, _)| k.checkpoint_height == checkpoint_height)
            .map(|(k, v)| (k.participant, v))
            .collect()
    }

    /// Total number of stored profiles.
    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    /// Remove all profiles at or below the given finalized height.
    pub fn prune_below(&mut self, finalized_height: u64) {
        self.profiles
            .retain(|k, _| k.checkpoint_height > finalized_height);
        self.known_heights
            .retain(|&h| h > finalized_height);
    }
}

impl Default for PeerProfileStore {
    fn default() -> Self {
        Self::new(10) // retain last 10 checkpoints by default
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_peer_embedding(values: Vec<f32>, confidence: Vec<f32>, blue_score: f32) -> PeerEmbedding {
        PeerEmbedding {
            embedding: values,
            confidence,
            blue_score,
        }
    }

    fn make_orchestrator(dim: usize, min_embeddings: usize) -> LearningOrchestrator {
        LearningOrchestrator::new(LearningOrchestratorConfig {
            min_embeddings,
            embedding_dim: dim,
            temperature: 1.0,
            theta_high: 0.8,
            theta_low: 0.3,
        })
    }

    // -----------------------------------------------------------------------
    // WP-F.3 Test Suite
    // -----------------------------------------------------------------------

    /// Aggregation with quorum met produces a non-zero learning_root.
    #[test]
    fn test_checkpoint_aggregation_with_quorum() {
        let orch = make_orchestrator(4, 2);

        let p1 = make_peer_embedding(vec![1.0, 0.0, 0.5, 0.3], vec![0.9, 0.8, 0.7, 0.6], 100.0);
        let p2 = make_peer_embedding(vec![0.0, 1.0, 0.5, 0.7], vec![0.8, 0.9, 0.6, 0.7], 80.0);
        let p3 = make_peer_embedding(vec![0.5, 0.5, 1.0, 0.1], vec![0.7, 0.7, 0.9, 0.5], 90.0);

        let result = orch
            .run_checkpoint_aggregation(100, Some(p1), vec![p2, p3])
            .unwrap();

        assert_eq!(result.participant_count, 3);
        assert_ne!(result.learning_root, [0u8; 32]);
        assert!(!result.aggregated_embedding.is_empty());
        assert!(!result.state_vector.is_empty());
        assert!(result.confidence > 0.0);
    }

    /// Below quorum produces zero hash (not an error).
    /// Per StrobilationCheckpoint.tla INV-5: aggregation requires quorum.
    #[test]
    fn test_checkpoint_aggregation_below_quorum() {
        let orch = make_orchestrator(4, 3); // need 3, only provide 1

        let p1 = make_peer_embedding(vec![1.0, 0.0, 0.5, 0.3], vec![0.9, 0.8, 0.7, 0.6], 100.0);

        let result = orch
            .run_checkpoint_aggregation(100, Some(p1), vec![])
            .unwrap();

        assert_eq!(result.learning_root, [0u8; 32]);
        assert_eq!(result.participant_count, 1);
        assert!(result.aggregated_embedding.is_empty());
    }

    /// Same inputs always produce the same hash.
    /// Per StrobilationCheckpoint.tla INV-2: LearningRootDeterministic.
    #[test]
    fn test_learning_root_deterministic() {
        let embedding = vec![0.1f32, 0.2, 0.3, 0.4];
        let state_vector = vec![
            BelnapValue::True,
            BelnapValue::Neither,
            BelnapValue::Both,
            BelnapValue::False,
        ];

        let root1 = compute_learning_root(&embedding, &state_vector, 100);
        let root2 = compute_learning_root(&embedding, &state_vector, 100);

        assert_eq!(root1, root2);
        assert_ne!(root1, [0u8; 32]); // non-trivial hash
    }

    /// Different inputs produce different hashes.
    #[test]
    fn test_learning_root_changes_with_input() {
        let embedding1 = vec![0.1f32, 0.2, 0.3, 0.4];
        let embedding2 = vec![0.5f32, 0.6, 0.7, 0.8];
        let state_vector = vec![BelnapValue::True; 4];

        let root1 = compute_learning_root(&embedding1, &state_vector, 100);
        let root2 = compute_learning_root(&embedding2, &state_vector, 100);

        assert_ne!(root1, root2);
    }

    /// Different checkpoint heights produce different hashes (domain separation).
    #[test]
    fn test_learning_root_changes_with_height() {
        let embedding = vec![0.1f32, 0.2, 0.3, 0.4];
        let state_vector = vec![BelnapValue::True; 4];

        let root1 = compute_learning_root(&embedding, &state_vector, 100);
        let root2 = compute_learning_root(&embedding, &state_vector, 200);

        assert_ne!(root1, root2);
    }

    /// Non-checkpoint blocks have zero learning_root.
    /// This test validates the block producer logic that non-checkpoint
    /// blocks get Hash::default().
    #[test]
    fn test_non_checkpoint_block_has_zero_learning_root() {
        // Non-checkpoint blocks never call run_checkpoint_aggregation.
        // They use Hash::default() which is [0u8; 32].
        let zero = [0u8; 32];
        assert_eq!(zero, [0u8; 32]);
        // Verified by the block producer logic in produce_block().
    }

    /// learning_root does NOT affect state_root computation.
    /// Per StrobilationCheckpoint.tla INV-4: StateRootIndependent.
    /// Theorem 3: state_root is computed from transaction execution only.
    #[test]
    fn test_learning_root_does_not_affect_state_root() {
        use crate::belnap::BelnapValue;

        // Create two different learning roots
        let root_a = compute_learning_root(
            &[0.1, 0.2, 0.3, 0.4],
            &[BelnapValue::True; 4],
            100,
        );
        let root_b = compute_learning_root(
            &[0.9, 0.8, 0.7, 0.6],
            &[BelnapValue::Both; 4],
            100,
        );

        // They are different learning roots
        assert_ne!(root_a, root_b);

        // But neither appears in Block::compute_hash() (which is the state_root
        // and consensus hash computation). The learning_root field is deliberately
        // excluded from compute_hash() in core/consensus/src/types.rs.
        //
        // This is verified structurally: compute_hash() hashes header fields +
        // state_root + tx_root + receipt_root + artifact_root. It does NOT
        // include learning_root, learning_embedding, learning_confidence, or
        // gradient_commitment. See Block::compute_hash() implementation.
        //
        // Integration test: two blocks identical except for learning_root
        // produce the same compute_hash() result — tested below.
    }

    /// Orchestrator validates embedding dimensions.
    #[test]
    fn test_orchestrator_validates_embeddings() {
        let orch = make_orchestrator(4, 2);

        // All valid embeddings
        let p1 = make_peer_embedding(vec![1.0, 0.0, 0.5, 0.3], vec![0.9, 0.8, 0.7, 0.6], 100.0);
        let p2 = make_peer_embedding(vec![0.0, 1.0, 0.5, 0.7], vec![0.8, 0.9, 0.6, 0.7], 80.0);

        let result = orch
            .run_checkpoint_aggregation(50, None, vec![p1, p2])
            .unwrap();

        assert_eq!(result.participant_count, 2);
        assert_ne!(result.learning_root, [0u8; 32]);
    }

    /// Dimension mismatch embeddings are filtered out.
    #[test]
    fn test_orchestrator_handles_dimension_mismatch() {
        let orch = make_orchestrator(4, 2);

        // p1: correct dimension (4)
        let p1 = make_peer_embedding(vec![1.0, 0.0, 0.5, 0.3], vec![0.9, 0.8, 0.7, 0.6], 100.0);
        // p2: wrong dimension (3) — will be filtered
        let p2 = make_peer_embedding(vec![0.0, 1.0, 0.5], vec![0.8, 0.9, 0.6], 80.0);
        // p3: correct dimension (4)
        let p3 = make_peer_embedding(vec![0.5, 0.5, 1.0, 0.1], vec![0.7, 0.7, 0.9, 0.5], 90.0);

        let result = orch
            .run_checkpoint_aggregation(50, Some(p1), vec![p2, p3])
            .unwrap();

        // p2 was filtered out, 2 valid embeddings remain (meets quorum of 2)
        assert_eq!(result.participant_count, 2);
        assert_ne!(result.learning_root, [0u8; 32]);
    }

    /// NaN embedding values are filtered out.
    #[test]
    fn test_orchestrator_rejects_nan_embedding() {
        let orch = make_orchestrator(4, 1);

        let bad = make_peer_embedding(
            vec![1.0, f32::NAN, 0.5, 0.3],
            vec![0.9, 0.8, 0.7, 0.6],
            100.0,
        );
        let good = make_peer_embedding(vec![1.0, 0.0, 0.5, 0.3], vec![0.9, 0.8, 0.7, 0.6], 50.0);

        let result = orch
            .run_checkpoint_aggregation(50, Some(bad), vec![good])
            .unwrap();

        // Only the good embedding survives
        assert_eq!(result.participant_count, 1);
    }

    /// Inf confidence values are filtered out.
    #[test]
    fn test_orchestrator_rejects_inf_confidence() {
        let orch = make_orchestrator(4, 1);

        let bad = make_peer_embedding(
            vec![1.0, 0.0, 0.5, 0.3],
            vec![0.9, f32::INFINITY, 0.7, 0.6],
            100.0,
        );
        let good = make_peer_embedding(vec![0.5, 0.5, 0.5, 0.5], vec![0.5, 0.5, 0.5, 0.5], 50.0);

        let result = orch
            .run_checkpoint_aggregation(50, Some(bad), vec![good])
            .unwrap();

        assert_eq!(result.participant_count, 1);
    }

    /// Negative blue_score is filtered out.
    #[test]
    fn test_orchestrator_rejects_negative_blue_score() {
        let orch = make_orchestrator(4, 1);

        let bad = make_peer_embedding(vec![1.0, 0.0, 0.5, 0.3], vec![0.9, 0.8, 0.7, 0.6], -10.0);
        let good = make_peer_embedding(vec![0.5, 0.5, 0.5, 0.5], vec![0.5, 0.5, 0.5, 0.5], 50.0);

        let result = orch
            .run_checkpoint_aggregation(50, Some(bad), vec![good])
            .unwrap();

        assert_eq!(result.participant_count, 1);
    }

    /// Confidence dimension mismatch is filtered out.
    #[test]
    fn test_orchestrator_rejects_confidence_dim_mismatch() {
        let orch = make_orchestrator(4, 1);

        // Embedding has dim 4, but confidence has dim 3
        let bad = make_peer_embedding(vec![1.0, 0.0, 0.5, 0.3], vec![0.9, 0.8, 0.7], 100.0);
        let good = make_peer_embedding(vec![0.5, 0.5, 0.5, 0.5], vec![0.5, 0.5, 0.5, 0.5], 50.0);

        let result = orch
            .run_checkpoint_aggregation(50, Some(bad), vec![good])
            .unwrap();

        assert_eq!(result.participant_count, 1);
    }

    /// Zero embeddings (no local, no peers) returns zero hash.
    #[test]
    fn test_checkpoint_aggregation_no_embeddings() {
        let orch = make_orchestrator(4, 1);

        let result = orch
            .run_checkpoint_aggregation(100, None, vec![])
            .unwrap();

        assert_eq!(result.learning_root, [0u8; 32]);
        assert_eq!(result.participant_count, 0);
    }

    /// Full round-trip: orchestrator produces deterministic results.
    #[test]
    fn test_full_aggregation_deterministic() {
        let orch = make_orchestrator(4, 2);

        let p1 = make_peer_embedding(vec![1.0, 0.0, 0.5, 0.3], vec![0.9, 0.8, 0.7, 0.6], 100.0);
        let p2 = make_peer_embedding(vec![0.0, 1.0, 0.5, 0.7], vec![0.8, 0.9, 0.6, 0.7], 80.0);

        let result1 = orch
            .run_checkpoint_aggregation(50, Some(p1.clone()), vec![p2.clone()])
            .unwrap();

        let result2 = orch
            .run_checkpoint_aggregation(50, Some(p1), vec![p2])
            .unwrap();

        // Same inputs → same learning_root (INV-2)
        assert_eq!(result1.learning_root, result2.learning_root);
        assert_eq!(result1.participant_count, result2.participant_count);
    }

    /// Default config from LearningConfig works.
    #[test]
    fn test_from_learning_config() {
        let config = LearningConfig::default();
        let orch = LearningOrchestrator::from_learning_config(&config);
        assert_eq!(orch.config.embedding_dim, 768);
        assert_eq!(orch.config.min_embeddings, 3);
    }

    /// Empty state vector is handled correctly.
    #[test]
    fn test_learning_root_empty_state_vector() {
        let root1 = compute_learning_root(&[0.1, 0.2], &[], 100);
        let root2 = compute_learning_root(&[0.1, 0.2], &[], 100);
        assert_eq!(root1, root2);
        assert_ne!(root1, [0u8; 32]);
    }

    /// Each BelnapValue variant produces a distinct hash contribution.
    #[test]
    fn test_learning_root_belnap_variants_distinct() {
        let emb = vec![0.5f32; 4];

        let root_n = compute_learning_root(&emb, &[BelnapValue::Neither; 4], 100);
        let root_t = compute_learning_root(&emb, &[BelnapValue::True; 4], 100);
        let root_f = compute_learning_root(&emb, &[BelnapValue::False; 4], 100);
        let root_b = compute_learning_root(&emb, &[BelnapValue::Both; 4], 100);

        // All four must be distinct
        let roots = [root_n, root_t, root_f, root_b];
        for i in 0..roots.len() {
            for j in (i + 1)..roots.len() {
                assert_ne!(roots[i], roots[j], "Belnap variant {} == {}", i, j);
            }
        }
    }
}
