//! Checkpoint integration for learning synchronization.
//!
//! Implements Data Structure 3 from Gradient Papers No. II.

use crate::aggregation::AggregationResult;
use crate::belnap::BelnapValue;
use crate::embeddings::EmbeddingVector;
use crate::types::{Hash, PublicKey};
use serde::{Deserialize, Serialize};

/// A learning checkpoint, triggered by BFT finality.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningCheckpoint {
    /// Block height at which this checkpoint occurred.
    pub height: u64,

    /// State root at this checkpoint.
    pub state_root: Hash,

    /// Snapshot of participant embeddings at this checkpoint.
    pub embedding_snapshot: Vec<(PublicKey, EmbeddingVector)>,

    /// Aggregated embedding result (legacy single-output, kept for backward compat).
    pub aggregated_result: Option<EmbeddingVector>,

    /// Timestamp of this checkpoint.
    pub timestamp: u64,

    /// Learning round triggered by this checkpoint.
    pub learning_round: u64,

    // --- Sprint M: Learning extension fields (Paper II §4.1, GAP-7) ---

    /// Merkle root of routing model weights at this checkpoint.
    /// None until routing model is trained (Sprint N+).
    #[serde(default)]
    pub routing_weights_hash: Option<Hash>,

    /// Merkle root of active adapter registry at this checkpoint.
    /// None until adapters exist (Sprint O).
    #[serde(default)]
    pub adapter_registry_hash: Option<Hash>,

    /// Merkle root of per-node performance metrics at this checkpoint.
    #[serde(default)]
    pub performance_profile_hash: Option<Hash>,

    /// Belnap consensus state vector from paraconsistent aggregation.
    /// Length = embedding_dimensions. None until aggregation completes.
    #[serde(default)]
    pub state_vector: Option<Vec<BelnapValue>>,

    /// Full dual-output aggregation result (embedding + state_vector + confidence).
    /// None until paraconsistent aggregation completes.
    #[serde(default)]
    pub aggregation_result: Option<AggregationResult>,
}

impl LearningCheckpoint {
    /// Create a new checkpoint.
    pub fn new(
        height: u64,
        state_root: Hash,
        embedding_snapshot: Vec<(PublicKey, EmbeddingVector)>,
        learning_round: u64,
    ) -> Self {
        Self {
            height,
            state_root,
            embedding_snapshot,
            aggregated_result: None,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            learning_round,
            routing_weights_hash: None,
            adapter_registry_hash: None,
            performance_profile_hash: None,
            state_vector: None,
            aggregation_result: None,
        }
    }

    /// Set the aggregated result after simple (legacy) aggregation completes.
    pub fn set_aggregated_result(&mut self, result: EmbeddingVector) {
        self.aggregated_result = Some(result);
    }

    /// Set the full paraconsistent aggregation result (Sprint M+).
    ///
    /// Populates both the legacy `aggregated_result` field (for backward compat)
    /// and the new `state_vector` and `aggregation_result` fields.
    pub fn set_paraconsistent_result(&mut self, result: AggregationResult) {
        self.aggregated_result = Some(result.embedding.clone());
        self.state_vector = Some(result.state_vector.clone());
        self.aggregation_result = Some(result);
    }

    /// Set the routing weights hash.
    pub fn set_routing_weights_hash(&mut self, hash: Hash) {
        self.routing_weights_hash = Some(hash);
    }

    /// Set the adapter registry hash.
    pub fn set_adapter_registry_hash(&mut self, hash: Hash) {
        self.adapter_registry_hash = Some(hash);
    }

    /// Set the performance profile hash.
    pub fn set_performance_profile_hash(&mut self, hash: Hash) {
        self.performance_profile_hash = Some(hash);
    }

    /// Get the number of participants in this checkpoint.
    pub fn participant_count(&self) -> usize {
        self.embedding_snapshot.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_creation() {
        let snap = vec![
            ([1u8; 32], EmbeddingVector::zeros(4)),
            ([2u8; 32], EmbeddingVector::zeros(4)),
        ];
        let cp = LearningCheckpoint::new(100, [0u8; 32], snap, 5);
        assert_eq!(cp.height, 100);
        assert_eq!(cp.participant_count(), 2);
        assert!(cp.aggregated_result.is_none());
    }

    #[test]
    fn test_checkpoint_with_result() {
        let mut cp = LearningCheckpoint::new(100, [0u8; 32], vec![], 5);
        let result = EmbeddingVector::new(vec![0.5, 0.5]).unwrap();
        cp.set_aggregated_result(result);
        assert!(cp.aggregated_result.is_some());
    }

    #[test]
    fn test_checkpoint_serialization() {
        let cp = LearningCheckpoint::new(100, [0u8; 32], vec![], 5);
        let json = serde_json::to_string(&cp).unwrap();
        let deserialized: LearningCheckpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.height, 100);
        assert_eq!(deserialized.learning_round, 5);
    }

    // --- Sprint M: WP-M.2 tests ---

    #[test]
    fn test_checkpoint_new_fields_default_none() {
        let cp = LearningCheckpoint::new(100, [0u8; 32], vec![], 5);
        assert!(cp.routing_weights_hash.is_none());
        assert!(cp.adapter_registry_hash.is_none());
        assert!(cp.performance_profile_hash.is_none());
        assert!(cp.state_vector.is_none());
        assert!(cp.aggregation_result.is_none());
    }

    #[test]
    fn test_checkpoint_set_paraconsistent_result() {
        let mut cp = LearningCheckpoint::new(100, [0u8; 32], vec![], 5);
        let result = AggregationResult {
            embedding: EmbeddingVector::new(vec![0.6, 0.8]).unwrap(),
            state_vector: vec![BelnapValue::True, BelnapValue::Both],
            confidence: 0.75,
        };
        cp.set_paraconsistent_result(result);

        // Legacy field populated for backward compat
        assert!(cp.aggregated_result.is_some());
        // New fields populated
        assert!(cp.aggregation_result.is_some());
        let full = cp.aggregation_result.as_ref().unwrap();
        assert_eq!(full.state_vector[1], BelnapValue::Both);
        assert_eq!(cp.state_vector.as_ref().unwrap()[0], BelnapValue::True);
    }

    #[test]
    fn test_checkpoint_hash_setters() {
        let mut cp = LearningCheckpoint::new(100, [0u8; 32], vec![], 5);
        cp.set_routing_weights_hash([0xAA; 32]);
        cp.set_adapter_registry_hash([0xBB; 32]);
        cp.set_performance_profile_hash([0xCC; 32]);

        assert_eq!(cp.routing_weights_hash, Some([0xAA; 32]));
        assert_eq!(cp.adapter_registry_hash, Some([0xBB; 32]));
        assert_eq!(cp.performance_profile_hash, Some([0xCC; 32]));
    }

    #[test]
    fn test_checkpoint_new_fields_serialization_roundtrip() {
        let mut cp = LearningCheckpoint::new(200, [1u8; 32], vec![], 10);
        cp.set_routing_weights_hash([0x01; 32]);
        cp.state_vector = Some(vec![BelnapValue::Both, BelnapValue::True]);

        let json = serde_json::to_string(&cp).unwrap();
        let deserialized: LearningCheckpoint = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.routing_weights_hash, Some([0x01; 32]));
        assert_eq!(
            deserialized.state_vector.as_ref().unwrap()[0],
            BelnapValue::Both
        );
    }

    #[test]
    fn test_checkpoint_backward_compat_deserialization() {
        // Simulate old JSON without Sprint M fields
        let old_json = r#"{
            "height": 50,
            "state_root": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "embedding_snapshot": [],
            "aggregated_result": null,
            "timestamp": 1000,
            "learning_round": 3
        }"#;
        let cp: LearningCheckpoint = serde_json::from_str(old_json).unwrap();
        assert_eq!(cp.height, 50);
        assert!(cp.routing_weights_hash.is_none());
        assert!(cp.state_vector.is_none());
        assert!(cp.aggregation_result.is_none());
    }
}
