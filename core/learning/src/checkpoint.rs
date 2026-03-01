//! Checkpoint integration for learning synchronization.
//!
//! Implements Data Structure 3 from Gradient Papers No. II.

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

    /// Aggregated embedding result (computed after aggregation).
    pub aggregated_result: Option<EmbeddingVector>,

    /// Timestamp of this checkpoint.
    pub timestamp: u64,

    /// Learning round triggered by this checkpoint.
    pub learning_round: u64,
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
        }
    }

    /// Set the aggregated result after aggregation completes.
    pub fn set_aggregated_result(&mut self, result: EmbeddingVector) {
        self.aggregated_result = Some(result);
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
}
