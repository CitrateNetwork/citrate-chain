//! Knowledge state representation.
//!
//! Implements Definition 4 from Gradient Papers No. II.

use crate::belnap::BelnapValue;
use crate::embeddings::EmbeddingVector;
use crate::types::PublicKey;
use serde::{Deserialize, Serialize};

/// A knowledge state combines an embedding with per-dimension Belnap confidence.
///
/// This represents what a participant "knows" — both the content (embedding)
/// and the certainty (Belnap values per dimension).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeState {
    /// The embedding representing this knowledge.
    pub embedding: EmbeddingVector,

    /// Per-dimension confidence using Belnap four-valued logic.
    /// Length must match embedding dimensions.
    pub confidence: Vec<BelnapValue>,

    /// Timestamp when this state was created.
    pub timestamp: u64,

    /// Owner of this knowledge state.
    pub owner: PublicKey,

    /// Learning round in which this state was produced.
    pub round: u64,
}

impl KnowledgeState {
    /// Create a new knowledge state.
    ///
    /// Confidence vector must have the same length as the embedding.
    pub fn new(
        embedding: EmbeddingVector,
        confidence: Vec<BelnapValue>,
        owner: PublicKey,
        round: u64,
        timestamp: u64,
    ) -> Result<Self, crate::errors::LearningError> {
        if confidence.len() != embedding.dim() {
            return Err(crate::errors::LearningError::DimensionMismatch {
                expected: embedding.dim(),
                got: confidence.len(),
            });
        }
        Ok(Self {
            embedding,
            confidence,
            timestamp,
            owner,
            round,
        })
    }

    /// Compute the overall confidence level.
    ///
    /// Returns the fraction of dimensions with True or Both confidence.
    pub fn confidence_ratio(&self) -> f32 {
        if self.confidence.is_empty() {
            return 0.0;
        }
        let confident = self
            .confidence
            .iter()
            .filter(|c| matches!(c, BelnapValue::True | BelnapValue::Both))
            .count();
        confident as f32 / self.confidence.len() as f32
    }

    /// Merge two knowledge states using Belnap join on confidence.
    pub fn merge(&self, other: &KnowledgeState) -> Result<Self, crate::errors::LearningError> {
        if self.embedding.dim() != other.embedding.dim() {
            return Err(crate::errors::LearningError::DimensionMismatch {
                expected: self.embedding.dim(),
                got: other.embedding.dim(),
            });
        }

        // Merge embeddings by weighted average (weight by confidence ratio)
        let w_self = self.confidence_ratio();
        let w_other = other.confidence_ratio();
        let total = w_self + w_other;

        let merged_embedding = if total < f32::EPSILON {
            EmbeddingVector::zeros(self.embedding.dim())
        } else {
            self.embedding
                .scale(w_self / total)
                .add(&other.embedding.scale(w_other / total))?
        };

        // Merge confidence using Belnap join
        let merged_confidence: Vec<BelnapValue> = self
            .confidence
            .iter()
            .zip(other.confidence.iter())
            .map(|(a, b)| a.join(*b))
            .collect();

        Ok(KnowledgeState {
            embedding: merged_embedding,
            confidence: merged_confidence,
            timestamp: std::cmp::max(self.timestamp, other.timestamp),
            owner: self.owner, // Keep self's owner
            round: std::cmp::max(self.round, other.round),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_knowledge_state_creation() {
        let emb = EmbeddingVector::new(vec![1.0, 2.0, 3.0]).unwrap();
        let conf = vec![BelnapValue::True, BelnapValue::Neither, BelnapValue::False];
        let ks = KnowledgeState::new(emb, conf, [0u8; 32], 1, 1000).unwrap();
        assert_eq!(ks.embedding.dim(), 3);
        assert_eq!(ks.confidence.len(), 3);
    }

    #[test]
    fn test_dimension_mismatch() {
        let emb = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
        let conf = vec![BelnapValue::True]; // Wrong length
        assert!(KnowledgeState::new(emb, conf, [0u8; 32], 1, 1000).is_err());
    }

    #[test]
    fn test_confidence_ratio() {
        let emb = EmbeddingVector::new(vec![1.0, 2.0, 3.0, 4.0]).unwrap();
        let conf = vec![
            BelnapValue::True,
            BelnapValue::Both,
            BelnapValue::False,
            BelnapValue::Neither,
        ];
        let ks = KnowledgeState::new(emb, conf, [0u8; 32], 1, 1000).unwrap();
        // True and Both count as "confident" = 2 out of 4
        assert!((ks.confidence_ratio() - 0.5).abs() < 1e-6);
    }

    #[test]
    fn test_merge_knowledge_states() {
        let emb1 = EmbeddingVector::new(vec![1.0, 0.0]).unwrap();
        let conf1 = vec![BelnapValue::True, BelnapValue::Neither];
        let ks1 = KnowledgeState::new(emb1, conf1, [1u8; 32], 1, 100).unwrap();

        let emb2 = EmbeddingVector::new(vec![0.0, 1.0]).unwrap();
        let conf2 = vec![BelnapValue::False, BelnapValue::True];
        let ks2 = KnowledgeState::new(emb2, conf2, [2u8; 32], 2, 200).unwrap();

        let merged = ks1.merge(&ks2).unwrap();
        assert_eq!(merged.confidence[0], BelnapValue::True.join(BelnapValue::False)); // Both
        assert_eq!(merged.confidence[1], BelnapValue::Neither.join(BelnapValue::True)); // True
        assert_eq!(merged.round, 2);
        assert_eq!(merged.timestamp, 200);
    }
}
