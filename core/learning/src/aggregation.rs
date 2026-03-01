//! Embedding aggregation.
//!
//! Implements Algorithm 1 and Definition 5 from Gradient Papers No. II.

use crate::embeddings::EmbeddingVector;
use crate::errors::{LearningError, LearningResult};

/// Trait for embedding aggregation strategies.
pub trait Aggregator: Send + Sync {
    /// Aggregate a set of weighted embeddings into a single result.
    fn aggregate(
        &self,
        embeddings: &[(EmbeddingVector, f32)],
    ) -> LearningResult<EmbeddingVector>;
}

/// Weighted mean aggregation (Algorithm 1 from Paper II).
pub struct WeightedMeanAggregator {
    /// Expected embedding dimensionality.
    expected_dim: usize,
}

impl WeightedMeanAggregator {
    /// Create a new weighted mean aggregator.
    pub fn new(expected_dim: usize) -> Self {
        Self { expected_dim }
    }
}

impl Aggregator for WeightedMeanAggregator {
    fn aggregate(
        &self,
        embeddings: &[(EmbeddingVector, f32)],
    ) -> LearningResult<EmbeddingVector> {
        if embeddings.is_empty() {
            return Ok(EmbeddingVector::zeros(self.expected_dim));
        }

        let mut result = EmbeddingVector::zeros(self.expected_dim);
        let mut total_weight: f32 = 0.0;

        for (embedding, weight) in embeddings {
            // Validate dimension
            if embedding.dim() != self.expected_dim {
                return Err(LearningError::DimensionMismatch {
                    expected: self.expected_dim,
                    got: embedding.dim(),
                });
            }

            // Skip zero or negative weight
            if *weight <= 0.0 {
                continue;
            }

            // Validate embedding values
            for v in &embedding.data {
                if v.is_nan() || v.is_infinite() {
                    return Err(LearningError::InvalidEmbedding {
                        reason: "NaN or Inf in embedding".to_string(),
                    });
                }
            }

            result = result.add(&embedding.scale(*weight))?;
            total_weight += weight;
        }

        if total_weight > f32::EPSILON {
            result = result.scale(1.0 / total_weight);
        }

        Ok(result.normalize())
    }
}

/// Convert a blue score to a normalized weight.
pub fn blue_score_to_weight(blue_score: u64, total_blue_scores: u64) -> f32 {
    if total_blue_scores == 0 {
        return 0.0;
    }
    (blue_score as f32) / (total_blue_scores as f32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agg(dim: usize) -> WeightedMeanAggregator {
        WeightedMeanAggregator::new(dim)
    }

    // PC-T13: Weighted mean correctness
    #[test]
    fn test_weighted_mean() {
        let aggregator = agg(2);
        let e1 = EmbeddingVector::new(vec![1.0, 0.0]).unwrap();
        let e2 = EmbeddingVector::new(vec![0.0, 1.0]).unwrap();

        let result = aggregator
            .aggregate(&[(e1, 1.0), (e2, 1.0)])
            .unwrap();

        // Equal weights → average → normalize
        // (0.5, 0.5) normalized → (0.707, 0.707)
        let expected_val = 1.0 / (2.0f32).sqrt();
        assert!((result.data[0] - expected_val).abs() < 1e-4);
        assert!((result.data[1] - expected_val).abs() < 1e-4);
    }

    // PC-T14: Zero-weight participant excluded
    #[test]
    fn test_zero_weight_excluded() {
        let aggregator = agg(2);
        let e1 = EmbeddingVector::new(vec![1.0, 0.0]).unwrap();
        let e2 = EmbeddingVector::new(vec![0.0, 1.0]).unwrap();

        let result = aggregator
            .aggregate(&[(e1, 1.0), (e2, 0.0)])
            .unwrap();

        // Only e1 contributes → (1.0, 0.0) normalized
        assert!((result.data[0] - 1.0).abs() < 1e-6);
        assert!(result.data[1].abs() < 1e-6);
    }

    // PC-T15: Single participant identity
    #[test]
    fn test_single_participant_identity() {
        let aggregator = agg(3);
        let e = EmbeddingVector::new(vec![3.0, 4.0, 0.0]).unwrap();
        let expected = e.normalize();

        let result = aggregator.aggregate(&[(e, 1.0)]).unwrap();

        for (a, b) in result.data.iter().zip(expected.data.iter()) {
            assert!((a - b).abs() < 1e-6);
        }
    }

    // PC-T17: Stale embeddings excluded (handled by caller, but empty list works)
    #[test]
    fn test_empty_input() {
        let aggregator = agg(4);
        let result = aggregator.aggregate(&[]).unwrap();
        assert_eq!(result.dim(), 4);
        assert_eq!(result.l2_norm(), 0.0);
    }

    // PC-T19: NaN/Inf rejection
    #[test]
    fn test_nan_rejection() {
        let aggregator = agg(2);
        // Can't create invalid EmbeddingVector via new(), but we can
        // bypass by constructing directly
        let bad = EmbeddingVector { data: vec![f32::NAN, 1.0] };
        let result = aggregator.aggregate(&[(bad, 1.0)]);
        assert!(result.is_err());
    }

    #[test]
    fn test_inf_rejection() {
        let aggregator = agg(2);
        let bad = EmbeddingVector { data: vec![f32::INFINITY, 1.0] };
        let result = aggregator.aggregate(&[(bad, 1.0)]);
        assert!(result.is_err());
    }

    // PC-T20: Dimension mismatch
    #[test]
    fn test_dimension_mismatch() {
        let aggregator = agg(3);
        let e = EmbeddingVector::new(vec![1.0, 2.0]).unwrap(); // dim 2, expected 3
        let result = aggregator.aggregate(&[(e, 1.0)]);
        assert!(result.is_err());
    }

    #[test]
    fn test_blue_score_weights() {
        assert_eq!(blue_score_to_weight(50, 100), 0.5);
        assert_eq!(blue_score_to_weight(0, 100), 0.0);
        assert_eq!(blue_score_to_weight(100, 100), 1.0);
        assert_eq!(blue_score_to_weight(0, 0), 0.0);
    }
}
