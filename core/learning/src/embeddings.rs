//! Embedding vectors and similarity metrics.
//!
//! Implements Definitions 2-3 from Gradient Papers No. II.

use crate::errors::{LearningError, LearningResult};
use serde::{Deserialize, Serialize};

/// A fixed-dimension embedding vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingVector {
    /// The raw vector data.
    pub data: Vec<f32>,
}

impl EmbeddingVector {
    /// Create a new embedding vector.
    pub fn new(data: Vec<f32>) -> LearningResult<Self> {
        // Validate no NaN or Inf values
        for (i, &v) in data.iter().enumerate() {
            if v.is_nan() || v.is_infinite() {
                return Err(LearningError::InvalidEmbedding {
                    reason: format!("value at index {} is {}", i, v),
                });
            }
        }
        Ok(Self { data })
    }

    /// Create a zero vector of the given dimension.
    pub fn zeros(dim: usize) -> Self {
        Self {
            data: vec![0.0; dim],
        }
    }

    /// Get the dimensionality of this vector.
    pub fn dim(&self) -> usize {
        self.data.len()
    }

    /// Compute the L2 norm of this vector.
    pub fn l2_norm(&self) -> f32 {
        self.data.iter().map(|x| x * x).sum::<f32>().sqrt()
    }

    /// Return a normalized (unit-length) copy of this vector.
    ///
    /// Returns a zero vector if the input is a zero vector.
    pub fn normalize(&self) -> Self {
        let norm = self.l2_norm();
        if norm < f32::EPSILON {
            return Self::zeros(self.dim());
        }
        Self {
            data: self.data.iter().map(|x| x / norm).collect(),
        }
    }

    /// Compute the dot product with another vector.
    pub fn dot(&self, other: &Self) -> LearningResult<f32> {
        if self.dim() != other.dim() {
            return Err(LearningError::DimensionMismatch {
                expected: self.dim(),
                got: other.dim(),
            });
        }
        Ok(self
            .data
            .iter()
            .zip(other.data.iter())
            .map(|(a, b)| a * b)
            .sum())
    }

    /// Compute cosine similarity with another vector.
    ///
    /// Returns a value in [-1, 1]. Returns 0.0 if either vector is zero.
    pub fn cosine_similarity(&self, other: &Self) -> LearningResult<f32> {
        let dot = self.dot(other)?;
        let norm_a = self.l2_norm();
        let norm_b = other.l2_norm();
        if norm_a < f32::EPSILON || norm_b < f32::EPSILON {
            return Ok(0.0);
        }
        Ok(dot / (norm_a * norm_b))
    }

    /// Compute Euclidean distance to another vector.
    pub fn euclidean_distance(&self, other: &Self) -> LearningResult<f32> {
        if self.dim() != other.dim() {
            return Err(LearningError::DimensionMismatch {
                expected: self.dim(),
                got: other.dim(),
            });
        }
        let sum_sq: f32 = self
            .data
            .iter()
            .zip(other.data.iter())
            .map(|(a, b)| (a - b) * (a - b))
            .sum();
        Ok(sum_sq.sqrt())
    }

    /// Element-wise addition.
    pub fn add(&self, other: &Self) -> LearningResult<Self> {
        if self.dim() != other.dim() {
            return Err(LearningError::DimensionMismatch {
                expected: self.dim(),
                got: other.dim(),
            });
        }
        Ok(Self {
            data: self
                .data
                .iter()
                .zip(other.data.iter())
                .map(|(a, b)| a + b)
                .collect(),
        })
    }

    /// Scalar multiplication.
    pub fn scale(&self, scalar: f32) -> Self {
        Self {
            data: self.data.iter().map(|x| x * scalar).collect(),
        }
    }
}

impl PartialEq for EmbeddingVector {
    fn eq(&self, other: &Self) -> bool {
        if self.dim() != other.dim() {
            return false;
        }
        self.data
            .iter()
            .zip(other.data.iter())
            .all(|(a, b)| (a - b).abs() < f32::EPSILON)
    }
}

/// An embedding space with a fixed dimensionality.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingSpace {
    /// Number of dimensions.
    pub dimensions: usize,
}

impl EmbeddingSpace {
    /// Create a new embedding space.
    pub fn new(dimensions: usize) -> LearningResult<Self> {
        if dimensions == 0 {
            return Err(LearningError::ConfigInvalid {
                field: "dimensions".to_string(),
                reason: "must be > 0".to_string(),
            });
        }
        if dimensions > 1024 {
            return Err(LearningError::ConfigInvalid {
                field: "dimensions".to_string(),
                reason: "must be <= 1024".to_string(),
            });
        }
        Ok(Self { dimensions })
    }

    /// Validate that an embedding belongs to this space.
    pub fn validate(&self, embedding: &EmbeddingVector) -> LearningResult<()> {
        if embedding.dim() != self.dimensions {
            return Err(LearningError::DimensionMismatch {
                expected: self.dimensions,
                got: embedding.dim(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // PC-T09: Embedding normalize
    #[test]
    fn test_normalize() {
        let v = EmbeddingVector::new(vec![3.0, 4.0]).unwrap();
        let n = v.normalize();
        let norm = n.l2_norm();
        assert!((norm - 1.0).abs() < 1e-6, "norm should be 1.0, got {}", norm);
        // Direction preserved: ratio should be 3:4
        assert!((n.data[0] / n.data[1] - 0.75).abs() < 1e-6);
    }

    #[test]
    fn test_normalize_zero_vector() {
        let v = EmbeddingVector::zeros(4);
        let n = v.normalize();
        assert_eq!(n.l2_norm(), 0.0);
    }

    // PC-T10: Embedding similarity
    #[test]
    fn test_cosine_similarity() {
        let a = EmbeddingVector::new(vec![1.0, 0.0]).unwrap();
        let b = EmbeddingVector::new(vec![0.0, 1.0]).unwrap();
        let c = EmbeddingVector::new(vec![1.0, 0.0]).unwrap();

        // Orthogonal vectors → 0
        let sim_ab = a.cosine_similarity(&b).unwrap();
        assert!((sim_ab).abs() < 1e-6);

        // Identical vectors → 1
        let sim_ac = a.cosine_similarity(&c).unwrap();
        assert!((sim_ac - 1.0).abs() < 1e-6);

        // Opposite vectors → -1
        let d = EmbeddingVector::new(vec![-1.0, 0.0]).unwrap();
        let sim_ad = a.cosine_similarity(&d).unwrap();
        assert!((sim_ad + 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_cosine_similarity_zero_vector() {
        let a = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
        let z = EmbeddingVector::zeros(2);
        assert_eq!(a.cosine_similarity(&z).unwrap(), 0.0);
    }

    #[test]
    fn test_euclidean_distance() {
        let a = EmbeddingVector::new(vec![0.0, 0.0]).unwrap();
        let b = EmbeddingVector::new(vec![3.0, 4.0]).unwrap();
        let dist = a.euclidean_distance(&b).unwrap();
        assert!((dist - 5.0).abs() < 1e-6);
    }

    #[test]
    fn test_dimension_mismatch() {
        let a = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
        let b = EmbeddingVector::new(vec![1.0, 2.0, 3.0]).unwrap();
        assert!(a.cosine_similarity(&b).is_err());
        assert!(a.euclidean_distance(&b).is_err());
        assert!(a.dot(&b).is_err());
    }

    #[test]
    fn test_invalid_embedding_nan() {
        let result = EmbeddingVector::new(vec![1.0, f32::NAN]);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_embedding_inf() {
        let result = EmbeddingVector::new(vec![f32::INFINITY, 1.0]);
        assert!(result.is_err());
    }

    #[test]
    fn test_embedding_space_validation() {
        let space = EmbeddingSpace::new(3).unwrap();
        let good = EmbeddingVector::new(vec![1.0, 2.0, 3.0]).unwrap();
        let bad = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
        assert!(space.validate(&good).is_ok());
        assert!(space.validate(&bad).is_err());
    }

    #[test]
    fn test_embedding_space_bounds() {
        assert!(EmbeddingSpace::new(0).is_err());
        assert!(EmbeddingSpace::new(1025).is_err());
        assert!(EmbeddingSpace::new(128).is_ok());
        assert!(EmbeddingSpace::new(1024).is_ok());
    }
}
