//! Embedding aggregation.
//!
//! Implements Algorithm 1 and Definition 6 from Gradient Papers No. II.
//!
//! Two aggregation strategies are provided:
//!
//! 1. **`WeightedMeanAggregator`** — simple weighted mean returning a single embedding.
//!    Legacy interface used by existing callers.
//!
//! 2. **`ParaconsistentAggregator`** — dual-output aggregation returning both an
//!    aggregated embedding AND a Belnap state vector capturing epistemic agreement
//!    structure. This is the core Paraconsensus contribution.

use crate::belnap::{classify_belnap, reduce_belnap_states, softmax_weights, BelnapValue};
use crate::embeddings::EmbeddingVector;
use crate::errors::{LearningError, LearningResult};
use serde::{Deserialize, Serialize};

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

// ---------------------------------------------------------------------------
// WP-M.1b: Dual-output paraconsistent aggregation (Paper II §3.2, Definition 6)
// ---------------------------------------------------------------------------

/// The dual output of paraconsistent aggregation (Definition 6, Paper II §3.2).
///
/// The two primary fields are computed **independently**:
/// - `embedding` is a confidence-and-trust-weighted numeric mean
/// - `state_vector` is a pure Belnap lattice reduction capturing agreement structure
///
/// The routing model in Sprint N takes BOTH fields as input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationResult {
    /// Aggregated embedding: `e_agg[j] = Σ(wᵢ · cᵢ[j] · eᵢ[j]) / Σ(wᵢ · cᵢ[j])`
    /// where `wᵢ` = softmax trust weight, `cᵢ[j]` = raw per-dimension confidence.
    /// L2-normalized.
    pub embedding: EmbeddingVector,

    /// Consensus state vector: `s[j] = ⊔ φ(eᵢ)[j]` over all participants.
    /// A `Both` at dimension `j` indicates genuine paraconsistent disagreement.
    pub state_vector: Vec<BelnapValue>,

    /// Mean effective weight across dimensions: `Σⱼ Σᵢ(wᵢ · cᵢ[j]) / d`.
    /// Higher values indicate more confident aggregation.
    pub confidence: f32,
}

/// Typed input bundle for [`ParaconsistentAggregator::aggregate_paraconsistent`].
///
/// All per-participant slices must have length `n`. Each `confidences[i]` slice
/// must have length `dim` (the embedding dimension).
pub struct AggregationInput<'a> {
    /// Embedding vectors, one per participant.
    pub embeddings: &'a [&'a EmbeddingVector],
    /// Raw per-dimension f32 confidence values, one slice per participant.
    /// These are pre-φ softmax entropy confidences in `[0, 1]`.
    pub confidences: &'a [&'a [f32]],
    /// Blue scores from consensus (as f32), one per participant.
    pub blue_scores: &'a [f32],
    /// Temperature τ for softmax trust weight computation.
    pub temperature: f32,
    /// High confidence threshold θ_high for φ classification.
    pub theta_high: f32,
    /// Low confidence threshold θ_low for φ classification.
    pub theta_low: f32,
}

impl<'a> AggregationInput<'a> {
    /// Validate that all slices are consistently dimensioned.
    ///
    /// Returns the number of participants on success, or an error if dimensions
    /// or slice lengths are inconsistent.
    pub fn validate(&self) -> LearningResult<usize> {
        let n = self.embeddings.len();
        if n == 0 {
            return Ok(0);
        }
        if self.confidences.len() != n {
            return Err(LearningError::AggregationFailed {
                reason: format!(
                    "confidences length {} != embeddings length {}",
                    self.confidences.len(),
                    n
                ),
            });
        }
        if self.blue_scores.len() != n {
            return Err(LearningError::AggregationFailed {
                reason: format!(
                    "blue_scores length {} != embeddings length {}",
                    self.blue_scores.len(),
                    n
                ),
            });
        }
        let dim = self.embeddings[0].dim();
        for (i, emb) in self.embeddings.iter().enumerate() {
            if emb.dim() != dim {
                return Err(LearningError::DimensionMismatch {
                    expected: dim,
                    got: emb.dim(),
                });
            }
            if self.confidences[i].len() != dim {
                return Err(LearningError::AggregationFailed {
                    reason: format!(
                        "participant {} confidence dim {} != embedding dim {}",
                        i,
                        self.confidences[i].len(),
                        dim
                    ),
                });
            }
        }
        Ok(n)
    }
}

/// Paraconsistent aggregator implementing Algorithm 1 from Paper II §3.2.
///
/// Produces a dual output: aggregated embedding AND Belnap state vector.
/// Without the state vector, aggregation degenerates to standard federated averaging.
pub struct ParaconsistentAggregator {
    expected_dim: usize,
}

impl ParaconsistentAggregator {
    /// Create a new paraconsistent aggregator for the given embedding dimension.
    pub fn new(expected_dim: usize) -> Self {
        Self { expected_dim }
    }

    /// Perform paraconsistent aggregation (Algorithm 1, Paper II §3.2).
    ///
    /// Returns `AggregationResult { embedding, state_vector, confidence }`.
    ///
    /// # Algorithm
    /// 1. Compute softmax trust weights from blue scores: `w = softmax(b/τ)`
    /// 2. Classify each participant via φ → per-participant per-dimension Belnap states
    /// 3. Reduce to consensus state vector via join across participants
    /// 4. Compute confidence-weighted embedding: `e_agg[j] = Σ(wᵢ · cᵢⱼ · eᵢⱼ) / Σ(wᵢ · cᵢⱼ)`
    /// 5. L2-normalize and return
    #[allow(clippy::needless_range_loop)]
    pub fn aggregate_paraconsistent(
        &self,
        input: &AggregationInput<'_>,
    ) -> LearningResult<AggregationResult> {
        let n = input.validate()?;

        if n == 0 {
            return Ok(AggregationResult {
                embedding: EmbeddingVector::zeros(self.expected_dim),
                state_vector: vec![],
                confidence: 0.0,
            });
        }

        let dim = input.embeddings[0].dim();
        if dim != self.expected_dim {
            return Err(LearningError::DimensionMismatch {
                expected: self.expected_dim,
                got: dim,
            });
        }

        // Validate no NaN/Inf in embeddings
        for (i, emb) in input.embeddings.iter().enumerate() {
            for v in &emb.data {
                if v.is_nan() || v.is_infinite() {
                    return Err(LearningError::InvalidEmbedding {
                        reason: format!("NaN or Inf at participant {}", i),
                    });
                }
            }
        }

        // Step 1: Trust weights via softmax(blue_scores / τ)
        let trust_weights = softmax_weights(input.blue_scores, input.temperature);

        // Step 2: Classify each participant via φ
        let classifications = classify_belnap(
            input.embeddings,
            input.confidences,
            input.blue_scores,
            input.temperature,
            input.theta_high,
            input.theta_low,
        );

        // Step 3: Reduce classification matrix to consensus state vector
        let state_vector = reduce_belnap_states(&classifications);

        // Step 4: Compute confidence-and-trust-weighted embedding
        // e_agg[j] = Σ(wᵢ · cᵢ[j] · eᵢ[j]) / Σ(wᵢ · cᵢ[j])
        let mut numerator = vec![0.0f32; dim];
        let mut denominator = vec![0.0f32; dim];

        for i in 0..n {
            let w_i = trust_weights[i];
            for j in 0..dim {
                let c_ij = input.confidences[i][j].clamp(0.0, 1.0);
                let effective_weight = w_i * c_ij;
                numerator[j] += effective_weight * input.embeddings[i].data[j];
                denominator[j] += effective_weight;
            }
        }

        let mut e_agg_data = vec![0.0f32; dim];
        let mut total_effective_weight = 0.0f32;
        for j in 0..dim {
            if denominator[j] > f32::EPSILON {
                e_agg_data[j] = numerator[j] / denominator[j];
                total_effective_weight += denominator[j];
            }
        }

        let mean_confidence = if dim > 0 {
            total_effective_weight / dim as f32
        } else {
            0.0
        };

        let e_agg = EmbeddingVector { data: e_agg_data }.normalize();

        Ok(AggregationResult {
            embedding: e_agg,
            state_vector,
            confidence: mean_confidence,
        })
    }
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

    // -------------------------------------------------------------------
    // WP-M.1b: ParaconsistentAggregator unit tests
    // -------------------------------------------------------------------

    fn make_conf(dim: usize, level: f32) -> Vec<f32> {
        vec![level; dim]
    }

    // PC-T13a: Unanimous agreement → all True state vector
    #[test]
    fn test_paraconsistent_unanimous_agreement() {
        let agg = ParaconsistentAggregator::new(2);
        let e1 = EmbeddingVector::new(vec![1.0, 0.0]).unwrap();
        let e2 = EmbeddingVector::new(vec![1.0, 0.0]).unwrap();
        let conf = make_conf(2, 0.9);
        let input = AggregationInput {
            embeddings: &[&e1, &e2],
            confidences: &[&conf, &conf],
            blue_scores: &[1.0, 1.0],
            temperature: 1.0,
            theta_high: 0.8,
            theta_low: 0.3,
        };
        let result = agg.aggregate_paraconsistent(&input).unwrap();

        assert_eq!(result.state_vector.len(), 2);
        for &v in &result.state_vector {
            assert_eq!(v, BelnapValue::True,
                "unanimous agreement should produce True state vector");
        }
        assert_eq!(result.embedding.dim(), 2);
    }

    // PC-T13b: Equal-trust disagreement → Both in state vector
    #[test]
    fn test_paraconsistent_disagreement_both() {
        let agg = ParaconsistentAggregator::new(1);
        let e1 = EmbeddingVector::new(vec![5.0]).unwrap();
        let e2 = EmbeddingVector::new(vec![-5.0]).unwrap();
        let conf = make_conf(1, 0.95);
        let input = AggregationInput {
            embeddings: &[&e1, &e2],
            confidences: &[&conf, &conf],
            blue_scores: &[1.0, 1.0],
            temperature: 1.0,
            theta_high: 0.8,
            theta_low: 0.3,
        };
        let result = agg.aggregate_paraconsistent(&input).unwrap();

        assert_eq!(result.state_vector[0], BelnapValue::Both,
            "comparable-trust disagreement should produce Both");
    }

    // PC-T13c: e_agg and state_vector are independent
    #[test]
    fn test_paraconsistent_outputs_independent() {
        let agg = ParaconsistentAggregator::new(2);
        // dim 0: agreement (both positive)
        // dim 1: disagreement (opposite directions)
        let e1 = EmbeddingVector::new(vec![1.0, 1.0]).unwrap();
        let e2 = EmbeddingVector::new(vec![1.0, -1.0]).unwrap();
        let conf = make_conf(2, 0.95);
        let input = AggregationInput {
            embeddings: &[&e1, &e2],
            confidences: &[&conf, &conf],
            blue_scores: &[1.0, 1.0],
            temperature: 1.0,
            theta_high: 0.8,
            theta_low: 0.3,
        };
        let result = agg.aggregate_paraconsistent(&input).unwrap();

        // dim 0: agreement → True
        assert_eq!(result.state_vector[0], BelnapValue::True);
        // dim 1: disagreement → Both
        assert_eq!(result.state_vector[1], BelnapValue::Both);
    }

    #[test]
    fn test_paraconsistent_empty_input() {
        let agg = ParaconsistentAggregator::new(4);
        let input = AggregationInput {
            embeddings: &[],
            confidences: &[],
            blue_scores: &[],
            temperature: 1.0,
            theta_high: 0.8,
            theta_low: 0.3,
        };
        let result = agg.aggregate_paraconsistent(&input).unwrap();
        assert_eq!(result.embedding.dim(), 4);
        assert!(result.state_vector.is_empty());
        assert_eq!(result.confidence, 0.0);
    }

    #[test]
    fn test_paraconsistent_low_confidence_neither() {
        let agg = ParaconsistentAggregator::new(2);
        let e1 = EmbeddingVector::new(vec![1.0, -1.0]).unwrap();
        let e2 = EmbeddingVector::new(vec![-1.0, 1.0]).unwrap();
        let low_conf = make_conf(2, 0.1);
        let input = AggregationInput {
            embeddings: &[&e1, &e2],
            confidences: &[&low_conf, &low_conf],
            blue_scores: &[1.0, 1.0],
            temperature: 1.0,
            theta_high: 0.8,
            theta_low: 0.3,
        };
        let result = agg.aggregate_paraconsistent(&input).unwrap();

        for &v in &result.state_vector {
            assert_eq!(v, BelnapValue::Neither,
                "low confidence should produce Neither");
        }
    }

    #[test]
    fn test_paraconsistent_dimension_mismatch() {
        let agg = ParaconsistentAggregator::new(3);
        let e1 = EmbeddingVector::new(vec![1.0, 0.0]).unwrap(); // dim 2, not 3
        let conf = make_conf(2, 0.9);
        let input = AggregationInput {
            embeddings: &[&e1],
            confidences: &[&conf],
            blue_scores: &[1.0],
            temperature: 1.0,
            theta_high: 0.8,
            theta_low: 0.3,
        };
        assert!(agg.aggregate_paraconsistent(&input).is_err());
    }

    #[test]
    fn test_paraconsistent_nan_rejection() {
        let agg = ParaconsistentAggregator::new(2);
        let bad = EmbeddingVector { data: vec![f32::NAN, 1.0] };
        let conf = make_conf(2, 0.9);
        let input = AggregationInput {
            embeddings: &[&bad],
            confidences: &[&conf],
            blue_scores: &[1.0],
            temperature: 1.0,
            theta_high: 0.8,
            theta_low: 0.3,
        };
        assert!(agg.aggregate_paraconsistent(&input).is_err());
    }
}

// ---------------------------------------------------------------------------
// WP-M.4: Property-based tests for dual-output aggregation
// ---------------------------------------------------------------------------

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// Strategy: 2-8 participants, 2-16 dimensions, valid f32 values
    fn aggregation_inputs(
    ) -> impl Strategy<Value = (Vec<Vec<f32>>, Vec<Vec<f32>>, Vec<f32>, usize)> {
        (2usize..=8, 2usize..=16).prop_flat_map(|(n, dim)| {
            let embeddings = proptest::collection::vec(
                proptest::collection::vec(-10.0f32..10.0f32, dim..=dim),
                n..=n,
            );
            let confidences = proptest::collection::vec(
                proptest::collection::vec(0.0f32..1.0f32, dim..=dim),
                n..=n,
            );
            let blue_scores = proptest::collection::vec(0.1f32..100.0f32, n..=n);
            (embeddings, confidences, blue_scores, Just(dim))
        })
    }

    fn run_aggregation(
        emb_data: &[Vec<f32>],
        conf_data: &[Vec<f32>],
        scores: &[f32],
        dim: usize,
    ) -> AggregationResult {
        let embeddings: Vec<EmbeddingVector> = emb_data
            .iter()
            .map(|d| EmbeddingVector { data: d.clone() })
            .collect();
        let emb_refs: Vec<&EmbeddingVector> = embeddings.iter().collect();
        let conf_refs: Vec<&[f32]> = conf_data.iter().map(|c| c.as_slice()).collect();

        let agg = ParaconsistentAggregator::new(dim);
        let input = AggregationInput {
            embeddings: &emb_refs,
            confidences: &conf_refs,
            blue_scores: scores,
            temperature: 1.0,
            theta_high: 0.8,
            theta_low: 0.3,
        };
        agg.aggregate_paraconsistent(&input).unwrap()
    }

    proptest! {
        /// Property 1: Output dimensions always match input dimensions.
        #[test]
        fn prop_dimension_consistency(
            (emb_data, conf_data, scores, dim) in aggregation_inputs()
        ) {
            let result = run_aggregation(&emb_data, &conf_data, &scores, dim);
            prop_assert_eq!(result.embedding.dim(), dim,
                "embedding dim must match input dim");
            prop_assert_eq!(result.state_vector.len(), dim,
                "state_vector len must match input dim");
        }

        /// Property 2: Aggregated embedding norm is bounded ≤ 1.0 + ε (normalized).
        #[test]
        fn prop_norm_bounded(
            (emb_data, conf_data, scores, dim) in aggregation_inputs()
        ) {
            let result = run_aggregation(&emb_data, &conf_data, &scores, dim);
            let norm = result.embedding.l2_norm();
            prop_assert!(norm <= 1.0 + 1e-4,
                "e_agg L2 norm {} exceeds 1.0 + ε", norm);
        }

        /// Property 3: Identical participants with high confidence produce all-True state vector.
        /// This is a fundamental property of consensus: agreement → True.
        #[test]
        fn prop_identical_participants_all_true(
            dim in 2usize..=16,
            n in 2usize..=8,
            base in proptest::collection::vec(-10.0f32..10.0f32, 2..=16),
        ) {
            let dim = dim.min(base.len());
            let base_data: Vec<f32> = base[..dim].to_vec();
            // All participants have the same embedding and high confidence
            let emb_data: Vec<Vec<f32>> = (0..n).map(|_| base_data.clone()).collect();
            let conf_data: Vec<Vec<f32>> = (0..n).map(|_| vec![0.95; dim]).collect();
            let scores: Vec<f32> = (0..n).map(|_| 1.0).collect();

            let result = run_aggregation(&emb_data, &conf_data, &scores, dim);

            for (j, &v) in result.state_vector.iter().enumerate() {
                prop_assert_eq!(v, BelnapValue::True,
                    "identical participants should yield True at dim {}", j);
            }
        }

        /// Property 4: If two equal-trust participants have opposite high-confidence
        /// values at some dimension, state_vector at that dimension should be Both.
        #[test]
        fn prop_disagreement_yields_both(
            dim in 2usize..=8,
            target_j in 0usize..8,
        ) {
            let target_j = target_j % dim;
            let mut e1_data = vec![1.0f32; dim];
            let mut e2_data = vec![1.0f32; dim];
            e1_data[target_j] = 5.0;
            e2_data[target_j] = -5.0;
            let conf = vec![0.95f32; dim]; // high confidence
            let scores = vec![1.0, 1.0]; // equal trust

            let result = run_aggregation(
                &[e1_data, e2_data],
                &[conf.clone(), conf],
                &scores,
                dim,
            );

            prop_assert_eq!(result.state_vector[target_j], BelnapValue::Both,
                "disagreement at dim {} should produce Both", target_j);
        }
    }
}
