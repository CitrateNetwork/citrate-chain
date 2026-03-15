//! Routing model for embedding-to-destination mapping.
//!
//! Implements Algorithm 2 and Definition 6 from Gradient Papers No. II.
//! The router accepts three inputs: query embedding, aggregated embedding,
//! and Belnap state vector — the state vector is what gives the router
//! paraconsistent awareness.

use crate::belnap::BelnapValue;
use crate::embeddings::EmbeddingVector;
use crate::errors::{LearningError, LearningResult};
use serde::{Deserialize, Serialize};

/// A routing decision: which destination(s) to send an embedding to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingDecision {
    /// Probability distribution over destinations.
    pub probabilities: Vec<f32>,
    /// Selected destination index (argmax of probabilities).
    pub selected: usize,
}

/// Trait for routing models.
///
/// Routes using three inputs: query embedding, aggregated embedding,
/// and Belnap state vector from paraconsistent aggregation.
pub trait Router: Send + Sync {
    /// Route using (query, e_agg, state_vector) triple.
    fn route(
        &self,
        query: &EmbeddingVector,
        e_agg: &EmbeddingVector,
        state_vector: &[BelnapValue],
    ) -> LearningResult<RoutingDecision>;

    /// Perform a single training step with the full triple.
    fn train_step(
        &mut self,
        query: &EmbeddingVector,
        e_agg: &EmbeddingVector,
        state_vector: &[BelnapValue],
        target: usize,
        learning_rate: f32,
    ) -> LearningResult<f32>;
}

/// Encode a BelnapValue as a one-hot vector of length 4.
fn belnap_one_hot(value: &BelnapValue) -> [f32; 4] {
    match value {
        BelnapValue::True => [1.0, 0.0, 0.0, 0.0],
        BelnapValue::False => [0.0, 1.0, 0.0, 0.0],
        BelnapValue::Both => [0.0, 0.0, 1.0, 0.0],
        BelnapValue::Neither => [0.0, 0.0, 0.0, 1.0],
    }
}

/// Encode a Belnap state vector as a flat one-hot vector.
///
/// Each BelnapValue becomes 4 floats, so output length = state_vector.len() * 4.
pub fn encode_belnap_flat(state_vector: &[BelnapValue]) -> Vec<f32> {
    let mut encoded = Vec::with_capacity(state_vector.len() * 4);
    for v in state_vector {
        encoded.extend_from_slice(&belnap_one_hot(v));
    }
    encoded
}

/// Multi-Layer Perceptron router with Belnap state vector awareness.
///
/// Architecture:
///   Input: concat(query, e_agg, projected_state_vector)  [3 * embedding_dim]
///   → Linear(hidden_dim) → ReLU
///   → Linear(num_destinations) → Softmax
///
/// The Belnap state vector is one-hot encoded (dim * 4) then linearly
/// projected to embedding_dim. The projection is learned during training.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlpRouter {
    /// Embedding dimension (query/e_agg/projected state each have this dim).
    embedding_dim: usize,
    /// Belnap projection: [embedding_dim × (embedding_dim * 4)]
    belnap_projection: Vec<Vec<f32>>,
    /// Weights for first layer: [hidden_dim × (3 * embedding_dim)]
    weights_1: Vec<Vec<f32>>,
    /// Biases for first layer: [hidden_dim]
    biases_1: Vec<f32>,
    /// Weights for second layer: [output_dim × hidden_dim]
    weights_2: Vec<Vec<f32>>,
    /// Biases for second layer: [output_dim]
    biases_2: Vec<f32>,
    /// Hidden dimension.
    hidden_dim: usize,
    /// Output dimension (number of destinations).
    output_dim: usize,
}

impl MlpRouter {
    /// Create a new MLP router with Xavier initialization.
    ///
    /// `embedding_dim`: dimension of query/e_agg vectors (and projection output).
    /// `hidden_dim`: hidden layer size.
    /// `output_dim`: number of routing destinations.
    /// `seed`: for deterministic initialization.
    pub fn new(embedding_dim: usize, hidden_dim: usize, output_dim: usize, seed: u64) -> Self {
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};

        let mut rng = StdRng::seed_from_u64(seed);

        // Belnap projection: embedding_dim × (embedding_dim * 4)
        let one_hot_dim = embedding_dim * 4;
        let proj_scale = (2.0 / (one_hot_dim + embedding_dim) as f32).sqrt();
        let belnap_projection: Vec<Vec<f32>> = (0..embedding_dim)
            .map(|_| {
                (0..one_hot_dim)
                    .map(|_| rng.gen_range(-proj_scale..proj_scale))
                    .collect()
            })
            .collect();

        // MLP input is concat(query, e_agg, projected_state) = 3 * embedding_dim
        let input_dim = 3 * embedding_dim;
        let scale_1 = (2.0 / (input_dim + hidden_dim) as f32).sqrt();
        let scale_2 = (2.0 / (hidden_dim + output_dim) as f32).sqrt();

        let weights_1: Vec<Vec<f32>> = (0..hidden_dim)
            .map(|_| {
                (0..input_dim)
                    .map(|_| rng.gen_range(-scale_1..scale_1))
                    .collect()
            })
            .collect();

        let biases_1 = vec![0.0; hidden_dim];

        let weights_2: Vec<Vec<f32>> = (0..output_dim)
            .map(|_| {
                (0..hidden_dim)
                    .map(|_| rng.gen_range(-scale_2..scale_2))
                    .collect()
            })
            .collect();

        let biases_2 = vec![0.0; output_dim];

        Self {
            embedding_dim,
            belnap_projection,
            weights_1,
            biases_1,
            weights_2,
            biases_2,
            hidden_dim,
            output_dim,
        }
    }

    /// Project a one-hot encoded Belnap state vector to embedding_dim.
    fn project_belnap(&self, one_hot: &[f32]) -> Vec<f32> {
        let mut projected = vec![0.0f32; self.embedding_dim];
        for (i, p) in projected.iter_mut().enumerate() {
            let mut sum = 0.0f32;
            for (j, &oh) in one_hot.iter().enumerate() {
                if oh != 0.0 {
                    sum += self.belnap_projection[i][j] * oh;
                }
            }
            *p = sum;
        }
        projected
    }

    /// Build the full input vector: concat(query, e_agg, projected_state).
    fn build_input(
        &self,
        query: &EmbeddingVector,
        e_agg: &EmbeddingVector,
        state_vector: &[BelnapValue],
    ) -> LearningResult<Vec<f32>> {
        if query.dim() != self.embedding_dim {
            return Err(LearningError::DimensionMismatch {
                expected: self.embedding_dim,
                got: query.dim(),
            });
        }
        if e_agg.dim() != self.embedding_dim {
            return Err(LearningError::DimensionMismatch {
                expected: self.embedding_dim,
                got: e_agg.dim(),
            });
        }
        if state_vector.len() != self.embedding_dim {
            return Err(LearningError::DimensionMismatch {
                expected: self.embedding_dim,
                got: state_vector.len(),
            });
        }

        let one_hot = encode_belnap_flat(state_vector);
        let projected = self.project_belnap(&one_hot);

        let mut input = Vec::with_capacity(3 * self.embedding_dim);
        input.extend_from_slice(&query.data);
        input.extend_from_slice(&e_agg.data);
        input.extend_from_slice(&projected);
        Ok(input)
    }

    /// Forward pass through the 2-layer MLP.
    /// Returns (hidden activations, logits).
    #[allow(clippy::needless_range_loop)]
    fn forward(&self, input: &[f32]) -> (Vec<f32>, Vec<f32>) {
        let input_dim = 3 * self.embedding_dim;

        // Layer 1: hidden = ReLU(W1 * input + b1)
        let mut hidden = vec![0.0f32; self.hidden_dim];
        for (i, h) in hidden.iter_mut().enumerate() {
            let mut sum = self.biases_1[i];
            for j in 0..input_dim {
                sum += self.weights_1[i][j] * input[j];
            }
            *h = sum.max(0.0); // ReLU
        }

        // Layer 2: logits = W2 * hidden + b2
        let mut logits = vec![0.0f32; self.output_dim];
        for (i, l) in logits.iter_mut().enumerate() {
            let mut sum = self.biases_2[i];
            for (j, &h) in hidden.iter().enumerate() {
                sum += self.weights_2[i][j] * h;
            }
            *l = sum;
        }

        (hidden, logits)
    }

    /// Softmax function with numerical stability.
    fn softmax(logits: &[f32]) -> Vec<f32> {
        let max_logit = logits.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
        let exps: Vec<f32> = logits.iter().map(|l| (l - max_logit).exp()).collect();
        let sum: f32 = exps.iter().sum();
        exps.iter().map(|e| e / sum).collect()
    }
}

impl Router for MlpRouter {
    fn route(
        &self,
        query: &EmbeddingVector,
        e_agg: &EmbeddingVector,
        state_vector: &[BelnapValue],
    ) -> LearningResult<RoutingDecision> {
        let input = self.build_input(query, e_agg, state_vector)?;
        let (_, logits) = self.forward(&input);
        let probabilities = Self::softmax(&logits);
        let selected = probabilities
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(i, _)| i)
            .unwrap_or(0);

        Ok(RoutingDecision {
            probabilities,
            selected,
        })
    }

    #[allow(clippy::needless_range_loop)]
    fn train_step(
        &mut self,
        query: &EmbeddingVector,
        e_agg: &EmbeddingVector,
        state_vector: &[BelnapValue],
        target: usize,
        learning_rate: f32,
    ) -> LearningResult<f32> {
        if target >= self.output_dim {
            return Err(LearningError::RoutingFailed {
                reason: format!(
                    "target {} >= num_destinations {}",
                    target, self.output_dim
                ),
            });
        }

        let input = self.build_input(query, e_agg, state_vector)?;
        let (hidden, logits) = self.forward(&input);
        let probs = Self::softmax(&logits);

        // Cross-entropy loss
        let loss = -probs[target].max(1e-7).ln();

        // Gradient of softmax + cross-entropy: d_logits = probs - one_hot(target)
        let mut d_logits = probs;
        d_logits[target] -= 1.0;

        // Backprop through layer 2
        let input_dim = 3 * self.embedding_dim;
        let mut d_hidden = vec![0.0f32; self.hidden_dim];
        for i in 0..self.output_dim {
            for j in 0..self.hidden_dim {
                d_hidden[j] += self.weights_2[i][j] * d_logits[i];
                self.weights_2[i][j] -= learning_rate * d_logits[i] * hidden[j];
            }
            self.biases_2[i] -= learning_rate * d_logits[i];
        }

        // Backprop through ReLU
        for (j, dh) in d_hidden.iter_mut().enumerate() {
            if hidden[j] <= 0.0 {
                *dh = 0.0;
            }
        }

        // Backprop through layer 1
        let mut d_input = vec![0.0f32; input_dim];
        for i in 0..self.hidden_dim {
            for j in 0..input_dim {
                d_input[j] += self.weights_1[i][j] * d_hidden[i];
                self.weights_1[i][j] -= learning_rate * d_hidden[i] * input[j];
            }
            self.biases_1[i] -= learning_rate * d_hidden[i];
        }

        // Backprop through Belnap projection (gradient from the 3rd segment of d_input)
        let proj_offset = 2 * self.embedding_dim;
        let one_hot = encode_belnap_flat(state_vector);
        for i in 0..self.embedding_dim {
            let d_proj_i = d_input[proj_offset + i];
            if d_proj_i.abs() > 1e-10 {
                for (j, &oh) in one_hot.iter().enumerate() {
                    if oh != 0.0 {
                        self.belnap_projection[i][j] -= learning_rate * d_proj_i * oh;
                    }
                }
            }
        }

        Ok(loss)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_embedding(dim: usize, val: f32) -> EmbeddingVector {
        EmbeddingVector::new(vec![val; dim]).unwrap()
    }

    fn make_state_vector(dim: usize, value: BelnapValue) -> Vec<BelnapValue> {
        vec![value; dim]
    }

    // PC-T23: MLP router forward pass with (query, e_agg, state_vector)
    #[test]
    fn test_router_forward_pass() {
        let dim = 4;
        let router = MlpRouter::new(dim, 8, 3, 42);
        let query = make_embedding(dim, 1.0);
        let e_agg = make_embedding(dim, 0.5);
        let state = make_state_vector(dim, BelnapValue::True);

        let decision = router.route(&query, &e_agg, &state).unwrap();

        // Probabilities sum to 1
        let sum: f32 = decision.probabilities.iter().sum();
        assert!((sum - 1.0).abs() < 1e-5, "sum = {}", sum);

        // All probabilities non-negative
        assert!(decision.probabilities.iter().all(|&p| p >= 0.0));

        // Selected is valid index
        assert!(decision.selected < 3);
    }

    // PC-T23a: Changing state vector changes routing output
    #[test]
    fn test_state_vector_affects_routing() {
        let dim = 4;
        let router = MlpRouter::new(dim, 8, 3, 42);
        let query = make_embedding(dim, 1.0);
        let e_agg = make_embedding(dim, 0.5);

        let state_true = make_state_vector(dim, BelnapValue::True);
        let state_both = make_state_vector(dim, BelnapValue::Both);

        let d1 = router.route(&query, &e_agg, &state_true).unwrap();
        let d2 = router.route(&query, &e_agg, &state_both).unwrap();

        // Probabilities should differ when state vector changes
        let diff: f32 = d1
            .probabilities
            .iter()
            .zip(d2.probabilities.iter())
            .map(|(a, b)| (a - b).abs())
            .sum();
        assert!(
            diff > 1e-6,
            "State vector should affect routing, but diff = {}",
            diff
        );
    }

    // PC-T23b: Belnap encoding correctness
    #[test]
    fn test_belnap_encoding() {
        // Test one-hot encoding
        assert_eq!(belnap_one_hot(&BelnapValue::True), [1.0, 0.0, 0.0, 0.0]);
        assert_eq!(belnap_one_hot(&BelnapValue::False), [0.0, 1.0, 0.0, 0.0]);
        assert_eq!(belnap_one_hot(&BelnapValue::Both), [0.0, 0.0, 1.0, 0.0]);
        assert_eq!(
            belnap_one_hot(&BelnapValue::Neither),
            [0.0, 0.0, 0.0, 1.0]
        );

        // Test flat encoding length
        let state = vec![BelnapValue::True, BelnapValue::False, BelnapValue::Both];
        let flat = encode_belnap_flat(&state);
        assert_eq!(flat.len(), 12); // 3 values * 4 one-hot each

        // Verify specific encoding
        assert_eq!(&flat[0..4], &[1.0, 0.0, 0.0, 0.0]); // True
        assert_eq!(&flat[4..8], &[0.0, 1.0, 0.0, 0.0]); // False
        assert_eq!(&flat[8..12], &[0.0, 0.0, 1.0, 0.0]); // Both
    }

    // PC-T24: Router prediction deterministic
    #[test]
    fn test_router_deterministic() {
        let dim = 4;
        let router = MlpRouter::new(dim, 8, 3, 42);
        let query = make_embedding(dim, 1.0);
        let e_agg = make_embedding(dim, 0.5);
        let state = make_state_vector(dim, BelnapValue::True);

        let d1 = router.route(&query, &e_agg, &state).unwrap();
        let d2 = router.route(&query, &e_agg, &state).unwrap();

        assert_eq!(d1.selected, d2.selected);
        for (a, b) in d1.probabilities.iter().zip(d2.probabilities.iter()) {
            assert!((a - b).abs() < 1e-7);
        }
    }

    // PC-T25: Router training step reduces loss
    #[test]
    fn test_training_step_reduces_loss() {
        let dim = 4;
        let mut router = MlpRouter::new(dim, 8, 3, 42);
        let query = make_embedding(dim, 1.0);
        let e_agg = make_embedding(dim, 0.5);
        let state = make_state_vector(dim, BelnapValue::True);
        let target = 1;

        let loss_before = router
            .train_step(&query, &e_agg, &state, target, 0.01)
            .unwrap();

        // Train several more steps
        for _ in 0..20 {
            router
                .train_step(&query, &e_agg, &state, target, 0.01)
                .unwrap();
        }

        let loss_after = router
            .train_step(&query, &e_agg, &state, target, 0.01)
            .unwrap();
        assert!(
            loss_after < loss_before,
            "loss should decrease: {} -> {}",
            loss_before,
            loss_after
        );
    }

    // PC-T33: Router convergence in 100 steps
    #[test]
    fn test_router_convergence_100_steps() {
        let dim = 4;
        let mut router = MlpRouter::new(dim, 16, 3, 42);
        let query = make_embedding(dim, 0.8);
        let e_agg = make_embedding(dim, 0.3);
        let state = make_state_vector(dim, BelnapValue::Neither);
        let target = 2;

        let mut last_loss = f32::MAX;
        for _ in 0..100 {
            last_loss = router
                .train_step(&query, &e_agg, &state, target, 0.01)
                .unwrap();
        }

        // After 100 steps, loss should be reasonably low
        assert!(
            last_loss < 1.0,
            "loss after 100 steps should be < 1.0, got {}",
            last_loss
        );

        // Router should select the target
        let decision = router.route(&query, &e_agg, &state).unwrap();
        assert_eq!(
            decision.selected, target,
            "router should converge to target {} but selected {}",
            target, decision.selected
        );
    }

    #[test]
    fn test_dimension_mismatch() {
        let router = MlpRouter::new(4, 8, 3, 42);
        let bad_query = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
        let good_e_agg = make_embedding(4, 0.5);
        let state = make_state_vector(4, BelnapValue::True);
        assert!(router.route(&bad_query, &good_e_agg, &state).is_err());
    }

    #[test]
    fn test_state_vector_dimension_mismatch() {
        let router = MlpRouter::new(4, 8, 3, 42);
        let query = make_embedding(4, 1.0);
        let e_agg = make_embedding(4, 0.5);
        let bad_state = vec![BelnapValue::True; 2]; // Wrong dimension
        assert!(router.route(&query, &e_agg, &bad_state).is_err());
    }
}
