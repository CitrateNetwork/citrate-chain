//! Routing model for embedding-to-destination mapping.
//!
//! Implements Algorithm 2 and Definition 6 from Gradient Papers No. II.

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
pub trait Router: Send + Sync {
    /// Route an embedding to a destination.
    fn route(&self, embedding: &EmbeddingVector) -> LearningResult<RoutingDecision>;

    /// Perform a single training step.
    fn train_step(
        &mut self,
        input: &EmbeddingVector,
        target: usize,
        learning_rate: f32,
    ) -> LearningResult<f32>;
}

/// Multi-Layer Perceptron router.
///
/// Architecture: Input(dim) → Linear(hidden) → ReLU → Linear(destinations) → Softmax
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlpRouter {
    /// Weights for first layer: [hidden_dim x input_dim]
    weights_1: Vec<Vec<f32>>,
    /// Biases for first layer: [hidden_dim]
    biases_1: Vec<f32>,
    /// Weights for second layer: [output_dim x hidden_dim]
    weights_2: Vec<Vec<f32>>,
    /// Biases for second layer: [output_dim]
    biases_2: Vec<f32>,
    /// Input dimension.
    input_dim: usize,
    /// Hidden dimension.
    hidden_dim: usize,
    /// Output dimension (number of destinations).
    output_dim: usize,
}

impl MlpRouter {
    /// Create a new MLP router with Xavier initialization.
    pub fn new(input_dim: usize, hidden_dim: usize, output_dim: usize, seed: u64) -> Self {
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};

        let mut rng = StdRng::seed_from_u64(seed);
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
            weights_1,
            biases_1,
            weights_2,
            biases_2,
            input_dim,
            hidden_dim,
            output_dim,
        }
    }

    /// Forward pass through the network.
    fn forward(&self, input: &[f32]) -> (Vec<f32>, Vec<f32>) {
        // Layer 1: hidden = ReLU(W1 * input + b1)
        let mut hidden = vec![0.0f32; self.hidden_dim];
        for (i, h) in hidden.iter_mut().enumerate() {
            let mut sum = self.biases_1[i];
            for (j, &x) in input.iter().enumerate() {
                sum += self.weights_1[i][j] * x;
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

    /// Softmax function.
    fn softmax(logits: &[f32]) -> Vec<f32> {
        let max_logit = logits.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
        let exps: Vec<f32> = logits.iter().map(|l| (l - max_logit).exp()).collect();
        let sum: f32 = exps.iter().sum();
        exps.iter().map(|e| e / sum).collect()
    }
}

impl Router for MlpRouter {
    fn route(&self, embedding: &EmbeddingVector) -> LearningResult<RoutingDecision> {
        if embedding.dim() != self.input_dim {
            return Err(LearningError::DimensionMismatch {
                expected: self.input_dim,
                got: embedding.dim(),
            });
        }

        let (_, logits) = self.forward(&embedding.data);
        let probabilities = Self::softmax(&logits);
        let selected = probabilities
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
            .map(|(i, _)| i)
            .unwrap_or(0);

        Ok(RoutingDecision {
            probabilities,
            selected,
        })
    }

    fn train_step(
        &mut self,
        input: &EmbeddingVector,
        target: usize,
        learning_rate: f32,
    ) -> LearningResult<f32> {
        if input.dim() != self.input_dim {
            return Err(LearningError::DimensionMismatch {
                expected: self.input_dim,
                got: input.dim(),
            });
        }
        if target >= self.output_dim {
            return Err(LearningError::RoutingFailed {
                reason: format!(
                    "target {} >= num_destinations {}",
                    target, self.output_dim
                ),
            });
        }

        let (hidden, logits) = self.forward(&input.data);
        let probs = Self::softmax(&logits);

        // Cross-entropy loss
        let loss = -probs[target].max(1e-7).ln();

        // Gradient of softmax + cross-entropy: d_logits = probs - one_hot(target)
        let mut d_logits = probs.clone();
        d_logits[target] -= 1.0;

        // Backprop through layer 2
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
        for i in 0..self.hidden_dim {
            for j in 0..self.input_dim {
                self.weights_1[i][j] -= learning_rate * d_hidden[i] * input.data[j];
            }
            self.biases_1[i] -= learning_rate * d_hidden[i];
        }

        Ok(loss)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // PC-T23: MLP router forward pass
    #[test]
    fn test_router_forward_pass() {
        let router = MlpRouter::new(4, 8, 3, 42);
        let input = EmbeddingVector::new(vec![1.0, 0.5, -0.3, 0.7]).unwrap();

        let decision = router.route(&input).unwrap();

        // Probabilities sum to 1
        let sum: f32 = decision.probabilities.iter().sum();
        assert!((sum - 1.0).abs() < 1e-5, "sum = {}", sum);

        // All probabilities non-negative
        assert!(decision.probabilities.iter().all(|&p| p >= 0.0));

        // Selected is valid index
        assert!(decision.selected < 3);
    }

    // PC-T24: Router prediction deterministic
    #[test]
    fn test_router_deterministic() {
        let router = MlpRouter::new(4, 8, 3, 42);
        let input = EmbeddingVector::new(vec![1.0, 0.5, -0.3, 0.7]).unwrap();

        let d1 = router.route(&input).unwrap();
        let d2 = router.route(&input).unwrap();

        assert_eq!(d1.selected, d2.selected);
        for (a, b) in d1.probabilities.iter().zip(d2.probabilities.iter()) {
            assert!((a - b).abs() < 1e-7);
        }
    }

    // PC-T25: Router training step
    #[test]
    fn test_training_step_reduces_loss() {
        let mut router = MlpRouter::new(4, 8, 3, 42);
        let input = EmbeddingVector::new(vec![1.0, 0.5, -0.3, 0.7]).unwrap();
        let target = 1;

        let loss_before = router.train_step(&input, target, 0.01).unwrap();

        // Train several more steps
        for _ in 0..20 {
            router.train_step(&input, target, 0.01).unwrap();
        }

        let loss_after = router.train_step(&input, target, 0.01).unwrap();
        assert!(
            loss_after < loss_before,
            "loss should decrease: {} -> {}",
            loss_before,
            loss_after
        );
    }

    #[test]
    fn test_dimension_mismatch() {
        let router = MlpRouter::new(4, 8, 3, 42);
        let bad_input = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
        assert!(router.route(&bad_input).is_err());
    }
}
