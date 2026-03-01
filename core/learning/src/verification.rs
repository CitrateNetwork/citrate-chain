//! Verification and Byzantine detection.
//!
//! Implements Algorithm 5 and adversarial detection from Gradient Papers No. II.

use crate::config::LearningConfig;
use crate::embeddings::EmbeddingVector;
use crate::errors::{LearningError, LearningResult};
use crate::types::PublicKey;

/// Byzantine behavior detector.
pub struct ByzantineDetector {
    config: LearningConfig,
    /// Flag history: (pubkey, round, reason)
    flag_history: Vec<(PublicKey, u64, String)>,
}

impl ByzantineDetector {
    /// Create a new detector.
    pub fn new(config: LearningConfig) -> Self {
        Self {
            config,
            flag_history: Vec::new(),
        }
    }

    /// Check if an embedding is a statistical outlier.
    ///
    /// Returns true if the embedding's distance from the mean exceeds
    /// `sigma_threshold` standard deviations.
    pub fn is_outlier(
        &self,
        embedding: &EmbeddingVector,
        mean: &EmbeddingVector,
        std_dev: f32,
    ) -> LearningResult<bool> {
        let distance = embedding.euclidean_distance(mean)?;
        Ok(distance > self.config.byzantine_sigma_threshold * std_dev)
    }

    /// Record a byzantine flag for a participant.
    pub fn record_flag(&mut self, pubkey: PublicKey, round: u64, reason: String) {
        self.flag_history.push((pubkey, round, reason));
    }

    /// Check if a participant should be excluded based on flag history.
    ///
    /// Excluded if flagged in N of the last M rounds.
    pub fn should_exclude(&self, pubkey: &PublicKey, current_round: u64) -> bool {
        let lookback = 5u64; // Last 5 rounds
        let min_round = current_round.saturating_sub(lookback);

        let recent_flags = self
            .flag_history
            .iter()
            .filter(|(pk, round, _)| pk == pubkey && *round >= min_round)
            .count();

        recent_flags >= self.config.byzantine_max_flags
    }

    /// Check if a participant can be re-admitted after cool-down.
    pub fn can_readmit(&self, excluded_since: u64, current_round: u64) -> bool {
        current_round.saturating_sub(excluded_since) >= self.config.byzantine_cooldown_rounds
    }

    /// Compute the mean embedding from a set of embeddings.
    pub fn compute_mean(embeddings: &[EmbeddingVector]) -> LearningResult<EmbeddingVector> {
        if embeddings.is_empty() {
            return Err(LearningError::AggregationFailed {
                reason: "empty embedding set".to_string(),
            });
        }

        let dim = embeddings[0].dim();
        let mut sum = EmbeddingVector::zeros(dim);
        for e in embeddings {
            sum = sum.add(e)?;
        }
        Ok(sum.scale(1.0 / embeddings.len() as f32))
    }

    /// Compute the standard deviation of distances from the mean.
    pub fn compute_std_dev(
        embeddings: &[EmbeddingVector],
        mean: &EmbeddingVector,
    ) -> LearningResult<f32> {
        if embeddings.len() < 2 {
            return Ok(0.0);
        }

        let distances: Vec<f32> = embeddings
            .iter()
            .map(|e| e.euclidean_distance(mean))
            .collect::<Result<Vec<_>, _>>()?;

        let mean_dist: f32 = distances.iter().sum::<f32>() / distances.len() as f32;
        let variance: f32 = distances
            .iter()
            .map(|d| (d - mean_dist) * (d - mean_dist))
            .sum::<f32>()
            / (distances.len() - 1) as f32;

        Ok(variance.sqrt())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> LearningConfig {
        LearningConfig {
            byzantine_sigma_threshold: 2.0,
            byzantine_max_flags: 3,
            byzantine_cooldown_rounds: 5,
            ..LearningConfig::default()
        }
    }

    // PC-T32: Byzantine detection
    #[test]
    fn test_outlier_detection() {
        let detector = ByzantineDetector::new(test_config());
        let mean = EmbeddingVector::new(vec![0.0, 0.0]).unwrap();
        let normal = EmbeddingVector::new(vec![0.5, 0.5]).unwrap();
        let outlier = EmbeddingVector::new(vec![100.0, 100.0]).unwrap();

        assert!(!detector.is_outlier(&normal, &mean, 1.0).unwrap());
        assert!(detector.is_outlier(&outlier, &mean, 1.0).unwrap());
    }

    #[test]
    fn test_exclusion_logic() {
        let mut detector = ByzantineDetector::new(test_config());
        let pk = [1u8; 32];

        // Flag 3 times in recent rounds
        detector.record_flag(pk, 10, "outlier".to_string());
        detector.record_flag(pk, 11, "outlier".to_string());
        detector.record_flag(pk, 12, "outlier".to_string());

        assert!(detector.should_exclude(&pk, 13));

        // Different participant not excluded
        assert!(!detector.should_exclude(&[2u8; 32], 13));
    }

    #[test]
    fn test_readmission() {
        let detector = ByzantineDetector::new(test_config());
        // Excluded at round 10, cool-down is 5
        assert!(!detector.can_readmit(10, 13)); // Only 3 rounds
        assert!(detector.can_readmit(10, 15)); // 5 rounds (exact)
        assert!(detector.can_readmit(10, 20)); // 10 rounds
    }

    #[test]
    fn test_compute_mean() {
        let embeddings = vec![
            EmbeddingVector::new(vec![1.0, 0.0]).unwrap(),
            EmbeddingVector::new(vec![0.0, 1.0]).unwrap(),
        ];
        let mean = ByzantineDetector::compute_mean(&embeddings).unwrap();
        assert!((mean.data[0] - 0.5).abs() < 1e-6);
        assert!((mean.data[1] - 0.5).abs() < 1e-6);
    }
}
