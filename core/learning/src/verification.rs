//! Verification and Byzantine detection.
//!
//! Implements Algorithm 5 and adversarial detection from Gradient Papers No. II.

use crate::adapters::{AdapterFactory, LoraAdapter};
use crate::belnap::BelnapValue;
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

    /// Check if a participant's Belnap state vector is inconsistent.
    ///
    /// A participant is considered inconsistent if the fraction of dimensions
    /// classified as `Both` exceeds `belnap_inconsistency_threshold`.
    /// This indicates the participant is producing contradictory evidence
    /// across too many dimensions.
    pub fn is_belnap_inconsistent(&self, state_vector: &[BelnapValue]) -> bool {
        if state_vector.is_empty() {
            return false;
        }
        let both_count = state_vector
            .iter()
            .filter(|&&v| v == BelnapValue::Both)
            .count();
        let fraction = both_count as f32 / state_vector.len() as f32;
        fraction > self.config.belnap_inconsistency_threshold
    }

    /// Run all Byzantine checks on a participant and auto-record flags.
    ///
    /// Checks:
    /// 1. Statistical outlier detection (embedding distance from mean)
    /// 2. Belnap inconsistency (too many Both dimensions)
    ///
    /// Returns a list of reasons the participant was flagged (empty if clean).
    pub fn check_and_flag(
        &mut self,
        pubkey: PublicKey,
        round: u64,
        embedding: &EmbeddingVector,
        mean: &EmbeddingVector,
        std_dev: f32,
        state_vector: &[BelnapValue],
    ) -> LearningResult<Vec<String>> {
        let mut reasons = Vec::new();

        // Check 1: Statistical outlier
        if self.is_outlier(embedding, mean, std_dev)? {
            reasons.push("statistical outlier".to_string());
        }

        // Check 2: Belnap inconsistency
        if self.is_belnap_inconsistent(state_vector) {
            reasons.push("belnap inconsistency".to_string());
        }

        // Auto-record all flags
        for reason in &reasons {
            self.record_flag(pubkey, round, reason.clone());
        }

        Ok(reasons)
    }

    /// Verify a LoRA adapter's provenance chain and hash integrity.
    ///
    /// Checks:
    /// 1. Provenance chain links are valid (each entry hashes to next parent)
    /// 2. Adapter hash matches its content (A, B matrices + metadata)
    pub fn verify_adapter_provenance(&self, adapter: &LoraAdapter) -> LearningResult<()> {
        // Verify provenance chain integrity
        adapter.provenance.validate()?;

        // Verify adapter hash matches content
        if !AdapterFactory::verify_lora_hash(adapter) {
            return Err(LearningError::AdapterError {
                reason: "LoRA adapter hash does not match content (possible tampering)".to_string(),
            });
        }

        Ok(())
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

    // PC-T32a: Belnap inconsistency detection
    #[test]
    fn test_belnap_inconsistency_detection() {
        let detector = ByzantineDetector::new(LearningConfig {
            belnap_inconsistency_threshold: 0.5,
            ..test_config()
        });

        // 60% Both → exceeds 0.5 threshold → inconsistent
        let mostly_both = vec![
            BelnapValue::Both,
            BelnapValue::Both,
            BelnapValue::Both,
            BelnapValue::True,
            BelnapValue::False,
        ];
        assert!(detector.is_belnap_inconsistent(&mostly_both));

        // 40% Both → below 0.5 threshold → consistent
        let mostly_true = vec![
            BelnapValue::Both,
            BelnapValue::Both,
            BelnapValue::True,
            BelnapValue::True,
            BelnapValue::True,
        ];
        assert!(!detector.is_belnap_inconsistent(&mostly_true));

        // Empty → not inconsistent
        assert!(!detector.is_belnap_inconsistent(&[]));
    }

    // PC-T32b: Combined check_and_flag
    #[test]
    fn test_check_and_flag_combined() {
        let mut detector = ByzantineDetector::new(LearningConfig {
            belnap_inconsistency_threshold: 0.5,
            ..test_config()
        });
        let pk = [3u8; 32];
        let mean = EmbeddingVector::new(vec![0.0, 0.0]).unwrap();

        // Normal participant: close to mean, low Both fraction → no flags
        let normal = EmbeddingVector::new(vec![0.5, 0.5]).unwrap();
        let clean_state = vec![BelnapValue::True, BelnapValue::True];
        let reasons = detector
            .check_and_flag(pk, 1, &normal, &mean, 1.0, &clean_state)
            .unwrap();
        assert!(reasons.is_empty());

        // Byzantine participant: outlier + inconsistent state
        let outlier = EmbeddingVector::new(vec![100.0, 100.0]).unwrap();
        let bad_state = vec![BelnapValue::Both, BelnapValue::Both];
        let reasons = detector
            .check_and_flag(pk, 2, &outlier, &mean, 1.0, &bad_state)
            .unwrap();
        assert_eq!(reasons.len(), 2);
        assert!(reasons.contains(&"statistical outlier".to_string()));
        assert!(reasons.contains(&"belnap inconsistency".to_string()));
    }

    // PC-T32c: False-positive avoidance — participants with some Both but below threshold pass
    #[test]
    fn test_belnap_false_positive_avoidance() {
        let mut detector = ByzantineDetector::new(LearningConfig {
            belnap_inconsistency_threshold: 0.5,
            ..test_config()
        });
        let pk = [4u8; 32];
        let mean = EmbeddingVector::new(vec![0.0, 0.0, 0.0, 0.0]).unwrap();

        // Participant near the mean with 25% Both — should not be flagged
        let normal = EmbeddingVector::new(vec![0.1, 0.1, 0.1, 0.1]).unwrap();
        let partial_both = vec![
            BelnapValue::Both,
            BelnapValue::True,
            BelnapValue::True,
            BelnapValue::True,
        ];
        let reasons = detector
            .check_and_flag(pk, 1, &normal, &mean, 1.0, &partial_both)
            .unwrap();
        assert!(reasons.is_empty(), "25% Both below 50% threshold should not flag");
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

    // PC-T41: LoRA adapter provenance verification + theft rejection
    #[test]
    fn test_lora_adapter_provenance_verification() {
        use crate::adapters::{AdapterFactory, AdapterMetadata};

        let detector = ByzantineDetector::new(test_config());
        let embedding = EmbeddingVector::new(vec![1.0, 2.0, 3.0]).unwrap();
        let metadata = AdapterMetadata {
            name: "test".to_string(),
            description: "test".to_string(),
            round: 1,
            participant_count: 5,
            created_at: 12345,
        };

        // Valid adapter passes verification
        let adapter = AdapterFactory::create_lora(
            &embedding, 2, metadata.clone(), [1u8; 32], 100, vec![0u8; 64],
        )
        .unwrap();
        assert!(detector.verify_adapter_provenance(&adapter).is_ok());

        // Tampered adapter fails hash check
        let mut tampered = adapter.clone();
        tampered.matrix_a[0][0] = 999.0;
        let result = detector.verify_adapter_provenance(&tampered);
        assert!(result.is_err());
        match result {
            Err(LearningError::AdapterError { reason }) => {
                assert!(reason.contains("hash does not match"));
            }
            _ => panic!("expected AdapterError"),
        }
    }
}
