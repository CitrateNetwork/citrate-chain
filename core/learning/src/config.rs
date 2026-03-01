//! Learning configuration.
//!
//! Implements Data Structure 2 from Gradient Papers No. II.

use crate::errors::{LearningError, LearningResult};
use serde::{Deserialize, Serialize};

/// Configuration for the Paraconsensus learning layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningConfig {
    /// Embedding vector dimensionality.
    /// Paper II Table A2 specifies 768 (common transformer hidden size).
    pub embedding_dimensions: usize,

    /// Minimum participants required to trigger aggregation.
    pub min_participants: usize,

    /// Maximum rounds to keep stale embeddings before pruning.
    pub stale_threshold_rounds: u64,

    /// Phase timeout in milliseconds.
    pub phase_timeout_ms: u64,

    /// Byzantine detection: standard deviation threshold for outlier.
    pub byzantine_sigma_threshold: f32,

    /// Byzantine detection: max consecutive flags before exclusion.
    pub byzantine_max_flags: usize,

    /// Byzantine detection: cool-down rounds before re-admission.
    pub byzantine_cooldown_rounds: u64,

    /// Router hidden layer dimension.
    pub router_hidden_dim: usize,

    /// Router number of output destinations.
    pub router_num_destinations: usize,

    /// Router learning rate.
    pub router_learning_rate: f32,

    /// Maximum adapter size in bytes.
    pub max_adapter_bytes: usize,

    /// Belnap classification high threshold (θ_high).
    /// Paper II Table A2: 0.8. Requires testnet calibration.
    pub belnap_high_threshold: f32,

    /// Belnap classification low threshold (θ_low).
    /// Paper II Table A2: 0.3. Requires testnet calibration.
    pub belnap_low_threshold: f32,

    /// Temperature parameter τ for softmax(blue_score/τ) trust weighting.
    /// Paper II Table A2: 1.0. Controls blue-score trust concentration.
    pub temperature: f32,

    /// LoRA adapter rank (r). Paper II Table A2: 16.
    pub lora_rank: usize,

    /// Adapter consolidation interval (in checkpoints).
    /// Paper II Table A2: every 1000 checkpoints (~83 min).
    pub adapter_consolidation_interval: u64,

    /// Macro-phase transition: minimum mean confidence for Collection → RoutingActive.
    /// Paper II §5: transition when confidence is sustained above threshold.
    pub macro_confidence_threshold: f32,

    /// Macro-phase transition: maximum router loss for RoutingActive → FullSystem.
    /// Paper II §5: transition when router converges below loss threshold.
    pub macro_loss_threshold: f32,

    /// Macro-phase transition: consecutive checkpoints above threshold required.
    pub macro_consecutive_checkpoints: u64,

    /// Byzantine detection: maximum fraction of dimensions classified as Both
    /// before flagging participant as inconsistent.
    pub belnap_inconsistency_threshold: f32,
}

impl Default for LearningConfig {
    fn default() -> Self {
        Self {
            embedding_dimensions: 768,       // Paper II Table A2
            min_participants: 3,
            stale_threshold_rounds: 10,
            phase_timeout_ms: 30_000,
            byzantine_sigma_threshold: 3.0,
            byzantine_max_flags: 3,
            byzantine_cooldown_rounds: 10,
            router_hidden_dim: 64,
            router_num_destinations: 4,
            router_learning_rate: 0.01,
            max_adapter_bytes: 1_048_576,    // 1 MB
            belnap_high_threshold: 0.8,      // Paper II Table A2
            belnap_low_threshold: 0.3,       // Paper II Table A2
            temperature: 1.0,                // Paper II Table A2
            lora_rank: 16,                   // Paper II Table A2
            adapter_consolidation_interval: 1_000, // Paper II Table A2 (~83 min)
            macro_confidence_threshold: 0.6,
            macro_loss_threshold: 0.5,
            macro_consecutive_checkpoints: 3,
            belnap_inconsistency_threshold: 0.5,
        }
    }
}

impl LearningConfig {
    /// Validate configuration values.
    pub fn validate(&self) -> LearningResult<()> {
        if self.embedding_dimensions == 0 {
            return Err(LearningError::ConfigInvalid {
                field: "embedding_dimensions".to_string(),
                reason: "must be > 0".to_string(),
            });
        }
        if self.embedding_dimensions > 4096 {
            return Err(LearningError::ConfigInvalid {
                field: "embedding_dimensions".to_string(),
                reason: "must be <= 4096".to_string(),
            });
        }
        if self.min_participants == 0 {
            return Err(LearningError::ConfigInvalid {
                field: "min_participants".to_string(),
                reason: "must be > 0".to_string(),
            });
        }
        if self.byzantine_sigma_threshold <= 0.0 {
            return Err(LearningError::ConfigInvalid {
                field: "byzantine_sigma_threshold".to_string(),
                reason: "must be > 0.0".to_string(),
            });
        }
        if self.router_hidden_dim == 0 {
            return Err(LearningError::ConfigInvalid {
                field: "router_hidden_dim".to_string(),
                reason: "must be > 0".to_string(),
            });
        }
        if self.router_num_destinations == 0 {
            return Err(LearningError::ConfigInvalid {
                field: "router_num_destinations".to_string(),
                reason: "must be > 0".to_string(),
            });
        }
        if self.router_learning_rate <= 0.0 || self.router_learning_rate > 1.0 {
            return Err(LearningError::ConfigInvalid {
                field: "router_learning_rate".to_string(),
                reason: "must be in (0.0, 1.0]".to_string(),
            });
        }
        if self.belnap_high_threshold <= self.belnap_low_threshold {
            return Err(LearningError::ConfigInvalid {
                field: "belnap_high_threshold".to_string(),
                reason: "must be > belnap_low_threshold".to_string(),
            });
        }
        if self.belnap_low_threshold < 0.0 || self.belnap_high_threshold > 1.0 {
            return Err(LearningError::ConfigInvalid {
                field: "belnap_thresholds".to_string(),
                reason: "must be in [0.0, 1.0]".to_string(),
            });
        }
        if self.temperature <= 0.0 {
            return Err(LearningError::ConfigInvalid {
                field: "temperature".to_string(),
                reason: "must be > 0.0".to_string(),
            });
        }
        if self.lora_rank == 0 {
            return Err(LearningError::ConfigInvalid {
                field: "lora_rank".to_string(),
                reason: "must be > 0".to_string(),
            });
        }
        if self.macro_confidence_threshold < 0.0 || self.macro_confidence_threshold > 1.0 {
            return Err(LearningError::ConfigInvalid {
                field: "macro_confidence_threshold".to_string(),
                reason: "must be in [0.0, 1.0]".to_string(),
            });
        }
        if self.macro_loss_threshold <= 0.0 {
            return Err(LearningError::ConfigInvalid {
                field: "macro_loss_threshold".to_string(),
                reason: "must be > 0.0".to_string(),
            });
        }
        if self.macro_consecutive_checkpoints == 0 {
            return Err(LearningError::ConfigInvalid {
                field: "macro_consecutive_checkpoints".to_string(),
                reason: "must be > 0".to_string(),
            });
        }
        if self.belnap_inconsistency_threshold < 0.0
            || self.belnap_inconsistency_threshold > 1.0
        {
            return Err(LearningError::ConfigInvalid {
                field: "belnap_inconsistency_threshold".to_string(),
                reason: "must be in [0.0, 1.0]".to_string(),
            });
        }
        Ok(())
    }
}

// PC-T12: Config validation
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_valid() {
        let config = LearningConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.embedding_dimensions, 768); // Paper II Table A2
        assert_eq!(config.min_participants, 3);
        assert_eq!(config.belnap_high_threshold, 0.8);
        assert_eq!(config.belnap_low_threshold, 0.3);
        assert_eq!(config.temperature, 1.0);
        assert_eq!(config.lora_rank, 16);
    }

    #[test]
    fn test_config_zero_dimensions() {
        let mut config = LearningConfig::default();
        config.embedding_dimensions = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_excessive_dimensions() {
        let mut config = LearningConfig::default();
        config.embedding_dimensions = 8192;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_zero_participants() {
        let mut config = LearningConfig::default();
        config.min_participants = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_negative_sigma() {
        let mut config = LearningConfig::default();
        config.byzantine_sigma_threshold = -1.0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_invalid_learning_rate() {
        let mut config = LearningConfig::default();
        config.router_learning_rate = 0.0;
        assert!(config.validate().is_err());

        config.router_learning_rate = 1.5;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_invalid_belnap_thresholds() {
        let mut config = LearningConfig::default();
        // high <= low
        config.belnap_high_threshold = 0.2;
        config.belnap_low_threshold = 0.5;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_invalid_temperature() {
        let mut config = LearningConfig::default();
        config.temperature = 0.0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_invalid_lora_rank() {
        let mut config = LearningConfig::default();
        config.lora_rank = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let config = LearningConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: LearningConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.embedding_dimensions, deserialized.embedding_dimensions);
        assert_eq!(config.min_participants, deserialized.min_participants);
    }
}
