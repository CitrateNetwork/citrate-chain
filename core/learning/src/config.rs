//! Learning configuration.
//!
//! Implements Data Structure 2 from Gradient Papers No. II.

use crate::errors::{LearningError, LearningResult};
use serde::{Deserialize, Serialize};

/// Configuration for the Paraconsensus learning layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningConfig {
    /// Embedding vector dimensionality.
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
}

impl Default for LearningConfig {
    fn default() -> Self {
        Self {
            embedding_dimensions: 128,
            min_participants: 3,
            stale_threshold_rounds: 10,
            phase_timeout_ms: 30_000,
            byzantine_sigma_threshold: 3.0,
            byzantine_max_flags: 3,
            byzantine_cooldown_rounds: 10,
            router_hidden_dim: 64,
            router_num_destinations: 4,
            router_learning_rate: 0.01,
            max_adapter_bytes: 1_048_576, // 1 MB
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
        if self.embedding_dimensions > 1024 {
            return Err(LearningError::ConfigInvalid {
                field: "embedding_dimensions".to_string(),
                reason: "must be <= 1024".to_string(),
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
        assert_eq!(config.embedding_dimensions, 128);
        assert_eq!(config.min_participants, 3);
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
        config.embedding_dimensions = 2048;
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
    fn test_config_serialization_roundtrip() {
        let config = LearningConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: LearningConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.embedding_dimensions, deserialized.embedding_dimensions);
        assert_eq!(config.min_participants, deserialized.min_participants);
    }
}
