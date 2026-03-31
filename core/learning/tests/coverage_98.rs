//! WP-RR.5: Coverage gap tests for citrate-learning (target: 98%).
//!
//! This integration test file targets untested branches and edge cases across
//! all modules in the learning crate that existing unit tests do not cover.
//! Each test is annotated with the module and branch it exercises.

use citrate_learning::adapters::{
    apply_adapter, apply_lora, apply_lora_confidence_gated, compose_adapters, compose_lora,
    compose_lora_chain, remove_lora, spectral_norm_bound, AdapterFactory, AdapterMetadata,
    AdapterRegistry, LoraAdapter, ProvenanceChain, ProvenanceEntry,
};
use citrate_learning::aggregation::{
    blue_score_to_weight, AggregationInput, AggregationResult, Aggregator,
    ParaconsistentAggregator, WeightedMeanAggregator,
};
use citrate_learning::belnap::{
    blue_scores_to_trust_weights, classify_belnap, reduce_belnap_states, softmax_weights,
    BelnapValue,
};
use citrate_learning::checkpoint::LearningCheckpoint;
use citrate_learning::config::LearningConfig;
use citrate_learning::embeddings::{EmbeddingSpace, EmbeddingVector};
use citrate_learning::errors::LearningError;
use citrate_learning::knowledge::KnowledgeState;
use citrate_learning::phases::{
    LearningPipeline, MacroPhaseManager, NetworkLearningPhase, OodaPhase, PhaseManager,
};
use citrate_learning::routing::{encode_belnap_flat, MlpRouter, Router, RoutingDecision};
use citrate_learning::safety::{LearningMode, SafetyGuard};
use citrate_learning::storage::PhaseStore;
use citrate_learning::types::{LearningRound, Participant, ParticipantRole};

// ============================================================================
// Helper functions
// ============================================================================

fn default_config() -> LearningConfig {
    LearningConfig::default()
}

fn test_metadata(round: u64) -> AdapterMetadata {
    AdapterMetadata {
        name: format!("test-adapter-{}", round),
        description: "coverage test adapter".to_string(),
        round,
        participant_count: 3,
        created_at: 99999,
    }
}

fn make_lora(dim: usize, rank: usize, round: u64) -> LoraAdapter {
    let embedding = EmbeddingVector::new(vec![1.0; dim]).unwrap();
    AdapterFactory::create_lora(
        &embedding,
        rank,
        test_metadata(round),
        [1u8; 32],
        100,
        vec![0u8; 64],
    )
    .unwrap()
}

// ============================================================================
// 1. Error type Display coverage
// ============================================================================

#[test]
fn test_all_error_variants_display() {
    // Exercises Display impl for every LearningError variant
    let errors: Vec<LearningError> = vec![
        LearningError::DimensionMismatch {
            expected: 768,
            got: 512,
        },
        LearningError::InvalidEmbedding {
            reason: "contains NaN".to_string(),
        },
        LearningError::AggregationFailed {
            reason: "too few inputs".to_string(),
        },
        LearningError::PhaseTimeout {
            phase: "Observe".to_string(),
            elapsed_ms: 30000,
        },
        LearningError::InvalidPhaseTransition {
            from: "Observe".to_string(),
            to: "Act".to_string(),
        },
        LearningError::RoutingFailed {
            reason: "bad target".to_string(),
        },
        LearningError::AdapterError {
            reason: "invalid rank".to_string(),
        },
        LearningError::CheckpointMissing {
            expected_height: 100,
        },
        LearningError::SafetyViolation {
            details: "state root mismatch".to_string(),
        },
        LearningError::ConfigInvalid {
            field: "temperature".to_string(),
            reason: "must be > 0".to_string(),
        },
        LearningError::ParticipantNotFound {
            id: "abc".to_string(),
        },
        LearningError::ByzantineBehavior {
            participant: "node1".to_string(),
            reason: "outlier".to_string(),
        },
        LearningError::Serialization("bad json".to_string()),
        LearningError::Storage("disk full".to_string()),
    ];
    for err in &errors {
        let s = format!("{}", err);
        assert!(!s.is_empty(), "error display should not be empty");
    }
}

// ============================================================================
// 2. Config validation: all remaining boundary paths
// ============================================================================

#[test]
fn test_config_zero_router_hidden_dim() {
    let mut config = default_config();
    config.router_hidden_dim = 0;
    assert!(config.validate().is_err());
}

#[test]
fn test_config_zero_router_num_destinations() {
    let mut config = default_config();
    config.router_num_destinations = 0;
    assert!(config.validate().is_err());
}

#[test]
fn test_config_learning_rate_exactly_one() {
    let mut config = default_config();
    config.router_learning_rate = 1.0;
    assert!(config.validate().is_ok());
}

#[test]
fn test_config_belnap_thresholds_equal() {
    let mut config = default_config();
    config.belnap_high_threshold = 0.5;
    config.belnap_low_threshold = 0.5;
    assert!(config.validate().is_err());
}

#[test]
fn test_config_belnap_low_negative() {
    let mut config = default_config();
    config.belnap_low_threshold = -0.1;
    assert!(config.validate().is_err());
}

#[test]
fn test_config_belnap_high_above_one() {
    let mut config = default_config();
    config.belnap_high_threshold = 1.1;
    assert!(config.validate().is_err());
}

#[test]
fn test_config_macro_confidence_threshold_bounds() {
    let mut config = default_config();
    config.macro_confidence_threshold = -0.01;
    assert!(config.validate().is_err());

    config.macro_confidence_threshold = 1.01;
    assert!(config.validate().is_err());

    config.macro_confidence_threshold = 0.0;
    assert!(config.validate().is_ok());

    config.macro_confidence_threshold = 1.0;
    assert!(config.validate().is_ok());
}

#[test]
fn test_config_macro_loss_threshold_zero() {
    let mut config = default_config();
    config.macro_loss_threshold = 0.0;
    assert!(config.validate().is_err());
}

#[test]
fn test_config_macro_consecutive_checkpoints_zero() {
    let mut config = default_config();
    config.macro_consecutive_checkpoints = 0;
    assert!(config.validate().is_err());
}

#[test]
fn test_config_belnap_inconsistency_threshold_bounds() {
    let mut config = default_config();
    config.belnap_inconsistency_threshold = -0.1;
    assert!(config.validate().is_err());

    config.belnap_inconsistency_threshold = 1.1;
    assert!(config.validate().is_err());

    config.belnap_inconsistency_threshold = 0.0;
    assert!(config.validate().is_ok());

    config.belnap_inconsistency_threshold = 1.0;
    assert!(config.validate().is_ok());
}

#[test]
fn test_config_boundary_dimensions() {
    let mut config = default_config();
    config.embedding_dimensions = 4096;
    assert!(config.validate().is_ok());

    config.embedding_dimensions = 4097;
    assert!(config.validate().is_err());

    config.embedding_dimensions = 1;
    assert!(config.validate().is_ok());
}

// ============================================================================
// 3. Belnap: k_level coverage + Display for all values
// ============================================================================

#[test]
fn test_belnap_k_level_all_values() {
    assert_eq!(BelnapValue::Neither.k_level(), 0);
    assert_eq!(BelnapValue::True.k_level(), 1);
    assert_eq!(BelnapValue::False.k_level(), 1);
    assert_eq!(BelnapValue::Both.k_level(), 2);
}

#[test]
fn test_belnap_default_is_neither() {
    let v: BelnapValue = Default::default();
    assert_eq!(v, BelnapValue::Neither);
}

// ============================================================================
// 4. Softmax edge cases
// ============================================================================

#[test]
fn test_softmax_weights_empty() {
    let w = softmax_weights(&[], 1.0);
    assert!(w.is_empty());
}

#[test]
fn test_softmax_weights_single_element() {
    let w = softmax_weights(&[42.0], 1.0);
    assert_eq!(w.len(), 1);
    assert!((w[0] - 1.0).abs() < 1e-6);
}

#[test]
fn test_softmax_weights_zero_temperature_clamps() {
    // Temperature <= epsilon should be clamped to 1.0
    let w = softmax_weights(&[1.0, 2.0, 3.0], 0.0);
    assert_eq!(w.len(), 3);
    let sum: f32 = w.iter().sum();
    assert!((sum - 1.0).abs() < 1e-5);
}

#[test]
fn test_softmax_weights_all_zeros() {
    let w = softmax_weights(&[0.0, 0.0, 0.0, 0.0], 1.0);
    for &wi in &w {
        assert!((wi - 0.25).abs() < 1e-5, "all-zero should give uniform");
    }
}

#[test]
fn test_blue_scores_to_trust_weights_empty() {
    let w = blue_scores_to_trust_weights(&[], 1.0);
    assert!(w.is_empty());
}

#[test]
fn test_blue_scores_to_trust_weights_single() {
    let w = blue_scores_to_trust_weights(&[42], 1.0);
    assert_eq!(w.len(), 1);
    assert!((w[0] - 1.0).abs() < 1e-6);
}

// ============================================================================
// 5. classify_belnap edge cases
// ============================================================================

#[test]
fn test_classify_belnap_empty() {
    let result = classify_belnap(&[], &[], &[], 1.0, 0.8, 0.3);
    assert!(result.is_empty());
}

#[test]
fn test_classify_belnap_high_conf_negligible_deviation() {
    // All embeddings identical with high confidence -> True at every dim
    let e = EmbeddingVector::new(vec![1.0, 2.0, 3.0]).unwrap();
    let conf = [0.95, 0.95, 0.95];
    let result = classify_belnap(
        &[&e, &e],
        &[&conf[..], &conf[..]],
        &[1.0, 1.0],
        1.0,
        0.8,
        0.3,
    );
    for participant in &result {
        for &v in participant {
            assert_eq!(v, BelnapValue::True);
        }
    }
}

#[test]
fn test_classify_belnap_grey_zone_confidence() {
    // Confidence between theta_low and theta_high (but below theta_high) -> Neither
    let e1 = EmbeddingVector::new(vec![10.0]).unwrap();
    let e2 = EmbeddingVector::new(vec![-10.0]).unwrap();
    let conf = [0.5]; // between 0.3 (low) and 0.8 (high)
    let result = classify_belnap(
        &[&e1, &e2],
        &[&conf[..], &conf[..]],
        &[1.0, 1.0],
        1.0,
        0.8,
        0.3,
    );
    for participant in &result {
        assert_eq!(participant[0], BelnapValue::Neither);
    }
}

// ============================================================================
// 6. reduce_belnap_states edge cases
// ============================================================================

#[test]
fn test_reduce_belnap_states_single_all_neither() {
    let classifications = vec![vec![BelnapValue::Neither; 3]];
    let s = reduce_belnap_states(&classifications);
    assert_eq!(s, vec![BelnapValue::Neither; 3]);
}

#[test]
fn test_reduce_belnap_states_all_both() {
    let classifications = vec![
        vec![BelnapValue::Both, BelnapValue::Both],
        vec![BelnapValue::True, BelnapValue::False],
    ];
    let s = reduce_belnap_states(&classifications);
    // join(Both, True) = Both, join(Both, False) = Both
    assert_eq!(s, vec![BelnapValue::Both, BelnapValue::Both]);
}

// ============================================================================
// 7. EmbeddingVector: add dimension mismatch, scale, PartialEq
// ============================================================================

#[test]
fn test_embedding_add_dimension_mismatch() {
    let a = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
    let b = EmbeddingVector::new(vec![1.0, 2.0, 3.0]).unwrap();
    assert!(a.add(&b).is_err());
}

#[test]
fn test_embedding_scale() {
    let v = EmbeddingVector::new(vec![2.0, 3.0]).unwrap();
    let scaled = v.scale(0.5);
    assert!((scaled.data[0] - 1.0).abs() < 1e-6);
    assert!((scaled.data[1] - 1.5).abs() < 1e-6);
}

#[test]
fn test_embedding_partial_eq() {
    let a = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
    let b = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
    let c = EmbeddingVector::new(vec![1.0, 3.0]).unwrap();
    let d = EmbeddingVector::new(vec![1.0, 2.0, 3.0]).unwrap();

    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_ne!(a, d); // Different dimensions
}

#[test]
fn test_embedding_zeros_and_dim() {
    let z = EmbeddingVector::zeros(5);
    assert_eq!(z.dim(), 5);
    assert_eq!(z.l2_norm(), 0.0);
}

#[test]
fn test_embedding_negative_inf() {
    let result = EmbeddingVector::new(vec![f32::NEG_INFINITY, 1.0]);
    assert!(result.is_err());
}

#[test]
fn test_embedding_space_boundary() {
    assert!(EmbeddingSpace::new(1).is_ok());
    assert!(EmbeddingSpace::new(1024).is_ok());
    assert!(EmbeddingSpace::new(0).is_err());
    assert!(EmbeddingSpace::new(1025).is_err());
}

// ============================================================================
// 8. KnowledgeState: merge with zero confidence, empty confidence
// ============================================================================

#[test]
fn test_knowledge_state_confidence_ratio_empty() {
    // Create a zero-dim embedding with empty confidence
    let emb = EmbeddingVector::zeros(0);
    let ks = KnowledgeState {
        embedding: emb,
        confidence: vec![],
        timestamp: 0,
        owner: [0u8; 32],
        round: 0,
    };
    assert_eq!(ks.confidence_ratio(), 0.0);
}

#[test]
fn test_knowledge_state_confidence_ratio_all_true() {
    let emb = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
    let conf = vec![BelnapValue::True, BelnapValue::True];
    let ks = KnowledgeState::new(emb, conf, [0u8; 32], 1, 100).unwrap();
    assert!((ks.confidence_ratio() - 1.0).abs() < 1e-6);
}

#[test]
fn test_knowledge_state_confidence_ratio_all_false_neither() {
    let emb = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
    let conf = vec![BelnapValue::False, BelnapValue::Neither];
    let ks = KnowledgeState::new(emb, conf, [0u8; 32], 1, 100).unwrap();
    assert_eq!(ks.confidence_ratio(), 0.0);
}

#[test]
fn test_knowledge_state_merge_both_zero_confidence() {
    // Both states have confidence_ratio = 0 (all False/Neither)
    let emb1 = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
    let conf1 = vec![BelnapValue::False, BelnapValue::Neither];
    let ks1 = KnowledgeState::new(emb1, conf1, [1u8; 32], 1, 100).unwrap();

    let emb2 = EmbeddingVector::new(vec![3.0, 4.0]).unwrap();
    let conf2 = vec![BelnapValue::Neither, BelnapValue::False];
    let ks2 = KnowledgeState::new(emb2, conf2, [2u8; 32], 2, 200).unwrap();

    let merged = ks1.merge(&ks2).unwrap();
    // Zero total weight -> zero embedding
    assert_eq!(merged.embedding.l2_norm(), 0.0);
    assert_eq!(merged.round, 2);
    assert_eq!(merged.timestamp, 200);
}

#[test]
fn test_knowledge_state_merge_dimension_mismatch() {
    let emb1 = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
    let conf1 = vec![BelnapValue::True, BelnapValue::True];
    let ks1 = KnowledgeState::new(emb1, conf1, [1u8; 32], 1, 100).unwrap();

    let emb2 = EmbeddingVector::new(vec![1.0, 2.0, 3.0]).unwrap();
    let conf2 = vec![BelnapValue::True, BelnapValue::True, BelnapValue::True];
    let ks2 = KnowledgeState::new(emb2, conf2, [2u8; 32], 1, 100).unwrap();

    assert!(ks1.merge(&ks2).is_err());
}

// ============================================================================
// 9. Verification: compute_mean empty, compute_std_dev edge cases
// ============================================================================

#[test]
fn test_compute_mean_empty() {
    use citrate_learning::verification::ByzantineDetector;
    let result = ByzantineDetector::compute_mean(&[]);
    assert!(result.is_err());
}

#[test]
fn test_compute_mean_single_element() {
    use citrate_learning::verification::ByzantineDetector;
    let embeddings = vec![EmbeddingVector::new(vec![3.0, 4.0]).unwrap()];
    let mean = ByzantineDetector::compute_mean(&embeddings).unwrap();
    assert!((mean.data[0] - 3.0).abs() < 1e-6);
    assert!((mean.data[1] - 4.0).abs() < 1e-6);
}

#[test]
fn test_compute_std_dev_single_element() {
    use citrate_learning::verification::ByzantineDetector;
    let embeddings = vec![EmbeddingVector::new(vec![1.0, 2.0]).unwrap()];
    let mean = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
    let std_dev = ByzantineDetector::compute_std_dev(&embeddings, &mean).unwrap();
    assert_eq!(std_dev, 0.0); // < 2 elements returns 0
}

#[test]
fn test_compute_std_dev_multiple_elements() {
    use citrate_learning::verification::ByzantineDetector;
    let embeddings = vec![
        EmbeddingVector::new(vec![0.0, 0.0]).unwrap(),
        EmbeddingVector::new(vec![2.0, 0.0]).unwrap(),
        EmbeddingVector::new(vec![0.0, 2.0]).unwrap(),
    ];
    let mean = ByzantineDetector::compute_mean(&embeddings).unwrap();
    let std_dev = ByzantineDetector::compute_std_dev(&embeddings, &mean).unwrap();
    assert!(std_dev > 0.0, "std_dev should be positive: {}", std_dev);
    assert!(std_dev.is_finite());
}

#[test]
fn test_byzantine_detector_outlier_at_boundary() {
    use citrate_learning::verification::ByzantineDetector;
    let config = LearningConfig {
        byzantine_sigma_threshold: 2.0,
        ..default_config()
    };
    let detector = ByzantineDetector::new(config);
    let mean = EmbeddingVector::new(vec![0.0]).unwrap();
    // Exactly at 2 * std_dev boundary (distance = 2.0, threshold = 2.0 * 1.0 = 2.0)
    let at_boundary = EmbeddingVector::new(vec![2.0]).unwrap();
    // Not outlier: distance == threshold, not strictly greater
    assert!(!detector.is_outlier(&at_boundary, &mean, 1.0).unwrap());

    // Just past boundary
    let past_boundary = EmbeddingVector::new(vec![2.01]).unwrap();
    assert!(detector.is_outlier(&past_boundary, &mean, 1.0).unwrap());
}

#[test]
fn test_byzantine_should_exclude_old_flags_ignored() {
    use citrate_learning::verification::ByzantineDetector;
    let config = LearningConfig {
        byzantine_max_flags: 3,
        ..default_config()
    };
    let mut detector = ByzantineDetector::new(config);
    let pk = [1u8; 32];

    // Flags at very old rounds (current_round=100, lookback=5, so min_round=95)
    detector.record_flag(pk, 1, "old".to_string());
    detector.record_flag(pk, 2, "old".to_string());
    detector.record_flag(pk, 3, "old".to_string());

    // Should NOT be excluded because flags are too old
    assert!(!detector.should_exclude(&pk, 100));
}

#[test]
fn test_byzantine_can_readmit_exact_boundary() {
    use citrate_learning::verification::ByzantineDetector;
    let config = LearningConfig {
        byzantine_cooldown_rounds: 10,
        ..default_config()
    };
    let detector = ByzantineDetector::new(config);

    // Excluded at round 5, cooldown 10
    assert!(!detector.can_readmit(5, 14)); // 9 rounds
    assert!(detector.can_readmit(5, 15)); // 10 rounds (exactly at cooldown)
}

#[test]
fn test_byzantine_can_readmit_saturating_sub() {
    use citrate_learning::verification::ByzantineDetector;
    let config = LearningConfig {
        byzantine_cooldown_rounds: 10,
        ..default_config()
    };
    let detector = ByzantineDetector::new(config);
    // excluded_since > current_round should not panic (saturating_sub)
    assert!(!detector.can_readmit(100, 5));
}

// ============================================================================
// 10. Adapter edge cases: rank = dim, rank = 0, dimension mismatch on LoRA ops
// ============================================================================

#[test]
fn test_lora_create_rank_zero() {
    let emb = EmbeddingVector::new(vec![1.0, 2.0, 3.0]).unwrap();
    let result = AdapterFactory::create_lora(
        &emb,
        0,
        test_metadata(1),
        [1u8; 32],
        100,
        vec![0u8; 64],
    );
    assert!(result.is_err());
}

#[test]
fn test_lora_create_rank_exceeds_dim() {
    let emb = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
    let result = AdapterFactory::create_lora(
        &emb,
        3, // rank > dim (2)
        test_metadata(1),
        [1u8; 32],
        100,
        vec![0u8; 64],
    );
    assert!(result.is_err());
}

#[test]
fn test_lora_create_rank_equals_dim() {
    let emb = EmbeddingVector::new(vec![1.0, 2.0, 3.0]).unwrap();
    let adapter = AdapterFactory::create_lora(
        &emb,
        3, // rank == dim
        test_metadata(1),
        [1u8; 32],
        100,
        vec![0u8; 64],
    )
    .unwrap();
    assert_eq!(adapter.rank, 3);
    assert_eq!(adapter.dim, 3);
}

#[test]
fn test_apply_lora_dimension_mismatch() {
    let adapter = make_lora(4, 2, 1);
    let wrong_dim_base = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
    assert!(apply_lora(&wrong_dim_base, &adapter).is_err());
}

#[test]
fn test_remove_lora_dimension_mismatch() {
    let adapter = make_lora(4, 2, 1);
    let base = EmbeddingVector::new(vec![1.0; 4]).unwrap();
    let wrong_dim = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
    assert!(remove_lora(&wrong_dim, &base, &adapter).is_err());
}

#[test]
fn test_confidence_gated_lora_dim_mismatch_confidence() {
    let adapter = make_lora(4, 2, 1);
    let base = EmbeddingVector::new(vec![1.0; 4]).unwrap();
    let wrong_conf = vec![0.9, 0.8]; // dim 2, not 4
    assert!(apply_lora_confidence_gated(&base, &adapter, &wrong_conf, 0.5).is_err());
}

#[test]
fn test_confidence_gated_lora_dim_mismatch_base() {
    let adapter = make_lora(4, 2, 1);
    let wrong_base = EmbeddingVector::new(vec![1.0; 3]).unwrap();
    let conf = vec![0.9; 4];
    assert!(apply_lora_confidence_gated(&wrong_base, &adapter, &conf, 0.5).is_err());
}

#[test]
fn test_confidence_gated_all_below_threshold() {
    let adapter = make_lora(3, 2, 1);
    let base = EmbeddingVector::new(vec![1.0, 2.0, 3.0]).unwrap();
    let conf = vec![0.1, 0.2, 0.05]; // All below threshold 0.5

    let result = apply_lora_confidence_gated(&base, &adapter, &conf, 0.5).unwrap();
    // All gated out -> result == base
    for i in 0..3 {
        assert!(
            (result.data[i] - base.data[i]).abs() < 1e-6,
            "dim {} should be unchanged",
            i
        );
    }
}

#[test]
fn test_spectral_norm_bound_rank_one() {
    let adapter = make_lora(3, 1, 1);
    let norm = spectral_norm_bound(&adapter);
    assert!(norm > 0.0);
    assert!(norm.is_finite());
}

// ============================================================================
// 11. Compose LoRA: dimension mismatch, chain edge cases
// ============================================================================

#[test]
fn test_compose_lora_dimension_mismatch() {
    let a = make_lora(4, 2, 1);
    let b = make_lora(3, 2, 2);
    let result = compose_lora(&a, &b, test_metadata(3), [1u8; 32], 300, vec![0u8; 64]);
    assert!(result.is_err());
}

#[test]
fn test_compose_lora_chain_empty() {
    let result = compose_lora_chain(&[], test_metadata(1), [1u8; 32], 100, vec![0u8; 64]);
    assert!(result.is_err());
}

#[test]
fn test_compose_lora_chain_single() {
    let a = make_lora(4, 2, 1);
    let result = compose_lora_chain(&[&a], test_metadata(1), [1u8; 32], 100, vec![0u8; 64]);
    assert!(result.is_ok());
    let composed = result.unwrap();
    assert_eq!(composed.rank, 2);
    assert_eq!(composed.dim, 4);
}

#[test]
fn test_compose_lora_chain_three() {
    let a = make_lora(3, 1, 1);
    let b = make_lora(3, 1, 2);
    let c = make_lora(3, 1, 3);
    let composed = compose_lora_chain(
        &[&a, &b, &c],
        test_metadata(4),
        [1u8; 32],
        400,
        vec![0u8; 64],
    )
    .unwrap();
    assert_eq!(composed.rank, 3); // 1+1+1
    assert_eq!(composed.dim, 3);
}

// ============================================================================
// 12. Provenance chain: missing parent hash on second entry
// ============================================================================

#[test]
fn test_provenance_chain_missing_parent_at_entry_1() {
    let entry0 = ProvenanceEntry {
        creator: [1u8; 32],
        round: 1,
        checkpoint_height: 100,
        parent_adapter_hash: None,
        timestamp: 10000,
        signature: vec![0u8; 64],
    };
    let entry1 = ProvenanceEntry {
        creator: [2u8; 32],
        round: 2,
        checkpoint_height: 200,
        parent_adapter_hash: None, // Missing parent hash!
        timestamp: 10001,
        signature: vec![0u8; 64],
    };
    let mut chain = ProvenanceChain::new(entry0);
    chain.append(entry1);
    let result = chain.validate();
    assert!(result.is_err());
    if let Err(LearningError::AdapterError { reason }) = result {
        assert!(reason.contains("missing parent hash"));
    }
}

#[test]
fn test_provenance_chain_empty() {
    let chain = ProvenanceChain {
        entries: vec![],
    };
    assert!(chain.is_empty());
    assert_eq!(chain.len(), 0);
    // Empty chain validates ok (no links to check)
    assert!(chain.validate().is_ok());
}

#[test]
fn test_provenance_chain_single_entry_validates() {
    let entry = ProvenanceEntry {
        creator: [1u8; 32],
        round: 1,
        checkpoint_height: 100,
        parent_adapter_hash: None,
        timestamp: 10000,
        signature: vec![0u8; 64],
    };
    let chain = ProvenanceChain::new(entry);
    assert_eq!(chain.len(), 1);
    assert!(!chain.is_empty());
    assert!(chain.validate().is_ok());
}

// ============================================================================
// 13. AdapterRegistry: edge cases
// ============================================================================

#[test]
fn test_adapter_registry_list_by_creator_empty() {
    let registry = AdapterRegistry::new();
    let list = registry.list_by_creator(&[99u8; 32]);
    assert!(list.is_empty());
}

#[test]
fn test_adapter_registry_query_nonexistent() {
    let registry = AdapterRegistry::new();
    assert!(registry.query(&[0u8; 32]).is_none());
    assert_eq!(registry.count(), 0);
}

// ============================================================================
// 14. Legacy adapter operations: apply_adapter, compose_adapters dim mismatch
// ============================================================================

#[test]
fn test_apply_adapter_dimension_mismatch() {
    let delta = EmbeddingVector::new(vec![0.1, 0.2, 0.3]).unwrap();
    let adapter = AdapterFactory::create(
        delta,
        test_metadata(1),
        [1u8; 32],
        100,
        vec![0u8; 64],
    )
    .unwrap();
    let bad_base = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
    assert!(apply_adapter(&bad_base, &adapter).is_err());
}

#[test]
fn test_compose_adapters_dimension_mismatch() {
    let d1 = EmbeddingVector::new(vec![0.1, 0.2]).unwrap();
    let d2 = EmbeddingVector::new(vec![0.1, 0.2, 0.3]).unwrap();
    let a1 = AdapterFactory::create(d1, test_metadata(1), [1u8; 32], 100, vec![0u8; 64]).unwrap();
    let a2 = AdapterFactory::create(d2, test_metadata(2), [2u8; 32], 200, vec![0u8; 64]).unwrap();
    assert!(compose_adapters(&a1, &a2).is_err());
}

// ============================================================================
// 15. Aggregation: validation failures
// ============================================================================

#[test]
fn test_aggregation_input_validate_confidence_count_mismatch() {
    let e = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
    let _conf = [0.9, 0.9];
    let input = AggregationInput {
        embeddings: &[&e],
        confidences: &[], // Empty, but 1 embedding
        blue_scores: &[1.0],
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    };
    assert!(input.validate().is_err());
}

#[test]
fn test_aggregation_input_validate_blue_scores_count_mismatch() {
    let e = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
    let conf = vec![0.9, 0.9];
    let input = AggregationInput {
        embeddings: &[&e],
        confidences: &[&conf],
        blue_scores: &[], // Empty, but 1 embedding
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    };
    assert!(input.validate().is_err());
}

#[test]
fn test_aggregation_input_validate_embedding_dim_mismatch() {
    let e1 = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
    let e2 = EmbeddingVector::new(vec![1.0, 2.0, 3.0]).unwrap();
    let conf1 = [0.9, 0.9];
    let conf2 = [0.9, 0.9, 0.9];
    let input = AggregationInput {
        embeddings: &[&e1, &e2],
        confidences: &[&conf1[..], &conf2[..]],
        blue_scores: &[1.0, 1.0],
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    };
    assert!(input.validate().is_err());
}

#[test]
fn test_aggregation_input_validate_confidence_dim_mismatch() {
    let e1 = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
    let e2 = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
    let conf1 = [0.9, 0.9];
    let conf2 = [0.9]; // Wrong dim
    let input = AggregationInput {
        embeddings: &[&e1, &e2],
        confidences: &[&conf1[..], &conf2[..]],
        blue_scores: &[1.0, 1.0],
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    };
    assert!(input.validate().is_err());
}

#[test]
fn test_paraconsistent_aggregator_nan_in_embedding() {
    let agg = ParaconsistentAggregator::new(2);
    let bad = EmbeddingVector {
        data: vec![f32::INFINITY, 1.0],
    };
    let conf = [0.9, 0.9];
    let input = AggregationInput {
        embeddings: &[&bad],
        confidences: &[&conf[..]],
        blue_scores: &[1.0],
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    };
    assert!(agg.aggregate_paraconsistent(&input).is_err());
}

#[test]
fn test_weighted_mean_negative_weight_excluded() {
    let agg = WeightedMeanAggregator::new(2);
    let e1 = EmbeddingVector::new(vec![1.0, 0.0]).unwrap();
    let e2 = EmbeddingVector::new(vec![0.0, 1.0]).unwrap();

    // Negative weight should be skipped
    let result = agg.aggregate(&[(e1, 1.0), (e2, -0.5)]).unwrap();
    assert!((result.data[0] - 1.0).abs() < 1e-6);
    assert!(result.data[1].abs() < 1e-6);
}

#[test]
fn test_blue_score_to_weight_edge_cases() {
    assert_eq!(blue_score_to_weight(0, 0), 0.0);
    assert_eq!(blue_score_to_weight(100, 0), 0.0);
    assert!((blue_score_to_weight(1, 3) - 1.0 / 3.0).abs() < 1e-6);
}

// ============================================================================
// 16. OodaPhase: Display, name, next cycle
// ============================================================================

#[test]
fn test_ooda_phase_cycle() {
    assert_eq!(OodaPhase::Observe.next(), OodaPhase::Orient);
    assert_eq!(OodaPhase::Orient.next(), OodaPhase::Decide);
    assert_eq!(OodaPhase::Decide.next(), OodaPhase::Act);
    assert_eq!(OodaPhase::Act.next(), OodaPhase::Observe);
}

#[test]
fn test_ooda_phase_name() {
    assert_eq!(OodaPhase::Observe.name(), "Observe");
    assert_eq!(OodaPhase::Orient.name(), "Orient");
    assert_eq!(OodaPhase::Decide.name(), "Decide");
    assert_eq!(OodaPhase::Act.name(), "Act");
}

#[test]
fn test_ooda_phase_display() {
    assert_eq!(format!("{}", OodaPhase::Observe), "Observe");
    assert_eq!(format!("{}", OodaPhase::Orient), "Orient");
    assert_eq!(format!("{}", OodaPhase::Decide), "Decide");
    assert_eq!(format!("{}", OodaPhase::Act), "Act");
}

#[test]
fn test_network_learning_phase_display() {
    assert_eq!(
        format!("{}", NetworkLearningPhase::Collection),
        "Collection"
    );
    assert_eq!(
        format!("{}", NetworkLearningPhase::RoutingActive),
        "RoutingActive"
    );
    assert_eq!(
        format!("{}", NetworkLearningPhase::FullSystem),
        "FullSystem"
    );
}

// ============================================================================
// 17. PhaseManager: transition failure, restore
// ============================================================================

#[test]
fn test_phase_manager_transition_fails_without_condition() {
    let mut pm = PhaseManager::new(LearningConfig {
        min_participants: 5,
        phase_timeout_ms: 999_999,
        ..default_config()
    });
    // Only 1 submission, need 5
    pm.record_submission();
    let result = pm.transition();
    assert!(result.is_err());
}

#[test]
fn test_phase_manager_restore() {
    use citrate_learning::phases::PhaseState;
    let state = PhaseState {
        phase: OodaPhase::Decide,
        round: 10,
        submissions: 7,
        condition_met: true,
        started_at_ms: 50000,
    };
    let pm = PhaseManager::restore(state, default_config());
    assert_eq!(pm.current_phase(), OodaPhase::Decide);
    assert_eq!(pm.current_round(), 10);
}

#[test]
fn test_phase_manager_elapsed_ms() {
    let pm = PhaseManager::new(default_config());
    // Should be very small (close to 0)
    let elapsed = pm.elapsed_ms();
    assert!(elapsed < 100, "elapsed should be small: {}", elapsed);
}

// ============================================================================
// 18. MacroPhaseManager: restore, RoutingActive with no router_loss
// ============================================================================

#[test]
fn test_macro_phase_manager_restore() {
    let config = default_config();
    let mgr = MacroPhaseManager::restore(NetworkLearningPhase::RoutingActive, config);
    assert_eq!(mgr.current_phase(), NetworkLearningPhase::RoutingActive);
    assert!(mgr.can_route());
    assert!(!mgr.can_adapt());
}

#[test]
fn test_macro_phase_routing_active_no_loss() {
    let config = LearningConfig {
        macro_confidence_threshold: 0.5,
        macro_consecutive_checkpoints: 1,
        ..default_config()
    };
    let mut mgr = MacroPhaseManager::new(config);
    mgr.evaluate_checkpoint(0.8, None); // Transitions to RoutingActive
    assert_eq!(mgr.current_phase(), NetworkLearningPhase::RoutingActive);

    // In RoutingActive, None router_loss => no transition
    let result = mgr.evaluate_checkpoint(0.9, None);
    assert!(result.is_none());
    assert_eq!(mgr.current_phase(), NetworkLearningPhase::RoutingActive);
}

#[test]
fn test_macro_phase_routing_active_loss_too_high_resets() {
    let config = LearningConfig {
        macro_confidence_threshold: 0.5,
        macro_loss_threshold: 0.5,
        macro_consecutive_checkpoints: 3,
        ..default_config()
    };
    let mut mgr = MacroPhaseManager::new(config);

    // Fast-forward to RoutingActive
    mgr.evaluate_checkpoint(0.8, None);
    mgr.evaluate_checkpoint(0.8, None);
    mgr.evaluate_checkpoint(0.8, None);
    assert_eq!(mgr.current_phase(), NetworkLearningPhase::RoutingActive);

    // Two low-loss checkpoints
    mgr.evaluate_checkpoint(0.3, Some(0.2));
    mgr.evaluate_checkpoint(0.3, Some(0.1));
    // Then a high-loss checkpoint -> resets counter
    mgr.evaluate_checkpoint(0.3, Some(0.8));
    // One more low-loss -> not enough consecutive
    let result = mgr.evaluate_checkpoint(0.3, Some(0.1));
    assert!(result.is_none());
    assert_eq!(mgr.current_phase(), NetworkLearningPhase::RoutingActive);
}

// ============================================================================
// 19. Safety: LearningMode Display, SafetyGuard Default impl
// ============================================================================

#[test]
fn test_learning_mode_display() {
    assert_eq!(format!("{}", LearningMode::Disabled), "disabled");
    assert_eq!(format!("{}", LearningMode::Passive), "passive");
    assert_eq!(format!("{}", LearningMode::Active), "active");
}

#[test]
fn test_safety_guard_default() {
    let guard = SafetyGuard::default();
    assert_eq!(guard.mode(), LearningMode::Disabled);
    assert!(!guard.is_enabled());
    assert!(!guard.is_active());
    assert!(guard.transition_log().is_empty());
}

#[test]
fn test_learning_mode_default() {
    let mode: LearningMode = Default::default();
    assert_eq!(mode, LearningMode::Disabled);
}

// ============================================================================
// 20. Storage: EmbeddingIndex edge cases
// ============================================================================

#[test]
fn test_embedding_index_default() {
    use citrate_learning::storage::EmbeddingIndex;
    let index = EmbeddingIndex::default();
    assert!(index.is_empty());
    assert_eq!(index.len(), 0);
}

#[test]
fn test_embedding_index_snapshot() {
    use citrate_learning::storage::EmbeddingIndex;
    let index = EmbeddingIndex::new();
    index.insert([1u8; 32], EmbeddingVector::zeros(2), 1, 100);
    index.insert([2u8; 32], EmbeddingVector::zeros(2), 2, 200);

    let snap = index.snapshot();
    assert_eq!(snap.len(), 2);
}

#[test]
fn test_embedding_index_remove_nonexistent() {
    use citrate_learning::storage::EmbeddingIndex;
    let index = EmbeddingIndex::new();
    assert!(index.remove(&[99u8; 32]).is_none());
}

#[test]
fn test_embedding_index_get_nonexistent() {
    use citrate_learning::storage::EmbeddingIndex;
    let index = EmbeddingIndex::new();
    assert!(index.get(&[99u8; 32]).is_none());
}

#[test]
fn test_embedding_index_prune_stale_none_removed() {
    use citrate_learning::storage::EmbeddingIndex;
    let index = EmbeddingIndex::new();
    index.insert([1u8; 32], EmbeddingVector::zeros(2), 10, 100);
    // Current round 12, max_age 5 -> prune round < 7. Round 10 is safe.
    assert_eq!(index.prune_stale(5, 12), 0);
    assert_eq!(index.len(), 1);
}

#[test]
fn test_embedding_index_prune_stale_saturating() {
    use citrate_learning::storage::EmbeddingIndex;
    let index = EmbeddingIndex::new();
    index.insert([1u8; 32], EmbeddingVector::zeros(2), 0, 100);
    // current_round=0, max_age=5 => min_round = 0.saturating_sub(5) = 0
    // round 0 < 0 is false, so nothing pruned
    assert_eq!(index.prune_stale(5, 0), 0);
}

#[test]
fn test_embedding_index_list_by_round_empty() {
    use citrate_learning::storage::EmbeddingIndex;
    let index = EmbeddingIndex::new();
    assert!(index.list_by_round(42).is_empty());
}

// ============================================================================
// 21. PhaseStore: edge cases, PhaseStore default
// ============================================================================

#[test]
fn test_phase_store_default() {
    let store = PhaseStore::default();
    assert!(store.load_phase_state().unwrap().is_none());
    assert!(store.load_macro_phase().unwrap().is_none());
}

#[test]
fn test_phase_store_recovery_with_no_state() {
    let store = PhaseStore::new();
    let result = store.load_phase_state_with_recovery().unwrap();
    assert!(result.is_none());
}

#[test]
fn test_phase_store_overwrite_phase_state() {
    use citrate_learning::phases::PhaseState;
    let store = PhaseStore::new();
    let state1 = PhaseState {
        phase: OodaPhase::Observe,
        round: 1,
        submissions: 0,
        condition_met: false,
        started_at_ms: 1000,
    };
    store.save_phase_state(&state1).unwrap();

    let state2 = PhaseState {
        phase: OodaPhase::Act,
        round: 5,
        submissions: 3,
        condition_met: true,
        started_at_ms: 5000,
    };
    store.save_phase_state(&state2).unwrap();

    let loaded = store.load_phase_state().unwrap().unwrap();
    assert_eq!(loaded.phase, OodaPhase::Act);
    assert_eq!(loaded.round, 5);
}

#[test]
fn test_phase_store_recovery_from_decide_phase() {
    use citrate_learning::phases::PhaseState;
    let store = PhaseStore::new();
    let state = PhaseState {
        phase: OodaPhase::Decide,
        round: 8,
        submissions: 5,
        condition_met: true,
        started_at_ms: 80000,
    };
    store.save_phase_state(&state).unwrap();

    let recovered = store.load_phase_state_with_recovery().unwrap().unwrap();
    assert_eq!(recovered.phase, OodaPhase::Observe); // Reset
    assert_eq!(recovered.round, 8); // Same round
    assert_eq!(recovered.submissions, 0); // Reset
    assert!(!recovered.condition_met); // Reset
}

#[test]
fn test_phase_store_recovery_from_act_phase() {
    use citrate_learning::phases::PhaseState;
    let store = PhaseStore::new();
    let state = PhaseState {
        phase: OodaPhase::Act,
        round: 3,
        submissions: 2,
        condition_met: false,
        started_at_ms: 30000,
    };
    store.save_phase_state(&state).unwrap();

    let recovered = store.load_phase_state_with_recovery().unwrap().unwrap();
    assert_eq!(recovered.phase, OodaPhase::Observe);
    assert_eq!(recovered.round, 3);
}

// ============================================================================
// 22. Routing: encode_belnap_flat, train_step target out of bounds
// ============================================================================

#[test]
fn test_encode_belnap_flat_empty() {
    let encoded = encode_belnap_flat(&[]);
    assert!(encoded.is_empty());
}

#[test]
fn test_encode_belnap_flat_all_values() {
    let state = vec![
        BelnapValue::True,
        BelnapValue::False,
        BelnapValue::Both,
        BelnapValue::Neither,
    ];
    let encoded = encode_belnap_flat(&state);
    assert_eq!(encoded.len(), 16); // 4 * 4
    assert_eq!(&encoded[0..4], &[1.0, 0.0, 0.0, 0.0]); // True
    assert_eq!(&encoded[4..8], &[0.0, 1.0, 0.0, 0.0]); // False
    assert_eq!(&encoded[8..12], &[0.0, 0.0, 1.0, 0.0]); // Both
    assert_eq!(&encoded[12..16], &[0.0, 0.0, 0.0, 1.0]); // Neither
}

#[test]
fn test_router_train_step_target_out_of_bounds() {
    let dim = 4;
    let mut router = MlpRouter::new(dim, 8, 3, 42);
    let query = EmbeddingVector::new(vec![1.0; dim]).unwrap();
    let e_agg = EmbeddingVector::new(vec![0.5; dim]).unwrap();
    let state = vec![BelnapValue::True; dim];

    let result = router.train_step(&query, &e_agg, &state, 5, 0.01); // target 5 >= 3 destinations
    assert!(result.is_err());
}

#[test]
fn test_router_e_agg_dimension_mismatch() {
    let router = MlpRouter::new(4, 8, 3, 42);
    let query = EmbeddingVector::new(vec![1.0; 4]).unwrap();
    let bad_e_agg = EmbeddingVector::new(vec![0.5; 2]).unwrap(); // Wrong dim
    let state = vec![BelnapValue::True; 4];
    assert!(router.route(&query, &bad_e_agg, &state).is_err());
}

// ============================================================================
// 23. Checkpoint: participant_count, serialization with all fields set
// ============================================================================

#[test]
fn test_checkpoint_participant_count() {
    let snap = vec![
        ([1u8; 32], EmbeddingVector::zeros(2)),
        ([2u8; 32], EmbeddingVector::zeros(2)),
        ([3u8; 32], EmbeddingVector::zeros(2)),
    ];
    let cp = LearningCheckpoint::new(100, [0u8; 32], snap, 1);
    assert_eq!(cp.participant_count(), 3);
}

#[test]
fn test_checkpoint_full_serialization_roundtrip() {
    let mut cp = LearningCheckpoint::new(200, [1u8; 32], vec![], 10);
    cp.set_routing_weights_hash([0xAA; 32]);
    cp.set_adapter_registry_hash([0xBB; 32]);
    cp.set_performance_profile_hash([0xCC; 32]);
    cp.set_paraconsistent_result(AggregationResult {
        embedding: EmbeddingVector::new(vec![0.5, 0.8]).unwrap(),
        state_vector: vec![BelnapValue::True, BelnapValue::Both],
        confidence: 0.75,
    });
    cp.macro_phase = Some(NetworkLearningPhase::FullSystem);

    let json = serde_json::to_string(&cp).unwrap();
    let deser: LearningCheckpoint = serde_json::from_str(&json).unwrap();

    assert_eq!(deser.height, 200);
    assert_eq!(deser.routing_weights_hash, Some([0xAA; 32]));
    assert_eq!(deser.adapter_registry_hash, Some([0xBB; 32]));
    assert_eq!(deser.performance_profile_hash, Some([0xCC; 32]));
    assert!(deser.aggregated_result.is_some()); // Backward compat
    assert!(deser.aggregation_result.is_some());
    assert_eq!(
        deser.macro_phase,
        Some(NetworkLearningPhase::FullSystem)
    );
    assert_eq!(
        deser.state_vector.as_ref().unwrap()[0],
        BelnapValue::True
    );
}

// ============================================================================
// 24. Types: ParticipantRole enum coverage, TimestampedEmbedding with confidence
// ============================================================================

#[test]
fn test_participant_role_eq() {
    assert_eq!(ParticipantRole::Full, ParticipantRole::Full);
    assert_ne!(ParticipantRole::Full, ParticipantRole::Observer);
    assert_ne!(ParticipantRole::Observer, ParticipantRole::Validator);
}

#[test]
fn test_participant_excluded_fields() {
    let p = Participant {
        pubkey: [1u8; 32],
        role: ParticipantRole::Validator,
        stake_weight: 0.3,
        current_embedding: None,
        confidence: vec![],
        last_active_round: 0,
        byzantine_flags: 2,
        excluded: true,
        excluded_since: Some(42),
    };
    let json = serde_json::to_string(&p).unwrap();
    let deser: Participant = serde_json::from_str(&json).unwrap();
    assert_eq!(deser.role, ParticipantRole::Validator);
    assert!(deser.excluded);
    assert_eq!(deser.excluded_since, Some(42));
    assert_eq!(deser.byzantine_flags, 2);
}

#[test]
fn test_learning_round_with_aggregated_embedding() {
    let round = LearningRound {
        round: 5,
        phase: OodaPhase::Act,
        participants: vec![[1u8; 32]],
        checkpoint_height: 500,
        started_at: 1000,
        completed_at: Some(2000),
        aggregated_embedding: Some(EmbeddingVector::new(vec![0.5, 0.5]).unwrap()),
    };
    let json = serde_json::to_string(&round).unwrap();
    let deser: LearningRound = serde_json::from_str(&json).unwrap();
    assert_eq!(deser.round, 5);
    assert_eq!(deser.completed_at, Some(2000));
    assert!(deser.aggregated_embedding.is_some());
}

// ============================================================================
// 25. Pipeline: router_mut accessor, act increments round
// ============================================================================

#[test]
fn test_pipeline_router_mut_accessible() {
    let config = LearningConfig {
        embedding_dimensions: 4,
        ..default_config()
    };
    let mut pipeline = LearningPipeline::new(&config);

    let query = EmbeddingVector::new(vec![1.0; 4]).unwrap();
    let e_agg = EmbeddingVector::new(vec![0.5; 4]).unwrap();
    let state = vec![BelnapValue::True; 4];

    // Train through the router_mut accessor
    let loss = pipeline
        .router_mut()
        .train_step(&query, &e_agg, &state, 1, 0.01)
        .unwrap();
    assert!(loss.is_finite());
}

#[test]
fn test_pipeline_act_increments_round() {
    let config = LearningConfig {
        embedding_dimensions: 4,
        lora_rank: 2,
        ..default_config()
    };
    let mut pipeline = LearningPipeline::new(&config);

    let e1 = EmbeddingVector::new(vec![1.0; 4]).unwrap();
    let conf = [0.9; 4];
    let query = EmbeddingVector::new(vec![0.5; 4]).unwrap();
    let input = AggregationInput {
        embeddings: &[&e1],
        confidences: &[&conf[..]],
        blue_scores: &[1.0],
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    };

    // First cycle
    let r1 = pipeline
        .execute_cycle(&query, &input, true, [1u8; 32], 100)
        .unwrap();
    let adapter1 = r1.adapter.unwrap();
    assert_eq!(adapter1.metadata.round, 1);

    // Second cycle
    let r2 = pipeline
        .execute_cycle(&query, &input, true, [1u8; 32], 200)
        .unwrap();
    let adapter2 = r2.adapter.unwrap();
    assert_eq!(adapter2.metadata.round, 2);
}

// ============================================================================
// 26. Safety: adapter safety with tampered adapter (violation path)
// ============================================================================

#[test]
fn test_safety_guard_verify_adapter_dimension_mismatch() {
    let guard = SafetyGuard::new();
    let base = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
    let adapter = make_lora(4, 2, 1); // dim 4, base is dim 2
    let result = guard.verify_adapter_safety(&base, &adapter);
    assert!(result.is_err());
}

// ============================================================================
// 27. Verification: verify_adapter_provenance with valid chain
// ============================================================================

#[test]
fn test_verify_adapter_provenance_valid() {
    use citrate_learning::verification::ByzantineDetector;
    let config = default_config();
    let detector = ByzantineDetector::new(config);

    let adapter = make_lora(4, 2, 1);
    assert!(detector.verify_adapter_provenance(&adapter).is_ok());
}

#[test]
fn test_verify_adapter_provenance_tampered_hash() {
    use citrate_learning::verification::ByzantineDetector;
    let config = default_config();
    let detector = ByzantineDetector::new(config);

    let mut adapter = make_lora(4, 2, 1);
    adapter.matrix_b[0][0] += 1.0; // Tamper
    let result = detector.verify_adapter_provenance(&adapter);
    assert!(result.is_err());
}

// ============================================================================
// 28. Embedding dot product and cosine similarity with zero vectors
// ============================================================================

#[test]
fn test_embedding_dot_product() {
    let a = EmbeddingVector::new(vec![1.0, 2.0, 3.0]).unwrap();
    let b = EmbeddingVector::new(vec![4.0, 5.0, 6.0]).unwrap();
    let dot = a.dot(&b).unwrap();
    assert!((dot - 32.0).abs() < 1e-6); // 4 + 10 + 18
}

#[test]
fn test_embedding_cosine_similarity_both_zero() {
    let a = EmbeddingVector::zeros(3);
    let b = EmbeddingVector::zeros(3);
    assert_eq!(a.cosine_similarity(&b).unwrap(), 0.0);
}

// ============================================================================
// 29. Integration: full end-to-end round with Byzantine detection
// ============================================================================

#[test]
fn test_full_round_with_byzantine_check() {
    use citrate_learning::verification::ByzantineDetector;

    let config = LearningConfig {
        embedding_dimensions: 3,
        byzantine_sigma_threshold: 2.0,
        belnap_inconsistency_threshold: 0.5,
        ..default_config()
    };
    let mut detector = ByzantineDetector::new(config);

    // Three participants: two honest, one outlier
    let e_honest1 = EmbeddingVector::new(vec![1.0, 1.0, 1.0]).unwrap();
    let e_honest2 = EmbeddingVector::new(vec![1.1, 0.9, 1.05]).unwrap();
    let e_byzantine = EmbeddingVector::new(vec![100.0, -100.0, 50.0]).unwrap();

    let all = vec![e_honest1.clone(), e_honest2.clone(), e_byzantine.clone()];
    let mean = ByzantineDetector::compute_mean(&all).unwrap();
    let std_dev = ByzantineDetector::compute_std_dev(&all, &mean).unwrap();

    // Check honest participant
    let clean_state = vec![BelnapValue::True; 3];
    let reasons = detector
        .check_and_flag([1u8; 32], 1, &e_honest1, &mean, std_dev, &clean_state)
        .unwrap();
    assert!(reasons.is_empty(), "honest participant should not be flagged");

    // Check byzantine participant
    let bad_state = vec![BelnapValue::Both; 3]; // 100% Both
    let reasons = detector
        .check_and_flag([3u8; 32], 1, &e_byzantine, &mean, std_dev, &bad_state)
        .unwrap();
    assert!(
        !reasons.is_empty(),
        "byzantine participant should be flagged: {:?}",
        reasons
    );
}

// ============================================================================
// 30. Routing: serialization roundtrip for RoutingDecision
// ============================================================================

#[test]
fn test_routing_decision_serialization() {
    let decision = RoutingDecision {
        probabilities: vec![0.2, 0.5, 0.3],
        selected: 1,
    };
    let json = serde_json::to_string(&decision).unwrap();
    let deser: RoutingDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(deser.selected, 1);
    assert_eq!(deser.probabilities.len(), 3);
    assert!((deser.probabilities[1] - 0.5).abs() < 1e-6);
}

// ============================================================================
// 31. MlpRouter: serialization roundtrip
// ============================================================================

#[test]
fn test_mlp_router_serialization_roundtrip() {
    let router = MlpRouter::new(4, 8, 3, 42);
    let json = serde_json::to_string(&router).unwrap();
    let deser: MlpRouter = serde_json::from_str(&json).unwrap();

    // Verify routing produces identical output
    let query = EmbeddingVector::new(vec![1.0; 4]).unwrap();
    let e_agg = EmbeddingVector::new(vec![0.5; 4]).unwrap();
    let state = vec![BelnapValue::True; 4];

    let d1 = router.route(&query, &e_agg, &state).unwrap();
    let d2 = deser.route(&query, &e_agg, &state).unwrap();
    assert_eq!(d1.selected, d2.selected);
    for (a, b) in d1.probabilities.iter().zip(d2.probabilities.iter()) {
        assert!((a - b).abs() < 1e-6);
    }
}

// ============================================================================
// 32. LoraAdapter serialization roundtrip
// ============================================================================

#[test]
fn test_lora_adapter_serialization_roundtrip() {
    let adapter = make_lora(4, 2, 1);
    let json = serde_json::to_string(&adapter).unwrap();
    let deser: LoraAdapter = serde_json::from_str(&json).unwrap();
    assert_eq!(deser.dim, 4);
    assert_eq!(deser.rank, 2);
    assert_eq!(deser.id, adapter.id);
    assert!(AdapterFactory::verify_lora_hash(&deser));
}

// ============================================================================
// 33. AggregationResult serialization
// ============================================================================

#[test]
fn test_aggregation_result_serialization() {
    let result = AggregationResult {
        embedding: EmbeddingVector::new(vec![0.5, 0.5]).unwrap(),
        state_vector: vec![BelnapValue::True, BelnapValue::Both],
        confidence: 0.85,
    };
    let json = serde_json::to_string(&result).unwrap();
    let deser: AggregationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(deser.state_vector.len(), 2);
    assert!((deser.confidence - 0.85).abs() < 1e-6);
}

// ============================================================================
// 34. Multiple rounds of phase transitions and state accumulation
// ============================================================================

#[test]
fn test_multiple_full_ooda_cycles() {
    let config = LearningConfig {
        min_participants: 1,
        phase_timeout_ms: 999_999,
        ..default_config()
    };
    let mut pm = PhaseManager::new(config);

    for expected_round in 0..3u64 {
        assert_eq!(pm.current_round(), expected_round);
        assert_eq!(pm.current_phase(), OodaPhase::Observe);

        // Observe -> Orient
        pm.record_submission();
        pm.transition().unwrap();
        assert_eq!(pm.current_phase(), OodaPhase::Orient);

        // Orient -> Decide
        pm.mark_condition_met();
        pm.transition().unwrap();
        assert_eq!(pm.current_phase(), OodaPhase::Decide);

        // Decide -> Act
        pm.mark_condition_met();
        pm.transition().unwrap();
        assert_eq!(pm.current_phase(), OodaPhase::Act);

        // Act -> Observe (next round)
        pm.mark_condition_met();
        pm.transition().unwrap();
    }
    assert_eq!(pm.current_round(), 3);
}
