//! WP-H.6: End-to-End Learning Pipeline Tests (13 pts)
//!
//! Simulates the full OODA cycle across 3 participants, verifying aggregation,
//! Belnap classification, MLP routing, LoRA adapter creation, safety invariant,
//! Byzantine detection, and state persistence.

use citrate_learning::adapters::{
    apply_lora, remove_lora, AdapterFactory, AdapterMetadata, LoraAdapter,
};
use citrate_learning::aggregation::{AggregationInput, ParaconsistentAggregator};
use citrate_learning::belnap::{classify_belnap, reduce_belnap_states, BelnapValue};
use citrate_learning::config::LearningConfig;
use citrate_learning::embeddings::EmbeddingVector;
use citrate_learning::phases::{
    LearningPipeline, MacroPhaseManager, NetworkLearningPhase, OodaPhase, PhaseManager, PhaseState,
};
use citrate_learning::routing::{MlpRouter, Router};
use citrate_learning::safety::SafetyGuard;
use citrate_learning::storage::PhaseStore;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_config(dim: usize) -> LearningConfig {
    LearningConfig {
        embedding_dimensions: dim,
        min_participants: 3,
        phase_timeout_ms: 10_000,
        lora_rank: 4,
        router_hidden_dim: 16,
        router_num_destinations: 4,
        macro_confidence_threshold: 0.5,
        macro_loss_threshold: 0.5,
        macro_consecutive_checkpoints: 1,
        ..LearningConfig::default()
    }
}

fn make_embedding(dim: usize, seed: f32) -> EmbeddingVector {
    let data: Vec<f32> = (0..dim)
        .map(|i| (seed + i as f32 * 0.1).sin())
        .collect();
    EmbeddingVector::new(data).unwrap()
}

fn make_confidence(dim: usize, level: f32) -> Vec<f32> {
    vec![level; dim]
}

fn make_adapter(dim: usize, rank: usize, round: u64, creator: [u8; 32]) -> LoraAdapter {
    let embedding = make_embedding(dim, round as f32);
    AdapterFactory::create_lora(
        &embedding,
        rank,
        AdapterMetadata {
            name: format!("adapter-round-{}", round),
            description: "test adapter".to_string(),
            round,
            participant_count: 3,
            created_at: round * 1000,
        },
        creator,
        round * 100,
        vec![0u8; 64],
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// Test 1: 3 participants submit embeddings → aggregation produces e_agg with
//         Belnap state vector
// ---------------------------------------------------------------------------

#[test]
fn test_three_participants_aggregation_with_belnap() {
    let dim = 16;
    let agg = ParaconsistentAggregator::new(dim);

    // Use identical embeddings so Belnap classification produces True
    let e = make_embedding(dim, 1.0);

    let conf = make_confidence(dim, 0.9);

    let input = AggregationInput {
        embeddings: &[&e, &e, &e],
        confidences: &[&conf, &conf, &conf],
        blue_scores: &[10.0, 8.0, 12.0],
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    };

    let result = agg.aggregate_paraconsistent(&input).unwrap();

    // e_agg dimension matches
    assert_eq!(result.embedding.dim(), dim);
    // State vector has correct length
    assert_eq!(result.state_vector.len(), dim);
    // Confidence is positive (participants had high confidence)
    assert!(result.confidence > 0.0, "confidence should be positive");
    // e_agg is L2-normalized (norm <= 1.0 + epsilon)
    assert!(
        result.embedding.l2_norm() <= 1.0 + 1e-4,
        "e_agg should be normalized, got norm={}",
        result.embedding.l2_norm()
    );

    // Identical embeddings with high confidence → all True
    for (j, &v) in result.state_vector.iter().enumerate() {
        assert_eq!(
            v,
            BelnapValue::True,
            "identical embeddings should produce True at dim {}, got {:?}",
            j,
            v
        );
    }
}

// ---------------------------------------------------------------------------
// Test 2: Belnap classification — all agree → True, mixed → Both, none → Neither
// ---------------------------------------------------------------------------

#[test]
fn test_belnap_classification_all_agree() {
    let dim = 16;
    let e = make_embedding(dim, 2.0);
    let conf = make_confidence(dim, 0.95);

    let result = classify_belnap(
        &[&e, &e, &e],
        &[&conf, &conf, &conf],
        &[10.0, 10.0, 10.0],
        1.0,
        0.8,
        0.3,
    );

    let state = reduce_belnap_states(&result);
    assert_eq!(state.len(), dim);
    for &v in &state {
        assert_eq!(v, BelnapValue::True, "unanimous agreement should be True");
    }
}

#[test]
fn test_belnap_classification_mixed_produces_both() {
    let dim = 16;
    // Two groups with opposite embeddings
    let e_pos: Vec<f32> = (0..dim).map(|_| 5.0).collect();
    let e_neg: Vec<f32> = (0..dim).map(|_| -5.0).collect();
    let e1 = EmbeddingVector::new(e_pos.clone()).unwrap();
    let e2 = EmbeddingVector::new(e_neg.clone()).unwrap();
    let e3 = EmbeddingVector::new(e_pos).unwrap();
    let e4 = EmbeddingVector::new(e_neg).unwrap();
    let conf = make_confidence(dim, 0.95);

    // Equal trust, 2 vs 2 split
    let result = classify_belnap(
        &[&e1, &e2, &e3, &e4],
        &[&conf, &conf, &conf, &conf],
        &[10.0, 10.0, 10.0, 10.0],
        1.0,
        0.8,
        0.3,
    );

    let state = reduce_belnap_states(&result);
    for &v in &state {
        assert_eq!(
            v,
            BelnapValue::Both,
            "equal-weight contradiction should produce Both"
        );
    }
}

#[test]
fn test_belnap_classification_no_evidence_neither() {
    let dim = 16;
    let e1 = make_embedding(dim, 1.0);
    let e2 = make_embedding(dim, 2.0);
    // Very low confidence — below theta_high (0.8)
    let low_conf = make_confidence(dim, 0.1);

    let result = classify_belnap(
        &[&e1, &e2],
        &[&low_conf, &low_conf],
        &[10.0, 10.0],
        1.0,
        0.8,
        0.3,
    );

    let state = reduce_belnap_states(&result);
    for &v in &state {
        assert_eq!(
            v,
            BelnapValue::Neither,
            "low confidence should produce Neither"
        );
    }
}

// ---------------------------------------------------------------------------
// Test 3: MLP router selects destination from aggregated + state vector
// ---------------------------------------------------------------------------

#[test]
fn test_router_selects_from_aggregated_result() {
    let dim = 16;
    let config = test_config(dim);
    let agg = ParaconsistentAggregator::new(dim);

    let e1 = make_embedding(dim, 1.0);
    let e2 = make_embedding(dim, 1.05);
    let e3 = make_embedding(dim, 1.1);
    let conf = make_confidence(dim, 0.9);
    let query = make_embedding(dim, 0.5);

    let input = AggregationInput {
        embeddings: &[&e1, &e2, &e3],
        confidences: &[&conf, &conf, &conf],
        blue_scores: &[10.0, 8.0, 12.0],
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    };

    let agg_result = agg.aggregate_paraconsistent(&input).unwrap();

    let router = MlpRouter::new(
        dim,
        config.router_hidden_dim,
        config.router_num_destinations,
        42,
    );

    let decision = router
        .route(&query, &agg_result.embedding, &agg_result.state_vector)
        .unwrap();

    // Probabilities sum to 1
    let prob_sum: f32 = decision.probabilities.iter().sum();
    assert!(
        (prob_sum - 1.0).abs() < 1e-4,
        "probabilities should sum to 1.0, got {}",
        prob_sum
    );
    // Selected is a valid destination
    assert!(decision.selected < config.router_num_destinations);
    // All probabilities are non-negative
    assert!(decision.probabilities.iter().all(|&p| p >= 0.0));
}

// ---------------------------------------------------------------------------
// Test 4: LoRA adapter generated and applied to base vector
// ---------------------------------------------------------------------------

#[test]
fn test_lora_adapter_generated_and_applied() {
    let dim = 16;
    let config = test_config(dim);
    let mut pipeline = LearningPipeline::new(&config);

    let e1 = make_embedding(dim, 1.0);
    let e2 = make_embedding(dim, 1.05);
    let e3 = make_embedding(dim, 1.1);
    let conf = make_confidence(dim, 0.9);
    let query = make_embedding(dim, 0.5);

    let input = AggregationInput {
        embeddings: &[&e1, &e2, &e3],
        confidences: &[&conf, &conf, &conf],
        blue_scores: &[10.0, 8.0, 12.0],
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    };

    let result = pipeline
        .execute_cycle(&query, &input, true, [1u8; 32], 100)
        .unwrap();

    let adapter = result.adapter.expect("should produce LoRA adapter");
    assert_eq!(adapter.dim, dim);
    assert_eq!(adapter.rank, config.lora_rank);
    assert!(AdapterFactory::verify_lora_hash(&adapter));

    // Apply adapter to a base vector
    let base = make_embedding(dim, 3.0);
    let modified = apply_lora(&base, &adapter).unwrap();
    assert_eq!(modified.dim(), dim);

    // Modified should differ from base
    let diff: f32 = base
        .data
        .iter()
        .zip(modified.data.iter())
        .map(|(a, b)| (a - b).abs())
        .sum();
    assert!(diff > 1e-8, "adapter should modify the base vector");
}

// ---------------------------------------------------------------------------
// Test 5: Safety guard verifies state root invariant (apply then remove = original)
// ---------------------------------------------------------------------------

#[test]
fn test_safety_guard_adapter_reversibility() {
    let dim = 16;
    let guard = SafetyGuard::new();
    let base = make_embedding(dim, 42.0);
    let adapter = make_adapter(dim, 4, 1, [1u8; 32]);

    // Verify the safety invariant: apply + remove = identity
    assert!(
        guard.verify_adapter_safety(&base, &adapter).is_ok(),
        "adapter should be cleanly reversible"
    );

    // Also verify manually
    let modified = apply_lora(&base, &adapter).unwrap();
    let restored = remove_lora(&modified, &base, &adapter).unwrap();

    for i in 0..dim {
        assert!(
            (restored.data[i] - base.data[i]).abs() < 1e-5,
            "dim {} mismatch after restore: {} vs {}",
            i,
            restored.data[i],
            base.data[i]
        );
    }

    // State root invariant (matching roots pass)
    let root = [0xABu8; 32];
    assert!(guard.verify_state_invariant(root, root).is_ok());

    // Mismatching roots fail
    let root_b = [0xCDu8; 32];
    assert!(guard.verify_state_invariant(root, root_b).is_err());
}

// ---------------------------------------------------------------------------
// Test 6: Byzantine participant (random embeddings) detected and excluded via
//         blue-score weighting
// ---------------------------------------------------------------------------

#[test]
fn test_byzantine_participant_excluded_by_blue_score() {
    let dim = 16;
    let agg = ParaconsistentAggregator::new(dim);

    // 2 honest participants with similar embeddings
    let honest = make_embedding(dim, 1.0);

    // 1 Byzantine with random/divergent embedding
    let byzantine_data: Vec<f32> = (0..dim).map(|i| ((i * 7 + 3) as f32).sin() * 100.0).collect();
    let byzantine = EmbeddingVector::new(byzantine_data).unwrap();

    let conf = make_confidence(dim, 0.9);

    // Honest nodes have much higher blue scores than byzantine
    let input = AggregationInput {
        embeddings: &[&honest, &honest, &byzantine],
        confidences: &[&conf, &conf, &conf],
        blue_scores: &[100.0, 100.0, 1.0], // Byzantine has very low blue score
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    };

    let result = agg.aggregate_paraconsistent(&input).unwrap();

    // The aggregated embedding should be close to the honest embedding
    // (Byzantine's contribution is suppressed by low blue score)
    let honest_normalized = honest.normalize();
    let sim = result.embedding.cosine_similarity(&honest_normalized).unwrap();
    assert!(
        sim > 0.8,
        "aggregated result should be dominated by honest participants, cosine sim = {}",
        sim
    );

    // State vector should show mostly True (honest majority dominates)
    let true_count = result
        .state_vector
        .iter()
        .filter(|&&v| v == BelnapValue::True)
        .count();
    assert!(
        true_count > dim / 2,
        "honest majority should produce mostly True, got {}/{}",
        true_count,
        dim
    );
}

// ---------------------------------------------------------------------------
// Test 7: Full OODA cycle — Observe → Orient → Decide → Act → verify outputs
// ---------------------------------------------------------------------------

#[test]
fn test_full_ooda_cycle_with_pipeline() {
    let dim = 16;
    let config = test_config(dim);

    // --- Observe Phase ---
    let mut phase_manager = PhaseManager::new(config.clone());
    assert_eq!(phase_manager.current_phase(), OodaPhase::Observe);

    // 3 participants submit
    phase_manager.record_submission();
    phase_manager.record_submission();
    phase_manager.record_submission();
    assert!(phase_manager.can_transition());
    let next = phase_manager.transition().unwrap();
    assert_eq!(next, OodaPhase::Orient);

    // --- Orient Phase ---
    let e1 = make_embedding(dim, 1.0);
    let e2 = make_embedding(dim, 1.05);
    let e3 = make_embedding(dim, 1.1);
    let conf = make_confidence(dim, 0.9);

    let mut pipeline = LearningPipeline::new(&config);
    let input = AggregationInput {
        embeddings: &[&e1, &e2, &e3],
        confidences: &[&conf, &conf, &conf],
        blue_scores: &[10.0, 8.0, 12.0],
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    };

    let agg_result = pipeline.orient(&input).unwrap();
    assert_eq!(agg_result.embedding.dim(), dim);
    assert_eq!(agg_result.state_vector.len(), dim);

    phase_manager.mark_condition_met();
    let next = phase_manager.transition().unwrap();
    assert_eq!(next, OodaPhase::Decide);

    // --- Decide Phase ---
    let query = make_embedding(dim, 0.5);
    let decision = pipeline.decide(&query, &agg_result).unwrap();
    assert!(decision.selected < config.router_num_destinations);
    let prob_sum: f32 = decision.probabilities.iter().sum();
    assert!((prob_sum - 1.0).abs() < 1e-4);

    phase_manager.mark_condition_met();
    let next = phase_manager.transition().unwrap();
    assert_eq!(next, OodaPhase::Act);

    // --- Act Phase ---
    let adapter = pipeline
        .act(&agg_result, &decision, [1u8; 32], 100)
        .unwrap();
    assert_eq!(adapter.dim, dim);
    assert_eq!(adapter.rank, config.lora_rank);
    assert!(AdapterFactory::verify_lora_hash(&adapter));

    // Verify safety
    let guard = SafetyGuard::new();
    let base = make_embedding(dim, 42.0);
    assert!(guard.verify_adapter_safety(&base, &adapter).is_ok());

    // Transition back to Observe (new round)
    phase_manager.mark_condition_met();
    let next = phase_manager.transition().unwrap();
    assert_eq!(next, OodaPhase::Observe);
    assert_eq!(phase_manager.current_round(), 1);
}

// ---------------------------------------------------------------------------
// Test 8: Learning state persists (serialize/deserialize PhaseStore)
// ---------------------------------------------------------------------------

#[test]
fn test_phase_store_persistence() {
    let store = PhaseStore::new();

    // Save OODA phase state
    let state = PhaseState {
        phase: OodaPhase::Decide,
        round: 7,
        submissions: 3,
        condition_met: false,
        started_at_ms: 123456789,
    };
    store.save_phase_state(&state).unwrap();

    // Load it back
    let loaded = store.load_phase_state().unwrap().unwrap();
    assert_eq!(loaded.phase, OodaPhase::Decide);
    assert_eq!(loaded.round, 7);
    assert_eq!(loaded.submissions, 3);
    assert!(!loaded.condition_met);

    // Save macro-phase
    store
        .save_macro_phase(NetworkLearningPhase::FullSystem)
        .unwrap();
    let macro_phase = store.load_macro_phase().unwrap().unwrap();
    assert_eq!(macro_phase, NetworkLearningPhase::FullSystem);

    // Test recovery: interrupted phase (not Observe) resets to Observe
    let interrupted = PhaseState {
        phase: OodaPhase::Act,
        round: 10,
        submissions: 2,
        condition_met: true,
        started_at_ms: 999999,
    };
    store.save_phase_state(&interrupted).unwrap();

    let recovered = store.load_phase_state_with_recovery().unwrap().unwrap();
    assert_eq!(recovered.phase, OodaPhase::Observe);
    assert_eq!(recovered.round, 10); // Same round
    assert_eq!(recovered.submissions, 0); // Reset
    assert!(!recovered.condition_met); // Reset

    // Non-interrupted (already Observe) stays as-is
    let observe_state = PhaseState {
        phase: OodaPhase::Observe,
        round: 15,
        submissions: 1,
        condition_met: false,
        started_at_ms: 555555,
    };
    store.save_phase_state(&observe_state).unwrap();
    let loaded = store.load_phase_state_with_recovery().unwrap().unwrap();
    assert_eq!(loaded.phase, OodaPhase::Observe);
    assert_eq!(loaded.submissions, 1); // Not reset
}

// ---------------------------------------------------------------------------
// Test 8b: Full state serialization roundtrip for PhaseState
// ---------------------------------------------------------------------------

#[test]
fn test_phase_state_json_roundtrip() {
    let state = PhaseState {
        phase: OodaPhase::Orient,
        round: 42,
        submissions: 10,
        condition_met: true,
        started_at_ms: 987654321,
    };

    let json = serde_json::to_string(&state).unwrap();
    let deserialized: PhaseState = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.phase, OodaPhase::Orient);
    assert_eq!(deserialized.round, 42);
    assert_eq!(deserialized.submissions, 10);
    assert!(deserialized.condition_met);
    assert_eq!(deserialized.started_at_ms, 987654321);
}

// ---------------------------------------------------------------------------
// Test: Complete execute_cycle integration covering all stages
// ---------------------------------------------------------------------------

#[test]
fn test_execute_cycle_end_to_end() {
    let dim = 16;
    let config = test_config(dim);
    let mut pipeline = LearningPipeline::new(&config);
    let mut macro_mgr = MacroPhaseManager::new(config.clone());

    let e1 = make_embedding(dim, 1.0);
    let e2 = make_embedding(dim, 1.05);
    let e3 = make_embedding(dim, 1.1);
    let conf = make_confidence(dim, 0.9);
    let query = make_embedding(dim, 0.5);

    let input = AggregationInput {
        embeddings: &[&e1, &e2, &e3],
        confidences: &[&conf, &conf, &conf],
        blue_scores: &[10.0, 8.0, 12.0],
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    };

    // Phase 1: Collection — no adapter
    assert_eq!(macro_mgr.current_phase(), NetworkLearningPhase::Collection);
    let result = pipeline
        .execute_cycle(&query, &input, macro_mgr.can_adapt(), [1u8; 32], 100)
        .unwrap();
    assert!(result.adapter.is_none());
    assert_eq!(result.aggregation.embedding.dim(), dim);

    // Transition to RoutingActive
    macro_mgr.evaluate_checkpoint(0.8, None);
    assert_eq!(
        macro_mgr.current_phase(),
        NetworkLearningPhase::RoutingActive
    );

    // Phase 2: RoutingActive — still no adapter
    let result = pipeline
        .execute_cycle(&query, &input, macro_mgr.can_adapt(), [1u8; 32], 200)
        .unwrap();
    assert!(result.adapter.is_none());

    // Transition to FullSystem
    macro_mgr.evaluate_checkpoint(0.8, Some(0.2));
    assert_eq!(
        macro_mgr.current_phase(),
        NetworkLearningPhase::FullSystem
    );

    // Phase 3: FullSystem — adapter produced
    let result = pipeline
        .execute_cycle(&query, &input, macro_mgr.can_adapt(), [1u8; 32], 300)
        .unwrap();
    let adapter = result.adapter.expect("FullSystem should produce adapter");
    assert_eq!(adapter.dim, dim);
    assert_eq!(adapter.rank, config.lora_rank);

    // Verify safety
    let guard = SafetyGuard::new();
    let base = make_embedding(dim, 99.0);
    assert!(guard.verify_adapter_safety(&base, &adapter).is_ok());
}
