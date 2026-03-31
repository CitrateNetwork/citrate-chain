//! WP-H.7: Belnap FOUR Adversarial Tests (8 pts)
//!
//! Verifies Belnap classification and lattice reduction under adversarial inputs:
//! identical participants, opposite halves, empty input, Byzantine floods,
//! NaN/Inf injection, idempotency, commutativity/associativity, and
//! extreme confidence values.

use citrate_learning::aggregation::{AggregationInput, ParaconsistentAggregator};
use citrate_learning::belnap::{classify_belnap, reduce_belnap_states, BelnapValue};
use citrate_learning::embeddings::EmbeddingVector;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_embedding(dim: usize, val: f32) -> EmbeddingVector {
    EmbeddingVector::new(vec![val; dim]).unwrap()
}

fn make_conf(dim: usize, level: f32) -> Vec<f32> {
    vec![level; dim]
}

// ---------------------------------------------------------------------------
// Test 1: All participants identical → all dimensions True
// ---------------------------------------------------------------------------

#[test]
fn test_all_identical_produces_all_true() {
    let dim = 16;
    let e = make_embedding(dim, 3.0);
    let conf = make_conf(dim, 0.95);

    let result = classify_belnap(
        &[&e, &e, &e, &e, &e],
        &[&conf, &conf, &conf, &conf, &conf],
        &[10.0, 10.0, 10.0, 10.0, 10.0],
        1.0,
        0.8,
        0.3,
    );

    let state = reduce_belnap_states(&result);
    assert_eq!(state.len(), dim);
    for (j, &v) in state.iter().enumerate() {
        assert_eq!(
            v,
            BelnapValue::True,
            "all identical → True at dim {}, got {:?}",
            j,
            v
        );
    }
}

// ---------------------------------------------------------------------------
// Test 2: Half participants opposite → all dimensions Both (contradiction)
// ---------------------------------------------------------------------------

#[test]
fn test_half_opposite_produces_all_both() {
    let dim = 16;
    let e_pos = make_embedding(dim, 5.0);
    let e_neg = make_embedding(dim, -5.0);
    let conf = make_conf(dim, 0.95);

    // 4 positive, 4 negative — equal trust
    let result = classify_belnap(
        &[&e_pos, &e_neg, &e_pos, &e_neg, &e_pos, &e_neg, &e_pos, &e_neg],
        &[&conf, &conf, &conf, &conf, &conf, &conf, &conf, &conf],
        &[10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0],
        1.0,
        0.8,
        0.3,
    );

    let state = reduce_belnap_states(&result);
    assert_eq!(state.len(), dim);
    for (j, &v) in state.iter().enumerate() {
        assert_eq!(
            v,
            BelnapValue::Both,
            "half opposite with equal trust → Both at dim {}, got {:?}",
            j,
            v
        );
    }
}

// ---------------------------------------------------------------------------
// Test 3: No participants → Neither (empty state vector)
// ---------------------------------------------------------------------------

#[test]
fn test_no_participants_produces_neither() {
    let dim = 16;
    let agg = ParaconsistentAggregator::new(dim);

    let input = AggregationInput {
        embeddings: &[],
        confidences: &[],
        blue_scores: &[],
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    };

    let result = agg.aggregate_paraconsistent(&input).unwrap();

    // Empty input → empty state vector
    assert!(result.state_vector.is_empty());
    assert_eq!(result.confidence, 0.0);
    // e_agg is zeros
    assert_eq!(result.embedding.dim(), dim);
    assert_eq!(result.embedding.l2_norm(), 0.0);

    // Also test reduce_belnap_states with empty input directly
    let empty: Vec<Vec<BelnapValue>> = vec![];
    let state = reduce_belnap_states(&empty);
    assert!(state.is_empty());
}

// ---------------------------------------------------------------------------
// Test 4: 1 honest + 32 Byzantine → honest survives via blue-score weighting
// ---------------------------------------------------------------------------

#[test]
fn test_one_honest_vs_32_byzantine_blue_score_weighting() {
    let dim = 16;
    let agg = ParaconsistentAggregator::new(dim);

    // 1 honest participant with very high blue score
    let honest = make_embedding(dim, 1.0);
    let honest_conf = make_conf(dim, 0.95);

    // 32 Byzantine participants with random embeddings and low blue scores
    let byz_embeddings: Vec<EmbeddingVector> = (0..32)
        .map(|i| {
            let data: Vec<f32> = (0..dim)
                .map(|j| ((i * 17 + j * 3) as f32 * 0.7).sin() * 100.0)
                .collect();
            EmbeddingVector::new(data).unwrap()
        })
        .collect();
    let byz_confs: Vec<Vec<f32>> = (0..32).map(|_| make_conf(dim, 0.9)).collect();

    let mut all_embeddings: Vec<&EmbeddingVector> = vec![&honest];
    for e in &byz_embeddings {
        all_embeddings.push(e);
    }

    let mut all_confs: Vec<&[f32]> = vec![&honest_conf];
    for c in &byz_confs {
        all_confs.push(c);
    }

    // Honest has blue score 1000, each Byzantine has blue score 1
    let mut blue_scores = vec![1000.0f32];
    blue_scores.extend(vec![1.0f32; 32]);

    let input = AggregationInput {
        embeddings: &all_embeddings,
        confidences: &all_confs,
        blue_scores: &blue_scores,
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    };

    let result = agg.aggregate_paraconsistent(&input).unwrap();

    // The aggregated embedding should be very close to the honest embedding
    // because the honest participant has overwhelming blue-score weight
    let honest_normalized = honest.normalize();
    let sim = result
        .embedding
        .cosine_similarity(&honest_normalized)
        .unwrap();
    assert!(
        sim > 0.9,
        "honest participant should dominate with high blue score, cosine sim = {}",
        sim
    );
}

// ---------------------------------------------------------------------------
// Test 5: NaN/Inf injection → classified as Neither, no corruption
// ---------------------------------------------------------------------------

#[test]
fn test_nan_inf_injection_rejected() {
    let dim = 16;
    let agg = ParaconsistentAggregator::new(dim);

    // Valid embedding
    let valid = make_embedding(dim, 1.0);
    let conf = make_conf(dim, 0.9);

    // NaN embedding — paraconsistent aggregator should reject
    let nan_emb = EmbeddingVector {
        data: vec![f32::NAN; dim],
    };
    let input = AggregationInput {
        embeddings: &[&valid, &nan_emb],
        confidences: &[&conf, &conf],
        blue_scores: &[10.0, 10.0],
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    };
    assert!(
        agg.aggregate_paraconsistent(&input).is_err(),
        "NaN embedding should be rejected"
    );

    // Inf embedding
    let inf_emb = EmbeddingVector {
        data: vec![f32::INFINITY; dim],
    };
    let input = AggregationInput {
        embeddings: &[&valid, &inf_emb],
        confidences: &[&conf, &conf],
        blue_scores: &[10.0, 10.0],
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    };
    assert!(
        agg.aggregate_paraconsistent(&input).is_err(),
        "Inf embedding should be rejected"
    );

    // Negative Inf
    let neg_inf_emb = EmbeddingVector {
        data: vec![f32::NEG_INFINITY; dim],
    };
    let input = AggregationInput {
        embeddings: &[&valid, &neg_inf_emb],
        confidences: &[&conf, &conf],
        blue_scores: &[10.0, 10.0],
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    };
    assert!(
        agg.aggregate_paraconsistent(&input).is_err(),
        "NegInf embedding should be rejected"
    );

    // Valid-only aggregation still works after rejections
    let input = AggregationInput {
        embeddings: &[&valid, &valid],
        confidences: &[&conf, &conf],
        blue_scores: &[10.0, 10.0],
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    };
    let result = agg.aggregate_paraconsistent(&input).unwrap();
    assert_eq!(result.embedding.dim(), dim);
    // No NaN/Inf in result
    for v in &result.embedding.data {
        assert!(v.is_finite(), "result should be finite, got {}", v);
    }
}

// ---------------------------------------------------------------------------
// Test 6: Property — reduce_belnap_states is idempotent
// ---------------------------------------------------------------------------

#[test]
fn test_reduce_belnap_states_idempotent() {
    use BelnapValue::*;

    // Various classification matrices
    let test_cases: Vec<Vec<Vec<BelnapValue>>> = vec![
        vec![vec![True, False, Both, Neither]],
        vec![
            vec![True, True, False],
            vec![False, True, True],
        ],
        vec![
            vec![Both, Neither, True],
            vec![Neither, Both, False],
            vec![True, False, Both],
        ],
        vec![
            vec![Neither; 8],
            vec![True; 8],
        ],
        vec![
            vec![Both; 4],
            vec![Both; 4],
            vec![Both; 4],
        ],
    ];

    for (i, classifications) in test_cases.iter().enumerate() {
        let s1 = reduce_belnap_states(classifications);
        // Reducing again with the result as a single row should give the same thing
        let s2 = reduce_belnap_states(std::slice::from_ref(&s1));
        assert_eq!(
            s1, s2,
            "reduce_belnap_states should be idempotent for test case {}",
            i
        );
    }
}

// ---------------------------------------------------------------------------
// Test 7: Property — lattice join is commutative and associative
// ---------------------------------------------------------------------------

#[test]
fn test_lattice_join_commutative_and_associative() {
    use BelnapValue::*;
    let all = [True, False, Both, Neither];

    // Commutativity: a.join(b) == b.join(a) for all pairs
    for &a in &all {
        for &b in &all {
            assert_eq!(
                a.join(b),
                b.join(a),
                "join not commutative for {:?}, {:?}",
                a,
                b
            );
        }
    }

    // Associativity: a.join(b).join(c) == a.join(b.join(c)) for all triples
    for &a in &all {
        for &b in &all {
            for &c in &all {
                assert_eq!(
                    a.join(b).join(c),
                    a.join(b.join(c)),
                    "join not associative for {:?}, {:?}, {:?}",
                    a,
                    b,
                    c
                );
            }
        }
    }

    // Idempotency: a.join(a) == a
    for &a in &all {
        assert_eq!(a.join(a), a, "join not idempotent for {:?}", a);
    }
}

// ---------------------------------------------------------------------------
// Test 8: Extreme confidence values (0.0, 1.0, -0.1, 1.1) → correctly classified
// ---------------------------------------------------------------------------

#[test]
fn test_extreme_confidence_values() {
    let dim = 4;
    let agg = ParaconsistentAggregator::new(dim);

    let e1 = make_embedding(dim, 1.0);
    let e2 = make_embedding(dim, 1.0);

    // Test with zero confidence
    let zero_conf = make_conf(dim, 0.0);
    let input = AggregationInput {
        embeddings: &[&e1, &e2],
        confidences: &[&zero_conf, &zero_conf],
        blue_scores: &[10.0, 10.0],
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    };
    let result = agg.aggregate_paraconsistent(&input).unwrap();
    assert_eq!(result.state_vector.len(), dim);
    // Zero confidence → below theta_high → Neither
    for &v in &result.state_vector {
        assert_eq!(v, BelnapValue::Neither, "zero confidence should be Neither");
    }

    // Test with maximum confidence (1.0)
    let max_conf = make_conf(dim, 1.0);
    let input = AggregationInput {
        embeddings: &[&e1, &e2],
        confidences: &[&max_conf, &max_conf],
        blue_scores: &[10.0, 10.0],
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    };
    let result = agg.aggregate_paraconsistent(&input).unwrap();
    for &v in &result.state_vector {
        assert_eq!(v, BelnapValue::True, "identical with max confidence should be True");
    }

    // Test with slightly negative confidence (-0.1) — should be clamped to 0.0
    let neg_conf = make_conf(dim, -0.1);
    let input = AggregationInput {
        embeddings: &[&e1, &e2],
        confidences: &[&neg_conf, &neg_conf],
        blue_scores: &[10.0, 10.0],
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    };
    let result = agg.aggregate_paraconsistent(&input).unwrap();
    // Negative confidence clamped to 0 → below theta_high → Neither
    for &v in &result.state_vector {
        assert_eq!(
            v,
            BelnapValue::Neither,
            "negative confidence should produce Neither"
        );
    }
    // Result should have no NaN/Inf
    for val in &result.embedding.data {
        assert!(val.is_finite(), "result should be finite, got {}", val);
    }

    // Test with slightly over-max confidence (1.1) — should be clamped to 1.0
    let over_conf = make_conf(dim, 1.1);
    let input = AggregationInput {
        embeddings: &[&e1, &e2],
        confidences: &[&over_conf, &over_conf],
        blue_scores: &[10.0, 10.0],
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    };
    let result = agg.aggregate_paraconsistent(&input).unwrap();
    // Over-max confidence clamped to 1.0 — should still work correctly
    for val in &result.embedding.data {
        assert!(val.is_finite(), "result should be finite, got {}", val);
    }
    assert_eq!(result.state_vector.len(), dim);
}
