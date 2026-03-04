//! Belnap FOUR-valued logic lattice.
//!
//! Implements Definition 1 from Gradient Papers No. II.
//!
//! The four values form a bilattice with two orderings:
//! - **Knowledge ordering** (≤k): N ≤k {T, F} ≤k B
//! - **Truth ordering** (≤t): F ≤t {N, B} ≤t T

use crate::embeddings::EmbeddingVector;
use serde::{Deserialize, Serialize};
use std::fmt;

/// The four Belnap truth values.
///
/// - `True` — Known to be true
/// - `False` — Known to be false
/// - `Both` — Known to be both true and false (paraconsistent)
/// - `Neither` — Unknown / no information
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BelnapValue {
    /// Known true.
    True,
    /// Known false.
    False,
    /// Both true and false (paraconsistent).
    Both,
    /// Neither true nor false (unknown).
    #[default]
    Neither,
}

impl BelnapValue {
    /// Lattice join (⊔) under knowledge ordering.
    ///
    /// Combines information: the result knows at least as much as either input.
    pub fn join(self, other: Self) -> Self {
        use BelnapValue::*;
        match (self, other) {
            (Neither, x) | (x, Neither) => x,
            (Both, _) | (_, Both) => Both,
            (True, True) => True,
            (False, False) => False,
            (True, False) | (False, True) => Both,
        }
    }

    /// Lattice meet (⊓) under knowledge ordering.
    ///
    /// Consensus: the result knows only what both inputs agree on.
    pub fn meet(self, other: Self) -> Self {
        use BelnapValue::*;
        match (self, other) {
            (Both, x) | (x, Both) => x,
            (Neither, _) | (_, Neither) => Neither,
            (True, True) => True,
            (False, False) => False,
            (True, False) | (False, True) => Neither,
        }
    }

    /// Negation operator.
    ///
    /// Swaps True ↔ False, preserves Both and Neither.
    pub fn negation(self) -> Self {
        use BelnapValue::*;
        match self {
            True => False,
            False => True,
            Both => Both,
            Neither => Neither,
        }
    }

    /// Knowledge ordering value (for comparison).
    ///
    /// N=0, T=1, F=1, B=2
    pub fn k_level(self) -> u8 {
        use BelnapValue::*;
        match self {
            Neither => 0,
            True | False => 1,
            Both => 2,
        }
    }

    /// Returns true if self ≤k other in the knowledge ordering.
    pub fn k_leq(self, other: Self) -> bool {
        // Knowledge ordering: N ≤k {T,F} ≤k B
        // But T and F are incomparable under ≤k
        use BelnapValue::*;
        match (self, other) {
            (x, y) if x == y => true,
            (Neither, _) => true,
            (_, Both) => true,
            _ => false,
        }
    }

    /// Returns true if self ≤t other in the truth ordering.
    pub fn t_leq(self, other: Self) -> bool {
        // Truth ordering: F ≤t {N,B} ≤t T
        // But N and B are incomparable under ≤t
        use BelnapValue::*;
        match (self, other) {
            (x, y) if x == y => true,
            (False, _) => true,
            (_, True) => true,
            _ => false,
        }
    }
}

impl fmt::Display for BelnapValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BelnapValue::True => write!(f, "T"),
            BelnapValue::False => write!(f, "F"),
            BelnapValue::Both => write!(f, "B"),
            BelnapValue::Neither => write!(f, "N"),
        }
    }
}

// ---------------------------------------------------------------------------
// WP-L.7: Classification function φ (Paper II §3.1, Definition 5)
// ---------------------------------------------------------------------------

/// Compute softmax weights from blue scores with temperature scaling.
///
/// `softmax(bᵢ/τ) = exp(bᵢ/τ) / Σ exp(bⱼ/τ)`
///
/// Returns uniform weights if `blue_scores` is empty or all zero.
/// Reused by Sprint M aggregation (GAP-9).
pub fn softmax_weights(blue_scores: &[f32], temperature: f32) -> Vec<f32> {
    if blue_scores.is_empty() {
        return vec![];
    }
    let tau = if temperature <= f32::EPSILON { 1.0 } else { temperature };
    let scaled: Vec<f32> = blue_scores.iter().map(|&b| b / tau).collect();
    let max_val = scaled.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
    let exps: Vec<f32> = scaled.iter().map(|&s| (s - max_val).exp()).collect();
    let sum: f32 = exps.iter().sum();
    if sum < f32::EPSILON {
        // All zero scores → uniform
        let uniform = 1.0 / blue_scores.len() as f32;
        return vec![uniform; blue_scores.len()];
    }
    exps.iter().map(|e| e / sum).collect()
}

/// Classify each participant's embedding into per-dimension Belnap states.
///
/// Implements Definition 5 (φ) from Paper II §3.1.
///
/// For each participant `i` and dimension `j`:
/// - **True**: confidence ≥ θ_high AND directionally consistent with blue-score-weighted majority
/// - **False**: confidence ≥ θ_high AND directionally inconsistent with majority
/// - **Both**: confidence ≥ θ_high AND at least one other comparably-trusted node also disagrees
///   at this dimension (genuine paraconsistent disagreement)
/// - **Neither**: confidence < θ_low (uncertain / no information)
///
/// Returns a `Vec` of `BelnapValue` vectors — one per participant, each of length `dim`.
///
/// # Panics
/// Panics if embeddings/confidences/blue_scores lengths don't match, or if any
/// confidence slice length doesn't match the embedding dimension.
#[allow(clippy::needless_range_loop)]
pub fn classify_belnap(
    embeddings: &[&EmbeddingVector],
    confidences: &[&[f32]],
    blue_scores: &[f32],
    temperature: f32,
    theta_high: f32,
    _theta_low: f32,
) -> Vec<Vec<BelnapValue>> {
    let n = embeddings.len();
    if n == 0 {
        return vec![];
    }
    assert_eq!(n, confidences.len(), "embeddings and confidences length mismatch");
    assert_eq!(n, blue_scores.len(), "embeddings and blue_scores length mismatch");

    let dim = embeddings[0].dim();
    for (i, emb) in embeddings.iter().enumerate() {
        assert_eq!(emb.dim(), dim, "embedding {} has wrong dimension", i);
        assert_eq!(confidences[i].len(), dim, "confidence {} has wrong dimension", i);
    }

    // Step 1: Compute trust weights via softmax(blue_scores / τ)
    let weights = softmax_weights(blue_scores, temperature);

    // Step 2: Compute weighted majority value per dimension
    let mut majority = vec![0.0f32; dim];
    for j in 0..dim {
        for i in 0..n {
            majority[j] += weights[i] * embeddings[i].data[j];
        }
    }

    let epsilon = 1e-6;

    // Step 3: Classify each participant, each dimension
    //
    // For each dimension j, we partition high-confidence participants into
    // "positive" (above majority) and "negative" (below majority) sides,
    // then classify based on which side has more total trust weight.
    let mut result = vec![vec![BelnapValue::Neither; dim]; n];

    for j in 0..dim {
        // Pre-compute deviations from majority and side weights
        let deviations: Vec<f32> = (0..n)
            .map(|i| embeddings[i].data[j] - majority[j])
            .collect();

        // Compute total trust weight on each side (only high-confidence participants)
        let mut pos_weight = 0.0f32;
        let mut neg_weight = 0.0f32;
        for i in 0..n {
            if confidences[i][j] < theta_high {
                continue;
            }
            if deviations[i] > epsilon {
                pos_weight += weights[i];
            } else if deviations[i] < -epsilon {
                neg_weight += weights[i];
            }
            // Negligible deviation participants don't contribute to either side
        }

        for i in 0..n {
            let conf = confidences[i][j];

            // Low confidence or grey zone → Neither
            if conf < theta_high {
                result[i][j] = BelnapValue::Neither;
                continue;
            }

            let dev_i = deviations[i];

            // Negligible deviation from majority → True
            if dev_i.abs() <= epsilon {
                result[i][j] = BelnapValue::True;
                continue;
            }

            // Determine which side this participant is on
            let (my_side_weight, other_side_weight) = if dev_i > 0.0 {
                (pos_weight, neg_weight)
            } else {
                (neg_weight, pos_weight)
            };

            // No opposition at all → True
            if other_side_weight < epsilon {
                result[i][j] = BelnapValue::True;
                continue;
            }

            // On the heavier side → True (consistent with majority)
            if my_side_weight > other_side_weight + epsilon {
                result[i][j] = BelnapValue::True;
                continue;
            }

            // Sides are approximately equal → genuine disagreement → Both
            if (my_side_weight - other_side_weight).abs() <= epsilon {
                result[i][j] = BelnapValue::Both;
                continue;
            }

            // On the lighter (minority) side — check for allies
            let sign_i = dev_i.signum();
            let mut has_ally = false;
            for k in 0..n {
                if k == i {
                    continue;
                }
                if confidences[k][j] < theta_high {
                    continue;
                }
                if weights[k] < 0.5 * weights[i] {
                    continue;
                }
                if deviations[k].abs() > epsilon && deviations[k].signum() == sign_i {
                    has_ally = true;
                    break;
                }
            }

            if has_ally {
                // Has a comparably-trusted ally on the same side → Both
                result[i][j] = BelnapValue::Both;
            } else {
                // Alone on the minority side → False
                result[i][j] = BelnapValue::False;
            }
        }
    }

    result
}

// ---------------------------------------------------------------------------
// WP-M.5: Blue score normalization bridge (Paper II §3.2, GAP-9)
// ---------------------------------------------------------------------------

/// Convert consensus-layer `u64` blue scores to softmax trust weights.
///
/// Bridge from integer blue scores (as stored in `BlockHeader.blue_score`) to the
/// float softmax computation used by paraconsistent aggregation.
///
/// Equivalent to `softmax_weights(&scores_as_f32, temperature)`.
pub fn blue_scores_to_trust_weights(blue_scores: &[u64], temperature: f32) -> Vec<f32> {
    let float_scores: Vec<f32> = blue_scores.iter().map(|&s| s as f32).collect();
    softmax_weights(&float_scores, temperature)
}

// ---------------------------------------------------------------------------
// WP-M.1a: State vector reduction (Paper II §3.2, Algorithm 1 step 3)
// ---------------------------------------------------------------------------

/// Reduce per-participant Belnap classification matrices to a consensus state vector.
///
/// Implements the state-vector reduction step from Algorithm 1, Paper II §3.2:
///
///   `s[j] = ⊔ { classifications[i][j] | i in 0..n }`
///
/// The join (⊔) follows the knowledge ordering:
/// - If any participant is `Both` at dimension `j`, the state is `Both`
/// - If participants split `True`/`False`, the state is `Both`
/// - If all agree on `True`, the state is `True`
/// - `Neither` is absorbed by any other value
///
/// Returns an empty `Vec` if `classifications` is empty.
///
/// # Panics
///
/// Panics (debug only) if participant rows have inconsistent lengths.
pub fn reduce_belnap_states(classifications: &[Vec<BelnapValue>]) -> Vec<BelnapValue> {
    if classifications.is_empty() {
        return vec![];
    }
    let dim = classifications[0].len();
    debug_assert!(
        classifications.iter().all(|row| row.len() == dim),
        "all participant classification rows must have equal length"
    );

    let mut state = vec![BelnapValue::Neither; dim];
    for row in classifications {
        for j in 0..dim {
            state[j] = state[j].join(row[j]);
        }
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    // PC-T01: Belnap FOUR values construct correctly
    #[test]
    fn test_belnap_values_construct() {
        let t = BelnapValue::True;
        let f = BelnapValue::False;
        let b = BelnapValue::Both;
        let n = BelnapValue::Neither;

        assert_ne!(t, f);
        assert_ne!(t, b);
        assert_ne!(t, n);
        assert_ne!(f, b);
        assert_ne!(f, n);
        assert_ne!(b, n);
        assert_eq!(BelnapValue::default(), BelnapValue::Neither);
    }

    // PC-T07: Knowledge ordering correct
    #[test]
    fn test_knowledge_ordering() {
        use BelnapValue::*;

        // N ≤k everything
        assert!(Neither.k_leq(Neither));
        assert!(Neither.k_leq(True));
        assert!(Neither.k_leq(False));
        assert!(Neither.k_leq(Both));

        // T and F ≤k B
        assert!(True.k_leq(Both));
        assert!(False.k_leq(Both));

        // T and F are incomparable
        assert!(!True.k_leq(False));
        assert!(!False.k_leq(True));

        // B ≤k only B
        assert!(Both.k_leq(Both));
        assert!(!Both.k_leq(True));
        assert!(!Both.k_leq(False));
        assert!(!Both.k_leq(Neither));
    }

    // PC-T08: Truth ordering correct
    #[test]
    fn test_truth_ordering() {
        use BelnapValue::*;

        // F ≤t everything
        assert!(False.t_leq(False));
        assert!(False.t_leq(Neither));
        assert!(False.t_leq(Both));
        assert!(False.t_leq(True));

        // N and B ≤t T
        assert!(Neither.t_leq(True));
        assert!(Both.t_leq(True));

        // N and B are incomparable
        assert!(!Neither.t_leq(Both));
        assert!(!Both.t_leq(Neither));

        // T ≤t only T
        assert!(True.t_leq(True));
        assert!(!True.t_leq(False));
        assert!(!True.t_leq(Neither));
        assert!(!True.t_leq(Both));
    }

    // Join table verification (all 16 combinations)
    #[test]
    fn test_join_table() {
        use BelnapValue::*;

        // Row T
        assert_eq!(True.join(True), True);
        assert_eq!(True.join(False), Both);
        assert_eq!(True.join(Both), Both);
        assert_eq!(True.join(Neither), True);

        // Row F
        assert_eq!(False.join(True), Both);
        assert_eq!(False.join(False), False);
        assert_eq!(False.join(Both), Both);
        assert_eq!(False.join(Neither), False);

        // Row B
        assert_eq!(Both.join(True), Both);
        assert_eq!(Both.join(False), Both);
        assert_eq!(Both.join(Both), Both);
        assert_eq!(Both.join(Neither), Both);

        // Row N
        assert_eq!(Neither.join(True), True);
        assert_eq!(Neither.join(False), False);
        assert_eq!(Neither.join(Both), Both);
        assert_eq!(Neither.join(Neither), Neither);
    }

    // Meet table verification (all 16 combinations)
    #[test]
    fn test_meet_table() {
        use BelnapValue::*;

        // Row T
        assert_eq!(True.meet(True), True);
        assert_eq!(True.meet(False), Neither);
        assert_eq!(True.meet(Both), True);
        assert_eq!(True.meet(Neither), Neither);

        // Row F
        assert_eq!(False.meet(True), Neither);
        assert_eq!(False.meet(False), False);
        assert_eq!(False.meet(Both), False);
        assert_eq!(False.meet(Neither), Neither);

        // Row B
        assert_eq!(Both.meet(True), True);
        assert_eq!(Both.meet(False), False);
        assert_eq!(Both.meet(Both), Both);
        assert_eq!(Both.meet(Neither), Neither);

        // Row N
        assert_eq!(Neither.meet(True), Neither);
        assert_eq!(Neither.meet(False), Neither);
        assert_eq!(Neither.meet(Both), Neither);
        assert_eq!(Neither.meet(Neither), Neither);
    }

    #[test]
    fn test_negation() {
        use BelnapValue::*;
        assert_eq!(True.negation(), False);
        assert_eq!(False.negation(), True);
        assert_eq!(Both.negation(), Both);
        assert_eq!(Neither.negation(), Neither);
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", BelnapValue::True), "T");
        assert_eq!(format!("{}", BelnapValue::False), "F");
        assert_eq!(format!("{}", BelnapValue::Both), "B");
        assert_eq!(format!("{}", BelnapValue::Neither), "N");
    }

    // --- WP-L.7: φ classification tests ---

    #[test]
    fn test_softmax_weights_basic() {
        let w = softmax_weights(&[1.0, 1.0, 1.0], 1.0);
        assert_eq!(w.len(), 3);
        // Equal scores → uniform
        for &wi in &w {
            assert!((wi - 1.0 / 3.0).abs() < 1e-5);
        }

        // Higher score → higher weight
        let w2 = softmax_weights(&[10.0, 1.0], 1.0);
        assert!(w2[0] > w2[1]);
    }

    #[test]
    fn test_softmax_weights_temperature() {
        // High temperature → more uniform
        let w_hot = softmax_weights(&[10.0, 1.0], 100.0);
        // Low temperature → more peaked
        let w_cold = softmax_weights(&[10.0, 1.0], 0.1);
        // Hot should be more uniform (closer to 0.5 each)
        assert!((w_hot[0] - w_hot[1]).abs() < (w_cold[0] - w_cold[1]).abs());
    }

    // PC-T12a: All participants agree, high confidence → all True
    #[test]
    fn test_phi_unanimous_agreement() {
        let e1 = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
        let e2 = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
        let e3 = EmbeddingVector::new(vec![1.0, 2.0]).unwrap();
        let conf = [0.9, 0.9]; // high confidence in both dims
        let blue = vec![10.0, 10.0, 10.0]; // equal trust

        let result = classify_belnap(
            &[&e1, &e2, &e3],
            &[&conf[..], &conf[..], &conf[..]],
            &blue,
            1.0, 0.8, 0.3,
        );

        assert_eq!(result.len(), 3);
        for participant in &result {
            assert_eq!(participant.len(), 2);
            for &val in participant {
                assert_eq!(val, BelnapValue::True, "unanimous agreement should be True");
            }
        }
    }

    // PC-T12b: One participant disagrees, high confidence → False for dissenter
    #[test]
    fn test_phi_single_dissenter() {
        // Two nodes agree on [1.0, 1.0], one dissents to [-5.0, -5.0]
        let e1 = EmbeddingVector::new(vec![1.0, 1.0]).unwrap();
        let e2 = EmbeddingVector::new(vec![1.0, 1.0]).unwrap();
        let e3 = EmbeddingVector::new(vec![-5.0, -5.0]).unwrap();
        let conf = [0.9, 0.9];
        let blue = vec![10.0, 10.0, 10.0];

        let result = classify_belnap(
            &[&e1, &e2, &e3],
            &[&conf[..], &conf[..], &conf[..]],
            &blue,
            1.0, 0.8, 0.3,
        );

        // Majority (e1, e2) should be True
        assert_eq!(result[0][0], BelnapValue::True);
        assert_eq!(result[1][0], BelnapValue::True);
        // Dissenter (e3) should be False (alone in disagreeing against majority)
        assert_eq!(result[2][0], BelnapValue::False);
        assert_eq!(result[2][1], BelnapValue::False);
    }

    // PC-T12c: Two comparable-trust nodes disagree → Both
    #[test]
    fn test_phi_comparable_disagreement_both() {
        // Two nodes point in opposite directions with comparable trust
        let e1 = EmbeddingVector::new(vec![5.0]).unwrap();
        let e2 = EmbeddingVector::new(vec![-5.0]).unwrap();
        let conf1 = [0.95];
        let conf2 = [0.95];
        let blue = vec![10.0, 10.0]; // equal trust

        let result = classify_belnap(
            &[&e1, &e2],
            &[&conf1[..], &conf2[..]],
            &blue,
            1.0, 0.8, 0.3,
        );

        // Both nodes have comparable trust and disagree → Both for each
        assert_eq!(result[0][0], BelnapValue::Both,
            "comparable disagreement should yield Both, got {:?}", result[0][0]);
        assert_eq!(result[1][0], BelnapValue::Both,
            "comparable disagreement should yield Both, got {:?}", result[1][0]);
    }

    // PC-T12d: Low confidence → Neither regardless of direction
    #[test]
    fn test_phi_low_confidence_neither() {
        let e1 = EmbeddingVector::new(vec![1.0, -5.0]).unwrap();
        let e2 = EmbeddingVector::new(vec![-1.0, 5.0]).unwrap();
        let conf1 = [0.1, 0.2]; // below θ_low = 0.3
        let conf2 = [0.15, 0.25];
        let blue = vec![10.0, 10.0];

        let result = classify_belnap(
            &[&e1, &e2],
            &[&conf1[..], &conf2[..]],
            &blue,
            1.0, 0.8, 0.3,
        );

        for participant in &result {
            for &val in participant {
                assert_eq!(val, BelnapValue::Neither,
                    "low confidence should always be Neither");
            }
        }
    }

    // PC-T12e: Mixed confidence levels across dimensions
    #[test]
    fn test_phi_mixed_confidence() {
        // dim 0: both high confidence, agree → True
        // dim 1: participant 0 high conf, participant 1 low conf
        let e1 = EmbeddingVector::new(vec![1.0, 3.0]).unwrap();
        let e2 = EmbeddingVector::new(vec![1.0, -3.0]).unwrap();
        let conf1 = [0.9, 0.9]; // high in both
        let conf2 = [0.9, 0.1]; // high in dim 0, low in dim 1
        let blue = vec![10.0, 10.0];

        let result = classify_belnap(
            &[&e1, &e2],
            &[&conf1[..], &conf2[..]],
            &blue,
            1.0, 0.8, 0.3,
        );

        // dim 0: both agree → True
        assert_eq!(result[0][0], BelnapValue::True);
        assert_eq!(result[1][0], BelnapValue::True);
        // dim 1: participant 1 is low confidence → Neither
        assert_eq!(result[1][1], BelnapValue::Neither);
        // dim 1: participant 0 is high conf, alone with high conf → True
        // (the only high-conf voice, so it's trivially the majority)
        assert_eq!(result[0][1], BelnapValue::True);
    }

    // PC-T12f: Single participant → all True (no disagreement possible)
    #[test]
    fn test_phi_single_participant() {
        let e = EmbeddingVector::new(vec![1.0, -2.0, 3.0]).unwrap();
        let conf = [0.9, 0.9, 0.9];
        let blue = vec![10.0];

        let result = classify_belnap(
            &[&e],
            &[&conf[..]],
            &blue,
            1.0, 0.8, 0.3,
        );

        assert_eq!(result.len(), 1);
        for &val in &result[0] {
            assert_eq!(val, BelnapValue::True,
                "single participant is trivially consistent");
        }
    }

    // -----------------------------------------------------------------------
    // WP-M.5: blue_scores_to_trust_weights tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_blue_scores_to_trust_weights_basic() {
        let weights = blue_scores_to_trust_weights(&[10, 10, 10], 1.0);
        assert_eq!(weights.len(), 3);
        for &w in &weights {
            assert!((w - 1.0 / 3.0).abs() < 1e-5);
        }
    }

    #[test]
    fn test_blue_scores_to_trust_weights_monotone() {
        let weights = blue_scores_to_trust_weights(&[100, 10], 1.0);
        assert!(weights[0] > weights[1],
            "higher blue score should yield higher trust weight");
    }

    #[test]
    fn test_blue_scores_to_trust_weights_zero_total() {
        let weights = blue_scores_to_trust_weights(&[0, 0, 0], 1.0);
        for &w in &weights {
            assert!((w - 1.0 / 3.0).abs() < 1e-5,
                "all-zero blue scores should yield uniform weights");
        }
    }

    // -----------------------------------------------------------------------
    // WP-M.1a: reduce_belnap_states tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_reduce_empty() {
        let result = reduce_belnap_states(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_reduce_unanimous_true() {
        use BelnapValue::*;
        let classifications = vec![
            vec![True, True],
            vec![True, True],
        ];
        let s = reduce_belnap_states(&classifications);
        assert_eq!(s, vec![True, True]);
    }

    #[test]
    fn test_reduce_true_false_yields_both() {
        use BelnapValue::*;
        let classifications = vec![
            vec![True, False],
            vec![False, True],
        ];
        let s = reduce_belnap_states(&classifications);
        assert_eq!(s[0], Both);
        assert_eq!(s[1], Both);
    }

    #[test]
    fn test_reduce_neither_absorbed() {
        use BelnapValue::*;
        let classifications = vec![
            vec![Neither, True],
            vec![True, Neither],
        ];
        let s = reduce_belnap_states(&classifications);
        assert_eq!(s, vec![True, True]);
    }

    #[test]
    fn test_reduce_single_participant() {
        use BelnapValue::*;
        let classifications = vec![vec![True, False, Neither, Both]];
        let s = reduce_belnap_states(&classifications);
        assert_eq!(s, vec![True, False, Neither, Both]);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn arb_belnap() -> impl Strategy<Value = BelnapValue> {
        prop_oneof![
            Just(BelnapValue::True),
            Just(BelnapValue::False),
            Just(BelnapValue::Both),
            Just(BelnapValue::Neither),
        ]
    }

    // PC-T02: Join commutative
    proptest! {
        #[test]
        fn join_commutative(a in arb_belnap(), b in arb_belnap()) {
            prop_assert_eq!(a.join(b), b.join(a));
        }
    }

    // PC-T03: Join associative
    proptest! {
        #[test]
        fn join_associative(a in arb_belnap(), b in arb_belnap(), c in arb_belnap()) {
            prop_assert_eq!(a.join(b).join(c), a.join(b.join(c)));
        }
    }

    // PC-T04: Join idempotent
    proptest! {
        #[test]
        fn join_idempotent(a in arb_belnap()) {
            prop_assert_eq!(a.join(a), a);
        }
    }

    // PC-T05: Meet commutative
    proptest! {
        #[test]
        fn meet_commutative(a in arb_belnap(), b in arb_belnap()) {
            prop_assert_eq!(a.meet(b), b.meet(a));
        }
    }

    // PC-T06: Meet associative
    proptest! {
        #[test]
        fn meet_associative(a in arb_belnap(), b in arb_belnap(), c in arb_belnap()) {
            prop_assert_eq!(a.meet(b).meet(c), a.meet(b.meet(c)));
        }
    }

    // Absorption: a join (a meet b) = a
    proptest! {
        #[test]
        fn absorption_join_meet(a in arb_belnap(), b in arb_belnap()) {
            prop_assert_eq!(a.join(a.meet(b)), a);
        }
    }

    // Absorption: a meet (a join b) = a
    proptest! {
        #[test]
        fn absorption_meet_join(a in arb_belnap(), b in arb_belnap()) {
            prop_assert_eq!(a.meet(a.join(b)), a);
        }
    }

    // Double negation
    proptest! {
        #[test]
        fn double_negation(a in arb_belnap()) {
            prop_assert_eq!(a.negation().negation(), a);
        }
    }
}
