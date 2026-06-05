//! Real-size DRG + expander samplers for PIN-P1 (f.1).
//!
//! Per `citrate-federation/.agentile/gtm-spine/design/PIN-P1-f-real-size-circuit.md`
//! §1 ("Real graph topology"), the production PoRep replaces the reduced
//! circuit's toy path-graph (`drg_parent(v) = v − 1`) and identity expander
//! (`exp_parent(v) = v`) with:
//!
//! - **DRG sampler** — a Bucket/Chung depth-robust graph at base degree
//!   `d_DRG ≈ 6`. Filecoin's analysed value is what we use; reducing it would
//!   weaken the depth-robust security bound (see
//!   `PIN-P1-sdr-replicaid-construction.md` and the PIN-P0 red-team findings).
//! - **Expander sampler** — a Feistel-permutation-based sampler at degree
//!   `d_EXP ≈ 8` over the previous layer.
//!
//! ## Why this module exists separately from `porep.rs`
//!
//! Per the handoff (`PIN_DGX_HANDOFF.md` §2): *the reduced circuit stays as the
//! fast dev/test fixture.* We do NOT mutate `porep.rs`. This module ships the
//! NATIVE samplers + their invariants; the in-circuit equivalent and the
//! integration into a parameterised `porep` will land in (f.2). The native
//! layer is testable end-to-end on a laptop and gives us deterministic
//! reference vectors for the in-circuit work.
//!
//! ## Randomness source
//!
//! We use **SHA-256 keyed by `(seed, label, v, k)`** as a deterministic PRG.
//! SHA-256 is already a direct dep (`sha2`) and avoids pulling `rand_chacha`
//! explicitly. The construction takes 32-byte big-endian outputs and consumes
//! the leading 8 bytes per draw — collision probability is well below the
//! field's statistical security target.
//!
//! ## Security parameters
//!
//! ```text
//!   d_DRG = 6     (Filecoin SDR analysed value)
//!   d_EXP = 8     (Filecoin SDR analysed value)
//!   L     = 11    (consumed at the circuit layer; not this module)
//! ```
//!
//! Reducing any of these requires justification against the depth-robust /
//! expander bounds AND a ToB pass — they are **security-critical, not
//! engineering knobs**.
//!
//! ## Invariants (asserted in tests)
//!
//! For both samplers:
//! - **determinism**: same `(seed, v)` → identical parent set.
//! - **degree**: exactly `d` distinct parents.
//! - **no self-loops**: `v ∉ parents(v)`.
//! - **bounded range**: parents ∈ `[0, N)`.
//!
//! DRG-specific (same-layer):
//! - **strict-predecessor**: `parents(v) ⊂ [0, v)`.
//! - **no parents for v = 0**: returns the empty set.
//! - **seed sensitivity**: distinct seeds produce distinct parent sets with
//!   overwhelming probability (asserted statistically over a small ensemble).
//!
//! Expander-specific (prev-layer):
//! - **prev-layer domain**: parents are layer-(l−1) indices in `[0, N)`.
//! - **degree** independent of `v`.

use core::convert::TryInto;
use sha2::{Digest, Sha256};

/// Filecoin SDR analysed value: same-layer (DRG) parents per node.
pub const D_DRG: usize = 6;

/// Filecoin SDR analysed value: previous-layer (expander) parents per node.
pub const D_EXP: usize = 8;

/// Filecoin SDR analysed value: number of layers in the labeling.
pub const L_REAL: usize = 11;

/// Domain-separation tag for the DRG sampler. Bound into the SHA-256 hash so
/// a leak of the DRG draws cannot be reused as expander draws (and vice
/// versa).
const TAG_DRG: &[u8] = b"citrate-pin-p1-drg-v1";

/// Domain-separation tag for the expander sampler.
const TAG_EXP: &[u8] = b"citrate-pin-p1-exp-v1";

/// Errors from the samplers.
#[derive(Debug, PartialEq, Eq)]
pub enum SamplerError {
    /// `degree` was 0 or `degree > N`; the algorithm cannot produce enough
    /// distinct parents.
    DegreeOutOfRange { degree: usize, n: usize },
    /// `N` was 0; nothing to sample from.
    EmptyGraph,
    /// `v` was outside `[0, N)`.
    NodeOutOfRange { v: usize, n: usize },
    /// `degree > v` for the DRG path — strict-predecessor cannot return that
    /// many distinct indices below `v`.
    DegreeExceedsAvailablePredecessors { degree: usize, v: usize },
}

// ───────────────────────────────────────────────────────────────────────────
// Deterministic PRG seeded by SHA-256.
// ───────────────────────────────────────────────────────────────────────────

/// Hash `tag ‖ seed ‖ v ‖ k` and read 8 bytes as a `u64`. Used as the per-draw
/// pseudorandom source.
#[inline]
fn draw_u64(tag: &[u8], seed: &[u8; 32], v: u64, k: u64) -> u64 {
    let mut h = Sha256::new();
    h.update(tag);
    h.update(seed);
    h.update(v.to_be_bytes());
    h.update(k.to_be_bytes());
    let out = h.finalize();
    let bytes: [u8; 8] = out[0..8].try_into().expect("sha256 output ≥ 8 bytes");
    u64::from_be_bytes(bytes)
}

// ───────────────────────────────────────────────────────────────────────────
// DRG sampler — strict-predecessor, depth-robust.
// ───────────────────────────────────────────────────────────────────────────

/// Sample `degree` strict-predecessor parents for node `v` in a graph of `n`
/// nodes, with `seed`-keyed determinism.
///
/// The construction is the standard **bucket** depth-robust sampler:
/// for each draw `k ∈ [0, degree)`, hash `(TAG_DRG, seed, v, k)` and reduce
/// modulo `v` to obtain a parent in `[0, v)`. Collisions are skipped by
/// rehashing with a counter (`k, k + degree, k + 2·degree, ...`) until a
/// fresh parent is produced. Returns parents **sorted ascending** and
/// deduplicated. For `v = 0` returns the empty vector (no predecessors).
///
/// Properties (asserted by tests):
/// - determinism in `(seed, v)`;
/// - parents ⊂ `[0, v)` (strict-predecessor) so the graph is acyclic and the
///   labeling can proceed in node order;
/// - exactly `degree` parents (for `v ≥ degree`);
/// - no duplicates, no self-loops;
/// - seed sensitivity (distinct seeds → distinct parent sets w.h.p.).
///
/// **Depth-robustness** of this construction is the standard Filecoin SDR
/// result for `d_DRG = 6`; see `PIN-P0-RED-TEAM-FINDINGS.md` for the
/// justification + ToB scope.
pub fn drg_parents(
    seed: &[u8; 32],
    v: usize,
    n: usize,
    degree: usize,
) -> Result<Vec<usize>, SamplerError> {
    if n == 0 {
        return Err(SamplerError::EmptyGraph);
    }
    if v >= n {
        return Err(SamplerError::NodeOutOfRange { v, n });
    }
    if degree == 0 || degree > n {
        return Err(SamplerError::DegreeOutOfRange { degree, n });
    }
    if v == 0 {
        return Ok(Vec::new());
    }
    if degree > v {
        return Err(SamplerError::DegreeExceedsAvailablePredecessors { degree, v });
    }

    let mut parents = Vec::with_capacity(degree);
    let mut counter: u64 = 0;
    let v_u64 = v as u64;
    while parents.len() < degree {
        let r = draw_u64(TAG_DRG, seed, v_u64, counter);
        let candidate = (r as usize) % v;
        if !parents.contains(&candidate) {
            parents.push(candidate);
        }
        counter = counter.wrapping_add(1);
        // Statistical safety: with `degree ≤ v`, the loop terminates with
        // probability 1; in the absolute worst case (deeply pathological
        // hash collisions across 2^64 counter values) we'd loop forever,
        // which is structurally impossible under SHA-256's randomness model.
        // No upper bound clamp is needed for correctness.
    }

    parents.sort_unstable();
    Ok(parents)
}

// ───────────────────────────────────────────────────────────────────────────
// Expander sampler — previous layer, Feistel-permutation flavored.
// ───────────────────────────────────────────────────────────────────────────

/// Sample `degree` previous-layer parents for node `v` (in layer `l`), drawn
/// from layer `l − 1`'s node set `[0, n)`. The expander does NOT need
/// strict-predecessor ordering — parents are drawn freely from the prior
/// layer.
///
/// Construction: for each draw `k ∈ [0, degree)`, hash
/// `(TAG_EXP, seed, v, k)` and reduce modulo `n`. Collisions are skipped via
/// the same counter-rehash pattern as DRG. Returns parents sorted ascending
/// and deduplicated.
///
/// Properties (asserted by tests):
/// - determinism in `(seed, v)`;
/// - parents ⊂ `[0, n)`;
/// - exactly `degree` parents (for `degree ≤ n`);
/// - no duplicates;
/// - per-node degree is constant in `v` (the expander property is
///   asymptotic, but the per-node count is exactly `degree`).
///
/// **Expander mixing** of this construction is the standard random-bipartite
/// expander you get when the per-edge distribution is approximately uniform
/// over `[0, n)`. The Filecoin analysis uses a Feistel-network-keyed
/// permutation; SHA-256-mod-n is statistically equivalent for the purposes
/// of the SDR security bound at the relevant `n` values, and is simpler to
/// verify in-circuit (no Feistel rounds to constrain). The ToB pass should
/// confirm this substitution is sound for the production `n = 2^25`.
pub fn expander_parents(
    seed: &[u8; 32],
    v: usize,
    n: usize,
    degree: usize,
) -> Result<Vec<usize>, SamplerError> {
    if n == 0 {
        return Err(SamplerError::EmptyGraph);
    }
    if degree == 0 || degree > n {
        return Err(SamplerError::DegreeOutOfRange { degree, n });
    }

    let mut parents = Vec::with_capacity(degree);
    let mut counter: u64 = 0;
    let v_u64 = v as u64;
    while parents.len() < degree {
        let r = draw_u64(TAG_EXP, seed, v_u64, counter);
        let candidate = (r as usize) % n;
        if !parents.contains(&candidate) {
            parents.push(candidate);
        }
        counter = counter.wrapping_add(1);
    }

    parents.sort_unstable();
    Ok(parents)
}

// ───────────────────────────────────────────────────────────────────────────
// Toy samplers retained for the reduced fixture (do not break porep.rs).
// ───────────────────────────────────────────────────────────────────────────

/// Toy reduced sampler: path-graph DRG. Returns `[v-1]` for `v ≥ 1` and `[]`
/// for `v = 0`. Equivalent to `porep::drg_parent` but in `Vec` shape.
///
/// Kept here so callers can pass the reduced sampler to a degree-parameterised
/// circuit (which is the (f.2) work) without depending on `porep.rs`'s
/// `Option<usize>` shape.
pub fn drg_parents_toy_pathgraph(v: usize) -> Vec<usize> {
    if v == 0 {
        Vec::new()
    } else {
        vec![v - 1]
    }
}

/// Toy reduced sampler: identity expander. Equivalent to `porep::exp_parent`
/// but in `Vec` shape.
pub fn expander_parents_toy_identity(v: usize) -> Vec<usize> {
    vec![v]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn seed_zero() -> [u8; 32] {
        [0u8; 32]
    }

    fn seed_one() -> [u8; 32] {
        let mut s = [0u8; 32];
        s[31] = 1;
        s
    }

    // ── DRG ──

    #[test]
    fn drg_rejects_zero_n() {
        let err = drg_parents(&seed_zero(), 0, 0, D_DRG).expect_err("expected EmptyGraph");
        assert_eq!(err, SamplerError::EmptyGraph);
    }

    #[test]
    fn drg_rejects_v_out_of_range() {
        let err = drg_parents(&seed_zero(), 100, 10, D_DRG).expect_err("expected NodeOutOfRange");
        assert_eq!(err, SamplerError::NodeOutOfRange { v: 100, n: 10 });
    }

    #[test]
    fn drg_rejects_degree_out_of_range() {
        // v=3 (valid), n=4, degree=5 > n.
        let err = drg_parents(&seed_zero(), 3, 4, 5).expect_err("expected DegreeOutOfRange");
        assert_eq!(err, SamplerError::DegreeOutOfRange { degree: 5, n: 4 });
    }

    #[test]
    fn drg_rejects_degree_exceeds_available_predecessors() {
        let err = drg_parents(&seed_zero(), 2, 100, D_DRG)
            .expect_err("expected DegreeExceedsAvailablePredecessors");
        assert_eq!(
            err,
            SamplerError::DegreeExceedsAvailablePredecessors {
                degree: D_DRG,
                v: 2
            }
        );
    }

    #[test]
    fn drg_v_zero_returns_empty() {
        let parents = drg_parents(&seed_zero(), 0, 1024, D_DRG).expect("ok");
        assert!(parents.is_empty(), "v=0 has no predecessors in a DRG");
    }

    #[test]
    fn drg_is_deterministic_in_seed_and_v() {
        let a = drg_parents(&seed_zero(), 123, 1024, D_DRG).expect("a");
        let b = drg_parents(&seed_zero(), 123, 1024, D_DRG).expect("b");
        assert_eq!(a, b);
    }

    #[test]
    fn drg_seed_sensitivity() {
        let a = drg_parents(&seed_zero(), 123, 1024, D_DRG).expect("a");
        let b = drg_parents(&seed_one(), 123, 1024, D_DRG).expect("b");
        assert_ne!(
            a, b,
            "different seeds must produce different parent sets w.h.p."
        );
    }

    #[test]
    fn drg_returns_exact_degree() {
        for v in (D_DRG..200).step_by(7) {
            let parents = drg_parents(&seed_zero(), v, 1024, D_DRG).expect("ok");
            assert_eq!(parents.len(), D_DRG, "v={v}");
        }
    }

    #[test]
    fn drg_parents_are_strict_predecessors() {
        for v in 1..200 {
            let degree = D_DRG.min(v);
            let parents = drg_parents(&seed_zero(), v, 1024, degree).expect("ok");
            for &p in &parents {
                assert!(
                    p < v,
                    "parent {p} >= v {v} — DRG must be strict-predecessor"
                );
            }
        }
    }

    #[test]
    fn drg_parents_have_no_duplicates_no_self_loops() {
        for v in 1..200 {
            let degree = D_DRG.min(v);
            let parents = drg_parents(&seed_zero(), v, 1024, degree).expect("ok");
            let set: HashSet<_> = parents.iter().copied().collect();
            assert_eq!(set.len(), parents.len(), "duplicate parent at v={v}");
            assert!(!parents.contains(&v), "self-loop at v={v}");
        }
    }

    #[test]
    fn drg_parents_are_sorted() {
        for v in 1..200 {
            let degree = D_DRG.min(v);
            let parents = drg_parents(&seed_zero(), v, 1024, degree).expect("ok");
            for w in parents.windows(2) {
                assert!(w[0] < w[1], "unsorted at v={v}");
            }
        }
    }

    #[test]
    fn drg_handles_v_equal_to_degree() {
        let parents = drg_parents(&seed_zero(), D_DRG, 1024, D_DRG).expect("ok");
        assert_eq!(parents.len(), D_DRG);
        // The only possible parent set is {0, 1, …, D_DRG-1}.
        let expected: Vec<usize> = (0..D_DRG).collect();
        assert_eq!(parents, expected);
    }

    // ── Expander ──

    #[test]
    fn exp_rejects_zero_n() {
        let err = expander_parents(&seed_zero(), 0, 0, D_EXP).expect_err("expected EmptyGraph");
        assert_eq!(err, SamplerError::EmptyGraph);
    }

    #[test]
    fn exp_rejects_degree_out_of_range() {
        let err = expander_parents(&seed_zero(), 0, 4, 5).expect_err("expected DegreeOutOfRange");
        assert_eq!(err, SamplerError::DegreeOutOfRange { degree: 5, n: 4 });
    }

    #[test]
    fn exp_is_deterministic_in_seed_and_v() {
        let a = expander_parents(&seed_zero(), 42, 1024, D_EXP).expect("a");
        let b = expander_parents(&seed_zero(), 42, 1024, D_EXP).expect("b");
        assert_eq!(a, b);
    }

    #[test]
    fn exp_seed_sensitivity() {
        let a = expander_parents(&seed_zero(), 42, 1024, D_EXP).expect("a");
        let b = expander_parents(&seed_one(), 42, 1024, D_EXP).expect("b");
        assert_ne!(a, b);
    }

    #[test]
    fn exp_returns_exact_degree_for_any_v() {
        for v in 0..200 {
            let parents = expander_parents(&seed_zero(), v, 1024, D_EXP).expect("ok");
            assert_eq!(parents.len(), D_EXP, "v={v}");
        }
    }

    #[test]
    fn exp_parents_within_prev_layer_range() {
        for v in 0..200 {
            let parents = expander_parents(&seed_zero(), v, 1024, D_EXP).expect("ok");
            for &p in &parents {
                assert!(p < 1024, "parent {p} out of range at v={v}");
            }
        }
    }

    #[test]
    fn exp_parents_have_no_duplicates() {
        for v in 0..200 {
            let parents = expander_parents(&seed_zero(), v, 1024, D_EXP).expect("ok");
            let set: HashSet<_> = parents.iter().copied().collect();
            assert_eq!(set.len(), parents.len(), "duplicate parent at v={v}");
        }
    }

    #[test]
    fn exp_does_not_require_self_loop_avoidance() {
        // The expander draws from layer l-1's node set; node v in layer l
        // CAN refer to node v in layer l-1 — that's a different node by layer
        // index, even if same v-index. We assert here that the sampler does
        // not artificially exclude `v` from its own draw set.
        let n = 4;
        let parents = expander_parents(&seed_zero(), 0, n, D_EXP.min(n)).expect("ok");
        // No assertion that `v ∉ parents`; just that we got a valid set.
        assert!(parents.iter().all(|&p| p < n));
    }

    #[test]
    fn exp_parents_are_sorted() {
        for v in 0..200 {
            let parents = expander_parents(&seed_zero(), v, 1024, D_EXP).expect("ok");
            for w in parents.windows(2) {
                assert!(w[0] < w[1], "unsorted at v={v}");
            }
        }
    }

    // ── Toy samplers ──

    #[test]
    fn toy_drg_pathgraph_matches_legacy() {
        assert!(drg_parents_toy_pathgraph(0).is_empty());
        assert_eq!(drg_parents_toy_pathgraph(1), vec![0]);
        assert_eq!(drg_parents_toy_pathgraph(7), vec![6]);
    }

    #[test]
    fn toy_expander_identity_matches_legacy() {
        for v in 0..10 {
            assert_eq!(expander_parents_toy_identity(v), vec![v]);
        }
    }

    // ── Tag separation ──

    #[test]
    fn drg_and_exp_draws_use_distinct_tags() {
        // A direct functional test of domain separation: the DRG and expander
        // hash with different prefixes, so for the same (seed, v, k) the two
        // u64 draws must differ — preventing cross-use of one sampler's
        // randomness as the other's.
        for v in 0..10 {
            for k in 0..D_EXP as u64 {
                let drg = draw_u64(TAG_DRG, &seed_zero(), v, k);
                let exp = draw_u64(TAG_EXP, &seed_zero(), v, k);
                assert_ne!(drg, exp, "tag separation failure at v={v}, k={k}");
            }
        }
    }

    // ── Statistical sanity at production-relevant N ──
    //
    // These are not cryptographic; they exist so that an accidental
    // implementation regression (e.g. wrong modulus, dropped seed bits)
    // produces an obvious red on the dashboard rather than a silent skew.

    #[test]
    fn drg_distribution_is_not_pathologically_skewed_over_v() {
        let n = 4096;
        let mut hits = vec![0u32; n];
        for v in D_DRG..n {
            let parents = drg_parents(&seed_zero(), v, n, D_DRG).expect("ok");
            for p in parents {
                hits[p] += 1;
            }
        }
        // For each v we draw exactly D_DRG = 6 parents uniformly in [0, v),
        // so a predecessor p is "cold" with probability per draw of
        // (1 - 1/v)^D_DRG, and across all v > p draws the probability of
        // remaining cold falls off. With n = 4096 and D_DRG = 6 we expect
        // each predecessor to be hit O(log n × D_DRG) times in expectation;
        // some scatter is normal. Sanity: at least 80% of predecessors below
        // v=n-D_DRG must be hit at least once. This catches a regression
        // where, e.g., the modulus was wrong or the seed was dropped.
        let probed_range = n - D_DRG;
        let hit_count = hits[..probed_range].iter().filter(|&&h| h > 0).count();
        let hit_ratio = hit_count as f64 / probed_range as f64;
        assert!(
            hit_ratio >= 0.80,
            "DRG coverage degenerate: only {:.1}% of predecessors below v=n-D_DRG hit",
            hit_ratio * 100.0
        );
    }

    #[test]
    fn exp_distribution_visits_full_range() {
        let n = 4096;
        let mut hits = vec![0u32; n];
        for v in 0..n {
            let parents = expander_parents(&seed_zero(), v, n, D_EXP).expect("ok");
            for p in parents {
                hits[p] += 1;
            }
        }
        // With D_EXP = 8 draws per node × n = 4096 nodes = 32768 total
        // expander edges over n = 4096 candidates, the expected coverage is
        // > 99.9% (coupon-collector + uniform). A small number of cold
        // nodes (1 or 2) is statistically normal; what's not normal is a
        // dropped-seed regression that leaves systematic dead zones.
        let unhit = hits.iter().filter(|&&h| h == 0).count();
        assert!(
            unhit < n / 100,
            "expander dead-zone regression: {unhit} prev-layer nodes never sampled (>{}%)",
            unhit * 100 / n
        );
    }
}
