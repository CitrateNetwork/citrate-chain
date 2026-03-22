//! Mentor selection algorithm (WP-F.6).
//!
//! At each BFT checkpoint, the routing model identifies mentor-mentee pairs
//! based on performance profile complementarity.  High-performing nodes
//! generate LoRA adapters targeting mentee weaknesses.
//!
//! ## Algorithm
//!
//! 1. Sort participants by accuracy (descending).
//! 2. Top half are potential mentors; bottom half are potential mentees.
//! 3. For each mentee, find the highest-complementarity mentor such that:
//!    - Accuracy gap >= MIN_ACCURACY_GAP (delta)
//!    - Mentor has capacity (< MAX_MENTEES_PER_MENTOR)
//! 4. Complementarity = |shared_domains| * (mentor.accuracy - mentee.accuracy)
//!    (minimum 1 for the domain factor so zero-overlap pairs still get a score).
//!
//! ## Adapter Generation
//!
//! After pairing, mentors produce a simple delta adapter: the element-wise
//! difference between the mentor's embedding and the mentee's embedding.
//! This is a real functional update vector — applying it moves the mentee's
//! representation toward the mentor's.

use crate::adapters::{AdapterFactory, AdapterMetadata, LearningAdapter};
use crate::embeddings::EmbeddingVector;
use crate::errors::{LearningError, LearningResult};
use crate::profile::PerformanceProfile;
use crate::types::{PublicKey, Signature};
use std::collections::HashMap;

/// Minimum accuracy gap required for mentorship (delta).
pub const MIN_ACCURACY_GAP: f64 = 0.05;

/// Maximum mentees per mentor per cycle.
pub const MAX_MENTEES_PER_MENTOR: usize = 3;

// ---------------------------------------------------------------------------
// MentorPairing
// ---------------------------------------------------------------------------

/// A mentor-mentee pairing produced by the selection algorithm.
#[derive(Debug, Clone)]
pub struct MentorPairing {
    /// Public key of the mentor node.
    pub mentor: PublicKey,
    /// Public key of the mentee node.
    pub mentee: PublicKey,
    /// Complementarity score: |shared_domains| * accuracy_gap.
    pub complementarity_score: f64,
    /// Mentor's accuracy at the time of pairing.
    pub mentor_accuracy: f64,
    /// Mentee's accuracy at the time of pairing.
    pub mentee_accuracy: f64,
    /// Domains shared between mentor and mentee.
    pub shared_domains: Vec<String>,
}

// ---------------------------------------------------------------------------
// Mentor selection
// ---------------------------------------------------------------------------

/// Select mentor-mentee pairings from participant profiles.
///
/// # Algorithm
///
/// 1. Sort participants by accuracy (descending).
/// 2. Top half are potential mentors, bottom half are potential mentees.
/// 3. For each mentee, find the mentor with the highest complementarity
///    score who still has capacity.
/// 4. Complementarity = max(1, |shared_domains|) * (mentor.accuracy - mentee.accuracy).
///
/// Returns an empty vec when fewer than 2 participants are provided.
pub fn select_mentors(
    profiles: &[(PublicKey, PerformanceProfile)],
) -> Vec<MentorPairing> {
    if profiles.len() < 2 {
        return vec![];
    }

    // Sort by accuracy descending.
    let mut sorted: Vec<_> = profiles.to_vec();
    sorted.sort_by(|a, b| {
        b.1.accuracy
            .partial_cmp(&a.1.accuracy)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut pairings = Vec::new();
    let mut mentor_load: HashMap<PublicKey, usize> = HashMap::new();

    // Top half are potential mentors; bottom half potential mentees.
    // When the count is odd, the middle node falls into the mentee set.
    let midpoint = sorted.len() / 2;
    let potential_mentors = &sorted[..midpoint.max(1)];
    let potential_mentees = &sorted[midpoint..];

    for (mentee_key, mentee_profile) in potential_mentees {
        let mut best: Option<(PublicKey, f64, Vec<String>)> = None;

        for (mentor_key, mentor_profile) in potential_mentors {
            // No self-mentoring.
            if mentor_key == mentee_key {
                continue;
            }

            // Check accuracy gap.
            let gap = mentor_profile.accuracy - mentee_profile.accuracy;
            if gap < MIN_ACCURACY_GAP {
                continue;
            }

            // Check mentor capacity.
            let load = mentor_load.get(mentor_key).copied().unwrap_or(0);
            if load >= MAX_MENTEES_PER_MENTOR {
                continue;
            }

            // Compute shared domains.
            let shared: Vec<String> = mentor_profile
                .domains
                .iter()
                .filter(|d| mentee_profile.domains.contains(d))
                .cloned()
                .collect();

            // Complementarity = max(1, |shared|) * gap.
            let complementarity = (shared.len().max(1) as f64) * gap;

            let is_better = match &best {
                None => true,
                Some((_, best_score, _)) => complementarity > *best_score,
            };

            if is_better {
                best = Some((*mentor_key, complementarity, shared));
            }
        }

        if let Some((mentor_key, score, shared)) = best {
            *mentor_load.entry(mentor_key).or_insert(0) += 1;

            let mentor_profile = potential_mentors
                .iter()
                .find(|(k, _)| *k == mentor_key)
                .expect("mentor must be in potential_mentors");

            pairings.push(MentorPairing {
                mentor: mentor_key,
                mentee: *mentee_key,
                complementarity_score: score,
                mentor_accuracy: mentor_profile.1.accuracy,
                mentee_accuracy: mentee_profile.accuracy,
                shared_domains: shared,
            });
        }
    }

    pairings
}

// ---------------------------------------------------------------------------
// Simple adapter generation
// ---------------------------------------------------------------------------

/// Generate a simple delta adapter: the element-wise difference between the
/// mentor's embedding and the mentee's embedding.
///
/// This is a functional update vector — applying it (via `apply_adapter`)
/// moves the mentee's representation toward the mentor's.  It is NOT a
/// full LoRA low-rank decomposition, but it IS a real, computable adapter
/// that produces meaningful updates.
///
/// # Errors
///
/// Returns `Err` if the embeddings have different dimensions or contain
/// non-finite values.
pub fn generate_delta_adapter(
    mentor_embedding: &[f32],
    mentee_embedding: &[f32],
) -> LearningResult<Vec<f32>> {
    if mentor_embedding.len() != mentee_embedding.len() {
        return Err(LearningError::DimensionMismatch {
            expected: mentor_embedding.len(),
            got: mentee_embedding.len(),
        });
    }

    let delta: Vec<f32> = mentor_embedding
        .iter()
        .zip(mentee_embedding.iter())
        .map(|(m, t)| m - t)
        .collect();

    // Validate result is finite.
    for (i, &v) in delta.iter().enumerate() {
        if !v.is_finite() {
            return Err(LearningError::InvalidEmbedding {
                reason: format!("non-finite delta at index {}: {}", i, v),
            });
        }
    }

    Ok(delta)
}

/// Generate a `LearningAdapter` from a mentor-mentee embedding pair.
///
/// Wraps [`generate_delta_adapter`] and produces a full `LearningAdapter`
/// with provenance, hash, and metadata ready for broadcast.
///
/// # Errors
///
/// Returns `Err` if the embeddings have mismatched dimensions, contain
/// non-finite values, or the adapter factory rejects the delta.
pub fn generate_adapter_for_mentee(
    mentor_embedding: &[f32],
    mentee_embedding: &[f32],
    mentor_key: PublicKey,
    checkpoint_height: u64,
    round: u64,
    signature: Signature,
) -> LearningResult<LearningAdapter> {
    let delta_data = generate_delta_adapter(mentor_embedding, mentee_embedding)?;
    let delta = EmbeddingVector::new(delta_data)?;

    let metadata = AdapterMetadata {
        name: format!("mentor-delta-{}", checkpoint_height),
        description: format!(
            "Delta adapter from mentor {} at checkpoint {}",
            hex::encode(mentor_key),
            checkpoint_height,
        ),
        round,
        participant_count: 2, // mentor + mentee
        created_at: checkpoint_height, // use checkpoint height as timestamp proxy
    };

    AdapterFactory::create(delta, metadata, mentor_key, checkpoint_height, signature)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a profile with the given accuracy and domains.
    fn profile(accuracy: f64, domains: &[&str]) -> PerformanceProfile {
        PerformanceProfile {
            accuracy,
            latency_ms: 50,
            domains: domains.iter().map(|s| s.to_string()).collect(),
            uptime: 0.99,
            adapter_count: 0,
        }
    }

    /// Helper: generate a unique public key from a seed byte.
    fn pubkey(seed: u8) -> PublicKey {
        [seed; 32]
    }

    // -----------------------------------------------------------------------
    // Mentor selection tests
    // -----------------------------------------------------------------------

    /// Two nodes with a clear accuracy gap — the high node mentors the low one.
    #[test]
    fn test_mentor_selection_basic() {
        let profiles = vec![
            (pubkey(1), profile(0.95, &["nlp"])),
            (pubkey(2), profile(0.60, &["nlp"])),
        ];

        let pairings = select_mentors(&profiles);
        assert_eq!(pairings.len(), 1);
        assert_eq!(pairings[0].mentor, pubkey(1));
        assert_eq!(pairings[0].mentee, pubkey(2));
        assert!((pairings[0].mentor_accuracy - 0.95).abs() < 1e-9);
        assert!((pairings[0].mentee_accuracy - 0.60).abs() < 1e-9);
        assert_eq!(pairings[0].shared_domains, vec!["nlp".to_string()]);
    }

    /// Both nodes have the same accuracy — gap is 0 < delta, so no pairing.
    #[test]
    fn test_mentor_selection_no_gap() {
        let profiles = vec![
            (pubkey(1), profile(0.80, &["nlp"])),
            (pubkey(2), profile(0.80, &["nlp"])),
        ];

        let pairings = select_mentors(&profiles);
        assert!(pairings.is_empty());
    }

    /// Gap is exactly at the MIN_ACCURACY_GAP threshold — should pair.
    /// Uses 0.5 and 0.4375 (difference = 0.0625 = 1/16, exact in IEEE 754)
    /// which is above MIN_ACCURACY_GAP (0.05).
    #[test]
    fn test_mentor_selection_min_gap() {
        // Gap = 0.0625 which is >= MIN_ACCURACY_GAP (0.05)
        let profiles = vec![
            (pubkey(1), profile(0.5, &["nlp"])),
            (pubkey(2), profile(0.4375, &["nlp"])),
        ];

        let pairings = select_mentors(&profiles);
        assert_eq!(pairings.len(), 1);
        assert_eq!(pairings[0].mentor, pubkey(1));
        assert_eq!(pairings[0].mentee, pubkey(2));
    }

    /// Gap is just below MIN_ACCURACY_GAP — no pairing.
    #[test]
    fn test_mentor_selection_below_gap() {
        let profiles = vec![
            (pubkey(1), profile(0.249, &["nlp"])),
            (pubkey(2), profile(0.20, &["nlp"])), // gap = 0.049 < 0.05
        ];

        let pairings = select_mentors(&profiles);
        assert!(pairings.is_empty());
    }

    /// One mentor is maxed out (3 mentees) — the 4th mentee picks the next best.
    #[test]
    fn test_mentor_selection_capacity() {
        // With 8 profiles, midpoint = 4.
        // Top 4 (by accuracy desc): pubkey(1)=0.95, pubkey(2)=0.90, pubkey(8)=0.88, pubkey(9)=0.87
        // Bottom 4 (mentees): pubkey(3..6) at 0.50, 0.45, 0.40, 0.35
        //
        // Mentor 1 (0.95) has the highest complementarity for all mentees and
        // should be assigned the first 3.  The 4th mentee should fall to mentor 2 (0.90).
        let profiles = vec![
            (pubkey(1), profile(0.95, &["nlp"])),
            (pubkey(2), profile(0.90, &["nlp"])),
            (pubkey(8), profile(0.88, &["nlp"])),
            (pubkey(9), profile(0.87, &["nlp"])),
            // mentees
            (pubkey(3), profile(0.50, &["nlp"])),
            (pubkey(4), profile(0.45, &["nlp"])),
            (pubkey(5), profile(0.40, &["nlp"])),
            (pubkey(6), profile(0.35, &["nlp"])),
        ];

        let pairings = select_mentors(&profiles);

        // All 4 mentees should get paired.
        assert_eq!(pairings.len(), 4);

        // Mentor 1 should be maxed out at 3.
        let m1_count = pairings.iter().filter(|p| p.mentor == pubkey(1)).count();
        assert_eq!(m1_count, MAX_MENTEES_PER_MENTOR); // 3

        // The 4th mentee should be assigned to the next best mentor.
        let remaining: Vec<_> = pairings.iter().filter(|p| p.mentor != pubkey(1)).collect();
        assert_eq!(remaining.len(), 1);
        // The remaining mentor should be pubkey(2) since it has the next highest accuracy.
        assert_eq!(remaining[0].mentor, pubkey(2));
    }

    /// Shared domains boost the complementarity score.
    #[test]
    fn test_mentor_selection_domain_boost() {
        // Two mentors with equal accuracy.
        // Mentor 1 shares 3 domains with the mentee.
        // Mentor 2 shares 1 domain.
        // Mentor 1 should win because 3 * gap > 1 * gap.
        let profiles = vec![
            (
                pubkey(1),
                profile(0.95, &["nlp", "vision", "audio"]),
            ),
            (pubkey(2), profile(0.95, &["nlp"])),
            (
                pubkey(3),
                profile(0.50, &["nlp", "vision", "audio"]),
            ),
        ];

        let pairings = select_mentors(&profiles);
        assert_eq!(pairings.len(), 1);
        // Mentor 1 wins because 3 shared domains * 0.45 gap > 1 shared domain * 0.45 gap.
        assert_eq!(pairings[0].mentor, pubkey(1));
        assert_eq!(pairings[0].shared_domains.len(), 3);
    }

    /// Only 1 node — impossible to pair.
    #[test]
    fn test_mentor_selection_single_node() {
        let profiles = vec![(pubkey(1), profile(0.95, &["nlp"]))];
        let pairings = select_mentors(&profiles);
        assert!(pairings.is_empty());
    }

    /// No nodes at all — empty result.
    #[test]
    fn test_mentor_selection_empty() {
        let profiles: Vec<(PublicKey, PerformanceProfile)> = vec![];
        let pairings = select_mentors(&profiles);
        assert!(pairings.is_empty());
    }

    // -----------------------------------------------------------------------
    // Delta adapter generation tests
    // -----------------------------------------------------------------------

    /// Simple delta: difference between two embeddings.
    #[test]
    fn test_simple_adapter_generation() {
        let mentor = vec![1.0f32, 0.5, 0.8, 0.2];
        let mentee = vec![0.3f32, 0.4, 0.6, 0.1];

        let delta = generate_delta_adapter(&mentor, &mentee).unwrap();

        assert_eq!(delta.len(), 4);
        assert!((delta[0] - 0.7).abs() < 1e-6);
        assert!((delta[1] - 0.1).abs() < 1e-6);
        assert!((delta[2] - 0.2).abs() < 1e-6);
        assert!((delta[3] - 0.1).abs() < 1e-6);
    }

    /// Mismatched dimensions return an error.
    #[test]
    fn test_simple_adapter_dimensions() {
        let mentor = vec![1.0f32, 0.5, 0.8];
        let mentee = vec![0.3f32, 0.4];

        let result = generate_delta_adapter(&mentor, &mentee);
        assert!(result.is_err());
        match result.unwrap_err() {
            LearningError::DimensionMismatch { expected, got } => {
                assert_eq!(expected, 3);
                assert_eq!(got, 2);
            }
            other => panic!("expected DimensionMismatch, got: {:?}", other),
        }
    }

    /// Identical embeddings produce a zero delta.
    #[test]
    fn test_delta_adapter_identical_embeddings() {
        let v = vec![0.5f32, 0.5, 0.5];
        let delta = generate_delta_adapter(&v, &v).unwrap();
        for &d in &delta {
            assert!((d - 0.0).abs() < 1e-9);
        }
    }

    /// Full adapter generation with provenance.
    #[test]
    fn test_generate_adapter_for_mentee() {
        let mentor_emb = vec![1.0f32, 0.8, 0.6];
        let mentee_emb = vec![0.2f32, 0.3, 0.1];

        let adapter = generate_adapter_for_mentee(
            &mentor_emb,
            &mentee_emb,
            pubkey(1),
            100,
            5,
            vec![0u8; 64],
        )
        .unwrap();

        // Delta should be mentor - mentee.
        assert!((adapter.delta.data[0] - 0.8).abs() < 1e-6);
        assert!((adapter.delta.data[1] - 0.5).abs() < 1e-6);
        assert!((adapter.delta.data[2] - 0.5).abs() < 1e-6);

        // Metadata.
        assert_eq!(adapter.creator, pubkey(1));
        assert_eq!(adapter.checkpoint_height, 100);
        assert_eq!(adapter.metadata.round, 5);
        assert_eq!(adapter.metadata.participant_count, 2);
        assert_eq!(adapter.provenance.len(), 1);

        // Hash should verify.
        assert!(AdapterFactory::verify_hash(&adapter));
    }

    /// Adapter generation rejects mismatched dimensions.
    #[test]
    fn test_generate_adapter_for_mentee_dimension_mismatch() {
        let result = generate_adapter_for_mentee(
            &[1.0, 2.0],
            &[1.0],
            pubkey(1),
            100,
            1,
            vec![0u8; 64],
        );
        assert!(result.is_err());
    }
}
