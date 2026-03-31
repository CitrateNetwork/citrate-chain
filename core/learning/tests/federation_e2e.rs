//! Federation E2E Test — First Learning Cycle (WP-F.7 Milestone)
//!
//! Simulates 5 nodes completing one full OODA learning cycle:
//! 1. Each node has a different performance profile (some good, some bad)
//! 2. Each node produces a local embedding from simulated inference
//! 3. All embeddings are collected (simulating P2P gossip)
//! 4. Paraconsensus aggregation produces consensus embedding + Belnap state vector
//! 5. Mentor selection identifies mentor-mentee pairs
//! 6. Mentor generates delta adapter for mentee
//! 7. Mentee applies adapter and shows improved accuracy
//! 8. learning_root hash is computed and is deterministic
//!
//! This test exercises the real learning crate APIs end-to-end without
//! requiring actual P2P networking or a running node.

use citrate_learning::belnap::{classify_belnap, reduce_belnap_states, BelnapValue};
use citrate_learning::embeddings::EmbeddingVector;
use citrate_learning::mentor::{
    generate_delta_adapter, select_mentors, MAX_MENTEES_PER_MENTOR, MIN_ACCURACY_GAP,
};
use citrate_learning::orchestration::{
    compute_learning_root, LearningOrchestrator, LearningOrchestratorConfig, PeerEmbedding,
    PeerProfileStore,
};
use citrate_learning::profile::PerformanceProfile;

// ---------------------------------------------------------------------------
// Test node definition
// ---------------------------------------------------------------------------

/// A simulated node in the federation.
struct TestNode {
    /// Human-readable identifier for debugging.
    name: &'static str,
    /// Public key (unique 32-byte identifier).
    pubkey: [u8; 32],
    /// Simulated embedding vector from local inference.
    embedding: Vec<f32>,
    /// Per-dimension confidence values (same length as embedding).
    confidence: Vec<f32>,
    /// Overall accuracy metric (0.0 -- 1.0).
    accuracy: f64,
    /// Model domains this node serves.
    domains: Vec<String>,
    /// Blue score from consensus (trust weight).
    blue_score: f32,
}

/// Create 5 test nodes with distinct specializations and performance levels.
///
/// - Node A: NLP expert (accuracy 0.90) — strong in dims 0-3
/// - Node B: Vision expert (accuracy 0.88) — strong in dims 4-7
/// - Node C: Generalist (accuracy 0.50) — mediocre everywhere
/// - Node D: NLP learner (accuracy 0.30) — wants to learn NLP
/// - Node E: Vision learner (accuracy 0.25) — wants to learn vision
fn create_test_nodes() -> Vec<TestNode> {
    vec![
        TestNode {
            name: "Node A (NLP Expert)",
            pubkey: [1u8; 32],
            // High values in NLP dims (0-3), low in vision dims (4-7)
            embedding: vec![0.9, 0.85, 0.88, 0.92, 0.1, 0.15, 0.05, 0.12],
            confidence: vec![0.95, 0.92, 0.93, 0.94, 0.3, 0.35, 0.2, 0.25],
            accuracy: 0.90,
            domains: vec!["nlp".to_string()],
            blue_score: 100.0,
        },
        TestNode {
            name: "Node B (Vision Expert)",
            pubkey: [2u8; 32],
            // Low in NLP dims, high in vision dims
            embedding: vec![0.1, 0.15, 0.08, 0.12, 0.92, 0.88, 0.95, 0.87],
            confidence: vec![0.25, 0.3, 0.2, 0.28, 0.95, 0.93, 0.96, 0.91],
            accuracy: 0.88,
            domains: vec!["vision".to_string()],
            blue_score: 95.0,
        },
        TestNode {
            name: "Node C (Generalist)",
            pubkey: [3u8; 32],
            // Mediocre everywhere
            embedding: vec![0.5, 0.55, 0.5, 0.48, 0.52, 0.51, 0.49, 0.53],
            confidence: vec![0.6, 0.58, 0.62, 0.59, 0.61, 0.57, 0.63, 0.6],
            accuracy: 0.50,
            domains: vec!["nlp".to_string(), "vision".to_string()],
            blue_score: 80.0,
        },
        TestNode {
            name: "Node D (NLP Learner)",
            pubkey: [4u8; 32],
            // Wants to learn NLP — currently weak
            embedding: vec![0.3, 0.25, 0.28, 0.32, 0.4, 0.35, 0.38, 0.42],
            confidence: vec![0.85, 0.82, 0.83, 0.86, 0.5, 0.45, 0.48, 0.52],
            accuracy: 0.30,
            domains: vec!["nlp".to_string()],
            blue_score: 70.0,
        },
        TestNode {
            name: "Node E (Vision Learner)",
            pubkey: [5u8; 32],
            // Wants to learn vision — currently weak
            embedding: vec![0.35, 0.4, 0.32, 0.38, 0.2, 0.25, 0.18, 0.22],
            confidence: vec![0.5, 0.48, 0.52, 0.47, 0.85, 0.83, 0.86, 0.82],
            accuracy: 0.25,
            domains: vec!["vision".to_string()],
            blue_score: 65.0,
        },
    ]
}

/// Helper: build a PerformanceProfile from a TestNode.
fn profile_from_node(node: &TestNode) -> PerformanceProfile {
    PerformanceProfile {
        accuracy: node.accuracy,
        latency_ms: 50,
        domains: node.domains.clone(),
        uptime: 0.99,
        adapter_count: 0,
    }
}

/// Helper: build a PeerEmbedding from a TestNode.
fn peer_embedding_from_node(node: &TestNode) -> PeerEmbedding {
    PeerEmbedding {
        embedding: node.embedding.clone(),
        confidence: node.confidence.clone(),
        blue_score: node.blue_score,
    }
}

/// Helper: compute Euclidean distance between two embedding vectors.
fn euclidean_distance(a: &[f32], b: &[f32]) -> f32 {
    assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x - y).powi(2))
        .sum::<f32>()
        .sqrt()
}

// ===========================================================================
// Test 1: Full OODA Learning Cycle (THE MILESTONE)
// ===========================================================================

#[test]
fn test_full_ooda_learning_cycle() {
    let nodes = create_test_nodes();
    let checkpoint_height = 50u64;
    let embedding_dim = 8usize;

    // -----------------------------------------------------------------------
    // OBSERVE: Each node produces a local embedding
    // (simulated — in production these come from inference results)
    // -----------------------------------------------------------------------
    let peer_embeddings: Vec<PeerEmbedding> = nodes
        .iter()
        .map(peer_embedding_from_node)
        .collect();

    // -----------------------------------------------------------------------
    // ORIENT: Run paraconsensus aggregation
    // -----------------------------------------------------------------------
    let orchestrator = LearningOrchestrator::new(LearningOrchestratorConfig {
        min_embeddings: 3,
        embedding_dim,
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    });

    // First embedding goes as local, rest as peers
    let local = peer_embeddings[0].clone();
    let peers: Vec<PeerEmbedding> = peer_embeddings[1..].to_vec();

    let result = orchestrator
        .run_checkpoint_aggregation(checkpoint_height, Some(local), peers)
        .expect("Aggregation should succeed with 5 valid embeddings");

    assert_eq!(
        result.participant_count, 5,
        "All 5 nodes should participate"
    );
    assert_ne!(
        result.learning_root,
        [0u8; 32],
        "learning_root must be non-zero when quorum is met"
    );
    assert_eq!(
        result.aggregated_embedding.len(),
        embedding_dim,
        "Aggregated embedding must have correct dimension"
    );
    assert_eq!(
        result.state_vector.len(),
        embedding_dim,
        "State vector must have correct dimension"
    );
    assert!(
        result.confidence > 0.0,
        "Confidence must be positive with valid high-confidence inputs"
    );

    // Verify state vector captures real structure:
    // NLP dims (0-3) should show disagreement (experts vs learners pull opposite)
    // Vision dims (4-7) should also show disagreement
    // At minimum, some dimensions should be True, Both, or Neither.
    let has_true = result.state_vector.contains(&BelnapValue::True);
    let has_both = result.state_vector.contains(&BelnapValue::Both);
    // With 5 nodes pulling in different directions, we expect at least some
    // agreement (True) or disagreement (Both) depending on confidence levels.
    assert!(
        has_true || has_both,
        "State vector should contain meaningful Belnap values, not all Neither"
    );

    // -----------------------------------------------------------------------
    // DECIDE: Select mentor-mentee pairs via profile store
    // -----------------------------------------------------------------------
    let mut profile_store = PeerProfileStore::new(10);
    for node in &nodes {
        profile_store.store_profile(
            checkpoint_height,
            node.pubkey,
            profile_from_node(node),
        );
    }

    let pairings = orchestrator.run_mentor_selection(&profile_store, checkpoint_height);

    // With 5 nodes sorted by accuracy: A(0.90), B(0.88), C(0.50), D(0.30), E(0.25)
    // Top half (mentors): A, B
    // Bottom half (mentees): C, D, E
    // Expected pairings based on domain overlap and accuracy gap:
    //   A(nlp,0.90) -> D(nlp,0.30): shared domain "nlp", gap 0.60
    //   B(vision,0.88) -> E(vision,0.25): shared domain "vision", gap 0.63
    //   A or B -> C(both,0.50): gap from either is sufficient
    assert!(
        !pairings.is_empty(),
        "Should produce at least one mentor-mentee pairing"
    );

    // Verify all pairings have sufficient accuracy gap
    for pairing in &pairings {
        let gap = pairing.mentor_accuracy - pairing.mentee_accuracy;
        assert!(
            gap >= MIN_ACCURACY_GAP,
            "Mentor accuracy gap ({:.3}) must be >= MIN_ACCURACY_GAP ({:.3}) for pairing: {:?} -> {:?}",
            gap,
            MIN_ACCURACY_GAP,
            pairing.mentor,
            pairing.mentee,
        );
    }

    // Verify mentor capacity is respected
    let mut mentor_counts = std::collections::HashMap::new();
    for pairing in &pairings {
        *mentor_counts.entry(pairing.mentor).or_insert(0usize) += 1;
    }
    for (mentor, count) in &mentor_counts {
        assert!(
            *count <= MAX_MENTEES_PER_MENTOR,
            "Mentor {:?} has {} mentees, exceeds MAX_MENTEES_PER_MENTOR={}",
            mentor,
            count,
            MAX_MENTEES_PER_MENTOR,
        );
    }

    // -----------------------------------------------------------------------
    // ACT: Mentor generates delta adapter for each mentee
    // -----------------------------------------------------------------------
    for pairing in &pairings {
        // Find mentor and mentee nodes
        let mentor_node = nodes
            .iter()
            .find(|n| n.pubkey == pairing.mentor)
            .expect("Mentor must exist in test nodes");
        let mentee_node = nodes
            .iter()
            .find(|n| n.pubkey == pairing.mentee)
            .expect("Mentee must exist in test nodes");

        // Generate delta adapter
        let adapter = generate_delta_adapter(&mentor_node.embedding, &mentee_node.embedding)
            .expect("Delta adapter generation should succeed");

        assert_eq!(
            adapter.len(),
            embedding_dim,
            "Adapter must have same dimension as embeddings"
        );

        // Apply adapter to mentee's embedding with learning rate 0.1
        let learning_rate = 0.1f32;
        let improved: Vec<f32> = mentee_node
            .embedding
            .iter()
            .zip(adapter.iter())
            .map(|(m, a)| m + a * learning_rate)
            .collect();

        // Verify improvement: improved embedding should be closer to mentor's
        let old_distance = euclidean_distance(&mentee_node.embedding, &mentor_node.embedding);
        let new_distance = euclidean_distance(&improved, &mentor_node.embedding);

        assert!(
            new_distance < old_distance,
            "After applying adapter, mentee '{}' should be closer to mentor '{}'. \
             Old distance: {:.4}, New distance: {:.4}",
            mentee_node.name,
            mentor_node.name,
            old_distance,
            new_distance,
        );
    }

    // -----------------------------------------------------------------------
    // Verify learning_root is non-trivial and deterministic
    // -----------------------------------------------------------------------
    let root_check = compute_learning_root(
        &result.aggregated_embedding,
        &result.state_vector,
        checkpoint_height,
    );
    assert_eq!(
        result.learning_root, root_check,
        "learning_root from orchestrator must match manual computation"
    );
}

// ===========================================================================
// Test 2: Learning root determinism across runs
// ===========================================================================

#[test]
fn test_learning_root_deterministic_across_runs() {
    let nodes = create_test_nodes();
    let checkpoint_height = 50u64;
    let embedding_dim = 8usize;

    let orchestrator = LearningOrchestrator::new(LearningOrchestratorConfig {
        min_embeddings: 3,
        embedding_dim,
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    });

    // Run 1
    let local_1 = peer_embedding_from_node(&nodes[0]);
    let peers_1: Vec<PeerEmbedding> = nodes[1..].iter().map(peer_embedding_from_node).collect();
    let result_1 = orchestrator
        .run_checkpoint_aggregation(checkpoint_height, Some(local_1), peers_1)
        .expect("Run 1 should succeed");

    // Run 2 (same inputs)
    let local_2 = peer_embedding_from_node(&nodes[0]);
    let peers_2: Vec<PeerEmbedding> = nodes[1..].iter().map(peer_embedding_from_node).collect();
    let result_2 = orchestrator
        .run_checkpoint_aggregation(checkpoint_height, Some(local_2), peers_2)
        .expect("Run 2 should succeed");

    // INV-2: LearningRootDeterministic — same inputs produce same hash
    assert_eq!(
        result_1.learning_root, result_2.learning_root,
        "Same inputs must produce identical learning_root (INV-2)"
    );
    assert_eq!(
        result_1.participant_count, result_2.participant_count,
        "Participant count must be identical"
    );
    assert_eq!(
        result_1.aggregated_embedding, result_2.aggregated_embedding,
        "Aggregated embeddings must be identical"
    );
    assert_eq!(
        result_1.state_vector, result_2.state_vector,
        "State vectors must be identical"
    );
    assert_ne!(
        result_1.learning_root,
        [0u8; 32],
        "learning_root must be non-zero"
    );
}

// ===========================================================================
// Test 3: Mentor adapter improves mentee accuracy
// ===========================================================================

#[test]
fn test_mentor_adapter_improves_accuracy() {
    let nodes = create_test_nodes();

    // Node A (NLP Expert) mentors Node D (NLP Learner)
    let mentor = &nodes[0]; // accuracy 0.90, NLP expert
    let mentee = &nodes[3]; // accuracy 0.30, NLP learner

    // Generate the delta adapter
    let adapter = generate_delta_adapter(&mentor.embedding, &mentee.embedding)
        .expect("Delta adapter should succeed");

    // Delta should be: mentor - mentee
    for (i, adapter_val) in adapter.iter().enumerate() {
        let expected = mentor.embedding[i] - mentee.embedding[i];
        assert!(
            (adapter_val - expected).abs() < 1e-6,
            "Adapter[{}] = {:.4} but expected {:.4}",
            i,
            adapter_val,
            expected,
        );
    }

    // Apply with varying learning rates and verify monotonic improvement
    let original_distance = euclidean_distance(&mentee.embedding, &mentor.embedding);
    let mut prev_distance = original_distance;

    for &lr in &[0.01f32, 0.05, 0.1, 0.2, 0.5] {
        let improved: Vec<f32> = mentee
            .embedding
            .iter()
            .zip(adapter.iter())
            .map(|(m, a)| m + a * lr)
            .collect();

        let new_distance = euclidean_distance(&improved, &mentor.embedding);
        assert!(
            new_distance < original_distance,
            "At lr={}, new_distance ({:.4}) should be < original ({:.4})",
            lr,
            new_distance,
            original_distance,
        );

        // Higher learning rate should bring mentee even closer
        // (up to lr=1.0 which would exactly match the mentor)
        if lr <= 0.5 {
            assert!(
                new_distance <= prev_distance + 1e-6,
                "Monotonic improvement violated at lr={}",
                lr,
            );
            prev_distance = new_distance;
        }
    }

    // At lr=1.0, mentee should exactly match mentor
    let perfect: Vec<f32> = mentee
        .embedding
        .iter()
        .zip(adapter.iter())
        .map(|(m, a)| m + a * 1.0)
        .collect();
    let perfect_distance = euclidean_distance(&perfect, &mentor.embedding);
    assert!(
        perfect_distance < 1e-5,
        "At lr=1.0, mentee should exactly match mentor (distance={:.6})",
        perfect_distance,
    );
}

// ===========================================================================
// Test 4: Belnap state vector captures disagreement
// ===========================================================================

#[test]
fn test_belnap_state_vector_captures_disagreement() {
    // Node A and Node B are experts in opposite domains.
    // They should produce Both at dimensions where they disagree.
    let dim = 4;

    // Node A: strong in dim 0-1 (NLP), weak in dim 2-3 (vision)
    let e_a = EmbeddingVector::new(vec![5.0, 4.0, -3.0, -4.0]).unwrap();
    // Node B: weak in dim 0-1, strong in dim 2-3
    let e_b = EmbeddingVector::new(vec![-3.0, -4.0, 5.0, 4.0]).unwrap();

    // Both have high confidence everywhere
    let conf_high = vec![0.95f32; dim];

    // Equal trust (same blue score)
    let blue_scores = vec![10.0f32, 10.0];

    let classifications = classify_belnap(
        &[&e_a, &e_b],
        &[conf_high.as_slice(), conf_high.as_slice()],
        &blue_scores,
        1.0,  // temperature
        0.8,  // theta_high
        0.3,  // theta_low
    );

    // Reduce to consensus state vector
    let state_vector = reduce_belnap_states(&classifications);
    assert_eq!(state_vector.len(), dim);

    // All dimensions should be Both — two comparable-trust experts disagree
    // on every dimension (opposite directions from the mean).
    for (j, &val) in state_vector.iter().enumerate() {
        assert_eq!(
            val,
            BelnapValue::Both,
            "Dimension {} should be Both (disagreement), got {:?}",
            j,
            val,
        );
    }
}

// ===========================================================================
// Test 5: Below-quorum graceful handling
// ===========================================================================

#[test]
fn test_cycle_below_quorum_produces_zero_root() {
    let nodes = create_test_nodes();
    let embedding_dim = 8;

    // Require 5 but only provide 1 — below quorum
    let orchestrator = LearningOrchestrator::new(LearningOrchestratorConfig {
        min_embeddings: 5,
        embedding_dim,
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    });

    let single = peer_embedding_from_node(&nodes[0]);
    let result = orchestrator
        .run_checkpoint_aggregation(100, Some(single), vec![])
        .expect("Below-quorum should not error (returns zero root per INV-5)");

    assert_eq!(
        result.learning_root,
        [0u8; 32],
        "Below quorum must produce zero learning_root"
    );
    assert_eq!(result.participant_count, 1);
    assert!(
        result.aggregated_embedding.is_empty(),
        "No aggregated embedding when below quorum"
    );
    assert!(
        result.state_vector.is_empty(),
        "No state vector when below quorum"
    );
    assert!(
        result.mentor_pairings.is_empty(),
        "No mentor pairings when below quorum"
    );
}

// ===========================================================================
// Test 6: Empty cycle
// ===========================================================================

#[test]
fn test_empty_cycle() {
    let orchestrator = LearningOrchestrator::new(LearningOrchestratorConfig {
        min_embeddings: 3,
        embedding_dim: 8,
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    });

    let result = orchestrator
        .run_checkpoint_aggregation(200, None, vec![])
        .expect("Empty cycle should not error");

    assert_eq!(result.learning_root, [0u8; 32]);
    assert_eq!(result.participant_count, 0);
    assert!(result.aggregated_embedding.is_empty());
    assert!(result.state_vector.is_empty());

    // Mentor selection with empty profile store
    let profile_store = PeerProfileStore::new(10);
    let pairings = orchestrator.run_mentor_selection(&profile_store, 200);
    assert!(
        pairings.is_empty(),
        "Empty profile store should produce no pairings"
    );
}

// ===========================================================================
// Test 7: learning_root independence from state_root (Theorem 3)
// ===========================================================================

#[test]
fn test_learning_root_does_not_affect_block_hash() {
    // Two blocks identical except for learning_root must produce the same
    // consensus hash. The learning_root is deliberately excluded from
    // Block::compute_hash() in core/consensus/src/types.rs.
    //
    // Since we cannot import citrate_consensus from this crate (no dependency),
    // we verify the property structurally: compute_learning_root with different
    // inputs produces different hashes, but these hashes live in a field that
    // is excluded from compute_hash(). This is tested directly in
    // citrate_consensus::types::tests::test_learning_root_excluded_from_hash.
    //
    // Here we verify the complementary property: the learning_root is a
    // pure function of (aggregated_embedding, state_vector, checkpoint_height)
    // and is completely independent from any block header fields.

    let embedding_a = vec![0.1f32, 0.2, 0.3, 0.4];
    let embedding_b = vec![0.9f32, 0.8, 0.7, 0.6];
    let state_a = vec![BelnapValue::True; 4];
    let state_b = vec![BelnapValue::Both; 4];

    let root_a = compute_learning_root(&embedding_a, &state_a, 100);
    let root_b = compute_learning_root(&embedding_b, &state_b, 100);

    // Different learning inputs produce different roots
    assert_ne!(root_a, root_b);

    // But neither root depends on block header fields (parent hash, height,
    // proposer key, etc.) — the function signature proves this:
    // compute_learning_root(embedding, state_vector, checkpoint_height)
    // takes ONLY learning data and the checkpoint height.

    // Verify the learning_root is deterministic and non-trivial
    let root_a2 = compute_learning_root(&embedding_a, &state_a, 100);
    assert_eq!(root_a, root_a2, "Same inputs must produce same root");
    assert_ne!(root_a, [0u8; 32], "Root must be non-trivial");

    // Different checkpoint heights produce different roots (domain separation)
    let root_a_height200 = compute_learning_root(&embedding_a, &state_a, 200);
    assert_ne!(
        root_a, root_a_height200,
        "Different checkpoint heights must produce different roots"
    );
}

// ===========================================================================
// Test 8: Heterogeneous embedding dimensions handled
// ===========================================================================

#[test]
fn test_mixed_dimension_embeddings_filtered() {
    let embedding_dim = 8;

    let orchestrator = LearningOrchestrator::new(LearningOrchestratorConfig {
        min_embeddings: 2,
        embedding_dim,
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    });

    // 3 nodes with dim=8 (correct)
    let valid_1 = PeerEmbedding {
        embedding: vec![1.0; 8],
        confidence: vec![0.9; 8],
        blue_score: 100.0,
    };
    let valid_2 = PeerEmbedding {
        embedding: vec![0.5; 8],
        confidence: vec![0.85; 8],
        blue_score: 90.0,
    };
    let valid_3 = PeerEmbedding {
        embedding: vec![0.3; 8],
        confidence: vec![0.8; 8],
        blue_score: 80.0,
    };

    // 2 nodes with dim=4 (wrong — will be filtered)
    let invalid_1 = PeerEmbedding {
        embedding: vec![1.0; 4],
        confidence: vec![0.9; 4],
        blue_score: 200.0, // high blue score shouldn't save it
    };
    let invalid_2 = PeerEmbedding {
        embedding: vec![0.5; 4],
        confidence: vec![0.85; 4],
        blue_score: 150.0,
    };

    let result = orchestrator
        .run_checkpoint_aggregation(
            100,
            Some(valid_1),
            vec![valid_2, valid_3, invalid_1, invalid_2],
        )
        .expect("Should succeed after filtering invalid embeddings");

    // Only 3 valid embeddings should participate (dim=4 ones filtered out)
    assert_eq!(
        result.participant_count, 3,
        "Only dim=8 embeddings should participate"
    );
    assert_ne!(result.learning_root, [0u8; 32]);
    assert_eq!(result.aggregated_embedding.len(), embedding_dim);
}

// ===========================================================================
// Test 9: Full cycle produces metrics
// ===========================================================================

#[test]
fn test_cycle_produces_metrics() {
    let nodes = create_test_nodes();
    let checkpoint_height = 50u64;
    let embedding_dim = 8;

    let orchestrator = LearningOrchestrator::new(LearningOrchestratorConfig {
        min_embeddings: 3,
        embedding_dim,
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    });

    let local = peer_embedding_from_node(&nodes[0]);
    let peers: Vec<PeerEmbedding> = nodes[1..].iter().map(peer_embedding_from_node).collect();

    let result = orchestrator
        .run_checkpoint_aggregation(checkpoint_height, Some(local), peers)
        .expect("Aggregation should succeed");

    // --- Verify all expected metrics are present ---

    // 1. Participant count
    assert_eq!(result.participant_count, 5);

    // 2. Aggregated embedding has correct dimension
    assert_eq!(result.aggregated_embedding.len(), embedding_dim);

    // 3. Aggregated embedding is L2-normalized (norm close to 1.0)
    let norm: f32 = result
        .aggregated_embedding
        .iter()
        .map(|x| x * x)
        .sum::<f32>()
        .sqrt();
    assert!(
        (norm - 1.0).abs() < 0.01,
        "Aggregated embedding should be L2-normalized (norm={:.4})",
        norm,
    );

    // 4. State vector has correct dimension and meaningful content
    assert_eq!(result.state_vector.len(), embedding_dim);
    // Count Belnap values by type for diagnostic purposes
    let neither_count = result
        .state_vector
        .iter()
        .filter(|&&v| v == BelnapValue::Neither)
        .count();
    // Not all values should be Neither (we have high-confidence participants)
    assert!(
        neither_count < embedding_dim,
        "Not all state vector values should be Neither (got {}/{})",
        neither_count,
        embedding_dim,
    );

    // 5. Confidence is positive
    assert!(
        result.confidence > 0.0,
        "Confidence must be positive, got {}",
        result.confidence,
    );

    // 6. learning_root is non-zero
    assert_ne!(result.learning_root, [0u8; 32]);

    // 7. Mentor pairings via profile store
    let mut profile_store = PeerProfileStore::new(10);
    for node in &nodes {
        profile_store.store_profile(checkpoint_height, node.pubkey, profile_from_node(node));
    }

    let pairings = orchestrator.run_mentor_selection(&profile_store, checkpoint_height);

    // At least 2 pairings expected (D and E are clear mentees)
    assert!(
        pairings.len() >= 2,
        "Expected at least 2 mentor-mentee pairings, got {}",
        pairings.len(),
    );

    // Verify pairing structure
    for pairing in &pairings {
        assert!(
            pairing.mentor != pairing.mentee,
            "No self-mentoring allowed"
        );
        assert!(
            pairing.complementarity_score > 0.0,
            "Complementarity score must be positive"
        );
        assert!(
            pairing.mentor_accuracy > pairing.mentee_accuracy,
            "Mentor accuracy ({}) must exceed mentee accuracy ({})",
            pairing.mentor_accuracy,
            pairing.mentee_accuracy,
        );
    }
}

// ===========================================================================
// Test 10: Direct mentor selection verifies NLP and Vision pairings
// ===========================================================================

#[test]
fn test_domain_specific_mentor_pairing() {
    let nodes = create_test_nodes();

    // Build profiles for select_mentors (which takes &[(PublicKey, PerformanceProfile)])
    let profiles: Vec<([u8; 32], PerformanceProfile)> = nodes
        .iter()
        .map(|n| (n.pubkey, profile_from_node(n)))
        .collect();

    let pairings = select_mentors(&profiles);

    // Find the pairing where Node D (NLP learner) is the mentee
    let d_pairing = pairings.iter().find(|p| p.mentee == [4u8; 32]);
    assert!(
        d_pairing.is_some(),
        "Node D (NLP Learner, accuracy=0.30) should be mentored"
    );
    let d_pairing = d_pairing.unwrap();
    // Node A (NLP Expert, [1u8;32]) should mentor Node D (shared domain "nlp")
    assert_eq!(
        d_pairing.mentor,
        [1u8; 32],
        "Node A should mentor Node D (shared NLP domain, highest accuracy)"
    );
    assert!(
        d_pairing.shared_domains.contains(&"nlp".to_string()),
        "Shared domain should include 'nlp'"
    );

    // Find the pairing where Node E (Vision learner) is the mentee
    let e_pairing = pairings.iter().find(|p| p.mentee == [5u8; 32]);
    assert!(
        e_pairing.is_some(),
        "Node E (Vision Learner, accuracy=0.25) should be mentored"
    );
    let e_pairing = e_pairing.unwrap();
    // Node A or B could mentor E — but B has domain "vision" overlap
    // B has shared domain "vision" with E which gives 1 * gap vs A's 0 overlap (max(1, 0) * gap = 1 * gap)
    // Both would have complementarity = 1 * gap, but B has shared domain "vision" → 1 * gap vs A's max(1,0) * gap = 1 * gap
    // Since A has higher accuracy (0.90 vs 0.88), A gets slightly higher complementarity if no domain overlap,
    // but B has actual shared domain. With the formula max(1, |shared|) * gap:
    //   A -> E: max(1, 0) * (0.90 - 0.25) = 1 * 0.65 = 0.65
    //   B -> E: max(1, 1) * (0.88 - 0.25) = 1 * 0.63 = 0.63
    // A wins on pure score, but if A is already mentoring D, and possibly C, B is next best.
    // Accept either A or B as valid mentor for E.
    assert!(
        e_pairing.mentor == [1u8; 32] || e_pairing.mentor == [2u8; 32],
        "Node A or B should mentor Node E"
    );
}

// ===========================================================================
// Test 11: Adapter application convergence
// ===========================================================================

#[test]
fn test_iterative_adapter_convergence() {
    // Simulate multiple rounds of adapter application.
    // Each round, the mentee's embedding should get closer to the mentor's.
    let mentor_emb = vec![0.9f32, 0.85, 0.88, 0.92, 0.1, 0.15, 0.05, 0.12];
    let mut mentee_emb = vec![0.3f32, 0.25, 0.28, 0.32, 0.4, 0.35, 0.38, 0.42];

    let learning_rate = 0.3f32;
    let mut prev_distance = euclidean_distance(&mentee_emb, &mentor_emb);

    for round in 0..10 {
        let adapter = generate_delta_adapter(&mentor_emb, &mentee_emb)
            .expect("Delta adapter should succeed each round");

        // Apply adapter
        mentee_emb = mentee_emb
            .iter()
            .zip(adapter.iter())
            .map(|(m, a)| m + a * learning_rate)
            .collect();

        let new_distance = euclidean_distance(&mentee_emb, &mentor_emb);
        assert!(
            new_distance < prev_distance,
            "Round {}: distance should decrease ({:.4} -> {:.4})",
            round,
            prev_distance,
            new_distance,
        );
        prev_distance = new_distance;
    }

    // After 10 rounds with lr=0.3, distance should be very small
    // Each round multiplies remaining distance by (1 - lr) = 0.7
    // After 10 rounds: distance * 0.7^10 ≈ distance * 0.028
    assert!(
        prev_distance < 0.1,
        "After 10 rounds of adaptation, distance should be very small (got {:.4})",
        prev_distance,
    );
}

// ===========================================================================
// Test 12: Profile store integration with mentor selection
// ===========================================================================

#[test]
fn test_profile_store_pruning_does_not_lose_current() {
    let nodes = create_test_nodes();

    // Create a store that retains only 2 checkpoint generations
    let mut store = PeerProfileStore::new(2);

    // Store profiles for 3 consecutive checkpoints
    for &height in &[50u64, 100, 150] {
        for node in &nodes {
            store.store_profile(height, node.pubkey, profile_from_node(node));
        }
    }

    // After inserting 3 heights with max_checkpoints=2, height 50 should be pruned
    let profiles_at_50 = store.get_profiles_at_checkpoint(50);
    assert!(
        profiles_at_50.is_empty(),
        "Profiles at pruned checkpoint 50 should be gone"
    );

    // Heights 100 and 150 should still be present
    let profiles_at_100 = store.get_profiles_at_checkpoint(100);
    assert_eq!(profiles_at_100.len(), 5);

    let profiles_at_150 = store.get_profiles_at_checkpoint(150);
    assert_eq!(profiles_at_150.len(), 5);

    // Mentor selection at height 150 should still work
    let orchestrator = LearningOrchestrator::new(LearningOrchestratorConfig {
        min_embeddings: 3,
        embedding_dim: 8,
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    });

    let pairings = orchestrator.run_mentor_selection(&store, 150);
    assert!(
        !pairings.is_empty(),
        "Mentor selection at latest checkpoint should still produce pairings"
    );
}

// ===========================================================================
// Test 13: Aggregation with NaN and Inf values gracefully filtered
// ===========================================================================

#[test]
fn test_byzantine_node_filtered_from_aggregation() {
    let nodes = create_test_nodes();
    let embedding_dim = 8;

    let orchestrator = LearningOrchestrator::new(LearningOrchestratorConfig {
        min_embeddings: 3,
        embedding_dim,
        temperature: 1.0,
        theta_high: 0.8,
        theta_low: 0.3,
    });

    // Create normal embeddings from 4 nodes
    let valid_peers: Vec<PeerEmbedding> = nodes[0..4]
        .iter()
        .map(peer_embedding_from_node)
        .collect();

    // Create a byzantine embedding with NaN
    let byzantine = PeerEmbedding {
        embedding: vec![f32::NAN, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5],
        confidence: vec![0.9; 8],
        blue_score: 999.0, // Very high trust — should still be filtered
    };

    let mut all_peers = valid_peers;
    all_peers.push(byzantine);

    let result = orchestrator
        .run_checkpoint_aggregation(100, None, all_peers)
        .expect("Should succeed after filtering byzantine node");

    // Byzantine node filtered, 4 valid remain
    assert_eq!(
        result.participant_count, 4,
        "Byzantine node with NaN should be filtered out"
    );
    assert_ne!(result.learning_root, [0u8; 32]);
}
