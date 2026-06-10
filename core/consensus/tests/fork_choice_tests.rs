// Sprint NN: Fork choice and chain selection tests.
//
// These tests verify tip selection, tie-breaking, and finality depth
// properties that are critical for consensus safety during forks and reorgs.

use std::sync::Arc;

use citrate_consensus::dag_store::DagStore;
use citrate_consensus::finality::{FinalityConfig, FinalityTracker};
use citrate_consensus::ghostdag::GhostDag;
use citrate_consensus::types::*;

// ---------------------------------------------------------------------------
// Helper: create a test block
// ---------------------------------------------------------------------------
fn make_block(
    hash: [u8; 32],
    selected_parent: Hash,
    merge_parents: Vec<Hash>,
    height: u64,
    blue_score: u64,
) -> Block {
    BlockBuilder::new()
        .hash(Hash::new(hash))
        .parent(selected_parent)
        .merge_parents(merge_parents)
        .height(height)
        .timestamp(height)
        .blue_score(blue_score)
        // SECREM-01: admission enforces the canonical score→work relation.
        .blue_work(blue_work_for_score(blue_score))
        .build_unhashed()
}

/// Deterministic unique hash from an index.
fn hash_for(index: u64) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0..8].copy_from_slice(&index.to_le_bytes());
    h[31] = 0xCC; // distinct sentinel
    h
}

/// Seed the GhostDag engine with a genesis block.
async fn setup_genesis(dag_store: &Arc<DagStore>, ghostdag: &GhostDag) -> Hash {
    let genesis = make_block([0xFF; 32], Hash::default(), vec![], 0, 0);
    dag_store.store_block(genesis.clone()).await.unwrap();
    ghostdag.add_block(&genesis).await.unwrap();
    genesis.hash()
}

// ============================================================================
// 1. test_tip_selection_highest_blue_score
//    Create two tips with different blue scores. The GhostDag select_tip
//    method must prefer the one with the higher blue score.
// ============================================================================
#[tokio::test]
async fn test_tip_selection_highest_blue_score() {
    let params = GhostDagParams::default();
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let ghostdag = GhostDag::new(params, dag_store.clone());

    let genesis_hash = setup_genesis(&dag_store, &ghostdag).await;

    // Chain A: 5 blocks — higher blue score
    let mut prev_a = genesis_hash;
    for i in 1u64..=5 {
        let block = make_block(hash_for(i), prev_a, vec![], i, i);
        dag_store.store_block(block.clone()).await.unwrap();
        ghostdag.add_block(&block).await.unwrap();
        prev_a = block.hash();
    }

    // Chain B: 2 blocks off genesis — lower blue score
    let mut prev_b = genesis_hash;
    for i in 1u64..=2 {
        let block = make_block(hash_for(100 + i), prev_b, vec![], i, i);
        dag_store.store_block(block.clone()).await.unwrap();
        ghostdag.add_block(&block).await.unwrap();
        prev_b = block.hash();
    }

    let tips = ghostdag.get_tips().await;
    assert_eq!(tips.len(), 2, "Should have 2 tips (tip of each chain)");

    let selected = ghostdag.select_tip().await.unwrap();

    // The longer chain (A) should have higher blue score and be selected
    let score_a = ghostdag.get_blue_score(&prev_a).await.unwrap();
    let score_b = ghostdag.get_blue_score(&prev_b).await.unwrap();

    assert!(
        score_a > score_b,
        "Chain A (len=5, score={}) must have higher blue score than chain B (len=2, score={})",
        score_a,
        score_b
    );
    assert_eq!(
        selected, prev_a,
        "select_tip must choose the tip with the highest blue score"
    );
}

// ============================================================================
// 2. test_tip_selection_tiebreak_by_hash
//    Create two tips with the same blue score. The tie-break must be
//    deterministic — GhostDag's select_tip picks the tip with the higher
//    blue score, but when scores are equal the result must still be
//    consistent across calls.
// ============================================================================
#[tokio::test]
async fn test_tip_selection_tiebreak_by_hash() {
    let params = GhostDagParams::default();
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let ghostdag = GhostDag::new(params, dag_store.clone());

    let genesis_hash = setup_genesis(&dag_store, &ghostdag).await;

    // Two single-block forks off genesis — same depth, same blue score
    let block_a = make_block(hash_for(1), genesis_hash, vec![], 1, 1);
    let block_b = make_block(hash_for(2), genesis_hash, vec![], 1, 1);
    dag_store.store_block(block_a.clone()).await.unwrap();
    dag_store.store_block(block_b.clone()).await.unwrap();
    ghostdag.add_block(&block_a).await.unwrap();
    ghostdag.add_block(&block_b).await.unwrap();

    let tips = ghostdag.get_tips().await;
    assert_eq!(tips.len(), 2);

    // Call select_tip multiple times — result must be deterministic
    let selected_1 = ghostdag.select_tip().await.unwrap();
    let selected_2 = ghostdag.select_tip().await.unwrap();
    let selected_3 = ghostdag.select_tip().await.unwrap();

    assert_eq!(
        selected_1, selected_2,
        "Tie-break must be deterministic across calls"
    );
    assert_eq!(
        selected_2, selected_3,
        "Tie-break must be deterministic across calls"
    );

    // The selected tip must be one of the two tips
    assert!(
        selected_1 == block_a.hash() || selected_1 == block_b.hash(),
        "Selected tip must be one of the two tips"
    );
}

// ============================================================================
// 3. test_finality_depth_blocks_reorg
//    Create a chain of 20 blocks. Verify blocks at depth > finality_depth
//    are considered final and reorgs past them are rejected.
// ============================================================================
#[tokio::test]
async fn test_finality_depth_blocks_reorg() {
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let config = FinalityConfig {
        confirmation_depth: 5,
        emit_events: false,
        max_finalize_batch: 1000,
    };
    let tracker = FinalityTracker::new(dag_store.clone(), config);

    // Build chain of 20 blocks (heights 0..19)
    let mut prev = Hash::default();
    let mut blocks = Vec::new();
    for i in 0u64..20 {
        let block = make_block(hash_for(i + 1), prev, vec![], i, i);
        dag_store.store_block(block.clone()).await.unwrap();
        prev = block.hash();
        blocks.push(block);
    }

    let tip = blocks.last().unwrap();
    let finalized = tracker
        .update_finality(&tip.hash(), tip.header.height)
        .await
        .unwrap();

    // With depth=5 and tip at height 19, blocks at heights 0..14 should be finalized
    assert_eq!(
        finalized.len(),
        15,
        "Blocks at heights 0-14 should be finalized (15 blocks), got {}",
        finalized.len()
    );
    assert_eq!(tracker.get_finalized_height(), 14);

    // Verify finalized blocks
    for block in &blocks[..15] {
        assert!(
            tracker.is_finalized(&block.hash()).await,
            "Block at height {} should be finalized",
            block.header.height
        );
    }

    // Verify non-finalized blocks
    for block in &blocks[15..] {
        assert!(
            !tracker.is_finalized(&block.hash()).await,
            "Block at height {} should NOT be finalized",
            block.header.height
        );
    }

    // Reorg from a block BELOW the finalized height (height 10 < finalized 14)
    // should be REJECTED — it would orphan finalized blocks
    let result = tracker.check_reorg_allowed(&blocks[10].hash()).await;
    assert!(
        result.is_err(),
        "Reorg from height 10 (below finalized height 14) must be rejected"
    );

    // Reorg from an even earlier block (height 3) should also be REJECTED
    let result = tracker.check_reorg_allowed(&blocks[3].hash()).await;
    assert!(
        result.is_err(),
        "Reorg from height 3 (below finalized height 14) must be rejected"
    );

    // Reorg from an unfinalized block (height 16) should be ALLOWED
    let result = tracker.check_reorg_allowed(&blocks[16].hash()).await;
    assert!(
        result.is_ok(),
        "Reorg from unfinalized block (height 16) must be allowed"
    );
}
