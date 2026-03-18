// Sprint KK/LL: Consensus adversarial and stress integration tests
//
// These tests exercise the GhostDAG consensus engine under adversarial
// conditions: wide DAGs, deep chains, conflicting blocks, deterministic
// tip selection, finality at depth, and blue score monotonicity.

use std::sync::Arc;

use citrate_consensus::dag_store::DagStore;
use citrate_consensus::finality::{FinalityConfig, FinalityTracker};
use citrate_consensus::ghostdag::GhostDag;
use citrate_consensus::types::*;

// ---------------------------------------------------------------------------
// Helper: create a test block with given hash, selected parent, merge parents
// ---------------------------------------------------------------------------
fn make_block(
    hash: [u8; 32],
    selected_parent: Hash,
    merge_parents: Vec<Hash>,
    height: u64,
    blue_score: u64,
) -> Block {
    Block {
        header: BlockHeader {
            version: 1,
            block_hash: Hash::new(hash),
            selected_parent_hash: selected_parent,
            merge_parent_hashes: merge_parents,
            timestamp: height,
            height,
            blue_score,
            blue_work: 0,
            pruning_point: Hash::default(),
            proposer_pubkey: PublicKey::new([0; 32]),
            vrf_reveal: VrfProof {
                proof: vec![],
                output: Hash::default(),
            },
            base_fee_per_gas: 0,
            gas_used: 0,
            gas_limit: 30_000_000,
        },
        state_root: Hash::default(),
        tx_root: Hash::default(),
        receipt_root: Hash::default(),
        artifact_root: Hash::default(),
        ghostdag_params: GhostDagParams::default(),
        transactions: vec![],
        signature: Signature::new([0; 64]),
        embedded_models: vec![],
        required_pins: vec![],
        learning_embedding: None,
        learning_confidence: None,
        gradient_commitment: None,
    }
}

/// Helper: deterministic unique hash from an index
fn hash_for(index: u64) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0..8].copy_from_slice(&index.to_le_bytes());
    h[31] = 0xAA;
    h
}

/// Seed the GhostDag engine with a genesis block and return its hash.
async fn setup_genesis(dag_store: &Arc<DagStore>, ghostdag: &GhostDag) -> Hash {
    let genesis = make_block([0xFF; 32], Hash::default(), vec![], 0, 0);
    dag_store.store_block(genesis.clone()).await.unwrap();
    ghostdag.add_block(&genesis).await.unwrap();
    genesis.hash()
}

// ============================================================================
// 1. test_dag_with_100_parallel_blocks
// ============================================================================
#[tokio::test]
async fn test_dag_with_100_parallel_blocks() {
    let params = GhostDagParams {
        k: 18,
        max_parents: 10,
        ..GhostDagParams::default()
    };
    let dag_store = Arc::new(DagStore::new());
    let ghostdag = GhostDag::new(params, dag_store.clone());

    let genesis_hash = setup_genesis(&dag_store, &ghostdag).await;

    // Create 100 blocks all at height 1, all with genesis as selected parent
    let mut block_hashes = Vec::new();
    for i in 0u64..100 {
        let h = hash_for(i + 1);
        let block = make_block(h, genesis_hash, vec![], 1, 1);
        dag_store.store_block(block.clone()).await.unwrap();
        ghostdag.add_block(&block).await.unwrap();
        block_hashes.push(block.hash());
    }

    // All 100 should be tips (no children)
    let tips = ghostdag.get_tips().await;
    assert_eq!(tips.len(), 100, "All 100 parallel blocks should be tips");

    // Tip selection should succeed and pick one of them
    let best_tip = ghostdag.select_tip().await.unwrap();
    assert!(
        block_hashes.contains(&best_tip),
        "Selected tip must be one of the 100 parallel blocks"
    );

    // Create a merge block that references some of these as parents
    let merge_parents: Vec<Hash> = block_hashes[1..5].to_vec();
    let merge_hash = hash_for(200);
    let merge_block = make_block(merge_hash, block_hashes[0], merge_parents, 2, 2);
    dag_store.store_block(merge_block.clone()).await.unwrap();
    ghostdag.add_block(&merge_block).await.unwrap();

    // Blue set calculation for merge block should complete
    let blue_set = ghostdag.calculate_blue_set(&merge_block).await.unwrap();
    assert!(
        blue_set.score >= 2,
        "Merge block blue set score should be at least 2"
    );
}

// ============================================================================
// 2. test_bfs_depth_limit_respected
// ============================================================================
#[tokio::test]
async fn test_bfs_depth_limit_respected() {
    let params = GhostDagParams::default();
    let dag_store = Arc::new(DagStore::new());
    let ghostdag = GhostDag::new(params, dag_store.clone());

    let genesis_hash = setup_genesis(&dag_store, &ghostdag).await;

    // Create a deep chain of 100 blocks
    let mut prev = genesis_hash;
    for i in 1u64..=100 {
        let h = hash_for(i);
        let block = make_block(h, prev, vec![], i, i);
        dag_store.store_block(block.clone()).await.unwrap();
        ghostdag.add_block(&block).await.unwrap();
        prev = block.hash();
    }

    // Blue set of the deepest block should include all blocks in the chain
    let tip_block = dag_store.get_block(&prev).await.unwrap();
    let blue_set = ghostdag.calculate_blue_set(&tip_block).await.unwrap();

    // In a linear chain with k=18, all blocks should be blue:
    // 1 genesis (from setup_genesis) + 100 chain blocks = 101, plus the
    // genesis add_block added it with score 1. The tip's blue set includes itself.
    assert!(
        blue_set.score >= 101,
        "Linear chain of 101 blocks: all should be in the blue set, got {}",
        blue_set.score
    );

    // Verify tip selection works on a deep chain
    let selected = ghostdag.select_tip().await.unwrap();
    assert_eq!(selected, prev, "The deepest block should be the tip");
}

// ============================================================================
// 3. test_conflicting_blocks_same_parent
// ============================================================================
#[tokio::test]
async fn test_conflicting_blocks_same_parent() {
    let params = GhostDagParams::default();
    let dag_store = Arc::new(DagStore::new());
    let ghostdag = GhostDag::new(params, dag_store.clone());

    let genesis_hash = setup_genesis(&dag_store, &ghostdag).await;

    // Two blocks with the same selected parent (genesis)
    let block_a = make_block([0xA0; 32], genesis_hash, vec![], 1, 1);
    let block_b = make_block([0xB0; 32], genesis_hash, vec![], 1, 1);

    dag_store.store_block(block_a.clone()).await.unwrap();
    dag_store.store_block(block_b.clone()).await.unwrap();
    ghostdag.add_block(&block_a).await.unwrap();
    ghostdag.add_block(&block_b).await.unwrap();

    // Both should be stored
    assert!(dag_store.has_block(&block_a.hash()).await);
    assert!(dag_store.has_block(&block_b.hash()).await);

    // Both should be tips
    let tips = ghostdag.get_tips().await;
    assert_eq!(tips.len(), 2, "Two conflicting blocks should both be tips");
    assert!(tips.contains(&block_a.hash()));
    assert!(tips.contains(&block_b.hash()));

    // Each block's own blue set should contain genesis + self
    let blue_a = ghostdag.calculate_blue_set(&block_a).await.unwrap();
    let blue_b = ghostdag.calculate_blue_set(&block_b).await.unwrap();
    assert!(blue_a.contains(&genesis_hash));
    assert!(blue_a.contains(&block_a.hash()));
    assert!(blue_b.contains(&genesis_hash));
    assert!(blue_b.contains(&block_b.hash()));

    // Create a merge block that references both
    let merge = make_block([0xCC; 32], block_a.hash(), vec![block_b.hash()], 2, 2);
    dag_store.store_block(merge.clone()).await.unwrap();
    ghostdag.add_block(&merge).await.unwrap();

    // The merge block's blue set should contain all 4 blocks
    let blue_merge = ghostdag.calculate_blue_set(&merge).await.unwrap();
    assert!(blue_merge.contains(&genesis_hash));
    assert!(blue_merge.contains(&block_a.hash()));
    assert!(blue_merge.contains(&block_b.hash()));
    assert!(blue_merge.contains(&merge.hash()));
}

// ============================================================================
// 4. test_tip_selection_deterministic
// ============================================================================
#[tokio::test]
async fn test_tip_selection_deterministic() {
    async fn build_dag() -> Hash {
        let params = GhostDagParams::default();
        let dag_store = Arc::new(DagStore::new());
        let ghostdag = GhostDag::new(params, dag_store.clone());

        let genesis_hash = setup_genesis(&dag_store, &ghostdag).await;

        // Build a chain of 10 blocks
        let mut prev = genesis_hash;
        for i in 1u64..=10 {
            let h = hash_for(i);
            let block = make_block(h, prev, vec![], i, i);
            dag_store.store_block(block.clone()).await.unwrap();
            ghostdag.add_block(&block).await.unwrap();
            prev = block.hash();
        }

        ghostdag.select_tip().await.unwrap()
    }

    let tip1 = build_dag().await;
    let tip2 = build_dag().await;

    assert_eq!(
        tip1, tip2,
        "Identical DAGs must produce identical tip selection"
    );
}

// ============================================================================
// 5. test_finality_at_depth
// ============================================================================
#[tokio::test]
async fn test_finality_at_depth() {
    let dag_store = Arc::new(DagStore::new());
    let config = FinalityConfig {
        confirmation_depth: 10,
        emit_events: false,
        max_finalize_batch: 1000,
    };
    let tracker = FinalityTracker::new(dag_store.clone(), config);

    // Create a chain of 25 blocks (heights 0..24)
    let mut prev = Hash::default();
    let mut blocks = Vec::new();
    for i in 0u64..25 {
        let h = [(i + 1) as u8; 32];
        let block = make_block(h, prev, vec![], i, i);
        dag_store.store_block(block.clone()).await.unwrap();
        prev = block.hash();
        blocks.push(block);
    }

    let tip = blocks.last().unwrap();
    let finalized = tracker
        .update_finality(&tip.hash(), tip.header.height)
        .await
        .unwrap();

    // With depth=10 and tip at height 24, blocks 0..14 should be finalized
    assert_eq!(finalized.len(), 15, "15 blocks (height 0-14) should be finalized");
    assert_eq!(tracker.get_finalized_height(), 14);

    for block in &blocks[..15] {
        assert!(
            tracker.is_finalized(&block.hash()).await,
            "Block at height {} should be finalized",
            block.header.height
        );
    }
    for block in &blocks[15..] {
        assert!(
            !tracker.is_finalized(&block.hash()).await,
            "Block at height {} should NOT be finalized",
            block.header.height
        );
    }
}

// ============================================================================
// 6. test_blue_score_monotonicity
// ============================================================================
#[tokio::test]
async fn test_blue_score_monotonicity() {
    let params = GhostDagParams::default();
    let dag_store = Arc::new(DagStore::new());
    let ghostdag = GhostDag::new(params, dag_store.clone());

    let genesis_hash = setup_genesis(&dag_store, &ghostdag).await;

    // Build a linear chain of 50 blocks
    let mut prev = genesis_hash;
    let mut block_hashes = vec![genesis_hash];
    for i in 1u64..=50 {
        let h = hash_for(i);
        let block = make_block(h, prev, vec![], i, i);
        dag_store.store_block(block.clone()).await.unwrap();
        ghostdag.add_block(&block).await.unwrap();
        prev = block.hash();
        block_hashes.push(block.hash());
    }

    // Verify monotonicity: each block's blue score >= previous block's blue score
    let mut prev_score = 0u64;
    for hash in &block_hashes {
        let score = ghostdag.get_blue_score(hash).await.unwrap();
        assert!(
            score >= prev_score,
            "Blue score must be monotonically non-decreasing: {} < {}",
            score,
            prev_score
        );
        prev_score = score;
    }

    // The final block's blue score should be the total chain length
    let final_score = ghostdag.get_blue_score(block_hashes.last().unwrap()).await.unwrap();
    assert!(
        final_score >= 51,
        "Final block in a 51-block chain should have blue score >= 51, got {}",
        final_score
    );
}
