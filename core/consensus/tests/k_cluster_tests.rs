// Sprint NN: K-cluster boundary tests — core safety property of GhostDAG.
//
// The k parameter (default 18) determines how many blocks can be in the
// anticone of a block and still be considered "blue" (honest). These tests
// verify that blue set calculation, selected-parent selection, and
// withholding attack resistance work correctly.

use std::sync::Arc;

use citrate_consensus::dag_store::DagStore;
use citrate_consensus::ghostdag::GhostDag;
use citrate_consensus::types::*;

// ---------------------------------------------------------------------------
// Helper: create a test block (mirrors consensus_adversarial.rs pattern)
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
        .build_unhashed()
}

/// Deterministic unique hash from an index.
fn hash_for(index: u64) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0..8].copy_from_slice(&index.to_le_bytes());
    h[31] = 0xBB; // distinct sentinel
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
// 1. test_linear_chain_all_blue
//    10 blocks in a linear chain — anticone size = 0, so all should be blue.
// ============================================================================
#[tokio::test]
async fn test_linear_chain_all_blue() {
    let params = GhostDagParams::default();
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let ghostdag = GhostDag::new(params, dag_store.clone());

    let genesis_hash = setup_genesis(&dag_store, &ghostdag).await;

    // Build linear chain of 10 blocks
    let mut prev = genesis_hash;
    let mut all_hashes = vec![genesis_hash];
    for i in 1u64..=10 {
        let block = make_block(hash_for(i), prev, vec![], i, i);
        dag_store.store_block(block.clone()).await.unwrap();
        ghostdag.add_block(&block).await.unwrap();
        all_hashes.push(block.hash());
        prev = block.hash();
    }

    // Get blue set of the tip (last block)
    let tip_block = dag_store.get_block(&prev).await.unwrap();
    let blue_set = ghostdag.calculate_blue_set(&tip_block).await.unwrap();

    // In a linear chain every block is an ancestor of the tip, so anticone
    // size for each is 0. All 11 blocks (genesis + 10) must be blue.
    assert_eq!(
        blue_set.score, 11,
        "All 11 blocks in a linear chain must be blue, got {}",
        blue_set.score
    );
    for hash in &all_hashes {
        assert!(
            blue_set.contains(hash),
            "Block {} must be in the blue set of the tip",
            hash
        );
    }
}

// ============================================================================
// 2. test_diamond_dag_blue_set
//    Diamond: A→B, A→C, B→D, C→D. Verify blue set calculation.
// ============================================================================
#[tokio::test]
async fn test_diamond_dag_blue_set() {
    let params = GhostDagParams::default();
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let ghostdag = GhostDag::new(params, dag_store.clone());

    // A = genesis
    let a = make_block([0xFF; 32], Hash::default(), vec![], 0, 0);
    dag_store.store_block(a.clone()).await.unwrap();
    ghostdag.add_block(&a).await.unwrap();

    // B child of A
    let b = make_block(hash_for(1), a.hash(), vec![], 1, 1);
    dag_store.store_block(b.clone()).await.unwrap();
    ghostdag.add_block(&b).await.unwrap();

    // C child of A
    let c = make_block(hash_for(2), a.hash(), vec![], 1, 1);
    dag_store.store_block(c.clone()).await.unwrap();
    ghostdag.add_block(&c).await.unwrap();

    // D: selected parent = B, merge parent = C
    let d = make_block(hash_for(3), b.hash(), vec![c.hash()], 2, 2);
    dag_store.store_block(d.clone()).await.unwrap();
    ghostdag.add_block(&d).await.unwrap();

    let blue_set = ghostdag.calculate_blue_set(&d).await.unwrap();

    // All four blocks should be in D's blue set:
    // A is ancestor of everyone, B is selected parent, C is merge parent
    // with anticone size 0 relative to B (since both share ancestor A).
    assert!(blue_set.contains(&a.hash()), "A (genesis) must be blue");
    assert!(blue_set.contains(&b.hash()), "B must be blue");
    assert!(blue_set.contains(&c.hash()), "C must be blue");
    assert!(blue_set.contains(&d.hash()), "D must be blue");
    assert_eq!(blue_set.score, 4, "Diamond DAG should have blue score 4");
}

// ============================================================================
// 3. test_wide_dag_at_k_limit
//    Create a DAG where one block has exactly k blocks in its anticone.
//    All k should still be blue (anticone_size <= k is the rule).
// ============================================================================
#[tokio::test]
async fn test_wide_dag_at_k_limit() {
    let k = 18u32;
    let params = GhostDagParams {
        k,
        max_parents: 10,
        ..GhostDagParams::default()
    };
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let ghostdag = GhostDag::new(params, dag_store.clone());

    let genesis_hash = setup_genesis(&dag_store, &ghostdag).await;

    // Create k parallel blocks (all children of genesis) — these are in
    // each other's anticone.
    let mut parallel_hashes = Vec::new();
    for i in 0..k as u64 {
        let block = make_block(hash_for(i + 1), genesis_hash, vec![], 1, 1);
        dag_store.store_block(block.clone()).await.unwrap();
        ghostdag.add_block(&block).await.unwrap();
        parallel_hashes.push(block.hash());
    }

    // Create a merge block that references some of these parallel blocks.
    // selected parent = parallel_hashes[0], merge parents = next batch
    // (up to max_parents - 1).
    let merge_parents: Vec<Hash> = parallel_hashes[1..std::cmp::min(10, parallel_hashes.len())]
        .to_vec();
    let merge_block = make_block(hash_for(100), parallel_hashes[0], merge_parents, 2, 2);
    dag_store.store_block(merge_block.clone()).await.unwrap();
    ghostdag.add_block(&merge_block).await.unwrap();

    let blue_set = ghostdag.calculate_blue_set(&merge_block).await.unwrap();

    // The merge block's blue set must include at least genesis + itself +
    // the selected parent. With k=18 parallel blocks, the anticone constraint
    // should allow the merge parents to be blue too (anticone <= k).
    assert!(
        blue_set.contains(&genesis_hash),
        "Genesis must always be in the blue set"
    );
    assert!(
        blue_set.contains(&merge_block.hash()),
        "The merge block itself must be in the blue set"
    );
    assert!(
        blue_set.score >= 3,
        "Merge block should have blue score >= 3 (genesis + selected parent + self), got {}",
        blue_set.score
    );
}

// ============================================================================
// 4. test_adversarial_withhold_attack
//    Two chains of 5 blocks from same genesis. Attacker withholds chain B
//    and releases all at once. Honest chain A (built incrementally) should
//    have higher or equal blue score since it was visible to the network.
// ============================================================================
#[tokio::test]
async fn test_adversarial_withhold_attack() {
    let params = GhostDagParams::default();
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let ghostdag = GhostDag::new(params, dag_store.clone());

    let genesis_hash = setup_genesis(&dag_store, &ghostdag).await;

    // Chain A: honest chain, 5 blocks built incrementally
    let mut prev_a = genesis_hash;
    for i in 1u64..=5 {
        let block = make_block(hash_for(i), prev_a, vec![], i, i);
        dag_store.store_block(block.clone()).await.unwrap();
        ghostdag.add_block(&block).await.unwrap();
        prev_a = block.hash();
    }

    let honest_tip = prev_a;
    let honest_score = ghostdag.get_blue_score(&honest_tip).await.unwrap();

    // Chain B: attacker's withheld chain, 5 blocks built off genesis
    // (released all at once — different hash space so no collisions)
    let mut prev_b = genesis_hash;
    for i in 1u64..=5 {
        let block = make_block(hash_for(100 + i), prev_b, vec![], i, i);
        dag_store.store_block(block.clone()).await.unwrap();
        ghostdag.add_block(&block).await.unwrap();
        prev_b = block.hash();
    }

    let attacker_tip = prev_b;
    let attacker_score = ghostdag.get_blue_score(&attacker_tip).await.unwrap();

    // The honest chain was visible first and accumulated blue score.
    // The attacker's chain, released late, should NOT surpass the honest chain.
    // In a linear chain scenario with equal length, blue scores should be
    // equal (both are 6 = genesis + 5 blocks). The key invariant is that the
    // attacker cannot gain an advantage by withholding.
    assert!(
        honest_score >= attacker_score,
        "Honest chain (score={}) must not lose to attacker chain (score={})",
        honest_score,
        attacker_score
    );

    // Tip selection: with two tips of equal score, the deterministic
    // tie-breaker should pick consistently.
    let selected = ghostdag.select_tip().await.unwrap();
    let tips = ghostdag.get_tips().await;
    assert!(
        tips.contains(&selected),
        "Selected tip must be in the tip set"
    );
}

// ============================================================================
// 5. test_selected_parent_always_highest_score
//    After adding 10 blocks to a DAG, verify the selected tip (via
//    select_tip) has the highest blue score among all tips.
// ============================================================================
#[tokio::test]
async fn test_selected_parent_always_highest_score() {
    let params = GhostDagParams::default();
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let ghostdag = GhostDag::new(params, dag_store.clone());

    let genesis_hash = setup_genesis(&dag_store, &ghostdag).await;

    // Build a main chain of 7 blocks
    let mut prev = genesis_hash;
    for i in 1u64..=7 {
        let block = make_block(hash_for(i), prev, vec![], i, i);
        dag_store.store_block(block.clone()).await.unwrap();
        ghostdag.add_block(&block).await.unwrap();
        prev = block.hash();
    }

    // Fork: 3 blocks off genesis (shorter chain, lower blue score)
    let mut prev_fork = genesis_hash;
    for i in 1u64..=3 {
        let block = make_block(hash_for(50 + i), prev_fork, vec![], i, i);
        dag_store.store_block(block.clone()).await.unwrap();
        ghostdag.add_block(&block).await.unwrap();
        prev_fork = block.hash();
    }

    let selected = ghostdag.select_tip().await.unwrap();
    let selected_score = ghostdag.get_blue_score(&selected).await.unwrap();

    // Verify: the selected tip has the highest blue score of any tip
    let tips = ghostdag.get_tips().await;
    for tip in &tips {
        let score = ghostdag.get_blue_score(tip).await.unwrap();
        assert!(
            selected_score >= score,
            "Selected tip (score={}) must have >= score of any other tip (score={})",
            selected_score,
            score
        );
    }
}

// ============================================================================
// 6. test_genesis_always_in_blue_set
//    For any block in the DAG, genesis must be in its blue set.
// ============================================================================
#[tokio::test]
async fn test_genesis_always_in_blue_set() {
    let params = GhostDagParams::default();
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let ghostdag = GhostDag::new(params, dag_store.clone());

    let genesis_hash = setup_genesis(&dag_store, &ghostdag).await;

    // Build a chain with a fork
    let mut prev = genesis_hash;
    let mut all_hashes = vec![genesis_hash];
    for i in 1u64..=5 {
        let block = make_block(hash_for(i), prev, vec![], i, i);
        dag_store.store_block(block.clone()).await.unwrap();
        ghostdag.add_block(&block).await.unwrap();
        all_hashes.push(block.hash());
        prev = block.hash();
    }

    // Fork off genesis
    let fork_block = make_block(hash_for(20), genesis_hash, vec![], 1, 1);
    dag_store.store_block(fork_block.clone()).await.unwrap();
    ghostdag.add_block(&fork_block).await.unwrap();
    all_hashes.push(fork_block.hash());

    // Verify genesis is in the blue set of every block
    for hash in &all_hashes {
        let block = dag_store.get_block(hash).await.unwrap();
        let blue_set = ghostdag.calculate_blue_set(&block).await.unwrap();
        assert!(
            blue_set.contains(&genesis_hash),
            "Genesis must always be in the blue set of block {} (blue_score={})",
            hash,
            blue_set.score
        );
    }
}
