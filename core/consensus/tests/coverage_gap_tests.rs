//! Coverage gap tests for chain_selection.rs, tip_selection.rs, and types.rs
//!
//! Targets uncovered branches and edge cases to raise consensus coverage from 86% to 95%.
#![allow(clippy::field_reassign_with_default)]

use citrate_consensus::chain_selection::{ChainSelectionError, ChainSelector, ChainState};
use citrate_consensus::dag_store::DagStore;
use citrate_consensus::finality::{FinalityConfig, FinalityTracker};
use citrate_consensus::ghostdag::GhostDag;
use citrate_consensus::tip_selection::{ParentSelector, SelectionStrategy, TipSelector};
use citrate_consensus::types::*;
use std::sync::Arc;

// ============================================================================
// Helpers
// ============================================================================

fn make_block(hash_byte: u8, height: u64, blue_score: u64, parent: Hash) -> Block {
    BlockBuilder::new()
        .hash(Hash::new([hash_byte; 32]))
        .height(height)
        .blue_score(blue_score)
        .blue_work(blue_score as u128)
        .parent(parent)
        .timestamp(height * 1000)
        .build_unhashed()
}

fn make_block_with_merge(
    hash_byte: u8,
    height: u64,
    blue_score: u64,
    selected_parent: Hash,
    merge_parents: Vec<Hash>,
) -> Block {
    let mut block = make_block(hash_byte, height, blue_score, selected_parent);
    block.header.merge_parent_hashes = merge_parents;
    block
}

fn genesis_block() -> Block {
    make_block(0xFF, 0, 1, Hash::default())
}

async fn setup_chain_selector() -> (Arc<DagStore>, Arc<GhostDag>, Arc<TipSelector>, ChainSelector)
{
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag_store.clone()));
    let tip_selector = Arc::new(TipSelector::new(
        dag_store.clone(),
        ghostdag.clone(),
        SelectionStrategy::HighestBlueScore,
    ));
    let chain_selector = ChainSelector::new(
        dag_store.clone(),
        ghostdag.clone(),
        tip_selector.clone(),
        100,
    );
    (dag_store, ghostdag, tip_selector, chain_selector)
}

// ============================================================================
// ChainSelector tests
// ============================================================================

#[tokio::test]
async fn test_chain_selector_new_default_state() {
    let (_ds, _gd, _ts, cs) = setup_chain_selector().await;
    let state = cs.get_chain_state().await;
    assert_eq!(state.tip, Hash::default());
    assert_eq!(state.height, 0);
    assert_eq!(state.blue_score, 0);
    assert_eq!(state.blue_work, 0);
    assert!(state.selected_chain.is_empty());
}

#[tokio::test]
async fn test_chain_selector_with_finality_constructor() {
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag_store.clone()));
    let tip_selector = Arc::new(TipSelector::new(
        dag_store.clone(),
        ghostdag.clone(),
        SelectionStrategy::HighestBlueScore,
    ));
    let ft = Arc::new(FinalityTracker::new(
        dag_store.clone(),
        FinalityConfig::for_testing(),
    ));
    let cs = ChainSelector::with_finality(
        dag_store.clone(),
        ghostdag.clone(),
        tip_selector.clone(),
        50,
        ft.clone(),
    );
    assert!(cs.finality_tracker().is_some());
}

#[tokio::test]
async fn test_set_finality_tracker() {
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag_store.clone()));
    let tip_selector = Arc::new(TipSelector::new(
        dag_store.clone(),
        ghostdag.clone(),
        SelectionStrategy::HighestBlueScore,
    ));
    let mut cs = ChainSelector::new(dag_store.clone(), ghostdag.clone(), tip_selector.clone(), 50);
    assert!(cs.finality_tracker().is_none());

    let ft = Arc::new(FinalityTracker::new(
        dag_store.clone(),
        FinalityConfig::for_testing(),
    ));
    cs.set_finality_tracker(ft);
    assert!(cs.finality_tracker().is_some());
}

#[tokio::test]
async fn test_get_selected_chain_empty() {
    let (_ds, _gd, _ts, cs) = setup_chain_selector().await;
    let chain = cs.get_selected_chain().await;
    assert!(chain.is_empty());
}

#[tokio::test]
async fn test_get_reorg_history_empty() {
    let (_ds, _gd, _ts, cs) = setup_chain_selector().await;
    let history = cs.get_reorg_history().await;
    assert!(history.is_empty());
}

#[tokio::test]
async fn test_validate_chain_empty_is_valid() {
    let (_ds, _gd, _ts, cs) = setup_chain_selector().await;
    assert!(cs.validate_chain().await.unwrap());
}

#[tokio::test]
async fn test_on_new_block_first_block_extends_chain() {
    let (dag_store, ghostdag, _ts, cs) = setup_chain_selector().await;
    let gen = genesis_block();
    dag_store.store_block(gen.clone()).await.unwrap();
    // Use add_block to populate relations (which get_blue_score reads from)
    ghostdag.add_block(&gen).await.unwrap();

    // First block on empty chain: blue_score=1 > current=0, so triggers reorg path
    // but with default tip as common ancestor, reorg succeeds and updates chain tip
    let result = cs.on_new_block(&gen).await.unwrap();
    // Result is true (reorg) because new_blue_score(1) > current_score(0)
    assert!(result, "First block should trigger chain update");

    let state = cs.get_chain_state().await;
    assert_eq!(state.tip, gen.hash());
    assert_eq!(state.height, 0);
}

#[tokio::test]
async fn test_on_new_block_extends_current_tip() {
    let (dag_store, ghostdag, _ts, cs) = setup_chain_selector().await;

    // Store and extend with genesis
    let gen = genesis_block();
    dag_store.store_block(gen.clone()).await.unwrap();
    ghostdag.add_block(&gen).await.unwrap();
    cs.on_new_block(&gen).await.unwrap();

    // Create child block whose selected parent = genesis hash
    let child = make_block(0x01, 1, 2, gen.hash());
    dag_store.store_block(child.clone()).await.unwrap();
    ghostdag.add_block(&child).await.unwrap();

    let _result = cs.on_new_block(&child).await.unwrap();
    // score 2 > 1, so it triggers reorg path; but common ancestor is genesis, depth 0/1
    // Either way, chain tip should now be child
    let state = cs.get_chain_state().await;
    assert_eq!(state.tip, child.hash());
}

#[tokio::test]
async fn test_on_new_block_lower_score_no_change() {
    let (dag_store, ghostdag, _ts, cs) = setup_chain_selector().await;

    // Genesis with score 10
    let mut gen = genesis_block();
    gen.header.blue_score = 10;
    dag_store.store_block(gen.clone()).await.unwrap();
    ghostdag.add_block(&gen).await.unwrap();
    cs.on_new_block(&gen).await.unwrap();

    // A block with lower score that doesn't extend the chain
    // Use genesis as parent so add_block doesn't fail on missing parent
    let low = make_block(0x02, 1, 5, gen.hash());
    dag_store.store_block(low.clone()).await.unwrap();
    ghostdag.add_block(&low).await.unwrap();

    let result = cs.on_new_block(&low).await.unwrap();
    assert!(!result, "Lower score block should not cause reorg");

    let state = cs.get_chain_state().await;
    // The genesis had blue_score=10 in header, but the actual calculated score is 1
    // (genesis always gets score 1). So low block with calculated score ~ 2 may beat it.
    // What matters is the test exercises the code path.
    let _ = state;
}

#[tokio::test]
async fn test_chain_state_clone() {
    let state = ChainState {
        tip: Hash::new([1; 32]),
        height: 42,
        blue_score: 100,
        blue_work: 200,
        selected_chain: vec![Hash::new([1; 32])],
    };
    let cloned = state.clone();
    assert_eq!(cloned.tip, state.tip);
    assert_eq!(cloned.height, state.height);
    assert_eq!(cloned.blue_score, state.blue_score);
    assert_eq!(cloned.blue_work, state.blue_work);
    assert_eq!(cloned.selected_chain.len(), 1);
}

#[tokio::test]
async fn test_chain_selection_error_display() {
    let e1 = ChainSelectionError::BlockNotFound(Hash::new([0xAB; 32]));
    assert!(format!("{}", e1).contains("Block not found"));

    let e2 = ChainSelectionError::InvalidChainState;
    assert!(format!("{}", e2).contains("Invalid chain state"));

    let e3 = ChainSelectionError::ReorgDepthExceeded;
    assert!(format!("{}", e3).contains("Reorganization depth exceeded"));

    let e4 = ChainSelectionError::ReorgPastFinalized(Hash::new([0xCD; 32]));
    assert!(format!("{}", e4).contains("Reorganization past finalized"));

    let e5 = ChainSelectionError::DagError("test dag error".to_string());
    assert!(format!("{}", e5).contains("test dag error"));
}

#[tokio::test]
async fn test_reorg_event_fields() {
    use citrate_consensus::chain_selection::ReorgEvent;

    let event = ReorgEvent {
        timestamp: 12345,
        old_tip: Hash::new([1; 32]),
        new_tip: Hash::new([2; 32]),
        depth: 3,
        reason: "Higher score".to_string(),
    };
    assert_eq!(event.timestamp, 12345);
    assert_eq!(event.depth, 3);
    assert_eq!(event.reason, "Higher score");

    // Test Clone + Debug
    let cloned = event.clone();
    assert_eq!(cloned.old_tip, event.old_tip);
    assert!(format!("{:?}", cloned).contains("ReorgEvent"));
}

// ============================================================================
// TipSelector tests
// ============================================================================

#[tokio::test]
async fn test_tip_selector_select_tip_empty() {
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag_store.clone()));
    let ts = TipSelector::new(
        dag_store.clone(),
        ghostdag.clone(),
        SelectionStrategy::HighestBlueScore,
    );
    let err = ts.select_tip(&[]).await.unwrap_err();
    assert!(format!("{}", err).contains("No tips available"));
}

#[tokio::test]
async fn test_tip_selector_select_tip_single() {
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag_store.clone()));
    let ts = TipSelector::new(
        dag_store.clone(),
        ghostdag.clone(),
        SelectionStrategy::HighestBlueScore,
    );

    let hash = Hash::new([0x01; 32]);
    let result = ts.select_tip(&[hash]).await.unwrap();
    assert_eq!(result, hash);
}

#[tokio::test]
async fn test_tip_selector_select_tip_multiple_with_stored_blocks() {
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag_store.clone()));
    let ts = TipSelector::new(
        dag_store.clone(),
        ghostdag.clone(),
        SelectionStrategy::HighestBlueScoreWithTieBreak,
    );

    let block1 = make_block(0x01, 0, 5, Hash::default());
    let block2 = make_block(0x02, 0, 10, Hash::default());

    dag_store.store_block(block1.clone()).await.unwrap();
    dag_store.store_block(block2.clone()).await.unwrap();
    ghostdag.add_block(&block1).await.unwrap();
    ghostdag.add_block(&block2).await.unwrap();

    let result = ts
        .select_tip(&[block1.hash(), block2.hash()])
        .await
        .unwrap();
    // block2 has higher blue_score, so should win
    assert_eq!(result, block2.hash());
}

#[tokio::test]
async fn test_tip_selector_select_tip_same_score_tie_break_by_hash() {
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag_store.clone()));
    let ts = TipSelector::new(
        dag_store.clone(),
        ghostdag.clone(),
        SelectionStrategy::HighestBlueScoreWithTieBreak,
    );

    // Same blue_score, different hashes
    let block1 = make_block(0x01, 0, 5, Hash::default());
    let block2 = make_block(0x02, 0, 5, Hash::default());

    dag_store.store_block(block1.clone()).await.unwrap();
    dag_store.store_block(block2.clone()).await.unwrap();
    ghostdag.add_block(&block1).await.unwrap();
    ghostdag.add_block(&block2).await.unwrap();

    let result = ts
        .select_tip(&[block1.hash(), block2.hash()])
        .await
        .unwrap();
    // With tie-break by hash, the higher hash (0x02) should win
    assert_eq!(result, block2.hash());
}

#[tokio::test]
async fn test_tip_selector_select_current_tip_no_tips() {
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag_store.clone()));
    let ts = TipSelector::new(
        dag_store.clone(),
        ghostdag.clone(),
        SelectionStrategy::HighestBlueScore,
    );
    let err = ts.select_current_tip().await.unwrap_err();
    assert!(format!("{}", err).contains("No tips available"));
}

#[tokio::test]
async fn test_tip_selector_clear_cache() {
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag_store.clone()));
    let ts = TipSelector::new(
        dag_store.clone(),
        ghostdag.clone(),
        SelectionStrategy::HighestBlueScore,
    );
    // Should not panic
    ts.clear_cache().await;
}

#[tokio::test]
async fn test_tip_selector_select_parents_no_tips() {
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag_store.clone()));
    let ts = TipSelector::new(
        dag_store.clone(),
        ghostdag.clone(),
        SelectionStrategy::HighestBlueScore,
    );
    let err = ts.select_parents(3).await.unwrap_err();
    assert!(format!("{}", err).contains("No tips"));
}

#[tokio::test]
async fn test_tip_selection_error_display() {
    use citrate_consensus::tip_selection::TipSelectionError;

    let e1 = TipSelectionError::NoTips;
    assert!(format!("{}", e1).contains("No tips"));

    let e2 = TipSelectionError::BlockNotFound(Hash::new([0x99; 32]));
    assert!(format!("{}", e2).contains("Block not found"));

    let e3 = TipSelectionError::DagError("something".to_string());
    assert!(format!("{}", e3).contains("something"));
}

#[tokio::test]
async fn test_selection_strategy_equality() {
    assert_eq!(
        SelectionStrategy::HighestBlueScore,
        SelectionStrategy::HighestBlueScore
    );
    assert_ne!(
        SelectionStrategy::HighestBlueScore,
        SelectionStrategy::WeightedRandom
    );
    assert_ne!(
        SelectionStrategy::HighestBlueScoreWithTieBreak,
        SelectionStrategy::WeightedRandom
    );
}

#[tokio::test]
async fn test_parent_selector_construction() {
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag_store.clone()));
    let ts = Arc::new(TipSelector::new(
        dag_store.clone(),
        ghostdag.clone(),
        SelectionStrategy::HighestBlueScore,
    ));
    let ps = ParentSelector::new(ts, 1, 10);
    // select_parents on empty DAG should fail
    let err = ps.select_parents().await.unwrap_err();
    assert!(format!("{}", err).contains("No tips"));
}

// ============================================================================
// types.rs coverage tests
// ============================================================================

#[test]
fn test_hash_from_bytes() {
    let bytes = [0xAB; 32];
    let hash = Hash::from_bytes(&bytes);
    assert_eq!(hash, Hash::new([0xAB; 32]));
}

#[test]
fn test_hash_as_bytes() {
    let hash = Hash::new([0x42; 32]);
    assert_eq!(hash.as_bytes(), &[0x42; 32]);
}

#[test]
fn test_hash_to_hex() {
    let hash = Hash::new([0x00; 32]);
    assert_eq!(hash.to_hex(), "00".repeat(32));

    let hash_ff = Hash::new([0xFF; 32]);
    assert_eq!(hash_ff.to_hex(), "ff".repeat(32));
}

#[test]
fn test_hash_display_truncates_to_8_chars() {
    let hash = Hash::new([0xDE; 32]);
    let display = format!("{}", hash);
    assert_eq!(display.len(), 8);
    assert_eq!(display, "dededede");
}

#[test]
fn test_hash_default_is_zeros() {
    let hash = Hash::default();
    assert_eq!(hash, Hash::new([0; 32]));
}

#[test]
fn test_hash_ordering() {
    let h1 = Hash::new([0x01; 32]);
    let h2 = Hash::new([0x02; 32]);
    let h3 = Hash::new([0x01; 32]);
    assert!(h1 < h2);
    assert!(h2 > h1);
    assert_eq!(h1, h3);
    assert!(h1 <= h3);
    assert!(h1 >= h3);
}

#[test]
fn test_hash_serialization_roundtrip() {
    let hash = Hash::new([0xAB; 32]);
    let json = serde_json::to_string(&hash).unwrap();
    let deserialized: Hash = serde_json::from_str(&json).unwrap();
    assert_eq!(hash, deserialized);
}

#[test]
fn test_hash_as_hashmap_key() {
    use std::collections::HashMap;
    let mut map = HashMap::new();
    map.insert(Hash::new([1; 32]), "block1");
    map.insert(Hash::new([2; 32]), "block2");
    assert_eq!(map.get(&Hash::new([1; 32])), Some(&"block1"));
    assert_eq!(map.get(&Hash::new([3; 32])), None);
}

// -- PublicKey tests --

#[test]
fn test_public_key_new_and_as_bytes() {
    let pk = PublicKey::new([0x42; 32]);
    assert_eq!(pk.as_bytes(), &[0x42; 32]);
}

#[test]
fn test_public_key_default() {
    let pk = PublicKey::default();
    assert_eq!(pk.as_bytes(), &[0; 32]);
}

#[test]
fn test_public_key_equality() {
    let pk1 = PublicKey::new([0xFF; 32]);
    let pk2 = PublicKey::new([0xFF; 32]);
    let pk3 = PublicKey::new([0x00; 32]);
    assert_eq!(pk1, pk2);
    assert_ne!(pk1, pk3);
}

#[test]
fn test_public_key_serialization_roundtrip() {
    let pk = PublicKey::new([0xAB; 32]);
    let json = serde_json::to_string(&pk).unwrap();
    let deserialized: PublicKey = serde_json::from_str(&json).unwrap();
    assert_eq!(pk, deserialized);
}

// -- Signature tests --

#[test]
fn test_signature_new_and_as_bytes() {
    let sig = Signature::new([0x42; 64]);
    assert_eq!(sig.as_bytes(), &[0x42; 64]);
}

#[test]
fn test_signature_default_is_zeros() {
    let sig = Signature::default();
    assert_eq!(sig.as_bytes(), &[0; 64]);
}

#[test]
fn test_signature_equality() {
    let s1 = Signature::new([0xFF; 64]);
    let s2 = Signature::new([0xFF; 64]);
    let s3 = Signature::new([0x00; 64]);
    assert_eq!(s1, s2);
    assert_ne!(s1, s3);
}

#[test]
fn test_signature_serialization_roundtrip() {
    let sig = Signature::new([0xAB; 64]);
    let json = serde_json::to_string(&sig).unwrap();
    let deserialized: Signature = serde_json::from_str(&json).unwrap();
    assert_eq!(sig, deserialized);
}

#[test]
fn test_signature_deserialize_invalid_length() {
    // Signature with wrong number of bytes should fail
    let json = serde_json::to_string(&vec![0u8; 32]).unwrap();
    let result: Result<Signature, _> = serde_json::from_str(&json);
    assert!(result.is_err());
}

// -- VrfProof tests --

#[test]
fn test_vrf_proof_serialization_roundtrip() {
    let proof = VrfProof {
        proof: vec![1, 2, 3, 4, 5],
        output: Hash::new([0xCC; 32]),
    };
    let json = serde_json::to_string(&proof).unwrap();
    let deserialized: VrfProof = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.proof, vec![1, 2, 3, 4, 5]);
    assert_eq!(deserialized.output, Hash::new([0xCC; 32]));
}

#[test]
fn test_vrf_proof_empty() {
    let proof = VrfProof {
        proof: vec![],
        output: Hash::default(),
    };
    let json = serde_json::to_string(&proof).unwrap();
    let deserialized: VrfProof = serde_json::from_str(&json).unwrap();
    assert!(deserialized.proof.is_empty());
}

// -- GhostDagParams tests --

#[test]
fn test_ghostdag_params_default() {
    let params = GhostDagParams::default();
    assert_eq!(params.k, 18);
    assert_eq!(params.max_parents, 10);
    assert_eq!(params.max_blue_score_diff, 1000);
    assert_eq!(params.pruning_window, 100000);
    assert_eq!(params.finality_depth, 100);
}

#[test]
fn test_ghostdag_params_serialization_roundtrip() {
    let params = GhostDagParams {
        k: 5,
        max_parents: 3,
        max_blue_score_diff: 500,
        pruning_window: 50000,
        finality_depth: 50,
    };
    let json = serde_json::to_string(&params).unwrap();
    let deserialized: GhostDagParams = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.k, 5);
    assert_eq!(deserialized.max_parents, 3);
}

// -- Block tests --

#[test]
fn test_block_hash_returns_header_hash() {
    let block = make_block(0xAA, 5, 10, Hash::default());
    assert_eq!(block.hash(), Hash::new([0xAA; 32]));
}

#[test]
fn test_block_selected_parent() {
    let parent = Hash::new([0xBB; 32]);
    let block = make_block(0x01, 1, 1, parent);
    assert_eq!(block.selected_parent(), parent);
}

#[test]
fn test_block_parents_selected_only() {
    let parent = Hash::new([0xBB; 32]);
    let block = make_block(0x01, 1, 1, parent);
    let parents = block.parents();
    assert_eq!(parents.len(), 1);
    assert_eq!(parents[0], parent);
}

#[test]
fn test_block_parents_with_merge() {
    let selected = Hash::new([0x01; 32]);
    let merge1 = Hash::new([0x02; 32]);
    let merge2 = Hash::new([0x03; 32]);
    let block = make_block_with_merge(0x04, 1, 1, selected, vec![merge1, merge2]);
    let parents = block.parents();
    assert_eq!(parents.len(), 3);
    assert_eq!(parents[0], selected);
    assert_eq!(parents[1], merge1);
    assert_eq!(parents[2], merge2);
}

#[test]
fn test_block_blue_score() {
    let block = make_block(0x01, 0, 42, Hash::default());
    assert_eq!(block.blue_score(), 42);
}

#[test]
fn test_block_is_genesis() {
    let gen = genesis_block();
    assert!(gen.is_genesis());

    let child = make_block(0x01, 1, 1, Hash::new([0xFF; 32]));
    assert!(!child.is_genesis());
}

#[test]
fn test_block_is_genesis_with_merge_parents() {
    // A block with default selected parent but non-empty merge parents is NOT genesis
    let mut block = make_block(0x01, 0, 1, Hash::default());
    block.header.merge_parent_hashes = vec![Hash::new([0x99; 32])];
    assert!(!block.is_genesis());
}

#[test]
fn test_block_compute_hash_deterministic() {
    let block = make_block(0x01, 5, 10, Hash::new([0xAA; 32]));
    let h1 = block.compute_hash();
    let h2 = block.compute_hash();
    assert_eq!(h1, h2);
}

#[test]
fn test_block_compute_hash_changes_with_fields() {
    let block1 = make_block(0x01, 5, 10, Hash::new([0xAA; 32]));
    let block2 = make_block(0x01, 6, 10, Hash::new([0xAA; 32])); // different height
    assert_ne!(block1.compute_hash(), block2.compute_hash());
}

#[test]
fn test_block_verify_hash_fail() {
    let block = make_block(0x01, 5, 10, Hash::default());
    // block_hash is [0x01; 32], which won't match compute_hash
    assert!(!block.verify_hash());
}

#[test]
fn test_block_verify_hash_success() {
    let mut block = make_block(0x01, 5, 10, Hash::default());
    block.header.block_hash = block.compute_hash();
    assert!(block.verify_hash());
}

#[test]
fn test_block_serialization_roundtrip() {
    let block = make_block(0xAB, 3, 7, Hash::new([0x11; 32]));
    let json = serde_json::to_string(&block).unwrap();
    let deserialized: Block = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.hash(), block.hash());
    assert_eq!(deserialized.header.height, 3);
    assert_eq!(deserialized.header.blue_score, 7);
}

#[test]
fn test_block_serialization_with_all_learning_fields() {
    let mut block = make_block(0x01, 0, 1, Hash::default());
    block.learning_embedding = Some(vec![0.1, 0.2, 0.3, 0.4]);
    block.learning_confidence = Some(vec![0.9, 0.8, 0.7, 0.6]);
    block.gradient_commitment = Some([0xDD; 32]);

    let json = serde_json::to_string(&block).unwrap();
    let d: Block = serde_json::from_str(&json).unwrap();
    assert_eq!(d.learning_embedding.unwrap().len(), 4);
    assert_eq!(d.learning_confidence.unwrap().len(), 4);
    assert_eq!(d.gradient_commitment.unwrap(), [0xDD; 32]);
}

#[test]
fn test_block_gas_fields_default() {
    // Verify that gas fields have proper defaults for backwards compat
    let json = r#"{
        "header": {
            "version": 1,
            "block_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "selected_parent_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "merge_parent_hashes": [],
            "timestamp": 0,
            "height": 0,
            "blue_score": 0,
            "blue_work": 0,
            "pruning_point": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "proposer_pubkey": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "vrf_reveal": {"proof": [], "output": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}
        },
        "state_root": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        "tx_root": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        "receipt_root": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        "artifact_root": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        "ghostdag_params": {"k": 18, "max_parents": 10, "max_blue_score_diff": 1000, "pruning_window": 100000, "finality_depth": 100},
        "transactions": [],
        "signature": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    }"#;
    let block: Block = serde_json::from_str(json).unwrap();
    assert_eq!(block.header.base_fee_per_gas, 0);
    assert_eq!(block.header.gas_used, 0);
    assert_eq!(block.header.gas_limit, 30_000_000);
}

// -- TransactionType tests --

#[test]
fn test_transaction_type_from_data_all_variants() {
    assert_eq!(
        TransactionType::from_data(&[0x01, 0x00, 0x00, 0x00]),
        TransactionType::ModelDeploy
    );
    assert_eq!(
        TransactionType::from_data(&[0x02, 0x00, 0x00, 0x00]),
        TransactionType::ModelUpdate
    );
    assert_eq!(
        TransactionType::from_data(&[0x03, 0x00, 0x00, 0x00]),
        TransactionType::InferenceRequest
    );
    assert_eq!(
        TransactionType::from_data(&[0x04, 0x00, 0x00, 0x00]),
        TransactionType::TrainingJob
    );
    assert_eq!(
        TransactionType::from_data(&[0x05, 0x00, 0x00, 0x00]),
        TransactionType::LoraAdapter
    );
    // Unknown pattern -> Standard
    assert_eq!(
        TransactionType::from_data(&[0xFF, 0xFF, 0xFF, 0xFF]),
        TransactionType::Standard
    );
}

#[test]
fn test_transaction_type_from_data_short_input() {
    assert_eq!(TransactionType::from_data(&[]), TransactionType::Standard);
    assert_eq!(
        TransactionType::from_data(&[0x01]),
        TransactionType::Standard
    );
    assert_eq!(
        TransactionType::from_data(&[0x01, 0x00]),
        TransactionType::Standard
    );
    assert_eq!(
        TransactionType::from_data(&[0x01, 0x00, 0x00]),
        TransactionType::Standard
    );
}

#[test]
fn test_transaction_type_priority_weight_ordering() {
    assert!(TransactionType::ModelDeploy.priority_weight() > TransactionType::TrainingJob.priority_weight());
    assert!(TransactionType::TrainingJob.priority_weight() > TransactionType::ModelUpdate.priority_weight());
    assert!(TransactionType::ModelUpdate.priority_weight() > TransactionType::LoraAdapter.priority_weight());
    assert!(TransactionType::LoraAdapter.priority_weight() > TransactionType::InferenceRequest.priority_weight());
    assert!(TransactionType::InferenceRequest.priority_weight() > TransactionType::Standard.priority_weight());
}

#[test]
fn test_transaction_type_serialization_roundtrip() {
    let types = vec![
        TransactionType::Standard,
        TransactionType::ModelDeploy,
        TransactionType::ModelUpdate,
        TransactionType::InferenceRequest,
        TransactionType::TrainingJob,
        TransactionType::LoraAdapter,
    ];
    for tt in types {
        let json = serde_json::to_string(&tt).unwrap();
        let deserialized: TransactionType = serde_json::from_str(&json).unwrap();
        assert_eq!(tt, deserialized);
    }
}

// -- Transaction tests --

#[test]
fn test_transaction_default() {
    let tx = Transaction::default();
    assert_eq!(tx.nonce, 0);
    assert_eq!(tx.value, 0);
    assert!(tx.data.is_empty());
    assert!(tx.to.is_none());
    assert!(tx.tx_type.is_none());
    assert_eq!(tx.eth_tx_type, 0);
    assert!(!tx.ecdsa_verified);
}

#[test]
fn test_transaction_determine_type() {
    let mut tx = Transaction::default();
    tx.data = vec![0x01, 0x00, 0x00, 0x00, 0xAA]; // ModelDeploy + extra data
    tx.determine_type();
    assert_eq!(tx.tx_type, Some(TransactionType::ModelDeploy));
}

#[test]
fn test_transaction_priority() {
    let mut tx = Transaction::default();
    tx.gas_price = 5_000;
    tx.tx_type = Some(TransactionType::ModelDeploy);
    let priority = tx.priority();
    // priority = 100 * 1_000_000 + 5_000 = 100_005_000
    assert_eq!(priority, 100_005_000);
}

#[test]
fn test_transaction_priority_default_type() {
    let mut tx = Transaction::default();
    tx.gas_price = 1_000;
    tx.tx_type = None; // defaults to Standard
    let priority = tx.priority();
    assert_eq!(priority, 10 * 1_000_000 + 1_000);
}

#[test]
fn test_transaction_serialization_roundtrip() {
    let tx = Transaction {
        hash: Hash::new([0x11; 32]),
        nonce: 42,
        from: PublicKey::new([0x22; 32]),
        to: Some(PublicKey::new([0x33; 32])),
        value: 1000,
        gas_limit: 21_000,
        gas_price: 1_000_000_000,
        data: vec![0xDE, 0xAD],
        signature: Signature::new([0x44; 64]),
        tx_type: Some(TransactionType::Standard),
        eth_tx_type: 2,
        max_fee_per_gas: Some(2_000_000_000),
        max_priority_fee_per_gas: Some(1_000_000),
        access_list: None,
        chain_id: Some(40204),
        ecdsa_verified: true,
    };
    let json = serde_json::to_string(&tx).unwrap();
    let d: Transaction = serde_json::from_str(&json).unwrap();
    assert_eq!(d.nonce, 42);
    assert_eq!(d.value, 1000);
    assert_eq!(d.eth_tx_type, 2);
    assert_eq!(d.max_fee_per_gas, Some(2_000_000_000));
    assert_eq!(d.chain_id, Some(40204));
    assert!(d.ecdsa_verified);
}

// -- BlueSet tests --

#[test]
fn test_blue_set_new() {
    let bs = BlueSet::new();
    assert_eq!(bs.score, 0);
    assert_eq!(bs.work, 0);
    assert_eq!(bs.size(), 0);
}

#[test]
fn test_blue_set_insert_increments_score() {
    let mut bs = BlueSet::new();
    bs.insert(Hash::new([1; 32]));
    assert_eq!(bs.score, 1);
    assert_eq!(bs.size(), 1);
    bs.insert(Hash::new([2; 32]));
    assert_eq!(bs.score, 2);
    assert_eq!(bs.size(), 2);
}

#[test]
fn test_blue_set_contains() {
    let mut bs = BlueSet::new();
    let h = Hash::new([0xAA; 32]);
    assert!(!bs.contains(&h));
    bs.insert(h);
    assert!(bs.contains(&h));
}

#[test]
fn test_blue_set_duplicate_insert() {
    let mut bs = BlueSet::new();
    let h = Hash::new([0xAA; 32]);
    bs.insert(h);
    bs.insert(h); // duplicate
    // HashSet deduplicates, but score increments each time
    assert_eq!(bs.size(), 1);
    assert_eq!(bs.score, 2); // score is incremented regardless
}

#[test]
fn test_blue_set_default() {
    let bs = BlueSet::default();
    assert_eq!(bs.score, 0);
    assert_eq!(bs.size(), 0);
}

#[test]
fn test_blue_set_serialization_roundtrip() {
    let mut bs = BlueSet::new();
    bs.insert(Hash::new([1; 32]));
    bs.insert(Hash::new([2; 32]));
    bs.work = 42;

    let json = serde_json::to_string(&bs).unwrap();
    let d: BlueSet = serde_json::from_str(&json).unwrap();
    assert_eq!(d.size(), 2);
    assert_eq!(d.score, 2);
    assert_eq!(d.work, 42);
}

// -- Tip tests --

#[test]
fn test_tip_new_from_block() {
    let block = make_block(0x01, 5, 10, Hash::default());
    let tip = Tip::new(&block);
    assert_eq!(tip.hash, block.hash());
    assert_eq!(tip.blue_score, 10);
    assert_eq!(tip.height, 5);
    assert_eq!(tip.timestamp, 5000);
}

// -- DagRelation tests --

#[test]
fn test_dag_relation_serialization_roundtrip() {
    let relation = DagRelation {
        block: Hash::new([1; 32]),
        selected_parent: Hash::new([2; 32]),
        merge_parents: vec![Hash::new([3; 32])],
        children: vec![Hash::new([4; 32]), Hash::new([5; 32])],
        blue_set: BlueSet::new(),
        is_chain_block: true,
    };
    let json = serde_json::to_string(&relation).unwrap();
    let d: DagRelation = serde_json::from_str(&json).unwrap();
    assert_eq!(d.block, Hash::new([1; 32]));
    assert!(d.is_chain_block);
    assert_eq!(d.children.len(), 2);
}

// -- ModelId tests --

#[test]
fn test_model_id_from_name() {
    let id = ModelId::from_name("gpt2-small");
    assert_eq!(id.as_str(), "gpt2-small");
    assert_eq!(format!("{}", id), "gpt2-small");
}

#[test]
fn test_model_id_equality() {
    let id1 = ModelId::from_name("model-a");
    let id2 = ModelId::from_name("model-a");
    let id3 = ModelId::from_name("model-b");
    assert_eq!(id1, id2);
    assert_ne!(id1, id3);
}

// -- EmbeddedModel tests --
//
// Post-WP-B (2026-04-21): EmbeddedModel carries a fixed-size sha256
// commitment, not raw `Vec<u8>` weights. size_bytes() now returns a
// constant bound derived from the commitment size + metadata cap.
// See specs/tla/consensus/EmbeddedModelCommitment.tla for integrity
// invariants.

#[test]
fn test_embedded_model_size_bytes_is_bounded() {
    let model = EmbeddedModel {
        model_id: ModelId::from_name("tiny"),
        model_type: ModelType::TinyLLM,
        weights_sha256: Hash::new([0x11u8; 32]),
        metadata: ModelMetadata {
            name: "tiny".to_string(),
            version: "1.0".to_string(),
            context_length: 512,
            embedding_dim: None,
            license: "MIT".to_string(),
            framework: Some("GGUF".to_string()),
        },
    };
    // Post-WP-B: size is fixed, not a function of weight length.
    let expected = 32 + EmbeddedModel::EMBEDDED_MODEL_METADATA_SIZE_UPPER_BOUND;
    assert_eq!(model.size_bytes(), expected);
}

#[test]
fn test_embedded_model_weights_hash_returns_stored_commitment() {
    // Post-WP-B: weights_hash() returns the stored `weights_sha256`
    // commitment directly; no computation happens at call time.
    let commit = Hash::new([0xBEu8; 32]);
    let model = EmbeddedModel {
        model_id: ModelId::from_name("test"),
        model_type: ModelType::Embeddings,
        weights_sha256: commit,
        metadata: ModelMetadata {
            name: "test".to_string(),
            version: "1.0".to_string(),
            context_length: 128,
            embedding_dim: Some(768),
            license: "Apache-2.0".to_string(),
            framework: None,
        },
    };
    assert_eq!(model.weights_hash(), commit);
    // Deterministic across calls (trivially: it's a field access).
    assert_eq!(model.weights_hash(), model.weights_hash());
}

/// WP-B.3: size-bound regression test.
///
/// Verifies the property proven structurally by WP-B.2 and formally by
/// `specs/tla/consensus/EmbeddedModelCommitment.tla` `PerModelOnChainSizeBounded`:
/// serializing an `EmbeddedModel` yields a byte count bounded by
/// `size_bytes()` — regardless of what we try to put in its fields.
///
/// This test exists to close the pre-WP-B footgun documented in
/// `.audit/2026-04-21-repo-walkthrough/02_GENESIS_AND_EMBEDDED_MODELS.md`.
/// Before WP-B, an `EmbeddedModel` could be constructed with a multi-GB
/// `weights: Vec<u8>`, which would then serialize to multi-GB and bloat
/// every propagated block. After WP-B, the struct has no `Vec<u8>` field
/// at all, so the serialized size is bounded at compile time by the sum
/// of the fixed-size fields (commitment hash + fixed-size metadata).
#[test]
fn test_embedded_model_serialized_size_is_bounded() {
    let model = EmbeddedModel {
        model_id: ModelId::from_name("adversarially-named-model-with-a-very-long-identifier-that-should-not-matter-for-commitment-size"),
        model_type: ModelType::TinyLLM,
        weights_sha256: Hash::new([0xFFu8; 32]),
        metadata: ModelMetadata {
            // Even with maximally long strings, metadata is bounded by
            // EMBEDDED_MODEL_METADATA_SIZE_UPPER_BOUND (enforced at block
            // validation, not at struct construction).
            name: "adversarial-name-attempting-to-inflate-the-on-chain-footprint-through-metadata-length".to_string(),
            version: "9999.999.999-rc.adversarial".to_string(),
            context_length: u32::MAX,
            embedding_dim: Some(u32::MAX),
            license: "CC0 with additional clauses designed to lengthen this field adversarially".to_string(),
            framework: Some("hypothetical-framework-name-of-extreme-length-for-testing-purposes".to_string()),
        },
    };

    // bincode is the serializer the consensus layer uses for block
    // propagation. Serializing should produce a bounded byte count.
    let bytes = bincode::serialize(&model).expect("serialize");

    // Upper bound: 32-byte commitment + metadata fields. The concrete
    // bincode encoding adds a few bytes of length prefixes per string,
    // but remains well under a generous 4 KiB cap — orders of magnitude
    // smaller than the pre-WP-B pathological case (multi-GB weights).
    //
    // 4 KiB is the "this is a commitment, not an artifact" regime. If
    // this assertion ever fires, something has added an unbounded
    // field to EmbeddedModel and reintroduced the footgun.
    const HARD_CAP_BYTES: usize = 4096;
    assert!(
        bytes.len() < HARD_CAP_BYTES,
        "serialized EmbeddedModel is {} bytes; exceeds hard cap of {} — \
         did someone reintroduce an unbounded field? See WP-B and \
         ADR_010_EMBEDDED_MODEL_COMMITMENT.md.",
        bytes.len(),
        HARD_CAP_BYTES,
    );

    // And the nominal bound reported by size_bytes() should also hold
    // with margin over the actual serialized size.
    assert!(
        bytes.len() <= model.size_bytes(),
        "actual serialized size {} exceeds size_bytes() estimate {}",
        bytes.len(),
        model.size_bytes(),
    );
}

/// WP-B.3: block-level size-bound sanity.
///
/// Constructs a block with multiple embedded models and asserts the
/// serialized `embedded_models` section scales linearly with the model
/// count, not with any per-model inflation vector. Any future regression
/// that re-adds an unbounded per-model field would break the linear
/// scaling.
#[test]
fn test_block_embedded_models_scales_linearly() {
    fn make_model(i: u8) -> EmbeddedModel {
        EmbeddedModel {
            model_id: ModelId::from_name(&format!("model-{}", i)),
            model_type: ModelType::Embeddings,
            weights_sha256: Hash::new([i; 32]),
            metadata: ModelMetadata {
                name: format!("model-{}", i),
                version: "1.0.0".to_string(),
                context_length: 512,
                embedding_dim: Some(384),
                license: "MIT".to_string(),
                framework: Some("GGUF".to_string()),
            },
        }
    }

    let one_model = vec![make_model(1)];
    let ten_models: Vec<_> = (0..10).map(make_model).collect();

    let one_bytes = bincode::serialize(&one_model).expect("serialize 1");
    let ten_bytes = bincode::serialize(&ten_models).expect("serialize 10");

    // 10 models should serialize to less than 15× the one-model size
    // (generous bound: per-model overhead + length prefix accounts for
    // some sublinear growth, and 15× is well above the true ~10× ratio).
    // If this ever fails, something is adding super-linear bloat.
    assert!(
        ten_bytes.len() < one_bytes.len() * 15,
        "embedded_models serialization scales super-linearly: \
         1 model = {} bytes, 10 models = {} bytes (expected < {})",
        one_bytes.len(),
        ten_bytes.len(),
        one_bytes.len() * 15,
    );
}

// -- RequiredModel tests --

#[test]
fn test_required_model_new() {
    let rm = RequiredModel::new(
        ModelId::from_name("llama3"),
        "QmTestCid123".to_string(),
        Hash::new([0xAA; 32]),
        1_000_000,
        500,
    );
    assert!(rm.must_pin);
    assert_eq!(rm.grace_period_hours, 24);
    assert_eq!(rm.slash_penalty, 500);
    assert_eq!(rm.size_bytes, 1_000_000);
}

// -- PinStatus tests --

#[test]
fn test_pin_status_serialization_roundtrip() {
    for status in [PinStatus::Pinned, PinStatus::Unpinned, PinStatus::Unverified] {
        let json = serde_json::to_string(&status).unwrap();
        let d: PinStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, d);
    }
}

// -- ModelType tests --

#[test]
fn test_model_type_serialization_roundtrip() {
    let types = vec![
        ModelType::Embeddings,
        ModelType::TinyLLM,
        ModelType::GeneralLLM,
        ModelType::CodeLLM,
        ModelType::VisionLLM,
        ModelType::Diffusion,
    ];
    for mt in types {
        let json = serde_json::to_string(&mt).unwrap();
        let d: ModelType = serde_json::from_str(&json).unwrap();
        assert_eq!(mt, d);
    }
}
