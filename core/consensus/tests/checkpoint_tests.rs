// Sprint NN WP-NN.5: BFT Checkpoint & Total Ordering Tests
//
// Tests checkpoint quorum enforcement, duplicate vote rejection,
// non-committee vote rejection, and total ordering on non-trivial DAGs.

use std::sync::Arc;
use citrate_consensus::checkpoint::{CheckpointConfig, CheckpointManager, CheckpointVote};
use citrate_consensus::dag_store::DagStore;
use citrate_consensus::ghostdag::GhostDag;
use citrate_consensus::ordering::TotalOrdering;
use citrate_consensus::types::*;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Signer;

fn test_key(seed: u8) -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    bytes[1] = seed.wrapping_mul(37);
    SigningKey::from_bytes(&bytes)
}

fn make_signed_vote(signing_key: &SigningKey, height: u64, block_hash: Hash) -> CheckpointVote {
    make_signed_vote_for_chain(signing_key, height, block_hash, 40204)
}

fn make_signed_vote_for_chain(
    signing_key: &SigningKey,
    height: u64,
    block_hash: Hash,
    chain_id: u64,
) -> CheckpointVote {
    let pubkey_bytes = signing_key.verifying_key().to_bytes();

    // RM-B1 / WP-B2.2 (H-02): use the canonical helper so tests
    // sign exactly the bytes the verifier checks.
    let message = citrate_consensus::checkpoint::canonical_vote_message(
        chain_id, height, &block_hash,
    );

    let sig = signing_key.sign(&message);

    CheckpointVote {
        height,
        block_hash,
        voter: PublicKey::new(pubkey_bytes),
        signature: Signature::new(sig.to_bytes()),
    }
}

fn make_block(hash: Hash, parent: Hash, merge: Vec<Hash>, height: u64, blue_score: u64) -> Block {
    BlockBuilder::new()
        .hash(hash)
        .parent(parent)
        .merge_parents(merge)
        .height(height)
        .timestamp(height)
        .blue_score(blue_score)
        // SECREM-01: admission enforces the canonical score→work relation.
        .blue_work(citrate_consensus::types::blue_work_for_score(blue_score))
        .build_unhashed()
}

fn hash_for(n: u64) -> Hash {
    let mut h = [0u8; 32];
    h[0..8].copy_from_slice(&n.to_le_bytes());
    h[31] = 0xFF; // Avoid collision with Hash::default()
    Hash::new(h)
}

// ============================================================
// BFT Checkpoint Tests
// ============================================================

#[tokio::test]
async fn test_checkpoint_quorum_requires_threshold() {
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let config = CheckpointConfig::for_testing();
    let mgr = CheckpointManager::new(config, dag_store.clone());

    // Store a block at checkpoint height (testing config uses interval=10)
    let block = make_block(hash_for(50), hash_for(49), vec![], 50, 50);
    dag_store.store_block(block.clone()).await.unwrap();

    // Testing config: committee=5, quorum=4, interval=5
    let keys: Vec<SigningKey> = (0..5).map(test_key).collect();
    let committee: Vec<PublicKey> = keys.iter()
        .map(|k| PublicKey::new(k.verifying_key().to_bytes()))
        .collect();

    // Height must be multiple of interval (5)
    mgr.propose(50, hash_for(50), committee).await.unwrap();

    // Submit 3 votes — quorum is 4, so NOT reached
    for (i, key) in keys.iter().enumerate().take(3) {
        let vote = make_signed_vote(key, 50, hash_for(50));
        let reached = mgr.submit_vote(vote).await.unwrap();
        assert!(!reached, "Vote {} of 4 quorum — should not be reached yet", i + 1);
    }

    // Verify can't finalize yet
    let result = mgr.finalize_checkpoint(50).await;
    assert!(result.is_err(), "Cannot finalize without quorum (3/4)");
}

#[tokio::test]
async fn test_checkpoint_quorum_reached_with_enough_votes() {
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let config = CheckpointConfig::for_testing();
    let mgr = CheckpointManager::new(config, dag_store.clone());

    let block = make_block(hash_for(50), hash_for(49), vec![], 50, 50);
    dag_store.store_block(block.clone()).await.unwrap();

    // Testing config: committee=5, quorum=4
    let keys: Vec<SigningKey> = (0..5).map(|i| test_key(i + 10)).collect();
    let committee: Vec<PublicKey> = keys.iter()
        .map(|k| PublicKey::new(k.verifying_key().to_bytes()))
        .collect();

    mgr.propose(50, hash_for(50), committee).await.unwrap();

    // Submit 4 votes — quorum reached at 4th
    for (i, key) in keys.iter().enumerate().take(3) {
        let vote = make_signed_vote(key, 50, hash_for(50));
        let reached = mgr.submit_vote(vote).await.unwrap();
        assert!(!reached, "Vote {} — quorum not yet", i + 1);
    }

    let vote4 = make_signed_vote(&keys[3], 50, hash_for(50));
    let reached = mgr.submit_vote(vote4).await.unwrap();
    assert!(reached, "4 of 4 quorum — should be reached");
}

#[tokio::test]
async fn test_checkpoint_duplicate_vote_rejected() {
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let config = CheckpointConfig::for_testing();
    let mgr = CheckpointManager::new(config, dag_store.clone());

    let block = make_block(hash_for(50), hash_for(49), vec![], 50, 50);
    dag_store.store_block(block.clone()).await.unwrap();

    let key = test_key(20);
    let committee = vec![PublicKey::new(key.verifying_key().to_bytes())];
    mgr.propose(50, hash_for(50), committee).await.unwrap();

    let vote = make_signed_vote(&key, 50, hash_for(50));
    mgr.submit_vote(vote).await.unwrap();

    // Second vote from same voter
    let vote2 = make_signed_vote(&key, 50, hash_for(50));
    let result = mgr.submit_vote(vote2).await;
    assert!(result.is_err(), "Duplicate vote must be rejected");
}

#[tokio::test]
async fn test_checkpoint_non_committee_vote_rejected() {
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let config = CheckpointConfig::for_testing();
    let mgr = CheckpointManager::new(config, dag_store.clone());

    let block = make_block(hash_for(50), hash_for(49), vec![], 50, 50);
    dag_store.store_block(block.clone()).await.unwrap();

    let committee_key = test_key(30);
    let outsider_key = test_key(31);
    let committee = vec![PublicKey::new(committee_key.verifying_key().to_bytes())];
    mgr.propose(50, hash_for(50), committee).await.unwrap();

    // Outsider tries to vote
    let vote = make_signed_vote(&outsider_key, 50, hash_for(50));
    let result = mgr.submit_vote(vote).await;
    assert!(result.is_err(), "Non-committee member vote must be rejected");
}

// ============================================================
// Total Ordering Tests
// ============================================================

#[tokio::test]
async fn test_total_ordering_linear_chain() {
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let params = GhostDagParams::default();
    let ghostdag = Arc::new(GhostDag::new(params, dag_store.clone()));

    // Genesis
    let genesis = make_block(hash_for(0xFF00), Hash::default(), vec![], 0, 0);
    dag_store.store_block(genesis.clone()).await.unwrap();
    ghostdag.add_block(&genesis).await.unwrap();

    // Chain: genesis → b1 → b2 → b3
    let mut prev = hash_for(0xFF00);
    let mut hashes = vec![prev];
    for i in 1..=3u64 {
        let block = make_block(hash_for(i * 100), prev, vec![], i, i);
        dag_store.store_block(block.clone()).await.unwrap();
        ghostdag.add_block(&block).await.unwrap();
        prev = hash_for(i * 100);
        hashes.push(prev);
    }

    let ordering = TotalOrdering::new(dag_store, ghostdag);
    let order = ordering.get_total_order(prev).await.unwrap();

    // Linear chain: total order should be genesis → b1 → b2 → b3
    assert!(order.len() >= 3, "Total order must include at least the chain blocks");
}

#[tokio::test]
async fn test_total_ordering_deterministic() {
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let params = GhostDagParams::default();
    let ghostdag = Arc::new(GhostDag::new(params, dag_store.clone()));

    // Build a small DAG
    let genesis = make_block(hash_for(0xFF00), Hash::default(), vec![], 0, 0);
    dag_store.store_block(genesis.clone()).await.unwrap();
    ghostdag.add_block(&genesis).await.unwrap();

    let b1 = make_block(hash_for(200), hash_for(0xFF00), vec![], 1, 1);
    dag_store.store_block(b1.clone()).await.unwrap();
    ghostdag.add_block(&b1).await.unwrap();

    let b2 = make_block(hash_for(300), hash_for(0xFF00), vec![], 1, 1);
    dag_store.store_block(b2.clone()).await.unwrap();
    ghostdag.add_block(&b2).await.unwrap();

    let merge = make_block(hash_for(400), hash_for(200), vec![hash_for(300)], 2, 3);
    dag_store.store_block(merge.clone()).await.unwrap();
    ghostdag.add_block(&merge).await.unwrap();

    let ordering = TotalOrdering::new(dag_store, ghostdag);

    // Run ordering twice — must be identical
    let order1 = ordering.get_total_order(hash_for(400)).await.unwrap();
    let order2 = ordering.get_total_order(hash_for(400)).await.unwrap();
    assert_eq!(order1, order2, "Total ordering must be deterministic");
}
