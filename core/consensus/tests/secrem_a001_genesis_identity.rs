//! SECREM-A001 tripwire: genesis is an IDENTITY, not a shape.
//!
//! Finding CHAIN-B-A001 (CRITICAL). `Block::is_genesis()` is a purely
//! structural predicate (zero selected parent + no merge parents) with no
//! height/hash/chain-identity binding, and every consensus admission gate used
//! to short-circuit on it. An unauthenticated peer could therefore mint blocks
//! that pass admission by *shaping* them like genesis — an arbitrary height, an
//! empty VRF proof, a zero proposer key and a zero signature — bypassing the
//! parent / VRF / proposer-eligibility / signature checks entirely.
//!
//! The fix binds the genesis admission exemption to identity: a block is exempt
//! only if it is parentless AND at height 0 AND (once the node knows its chain's
//! canonical genesis hash) its self-consistent block hash equals that hash.
//!
//! RED (pre-fix): the shaped pseudo-genesis at height 1_000_000 is accepted by
//! `validate_block_consistency` and by a strict-VRF `DagStore::store_block`.
//! GREEN (post-fix): only the true height-0 genesis is exempt; the shaped block
//! is rejected and goes through normal admission (which fails it: missing
//! parent / empty VRF).

use citrate_consensus::{
    Block, BlockBuilder, DagStore, DagStoreError, GhostDag, GhostDagError, GhostDagParams, Hash,
};
use std::sync::Arc;

/// The canonical genesis: parentless, height 0, hash self-consistent (`build()`
/// computes the block hash from the contents, the way the real genesis is).
fn true_genesis() -> Block {
    BlockBuilder::new()
        .parent(Hash::default())
        .height(0)
        .timestamp(1_700_000_000)
        .build()
}

/// The attacker's forged block: shaped like genesis (no selected parent, no
/// merge parents) but at an arbitrary non-zero height, with the empty VRF proof
/// / zero proposer key / zero signature the builder leaves by default.
fn shaped_pseudo_genesis() -> Block {
    BlockBuilder::new()
        .parent(Hash::default()) // <- structural "genesis" shape
        .height(1_000_000) // <- but NOT height 0
        .blue_score(u64::MAX / 2)
        .timestamp(1_700_000_000)
        .build()
}

/// The true genesis MUST remain admissible (the fix is inert on honest traffic).
#[tokio::test]
async fn true_genesis_is_still_admitted() {
    let dag = Arc::new(DagStore::new()); // strict VRF (production default)
    let ghostdag = GhostDag::new(GhostDagParams::default(), dag.clone());
    let genesis = true_genesis();

    ghostdag
        .validate_block_consistency(&genesis)
        .await
        .expect("SECREM-A001: the true height-0 genesis must pass consistency");

    dag.store_block(genesis)
        .await
        .expect("SECREM-A001: the true height-0 genesis must be admitted");
}

/// GhostDAG consistency must REJECT a shaped pseudo-genesis at a non-zero height.
/// Pre-fix this returned `Ok(())` via the `is_genesis()` short-circuit (RED).
#[tokio::test]
async fn shaped_pseudo_genesis_rejected_by_consistency() {
    let dag = Arc::new(DagStore::new());
    let ghostdag = GhostDag::new(GhostDagParams::default(), dag);
    let forged = shaped_pseudo_genesis();

    let result = ghostdag.validate_block_consistency(&forged).await;

    assert!(
        matches!(result, Err(GhostDagError::InvalidParents)),
        "SECREM-A001: a parentless block at height {} must be rejected as \
         missing its parent, not exempted as genesis — got {:?}",
        forged.header.height,
        result
    );
}

/// A strict-VRF DAG store must REJECT the shaped pseudo-genesis: with the
/// genesis exemption bound to identity, the forged block is subjected to the
/// full VRF admission gate, which fails it (empty proof / zero proposer).
/// Pre-fix `store_block` accepted it and it became a permanent DAG tip (RED).
#[tokio::test]
async fn shaped_pseudo_genesis_rejected_by_strict_store() {
    let dag = DagStore::new(); // strict_vrf = true
    let forged = shaped_pseudo_genesis();

    let result = dag.store_block(forged).await;

    assert!(
        matches!(result, Err(DagStoreError::InvalidVrf(_))),
        "SECREM-A001: a strict-VRF store must reject a shaped pseudo-genesis, \
         got {:?}",
        result
    );
    assert_eq!(
        dag.get_tips().await.len(),
        0,
        "SECREM-A001: the forged block must not become a DAG tip"
    );
}

/// With the canonical genesis hash configured, an alternate height-0 block whose
/// hash is NOT the configured genesis hash is also rejected (a rogue alternate
/// genesis cannot pollute the height-0 slot).
#[tokio::test]
async fn alternate_height0_block_rejected_when_genesis_configured() {
    let dag = DagStore::new();
    let genesis = true_genesis();
    // Bind the store to this chain's canonical genesis identity.
    dag.set_configured_genesis(genesis.hash());

    // The real genesis is still accepted.
    dag.store_block(genesis)
        .await
        .expect("true genesis admitted");

    // A different height-0 parentless block (different contents ⇒ different
    // hash) is NOT the configured genesis, so it is subjected to full admission
    // and rejected in strict mode.
    let rogue = BlockBuilder::new()
        .parent(Hash::default())
        .height(0)
        .timestamp(1_700_000_042) // different content ⇒ different hash
        .build();

    let result = dag.store_block(rogue).await;
    assert!(
        matches!(result, Err(DagStoreError::InvalidVrf(_))),
        "SECREM-A001: with genesis configured, a non-canonical height-0 block \
         must not be treated as genesis, got {:?}",
        result
    );
}
