//! Pins the genesis-identity exemption at the DAG store's VRF gates.
//!
//! `DagStore::store_block` exempts only the configured genesis from the
//! cryptographic VRF check, at two places: the outer `strict_vrf` gate in
//! `store_block` and the early return inside `verify_block_vrf_crypto`. The
//! existing suite only offers a parentless block that also fails the
//! structural admission checks (empty VRF proof, zero proposer and signature),
//! so either exemption could fall back to the parentless *shape* without any
//! test noticing. These tests give the parentless block plausible,
//! non-zero header fields, so only the cryptographic gate can refuse it.

use citrate_consensus::{
    Block, BlockBuilder, DagStore, DagStoreError, Hash, PublicKey, Signature, VrfProof,
};

/// Parentless (genesis-shaped) and structurally plausible: non-zero proposer,
/// non-empty VRF proof, non-zero VRF output, non-zero signature. None of it
/// verifies.
fn plausible_parentless(height: u64, ts: u64) -> Block {
    BlockBuilder::new()
        .parent(Hash::default())
        .height(height)
        .timestamp(ts)
        .proposer(PublicKey::new([7u8; 32]))
        .vrf_reveal(VrfProof {
            proof: vec![0x5A; 80],
            output: Hash::new([9u8; 32]),
        })
        .signature(Signature::new([3u8; 64]))
        .build()
}

#[tokio::test]
async fn parentless_block_at_nonzero_height_is_vrf_checked_by_the_store() {
    let dag = DagStore::new(); // strict VRF, the production default
    let forged = plausible_parentless(1_000_000, 1_700_000_000);

    let result = dag.store_block(forged).await;

    assert!(
        matches!(result, Err(DagStoreError::InvalidVrf(_))),
        "a parentless block above height 0 must go through the VRF check, got {result:?}"
    );
    assert!(
        dag.get_tips().await.is_empty(),
        "the refused block must not become a DAG tip"
    );
}

#[tokio::test]
async fn non_canonical_height0_block_is_vrf_checked_once_genesis_is_configured() {
    let dag = DagStore::new();
    let genesis = BlockBuilder::new()
        .parent(Hash::default())
        .height(0)
        .timestamp(1_700_000_000)
        .build();
    dag.set_configured_genesis(genesis.hash());
    dag.store_block(genesis.clone())
        .await
        .expect("the configured genesis is admitted");

    let rogue = plausible_parentless(0, 1_700_000_042);
    assert_ne!(rogue.hash(), genesis.hash());

    let result = dag.store_block(rogue).await;
    assert!(
        matches!(result, Err(DagStoreError::InvalidVrf(_))),
        "a height-0 block that is not the configured genesis must be VRF-checked, got {result:?}"
    );
    let tips: Vec<Hash> = dag.get_tips().await.iter().map(|t| t.hash).collect();
    assert_eq!(
        tips,
        vec![genesis.hash()],
        "only the configured genesis is a tip"
    );
}
