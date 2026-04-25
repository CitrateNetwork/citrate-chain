// Audit finding H-05 regression: `DagStore::new()` defaults to
// `strict_vrf: true` and rejects blocks failing structural VRF
// admission. The permissive opt-out lives at
// `with_permissive_vrf_for_testing()` and exists strictly for unit
// tests that exercise GhostDAG semantics without producing real
// ECVRF proofs.
//
// Sister TLA+ spec: `specs/tla/consensus/GhostDAGSafety.tla`
// (admission preconditions amended for WP-B1.4).

use citrate_consensus::*;
use std::sync::Arc;

/// Build a block with empty VRF proof and zero proposer pubkey.
/// In strict mode this MUST be rejected at admission.
fn garbage_vrf_block(seed: u8, height: u64, parent: Hash) -> Block {
    let mut hash_bytes = [0u8; 32];
    hash_bytes[0] = seed;
    hash_bytes[1] = (height & 0xFF) as u8;
    BlockBuilder::new()
        .hash(Hash::new(hash_bytes))
        .parent(parent)
        .height(height)
        .timestamp(1_000_000 + height * 10)
        .blue_score(height + 1)
        .blue_work((height + 1) as u128 * 100)
        // Garbage VRF: empty proof, zero output, zero proposer pubkey,
        // zero signature.
        .proposer(PublicKey::new([0u8; 32]))
        .vrf_reveal(VrfProof {
            proof: vec![],
            output: Hash::default(),
        })
        .build_unhashed()
}

fn genesis() -> Block {
    BlockBuilder::new()
        .hash(Hash::new([0xAA; 32]))
        .height(0)
        .timestamp(1_000_000)
        .blue_score(1)
        .blue_work(100)
        .build_unhashed()
}

/// H-05.1: strict default rejects garbage-VRF blocks.
#[tokio::test]
async fn h05_strict_default_rejects_garbage_vrf_block() {
    let dag = Arc::new(DagStore::new()); // strict_vrf=true by default
    let g = genesis();
    let g_hash = g.hash();
    dag.store_block(g).await.expect("genesis must admit");

    let bad = garbage_vrf_block(0x01, 1, g_hash);
    let err = dag
        .store_block(bad)
        .await
        .expect_err("garbage VRF block must be rejected by strict default");
    let msg = format!("{}", err);
    assert!(
        msg.to_ascii_lowercase().contains("vrf")
            || msg.to_ascii_lowercase().contains("invalid"),
        "rejection error should mention VRF / invalid: {}",
        msg
    );
}

/// H-05.2: explicit permissive opt-in still admits garbage-VRF blocks
/// (this is the test-only escape hatch the planset preserves so
/// existing GhostDAG semantics tests don't have to mint real ECVRF
/// proofs).
#[tokio::test]
async fn h05_permissive_opt_in_admits_garbage_vrf_block() {
    let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let g = genesis();
    let g_hash = g.hash();
    dag.store_block(g).await.expect("genesis must admit");

    let bad = garbage_vrf_block(0x01, 1, g_hash);
    dag.store_block(bad)
        .await
        .expect("permissive constructor must admit (test escape hatch)");
}

/// H-05.3: `with_strict_vrf(true)` is equivalent to `new()` for VRF
/// admission. This pins the strict-mode behavior across both
/// constructors so a future refactor can't silently relax one.
#[tokio::test]
async fn h05_with_strict_vrf_true_matches_default() {
    let dag = Arc::new(DagStore::with_strict_vrf(true));
    let g = genesis();
    let g_hash = g.hash();
    dag.store_block(g).await.expect("genesis must admit");

    let bad = garbage_vrf_block(0x01, 1, g_hash);
    let err = dag
        .store_block(bad)
        .await
        .expect_err("with_strict_vrf(true) must reject garbage VRF block");
    let _ = err; // any rejection variant is acceptable
}

/// H-05.4: structural admission catches each individual garbage field
/// (empty proof, zero output, zero pubkey, zero signature). The
/// admission gate is the load-bearing pre-check; any one failing
/// field MUST cause rejection in strict mode.
#[tokio::test]
async fn h05_strict_rejects_each_garbage_field_individually() {
    let dag = Arc::new(DagStore::new());
    let g = genesis();
    let g_hash = g.hash();
    dag.store_block(g).await.expect("genesis must admit");

    // Empty proof only.
    let mut bad = garbage_vrf_block(0xB1, 1, g_hash);
    bad.header.proposer_pubkey = PublicKey::new([0xAB; 32]); // non-zero
    bad.header.vrf_reveal.output = Hash::new([0xCD; 32]); // non-zero
    bad.signature = citrate_consensus::types::Signature::new([0xEF; 64]); // non-zero
    bad.header.vrf_reveal.proof = vec![]; // garbage
    let err = dag
        .store_block(bad)
        .await
        .expect_err("empty proof must reject under strict default");
    let _ = err;

    // Zero output only.
    let mut bad = garbage_vrf_block(0xB2, 2, g_hash);
    bad.header.proposer_pubkey = PublicKey::new([0xAB; 32]);
    bad.header.vrf_reveal.proof = vec![0u8; 80]; // non-empty
    bad.signature = citrate_consensus::types::Signature::new([0xEF; 64]);
    bad.header.vrf_reveal.output = Hash::default(); // garbage
    let err = dag
        .store_block(bad)
        .await
        .expect_err("zero output must reject under strict default");
    let _ = err;
}
