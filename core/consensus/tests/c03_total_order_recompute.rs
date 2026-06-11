// Audit finding C-03 regression: previously the total-order
// iterator's mergeset sort key read `block.header.blue_score`
// directly. A malicious proposer could stuff `u64::MAX` (or any
// other value) into the header to bias the mergeset ordering
// toward their own block — enabling MEV / sandwich attacks
// without controlling the chain tip.
//
// Fix (WP-B4.1): the sort key is now the *locally recomputed*
// `ghostdag.calculate_blue_score(&block)`. The header value is
// ignored for ordering purposes.
//
// SECREM-01 (pre-audit 2026-06-09, CONS-2/3) strengthened the model:
// `GhostDag::add_block` now REJECTS out-of-band header scores at
// admission (`validate_block_consistency`), so a u64::MAX header lie
// can no longer even enter the DAG. These tests were updated from
// "lying blocks are admitted but ordering ignores the lie" to the
// stronger property "lying blocks are rejected at admission, and the
// recomputed score remains structural for everything admitted."

use citrate_consensus::ghostdag::GhostDagError;
use citrate_consensus::types::blue_work_for_score;
use citrate_consensus::*;
use std::sync::Arc;

fn block_with_header_score(seed: u8, height: u64, parent: Hash, header_score: u64) -> Block {
    let mut hash_bytes = [0u8; 32];
    hash_bytes[0] = seed;
    hash_bytes[1] = (height & 0xFF) as u8;
    BlockBuilder::new()
        .hash(Hash::new(hash_bytes))
        .parent(parent)
        .height(height)
        .timestamp(1_000_000 + height * 10)
        .blue_score(header_score)
        // Work must be the canonical derivation or admission rejects it
        // before the score check is even interesting.
        .blue_work(blue_work_for_score(header_score))
        .proposer(PublicKey::new([0xAB; 32]))
        .vrf_reveal(VrfProof {
            proof: vec![0u8; 80],
            output: Hash::new([0xCD; 32]),
        })
        .build_unhashed()
}

/// C-03.1 (strengthened by SECREM-01): a malicious proposer claiming
/// `header.blue_score = u64::MAX` is rejected at ADMISSION — the ordering
/// layer (whose sort key is the recomputed score, WP-B4.1) never sees the
/// block at all. Honest siblings are admitted and their recomputed scores
/// are structural.
#[tokio::test]
async fn c03_malicious_blue_score_ignored_by_ordering() {
    let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag.clone()));

    // Genesis (height 0).
    let genesis = block_with_header_score(0xAA, 0, Hash::default(), 1);
    let g_hash = genesis.hash();
    dag.store_block(genesis.clone()).await.expect("genesis");
    ghostdag.add_block(&genesis).await.expect("ghostdag genesis");

    // Honest child at height 1 (band for a child of genesis is exactly
    // genesis.header.blue_score + 1 = 2).
    let child_a = block_with_header_score(0x01, 1, g_hash, 2);
    dag.store_block(child_a.clone()).await.expect("child a");
    ghostdag.add_block(&child_a).await.expect("ghostdag a");

    // Child B claims `u64::MAX` to bias mergeset ordering. Pre-SECREM it
    // was admitted (ordering ignored the lie); now it dies at the gate.
    let child_b = block_with_header_score(0x02, 1, g_hash, u64::MAX);
    dag.store_block(child_b.clone()).await.expect("child b");
    let err = ghostdag
        .add_block(&child_b)
        .await
        .expect_err("C-03/CONS-2 regression: u64::MAX header score admitted");
    assert!(
        matches!(err, GhostDagError::BlueScoreOutOfRange { claimed: u64::MAX, .. }),
        "wrong rejection reason: {err:?}"
    );

    // The admitted honest child's score is structural.
    let score_a = ghostdag.get_blue_score(&child_a.hash()).await.expect("a");
    assert_eq!(score_a, 2);
    // The malicious block never entered the relations the ordering reads.
    assert!(ghostdag.get_blue_score(&child_b.hash()).await.is_err());
}

/// C-03.2 (strengthened by SECREM-01): the recomputed blue score is
/// invariant under proposer-supplied header values, and out-of-band header
/// claims (0, 12345 on a height-1 child) are rejected at admission. The
/// recomputation itself — `calculate_blue_set`, which never reads the
/// header score — still yields the structural value for any block shape.
#[tokio::test]
async fn c03_recomputed_score_invariant_under_header_lies() {
    let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag.clone()));

    let genesis = block_with_header_score(0xAA, 0, Hash::default(), 1);
    let g_hash = genesis.hash();
    dag.store_block(genesis.clone()).await.expect("genesis");
    ghostdag.add_block(&genesis).await.expect("g add");

    // Out-of-band claims are rejected at admission (band is exactly {2}).
    for lie in [0u64, 1, 3, 12_345] {
        let liar = block_with_header_score(0x10 + (lie % 200) as u8, 1, g_hash, lie);
        dag.store_block(liar.clone()).await.expect("store liar");
        assert!(
            matches!(
                ghostdag.add_block(&liar).await,
                Err(GhostDagError::BlueScoreOutOfRange { .. })
            ),
            "header score {lie} admitted on a child of genesis (band is {{2}})"
        );
        // The recomputation is structural regardless of the header claim —
        // calculate_blue_score never consults header.blue_score.
        let recomputed = ghostdag.calculate_blue_score(&liar).await.expect("score");
        assert_eq!(
            recomputed, 2,
            "C-03: locally-recomputed score is structural (genesis + self), not {lie}"
        );
    }

    // The honest claim is admitted and matches the recomputation.
    let honest = block_with_header_score(0x01, 1, g_hash, 2);
    dag.store_block(honest.clone()).await.expect("honest");
    ghostdag.add_block(&honest).await.expect("honest admitted");
    assert_eq!(
        ghostdag.get_blue_score(&honest.hash()).await.expect("score"),
        2
    );
}
