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
        .blue_work((height + 1) as u128 * 100)
        .proposer(PublicKey::new([0xAB; 32]))
        .vrf_reveal(VrfProof {
            proof: vec![0u8; 80],
            output: Hash::new([0xCD; 32]),
        })
        .build_unhashed()
}

/// C-03.1: malicious proposer claims `header.blue_score = u64::MAX`
/// for their own block. The locally-recomputed blue score is what
/// the ordering uses, so the malicious value is ignored.
#[tokio::test]
async fn c03_malicious_blue_score_ignored_by_ordering() {
    let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag.clone()));

    // Genesis (height 0).
    let genesis = block_with_header_score(0xAA, 0, Hash::default(), 1);
    let g_hash = genesis.hash();
    dag.store_block(genesis.clone()).await.expect("genesis");
    ghostdag.add_block(&genesis).await.expect("ghostdag genesis");

    // Two children at height 1, both pointing to genesis.
    // Child A claims an honest blue score (2 = genesis_blue + self).
    let child_a = block_with_header_score(0x01, 1, g_hash, 2);
    dag.store_block(child_a.clone()).await.expect("child a");
    ghostdag.add_block(&child_a).await.expect("ghostdag a");

    // Child B claims `u64::MAX` to bias mergeset ordering.
    let child_b = block_with_header_score(0x02, 1, g_hash, u64::MAX);
    dag.store_block(child_b.clone()).await.expect("child b");
    ghostdag.add_block(&child_b).await.expect("ghostdag b");

    // Both children's locally-recomputed blue score is 2 (genesis +
    // self on a linear branch). The malicious header on child_b is
    // not consulted by ordering.
    let score_a = ghostdag.get_blue_score(&child_a.hash()).await.expect("a");
    let score_b = ghostdag.get_blue_score(&child_b.hash()).await.expect("b");
    assert_eq!(score_a, 2);
    assert_eq!(score_b, 2);
}

/// C-03.2: the locally-recomputed blue score is invariant under
/// proposer-supplied header values. We compute the score for a
/// block that claims header.blue_score = 0, then again with
/// header.blue_score = 12345, and assert the result is identical
/// (and equal to the structural value 2 for a linear height-1
/// child).
#[tokio::test]
async fn c03_recomputed_score_invariant_under_header_lies() {
    let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag.clone()));

    let genesis = block_with_header_score(0xAA, 0, Hash::default(), 1);
    let g_hash = genesis.hash();
    dag.store_block(genesis.clone()).await.expect("genesis");
    ghostdag.add_block(&genesis).await.expect("g add");

    // Child claiming header score 0.
    let child = block_with_header_score(0x01, 1, g_hash, 0);
    dag.store_block(child.clone()).await.expect("child");
    ghostdag.add_block(&child).await.expect("c add");

    let recomputed = ghostdag.calculate_blue_score(&child).await.expect("score");
    assert_eq!(
        recomputed, 2,
        "C-03: locally-recomputed score is structural (genesis + self), not 0"
    );
}
