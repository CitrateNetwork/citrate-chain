//! SECREM-01 CONS-1/2/3 regression suite (pre-audit 2026-06-09).
//!
//! The finding class: the chain cryptographically *bound* self-reported
//! header fields (`height`, `blue_score`, `blue_work`) but never *recomputed*
//! them — proving the proposer committed to a number, not that the number
//! was true. One forged header could (CONS-1) drag the finality boundary
//! forward and lock in attacker history, or (CONS-2) poison the fork-choice
//! baseline with `u64::MAX` so no honest block could ever reorg it.
//!
//! Red state (pre-fix): `GhostDag::add_block` accepted every block whose
//! parents resolved, regardless of claimed height/score/work — the
//! "*_rejected" tests below all FAILED (the forged blocks were admitted).
//! Post-fix, `validate_block_consistency` gates every relation-building
//! ingest path.

use citrate_consensus::chain_selection::ChainSelector;
use citrate_consensus::dag_store::DagStore;
use citrate_consensus::ghostdag::{GhostDag, GhostDagError};
use citrate_consensus::tip_selection::TipSelector;
use citrate_consensus::types::{
    blue_work_for_score, Block, BlockBuilder, GhostDagParams, Hash, PublicKey,
};
use std::sync::Arc;

fn height_hash(tag: u8, height: u64) -> Hash {
    let mut bytes = [0u8; 32];
    bytes[0] = tag;
    bytes[1] = 0xC5; // never all-zero (zero = genesis sentinel)
    bytes[8..16].copy_from_slice(&height.to_be_bytes());
    Hash::new(bytes)
}

/// A consistent (honest) block: height/score/work all linked to the parent.
fn honest_block(tag: u8, parent: &Block) -> Block {
    let height = parent.header.height + 1;
    let score = parent.header.blue_score + 1;
    BlockBuilder::new()
        .hash(height_hash(tag, height))
        .parent(parent.hash())
        .height(height)
        .timestamp(1_700_000_000 + height)
        .blue_score(score)
        .blue_work(blue_work_for_score(score))
        .proposer(PublicKey::new([1; 32]))
        .build_unhashed()
}

fn genesis() -> Block {
    BlockBuilder::new()
        .hash(height_hash(0xFF, 0))
        .parent(Hash::default())
        .height(0)
        .timestamp(1_700_000_000)
        .blue_score(0)
        .blue_work(0)
        .proposer(PublicKey::new([1; 32]))
        .build_unhashed()
}

/// DAG with genesis + a chain of `n` honest blocks. Returns the components
/// and the tip block.
async fn dag_with_chain(n: u64) -> (Arc<DagStore>, GhostDag, Block) {
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let ghostdag = GhostDag::new(GhostDagParams::default(), dag_store.clone());

    let g = genesis();
    dag_store.store_block(g.clone()).await.expect("store genesis");
    ghostdag.add_block(&g).await.expect("admit genesis");

    let mut tip = g;
    for i in 0..n {
        let b = honest_block(0x10 + i as u8, &tip);
        dag_store.store_block(b.clone()).await.expect("store honest block");
        ghostdag.add_block(&b).await.expect("admit honest block");
        tip = b;
    }
    (dag_store, ghostdag, tip)
}

// ---------------------------------------------------------------------------
// CONS-1: forged height
// ---------------------------------------------------------------------------

/// The exact attack from the report: an elected proposer publishes one block
/// claiming height 10,000,000 on a chain whose real tip is ~5. Pre-fix the
/// node consumed the claim and finalized still-reorg-eligible blocks.
#[tokio::test]
async fn cons1_forged_height_rejected_at_admission() {
    let (_store, ghostdag, tip) = dag_with_chain(5).await;

    let score = tip.header.blue_score + 1;
    let forged = BlockBuilder::new()
        .hash(height_hash(0xA1, 10_000_000))
        .parent(tip.hash())
        .height(10_000_000)
        .timestamp(1_700_000_100)
        .blue_score(score)
        .blue_work(blue_work_for_score(score))
        .proposer(PublicKey::new([2; 32]))
        .build_unhashed();

    let err = ghostdag.add_block(&forged).await.expect_err(
        "CONS-1 regression: forged-height block was admitted to the DAG",
    );
    assert!(
        matches!(err, GhostDagError::HeightMismatch { claimed: 10_000_000, expected: 6 }),
        "wrong rejection reason: {err:?}"
    );
}

#[tokio::test]
async fn cons1_height_must_be_exactly_parent_plus_one() {
    let (_store, ghostdag, tip) = dag_with_chain(3).await;

    for claimed in [tip.header.height, tip.header.height + 2, 0] {
        let score = tip.header.blue_score + 1;
        let b = BlockBuilder::new()
            .hash(height_hash(0xA2, claimed.max(1)))
            .parent(tip.hash())
            .height(claimed)
            .timestamp(1_700_000_100)
            .blue_score(score)
            .blue_work(blue_work_for_score(score))
            .proposer(PublicKey::new([2; 32]))
            .build_unhashed();
        assert!(
            ghostdag.add_block(&b).await.is_err(),
            "height {claimed} admitted on a tip of height {}",
            tip.header.height
        );
    }
}

// ---------------------------------------------------------------------------
// CONS-2: forged blue score / blue work
// ---------------------------------------------------------------------------

/// The exact attack from the report: `header.blue_score = u64::MAX` on a
/// block extending the tip. Pre-fix this poisoned the fork-choice baseline
/// so no honest block could ever exceed it — reorgs permanently suppressed.
#[tokio::test]
async fn cons2_u64max_blue_score_rejected_at_admission() {
    let (_store, ghostdag, tip) = dag_with_chain(5).await;

    let forged = BlockBuilder::new()
        .hash(height_hash(0xB1, tip.header.height + 1))
        .parent(tip.hash())
        .height(tip.header.height + 1)
        .timestamp(1_700_000_100)
        .blue_score(u64::MAX)
        .blue_work(blue_work_for_score(u64::MAX))
        .proposer(PublicKey::new([2; 32]))
        .build_unhashed();

    let err = ghostdag.add_block(&forged).await.expect_err(
        "CONS-2 regression: u64::MAX blue_score block was admitted",
    );
    assert!(
        matches!(err, GhostDagError::BlueScoreOutOfRange { claimed: u64::MAX, .. }),
        "wrong rejection reason: {err:?}"
    );
}

/// Inflation is bounded by the feasible band [sp+1, sp+1+|merge_parents|]:
/// with no merge parents, exactly sp+1 is admissible.
#[tokio::test]
async fn cons2_blue_score_band_enforced() {
    let (_store, ghostdag, tip) = dag_with_chain(3).await;
    let sp_score = tip.header.blue_score;

    // Below band and above band (no merge parents → band is exactly sp+1).
    for claimed in [sp_score, sp_score + 2, sp_score + 100] {
        let b = BlockBuilder::new()
            .hash(height_hash(0xB2, claimed))
            .parent(tip.hash())
            .height(tip.header.height + 1)
            .timestamp(1_700_000_100)
            .blue_score(claimed)
            .blue_work(blue_work_for_score(claimed))
            .proposer(PublicKey::new([2; 32]))
            .build_unhashed();
        assert!(
            ghostdag.add_block(&b).await.is_err(),
            "blue_score {claimed} admitted outside band (sp = {sp_score}, no merges)"
        );
    }

    // In band: accepted.
    let honest = honest_block(0xB3, &tip);
    ghostdag
        .add_block(&honest)
        .await
        .expect("in-band honest block must be admitted");
}

/// blue_work is a pure function of blue_score — any self-reported deviation
/// is rejected (work is never consumed from the wire).
#[tokio::test]
async fn cons2_self_reported_blue_work_rejected() {
    let (_store, ghostdag, tip) = dag_with_chain(2).await;

    let score = tip.header.blue_score + 1;
    let b = BlockBuilder::new()
        .hash(height_hash(0xB4, tip.header.height + 1))
        .parent(tip.hash())
        .height(tip.header.height + 1)
        .timestamp(1_700_000_100)
        .blue_score(score)
        .blue_work(u128::MAX) // forged work
        .proposer(PublicKey::new([2; 32]))
        .build_unhashed();

    let err = ghostdag
        .add_block(&b)
        .await
        .expect_err("forged blue_work admitted");
    assert!(
        matches!(err, GhostDagError::BlueWorkMismatch { .. }),
        "wrong rejection reason: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// CONS-3: structural linkage
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cons3_missing_selected_parent_rejected() {
    let (_store, ghostdag, _tip) = dag_with_chain(2).await;

    let phantom = height_hash(0xEE, 99);
    let b = BlockBuilder::new()
        .hash(height_hash(0xC1, 100))
        .parent(phantom)
        .height(100)
        .timestamp(1_700_000_100)
        .blue_score(100)
        .blue_work(blue_work_for_score(100))
        .proposer(PublicKey::new([2; 32]))
        .build_unhashed();

    let err = ghostdag
        .add_block(&b)
        .await
        .expect_err("block on phantom parent admitted");
    assert!(
        matches!(err, GhostDagError::MissingParent(p) if p == phantom),
        "wrong rejection reason: {err:?}"
    );
}

#[tokio::test]
async fn cons3_missing_merge_parent_rejected() {
    let (_store, ghostdag, tip) = dag_with_chain(2).await;

    let phantom = height_hash(0xEE, 98);
    let score = tip.header.blue_score + 1;
    let b = BlockBuilder::new()
        .hash(height_hash(0xC2, tip.header.height + 1))
        .parent(tip.hash())
        .merge_parents(vec![phantom])
        .height(tip.header.height + 1)
        .timestamp(1_700_000_100)
        .blue_score(score)
        .blue_work(blue_work_for_score(score))
        .proposer(PublicKey::new([2; 32]))
        .build_unhashed();

    assert!(
        matches!(
            ghostdag.add_block(&b).await,
            Err(GhostDagError::MissingParent(p)) if p == phantom
        ),
        "phantom merge parent admitted"
    );
}

#[tokio::test]
async fn cons3_duplicate_and_aliased_merge_parents_rejected() {
    let (dag_store, ghostdag, tip) = dag_with_chain(2).await;

    // A sibling so we have a legitimate merge candidate.
    let sibling = {
        let parent = dag_store
            .get_block(&tip.header.selected_parent_hash)
            .await
            .expect("parent exists");
        let score = parent.header.blue_score + 1;
        let b = BlockBuilder::new()
            .hash(height_hash(0xC3, parent.header.height + 1))
            .parent(parent.hash())
            .height(parent.header.height + 1)
            .timestamp(1_700_000_090)
            .blue_score(score)
            .blue_work(blue_work_for_score(score))
            .proposer(PublicKey::new([3; 32]))
            .build_unhashed();
        dag_store.store_block(b.clone()).await.expect("store sibling");
        ghostdag.add_block(&b).await.expect("admit sibling");
        b
    };

    let score = tip.header.blue_score + 1;
    let mk = |merges: Vec<Hash>, tag: u8, score: u64| {
        BlockBuilder::new()
            .hash(height_hash(tag, tip.header.height + 1))
            .parent(tip.hash())
            .merge_parents(merges)
            .height(tip.header.height + 1)
            .timestamp(1_700_000_100)
            .blue_score(score)
            .blue_work(blue_work_for_score(score))
            .proposer(PublicKey::new([2; 32]))
            .build_unhashed()
    };

    // Duplicate merge parent.
    assert!(
        ghostdag
            .add_block(&mk(vec![sibling.hash(), sibling.hash()], 0xC4, score + 1))
            .await
            .is_err(),
        "duplicate merge parents admitted"
    );
    // Merge parent aliasing the selected parent.
    assert!(
        ghostdag
            .add_block(&mk(vec![tip.hash()], 0xC5, score + 1))
            .await
            .is_err(),
        "merge parent aliasing selected parent admitted"
    );
    // Legitimate single merge parent (in band): admitted.
    ghostdag
        .add_block(&mk(vec![sibling.hash()], 0xC6, score + 1))
        .await
        .expect("legitimate merge block must be admitted");
}

#[tokio::test]
async fn cons3_merge_parent_count_capped() {
    let (dag_store, ghostdag, _tip) = dag_with_chain(1).await;

    // Build max_parents + 1 siblings off genesis, then a block merging all
    // of them — must exceed the cap and be rejected.
    let max = GhostDagParams::default().max_parents;
    let g = dag_store
        .get_block(&height_hash(0xFF, 0))
        .await
        .expect("genesis");
    let mut merges = Vec::new();
    for i in 0..(max + 1) {
        let score = g.header.blue_score + 1;
        let b = BlockBuilder::new()
            .hash(height_hash(0xD0 + i as u8, 1 + i as u64 * 1000))
            .parent(g.hash())
            .height(g.header.height + 1)
            .timestamp(1_700_000_050 + i as u64)
            .blue_score(score)
            .blue_work(blue_work_for_score(score))
            .proposer(PublicKey::new([4; 32]))
            .build_unhashed();
        dag_store.store_block(b.clone()).await.expect("store sibling");
        ghostdag.add_block(&b).await.expect("admit sibling");
        merges.push(b.hash());
    }

    let anchor = dag_store
        .get_block(&merges[0])
        .await
        .expect("anchor sibling");
    let score = anchor.header.blue_score + 1 + max as u64;
    let overfull = BlockBuilder::new()
        .hash(height_hash(0xCF, 2))
        .parent(anchor.hash())
        .merge_parents(merges[1..].to_vec()) // max_parents merges + selected = max+1 parents
        .height(anchor.header.height + 1)
        .timestamp(1_700_000_200)
        .blue_score(score)
        .blue_work(blue_work_for_score(score))
        .proposer(PublicKey::new([2; 32]))
        .build_unhashed();

    // merges[1..] has exactly max_parents entries → over the merge cap.
    assert!(
        matches!(
            ghostdag.add_block(&overfull).await,
            Err(GhostDagError::InvalidLinkage(_))
        ),
        "merge-parent count above max_parents admitted"
    );
}

/// Selected-parent rule: merging a branch heavier than the selected parent
/// is a fork-choice manipulation, not a legal merge.
#[tokio::test]
async fn cons3_selected_parent_must_be_heaviest() {
    let (dag_store, ghostdag, tip) = dag_with_chain(4).await;

    // Light sibling branch off genesis (score 1 « tip score 5).
    let g = dag_store
        .get_block(&height_hash(0xFF, 0))
        .await
        .expect("genesis");
    let light = BlockBuilder::new()
        .hash(height_hash(0xE1, 1))
        .parent(g.hash())
        .height(1)
        .timestamp(1_700_000_010)
        .blue_score(1)
        .blue_work(blue_work_for_score(1))
        .proposer(PublicKey::new([5; 32]))
        .build_unhashed();
    dag_store.store_block(light.clone()).await.expect("store light");
    ghostdag.add_block(&light).await.expect("admit light");

    // Attacker extends the LIGHT branch while merging the heavy tip.
    let b = BlockBuilder::new()
        .hash(height_hash(0xE2, 2))
        .parent(light.hash())
        .merge_parents(vec![tip.hash()])
        .height(light.header.height + 1)
        .timestamp(1_700_000_300)
        .blue_score(light.header.blue_score + 2)
        .blue_work(blue_work_for_score(light.header.blue_score + 2))
        .proposer(PublicKey::new([2; 32]))
        .build_unhashed();

    assert!(
        matches!(
            ghostdag.add_block(&b).await,
            Err(GhostDagError::InvalidLinkage(_))
        ),
        "light selected parent with heavier merge parent admitted"
    );
}

// ---------------------------------------------------------------------------
// CONS-2 end-to-end: the fork-choice baseline cannot be poisoned
// ---------------------------------------------------------------------------

/// Full scenario: attacker tries the baseline-poisoning attack through the
/// chain selector. The forged block dies at admission; an honest competitor
/// still wins fork choice afterward (pre-fix: the poisoned baseline made
/// every later honest block lose).
#[tokio::test]
async fn cons2_fork_choice_baseline_cannot_be_poisoned() {
    let dag_store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag_store.clone()));
    let tip_selector = Arc::new(TipSelector::new(
        dag_store.clone(),
        ghostdag.clone(),
        citrate_consensus::tip_selection::SelectionStrategy::HighestBlueScoreWithTieBreak,
    ));
    let selector = ChainSelector::new(
        dag_store.clone(),
        ghostdag.clone(),
        tip_selector,
        100,
    );

    let g = genesis();
    dag_store.store_block(g.clone()).await.expect("store genesis");
    ghostdag.add_block(&g).await.expect("admit genesis");
    selector.on_new_block(&g).await.expect("select genesis");

    let b1 = honest_block(0x71, &g);
    dag_store.store_block(b1.clone()).await.expect("store b1");
    ghostdag.add_block(&b1).await.expect("admit b1");
    selector.on_new_block(&b1).await.expect("select b1");

    // Attack: extend tip with u64::MAX score. Must die at admission and
    // therefore never reach the selector.
    let poisoned = BlockBuilder::new()
        .hash(height_hash(0x72, 2))
        .parent(b1.hash())
        .height(b1.header.height + 1)
        .timestamp(1_700_000_100)
        .blue_score(u64::MAX)
        .blue_work(blue_work_for_score(u64::MAX))
        .proposer(PublicKey::new([2; 32]))
        .build_unhashed();
    assert!(ghostdag.add_block(&poisoned).await.is_err());

    // Honest continuation still extends the chain normally.
    let b2 = honest_block(0x73, &b1);
    dag_store.store_block(b2.clone()).await.expect("store b2");
    ghostdag.add_block(&b2).await.expect("admit b2");
    selector.on_new_block(&b2).await.expect("select b2");

    let state = selector.get_chain_state().await;
    assert_eq!(state.tip, b2.hash(), "honest block must win fork choice");
    assert!(
        state.blue_score < u64::MAX / 2,
        "baseline must reflect recomputed score, not a forged header"
    );
}
