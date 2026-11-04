//! #184: time slots (G9) and equivocation (G10). Spec: planset
//! 2026-11-03-r1007-v060, `06_CONSENSUS_SPEC.md` §1.1 (`slot`), §2 G9, G10.
//!
//! A block's slot is `(timestamp - genesis.timestamp) / SLOT_DURATION`. Its
//! slot must be strictly greater than the slot of every parent, its VRF is
//! bound to that slot, and two blocks of one proposer in one slot equivocate:
//! the second one GHOSTDAG meets is colored red.
//!
//! Every header here is built by hand with the values the spec defines; no
//! expectation is computed by the code under test.

use citrate_consensus::dag_store::DagStore;
use citrate_consensus::ghostdag::GhostDag;
use citrate_consensus::slots::{MAX_FUTURE_SLOT_DRIFT_SECS, SLOT_DURATION_SECS};
use citrate_consensus::types::{
    blue_work_for_score, Block, BlockBuilder, GhostDagParams, Hash, PublicKey, VrfProof,
};
use std::sync::Arc;

/// The genesis timestamp of every DAG here (a slot boundary).
const G_TS: u64 = 1_767_225_600;

fn hash_of(tag: &[u8]) -> Hash {
    let mut b = [0u8; 32];
    for (d, s) in b.iter_mut().zip(tag.iter()) {
        *d = *s;
    }
    Hash::new(b)
}

fn proposer(tag: u8) -> PublicKey {
    PublicKey::new([tag; 32])
}

/// The first second of `slot`.
fn ts(slot: u64) -> u64 {
    G_TS + slot * SLOT_DURATION_SECS
}

struct Spec {
    id: Hash,
    sp: Hash,
    merges: Vec<Hash>,
    height: u64,
    score: u64,
    timestamp: u64,
    proposer: PublicKey,
    vrf: Hash,
}

fn build(s: Spec) -> Block {
    BlockBuilder::new()
        .hash(s.id)
        .parent(s.sp)
        .merge_parents(s.merges)
        .height(s.height)
        .blue_score(s.score)
        .blue_work(blue_work_for_score(s.score))
        .timestamp(s.timestamp)
        .proposer(s.proposer)
        .vrf_reveal(VrfProof {
            proof: Vec::new(),
            output: s.vrf,
        })
        .build_unhashed()
}

/// A linear child of `parent` (height h, score h) at `timestamp`.
fn child(id: &[u8], parent: &Block, timestamp: u64, who: u8) -> Block {
    build(Spec {
        id: hash_of(id),
        sp: parent.hash(),
        merges: vec![],
        height: parent.header.height + 1,
        score: parent.header.blue_score + 1,
        timestamp,
        proposer: proposer(who),
        vrf: Hash::default(),
    })
}

fn genesis() -> Block {
    build(Spec {
        id: hash_of(b"G"),
        sp: Hash::default(),
        merges: vec![],
        height: 0,
        score: 0,
        timestamp: G_TS,
        proposer: PublicKey::default(),
        vrf: Hash::default(),
    })
}

fn engine() -> (Arc<DagStore>, GhostDag) {
    let store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let gd = GhostDag::new(GhostDagParams::default(), store.clone());
    (store, gd)
}

/// The production admission order (`node/src/admission.rs`).
async fn admit(store: &DagStore, gd: &GhostDag, b: &Block) -> Result<(), String> {
    gd.validate_block_consistency(b)
        .await
        .map_err(|e| e.to_string())?;
    store
        .store_block(b.clone())
        .await
        .map_err(|e| e.to_string())?;
    gd.add_block(b).await.map_err(|e| e.to_string())
}

async fn admit_ok(store: &DagStore, gd: &GhostDag, b: &Block) {
    if let Err(e) = admit(store, gd, b).await {
        panic!(
            "block {} @ {} (ts {}) must be admitted: {e}",
            b.hash(),
            b.header.height,
            b.header.timestamp
        );
    }
}

async fn verdict(gd: &GhostDag, b: &Block) -> Result<(), String> {
    gd.validate_block_consistency(b)
        .await
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// G9: the slot strictly increases along every parent edge
// ---------------------------------------------------------------------------

/// A (slot 1) and B (slot 3) on genesis. A carries the larger VRF output, so it
/// is the heavier parent and the selected parent of a block merging both. A
/// child at slot 2 is after its selected parent but not after its merge
/// parent B: invalid. At slot 3 it shares B's slot: invalid. At slot 4: valid.
/// The pre-r1007 rule compared the timestamp with the selected parent only.
#[tokio::test]
async fn slot_must_strictly_increase_over_every_parent() {
    let (store, gd) = engine();
    let g = genesis();
    admit_ok(&store, &gd, &g).await;
    let a = build(Spec {
        id: hash_of(b"A"),
        sp: g.hash(),
        merges: vec![],
        height: 1,
        score: 1,
        timestamp: ts(1),
        proposer: proposer(0xA),
        vrf: Hash::new([0xFF; 32]),
    });
    let b = build(Spec {
        id: hash_of(b"B"),
        sp: g.hash(),
        merges: vec![],
        height: 1,
        score: 1,
        timestamp: ts(3),
        proposer: proposer(0xB),
        vrf: Hash::new([0x01; 32]),
    });
    admit_ok(&store, &gd, &a).await;
    admit_ok(&store, &gd, &b).await;
    let c = |slot: u64| {
        build(Spec {
            id: hash_of(b"C"),
            sp: a.hash(),
            merges: vec![b.hash()],
            height: 2,
            score: 3,
            timestamp: ts(slot),
            proposer: proposer(0xC),
            vrf: Hash::default(),
        })
    };
    for bad in [2u64, 3] {
        assert!(
            verdict(&gd, &c(bad)).await.is_err(),
            "slot {bad} is not after merge parent B's slot 3 and must be rejected"
        );
    }
    assert_eq!(verdict(&gd, &c(4)).await, Ok(()), "slot 4 > every parent");

    // Within a slot the second does not count: the last second of slot 3 is
    // still slot 3.
    if SLOT_DURATION_SECS > 1 {
        let mut late = c(3);
        late.header.timestamp = ts(4) - 1;
        assert!(verdict(&gd, &late).await.is_err());
    }
}

/// #184: a child stamped with its parent's timestamp is in its parent's slot.
/// FWA-C1-03 accepted `timestamp == parent`; G9 does not.
#[tokio::test]
async fn equal_timestamp_child_rejected() {
    let (store, gd) = engine();
    let g = genesis();
    admit_ok(&store, &gd, &g).await;
    let a = child(b"A", &g, ts(5), 0xA);
    admit_ok(&store, &gd, &a).await;

    let equal = child(b"B", &a, a.header.timestamp, 0xB);
    assert!(
        verdict(&gd, &equal).await.is_err(),
        "a child with its parent's timestamp must be rejected"
    );
    // So is a child of genesis stamped at genesis (slot 0).
    let at_genesis = child(b"Z", &g, G_TS, 0xC);
    assert!(verdict(&gd, &at_genesis).await.is_err());
    // And a timestamp before genesis has no slot at all.
    let before = child(b"Y", &g, G_TS - 1, 0xC);
    assert!(verdict(&gd, &before).await.is_err());

    let next = child(b"B", &a, ts(6), 0xB);
    assert_eq!(verdict(&gd, &next).await, Ok(()), "the next slot is valid");
}

/// Ingress policy (local, not a validity rule): a block more than
/// MAX_FUTURE_SLOT_DRIFT_SECS ahead of the local clock is not admitted by
/// gossip or sync until its slot arrives. It was 900 s before r1007.
#[tokio::test]
async fn future_slot_beyond_drift_rejected() {
    use citrate_consensus::hardening::within_future_drift;
    let now = ts(10_000);
    assert_eq!(MAX_FUTURE_SLOT_DRIFT_SECS, 15, "spec G9 proposes 15 s");
    assert!(within_future_drift(now, now));
    assert!(within_future_drift(now + MAX_FUTURE_SLOT_DRIFT_SECS, now));
    assert!(
        !within_future_drift(now + MAX_FUTURE_SLOT_DRIFT_SECS + SLOT_DURATION_SECS, now),
        "a block one slot beyond the drift must be held, not admitted"
    );
    assert!(
        !within_future_drift(now + 900, now),
        "the pre-r1007 15-minute window is closed"
    );
}

/// #184: one proposer cannot extend a chain faster than one block per slot.
///
/// A lone proposer that seals a chain as fast as it can is limited to one block
/// per slot: every block it stacks inside a slot it already used is invalid,
/// and the gossip/sync ingress holds blocks more than the drift ahead of the
/// local clock. So over the slots [1, T] its longest chain has at most
/// T + drift blocks, however fast it can sign.
#[tokio::test]
async fn one_proposer_cannot_extend_faster_than_one_block_per_slot() {
    use citrate_consensus::hardening::within_future_drift;
    let (store, gd) = engine();
    let g = genesis();
    admit_ok(&store, &gd, &g).await;

    // The attacker stamps every block "now": all in slot 1.
    let first = child(b"P1", &g, ts(1), 0x66);
    admit_ok(&store, &gd, &first).await;
    let mut tip = first.clone();
    for i in 2..=10u8 {
        let same_slot = child(&[b'P', i], &tip, ts(1), 0x66);
        assert!(
            verdict(&gd, &same_slot).await.is_err(),
            "block {i} of one proposer in slot 1 must be rejected"
        );
        // Nor may it reuse its slot by bumping the second inside the slot.
        if SLOT_DURATION_SECS > 1 {
            let mut inside = same_slot.clone();
            inside.header.timestamp = ts(2) - 1;
            assert!(verdict(&gd, &inside).await.is_err());
        }
    }
    // One block per slot is the only way forward: T slots, T blocks.
    const T: u64 = 30;
    for slot in 2..=T {
        let next = child(format!("Q{slot}").as_bytes(), &tip, ts(slot), 0x66);
        admit_ok(&store, &gd, &next).await;
        tip = next;
    }
    assert_eq!(tip.header.height, T, "T slots carried exactly T blocks");

    // Running ahead of the clock is bounded by the ingress drift: with the
    // local clock at slot T, the proposer's blocks for slot T + drift + 1 and
    // beyond are not admitted.
    let now = ts(T);
    let drift_slots = MAX_FUTURE_SLOT_DRIFT_SECS / SLOT_DURATION_SECS;
    assert!(within_future_drift(ts(T + drift_slots), now));
    assert!(!within_future_drift(ts(T + drift_slots + 1), now));
}

// ---------------------------------------------------------------------------
// G10: equivocation is red
// ---------------------------------------------------------------------------

/// Proposer X seals A and A' in slot 1; Y seals B in slot 1. C (slot 2)
/// merges all three. Exactly one of A / A' is colored red, B is blue, and the
/// pair adds weight once: blue_score(C) = 1 (SP's) + 2 blues, not + 3.
#[tokio::test]
async fn equivocation_two_blocks_same_proposer_same_slot_colored_red() {
    let (store, gd) = engine();
    let g = genesis();
    admit_ok(&store, &gd, &g).await;
    let a = child(b"A", &g, ts(1), 0x58);
    let a2 = child(b"A2", &g, ts(1), 0x58);
    let b = child(b"B", &g, ts(1), 0x59);
    for x in [&a, &a2, &b] {
        admit_ok(&store, &gd, x).await;
    }

    let parents = vec![a.hash(), a2.hash(), b.hash()];
    let (sp, merges, height, data) = gd
        .ghostdag_for_parents(&parents)
        .await
        .expect("parents are valid");
    assert_eq!(height, 2);
    let reds: Vec<Hash> = data.mergeset_reds.clone();
    assert_eq!(reds.len(), 1, "exactly one block is red: {reds:?}");
    assert!(
        reds[0] == a.hash() || reds[0] == a2.hash(),
        "the red block is one of the equivocating pair"
    );
    assert!(data.mergeset_blues.contains(&b.hash()), "B stays blue");
    assert_eq!(data.blue_score, 1 + 2, "the pair adds weight once");

    // The header committing that score is admitted; one counting both is not.
    let c = |score: u64| {
        build(Spec {
            id: hash_of(b"C"),
            sp,
            merges: merges.clone(),
            height: 2,
            score,
            timestamp: ts(2),
            proposer: proposer(0x5A),
            vrf: Hash::default(),
        })
    };
    assert!(verdict(&gd, &c(4)).await.is_err(), "both halves counted");
    admit_ok(&store, &gd, &c(3)).await;
}

/// Seven producers, seven proposers, one slot, one parent: all seven are
/// admitted, and the block of the next slot that merges them colors all seven
/// blue (k = 18). G9 and G10 never touch honest concurrency.
#[tokio::test]
async fn honest_concurrent_producers_unaffected() {
    let (store, gd) = engine();
    let g = genesis();
    admit_ok(&store, &gd, &g).await;
    let base = child(b"base", &g, ts(1), 0x10);
    admit_ok(&store, &gd, &base).await;

    let mut siblings = Vec::new();
    for p in 0..7u8 {
        let s = child(&[b'S', p], &base, ts(2), 0x20 + p);
        admit_ok(&store, &gd, &s).await;
        siblings.push(s.hash());
    }
    let (sp, merges, height, data) = gd
        .ghostdag_for_parents(&siblings)
        .await
        .expect("seven honest siblings are valid parents");
    assert_eq!(merges.len(), 6);
    assert!(data.mergeset_reds.is_empty(), "no honest sibling is red");
    assert_eq!(data.mergeset_blues.len(), 7);
    let next = build(Spec {
        id: hash_of(b"next"),
        sp,
        merges,
        height,
        score: data.blue_score,
        timestamp: ts(3),
        proposer: proposer(0x30),
        vrf: Hash::default(),
    });
    assert_eq!(next.header.blue_score, 2 + 7);
    admit_ok(&store, &gd, &next).await;
}
