//! S3-1 / ADR CV-3: one blue score, committed in the header, validated at
//! admission, read by fork choice. Spec: planset 2026-11-03-r1007-v060,
//! `06_CONSENSUS_SPEC.md` §2 (G2, G3, G4, G6, G7, G8, G12).
//!
//! Every test here builds headers by hand with the values the spec defines
//! and checks the verdict admission reaches on them. None of them reads a
//! score the implementation computed to build its own expectation.
//!
//! `coloring_matches_kaspa_vectors` runs the GHOSTDAG test DAGs of
//! rusty-kaspa (kaspanet/rusty-kaspa af6ff23a,
//! `testing/integration/testdata/dags/dag0..5.json`, ISC License,
//! Copyright (c) 2022-2024 Kaspa developers), copied unmodified into
//! `tests/fixtures/kaspa_ghostdag/`. Kaspa's genesis has blue score 0, as the
//! spec's does (G7), so the expected scores apply as they are. Kaspa orders
//! blocks by (blue_work, hash); the spec orders by (blue_work, vrf_output,
//! hash), which is the same order when every VRF output is zero, as here.

use citrate_consensus::dag_store::{DagStore, KvStore};
use citrate_consensus::ghostdag::GhostDag;
use citrate_consensus::types::{
    blue_work_for_score, Block, BlockBuilder, GhostDagParams, Hash, VrfProof,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

fn hash_of(tag: &[u8]) -> Hash {
    let mut b = [0u8; 32];
    for (d, s) in b.iter_mut().zip(tag.iter()) {
        *d = *s;
    }
    Hash::new(b)
}

/// A header-only block: `height` and the committed `score` as given, work
/// derived from the score (G7 unit work), VRF output `vrf`.
fn block(id: Hash, sp: Hash, merges: Vec<Hash>, height: u64, score: u64, vrf: Hash) -> Block {
    BlockBuilder::new()
        .hash(id)
        .parent(sp)
        .merge_parents(merges)
        .height(height)
        .blue_score(score)
        .blue_work(blue_work_for_score(score))
        .vrf_reveal(VrfProof {
            proof: Vec::new(),
            output: vrf,
        })
        .build_unhashed()
}

fn genesis(id: Hash) -> Block {
    block(id, Hash::default(), Vec::new(), 0, 0, Hash::default())
}

fn engine(k: u32) -> (Arc<DagStore>, GhostDag) {
    let store = Arc::new(DagStore::with_permissive_vrf_for_testing());
    let params = GhostDagParams {
        k,
        ..GhostDagParams::default()
    };
    let gd = GhostDag::new(params, store.clone());
    (store, gd)
}

/// The production admission order: consistency gate, DAG write, fork-choice
/// registration (`node/src/admission.rs`).
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
            "block {} @ {} (score {}) must be admitted: {e}",
            b.hash(),
            b.header.height,
            b.header.blue_score
        );
    }
}

async fn verdict(gd: &GhostDag, b: &Block) -> Result<(), String> {
    gd.validate_block_consistency(b)
        .await
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// G7: the committed score is the exact GHOSTDAG value
// ---------------------------------------------------------------------------

/// Two siblings A, B at height 1 (score 1 each). C merges both: its mergeset
/// is {SP, other}, both blue, so blue_score(C) = 1 + 2 = 3, and only 3. The
/// old band `[sp+1, sp+1+|merges|]` = [2, 3] accepted 2 as well.
#[tokio::test]
async fn header_score_mismatch_rejected() {
    let (store, gd) = engine(18);
    let g = genesis(hash_of(b"G"));
    admit_ok(&store, &gd, &g).await;
    let a = block(hash_of(b"A"), g.hash(), vec![], 1, 1, Hash::default());
    let b = block(hash_of(b"B"), g.hash(), vec![], 1, 1, Hash::default());
    admit_ok(&store, &gd, &a).await;
    admit_ok(&store, &gd, &b).await;
    // Key ties on work and VRF, so the larger hash ("B") is the selected parent.
    let c = |score: u64| {
        block(
            hash_of(b"C"),
            b.hash(),
            vec![a.hash()],
            2,
            score,
            Hash::default(),
        )
    };
    for wrong in [0u64, 1, 2, 4, 5, u64::MAX / 2] {
        assert!(
            verdict(&gd, &c(wrong)).await.is_err(),
            "header blue_score {wrong} is not the GHOSTDAG score (3) and must be rejected"
        );
    }
    assert_eq!(
        verdict(&gd, &c(3)).await,
        Ok(()),
        "the exact score is admitted"
    );
}

/// Work is the score times WORK_UNIT; any other value is rejected even when
/// the score is right.
#[tokio::test]
async fn header_blue_work_mismatch_rejected() {
    let (store, gd) = engine(18);
    let g = genesis(hash_of(b"G"));
    admit_ok(&store, &gd, &g).await;
    let mut a = block(hash_of(b"A"), g.hash(), vec![], 1, 1, Hash::default());
    for wrong in [0u128, blue_work_for_score(2), blue_work_for_score(1) + 1] {
        a.header.blue_work = wrong;
        assert!(
            verdict(&gd, &a).await.is_err(),
            "blue_work {wrong} rejected"
        );
    }
    a.header.blue_work = blue_work_for_score(1);
    assert_eq!(verdict(&gd, &a).await, Ok(()));
}

// ---------------------------------------------------------------------------
// G2: parents are an antichain
// ---------------------------------------------------------------------------

#[tokio::test]
async fn parents_that_are_ancestors_rejected() {
    let (store, gd) = engine(18);
    let g = genesis(hash_of(b"G"));
    admit_ok(&store, &gd, &g).await;
    let a1 = block(hash_of(b"z1"), g.hash(), vec![], 1, 1, Hash::default());
    let a2 = block(hash_of(b"z2"), a1.hash(), vec![], 2, 2, Hash::default());
    let m1 = block(hash_of(b"m1"), g.hash(), vec![], 1, 1, Hash::default());
    let m2 = block(hash_of(b"m2"), m1.hash(), vec![], 2, 2, Hash::default());
    for b in [&a1, &a2, &m1, &m2] {
        admit_ok(&store, &gd, b).await;
    }
    // The z chain is heavier than the m chain at equal work (larger hash).
    // Case 1: the merge parent z1 is in the past of the selected parent z2.
    // It adds nothing to the mergeset, so the only plausible score is 3.
    for score in [3u64, 4] {
        let x = block(
            hash_of(b"x1"),
            a2.hash(),
            vec![a1.hash()],
            3,
            score,
            Hash::default(),
        );
        let why = verdict(&gd, &x)
            .await
            .expect_err("a merge parent in the past of the selected parent must be rejected");
        assert!(why.contains("antichain"), "score {score}: {why}");
    }
    // Case 2: one merge parent (m1) is in the past of another (m2). Both are
    // outside past(z2), so the mergeset is {m1, m2} however they are listed.
    for score in [3u64, 4, 5] {
        let x = block(
            hash_of(b"x2"),
            a2.hash(),
            vec![m1.hash(), m2.hash()],
            3,
            score,
            Hash::default(),
        );
        let why = verdict(&gd, &x)
            .await
            .expect_err("a merge parent in the past of another merge parent must be rejected");
        assert!(why.contains("antichain"), "score {score}: {why}");
    }
    // Case 3: the selected parent is in the past of a merge parent. The merge
    // parent is then heavier, so this is also a G3 violation.
    let x = block(
        hash_of(b"x3"),
        a1.hash(),
        vec![a2.hash()],
        2,
        4,
        Hash::default(),
    );
    assert!(verdict(&gd, &x).await.is_err());
    // Control: the same parents without the redundant one are admitted.
    let ok = block(
        hash_of(b"x4"),
        a2.hash(),
        vec![m2.hash()],
        3,
        5,
        Hash::default(),
    );
    assert_eq!(
        verdict(&gd, &ok).await,
        Ok(()),
        "z2 + m2 (mergeset z2, m1, m2) scores 2 + 3"
    );
}

// ---------------------------------------------------------------------------
// G3 / G8: the selected parent is derived, and fork choice uses the same Key
// ---------------------------------------------------------------------------

#[tokio::test]
async fn selected_parent_is_derived_heaviest() {
    let (store, gd) = engine(18);
    let g = genesis(hash_of(b"G"));
    admit_ok(&store, &gd, &g).await;

    // Tie on blue_work and VRF output: the larger hash is heavier.
    let lo = block(hash_of(b"\x10lo"), g.hash(), vec![], 1, 1, Hash::default());
    let hi = block(hash_of(b"\x20hi"), g.hash(), vec![], 1, 1, Hash::default());
    admit_ok(&store, &gd, &lo).await;
    admit_ok(&store, &gd, &hi).await;
    let wrong = block(
        hash_of(b"w1"),
        lo.hash(),
        vec![hi.hash()],
        2,
        3,
        Hash::default(),
    );
    assert!(
        verdict(&gd, &wrong).await.is_err(),
        "the selected parent must be the parent with the largest (blue_work, vrf, hash)"
    );
    let right = block(
        hash_of(b"w2"),
        hi.hash(),
        vec![lo.hash()],
        2,
        3,
        Hash::default(),
    );
    assert_eq!(verdict(&gd, &right).await, Ok(()));
    assert_eq!(
        gd.select_tip().await.expect("tip"),
        hi.hash(),
        "fork choice breaks the tie the same way the header rule does"
    );

    // Tie on blue_work, different VRF outputs: the VRF decides before the
    // hash (the hash is grindable, the VRF output is not).
    let (store, gd) = engine(18);
    admit_ok(&store, &gd, &g).await;
    let v_hi = block(hash_of(b"\x10vh"), g.hash(), vec![], 1, 1, hash_of(b"\xF0"));
    let v_lo = block(hash_of(b"\x20vl"), g.hash(), vec![], 1, 1, hash_of(b"\x01"));
    admit_ok(&store, &gd, &v_hi).await;
    admit_ok(&store, &gd, &v_lo).await;
    let wrong = block(
        hash_of(b"w3"),
        v_lo.hash(),
        vec![v_hi.hash()],
        2,
        3,
        Hash::default(),
    );
    assert!(
        verdict(&gd, &wrong).await.is_err(),
        "the larger VRF output wins the tie, whatever the hashes"
    );
    let right = block(
        hash_of(b"w4"),
        v_hi.hash(),
        vec![v_lo.hash()],
        2,
        3,
        Hash::default(),
    );
    assert_eq!(verdict(&gd, &right).await, Ok(()));
    assert_eq!(gd.select_tip().await.expect("tip"), v_hi.hash());

    // Strictly more blue work always wins, regardless of VRF and hash.
    let (store, gd) = engine(18);
    admit_ok(&store, &gd, &g).await;
    let s1 = block(hash_of(b"\xFFs1"), g.hash(), vec![], 1, 1, hash_of(b"\xFF"));
    let t1 = block(hash_of(b"\x01t1"), g.hash(), vec![], 1, 1, Hash::default());
    let t2 = block(hash_of(b"\x01t2"), t1.hash(), vec![], 2, 2, Hash::default());
    for b in [&s1, &t1, &t2] {
        admit_ok(&store, &gd, b).await;
    }
    let wrong = block(
        hash_of(b"w5"),
        s1.hash(),
        vec![t2.hash()],
        2,
        4,
        Hash::default(),
    );
    assert!(verdict(&gd, &wrong).await.is_err());
    let right = block(
        hash_of(b"w6"),
        t2.hash(),
        vec![s1.hash()],
        3,
        4,
        Hash::default(),
    );
    assert_eq!(verdict(&gd, &right).await, Ok(()));
}

// ---------------------------------------------------------------------------
// G4: mergeset size bound
// ---------------------------------------------------------------------------

/// A main chain of 25 blocks and `side` side chains from genesis, merged in
/// one block. Side chain `i` has `lens[i]` blocks.
async fn wide_merge(lens: &[u64]) -> (Arc<DagStore>, GhostDag, Hash, Vec<Hash>) {
    let (store, gd) = engine(18);
    let g = genesis(hash_of(b"G"));
    admit_ok(&store, &gd, &g).await;
    let mut tip = g.hash();
    for h in 1..=25u64 {
        let mut id = [0u8; 32];
        id[0] = 0xEE;
        id[1..9].copy_from_slice(&h.to_be_bytes());
        let b = block(Hash::new(id), tip, vec![], h, h, Hash::default());
        admit_ok(&store, &gd, &b).await;
        tip = b.hash();
    }
    let mut side_tips = Vec::new();
    for (i, len) in lens.iter().enumerate() {
        let mut t = g.hash();
        for h in 1..=*len {
            let mut id = [0u8; 32];
            id[0] = 0x11;
            id[1] = i as u8;
            id[2..10].copy_from_slice(&h.to_be_bytes());
            let b = block(Hash::new(id), t, vec![], h, h, Hash::default());
            admit_ok(&store, &gd, &b).await;
            t = b.hash();
        }
        side_tips.push(t);
    }
    (store, gd, tip, side_tips)
}

#[tokio::test]
async fn mergeset_exceeding_bound_rejected() {
    // 9 side chains of 20 + the selected parent: |Mergeset| = 181 > 180.
    let (_store, gd, tip, sides) = wide_merge(&[20; 9]).await;
    for score in 26..=45u64 {
        let b = block(
            hash_of(b"big"),
            tip,
            sides.clone(),
            26,
            score,
            Hash::default(),
        );
        let v = verdict(&gd, &b).await;
        assert!(
            v.is_err(),
            "a mergeset of 181 blocks exceeds MERGESET_SIZE_LIMIT (180) and must be \
             rejected whatever the header claims (score {score})"
        );
    }
    // At the bound (179 side blocks + SP = 180) the size rule does not fire:
    // the verdict on a deliberately wrong score names the score, not the size.
    let (_store, gd, tip, sides) = wide_merge(&[20, 20, 20, 20, 20, 20, 20, 20, 19]).await;
    let b = block(hash_of(b"edge"), tip, sides, 26, 1, Hash::default());
    let why = verdict(&gd, &b)
        .await
        .expect_err("score 1 is wrong for any mergeset");
    assert!(
        !why.to_lowercase().contains("mergeset"),
        "a mergeset of exactly 180 is within the bound: {why}"
    );
}

// ---------------------------------------------------------------------------
// G6: coloring over the whole mergeset, both k-cluster conditions
// ---------------------------------------------------------------------------

/// Main chain G-A-B-C, side chain G-S1-S2. D (SP = C) merges S2 only; S1 is an
/// unmerged ancestor of S2 outside past(C), so Mergeset*(D) = {S1, S2}, both
/// blue at K = 18: blue_score(D) = 3 + 3 = 6. Coloring only the direct merge
/// parent gives 5.
#[tokio::test]
async fn unmerged_ancestor_of_merge_parent_is_colored() {
    let (store, gd) = engine(18);
    let g = genesis(hash_of(b"G"));
    admit_ok(&store, &gd, &g).await;
    let a = block(hash_of(b"\xA0"), g.hash(), vec![], 1, 1, Hash::default());
    let b = block(hash_of(b"\xA1"), a.hash(), vec![], 2, 2, Hash::default());
    let c = block(hash_of(b"\xA2"), b.hash(), vec![], 3, 3, Hash::default());
    let s1 = block(hash_of(b"\x51"), g.hash(), vec![], 1, 1, Hash::default());
    let s2 = block(hash_of(b"\x52"), s1.hash(), vec![], 2, 2, Hash::default());
    for x in [&a, &b, &c, &s1, &s2] {
        admit_ok(&store, &gd, x).await;
    }
    let d = |score| {
        block(
            hash_of(b"D"),
            c.hash(),
            vec![s2.hash()],
            4,
            score,
            Hash::default(),
        )
    };
    for wrong in [4u64, 5, 7] {
        assert!(verdict(&gd, &d(wrong)).await.is_err(), "score {wrong}");
    }
    admit_ok(&store, &gd, &d(6)).await;
    assert_eq!(gd.get_blue_score(&d(6).hash()).await.expect("ranked"), 6);
    let data = gd.ghostdag_data(&d(6).hash()).await.expect("record");
    assert_eq!(data.mergeset_blues, vec![c.hash(), s1.hash(), s2.hash()]);
    assert!(data.mergeset_reds.is_empty());
}

/// K = 2. b1, b2, b3 are siblings at height 1. P (SP b1) merges b2 and b3:
/// three mutually-anticone blues, so b1's blue anticone is {b2, b3}, size K.
/// c1 (SP b3) merges b2. B (SP P) merges c1: c1's blue anticone in B is {P,
/// b1} (b2 and b3 are in its past), size 2 <= K, so the first k-cluster
/// condition alone colors it blue. But b1 already has K blues in its
/// anticone, so adding c1 would give b1 K + 1: the second condition colors c1
/// red. blue_score(B) = blue_score(P) + |{P}| = 4 + 1 = 5, not 6.
#[tokio::test]
async fn second_kcluster_condition_turns_candidate_red() {
    let (store, gd) = engine(2);
    let g = genesis(hash_of(b"G"));
    admit_ok(&store, &gd, &g).await;
    let b2 = block(hash_of(b"\x10b2"), g.hash(), vec![], 1, 1, Hash::default());
    let b3 = block(hash_of(b"\x20b3"), g.hash(), vec![], 1, 1, Hash::default());
    let b1 = block(hash_of(b"\x30b1"), g.hash(), vec![], 1, 1, Hash::default());
    for x in [&b1, &b2, &b3] {
        admit_ok(&store, &gd, x).await;
    }
    // P: mergeset {b1, b2, b3}, all blue: 1 + 3.
    let p = block(
        hash_of(b"\x40P"),
        b1.hash(),
        vec![b2.hash(), b3.hash()],
        2,
        4,
        Hash::default(),
    );
    admit_ok(&store, &gd, &p).await;
    // c1: mergeset {b3, b2}: 1 + 2.
    let c1 = block(
        hash_of(b"\x50c1"),
        b3.hash(),
        vec![b2.hash()],
        2,
        3,
        Hash::default(),
    );
    admit_ok(&store, &gd, &c1).await;
    let bb = |score| {
        block(
            hash_of(b"\x60B"),
            p.hash(),
            vec![c1.hash()],
            3,
            score,
            Hash::default(),
        )
    };
    assert!(
        verdict(&gd, &bb(6)).await.is_err(),
        "c1 is red by the second k-cluster condition; a header counting it blue is wrong"
    );
    admit_ok(&store, &gd, &bb(5)).await;
    assert_eq!(gd.get_blue_score(&bb(5).hash()).await.expect("ranked"), 5);
    let data = gd.ghostdag_data(&bb(5).hash()).await.expect("record");
    assert_eq!(data.mergeset_blues, vec![p.hash()]);
    assert_eq!(data.mergeset_reds, vec![c1.hash()]);
    // The first condition alone would have colored c1 blue: its blue
    // anticone in B is {P, b1}, two blocks, within K.
    let p_data = gd.ghostdag_data(&p.hash()).await.expect("record");
    assert_eq!(p_data.blues_anticone_sizes.get(&b1.hash()), Some(&2));
}

#[derive(serde::Deserialize)]
struct KaspaDag {
    #[serde(rename = "K")]
    k: u32,
    #[serde(rename = "GenesisID")]
    genesis_id: String,
    #[serde(rename = "Blocks")]
    blocks: Vec<KaspaBlock>,
}

#[derive(serde::Deserialize)]
struct KaspaBlock {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "ExpectedScore")]
    score: u64,
    #[serde(rename = "ExpectedSelectedParent")]
    selected_parent: String,
    #[serde(rename = "ExpectedReds")]
    reds: Vec<String>,
    #[serde(rename = "ExpectedBlues")]
    blues: Vec<String>,
    #[serde(rename = "Parents")]
    parents: Vec<String>,
}

/// Kaspa's `string_to_hash`: the id's bytes, zero-padded to 32.
fn kaspa_hash(id: &str) -> Hash {
    hash_of(id.as_bytes())
}

/// Each vector block is built with Kaspa's expected selected parent and blue
/// score, and must be admitted; the same block with any other score, or with
/// another parent named as the selected parent, must be rejected.
#[tokio::test]
async fn coloring_matches_kaspa_vectors() {
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kaspa_ghostdag");
    for n in 0..=5 {
        let path = dir.join(format!("dag{n}.json"));
        let raw = std::fs::read_to_string(&path).expect("vector file");
        let dag: KaspaDag = serde_json::from_str(&raw).expect("vector json");
        let (store, gd) = engine(dag.k);
        let g = genesis(kaspa_hash(&dag.genesis_id));
        admit_ok(&store, &gd, &g).await;
        let mut height: HashMap<String, u64> = HashMap::new();
        height.insert(dag.genesis_id.clone(), 0);
        for kb in &dag.blocks {
            let sp = kaspa_hash(&kb.selected_parent);
            let merges: Vec<Hash> = kb
                .parents
                .iter()
                .filter(|p| **p != kb.selected_parent)
                .map(|p| kaspa_hash(p))
                .collect();
            let h = height[&kb.selected_parent] + 1;
            let mk = |score| {
                block(
                    kaspa_hash(&kb.id),
                    sp,
                    merges.clone(),
                    h,
                    score,
                    Hash::default(),
                )
            };
            for wrong in [kb.score.saturating_sub(1), kb.score + 1] {
                if wrong != kb.score {
                    assert!(
                        verdict(&gd, &mk(wrong)).await.is_err(),
                        "dag{n} {}: score {wrong} accepted, Kaspa says {}",
                        kb.id,
                        kb.score
                    );
                }
            }
            if let Some(other) = kb.parents.iter().find(|p| **p != kb.selected_parent) {
                let mut swapped_merges: Vec<Hash> = kb
                    .parents
                    .iter()
                    .filter(|p| *p != other)
                    .map(|p| kaspa_hash(p))
                    .collect();
                swapped_merges.sort();
                let swapped = block(
                    kaspa_hash(&kb.id),
                    kaspa_hash(other),
                    swapped_merges,
                    height[other] + 1,
                    kb.score,
                    Hash::default(),
                );
                assert!(
                    verdict(&gd, &swapped).await.is_err(),
                    "dag{n} {}: {other} named as selected parent, Kaspa says {}",
                    kb.id,
                    kb.selected_parent
                );
            }
            let b = mk(kb.score);
            if let Err(e) = admit(&store, &gd, &b).await {
                panic!("dag{n} {}: Kaspa's score {} rejected: {e}", kb.id, kb.score);
            }
            height.insert(kb.id.clone(), h);
        }
        // The persisted records match Kaspa's mergeset coloring and order
        // (SP first, then ascending Key), read back by a fresh engine.
        let fresh = GhostDag::new(
            GhostDagParams {
                k: dag.k,
                ..GhostDagParams::default()
            },
            store.clone(),
        );
        for kb in &dag.blocks {
            let id = kaspa_hash(&kb.id);
            for engine_view in [&gd, &fresh] {
                let data = engine_view.ghostdag_data(&id).await.expect("record");
                let names = |v: &[String]| v.iter().map(|x| kaspa_hash(x)).collect::<Vec<_>>();
                assert_eq!(
                    data.selected_parent,
                    kaspa_hash(&kb.selected_parent),
                    "dag{n} {}",
                    kb.id
                );
                assert_eq!(
                    data.mergeset_blues,
                    names(&kb.blues),
                    "dag{n} {} blues",
                    kb.id
                );
                assert_eq!(data.mergeset_reds, names(&kb.reds), "dag{n} {} reds", kb.id);
                assert_eq!(data.blue_score, kb.score, "dag{n} {}", kb.id);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// G12: a pruned, restarted node validates new headers from committed values
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MemKv {
    #[allow(clippy::type_complexity)]
    data: Mutex<HashMap<String, HashMap<Vec<u8>, Vec<u8>>>>,
}

impl KvStore for MemKv {
    fn kv_get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let d = self.data.lock().map_err(|e| e.to_string())?;
        Ok(d.get(cf).and_then(|m| m.get(key).cloned()))
    }
    fn kv_put(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<(), String> {
        let mut d = self.data.lock().map_err(|e| e.to_string())?;
        d.entry(cf.to_string())
            .or_default()
            .insert(key.to_vec(), value.to_vec());
        Ok(())
    }
    fn kv_delete(&self, cf: &str, key: &[u8]) -> Result<(), String> {
        let mut d = self.data.lock().map_err(|e| e.to_string())?;
        if let Some(m) = d.get_mut(cf) {
            m.remove(key);
        }
        Ok(())
    }
    fn kv_exists(&self, cf: &str, key: &[u8]) -> Result<bool, String> {
        Ok(self.kv_get(cf, key)?.is_some())
    }
    fn kv_iter_cf(&self, cf: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
        let d = self.data.lock().map_err(|e| e.to_string())?;
        Ok(d.get(cf)
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default())
    }
}

fn layer_id(h: u64, side: u8) -> Hash {
    let mut id = [0u8; 32];
    id[0] = side;
    id[1..9].copy_from_slice(&h.to_be_bytes());
    id[31] = 0x7A;
    Hash::new(id)
}

/// Two producers per height, each naming both blocks of the height below as
/// parents. The selected parent is the heavier of the two (equal work and VRF,
/// so the larger hash: side 0xB0), the other is the only mergeset block and
/// is blue, so every block at height h >= 1 scores 2h - 1.
fn two_wide(height: u64) -> Vec<Block> {
    let g = genesis(layer_id(0, 0x01));
    let mut all = vec![g.clone()];
    let mut prev = vec![g.hash()];
    for h in 1..=height {
        let (sp, merges) = if prev.len() == 1 {
            (prev[0], vec![])
        } else {
            (prev[1], vec![prev[0]])
        };
        let score = 2 * h - 1;
        let mut layer = Vec::new();
        for side in [0xA0u8, 0xB0] {
            let b = block(
                layer_id(h, side),
                sp,
                merges.clone(),
                h,
                score,
                Hash::default(),
            );
            layer.push(b.hash());
            all.push(b);
        }
        prev = layer;
    }
    all
}

async fn persistent(kv: Arc<MemKv>) -> Arc<DagStore> {
    Arc::new(DagStore::persistent_with_strict_vrf(kv, false).expect("persistent store"))
}

#[tokio::test]
async fn pruned_node_validates_new_headers_from_committed_values() {
    const TOP: u64 = 300;
    const FLOOR: u64 = 90; // below TOP + 1 - GHOSTDAG_WINDOW (200)
    let blocks = two_wide(TOP);
    let parents = |b: &[Block]| {
        let top: Vec<&Block> = b.iter().filter(|x| x.header.height == TOP).collect();
        (top[1].hash(), top[0].hash())
    };
    let (sp, mp) = parents(&blocks);
    let next = |score| {
        block(
            hash_of(b"next"),
            sp,
            vec![mp],
            TOP + 1,
            score,
            Hash::default(),
        )
    };

    // First process: admit everything, then prune below FLOOR.
    let kv = Arc::new(MemKv::default());
    {
        let store = persistent(kv.clone()).await;
        let gd = GhostDag::new(GhostDagParams::default(), store.clone());
        for b in &blocks {
            admit_ok(&store, &gd, b).await;
        }
        let floor = blocks
            .iter()
            .find(|b| b.header.height == FLOOR)
            .expect("floor block")
            .hash();
        store.update_pruning_point(floor).await.expect("pp");
        assert!(store.prune().await.expect("prune") > 0);
    }

    // Second process over the pruned store, rehydrated the production way.
    let store = persistent(kv.clone()).await;
    let gd = GhostDag::new(GhostDagParams::default(), store.clone());
    for b in blocks.iter().filter(|b| b.header.height >= FLOOR) {
        gd.register_existing_block(b)
            .await
            .expect("a retained block registers from its committed header");
    }
    gd.reconcile_tips_from_dag_store().await;

    // Fork choice ranks on the committed values.
    for t in gd.get_tips().await {
        let header = store.get_header(&t).await.expect("tip header");
        assert_eq!(
            gd.get_blue_score(&t).await.expect("tip ranked"),
            header.blue_score,
            "fork choice must rank a tip on its committed blue_score"
        );
    }
    assert_eq!(gd.select_tip().await.expect("tip"), sp);

    // A new header on top is judged exactly as an unpruned node judges it.
    let exact = 2 * (TOP + 1) - 1;
    for wrong in [exact - 1, exact + 1] {
        assert!(verdict(&gd, &next(wrong)).await.is_err(), "score {wrong}");
    }
    assert_eq!(
        verdict(&gd, &next(exact)).await,
        Ok(()),
        "the pruned node must validate the next block from its window alone"
    );
    admit_ok(&store, &gd, &next(exact)).await;
    assert_eq!(gd.select_tip().await.expect("tip"), next(exact).hash());
    assert_eq!(
        gd.get_blue_score(&next(exact).hash())
            .await
            .expect("ranked"),
        exact
    );
}
