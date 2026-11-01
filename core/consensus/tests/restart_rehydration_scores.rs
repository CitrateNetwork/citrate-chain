#![allow(clippy::type_complexity)]
// Fork-choice scores across a restart of a pruned node, on a DAG that merges
// at every height (the shape a multi-producer fleet builds).
//
// What is pinned:
//   * the fork-choice score of every retained block (the canonical chain AND
//     a side branch the eager load never visits) is the same after a restart
//     through the node's rehydration sequence as before it;
//   * fork choice picks the same tip;
//   * a peer block extending the tip, or merging the side tip, is admitted
//     after the restart, although genesis and every block below the pruning
//     point are absent from the DAG store;
//   * the gap between the fork-choice score and the header score is exactly the
//     number of blue merge parents on the selected chain: the producer writes
//     `parent + 1` into headers, fork choice counts blue merge parents.
//
// The rehydration sequence mirrors the node: the boot-time tip reconcile, then
// the producer's eager load (every canonical height from 0, through
// `register_existing_block`), then the reconcile again. On a pruned store the
// node's `store_block` of a pruned height fails (strict VRF: its parent is gone),
// so this test does not re-store those heights either.

use citrate_consensus::dag_store::{cf, KvOp, KvStore};
use citrate_consensus::types::{Block, BlockBuilder, GhostDagParams, Hash};
use citrate_consensus::{DagStore, GhostDag};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct MemKv {
    inner: Mutex<HashMap<(String, Vec<u8>), Vec<u8>>>,
    /// Reads of block bodies (`DAG_BLOCKS`): every one is a backend read plus
    /// a full-block decode on a live node.
    body_reads: AtomicUsize,
}

impl KvStore for MemKv {
    fn kv_get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        if cf == cf::DAG_BLOCKS {
            self.body_reads.fetch_add(1, Ordering::SeqCst);
        }
        Ok(self
            .inner
            .lock()
            .map_err(|e| e.to_string())?
            .get(&(cf.to_string(), key.to_vec()))
            .cloned())
    }
    fn kv_put(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<(), String> {
        self.inner
            .lock()
            .map_err(|e| e.to_string())?
            .insert((cf.to_string(), key.to_vec()), value.to_vec());
        Ok(())
    }
    fn kv_delete(&self, cf: &str, key: &[u8]) -> Result<(), String> {
        self.inner
            .lock()
            .map_err(|e| e.to_string())?
            .remove(&(cf.to_string(), key.to_vec()));
        Ok(())
    }
    fn kv_exists(&self, cf: &str, key: &[u8]) -> Result<bool, String> {
        Ok(self.kv_get(cf, key)?.is_some())
    }
    fn kv_iter_cf(&self, cf: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
        Ok(self
            .inner
            .lock()
            .map_err(|e| e.to_string())?
            .iter()
            .filter(|((c, _), _)| c == cf)
            .map(|((_, k), v)| (k.clone(), v.clone()))
            .collect())
    }
    fn kv_write_batch(&self, ops: &[KvOp]) -> Result<(), String> {
        for op in ops {
            match op {
                KvOp::Put { cf, key, value } => self.kv_put(cf, key, value)?,
                KvOp::Delete { cf, key } => self.kv_delete(cf, key)?,
            }
        }
        Ok(())
    }
}

fn hash(tag: u8, height: u64) -> Hash {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&height.to_be_bytes());
    h[31] = tag;
    Hash::new(h)
}

/// A block as the live producers write it: header blue_score = parent's + 1.
fn block(tag: u8, height: u64, parent: Hash, merges: Vec<Hash>) -> Block {
    BlockBuilder::new()
        .hash(hash(tag, height))
        .parent(parent)
        .merge_parents(merges)
        .height(height)
        .blue_score(height)
        .blue_work(citrate_consensus::types::blue_work_for_score(height))
        .build_unhashed()
}

const CANON: u8 = 0xA0;
const SIBLING: u8 = 0xB0;
const SIDE: u8 = 0xC0;
const PEER: u8 = 0xD0;

/// Canonical chain A_0..A_n where every A_h (h >= 2) merges the sibling
/// B_{h-1} (same selected parent as A_{h-1}), plus one unmerged side tip C at
/// `side_h` off A_{side_h - 1}. Returns (canonical, siblings, side tip).
fn build_dag(n: u64, side_h: u64) -> (Vec<Block>, Vec<Block>, Block) {
    let genesis = block(CANON, 0, Hash::default(), vec![]);
    let mut canon = vec![genesis];
    let mut sibs: Vec<Block> = Vec::new();
    for h in 1..=n {
        let sp = canon[(h - 1) as usize].hash();
        let merges = if h >= 2 {
            vec![sibs[(h - 2) as usize].hash()]
        } else {
            vec![]
        };
        canon.push(block(CANON, h, sp, merges));
        if h < n {
            sibs.push(block(SIBLING, h, sp, vec![]));
        }
    }
    let side = block(SIDE, side_h, canon[(side_h - 1) as usize].hash(), vec![]);
    (canon, sibs, side)
}

async fn admit(dag: &DagStore, gd: &GhostDag, b: &Block) {
    dag.store_block(b.clone()).await.expect("store");
    gd.add_block(b).await.expect("ghostdag admit");
}

#[tokio::test]
async fn restart_of_a_pruned_node_keeps_fork_choice_and_admits_peer_blocks() {
    const N: u64 = 320;
    const PRUNE_AT: u64 = 60;
    const SIDE_H: u64 = N - 3;

    let kv = Arc::new(MemKv::default());
    let (canon, sibs, side) = build_dag(N, SIDE_H);

    // ---- process 1: the live receive path ----
    let mut before: HashMap<Hash, u64> = HashMap::new();
    let tip_before;
    {
        let dag = Arc::new(DagStore::persistent_with_strict_vrf(kv.clone(), false).expect("store"));
        let gd = GhostDag::new(GhostDagParams::default(), dag.clone());
        admit(&dag, &gd, &canon[0]).await;
        for h in 1..=N {
            admit(&dag, &gd, &canon[h as usize]).await;
            if h < N {
                admit(&dag, &gd, &sibs[(h - 1) as usize]).await;
            }
            if h == SIDE_H {
                admit(&dag, &gd, &side).await;
            }
        }
        for b in canon
            .iter()
            .chain(sibs.iter())
            .chain(std::iter::once(&side))
        {
            if b.header.height >= PRUNE_AT {
                before.insert(b.hash(), gd.get_blue_score(&b.hash()).await.expect("score"));
            }
        }
        tip_before = gd.select_tip().await.expect("tip");
        assert_eq!(tip_before, canon[N as usize].hash());

        // The fork-choice score counts every blue merge parent; the header
        // carries parent + 1. For the tip that gap is the N - 1 merged siblings.
        let tip_score = before[&tip_before];
        assert_eq!(
            tip_score,
            canon[N as usize].header.blue_score + 1 + (N - 1),
            "fork-choice score = header + 1 + blue merge parents on the selected chain"
        );

        dag.update_pruning_point(canon[PRUNE_AT as usize].hash())
            .await
            .expect("pruning point");
        assert!(dag.prune().await.expect("prune") > 0);
    }

    // ---- process 2: restart through the node's rehydration sequence ----
    let dag = Arc::new(DagStore::persistent_with_strict_vrf(kv.clone(), false).expect("reload"));
    assert!(
        !dag.has_block(&canon[0].hash()).await,
        "genesis is below the pruning point and absent after the restart"
    );
    let gd = GhostDag::new(GhostDagParams::default(), dag.clone());
    gd.reconcile_tips_from_dag_store().await; // main.rs, before the producer
    for b in &canon {
        // A pruned height is not re-stored (the node's strict store refuses it:
        // its parent is gone); the producer registers it regardless.
        let _ = gd.register_existing_block(b).await;
    }
    gd.reconcile_tips_from_dag_store().await; // end of the producer's eager load

    for (h, score) in &before {
        assert_eq!(
            gd.fork_choice_score(h).await,
            Some(*score),
            "block {h}: a restart must not change its fork-choice score"
        );
    }
    assert_eq!(
        gd.select_tip().await.expect("tip"),
        tip_before,
        "a restart must not change fork choice"
    );

    // A peer extends the tip, and another merges the side tip, after the
    // restart. Both must be admitted and scored on the pre-restart scale.
    let tip = &canon[N as usize];
    let p1 = block(PEER, N + 1, tip.hash(), vec![]);
    gd.validate_block_consistency(&p1)
        .await
        .expect("peer block passes the consistency gate after a restart");
    admit(&dag, &gd, &p1).await;
    assert_eq!(
        gd.get_blue_score(&p1.hash()).await.ok(),
        Some(before[&tip.hash()] + 1)
    );

    let p2 = block(PEER + 1, N + 2, p1.hash(), vec![side.hash()]);
    gd.validate_block_consistency(&p2)
        .await
        .expect("merging the side tip passes the consistency gate after a restart");
    admit(&dag, &gd, &p2).await;
    assert_eq!(
        gd.get_blue_score(&p2.hash()).await.ok(),
        Some(before[&tip.hash()] + 1 + 1 + 1),
        "the side tip is blue (anticone within k) and counts once"
    );
}

/// After a restart every block loaded from the backend is a header-only
/// skeleton (bodies reload on demand), and `relations` holds only what the
/// eager load registered: the canonical chain. Pre-restart siblings inside the
/// merge-score window are in neither. Rehydration and the next admission must
/// not reload block bodies to score blocks: on a fleet that merges at every
/// height that is hundreds of backend reads and full decodes per block, which
/// stalls the eager load (the producer starts only after it) and the receive
/// path behind it.
#[tokio::test]
async fn restart_rehydration_and_the_next_admission_do_not_reload_block_bodies() {
    const N: u64 = 320;
    const PRUNE_AT: u64 = 60;
    const SIDE_H: u64 = N - 3;

    let kv = Arc::new(MemKv::default());
    let (canon, sibs, side) = build_dag(N, SIDE_H);
    let tip_score;
    {
        let dag = Arc::new(DagStore::persistent_with_strict_vrf(kv.clone(), false).expect("store"));
        let gd = GhostDag::new(GhostDagParams::default(), dag.clone());
        admit(&dag, &gd, &canon[0]).await;
        for h in 1..=N {
            admit(&dag, &gd, &canon[h as usize]).await;
            if h < N {
                admit(&dag, &gd, &sibs[(h - 1) as usize]).await;
            }
            if h == SIDE_H {
                admit(&dag, &gd, &side).await;
            }
        }
        tip_score = gd
            .get_blue_score(&canon[N as usize].hash())
            .await
            .expect("tip score");
        dag.update_pruning_point(canon[PRUNE_AT as usize].hash())
            .await
            .expect("pruning point");
        assert!(dag.prune().await.expect("prune") > 0);
    }

    let dag = Arc::new(DagStore::persistent_with_strict_vrf(kv.clone(), false).expect("reload"));
    let gd = GhostDag::new(GhostDagParams::default(), dag.clone());

    kv.body_reads.store(0, Ordering::SeqCst);
    gd.reconcile_tips_from_dag_store().await;
    for b in &canon {
        let _ = gd.register_existing_block(b).await;
    }
    gd.reconcile_tips_from_dag_store().await;
    let rehydration_reads = kv.body_reads.load(Ordering::SeqCst);
    assert!(
        rehydration_reads <= 8,
        "rehydrating {} canonical blocks reloaded {} block bodies; it must read the \
         durable score, not walk the merge-score window",
        canon.len(),
        rehydration_reads
    );

    // The next peer block merges the side tip, so its score walks the window.
    let tip = &canon[N as usize];
    let p1 = block(PEER, N + 1, tip.hash(), vec![side.hash()]);
    kv.body_reads.store(0, Ordering::SeqCst);
    gd.validate_block_consistency(&p1)
        .await
        .expect("consistency gate after a restart");
    admit(&dag, &gd, &p1).await;
    let admission_reads = kv.body_reads.load(Ordering::SeqCst);
    assert_eq!(
        gd.get_blue_score(&p1.hash()).await.ok(),
        Some(tip_score + 1 + 1),
        "scored on the pre-restart scale, the side tip blue"
    );
    assert!(
        admission_reads <= 8,
        "admitting one block after a restart reloaded {} block bodies; scoring reads \
         parent links, which every skeleton holds",
        admission_reads
    );
}

/// Per-block admission cost after a restart, at the shape of a fleet that
/// seals two siblings beside every canonical block (3 blocks per height, each
/// canonical block merging the previous height's two siblings), for both a
/// follower (only the tips are re-registered at boot) and a producer (the eager
/// load re-registers the canonical chain). Counts backend body reloads per
/// admitted block over the first window after the restart, and prints the
/// cost so a devnet apply rate can be compared against it.
#[tokio::test]
async fn admission_after_a_restart_costs_no_body_reloads_per_block() {
    const PRE: u64 = 900;
    const PRUNE_AT: u64 = 300;
    const POST: u64 = 250;

    fn sib(tag: u8, h: u64, sp: Hash) -> Block {
        block(tag, h, sp, vec![])
    }

    for producer_style in [false, true] {
        let kv = Arc::new(MemKv::default());
        let mut canon: Vec<Block> = vec![block(CANON, 0, Hash::default(), vec![])];
        let mut prev_sibs: Vec<Hash> = Vec::new();
        {
            let dag =
                Arc::new(DagStore::persistent_with_strict_vrf(kv.clone(), false).expect("store"));
            let gd = GhostDag::new(GhostDagParams::default(), dag.clone());
            admit(&dag, &gd, &canon[0]).await;
            for h in 1..=PRE {
                let sp = canon[(h - 1) as usize].hash();
                let c = block(CANON, h, sp, std::mem::take(&mut prev_sibs));
                let s1 = sib(SIBLING, h, sp);
                let s2 = sib(SIDE, h, sp);
                for b in [&c, &s1, &s2] {
                    admit(&dag, &gd, b).await;
                }
                prev_sibs = vec![s1.hash(), s2.hash()];
                canon.push(c);
            }
            dag.update_pruning_point(canon[PRUNE_AT as usize].hash())
                .await
                .expect("pruning point");
            assert!(dag.prune().await.expect("prune") > 0);
        }

        let dag =
            Arc::new(DagStore::persistent_with_strict_vrf(kv.clone(), false).expect("reload"));
        let gd = GhostDag::new(GhostDagParams::default(), dag.clone());
        let boot = std::time::Instant::now();
        kv.body_reads.store(0, Ordering::SeqCst);
        gd.reconcile_tips_from_dag_store().await;
        if producer_style {
            for b in &canon {
                let _ = gd.register_existing_block(b).await;
            }
            gd.reconcile_tips_from_dag_store().await;
        }
        let boot_reads = kv.body_reads.load(Ordering::SeqCst);
        let boot_time = boot.elapsed();

        let mut first_window_reads = 0usize;
        let mut first_window_blocks = 0usize;
        let started = std::time::Instant::now();
        let mut first_window_time = std::time::Duration::ZERO;
        for h in (PRE + 1)..=(PRE + POST) {
            let sp = canon[(h - 1) as usize].hash();
            let c = block(PEER, h, sp, std::mem::take(&mut prev_sibs));
            let s1 = sib(PEER + 1, h, sp);
            let s2 = sib(PEER + 2, h, sp);
            kv.body_reads.store(0, Ordering::SeqCst);
            for b in [&c, &s1, &s2] {
                gd.validate_block_consistency(b)
                    .await
                    .expect("consistency gate");
                admit(&dag, &gd, b).await;
            }
            if h <= PRE + 200 {
                first_window_reads += kv.body_reads.load(Ordering::SeqCst);
                first_window_blocks += 3;
                first_window_time = started.elapsed();
            }
            prev_sibs = vec![s1.hash(), s2.hash()];
            canon.push(c);
        }
        let total = started.elapsed();
        let per_block_reads = first_window_reads as f64 / first_window_blocks as f64;
        eprintln!(
            "restart cost ({}): boot {} body reloads in {:?}; first 200 heights after the \
             restart: {:.1} body reloads/block, {:?}/block; all {} heights: {:?}/block",
            if producer_style {
                "producer"
            } else {
                "follower"
            },
            boot_reads,
            boot_time,
            per_block_reads,
            first_window_time / first_window_blocks as u32,
            POST,
            total / (POST * 3) as u32
        );
        assert!(
            per_block_reads <= 4.0,
            "{}: {per_block_reads:.1} body reloads per admitted block after a restart",
            if producer_style {
                "producer"
            } else {
                "follower"
            }
        );
    }
}
