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

use citrate_consensus::dag_store::{KvOp, KvStore};
use citrate_consensus::types::{Block, BlockBuilder, GhostDagParams, Hash};
use citrate_consensus::{DagStore, GhostDag};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct MemKv {
    inner: Mutex<HashMap<(String, Vec<u8>), Vec<u8>>>,
}

impl KvStore for MemKv {
    fn kv_get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
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
        for b in canon.iter().chain(sibs.iter()).chain(std::iter::once(&side)) {
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
    assert_eq!(gd.get_blue_score(&p1.hash()).await.ok(), Some(before[&tip.hash()] + 1));

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
