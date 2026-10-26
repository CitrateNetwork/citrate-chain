// Behaviour of the bounded body window in a persistent DagStore: the cap holds,
// every body still reads back byte-identical (from memory or the backend), a
// restart loads skeletons only, a missing backend body fails closed, and an
// in-memory store (nothing to reload from) never strips.

use citrate_consensus::dag_store::{cf, KvOp, KvStore};
use citrate_consensus::types::{Block, BlockBuilder, Hash, PublicKey, Transaction};
use citrate_consensus::DagStore;
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

fn block(height: u64, parent: Hash, txs: usize) -> Block {
    let mut hb = [0u8; 32];
    hb[..8].copy_from_slice(&height.to_be_bytes());
    hb[31] = 0xD1;
    let txs: Vec<Transaction> = (0..txs)
        .map(|i| {
            let mut th = [0u8; 32];
            th[..8].copy_from_slice(&height.to_be_bytes());
            th[8..16].copy_from_slice(&(i as u64).to_be_bytes());
            Transaction {
                hash: Hash::new(th),
                nonce: i as u64,
                from: PublicKey::new([3u8; 32]),
                data: vec![height as u8; 64],
                ..Default::default()
            }
        })
        .collect();
    BlockBuilder::new()
        .hash(Hash::new(hb))
        .height(height)
        .parent(parent)
        .transactions(txs)
        .learning_embedding(Some(vec![0.5; 16]))
        .build_unhashed()
}

fn bytes(b: &Block) -> Vec<u8> {
    bincode::serialize(b).expect("serialize")
}

async fn fill(store: &DagStore, n: u64, txs: usize) -> Vec<Block> {
    let mut parent = Hash::default();
    let mut out = Vec::new();
    for h in 1..=n {
        let b = block(h, parent, txs);
        parent = b.hash();
        store.store_block(b.clone()).await.expect("store");
        out.push(b);
    }
    out
}

#[tokio::test]
async fn cap_holds_and_every_body_reads_back_identical() {
    let kv = Arc::new(MemKv::default());
    let store = DagStore::persistent_with_strict_vrf(kv, false)
        .expect("store")
        .with_resident_body_cap(8);
    let blocks = fill(&store, 50, 5).await;
    assert_eq!(
        store.resident_body_count(),
        8,
        "resident bodies exceed the cap"
    );
    for b in &blocks {
        let got = store.get_block(&b.hash()).await.expect("get");
        assert_eq!(bytes(&got), bytes(b), "block {} changed", b.header.height);
        let at = store.get_blocks_at_height(b.header.height).await;
        assert_eq!(at.len(), 1);
        assert_eq!(bytes(&at[0]), bytes(b));
    }
    // Skeleton readers still see headers for stripped blocks.
    assert!(store.has_block(&blocks[0].hash()).await);
    assert_eq!(
        store.get_parents(&blocks[1].hash()).await.expect("parents"),
        vec![blocks[0].hash()]
    );
}

#[tokio::test]
async fn cap_zero_strips_every_body_and_still_reads_back() {
    let kv = Arc::new(MemKv::default());
    let store = DagStore::persistent_with_strict_vrf(kv, false)
        .expect("store")
        .with_resident_body_cap(0);
    let blocks = fill(&store, 10, 3).await;
    assert_eq!(store.resident_body_count(), 0);
    for b in &blocks {
        assert_eq!(
            bytes(&store.get_block(&b.hash()).await.expect("get")),
            bytes(b)
        );
    }
}

#[tokio::test]
async fn restart_loads_skeletons_and_reloads_bodies() {
    let kv = Arc::new(MemKv::default());
    let blocks = {
        let store = DagStore::persistent_with_strict_vrf(kv.clone(), false).expect("store");
        fill(&store, 20, 4).await
    };
    let reopened = DagStore::persistent_with_strict_vrf(kv, false).expect("reopen");
    assert_eq!(
        reopened.resident_body_count(),
        0,
        "restart must not load bodies"
    );
    assert_eq!(reopened.get_stats().await.total_blocks, 20);
    for b in &blocks {
        assert_eq!(
            bytes(&reopened.get_block(&b.hash()).await.expect("get")),
            bytes(b)
        );
    }
}

#[tokio::test]
async fn missing_backend_body_fails_closed() {
    let kv = Arc::new(MemKv::default());
    let store = DagStore::persistent_with_strict_vrf(kv.clone(), false)
        .expect("store")
        .with_resident_body_cap(2);
    let blocks = fill(&store, 6, 4).await;
    let victim = blocks[0].hash();
    kv.kv_delete(cf::DAG_BLOCKS, victim.as_bytes())
        .expect("delete");
    let r = store.get_block(&victim).await;
    assert!(
        r.is_err(),
        "a stripped block with no backend body must be an error, got {:?}",
        r.map(|b| b.transactions.len())
    );
    // A resident (recent) block is unaffected.
    let recent = blocks[5].hash();
    kv.kv_delete(cf::DAG_BLOCKS, recent.as_bytes())
        .expect("delete");
    assert_eq!(
        store
            .get_block(&recent)
            .await
            .expect("resident")
            .transactions
            .len(),
        4
    );
}

#[tokio::test]
async fn corrupt_backend_body_fails_closed() {
    let kv = Arc::new(MemKv::default());
    let store = DagStore::persistent_with_strict_vrf(kv.clone(), false)
        .expect("store")
        .with_resident_body_cap(1);
    let blocks = fill(&store, 4, 2).await;
    // Swap block 1's backend bytes for block 2's: hash mismatch must be refused.
    let other = kv
        .kv_get(cf::DAG_BLOCKS, blocks[1].hash().as_bytes())
        .expect("get")
        .expect("present");
    kv.kv_put(cf::DAG_BLOCKS, blocks[0].hash().as_bytes(), &other)
        .expect("put");
    assert!(store.get_block(&blocks[0].hash()).await.is_err());
    kv.kv_put(cf::DAG_BLOCKS, blocks[0].hash().as_bytes(), b"garbage")
        .expect("put");
    assert!(store.get_block(&blocks[0].hash()).await.is_err());
}

#[tokio::test]
async fn in_memory_store_never_strips() {
    let store = DagStore::with_permissive_vrf_for_testing().with_resident_body_cap(1);
    let blocks = fill(&store, 10, 3).await;
    assert_eq!(store.resident_body_count(), 0);
    for b in &blocks {
        assert_eq!(
            bytes(&store.get_block(&b.hash()).await.expect("get")),
            bytes(b)
        );
    }
}

#[tokio::test]
async fn prune_forgets_residency() {
    let kv = Arc::new(MemKv::default());
    let store = DagStore::persistent_with_strict_vrf(kv, false)
        .expect("store")
        .with_resident_body_cap(4);
    let blocks = fill(&store, 12, 2).await;
    // Pruning below height 11 removes 10 blocks, two of which held bodies.
    store
        .update_pruning_point(blocks[10].hash())
        .await
        .expect("pruning point");
    assert_eq!(store.prune().await.expect("prune"), 10);
    assert_eq!(store.resident_body_count(), 2);
    assert!(store.get_block(&blocks[0].hash()).await.is_err());
    assert_eq!(
        bytes(&store.get_block(&blocks[11].hash()).await.expect("get")),
        bytes(&blocks[11])
    );
}
