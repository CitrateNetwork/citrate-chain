#![allow(clippy::type_complexity)]
// Audit finding M-06 regression: previously
// `bincode::serialize(...).unwrap_or_default()` silently emitted an
// empty `Vec<u8>` on encode failure, which the kv_put would dutifully
// store, and the next restart would silently drop the entry on
// deserialize. The fix routes serialization errors through `match`
// + log + skip the kv_put (for `()`-returning helpers) or `?`
// propagation (for fallible call sites).
//
// This integration test pins the match-based path on the persist
// helpers via a real RocksDB-shaped backend. The proptest-style
// "serialization always fails" coverage isn't possible here without
// a custom Serialize impl that errors — `Block` always serializes
// cleanly under bincode 1.x — so the load-bearing guard is the
// Semgrep rule `b1-bincode-unwrap-or-default.yaml` (WP-B1.6) which
// fires CI on the pattern resurfacing in code.

use citrate_consensus::*;
use std::sync::{Arc, Mutex};

/// Minimal in-memory KV store that mirrors RocksDB's API surface.
struct MemKv {
    inner: Mutex<std::collections::HashMap<(String, Vec<u8>), Vec<u8>>>,
}

impl MemKv {
    fn new() -> Self {
        Self {
            inner: Mutex::new(std::collections::HashMap::new()),
        }
    }
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
        Ok(self
            .inner
            .lock()
            .map_err(|e| e.to_string())?
            .contains_key(&(cf.to_string(), key.to_vec())))
    }

    fn kv_iter_cf(&self, cf: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
        Ok(self
            .inner
            .lock()
            .map_err(|e| e.to_string())?
            .iter()
            .filter_map(|((c, k), v)| {
                if c == cf {
                    Some((k.clone(), v.clone()))
                } else {
                    None
                }
            })
            .collect())
    }
}

fn build_block(seed: u8, height: u64, parent: Hash) -> Block {
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
        .build_unhashed()
}

/// M-06.1: writing a block through `persist_block` (via store_block)
/// produces a non-empty serialized payload in the backend. If
/// serialization had silently emitted empty bytes (the pre-fix
/// behavior) the persisted value would be `[]`, and the
/// `bincode::deserialize` round-trip would fail.
#[tokio::test]
async fn m06_persist_block_round_trips_non_empty() {
    let kv = Arc::new(MemKv::new());
    let store = DagStore::persistent_with_strict_vrf(kv.clone() as Arc<dyn KvStore>, false)
        .expect("persistent dag store must build");

    let genesis = build_block(0xAA, 0, Hash::default());
    let g_hash = genesis.hash();
    store
        .store_block(genesis)
        .await
        .expect("genesis must admit");

    // Reach into the backend directly and assert the persisted block
    // bytes deserialize cleanly. If the pre-fix `unwrap_or_default()`
    // path were still in place and serialization had failed, this read
    // would yield empty bytes which deserialize-fail on bincode.
    let stored = kv
        .kv_get("dag_blocks", g_hash.as_bytes())
        .expect("kv_get must succeed")
        .expect("genesis must be persisted");
    assert!(!stored.is_empty(), "M-06: persisted block bytes must not be empty");
    let _: Block = bincode::deserialize(&stored).expect("M-06: persisted bytes must deserialize");
}

/// M-06.2: a fresh `DagStore::persistent_with_strict_vrf(kv, false)` reload
/// after writing a block recovers identical state. This pins the
/// "no silent persistence drop" guarantee end-to-end.
#[tokio::test]
async fn m06_persist_then_reload_round_trip() {
    let kv: Arc<dyn KvStore> = Arc::new(MemKv::new());

    // First boot: write a small chain.
    {
        let store = DagStore::persistent_with_strict_vrf(kv.clone(), false)
            .expect("first persistent dag store");

        let g = build_block(0xAA, 0, Hash::default());
        let g_hash = g.hash();
        store.store_block(g).await.expect("genesis admit");
        let b1 = build_block(0x01, 1, g_hash);
        store.store_block(b1).await.expect("b1 admit");
    }

    // Second boot: reload from the same backend, expect both blocks visible.
    let store2 = DagStore::persistent_with_strict_vrf(kv, false)
        .expect("second persistent dag store");
    let stats = store2.get_stats().await;
    assert_eq!(stats.total_blocks, 2, "M-06: reload must recover all blocks");
}

/// M-06.3: round-trip a checkpoint serialization manually to assert
/// the structure can serialize cleanly under bincode (the pre-fix
/// `unwrap_or_default()` would have masked a regression that broke
/// CheckpointVote serialization).
#[test]
fn m06_checkpoint_serialization_is_total() {
    let voter = PublicKey::new([0x42; 32]);
    let vote = CheckpointVote {
        height: 100,
        block_hash: Hash::new([0xCD; 32]),
        voter,
        signature: citrate_consensus::types::Signature::new([0xEF; 64]),
    };
    let bytes = bincode::serialize(&vote).expect("M-06: vote must serialize");
    assert!(!bytes.is_empty());
    let _: CheckpointVote = bincode::deserialize(&bytes).expect("M-06: vote round-trips");
}
