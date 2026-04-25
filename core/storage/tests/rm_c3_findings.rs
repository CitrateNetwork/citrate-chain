// Aggregate regression tests for RM-C3 audit findings:
//   M-API-01 (MEDIUM) — sync writes available on RocksDB
//   L-STORE-01 (LOW)  — O(1) cached latest_height
//
// Pre-fix `get_latest_height` iterated all of CF_METADATA on every
// call (~31M entries after a year of 1s blocks). Pre-fix
// `write_batch` used non-sync WriteOptions; a power loss between
// commit and OS flush silently rolled back finalised state.
//
// Post-fix:
//   - `RocksDB::write_batch_sync(batch)` provides an explicit
//     `sync=true` path for finalised-block commits.
//   - `BlockStore::get_latest_height` returns from a cached
//     atomic updated inside `put_block`'s WriteBatch. The fallback
//     `get_latest_height_seek` preserves the O(N) path for the
//     cache-rebuild on construction.

use citrate_consensus::types::{BlockBuilder, Hash};
use citrate_storage::chain::block_store::BlockStore;
use citrate_storage::db::RocksDB;
use std::sync::Arc;
use tempfile::TempDir;

fn temp_db() -> (Arc<RocksDB>, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    let db = Arc::new(RocksDB::open(dir.path()).expect("open"));
    (db, dir)
}

fn build_block_at_height(height: u64) -> citrate_consensus::types::Block {
    BlockBuilder::new()
        .timestamp(1_000_000 + height * 10)
        .height(height)
        .blue_score(height + 1)
        .blue_work((height + 1) as u128 * 100)
        .state_root(Hash::new([0xAA; 32]))
        .tx_root(Hash::new([0xBB; 32]))
        .receipt_root(Hash::new([0xCC; 32]))
        .artifact_root(Hash::new([0xDD; 32]))
        .build()
}

/// L-STORE-01.1: latest_height starts at 0 on a fresh DB.
#[test]
fn l_store_01_fresh_db_latest_height_zero() {
    let (db, _dir) = temp_db();
    let store = BlockStore::new(db);
    assert_eq!(store.get_latest_height().expect("get"), 0);
}

/// L-STORE-01.2: writing a block at height N bumps the cached
/// latest_height to N.
#[test]
fn l_store_01_put_block_updates_latest_height() {
    let (db, _dir) = temp_db();
    let store = BlockStore::new(db);

    let block_5 = build_block_at_height(5);
    store.put_block(&block_5).expect("put");
    assert_eq!(store.get_latest_height().expect("get"), 5);

    let block_10 = build_block_at_height(10);
    store.put_block(&block_10).expect("put");
    assert_eq!(store.get_latest_height().expect("get"), 10);
}

/// L-STORE-01.3: writing an out-of-order older block does NOT
/// regress the cached height. The cache is monotonic.
#[test]
fn l_store_01_older_block_does_not_regress_cache() {
    let (db, _dir) = temp_db();
    let store = BlockStore::new(db);

    store.put_block(&build_block_at_height(10)).expect("put 10");
    store.put_block(&build_block_at_height(5)).expect("put 5");

    assert_eq!(
        store.get_latest_height().expect("get"),
        10,
        "L-STORE-01: out-of-order writes must not regress cached height"
    );
}

/// L-STORE-01.4: cached latest_height matches the seek-path
/// fallback (verifies cache and disk agree).
#[test]
fn l_store_01_cached_matches_seek_fallback() {
    let (db, _dir) = temp_db();
    let store = BlockStore::new(db);

    for h in 1..=20 {
        store.put_block(&build_block_at_height(h)).expect("put");
    }

    let cached = store.get_latest_height().expect("cached");
    let seek = store.get_latest_height_seek().expect("seek");
    assert_eq!(
        cached, seek,
        "L-STORE-01: cached value must match the disk-truth seek result"
    );
    assert_eq!(cached, 20);
}

/// L-STORE-01.5: cache survives BlockStore reconstruction —
/// `BlockStore::new` reads the persisted LATEST_HEIGHT_KEY.
#[test]
fn l_store_01_cache_warms_from_disk_on_construction() {
    let (db, _dir) = temp_db();
    {
        let store = BlockStore::new(db.clone());
        for h in 1..=15 {
            store.put_block(&build_block_at_height(h)).expect("put");
        }
        assert_eq!(store.get_latest_height().expect("get"), 15);
    }

    // Fresh BlockStore on the same DB reads the persisted cache.
    let store2 = BlockStore::new(db);
    assert_eq!(
        store2.get_latest_height().expect("get"),
        15,
        "L-STORE-01: cache must warm from disk on reconstruction"
    );
}

/// M-API-01.1: write_batch_sync API exists and commits
/// successfully. (Verifying actual fsync semantics requires
/// fault-injection at the OS layer — out of scope for unit tests.)
#[test]
fn m_api_01_write_batch_sync_commits_successfully() {
    use citrate_storage::db::column_families::CF_METADATA;
    let (db, _dir) = temp_db();
    let mut batch = db.batch();
    db.batch_put_cf(&mut batch, CF_METADATA, b"sync_test", b"value")
        .expect("batch_put");
    db.write_batch_sync(batch).expect("write_batch_sync");

    let value = db.get_cf(CF_METADATA, b"sync_test").expect("get");
    assert_eq!(value, Some(b"value".to_vec()));
}
