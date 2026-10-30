//! Pins for `BlockStore::put_block` read-modify-write guards.
//!
//! The existing unit tests in `chain/block_store.rs` cover the child-link
//! de-duplication and the concurrent-ingest lock, but their height test spawns
//! the puts in ascending order, so a store that simply wrote the latest put's
//! height (instead of the maximum) still passed. These tests drive the
//! out-of-order case deterministically and also check the persisted value
//! after a reopen, not just the in-memory cache.

use citrate_consensus::types::{Block, BlockBuilder, Hash, PublicKey};
use citrate_storage::chain::BlockStore;
use citrate_storage::db::RocksDB;
use std::sync::Arc;
use tempfile::TempDir;

fn block_at(height: u64, parent: Hash, seed: u8) -> Block {
    BlockBuilder::new()
        .hash(Hash::new([seed; 32]))
        .parent(parent)
        .height(height)
        .timestamp(1_000_000 + height)
        .blue_score(height * 10)
        .blue_work(height as u128 * 100)
        .proposer(PublicKey::new([1; 32]))
        .build_unhashed()
}

/// A lower block stored after a higher one (sync back-fill, a late sibling)
/// must not move the latest height backwards, in memory or on disk.
#[test]
fn latest_height_does_not_regress_when_a_lower_block_arrives_later() {
    let dir = TempDir::new().expect("tempdir");
    let parent = Hash::new([0xAB; 32]);
    {
        let db = Arc::new(RocksDB::open(dir.path()).expect("open db"));
        let store = BlockStore::new(db);

        store.put_block(&block_at(9, parent, 0x09)).expect("put 9");
        assert_eq!(store.get_latest_height().expect("height"), 9);

        store.put_block(&block_at(4, parent, 0x04)).expect("put 4");
        assert_eq!(
            store.get_latest_height().expect("height"),
            9,
            "a lower block stored later must not lower the cached latest height"
        );

        // Equal height (a sibling) also leaves it alone.
        store
            .put_block(&block_at(9, parent, 0x19))
            .expect("put sibling 9");
        assert_eq!(store.get_latest_height().expect("height"), 9);
    }

    // The persisted marker is what a restart warms the cache from.
    let db = Arc::new(RocksDB::open(dir.path()).expect("reopen db"));
    let reopened = BlockStore::new(db);
    assert_eq!(
        reopened.get_latest_height().expect("height"),
        9,
        "the persisted latest-height marker must not regress either"
    );
}

/// Re-storing a block that is already linked under its parent (a producer
/// retry, overlapping sync ranges) keeps exactly one link, and does not drop
/// a sibling's link either.
#[test]
fn re_put_keeps_one_link_per_child_and_preserves_siblings() {
    let dir = TempDir::new().expect("tempdir");
    let db = Arc::new(RocksDB::open(dir.path()).expect("open db"));
    let store = BlockStore::new(db);
    let parent = Hash::new([0xCD; 32]);

    let a = block_at(1, parent, 0xA1);
    let b = block_at(1, parent, 0xB1);
    store.put_block(&a).expect("put a");
    store.put_block(&b).expect("put b");
    store.put_block(&a).expect("re-put a");
    store.put_block(&b).expect("re-put b");

    let mut children = store.get_children(&parent).expect("children");
    children.sort_by_key(|h| *h.as_bytes());
    let mut expected = vec![a.hash(), b.hash()];
    expected.sort_by_key(|h| *h.as_bytes());
    assert_eq!(children, expected, "each child linked exactly once");
}
