//! Integration test for MVCC per-account version persistence.
//!
//! Sprint P950-A-4 WP-A.4.3. Verifies that per-account versions written
//! via [`StateStoreTrait::put_account_versions`] round-trip through
//! RocksDB and are recoverable via [`StateStoreTrait::get_all_account_versions`].

use citrate_execution::executor::StateStoreTrait;
use citrate_execution::types::Address;
use citrate_storage::db::RocksDB;
use citrate_storage::state::state_store::StateStore;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;

fn addr(n: u8) -> Address {
    let mut a = [0u8; 20];
    a[0] = n;
    Address(a)
}

#[test]
fn put_and_get_single_version_round_trip() {
    let temp = TempDir::new().unwrap();
    let db = Arc::new(RocksDB::open(temp.path()).unwrap());
    let store = StateStore::new(db);

    store.put_account_version(&addr(1), 42).unwrap();
    let all = store.get_all_account_versions().unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0], (addr(1), 42));
}

#[test]
fn put_many_versions_batch() {
    let temp = TempDir::new().unwrap();
    let db = Arc::new(RocksDB::open(temp.path()).unwrap());
    let store = StateStore::new(db);

    let entries: Vec<(Address, u64)> = (1..=10u8).map(|i| (addr(i), i as u64 * 100)).collect();
    store.put_account_versions(&entries).unwrap();

    let all = store.get_all_account_versions().unwrap();
    let got: HashMap<Address, u64> = all.into_iter().collect();
    for (a, v) in &entries {
        assert_eq!(got.get(a), Some(v));
    }
    assert_eq!(got.len(), 10);
}

#[test]
fn global_version_round_trip() {
    let temp = TempDir::new().unwrap();
    let db = Arc::new(RocksDB::open(temp.path()).unwrap());
    let store = StateStore::new(db);

    // Initially absent
    assert_eq!(store.get_global_version().unwrap(), None);

    store.put_global_version(1234).unwrap();
    assert_eq!(store.get_global_version().unwrap(), Some(1234));

    // Overwrite
    store.put_global_version(5678).unwrap();
    assert_eq!(store.get_global_version().unwrap(), Some(5678));
}

#[test]
fn global_version_sentinel_excluded_from_account_iter() {
    // The global-version sentinel key [0xFF; 20] lives in the same column
    // family as account versions. get_all_account_versions must NOT return
    // it as an account entry.
    let temp = TempDir::new().unwrap();
    let db = Arc::new(RocksDB::open(temp.path()).unwrap());
    let store = StateStore::new(db);

    store.put_global_version(999).unwrap();
    store.put_account_version(&addr(1), 5).unwrap();
    store.put_account_version(&addr(2), 7).unwrap();

    let all = store.get_all_account_versions().unwrap();
    assert_eq!(all.len(), 2, "global-version sentinel must not leak into account iter");
    let got: HashMap<Address, u64> = all.into_iter().collect();
    assert_eq!(got[&addr(1)], 5);
    assert_eq!(got[&addr(2)], 7);

    // global_version still reachable via its own getter
    assert_eq!(store.get_global_version().unwrap(), Some(999));
}

#[test]
fn versions_survive_reopen() {
    // Write versions, close the DB, reopen from the same path, read them back.
    // This is the restart-survival test — the whole point of persistence.
    let temp = TempDir::new().unwrap();

    {
        let db = Arc::new(RocksDB::open(temp.path()).unwrap());
        let store = StateStore::new(db);
        store.put_account_version(&addr(1), 100).unwrap();
        store.put_account_version(&addr(2), 200).unwrap();
        store.put_global_version(500).unwrap();
        // drop db here
    }

    // Reopen
    {
        let db = Arc::new(RocksDB::open(temp.path()).unwrap());
        let store = StateStore::new(db);
        let all = store.get_all_account_versions().unwrap();
        let got: HashMap<Address, u64> = all.into_iter().collect();
        assert_eq!(got.get(&addr(1)), Some(&100));
        assert_eq!(got.get(&addr(2)), Some(&200));
        assert_eq!(got.len(), 2);
        assert_eq!(store.get_global_version().unwrap(), Some(500));
    }
}

#[test]
fn empty_batch_is_noop() {
    let temp = TempDir::new().unwrap();
    let db = Arc::new(RocksDB::open(temp.path()).unwrap());
    let store = StateStore::new(db);

    store.put_account_versions(&[]).unwrap();
    assert_eq!(store.get_all_account_versions().unwrap().len(), 0);
}

#[test]
fn overwrite_semantics() {
    // Writing the same address twice keeps the latest value.
    let temp = TempDir::new().unwrap();
    let db = Arc::new(RocksDB::open(temp.path()).unwrap());
    let store = StateStore::new(db);

    store.put_account_version(&addr(1), 5).unwrap();
    store.put_account_version(&addr(1), 10).unwrap();
    store.put_account_version(&addr(1), 7).unwrap(); // latest wins, even if smaller

    let all = store.get_all_account_versions().unwrap();
    assert_eq!(all, vec![(addr(1), 7)]);
}

#[test]
fn batch_overwrites_single() {
    // Mixed interleaving of single + batch puts should be consistent.
    let temp = TempDir::new().unwrap();
    let db = Arc::new(RocksDB::open(temp.path()).unwrap());
    let store = StateStore::new(db);

    store.put_account_version(&addr(1), 5).unwrap();
    store
        .put_account_versions(&[(addr(1), 50), (addr(2), 60)])
        .unwrap();

    let all: HashMap<Address, u64> = store.get_all_account_versions().unwrap().into_iter().collect();
    assert_eq!(all[&addr(1)], 50);
    assert_eq!(all[&addr(2)], 60);
}
