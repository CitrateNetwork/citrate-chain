// The legacy hydration view, used by a restarted node below the storage-root
// hardening height, must be exactly what `get_all_storage` returned before the
// fork existed: 32-byte keys only, values cut or zero-padded to 32 bytes, in
// store order. And a record that no writer can produce is an error.

use citrate_execution::types::Address;
use citrate_storage::db::column_families::CF_STORAGE;
use citrate_storage::db::RocksDB;
use citrate_storage::state::{legacy_hydration_view, StateStore, StorageBytes};
use std::sync::Arc;
use tempfile::TempDir;

/// `((address, key), value)` as raw bytes.
type RawRecord = ((Address, Vec<u8>), Vec<u8>);

fn open() -> (TempDir, Arc<RocksDB>, StateStore) {
    let tmp = TempDir::new().expect("tempdir");
    let db = Arc::new(RocksDB::open(tmp.path()).expect("open db"));
    (tmp, db.clone(), StateStore::new(db))
}

/// The pre-fork reader, verbatim in behaviour, over the same raw records.
fn pre_fork_reader(raw: &[(Vec<u8>, Vec<u8>)]) -> Vec<RawRecord> {
    let mut out = Vec::new();
    for (key, value) in raw {
        if key.len() == 52 {
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&key[..20]);
            let mut word = [0u8; 32];
            if value.len() >= 32 {
                word.copy_from_slice(&value[..32]);
            }
            out.push(((Address(addr), key[20..].to_vec()), word.to_vec()));
        }
    }
    out
}

#[test]
fn legacy_view_matches_the_pre_fork_reader_record_for_record() {
    let (_tmp, db, store) = open();
    let gov = {
        let mut a = [0u8; 20];
        a[18] = 0x10;
        a[19] = 0x03;
        Address(a)
    };
    let evm = Address([0xEE; 20]);
    let mut pending = b"PENDING:".to_vec();
    pending.extend_from_slice(&[0xC1; 32]);
    let writes: Vec<(Address, Vec<u8>, Vec<u8>)> = vec![
        (gov, b"ADMIN".to_vec(), vec![0xA1; 20]),
        (gov, pending, b"v1".to_vec()),
        (evm, vec![0x01; 32], vec![0x02; 32]),
        (evm, vec![0x03; 32], b"short".to_vec()),
        (evm, vec![0x04; 32], vec![0x05; 40]),
        (evm, vec![0x06; 32], vec![]),
    ];
    for (a, k, v) in &writes {
        store.put_storage(a, k, v).expect("put");
    }
    let raw: Vec<(Vec<u8>, Vec<u8>)> = db
        .iter_cf(CF_STORAGE)
        .expect("iter")
        .map(|(k, v)| (k.to_vec(), v.to_vec()))
        .collect();
    let expected = pre_fork_reader(&raw);
    let got: Vec<RawRecord> = legacy_hydration_view(store.get_all_storage().expect("records"))
        .into_iter()
        .map(|((a, k), v)| ((a, k.into_vec()), v.into_vec()))
        .collect();
    assert_eq!(got, expected);
    assert_eq!(got.len(), 4, "only the four 32-byte-key records survive");

    // The full view keeps all six, byte for byte.
    let full = store.get_all_storage().expect("records");
    assert_eq!(full.len(), writes.len());
    for (a, k, v) in &writes {
        assert!(
            full.contains(&((*a, StorageBytes(k.clone())), StorageBytes(v.clone()))),
            "record {k:?} must hydrate unchanged"
        );
    }
}

#[test]
fn a_record_shorter_than_an_address_is_an_error_not_skipped() {
    let (_tmp, db, store) = open();
    store
        .put_storage(&Address([0x11; 20]), &[0x01; 32], &[0x02; 32])
        .expect("put");
    db.put_cf(CF_STORAGE, &[0xAB; 7], b"x").expect("raw put");
    let err = store
        .get_all_storage()
        .expect_err("a 7-byte storage key cannot come from any writer");
    assert!(err.to_string().contains("7-byte key"), "{err}");
}
