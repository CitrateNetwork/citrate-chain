// Every storage record the executor persists must come back from
// `StateStore::get_all_storage`, the node's restart-hydration path, with the
// same key and value bytes.
//
// The executor writes EVM slots (32-byte key and value) and its own
// variable-length records under precompile addresses: the governance admin
// (`ADMIN`, 20-byte value), pending and applied parameters
// (`PENDING:`/`PARAM:` + 32-byte key, variable value), and the model CID and
// artifact / proof indexes (`MODEL_CID:` etc. + 32-byte hash, string or JSON
// value).

use citrate_execution::types::Address;
use citrate_storage::db::RocksDB;
use citrate_storage::state::StateStore;
use std::sync::Arc;
use tempfile::TempDir;

fn open() -> (TempDir, StateStore) {
    let tmp = TempDir::new().expect("tempdir");
    let db = Arc::new(RocksDB::open(tmp.path()).expect("open db"));
    (tmp, StateStore::new(db))
}

/// 0x…10NN, the executor-native precompile addresses.
fn precompile(nn: u8) -> Address {
    let mut a = [0u8; 20];
    a[18] = 0x10;
    a[19] = nn;
    Address(a)
}

fn executor_records() -> Vec<(Address, Vec<u8>, Vec<u8>)> {
    let gov = precompile(0x03);
    let art = precompile(0x02);
    let k32 = [0xC1u8; 32];
    let mut pending = b"PENDING:".to_vec();
    pending.extend_from_slice(&k32);
    let mut param = b"PARAM:".to_vec();
    param.extend_from_slice(&k32);
    let mut cid = b"MODEL_CID:".to_vec();
    cid.extend_from_slice(&[0x4D; 32]);
    let mut arts = b"MODEL_ARTS:".to_vec();
    arts.extend_from_slice(&[0x4D; 32]);
    vec![
        (gov, b"ADMIN".to_vec(), vec![0xA1; 20]),
        (
            gov,
            pending,
            [7u64.to_le_bytes().to_vec(), b"v1".to_vec()].concat(),
        ),
        (gov, param, b"v1".to_vec()),
        (art, cid, b"bafy-test-cid".to_vec()),
        (art, arts, br#"["bafy-test-cid"]"#.to_vec()),
        // An EVM slot, the one shape that survives today (control).
        (Address([0xEE; 20]), vec![0x01; 32], vec![0x02; 32]),
    ]
}

#[test]
fn every_persisted_storage_record_is_returned_by_hydration() {
    let (_tmp, store) = open();
    let records = executor_records();
    for (a, k, v) in &records {
        store.put_storage(a, k, v).expect("put");
    }
    let hydrated = store.get_all_storage().expect("get_all_storage");
    assert_eq!(
        hydrated.len(),
        records.len(),
        "restart hydration returned {} of {} persisted storage records",
        hydrated.len(),
        records.len()
    );
}

#[test]
fn a_short_value_is_not_hydrated_as_zero_padding() {
    // A 32-byte key with a 2-byte value: hydration must not turn it into 32
    // zero bytes.
    let (_tmp, store) = open();
    let a = Address([0xEF; 20]);
    store.put_storage(&a, &[0x05; 32], b"v1").expect("put");
    let hydrated = store.get_all_storage().expect("get_all_storage");
    let values: Vec<Vec<u8>> = hydrated
        .iter()
        .map(|(_, v)| v.as_bytes().to_vec())
        .collect();
    assert_eq!(
        values,
        vec![b"v1".to_vec()],
        "value bytes changed on hydration"
    );
}
