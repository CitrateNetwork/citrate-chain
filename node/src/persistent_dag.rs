// WP-S.1: RocksDB KvStore implementation for persistent DAG storage.

use citrate_consensus::dag_store::KvStore;
use citrate_storage::db::RocksDB;
use std::sync::Arc;

/// Adapter that implements the consensus crate's `KvStore` trait using `citrate_storage::RocksDB`.
pub struct RocksDbKvStore {
    db: Arc<RocksDB>,
}

impl RocksDbKvStore {
    pub fn new(db: Arc<RocksDB>) -> Self {
        Self { db }
    }
}

impl KvStore for RocksDbKvStore {
    fn kv_get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        self.db.get_cf(cf, key).map_err(|e| e.to_string())
    }

    fn kv_put(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<(), String> {
        self.db.put_cf(cf, key, value).map_err(|e| e.to_string())
    }

    fn kv_delete(&self, cf: &str, key: &[u8]) -> Result<(), String> {
        self.db.delete_cf(cf, key).map_err(|e| e.to_string())
    }

    fn kv_exists(&self, cf: &str, key: &[u8]) -> Result<bool, String> {
        self.db.exists_cf(cf, key).map_err(|e| e.to_string())
    }

    fn kv_iter_cf(&self, cf: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
        self.db
            .iter_cf(cf)
            .map(|iter| {
                iter.map(|(k, v)| (k.to_vec(), v.to_vec()))
                    .collect()
            })
            .map_err(|e| e.to_string())
    }
}
