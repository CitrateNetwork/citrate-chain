// WP-S.1: RocksDB KvStore implementation for persistent DAG storage.

use citrate_consensus::dag_store::{KvOp, KvStore};
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

    /// RM-B1 / WP-B1.3 (audit H-04): override the trait default with
    /// a real RocksDB `WriteBatch` so multi-op block-admission writes
    /// commit atomically. A power loss between two ops can no longer
    /// leave the DAG in a partial state.
    fn kv_write_batch(&self, ops: &[KvOp]) -> Result<(), String> {
        let mut batch = self.db.batch();
        for op in ops {
            match op {
                KvOp::Put { cf, key, value } => {
                    self.db
                        .batch_put_cf(&mut batch, cf, key, value)
                        .map_err(|e| e.to_string())?;
                }
                KvOp::Delete { cf, key } => {
                    self.db
                        .batch_delete_cf(&mut batch, cf, key)
                        .map_err(|e| e.to_string())?;
                }
            }
        }
        self.db.write_batch(batch).map_err(|e| e.to_string())
    }
}
