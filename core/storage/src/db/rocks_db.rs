// citrate/core/storage/src/db/rocks_db.rs

use super::column_families::all_column_families;
use anyhow::Result;
use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, DB};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::Arc;
use tracing::{debug, info};

// Simpler alias for iterator item type to reduce signature complexity
type KvItem = (Box<[u8]>, Box<[u8]>);

/// RocksDB wrapper for blockchain storage.
///
/// REM-2 / WP-H1.3 (audit M-API-01): the `*_count` atomic counters
/// observe whether producer-path callers (block_store::put_block,
/// transaction_store::put_receipts, persistent_dag::kv_write_batch)
/// commit via the durable `write_batch_sync` path. Cost is one
/// relaxed atomic add per write — negligible relative to a RocksDB
/// commit. Tests assert `sync_count > 0` after a producer commit;
/// the durability tripwire (`m-api-01-no-fsync.yaml`) catches the
/// pattern at lint time.
pub struct RocksDB {
    db: Arc<DB>,
    /// Number of `write_batch` (non-fsync) calls — see struct doc.
    write_batch_count: Arc<AtomicU64>,
    /// Number of `write_batch_sync` (fsync) calls — see struct doc.
    write_batch_sync_count: Arc<AtomicU64>,
}

impl RocksDB {
    /// Open database with default options
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        // Use compression in prod; disable in tests or when feature `no-compression` is set
        let compression = if cfg!(any(test, feature = "no-compression")) {
            rocksdb::DBCompressionType::None
        } else {
            rocksdb::DBCompressionType::Lz4
        };
        db_opts.set_compression_type(compression);

        // Performance optimizations
        db_opts.set_write_buffer_size(128 * 1024 * 1024); // 128MB
        db_opts.set_max_write_buffer_number(3);
        db_opts.set_target_file_size_base(64 * 1024 * 1024); // 64MB
        db_opts.set_max_bytes_for_level_base(512 * 1024 * 1024); // 512MB
        db_opts.increase_parallelism(num_cpus::get() as i32);

        // Create column family descriptors
        let cfs: Vec<ColumnFamilyDescriptor> = all_column_families()
            .into_iter()
            .map(|name| {
                let mut cf_opts = Options::default();
                cf_opts.set_compression_type(compression);
                ColumnFamilyDescriptor::new(name, cf_opts)
            })
            .collect();

        let db = DB::open_cf_descriptors(&db_opts, path, cfs)?;

        info!("RocksDB opened successfully");
        Ok(Self {
            db: Arc::new(db),
            write_batch_count: Arc::new(AtomicU64::new(0)),
            write_batch_sync_count: Arc::new(AtomicU64::new(0)),
        })
    }

    /// REM-2 / WP-H1.3: number of non-fsync `write_batch` calls observed
    /// since open. Used by durability tests to assert that producer-path
    /// commits go through `write_batch_sync` (fsync) rather than
    /// `write_batch` (OS page cache only).
    pub fn write_batch_count(&self) -> u64 {
        self.write_batch_count.load(AtomicOrdering::Relaxed)
    }

    /// REM-2 / WP-H1.3: number of fsync `write_batch_sync` calls
    /// observed since open. Used by durability tests.
    pub fn write_batch_sync_count(&self) -> u64 {
        self.write_batch_sync_count.load(AtomicOrdering::Relaxed)
    }

    /// Get a value from a column family
    pub fn get_cf(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let cf_handle = self.cf_handle(cf)?;
        Ok(self.db.get_cf(&cf_handle, key)?)
    }

    /// Put a value in a column family
    pub fn put_cf(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let cf_handle = self.cf_handle(cf)?;
        self.db.put_cf(&cf_handle, key, value)?;
        Ok(())
    }

    /// Delete a key from a column family
    pub fn delete_cf(&self, cf: &str, key: &[u8]) -> Result<()> {
        let cf_handle = self.cf_handle(cf)?;
        self.db.delete_cf(&cf_handle, key)?;
        Ok(())
    }

    /// Check if a key exists in a column family
    pub fn exists_cf(&self, cf: &str, key: &[u8]) -> Result<bool> {
        Ok(self.get_cf(cf, key)?.is_some())
    }

    /// Write a batch of operations atomically with the default
    /// (non-sync) WriteOptions. WAL is on, but writes return as
    /// soon as the OS buffer accepts them.
    ///
    /// REM-2 / WP-H1.3 (audit M-API-01): producer-path writers
    /// MUST NOT call this method — use `write_batch_sync` instead.
    /// Acceptable callers: caches, metrics, GC/pruning, MVCC
    /// version persistence (documented as conservatively-safe on
    /// restart). The Semgrep tripwire `m-api-01-no-fsync.yaml`
    /// enforces this at lint time across the producer paths.
    pub fn write_batch(&self, batch: WriteBatch) -> Result<()> {
        self.db.write(batch)?;
        self.write_batch_count.fetch_add(1, AtomicOrdering::Relaxed);
        Ok(())
    }

    /// Write a batch of operations atomically with `sync=true`.
    ///
    /// REM-2 / WP-H1.3 (audit M-API-01): producer write path MUST
    /// use this. Forces fsync via `RocksDB::WriteOptions::set_sync(true)`.
    /// Cost: ~1-2 ms p99 on testnet hardware (verified by
    /// `bench_producer_durability` when present). Pre-fix all writes
    /// used the default `WriteOptions { sync: false }`. A power loss
    /// between block commit and OS flush silently rolled back
    /// finalised state. Use this method for the producer's finalised
    /// commits — block, tx index, receipts, DAG persistence — and
    /// any other write whose loss would cause a finality regression
    /// or `eth_getTransactionReceipt`-returns-null gap.
    pub fn write_batch_sync(&self, batch: WriteBatch) -> Result<()> {
        let mut opts = rocksdb::WriteOptions::default();
        opts.set_sync(true);
        self.db.write_opt(batch, &opts)?;
        self.write_batch_sync_count
            .fetch_add(1, AtomicOrdering::Relaxed);
        Ok(())
    }

    /// Create a new write batch
    pub fn batch(&self) -> WriteBatch {
        WriteBatch::default()
    }

    /// Add put operation to batch
    pub fn batch_put_cf(
        &self,
        batch: &mut WriteBatch,
        cf: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<()> {
        let cf_handle = self.cf_handle(cf)?;
        batch.put_cf(&cf_handle, key, value);
        Ok(())
    }

    /// Add delete operation to batch
    pub fn batch_delete_cf(&self, batch: &mut WriteBatch, cf: &str, key: &[u8]) -> Result<()> {
        let cf_handle = self.cf_handle(cf)?;
        batch.delete_cf(&cf_handle, key);
        Ok(())
    }

    /// Get iterator for a column family
    pub fn iter_cf(&self, cf: &str) -> Result<impl Iterator<Item = KvItem> + '_> {
        let cf_handle = self.cf_handle(cf)?;
        Ok(self
            .db
            .iterator_cf(&cf_handle, rocksdb::IteratorMode::Start)
            .filter_map(|r| r.ok()))
    }

    /// Get iterator with prefix for a column family
    pub fn prefix_iter_cf(
        &self,
        cf: &str,
        prefix: &[u8],
    ) -> Result<impl Iterator<Item = KvItem> + '_> {
        let cf_handle = self.cf_handle(cf)?;
        Ok(self
            .db
            .prefix_iterator_cf(&cf_handle, prefix)
            .filter_map(|r| r.ok()))
    }

    /// Compact a column family
    pub fn compact_cf(&self, cf: &str) -> Result<()> {
        let cf_handle = self.cf_handle(cf)?;
        self.db
            .compact_range_cf(&cf_handle, None::<&[u8]>, None::<&[u8]>);
        debug!("Compacted column family: {}", cf);
        Ok(())
    }

    /// Get column family handle
    fn cf_handle(&self, name: &str) -> Result<&rocksdb::ColumnFamily> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| anyhow::anyhow!("Column family {} not found", name))
    }

    /// Get database statistics
    pub fn get_statistics(&self) -> String {
        self.db
            .property_value("rocksdb.stats")
            .unwrap_or_default()
            .unwrap_or_else(|| "No statistics available".to_string())
    }

    /// Flush all column families
    pub fn flush(&self) -> Result<()> {
        for cf_name in all_column_families() {
            if let Ok(cf) = self.cf_handle(cf_name) {
                self.db.flush_cf(&cf)?;
            }
        }
        Ok(())
    }
}

impl Clone for RocksDB {
    fn clone(&self) -> Self {
        Self {
            db: Arc::clone(&self.db),
            write_batch_count: Arc::clone(&self.write_batch_count),
            write_batch_sync_count: Arc::clone(&self.write_batch_sync_count),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_basic_operations() {
        let temp_dir = TempDir::new().unwrap();
        let db = RocksDB::open(temp_dir.path()).unwrap();

        // Test put and get
        db.put_cf("blocks", b"key1", b"value1").unwrap();
        let value = db.get_cf("blocks", b"key1").unwrap();
        assert_eq!(value, Some(b"value1".to_vec()));

        // Test exists
        assert!(db.exists_cf("blocks", b"key1").unwrap());
        assert!(!db.exists_cf("blocks", b"key2").unwrap());

        // Test delete
        db.delete_cf("blocks", b"key1").unwrap();
        assert!(!db.exists_cf("blocks", b"key1").unwrap());
    }

    #[test]
    fn test_batch_operations() {
        let temp_dir = TempDir::new().unwrap();
        let db = RocksDB::open(temp_dir.path()).unwrap();

        let mut batch = db.batch();
        db.batch_put_cf(&mut batch, "blocks", b"key1", b"value1")
            .unwrap();
        db.batch_put_cf(&mut batch, "blocks", b"key2", b"value2")
            .unwrap();
        db.batch_delete_cf(&mut batch, "blocks", b"key3").unwrap();

        db.write_batch(batch).unwrap();

        assert_eq!(
            db.get_cf("blocks", b"key1").unwrap(),
            Some(b"value1".to_vec())
        );
        assert_eq!(
            db.get_cf("blocks", b"key2").unwrap(),
            Some(b"value2".to_vec())
        );
    }
}
