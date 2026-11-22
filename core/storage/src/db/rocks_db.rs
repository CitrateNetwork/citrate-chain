// citrate/core/storage/src/db/rocks_db.rs

use super::column_families::all_column_families;
use crate::crypto::at_rest::{
    AtRestCipher, AtRestError, AtRestStats, EncryptionAtRestConfig, EncryptionMeta,
};
use anyhow::Result;
use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, DB};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::Arc;
use tracing::{debug, error, info};

// Simpler alias for iterator item type to reduce signature complexity
type KvItem = (Box<[u8]>, Box<[u8]>);

/// Env var: database-wide memtable budget in MiB (all column families).
pub const MEMTABLE_BUDGET_ENV: &str = "CITRATE_ROCKSDB_MEMTABLE_MB";
/// Env var: shared block cache size in MiB (all column families).
pub const BLOCK_CACHE_ENV: &str = "CITRATE_ROCKSDB_BLOCK_CACHE_MB";

/// RocksDB memory budget. The defaults are sized for an 8 GB host running a
/// producer: 128 MiB of memtables and a 64 MiB block cache shared by every
/// column family. Without them each of the ~22 column families had its own
/// 64 MiB memtable threshold (x2 buffers) and its own block cache, so RocksDB's
/// memory grew with the number of column families written, and memtables of a
/// column family that stopped receiving writes were never flushed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RocksMemoryBudget {
    /// Total memtable bytes across all column families before a flush is forced.
    pub memtable_bytes: usize,
    /// Shared LRU block cache capacity.
    pub block_cache_bytes: usize,
}

/// Smallest budget accepted from the environment (a typo must not make every
/// write flush).
const MIN_BUDGET_MB: usize = 8;

impl Default for RocksMemoryBudget {
    fn default() -> Self {
        Self {
            memtable_bytes: 128 * 1024 * 1024,
            block_cache_bytes: 64 * 1024 * 1024,
        }
    }
}

impl RocksMemoryBudget {
    /// The default budget with any `CITRATE_ROCKSDB_*_MB` override applied.
    pub fn from_env() -> Self {
        Self::from_values(
            std::env::var(MEMTABLE_BUDGET_ENV).ok().as_deref(),
            std::env::var(BLOCK_CACHE_ENV).ok().as_deref(),
        )
    }

    /// Parse overrides (MiB). Unset or unparsable keeps the default; values
    /// below 8 MiB are raised to 8 MiB.
    pub fn from_values(memtable_mb: Option<&str>, block_cache_mb: Option<&str>) -> Self {
        let d = Self::default();
        let mb = |raw: Option<&str>, default: usize| -> usize {
            match raw.and_then(|r| r.trim().parse::<usize>().ok()) {
                Some(v) => v.max(MIN_BUDGET_MB).saturating_mul(1024 * 1024),
                None => default,
            }
        };
        Self {
            memtable_bytes: mb(memtable_mb, d.memtable_bytes),
            block_cache_bytes: mb(block_cache_mb, d.block_cache_bytes),
        }
    }
}

/// Point-in-time RocksDB memory use, in bytes. See [`RocksDB::memory_usage`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RocksMemoryUsage {
    /// Active + immutable memtables across all column families.
    pub memtables: u64,
    /// Block cache usage (largest per-CF reading; equal to the shared cache's
    /// usage when the cache is shared).
    pub block_cache: u64,
    /// Sum of per-CF block cache readings (equals `block_cache` x CFs when the
    /// cache is shared; the true total when each CF has its own cache).
    pub block_cache_sum_over_cfs: u64,
    /// Index/filter blocks held by open table readers outside the cache.
    pub table_readers: u64,
}

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
    /// Encryption-at-rest cipher (STOR-EAR). `None` = raw plaintext path
    /// (the default — identical behavior and performance to pre-encryption
    /// builds). `Some` = every VALUE through get/put/batch/iterator paths
    /// is sealed/opened with AES-256-GCM; record keys stay plaintext so
    /// iteration and prefix scans keep working.
    cipher: Option<Arc<AtRestCipher>>,
    /// Number of `write_batch` (non-fsync) calls — see struct doc.
    write_batch_count: Arc<AtomicU64>,
    /// Number of `write_batch_sync` (fsync) calls — see struct doc.
    write_batch_sync_count: Arc<AtomicU64>,
}

impl RocksDB {
    /// Open database with default options (no encryption at rest).
    ///
    /// Fails with a clear error if the data directory belongs to an
    /// encrypted database (`encryption.meta` present, or — as a fallback
    /// when the marker was deleted — a probe read finds sealed values):
    /// there is no in-place migration in either direction.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if EncryptionMeta::load(path)?.is_some() {
            return Err(
                AtRestError::EncryptedDbWithoutEncryption(path.display().to_string()).into(),
            );
        }

        let db = Self::open_inner(path, None)?;

        // Probe read: the meta marker is the primary mismatch guard, but if
        // it was deleted out-of-band the values would still be sealed. Only
        // errors when values are found AND all sampled ones look sealed, so
        // a legitimate plaintext DB cannot trip it.
        db.probe_for_sealed_values(path)?;
        Ok(db)
    }

    /// Open an existing database READ-ONLY (no encryption at rest), with
    /// every column family it has. Nothing is created and nothing can be
    /// written: a write through the handle fails at RocksDB. Works while the
    /// node that owns the directory is running (RocksDB read-only opens take
    /// no lock), so tools such as the replay recorder
    /// (`tools/replay-ref`) can dump a live node's data dir.
    ///
    /// An encrypted database is refused (its values need the key).
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if EncryptionMeta::load(path)?.is_some() {
            return Err(
                AtRestError::EncryptedDbWithoutEncryption(path.display().to_string()).into(),
            );
        }
        let opts = Self::read_only_options();
        let cfs = DB::list_cf(&opts, path)?;
        let db = DB::open_cf_for_read_only(&opts, path, cfs, false)?;
        let db = Self {
            db: Arc::new(db),
            cipher: None,
            write_batch_count: Arc::new(AtomicU64::new(0)),
            write_batch_sync_count: Arc::new(AtomicU64::new(0)),
        };
        db.probe_for_sealed_values(path)?;
        Ok(db)
    }

    /// Open an existing database READ-ONLY with every column family it has,
    /// encrypted at rest when `encryption` is given (the key is verified
    /// against the stored commitment; a wrong key is an error), plaintext
    /// otherwise ([`Self::open_read_only`]). Nothing is created or written.
    /// lets a cold resync read the signed-vote record out of a
    /// moved encrypted chain database.
    pub fn open_read_only_with(
        path: impl AsRef<Path>,
        encryption: Option<&EncryptionAtRestConfig>,
    ) -> Result<Self> {
        let path = path.as_ref();
        let Some(config) = encryption else {
            return Self::open_read_only(path);
        };
        if EncryptionMeta::load(path)?.is_none() {
            anyhow::bail!(
                "{} is not an encrypted database (no encryption.meta)",
                path.display()
            );
        }
        let cipher = AtRestCipher::open_or_init(path, config)?;
        let opts = Self::read_only_options();
        let cfs = DB::list_cf(&opts, path)?;
        let db = DB::open_cf_for_read_only(&opts, path, cfs, false)?;
        Ok(Self {
            db: Arc::new(db),
            cipher: Some(Arc::new(cipher)),
            write_batch_count: Arc::new(AtomicU64::new(0)),
            write_batch_sync_count: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Open database with encryption at rest enabled.
    ///
    /// Key/meta lifecycle (see [`AtRestCipher::open_or_init`]): a fresh
    /// directory writes `encryption.meta` (KDF salt + key commitment); an
    /// existing encrypted DB verifies the supplied key against the stored
    /// commitment and fails with an explicit wrong-key error on mismatch;
    /// an existing plaintext DB fails with a wipe-and-resync error.
    pub fn open_encrypted(path: impl AsRef<Path>, config: &EncryptionAtRestConfig) -> Result<Self> {
        let path = path.as_ref();
        let cipher = AtRestCipher::open_or_init(path, config)?;
        let db = Self::open_inner(path, Some(Arc::new(cipher)))?;
        info!("RocksDB opened with encryption at rest (AES-256-GCM, values only)");
        Ok(db)
    }

    /// Bound the table files RocksDB keeps open (see `crate::fd_limit`). The
    /// default `max_open_files = -1` opens every SST at DB::Open and holds it,
    /// so a database with more SSTs than the process's open-file limit (256 for
    /// a macOS GUI-launched node) failed every open with EMFILE. Bounded, the
    /// table cache is an LRU over at most `max_open_files` table readers.
    fn bound_open_files(opts: &mut Options) -> i32 {
        let max_open_files = crate::fd_limit::rocksdb_max_open_files();
        opts.set_max_open_files(max_open_files);
        // Fewer cache shards for a small budget, so each shard holds several
        // table readers instead of one.
        if max_open_files < 1024 {
            opts.set_table_cache_num_shard_bits(4);
        }
        max_open_files
    }

    fn read_only_options() -> Options {
        let mut opts = Options::default();
        Self::bound_open_files(&mut opts);
        opts
    }

    fn open_inner(path: &Path, cipher: Option<Arc<AtRestCipher>>) -> Result<Self> {
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        let max_open_files = Self::bound_open_files(&mut db_opts);
        // Use compression in prod; disable in tests or when feature
        // `no-compression` is set. Encrypted values are high-entropy and
        // incompressible, so encryption also disables RocksDB compression.
        let compression = if cipher.is_some() || cfg!(any(test, feature = "no-compression")) {
            rocksdb::DBCompressionType::None
        } else {
            rocksdb::DBCompressionType::Lz4
        };
        db_opts.set_compression_type(compression);

        // Memory budget (see `RocksMemoryBudget`): one database-wide memtable
        // limit and one block cache shared by every column family, with index
        // and filter blocks charged to that cache, so RocksDB's footprint does
        // not scale with the number of column families or SST files.
        let budget = RocksMemoryBudget::from_env();
        db_opts.set_db_write_buffer_size(budget.memtable_bytes);
        let block_cache = rocksdb::Cache::new_lru_cache(budget.block_cache_bytes);
        let table_opts = || {
            let mut t = rocksdb::BlockBasedOptions::default();
            t.set_block_cache(&block_cache);
            t.set_cache_index_and_filter_blocks(true);
            t.set_pin_l0_filter_and_index_blocks_in_cache(true);
            t
        };

        // Performance optimizations
        db_opts.set_write_buffer_size(128 * 1024 * 1024); // 128MB
        db_opts.set_max_write_buffer_number(3);
        db_opts.set_target_file_size_base(64 * 1024 * 1024); // 64MB
        db_opts.set_max_bytes_for_level_base(512 * 1024 * 1024); // 512MB
        db_opts.increase_parallelism(num_cpus::get() as i32);
        db_opts.set_block_based_table_factory(&table_opts());

        // Create column family descriptors
        let cfs: Vec<ColumnFamilyDescriptor> = all_column_families()
            .into_iter()
            .map(|name| {
                let mut cf_opts = Options::default();
                cf_opts.set_compression_type(compression);
                cf_opts.set_block_based_table_factory(&table_opts());
                ColumnFamilyDescriptor::new(name, cf_opts)
            })
            .collect();

        let db = DB::open_cf_descriptors(&db_opts, path, cfs)?;

        info!(
            "RocksDB opened successfully (memtable budget {} MiB, shared block cache {} MiB, max open files {})",
            budget.memtable_bytes / (1024 * 1024),
            budget.block_cache_bytes / (1024 * 1024),
            max_open_files
        );
        Ok(Self {
            db: Arc::new(db),
            cipher,
            write_batch_count: Arc::new(AtomicU64::new(0)),
            write_batch_sync_count: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Sample the first value of a few high-traffic column families; if
    /// values exist and every sampled one carries the at-rest envelope
    /// prefix, this is an encrypted database whose `encryption.meta` went
    /// missing — refuse the plaintext open.
    fn probe_for_sealed_values(&self, path: &Path) -> Result<()> {
        let mut sampled = 0usize;
        let mut sealed = 0usize;
        for cf in ["blocks", "accounts", "transactions", "metadata"] {
            if let Ok(cf_handle) = self.cf_handle(cf) {
                if let Some(Ok((_, value))) = self
                    .db
                    .iterator_cf(&cf_handle, rocksdb::IteratorMode::Start)
                    .next()
                {
                    sampled = sampled.saturating_add(1);
                    if AtRestCipher::looks_sealed(&value) {
                        sealed = sealed.saturating_add(1);
                    }
                }
            }
        }
        if sampled > 0 && sealed == sampled {
            return Err(AtRestError::EncryptedValuesWithoutMeta(path.display().to_string()).into());
        }
        Ok(())
    }

    /// Whether encryption at rest is active for this database.
    pub fn is_encrypted(&self) -> bool {
        self.cipher.is_some()
    }

    /// Encryption counters (None when encryption is off).
    pub fn encryption_stats(&self) -> Option<AtRestStats> {
        self.cipher.as_ref().map(|c| c.stats())
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

    /// Get a value from a column family (decrypted when encryption is on)
    pub fn get_cf(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let cf_handle = self.cf_handle(cf)?;
        let value = self.db.get_cf(&cf_handle, key)?;
        match (&self.cipher, value) {
            (Some(cipher), Some(stored)) => Ok(Some(cipher.open_value(cf, key, &stored)?)),
            (_, value) => Ok(value),
        }
    }

    /// Put a value in a column family (encrypted when encryption is on)
    pub fn put_cf(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let cf_handle = self.cf_handle(cf)?;
        match &self.cipher {
            Some(cipher) => self
                .db
                .put_cf(&cf_handle, key, cipher.seal(cf, key, value)?)?,
            None => self.db.put_cf(&cf_handle, key, value)?,
        }
        Ok(())
    }

    /// Delete a key from a column family
    pub fn delete_cf(&self, cf: &str, key: &[u8]) -> Result<()> {
        let cf_handle = self.cf_handle(cf)?;
        self.db.delete_cf(&cf_handle, key)?;
        Ok(())
    }

    /// Check if a key exists in a column family (presence check on the
    /// stored bytes — never decrypts)
    pub fn exists_cf(&self, cf: &str, key: &[u8]) -> Result<bool> {
        let cf_handle = self.cf_handle(cf)?;
        Ok(self.db.get_pinned_cf(&cf_handle, key)?.is_some())
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

    /// Add put operation to batch (encrypted when encryption is on)
    pub fn batch_put_cf(
        &self,
        batch: &mut WriteBatch,
        cf: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<()> {
        let cf_handle = self.cf_handle(cf)?;
        match &self.cipher {
            Some(cipher) => batch.put_cf(&cf_handle, key, cipher.seal(cf, key, value)?),
            None => batch.put_cf(&cf_handle, key, value),
        }
        Ok(())
    }

    /// Add delete operation to batch
    pub fn batch_delete_cf(&self, batch: &mut WriteBatch, cf: &str, key: &[u8]) -> Result<()> {
        let cf_handle = self.cf_handle(cf)?;
        batch.delete_cf(&cf_handle, key);
        Ok(())
    }

    /// Decrypt an iterator item when encryption is on. Mirrors the
    /// existing `.filter_map(|r| r.ok())` error-swallowing semantics for
    /// storage-level errors: an undecryptable value is logged and skipped
    /// (a wrong key can never reach here — it is rejected at open time by
    /// the encryption.meta key commitment).
    fn map_iter_item(cipher: &Option<Arc<AtRestCipher>>, cf: &str, item: KvItem) -> Option<KvItem> {
        match cipher {
            None => Some(item),
            Some(cipher) => {
                let (key, stored) = item;
                match cipher.open_value(cf, &key, &stored) {
                    Ok(plain) => Some((key, plain.into_boxed_slice())),
                    Err(e) => {
                        error!(
                            "skipping undecryptable value in cf '{}' (key {}): {}",
                            cf,
                            hex::encode(key.get(..16).unwrap_or(&key)),
                            e
                        );
                        None
                    }
                }
            }
        }
    }

    /// Get iterator for a column family (values decrypted when encryption is on)
    pub fn iter_cf(&self, cf: &str) -> Result<impl Iterator<Item = KvItem> + '_> {
        let cf_handle = self.cf_handle(cf)?;
        let cipher = self.cipher.clone();
        let cf_name = cf.to_string();
        Ok(self
            .db
            .iterator_cf(&cf_handle, rocksdb::IteratorMode::Start)
            .filter_map(|r| r.ok())
            .filter_map(move |item| Self::map_iter_item(&cipher, &cf_name, item)))
    }

    /// Get iterator with prefix for a column family (values decrypted when
    /// encryption is on)
    pub fn prefix_iter_cf(
        &self,
        cf: &str,
        prefix: &[u8],
    ) -> Result<impl Iterator<Item = KvItem> + '_> {
        let cf_handle = self.cf_handle(cf)?;
        let cipher = self.cipher.clone();
        let cf_name = cf.to_string();
        Ok(self
            .db
            .prefix_iterator_cf(&cf_handle, prefix)
            .filter_map(|r| r.ok())
            .filter_map(move |item| Self::map_iter_item(&cipher, &cf_name, item)))
    }

    /// Every entry of `cf` whose key starts with `prefix`, in key order, values
    /// decrypted. Unlike [`Self::prefix_iter_cf`], a read error or a value that
    /// does not decrypt is an `Err`, never a silently missing entry: for data
    /// whose absence is unsafe (the signed-vote record).
    pub fn prefix_entries_strict_cf(&self, cf: &str, prefix: &[u8]) -> Result<Vec<KvItem>> {
        let cf_handle = self.cf_handle(cf)?;
        let mut out = Vec::new();
        for item in self.db.prefix_iterator_cf(&cf_handle, prefix) {
            let (key, stored) = item?;
            if !key.starts_with(prefix) {
                break;
            }
            let value = match &self.cipher {
                None => stored,
                Some(c) => c.open_value(cf, &key, &stored)?.into_boxed_slice(),
            };
            out.push((key, value));
        }
        Ok(out)
    }

    /// Visit the keys of `cf` that start with `prefix`, in key order, without
    /// collecting them. Unlike [`Self::prefix_iter_cf`], a storage error ends
    /// the scan with `Err` instead of being skipped, so a caller never mistakes
    /// a failed read for a missing key. An `Err` from `visit` also ends the scan
    /// and is returned. Values are not read.
    pub fn for_each_prefix_key_cf(
        &self,
        cf: &str,
        prefix: &[u8],
        mut visit: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        let cf_handle = self.cf_handle(cf)?;
        for item in self.db.prefix_iterator_cf(&cf_handle, prefix) {
            let (key, _) = item?;
            if !key.starts_with(prefix) {
                break;
            }
            visit(&key)?;
        }
        Ok(())
    }

    /// Visit the keys of `cf` from `from` (inclusive) up to `to` (exclusive;
    /// `None`: no upper bound) that start with `prefix`, in key order, without
    /// reading values or collecting them. The scan ends at the first key past
    /// `to` or without `prefix`. Errors end the scan as in
    /// [`Self::for_each_prefix_key_cf`].
    pub fn for_each_key_in_range_cf(
        &self,
        cf: &str,
        from: &[u8],
        to: Option<&[u8]>,
        prefix: &[u8],
        mut visit: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        let cf_handle = self.cf_handle(cf)?;
        let mode = rocksdb::IteratorMode::From(from, rocksdb::Direction::Forward);
        for item in self.db.iterator_cf(&cf_handle, mode) {
            let (key, _) = item?;
            if !key.starts_with(prefix) {
                break;
            }
            if let Some(end) = to {
                if key.as_ref() >= end {
                    break;
                }
            }
            visit(&key)?;
        }
        Ok(())
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

    /// Memory RocksDB holds right now, summed over every column family:
    /// memtables (active + immutable, not yet flushed), the block cache, and
    /// table readers (index/filter blocks held outside the cache).
    pub fn memory_usage(&self) -> RocksMemoryUsage {
        let mut out = RocksMemoryUsage::default();
        let prop = |cf: &rocksdb::ColumnFamily, name: &str| -> u64 {
            self.db
                .property_int_value_cf(cf, name)
                .ok()
                .flatten()
                .unwrap_or(0)
        };
        let mut caches_seen: u64 = 0;
        for cf_name in all_column_families() {
            if let Ok(cf) = self.cf_handle(cf_name) {
                out.memtables = out
                    .memtables
                    .saturating_add(prop(cf, "rocksdb.cur-size-all-mem-tables"));
                out.table_readers = out
                    .table_readers
                    .saturating_add(prop(cf, "rocksdb.estimate-table-readers-mem"));
                // With a shared cache every CF reports the same usage; with
                // per-CF caches they differ. Report the largest single reading
                // plus the sum, so either layout is visible.
                let c = prop(cf, "rocksdb.block-cache-usage");
                caches_seen = caches_seen.saturating_add(c);
                out.block_cache = out.block_cache.max(c);
            }
        }
        out.block_cache_sum_over_cfs = caches_seen;
        out
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
            cipher: self.cipher.clone(),
            write_batch_count: Arc::clone(&self.write_batch_count),
            write_batch_sync_count: Arc::clone(&self.write_batch_sync_count),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// a signed-vote value that does not decrypt must
    /// fail the export, never vanish from it (a missing vote is a vote this
    /// validator may sign again with a different hash).
    #[test]
    fn signed_vote_export_fails_on_an_undecryptable_value() {
        let dir = TempDir::new().expect("tempdir");
        let db =
            RocksDB::open_encrypted(dir.path(), &EncryptionAtRestConfig::with_raw_key([7u8; 32]))
                .expect("open");
        let good = citrate_consensus::checkpoint_gadget::signed_vote_key(40204, 50);
        let bad = citrate_consensus::checkpoint_gadget::signed_vote_key(40204, 100);
        db.put_cf("dag_metadata", &good, &[1u8; 32]).expect("seal");
        // A sealed-looking value whose tag cannot verify.
        let cf = db.cf_handle("dag_metadata").expect("cf");
        let mut garbage = db.db.get_cf(cf, &good).expect("raw read").expect("present");
        if let Some(last) = garbage.last_mut() {
            *last ^= 0xFF;
        }
        db.db.put_cf(cf, &bad, &garbage).expect("raw write");
        assert!(
            crate::signed_votes::export(&db).is_err(),
            "an undecryptable vote must fail the export"
        );
    }

    /// The replay recorder's open: reads what a writer left, beside a live
    /// writer too, and can never write.
    #[test]
    fn read_only_open_reads_and_never_writes() {
        let dir = TempDir::new().expect("tempdir");
        let writer = RocksDB::open(dir.path()).expect("open");
        writer.put_cf("blocks", b"k", b"v").expect("put");
        writer.flush().expect("flush");
        let reader = RocksDB::open_read_only(dir.path()).expect("read-only open");
        assert_eq!(
            reader.get_cf("blocks", b"k").expect("get"),
            Some(b"v".to_vec())
        );
        assert!(
            reader.put_cf("blocks", b"k2", b"v").is_err(),
            "a write went through"
        );
        drop(writer);
        let reader2 = RocksDB::open_read_only(dir.path()).expect("reopen");
        assert_eq!(
            reader2.get_cf("blocks", b"k").expect("get"),
            Some(b"v".to_vec())
        );
        assert!(
            RocksDB::open_read_only(dir.path().join("missing")).is_err(),
            "nothing is created"
        );
    }

    const MANY_SST_CHILD: &str = "CITRATE_MANY_SST_CHILD_DIR";
    const MANY_SST_KEYS: u64 = 20_000;
    const MANY_SST_EXTRA: u64 = 2_000;

    fn many_sst_key(i: u64) -> Vec<u8> {
        format!("k{i:010}").into_bytes()
    }

    fn many_sst_value(i: u64) -> Vec<u8> {
        let h = blake3::hash(&i.to_le_bytes());
        h.as_bytes().repeat(32)
    }

    fn sst_count(dir: &Path) -> usize {
        std::fs::read_dir(dir)
            .expect("read db dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "sst"))
            .count()
    }

    /// A chain database with well over 300 SST files (tiny write buffer and
    /// target file size), spread over the levels as a long-running node's is.
    /// Built with a bounded table cache so the build itself works under any
    /// fd limit.
    fn build_many_sst_db(path: &Path) -> usize {
        let small = || {
            let mut o = Options::default();
            o.set_write_buffer_size(128 * 1024);
            o.set_target_file_size_base(32 * 1024);
            o.set_max_bytes_for_level_base(256 * 1024);
            o.set_compression_type(rocksdb::DBCompressionType::None);
            o
        };
        let mut db_opts = small();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        db_opts.set_max_open_files(64);
        let cfs = vec![
            ColumnFamilyDescriptor::new("default", small()),
            ColumnFamilyDescriptor::new("state", small()),
        ];
        let db = DB::open_cf_descriptors(&db_opts, path, cfs).expect("build db");
        let cf = db.cf_handle("state").expect("state cf");
        // Keys in a scattered order (7919 is prime to the key count), so
        // flushed files overlap and compaction rewrites them into
        // target-size files instead of moving whole memtables down a level.
        let order: Vec<u64> = (0..MANY_SST_KEYS)
            .map(|i| (i * 7919) % MANY_SST_KEYS)
            .collect();
        for chunk in order.chunks(50) {
            let mut batch = WriteBatch::default();
            for &i in chunk {
                batch.put_cf(cf, many_sst_key(i), many_sst_value(i));
            }
            db.write(batch).expect("write");
        }
        db.flush_cf(cf).expect("flush");
        db.compact_range_cf(cf, None::<&[u8]>, None::<&[u8]>);
        drop(db);
        sst_count(path)
    }

    /// Production crash loop (Citrate Core 0.5.7, macOS): a node launched with
    /// the GUI soft fd limit of 256 and a chain database of 282 SSTs failed
    /// every start with "While open a file for random read: …sst: Too many
    /// open files", because RocksDB kept every table file open
    /// (`max_open_files = -1`). With the table cache bounded from the fd
    /// limit, a child process held to a soft limit of 256 opens a 300+ SST
    /// database, reads across every file, writes more, and reopens after a
    /// restart, read-write and read-only.
    #[test]
    fn many_ssts_open_read_write_and_reopen_under_a_256_fd_limit() {
        if let Ok(dir) = std::env::var(MANY_SST_CHILD) {
            let path = Path::new(&dir);
            crate::fd_limit::set_soft(256).expect("lower soft limit to 256");
            assert_eq!(crate::fd_limit::current().map(|l| l.soft), Some(256));
            assert_eq!(crate::fd_limit::rocksdb_max_open_files(), 64);
            {
                let db = RocksDB::open(path).expect("open a 300+ SST db under a 256 fd limit");
                for i in (0..MANY_SST_KEYS).step_by(7) {
                    assert_eq!(
                        db.get_cf("state", &many_sst_key(i)).expect("read"),
                        Some(many_sst_value(i)),
                        "key {i}"
                    );
                }
                assert_eq!(
                    db.iter_cf("state").expect("iter").count() as u64,
                    MANY_SST_KEYS
                );
                let mut batch = db.batch();
                for i in MANY_SST_KEYS..MANY_SST_KEYS + MANY_SST_EXTRA {
                    db.batch_put_cf(&mut batch, "state", &many_sst_key(i), &many_sst_value(i))
                        .expect("batch put");
                }
                db.write_batch_sync(batch).expect("write more");
                db.flush().expect("flush");
            }
            // Restart.
            let db = RocksDB::open(path).expect("reopen after restart");
            for i in (0..MANY_SST_KEYS + MANY_SST_EXTRA).step_by(11) {
                assert_eq!(
                    db.get_cf("state", &many_sst_key(i))
                        .expect("read after reopen"),
                    Some(many_sst_value(i)),
                    "key {i} after reopen"
                );
            }
            drop(db);
            let ro = RocksDB::open_read_only(path).expect("read-only open under 256");
            assert_eq!(
                ro.iter_cf("state").expect("iter").count() as u64,
                MANY_SST_KEYS + MANY_SST_EXTRA
            );
            return;
        }
        let dir = TempDir::new().expect("tempdir");
        let ssts = build_many_sst_db(dir.path());
        assert!(ssts > 300, "built only {ssts} SST files");
        let exe = std::env::current_exe().expect("test binary");
        let out = std::process::Command::new(exe)
            .args([
                "--exact",
                "db::rocks_db::tests::many_ssts_open_read_write_and_reopen_under_a_256_fd_limit",
                "--nocapture",
            ])
            .env(MANY_SST_CHILD, dir.path())
            .env_remove(crate::fd_limit::MAX_OPEN_FILES_ENV)
            .output()
            .expect("run child");
        assert!(
            out.status.success(),
            "child failed ({ssts} SSTs):\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("1 passed"),
            "the child ran the test"
        );
    }

    #[test]
    fn memory_budget_overrides_parse_and_clamp() {
        let d = RocksMemoryBudget::default();
        assert_eq!(RocksMemoryBudget::from_values(None, None), d);
        assert_eq!(RocksMemoryBudget::from_values(Some("junk"), Some("")), d);
        let b = RocksMemoryBudget::from_values(Some(" 256 "), Some("32"));
        assert_eq!(b.memtable_bytes, 256 * 1024 * 1024);
        assert_eq!(b.block_cache_bytes, 32 * 1024 * 1024);
        // Below the floor is raised, never honoured (0 would flush every write).
        let tiny = RocksMemoryBudget::from_values(Some("0"), Some("1"));
        assert_eq!(tiny.memtable_bytes, 8 * 1024 * 1024);
        assert_eq!(tiny.block_cache_bytes, 8 * 1024 * 1024);
    }

    /// The shared block cache never grows past its capacity, however many
    /// column families are read.
    #[test]
    fn block_cache_is_shared_and_bounded() {
        let temp_dir = TempDir::new().unwrap();
        let db = RocksDB::open(temp_dir.path()).unwrap();
        let value = vec![0x5Au8; 4096];
        let cfs = all_column_families();
        for cf in &cfs {
            let mut batch = db.batch();
            for i in 0u64..1024 {
                db.batch_put_cf(&mut batch, cf, &i.to_be_bytes(), &value)
                    .unwrap();
            }
            db.write_batch(batch).unwrap();
        }
        db.flush().unwrap();
        // Read a different number of blocks from each column family, so
        // per-CF caches would report different usage figures.
        for (n, cf) in cfs.iter().enumerate() {
            for i in 0u64..(40 * (n as u64 + 1)).min(1024) {
                assert!(db.get_cf(cf, &i.to_be_bytes()).unwrap().is_some());
            }
        }
        let usage = db.memory_usage();
        let cap = RocksMemoryBudget::default().block_cache_bytes as u64;
        assert!(usage.block_cache > 0, "reads should populate the cache");
        assert!(
            usage.block_cache <= cap,
            "block cache {} > cap {cap}",
            usage.block_cache
        );
        // One cache: every CF reports the same usage figure.
        assert_eq!(
            usage.block_cache_sum_over_cfs,
            usage.block_cache * cfs.len() as u64,
            "column families are not sharing one block cache"
        );
    }

    /// Memtables are bounded in TOTAL, not just per column family. Writing a
    /// few MB into each of the ~22 column families stays under every per-CF
    /// flush threshold, so without a database-wide write-buffer budget the
    /// memtables keep all of it in memory, indefinitely (nothing flushes an
    /// idle CF). The budget forces a flush once the total crosses it.
    #[test]
    fn memtables_are_bounded_across_column_families() {
        let temp_dir = TempDir::new().unwrap();
        let db = RocksDB::open(temp_dir.path()).unwrap();
        let per_cf: usize = 12 * 1024 * 1024;
        let value = vec![0xA5u8; 4096];
        let cfs = all_column_families();
        for cf in &cfs {
            let mut written = 0usize;
            let mut i: u64 = 0;
            while written < per_cf {
                let mut batch = db.batch();
                for _ in 0..64 {
                    db.batch_put_cf(&mut batch, cf, &i.to_be_bytes(), &value)
                        .unwrap();
                    i += 1;
                    written += value.len();
                }
                db.write_batch(batch).unwrap();
            }
        }
        let written_total = (per_cf * cfs.len()) as u64;
        let bound = RocksMemoryBudget::default().memtable_bytes as u64 * 3 / 2;
        // Flushes run in the background: give them time to release memtables.
        let mut mem = db.memory_usage().memtables;
        for _ in 0..100 {
            if mem <= bound {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
            mem = db.memory_usage().memtables;
        }
        assert!(
            mem <= bound,
            "memtables hold {mem} B after writing {written_total} B; bound {bound} B"
        );
        // Everything written is still readable after the flushes.
        for cf in &cfs {
            assert_eq!(db.get_cf(cf, &0u64.to_be_bytes()).unwrap().unwrap(), value);
        }
    }

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
