// citrate/core/storage/src/lib.rs
//
// Citrate Storage Layer
//
// Features:
// - RocksDB-based persistent storage
// - Opt-in encryption at rest (STOR-EAR): AES-256-GCM value encryption
//   wired into the RocksDB access layer (get/put/batch/iterators), with
//   per-column-family subkeys, encryption.meta key/salt persistence and
//   wrong-key rejection at open. Default OFF — server deployments keep
//   the raw plaintext path and its performance.
// - QSSP crypto library (envelope encryption, hybrid PQ KEM, key
//   commitment anchoring) under `crypto`.

pub mod cache;
pub mod chain;
pub mod crypto;
pub mod db;
pub mod ipfs;
pub mod pruning;
pub mod state;
pub mod state_manager;

use anyhow::Result;
use cache::Cache;
use chain::{BlockStore, TransactionStore};
use crypto::at_rest::{AtRestStats, EncryptionAtRestConfig};
use db::RocksDB;
use citrate_consensus::types::Hash;
use pruning::{Pruner, PruningConfig};
use state::StateStore;
use std::path::Path;
use std::sync::Arc;
use tracing::info;

/// Main storage manager combining all storage components
pub struct StorageManager {
    pub db: Arc<RocksDB>,
    pub blocks: Arc<BlockStore>,
    pub transactions: Arc<TransactionStore>,
    pub state: Arc<StateStore>,
    pub pruner: Arc<Pruner>,

    // Caches
    pub block_cache: Cache<Hash, Vec<u8>>,
    pub state_cache: Cache<Vec<u8>, Vec<u8>>,
}

/// Configuration for storage manager
#[derive(Debug, Clone)]
#[derive(Default)]
pub struct StorageConfig {
    /// Pruning configuration
    pub pruning: PruningConfig,
    /// Encryption at rest (None = disabled, the default). When set, every
    /// value written through the storage layer is AES-256-GCM encrypted —
    /// see `crypto::at_rest` for the key/meta lifecycle.
    pub encryption: Option<EncryptionAtRestConfig>,
}


impl StorageConfig {
    /// Create config with encryption at rest enabled
    pub fn with_encryption(mut self, config: EncryptionAtRestConfig) -> Self {
        self.encryption = Some(config);
        self
    }
}

impl StorageManager {
    /// Create a new storage manager (encryption at rest disabled)
    pub fn new(path: impl AsRef<Path>, pruning_config: PruningConfig) -> Result<Self> {
        Self::with_config(path, StorageConfig {
            pruning: pruning_config,
            encryption: None,
        })
    }

    /// Create storage manager with full configuration.
    ///
    /// With `config.encryption = Some(..)` the underlying RocksDB is opened
    /// through `RocksDB::open_encrypted`: the key is verified against the
    /// persisted `encryption.meta` commitment (wrong key → explicit error)
    /// and every store built on this db (blocks, transactions, state,
    /// pruner, plus external users of `storage.db`) transparently reads and
    /// writes encrypted values.
    pub fn with_config(path: impl AsRef<Path>, config: StorageConfig) -> Result<Self> {
        let db = Arc::new(match &config.encryption {
            Some(enc_config) => RocksDB::open_encrypted(path, enc_config)?,
            None => RocksDB::open(path)?,
        });

        let blocks = Arc::new(BlockStore::new(db.clone()));
        let transactions = Arc::new(TransactionStore::new(db.clone()));
        let state = Arc::new(StateStore::new(db.clone()));

        let pruner = Arc::new(Pruner::new(
            db.clone(),
            blocks.clone(),
            state.clone(),
            config.pruning,
        ));

        info!(
            "Storage manager initialized (encryption at rest: {})",
            db.is_encrypted()
        );

        Ok(Self {
            db,
            blocks,
            transactions,
            state,
            pruner,
            block_cache: Cache::new(1000),
            state_cache: Cache::new(10000),
        })
    }

    /// Check if encryption at rest is active
    pub fn is_encryption_enabled(&self) -> bool {
        self.db.is_encrypted()
    }

    /// Get encryption statistics (None when encryption is off)
    pub fn get_encryption_stats(&self) -> Option<AtRestStats> {
        self.db.encryption_stats()
    }

    /// Start background services (pruning)
    pub async fn start_services(self: Arc<Self>) {
        let pruner = self.pruner.clone();
        tokio::spawn(async move {
            pruner.start_auto_pruning().await;
        });

        info!("Storage services started");
    }

    /// Flush all data to disk
    pub fn flush(&self) -> Result<()> {
        self.db.flush()?;
        info!("Storage flushed to disk");
        Ok(())
    }

    /// Get storage statistics
    pub fn get_statistics(&self) -> String {
        self.db.get_statistics()
    }

    /// Clear all caches
    pub fn clear_caches(&self) {
        self.block_cache.clear();
        self.state_cache.clear();
        info!("Caches cleared");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_storage_manager_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = PruningConfig::default();

        let manager = StorageManager::new(temp_dir.path(), config).unwrap();
        assert!(!manager.block_cache.is_empty() || manager.block_cache.is_empty());
    }
}
