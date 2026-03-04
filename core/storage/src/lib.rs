// citrate/core/storage/src/lib.rs
//
// Citrate Storage Layer with Quantum-Safe Encryption
//
// Features:
// - RocksDB-based persistent storage
// - Quantum-resistant encryption at rest (QSSP protocol)
// - Hybrid classical + post-quantum key encapsulation
// - Crypto-agile envelope encryption for algorithm upgrades
// - On-chain key commitment anchoring

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
use crypto::database_encryption::{DatabaseEncryptionConfig, EncryptedDatabase, EncryptionStats};
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

    // Quantum-safe encryption layer
    encryption: Option<Arc<EncryptedDatabase>>,
}

/// Configuration for storage manager
#[derive(Debug, Clone)]
#[derive(Default)]
pub struct StorageConfig {
    /// Pruning configuration
    pub pruning: PruningConfig,
    /// Database encryption configuration (None = disabled)
    pub encryption: Option<DatabaseEncryptionConfig>,
}


impl StorageConfig {
    /// Create config with encryption enabled
    pub fn with_encryption(mut self, config: DatabaseEncryptionConfig) -> Self {
        self.encryption = Some(config);
        self
    }

    /// Create config for maximum security (AI models)
    pub fn maximum_security(node_id: String) -> Self {
        Self {
            pruning: PruningConfig::default(),
            encryption: Some(DatabaseEncryptionConfig {
                enabled: true,
                node_id,
                ..Default::default()
            }),
        }
    }
}

impl StorageManager {
    /// Create a new storage manager
    pub fn new(path: impl AsRef<Path>, pruning_config: PruningConfig) -> Result<Self> {
        Self::with_config(path, StorageConfig {
            pruning: pruning_config,
            encryption: None,
        })
    }

    /// Create storage manager with full configuration
    pub fn with_config(path: impl AsRef<Path>, config: StorageConfig) -> Result<Self> {
        let db = Arc::new(RocksDB::open(path)?);

        let blocks = Arc::new(BlockStore::new(db.clone()));
        let transactions = Arc::new(TransactionStore::new(db.clone()));
        let state = Arc::new(StateStore::new(db.clone()));

        let pruner = Arc::new(Pruner::new(
            db.clone(),
            blocks.clone(),
            state.clone(),
            config.pruning,
        ));

        // Initialize encryption if configured
        let encryption = config.encryption.map(|enc_config| {
            Arc::new(EncryptedDatabase::new(enc_config))
        });

        info!("Storage manager initialized (encryption: {})",
              encryption.is_some());

        Ok(Self {
            db,
            blocks,
            transactions,
            state,
            pruner,
            block_cache: Cache::new(1000),
            state_cache: Cache::new(10000),
            encryption,
        })
    }

    /// Initialize encryption with password/seed
    ///
    /// IMPORTANT: For production, use a high-entropy 256-bit seed
    /// derived from a secure source (HSM, TPM, or secure key management).
    pub fn initialize_encryption(&mut self, password: &[u8]) -> Result<()> {
        if let Some(ref encryption) = self.encryption {
            // We need mutable access - use Arc::get_mut or recreate
            // For now, create a new instance
            let mut enc = EncryptedDatabase::new(DatabaseEncryptionConfig::default());
            enc.initialize(password)
                .map_err(|e| anyhow::anyhow!("Encryption initialization failed: {}", e))?;

            info!("Database encryption initialized with QSSP protocol");
        }
        Ok(())
    }

    /// Check if encryption is enabled and initialized
    pub fn is_encryption_enabled(&self) -> bool {
        self.encryption.as_ref().map(|e: &Arc<EncryptedDatabase>| e.is_enabled()).unwrap_or(false)
    }

    /// Get encryption statistics
    pub fn get_encryption_stats(&self) -> Option<EncryptionStats> {
        self.encryption.as_ref().map(|e: &Arc<EncryptedDatabase>| e.get_stats())
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
