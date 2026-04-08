// citrate/core/execution/src/state/state_db.rs

// State database managing all state
use crate::state::{AccountManager, Trie};
use crate::types::{Address, ExecutionError, JobId, ModelId, ModelState, TrainingJob};
use dashmap::{DashMap, DashSet};
use citrate_consensus::types::Hash;
use std::sync::Arc;
use tracing::{debug, info};

/// State root hash
pub type StateRoot = Hash;

/// State database managing all state
pub struct StateDB {
    /// Account manager
    pub accounts: Arc<AccountManager>,

    /// Storage tries for each account
    storage_tries: Arc<DashMap<Address, Trie>>,

    /// Contract code storage
    code_storage: Arc<DashMap<Hash, Vec<u8>>>,

    /// Model registry
    models: Arc<DashMap<ModelId, ModelState>>,

    /// Training jobs
    training_jobs: Arc<DashMap<JobId, TrainingJob>>,

    /// Global state trie
    state_trie: Arc<parking_lot::RwLock<Trie>>,

    /// C6 fix: Track dirty storage slots for persistence.
    /// Stores (address, key) pairs that have been modified since last commit.
    dirty_storage: Arc<DashSet<(Address, Vec<u8>)>>,
}

impl StateDB {
    pub fn new() -> Self {
        Self {
            accounts: Arc::new(AccountManager::new()),
            storage_tries: Arc::new(DashMap::new()),
            code_storage: Arc::new(DashMap::new()),
            models: Arc::new(DashMap::new()),
            training_jobs: Arc::new(DashMap::new()),
            state_trie: Arc::new(parking_lot::RwLock::new(Trie::new())),
            dirty_storage: Arc::new(DashSet::new()),
        }
    }

    /// Get storage value
    pub fn get_storage(&self, address: &Address, key: &[u8]) -> Option<Vec<u8>> {
        self.storage_tries
            .get(address)
            .and_then(|trie| trie.get(key))
    }

    /// Set storage value
    pub fn set_storage(&self, address: Address, key: Vec<u8>, value: Vec<u8>) {
        self.dirty_storage.insert((address, key.clone()));
        self.storage_tries
            .entry(address)
            .or_default()
            .insert(key, value);
    }

    /// Delete storage value
    pub fn delete_storage(&self, address: Address, key: &[u8]) {
        self.dirty_storage.insert((address, key.to_vec()));
        if let Some(mut trie) = self.storage_tries.get_mut(&address) {
            trie.remove(key);
        }
    }

    /// Get all dirty storage slots and clear dirty tracking
    pub fn take_dirty_storage(&self) -> Vec<(Address, Vec<u8>)> {
        let entries: Vec<_> = self.dirty_storage.iter().map(|r| r.clone()).collect();
        self.dirty_storage.clear();
        entries
    }

    /// Get contract code
    pub fn get_code(&self, code_hash: &Hash) -> Option<Vec<u8>> {
        self.code_storage.get(code_hash).map(|c| c.clone())
    }

    /// Set contract code
    pub fn set_code(&self, address: Address, code: Vec<u8>) -> Hash {
        let code_hash = Self::hash_code(&code);
        self.code_storage.insert(code_hash, code);
        self.accounts.set_code_hash(address, code_hash);
        code_hash
    }

    /// Register model
    pub fn register_model(
        &self,
        model_id: ModelId,
        model: ModelState,
    ) -> Result<(), ExecutionError> {
        if self.models.contains_key(&model_id) {
            return Err(ExecutionError::Reverted("Model already exists".to_string()));
        }

        self.models.insert(model_id, model);
        info!("Registered model: {:?}", model_id);
        Ok(())
    }

    /// Get model
    pub fn get_model(&self, model_id: &ModelId) -> Option<ModelState> {
        self.models.get(model_id).map(|m| m.clone())
    }

    /// Update model
    pub fn update_model(&self, model_id: ModelId, model: ModelState) -> Result<(), ExecutionError> {
        if !self.models.contains_key(&model_id) {
            return Err(ExecutionError::ModelNotFound(model_id));
        }

        self.models.insert(model_id, model);
        Ok(())
    }

    /// Return all registered models currently in memory
    pub fn all_models(&self) -> Vec<(ModelId, ModelState)> {
        self.models
            .iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect()
    }

    /// Create training job
    pub fn create_training_job(&self, job: TrainingJob) -> Result<(), ExecutionError> {
        let job_id = job.id;
        if self.training_jobs.contains_key(&job_id) {
            return Err(ExecutionError::Reverted("Job already exists".to_string()));
        }

        self.training_jobs.insert(job_id, job);
        info!("Created training job: {:?}", job_id);
        Ok(())
    }

    /// Get training job
    pub fn get_training_job(&self, job_id: &JobId) -> Option<TrainingJob> {
        self.training_jobs.get(job_id).map(|j| j.clone())
    }

    /// Update training job
    pub fn update_training_job(
        &self,
        job_id: JobId,
        job: TrainingJob,
    ) -> Result<(), ExecutionError> {
        if !self.training_jobs.contains_key(&job_id) {
            return Err(ExecutionError::Reverted("Job not found".to_string()));
        }

        self.training_jobs.insert(job_id, job);
        Ok(())
    }

    /// Calculate state root
    pub fn calculate_state_root(&self) -> StateRoot {
        let mut state_trie = self.state_trie.write();

        // Update state trie with account data
        for address in self.accounts.get_dirty_accounts() {
            let account = self.accounts.get_account(&address);
            let encoded = match bincode::serialize(&account) {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::error!("Account serialization failed for {:?}: {}", address, e);
                    continue;
                }
            };
            state_trie.insert(address.0.to_vec(), encoded);

            // Update storage root for account
            if let Some(storage_trie) = self.storage_tries.get(&address) {
                let storage_root = storage_trie.root_hash();
                let mut account = self.accounts.get_account(&address);
                account.storage_root = storage_root;
                self.accounts.set_account(address, account);
            }
        }

        state_trie.root_hash()
    }

    /// Commit state changes
    pub fn commit(&self) -> StateRoot {
        let root = self.calculate_state_root();
        self.accounts.clear_dirty();
        debug!("State committed with root: {:?}", root);
        root
    }

    /// Get the current state root hash (non-mutating)
    ///
    /// This returns the root hash of the current state trie without
    /// committing any changes. Used for block building verification.
    pub fn get_root_hash(&self) -> anyhow::Result<StateRoot> {
        Ok(self.calculate_state_root())
    }

    /// Create snapshot for rollback
    pub fn snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            accounts: self.accounts.snapshot(),
            storage_tries: self
                .storage_tries
                .iter()
                .map(|e| (*e.key(), e.value().clone()))
                .collect(),
            models: self
                .models
                .iter()
                .map(|e| (*e.key(), e.value().clone()))
                .collect(),
            training_jobs: self
                .training_jobs
                .iter()
                .map(|e| (*e.key(), e.value().clone()))
                .collect(),
            dirty_storage: self
                .dirty_storage
                .iter()
                .map(|entry| entry.clone())
                .collect(),
        }
    }

    /// Restore from snapshot
    pub fn restore(&self, snapshot: StateSnapshot) {
        // Restore accounts
        self.accounts.restore(snapshot.accounts);

        // Restore storage tries
        self.storage_tries.clear();
        for (addr, trie) in snapshot.storage_tries {
            self.storage_tries.insert(addr, trie);
        }

        self.dirty_storage.clear();
        for entry in snapshot.dirty_storage {
            self.dirty_storage.insert(entry);
        }

        // Restore models
        self.models.clear();
        for (id, model) in snapshot.models {
            self.models.insert(id, model);
        }

        // Restore training jobs
        self.training_jobs.clear();
        for (id, job) in snapshot.training_jobs {
            self.training_jobs.insert(id, job);
        }

        debug!("State restored from snapshot");
    }

    /// Hash code using Keccak256
    fn hash_code(code: &[u8]) -> Hash {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(code);
        Hash::new(hasher.finalize().into())
    }
}

impl Default for StateDB {
    fn default() -> Self {
        Self::new()
    }
}

/// State snapshot for rollback
pub struct StateSnapshot {
    accounts: crate::state::account::AccountSnapshot,
    storage_tries: Vec<(Address, Trie)>,
    models: Vec<(ModelId, ModelState)>,
    training_jobs: Vec<(JobId, TrainingJob)>,
    dirty_storage: Vec<(Address, Vec<u8>)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitive_types::U256;

    #[test]
    fn test_storage_operations() {
        let db = StateDB::new();
        let addr = Address([1; 20]);

        // Set storage
        db.set_storage(addr, b"key1".to_vec(), b"value1".to_vec());
        db.set_storage(addr, b"key2".to_vec(), b"value2".to_vec());

        // Get storage
        assert_eq!(db.get_storage(&addr, b"key1"), Some(b"value1".to_vec()));
        assert_eq!(db.get_storage(&addr, b"key2"), Some(b"value2".to_vec()));

        // Delete storage
        db.delete_storage(addr, b"key1");
        assert_eq!(db.get_storage(&addr, b"key1"), None);
    }

    // -----------------------------------------------------------------------
    // Property-based tests (proptest)
    // -----------------------------------------------------------------------
    use proptest::prelude::*;

    proptest! {
        /// Property: set_storage then get_storage round-trip returns the same value.
        #[test]
        fn prop_storage_set_get_roundtrip(
            addr_byte in any::<u8>(),
            key in prop::collection::vec(any::<u8>(), 1..32),
            value in prop::collection::vec(any::<u8>(), 1..64),
        ) {
            let db = StateDB::new();
            let mut addr_bytes = [0u8; 20];
            addr_bytes[0] = addr_byte;
            let addr = Address(addr_bytes);
            db.set_storage(addr, key.clone(), value.clone());
            let retrieved = db.get_storage(&addr, &key);
            prop_assert_eq!(retrieved, Some(value),
                "get_storage must return value set by set_storage");
        }
    }

    #[test]
    fn test_code_storage() {
        let db = StateDB::new();
        let addr = Address([1; 20]);
        let code = vec![0x60, 0x60, 0x60, 0x40];

        let code_hash = db.set_code(addr, code.clone());

        assert_eq!(db.get_code(&code_hash), Some(code));
        assert_eq!(db.accounts.get_code_hash(&addr), code_hash);
    }

    #[test]
    fn test_snapshot_restore() {
        let db = StateDB::new();
        let addr = Address([1; 20]);

        // Set initial state
        db.accounts.set_balance(addr, U256::from(1000));
        db.set_storage(addr, b"key".to_vec(), b"value".to_vec());

        // Create snapshot
        let snapshot = db.snapshot();

        // Modify state
        db.accounts.set_balance(addr, U256::from(2000));
        db.set_storage(addr, b"key".to_vec(), b"new_value".to_vec());

        // Verify changes
        assert_eq!(db.accounts.get_balance(&addr), U256::from(2000));
        assert_eq!(db.get_storage(&addr, b"key"), Some(b"new_value".to_vec()));

        // Restore snapshot
        db.restore(snapshot);

        // Verify restoration
        assert_eq!(db.accounts.get_balance(&addr), U256::from(1000));
        assert_eq!(db.get_storage(&addr, b"key"), Some(b"value".to_vec()));
    }
}
