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

    /// Track code hashes deployed since the last commit, so contract code is
    /// persisted through the SAME deferred path as accounts/storage rather than
    /// written to the store eagerly. This lets the execute-on-receive reorg
    /// re-apply a branch in-memory (`apply_block_no_persist`) with NO durable
    /// writes — an aborted reorg that deployed a contract leaves nothing on disk.
    dirty_code: Arc<DashSet<Hash>>,
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
            dirty_code: Arc::new(DashSet::new()),
        }
    }

    /// Drain the set of code hashes deployed since the last commit (for the
    /// caller to persist). Clears the dirty-code set.
    pub fn take_dirty_code(&self) -> Vec<(Hash, Vec<u8>)> {
        let hashes: Vec<Hash> = self.dirty_code.iter().map(|h| *h).collect();
        let mut out = Vec::with_capacity(hashes.len());
        for h in hashes {
            self.dirty_code.remove(&h);
            if let Some(code) = self.code_storage.get(&h) {
                out.push((h, code.clone()));
            }
        }
        out
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

    /// PIL-13b: warm the in-memory storage cache from the persistent
    /// store. Unlike `set_storage`, this does NOT mark the slot dirty —
    /// the value we just loaded is already what's on disk, so re-writing
    /// it would create a no-op flush at next commit. Used by the REVM
    /// Database adapter to hydrate cold-cache misses for view calls.
    pub fn cache_storage(&self, address: Address, key: Vec<u8>, value: Vec<u8>) {
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
        self.dirty_code.insert(code_hash);
        self.accounts.set_code_hash(address, code_hash);
        code_hash
    }

    /// PIL-13b: warm the in-memory code cache with bytecode loaded from
    /// the persistent store. Unlike `set_code`, this takes the already-
    /// known `code_hash` (the store keys code by hash) and does not
    /// touch any account's `code_hash` — the caller has already
    /// determined which account owns this code. Used by the REVM
    /// Database adapter to hydrate cold-cache misses without recomputing
    /// the hash.
    pub fn cache_code(&self, code_hash: Hash, code: Vec<u8>) {
        self.code_storage.insert(code_hash, code);
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

    /// Calculate state root.
    ///
    /// CONSENSUS-CRITICAL — must be IDEMPOTENT and a PURE function of the
    /// current account/storage state. The previous implementation inserted each
    /// dirty account into the trie with its CURRENT `storage_root`, then
    /// recomputed and wrote back a fresh `storage_root` as a side effect
    /// *after* the insert. Because a dirty account stays dirty until `commit`,
    /// a second call inserted the now-updated `storage_root` and produced a
    /// DIFFERENT root. The producer calls this 2-3x per block while a validator
    /// calls it once, so for any block touching contract storage the producer's
    /// claimed root and the validator's computed root diverged — splitting the
    /// fleet (observed at block 235: claimed d9238df1 vs computed 5fb263db).
    ///
    /// The fix has two parts:
    ///
    /// 1. Fold the freshly-computed `storage_root` into the account BEFORE
    ///    encoding and inserting it, so the trie value written for an address is
    ///    the final account state on the very first call. Repeated calls
    ///    recompute the identical `storage_root` and insert identical bytes, so
    ///    the root is stable (see `idempotency_probe`).
    ///
    /// 2. Insert accounts in ADDRESS-SORTED order. `get_dirty_accounts()`
    ///    iterates a `DashMap` whose order is randomized per-instance, and the
    ///    hand-rolled `Trie` is NOT canonically insertion-order-independent for
    ///    all key distributions (it is a bespoke structure, not a normalized
    ///    MPT). Inserting in random order therefore produced a different root on
    ///    each node for the identical state — the deeper half of the fleet split.
    ///    A fixed sort makes every node build the trie via the same insertion
    ///    sequence (and since execution is deterministic + serial, every node
    ///    marks the same accounts dirty per block), so the accumulated trie —
    ///    and its root — is identical across the fleet (see
    ///    `state_root_is_operation_order_independent`).
    pub fn calculate_state_root(&self) -> StateRoot {
        let mut state_trie = self.state_trie.write();

        // Deterministic insertion order (see doc item 2).
        let mut dirty = self.accounts.get_dirty_accounts();
        dirty.sort_unstable_by(|a, b| a.0.cmp(&b.0));

        // Update state trie with account data
        for address in dirty {
            let mut account = self.accounts.get_account(&address);

            // Fold the CURRENT storage root into the account first, so the
            // encoded trie value is a pure function of state (idempotent). An
            // account with no storage trie keeps its existing `storage_root`.
            if let Some(storage_trie) = self.storage_tries.get(&address) {
                account.storage_root = storage_trie.root_hash();
                // Keep the account store consistent with what we hash. This
                // re-marks the account dirty, but every future call recomputes
                // the identical storage_root, so the result stays stable.
                self.accounts.set_account(address, account.clone());
            }

            let encoded = match bincode::serialize(&account) {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::error!("Account serialization failed for {:?}: {}", address, e);
                    continue;
                }
            };
            state_trie.insert(address.0.to_vec(), encoded);
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
            dirty_code: self.dirty_code.iter().map(|h| *h).collect(),
            state_trie: self.state_trie.read().clone(),
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

        // Restore the dirty-code set so a reverted deploy is not later persisted
        // (its code_storage entry may remain — harmless, content-addressed orphan).
        self.dirty_code.clear();
        for h in snapshot.dirty_code {
            self.dirty_code.insert(h);
        }

        // Restore the accumulating account trie (see StateSnapshot::state_trie).
        *self.state_trie.write() = snapshot.state_trie;

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

/// State snapshot for rollback.
///
/// `Clone` supports the execute-on-receive reorg snapshot ring
/// (`node/src/canonical_apply.rs`): the ring retains one snapshot per applied
/// block within the reorg window and must restore from a stored snapshot
/// (possibly more than once), so it clones rather than moves.
#[derive(Clone)]
pub struct StateSnapshot {
    accounts: crate::state::account::AccountSnapshot,
    storage_tries: Vec<(Address, Trie)>,
    models: Vec<(ModelId, ModelState)>,
    training_jobs: Vec<(JobId, TrainingJob)>,
    dirty_storage: Vec<(Address, Vec<u8>)>,
    /// Code hashes deployed-but-not-yet-persisted at snapshot time. Captured so a
    /// revert (failed apply, aborted reorg) does not later persist a reverted
    /// deploy's code. See `StateDB::dirty_code`.
    dirty_code: Vec<Hash>,
    /// The accumulating account trie. `calculate_state_root` mutates this (it is NOT
    /// rebuilt from scratch), so a snapshot that omitted it left the trie polluted after
    /// a restore — a rejected apply_block would then still report the (uncommitted)
    /// candidate root. Capturing + restoring it makes revert byte-exact.
    state_trie: Trie,
}

impl StateSnapshot {
    /// All captured accounts (address → state). For reorg store reconciliation.
    pub fn account_entries(&self) -> &[(Address, crate::types::AccountState)] {
        self.accounts.entries()
    }

    /// All captured contract storage as address → (slot key → value). Enumerated
    /// from each contract's storage trie. For reorg store reconciliation.
    pub fn storage_map(
        &self,
    ) -> std::collections::HashMap<Address, std::collections::HashMap<Vec<u8>, Vec<u8>>> {
        self.storage_tries
            .iter()
            .map(|(addr, trie)| (*addr, trie.entries_map()))
            .collect()
    }
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

#[cfg(test)]
mod idempotency_probe {
    use super::*;

    /// DECISIVE PROBE (fleet-split non-determinism): `calculate_state_root`
    /// inserts a dirty account into the persistent trie with its CURRENT
    /// `storage_root`, then recomputes+writes back a fresh `storage_root` as a
    /// side effect. The account stays dirty (only `commit` clears dirty), so a
    /// SECOND call inserts the now-updated `storage_root` → a DIFFERENT trie
    /// value → a DIFFERENT root. The producer calls this 2-3x/block; the
    /// validator calls it once → they compute different roots for any block
    /// touching contract storage. That is the "claimed vs computed" split.
    #[test]
    fn calculate_state_root_is_idempotent() {
        let db = StateDB::new();
        let addr = Address([0x11u8; 20]);
        db.set_code(addr, vec![1, 2, 3, 4]);              // marks account dirty
        db.set_storage(addr, vec![7u8; 32], vec![9u8; 32]); // gives it a storage trie
        let r1 = db.calculate_state_root();
        let r2 = db.calculate_state_root();
        let r3 = db.calculate_state_root();
        assert_eq!(r1, r2, "NON-IDEMPOTENT state root: r1 != r2 (storage_root side-effect)");
        assert_eq!(r2, r3, "NON-IDEMPOTENT state root: r2 != r3");
    }

    /// DIRECT MODEL of the fleet split: the producer computes the root by calling
    /// `calculate_state_root` more than once per block (producer.rs:986 then
    /// again at :1051), while a validator computes it once (canonical_apply.rs:985)
    /// on a freshly-executed copy of the same state. For a block that touches
    /// contract storage, the buggy side-effect made the producer's later call and
    /// the validator's single call insert different `storage_root`s → different
    /// roots → the exact "claimed vs computed" mismatch that split the fleet.
    /// Both paths reach the SAME logical state, so their roots must be equal.
    #[test]
    fn producer_multicall_and_validator_singlecall_agree_with_storage() {
        let addr = Address([0x22u8; 20]);

        // Producer: build state, then compute the root MORE THAN ONCE.
        let producer = StateDB::new();
        producer.set_code(addr, vec![9, 9, 9]);
        producer.set_storage(addr, vec![1u8; 32], vec![2u8; 32]);
        let _first = producer.calculate_state_root(); // producer.rs:986
        let producer_root = producer.calculate_state_root(); // producer.rs:1051

        // Validator: fresh executor reaches the identical logical state, ONE call.
        let validator = StateDB::new();
        validator.set_code(addr, vec![9, 9, 9]);
        validator.set_storage(addr, vec![1u8; 32], vec![2u8; 32]);
        let validator_root = validator.calculate_state_root(); // canonical_apply.rs:985

        assert_eq!(
            producer_root, validator_root,
            "producer (multi-call) and validator (single-call) roots diverged on a storage block \
             — this is the fleet-split bug"
        );
    }

    /// The root must be a PURE function of the final state — independent of the
    /// ORDER operations were applied in (two nodes execute the same block but may
    /// touch accounts/storage in different internal orders).
    #[test]
    fn state_root_is_operation_order_independent() {
        // Enough distinct accounts that any order-dependent hashing (e.g. folding
        // a HashMap in iteration order) reliably diverges between the two runs —
        // a 2-account version was too small to catch it.
        let mk = |i: u8| {
            let mut a = [0u8; 20];
            a[0] = i;
            a[19] = i.wrapping_mul(3).wrapping_add(1);
            Address(a)
        };
        let apply = |db: &StateDB, order: &[u8]| {
            for &i in order {
                let addr = mk(i);
                db.set_code(addr, vec![i, i.wrapping_add(1)]);
                db.set_storage(addr, vec![i; 32], vec![i.wrapping_mul(7); 32]);
            }
        };
        let fwd: Vec<u8> = (0u8..48).collect();
        let rev: Vec<u8> = (0u8..48).rev().collect();
        let shuf: Vec<u8> = (0u8..48).map(|i| ((i as usize * 37 + 5) % 48) as u8).collect();

        let db1 = StateDB::new();
        apply(&db1, &fwd);
        let root1 = db1.calculate_state_root();

        let db2 = StateDB::new();
        apply(&db2, &rev);
        let root2 = db2.calculate_state_root();

        let db3 = StateDB::new();
        apply(&db3, &shuf);
        let root3 = db3.calculate_state_root();

        assert_eq!(root1, root2, "state root must not depend on operation order (reversed)");
        assert_eq!(root1, root3, "state root must not depend on operation order (shuffled)");
    }
}

/// SRP-S1 WP-1.2 — RED probes for the state-root PURITY bug.
///
/// These encode ADR-2026-07-21-state-root-purity Decision §1 (root = pure function of the
/// committed set) and §2 (the per-contract storage sub-tries are the SAME accumulator bug),
/// and are the pass/fail oracle for SRP-S1 Phase 2. They MUST FAIL on the current
/// accumulator implementation and pass once `calculate_state_root` derives BOTH the account
/// trie and every `storage_root` from the committed resident set each call.
///
/// The mechanism they exploit: `calculate_state_root` re-folds `storage_root` only for
/// accounts DIRTY at the instant it runs (`:247`), off a persistent, never-rebuilt
/// `storage_trie` (`:20`). `cache_storage` (`:95-100`) changes a slot WITHOUT marking the
/// account dirty (it models the lazy read-through hydration `revm_adapter.rs:261-296`). So a
/// slot can change in committed state while the root keeps a stale value — the exact class of
/// bug that put the live fleet on the same root with different committed state.
#[cfg(test)]
mod srp_purity_red {
    use super::*;

    /// The direct model of the live fleet split, at the storage layer: two StateDBs reach
    /// the SAME committed state (contract `c`, slot `k` = `v2`) via different histories, and
    /// MUST commit the same root. On `main` they diverge because `db_hist` folded `v1` and
    /// never re-folded after the non-dirtying change to `v2`.
    #[test]
    fn state_root_is_pure_function_of_committed_state() {
        let c = Address([0x44u8; 20]);
        let k = vec![2u8; 32];
        let v1 = vec![0x11u8; 32];
        let v2 = vec![0x22u8; 32];

        // db_hist: fold v1, commit (clears dirty), then change the slot to v2 via the
        // non-dirtying hydration path — committed state is now v2 but the account is clean.
        let db_hist = StateDB::new();
        db_hist.set_code(c, vec![9, 9, 9]);
        db_hist.set_storage(c, k.clone(), v1);
        let _ = db_hist.commit();
        db_hist.cache_storage(c, k.clone(), v2.clone());
        assert_eq!(
            db_hist.get_storage(&c, &k),
            Some(v2.clone()),
            "precondition: committed slot must be v2 after cache_storage"
        );
        let root_hist = db_hist.calculate_state_root();

        // db_fresh: reach the SAME committed state directly (v2 dirty-folded).
        let db_fresh = StateDB::new();
        db_fresh.set_code(c, vec![9, 9, 9]);
        db_fresh.set_storage(c, k.clone(), v2);
        let root_fresh = db_fresh.calculate_state_root();

        assert_eq!(
            root_hist, root_fresh,
            "IMPURE ROOT (SRP): identical committed state, different root — the root is a \
             function of dirty/insertion history, not of committed state (state_db.rs:247,257)"
        );
    }

    /// A committed storage change that did not re-dirty the account MUST move the root.
    /// On `main` the root is unchanged (the storage_root is stale) — RED.
    #[test]
    fn storage_root_reflects_committed_slot_not_dirty_history() {
        let c = Address([0x55u8; 20]);
        let k = vec![3u8; 32];
        let db = StateDB::new();
        db.set_code(c, vec![7, 7]);
        db.set_storage(c, k.clone(), vec![0xAAu8; 32]);
        let root_before = db.commit(); // folds storage_root over 0xAA, clears dirty

        // Committed state changes to 0xBB via the non-dirtying path.
        db.cache_storage(c, k.clone(), vec![0xBBu8; 32]);
        assert_eq!(db.get_storage(&c, &k), Some(vec![0xBBu8; 32]));

        let root_after = db.calculate_state_root();
        assert_ne!(
            root_after, root_before,
            "STORAGE STALENESS (SRP): the root ignored a committed slot change — storage \
             sub-trie is a stale accumulator (state_db.rs:20,257-258)"
        );
    }
}


