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

    /// SRP-S3b diagnostic: recompute an account's storage_root FRESH from its resident
    /// storage trie (what `calculate_state_root` folds), or `None` if no trie is resident.
    pub fn get_storage_root_recomputed(&self, address: &Address) -> Option<Hash> {
        self.storage_tries.get(address).map(|t| t.root_hash())
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

        // SRP (ADR-2026-07-21-state-root-purity, Decision §1+§2): the consensus root MUST
        // be a PURE FUNCTION of committed state — identical whether a node produced,
        // gossip-received, or cold-synced the block — never a function of dirty/insertion
        // history. The pre-fix code folded ONLY the dirty accounts into a persistent,
        // never-rebuilt accumulator, so an account/slot changed via a path that left it
        // clean at fold time (zero-reward guard, non-dirtying read-through, cache_storage)
        // kept a STALE trie value. Warm fleet nodes shared that stale accumulation and
        // agreed on a root while their committed balances diverged; a cold node rebuilt a
        // different history and computed a different root — the sync wedge.
        //
        // Fix: rebuild the trie FRESH from the full committed RESIDENT account set every
        // call (never the store — the store is stale at root time: written after the root
        // and holding the abandoned branch mid-reorg), folding EVERY account's CURRENT
        // storage_root (§2: the per-contract storage sub-tries are the same accumulator
        // class). The resident map is never evicted; a restarted node fully hydrates it
        // first (WP-2.2). Deterministic address-sorted insertion preserves the PR-#88
        // order-independence invariant.
        *state_trie = Trie::new();

        let mut all = self.accounts.all_accounts();
        all.sort_unstable_by(|a, b| a.0 .0.cmp(&b.0 .0));

        for (address, mut account) in all {
            // Fold this account's storage_root computed FRESH from its committed slot
            // trie — for EVERY account, not just dirty ones — so a slot change via any
            // path is reflected. (Recomputes identically each call → idempotent.)
            if let Some(storage_trie) = self.storage_tries.get(&address) {
                account.storage_root = storage_trie.root_hash();
                // Keep the resident account consistent with what we hash.
                self.accounts.set_account(address, account.clone());
            }

            // SRP-S3 (EIP-158): an EMPTY account (no balance/nonce/code/storage/perms)
            // carries NO committed state and is indistinguishable from an absent one, so
            // it MUST NOT be folded. The fold iterates the volatile RESIDENT map, so a
            // read-through / restart reconstruction can leave an empty account resident
            // on one node but not another with identical committed state; folding it
            // forks the chain on an empty post-restart block (block 2042). Checked AFTER
            // the fresh storage_root recompute above so an account with live storage is
            // never mistaken for empty. See ADR-2026-07-21-restart-produce-purity.
            if account.is_empty() {
                continue;
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

    /// SRP-S4 diagnostic — an INJECTIVE full-state fingerprint that DISTINGUISHES two
    /// states which `calculate_state_root` maps to the SAME root. Unlike the consensus
    /// root it (a) folds EVERY resident account INCLUDING the EIP-158-empty ones the root
    /// SKIPS (with an explicit `empty` flag), and (b) folds each account's RAW storage
    /// slots — so an empty account resident on one node but absent on another, a torn
    /// mid-reorg read, or any residency artifact changes the fingerprint even when the
    /// consensus root agrees. Deploy under `CITRATE_SRP_FINGERPRINT`, log per block, then
    /// diff two nodes at a wedge height. DIAGNOSTIC ONLY — never a consensus value.
    pub fn full_state_fingerprint(&self) -> Hash {
        use sha3::{Digest, Keccak256};
        let mut all = self.accounts.all_accounts();
        all.sort_unstable_by(|a, b| a.0 .0.cmp(&b.0 .0));
        let mut h = Keccak256::new();
        for (address, mut account) in all {
            let slots: Vec<(Vec<u8>, Vec<u8>)> = match self.storage_tries.get(&address) {
                Some(t) => {
                    account.storage_root = t.root_hash();
                    let mut s: Vec<(Vec<u8>, Vec<u8>)> = t.entries_map().into_iter().collect();
                    s.sort();
                    s
                }
                None => Vec::new(),
            };
            h.update(address.0);
            let mut bal = [0u8; 32];
            account.balance.to_big_endian(&mut bal);
            h.update(bal);
            h.update(account.nonce.to_be_bytes());
            h.update(account.code_hash.as_bytes());
            h.update(account.storage_root.as_bytes());
            h.update([u8::from(account.is_empty())]);
            for (k, v) in slots {
                h.update((k.len() as u32).to_be_bytes());
                h.update(&k);
                h.update((v.len() as u32).to_be_bytes());
                h.update(&v);
            }
        }
        Hash::new(h.finalize().into())
    }

    /// SRP-S4 diagnostic — per-account lines for the injective fingerprint above, so a
    /// diff of two nodes' dumps at a wedge height NAMES the diverging account/slot-count.
    pub fn full_state_digest_lines(&self) -> Vec<String> {
        let mut all = self.accounts.all_accounts();
        all.sort_unstable_by(|a, b| a.0 .0.cmp(&b.0 .0));
        all.into_iter()
            .map(|(address, mut account)| {
                let nslots = match self.storage_tries.get(&address) {
                    Some(t) => {
                        account.storage_root = t.root_hash();
                        t.entries_map().len()
                    }
                    None => 0,
                };
                format!(
                    "0x{} bal={} nonce={} code={} sroot={} empty={} slots={}",
                    hex::encode(address.0),
                    account.balance,
                    account.nonce,
                    hex::encode(&account.code_hash.as_bytes()[..4]),
                    hex::encode(&account.storage_root.as_bytes()[..4]),
                    u8::from(account.is_empty()),
                    nslots,
                )
            })
            .collect()
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

    // ═══════════════════════════════════════════════════════════════════════════
    // SRP-S3 (restart-produced purity): the fold in `calculate_state_root` iterates
    // the RESIDENT account map (`all_accounts()`), so the root depends on WHICH
    // accounts are materialized — a node-local, restart/history-dependent property.
    // A read-through or a restart's bulk hydration can leave an EMPTY (all-default)
    // account resident on one node but not another WITH IDENTICAL COMMITTED STATE.
    // Folding that empty account changes the root → the block-2042 split-brain on an
    // EMPTY post-restart block (reward accounts identical; a spurious empty account
    // differs). Fix: EIP-158 — an empty account is indistinguishable from an absent
    // one and MUST NOT be folded. This test FAILS on `main`, PASSES after the fix.
    #[test]
    fn srp_s3_resident_empty_account_must_not_change_root() {
        use crate::types::{Address, AccountState};
        use primitive_types::U256;

        // Two DBs reach byte-identical COMMITTED state (one non-empty account).
        let committed = Address([0x11u8; 20]);
        let a = StateDB::new();
        let b = StateDB::new();
        a.accounts.set_balance(committed, U256::from(1000u64));
        b.accounts.set_balance(committed, U256::from(1000u64));
        let root_a = a.calculate_state_root();

        // `b` additionally has a spurious RESIDENT empty account — exactly what a
        // non-dirtying read-through (`load_account` with default) or a restart's
        // reconstruction materializes. Committed state is UNCHANGED (an empty account
        // is not committed state).
        b.accounts
            .load_account(Address([0x99u8; 20]), AccountState::default());
        let root_b = b.calculate_state_root();

        assert_eq!(
            root_a, root_b,
            "SRP-S3: a resident EMPTY account must not change the consensus root \
             (EIP-158: empty ≡ absent). The root is being folded from the volatile \
             resident set, so restart-reconstructed residency forks the chain (block 2042)."
        );
    }
}


