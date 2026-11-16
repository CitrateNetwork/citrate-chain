// citrate/core/execution/src/state/state_db.rs

// State database managing all state
use crate::state::mpt::{Mpt, EMPTY_ROOT};
use crate::state::mpt_state::{account_trie_key, encode_account, storage_trie_key};
use crate::state::{AccountManager, Trie};
use crate::types::{Address, ExecutionError, JobId, ModelId, ModelState, TrainingJob};
use citrate_consensus::types::Hash;
use dashmap::{DashMap, DashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, info};

/// State root hash
pub type StateRoot = Hash;

/// State database managing all state
pub struct StateDB {
    /// Account manager
    pub accounts: Arc<AccountManager>,

    /// Storage tries for each account, copy-on-write: a `StateSnapshot` holds
    /// another reference to each trie instead of a deep copy, and a write after
    /// a snapshot copies only the one trie it touches (`Arc::make_mut`). The
    /// reorg ring keeps 100 snapshots, so this is what keeps its cost
    /// proportional to what changed rather than 100x the contract state. The
    /// copy itself is O(1) in the contract's slots (the slot set is a
    /// persistent map, `crate::state::slot_map`), and the write copies one
    /// O(log n) path: see [`write_trie`].
    storage_tries: Arc<DashMap<Address, Arc<Trie>>>,

    /// Contract code storage
    code_storage: Arc<DashMap<Hash, Vec<u8>>>,

    /// Model registry
    models: Arc<DashMap<ModelId, ModelState>>,

    /// Training jobs
    training_jobs: Arc<DashMap<JobId, TrainingJob>>,

    /// Global state trie (rebuilt whole by `calculate_state_root`; shared, not
    /// copied, by snapshots).
    state_trie: Arc<parking_lot::RwLock<Arc<Trie>>>,

    /// C6 fix: Track dirty storage slots for persistence.
    /// Stores (address, key) pairs that have been modified since last commit.
    dirty_storage: Arc<DashSet<(Address, Vec<u8>)>>,

    /// Track code hashes deployed since the last commit, so contract code is
    /// persisted through the SAME deferred path as accounts/storage rather than
    /// written to the store eagerly. This lets the execute-on-receive reorg
    /// re-apply a branch in-memory (`apply_block_no_persist`) with NO durable
    /// writes — an aborted reorg that deployed a contract leaves nothing on disk.
    dirty_code: Arc<DashSet<Hash>>,

    /// Height of the block whose post-state this db holds. It selects the
    /// storage-root rule (`crate::storage_root_hardening`) for
    /// [`Self::calculate_state_root`]. Set by block reward settlement (the one
    /// step the producer, block import and trusted replay all run, after
    /// execution and before the root), by restart hydration to the applied tip,
    /// and carried by snapshots so a revert restores it. `0` (genesis) until
    /// then.
    root_height: AtomicU64,

    /// Bumped on every change to `models` or `training_jobs` (and on every
    /// restore). Never decreases, so an equal value read twice from the same
    /// db means neither registry changed in between: the undo record of a
    /// block that touches neither needs no model/job comparison.
    model_job_generation: AtomicU64,

    /// CV-14: the standard secure account MPT, folded incrementally from
    /// `AccountManager::take_root_touched` (see `Self::mpt_state_root`). Shared,
    /// not copied, by snapshots (its nodes are immutable).
    account_mpt: Arc<parking_lot::Mutex<Mpt>>,

    /// Accounts folded since the trie nodes were last handed to the node store,
    /// and whether a restore made every trie a candidate (see
    /// `Self::persist_trie_nodes`).
    unpersisted: Arc<parking_lot::Mutex<(std::collections::HashSet<Address>, bool)>>,

    /// Accounts re-encoded into the account MPT so far (a cost counter: a
    /// restart that reuses persisted trie nodes folds none).
    folded_accounts: Arc<AtomicU64>,
}

/// The sink [`StateDB::persist_trie_nodes`] hands a state's new trie nodes to,
/// with its root.
pub type TrieNodeWriter<'a> =
    dyn FnMut(&StateRoot, &[crate::state::mpt::TrieNodeRecord]) -> anyhow::Result<()> + 'a;

/// Which state-root function applies to a post-state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootRule {
    /// The legacy structural root; `canonical` = storage roots from the slot set
    /// (`crate::storage_root_hardening`).
    Legacy { canonical: bool },
    /// The standard MPT root (`crate::mpt_state_root`, CV-14).
    Mpt,
}

/// What [`StateDB::reuse_persisted_trie`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrieReuse {
    /// Accounts whose leaves were checked against the resident state.
    pub accounts: usize,
    /// Storage tries loaded from the node store and installed.
    pub storage_tries: usize,
}

/// A slot proof (`eth_getProof` `storageProof` entry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageProof {
    /// The slot key as stored (32 bytes for an EVM slot).
    pub key: Vec<u8>,
    /// The resident value (`None`: absent).
    pub value: Option<Vec<u8>>,
    /// RLP of the storage-trie nodes on keccak256(key)'s path, root first.
    pub proof: Vec<Vec<u8>>,
}

/// An account proof against the MPT state root (`eth_getProof`).
/// Data source: the node's incremental account and storage MPTs in this
/// `StateDB` (the same tries the block's committed state root is the root of).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateProof {
    pub state_root: StateRoot,
    pub address: Address,
    /// RLP of the account-trie nodes on keccak256(address)'s path, root first.
    pub account_proof: Vec<Vec<u8>>,
    /// The account leaf (`None`: absent or empty). Its encoding is
    /// `crate::state::mpt_state::encode_account`.
    pub account_leaf: Option<Vec<u8>>,
    /// The account's storage root (`EMPTY_ROOT` when it holds no slot).
    pub storage_hash: [u8; 32],
    pub storage: Vec<StorageProof>,
}

impl StateDB {
    pub fn new() -> Self {
        Self {
            accounts: Arc::new(AccountManager::new()),
            storage_tries: Arc::new(DashMap::new()),
            code_storage: Arc::new(DashMap::new()),
            models: Arc::new(DashMap::new()),
            training_jobs: Arc::new(DashMap::new()),
            state_trie: Arc::new(parking_lot::RwLock::new(Arc::new(Trie::new()))),
            dirty_storage: Arc::new(DashSet::new()),
            dirty_code: Arc::new(DashSet::new()),
            root_height: AtomicU64::new(0),
            model_job_generation: AtomicU64::new(0),
            account_mpt: Arc::new(parking_lot::Mutex::new(Mpt::new())),
            unpersisted: Arc::new(parking_lot::Mutex::new((Default::default(), true))),
            folded_accounts: Arc::new(AtomicU64::new(0)),
        }
    }

    /// SRP-S4: an ISOLATED copy for RPC simulation. Copies the MUTABLE committed state
    /// (accounts, storage tries, state trie, models, training jobs) so mutations never
    /// touch `self`'s consensus state, but SHARES the immutable, content-addressed
    /// `code_storage` (a code hash always maps to the same bytes) so contract execution
    /// still finds bytecode. `snapshot()`/`restore()` alone do NOT copy code bytes (only
    /// dirty-code hashes), because the reorg use-case restores onto the SAME db where
    /// code persists; a fresh isolated db needs the shared code map.
    pub fn isolated_clone(&self) -> Self {
        let iso = Self {
            accounts: Arc::new(AccountManager::new()),
            storage_tries: Arc::new(DashMap::new()),
            code_storage: self.code_storage.clone(),
            models: Arc::new(DashMap::new()),
            training_jobs: Arc::new(DashMap::new()),
            state_trie: Arc::new(parking_lot::RwLock::new(Arc::new(Trie::new()))),
            dirty_storage: Arc::new(DashSet::new()),
            dirty_code: Arc::new(DashSet::new()),
            root_height: AtomicU64::new(0),
            model_job_generation: AtomicU64::new(0),
            account_mpt: Arc::new(parking_lot::Mutex::new(Mpt::new())),
            unpersisted: Arc::new(parking_lot::Mutex::new((Default::default(), true))),
            folded_accounts: Arc::new(AtomicU64::new(0)),
        };
        iso.restore(self.snapshot());
        iso
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
        let rule = self.root_rule(
            crate::storage_root_hardening::storage_root_hardening_height(),
            self.root_height(),
        );
        self.storage_root_with_rule(address, rule)
    }

    /// An account's storage_root under an explicit activation and height (the
    /// fold [`Self::calculate_state_root_with`] uses), or `None` if no trie is
    /// resident.
    pub fn storage_root_with(
        &self,
        activation: Option<u64>,
        height: u64,
        address: &Address,
    ) -> Option<Hash> {
        self.storage_root_with_rule(address, self.root_rule(activation, height))
    }

    fn storage_root_with_rule(&self, address: &Address, rule: RootRule) -> Option<Hash> {
        self.storage_tries
            .get(address)
            .map(|t| Self::storage_root_of(&t, rule))
    }

    /// The storage root of one trie: the MPT root under the MPT rule; else a
    /// function of its slot set from the hardening height, the legacy
    /// structural hash below it.
    fn storage_root_of(trie: &Trie, rule: RootRule) -> Hash {
        match rule {
            RootRule::Mpt => Hash::new(trie.mpt_root()),
            RootRule::Legacy { canonical: true } => trie.root_hash(),
            RootRule::Legacy { canonical: false } => trie.legacy_root_hash(),
        }
    }

    /// The root rule for the post-state of the block at `height`, under the
    /// storage-root hardening `activation` and the process-wide MPT activation.
    fn root_rule(&self, activation: Option<u64>, height: u64) -> RootRule {
        if crate::mpt_state_root::mpt_state_root_active(height) {
            RootRule::Mpt
        } else {
            RootRule::Legacy {
                canonical: crate::storage_root_hardening::active_at(activation, height),
            }
        }
    }

    /// Record the height of the block whose post-state this db now holds.
    pub fn set_root_height(&self, height: u64) {
        self.root_height.store(height, Ordering::SeqCst);
    }

    /// The height of the block whose post-state this db holds (see
    /// `root_height`).
    pub fn root_height(&self) -> u64 {
        self.root_height.load(Ordering::SeqCst)
    }

    /// Set storage value
    pub fn set_storage(&self, address: Address, key: Vec<u8>, value: Vec<u8>) {
        self.dirty_storage.insert((address, key.clone()));
        let mut trie = self
            .storage_tries
            .entry(address)
            .or_insert_with(|| Arc::new(Trie::for_current_rule()));
        write_trie(trie.value_mut()).insert(key, value);
        drop(trie);
        self.accounts.mark_root_touched(address);
    }

    /// PIL-13b: warm the in-memory storage cache from the persistent
    /// store. Unlike `set_storage`, this does NOT mark the slot dirty —
    /// the value we just loaded is already what's on disk, so re-writing
    /// it would create a no-op flush at next commit. Used by the REVM
    /// Database adapter to hydrate cold-cache misses for view calls.
    pub fn cache_storage(&self, address: Address, key: Vec<u8>, value: Vec<u8>) {
        let mut trie = self
            .storage_tries
            .entry(address)
            .or_insert_with(|| Arc::new(Trie::for_current_rule()));
        write_trie(trie.value_mut()).insert(key, value);
        drop(trie);
        // Not dirty (the store has it), but the root must still see it.
        self.accounts.mark_root_touched(address);
    }

    /// Delete storage value
    pub fn delete_storage(&self, address: Address, key: &[u8]) {
        self.dirty_storage.insert((address, key.to_vec()));
        if let Some(mut trie) = self.storage_tries.get_mut(&address) {
            write_trie(trie.value_mut()).remove(key);
        }
        self.accounts.mark_root_touched(address);
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
        self.bump_model_job_generation();
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
        self.bump_model_job_generation();
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
        self.bump_model_job_generation();
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
        self.bump_model_job_generation();
        Ok(())
    }

    /// Apply a model-registry entry recorded in a committed tx journal.
    ///
    /// Insert-or-replace: the executor already checked existence against the
    /// journal-first view when the tx ran, and the MVCC check guarantees no
    /// other committed tx changed the entry since. Only the journal drain calls
    /// this; inside a tx, write through the journal.
    pub(crate) fn apply_journaled_model(&self, model_id: ModelId, model: ModelState) {
        self.models.insert(model_id, model);
        self.bump_model_job_generation();
    }

    /// Apply a training-job entry recorded in a committed tx journal
    /// (see [`Self::apply_journaled_model`]).
    pub(crate) fn apply_journaled_job(&self, job_id: JobId, job: TrainingJob) {
        self.training_jobs.insert(job_id, job);
        self.bump_model_job_generation();
    }

    fn bump_model_job_generation(&self) {
        self.model_job_generation.fetch_add(1, Ordering::SeqCst);
    }

    /// The model/job change counter (see the field). Pair it with a
    /// [`Self::snapshot`] taken at the same moment and pass both to
    /// [`Self::model_job_pre_images`].
    pub fn model_job_generation(&self) -> u64 {
        self.model_job_generation.load(Ordering::SeqCst)
    }

    /// The model and training-job pre-images, in `prev`, of every entry that
    /// differs now (`None`: absent in `prev`). `prev` must be a snapshot of
    /// this db taken when [`Self::model_job_generation`] read `generation`;
    /// when it still reads the same, neither registry changed and the answer
    /// is empty without comparing anything.
    pub fn model_job_pre_images(
        &self,
        prev: &StateSnapshot,
        generation: u64,
    ) -> crate::executor::ModelJobUndo {
        if self.model_job_generation() == generation {
            return crate::executor::ModelJobUndo::default();
        }
        let jobs: Vec<(JobId, TrainingJob)> = self
            .training_jobs
            .iter()
            .map(|e| (*e.key(), e.value().clone()))
            .collect();
        crate::executor::ModelJobUndo {
            models: pre_images_by_encoding(&prev.models, &self.all_models()),
            jobs: pre_images_by_encoding(&prev.training_jobs, &jobs),
        }
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
    ///
    /// The storage-root rule follows the process-wide storage-root hardening
    /// height and this db's [`Self::root_height`]; see
    /// [`Self::calculate_state_root_with`].
    pub fn calculate_state_root(&self) -> StateRoot {
        self.calculate_state_root_at(self.root_height())
    }

    /// The state root of the post-state of the block at `height`, under the
    /// process-wide storage-root hardening height.
    pub fn calculate_state_root_at(&self, height: u64) -> StateRoot {
        self.calculate_state_root_with(
            crate::storage_root_hardening::storage_root_hardening_height(),
            height,
        )
    }

    /// The state root under an explicit storage-root hardening `activation`,
    /// for the post-state of the block at `height`. At and after the activation
    /// each account's `storage_root` is a function of its slot set only; below
    /// it (and with no activation) it is the legacy structural hash, so every
    /// historical root is reproduced byte for byte.
    pub fn calculate_state_root_with(&self, activation: Option<u64>, height: u64) -> StateRoot {
        // CV-14: from the MPT activation, the standard incremental root.
        let rule = self.root_rule(activation, height);
        if rule == RootRule::Mpt {
            return self.mpt_state_root();
        }
        let mut state_trie_slot = self.state_trie.write();
        let mut state_trie = Trie::new();

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

        let mut all = self.accounts.all_accounts();
        all.sort_unstable_by_key(|a| a.0 .0);

        for (address, mut account) in all {
            // Fold this account's storage_root computed FRESH from its committed slot
            // trie — for EVERY account, not just dirty ones — so a slot change via any
            // path is reflected. (Recomputes identically each call → idempotent.)
            if let Some(storage_trie) = self.storage_tries.get(&address) {
                account.storage_root = Self::storage_root_of(&storage_trie, rule);
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

        // Rebuilt by inserts only, so the structural hash is already a function
        // of the account set.
        let root = state_trie.legacy_root_hash();
        *state_trie_slot = Arc::new(state_trie);
        root
    }

    /// CV-14 (a)+(b): the standard secure MPT state root, computed
    /// incrementally.
    ///
    /// PURITY (ADR-2026-07-21-state-root-purity keeps its intent: the root
    /// commits to the committed state and to nothing else). The account trie
    /// is NOT rebuilt from the resident set every call. Instead:
    ///
    ///   * every change to a resident account or to its storage, by any path
    ///     (writes, non-dirtying loads and read-throughs, restores, undo
    ///     pre-images), records the address in `AccountManager::root_touched`,
    ///     and every storage-trie change records the slot key in that trie;
    ///   * this fold re-encodes exactly those accounts (with their storage
    ///     roots, themselves caught up the same way) and updates their paths;
    ///   * so between folds, every address not recorded has a leaf equal to the
    ///     encoding of its resident entry, and after the fold all of them do.
    ///
    /// The MPT has one shape per key/value set and each node's cached hash is a
    /// function of that node alone, so the result equals the from-scratch root
    /// of the same state ([`Self::reference_state_root`]) whatever was cached,
    /// in whatever order the changes came (`incremental_root_equals_from_scratch`,
    /// `root_is_pure_function_of_state`). Cost: O(changed keys x depth).
    pub fn mpt_state_root(&self) -> StateRoot {
        let mut trie = self.account_mpt.lock();
        let touched = self.accounts.take_root_touched();
        if touched.is_empty() {
            return Hash::new(trie.root_hash());
        }
        for address in &touched {
            let key = account_trie_key(&address.0);
            let storage_root = self
                .storage_tries
                .get(address)
                .map(|t| t.mpt_root())
                .unwrap_or(EMPTY_ROOT);
            match self.committed_account(address) {
                None => trie.remove(&key),
                Some(account) => {
                    // Keep the resident account consistent with what is hashed
                    // (`Hash::default()` is how the executor spells "no storage").
                    let folded = if storage_root == EMPTY_ROOT {
                        Hash::default()
                    } else {
                        Hash::new(storage_root)
                    };
                    self.accounts.set_folded_storage_root(*address, folded);
                    match encode_account(&account, &storage_root) {
                        Some(leaf) => trie.insert(&key, &leaf),
                        None => trie.remove(&key),
                    }
                }
            }
        }
        self.folded_accounts
            .fetch_add(touched.len() as u64, Ordering::Relaxed);
        self.unpersisted.lock().0.extend(touched);
        let root = Hash::new(trie.root_hash());
        drop(trie);
        // Debug builds (every test, every debug devnet) check the incremental
        // root against the from-scratch reference on every fold: a change that
        // reached the state without reaching `root_touched` fails here, at the
        // block that made it.
        #[cfg(debug_assertions)]
        {
            let reference = self.reference_state_root();
            debug_assert_eq!(
                root, reference,
                "CV-14: incremental MPT root != from-scratch reference (a state change bypassed root_touched)"
            );
        }
        root
    }

    /// Accounts re-encoded into the account MPT since this db was created.
    pub fn mpt_folded_accounts(&self) -> u64 {
        self.folded_accounts.load(Ordering::Relaxed)
    }

    /// The account the MPT state root commits for `address`: its resident
    /// entry, or, for an address that holds storage but has no resident entry
    /// (the governance precompile writes its slots without creating one), the
    /// default account holding those slots. `None`: nothing to commit.
    /// Spec: docs/consensus/STATE_ROOT_MPT.md §3.
    fn committed_account(&self, address: &Address) -> Option<crate::types::AccountState> {
        self.accounts.get_resident(address).or_else(|| {
            self.storage_tries
                .contains_key(address)
                .then(crate::types::AccountState::default)
        })
    }

    /// Every (address, account) [`Self::committed_account`] names: the resident
    /// accounts plus the storage-only addresses.
    fn committed_accounts(&self) -> Vec<(Address, crate::types::AccountState)> {
        let mut all = self.accounts.all_accounts();
        let resident: std::collections::HashSet<Address> = all.iter().map(|(a, _)| *a).collect();
        for entry in self.storage_tries.iter() {
            if !resident.contains(entry.key()) {
                all.push((*entry.key(), crate::types::AccountState::default()));
            }
        }
        all
    }

    /// The MPT state root of the resident state computed FROM SCRATCH: every
    /// committed account (resident, or storage-only) and slot re-encoded and
    /// the whole trie built in one pass (`mpt::root_from_sorted`), with no cache, no incremental trie and
    /// no side effect. The reference [`Self::mpt_state_root`] is tested and
    /// replayed against (tools/replay-ref).
    pub fn reference_state_root(&self) -> StateRoot {
        let entries: Vec<(Vec<u8>, Vec<u8>)> = self
            .committed_accounts()
            .into_iter()
            .filter_map(|(address, account)| {
                let storage_root = self
                    .storage_tries
                    .get(&address)
                    .map(|t| t.reference_mpt_root())
                    .unwrap_or(EMPTY_ROOT);
                encode_account(&account, &storage_root)
                    .map(|leaf| (account_trie_key(&address.0).to_vec(), leaf))
            })
            .collect();
        Hash::new(crate::state::mpt::root_from_sorted(entries))
    }

    /// The from-scratch reference for [`Self::calculate_state_root_with`]: the
    /// MPT reference under the MPT rule; the legacy root (already rebuilt from
    /// scratch every call) below it.
    pub fn reference_state_root_with(&self, activation: Option<u64>, height: u64) -> StateRoot {
        match self.root_rule(activation, height) {
            RootRule::Mpt => self.reference_state_root(),
            RootRule::Legacy { .. } => self.calculate_state_root_with(activation, height),
        }
    }

    /// Whether this db's post-state is rooted by the MPT rule.
    pub fn mpt_rule_active(&self) -> bool {
        crate::mpt_state_root::mpt_state_root_active(self.root_height())
    }

    /// The `eth_getProof` proof of `address` and its slots `keys` against the
    /// current MPT state root. Data source: this db's incremental account and
    /// storage MPTs. An error when the MPT rule is not active for this
    /// post-state (the legacy root has no proofs).
    pub fn get_proof(&self, address: &Address, keys: &[Vec<u8>]) -> Result<StateProof, String> {
        if !self.mpt_rule_active() {
            return Err(format!(
                "state proofs need the MPT state root (CV-14); it is not active at height {}",
                self.root_height()
            ));
        }
        let state_root = self.mpt_state_root();
        let account_trie = self.account_mpt.lock().clone();
        let account_key = account_trie_key(&address.0);
        let storage = self
            .storage_tries
            .get(address)
            .map(|t| t.mpt())
            .unwrap_or_default();
        Ok(StateProof {
            state_root,
            address: *address,
            account_proof: account_trie.proof(&account_key),
            account_leaf: account_trie.get(&account_key).map(<[u8]>::to_vec),
            storage_hash: storage.root_hash(),
            storage: keys
                .iter()
                .map(|k| StorageProof {
                    key: k.clone(),
                    value: self.get_storage(address, k),
                    proof: storage.proof(&storage_trie_key(k)),
                })
                .collect(),
        })
    }

    /// Hand every trie node of the current MPT state that the node store does
    /// not have yet to `write` (with the state root), then record them as
    /// persisted. Returns (root, nodes written). Under the legacy rule there
    /// is nothing to persist.
    ///
    /// The node store is a cache: a node it lacks (a failed write, a crash, a
    /// prune) makes a restart rebuild the trie from state
    /// ([`Self::reuse_persisted_trie`] fails over), never changes a root.
    pub fn persist_trie_nodes(
        &self,
        write: &mut TrieNodeWriter<'_>,
    ) -> anyhow::Result<(StateRoot, usize)> {
        let root = self.mpt_state_root();
        let account = self.account_mpt.lock().clone();
        let (addresses, all) = {
            let mut u = self.unpersisted.lock();
            (std::mem::take(&mut u.0), std::mem::replace(&mut u.1, false))
        };
        let storage: Vec<Mpt> = if all {
            self.storage_tries.iter().map(|t| t.value().mpt()).collect()
        } else {
            addresses
                .iter()
                .filter_map(|a| self.storage_tries.get(a).map(|t| t.mpt()))
                .collect()
        };
        let mut nodes = Vec::new();
        account.collect_unpersisted(&mut nodes);
        for m in &storage {
            m.collect_unpersisted(&mut nodes);
        }
        nodes.sort_unstable_by_key(|a| a.0);
        nodes.dedup_by(|a, b| a.0 == b.0);
        if let Err(e) = write(&root, &nodes) {
            // Keep them candidates for the next attempt.
            let mut u = self.unpersisted.lock();
            u.0.extend(addresses);
            u.1 |= all;
            return Err(e);
        }
        account.mark_persisted();
        for m in &storage {
            m.mark_persisted();
        }
        Ok((root, nodes.len()))
    }

    /// Restart: reuse the persisted trie with root `root` (from `source`, RLP
    /// by node hash) instead of rebuilding it from the hydrated state.
    ///
    /// Every node is checked as it loads (hash, canonical encoding and shape),
    /// and every leaf against the hydrated resident state: each account leaf
    /// must be the encoding of its resident account, each storage trie must
    /// hold exactly the resident slots, and every resident account without a
    /// leaf must be empty. Only then is the trie installed. On any difference
    /// nothing in the account trie changes and the error says why; the next
    /// root is then built from the resident state as on a cold start. Either
    /// way the root is the same function of the state (purity), the store only
    /// saves the rebuild.
    pub fn reuse_persisted_trie(
        &self,
        root: &StateRoot,
        source: &dyn Fn(&[u8; 32]) -> Option<Vec<u8>>,
    ) -> Result<TrieReuse, String> {
        use std::collections::HashMap;
        let account_trie = Mpt::load(root.as_bytes(), source).map_err(|e| e.to_string())?;
        let mut by_key: HashMap<[u8; 32], (Address, crate::types::AccountState)> = self
            .committed_accounts()
            .into_iter()
            .map(|(a, s)| (account_trie_key(&a.0), (a, s)))
            .collect();
        let mut reuse = TrieReuse {
            accounts: 0,
            storage_tries: 0,
        };
        let mut folded: Vec<(Address, Hash)> = Vec::new();
        for (key, leaf) in account_trie.entries() {
            let key = <[u8; 32]>::try_from(key.as_slice())
                .map_err(|_| "an account-trie key that is not 32 bytes".to_string())?;
            let (address, account) = by_key
                .remove(&key)
                .ok_or_else(|| format!("a leaf 0x{} for no resident account", hex::encode(key)))?;
            let storage_root = crate::state::mpt_state::account_leaf_storage_root(&leaf)
                .ok_or_else(|| format!("account {address}: malformed leaf"))?;
            let installed = match self.storage_tries.get(&address) {
                Some(t) => {
                    let m = Mpt::load(&storage_root, source).map_err(|e| e.to_string())?;
                    t.install_mpt_if_matches(m)
                }
                None => storage_root == EMPTY_ROOT,
            };
            if !installed {
                return Err(format!("account {address}: storage differs from its trie"));
            }
            if storage_root != EMPTY_ROOT {
                reuse.storage_tries = reuse.storage_tries.saturating_add(1);
            }
            if encode_account(&account, &storage_root).as_deref() != Some(leaf.as_slice()) {
                return Err(format!(
                    "account {address}: resident state differs from its leaf"
                ));
            }
            folded.push((
                address,
                if storage_root == EMPTY_ROOT {
                    Hash::default()
                } else {
                    Hash::new(storage_root)
                },
            ));
            reuse.accounts = reuse.accounts.saturating_add(1);
        }
        // Resident accounts with no leaf must be empty (absent from the trie).
        for (address, account) in by_key.values() {
            let empty_storage = match self.storage_tries.get(address) {
                Some(t) => t.install_mpt_if_matches(Mpt::new()),
                None => true,
            };
            if !empty_storage || encode_account(account, &EMPTY_ROOT).is_some() {
                return Err(format!("account {address}: resident but not in the trie"));
            }
        }
        let mut trie = self.account_mpt.lock();
        *trie = account_trie;
        let _ = self.accounts.take_root_touched();
        for (address, sr) in folded {
            self.accounts.set_folded_storage_root(address, sr);
        }
        // Everything installed came from the store.
        *self.unpersisted.lock() = (Default::default(), false);
        Ok(reuse)
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
        let rule = self.root_rule(
            crate::storage_root_hardening::storage_root_hardening_height(),
            self.root_height(),
        );
        let mut all = self.accounts.all_accounts();
        all.sort_unstable_by_key(|a| a.0 .0);
        let mut h = Keccak256::new();
        for (address, mut account) in all {
            let slots: Vec<(Vec<u8>, Vec<u8>)> = match self.storage_tries.get(&address) {
                Some(t) => {
                    account.storage_root = Self::storage_root_of(&t, rule);
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
        let rule = self.root_rule(
            crate::storage_root_hardening::storage_root_hardening_height(),
            self.root_height(),
        );
        let mut all = self.accounts.all_accounts();
        all.sort_unstable_by_key(|a| a.0 .0);
        all.into_iter()
            .map(|(address, mut account)| {
                let nslots = match self.storage_tries.get(&address) {
                    Some(t) => {
                        account.storage_root = Self::storage_root_of(&t, rule);
                        t.len()
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
            root_height: self.root_height(),
            account_mpt: self.account_mpt.lock().clone(),
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
        self.set_root_height(snapshot.root_height);
        // CV-14: the account MPT the snapshot's accounts were folded into, with
        // the snapshot's root-touched set (restored by `accounts.restore`).
        *self.account_mpt.lock() = snapshot.account_mpt;
        // The restored tries may hold nodes never handed to the store.
        self.unpersisted.lock().1 = true;

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
        self.bump_model_job_generation();

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

/// An account's value before a change (`None`: absent).
pub type AccountPreImage = (Address, Option<crate::types::AccountState>);

/// A storage slot's value before a change: `(address, slot key, value)`
/// (`None`: absent).
pub type StoragePreImage = (Address, Vec<u8>, Option<Vec<u8>>);

/// State snapshot for rollback.
///
/// `Clone` supports the execute-on-receive reorg snapshot ring
/// (`node/src/canonical_apply.rs`): the ring retains one snapshot per applied
/// block within the reorg window and must restore from a stored snapshot
/// (possibly more than once), so it clones rather than moves.
#[derive(Clone)]
pub struct StateSnapshot {
    accounts: crate::state::account::AccountSnapshot,
    /// Shared with the live `StateDB` (copy-on-write; see `StateDB::storage_tries`).
    storage_tries: Vec<(Address, Arc<Trie>)>,
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
    state_trie: Arc<Trie>,
    /// `StateDB::root_height` at snapshot time, so a revert also restores the
    /// storage-root rule of the restored state.
    root_height: u64,
    /// CV-14: the account MPT at snapshot time (shared nodes, O(1) to hold).
    /// Together with the accounts' root-touched set it is consistent with the
    /// snapshot's accounts: restoring both restores the incremental root.
    account_mpt: Mpt,
}

impl StateSnapshot {
    /// All captured accounts (address → state). For reorg store reconciliation.
    pub fn account_entries(&self) -> &[(Address, crate::types::AccountState)] {
        self.accounts.entries()
    }

    /// The pre-images, in `prev`, of every account and storage slot whose
    /// value differs in `self`: applying them to `self` with
    /// [`Self::with_pre_images`] gives `prev`'s accounts and storage. `None`
    /// means the key is absent in `prev`. Storage tries `self` still shares
    /// with `prev` (the same `Arc`: copy-on-write leaves an unchanged trie
    /// shared while `prev` holds it) are skipped without being read.
    pub fn pre_images_since(
        &self,
        prev: &StateSnapshot,
    ) -> (Vec<AccountPreImage>, Vec<StoragePreImage>) {
        use std::collections::HashMap;
        let before: HashMap<&Address, &crate::types::AccountState> =
            prev.account_entries().iter().map(|(a, s)| (a, s)).collect();
        let after: HashMap<&Address, &crate::types::AccountState> =
            self.account_entries().iter().map(|(a, s)| (a, s)).collect();
        let mut accounts = Vec::new();
        for (addr, state) in &after {
            let old = before.get(addr).copied();
            if old != Some(*state) {
                accounts.push((**addr, old.cloned()));
            }
        }
        for (addr, state) in &before {
            if !after.contains_key(addr) {
                accounts.push((**addr, Some((*state).clone())));
            }
        }

        let before_tries: HashMap<&Address, &Arc<Trie>> =
            prev.storage_tries.iter().map(|(a, t)| (a, t)).collect();
        let after_tries: HashMap<&Address, &Arc<Trie>> =
            self.storage_tries.iter().map(|(a, t)| (a, t)).collect();
        let mut storage = Vec::new();
        for (addr, trie) in &after_tries {
            let old = before_tries.get(addr).copied();
            if old.is_some_and(|o| Arc::ptr_eq(o, trie)) {
                continue;
            }
            // Only the slots that differ are visited: the two versions share
            // every other node of the slot map.
            match old {
                Some(o) => o.diff_slots(trie, |key, was, _now| {
                    storage.push((**addr, key.to_vec(), was.map(<[u8]>::to_vec)));
                }),
                None => trie.for_each_slot(|key, _| storage.push((**addr, key.to_vec(), None))),
            }
        }
        for (addr, trie) in &before_tries {
            if !after_tries.contains_key(addr) {
                trie.for_each_slot(|key, value| {
                    storage.push((**addr, key.to_vec(), Some(value.to_vec())));
                });
            }
        }
        (accounts, storage)
    }

    /// The pre-images, in `prev`, of every model and training job that differs
    /// in `self` (compared by their encoding; `None`: absent in `prev`).
    pub fn model_job_pre_images_since(
        &self,
        prev: &StateSnapshot,
    ) -> crate::executor::ModelJobUndo {
        crate::executor::ModelJobUndo {
            models: pre_images_by_encoding(&prev.models, &self.models),
            jobs: pre_images_by_encoding(&prev.training_jobs, &self.training_jobs),
        }
    }

    /// This snapshot with model and training-job pre-images applied (`Some`
    /// is written, `None` removes the entry).
    pub fn with_model_job_pre_images(mut self, undo: &crate::executor::ModelJobUndo) -> Self {
        self.models = apply_pre_images(std::mem::take(&mut self.models), &undo.models);
        self.training_jobs = apply_pre_images(std::mem::take(&mut self.training_jobs), &undo.jobs);
        self
    }

    /// This snapshot with `accounts` and `storage` pre-images applied (a
    /// `Some` value is written, `None` removes the key; a contract left with
    /// no slots keeps no trie, as a node hydrated from the store has none),
    /// nothing dirty, and `root_height` as given. Models, training jobs and
    /// shared tries are carried over unchanged. The inverse of
    /// [`Self::pre_images_since`] for accounts and storage.
    pub fn with_pre_images(
        &self,
        accounts: &[AccountPreImage],
        storage: &[StoragePreImage],
        root_height: u64,
    ) -> StateSnapshot {
        use std::collections::{HashMap, HashSet};
        let mut account_map: HashMap<Address, crate::types::AccountState> =
            self.account_entries().iter().cloned().collect();
        for (addr, state) in accounts {
            match state {
                Some(s) => {
                    account_map.insert(*addr, s.clone());
                }
                None => {
                    account_map.remove(addr);
                }
            }
        }
        let mut tries: HashMap<Address, Arc<Trie>> = self.storage_tries.iter().cloned().collect();
        let mut shrunk: HashSet<Address> = HashSet::new();
        // CV-14: every account the pre-images change, or whose storage they
        // change, must be re-folded into the (shared) account MPT.
        let mut root_touched: HashSet<Address> =
            self.accounts.root_touched().iter().copied().collect();
        root_touched.extend(accounts.iter().map(|(a, _)| *a));
        root_touched.extend(storage.iter().map(|(a, _, _)| *a));
        for (addr, key, value) in storage {
            let trie = tries
                .entry(*addr)
                .or_insert_with(|| Arc::new(Trie::for_current_rule()));
            match value {
                Some(v) => write_trie(trie).insert(key.clone(), v.clone()),
                None => {
                    write_trie(trie).remove(key);
                    shrunk.insert(*addr);
                }
            }
        }
        for addr in shrunk {
            if tries.get(&addr).is_some_and(|t| t.is_empty()) {
                tries.remove(&addr);
            }
        }
        StateSnapshot {
            accounts: crate::state::account::AccountSnapshot::from_entries(
                account_map.into_iter().collect(),
                root_touched.into_iter().collect(),
            ),
            storage_tries: tries.into_iter().collect(),
            models: self.models.clone(),
            training_jobs: self.training_jobs.clone(),
            dirty_storage: Vec::new(),
            dirty_code: Vec::new(),
            state_trie: self.state_trie.clone(),
            root_height,
            account_mpt: self.account_mpt.clone(),
        }
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

/// A storage trie made writable: copied if a snapshot shares it (O(1) in its
/// slots, see `Trie`'s `Clone`), and without its legacy tree once no legacy
/// root is reachable in this process (`crate::mpt_state_root::legacy_root_reachable`:
/// the MPT rule from genesis), so no old-format tree is maintained under it.
fn write_trie(trie: &mut Arc<Trie>) -> &mut Trie {
    let t = Arc::make_mut(trie);
    if t.has_legacy_tree() && !crate::mpt_state_root::legacy_root_reachable() {
        t.drop_legacy();
    }
    t
}

/// The entries of `before` that differ in `after` (by encoding), with their
/// `before` value; `None` for entries `after` added.
fn pre_images_by_encoding<K, V>(before: &[(K, V)], after: &[(K, V)]) -> Vec<(K, Option<V>)>
where
    K: Copy + Eq + std::hash::Hash,
    V: Clone + serde::Serialize,
{
    use std::collections::HashMap;
    let enc = |v: &V| bincode::serialize(v).ok();
    let was: HashMap<K, &V> = before.iter().map(|(k, v)| (*k, v)).collect();
    let now: HashMap<K, &V> = after.iter().map(|(k, v)| (*k, v)).collect();
    let mut out = Vec::new();
    for (k, v) in &now {
        match was.get(k) {
            Some(old) if enc(old).is_some() && enc(old) == enc(v) => {}
            old => out.push((*k, old.map(|o| (*o).clone()))),
        }
    }
    for (k, v) in &was {
        if !now.contains_key(k) {
            out.push((*k, Some((*v).clone())));
        }
    }
    out
}

/// `entries` with `pre_images` applied: `Some` is written, `None` removed.
fn apply_pre_images<K, V>(entries: Vec<(K, V)>, pre_images: &[(K, Option<V>)]) -> Vec<(K, V)>
where
    K: Copy + Eq + std::hash::Hash,
    V: Clone,
{
    let mut map: std::collections::HashMap<K, V> = entries.into_iter().collect();
    for (k, v) in pre_images {
        match v {
            Some(v) => {
                map.insert(*k, v.clone());
            }
            None => {
                map.remove(k);
            }
        }
    }
    map.into_iter().collect()
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

    /// A block's model/job pre-images, from the db and a snapshot taken with
    /// its generation: empty when neither registry changed (no comparison),
    /// otherwise exactly the entries that changed, with their earlier value.
    /// A restore counts as a change.
    #[test]
    fn model_job_pre_images_track_every_registry_change() {
        use crate::types::{ModelMetadata, UsageStats};
        let model = |version: u32| ModelState {
            owner: Address([1; 20]),
            model_hash: Hash::new([0x77; 32]),
            version,
            metadata: ModelMetadata::default(),
            access_policy: crate::types::AccessPolicy::Public,
            usage_stats: UsageStats::default(),
        };
        let (m1, m2) = (ModelId(Hash::new([1; 32])), ModelId(Hash::new([2; 32])));
        let db = StateDB::new();
        db.register_model(m1, model(1)).expect("register");
        let gen = db.model_job_generation();
        let before = db.snapshot();
        db.accounts.set_balance(Address([9; 20]), U256::from(5));
        assert_eq!(
            db.model_job_pre_images(&before, gen),
            crate::executor::ModelJobUndo::default(),
            "no registry change: empty"
        );
        db.update_model(m1, model(2)).expect("update");
        db.register_model(m2, model(1)).expect("register");
        let undo = db.model_job_pre_images(&before, gen);
        let mut got: Vec<(ModelId, Option<u32>)> = undo
            .models
            .iter()
            .map(|(id, m)| (*id, m.as_ref().map(|m| m.version)))
            .collect();
        got.sort_by_key(|(id, _)| id.0);
        assert_eq!(got, vec![(m1, Some(1)), (m2, None)]);
        assert!(undo.jobs.is_empty());
        // Applied back, the pre-images give the earlier registry.
        let back = db.snapshot().with_model_job_pre_images(&undo);
        let restored = StateDB::new();
        restored.restore(back);
        assert_eq!(restored.get_model(&m1).map(|m| m.version), Some(1));
        assert!(restored.get_model(&m2).is_none());
        // A restore moves the generation: a stale pairing never reads "unchanged".
        let gen2 = db.model_job_generation();
        db.restore(before.clone());
        assert_ne!(db.model_job_generation(), gen2);
    }

    /// The pre-images of a change, applied back, give the earlier state: the
    /// same accounts, the same slots, the same root. A trie the change never
    /// touched is not read.
    #[test]
    fn pre_images_since_and_with_pre_images_are_inverse() {
        let db = StateDB::new();
        let (a, b, c, d) = (
            Address([1; 20]),
            Address([2; 20]),
            Address([3; 20]),
            Address([4; 20]),
        );
        db.accounts.set_balance(a, U256::from(1000));
        db.accounts.set_balance(b, U256::from(7));
        db.set_storage(a, b"k1".to_vec(), b"v1".to_vec());
        db.set_storage(a, b"k2".to_vec(), b"v2".to_vec());
        db.set_storage(d, b"same".to_vec(), b"untouched".to_vec());
        let prev_root = db.calculate_state_root();
        let prev = db.snapshot();

        db.accounts.set_balance(a, U256::from(900)); // changed
        db.accounts.set_balance(c, U256::from(100)); // created
        db.set_storage(a, b"k1".to_vec(), b"v1b".to_vec()); // slot changed
        db.delete_storage(a, b"k2"); // slot removed
        db.set_storage(c, b"n".to_vec(), b"new".to_vec()); // new contract storage
        db.set_root_height(9);
        let _ = db.calculate_state_root();
        let cur = db.snapshot();

        let (accounts, storage) = cur.pre_images_since(&prev);
        assert!(
            storage.iter().all(|(addr, _, _)| *addr != d),
            "a shared, untouched trie is skipped: {storage:?}"
        );
        assert!(
            accounts.contains(&(c, None)),
            "a created account reverts to absent"
        );
        assert!(storage.contains(&(a, b"k2".to_vec(), Some(b"v2".to_vec()))));
        assert!(storage.contains(&(c, b"n".to_vec(), None)));

        let back = cur.with_pre_images(&accounts, &storage, prev.root_height);
        let restored = StateDB::new();
        restored.restore(back);
        assert_eq!(restored.calculate_state_root(), prev_root);
        assert_eq!(restored.accounts.get_balance(&a), U256::from(1000));
        assert!(!restored.accounts.exists(&c));
        assert_eq!(restored.get_storage(&a, b"k1"), Some(b"v1".to_vec()));
        assert_eq!(restored.get_storage(&a, b"k2"), Some(b"v2".to_vec()));
        assert_eq!(restored.get_storage(&c, b"n"), None);
        assert!(
            !restored.storage_tries.contains_key(&c),
            "a contract left with no slots keeps no trie, as after hydration"
        );
        assert_eq!(restored.root_height(), prev.root_height);
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
        db.set_code(addr, vec![1, 2, 3, 4]); // marks account dirty
        db.set_storage(addr, vec![7u8; 32], vec![9u8; 32]); // gives it a storage trie
        let r1 = db.calculate_state_root();
        let r2 = db.calculate_state_root();
        let r3 = db.calculate_state_root();
        assert_eq!(
            r1, r2,
            "NON-IDEMPOTENT state root: r1 != r2 (storage_root side-effect)"
        );
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
        let shuf: Vec<u8> = (0u8..48)
            .map(|i| ((i as usize * 37 + 5) % 48) as u8)
            .collect();

        let db1 = StateDB::new();
        apply(&db1, &fwd);
        let root1 = db1.calculate_state_root();

        let db2 = StateDB::new();
        apply(&db2, &rev);
        let root2 = db2.calculate_state_root();

        let db3 = StateDB::new();
        apply(&db3, &shuf);
        let root3 = db3.calculate_state_root();

        assert_eq!(
            root1, root2,
            "state root must not depend on operation order (reversed)"
        );
        assert_eq!(
            root1, root3,
            "state root must not depend on operation order (shuffled)"
        );
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
        use crate::types::{AccountState, Address};
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
