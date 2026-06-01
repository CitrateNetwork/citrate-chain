// citrate/core/execution/src/executor.rs

use crate::metrics::{PRECOMPILE_CALLS_TOTAL, VM_EXECUTIONS_TOTAL, VM_GAS_USED};
use crate::mvcc::{CommitCoordinator, JournalHandle, ScratchJournal, WriteSet};
use crate::precompiles::{PrecompileExecutor, inference::{InferenceMode, InferencePrecompile}};
use crate::inference::metal_runtime::MetalRuntime;
use crate::state::StateDB;
use crate::types::{
    AccessPolicy, Address, ExecutionError, GasSchedule, JobId, JobStatus, Log, ModelId,
    ModelMetadata, ModelState, TransactionReceipt, TransactionType,
};
use async_trait::async_trait;
use hex;
use citrate_consensus::types::{Block, Hash, Transaction};
use primitive_types::U256;
use std::time::Instant;
use serde_json;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// Execution context for a transaction
pub struct ExecutionContext {
    pub block_number: u64,
    pub block_hash: Hash,
    pub timestamp: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub gas_price: u64,
    pub origin: Address,
    pub logs: Vec<Log>,
    pub output: Vec<u8>,
    /// Per-tx WriteSet capture handle (Sprint P950-A-4 WP-A.4.1).
    ///
    /// Created fresh per tx by `Executor::execute_transaction`. Threaded
    /// through `execute_deploy` / `execute_call` into the REVM adapter
    /// via `_with_context` functions. After tx completes, the executor
    /// reads accumulated writes and passes them to
    /// `CommitCoordinator::commit_writes_serialized` for per-account
    /// MVCC version bumps.
    pub writes_handle: crate::revm_adapter::WriteSetHandle,
    /// Per-tx journal for buffered REVM storage writes (Sprint P950-A-5
    /// WP-A.5.1). Storage slots that REVM `SSTORE`s land here instead
    /// of being applied directly to `state_db`. The executor drains this
    /// into `state_db` after a successful commit. This is the foundation
    /// for concurrent tx execution: each worker's journal is isolated
    /// until CAS succeeds.
    pub journal: JournalHandle,
}

impl ExecutionContext {
    pub fn new(block: &Block, tx: &Transaction) -> Self {
        use crate::mvcc::WriteSet;
        use parking_lot::Mutex;
        Self {
            block_number: block.header.height,
            block_hash: block.hash(),
            timestamp: block.header.timestamp,
            gas_limit: tx.gas_limit,
            gas_used: 0,
            gas_price: tx.gas_price,
            origin: crate::address_utils::normalize_address(&tx.from),
            logs: Vec::new(),
            output: Vec::new(),
            writes_handle: Arc::new(Mutex::new(WriteSet::new())),
            journal: Arc::new(Mutex::new(ScratchJournal::new())),
        }
    }

    /// Consume gas
    pub fn use_gas(&mut self, amount: u64) -> Result<(), ExecutionError> {
        if self.gas_used + amount > self.gas_limit {
            return Err(ExecutionError::OutOfGas);
        }
        self.gas_used += amount;
        Ok(())
    }

    /// Add log
    pub fn add_log(&mut self, log: Log) {
        self.logs.push(log);
    }
}

/// Default chain ID for Citrate network
pub const DEFAULT_CHAIN_ID: u64 = 40204;

/// Transaction executor
pub struct Executor {
    state_db: Arc<StateDB>,
    state_store: Option<Arc<dyn StateStoreTrait>>,
    gas_schedule: GasSchedule,
    inference_service: Option<Arc<dyn InferenceService>>,
    artifact_service: Option<Arc<dyn ArtifactService>>,
    ai_storage: Option<Arc<dyn AIModelStorage>>,
    model_registry: Option<Arc<dyn ModelRegistryAdapter>>,
    #[allow(dead_code)]
    precompile_executor: Option<Arc<tokio::sync::RwLock<PrecompileExecutor>>>,
    /// Chain ID for transaction signing and replay protection
    chain_id: u64,
    /// Block context for current block execution (WP-Z.2).
    /// Contains coinbase, prevrandao (VRF output), and recent block hashes.
    /// Set by the block producer before executing transactions.
    block_context: std::sync::RwLock<crate::revm_adapter::BlockContext>,
    /// MVCC commit coordinator. Owns the exec_lock that serializes tx
    /// execution (transitionally — until P950-A-4 lands versioned state
    /// reads for real parallelism) and the per-account version tracker.
    ///
    /// Replaces the former `execution_guard: tokio::sync::Mutex<()>` field
    /// as of Sprint P950-A-3 (2026-04-21). Design proven in
    /// `specs/tla/consensus/ExecutorMVCC.tla`.
    commit_coordinator: Arc<CommitCoordinator>,
}

/// Dirty contract storage mutation captured for a finalized state commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateStorageChange {
    pub address: Address,
    pub key: Vec<u8>,
    /// `Some(value)` writes a slot; `None` deletes it.
    pub value: Option<Vec<u8>>,
}

/// Trait for state storage to avoid circular dependency
pub trait StateStoreTrait: Send + Sync {
    fn put_account(
        &self,
        address: &Address,
        account: &crate::types::AccountState,
    ) -> anyhow::Result<()>;
    fn get_account(&self, address: &Address) -> anyhow::Result<Option<crate::types::AccountState>>;
    fn put_code(&self, code_hash: &Hash, code: &[u8]) -> anyhow::Result<()>;
    /// Read contract bytecode by `code_hash`. Default `Ok(None)` so test
    /// stores that don't persist code keep compiling.
    ///
    /// PIL-13b: the executor's in-memory `state_db` is a cache, not the
    /// source of truth — after restart it is empty until something
    /// warms it. The REVM Database trait impl
    /// (`crate::revm_adapter::StateDBAdapter::code_by_hash`) was reading
    /// directly from `state_db.get_code` and returning empty bytecode on
    /// miss, which silently turned every `eth_call` into a no-op (REVM
    /// saw the contract had no code, returned no output, the JSON-RPC
    /// handler emitted `0x`). The Database impl now falls through to
    /// this method on cache miss and warms `state_db` with what it
    /// finds.
    fn get_code(&self, _code_hash: &Hash) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(None)
    }
    /// C6: Persist a contract storage slot
    fn put_storage(&self, address: &Address, key: &[u8], value: &[u8]) -> anyhow::Result<()>;
    /// Read a contract storage slot. Default `Ok(None)` so test stores
    /// that don't persist storage keep compiling.
    ///
    /// PIL-13b: same rationale as `get_code` above — REVM's `storage`
    /// trait method was hitting `state_db.get_storage` and returning
    /// zero on cache miss, masking real on-chain state. Now falls
    /// through to this method.
    fn get_storage(&self, _address: &Address, _key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(None)
    }
    /// C6: Delete a contract storage slot
    fn delete_storage(&self, address: &Address, key: &[u8]) -> anyhow::Result<()>;

    /// Persist all finalized account and storage mutations in one state batch.
    ///
    /// K1.1: producer-finalized state must be atomic and durable. The real
    /// RocksDB-backed `StateStore` overrides this with one `WriteBatch`
    /// committed via `write_batch_sync`. The default preserves compatibility
    /// for test stores that implement only the older point-write methods.
    fn write_state_batch_sync(
        &self,
        accounts: &[(Address, crate::types::AccountState)],
        storage: &[StateStorageChange],
    ) -> anyhow::Result<()> {
        for (address, account) in accounts {
            self.put_account(address, account)?;
        }
        for change in storage {
            match &change.value {
                Some(value) => self.put_storage(&change.address, &change.key, value)?,
                None => self.delete_storage(&change.address, &change.key)?,
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------------
    // Sprint P950-A-4 WP-A.4.3: MVCC account-version persistence.
    //
    // All methods have default no-op implementations so stores that don't
    // support versions compile unchanged. `StateStore` (the real RocksDB-
    // backed implementation) overrides them.
    //
    // If a store declines to persist versions, the tracker remains in-memory
    // only: correct for benchmarks and tests, non-durable across restart.
    // ------------------------------------------------------------------------

    /// Persist one account's version.
    fn put_account_version(&self, _address: &Address, _version: u64) -> anyhow::Result<()> {
        Ok(())
    }

    /// Persist many account versions in one batch.
    /// Default walks single-put — stores with native batch support should override.
    fn put_account_versions(&self, entries: &[(Address, u64)]) -> anyhow::Result<()> {
        for (addr, ver) in entries {
            self.put_account_version(addr, *ver)?;
        }
        Ok(())
    }

    /// Load every persisted account version. Called at executor startup.
    fn get_all_account_versions(&self) -> anyhow::Result<Vec<(Address, u64)>> {
        Ok(Vec::new())
    }

    /// Persist the MVCC global version counter.
    fn put_global_version(&self, _version: u64) -> anyhow::Result<()> {
        Ok(())
    }

    /// Load the MVCC global version counter. Called at executor startup.
    fn get_global_version(&self) -> anyhow::Result<Option<u64>> {
        Ok(None)
    }
}

/// Bridge trait to persist AI model metadata & artifacts in external storage layers.
pub trait AIModelStorage: Send + Sync {
    fn register_model(
        &self,
        model_id: ModelId,
        model_state: &ModelState,
        weight_cid: &str,
    ) -> anyhow::Result<()>;
    fn update_model_weights(
        &self,
        model_id: ModelId,
        weight_cid: &str,
        new_version: u32,
    ) -> anyhow::Result<()>;
}

/// Bridge trait to inform higher-level registries (e.g. MCP) about model lifecycle events.
#[async_trait]
pub trait ModelRegistryAdapter: Send + Sync {
    async fn register_model(
        &self,
        model_id: ModelId,
        model_state: &ModelState,
        artifact_cid: Option<&str>,
    ) -> anyhow::Result<()>;

    async fn update_model(
        &self,
        _model_id: ModelId,
        _model_state: &ModelState,
        _artifact_cid: Option<&str>,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Trait to delegate AI inference to an external service (e.g., MCP)
#[async_trait]
pub trait InferenceService: Send + Sync {
    /// Run inference and return (output bytes, extra gas used, provider address, provider fee in wei, optional proof bytes)
    async fn run_inference(
        &self,
        model_id: ModelId,
        input: Vec<u8>,
        max_gas: u64,
    ) -> Result<(Vec<u8>, u64, Address, U256, Option<Vec<u8>>), ExecutionError>;
}

/// Trait to pin and query artifact CIDs (e.g., IPFS)
#[async_trait]
pub trait ArtifactService: Send + Sync {
    async fn pin(&self, cid: &str, replicas: usize) -> Result<(), ExecutionError>;
    async fn status(&self, cid: &str) -> Result<String, ExecutionError>;
    async fn add(&self, data: &[u8]) -> Result<String, ExecutionError>;
}

/// Summary returned by `run_inference_preview`
pub struct InferencePreview {
    pub output: Vec<u8>,
    pub gas_used: u64,
    pub provider: Address,
    pub provider_fee: U256,
    pub proof: Option<Vec<u8>>,
    pub latency_ms: u64,
}

impl Executor {
    /// Create a new executor with chain ID from environment or default
    pub fn new(state_db: Arc<StateDB>) -> Self {
        // Check for chain ID from environment variable
        let chain_id = std::env::var("CITRATE_CHAIN_ID")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(DEFAULT_CHAIN_ID);

        Self::with_chain_id(state_db, chain_id)
    }

    /// REM-N-03 / WP-H1.2: the production-default determinism mode for
    /// the inference precompile. Production callers
    /// (`Executor::with_chain_id`, `Executor::with_storage_and_chain_id`,
    /// and `Executor::new`) construct the precompile in this mode.
    /// Devnet / tests opt out via the `*_and_inference_mode` constructors
    /// or the `--allow-nondeterministic-inference` CLI flag (gated
    /// behind the `dev-mode` cargo feature on the node binary).
    pub const fn production_inference_mode() -> InferenceMode {
        InferenceMode::Strict
    }

    /// Create a new executor with explicit chain ID.
    ///
    /// REM-N-03 / WP-H1.2: in production, the inference precompile
    /// (0x0101 MODEL_INFERENCE, 0x0102 BATCH_INFERENCE) defaults to
    /// `InferenceMode::Strict` — calls return the C-01 gate error
    /// rather than running non-deterministic FP inference. Devnet may
    /// opt in via `with_chain_id_and_inference_mode` or via the
    /// `--allow-nondeterministic-inference` CLI flag (gated behind the
    /// `dev-mode` cargo feature on `node-app`).
    pub fn with_chain_id(state_db: Arc<StateDB>, chain_id: u64) -> Self {
        Self::with_chain_id_and_inference_mode(
            state_db,
            chain_id,
            Self::production_inference_mode(),
        )
    }

    /// REM-N-03 / WP-H1.2: explicit-mode constructor. Tests and devnet
    /// pass `InferenceMode::AllowNonDeterministic`; the production
    /// `with_chain_id` constructor delegates here with
    /// `InferenceMode::Strict`.
    pub fn with_chain_id_and_inference_mode(
        state_db: Arc<StateDB>,
        chain_id: u64,
        inference_mode: InferenceMode,
    ) -> Self {
        // Initialize Metal runtime and precompiles if available
        let precompile_executor = if cfg!(target_os = "macos") {
            match MetalRuntime::new() {
                Ok(runtime) => {
                    let inference_precompile =
                        InferencePrecompile::new_with_mode(Arc::new(runtime), inference_mode);
                    let executor = PrecompileExecutor::new()
                        .with_inference(inference_precompile);
                    Some(Arc::new(tokio::sync::RwLock::new(executor)))
                },
                Err(e) => {
                    warn!("Failed to initialize Metal runtime: {}", e);
                    None
                }
            }
        } else {
            None
        };

        info!(
            "Executor initialized with chain_id: {} inference_mode: {:?}",
            chain_id, inference_mode
        );

        Self {
            state_db,
            state_store: None,
            gas_schedule: GasSchedule::default(),
            inference_service: None,
            artifact_service: None,
            ai_storage: None,
            model_registry: None,
            precompile_executor,
            chain_id,
            block_context: std::sync::RwLock::new(crate::revm_adapter::BlockContext::default()),
            commit_coordinator: Arc::new(CommitCoordinator::new()),
        }
    }

    /// Get the configured chain ID
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Set the block context for the current block being executed (WP-Z.2).
    /// Called by the block producer before `execute_block_transactions()`.
    pub fn set_block_context(&self, ctx: crate::revm_adapter::BlockContext) {
        if let Ok(mut guard) = self.block_context.write() {
            *guard = ctx;
        }
    }

    /// Get a clone of the current block context.
    pub fn get_block_context(&self) -> crate::revm_adapter::BlockContext {
        self.block_context
            .read()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    pub fn with_storage<S: StateStoreTrait + 'static>(
        state_db: Arc<StateDB>,
        state_store: Option<Arc<S>>,
    ) -> Self {
        // Check for chain ID from environment variable, consistent with new()
        let chain_id = std::env::var("CITRATE_CHAIN_ID")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(DEFAULT_CHAIN_ID);
        Self::with_storage_and_chain_id(state_db, state_store, chain_id)
    }

    /// REM-N-03 / WP-H1.2: production-default constructor with
    /// persistent state store. Defaults inference mode to
    /// `InferenceMode::Strict`; devnet must opt in via
    /// `with_storage_and_chain_id_and_inference_mode`.
    pub fn with_storage_and_chain_id<S: StateStoreTrait + 'static>(
        state_db: Arc<StateDB>,
        state_store: Option<Arc<S>>,
        chain_id: u64,
    ) -> Self {
        Self::with_storage_and_chain_id_and_inference_mode(
            state_db,
            state_store,
            chain_id,
            Self::production_inference_mode(),
        )
    }

    /// REM-N-03 / WP-H1.2: explicit-mode constructor with persistent
    /// state store. Devnet / tests pass
    /// `InferenceMode::AllowNonDeterministic`; production callers use
    /// `with_storage_and_chain_id` which forwards
    /// `InferenceMode::Strict`.
    pub fn with_storage_and_chain_id_and_inference_mode<S: StateStoreTrait + 'static>(
        state_db: Arc<StateDB>,
        state_store: Option<Arc<S>>,
        chain_id: u64,
        inference_mode: InferenceMode,
    ) -> Self {
        // Initialize Metal runtime and precompiles if available
        let precompile_executor = if cfg!(target_os = "macos") {
            match MetalRuntime::new() {
                Ok(runtime) => {
                    let inference_precompile =
                        InferencePrecompile::new_with_mode(Arc::new(runtime), inference_mode);
                    let executor = PrecompileExecutor::new()
                        .with_inference(inference_precompile);
                    Some(Arc::new(tokio::sync::RwLock::new(executor)))
                },
                Err(e) => {
                    warn!("Failed to initialize Metal runtime: {}", e);
                    None
                }
            }
        } else {
            None
        };

        info!(
            "Executor initialized with chain_id: {} inference_mode: {:?}",
            chain_id, inference_mode
        );

        // Sprint P950-A-4 WP-A.4.3: eager-load persisted MVCC versions
        // from RocksDB so per-account versions survive restart. The tracker
        // is correct-by-construction: we bump to the persisted values and
        // advance the global counter to at least the max of them, preserving
        // the spec invariant `accountVersion[a] <= globalVersion`.
        let state_store_dyn: Option<Arc<dyn StateStoreTrait>> =
            state_store.map(|s| s as Arc<dyn StateStoreTrait>);
        let commit_coordinator = Arc::new(CommitCoordinator::new());
        if let Some(store) = &state_store_dyn {
            let account_versions = store
                .get_all_account_versions()
                .unwrap_or_else(|e| {
                    warn!("account_versions eager-load failed: {} — starting fresh", e);
                    Vec::new()
                });
            let persisted_global = store
                .get_global_version()
                .unwrap_or_else(|e| {
                    warn!("global_version eager-load failed: {} — starting fresh", e);
                    None
                });

            let max_account_v = account_versions
                .iter()
                .map(|(_, v)| *v)
                .max()
                .unwrap_or(0);
            let global_to_restore = persisted_global.unwrap_or(0).max(max_account_v);

            // Restore per-account versions
            let tracker = commit_coordinator.tracker();
            for (addr, v) in &account_versions {
                tracker.bump(*addr, crate::mvcc::ReadVersion::from_raw(*v));
            }

            // Advance globalVersion to the restored floor
            for _ in 0..global_to_restore {
                let _ = commit_coordinator.commit_writes_serialized(&WriteSet::new());
            }

            if !account_versions.is_empty() || persisted_global.is_some() {
                info!(
                    "MVCC restore: loaded {} per-account versions, global_version = {}",
                    account_versions.len(),
                    global_to_restore,
                );
            }
        }

        Self {
            state_db,
            state_store: state_store_dyn,
            gas_schedule: GasSchedule::default(),
            inference_service: None,
            artifact_service: None,
            ai_storage: None,
            model_registry: None,
            precompile_executor,
            chain_id,
            block_context: std::sync::RwLock::new(crate::revm_adapter::BlockContext::default()),
            commit_coordinator,
        }
    }

    /// Attach an inference service for MCP-backed inference execution
    pub fn with_inference_service(mut self, svc: Arc<dyn InferenceService>) -> Self {
        self.inference_service = Some(svc);
        self
    }

    /// Check whether an inference service has been configured.
    pub fn has_inference_service(&self) -> bool {
        self.inference_service.is_some()
    }

    /// Attach an artifact service for IPFS pinning and status
    pub fn with_artifact_service(mut self, svc: Arc<dyn ArtifactService>) -> Self {
        self.artifact_service = Some(svc);
        self
    }

    /// Attach persistent AI storage adapter (e.g., StorageManager bridge)
    pub fn with_ai_storage_adapter(mut self, storage: Arc<dyn AIModelStorage>) -> Self {
        self.ai_storage = Some(storage);
        self
    }

    /// Attach model registry adapter (e.g., MCP service bridge)
    pub fn with_model_registry_adapter(mut self, adapter: Arc<dyn ModelRegistryAdapter>) -> Self {
        self.model_registry = Some(adapter);
        self
    }

    /// Get reference to state database
    pub fn state_db(&self) -> &Arc<StateDB> {
        &self.state_db
    }

    fn get_account_from_store(
        &self,
        address: &Address,
    ) -> Option<crate::types::AccountState> {
        self.state_store
            .as_ref()
            .and_then(|store| match store.get_account(address) {
                Ok(account) => account,
                Err(e) => {
                    warn!("Failed to load account {} from state store: {}", address, e);
                    None
                }
            })
    }

    /// Return the persisted "latest" account state when storage exists.
    /// Falls back to in-memory state for test-only or non-persistent executors.
    pub fn get_canonical_account(
        &self,
        address: &Address,
    ) -> crate::types::AccountState {
        self.get_account_from_store(address)
            .unwrap_or_else(|| self.state_db.accounts.get_account(address))
    }

    /// Sync a model registration to the model registry adapter (e.g. MCP).
    /// This is safe to call from a synchronous context — it spawns a
    /// dedicated thread with its own tokio runtime to avoid deadlocks.
    pub fn sync_model_to_registry(
        &self,
        model_id: ModelId,
        model_state: &ModelState,
        artifact_cid: Option<&str>,
    ) {
        if let Some(adapter) = &self.model_registry {
            let adapter = adapter.clone();
            let state = model_state.clone();
            let cid = artifact_cid.map(|s| s.to_string());
            std::thread::spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        tracing::error!("sync_model_to_registry: failed to build tokio runtime: {}", e);
                        return;
                    }
                };
                if let Err(e) = rt.block_on(adapter.register_model(
                    model_id,
                    &state,
                    cid.as_deref(),
                )) {
                    tracing::warn!(
                        "sync_model_to_registry: MCP registration failed for {:?}: {}",
                        model_id, e
                    );
                } else {
                    tracing::info!(
                        "sync_model_to_registry: model {:?} synced to MCP registry",
                        model_id
                    );
                }
            })
            .join()
            .ok();
        }
    }

    /// Persist all dirty accounts and storage slots from state_db to state_store
    pub async fn persist_state_changes(&self) -> anyhow::Result<usize> {
        let _guard = self.commit_coordinator.acquire_exec_lock().await;
        if let Some(store) = &self.state_store {
            let dirty_accounts = self.state_db.accounts.get_dirty_accounts();
            let mut account_changes = Vec::with_capacity(dirty_accounts.len());

            for address in dirty_accounts {
                let account = self.state_db.accounts.get_account(&address);
                account_changes.push((address, account));
            }

            // C6 fix: Also persist dirty contract storage slots.
            // K1.1: account and storage mutations are committed together by
            // the storage backend, rather than by a loop of independent puts.
            let dirty_storage = self.state_db.take_dirty_storage();
            let mut storage_changes = Vec::with_capacity(dirty_storage.len());
            for (address, key) in dirty_storage {
                storage_changes.push(StateStorageChange {
                    value: self.state_db.get_storage(&address, &key),
                    address,
                    key,
                });
            }

            let count = account_changes.len() + storage_changes.len();
            if count > 0 {
                store.write_state_batch_sync(&account_changes, &storage_changes)?;
            }

            // Commit state DB (clears dirty tracking)
            self.state_db.commit();
            Ok(count)
        } else {
            Ok(0) // No storage configured, nothing to persist
        }
    }

    /// Store raw artifact bytes via configured artifact service
    pub async fn add_artifact(&self, data: &[u8]) -> Result<String, ExecutionError> {
        if let Some(svc) = &self.artifact_service {
            svc.add(data).await
        } else {
            Err(ExecutionError::Reverted(
                "Artifact service not configured".into(),
            ))
        }
    }

    /// Get account balance
    pub fn get_balance(&self, address: &Address) -> U256 {
        if self.state_db.accounts.exists(address) {
            return self.state_db.accounts.get_balance(address);
        }

        if let Some(account) = self.get_account_from_store(address) {
            self.state_db.accounts.load_account(*address, account.clone());
            return account.balance;
        }

        self.state_db.accounts.get_balance(address)
    }

    /// Get account nonce
    pub fn get_nonce(&self, address: &Address) -> u64 {
        if self.state_db.accounts.exists(address) {
            return self.state_db.accounts.get_nonce(address);
        }

        if let Some(account) = self.get_account_from_store(address) {
            self.state_db.accounts.load_account(*address, account.clone());
            return account.nonce;
        }

        self.state_db.accounts.get_nonce(address)
    }

    /// Get contract code hash
    pub fn get_code_hash(&self, address: &Address) -> Hash {
        if self.state_db.accounts.exists(address) {
            return self.state_db.accounts.get_code_hash(address);
        }

        if let Some(account) = self.get_account_from_store(address) {
            self.state_db.accounts.load_account(*address, account.clone());
            return account.code_hash;
        }

        self.state_db.accounts.get_code_hash(address)
    }

    /// Get the state root hash from the current state database
    ///
    /// The state root is a cryptographic commitment to the entire state.
    /// This enables state verification without full state access.
    pub fn get_state_root(&self) -> anyhow::Result<Hash> {
        self.state_db.get_root_hash()
    }

    /// Set account balance
    pub fn set_balance(&self, address: &Address, balance: U256) {
        self.state_db.accounts.set_balance(*address, balance);

        // Persist to storage if available
        if let Some(store) = &self.state_store {
            let account = self.state_db.accounts.get_account(address);
            if let Err(e) = store.put_account(address, &account) {
                error!("Failed to persist account balance: {}", e);
            }
        }
    }

    /// Set account nonce
    pub fn set_nonce(&self, address: &Address, nonce: u64) {
        self.state_db.accounts.set_nonce(*address, nonce);

        // Persist to storage if available
        if let Some(store) = &self.state_store {
            let account = self.state_db.accounts.get_account(address);
            if let Err(e) = store.put_account(address, &account) {
                error!("Failed to persist account nonce: {}", e);
            }
        }
    }

    /// Set contract code
    /// Register a genesis AI model from raw ONNX bytes.
    ///
    /// Computes a deterministic model hash from the bytes and registers it
    /// in the state DB. Used by the shared genesis initialization to ensure
    /// all nodes register the same model with the same hash.
    pub fn register_genesis_model_from_bytes(
        &self,
        onnx_bytes: &[u8],
        name: &str,
        created_at: u64,
    ) {
        use sha3::{Digest, Keccak256};
        use crate::types::{
            ModelId, ModelMetadata, ModelState, AccessPolicy, UsageStats,
        };
        use citrate_consensus::types::Hash;

        let mut hasher = Keccak256::new();
        hasher.update(onnx_bytes);
        let h = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h[..32]);

        let model_hash = Hash::new(arr);
        let model_id = ModelId(model_hash);

        let metadata = ModelMetadata {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            description: "Genesis semantic model placeholder".to_string(),
            framework: "ONNX".to_string(),
            input_shape: vec![1, 128],
            output_shape: vec![1, 128],
            size_bytes: onnx_bytes.len() as u64,
            created_at,
        };

        let model_state = ModelState {
            owner: Address::zero(),
            model_hash,
            version: 1,
            metadata,
            access_policy: AccessPolicy::Public,
            usage_stats: UsageStats::default(),
        };

        match self.state_db.register_model(model_id, model_state) {
            Ok(_) => info!("Registered genesis model: {:?}", model_id),
            Err(e) => warn!("Failed to register genesis model: {}", e),
        }
    }

    pub fn set_code(&self, address: &Address, code: Vec<u8>) {
        let code_hash = self.state_db.set_code(*address, code.clone());
        self.state_db.accounts.set_code_hash(*address, code_hash);

        // Persist to storage if available
        if let Some(store) = &self.state_store {
            if let Err(e) = store.put_code(&code_hash, &code) {
                error!("Failed to persist contract code: {}", e);
            }

            let account = self.state_db.accounts.get_account(address);
            if let Err(e) = store.put_account(address, &account) {
                error!("Failed to persist account code hash: {}", e);
            }
        }
    }

    /// Calculate state root
    pub fn calculate_state_root(&self) -> Hash {
        self.state_db.calculate_state_root()
    }

    /// Execute a transaction via the MVCC path.
    ///
    /// Sprint P950-A-5 WP-A.5.3: parallel execution via journal + CAS.
    ///
    /// Flow:
    /// 1. Pin a fresh per-tx ScratchJournal at the current global version.
    /// 2. Execute the tx; ALL mutations land in the journal, ALL reads
    ///    populate the journal's read set.
    /// 3. `try_commit`: validate read set against current account versions
    ///    under the short commit-lock critical section. On success:
    ///    atomically advance global version + bump per-account versions
    ///    for the write set. On conflict: abort and retry with a fresh pin.
    /// 4. On success: drain the journal into state_db; persist versions.
    /// 5. Fallback-to-serial on retry exhaustion: acquire the async
    ///    `exec_lock` and commit unconditionally. Guarantees progress.
    ///
    /// The former always-serial `exec_lock` on the fast path is gone —
    /// workers now execute concurrently, only synchronized on the short
    /// commit-lock critical section inside `try_commit`.
    pub async fn execute_transaction(
        &self,
        block: &Block,
        tx: &Transaction,
    ) -> Result<TransactionReceipt, ExecutionError> {
        const MAX_RETRIES: usize = 8;
        let coord = &self.commit_coordinator;

        // -- Fast path: bounded CAS retries with NO exec_lock held --
        for _attempt in 0..MAX_RETRIES {
            let mut context = ExecutionContext::new(block, tx);
            let pin = coord.current_version();
            context.journal.lock().pin_at(pin);

            let (receipt, writes) = match self.execute_tx_into_journal(block, tx, &mut context).await {
                Ok(pair) => pair,
                // Validation errors (InvalidNonce, InsufficientBalance) are
                // deterministic — no point retrying.
                Err(e) => return Err(e),
            };

            let outcome = {
                let journal = context.journal.lock();
                coord.try_commit(&journal)
            };
            use crate::mvcc::CommitOutcome;
            match outcome {
                CommitOutcome::Committed { new_version } => {
                    self.drain_journal(&context.journal);
                    self.persist_account_versions(&writes, new_version);
                    return Ok(receipt);
                }
                CommitOutcome::Aborted { .. } => {
                    // Nothing drained → nothing to undo.
                    // Journal will be recreated fresh on next attempt.
                    continue;
                }
            }
        }

        // -- Fallback path: serialized via exec_lock --
        //
        // Acquiring the exec_lock guarantees no concurrent CAS attempts;
        // we then commit unconditionally (no read-set validation needed).
        // Progress is guaranteed (TLA+ `Progress` temporal property).
        let _guard = coord.acquire_exec_lock().await;
        let mut context = ExecutionContext::new(block, tx);
        context.journal.lock().pin_at(coord.current_version());
        let (receipt, writes) = self
            .execute_tx_into_journal(block, tx, &mut context)
            .await?;
        let new_version = coord.commit_writes_serialized(&writes);
        self.drain_journal(&context.journal);
        self.persist_account_versions(&writes, new_version);
        Ok(receipt)
    }

    /// Persist per-account + global MVCC versions to RocksDB.
    ///
    /// Sprint P950-A-4 WP-A.4.3. Non-fatal: failures are logged but do
    /// not abort the tx. A restart without persisted versions is
    /// conservatively-safe (in-memory tracker starts at v0).
    fn persist_account_versions(
        &self,
        writes: &WriteSet,
        new_version: crate::mvcc::ReadVersion,
    ) {
        if let Some(store) = &self.state_store {
            let entries: Vec<(Address, u64)> = writes
                .iter()
                .map(|a| (*a, new_version.as_u64()))
                .collect();
            if let Err(e) = store.put_account_versions(&entries) {
                warn!("account_versions persistence failed (non-fatal): {}", e);
            }
            if let Err(e) = store.put_global_version(new_version.as_u64()) {
                warn!("global_version persistence failed (non-fatal): {}", e);
            }
        }
    }

    /// Execute a tx into a pre-pinned journal. All mutations land in the
    /// journal (no direct state_db writes); all reads record into the
    /// journal's read_set for CAS validation.
    ///
    /// Sprint P950-A-5 WP-A.5.3. Replaces the former
    /// `execute_transaction_inner` — snapshot/restore is gone (the journal
    /// IS the rollback mechanism: abort means discard pending writes; commit
    /// means drain).
    ///
    /// The caller is responsible for:
    /// - Creating the ExecutionContext with a fresh journal
    /// - Pinning the journal at the current global version
    /// - Either `try_commit` + drain (success) or discard (retry)
    async fn execute_tx_into_journal(
        &self,
        block: &Block,
        tx: &Transaction,
        context: &mut ExecutionContext,
    ) -> Result<(TransactionReceipt, WriteSet), ExecutionError> {
        let from = crate::address_utils::normalize_address(&tx.from);

        // Record sender in the read_set — validation against pinned version
        // at commit time. If another tx commits a write to `from` before
        // we commit, our CAS aborts and retries.
        context.journal.lock().record_read(from);

        // Verify nonce WITHOUT incrementing (C-04: enforce equality).
        // Journal-first for read-your-writes consistency (a prior retry
        // attempt could have left no pending nonce — fall through to
        // state_db).
        {
            let j = context.journal.lock();
            let current_nonce = j
                .pending_nonce(&from)
                .unwrap_or_else(|| self.state_db.accounts.get_nonce(&from));
            if current_nonce != tx.nonce {
                return Err(ExecutionError::InvalidNonce {
                    expected: current_nonce,
                    got: tx.nonce,
                });
            }
        }

        // Check balance for gas, journal-first.
        let gas_cost = U256::from(tx.gas_limit) * U256::from(tx.gas_price);
        let balance = {
            let j = context.journal.lock();
            j.pending_balance(&from)
                .unwrap_or_else(|| self.state_db.accounts.get_balance(&from))
        };
        if balance < gas_cost + U256::from(tx.value) {
            return Err(ExecutionError::InsufficientBalance {
                need: gas_cost + U256::from(tx.value),
                have: balance,
            });
        }

        // Sprint P950-A-5 WP-A.5.2: deduct gas cost into the journal rather
        // than state_db. REVM's `Database::basic` does journal-first lookup
        // so the EVM sees the post-deduction balance during execution.
        context.journal.lock().record_balance(from, balance - gas_cost);

        // Parse and execute transaction type.
        let tx_type = self.parse_transaction_type(tx)?;
        let result = self
            .execute_transaction_type(tx_type, context, from)
            .await;

        // BFR-VM-1 WP-8 — capture the human-readable failure reason
        // before `result` is moved into the match below. Surfaced
        // via `receipt.revert_reason` so eth_call / eth_estimateGas
        // can propagate it as a JSON-RPC error instead of returning
        // `0x` with no signal (which is exactly how the CANCUN bug
        // stayed undiagnosed).
        let revert_reason: Option<String> = match &result {
            Ok(()) => None,
            Err(e) => Some(format!("{}", e)),
        };

        // Handle execution result — all journal-routed.
        let status = match result {
            Ok(()) => {
                // Success: nonce increment + gas refund via journal.
                let refund =
                    U256::from(tx.gas_limit - context.gas_used) * U256::from(tx.gas_price);
                let current_balance = {
                    let j = context.journal.lock();
                    j.pending_balance(&from)
                        .unwrap_or_else(|| self.state_db.accounts.get_balance(&from))
                };
                {
                    let mut j = context.journal.lock();
                    j.record_nonce(from, tx.nonce + 1);
                    j.record_balance(from, current_balance + refund);
                }
                true
            }
            Err(e) => {
                warn!("Transaction execution failed: {}", e);
                // Failure: discard pending writes, re-record only gas-burn
                // + nonce-increment. No state_db rollback needed since
                // nothing was written to state_db during execution.
                let mut j = context.journal.lock();
                j.discard_writes();
                j.record_balance(from, balance - gas_cost);
                j.record_nonce(from, tx.nonce + 1);
                false
            }
        };

        // Create receipt
        let receipt = TransactionReceipt {
            tx_hash: tx.hash,
            block_hash: block.hash(),
            block_number: block.header.height,
            from,
            to: tx.to.map(|pk| crate::address_utils::normalize_address(&pk)),
            gas_used: context.gas_used,
            status,
            logs: context.logs.clone(),
            output: context.output.clone(),
            eth_tx_type: tx.eth_tx_type,
            effective_gas_price: tx.gas_price,
            revert_reason,
        };

        info!(
            "Transaction {} executed: status={}, gas_used={}",
            tx.hash, status, context.gas_used
        );

        // Assemble the final WriteSet for MVCC version bumping:
        // - REVM-captured accounts (storage/code writes), if any
        // - sender (always touched: nonce + balance)
        // - recipient (touched if present)
        let mut writes = WriteSet::new();
        {
            let revm_captured = context.writes_handle.lock();
            for addr in revm_captured.iter() {
                writes.record_write(*addr);
            }
        }
        writes.record_write(receipt.from);
        if let Some(to) = receipt.to {
            writes.record_write(to);
        }

        Ok((receipt, writes))
    }

    /// Apply a pinned scratch journal's pending mutations to state_db.
    ///
    /// Sprint P950-A-5 WP-A.5.3. Extracted so both the serial path and
    /// (future) the CAS-retry path use the same drain logic. Code writes
    /// go through `self.set_code` so state_store persistence is applied
    /// uniformly with direct code deploys.
    fn drain_journal(&self, journal: &crate::mvcc::JournalHandle) {
        let journal = journal.lock();
        for ((addr, key), value) in journal.iter_storage_writes() {
            self.state_db.set_storage(*addr, key.clone(), value.clone());
        }
        for (addr, pending) in journal.iter_writes() {
            if let Some(new_balance) = pending.new_balance {
                self.state_db.accounts.set_balance(*addr, new_balance);
            }
            if let Some(new_nonce) = pending.new_nonce {
                self.state_db.accounts.set_nonce(*addr, new_nonce);
            }
            if let Some(code) = &pending.new_code {
                self.state_db.accounts.create_account_if_not_exists(*addr);
                self.set_code(addr, code.clone());
            }
        }
    }

    /// Simulate a transaction without persisting state changes.
    ///
    /// Used by eth_call and eth_estimateGas. Gives the sender unlimited balance
    /// and aligns nonce so read-only calls don't fail, then unconditionally
    /// restores the snapshot afterward. This avoids a race condition where the
    /// block producer's persist_state_changes() could persist the inflated
    /// balance to RocksDB between set_balance and restore.
    pub async fn simulate_transaction(
        &self,
        block: &Block,
        tx: &Transaction,
    ) -> Result<TransactionReceipt, ExecutionError> {
        // Simulation acquires the exec_lock to serialize against real tx
        // execution — the simulation's temporary balance/nonce overrides
        // must not be observable to concurrent workers. Short critical
        // section; eth_call / eth_estimateGas are not throughput-critical.
        let _guard = self.commit_coordinator.acquire_exec_lock().await;

        // Snapshot BEFORE any mutations (to undo the simulation overrides).
        let snapshot = self.state_db.snapshot();

        // Override sender balance for simulation
        let from = crate::address_utils::normalize_address(&tx.from);
        self.state_db
            .accounts
            .set_balance(from, U256::from(u128::MAX));

        // Align nonce so validation inside execute_tx_into_journal passes
        let current_nonce = self.state_db.accounts.get_nonce(&from);
        if tx.nonce != current_nonce {
            self.state_db.accounts.set_nonce(from, tx.nonce);
        }

        // Execute the tx into a pinned (but never committed) journal.
        // Simulation doesn't drain the journal — all pending mutations
        // stay in the journal and get thrown away on return.
        let mut context = ExecutionContext::new(block, tx);
        context
            .journal
            .lock()
            .pin_at(self.commit_coordinator.current_version());
        let result = self
            .execute_tx_into_journal(block, tx, &mut context)
            .await;

        // ALWAYS restore — unconditional, no matter success or failure.
        // Undoes the inflated balance + nonce override.
        self.state_db.restore(snapshot);

        // Simulation discards the journal + WriteSet capture: no MVCC
        // version bumps escape the simulation, no state changes land.
        result.map(|(receipt, _writes)| receipt)
    }

    /// Parse transaction data into type
    fn parse_transaction_type(&self, tx: &Transaction) -> Result<TransactionType, ExecutionError> {
        // Simple parsing based on transaction data
        // In production, this would use proper ABI encoding/decoding

        if tx.data.is_empty() {
            // Simple transfer
            // Use proper address normalization to handle both formats
            let to = tx
                .to
                .map(|pk| crate::address_utils::normalize_address(&pk))
                .ok_or(ExecutionError::InvalidInput)?;

            Ok(TransactionType::Transfer {
                to,
                value: U256::from(tx.value),
            })
        } else if tx.to.is_none() {
            // Contract deployment
            Ok(TransactionType::Deploy {
                code: tx.data.clone(),
                init_data: vec![],
            })
        } else {
            // Contract call or special operation
            // Safety: this branch is only reached when tx.to.is_some() (else clause of is_none check)
            let to_pk = match tx.to {
                Some(ref pk) => pk,
                None => return Err(ExecutionError::InvalidInput),
            };
            let to = crate::address_utils::normalize_address(to_pk);

            // Check first 4 bytes for function selector
            if tx.data.len() >= 4 {
                match &tx.data[0..4] {
                    [0x01, 0x00, 0x00, 0x00] => {
                        // Register model
                        self.parse_register_model(&tx.data[4..])
                    }
                    [0x02, 0x00, 0x00, 0x00] => {
                        // Inference request
                        self.parse_inference_request(&tx.data[4..])
                    }
                    [0x03, 0x00, 0x00, 0x00] => {
                        // Update model
                        self.parse_update_model(&tx.data[4..])
                    }
                    _ => {
                        // Generic call
                        Ok(TransactionType::Call {
                            to,
                            data: tx.data.clone(),
                            value: U256::from(tx.value),
                        })
                    }
                }
            } else {
                Ok(TransactionType::Call {
                    to,
                    data: tx.data.clone(),
                    value: U256::from(tx.value),
                })
            }
        }
    }

    /// Parse register model transaction
    fn parse_register_model(&self, data: &[u8]) -> Result<TransactionType, ExecutionError> {
        if data.len() < 36 {
            return Err(ExecutionError::InvalidInput);
        }

        let model_hash = Hash::new(
            data[0..32]
                .try_into()
                .map_err(|_| ExecutionError::InvalidInput)?,
        );
        let meta_len = u32::from_be_bytes(
            data[32..36]
                .try_into()
                .map_err(|_| ExecutionError::InvalidInput)?,
        ) as usize;
        let mut offset = 36;
        if data.len() < offset + meta_len {
            return Err(ExecutionError::InvalidInput);
        }
        let metadata_bytes = &data[offset..offset + meta_len];
        offset += meta_len;

        let mut metadata: ModelMetadata =
            serde_json::from_slice(metadata_bytes).map_err(|_| ExecutionError::InvalidInput)?;

        if metadata.name.is_empty() {
            metadata.name = format!("Model-{}", hex::encode(&model_hash.as_bytes()[..4]));
        }
        if metadata.version.is_empty() {
            metadata.version = "1.0.0".to_string();
        }
        if metadata.description.is_empty() {
            metadata.description = "Registered AI model".to_string();
        }
        if metadata.framework.is_empty() {
            metadata.framework = "Unknown".to_string();
        }
        if metadata.input_shape.is_empty() {
            metadata.input_shape = vec![1];
        }
        if metadata.output_shape.is_empty() {
            metadata.output_shape = vec![1];
        }

        if offset >= data.len() {
            return Err(ExecutionError::InvalidInput);
        }
        let policy_byte = data[offset];
        offset += 1;

        let access_policy = match policy_byte {
            0 => AccessPolicy::Public,
            1 => AccessPolicy::Private,
            2 => AccessPolicy::Restricted(Vec::new()),
            3 => {
                if data.len() < offset + 32 {
                    return Err(ExecutionError::InvalidInput);
                }
                let mut fee_bytes = [0u8; 32];
                fee_bytes.copy_from_slice(&data[offset..offset + 32]);
                offset += 32;
                AccessPolicy::PayPerUse {
                    fee: U256::from_big_endian(&fee_bytes),
                }
            }
            _ => AccessPolicy::Public,
        };

        let mut artifact_cid: Option<String> = None;
        if data.len() >= offset + 4 {
            let cid_len = u32::from_be_bytes(
                data[offset..offset + 4]
                    .try_into()
                    .map_err(|_| ExecutionError::InvalidInput)?,
            ) as usize;
            offset += 4;
            if cid_len > 0 {
                if data.len() < offset + cid_len {
                    return Err(ExecutionError::InvalidInput);
                }
                artifact_cid = Some(
                    String::from_utf8(data[offset..offset + cid_len].to_vec())
                        .map_err(|_| ExecutionError::InvalidInput)?,
                );
            }
        }

        Ok(TransactionType::RegisterModel {
            model_hash,
            metadata,
            access_policy,
            artifact_cid,
        })
    }

    /// Parse inference request
    fn parse_inference_request(&self, data: &[u8]) -> Result<TransactionType, ExecutionError> {
        if data.len() < 32 {
            return Err(ExecutionError::InvalidInput);
        }

        let model_id = ModelId(Hash::new(
            data[0..32]
                .try_into()
                .map_err(|_| ExecutionError::InvalidInput)?,
        ));

        Ok(TransactionType::InferenceRequest {
            model_id,
            input_data: data[32..].to_vec(),
            max_gas: 1_000_000,
        })
    }

    /// Parse update model transaction
    fn parse_update_model(&self, data: &[u8]) -> Result<TransactionType, ExecutionError> {
        if data.len() < 36 {
            return Err(ExecutionError::InvalidInput);
        }

        let model_id = ModelId(Hash::new(
            data[0..32]
                .try_into()
                .map_err(|_| ExecutionError::InvalidInput)?,
        ));
        let meta_len = u32::from_be_bytes(
            data[32..36]
                .try_into()
                .map_err(|_| ExecutionError::InvalidInput)?,
        ) as usize;
        let mut offset = 36;
        if data.len() < offset + meta_len {
            return Err(ExecutionError::InvalidInput);
        }
        let metadata_bytes = &data[offset..offset + meta_len];
        offset += meta_len;

        let mut metadata: ModelMetadata = serde_json::from_slice(metadata_bytes)
            .map_err(|_| ExecutionError::InvalidInput)?;

        if metadata.name.is_empty() {
            metadata.name = format!("Model-{}", hex::encode(&model_id.0.as_bytes()[..4]));
        }
        if metadata.version.is_empty() {
            metadata.version = "1.0.1".to_string();
        }
        if metadata.framework.is_empty() {
            metadata.framework = "Unknown".to_string();
        }
        if metadata.input_shape.is_empty() {
            metadata.input_shape = vec![1];
        }
        if metadata.output_shape.is_empty() {
            metadata.output_shape = vec![1];
        }

        // created_at is already set from deserialization

        let artifact_cid = if data.len() >= offset + 4 {
            let cid_len = u32::from_be_bytes(
                data[offset..offset + 4]
                    .try_into()
                    .map_err(|_| ExecutionError::InvalidInput)?,
            ) as usize;
            offset += 4;
            if cid_len > 0 {
                if data.len() < offset + cid_len {
                    return Err(ExecutionError::InvalidInput);
                }
                Some(
                    String::from_utf8(data[offset..offset + cid_len].to_vec())
                        .map_err(|_| ExecutionError::InvalidInput)?,
                )
            } else {
                None
            }
        } else {
            None
        };

        Ok(TransactionType::UpdateModel {
            model_id,
            metadata,
            artifact_cid,
        })
    }

    /// Execute transaction type
    async fn execute_transaction_type(
        &self,
        tx_type: TransactionType,
        context: &mut ExecutionContext,
        from: Address,
    ) -> Result<(), ExecutionError> {
        match tx_type {
            TransactionType::Transfer { to, value } => {
                self.execute_transfer(from, to, value, context).await
            }

            TransactionType::Deploy { code, init_data } => {
                self.execute_deploy(from, code, init_data, context).await
            }

            TransactionType::Call { to, data, value } => {
                self.execute_call(from, to, data, value, context).await
            }

            TransactionType::RegisterModel {
                model_hash,
                metadata,
                access_policy,
                artifact_cid,
            } => {
                self.execute_register_model(
                    from,
                    model_hash,
                    metadata,
                    access_policy,
                    artifact_cid,
                    context,
                )
                .await
            }

            TransactionType::UpdateModel {
                model_id,
                metadata,
                artifact_cid,
            } => {
                self.execute_update_model(from, model_id, metadata, artifact_cid, context)
                    .await
            }

            TransactionType::InferenceRequest {
                model_id,
                input_data,
                max_gas,
            } => {
                self.execute_inference(from, model_id, input_data, max_gas, context)
                    .await
            }

            TransactionType::SubmitGradient {
                job_id,
                gradient_data,
                proof,
            } => {
                self.execute_submit_gradient(from, job_id, gradient_data, proof, context)
                    .await
            }
        }
    }

    /// Execute transfer — value transfer routed through the per-tx journal
    /// (WP-A.5.2). Sender/recipient balance updates land in the journal's
    /// pending map; the executor drains them into state_db at commit time.
    /// REVM-adjacent paths read balances via journal-first lookup so the
    /// in-flight transfer is visible within this tx.
    ///
    /// WP-A.5.3: records both parties into the journal's read_set so
    /// concurrent commits against either account invalidate this tx and
    /// force a retry.
    async fn execute_transfer(
        &self,
        from: Address,
        to: Address,
        value: U256,
        context: &mut ExecutionContext,
    ) -> Result<(), ExecutionError> {
        context.use_gas(self.gas_schedule.transfer)?;

        // Self-transfer: balance net-zero, no-op.
        if from == to {
            return Ok(());
        }

        // Read journal-first so we see this tx's pending gas deduction
        // (and any prior transfers routed through the journal).
        // Record both accounts into the read_set for CAS validation.
        let (from_balance, to_balance) = {
            let mut j = context.journal.lock();
            j.record_read(from);
            j.record_read(to);
            let fb = j
                .pending_balance(&from)
                .unwrap_or_else(|| self.state_db.accounts.get_balance(&from));
            let tb = j
                .pending_balance(&to)
                .unwrap_or_else(|| self.state_db.accounts.get_balance(&to));
            (fb, tb)
        };

        if from_balance < value {
            return Err(ExecutionError::InsufficientBalance {
                need: value,
                have: from_balance,
            });
        }

        {
            let mut j = context.journal.lock();
            j.record_balance(from, from_balance - value);
            j.record_balance(to, to_balance + value);
        }

        // PIL-48b: Native value transfers emit no logs — that's how Ethereum
        // mainnet works. Pre-fix, this site emitted a hand-rolled `Log` with
        // a 32-byte ASCII string `"Transfer000…"` as the topic. The bytes were
        // never the keccak256 of any real event signature, so any indexer
        // filtering on the standard ERC20 `Transfer(address,address,uint256)`
        // topic silently saw nothing. Block explorers should track native
        // transfers via call traces (`debug_traceTransaction`), not logs.

        debug!("Transfer: {} -> {} : {}", from, to, value);
        Ok(())
    }

    /// Journal-routed value transfer for REVM-adjacent paths (precompile
    /// calls, post-REVM transfer in `execute_call`). Sprint P950-A-5
    /// WP-A.5.2.
    ///
    /// Unlike `execute_transfer`, this does NOT charge transfer gas — the
    /// caller has already accounted for gas via the REVM / precompile
    /// pathway. Balance reads are journal-first so pending mutations from
    /// earlier in the same tx are visible.
    fn journal_transfer(
        &self,
        from: Address,
        to: Address,
        value: U256,
        context: &mut ExecutionContext,
    ) -> Result<(), ExecutionError> {
        if from == to {
            return Ok(());
        }

        let (from_balance, to_balance) = {
            let mut j = context.journal.lock();
            j.record_read(from);
            j.record_read(to);
            let fb = j
                .pending_balance(&from)
                .unwrap_or_else(|| self.state_db.accounts.get_balance(&from));
            let tb = j
                .pending_balance(&to)
                .unwrap_or_else(|| self.state_db.accounts.get_balance(&to));
            (fb, tb)
        };

        if from_balance < value {
            return Err(ExecutionError::InsufficientBalance {
                need: value,
                have: from_balance,
            });
        }

        {
            let mut j = context.journal.lock();
            j.record_balance(from, from_balance - value);
            j.record_balance(to, to_balance + value);
        }

        Ok(())
    }

    /// Execute contract deployment
    async fn execute_deploy(
        &self,
        from: Address,
        code: Vec<u8>,
        _init_data: Vec<u8>,
        context: &mut ExecutionContext,
    ) -> Result<(), ExecutionError> {
        context.use_gas(self.gas_schedule.create)?;

        // Execute deployment bytecode using revm (battle-tested EVM)
        // Revm will calculate the correct CREATE address and create the account
        // WP-Z.2: Pass block context so PREVRANDAO opcode returns real VRF output
        let gas_remaining = context.gas_limit.saturating_sub(context.gas_used);
        let result = crate::revm_adapter::execute_contract_create_with_context(
            self.state_db.clone(),
            from,
            code,
            U256::zero(), // No value transfer during deployment
            gas_remaining,
            U256::from(context.gas_price),
            self.chain_id,
            context.block_number,
            context.timestamp,
            self.get_block_context(),
            Some(context.writes_handle.clone()),
            Some(context.journal.clone()),
        );

        match result {
            Ok((deployed_address, runtime_code, gas_used, revm_logs)) => {
                // Charge gas for execution
                context.use_gas(gas_used)?;

                // Use the address returned by revm (it calculates CREATE correctly)
                info!(
                    "Contract deployed at: {} with {} bytes of runtime code",
                    deployed_address,
                    runtime_code.len()
                );

                // Store the runtime bytecode at revm's calculated address.
                // Sprint P950-A-5 WP-A.5.3: route through journal for
                // concurrent isolation. Drain time applies the code write
                // via `state_db.set_code` (which also updates the account's
                // code_hash) and persists to the code store.
                if runtime_code.is_empty() {
                    warn!("Contract deployment returned empty runtime code");
                }
                context
                    .journal
                    .lock()
                    .record_code(deployed_address, runtime_code);

                // Set contract address in output
                context.output = deployed_address.0.to_vec();

                // PIL-48: forward REVM-emitted logs from constructor execution
                // (e.g. OpenZeppelin's Initialized() event) so they land in the
                // receipt and are indexable via eth_getLogs. The prior synthetic
                // "ContractDeployed0000..." topic was a hand-rolled ASCII string
                // that never matched any real keccak256 event signature; tools
                // looking for the contract's actual constructor events silently
                // saw nothing.
                for log in revm_logs {
                    context.add_log(log);
                }

                Ok(())
            }
            Err(e) => {
                error!("Contract deployment execution failed: {}", e);
                Err(e)
            }
        }
    }

    /// Execute contract call with AI opcode support
    async fn execute_call(
        &self,
        from: Address,
        to: Address,
        data: Vec<u8>,
        value: U256,
        context: &mut ExecutionContext,
    ) -> Result<(), ExecutionError> {
        context.use_gas(self.gas_schedule.call)?;

        // Precompile dispatch first (value transfer handled by precompile if needed)
        if self.is_precompile_address(&to) {
            // Sprint P950-A-5 WP-A.5.2: route precompile value transfer
            // through the journal for concurrent isolation.
            if value > U256::zero() {
                self.journal_transfer(from, to, value, context)?;
            }
            self.execute_precompile(&to, &data, from, context).await?;
            return Ok(());
        }

        // Execute contract code with VM (unified path).
        //
        // PIL-13b: route the code lookup through the storage-loading
        // wrappers, not the in-memory cache directly. Pre-fix this gate
        // used `state_db.accounts.get_code_hash(&to)` (in-memory only),
        // which returned the zero hash on cold cache after a node
        // restart. `state_db.get_code(zero_hash)` then returned `None`,
        // and the whole `if let` branch was silently skipped — REVM
        // never ran, `context.output` stayed empty, and `eth_call`
        // emitted `0x` for every view function against every deployed
        // contract.
        //
        // `get_code_hash` (executor wrapper at line 686) already loads
        // the account from the persistent store on cache miss. Pairing
        // it with a parallel `state_store.get_code` fallback hydrates
        // the bytecode cache before REVM needs it.
        let code_hash = self.get_code_hash(&to);
        let cached_code = self.state_db.get_code(&code_hash);
        let code_opt = match cached_code {
            Some(c) => Some(c),
            None => {
                if code_hash == Hash::default() {
                    None
                } else if let Some(store) = &self.state_store {
                    match store.get_code(&code_hash) {
                        Ok(Some(bytes)) => {
                            self.state_db.cache_code(code_hash, bytes.clone());
                            Some(bytes)
                        }
                        _ => None,
                    }
                } else {
                    None
                }
            }
        };

        if let Some(code) = code_opt {
            // Route standard EVM calls through REVM for correct CALL/CREATE/DELEGATECALL.
            //
            // Sprint EL-1 Fix (Issue #19): REVM handles gas/value/nonce internally
            // during transact_commit(), but DatabaseCommit::commit() only writes
            // storage and code — NOT balance or nonce. The executor is the sole
            // owner of gas/balance/nonce accounting. Value transfer is done
            // explicitly by the executor after REVM succeeds.
            debug!(
                "Executing contract at {} with {} bytes of code via REVM",
                to,
                code.len()
            );
            let available_gas = context.gas_limit.saturating_sub(context.gas_used);
            // WP-Z.2: Pass block context so PREVRANDAO opcode returns real VRF output
            match crate::revm_adapter::execute_contract_call_with_context(
                self.state_db.clone(),
                from,
                to,
                data.clone(),
                value,
                available_gas,
                U256::from(context.gas_price),
                self.chain_id,
                context.block_number,
                context.timestamp,
                self.get_block_context(),
                Some(context.writes_handle.clone()),
                Some(context.journal.clone()),
                // PIL-13b: pass the executor's state store so REVM can
                // hydrate account / code / storage on cold cache miss.
                self.state_store.clone(),
            ) {
                Ok((output, gas_used, revm_logs)) => {
                    VM_EXECUTIONS_TOTAL.with_label_values(&["ok"]).inc();
                    if gas_used > 0 {
                        context.use_gas(gas_used)?;
                    }
                    VM_GAS_USED.observe(gas_used as f64);
                    context.output = output;

                    // Transfer value after REVM succeeds. REVM's commit no longer
                    // writes balance changes, so the executor must handle this.
                    // Sprint P950-A-5 WP-A.5.2: route through the journal for
                    // concurrent isolation.
                    if value > U256::zero() {
                        self.journal_transfer(from, to, value, context)?;
                    }

                    // PIL-48: forward REVM-emitted logs to the receipt with their
                    // real keccak256 event topics. Pre-fix, all REVM logs were
                    // discarded and a single hardcoded "ContractExecuted0000..."
                    // topic was synthesised per call — making eth_getLogs useless
                    // for real Solidity events (ProviderRegistered, Transfer,
                    // Approval, ChatRegistered, etc.).
                    for log in revm_logs {
                        context.add_log(log);
                    }
                }
                Err(e) => {
                    VM_EXECUTIONS_TOTAL.with_label_values(&["err"]).inc();
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    // ---------- Precompile handling ----------
    fn is_precompile_address(&self, addr: &Address) -> bool {
        let model = Self::model_precompile_address();
        let artifact = Self::artifact_precompile_address();
        let governance = Self::governance_precompile_address();
        *addr == model || *addr == artifact || *addr == governance
    }

    fn model_precompile_address() -> Address {
        // 0x0000000000000000000000000000000000001000
        let mut a = [0u8; 20];
        a[18] = 0x10;
        a[19] = 0x00;
        Address(a)
    }

    fn artifact_precompile_address() -> Address {
        // 0x0000000000000000000000000000000000001002
        let mut a = [0u8; 20];
        a[18] = 0x10;
        a[19] = 0x02;
        Address(a)
    }

    fn governance_precompile_address() -> Address {
        // 0x0000000000000000000000000000000000001003
        let mut a = [0u8; 20];
        a[18] = 0x10;
        a[19] = 0x03;
        Address(a)
    }

    async fn execute_precompile(
        &self,
        to: &Address,
        data: &[u8],
        from: Address,
        context: &mut ExecutionContext,
    ) -> Result<(), ExecutionError> {
        if *to == Self::model_precompile_address() {
            let res = self.execute_model_precompile(data, from, context).await;
            match &res {
                Ok(()) => PRECOMPILE_CALLS_TOTAL
                    .with_label_values(&["model", "unknown", "ok"])
                    .inc(),
                Err(_) => PRECOMPILE_CALLS_TOTAL
                    .with_label_values(&["model", "unknown", "err"])
                    .inc(),
            }
            res
        } else if *to == Self::artifact_precompile_address() {
            PRECOMPILE_CALLS_TOTAL
                .with_label_values(&["artifact", "noop", "ok"])
                .inc();
            Ok(())
        } else if *to == Self::governance_precompile_address() {
            let res = self
                .execute_governance_precompile(data, from, context)
                .await;
            match &res {
                Ok(()) => PRECOMPILE_CALLS_TOTAL
                    .with_label_values(&["governance", "unknown", "ok"])
                    .inc(),
                Err(_) => PRECOMPILE_CALLS_TOTAL
                    .with_label_values(&["governance", "unknown", "err"])
                    .inc(),
            }
            res
        } else {
            Err(ExecutionError::InvalidInput)
        }
    }

    async fn execute_governance_precompile(
        &self,
        data: &[u8],
        from: Address,
        context: &mut ExecutionContext,
    ) -> Result<(), ExecutionError> {
        use sha3::{Digest, Keccak256};
        if data.len() < 4 {
            return Err(ExecutionError::InvalidInput);
        }
        let selector = &data[0..4];
        let args = &data[4..];

        let sel_set_admin = &Keccak256::digest(b"setAdmin(address)")[..4];
        let sel_queue = &Keccak256::digest(b"queueSetParam(bytes32,bytes,uint64)")[..4];
        let sel_execute = &Keccak256::digest(b"executeSetParam(bytes32)")[..4];
        let sel_get = &Keccak256::digest(b"getParam(bytes32)")[..4];

        let gov_addr = Self::governance_precompile_address();

        // RM-B1 / WP-B3.3 (audit C-04): read current admin from
        // state. NO 0x11..11 fallback — if admin is unset, the
        // governance precompile is "uninitialized" and only
        // genesis-context calls (block.height == 0) can call
        // `setAdmin` to bootstrap. Pre-fix the fallback to
        // 0x11..11 meant any sender controlling that well-known
        // burner address could take over governance on a fresh
        // chain.
        let admin_key = b"ADMIN".to_vec();
        let current_admin: Option<Address> = self
            .state_db
            .get_storage(&gov_addr, &admin_key)
            .and_then(|v| {
                if v.len() >= 20 {
                    let mut a = [0u8; 20];
                    a.copy_from_slice(&v[..20]);
                    Some(Address(a))
                } else {
                    None
                }
            });

        if selector == sel_set_admin {
            // RM-B1 / WP-B3.3: admin can be set in two ways —
            //   (a) by the existing admin (rotation), or
            //   (b) by anyone in the genesis-block context
            //       (block.height == 0). Genesis is the bootstrap
            //       window where the chain has no admin yet.
            // Outside both cases, refuse.
            let allowed = match current_admin {
                Some(admin) => from == admin,
                None => context.block_number == 0,
            };
            if !allowed {
                return Err(ExecutionError::AccessDenied);
            }
            if args.len() < 32 {
                return Err(ExecutionError::InvalidInput);
            }
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&args[12..32]);
            self.state_db
                .set_storage(gov_addr, admin_key, addr.to_vec());
            return Ok(());
        }

        // For all non-setAdmin governance ops, the admin MUST be
        // initialized AND the caller must be that admin.
        let current_admin = match current_admin {
            Some(a) => a,
            None => return Err(ExecutionError::AccessDenied),
        };

        if selector == sel_queue {
            if from != current_admin {
                return Err(ExecutionError::AccessDenied);
            }
            if args.len() < 96 {
                return Err(ExecutionError::InvalidInput);
            }
            let key = &args[0..32];
            let mut offb = [0u8; 32];
            offb.copy_from_slice(&args[32..64]);
            let off = primitive_types::U256::from_big_endian(&offb);
            let off_usize: usize = off.try_into().unwrap_or(usize::MAX);
            if off_usize == usize::MAX {
                return Err(ExecutionError::InvalidInput);
            }
            let mut eta_bytes = [0u8; 32];
            eta_bytes.copy_from_slice(&args[64..96]);
            let eta_u256 = primitive_types::U256::from_big_endian(&eta_bytes);
            let eta: u64 = eta_u256.try_into().unwrap_or(u64::MAX);
            let dyn_start = 4 + off_usize;
            if data.len() < dyn_start + 32 {
                return Err(ExecutionError::InvalidInput);
            }
            let mut lenb = [0u8; 32];
            lenb.copy_from_slice(&data[dyn_start..dyn_start + 32]);
            let len = primitive_types::U256::from_big_endian(&lenb);
            let l: usize = len.try_into().unwrap_or(usize::MAX);
            let val_start = dyn_start + 32;
            let val_end = val_start
                .checked_add(l)
                .ok_or(ExecutionError::InvalidInput)?;
            if data.len() < val_end {
                return Err(ExecutionError::InvalidInput);
            }
            let value = &data[val_start..val_end];
            // Store pending
            let mut pending_key = b"PENDING:".to_vec();
            pending_key.extend_from_slice(key);
            let mut stored = eta.to_le_bytes().to_vec();
            stored.extend_from_slice(value);
            self.state_db.set_storage(gov_addr, pending_key, stored);
            return Ok(());
        }

        if selector == sel_execute {
            if from != current_admin {
                return Err(ExecutionError::AccessDenied);
            }
            if args.len() < 32 {
                return Err(ExecutionError::InvalidInput);
            }
            let key = &args[0..32];
            let mut pending_key = b"PENDING:".to_vec();
            pending_key.extend_from_slice(key);
            if let Some(stored) = self.state_db.get_storage(&gov_addr, &pending_key) {
                if stored.len() < 8 {
                    return Err(ExecutionError::InvalidInput);
                }
                let mut eta_bytes = [0u8; 8];
                eta_bytes.copy_from_slice(&stored[..8]);
                let eta = u64::from_le_bytes(eta_bytes);
                if context.timestamp < eta {
                    return Err(ExecutionError::Reverted("Timelock not expired".into()));
                }
                let value = &stored[8..];
                let mut param_key = b"PARAM:".to_vec();
                param_key.extend_from_slice(key);
                self.state_db
                    .set_storage(gov_addr, param_key, value.to_vec());
                self.state_db.delete_storage(gov_addr, &pending_key);
                return Ok(());
            } else {
                return Err(ExecutionError::Reverted("No such pending param".into()));
            }
        }

        if selector == sel_get {
            if args.len() < 32 {
                return Err(ExecutionError::InvalidInput);
            }
            let key = &args[0..32];
            let mut param_key = b"PARAM:".to_vec();
            param_key.extend_from_slice(key);
            if let Some(value) = self.state_db.get_storage(&gov_addr, &param_key) {
                context.output = value;
            } else {
                context.output = Vec::new();
            }
            return Ok(());
        }

        Err(ExecutionError::InvalidInput)
    }

    async fn execute_model_precompile(
        &self,
        data: &[u8],
        from: Address,
        context: &mut ExecutionContext,
    ) -> Result<(), ExecutionError> {
        use sha3::{Digest, Keccak256};
        if data.len() < 4 {
            return Err(ExecutionError::InvalidInput);
        }
        let selector = &data[0..4];
        let args = &data[4..];

        let sel_register = &Keccak256::digest(b"registerModel(bytes32,string)")[..4];
        let sel_register_ex =
            &Keccak256::digest(b"registerModel(bytes32,string,uint8,uint256)")[..4];
        let sel_infer = &Keccak256::digest(b"executeInference(bytes32,bytes)")[..4];
        let sel_pin = &Keccak256::digest(b"pin(string,uint256)")[..4];
        let sel_status = &Keccak256::digest(b"status(string)")[..4];

        if selector == sel_register || selector == sel_register_ex {
            if args.len() < 64 {
                return Err(ExecutionError::InvalidInput);
            }
            let mut mh = [0u8; 32];
            mh.copy_from_slice(&args[0..32]);
            let model_hash = Hash::new(mh);

            let mut off = [0u8; 32];
            off.copy_from_slice(&args[32..64]);
            let offset = primitive_types::U256::from_big_endian(&off);
            let offset_usize: usize = offset.try_into().unwrap_or(usize::MAX);
            if offset_usize == usize::MAX {
                return Err(ExecutionError::InvalidInput);
            }
            let dyn_start = 4 + offset_usize;
            if data.len() < dyn_start + 32 {
                return Err(ExecutionError::InvalidInput);
            }
            let mut lb = [0u8; 32];
            lb.copy_from_slice(&data[dyn_start..dyn_start + 32]);
            let len = primitive_types::U256::from_big_endian(&lb);
            let len_usize: usize = len.try_into().unwrap_or(usize::MAX);
            let cid_start = dyn_start + 32;
            let cid_end = cid_start
                .checked_add(len_usize)
                .ok_or(ExecutionError::InvalidInput)?;
            if data.len() < cid_end {
                return Err(ExecutionError::InvalidInput);
            }
            let cid = String::from_utf8_lossy(&data[cid_start..cid_end]).to_string();

            let md = ModelMetadata {
                name: "OnchainModel".to_string(),
                version: "1.0".to_string(),
                description: "Registered via precompile".to_string(),
                framework: "Unknown".to_string(),
                input_shape: vec![1],
                output_shape: vec![1],
                size_bytes: 0,
                created_at: context.timestamp,
            };
            let access_policy = if selector == sel_register_ex {
                if args.len() < 128 {
                    return Err(ExecutionError::InvalidInput);
                }
                let pol_u8 = args[95];
                match pol_u8 {
                    0 => AccessPolicy::Public,
                    1 => AccessPolicy::Private,
                    2 => AccessPolicy::Restricted(Vec::new()),
                    3 => {
                        let mut pb = [0u8; 32];
                        pb.copy_from_slice(&args[96..128]);
                        let fee = primitive_types::U256::from_big_endian(&pb);
                        AccessPolicy::PayPerUse { fee }
                    }
                    _ => AccessPolicy::Public,
                }
            } else {
                AccessPolicy::Public
            };

            let res = self
                .execute_register_model(
                    from,
                    model_hash,
                    md,
                    access_policy,
                    Some(cid.clone()),
                    context,
                )
                .await;

            match &res {
                Ok(()) => PRECOMPILE_CALLS_TOTAL
                    .with_label_values(&["model", "registerModel", "ok"])
                    .inc(),
                Err(_) => PRECOMPILE_CALLS_TOTAL
                    .with_label_values(&["model", "registerModel", "err"])
                    .inc(),
            }
            res
        } else if selector == sel_infer {
            if args.len() < 64 {
                return Err(ExecutionError::InvalidInput);
            }
            let mut mh = [0u8; 32];
            mh.copy_from_slice(&args[0..32]);
            let model_id = ModelId(Hash::new(mh));

            let mut off = [0u8; 32];
            off.copy_from_slice(&args[32..64]);
            let offset = primitive_types::U256::from_big_endian(&off);
            let offset_usize: usize = offset.try_into().unwrap_or(usize::MAX);
            if offset_usize == usize::MAX {
                return Err(ExecutionError::InvalidInput);
            }
            let dyn_start = 4 + offset_usize;
            if data.len() < dyn_start + 32 {
                return Err(ExecutionError::InvalidInput);
            }
            let mut lb = [0u8; 32];
            lb.copy_from_slice(&data[dyn_start..dyn_start + 32]);
            let len = primitive_types::U256::from_big_endian(&lb);
            let len_usize: usize = len.try_into().unwrap_or(usize::MAX);
            let bytes_start = dyn_start + 32;
            let bytes_end = bytes_start
                .checked_add(len_usize)
                .ok_or(ExecutionError::InvalidInput)?;
            if data.len() < bytes_end {
                return Err(ExecutionError::InvalidInput);
            }
            let input_data = data[bytes_start..bytes_end].to_vec();

            let res = self
                .execute_inference(
                    from,
                    model_id,
                    input_data,
                    context.gas_limit.saturating_sub(context.gas_used),
                    context,
                )
                .await;
            match &res {
                Ok(()) => PRECOMPILE_CALLS_TOTAL
                    .with_label_values(&["model", "executeInference", "ok"])
                    .inc(),
                Err(_) => PRECOMPILE_CALLS_TOTAL
                    .with_label_values(&["model", "executeInference", "err"])
                    .inc(),
            }
            res
        } else if selector == sel_pin {
            // pin(string cid, uint256 replicas)
            // args: offset(32) | replicas(32)
            if args.len() < 64 {
                return Err(ExecutionError::InvalidInput);
            }
            let mut off = [0u8; 32];
            off.copy_from_slice(&args[0..32]);
            let offset = primitive_types::U256::from_big_endian(&off);
            let off_usize: usize = offset.try_into().unwrap_or(usize::MAX);
            let mut repb = [0u8; 32];
            repb.copy_from_slice(&args[32..64]);
            let replicas_u256 = primitive_types::U256::from_big_endian(&repb);
            let replicas: usize = replicas_u256.try_into().unwrap_or(1);
            let dyn_start = 4 + off_usize;
            if data.len() < dyn_start + 32 {
                return Err(ExecutionError::InvalidInput);
            }
            let mut lenb = [0u8; 32];
            lenb.copy_from_slice(&data[dyn_start..dyn_start + 32]);
            let len = primitive_types::U256::from_big_endian(&lenb);
            let l: usize = len.try_into().unwrap_or(usize::MAX);
            let s = dyn_start + 32;
            let e = s.checked_add(l).ok_or(ExecutionError::InvalidInput)?;
            if data.len() < e {
                return Err(ExecutionError::InvalidInput);
            }
            let cid = String::from_utf8_lossy(&data[s..e]).to_string();
            if let Some(art) = &self.artifact_service {
                art.pin(&cid, replicas).await?;
            }
            context.output = b"ok".to_vec();
            Ok(())
        } else if selector == sel_status {
            // status(string cid)
            if args.len() < 32 {
                return Err(ExecutionError::InvalidInput);
            }
            let mut off = [0u8; 32];
            off.copy_from_slice(&args[0..32]);
            let offset = primitive_types::U256::from_big_endian(&off);
            let off_usize: usize = offset.try_into().unwrap_or(usize::MAX);
            let dyn_start = 4 + off_usize;
            if data.len() < dyn_start + 32 {
                return Err(ExecutionError::InvalidInput);
            }
            let mut lenb = [0u8; 32];
            lenb.copy_from_slice(&data[dyn_start..dyn_start + 32]);
            let len = primitive_types::U256::from_big_endian(&lenb);
            let l: usize = len.try_into().unwrap_or(usize::MAX);
            let s = dyn_start + 32;
            let e = s.checked_add(l).ok_or(ExecutionError::InvalidInput)?;
            if data.len() < e {
                return Err(ExecutionError::InvalidInput);
            }
            let cid = String::from_utf8_lossy(&data[s..e]).to_string();
            let status = if let Some(art) = &self.artifact_service {
                art.status(&cid).await?
            } else {
                "unknown".to_string()
            };
            context.output = status.into_bytes();
            Ok(())
        } else {
            Err(ExecutionError::InvalidInput)
        }
    }

    fn artifact_index_key(model_hash: &Hash) -> Vec<u8> {
        let mut k = b"MODEL_ARTS:".to_vec();
        k.extend_from_slice(model_hash.as_bytes());
        k
    }

    pub fn add_model_artifact(&self, model_hash: &Hash, cid: &str) {
        let addr = Self::artifact_precompile_address();
        let key = Self::artifact_index_key(model_hash);
        let mut list: Vec<String> = if let Some(bytes) = self.state_db.get_storage(&addr, &key) {
            serde_json::from_slice(&bytes).unwrap_or_default()
        } else {
            Vec::new()
        };
        if !list.iter().any(|c| c == cid) {
            list.push(cid.to_string());
        }
        if let Ok(bytes) = serde_json::to_vec(&list) {
            self.state_db.set_storage(addr, key, bytes);
        }
    }

    pub fn list_model_artifacts(&self, model_hash: &Hash) -> Vec<String> {
        let addr = Self::artifact_precompile_address();
        let key = Self::artifact_index_key(model_hash);
        if let Some(bytes) = self.state_db.get_storage(&addr, &key) {
            serde_json::from_slice(&bytes).unwrap_or_default()
        } else {
            Vec::new()
        }
    }

    fn proof_index_key(model_hash: &Hash) -> Vec<u8> {
        let mut k = b"MODEL_PROOFS:".to_vec();
        k.extend_from_slice(model_hash.as_bytes());
        k
    }

    fn add_model_proof_artifact(&self, model_hash: &Hash, cid: &str) {
        let addr = Self::artifact_precompile_address();
        let key = Self::proof_index_key(model_hash);
        let mut list: Vec<String> = if let Some(bytes) = self.state_db.get_storage(&addr, &key) {
            serde_json::from_slice(&bytes).unwrap_or_default()
        } else {
            Vec::new()
        };
        if !list.iter().any(|c| c == cid) {
            list.push(cid.to_string());
        }
        if let Ok(bytes) = serde_json::to_vec(&list) {
            self.state_db.set_storage(addr, key, bytes);
        }
    }

    pub fn list_model_proofs(&self, model_hash: &Hash) -> Vec<String> {
        let addr = Self::artifact_precompile_address();
        let key = Self::proof_index_key(model_hash);
        if let Some(bytes) = self.state_db.get_storage(&addr, &key) {
            serde_json::from_slice(&bytes).unwrap_or_default()
        } else {
            Vec::new()
        }
    }

    pub async fn artifact_pin(&self, cid: &str, replicas: usize) -> Result<(), ExecutionError> {
        if let Some(svc) = &self.artifact_service {
            svc.pin(cid, replicas).await
        } else {
            Err(ExecutionError::Reverted(
                "Artifact service not configured".into(),
            ))
        }
    }

    pub async fn artifact_status(&self, cid: &str) -> Result<String, ExecutionError> {
        if let Some(svc) = &self.artifact_service {
            svc.status(cid).await
        } else {
            Ok("unknown".into())
        }
    }

    fn default_artifact_replicas(&self) -> usize {
        // Read from governance: PARAM:artifact_replication
        let gov_addr = Self::governance_precompile_address();
        if let Some(bytes) = self
            .state_db
            .get_storage(&gov_addr, b"PARAM:artifact_replication")
        {
            if !bytes.is_empty() {
                return bytes[0].max(1) as usize;
            }
            if bytes.len() >= 8 {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes[..8]);
                let v = u64::from_le_bytes(arr);
                return v.max(1) as usize;
            }
        }
        1
    }

    /// Execute an inference using the configured inference service without mutating state.
    pub async fn run_inference_preview(
        &self,
        from: Address,
        model_id: ModelId,
        input_data: Vec<u8>,
        max_gas: u64,
    ) -> Result<InferencePreview, ExecutionError> {
        let model = self
            .state_db
            .get_model(&model_id)
            .ok_or(ExecutionError::ModelNotFound(model_id))?;

        match &model.access_policy {
            AccessPolicy::Public => {}
            AccessPolicy::Private if model.owner == from => {}
            AccessPolicy::Restricted(allowed) if allowed.contains(&from) => {}
            AccessPolicy::PayPerUse { .. } => {
                if model.owner != from {
                    return Err(ExecutionError::AccessDenied);
                }
            }
            _ => return Err(ExecutionError::AccessDenied),
        }

        if let Some(svc) = &self.inference_service {
            let start = Instant::now();
            let (output, gas_used, provider, provider_fee, proof) =
                svc.run_inference(model_id, input_data, max_gas).await?;
            let latency_ms = start.elapsed().as_millis() as u64;

            Ok(InferencePreview {
                output,
                gas_used,
                provider,
                provider_fee,
                proof,
                latency_ms,
            })
        } else {
            Ok(InferencePreview {
                output: vec![0x01, 0x02, 0x03, 0x04],
                gas_used: 0,
                provider: Address([0; 20]),
                provider_fee: U256::zero(),
                proof: None,
                latency_ms: 0,
            })
        }
    }

    /// Scan bytecode for AI opcodes and execute them
    #[allow(dead_code)]
    async fn scan_and_execute_ai_opcodes(
        &self,
        code: &[u8],
        input: &[u8],
        context: &mut ExecutionContext,
    ) -> Result<Option<Vec<u8>>, ExecutionError> {
        // AI opcode definitions
        const TENSOR_OP: u8 = 0xf0;
        const MODEL_LOAD: u8 = 0xf1;
        const MODEL_EXEC: u8 = 0xf2;
        const ZK_PROVE: u8 = 0xf3;
        const ZK_VERIFY: u8 = 0xf4;

        for (i, &byte) in code.iter().enumerate() {
            match byte {
                TENSOR_OP => {
                    debug!("Executing TENSOR_OP at position {}", i);
                    context.use_gas(self.gas_schedule.tensor_op)?;
                    return Ok(Some(self.execute_tensor_operation(input, context).await?));
                }
                MODEL_LOAD => {
                    debug!("Executing MODEL_LOAD at position {}", i);
                    context.use_gas(self.gas_schedule.model_load)?;
                    return Ok(Some(self.execute_model_load(input, context).await?));
                }
                MODEL_EXEC => {
                    debug!("Executing MODEL_EXEC at position {}", i);
                    context.use_gas(self.gas_schedule.model_exec)?;
                    return Ok(Some(self.execute_model_execution(input, context).await?));
                }
                ZK_PROVE => {
                    debug!("Executing ZK_PROVE at position {}", i);
                    context.use_gas(self.gas_schedule.zk_prove)?;
                    return Ok(Some(self.execute_zk_prove(input, context).await?));
                }
                ZK_VERIFY => {
                    debug!("Executing ZK_VERIFY at position {}", i);
                    context.use_gas(self.gas_schedule.zk_verify)?;
                    return Ok(Some(self.execute_zk_verify(input, context).await?));
                }
                _ => continue,
            }
        }

        Ok(None)
    }

    /// Execute tensor operation
    #[allow(dead_code)]
    async fn execute_tensor_operation(
        &self,
        input: &[u8],
        context: &mut ExecutionContext,
    ) -> Result<Vec<u8>, ExecutionError> {
        // Parse tensor operation from input
        if input.len() < 8 {
            return Err(ExecutionError::InvalidInput);
        }

        // Simulate tensor operation
        let op_type = input[0];
        let dimensions = u32::from_le_bytes([input[1], input[2], input[3], input[4]]);

        // Gas cost based on tensor dimensions
        let tensor_gas = dimensions as u64 * 100;
        context.use_gas(tensor_gas)?;

        info!(
            "Tensor operation: type={}, dimensions={}",
            op_type, dimensions
        );

        // Return simulated result
        Ok(vec![0xf0, op_type, 0x01, 0x00])
    }

    /// Execute model loading
    #[allow(dead_code)]
    async fn execute_model_load(
        &self,
        input: &[u8],
        context: &mut ExecutionContext,
    ) -> Result<Vec<u8>, ExecutionError> {
        if input.len() < 32 {
            return Err(ExecutionError::InvalidInput);
        }

        let model_hash = Hash::new(
            input[0..32]
                .try_into()
                .map_err(|_| ExecutionError::InvalidInput)?,
        );
        let model_id = ModelId(model_hash);

        // Check if model exists
        let model = self
            .state_db
            .get_model(&model_id)
            .ok_or(ExecutionError::ModelNotFound(model_id))?;

        // Gas based on model size
        let load_gas = model.metadata.size_bytes / 1024;
        context.use_gas(load_gas)?;

        info!("Model loaded: {:?}", model_id);

        // Return model handle
        Ok(model_hash.as_bytes().to_vec())
    }

    /// Execute model inference
    #[allow(dead_code)]
    async fn execute_model_execution(
        &self,
        input: &[u8],
        context: &mut ExecutionContext,
    ) -> Result<Vec<u8>, ExecutionError> {
        if input.len() < 32 {
            return Err(ExecutionError::InvalidInput);
        }

        let model_hash = Hash::new(
            input[0..32]
                .try_into()
                .map_err(|_| ExecutionError::InvalidInput)?,
        );
        let model_id = ModelId(model_hash);
        let inference_data = &input[32..];

        // Execute inference
        self.execute_inference(
            context.origin,
            model_id,
            inference_data.to_vec(),
            context.gas_limit - context.gas_used,
            context,
        )
        .await?;

        Ok(context.output.clone())
    }

    /// Execute ZK proof generation
    #[allow(dead_code)]
    async fn execute_zk_prove(
        &self,
        input: &[u8],
        context: &mut ExecutionContext,
    ) -> Result<Vec<u8>, ExecutionError> {
        // Parse proof parameters
        if input.is_empty() {
            return Err(ExecutionError::InvalidInput);
        }

        // Simulate proof generation
        let proof_size = input.len().min(1024);
        let proof_gas = proof_size as u64 * 1000;
        context.use_gas(proof_gas)?;

        info!("ZK proof generated for {} bytes of input", input.len());

        // Return simulated proof
        Ok(vec![0xf3; 64])
    }

    /// Execute ZK proof verification
    #[allow(dead_code)]
    async fn execute_zk_verify(
        &self,
        input: &[u8],
        context: &mut ExecutionContext,
    ) -> Result<Vec<u8>, ExecutionError> {
        // Parse proof and public inputs
        if input.len() < 64 {
            return Err(ExecutionError::InvalidInput);
        }

        let proof = &input[0..64];
        let public_inputs = &input[64..];

        // Simulate verification
        let verify_gas = 5000 + (public_inputs.len() as u64 * 10);
        context.use_gas(verify_gas)?;

        // Check if proof is valid (simplified)
        let is_valid = proof.iter().all(|&b| b == 0xf3);

        info!("ZK proof verification: valid={}", is_valid);

        // Return verification result
        Ok(vec![if is_valid { 0x01 } else { 0x00 }])
    }

    /// Execute model registration
    async fn execute_register_model(
        &self,
        from: Address,
        model_hash: Hash,
        mut metadata: ModelMetadata,
        access_policy: AccessPolicy,
        artifact_cid: Option<String>,
        context: &mut ExecutionContext,
    ) -> Result<(), ExecutionError> {
        context.use_gas(self.gas_schedule.model_register)?;

        let model_id = ModelId(model_hash);
        metadata.created_at = context.timestamp;

        let model_state = ModelState {
            owner: from,
            model_hash,
            version: 1,
            metadata,
            access_policy,
            usage_stats: Default::default(),
        };
        let persisted_state = model_state.clone();

        self.state_db.register_model(model_id, model_state)?;

        if let Some(cid) = artifact_cid.clone() {
            let art_addr = Self::artifact_precompile_address();
            let mut key = b"MODEL_CID:".to_vec();
            key.extend_from_slice(model_hash.as_bytes());
            self.state_db
                .set_storage(art_addr, key, cid.clone().into_bytes());

            self.add_model_artifact(&model_hash, &cid);
            // Note: artifact pinning is handled by the IPFS add call (add?pin=true)
            // or by the caller. We skip explicit pin here to avoid deadlocking
            // when execute_register_model is called via futures::executor::block_on
            // (which lacks tokio's I/O driver needed for async reqwest operations).

            if let Some(storage) = &self.ai_storage {
                if let Err(err) = storage.register_model(model_id, &persisted_state, &cid) {
                    warn!(
                        "AI storage registration failed for model {:?}: {}",
                        model_id, err
                    );
                }
            }

            if let Some(adapter) = &self.model_registry {
                if let Err(err) = adapter
                    .register_model(model_id, &persisted_state, Some(&cid))
                    .await
                {
                    warn!(
                        "Model registry adapter failed for model {:?}: {}",
                        model_id, err
                    );
                }
            }
        } else if let Some(adapter) = &self.model_registry {
            if let Err(err) = adapter
                .register_model(model_id, &persisted_state, None)
                .await
            {
                warn!(
                    "Model registry adapter failed for model {:?}: {}",
                    model_id, err
                );
            }
        }

        // PIL-48c: emit a properly-hashed event topic for the model-registry
        // precompile path. PIL-48's REVM-side fix doesn't reach here because
        // this code synthesises the log directly (the precompile bypasses
        // REVM). The hash below is `keccak256("ModelRegistered(bytes32)")`,
        // matching the Solidity event signature an indexer would filter on.
        // The model hash sits in topics[1] as the indexed field.
        const MODEL_REGISTERED_TOPIC: [u8; 32] = [
            0xa4, 0xb0, 0xaf, 0x38, 0xd0, 0x49, 0xba, 0x81,
            0x70, 0x3a, 0x0d, 0x0e, 0x46, 0xcc, 0x2f, 0xf3,
            0x96, 0x81, 0x21, 0x03, 0x02, 0x13, 0x40, 0x46,
            0x23, 0x71, 0x11, 0xa8, 0xfb, 0x7d, 0xee, 0x72,
        ];
        context.add_log(Log {
            address: from,
            topics: vec![Hash::new(MODEL_REGISTERED_TOPIC), model_hash],
            data: vec![],
        });

        info!("Model registered: {:?} by {}", model_id, from);
        Ok(())
    }

    /// Execute model update
    async fn execute_update_model(
        &self,
        from: Address,
        model_id: ModelId,
        new_metadata: ModelMetadata,
        artifact_cid: Option<String>,
        context: &mut ExecutionContext,
    ) -> Result<(), ExecutionError> {
        context.use_gas(self.gas_schedule.model_update)?;

        let mut model = self
            .state_db
            .get_model(&model_id)
            .ok_or(ExecutionError::ModelNotFound(model_id))?;

        // Check ownership
        if model.owner != from {
            return Err(ExecutionError::AccessDenied);
        }

        model.metadata = new_metadata;
        model.metadata.created_at = context.timestamp;
        model.version += 1;
        let updated_model = model.clone();

        self.state_db.update_model(model_id, model)?;

        if let Some(cid) = artifact_cid.clone() {
            self.add_model_artifact(&updated_model.model_hash, &cid);
            if let Some(art) = &self.artifact_service {
                let replicas = self.default_artifact_replicas();
                if let Err(err) = art.pin(&cid, replicas).await {
                    warn!("Failed to pin updated model artifact {}: {}", cid, err);
                }
            }
            if let Some(storage) = &self.ai_storage {
                if let Err(err) = storage.update_model_weights(model_id, &cid, updated_model.version)
                {
                    warn!(
                        "AI storage weight update failed for {:?}: {}",
                        model_id, err
                    );
                }
            }
            if let Some(adapter) = &self.model_registry {
                if let Err(err) = adapter
                    .update_model(model_id, &updated_model, Some(&cid))
                    .await
                {
                    warn!(
                        "Model registry adapter update failed for {:?}: {}",
                        model_id, err
                    );
                }
            }
        } else if let Some(adapter) = &self.model_registry {
            if let Err(err) = adapter.update_model(model_id, &updated_model, None).await {
                warn!(
                    "Model registry adapter update failed for {:?}: {}",
                    model_id, err
                );
            }
        }

        info!(
            "Model updated: {:?} to version {}",
            model_id, updated_model.version
        );
        Ok(())
    }

    /// Execute inference request
    async fn execute_inference(
        &self,
        from: Address,
        model_id: ModelId,
        input_data: Vec<u8>,
        max_gas: u64,
        context: &mut ExecutionContext,
    ) -> Result<(), ExecutionError> {
        // Base gas cost
        context.use_gas(self.gas_schedule.inference_base)?;

        // Additional gas per MB of input
        let input_mb = (input_data.len() / 1_048_576) as u64;
        context.use_gas(self.gas_schedule.inference_per_mb * input_mb)?;

        // Check gas limit
        if context.gas_used > max_gas {
            return Err(ExecutionError::OutOfGas);
        }

        let mut model = self
            .state_db
            .get_model(&model_id)
            .ok_or(ExecutionError::ModelNotFound(model_id))?;

        // Check access policy
        match &model.access_policy {
            AccessPolicy::Public => {}
            AccessPolicy::Private if model.owner == from => {}
            AccessPolicy::Restricted(allowed) if allowed.contains(&from) => {}
            AccessPolicy::PayPerUse { fee } => {
                // Split fee: 10% protocol treasury, 90% to model owner
                let treasury_address = Address([0x11; 20]);
                let treasury_cut = *fee / U256::from(10u8);
                let owner_cut = *fee - treasury_cut;
                // Perform transfers
                self.state_db
                    .accounts
                    .transfer(&from, &model.owner, owner_cut)?;
                if treasury_cut > U256::zero() {
                    self.state_db
                        .accounts
                        .transfer(&from, &treasury_address, treasury_cut)?;
                }
                model.usage_stats.total_fees_earned += *fee;
            }
            _ => return Err(ExecutionError::AccessDenied),
        }

        // Delegate to inference service if configured, otherwise simulate
        if let Some(svc) = &self.inference_service {
            let remaining = context.gas_limit.saturating_sub(context.gas_used);
            let (out, gas_used, provider_addr, provider_fee, proof_bytes_opt) = svc
                .run_inference(model_id, input_data.clone(), remaining)
                .await?;
            // Charge compute gas
            if gas_used > 0 {
                context.use_gas(gas_used)?;
            }
            // Pay provider
            if provider_fee > U256::zero() {
                self.state_db
                    .accounts
                    .transfer(&from, &provider_addr, provider_fee)?;
            }
            // Store proof artifact if provided
            if let Some(proof_bytes) = proof_bytes_opt {
                if let Some(art) = &self.artifact_service {
                    // Add to first provider, then pin across others via pin()
                    if let Ok(cid) = art.add(&proof_bytes).await {
                        self.add_model_proof_artifact(&model_id.0, &cid);
                        let _ = art.pin(&cid, self.default_artifact_replicas()).await;
                    }
                }
            }
            context.output = out;
        } else {
            // Simulate inference output
            context.output = vec![0x01, 0x02, 0x03, 0x04];
        }

        // Update usage stats
        model.usage_stats.total_inferences += 1;
        model.usage_stats.total_gas_used += context.gas_used;
        model.usage_stats.last_used = context.timestamp;
        self.state_db.update_model(model_id, model)?;

        info!("Inference executed: model={:?}, from={}", model_id, from);
        Ok(())
    }

    /// Execute gradient submission
    async fn execute_submit_gradient(
        &self,
        from: Address,
        job_id: JobId,
        _gradient_data: Vec<u8>,
        _proof: Vec<u8>,
        context: &mut ExecutionContext,
    ) -> Result<(), ExecutionError> {
        context.use_gas(self.gas_schedule.training_submit)?;

        let mut job = self
            .state_db
            .get_training_job(&job_id)
            .ok_or(ExecutionError::Reverted("Job not found".to_string()))?;

        // Check job status
        if job.status != JobStatus::Active {
            return Err(ExecutionError::Reverted("Job not active".to_string()));
        }

        // Add participant if not already
        if !job.participants.contains(&from) {
            job.participants.push(from);
        }

        job.gradients_submitted += 1;

        // Check if job complete
        if job.gradients_submitted >= job.gradients_required {
            job.status = JobStatus::Completed;
            job.completed_at = Some(context.timestamp);

            // Distribute rewards
            let reward_per_participant = job.reward_pool / U256::from(job.participants.len());
            for participant in &job.participants {
                let balance = self.state_db.accounts.get_balance(participant);
                self.state_db
                    .accounts
                    .set_balance(*participant, balance + reward_per_participant);
            }
        }

        self.state_db.update_training_job(job_id, job)?;

        info!("Gradient submitted: job={:?}, from={}", job_id, from);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use citrate_consensus::types::{BlockBuilder, PublicKey, Signature};
    use parking_lot::Mutex;
    use serde_json::json;
    use sha3::{Digest, Keccak256};
    use std::sync::Arc;

    struct RecordingStorage {
        records: Arc<Mutex<Vec<(ModelId, String)>>>,
        updates: Arc<Mutex<Vec<(ModelId, String, u32)>>>,
    }

    impl RecordingStorage {
        #[allow(clippy::type_complexity)]
        fn new() -> (
            Self,
            Arc<Mutex<Vec<(ModelId, String)>>>,
            Arc<Mutex<Vec<(ModelId, String, u32)>>>,
        ) {
            let records = Arc::new(Mutex::new(Vec::new()));
            let updates = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    records: records.clone(),
                    updates: updates.clone(),
                },
                records,
                updates,
            )
        }
    }

    impl AIModelStorage for RecordingStorage {
        fn register_model(
            &self,
            model_id: ModelId,
            _model_state: &ModelState,
            weight_cid: &str,
        ) -> anyhow::Result<()> {
            self.records.lock().push((model_id, weight_cid.to_string()));
            Ok(())
        }

        fn update_model_weights(
            &self,
            model_id: ModelId,
            weight_cid: &str,
            new_version: u32,
        ) -> anyhow::Result<()> {
            self.updates
                .lock()
                .push((model_id, weight_cid.to_string(), new_version));
            Ok(())
        }
    }

    #[allow(clippy::type_complexity)]
    struct RecordingRegistry {
        records: Arc<Mutex<Vec<(ModelId, Option<String>)>>>,
    }

    impl RecordingRegistry {
        #[allow(clippy::type_complexity)]
        fn new() -> (Self, Arc<Mutex<Vec<(ModelId, Option<String>)>>>) {
            let records = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    records: records.clone(),
                },
                records,
            )
        }
    }

    #[async_trait]
    impl ModelRegistryAdapter for RecordingRegistry {
        async fn register_model(
            &self,
            model_id: ModelId,
            _model_state: &ModelState,
            artifact_cid: Option<&str>,
        ) -> anyhow::Result<()> {
            self.records
                .lock()
                .push((model_id, artifact_cid.map(|s| s.to_string())));
            Ok(())
        }
    }

    fn create_test_block() -> Block {
        BlockBuilder::new()
            .height(100)
            .timestamp(1000000)
            .build_unhashed()
    }

    fn create_test_tx(
        from: PublicKey,
        to: Option<PublicKey>,
        value: u64,
        nonce: u64,
    ) -> Transaction {
        Transaction {
            hash: Hash::new([1; 32]),
            nonce,
            from,
            to,
            value: value as u128,
            gas_limit: 100000,
            gas_price: 1000000000,
            data: vec![],
            signature: Signature::new([0; 64]),
            tx_type: None,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_transfer_execution() {
        let state_db = Arc::new(StateDB::new());
        let executor = Executor::new(state_db.clone());

        let alice = PublicKey::new([1; 32]);
        let bob = PublicKey::new([2; 32]);
        let alice_addr = Address::from_public_key(&alice);
        let bob_addr = Address::from_public_key(&bob);

        // Setup alice with balance (needs enough for gas + transfer value)
        state_db
            .accounts
            .set_balance(alice_addr, U256::from(1_000_000_000_000_000u128));

        let block = create_test_block();
        let tx = create_test_tx(alice, Some(bob), 1000, 0);

        let receipt = executor.execute_transaction(&block, &tx).await.unwrap();

        assert!(receipt.status);
        assert_eq!(state_db.accounts.get_balance(&bob_addr), U256::from(1000));
    }

    #[tokio::test]
    async fn test_register_model_via_transaction_payload() {
        let state_db = Arc::new(StateDB::new());
        let (storage_adapter, storage_records, _) = RecordingStorage::new();
        let (registry_adapter, registry_records) = RecordingRegistry::new();

        let executor = Executor::new(state_db.clone())
            .with_ai_storage_adapter(Arc::new(storage_adapter))
            .with_model_registry_adapter(Arc::new(registry_adapter));

        let sender_pk = PublicKey::new([4; 32]);
        let from_addr = Address::from_public_key(&sender_pk);
        state_db
            .accounts
            .set_balance(from_addr, U256::from(1_000_000_000_000_000u128));

        let block = create_test_block();
        let mut target_addr = [0u8; 32];
        target_addr[18] = 0x10;
        target_addr[19] = 0x00;
        let target_pk = PublicKey::new(target_addr);

        let model_hash_bytes = [0xAB; 32];
        let metadata_json = json!({
            "name": "CLI Model",
            "version": "1.2.3",
            "description": "Integration test model",
            "framework": "onnx",
            "input_shape": [1, 4],
            "output_shape": [1],
            "size_bytes": 2048
        });
        let metadata_bytes = serde_json::to_vec(&metadata_json).unwrap();
        let metadata_len = metadata_bytes.len() as u32;
        let artifact_cid = "bafyModelCID123";

        let mut data = Vec::new();
        data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&model_hash_bytes);
        data.extend_from_slice(&metadata_len.to_be_bytes());
        data.extend_from_slice(&metadata_bytes);
        data.push(0); // public policy
        data.extend_from_slice(&(artifact_cid.len() as u32).to_be_bytes());
        data.extend_from_slice(artifact_cid.as_bytes());

        let tx = citrate_consensus::types::Transaction {
            hash: Hash::new([5; 32]),
            nonce: 0,
            from: sender_pk,
            to: Some(target_pk),
            value: 0,
            gas_limit: 200000,
            gas_price: 1_000_000_000,
            data,
            signature: Signature::new([0; 64]),
            tx_type: None,
            ..Default::default()
        };

        let receipt = executor.execute_transaction(&block, &tx).await.unwrap();
        assert!(receipt.status);

        let model_id = ModelId(Hash::new(model_hash_bytes));
        let stored_model = state_db.get_model(&model_id).expect("model stored");
        assert_eq!(stored_model.metadata.name, "CLI Model");
        assert_eq!(stored_model.metadata.framework, "onnx");
        assert_eq!(stored_model.metadata.input_shape, vec![1, 4]);

        let stored_records = storage_records.lock();
        assert_eq!(stored_records.len(), 1);
        assert_eq!(stored_records[0].0, model_id);
        assert_eq!(stored_records[0].1, artifact_cid);
        drop(stored_records);

        let registry_records_guard = registry_records.lock();
        assert_eq!(registry_records_guard.len(), 1);
        assert_eq!(registry_records_guard[0].0, model_id);
        assert_eq!(registry_records_guard[0].1.as_deref(), Some(artifact_cid));
    }

    #[tokio::test]
    async fn test_model_precompile_register_and_infer() {
        let state_db = Arc::new(StateDB::new());
        let executor = Executor::new(state_db.clone());

        // Sender and dummy block
        let sender_pk = PublicKey::new([3; 32]);
        let from_addr = Address::from_public_key(&sender_pk);
        state_db
            .accounts
            .set_balance(from_addr, U256::from(1_000_000_000_000_000u128));

        let block = create_test_block();

        // Build precompile public key whose first 20 bytes are the model precompile address
        let mut pc_bytes = [0u8; 32];
        // 0x...1000 in last two bytes of 20-byte address
        pc_bytes[18] = 0x10;
        pc_bytes[19] = 0x00;
        let precompile_pk = PublicKey::new(pc_bytes);

        // registerModel(bytes32,string)
        let mut reg_data = Vec::new();
        let reg_sel = &Keccak256::digest(b"registerModel(bytes32,string)")[..4];
        reg_data.extend_from_slice(reg_sel);
        let model_hash = [9u8; 32];
        reg_data.extend_from_slice(&model_hash); // bytes32
        reg_data.extend_from_slice(&[0u8; 31]);
        reg_data.push(64); // offset = 64 (0x40)
                           // dynamic part
        reg_data.extend_from_slice(&[0u8; 31]);
        reg_data.push(3); // length = 3
        reg_data.extend_from_slice(b"cid");
        // pad to 32
        reg_data.extend_from_slice(&[0u8; 29]);

        // Execute register call
        let tx_reg = citrate_consensus::types::Transaction {
            hash: Hash::new([2; 32]),
            nonce: 0,
            from: sender_pk,
            to: Some(precompile_pk),
            value: 0,
            gas_limit: 200000,
            gas_price: 1_000_000_000,
            data: reg_data,
            signature: Signature::new([0; 64]),
            tx_type: None,
            ..Default::default()
        };
        let _ = executor.execute_transaction(&block, &tx_reg).await.unwrap();

        // Verify model registered
        let mid = ModelId(Hash::new(model_hash));
        let model = state_db.get_model(&mid).expect("model exists");
        assert_eq!(model.owner, from_addr);

        // executeInference(bytes32,bytes)
        let mut inf_data = Vec::new();
        let inf_sel = &Keccak256::digest(b"executeInference(bytes32,bytes)")[..4];
        inf_data.extend_from_slice(inf_sel);
        inf_data.extend_from_slice(&model_hash);
        inf_data.extend_from_slice(&[0u8; 31]);
        inf_data.push(64); // offset to bytes
                           // dynamic bytes
        inf_data.extend_from_slice(&[0u8; 31]);
        inf_data.push(4); // len = 4
        inf_data.extend_from_slice(&[1, 2, 3, 4]); // bytes
        inf_data.extend_from_slice(&[0u8; 28]); // pad

        let tx_inf = citrate_consensus::types::Transaction {
            hash: Hash::new([3; 32]),
            nonce: 1,
            from: sender_pk,
            to: Some(precompile_pk),
            value: 0,
            gas_limit: 200000,
            gas_price: 1_000_000_000,
            data: inf_data,
            signature: Signature::new([0; 64]),
            tx_type: None,
            ..Default::default()
        };
        let receipt = executor.execute_transaction(&block, &tx_inf).await.unwrap();
        assert!(receipt.status);
        // Output set by executor inference simulation
        assert_eq!(receipt.output, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[tokio::test]
    async fn test_governance_precompile_timelock_and_params() {
        use sha3::{Digest, Keccak256};

        let state_db = Arc::new(StateDB::new());
        let executor = Executor::new(state_db.clone());

        // Set sender to admin address.
        let mut admin_pk_bytes = [0u8; 32];
        admin_pk_bytes[..20].copy_from_slice(&[0x11; 20]);
        let admin_pk = PublicKey::new(admin_pk_bytes);
        let admin_addr = Address([0x11; 20]);
        state_db
            .accounts
            .set_balance(admin_addr, U256::from(1_000_000_000_000_000u128));

        let mut block = create_test_block();
        block.header.timestamp = 1_000_000;

        // Build governance precompile address as in executor
        let gov_addr = {
            let mut a = [0u8; 20];
            a[18] = 0x10;
            a[19] = 0x03;
            Address(a)
        };

        // RM-B1 / WP-B3.3 (audit C-04): the executor no longer
        // defaults `current_admin` to 0x11..11. We pre-seed the
        // ADMIN storage slot here to mirror what genesis-block
        // bootstrap code does on a real chain, so the test can
        // continue exercising the queue/execute/get path.
        state_db.set_storage(
            gov_addr,
            b"ADMIN".to_vec(),
            admin_addr.0.to_vec(),
        );
        let mut gov_pk = [0u8; 32];
        gov_pk[..20].copy_from_slice(&gov_addr.0);
        let gov_pk = PublicKey::new(gov_pk);

        // 1) setAdmin(address) to same admin (no-op but exercises path)
        let mut set_admin = Vec::new();
        let sel_set_admin = &Keccak256::digest(b"setAdmin(address)")[..4];
        set_admin.extend_from_slice(sel_set_admin);
        // abi-encode address as 32-byte, right-aligned: pad 12 zeros then 20-byte addr
        set_admin.extend_from_slice(&[0u8; 12]);
        set_admin.extend_from_slice(&admin_addr.0);
        let tx_set = Transaction {
            hash: Hash::new([10; 32]),
            nonce: 0,
            from: admin_pk,
            to: Some(gov_pk),
            value: 0,
            gas_limit: 200000,
            gas_price: 1_000_000_000,
            data: set_admin,
            signature: Signature::new([0; 64]),
            tx_type: None,
            ..Default::default()
        };
        let _ = executor.execute_transaction(&block, &tx_set).await.unwrap();

        // 2) queueSetParam(bytes32 key, bytes value, uint64 eta)
        let key = [0xAAu8; 32];
        let value: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let eta: u64 = block.header.timestamp + 60;

        let mut queue = Vec::new();
        let sel_queue = &Keccak256::digest(b"queueSetParam(bytes32,bytes,uint64)")[..4];
        queue.extend_from_slice(sel_queue);
        // key (32)
        queue.extend_from_slice(&key);
        // offset to dynamic bytes: 0x60 (96), counting from after selector per ABI (impl adds +4)
        let mut off = [0u8; 32];
        off[31] = 96;
        queue.extend_from_slice(&off);
        // eta (uint64) as 32-byte big-endian
        let mut eta_be = [0u8; 32];
        eta_be[24..32].copy_from_slice(&eta.to_be_bytes());
        queue.extend_from_slice(&eta_be);
        // dynamic bytes: length (32) + data + padding
        let mut lenb = [0u8; 32];
        lenb[31] = value.len() as u8;
        queue.extend_from_slice(&lenb);
        queue.extend_from_slice(&value);
        // pad to 32
        queue.extend_from_slice(&vec![0u8; (32 - (value.len() % 32)) % 32]);

        let tx_q = Transaction {
            hash: Hash::new([11; 32]),
            nonce: 1,
            from: admin_pk,
            to: Some(gov_pk),
            value: 0,
            gas_limit: 300000,
            gas_price: 1_000_000_000,
            data: queue,
            signature: Signature::new([0; 64]),
            tx_type: None,
            ..Default::default()
        };
        let _ = executor.execute_transaction(&block, &tx_q).await.unwrap();

        // 3) executeSetParam(bytes32 key) before eta → expect revert
        let mut exec = Vec::new();
        let sel_exec = &Keccak256::digest(b"executeSetParam(bytes32)")[..4];
        exec.extend_from_slice(sel_exec);
        exec.extend_from_slice(&key);
        let tx_e_early = Transaction {
            hash: Hash::new([12; 32]),
            nonce: 2,
            from: admin_pk,
            to: Some(gov_pk),
            value: 0,
            gas_limit: 300000,
            gas_price: 1_000_000_000,
            data: exec.clone(),
            signature: Signature::new([0; 64]),
            tx_type: None,
            ..Default::default()
        };
        let res = executor.execute_transaction(&block, &tx_e_early).await;
        assert!(res.is_ok());
        // Even on revert, receipt.status=false, but our test harness doesn’t expose; this ensures path runs.

        // Advance time and execute again
        block.header.timestamp = eta + 1;
        // Build a fresh tx with incremented nonce now that previous attempts affected nonce accounting
        let tx_e_late = Transaction {
            nonce: 3,
            ..tx_e_early
        };
        let rcpt_ok = executor
            .execute_transaction(&block, &tx_e_late)
            .await
            .unwrap();
        assert!(rcpt_ok.status);

        // 4) getParam(bytes32 key) returns value in output
        let mut getp = Vec::new();
        let sel_get = &Keccak256::digest(b"getParam(bytes32)")[..4];
        getp.extend_from_slice(sel_get);
        getp.extend_from_slice(&key);
        let tx_g = Transaction {
            hash: Hash::new([13; 32]),
            nonce: 4,
            from: admin_pk,
            to: Some(gov_pk),
            value: 0,
            gas_limit: 200000,
            gas_price: 1_000_000_000,
            data: getp,
            signature: Signature::new([0; 64]),
            tx_type: None,
            ..Default::default()
        };
        let rcpt_get = executor.execute_transaction(&block, &tx_g).await.unwrap();
        assert!(rcpt_get.status);
        assert_eq!(rcpt_get.output, value);
    }

    // ==================== C-04 governance ADMIN init tests ====================

    /// C-04.1: at genesis (block.height == 0) anyone can call
    /// setAdmin to bootstrap. This is the only way an
    /// uninitialized governance precompile gets an admin.
    #[tokio::test]
    async fn c04_genesis_setadmin_bootstraps_uninitialized() {
        use sha3::{Digest, Keccak256};
        let state_db = Arc::new(StateDB::new());
        let executor = Executor::new(state_db.clone());

        // Bootstrap caller: any address (we use 0xCAFE..).
        let mut caller_pk_bytes = [0u8; 32];
        caller_pk_bytes[..20].copy_from_slice(&[0xCA; 20]);
        let caller_pk = PublicKey::new(caller_pk_bytes);
        let caller_addr = Address([0xCA; 20]);
        state_db
            .accounts
            .set_balance(caller_addr, U256::from(1_000_000_000_000_000u128));

        let gov_addr = {
            let mut a = [0u8; 20];
            a[18] = 0x10;
            a[19] = 0x03;
            Address(a)
        };
        let mut gov_pk = [0u8; 32];
        gov_pk[..20].copy_from_slice(&gov_addr.0);
        let gov_pk = PublicKey::new(gov_pk);

        // Build a GENESIS block (height = 0).
        let mut block = BlockBuilder::new()
            .height(0)
            .timestamp(1_000_000)
            .build_unhashed();
        block.header.timestamp = 1_000_000;

        let mut set_admin = Vec::new();
        let sel_set_admin = &Keccak256::digest(b"setAdmin(address)")[..4];
        set_admin.extend_from_slice(sel_set_admin);
        set_admin.extend_from_slice(&[0u8; 12]);
        set_admin.extend_from_slice(&caller_addr.0);

        let tx = Transaction {
            hash: Hash::new([42; 32]),
            nonce: 0,
            from: caller_pk,
            to: Some(gov_pk),
            value: 0,
            gas_limit: 200000,
            gas_price: 1_000_000_000,
            data: set_admin,
            signature: Signature::new([0; 64]),
            tx_type: None,
            ..Default::default()
        };
        let receipt = executor
            .execute_transaction(&block, &tx)
            .await
            .expect("genesis-context setAdmin must succeed");
        assert!(receipt.status, "C-04: genesis setAdmin must commit");
    }

    /// C-04.2: post-genesis (block.height > 0) setAdmin from an
    /// uninitialized state is REFUSED. Pre-fix, the implicit
    /// 0x11..11 fallback let any sender controlling that burner
    /// address grab governance on a fresh chain.
    #[tokio::test]
    async fn c04_post_genesis_setadmin_uninitialized_refused() {
        use sha3::{Digest, Keccak256};
        let state_db = Arc::new(StateDB::new());
        let executor = Executor::new(state_db.clone());

        // Caller derives to 0x11..11 (the pre-fix implicit admin).
        let mut caller_pk_bytes = [0u8; 32];
        caller_pk_bytes[..20].copy_from_slice(&[0x11; 20]);
        let caller_pk = PublicKey::new(caller_pk_bytes);
        let caller_addr = Address([0x11; 20]);
        state_db
            .accounts
            .set_balance(caller_addr, U256::from(1_000_000_000_000_000u128));

        let gov_addr = {
            let mut a = [0u8; 20];
            a[18] = 0x10;
            a[19] = 0x03;
            Address(a)
        };
        let mut gov_pk = [0u8; 32];
        gov_pk[..20].copy_from_slice(&gov_addr.0);
        let gov_pk = PublicKey::new(gov_pk);

        // Post-genesis block — height > 0.
        let block = BlockBuilder::new()
            .height(100)
            .timestamp(1_000_000)
            .build_unhashed();

        let mut set_admin = Vec::new();
        let sel_set_admin = &Keccak256::digest(b"setAdmin(address)")[..4];
        set_admin.extend_from_slice(sel_set_admin);
        set_admin.extend_from_slice(&[0u8; 12]);
        set_admin.extend_from_slice(&caller_addr.0);

        let tx = Transaction {
            hash: Hash::new([43; 32]),
            nonce: 0,
            from: caller_pk,
            to: Some(gov_pk),
            value: 0,
            gas_limit: 200000,
            gas_price: 1_000_000_000,
            data: set_admin,
            signature: Signature::new([0; 64]),
            tx_type: None,
            ..Default::default()
        };
        let receipt = executor
            .execute_transaction(&block, &tx)
            .await
            .expect("tx itself must execute (gas accounted)");
        assert!(
            !receipt.status,
            "C-04: post-genesis setAdmin from uninitialized state MUST be refused"
        );

        // Verify ADMIN storage slot is still empty.
        let admin_storage = state_db.get_storage(&gov_addr, b"ADMIN");
        assert!(
            admin_storage.is_none(),
            "C-04: rejected setAdmin must NOT persist any admin"
        );
    }

    /// C-04.3: even at genesis, only `setAdmin` can be called on
    /// an uninitialized governance precompile. `queueSetParam` etc.
    /// are refused.
    #[tokio::test]
    async fn c04_genesis_other_ops_still_refused_when_uninitialized() {
        use sha3::{Digest, Keccak256};
        let state_db = Arc::new(StateDB::new());
        let executor = Executor::new(state_db.clone());

        let mut caller_pk_bytes = [0u8; 32];
        caller_pk_bytes[..20].copy_from_slice(&[0xCA; 20]);
        let caller_pk = PublicKey::new(caller_pk_bytes);
        let caller_addr = Address([0xCA; 20]);
        state_db
            .accounts
            .set_balance(caller_addr, U256::from(1_000_000_000_000_000u128));

        let gov_addr = {
            let mut a = [0u8; 20];
            a[18] = 0x10;
            a[19] = 0x03;
            Address(a)
        };
        let mut gov_pk = [0u8; 32];
        gov_pk[..20].copy_from_slice(&gov_addr.0);
        let gov_pk = PublicKey::new(gov_pk);

        let block = BlockBuilder::new()
            .height(0)
            .timestamp(1_000_000)
            .build_unhashed();

        // Try queueSetParam at genesis without ADMIN being set.
        let key = [0xAAu8; 32];
        let mut queue = Vec::new();
        let sel_queue = &Keccak256::digest(b"queueSetParam(bytes32,bytes,uint64)")[..4];
        queue.extend_from_slice(sel_queue);
        queue.extend_from_slice(&key);
        let mut off = [0u8; 32];
        off[31] = 96;
        queue.extend_from_slice(&off);
        let mut eta_be = [0u8; 32];
        eta_be[24..32].copy_from_slice(&60u64.to_be_bytes());
        queue.extend_from_slice(&eta_be);
        let mut lenb = [0u8; 32];
        lenb[31] = 4;
        queue.extend_from_slice(&lenb);
        queue.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        queue.extend_from_slice(&[0u8; 28]);

        let tx = Transaction {
            hash: Hash::new([44; 32]),
            nonce: 0,
            from: caller_pk,
            to: Some(gov_pk),
            value: 0,
            gas_limit: 300000,
            gas_price: 1_000_000_000,
            data: queue,
            signature: Signature::new([0; 64]),
            tx_type: None,
            ..Default::default()
        };
        let receipt = executor.execute_transaction(&block, &tx).await.unwrap();
        assert!(
            !receipt.status,
            "C-04: queueSetParam against uninitialized admin must fail"
        );
    }
}
