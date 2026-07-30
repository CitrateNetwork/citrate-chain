// citrate/core/execution/src/revm_adapter.rs

use crate::mvcc::{JournalHandle, WriteSet};
use crate::state::StateDB;
use crate::types::{Address, ExecutionError, Log as CitrateLog};
use citrate_consensus::types::Hash;
use parking_lot::Mutex;
use primitive_types::U256;
use revm::{
    handler::register::EvmHandler,
    precompile::{
        Precompile, PrecompileError as RevmPrecompileError,
        PrecompileErrors as RevmPrecompileErrors, PrecompileOutput as RevmPrecompileOutput,
        PrecompileResult as RevmPrecompileResult, StatefulPrecompile,
    },
    primitives::{
        AccountInfo, Address as RevmAddress, Bytecode, Bytes, Env, ExecutionResult,
        Log as RevmLog, Output, TransactTo, B256, U256 as RevmU256, SpecId, KECCAK_EMPTY,
    },
    ContextPrecompile, Database, DatabaseCommit, Evm,
};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

// PIL-48: Convert REVM's emitted log (alloy_primitives::Log) into citrate's
// receipt-log shape. Previously the executor discarded REVM logs entirely
// and synthesised a single hardcoded "ContractExecuted0000..." topic per
// call, so eth_getLogs for a real event signature (e.g. ProviderRegistered)
// returned nothing — silently breaking subgraphs, Foundry test assertions
// on events, and any off-chain indexer.
fn convert_revm_log(rlog: &RevmLog) -> CitrateLog {
    CitrateLog {
        address: Address(rlog.address.0 .0),
        topics: rlog.data.topics().iter().map(|t| Hash::new(t.0)).collect(),
        data: rlog.data.data.to_vec(),
    }
}

/// Shared handle for per-tx WriteSet capture (Sprint P950-A-4, WP-A.4.1).
///
/// The executor creates one of these per tx, threads it through the
/// REVM adapter, and reads it at commit time to know which accounts
/// need their MVCC versions bumped.
pub type WriteSetHandle = Arc<Mutex<WriteSet>>;

// Re-export JournalHandle from the mvcc module so callers importing
// from revm_adapter can find it without an extra `use` path.
pub use crate::mvcc::JournalHandle as RevmJournalHandle;

/// Adapter to make StateDB compatible with revm's Database trait
pub struct StateDBAdapter {
    state_db: Arc<StateDB>,
    /// PIL-13b: persistent state store, queried on `state_db` cache miss.
    ///
    /// `state_db` is an in-memory cache, not the source of truth. After
    /// a node restart it is empty. The Database trait impl below was
    /// returning empty data on cache miss (eth_call → `0x` despite the
    /// contract being deployed on disk), which silently broke every
    /// view function for chatbot / SDK developers querying state after
    /// the chain came back up.
    ///
    /// When set, every cache-miss in `basic` / `code_by_hash` / `storage`
    /// falls through to this store; the result is then written into
    /// `state_db` so subsequent reads in the same execution hit the
    /// cache. `None` preserves legacy in-memory-only behaviour for
    /// standalone tests that don't wire up a real store.
    state_store: Option<Arc<dyn crate::executor::StateStoreTrait>>,
    /// WP-X.4: Block number → block hash mapping for BLOCKHASH opcode.
    /// EVM spec: BLOCKHASH returns the hash for the 256 most recent blocks.
    block_hashes: HashMap<u64, [u8; 32]>,
    /// Optional per-tx write set capture (Sprint P950-A-4).
    ///
    /// When `Some`, every account touched by REVM's `DatabaseCommit::commit`
    /// is recorded here so the executor can bump per-account MVCC versions
    /// for all storage-writing transactions, not just transfers.
    ///
    /// When `None` (used by standalone tests and legacy paths), the
    /// adapter behaves exactly as before — no write-set capture.
    writes: Option<WriteSetHandle>,
    /// Optional per-tx journal for buffered storage writes (Sprint
    /// P950-A-5 WP-A.5.1). When `Some`, REVM's `DatabaseCommit::commit`
    /// writes storage slots into the journal's pending_storage map
    /// instead of directly into `state_db`. Storage reads check the
    /// journal first (read-your-writes within a tx) then fall back to
    /// `state_db`. The executor drains the journal into `state_db` on
    /// successful commit.
    ///
    /// When `None`, legacy behavior: REVM writes go directly to
    /// `state_db`. This preserves every existing test path.
    journal: Option<JournalHandle>,
    /// Which value-transfer rule this execution runs under. See
    /// [`ValueSemantics`]. Defaults to [`ValueSemantics::RevmAuthoritative`]
    /// — the correct rule — so that new code and tests get it without
    /// opting in; the executor explicitly selects the legacy rule below
    /// the activation height.
    value_semantics: ValueSemantics,
}

/// Which party owns native value movement during a REVM execution.
///
/// This is a **consensus rule**: the two variants produce different state
/// roots for the same transaction, so which one applies is decided by block
/// height, not by preference. See
/// [`VALUE_TRANSFER_ACTIVATION_HEIGHT`](crate::executor::VALUE_TRANSFER_ACTIVATION_HEIGHT).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueSemantics {
    /// Pre-activation. `DatabaseCommit::commit` DROPS every balance change
    /// REVM computed, and the executor re-applies only the top-level
    /// `from → to` leg by hand. Consequence: every transfer a contract
    /// performs itself is silently discarded while the callee's storage
    /// commits as though the money arrived.
    ///
    /// This is a bug. It is retained solely so blocks already on the chain
    /// replay to the roots they were produced with — re-judging history
    /// under the corrected rule forks just as surely as activating early.
    LegacyDropInternal,
    /// Post-activation. REVM owns value movement end to end: it is handed a
    /// zero gas price (so it does no gas accounting, which is the executor's
    /// job), and `commit` applies its balance changes wholesale — top-level
    /// leg, internal `call{value:}`, and selfdestruct alike.
    RevmAuthoritative,
}

impl StateDBAdapter {
    pub fn new(state_db: Arc<StateDB>) -> Self {
        Self {
            state_db,
            state_store: None,
            block_hashes: HashMap::new(),
            writes: None,
            journal: None,
            value_semantics: ValueSemantics::RevmAuthoritative,
        }
    }

    /// Select the value-transfer rule for this execution (consensus-gated by
    /// block height — see [`ValueSemantics`]).
    pub fn with_value_semantics(mut self, value_semantics: ValueSemantics) -> Self {
        self.value_semantics = value_semantics;
        self
    }

    /// PIL-13b: attach a persistent state store for cold-cache fallback.
    ///
    /// When set, the Database trait methods (`basic`, `code_by_hash`,
    /// `storage`) consult this store on cache miss instead of returning
    /// empty / default values. Hydrated entries are written back to
    /// `state_db` so further reads in the same execution are fast.
    pub fn with_state_store(
        mut self,
        state_store: Arc<dyn crate::executor::StateStoreTrait>,
    ) -> Self {
        self.state_store = Some(state_store);
        self
    }

    /// Set block hashes for BLOCKHASH opcode support (WP-X.4).
    /// Should contain the most recent 256 block number → hash mappings.
    pub fn with_block_hashes(mut self, hashes: HashMap<u64, [u8; 32]>) -> Self {
        self.block_hashes = hashes;
        self
    }

    /// Attach a per-tx WriteSet handle for account capture (WP-A.4.1).
    ///
    /// When set, `DatabaseCommit::commit` records every account it
    /// touches (storage writes + code deploys). The executor reads the
    /// handle after REVM returns and feeds it to
    /// [`crate::mvcc::CommitCoordinator::commit_writes_serialized`].
    pub fn with_writes(mut self, writes: WriteSetHandle) -> Self {
        self.writes = Some(writes);
        self
    }

    /// Attach a per-tx journal for buffered storage writes (Sprint
    /// P950-A-5 WP-A.5.1).
    ///
    /// When set, REVM storage writes buffer into the journal instead of
    /// hitting `state_db` directly. Reads check the journal first so
    /// read-your-writes works within a tx. The executor drains the
    /// journal into `state_db` on successful commit.
    pub fn with_journal(mut self, journal: JournalHandle) -> Self {
        self.journal = Some(journal);
        self
    }
}

impl Database for StateDBAdapter {
    type Error = ExecutionError;

    fn basic(&mut self, address: RevmAddress) -> Result<Option<AccountInfo>, Self::Error> {
        let addr = Address(address.0 .0);

        // Sprint P950-A-5 WP-A.5.2: journal-first read for balance and
        // nonce. If this tx previously wrote to the account (via the
        // executor's journal-routed path), return the pending value.
        // Otherwise fall through to committed state in state_db.
        //
        // Sprint P950-A-5 WP-A.5.3: also record the account in the
        // journal's read_set so concurrent commits that write to this
        // account invalidate our pin and force a retry.
        //
        // This is what enables REVM to see post-gas-deduction balance
        // during execution even when the executor routes gas deduction
        // through the journal (concurrent-safe path) rather than
        // mutating state_db eagerly.
        let (balance, nonce) = if let Some(journal) = &self.journal {
            let mut j = journal.lock();
            j.record_read(addr);
            let pending_balance = j.pending_balance(&addr);
            let pending_nonce = j.pending_nonce(&addr);
            (
                pending_balance.unwrap_or_else(|| self.state_db.accounts.get_balance(&addr)),
                pending_nonce.unwrap_or_else(|| self.state_db.accounts.get_nonce(&addr)),
            )
        } else {
            (
                self.state_db.accounts.get_balance(&addr),
                self.state_db.accounts.get_nonce(&addr),
            )
        };

        // PIL-13b: on cold cache, hydrate balance/nonce/code_hash from
        // the persistent state store. Pre-fix, a fresh-restart node had
        // empty state_db.accounts and every account looked uninitialised
        // — `eth_call` against deployed contracts returned `0x` because
        // REVM thought the account had no code, and `eth_getBalance` was
        // only working because it goes through `executor.get_balance`
        // which has its own storage-load wrapper. After this hydration,
        // REVM sees the real on-chain account and contract code.
        if !self.state_db.accounts.exists(&addr) {
            if let Some(store) = &self.state_store {
                if let Ok(Some(account)) = store.get_account(&addr) {
                    self.state_db.accounts.load_account(addr, account);
                }
            }
        }

        let code_hash = self.state_db.accounts.get_code_hash(&addr);

        // Convert to revm types
        let balance_revm = RevmU256::from_limbs(balance.0);

        // Check if code_hash is default (all zeros) - if so, use KECCAK_EMPTY
        // This is critical for EIP-3607 check - revm rejects transactions from accounts with code
        let code_hash_b256 = if code_hash.as_bytes().iter().all(|&b| b == 0) {
            KECCAK_EMPTY  // Proper empty code hash
        } else {
            B256::from_slice(code_hash.as_bytes())
        };

        Ok(Some(AccountInfo {
            balance: balance_revm,
            nonce,
            code_hash: code_hash_b256,
            code: None, // Lazy load code
        }))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        let hash = citrate_consensus::types::Hash::new(code_hash.0);

        // RM-B1 / WP-B5.4 (audit H-03): mark the tx as requiring
        // serial commit. The MVCC read_set keys on `Address`, but
        // this method only has the code-hash and not the address
        // that owns it — so we cannot record a per-account read
        // here. Pre-fix this meant a concurrent SELFDESTRUCT+CREATE2
        // could replace the code under us between our pin and our
        // commit, and the commit would land with stale-code-derived
        // state. Falling back to serial commit when ANY tx accesses
        // code-by-hash is conservative (over-aborts under contention)
        // but structurally safe.
        if let Some(journal) = &self.journal {
            let mut j = journal.lock();
            j.mark_requires_serial_commit();
        }

        // PIL-13b: try in-memory cache first, fall through to persistent
        // store on miss, warm cache with the result.
        let code = if let Some(c) = self.state_db.get_code(&hash) {
            c
        } else if let Some(store) = &self.state_store {
            match store.get_code(&hash) {
                Ok(Some(bytes)) => {
                    // Insert into state_db.code_storage so subsequent
                    // reads in this execution hit the cache.
                    self.state_db.cache_code(hash, bytes.clone());
                    bytes
                }
                _ => Vec::new(),
            }
        } else {
            Vec::new()
        };

        Ok(Bytecode::new_raw(Bytes::from(code)))
    }

    fn storage(&mut self, address: RevmAddress, index: RevmU256) -> Result<RevmU256, Self::Error> {
        let addr = Address(address.0 .0);
        let key_bytes: [u8; 32] = index.to_be_bytes();

        // Sprint P950-A-5 WP-A.5.1: journal-first read for read-your-writes
        // semantics within a tx. If this tx previously SSTOREd the slot,
        // the pending value is in the journal; return it. Only fall through
        // to state_db if the slot hasn't been written yet in this tx.
        //
        // Sprint P950-A-5 WP-A.5.3: record the account in the journal's
        // read_set so concurrent commits to this account's storage
        // invalidate the pin and force retry.
        if let Some(journal) = &self.journal {
            let mut j = journal.lock();
            j.record_read(addr);
            if let Some(pending) = j.pending_storage(&addr, &key_bytes).map(|v| v.to_vec()) {
                let mut padded = [0u8; 32];
                let len = pending.len().min(32);
                padded[32 - len..].copy_from_slice(&pending[pending.len() - len..]);
                return Ok(RevmU256::from_be_bytes(padded));
            }
        }

        // Get storage value as bytes from committed state.
        // PIL-13b: in-memory cache miss falls through to the persistent
        // store. The store returns Ok(None) for slots that have never
        // been written; treat those as zero (canonical EVM semantics).
        // On a hit, warm the in-memory cache so subsequent reads in this
        // execution are fast.
        let value_bytes = if let Some(v) = self.state_db.get_storage(&addr, &key_bytes) {
            v
        } else if let Some(store) = &self.state_store {
            match store.get_storage(&addr, &key_bytes) {
                Ok(Some(bytes)) => {
                    self.state_db
                        .cache_storage(addr, key_bytes.to_vec(), bytes.clone());
                    bytes
                }
                _ => vec![0u8; 32],
            }
        } else {
            vec![0u8; 32]
        };

        // Pad to 32 bytes if needed
        let mut padded = [0u8; 32];
        let len = value_bytes.len().min(32);
        padded[32 - len..].copy_from_slice(&value_bytes[value_bytes.len() - len..]);

        Ok(RevmU256::from_be_bytes(padded))
    }

    fn block_hash(&mut self, number: RevmU256) -> Result<B256, Self::Error> {
        // WP-X.4: Return real block hash from the recent-blocks map.
        // EVM spec: BLOCKHASH only works for the 256 most recent blocks.
        let height = number.as_limbs()[0]; // Safe: block numbers fit in u64
        match self.block_hashes.get(&height) {
            Some(hash) => Ok(B256::from_slice(hash)),
            None => Ok(B256::ZERO), // Unknown/old block → zero (EVM spec compliant)
        }
    }
}

impl DatabaseCommit for StateDBAdapter {
    fn commit(&mut self, changes: revm::primitives::HashMap<RevmAddress, revm::primitives::Account>) {
        for (address, account) in changes {
            let addr = Address(address.0 .0);

            // Sprint P950-A-4 WP-A.4.1: capture touched accounts into the
            // per-tx WriteSet handle. Every account in this changes map
            // had at least one storage slot or code write; the executor
            // uses this set to bump per-account MVCC versions at commit.
            if let Some(ws) = &self.writes {
                ws.lock().record_write(addr);
            }

            // ---- Nonce: still the executor's ----
            // `executor.check_and_increment_nonce()` owns nonces; REVM also
            // bumps the caller's nonce internally, so committing REVM's would
            // double-increment. Nonce writes stay dropped here.
            //
            // ---- Balance: REVM's, as of the internal-value-transfer fix ----
            // Sprint EL-1 Fix (Issue #19) originally dropped balances too,
            // because REVM charged gas and the executor charged it again.
            // The cure was worse than the disease: the executor only ever
            // re-applied the TOP-LEVEL `from → to` transfer, so every value
            // transfer a contract performed itself — `call{value:}`, a
            // payable forward, a payout — was silently discarded while the
            // callee's storage committed as though the money had arrived.
            // On live 40204 that left `LiquidStakingPool` reporting
            // `totalPooled = 32,000 SALT` against an actual balance of 0.
            //
            // The double-deduction it was avoiding is now prevented at the
            // source instead: REVM is handed a ZERO gas price (see
            // `execute_contract_call_with_context`), so it performs no gas
            // accounting at all and its balance deltas are exactly the value
            // movement. Committing them is therefore correct and complete —
            // top-level and internal transfers alike, plus selfdestruct.
            //
            // `info.balance` is absolute, not a delta, and REVM read the
            // pre-state through `basic()` below (journal-first), so writing
            // it back is consistent with in-flight pending writes.
            //
            // Gated on block height: below the activation the buggy rule is
            // reproduced exactly, so historical blocks replay to the roots
            // they were produced with.
            if self.value_semantics == ValueSemantics::RevmAuthoritative {
                let new_balance = U256(account.info.balance.into_limbs());
                if let Some(journal) = &self.journal {
                    journal.lock().record_balance(addr, new_balance);
                } else {
                    self.state_db.accounts.set_balance(addr, new_balance);
                }
            }

            // Update storage — present_value is the post-transaction value.
            //
            // Sprint P950-A-5 WP-A.5.1: when a journal is attached, storage
            // writes buffer there instead of hitting state_db directly. The
            // executor drains the journal into state_db on successful
            // commit. This keeps concurrent workers isolated: each worker's
            // pending writes don't leak to others until CAS succeeds.
            //
            // When the journal is absent (standalone tests + legacy paths),
            // writes go directly to state_db as before.
            for (key, value) in &account.storage {
                let key_bytes = key.to_be_bytes::<32>();
                let value_bytes = value.present_value.to_be_bytes::<32>();
                debug!(
                    "REVM commit storage: addr={} slot=0x{} value=0x{} (original=0x{})",
                    addr,
                    hex::encode(&key_bytes[28..]),
                    hex::encode(&value_bytes[28..]),
                    hex::encode(&value.original_value.to_be_bytes::<32>()[28..]),
                );
                if let Some(journal) = &self.journal {
                    journal.lock().record_storage_write(
                        addr,
                        key_bytes.to_vec(),
                        value_bytes.to_vec(),
                    );
                } else {
                    self.state_db.set_storage(addr, key_bytes.to_vec(), value_bytes.to_vec());
                }
            }

            // Update code if the account is a real contract.
            // REVM v10 includes a 1-byte sentinel (0x00 STOP) as `info.code` for
            // touched EOAs. Writing this to StateDB would set a non-KECCAK_EMPTY
            // code_hash, causing EIP-3607 to reject future transactions from that
            // address. Guard: only write code when the account's code_hash indicates
            // it is actually a contract (not KECCAK_EMPTY and not zero).
            let has_code = account.info.code.is_some();
            let acct_code_hash = account.info.code_hash;
            let is_contract = acct_code_hash != KECCAK_EMPTY && acct_code_hash != B256::ZERO;
            if is_contract {
                if let Some(code) = account.info.code {
                    let code_bytes = code.bytes().to_vec();
                    if !code_bytes.is_empty() {
                        // Sprint P950-A-5 WP-A.5.3: route code writes through
                        // the journal so mid-tx contract deployment (CREATE
                        // opcode) is isolated from concurrent workers.
                        if let Some(journal) = &self.journal {
                            journal.lock().record_code(addr, code_bytes);
                        } else {
                            self.state_db.set_code(addr, code_bytes);
                        }
                    }
                }
            }

            debug!(
                "REVM commit: addr={} storage_slots={} code_changed={}",
                addr, account.storage.len(), has_code
            );
        }
    }
}

/// Block context for EVM execution (WP-X.4)
#[derive(Debug, Clone, Default)]
pub struct BlockContext {
    /// Block proposer address (COINBASE opcode)
    pub coinbase: [u8; 20],
    /// VRF-derived randomness (PREVRANDAO opcode)
    pub prevrandao: [u8; 32],
    /// Recent block hashes for BLOCKHASH opcode (up to 256)
    pub block_hashes: HashMap<u64, [u8; 32]>,
}

// ---------------------------------------------------------------------------
// WP-B0 (TD-28): REVM ↔ Citrate custom-precompile bridge.
//
// Until this bridge existed, `Evm::builder()` shipped only the standard
// Ethereum precompiles (0x01–0x0a): a deployed contract's STATICCALL to the
// Citrate verify family (e.g. `IPFSIncentivesV2._verify()` → 0x0108, or
// `ComputeVerifier`'s ZK tier) hit an EMPTY ACCOUNT, returned `success=1`
// with empty returndata, and the caller read that as "invalid proof" —
// silently and forever. The Rust-side dispatch (`precompiles::execute`)
// was only reachable from direct Rust callers (tests, the API layer), never
// from EVM bytecode.
//
// The bridge registers the PURE precompile families
// (`precompiles::PURE_PRECOMPILE_ADDRESSES`: verify 0x0107–0x0109, Q16
// compute 0x010A–0x010F, learning 0x0110–0x0111, x402 0x0200–0x0202) as
// REVM custom precompiles in BOTH execution entry points (call + create).
// They are stateless, deterministic pure functions, safe in consensus on
// every node build. The inference family (0x0100–0x0106) requires the
// hosted model runtime and is deliberately NOT bridged.
//
// Error mapping: a precompile `Err` becomes
// `PrecompileErrors::Error(Other)`, which REVM turns into
// `InstructionResult::PrecompileError` — the calling frame fails
// (STATICCALL pushes 0), exactly the "revert/0 ⇒ reject" semantics
// `IPFSIncentivesV2._verify()` documents. Note 0x0108 itself is only LIVE
// when the node is built with `halo2-substrate`; without it the verifier
// returns its discoverable `SubstrateAbsent` error → the STATICCALL fails
// closed. ALL VALIDATOR BINARIES MUST AGREE ON THE FEATURE SET or they
// diverge on any tx that exercises 0x0108.
// ---------------------------------------------------------------------------

/// REVM adapter for one pure Citrate precompile address. Stateless — the
/// `StatefulPrecompile` trait is used only to capture the address (REVM's
/// `Precompile::Standard` is a bare fn pointer and cannot).
struct CitratePurePrecompile {
    addr: Address,
}

impl StatefulPrecompile for CitratePurePrecompile {
    fn call(&self, bytes: &Bytes, gas_limit: u64, _env: &Env) -> RevmPrecompileResult {
        match crate::precompiles::execute_pure(&self.addr, bytes.as_ref(), gas_limit) {
            Ok(res) => {
                if !res.success {
                    // The pure families signal failure via Err; a
                    // success=false Ok is a contract violation — fail the
                    // frame rather than return ambiguous bytes.
                    return Err(RevmPrecompileErrors::Error(RevmPrecompileError::other(
                        "Citrate precompile reported failure",
                    )));
                }
                Ok(RevmPrecompileOutput::new(res.gas_used, res.output.into()))
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("Insufficient gas") || msg.contains("Out of gas") {
                    Err(RevmPrecompileErrors::Error(RevmPrecompileError::OutOfGas))
                } else {
                    Err(RevmPrecompileErrors::Error(RevmPrecompileError::other(msg)))
                }
            }
        }
    }
}

/// Handler register that extends REVM's spec precompiles with the pure
/// Citrate families. Applied via `.append_handler_register(...)` on every
/// `Evm::builder()` in this adapter — call AND create paths — so serial
/// execution, `eth_call`, and deployment-time constructor code all see the
/// same precompile set.
fn register_citrate_precompiles<EXT, DB: Database>(handler: &mut EvmHandler<'_, EXT, DB>) {
    let prev = handler.pre_execution.load_precompiles.clone();
    handler.pre_execution.load_precompiles = Arc::new(move || {
        let mut precompiles = prev();
        precompiles.extend(crate::precompiles::PURE_PRECOMPILE_ADDRESSES.iter().map(|raw| {
            (
                RevmAddress::from_slice(raw),
                ContextPrecompile::Ordinary(Precompile::Stateful(Arc::new(
                    CitratePurePrecompile { addr: Address(*raw) },
                ))),
            )
        }));
        precompiles
    });
}

/// Execute contract creation using revm
#[allow(clippy::too_many_arguments)]
pub fn execute_contract_create(
    state_db: Arc<StateDB>,
    deployer: Address,
    init_code: Vec<u8>,
    value: U256,
    gas_limit: u64,
    gas_price: U256,
    chain_id: u64,
    block_number: u64,
    block_timestamp: u64,
) -> Result<(Address, Vec<u8>, u64), ExecutionError> {
    // PIL-48 backward-compat wrapper: drop the logs Vec for the legacy
    // 3-tuple signature used by tests + bench paths.
    execute_contract_create_with_context(
        state_db, deployer, init_code, value, gas_limit, gas_price,
        chain_id, block_number, block_timestamp, BlockContext::default(), None, None,
        // Correct semantics by default: this wrapper serves tests and bench
        // paths, which should exercise the rule the chain runs under after
        // activation, not the bug it is leaving behind.
        ValueSemantics::RevmAuthoritative,
    )
    .map(|(addr, code, gas, _logs)| (addr, code, gas))
}

/// Execute contract creation using revm with full block context (WP-X.4),
/// optional WriteSet capture (Sprint P950-A-4, WP-A.4.1), and optional
/// journal for buffered storage writes (Sprint P950-A-5, WP-A.5.1).
#[allow(clippy::too_many_arguments)]
pub fn execute_contract_create_with_context(
    state_db: Arc<StateDB>,
    deployer: Address,
    init_code: Vec<u8>,
    value: U256,
    gas_limit: u64,
    gas_price: U256,
    chain_id: u64,
    block_number: u64,
    block_timestamp: u64,
    block_ctx: BlockContext,
    writes_handle: Option<WriteSetHandle>,
    journal_handle: Option<JournalHandle>,
    value_semantics: ValueSemantics,
) -> Result<(Address, Vec<u8>, u64, Vec<CitrateLog>), ExecutionError> {
    debug!("Executing contract creation with revm");
    debug!("  Deployer: {}", deployer);
    debug!("  Init code size: {} bytes", init_code.len());
    debug!("  Gas limit: {}", gas_limit);

    // Create database adapter with block hashes + optional write/journal capture
    let mut db = StateDBAdapter::new(state_db.clone())
        .with_block_hashes(block_ctx.block_hashes)
        .with_value_semantics(value_semantics);
    if let Some(h) = writes_handle {
        db = db.with_writes(h);
    }
    if let Some(j) = journal_handle {
        db = db.with_journal(j);
    }

    // Build EVM with transaction
    let coinbase = block_ctx.coinbase;
    let prevrandao = block_ctx.prevrandao;
    let mut evm = Evm::builder()
        .with_db(&mut db)
        // WP-B0 (TD-28): expose the pure Citrate precompile families
        // (verify/compute/learning/x402) to contract code. Without this,
        // STATICCALLs to e.g. 0x0108 hit an empty account and silently
        // return success with no data.
        .append_handler_register(register_citrate_precompiles)
        .modify_cfg_env(|cfg| {
            cfg.chain_id = chain_id;
        })
        // DPF-VM-1 — CANCUN enables MCOPY (EIP-5656) which Solidity
        // 0.8.25+ emits for dynamic-bytes ABI return encoding. Pre-
        // CANCUN halted with InvalidOpcode, which the executor's
        // status-bit pattern silently swallowed as Ok(receipt{status:
        // false, output:vec![]}); eth_call then hex-encoded empty
        // bytes → "0x" with no JSON-RPC error to surface the bug.
        // See `.agentile/sprints/active/2026-05-12-dpf-vm-1-dynamic-returns/SPRINT.md`.
        .with_spec_id(SpecId::CANCUN)
        .modify_tx_env(|tx| {
            tx.caller = RevmAddress::from_slice(&deployer.0);
            tx.transact_to = TransactTo::Create;
            tx.data = Bytes::from(init_code);
            tx.value = RevmU256::from_limbs(value.0);
            tx.gas_limit = gas_limit;
            // ZERO, deliberately — see `DatabaseCommit::commit`.
            //
            // The executor is the sole owner of gas accounting: it deducts
            // gas upfront and refunds on success. If REVM also charged gas,
            // committing its balance changes would double-deduct — which is
            // precisely why Sprint EL-1 dropped balances wholesale, and why
            // contract-initiated value transfers went missing for so long.
            //
            // Zeroing the gas price here is how we say "REVM does no gas
            // accounting on this chain". Its resulting balance deltas are
            // then exactly the value movement, which `commit` can apply
            // wholesale. REVM's affordability precheck degrades to
            // `balance >= value`, the correct residual test given the
            // executor already took gas out. `block.basefee` is 0 (never
            // set), so a zero gas price still validates.
            //
            // Known, contained deviation: the GASPRICE opcode returns 0
            // inside REVM-executed code. No contract deployed on 40204 reads
            // `tx.gasprice` — verified by grep over `contracts/src`.
            //
            // Below the activation height the real gas price is passed
            // through unchanged. That matters even though pre-activation
            // balances are discarded: REVM's affordability precheck is
            // `balance >= gas_limit * gas_price + value`, so zeroing the
            // price early would let transactions succeed that historically
            // failed, changing replayed history.
            tx.gas_price = match value_semantics {
                ValueSemantics::RevmAuthoritative => RevmU256::ZERO,
                ValueSemantics::LegacyDropInternal => RevmU256::from_limbs(gas_price.0),
            };
            tx.chain_id = Some(chain_id);
        })
        .modify_block_env(|block| {
            block.number = RevmU256::from(block_number);
            block.timestamp = RevmU256::from(block_timestamp);
            // WP-X.4: Real coinbase and prevrandao
            block.coinbase = RevmAddress::from_slice(&coinbase);
            block.prevrandao = Some(B256::from_slice(&prevrandao));
        })
        .build();

    // Execute transaction
    let result = evm.transact_commit().map_err(|e| {
        ExecutionError::Reverted(format!("revm execution failed: {:?}", e))
    })?;

    match result {
        ExecutionResult::Success {
            output,
            gas_used,
            logs,
            ..
        } => {
            // PIL-48: forward REVM-emitted logs (correctly-hashed event topics)
            // up to the executor so they land in the receipt and become visible
            // via eth_getLogs. Constructor events (e.g. OpenZeppelin's
            // Initialized()) are emitted here.
            let citrate_logs: Vec<CitrateLog> = logs.iter().map(convert_revm_log).collect();
            match output {
                Output::Create(runtime_code, Some(contract_address)) => {
                    let addr = Address(contract_address.0 .0);
                    let code = runtime_code.to_vec();

                    info!(
                        "Contract deployed successfully at {} with {} bytes of runtime code",
                        addr,
                        code.len()
                    );

                    Ok((addr, code, gas_used, citrate_logs))
                }
                Output::Create(_, None) => {
                    Err(ExecutionError::Reverted(
                        "Contract creation failed: no address returned".to_string(),
                    ))
                }
                _ => Err(ExecutionError::Reverted(
                    "Unexpected output type for contract creation".to_string(),
                )),
            }
        }
        ExecutionResult::Revert { gas_used, output } => {
            let reason = if !output.is_empty() {
                format!("0x{}", hex::encode(&output))
            } else {
                "Unknown reason".to_string()
            };
            Err(ExecutionError::Reverted(format!(
                "Contract creation reverted: {} (gas used: {})",
                reason, gas_used
            )))
        }
        ExecutionResult::Halt { reason, gas_used } => Err(ExecutionError::Reverted(format!(
            "Contract creation halted: {:?} (gas used: {})",
            reason, gas_used
        ))),
    }
}

/// Execute contract call using revm
#[allow(clippy::too_many_arguments)]
pub fn execute_contract_call(
    state_db: Arc<StateDB>,
    caller: Address,
    contract: Address,
    calldata: Vec<u8>,
    value: U256,
    gas_limit: u64,
    gas_price: U256,
    chain_id: u64,
    block_number: u64,
    block_timestamp: u64,
) -> Result<(Vec<u8>, u64), ExecutionError> {
    // PIL-48 backward-compat wrapper: drop the logs Vec for the legacy
    // 2-tuple signature used by tests + bench paths.
    execute_contract_call_with_context(
        state_db, caller, contract, calldata, value, gas_limit, gas_price,
        chain_id, block_number, block_timestamp, BlockContext::default(), None, None,
        // PIL-13b: legacy convenience wrapper used by benches + tests
        // that don't wire a state store. Cold-cache loads are skipped;
        // the call falls back to the in-memory state_db only.
        None,
        // Correct semantics by default: this wrapper serves tests and bench
        // paths, which should exercise the rule the chain runs under after
        // activation, not the bug it is leaving behind.
        ValueSemantics::RevmAuthoritative,
    )
    .map(|(output, gas, _logs)| (output, gas))
}

/// Execute contract call using revm with full block context (WP-X.4),
/// optional WriteSet capture (Sprint P950-A-4, WP-A.4.1), and optional
/// journal for buffered storage writes (Sprint P950-A-5, WP-A.5.1).
#[allow(clippy::too_many_arguments)]
pub fn execute_contract_call_with_context(
    state_db: Arc<StateDB>,
    caller: Address,
    contract: Address,
    calldata: Vec<u8>,
    value: U256,
    gas_limit: u64,
    gas_price: U256,
    chain_id: u64,
    block_number: u64,
    block_timestamp: u64,
    block_ctx: BlockContext,
    writes_handle: Option<WriteSetHandle>,
    journal_handle: Option<JournalHandle>,
    // PIL-13b: optional persistent state store for cold-cache fallback.
    // None preserves legacy behaviour for tests + bench paths that don't
    // wire a real store; Some hydrates account / code / storage misses
    // from RocksDB so eth_call against deployed contracts works on a
    // freshly-restarted node.
    state_store: Option<Arc<dyn crate::executor::StateStoreTrait>>,
    value_semantics: ValueSemantics,
) -> Result<(Vec<u8>, u64, Vec<CitrateLog>), ExecutionError> {
    debug!("Executing contract call with revm");
    debug!("  Caller: {}", caller);
    debug!("  Contract: {}", contract);
    debug!("  Calldata size: {} bytes", calldata.len());

    // Create database adapter with block hashes + optional write/journal capture
    let mut db = StateDBAdapter::new(state_db)
        .with_block_hashes(block_ctx.block_hashes)
        .with_value_semantics(value_semantics);
    if let Some(h) = writes_handle {
        db = db.with_writes(h);
    }
    if let Some(j) = journal_handle {
        db = db.with_journal(j);
    }
    if let Some(s) = state_store {
        db = db.with_state_store(s);
    }

    // Build EVM with transaction
    let coinbase = block_ctx.coinbase;
    let prevrandao = block_ctx.prevrandao;
    let mut evm = Evm::builder()
        .with_db(&mut db)
        // WP-B0 (TD-28): expose the pure Citrate precompile families
        // (verify/compute/learning/x402) to contract code. Without this,
        // STATICCALLs to e.g. 0x0108 hit an empty account and silently
        // return success with no data.
        .append_handler_register(register_citrate_precompiles)
        .modify_cfg_env(|cfg| {
            cfg.chain_id = chain_id;
        })
        // DPF-VM-1 — CANCUN enables MCOPY (EIP-5656) which Solidity
        // 0.8.25+ emits for dynamic-bytes ABI return encoding. Pre-
        // CANCUN halted with InvalidOpcode, which the executor's
        // status-bit pattern silently swallowed as Ok(receipt{status:
        // false, output:vec![]}); eth_call then hex-encoded empty
        // bytes → "0x" with no JSON-RPC error to surface the bug.
        // See `.agentile/sprints/active/2026-05-12-dpf-vm-1-dynamic-returns/SPRINT.md`.
        .with_spec_id(SpecId::CANCUN)
        .modify_tx_env(|tx| {
            tx.caller = RevmAddress::from_slice(&caller.0);
            tx.transact_to = TransactTo::Call(RevmAddress::from_slice(&contract.0));
            tx.data = Bytes::from(calldata);
            tx.value = RevmU256::from_limbs(value.0);
            tx.gas_limit = gas_limit;
            // ZERO, deliberately — see `DatabaseCommit::commit`.
            //
            // The executor is the sole owner of gas accounting: it deducts
            // gas upfront and refunds on success. If REVM also charged gas,
            // committing its balance changes would double-deduct — which is
            // precisely why Sprint EL-1 dropped balances wholesale, and why
            // contract-initiated value transfers went missing for so long.
            //
            // Zeroing the gas price here is how we say "REVM does no gas
            // accounting on this chain". Its resulting balance deltas are
            // then exactly the value movement, which `commit` can apply
            // wholesale. REVM's affordability precheck degrades to
            // `balance >= value`, the correct residual test given the
            // executor already took gas out. `block.basefee` is 0 (never
            // set), so a zero gas price still validates.
            //
            // Known, contained deviation: the GASPRICE opcode returns 0
            // inside REVM-executed code. No contract deployed on 40204 reads
            // `tx.gasprice` — verified by grep over `contracts/src`.
            //
            // Below the activation height the real gas price is passed
            // through unchanged. That matters even though pre-activation
            // balances are discarded: REVM's affordability precheck is
            // `balance >= gas_limit * gas_price + value`, so zeroing the
            // price early would let transactions succeed that historically
            // failed, changing replayed history.
            tx.gas_price = match value_semantics {
                ValueSemantics::RevmAuthoritative => RevmU256::ZERO,
                ValueSemantics::LegacyDropInternal => RevmU256::from_limbs(gas_price.0),
            };
            tx.chain_id = Some(chain_id);
        })
        .modify_block_env(|block| {
            block.number = RevmU256::from(block_number);
            block.timestamp = RevmU256::from(block_timestamp);
            // WP-X.4: Real coinbase and prevrandao
            block.coinbase = RevmAddress::from_slice(&coinbase);
            block.prevrandao = Some(B256::from_slice(&prevrandao));
        })
        .build();

    // Execute transaction
    let result = evm.transact_commit().map_err(|e| {
        ExecutionError::Reverted(format!("revm execution failed: {:?}", e))
    })?;

    match result {
        ExecutionResult::Success {
            output, gas_used, logs, ..
        } => {
            // PIL-48: forward REVM-emitted logs (correctly-hashed event topics)
            // up to the executor so they land in the receipt and become visible
            // via eth_getLogs. Without this, real Solidity events emitted by
            // the contract were silently discarded and replaced with a single
            // synthetic "ContractExecuted00..." topic.
            let citrate_logs: Vec<CitrateLog> = logs.iter().map(convert_revm_log).collect();
            match output {
                Output::Call(return_data) => Ok((return_data.to_vec(), gas_used, citrate_logs)),
                _ => Err(ExecutionError::Reverted(
                    "Unexpected output type for contract call".to_string(),
                )),
            }
        }
        ExecutionResult::Revert { gas_used, output } => {
            let reason = if !output.is_empty() {
                format!("0x{}", hex::encode(&output))
            } else {
                "Unknown reason".to_string()
            };
            Err(ExecutionError::Reverted(format!(
                "Contract call reverted: {} (gas used: {})",
                reason, gas_used
            )))
        }
        ExecutionResult::Halt { reason, gas_used } => Err(ExecutionError::Reverted(format!(
            "Contract call halted: {:?} (gas used: {})",
            reason, gas_used
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_hash_returns_real_hash() {
        let state_db = Arc::new(StateDB::new());
        let mut hashes = HashMap::new();
        let expected_hash = [0xAB; 32];
        hashes.insert(5u64, expected_hash);
        hashes.insert(10u64, [0xCD; 32]);

        let mut adapter = StateDBAdapter::new(state_db).with_block_hashes(hashes);

        let result = adapter.block_hash(RevmU256::from(5)).unwrap();
        assert_eq!(result, B256::from_slice(&expected_hash));

        let result10 = adapter.block_hash(RevmU256::from(10)).unwrap();
        assert_eq!(result10, B256::from_slice(&[0xCD; 32]));
    }

    #[test]
    fn test_block_hash_out_of_range_returns_zero() {
        let state_db = Arc::new(StateDB::new());
        let hashes = HashMap::new();
        let mut adapter = StateDBAdapter::new(state_db).with_block_hashes(hashes);

        let result = adapter.block_hash(RevmU256::from(999)).unwrap();
        assert_eq!(result, B256::ZERO);
    }

    #[test]
    fn test_block_hash_without_hashes_returns_zero() {
        let state_db = Arc::new(StateDB::new());
        let mut adapter = StateDBAdapter::new(state_db);

        let result = adapter.block_hash(RevmU256::from(0)).unwrap();
        assert_eq!(result, B256::ZERO);
    }

    #[test]
    fn test_block_context_coinbase_and_prevrandao() {
        // Deploy a minimal contract and verify block context is threaded through.
        let state_db = Arc::new(StateDB::new());
        let deployer = Address([1u8; 20]);
        state_db.accounts.set_balance(deployer, U256::from(10u64).pow(U256::from(18u64)));
        state_db.accounts.set_nonce(deployer, 0);

        let ctx = BlockContext {
            coinbase: [0x42; 20],
            prevrandao: [0xBE; 32],
            block_hashes: HashMap::new(),
        };

        // Minimal init code: PUSH1 0x00 PUSH1 0x00 RETURN (deploys empty contract)
        let init_code = vec![0x60, 0x00, 0x60, 0x00, 0xf3];

        let result = execute_contract_create_with_context(
            state_db,
            deployer,
            init_code,
            U256::zero(),
            1_000_000,
            U256::from(1_000_000_000u64),
            40204,
            100,
            1_000_000,
            ctx,
            None, // No WriteSet capture in this test
            None, // No journal buffering in this test
            ValueSemantics::RevmAuthoritative,
        );

        // Should succeed (not panic) with custom coinbase/prevrandao
        assert!(result.is_ok(), "Contract creation with custom block context should succeed: {:?}", result.err());
    }

    #[test]
    fn test_execute_contract_call_with_context() {
        let state_db = Arc::new(StateDB::new());
        let caller = Address([1u8; 20]);
        let contract = Address([2u8; 20]);
        state_db.accounts.set_balance(caller, U256::from(10u64).pow(U256::from(18u64)));

        // Deploy simple contract bytecode (PUSH1 0x42, PUSH1 0x00, MSTORE, PUSH1 0x20, PUSH1 0x00, RETURN)
        let runtime_code = vec![0x60, 0x42, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
        state_db.set_code(contract, runtime_code);

        let mut block_hashes = HashMap::new();
        block_hashes.insert(99u64, [0xFF; 32]);

        let ctx = BlockContext {
            coinbase: [0x42; 20],
            prevrandao: [0xBE; 32],
            block_hashes,
        };

        let result = execute_contract_call_with_context(
            state_db,
            caller,
            contract,
            vec![],
            U256::zero(),
            1_000_000,
            U256::from(1_000_000_000u64),
            40204,
            100,
            1_000_000,
            ctx,
            None, // No WriteSet capture in this test
            None, // No journal buffering in this test
            None, // PIL-13b: no state store — test uses in-memory state_db only
            ValueSemantics::RevmAuthoritative,
        );

        assert!(result.is_ok(), "Contract call with block context should succeed: {:?}", result.err());
    }

    /// PIN-P1(d): prove the EVM `block.prevrandao` opcode (0x44) returns the
    /// exact 32 bytes carried in `BlockContext.prevrandao` — i.e. the consensus
    /// ECVRF `vrf_reveal.output` once wired at the block-execution entrypoint.
    /// The pre-existing `test_execute_contract_call_with_context` only asserts
    /// "does not panic"; it never reads the value PREVRANDAO actually yields.
    /// This test executes a contract that returns `block.prevrandao` and asserts
    /// the returned 32 bytes equal the supplied VRF output.
    #[test]
    fn test_prevrandao_opcode_returns_vrf_output() {
        let state_db = Arc::new(StateDB::new());
        let caller = Address([1u8; 20]);
        let contract = Address([2u8; 20]);
        state_db
            .accounts
            .set_balance(caller, U256::from(10u64).pow(U256::from(18u64)));

        // Runtime bytecode:
        //   0x44             PREVRANDAO   (pushes block.prevrandao onto stack)
        //   0x60 0x00        PUSH1 0x00
        //   0x52             MSTORE       (store prevrandao at memory[0..32])
        //   0x60 0x20        PUSH1 0x20   (length = 32)
        //   0x60 0x00        PUSH1 0x00   (offset = 0)
        //   0xf3             RETURN       (return memory[0..32])
        let runtime_code = vec![0x44, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
        state_db.set_code(contract, runtime_code);

        // A known, non-zero VRF output (stands in for header.vrf_reveal.output).
        let vrf_output: [u8; 32] = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
            0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78,
            0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0,
        ];

        let ctx = BlockContext {
            coinbase: [0x42; 20],
            prevrandao: vrf_output,
            block_hashes: HashMap::new(),
        };

        let (output, _gas, _logs) = execute_contract_call_with_context(
            state_db,
            caller,
            contract,
            vec![],
            U256::zero(),
            1_000_000,
            U256::from(1_000_000_000u64),
            40204,
            100,
            1_000_000,
            ctx,
            None,
            None,
            None,
            ValueSemantics::RevmAuthoritative,
        )
        .expect("call returning block.prevrandao should succeed");

        assert_eq!(
            output.as_slice(),
            &vrf_output[..],
            "block.prevrandao must equal the BlockContext (VRF) output bytes"
        );
        // Sanity: a real VRF output is non-zero, distinguishing it from the
        // pre-wiring default (all zeros).
        assert_ne!(output.as_slice(), &[0u8; 32][..], "prevrandao should be non-zero");
    }

    /// PIN-P1(d): a default/zero `BlockContext` (e.g. a header whose
    /// `vrf_reveal.output` is all zeros, or any path that has not set a
    /// context) must still execute without panicking and yield zero — proving
    /// the wiring is additive and degrades safely.
    #[test]
    fn test_prevrandao_opcode_zero_default_is_safe() {
        let state_db = Arc::new(StateDB::new());
        let caller = Address([1u8; 20]);
        let contract = Address([2u8; 20]);
        state_db
            .accounts
            .set_balance(caller, U256::from(10u64).pow(U256::from(18u64)));

        let runtime_code = vec![0x44, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
        state_db.set_code(contract, runtime_code);

        let (output, _gas, _logs) = execute_contract_call_with_context(
            state_db,
            caller,
            contract,
            vec![],
            U256::zero(),
            1_000_000,
            U256::from(1_000_000_000u64),
            40204,
            100,
            1_000_000,
            BlockContext::default(),
            None,
            None,
            None,
            ValueSemantics::RevmAuthoritative,
        )
        .expect("call with default block context should not panic");

        assert_eq!(
            output.as_slice(),
            &[0u8; 32][..],
            "default BlockContext must yield zero prevrandao (no panic, no garbage)"
        );
    }

    /// PIL-48 regression: REVM-emitted log topics must round-trip up to the
    /// executor instead of being silently discarded. Pre-fix, every contract
    /// execution returned a single hand-rolled `"ContractExecuted0000..."`
    /// ASCII topic, so `eth_getLogs` against a real keccak256 event signature
    /// (ProviderRegistered, Transfer, etc.) was guaranteed to miss everything
    /// — invisible to Foundry, The Graph, and any off-chain listener.
    #[test]
    fn test_pil48_revm_log_topics_round_trip() {
        let state_db = Arc::new(StateDB::new());
        let caller = Address([1u8; 20]);
        let contract = Address([2u8; 20]);
        state_db
            .accounts
            .set_balance(caller, U256::from(10u64).pow(U256::from(18u64)));

        // Deterministic 32-byte topic. Picked to be obviously NOT the keccak256
        // of any string, AND obviously NOT ASCII — if the pre-fix synthetic
        // path returns, neither this test's assertion nor a naive ASCII check
        // could pass.
        let expected_topic: [u8; 32] = [
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        ];

        // Bytecode: PUSH32 <topic> + PUSH1 0 (length) + PUSH1 0 (offset) +
        // LOG1 + STOP. LOG1 pops offset, length, topic in that order off the
        // stack (offset at top), so we push topic first.
        let mut runtime_code = vec![0x7f]; // PUSH32
        runtime_code.extend_from_slice(&expected_topic);
        runtime_code.extend_from_slice(&[
            0x60, 0x00, // PUSH1 0  (length)
            0x60, 0x00, // PUSH1 0  (offset)
            0xa1,       // LOG1
            0x00,       // STOP
        ]);
        state_db.set_code(contract, runtime_code);

        let (_output, _gas, logs) = execute_contract_call_with_context(
            state_db,
            caller,
            contract,
            vec![],
            U256::zero(),
            1_000_000,
            U256::from(1_000_000_000u64),
            40204,
            1,
            1_000_000,
            BlockContext::default(),
            None,
            None,
            None,
            ValueSemantics::RevmAuthoritative,
        )
        .expect("LOG1 contract call should succeed");

        assert_eq!(logs.len(), 1, "Expected exactly one log emitted by LOG1");
        let log = &logs[0];
        assert_eq!(log.address, contract, "log address should be the contract");
        assert_eq!(log.topics.len(), 1, "LOG1 emits one topic");
        assert_eq!(
            log.topics[0],
            citrate_consensus::types::Hash::new(expected_topic),
            "REVM-emitted topic must round-trip exactly. Pre-fix, this came \
             back as ASCII bytes for \"ContractExecuted0000...\"."
        );
        assert!(log.data.is_empty(), "LOG1 with length=0 must have no data");
    }

    /// Sprint EL-1 regression (Issue #19): Verify that SSTORE values persist
    /// across separate REVM invocations. Deploy → write slot → commit → read
    /// slot in a new REVM call. The second read must return the written value.
    #[test]
    fn test_el1_sstore_persists_across_invocations() {
        let state_db = Arc::new(StateDB::new());
        let caller = Address([1u8; 20]);
        let contract = Address([2u8; 20]);

        // Fund caller
        state_db
            .accounts
            .set_balance(caller, U256::from(10u64).pow(U256::from(18u64)));

        // Simple contract: SSTORE(slot=0, value=0x42) then RETURN
        // PUSH1 0x42, PUSH1 0x00, SSTORE, STOP
        let store_code = vec![0x60, 0x42, 0x60, 0x00, 0x55, 0x00];
        state_db.set_code(contract, store_code);

        // First REVM invocation: write slot 0 = 0x42
        let result1 = execute_contract_call(
            state_db.clone(),
            caller,
            contract,
            vec![],
            U256::zero(),
            1_000_000,
            U256::from(1_000_000_000u64),
            40204,
            1,
            1_000_000,
        );
        assert!(result1.is_ok(), "First REVM call (SSTORE) should succeed: {:?}", result1.err());

        // Verify storage was written
        let slot_key = [0u8; 32];
        let stored = state_db.get_storage(&contract, &slot_key);
        assert!(stored.is_some(), "Storage slot 0 should have a value after SSTORE");
        let value_bytes = stored.unwrap();
        assert_eq!(value_bytes[31], 0x42, "Storage slot 0 should contain 0x42");

        // Second REVM invocation: read slot 0 via SLOAD → PUSH1 0x00 SLOAD → MSTORE → RETURN
        // PUSH1 0x00, SLOAD, PUSH1 0x00, MSTORE, PUSH1 0x20, PUSH1 0x00, RETURN
        let read_code = vec![0x60, 0x00, 0x54, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
        state_db.set_code(contract, read_code);

        let result2 = execute_contract_call(
            state_db.clone(),
            caller,
            contract,
            vec![],
            U256::zero(),
            1_000_000,
            U256::from(1_000_000_000u64),
            40204,
            2,
            2_000_000,
        );
        assert!(result2.is_ok(), "Second REVM call (SLOAD) should succeed: {:?}", result2.err());

        let (output, _gas) = result2.unwrap();
        assert_eq!(output.len(), 32, "SLOAD return should be 32 bytes");
        assert_eq!(output[31], 0x42, "SLOAD should return 0x42 from persisted storage");
    }

    /// Sprint EL-1 regression: Simulate ReentrancyGuard lifecycle.
    /// Slot goes 0 → 1 → 2 → 1 across a transaction. After commit,
    /// a fresh REVM invocation must read the final value (1).
    #[test]
    fn test_el1_reentrancy_guard_lifecycle() {
        let state_db = Arc::new(StateDB::new());
        let contract = Address([3u8; 20]);

        // Simulate ReentrancyGuard: _status slot starts at 0 (uninitialized)
        // Set it to 1 (NOT_ENTERED)
        let slot_key = [0u8; 32];
        let mut val_one = [0u8; 32];
        val_one[31] = 1;
        state_db.set_storage(contract, slot_key.to_vec(), val_one.to_vec());

        // Simulate entering guard: 1 → 2
        let mut val_two = [0u8; 32];
        val_two[31] = 2;
        state_db.set_storage(contract, slot_key.to_vec(), val_two.to_vec());

        // Simulate exiting guard: 2 → 1
        state_db.set_storage(contract, slot_key.to_vec(), val_one.to_vec());

        // Commit state (mimics block finalization)
        state_db.commit();

        // Verify final value is 1 (NOT_ENTERED)
        let stored = state_db.get_storage(&contract, &slot_key);
        assert!(stored.is_some(), "Storage should exist after commit");
        assert_eq!(stored.unwrap()[31], 1, "ReentrancyGuard _status should be 1 after lifecycle");
    }

    /// Sprint EL-1 regression: Snapshot restore must clear dirty_storage
    /// so that stale writes from a reverted transaction don't persist.
    #[test]
    fn test_el1_snapshot_restore_clears_dirty() {
        let state_db = Arc::new(StateDB::new());
        let addr = Address([4u8; 20]);

        // Set initial state
        state_db.set_storage(addr, b"slot_a".to_vec(), b"original".to_vec());
        let _ = state_db.take_dirty_storage(); // clear dirty

        // Snapshot
        let snap = state_db.snapshot();

        // Simulate a failed tx writing to storage
        state_db.set_storage(addr, b"slot_a".to_vec(), b"bad_value".to_vec());
        state_db.set_storage(addr, b"slot_b".to_vec(), b"stale".to_vec());

        // Dirty storage should have entries from the failed tx
        let dirty_before = state_db.take_dirty_storage();
        assert!(!dirty_before.is_empty(), "Should have dirty entries before restore");

        // Re-dirty for the restore test (take_dirty_storage already cleared)
        state_db.set_storage(addr, b"slot_a".to_vec(), b"bad_value2".to_vec());

        // Restore snapshot (should clear dirty_storage)
        state_db.restore(snap);

        // After restore, dirty_storage should be empty
        let dirty_after = state_db.take_dirty_storage();
        assert!(dirty_after.is_empty(), "dirty_storage must be empty after restore (Sprint EL-1 fix)");

        // Verify state was restored
        assert_eq!(
            state_db.get_storage(&addr, b"slot_a"),
            Some(b"original".to_vec()),
            "Storage should be restored to original value"
        );
        assert_eq!(
            state_db.get_storage(&addr, b"slot_b"),
            None,
            "Stale storage from failed tx should not exist"
        );
    }

    /// A contract that CALLs another address with value must actually move
    /// the native SALT.
    ///
    /// `DatabaseCommit::commit` deliberately discards REVM's balance writes
    /// (Sprint EL-1 Fix #19) because the executor owns gas/nonce/balance.
    /// But the executor only re-applies the **top-level** `from → to`
    /// transfer (`executor.rs` `execute_call`). Every value transfer a
    /// contract performs *itself* — CALL with value, a payable forward, a
    /// payout to a user — is therefore dropped, while the callee's storage
    /// is committed as if the money had arrived.
    ///
    /// Observed live on chain 40204: `MembershipStakeVault` grant 0 called
    /// `LiquidStakingPool.deposit{value: 32_000 ether}()`. The pool's
    /// storage recorded `totalPooled = 32_000e18` and minted 32,000 shares,
    /// but the pool's actual balance is 0 and the 32,000 SALT is still
    /// sitting in the vault.
    #[test]
    fn test_contract_initiated_value_transfer_moves_balance() {
        let state_db = Arc::new(StateDB::new());
        let caller = Address([1u8; 20]);
        let contract = Address([2u8; 20]);
        let recipient = Address([3u8; 20]);

        let one_eth = U256::from(10u64).pow(U256::from(18u64));
        state_db.accounts.set_balance(caller, one_eth);
        // Fund the contract so it has the SALT it is about to forward.
        state_db.accounts.set_balance(contract, one_eth);

        // CALL(gas, recipient, 1000, 0, 0, 0, 0) then STOP.
        // CALL pops gas, addr, value, argsOff, argsLen, retOff, retLen —
        // so they are pushed in reverse.
        let mut code: Vec<u8> = vec![
            0x60, 0x00, // retLen
            0x60, 0x00, // retOff
            0x60, 0x00, // argsLen
            0x60, 0x00, // argsOff
            0x61, 0x03, 0xe8, // value = 1000
            0x73, // PUSH20 recipient
        ];
        code.extend_from_slice(&recipient.0);
        code.extend_from_slice(&[
            0x5a, // GAS
            0xf1, // CALL
            0x00, // STOP
        ]);
        state_db.set_code(contract, code);

        let result = execute_contract_call(
            state_db.clone(),
            caller,
            contract,
            vec![],
            U256::zero(),
            1_000_000,
            U256::from(1_000_000_000u64),
            40204,
            1,
            1_000_000,
        );
        assert!(result.is_ok(), "CALL-with-value should succeed: {:?}", result.err());

        assert_eq!(
            state_db.accounts.get_balance(&recipient),
            U256::from(1000u64),
            "recipient must receive the 1000 wei the contract CALLed with — \
             a contract-initiated value transfer must not be silently dropped"
        );
        assert_eq!(
            state_db.accounts.get_balance(&contract),
            one_eth - U256::from(1000u64),
            "the forwarding contract must actually be debited"
        );
    }

    /// The top-level `caller → contract` value must be credited EXACTLY once.
    ///
    /// This is the guard on the other side of the fix. `commit` now applies
    /// REVM's balance changes, which already include the top-level leg, so
    /// the executor's old post-REVM `journal_transfer(from, to, value)` had
    /// to go. If anyone re-adds it, `contract` ends up +2000 here and this
    /// test fails.
    ///
    /// It also pins that REVM charges NO gas: this path calls REVM directly,
    /// without the executor's gas deduction, so the caller must be down
    /// exactly `value` and not a wei more.
    #[test]
    fn test_top_level_value_credited_exactly_once() {
        let state_db = Arc::new(StateDB::new());
        let caller = Address([1u8; 20]);
        let contract = Address([2u8; 20]);

        let one_eth = U256::from(10u64).pow(U256::from(18u64));
        state_db.accounts.set_balance(caller, one_eth);
        state_db.set_code(contract, vec![0x00]); // STOP

        let result = execute_contract_call(
            state_db.clone(),
            caller,
            contract,
            vec![],
            U256::from(1000u64),
            1_000_000,
            U256::from(1_000_000_000u64),
            40204,
            1,
            1_000_000,
        );
        assert!(result.is_ok(), "call should succeed: {:?}", result.err());

        assert_eq!(
            state_db.accounts.get_balance(&contract),
            U256::from(1000u64),
            "top-level value must be credited exactly once — 2000 here means \
             the executor's post-REVM journal_transfer was re-added on top of \
             REVM's own transfer"
        );
        assert_eq!(
            state_db.accounts.get_balance(&caller),
            one_eth - U256::from(1000u64),
            "caller must be down exactly the value — REVM is handed a zero gas \
             price and must charge no gas of its own"
        );
    }

    /// A reverted call must move no money, even though REVM performed the
    /// transfer internally before the revert unwound it.
    #[test]
    fn test_reverted_call_moves_no_value() {
        let state_db = Arc::new(StateDB::new());
        let caller = Address([1u8; 20]);
        let contract = Address([2u8; 20]);
        let recipient = Address([3u8; 20]);

        let one_eth = U256::from(10u64).pow(U256::from(18u64));
        state_db.accounts.set_balance(caller, one_eth);
        state_db.accounts.set_balance(contract, one_eth);

        // CALL(gas, recipient, 1000, 0,0,0,0) then REVERT(0, 0).
        let mut code: Vec<u8> = vec![
            0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, // ret/args
            0x61, 0x03, 0xe8, // value = 1000
            0x73, // PUSH20 recipient
        ];
        code.extend_from_slice(&recipient.0);
        code.extend_from_slice(&[
            0x5a, // GAS
            0xf1, // CALL
            0x50, // POP the CALL success flag
            0x60, 0x00, 0x60, 0x00, // revert offset/len
            0xfd, // REVERT
        ]);
        state_db.set_code(contract, code);

        let result = execute_contract_call(
            state_db.clone(),
            caller,
            contract,
            vec![],
            U256::zero(),
            1_000_000,
            U256::from(1_000_000_000u64),
            40204,
            1,
            1_000_000,
        );
        assert!(result.is_err(), "the call reverts, so it must report an error");

        assert_eq!(
            state_db.accounts.get_balance(&recipient),
            U256::zero(),
            "a reverted call must not move value"
        );
        assert_eq!(
            state_db.accounts.get_balance(&contract),
            one_eth,
            "the forwarding contract must be untouched after a revert"
        );
    }

    /// Below the activation height the ORIGINAL BUG must be reproduced exactly.
    ///
    /// This looks perverse and is not: blocks 0..activation were produced under
    /// the buggy rule and committed state roots that embed it. A node that
    /// "helpfully" moved the money while replaying them would compute different
    /// roots and fork itself off the chain. History has to stay wrong.
    #[test]
    fn test_legacy_semantics_still_drop_internal_transfers() {
        let state_db = Arc::new(StateDB::new());
        let caller = Address([1u8; 20]);
        let contract = Address([2u8; 20]);
        let recipient = Address([3u8; 20]);

        let one_eth = U256::from(10u64).pow(U256::from(18u64));
        state_db.accounts.set_balance(caller, one_eth);
        state_db.accounts.set_balance(contract, one_eth);

        let mut code: Vec<u8> = vec![
            0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00,
            0x61, 0x03, 0xe8, // value = 1000
            0x73,
        ];
        code.extend_from_slice(&recipient.0);
        code.extend_from_slice(&[0x5a, 0xf1, 0x00]);
        state_db.set_code(contract, code);

        let result = execute_contract_call_with_context(
            state_db.clone(),
            caller,
            contract,
            vec![],
            U256::zero(),
            1_000_000,
            U256::from(1_000_000_000u64),
            40204,
            1,
            1_000_000,
            BlockContext::default(),
            None,
            None,
            None,
            ValueSemantics::LegacyDropInternal,
        );
        assert!(result.is_ok(), "call should succeed: {:?}", result.err());

        assert_eq!(
            state_db.accounts.get_balance(&recipient),
            U256::zero(),
            "pre-activation, the internal transfer must still be dropped — \
             replaying history under the corrected rule forks the node"
        );
        assert_eq!(
            state_db.accounts.get_balance(&contract),
            one_eth,
            "and the forwarding contract must keep its balance, as it did"
        );
    }

    /// The gate must flip on block height, at exactly the documented boundary.
    #[test]
    fn test_value_semantics_activation_boundary() {
        use crate::executor::{value_semantics_at, VALUE_TRANSFER_ACTIVATION_HEIGHT};

        assert_eq!(
            value_semantics_at(VALUE_TRANSFER_ACTIVATION_HEIGHT - 1),
            ValueSemantics::LegacyDropInternal,
            "the block below activation still runs the old rule"
        );
        assert_eq!(
            value_semantics_at(VALUE_TRANSFER_ACTIVATION_HEIGHT),
            ValueSemantics::RevmAuthoritative,
            "activation is inclusive — the rule applies AT the height, not after"
        );
        assert_eq!(
            value_semantics_at(0),
            ValueSemantics::LegacyDropInternal,
            "genesis replays under the old rule"
        );
    }

    /// The activation height is a consensus constant: every node must use the
    /// same one or they disagree about state roots. Pinned so a future edit is
    /// a deliberate act with a failing test attached.
    #[test]
    // The comparison is constant BY DESIGN — that is the point of a pin. It
    // fails to compile-time-true only while the constant stays sane; lowering
    // it below the chain height turns this into a failing test, which is the
    // tripwire we want.
    #[allow(clippy::assertions_on_constants)]
    fn test_value_transfer_activation_height_is_the_agreed_consensus_value() {
        use crate::executor::VALUE_TRANSFER_ACTIVATION_HEIGHT;

        assert_eq!(
            VALUE_TRANSFER_ACTIVATION_HEIGHT, 300_000,
            "owner decision 2026-07-29, confirmed. Changing this changes which \
             state roots are valid — it requires a coordinated fleet upgrade, \
             not an edit"
        );
        assert!(
            VALUE_TRANSFER_ACTIVATION_HEIGHT > 84_240,
            "activation must be comfortably ahead of the chain height at the \
             time it was chosen (~84,240 on 2026-07-29, 2.000 s blocks), or \
             nodes activate before they can all be upgraded"
        );
    }

    /// Two hops: caller → A (top-level), A → B (internal), B → C (internal).
    /// Every leg must land. This is the shape the membership money path takes
    /// (orchestrator → vault → pool) and the shape M-2.0 will take
    /// (orchestrator → vault → MemberBond → ValidatorRegistry).
    #[test]
    fn test_nested_internal_transfers_all_apply() {
        let state_db = Arc::new(StateDB::new());
        let caller = Address([1u8; 20]);
        let a = Address([2u8; 20]);
        let b = Address([3u8; 20]);
        let c = Address([4u8; 20]);

        let one_eth = U256::from(10u64).pow(U256::from(18u64));
        state_db.accounts.set_balance(caller, one_eth);

        // Helper: code that CALLs `target` forwarding `amount` wei, then STOPs.
        let forward_to = |target: &Address, amount: u16| -> Vec<u8> {
            let mut code: Vec<u8> = vec![0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00];
            code.extend_from_slice(&[0x61, (amount >> 8) as u8, (amount & 0xff) as u8]);
            code.push(0x73);
            code.extend_from_slice(&target.0);
            code.extend_from_slice(&[0x5a, 0xf1, 0x00]);
            code
        };

        // A forwards 1000 of the 2000 it receives to B; B forwards 400 to C.
        state_db.set_code(a, forward_to(&b, 1000));
        state_db.set_code(b, forward_to(&c, 400));

        let result = execute_contract_call(
            state_db.clone(),
            caller,
            a,
            vec![],
            U256::from(2000u64),
            2_000_000,
            U256::from(1_000_000_000u64),
            40204,
            1,
            1_000_000,
        );
        assert!(result.is_ok(), "nested calls should succeed: {:?}", result.err());

        assert_eq!(
            state_db.accounts.get_balance(&a),
            U256::from(1000u64),
            "A keeps 2000 received minus 1000 forwarded"
        );
        assert_eq!(
            state_db.accounts.get_balance(&b),
            U256::from(600u64),
            "B keeps 1000 received minus 400 forwarded"
        );
        assert_eq!(
            state_db.accounts.get_balance(&c),
            U256::from(400u64),
            "C receives the innermost hop — two levels below the top-level call"
        );
        assert_eq!(
            state_db.accounts.get_balance(&caller),
            one_eth - U256::from(2000u64),
            "caller is down exactly the top-level value"
        );
    }
}
