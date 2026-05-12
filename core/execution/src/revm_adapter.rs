// citrate/core/execution/src/revm_adapter.rs

use crate::mvcc::{JournalHandle, WriteSet};
use crate::state::StateDB;
use crate::types::{Address, ExecutionError};
use parking_lot::Mutex;
use primitive_types::U256;
use revm::{
    primitives::{
        AccountInfo, Address as RevmAddress, Bytecode, Bytes, ExecutionResult, Output,
        TransactTo, B256, U256 as RevmU256, SpecId, KECCAK_EMPTY,
    },
    Database, DatabaseCommit, Evm,
};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

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
}

impl StateDBAdapter {
    pub fn new(state_db: Arc<StateDB>) -> Self {
        Self {
            state_db,
            block_hashes: HashMap::new(),
            writes: None,
            journal: None,
        }
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

        let code = self
            .state_db
            .get_code(&hash)
            .unwrap_or_default();

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

        // Get storage value as bytes from committed state
        let value_bytes = self
            .state_db
            .get_storage(&addr, &key_bytes)
            .unwrap_or_else(|| vec![0u8; 32]);

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

            // ---- Sprint EL-1 Fix (Issue #19) ----
            // Do NOT update balance or nonce from REVM. The executor is the
            // sole owner of gas/balance/nonce accounting:
            //   - executor.execute_transaction() deducts gas upfront and refunds on success
            //   - executor.check_and_increment_nonce() manages nonces
            // REVM also internally tracks gas/value/nonce, causing double-deduction
            // if we write REVM's values back to StateDB. Instead, REVM only commits
            // storage and code changes.

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
    execute_contract_create_with_context(
        state_db, deployer, init_code, value, gas_limit, gas_price,
        chain_id, block_number, block_timestamp, BlockContext::default(), None, None,
    )
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
) -> Result<(Address, Vec<u8>, u64), ExecutionError> {
    debug!("Executing contract creation with revm");
    debug!("  Deployer: {}", deployer);
    debug!("  Init code size: {} bytes", init_code.len());
    debug!("  Gas limit: {}", gas_limit);

    // Create database adapter with block hashes + optional write/journal capture
    let mut db = StateDBAdapter::new(state_db.clone())
        .with_block_hashes(block_ctx.block_hashes);
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
        .modify_cfg_env(|cfg| {
            cfg.chain_id = chain_id;
        })
        // BFR-VM-1 — CANCUN enables MCOPY (EIP-5656) which Solidity
        // 0.8.25+ emits for dynamic-bytes ABI return encoding. Pre-
        // CANCUN halted with InvalidOpcode, which the executor's
        // status-bit pattern silently swallowed as Ok(receipt{status:
        // false, output:vec![]}); eth_call then hex-encoded empty
        // bytes → "0x" with no JSON-RPC error to surface the bug.
        // See `.agentile/sprints/active/2026-05-12-bfr-vm-1-dynamic-returns/SPRINT.md`.
        .with_spec_id(SpecId::CANCUN)
        .modify_tx_env(|tx| {
            tx.caller = RevmAddress::from_slice(&deployer.0);
            tx.transact_to = TransactTo::Create;
            tx.data = Bytes::from(init_code);
            tx.value = RevmU256::from_limbs(value.0);
            tx.gas_limit = gas_limit;
            tx.gas_price = RevmU256::from_limbs(gas_price.0);
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
            ..
        } => {
            match output {
                Output::Create(runtime_code, Some(contract_address)) => {
                    let addr = Address(contract_address.0 .0);
                    let code = runtime_code.to_vec();

                    info!(
                        "Contract deployed successfully at {} with {} bytes of runtime code",
                        addr,
                        code.len()
                    );

                    Ok((addr, code, gas_used))
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
    execute_contract_call_with_context(
        state_db, caller, contract, calldata, value, gas_limit, gas_price,
        chain_id, block_number, block_timestamp, BlockContext::default(), None, None,
    )
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
) -> Result<(Vec<u8>, u64), ExecutionError> {
    debug!("Executing contract call with revm");
    debug!("  Caller: {}", caller);
    debug!("  Contract: {}", contract);
    debug!("  Calldata size: {} bytes", calldata.len());

    // Create database adapter with block hashes + optional write/journal capture
    let mut db = StateDBAdapter::new(state_db)
        .with_block_hashes(block_ctx.block_hashes);
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
        .modify_cfg_env(|cfg| {
            cfg.chain_id = chain_id;
        })
        // BFR-VM-1 — CANCUN enables MCOPY (EIP-5656) which Solidity
        // 0.8.25+ emits for dynamic-bytes ABI return encoding. Pre-
        // CANCUN halted with InvalidOpcode, which the executor's
        // status-bit pattern silently swallowed as Ok(receipt{status:
        // false, output:vec![]}); eth_call then hex-encoded empty
        // bytes → "0x" with no JSON-RPC error to surface the bug.
        // See `.agentile/sprints/active/2026-05-12-bfr-vm-1-dynamic-returns/SPRINT.md`.
        .with_spec_id(SpecId::CANCUN)
        .modify_tx_env(|tx| {
            tx.caller = RevmAddress::from_slice(&caller.0);
            tx.transact_to = TransactTo::Call(RevmAddress::from_slice(&contract.0));
            tx.data = Bytes::from(calldata);
            tx.value = RevmU256::from_limbs(value.0);
            tx.gas_limit = gas_limit;
            tx.gas_price = RevmU256::from_limbs(gas_price.0);
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
            output, gas_used, ..
        } => match output {
            Output::Call(return_data) => Ok((return_data.to_vec(), gas_used)),
            _ => Err(ExecutionError::Reverted(
                "Unexpected output type for contract call".to_string(),
            )),
        },
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
        );

        assert!(result.is_ok(), "Contract call with block context should succeed: {:?}", result.err());
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
}
