// citrate/core/execution/src/revm_adapter.rs

use crate::state::StateDB;
use crate::types::{Address, ExecutionError};
use primitive_types::U256;
use revm::{
    primitives::{
        AccountInfo, Address as RevmAddress, Bytecode, Bytes, ExecutionResult, Output,
        TransactTo, TxEnv, B256, U256 as RevmU256, SpecId, KECCAK_EMPTY,
    },
    Database, DatabaseCommit, Evm,
};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

/// Adapter to make StateDB compatible with revm's Database trait
pub struct StateDBAdapter {
    state_db: Arc<StateDB>,
    /// WP-X.4: Block number → block hash mapping for BLOCKHASH opcode.
    /// EVM spec: BLOCKHASH returns the hash for the 256 most recent blocks.
    block_hashes: HashMap<u64, [u8; 32]>,
}

impl StateDBAdapter {
    pub fn new(state_db: Arc<StateDB>) -> Self {
        Self {
            state_db,
            block_hashes: HashMap::new(),
        }
    }

    /// Set block hashes for BLOCKHASH opcode support (WP-X.4).
    /// Should contain the most recent 256 block number → hash mappings.
    pub fn with_block_hashes(mut self, hashes: HashMap<u64, [u8; 32]>) -> Self {
        self.block_hashes = hashes;
        self
    }
}

impl Database for StateDBAdapter {
    type Error = ExecutionError;

    fn basic(&mut self, address: RevmAddress) -> Result<Option<AccountInfo>, Self::Error> {
        let addr = Address(address.0 .0);
        let balance = self.state_db.accounts.get_balance(&addr);
        let nonce = self.state_db.accounts.get_nonce(&addr);
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
        let code = self
            .state_db
            .get_code(&hash)
            .unwrap_or_default();

        Ok(Bytecode::new_raw(Bytes::from(code)))
    }

    fn storage(&mut self, address: RevmAddress, index: RevmU256) -> Result<RevmU256, Self::Error> {
        let addr = Address(address.0 .0);
        let key_bytes: [u8; 32] = index.to_be_bytes();

        // Get storage value as bytes
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

            // Update balance
            let balance = U256::from_big_endian(&account.info.balance.to_be_bytes::<32>());
            self.state_db.accounts.set_balance(addr, balance);

            // Update nonce
            self.state_db.accounts.set_nonce(addr, account.info.nonce);

            // Update storage
            for (key, value) in account.storage {
                let key_bytes = key.to_be_bytes::<32>();
                let value_bytes = value.present_value.to_be_bytes::<32>();
                self.state_db.set_storage(addr, key_bytes.to_vec(), value_bytes.to_vec());
            }

            // Update code if changed
            if account.info.code.is_some() {
                let code = account.info.code.unwrap();
                let code_bytes = code.bytes().to_vec();
                if !code_bytes.is_empty() {
                    self.state_db.set_code(addr, code_bytes);
                }
            }
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
        chain_id, block_number, block_timestamp, BlockContext::default(),
    )
}

/// Execute contract creation using revm with full block context (WP-X.4)
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
) -> Result<(Address, Vec<u8>, u64), ExecutionError> {
    debug!("Executing contract creation with revm");
    debug!("  Deployer: {}", deployer);
    debug!("  Init code size: {} bytes", init_code.len());
    debug!("  Gas limit: {}", gas_limit);

    // Create database adapter with block hashes
    let mut db = StateDBAdapter::new(state_db.clone())
        .with_block_hashes(block_ctx.block_hashes);

    // Build EVM with transaction
    let coinbase = block_ctx.coinbase;
    let prevrandao = block_ctx.prevrandao;
    let mut evm = Evm::builder()
        .with_db(&mut db)
        .modify_cfg_env(|cfg| {
            cfg.chain_id = chain_id;
        })
        .with_spec_id(SpecId::SHANGHAI)
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
        chain_id, block_number, block_timestamp, BlockContext::default(),
    )
}

/// Execute contract call using revm with full block context (WP-X.4)
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
) -> Result<(Vec<u8>, u64), ExecutionError> {
    debug!("Executing contract call with revm");
    debug!("  Caller: {}", caller);
    debug!("  Contract: {}", contract);
    debug!("  Calldata size: {} bytes", calldata.len());

    // Create database adapter with block hashes
    let mut db = StateDBAdapter::new(state_db)
        .with_block_hashes(block_ctx.block_hashes);

    // Build EVM with transaction
    let coinbase = block_ctx.coinbase;
    let prevrandao = block_ctx.prevrandao;
    let mut evm = Evm::builder()
        .with_db(&mut db)
        .modify_cfg_env(|cfg| {
            cfg.chain_id = chain_id;
        })
        .with_spec_id(SpecId::SHANGHAI)
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
            1337,
            100,
            1_000_000,
            ctx,
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
            1337,
            100,
            1_000_000,
            ctx,
        );

        assert!(result.is_ok(), "Contract call with block context should succeed: {:?}", result.err());
    }
}
