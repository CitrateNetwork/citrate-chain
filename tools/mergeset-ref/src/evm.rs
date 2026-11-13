//! The reference's EVM driver (spec 06 §8.3: REVM is part of the trusted
//! base; the code that drives it is not). Written from the chain's documented
//! contract-transaction rules, not from `citrate_execution`'s executor or its
//! REVM adapter, and over the reference's own world state.
//!
//! RULES (each one is what a node must do; a divergence means one side breaks
//! one of them):
//!   * E1 call: a base charge of [`CALL_BASE_GAS`] comes first (a gas limit
//!     below it fails the tx). REVM runs the call with
//!     `gas_limit - CALL_BASE_GAS` if the recipient has code, or is a standard
//!     precompile (0x01..=0x09) with PBA hardening active, or, under supply
//!     hardening (spec 06 §3.12 T1, the r1007 rule), always. Otherwise (r1006
//!     history) a recipient without code runs nothing and moves no value: the
//!     tx succeeds with the base charge only.
//!   * E2 deployment: a base charge of [`CREATE_BASE_GAS`], then REVM CREATE
//!     with `gas_limit - CREATE_BASE_GAS`, carrying the tx value under supply
//!     hardening (§3.12 T2) and value 0 below it (the value is checked, not
//!     transferred). The created account's code is the runtime REVM returned,
//!     byte for byte.
//!   * E3 outcome: REVM success charges `base + REVM gas used`; anything else
//!     (revert, halt, REVM refusing the tx) fails it: the full gas limit is
//!     charged, the nonce moves, nothing else changes and no log is kept.
//!   * E4 commit of a successful call's changes: the balance of every account
//!     REVM reports (gas price 0, so REVM's balances are exactly the value
//!     movement, top-level and internal); every storage slot it reports, at
//!     its present value as a 32-byte big-endian word (zero kept, never
//!     deleted); the code of an account whose code hash is neither empty nor
//!     zero (original bytes under exact-create-code, REVM's analysed bytes
//!     otherwise) and, from the create-nonce fix, that contract's nonce. The
//!     sender's nonce is never REVM's: it is the tx nonce + 1.
//!   * E5 environment: CANCUN, the chain id, NUMBER / TIMESTAMP / COINBASE /
//!     PREVRANDAO of the accepting block, GASLIMIT = ACCEPT_GAS_LIMIT, base
//!     fee 0, BLOCKHASH(n) = the accepting block's selected-chain ancestor at
//!     n for the 256 heights below it, zero otherwise.
//!   * E6 §R' vest: a gasless system call from the reward minter, funded with
//!     the amount for the call's duration, to the registry with
//!     `creditReward(proposer key, amount)` and the amount as value, at
//!     NUMBER = height and TIMESTAMP = 0, [`SYSTEM_CALL_GAS_LIMIT`] gas. On
//!     success E4 applies; on failure nothing changes (the share burns).
//!
//! REFUSED ([`Unsupported`], never guessed): any call frame, top-level or
//! internal, into a low address (first 18 bytes zero) other than the standard
//! precompiles 0x01..=0x09 (the Citrate precompile families, the AI, model
//! and governance precompiles and the reserved ranges all live there, and the
//! reference does not implement them); AI operations; and blocks below an EVM
//! rule's activation (the legacy value semantics).

use std::collections::HashMap;
use std::convert::Infallible;

use revm::interpreter::{CallInputs, CallOutcome};
use revm::primitives::{
    AccountInfo, Address as RAddress, Bytecode, Bytes, ExecutionResult, Output, SpecId, TransactTo,
    B256, KECCAK_EMPTY, U256 as RU256,
};
use revm::{inspector_handle_register, Database, Evm, EvmContext, Inspector};

use primitive_types::U256;
use sha3::{Digest, Keccak256};

use crate::exec::{Account, RefLog, State, Unsupported, ACCEPT_GAS_LIMIT};

/// E1: the base charge of a call.
pub const CALL_BASE_GAS: u64 = 700;
/// E2: the base charge of a deployment.
pub const CREATE_BASE_GAS: u64 = 32_000;
/// E6: the gas of the §R' vest system call.
pub const SYSTEM_CALL_GAS_LIMIT: u64 = 1_000_000;
/// E6: `creditReward(bytes32,uint256)`.
pub const CREDIT_REWARD_SIGNATURE: &str = "creditReward(bytes32,uint256)";

/// keccak256.
pub fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

/// A low address: the first 18 bytes are zero (the precompile ranges).
pub fn is_low(a: &[u8; 20]) -> bool {
    a[..18].iter().all(|b| *b == 0)
}

/// A standard Ethereum precompile both sides take from REVM unchanged.
pub fn is_standard_precompile(a: &[u8; 20]) -> bool {
    is_low(a) && a[18] == 0 && (1..=9).contains(&a[19])
}

fn ru(v: U256) -> RU256 {
    RU256::from_limbs(v.0)
}

fn pu(v: RU256) -> U256 {
    U256(v.into_limbs())
}

/// The block environment of the accepting block (E5).
pub struct Env<'a> {
    pub chain_id: u64,
    pub number: u64,
    pub timestamp: u64,
    pub coinbase: [u8; 20],
    pub prevrandao: [u8; 32],
    pub block_hashes: &'a HashMap<u64, [u8; 32]>,
    /// Exact-create-code in force (E4).
    pub exact_create_code: bool,
    /// Create-nonce fix in force (E4).
    pub contract_nonces: bool,
}

/// What REVM is asked to run.
pub enum Kind {
    Call {
        to: [u8; 20],
        data: Vec<u8>,
        value: U256,
    },
    Create {
        init: Vec<u8>,
        value: U256,
    },
}

/// A successful REVM run's effect, not yet applied.
pub struct Success {
    pub gas_used: u64,
    pub logs: Vec<RefLog>,
    /// The accounts REVM reports, already translated by E4.
    changes: Vec<([u8; 20], Change)>,
    /// A top-level deployment: (created address, runtime code).
    pub created_top: Option<([u8; 20], Vec<u8>)>,
    /// Accounts created (top-level and by CREATE inside the call).
    pub created: u64,
}

struct Change {
    balance: U256,
    storage: Vec<([u8; 32], [u8; 32])>,
    code: Option<Vec<u8>>,
    nonce: Option<u64>,
}

/// The reference world state as a REVM database; `caller` reads
/// `caller_balance` (the balance after the fee was taken up front).
struct Db<'a> {
    state: &'a State,
    caller: [u8; 20],
    caller_balance: U256,
    block_hashes: &'a HashMap<u64, [u8; 32]>,
}

impl Database for Db<'_> {
    type Error = Infallible;

    fn basic(&mut self, address: RAddress) -> Result<Option<AccountInfo>, Infallible> {
        let a: [u8; 20] = address.0 .0;
        let acct = self.state.accounts.get(&a).cloned().unwrap_or_default();
        let balance = if a == self.caller {
            self.caller_balance
        } else {
            acct.balance
        };
        let code_hash = match &acct.code {
            Some(code) => B256::from(keccak(code)),
            None => KECCAK_EMPTY,
        };
        Ok(Some(AccountInfo {
            balance: ru(balance),
            nonce: acct.nonce,
            code_hash,
            code: None,
        }))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Infallible> {
        let code = self
            .state
            .codes
            .get(&code_hash.0)
            .cloned()
            .unwrap_or_default();
        Ok(Bytecode::new_raw(Bytes::from(code)))
    }

    fn storage(&mut self, address: RAddress, index: RU256) -> Result<RU256, Infallible> {
        let key: [u8; 32] = index.to_be_bytes();
        let v = self
            .state
            .accounts
            .get(&address.0 .0)
            .and_then(|a| a.storage.get(&key).copied())
            .unwrap_or([0u8; 32]);
        Ok(RU256::from_be_bytes(v))
    }

    fn block_hash(&mut self, number: RU256) -> Result<B256, Infallible> {
        let n = number.as_limbs()[0];
        Ok(match self.block_hashes.get(&n) {
            Some(h) if number.as_limbs()[1..].iter().all(|l| *l == 0) => B256::from(*h),
            _ => B256::ZERO,
        })
    }
}

/// Records the first call frame into an address the reference refuses.
#[derive(Default)]
struct Guard {
    refused: Option<[u8; 20]>,
}

impl<DB: Database> Inspector<DB> for Guard {
    fn call(
        &mut self,
        _context: &mut EvmContext<DB>,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        for a in [inputs.target_address.0 .0, inputs.bytecode_address.0 .0] {
            if is_low(&a) && !is_standard_precompile(&a) && self.refused.is_none() {
                self.refused = Some(a);
            }
        }
        None
    }
}

/// Run `kind` from `caller` with `gas_limit` on `state` (not mutated).
/// `Ok(None)` is a failed run (E3).
pub fn run(
    state: &State,
    env: &Env<'_>,
    caller: [u8; 20],
    caller_balance: U256,
    kind: Kind,
    gas_limit: u64,
    timestamp: u64,
) -> Result<Option<Success>, Unsupported> {
    let mut db = Db {
        state,
        caller,
        caller_balance,
        block_hashes: env.block_hashes,
    };
    let top_create = matches!(kind, Kind::Create { .. });
    let result = {
        let mut evm = Evm::builder()
            .with_db(&mut db)
            .with_external_context(Guard::default())
            .with_spec_id(SpecId::CANCUN)
            .modify_cfg_env(|cfg| cfg.chain_id = env.chain_id)
            .modify_tx_env(|tx| {
                tx.caller = RAddress::from(caller);
                match &kind {
                    Kind::Call { to, data, value } => {
                        tx.transact_to = TransactTo::Call(RAddress::from(*to));
                        tx.data = Bytes::from(data.clone());
                        tx.value = ru(*value);
                    }
                    Kind::Create { init, value } => {
                        tx.transact_to = TransactTo::Create;
                        tx.data = Bytes::from(init.clone());
                        tx.value = ru(*value);
                    }
                }
                tx.gas_limit = gas_limit;
                tx.gas_price = RU256::ZERO;
                tx.chain_id = Some(env.chain_id);
            })
            .modify_block_env(|b| {
                b.number = RU256::from(env.number);
                b.timestamp = RU256::from(timestamp);
                b.coinbase = RAddress::from(env.coinbase);
                b.prevrandao = Some(B256::from(env.prevrandao));
                b.gas_limit = RU256::from(ACCEPT_GAS_LIMIT);
            })
            .append_handler_register(inspector_handle_register)
            .build();
        let r = evm.transact();
        let refused = evm.context.external.refused;
        (r, refused)
    };
    let (outcome, refused) = result;
    if let Some(a) = refused {
        return Err(Unsupported(format!(
            "a call frame into 0x{}, a precompile the reference does not implement",
            hex::encode(a)
        )));
    }
    let Ok(rs) = outcome else {
        return Ok(None);
    };
    let (gas_used, logs, created_top) = match rs.result {
        ExecutionResult::Success {
            gas_used,
            logs,
            output,
            ..
        } => {
            let created_top = match output {
                Output::Create(runtime, Some(addr)) if top_create => {
                    Some((addr.0 .0, runtime.to_vec()))
                }
                Output::Create(_, _) => return Ok(None),
                Output::Call(_) if top_create => return Ok(None),
                Output::Call(_) => None,
            };
            let logs = logs
                .iter()
                .map(|l| RefLog {
                    address: l.address.0 .0,
                    topics: l.data.topics().iter().map(|t| t.0).collect(),
                    data: l.data.data.to_vec(),
                })
                .collect::<Vec<_>>();
            (gas_used, logs, created_top)
        }
        ExecutionResult::Revert { .. } | ExecutionResult::Halt { .. } => return Ok(None),
    };
    let mut created = 0u64;
    let mut changes = Vec::new();
    for (addr, account) in rs.state {
        if account.is_created() {
            created += 1;
        }
        let is_contract =
            account.info.code_hash != KECCAK_EMPTY && account.info.code_hash != B256::ZERO;
        let code = if is_contract {
            account
                .info
                .code
                .as_ref()
                .map(|c| {
                    if env.exact_create_code {
                        c.original_bytes().to_vec()
                    } else {
                        c.bytes().to_vec()
                    }
                })
                .filter(|c| !c.is_empty())
        } else {
            None
        };
        changes.push((
            addr.0 .0,
            Change {
                balance: pu(account.info.balance),
                storage: account
                    .storage
                    .iter()
                    .map(|(k, v)| (k.to_be_bytes::<32>(), v.present_value.to_be_bytes::<32>()))
                    .collect(),
                code,
                nonce: (env.contract_nonces && is_contract).then_some(account.info.nonce),
            },
        ));
    }
    Ok(Some(Success {
        gas_used,
        logs,
        changes,
        created_top,
        created,
    }))
}

impl Success {
    /// A success with no effect (E1: a call to an account without code).
    pub fn nothing() -> Self {
        Self {
            gas_used: 0,
            logs: Vec::new(),
            changes: Vec::new(),
            created_top: None,
            created: 0,
        }
    }

    /// Apply E4 (and E2's runtime code) to `state`.
    pub fn apply(&self, state: &mut State) {
        for (addr, c) in &self.changes {
            let a: &mut Account = state.accounts.entry(*addr).or_default();
            a.balance = c.balance;
            for (k, v) in &c.storage {
                a.storage.insert(*k, *v);
            }
            if let Some(n) = c.nonce {
                a.nonce = n;
            }
            if let Some(code) = &c.code {
                state.set_code(*addr, code.clone());
            }
        }
        if let Some((addr, runtime)) = &self.created_top {
            state.set_code(*addr, runtime.clone());
        }
    }
}

/// E6: `creditReward(pubkey, amount)` calldata.
pub fn credit_reward_calldata(pubkey: &[u8; 32], amount: U256) -> Vec<u8> {
    let mut data = keccak(CREDIT_REWARD_SIGNATURE.as_bytes())[..4].to_vec();
    data.extend_from_slice(pubkey);
    let mut amt = [0u8; 32];
    amount.to_big_endian(&mut amt);
    data.extend_from_slice(&amt);
    data
}
