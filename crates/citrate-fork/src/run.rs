//! Executes a [`Plan`] on top of a [`ForkState`] with the node's execution rules, and reports
//! what happened.
//!
//! What is the node's, not a copy:
//! * the Citrate precompile bridge (`revm_adapter::register_citrate_precompiles`), with the
//!   PBA hardening flag for the block being simulated (the release pin for the chain id from
//!   `citrate_consensus::hardening`, unless the caller overrides it for a devnet);
//! * the value-transfer rule (`executor::value_semantics_at`) and the EIP-161 contract-nonce
//!   rule (`executor::persist_contract_nonces_at`). The fork models the rules 40204 runs today
//!   (REVM-authoritative value movement, contract nonces persisted); a block where either
//!   legacy rule still applies is refused, never simulated wrongly;
//! * the EVM configuration the node builds: `SpecId::CANCUN`, the chain id, and gas price
//!   zero inside the EVM (the node's executor charges gas outside REVM, so the GASPRICE opcode
//!   reads 0 on 40204).
//!
//! Each step runs as its own transaction in one simulated block (the fork block + 1), from
//! the plan's sender, committing to the in-memory state before the next step. Gas is not
//! charged in the dry run; `gasUsed` is what the step consumed.
use std::collections::BTreeMap;

use citrate_execution::revm_adapter::{register_citrate_precompiles, ValueSemantics};
use revm::db::{AccountState, CacheDB};
use revm::interpreter::{CallInputs, CallOutcome};
use revm::primitives::{Address, Bytes, ExecutionResult, Output, SpecId, TransactTo, B256, U256};
use revm::{inspector_handle_register, Database, Evm, EvmContext, Inspector};
use serde::Serialize;

use crate::plan::{Plan, Step, Target};
use crate::state::{ForkBlock, ForkError, ForkState};
use crate::table::{self, Coverage, PrecompileRow};

/// The name a report carries in `engine` (core's deploy gate keys on it).
pub const ENGINE: &str = "citrate-fork";
/// Report format version.
pub const REPORT_SCHEMA: u32 = 1;
/// Return data kept per step in the report.
const MAX_OUTPUT_BYTES: usize = 16 * 1024;

/// Where the pre-state came from (for the report).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum StateSource {
    /// No accounts: an offline run.
    Empty,
    /// A JSON-RPC endpoint (scheme and host only).
    Rpc { origin: String },
}

/// What the simulation runs as.
#[derive(Debug, Clone)]
pub struct ForkConfig {
    pub chain_id: u64,
    /// The block the fork sits on; the steps run in block `number + 1`.
    pub block: ForkBlock,
    /// The PBA hardening activation height for this chain (None = off).
    pub hardening_height: Option<u64>,
    /// Where it came from, for the report.
    pub hardening_source: String,
    pub source: StateSource,
}

/// The release-pinned hardening height for `chain_id` (`citrate_consensus::hardening`).
pub fn pinned_hardening(chain_id: u64) -> Option<u64> {
    citrate_consensus::hardening::pinned_activation(chain_id)
}

/// The execution rules the simulated block runs under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Semantics {
    pub spec_id: String,
    pub gas_price_in_evm: u64,
    pub value_semantics: String,
    pub contract_nonces: String,
    pub pba_hardened: bool,
    pub pba_hardening_height: Option<u64>,
    pub pba_hardening_source: String,
    pub commd_fold_verify_linked: bool,
    pub halo2_verifier_linked: bool,
}

/// One touched Citrate precompile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Touch {
    pub address: String,
    pub coverage: Coverage,
    pub calls: u64,
    pub failed_calls: u64,
}

/// One executed step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StepReport {
    pub kind: String,
    /// `0x1` success, `0x0` revert or halt (receipt style).
    pub status: String,
    pub to: Option<String>,
    pub contract_address: Option<String>,
    pub gas_used: String,
    /// The exact calldata / init code executed.
    pub input: String,
    pub value: String,
    pub output: String,
    pub output_truncated: bool,
    pub error: Option<String>,
    pub logs: usize,
    pub precompiles_touched: Vec<Touch>,
}

/// The precompile section of a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrecompileReport {
    /// Addresses executed with the node's own code at this block.
    pub real: Vec<String>,
    /// Every Citrate precompile address and its coverage at this block.
    pub table: Vec<PrecompileRow>,
    /// Every Citrate precompile touched by any step.
    pub touched: Vec<Touch>,
    /// Touched addresses this fork cannot reproduce. Non-empty means the dry run does not
    /// show what 40204 would do.
    pub unavailable_touched: Vec<String>,
}

/// A dry-run report. The top-level `status` / `contractAddress` / `gasUsed` mirror the first
/// step (receipt style) so a receipt parser can read a create-first plan directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub engine: String,
    pub engine_version: String,
    pub schema: u32,
    pub chain_id: u64,
    pub fork_block: u64,
    pub simulated_block: u64,
    pub state_source: StateSource,
    pub sender: String,
    pub balance_overrides: BTreeMap<String, String>,
    pub semantics: Semantics,
    pub status: String,
    pub contract_address: Option<String>,
    pub gas_used: String,
    pub all_steps_succeeded: bool,
    pub steps: Vec<StepReport>,
    pub precompiles: PrecompileReport,
}

/// Records every call into a Citrate precompile address and whether it succeeded.
#[derive(Default)]
struct PrecompileTracer {
    hits: BTreeMap<u16, (u64, u64)>,
}

impl<DB: Database> Inspector<DB> for PrecompileTracer {
    fn call_end(
        &mut self,
        _context: &mut EvmContext<DB>,
        inputs: &CallInputs,
        outcome: CallOutcome,
    ) -> CallOutcome {
        if let Some(v) = table::short_address(&inputs.bytecode_address.0 .0) {
            let e = self.hits.entry(v).or_insert((0, 0));
            e.0 += 1;
            if !outcome.result.result.is_ok() {
                e.1 += 1;
            }
        }
        outcome
    }
}

fn touches(hits: &BTreeMap<u16, (u64, u64)>, hardened: bool) -> Vec<Touch> {
    hits.iter()
        .map(|(v, (calls, failed))| Touch {
            address: format!("0x{v:04x}"),
            coverage: table::coverage(*v, hardened).0,
            calls: *calls,
            failed_calls: *failed,
        })
        .collect()
}

fn hex0x(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

fn err(s: impl Into<String>) -> ForkError {
    ForkError(s.into())
}

/// Runs `plan` on `state` under `cfg`.
pub fn run(plan: &Plan, state: ForkState, cfg: &ForkConfig) -> Result<Report, ForkError> {
    let height = cfg
        .block
        .number
        .checked_add(1)
        .ok_or_else(|| err("block number overflow"))?;
    if citrate_execution::executor::value_semantics_at(height) != ValueSemantics::RevmAuthoritative
    {
        return Err(err(format!(
            "block {height} runs the legacy value-transfer rule, which this fork does not model"
        )));
    }
    if !citrate_execution::executor::persist_contract_nonces_at(height) {
        return Err(err(format!(
            "block {height} is below the CREATE-nonce activation ({}), which this fork does not model",
            citrate_execution::executor::create_nonce_fix_activation_height()
        )));
    }
    let hardened = citrate_execution::activation::active_at(cfg.hardening_height, height);
    let timestamp = cfg.block.timestamp.saturating_add(2);
    let mut db = CacheDB::new(state);

    let mut overrides = BTreeMap::new();
    for (addr, wei) in &plan.balances {
        let acc = db.load_account(*addr)?;
        acc.info.balance = *wei;
        if acc.account_state == AccountState::NotExisting {
            acc.account_state = AccountState::None;
        }
        overrides.insert(format!("{addr:#x}"), wei.to_string());
    }

    let mut created: BTreeMap<usize, Address> = BTreeMap::new();
    let mut steps = Vec::new();
    let mut all_hits: BTreeMap<u16, (u64, u64)> = BTreeMap::new();
    for (i, step) in plan.steps.iter().enumerate() {
        let (kind, transact_to, data, value, to_label) = match step {
            Step::Create { data, value } => ("create", TransactTo::Create, data, *value, None),
            Step::Call { to, data, value } => {
                let addr = match to {
                    Target::Address(a) => *a,
                    Target::Created(j) => *created
                        .get(j)
                        .ok_or_else(|| err(format!("step {i}: step {j} created no contract")))?,
                };
                (
                    "call",
                    TransactTo::Call(addr),
                    data,
                    *value,
                    Some(format!("{addr:#x}")),
                )
            }
        };
        let mut tracer = PrecompileTracer::default();
        let result = {
            let mut evm = Evm::builder()
                .with_db(&mut db)
                .with_external_context(&mut tracer)
                .append_handler_register(inspector_handle_register)
                .append_handler_register_box(Box::new(move |h| {
                    register_citrate_precompiles(h, hardened)
                }))
                .with_spec_id(SpecId::CANCUN)
                .modify_cfg_env(|c| c.chain_id = cfg.chain_id)
                .modify_block_env(|b| {
                    b.number = U256::from(height);
                    b.timestamp = U256::from(timestamp);
                    b.coinbase = cfg.block.coinbase;
                    // The node never sets the block gas limit or base fee inside REVM (its
                    // executor enforces the gas limit outside the EVM), so GASLIMIT reads
                    // revm's default (U256::MAX) and BASEFEE reads 0 on 40204. Leave both at
                    // revm's defaults so the fork reads the same (tests/node_parity.rs).
                    // PREVRANDAO: the fork cannot know the simulated block's VRF output; 0.
                    b.prevrandao = Some(B256::ZERO);
                })
                .modify_tx_env(|tx| {
                    tx.caller = plan.from;
                    tx.transact_to = transact_to;
                    tx.data = Bytes::from(data.clone());
                    tx.value = value;
                    tx.gas_limit = plan.gas_limit;
                    tx.gas_price = U256::ZERO;
                    tx.chain_id = Some(cfg.chain_id);
                    tx.nonce = None;
                })
                .build();
            evm.transact_commit()
        };
        let result = result.map_err(|e| err(format!("step {i}: {e:?}")))?;
        for (v, (c, f)) in &tracer.hits {
            let e = all_hits.entry(*v).or_insert((0, 0));
            e.0 += c;
            e.1 += f;
        }
        let (ok, gas, out, addr, error, logs) = match result {
            ExecutionResult::Success {
                gas_used,
                output,
                logs,
                ..
            } => match output {
                Output::Create(code, a) => (true, gas_used, code.to_vec(), a, None, logs.len()),
                Output::Call(o) => (true, gas_used, o.to_vec(), None, None, logs.len()),
            },
            ExecutionResult::Revert { gas_used, output } => (
                false,
                gas_used,
                output.to_vec(),
                None,
                Some("reverted".to_string()),
                0,
            ),
            ExecutionResult::Halt { reason, gas_used } => (
                false,
                gas_used,
                Vec::new(),
                None,
                Some(format!("halted: {reason:?}")),
                0,
            ),
        };
        if let Some(a) = addr {
            created.insert(i, a);
        }
        let truncated = out.len() > MAX_OUTPUT_BYTES;
        let shown = &out[..out.len().min(MAX_OUTPUT_BYTES)];
        steps.push(StepReport {
            kind: kind.to_string(),
            status: if ok { "0x1" } else { "0x0" }.to_string(),
            to: to_label,
            contract_address: addr.map(|a| format!("{a:#x}")),
            gas_used: format!("0x{gas:x}"),
            input: hex0x(data),
            value: value.to_string(),
            // A create's output is the runtime code; report its size instead of the code.
            output: if kind == "create" && ok {
                String::new()
            } else {
                hex0x(shown)
            },
            output_truncated: truncated && !(kind == "create" && ok),
            error,
            logs,
            precompiles_touched: touches(&tracer.hits, hardened),
        });
    }

    let touched = touches(&all_hits, hardened);
    let unavailable_touched = touched
        .iter()
        .filter(|t| t.coverage == Coverage::Unavailable)
        .map(|t| t.address.clone())
        .collect();
    let first = steps.first().ok_or_else(|| err("plan: no steps"))?.clone();
    Ok(Report {
        engine: ENGINE.to_string(),
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        schema: REPORT_SCHEMA,
        chain_id: cfg.chain_id,
        fork_block: cfg.block.number,
        simulated_block: height,
        state_source: cfg.source.clone(),
        sender: format!("{:#x}", plan.from),
        balance_overrides: overrides,
        semantics: Semantics {
            spec_id: "CANCUN".into(),
            gas_price_in_evm: 0,
            value_semantics: "revmAuthoritative".into(),
            contract_nonces: "eip161".into(),
            pba_hardened: hardened,
            pba_hardening_height: cfg.hardening_height,
            pba_hardening_source: cfg.hardening_source.clone(),
            commd_fold_verify_linked: citrate_execution::build_features::COMMD_FOLD_VERIFY,
            halo2_verifier_linked: citrate_execution::build_features::HALO2_SUBSTRATE,
        },
        status: first.status.clone(),
        contract_address: first.contract_address.clone(),
        gas_used: first.gas_used.clone(),
        all_steps_succeeded: steps.iter().all(|s| s.status == "0x1"),
        steps,
        precompiles: PrecompileReport {
            real: table::real_addresses(hardened),
            table: table::table(hardened),
            touched,
            unavailable_touched,
        },
    })
}
