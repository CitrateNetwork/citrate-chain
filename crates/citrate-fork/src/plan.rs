//! The dry-run plan: who sends, which fork-only balances to set, and the steps to execute in
//! order (contract creations and calls). Read from JSON.
//!
//! ```json
//! {
//!   "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
//!   "balances": { "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266": "10000000000000000000" },
//!   "steps": [
//!     { "kind": "create", "data": "0x6080…", "value": "0" },
//!     { "kind": "call", "to": "created:0", "data": "0xa0712d68…", "value": "5000000000000000000" }
//!   ]
//! }
//! ```
//!
//! `to` is a 20-byte address or `created:<i>`, the contract created by step `i`. Values are
//! decimal wei. `balances` only changes the fork's in-memory copy (a dry-run sender usually
//! holds no SALT); the report lists every override.
use std::collections::BTreeMap;

use revm::primitives::{Address, U256};
use serde::Deserialize;

use crate::state::ForkError;

/// At most this many steps per plan.
pub const MAX_STEPS: usize = 16;
/// At most this many balance overrides per plan.
pub const MAX_BALANCES: usize = 16;
/// The largest calldata or init code accepted for one step.
pub const MAX_DATA_BYTES: usize = 512 * 1024;
/// Gas limit of each step when the plan names none (the 40204 block gas limit).
pub const DEFAULT_GAS_LIMIT: u64 = 30_000_000;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RawPlan {
    pub from: String,
    #[serde(default)]
    pub balances: BTreeMap<String, String>,
    #[serde(default)]
    pub gas_limit: Option<u64>,
    pub steps: Vec<RawStep>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum RawStep {
    Create {
        data: String,
        #[serde(default)]
        value: Option<String>,
    },
    Call {
        to: String,
        #[serde(default)]
        data: Option<String>,
        #[serde(default)]
        value: Option<String>,
    },
}

/// A call target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Address(Address),
    /// The contract created by step `i` (which must be an earlier create step).
    Created(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Create {
        data: Vec<u8>,
        value: U256,
    },
    Call {
        to: Target,
        data: Vec<u8>,
        value: U256,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub from: Address,
    pub balances: Vec<(Address, U256)>,
    pub gas_limit: u64,
    pub steps: Vec<Step>,
}

fn err(s: impl Into<String>) -> ForkError {
    ForkError(s.into())
}

pub fn parse_address(s: &str, what: &str) -> Result<Address, ForkError> {
    let t = s
        .strip_prefix("0x")
        .ok_or_else(|| err(format!("{what}: expected a 0x-prefixed address")))?;
    if t.len() != 40 {
        return Err(err(format!("{what}: expected 20 bytes")));
    }
    let b = hex::decode(t).map_err(|e| err(format!("{what}: {e}")))?;
    Ok(Address::from_slice(&b))
}

fn parse_hex_data(s: &str, what: &str) -> Result<Vec<u8>, ForkError> {
    let t = s
        .strip_prefix("0x")
        .ok_or_else(|| err(format!("{what}: expected 0x-prefixed hex")))?;
    if t.len() / 2 > MAX_DATA_BYTES {
        return Err(err(format!("{what}: larger than {MAX_DATA_BYTES} bytes")));
    }
    hex::decode(t).map_err(|e| err(format!("{what}: {e}")))
}

fn parse_wei(s: Option<&str>, what: &str) -> Result<U256, ForkError> {
    let Some(s) = s else {
        return Ok(U256::ZERO);
    };
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(err(format!("{what}: expected decimal wei")));
    }
    U256::from_str_radix(s, 10).map_err(|e| err(format!("{what}: {e}")))
}

impl Plan {
    /// Parses and checks a plan.
    pub fn from_json(text: &str) -> Result<Plan, ForkError> {
        let raw: RawPlan = serde_json::from_str(text).map_err(|e| err(format!("plan: {e}")))?;
        Plan::from_raw(raw)
    }

    pub fn from_raw(raw: RawPlan) -> Result<Plan, ForkError> {
        if raw.steps.is_empty() {
            return Err(err("plan: no steps"));
        }
        if raw.steps.len() > MAX_STEPS {
            return Err(err(format!("plan: more than {MAX_STEPS} steps")));
        }
        if raw.balances.len() > MAX_BALANCES {
            return Err(err(format!(
                "plan: more than {MAX_BALANCES} balance overrides"
            )));
        }
        let from = parse_address(&raw.from, "from")?;
        let mut balances = Vec::new();
        for (a, v) in &raw.balances {
            balances.push((
                parse_address(a, "balances key")?,
                parse_wei(Some(v), "balances value")?,
            ));
        }
        let gas_limit = raw.gas_limit.unwrap_or(DEFAULT_GAS_LIMIT);
        if gas_limit == 0 || gas_limit > DEFAULT_GAS_LIMIT {
            return Err(err(format!(
                "plan: gasLimit must be between 1 and {DEFAULT_GAS_LIMIT}"
            )));
        }
        let mut steps = Vec::new();
        for (i, s) in raw.steps.iter().enumerate() {
            let what = format!("step {i}");
            steps.push(match s {
                RawStep::Create { data, value } => {
                    let data = parse_hex_data(data, &what)?;
                    if data.is_empty() {
                        return Err(err(format!("{what}: empty init code")));
                    }
                    Step::Create {
                        data,
                        value: parse_wei(value.as_deref(), &what)?,
                    }
                }
                RawStep::Call { to, data, value } => {
                    let to = match to.strip_prefix("created:") {
                        Some(n) => {
                            let j: usize = n
                                .parse()
                                .map_err(|_| err(format!("{what}: bad created:<step>")))?;
                            match raw.steps.get(j) {
                                Some(RawStep::Create { .. }) if j < i => Target::Created(j),
                                _ => {
                                    return Err(err(format!(
                                        "{what}: created:{j} must name an earlier create step"
                                    )))
                                }
                            }
                        }
                        None => Target::Address(parse_address(to, &what)?),
                    };
                    Step::Call {
                        to,
                        data: match data {
                            Some(d) => parse_hex_data(d, &what)?,
                            None => Vec::new(),
                        },
                        value: parse_wei(value.as_deref(), &what)?,
                    }
                }
            });
        }
        Ok(Plan {
            from,
            balances,
            gas_limit,
            steps,
        })
    }
}
