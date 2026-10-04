//! Which Citrate precompiles this fork runs with the node's own code, and which it cannot.
//!
//! The table is derived from `citrate_execution::precompiles` (the list the node's REVM bridge
//! registers) and the execution crate's build features, so it cannot drift from the node:
//!
//! | address | in this fork |
//! |---|---|
//! | the pure families the node bridges into REVM (`PURE_PRECOMPILE_ADDRESSES`: 0x0107–0x0109, 0x010A–0x010F, 0x0110–0x0111, 0x0120, 0x0130, 0x0200–0x0202) | **real**: the same function the node calls, with the same activation flag |
//! | 0x0130 at a hardened height when this build lacks `commd-fold-verify` | **unavailable**: the 40204 node links the live verifier there, this build does not |
//! | the inference family 0x0100–0x0106 | **unavailable**: it needs the hosted model runtime, which the node does not expose to contract code either |
//! | the other reserved slots 0x0112–0x013F, 0x0203–0x0209 | **unavailable**: unassigned |
//! | 0x1000 model, 0x1002 artifact, 0x1003 governance | **unavailable**: the node handles these only as the destination of a top-level transaction, never from contract code |
//!
//! "Unavailable" never means "simulated as success". The fork executes exactly what the node
//! would (below the PBA hardening height a call into an unbridged address reaches an empty
//! account and returns success with no data, on the chain as here; at and above it the call
//! fails). The report flags every touch of an unavailable address so a caller can refuse it.
use serde::Serialize;

/// The node's top-level-transaction precompiles (`Executor::{model,artifact,governance}_
/// precompile_address` in `core/execution/src/executor.rs`). Contract code cannot reach them.
pub const TX_LEVEL_PRECOMPILES: [(u16, &str); 3] = [
    (0x1000, "model"),
    (0x1002, "artifact"),
    (0x1003, "governance"),
];

/// How this fork treats one Citrate precompile address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Coverage {
    /// Executed by the node's own implementation.
    Real,
    /// The fork cannot reproduce what a contract would get on 40204 here.
    Unavailable,
}

/// One row of the table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrecompileRow {
    /// `0x0110`-style short address.
    pub address: String,
    pub coverage: Coverage,
    /// What the address is and why it is covered or not.
    pub note: String,
}

/// The short form `0x%04x` of a Citrate precompile address, if `addr` is one.
pub fn short_address(addr: &[u8; 20]) -> Option<u16> {
    if !addr[..18].iter().all(|b| *b == 0) {
        return None;
    }
    let v = (u16::from(addr[18]) << 8) | u16::from(addr[19]);
    is_citrate_precompile(v).then_some(v)
}

/// Citrate precompile ranges (the node's `PrecompileExecutor::is_precompile` ranges plus the
/// executor's top-level precompiles).
pub fn is_citrate_precompile(v: u16) -> bool {
    (0x0100..=0x013F).contains(&v)
        || (0x0200..=0x0209).contains(&v)
        || TX_LEVEL_PRECOMPILES.iter().any(|(a, _)| *a == v)
}

fn to_short(raw: &[u8; 20]) -> u16 {
    (u16::from(raw[18]) << 8) | u16::from(raw[19])
}

/// The coverage of address `v` at a block where the PBA hardening is (or is not) active.
pub fn coverage(v: u16, hardened: bool) -> (Coverage, String) {
    let bridged = citrate_execution::precompiles::PURE_PRECOMPILE_ADDRESSES
        .iter()
        .any(|raw| to_short(raw) == v);
    if bridged {
        if v == 0x0130 && hardened && !citrate_execution::build_features::COMMD_FOLD_VERIFY {
            return (
                Coverage::Unavailable,
                "0x0130 fold-verify: the 40204 node runs the live verifier at this height; this fork \
                 was built without it (build with --features commd-fold-verify)"
                    .into(),
            );
        }
        let note = match v {
            0x0108 if !citrate_execution::build_features::HALO2_SUBSTRATE => {
                "node implementation; fails closed (SubstrateAbsent), as on the default 40204 node build"
            }
            0x0130 if !hardened => "node implementation; fails (feature absent) below the hardening height, as on 40204",
            _ => "node implementation (the node's REVM bridge)",
        };
        return (Coverage::Real, note.into());
    }
    if let Some((_, name)) = TX_LEVEL_PRECOMPILES.iter().find(|(a, _)| *a == v) {
        return (
            Coverage::Unavailable,
            format!(
                "{name} precompile: the node handles it only as a top-level transaction destination; \
                 a contract call reaches an empty account"
            ),
        );
    }
    let what = if (0x0100..=0x0106).contains(&v) {
        "inference family: needs the hosted model runtime, which contract code cannot reach on 40204"
    } else {
        "reserved, unassigned"
    };
    let when = if hardened {
        "calls fail at this height"
    } else {
        "below the hardening height a call returns success with no data, on 40204 as here"
    };
    (Coverage::Unavailable, format!("{what}; {when}"))
}

/// Every Citrate precompile address with its coverage, ascending.
pub fn table(hardened: bool) -> Vec<PrecompileRow> {
    let mut all: Vec<u16> = (0x0100..=0x013F).chain(0x0200..=0x0209).collect();
    all.extend(TX_LEVEL_PRECOMPILES.iter().map(|(a, _)| *a));
    all.into_iter()
        .map(|v| {
            let (coverage, note) = coverage(v, hardened);
            PrecompileRow {
                address: format!("0x{v:04x}"),
                coverage,
                note,
            }
        })
        .collect()
}

/// The addresses this fork runs with real code, as `0x%04x` strings.
pub fn real_addresses(hardened: bool) -> Vec<String> {
    table(hardened)
        .into_iter()
        .filter(|r| r.coverage == Coverage::Real)
        .map(|r| r.address)
        .collect()
}
