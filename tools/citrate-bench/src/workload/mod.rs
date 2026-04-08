//! Workload classes.
//!
//! A workload class is one shape of transaction the benchmark can
//! emit: a simple transfer, an ERC-20 transfer, a LearningPool join,
//! etc. Each class implements `WorkloadClass` so the runner can ask
//! for a signed transaction without knowing the details.
//!
//! Phase 2 shipped `SimpleTransfer`. Phase 4 adds the address-table-
//! driven contract workloads (`WrappedSaltTransfer`,
//! `LearningPoolJoin`, `InferenceRouterRequest`,
//! `ClassroomTransferStudent`, `ForwarderExecute`) and `MixedWorkload`
//! which composes multiple classes under a deterministic weighted
//! schedule.

pub mod classroom;
pub mod forwarder;
pub mod inference_router;
pub mod learning_pool;
pub mod mix;
pub mod transfer;
pub mod wrapped_salt;

use std::sync::Arc;

use crate::address_table::AddressTable;
use crate::signers::Signer;
use crate::tx::SignedTx;
use crate::{Error, Result};

/// Context every workload needs to build a transaction.
///
/// Phase 2 used only `chain_id` and `gas_price_wei`. Phase 4 wires
/// the address table: contract workloads look up their target by
/// name (`"WrappedSALT"`, `"Forwarder"`, …) without plumbing another
/// argument through.
#[derive(Debug, Clone)]
pub struct WorkloadContext {
    pub chain_id: u64,
    pub gas_price_wei: u128,
    pub address_table: Option<Arc<AddressTable>>,
}

impl WorkloadContext {
    pub fn for_dry_run(chain_id: u64, gas_price_wei: u128) -> Self {
        Self {
            chain_id,
            gas_price_wei,
            address_table: None,
        }
    }

    pub fn with_address_table(mut self, table: Arc<AddressTable>) -> Self {
        self.address_table = Some(table);
        self
    }

    /// Resolve a contract name via the address table into its 20-byte
    /// address. Errors cleanly if the table is missing or the name is
    /// not found.
    pub fn resolve_contract(&self, name: &str) -> Result<[u8; 20]> {
        let table = self
            .address_table
            .as_ref()
            .ok_or_else(|| Error::Workload(format!("{name}: no address table bound")))?;
        let entry = table
            .find(name)
            .ok_or_else(|| Error::Workload(format!("{name}: not in address table")))?;
        parse_eth_address(&entry.address)
            .map_err(|e| Error::Workload(format!("{name}: address parse: {e}")))
    }
}

/// Parse a `0x`-prefixed (or bare) 40-hex-char address. Used by
/// workload contexts and test helpers alike.
fn parse_eth_address(s: &str) -> std::result::Result<[u8; 20], String> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    if stripped.len() != 40 {
        return Err(format!("address must be 40 hex chars, got {}", stripped.len()));
    }
    let bytes = hex::decode(stripped).map_err(|e| format!("hex: {e}"))?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// One shape of transaction the runner can produce.
///
/// Contract: given `(ctx, signer, nonce)`, return a `SignedTx` whose
/// `sender` equals `signer.address` and whose `nonce` equals the
/// argument. The runner enforces both in tests.
///
/// Workloads with sub-classes (e.g., `MixedWorkload`) override
/// `build_with_class` to return the name of the concrete class that
/// actually built the tx, so the runner can record an `effective_mix`
/// metric. The default implementation just returns `self.name()`,
/// which is correct for any leaf class.
pub trait WorkloadClass: Send + Sync {
    /// Stable class name used in reports and CLI output.
    fn name(&self) -> &'static str;

    /// Names of contracts this workload needs to find in the address
    /// table. `SimpleTransfer` returns an empty slice. Composite
    /// workloads (`MixedWorkload`) return an empty slice and rely on
    /// `aggregate_required_contracts` for the full set.
    fn required_contracts(&self) -> &'static [&'static str];

    /// Build and sign one transaction.
    fn build(&self, ctx: &WorkloadContext, signer: &Signer, nonce: u64) -> Result<SignedTx>;

    /// Build + report the concrete class name that produced the tx.
    ///
    /// Default implementation returns `(self.build(...)?, self.name())`,
    /// which is correct for leaf classes. `MixedWorkload` overrides
    /// this to dispatch into a sub-class and return that sub-class's
    /// name.
    fn build_with_class(
        &self,
        ctx: &WorkloadContext,
        signer: &Signer,
        nonce: u64,
    ) -> Result<(SignedTx, &'static str)> {
        let tx = self.build(ctx, signer, nonce)?;
        Ok((tx, self.name()))
    }

    /// Names of every concrete class this workload can produce txs
    /// for. Leaf classes return `[self.name()]`; `MixedWorkload`
    /// returns the union over its sub-classes. Used by the runner to
    /// pre-allocate per-class counters.
    fn class_roster(&self) -> Vec<&'static str> {
        vec![self.name()]
    }

    /// Union of every contract name needed across this workload and
    /// any sub-workloads. Leaf classes default to `required_contracts`.
    /// Composite workloads (`MixedWorkload`) override to flatmap
    /// sub-classes.
    fn aggregate_required_contracts(&self) -> Vec<&'static str> {
        self.required_contracts().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address_table::AddressTable;

    fn table_json() -> String {
        r#"{
          "chainId": 40204,
          "contracts": [
            { "name": "WrappedSALT", "address": "0x1111111111111111111111111111111111111111" },
            { "name": "Forwarder",   "address": "0x2222222222222222222222222222222222222222" }
          ]
        }"#
        .to_string()
    }

    fn table() -> Arc<AddressTable> {
        let t: AddressTable = serde_json::from_str(&table_json()).expect("parse");
        Arc::new(t)
    }

    #[test]
    fn context_resolves_contract_by_name() {
        let ctx = WorkloadContext::for_dry_run(40204, 1).with_address_table(table());
        let addr = ctx.resolve_contract("WrappedSALT").expect("resolve");
        assert_eq!(addr[19], 0x11);
    }

    #[test]
    fn context_errors_on_missing_contract() {
        let ctx = WorkloadContext::for_dry_run(40204, 1).with_address_table(table());
        assert!(ctx.resolve_contract("Nowhere").is_err());
    }

    #[test]
    fn context_errors_with_no_table() {
        let ctx = WorkloadContext::for_dry_run(40204, 1);
        assert!(ctx.resolve_contract("WrappedSALT").is_err());
    }
}
