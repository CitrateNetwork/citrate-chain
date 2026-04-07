//! Workload classes.
//!
//! A workload class is one shape of transaction the benchmark can
//! emit: a simple transfer, an ERC-20 transfer, a LearningPool stake,
//! etc. Each class implements `WorkloadClass` so the runner can ask
//! for a signed transaction without knowing the details.
//!
//! Phase 2 ships `SimpleTransfer` only. Phases 4+ add the
//! address-table-driven contract workloads (`WrappedSALT.transfer`,
//! `LearningPool.stake`, `AIInferenceRouterPortable.submitReceipt`,
//! `ClassroomClusterV1.recordSession`, `Forwarder.forward`).

pub mod transfer;

use std::sync::Arc;

use crate::address_table::AddressTable;
use crate::signers::Signer;
use crate::tx::SignedTx;
use crate::Result;

/// Context every workload needs to build a transaction.
///
/// Phase 2 uses only `chain_id` and `gas_price`. The address table is
/// held here so later phases' contract workloads can look up their
/// target by name without plumbing yet another argument.
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
}

/// One shape of transaction the runner can produce.
///
/// Contract: given `(ctx, signer, nonce)`, return a `SignedTx` whose
/// `sender` equals `signer.address` and whose `nonce` equals the
/// argument. The runner enforces both in tests.
pub trait WorkloadClass: Send + Sync {
    /// Stable class name used in reports and CLI output.
    fn name(&self) -> &'static str;

    /// Names of contracts this workload needs to find in the address
    /// table. The runner verifies these exist before the run starts.
    fn required_contracts(&self) -> &'static [&'static str];

    /// Build and sign one transaction.
    fn build(&self, ctx: &WorkloadContext, signer: &Signer, nonce: u64) -> Result<SignedTx>;
}
