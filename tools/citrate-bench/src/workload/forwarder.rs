//! `Forwarder.execute(ForwardRequest,bytes)` workload.
//!
//! Spec doc 16 listed this class as `forward(ForwardRequest,bytes)`,
//! but the deployed `Forwarder` contract
//! (`contracts/src/edu/Forwarder.sol`) exposes `execute(...)` for the
//! meta-tx entry point. This workload exercises that call.
//!
//! The function has `onlyRelayer` authorization, so unprivileged
//! signers hit an immediate revert. That is still useful for the
//! benchmark because:
//!
//! 1. The full `(ForwardRequest, bytes)` calldata encoding exercise
//!    is the main cost on the client side.
//! 2. The tx is still included in a block and still contributes to
//!    throughput accounting.
//!
//! Production benches that want the success path must configure a
//! relayer signer with `addRelayer(...)` pre-registered, populate
//! the `ForwardRequest` fields with valid device/session/nonce
//! state, and size the dummy `relayer_signature` to match whatever
//! the real relayer scheme requires.

use crate::signers::Signer;
use crate::tx::abi::{encode_forwarder_execute, ForwardRequestArgs};
use crate::tx::legacy::LegacyTx;
use crate::tx::SignedTx;
use crate::workload::{WorkloadClass, WorkloadContext};
use crate::Result;

/// Call `Forwarder.execute((...tuple...), relayerSignature)`.
#[derive(Debug, Clone)]
pub struct ForwarderExecute {
    pub org_principal_id: [u8; 32],
    pub classroom_id: u64,
    pub meta_nonce: u64,
    pub session_expiry: u64,
    pub device_cert_hash: [u8; 32],
    pub target: [u8; 20],
    pub data: Vec<u8>,
    pub relayer_signature: Vec<u8>,
    pub gas_limit: u64,
}

impl ForwarderExecute {
    /// Default: dummy `orgPrincipalId` / `deviceCertHash` seeded
    /// distinguishably, `classroomId = 1`, `nonce = 0`, far-future
    /// session expiry, target = `0x...de`, empty `data`, empty
    /// relayer signature, 200k gas. Will revert with
    /// `NotAuthorizedRelayer` for unprivileged signers.
    pub fn default_bench() -> Self {
        let mut org = [0u8; 32];
        org[0] = 0x11;
        let mut dev = [0u8; 32];
        dev[0] = 0x22;
        let mut target = [0u8; 20];
        target[19] = 0xde;
        Self {
            org_principal_id: org,
            classroom_id: 1,
            meta_nonce: 0,
            // Session expiry far enough in the future to survive any
            // benchmark window (Y2038 + 4 years).
            session_expiry: 2_200_000_000,
            device_cert_hash: dev,
            target,
            data: Vec::new(),
            relayer_signature: Vec::new(),
            gas_limit: 200_000,
        }
    }
}

impl WorkloadClass for ForwarderExecute {
    fn name(&self) -> &'static str {
        "forwarder"
    }

    fn required_contracts(&self) -> &'static [&'static str] {
        &["Forwarder"]
    }

    fn build(&self, ctx: &WorkloadContext, signer: &Signer, nonce: u64) -> Result<SignedTx> {
        let to = ctx.resolve_contract("Forwarder")?;
        let args = ForwardRequestArgs {
            org_principal_id: self.org_principal_id,
            classroom_id: self.classroom_id,
            nonce: self.meta_nonce,
            session_expiry: self.session_expiry,
            device_cert_hash: self.device_cert_hash,
            target: self.target,
            data: &self.data,
        };
        let data = encode_forwarder_execute(&args, &self.relayer_signature);

        let tx = LegacyTx {
            nonce,
            gas_price: ctx.gas_price_wei,
            gas_limit: self.gas_limit,
            to: Some(to),
            value: 0,
            data,
            chain_id: ctx.chain_id,
        };
        tx.sign(signer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address_table::AddressTable;
    use std::sync::Arc;

    fn signer() -> Signer {
        let mut k = [0u8; 32];
        k[31] = 0x88;
        Signer::from_key_bytes(&k).expect("signer")
    }

    fn ctx() -> WorkloadContext {
        let json = r#"{
          "chainId": 40204,
          "contracts": [
            { "name": "Forwarder", "address": "0xf1eae5dd4a1639922ea610142f7ce51330065b57" }
          ]
        }"#;
        let t: AddressTable = serde_json::from_str(json).expect("parse");
        WorkloadContext::for_dry_run(40204, 1_000_000_000).with_address_table(Arc::new(t))
    }

    #[test]
    fn name_is_stable() {
        assert_eq!(ForwarderExecute::default_bench().name(), "forwarder");
    }

    #[test]
    fn requires_forwarder() {
        assert_eq!(
            ForwarderExecute::default_bench().required_contracts(),
            &["Forwarder"]
        );
    }

    #[test]
    fn produces_tx_with_expected_fields() {
        let tx = ForwarderExecute::default_bench()
            .build(&ctx(), &signer(), 11)
            .expect("build");
        assert_eq!(tx.nonce, 11);
        assert_eq!(tx.sender, signer().address);
        assert!(!tx.raw.is_empty());
    }

    #[test]
    fn changing_meta_nonce_changes_raw() {
        let ctx = ctx();
        let mut w = ForwarderExecute::default_bench();
        let a = w.build(&ctx, &signer(), 0).expect("a");
        w.meta_nonce = 123;
        let b = w.build(&ctx, &signer(), 0).expect("b");
        assert_ne!(a.raw, b.raw);
    }

    #[test]
    fn nonempty_data_is_accepted() {
        let mut w = ForwarderExecute::default_bench();
        w.data = vec![0xca, 0xfe, 0xba, 0xbe];
        let tx = w.build(&ctx(), &signer(), 0).expect("build");
        assert!(!tx.raw.is_empty());
    }
}
