//! `WrappedSALT.transfer(address,uint256)` workload.
//!
//! ERC-20 style transfer against the deployed `WrappedSALT` contract.
//! The benchmark signer must have a non-zero WrappedSALT balance for
//! the transfer to succeed on-chain — signers without a balance still
//! exercise the submission path but their txs revert with "insufficient
//! balance", which the `effective_mix` metric attributes to
//! `wrapped_salt` regardless of receipt status.
//!
//! Data layout:
//!
//! ```text
//!   selector (4)  = 0xa9059cbb  ("transfer(address,uint256)")
//!   recipient (32) = left-padded address
//!   amount    (32) = big-endian uint256
//! ```

use crate::signers::Signer;
use crate::tx::abi::{encode_address, encode_uint256_u128, selector};
use crate::tx::legacy::LegacyTx;
use crate::tx::SignedTx;
use crate::workload::{WorkloadClass, WorkloadContext};
use crate::Result;

/// ERC-20 transfer against `WrappedSALT`.
#[derive(Debug, Clone)]
pub struct WrappedSaltTransfer {
    /// Amount (in wei units of the ERC-20, i.e., 1e18 per token) to
    /// transfer. 1 keeps the operation minimal; production benches
    /// should use a small value the signer holds.
    pub amount_wei: u128,
    /// Recipient of the transfer. Defaults to an EOA-shaped dead
    /// address via `default_bench`.
    pub recipient: [u8; 20],
    pub gas_limit: u64,
}

impl WrappedSaltTransfer {
    /// Default: 1-wei transfer to `0x...de`, 80_000 gas. The 80k
    /// ceiling comfortably covers a successful ERC-20 transfer (≈50k
    /// when the destination slot is already warm) plus the bench's
    /// preferred headroom for variability.
    pub fn default_bench() -> Self {
        let mut to = [0u8; 20];
        to[19] = 0xde;
        Self {
            amount_wei: 1,
            recipient: to,
            gas_limit: 80_000,
        }
    }
}

impl WorkloadClass for WrappedSaltTransfer {
    fn name(&self) -> &'static str {
        "wrapped_salt"
    }

    fn required_contracts(&self) -> &'static [&'static str] {
        &["WrappedSALT"]
    }

    fn build(&self, ctx: &WorkloadContext, signer: &Signer, nonce: u64) -> Result<SignedTx> {
        let to = ctx.resolve_contract("WrappedSALT")?;
        let mut data = Vec::with_capacity(4 + 64);
        data.extend_from_slice(&selector("transfer(address,uint256)"));
        data.extend_from_slice(&encode_address(&self.recipient));
        data.extend_from_slice(&encode_uint256_u128(self.amount_wei));

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
        k[31] = 0x44;
        Signer::from_key_bytes(&k).expect("signer")
    }

    fn ctx_with_wrapped_salt() -> WorkloadContext {
        let json = r#"{
          "chainId": 40204,
          "contracts": [
            { "name": "WrappedSALT", "address": "0x1f73bb479f397a34b5e3145e51d25bc5007273bf" }
          ]
        }"#;
        let t: AddressTable = serde_json::from_str(json).expect("parse");
        WorkloadContext::for_dry_run(40204, 1_000_000_000).with_address_table(Arc::new(t))
    }

    #[test]
    fn name_is_stable() {
        assert_eq!(WrappedSaltTransfer::default_bench().name(), "wrapped_salt");
    }

    #[test]
    fn requires_wrapped_salt() {
        assert_eq!(
            WrappedSaltTransfer::default_bench().required_contracts(),
            &["WrappedSALT"]
        );
    }

    #[test]
    fn errors_without_address_table() {
        let ctx = WorkloadContext::for_dry_run(40204, 1);
        let err = WrappedSaltTransfer::default_bench().build(&ctx, &signer(), 0);
        assert!(err.is_err());
    }

    #[test]
    fn produces_tx_with_expected_fields() {
        let ctx = ctx_with_wrapped_salt();
        let tx = WrappedSaltTransfer::default_bench()
            .build(&ctx, &signer(), 3)
            .expect("build");
        assert_eq!(tx.nonce, 3);
        assert_eq!(tx.sender, signer().address);
        assert!(!tx.raw.is_empty());
    }

    #[test]
    fn changing_recipient_changes_raw() {
        let ctx = ctx_with_wrapped_salt();
        let mut w = WrappedSaltTransfer::default_bench();
        let a = w.build(&ctx, &signer(), 0).expect("a");
        w.recipient[19] = 0xaa;
        let b = w.build(&ctx, &signer(), 0).expect("b");
        assert_ne!(a.raw, b.raw);
    }

    #[test]
    fn default_class_roster_returns_own_name() {
        let w = WrappedSaltTransfer::default_bench();
        assert_eq!(w.class_roster(), vec!["wrapped_salt"]);
    }
}
