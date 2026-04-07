//! Simple native-value transfer workload.
//!
//! This is the bedrock workload class: one EOA pays another one wei
//! with 21_000 gas. It exercises the sign → send → receipt pipeline
//! without involving any contract. Every Citrate testnet benchmark
//! run includes it as a baseline against which contract workloads can
//! be compared.

use crate::signers::Signer;
use crate::tx::legacy::LegacyTx;
use crate::tx::SignedTx;
use crate::workload::{WorkloadClass, WorkloadContext};
use crate::Result;

/// Native-value transfer. Default value is 1 wei — the transfer is
/// only there to advance nonce and consume gas, not to move money.
#[derive(Debug, Clone)]
pub struct SimpleTransfer {
    pub recipient: [u8; 20],
    pub value_wei: u128,
    pub gas_limit: u64,
}

impl SimpleTransfer {
    /// Default recipient: `0x00000000000000000000000000000000000000de` — an
    /// EOA-shaped address well outside the precompile range
    /// (0x01..=0x09).
    ///
    /// Why this matters: revm-based chains (including anvil) mark
    /// plain-value transfers to precompile addresses as reverted, so
    /// the naive choice of `0x...01` produces `status = 0x0` receipts
    /// even though gas is consumed and nonce is advanced. The benchmark
    /// would then misreport every tx as a revert. Picking any address
    /// above `0x09` avoids the issue.
    ///
    /// Defaults to 1 wei and 21_000 gas. Real benchmark configs should
    /// override `recipient` with an address they control.
    pub fn default_bench() -> Self {
        let mut to = [0u8; 20];
        to[19] = 0xde;
        Self {
            recipient: to,
            value_wei: 1,
            gas_limit: 21_000,
        }
    }
}

impl WorkloadClass for SimpleTransfer {
    fn name(&self) -> &'static str {
        "simple_transfer"
    }

    fn required_contracts(&self) -> &'static [&'static str] {
        &[]
    }

    fn build(&self, ctx: &WorkloadContext, signer: &Signer, nonce: u64) -> Result<SignedTx> {
        let tx = LegacyTx {
            nonce,
            gas_price: ctx.gas_price_wei,
            gas_limit: self.gas_limit,
            to: Some(self.recipient),
            value: self.value_wei,
            data: Vec::new(),
            chain_id: ctx.chain_id,
        };
        tx.sign(signer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer_with_last_byte(b: u8) -> Signer {
        let mut k = [0u8; 32];
        k[31] = b;
        Signer::from_key_bytes(&k).expect("signer")
    }

    #[test]
    fn name_is_stable() {
        assert_eq!(SimpleTransfer::default_bench().name(), "simple_transfer");
    }

    #[test]
    fn requires_no_contracts() {
        assert!(SimpleTransfer::default_bench().required_contracts().is_empty());
    }

    #[test]
    fn produces_signed_tx_with_matching_sender_and_nonce() {
        let signer = signer_with_last_byte(0x11);
        let workload = SimpleTransfer::default_bench();
        let ctx = WorkloadContext::for_dry_run(40204, 1_000_000_000);
        let signed = workload.build(&ctx, &signer, 42).expect("build");
        assert_eq!(signed.sender, signer.address);
        assert_eq!(signed.nonce, 42);
        assert!(!signed.raw.is_empty());
    }

    #[test]
    fn different_nonces_produce_different_raw_bytes() {
        let signer = signer_with_last_byte(0x22);
        let workload = SimpleTransfer::default_bench();
        let ctx = WorkloadContext::for_dry_run(40204, 1_000_000_000);
        let a = workload.build(&ctx, &signer, 0).expect("0");
        let b = workload.build(&ctx, &signer, 1).expect("1");
        assert_ne!(a.raw, b.raw);
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn different_chain_ids_produce_different_raw_bytes() {
        let signer = signer_with_last_byte(0x33);
        let workload = SimpleTransfer::default_bench();
        let a = workload
            .build(&WorkloadContext::for_dry_run(1, 1_000_000_000), &signer, 0)
            .expect("mainnet");
        let b = workload
            .build(
                &WorkloadContext::for_dry_run(40204, 1_000_000_000),
                &signer,
                0,
            )
            .expect("citrate");
        assert_ne!(a.raw, b.raw);
    }
}
