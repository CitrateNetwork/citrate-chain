//! `LearningPool.joinPool(uint256)` workload.
//!
//! Spec doc 16 listed this class as `stake(uint256)`, but the deployed
//! `LearningPool` contract (`contracts/src/LearningPool.sol`) has no
//! `stake` function. The closest state-mutating, single-argument call
//! is `joinPool(uint256 poolId)` which is `payable` and either joins
//! the pool (depositing `msg.value` as the member stake) or reverts
//! with `PoolNotFound` for unknown pool ids.
//!
//! Either outcome mines a block — reverted txs still count toward
//! inclusion throughput — so for benchmarking this is equivalent to
//! a "touch the LearningPool contract" workload. Production runs that
//! want successful joins must configure `pool_id` to an existing pool
//! and ensure the signer has sufficient balance and a free member
//! slot.

use crate::signers::Signer;
use crate::tx::abi::{encode_uint256_u64, selector};
use crate::tx::legacy::LegacyTx;
use crate::tx::SignedTx;
use crate::workload::{WorkloadClass, WorkloadContext};
use crate::Result;

/// Call `LearningPool.joinPool(uint256 poolId)` with a configurable
/// value and pool id.
#[derive(Debug, Clone)]
pub struct LearningPoolJoin {
    pub pool_id: u64,
    /// `msg.value` forwarded to the payable call. Real joins require
    /// this to be >= the pool's minimum stake; benchmark runs are
    /// fine with 0 (the tx will revert but still be included).
    pub value_wei: u128,
    pub gas_limit: u64,
}

impl LearningPoolJoin {
    /// Default: pool id 1, value 0, 120k gas. Generous gas ceiling
    /// because the revert path still runs several storage reads.
    pub fn default_bench() -> Self {
        Self {
            pool_id: 1,
            value_wei: 0,
            gas_limit: 120_000,
        }
    }
}

impl WorkloadClass for LearningPoolJoin {
    fn name(&self) -> &'static str {
        "learning_pool"
    }

    fn required_contracts(&self) -> &'static [&'static str] {
        &["LearningPool"]
    }

    fn build(&self, ctx: &WorkloadContext, signer: &Signer, nonce: u64) -> Result<SignedTx> {
        let to = ctx.resolve_contract("LearningPool")?;
        let mut data = Vec::with_capacity(4 + 32);
        data.extend_from_slice(&selector("joinPool(uint256)"));
        data.extend_from_slice(&encode_uint256_u64(self.pool_id));

        let tx = LegacyTx {
            nonce,
            gas_price: ctx.gas_price_wei,
            gas_limit: self.gas_limit,
            to: Some(to),
            value: self.value_wei,
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
        k[31] = 0x55;
        Signer::from_key_bytes(&k).expect("signer")
    }

    fn ctx() -> WorkloadContext {
        let json = r#"{
          "chainId": 40204,
          "contracts": [
            { "name": "LearningPool", "address": "0x9a58e44f8dd6fd6a75637a32e6e51c16440996f8" }
          ]
        }"#;
        let t: AddressTable = serde_json::from_str(json).expect("parse");
        WorkloadContext::for_dry_run(40204, 1_000_000_000).with_address_table(Arc::new(t))
    }

    #[test]
    fn name_is_stable() {
        assert_eq!(LearningPoolJoin::default_bench().name(), "learning_pool");
    }

    #[test]
    fn requires_learning_pool() {
        assert_eq!(
            LearningPoolJoin::default_bench().required_contracts(),
            &["LearningPool"]
        );
    }

    #[test]
    fn selector_is_deterministic() {
        // Cross-check: the selector is computed identically every time.
        let a = selector("joinPool(uint256)");
        let b = selector("joinPool(uint256)");
        assert_eq!(a, b);
        assert_ne!(a, [0, 0, 0, 0]);
    }

    #[test]
    fn produces_tx_with_expected_fields() {
        let tx = LearningPoolJoin::default_bench()
            .build(&ctx(), &signer(), 7)
            .expect("build");
        assert_eq!(tx.nonce, 7);
        assert_eq!(tx.sender, signer().address);
        assert!(!tx.raw.is_empty());
    }

    #[test]
    fn changing_pool_id_changes_raw() {
        let mut w = LearningPoolJoin::default_bench();
        let ctx = ctx();
        let a = w.build(&ctx, &signer(), 0).expect("a");
        w.pool_id = 42;
        let b = w.build(&ctx, &signer(), 0).expect("b");
        assert_ne!(a.raw, b.raw);
    }
}
