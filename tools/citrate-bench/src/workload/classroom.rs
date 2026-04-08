//! `ClassroomClusterV1.transferStudent(address,uint256,uint256)` workload.
//!
//! Spec doc 16 listed this class as `recordSession(...)`, but the
//! deployed `ClassroomClusterV1` contract
//! (`contracts/src/edu/ClassroomClusterV1.sol`) does not expose a
//! `recordSession` entry point. The closest state-mutating call with
//! a well-defined signature is `transferStudent(address student,
//! uint256 fromClassroom, uint256 toClassroom)`. It enforces
//! role-based authorization, so unprivileged signers will hit the
//! access-control revert path — which is fine for a benchmark: the
//! tx is still included in a block and still advances nonce.
//!
//! Data layout:
//!
//! ```text
//!   selector (4) = keccak256("transferStudent(address,uint256,uint256)")[..4]
//!   student         (32, address, left-padded)
//!   fromClassroom   (32, uint256)
//!   toClassroom     (32, uint256)
//! ```

use crate::signers::Signer;
use crate::tx::abi::{encode_address, encode_uint256_u64, selector};
use crate::tx::legacy::LegacyTx;
use crate::tx::SignedTx;
use crate::workload::{WorkloadClass, WorkloadContext};
use crate::Result;

/// Call `ClassroomClusterV1.transferStudent(student, from, to)`.
#[derive(Debug, Clone)]
pub struct ClassroomTransferStudent {
    pub student: [u8; 20],
    pub from_classroom: u64,
    pub to_classroom: u64,
    pub gas_limit: u64,
}

impl ClassroomTransferStudent {
    /// Default: dummy `student = 0x...de`, `from = 1`, `to = 2`,
    /// 120k gas. Will revert with an access-control error for
    /// unprivileged signers.
    pub fn default_bench() -> Self {
        let mut student = [0u8; 20];
        student[19] = 0xde;
        Self {
            student,
            from_classroom: 1,
            to_classroom: 2,
            gas_limit: 120_000,
        }
    }
}

impl WorkloadClass for ClassroomTransferStudent {
    fn name(&self) -> &'static str {
        "classroom"
    }

    fn required_contracts(&self) -> &'static [&'static str] {
        &["ClassroomClusterV1"]
    }

    fn build(&self, ctx: &WorkloadContext, signer: &Signer, nonce: u64) -> Result<SignedTx> {
        let to = ctx.resolve_contract("ClassroomClusterV1")?;
        let mut data = Vec::with_capacity(4 + 96);
        data.extend_from_slice(&selector("transferStudent(address,uint256,uint256)"));
        data.extend_from_slice(&encode_address(&self.student));
        data.extend_from_slice(&encode_uint256_u64(self.from_classroom));
        data.extend_from_slice(&encode_uint256_u64(self.to_classroom));

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
        k[31] = 0x77;
        Signer::from_key_bytes(&k).expect("signer")
    }

    fn ctx() -> WorkloadContext {
        let json = r#"{
          "chainId": 40204,
          "contracts": [
            { "name": "ClassroomClusterV1", "address": "0xc12dbcdb80ef2ae675315f455210f39a736a373c" }
          ]
        }"#;
        let t: AddressTable = serde_json::from_str(json).expect("parse");
        WorkloadContext::for_dry_run(40204, 1_000_000_000).with_address_table(Arc::new(t))
    }

    #[test]
    fn name_is_stable() {
        assert_eq!(ClassroomTransferStudent::default_bench().name(), "classroom");
    }

    #[test]
    fn requires_classroom_cluster() {
        assert_eq!(
            ClassroomTransferStudent::default_bench().required_contracts(),
            &["ClassroomClusterV1"]
        );
    }

    #[test]
    fn produces_tx_with_expected_fields() {
        let tx = ClassroomTransferStudent::default_bench()
            .build(&ctx(), &signer(), 5)
            .expect("build");
        assert_eq!(tx.nonce, 5);
        assert_eq!(tx.sender, signer().address);
        assert!(!tx.raw.is_empty());
    }

    #[test]
    fn changing_classroom_changes_raw() {
        let ctx = ctx();
        let mut w = ClassroomTransferStudent::default_bench();
        let a = w.build(&ctx, &signer(), 0).expect("a");
        w.from_classroom = 99;
        let b = w.build(&ctx, &signer(), 0).expect("b");
        assert_ne!(a.raw, b.raw);
    }
}
