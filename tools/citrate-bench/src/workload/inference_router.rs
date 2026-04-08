//! `AIInferenceRouterPortable.requestInference(bytes32,bytes32,uint256)` workload.
//!
//! Spec doc 16 listed this class as `submitReceipt(...)`, but the
//! deployed `AIInferenceRouterPortable` contract
//! (`contracts/src/edu/ai-gateway/AIInferenceRouterPortable.sol`) has
//! no `submitReceipt` function — requests land via `requestInference`
//! and workers call back with `fulfillInference`. The client-driven
//! entry point is `requestInference`, so that is what this workload
//! exercises.
//!
//! The function is `payable` and reverts with `InsufficientPayment`
//! if `msg.value < maxPrice`, so we set `maxPrice = 0` and attach
//! `value = 0`. It will then try `registry.getModelHash(modelId)`,
//! which reverts for the all-zero dummy `modelId` — the bench still
//! counts the inclusion.
//!
//! Data layout:
//!
//! ```text
//!   selector (4) = keccak256("requestInference(bytes32,bytes32,uint256)")[..4]
//!   modelId          (32, bytes32)
//!   inputCommitment  (32, bytes32, must be non-zero per contract)
//!   maxPrice         (32, uint256)
//! ```
//!
//! `inputCommitment` must be non-zero (the contract reverts with
//! `ZeroCommitment` otherwise), so we put a sentinel `0x01` in the
//! low byte of the default commitment.

use crate::signers::Signer;
use crate::tx::abi::{encode_bytes32, encode_uint256_u128, selector};
use crate::tx::legacy::LegacyTx;
use crate::tx::SignedTx;
use crate::workload::{WorkloadClass, WorkloadContext};
use crate::Result;

/// Call `requestInference(modelId, inputCommitment, maxPrice)`.
#[derive(Debug, Clone)]
pub struct InferenceRouterRequest {
    pub model_id: [u8; 32],
    pub input_commitment: [u8; 32],
    pub max_price_wei: u128,
    pub value_wei: u128,
    pub gas_limit: u64,
}

impl InferenceRouterRequest {
    /// Default: dummy `modelId`, non-zero `inputCommitment`, zero
    /// price, 150k gas. Will revert with `ModelNotRegistered` but
    /// still land in a block.
    pub fn default_bench() -> Self {
        let model_id = [0u8; 32];
        let mut input_commitment = [0u8; 32];
        input_commitment[31] = 0x01;
        Self {
            model_id,
            input_commitment,
            max_price_wei: 0,
            value_wei: 0,
            gas_limit: 150_000,
        }
    }
}

impl WorkloadClass for InferenceRouterRequest {
    fn name(&self) -> &'static str {
        "inference_router"
    }

    fn required_contracts(&self) -> &'static [&'static str] {
        &["AIInferenceRouterPortable"]
    }

    fn build(&self, ctx: &WorkloadContext, signer: &Signer, nonce: u64) -> Result<SignedTx> {
        let to = ctx.resolve_contract("AIInferenceRouterPortable")?;
        let mut data = Vec::with_capacity(4 + 96);
        data.extend_from_slice(&selector(
            "requestInference(bytes32,bytes32,uint256)",
        ));
        data.extend_from_slice(&encode_bytes32(&self.model_id));
        data.extend_from_slice(&encode_bytes32(&self.input_commitment));
        data.extend_from_slice(&encode_uint256_u128(self.max_price_wei));

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
        k[31] = 0x66;
        Signer::from_key_bytes(&k).expect("signer")
    }

    fn ctx() -> WorkloadContext {
        let json = r#"{
          "chainId": 40204,
          "contracts": [
            { "name": "AIInferenceRouterPortable", "address": "0x516380b0acef9a9541641c85dbe0bf89b3e56977" }
          ]
        }"#;
        let t: AddressTable = serde_json::from_str(json).expect("parse");
        WorkloadContext::for_dry_run(40204, 1_000_000_000).with_address_table(Arc::new(t))
    }

    #[test]
    fn name_is_stable() {
        assert_eq!(
            InferenceRouterRequest::default_bench().name(),
            "inference_router"
        );
    }

    #[test]
    fn requires_ai_inference_router() {
        assert_eq!(
            InferenceRouterRequest::default_bench().required_contracts(),
            &["AIInferenceRouterPortable"]
        );
    }

    #[test]
    fn default_commitment_is_nonzero() {
        let w = InferenceRouterRequest::default_bench();
        assert!(w.input_commitment.iter().any(|&b| b != 0));
    }

    #[test]
    fn produces_tx_with_expected_fields() {
        let tx = InferenceRouterRequest::default_bench()
            .build(&ctx(), &signer(), 2)
            .expect("build");
        assert_eq!(tx.nonce, 2);
        assert_eq!(tx.sender, signer().address);
        assert!(!tx.raw.is_empty());
    }
}
