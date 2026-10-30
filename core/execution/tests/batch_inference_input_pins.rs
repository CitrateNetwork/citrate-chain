//! Pins for the 0x0102 batch-inference input checks, driven through the
//! precompile's dispatch entry with a deployed model in its cache.
//!
//! An empty batch must be refused: without the check the call succeeds,
//! charges zero gas and returns nothing. A batch-size word above `u32` must be
//! refused by name, not truncated to its low 32 bits.

use citrate_execution::inference::metal_runtime::MetalRuntime;
use citrate_execution::precompiles::inference::{addresses, InferencePrecompile};
use citrate_execution::types::Address;
use primitive_types::U256;
use std::sync::Arc;

fn deploy_input(metadata: &[u8], weights: &[u8]) -> Vec<u8> {
    let mut input = Vec::new();
    let mut w = [0u8; 32];
    U256::from(weights.len()).to_big_endian(&mut w);
    input.extend_from_slice(&w);
    let mut m = [0u8; 32];
    U256::from(metadata.len()).to_big_endian(&mut m);
    input.extend_from_slice(&m);
    input.extend_from_slice(metadata);
    input.extend_from_slice(weights);
    input
}

/// A precompile with one deployed model; returns it and the model id.
fn with_model() -> (InferencePrecompile, [u8; 32]) {
    let runtime = Arc::new(MetalRuntime::new().expect("runtime"));
    let mut p = InferencePrecompile::new(runtime);
    let out = p
        .execute(
            &Address(addresses::MODEL_DEPLOY),
            &deploy_input(&[0x01; 16], &[0x02; 64]),
            1_000_000,
        )
        .expect("deploy model");
    let id: [u8; 32] = out.output.try_into().expect("32-byte model id");
    (p, id)
}

fn batch_input(model_id: &[u8; 32], batch_size: U256, payload: &[u8]) -> Vec<u8> {
    let mut input = model_id.to_vec();
    let mut b = [0u8; 32];
    batch_size.to_big_endian(&mut b);
    input.extend_from_slice(&b);
    input.extend_from_slice(payload);
    input
}

#[test]
fn empty_batch_is_refused() {
    let (mut p, id) = with_model();
    let res = p.execute(
        &Address(addresses::BATCH_INFERENCE),
        &batch_input(&id, U256::zero(), &[0u8; 16]),
        1_000_000,
    );
    match res {
        Err(e) => assert!(e.to_string().contains("Empty batch"), "got: {e}"),
        Ok(out) => panic!(
            "an empty batch must be refused, got success with gas_used={}",
            out.gas_used
        ),
    }
}

#[test]
fn batch_size_above_u32_is_refused_by_name() {
    let (mut p, id) = with_model();
    for size in [
        U256::from(1u64) << 32,
        (U256::from(1u64) << 32) + U256::from(1u64),
        U256::MAX,
    ] {
        let res = p.execute(
            &Address(addresses::BATCH_INFERENCE),
            &batch_input(&id, size, &[0u8; 16]),
            u64::MAX,
        );
        let msg = match res {
            Err(e) => e.to_string(),
            Ok(out) => panic!("batch size {size} accepted (gas_used={})", out.gas_used),
        };
        assert!(
            msg.contains("exceeds u32"),
            "batch size {size} must be refused as too large, got: {msg}"
        );
    }
}
