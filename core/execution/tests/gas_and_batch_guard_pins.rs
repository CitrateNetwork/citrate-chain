//! Pins for executor gas-accounting and batch-execution guards.
//!
//! - `ExecutionContext::use_gas` computes the new total with a checked add, so
//!   a charge that would overflow `u64` is rejected as out-of-gas instead of
//!   wrapping to a small total that passes the limit check. Pinned both on the
//!   method and at a real call site: a model runtime that reports an absurd
//!   compute-gas figure on the legacy (pre-activation) inference path.
//! - `ParallelExecutor::execute_batch_with` fails the whole batch on the first
//!   transaction error, rather than dropping the failing transaction from the
//!   receipt set.
//!
//! No activation height is set in this file, so the legacy inference path is
//! the one that runs.

use std::sync::Arc;

use async_trait::async_trait;
use citrate_consensus::types::{Block, BlockBuilder, Hash, PublicKey, Signature, Transaction};
use citrate_execution::executor::{ExecutionContext, InferenceService};
use citrate_execution::parallel::ParallelExecutor;
use citrate_execution::types::{
    AccessPolicy, Address, ExecutionError, ModelId, ModelMetadata, ModelState, UsageStats,
};
use citrate_execution::{address_utils, Executor, StateDB};
use primitive_types::U256;

fn block_at(height: u64) -> Block {
    BlockBuilder::new()
        .hash(Hash::new([height as u8; 32]))
        .parent(Hash::default())
        .height(height)
        .timestamp(1_000_000 + height)
        .build_unhashed()
}

// ---------------------------------------------------------------------------
// use_gas overflow
// ---------------------------------------------------------------------------

#[test]
fn use_gas_rejects_a_charge_that_would_overflow() {
    let blk = block_at(1);
    let tx = Transaction {
        gas_limit: 1_000_000,
        ..Default::default()
    };
    let mut ctx = ExecutionContext::new(&blk, &tx);
    ctx.gas_limit = 1_000_000;
    ctx.use_gas(21_000).expect("ordinary charge fits");
    assert_eq!(ctx.gas_used, 21_000);

    let err = ctx
        .use_gas(u64::MAX - 1_000)
        .expect_err("a charge whose sum overflows u64 must be refused");
    assert!(matches!(err, ExecutionError::OutOfGas), "got {err:?}");
    assert_eq!(
        ctx.gas_used, 21_000,
        "a refused charge leaves gas_used unchanged"
    );

    // The exact limit is still accepted; one more unit is not.
    ctx.use_gas(1_000_000 - 21_000)
        .expect("charge up to the limit");
    assert!(matches!(ctx.use_gas(1), Err(ExecutionError::OutOfGas)));
}

/// A model runtime that reports a compute-gas figure close to `u64::MAX`.
struct AbsurdGasRuntime;

#[async_trait]
impl InferenceService for AbsurdGasRuntime {
    async fn run_inference(
        &self,
        _model_id: ModelId,
        _input: Vec<u8>,
        _max_gas: u64,
    ) -> Result<(Vec<u8>, u64, Address, U256, Option<Vec<u8>>), ExecutionError> {
        Ok((
            vec![1, 2, 3],
            u64::MAX - 1_000,
            Address([0xA1; 20]),
            U256::zero(),
            None,
        ))
    }
}

fn model_id() -> ModelId {
    ModelId(Hash::new([0x4D; 32]))
}

fn sender_key() -> PublicKey {
    PublicKey::new([0x5A; 32])
}

#[tokio::test]
async fn inference_with_an_overflowing_gas_report_does_not_succeed() {
    let state = Arc::new(StateDB::new());
    let from = address_utils::normalize_address(&sender_key());
    state
        .accounts
        .set_balance(from, U256::from(10u64).pow(U256::from(21u64)));
    state
        .register_model(
            model_id(),
            ModelState {
                owner: Address([0xAA; 20]),
                model_hash: Hash::new([0x01; 32]),
                version: 1,
                metadata: ModelMetadata::default(),
                access_policy: AccessPolicy::Public,
                usage_stats: UsageStats::default(),
            },
        )
        .expect("register model");
    let executor = Executor::new(state).with_inference_service(Arc::new(AbsurdGasRuntime));

    let mut data = vec![0x02, 0x00, 0x00, 0x00];
    data.extend_from_slice(model_id().0.as_bytes());
    data.extend_from_slice(b"prompt");
    let tx = Transaction {
        hash: Hash::new([0x19; 32]),
        nonce: 0,
        from: sender_key(),
        to: Some(PublicKey::new([0x77; 32])),
        value: 0,
        gas_limit: 2_000_000,
        gas_price: 1_000_000_000,
        data,
        signature: Signature::new([1; 64]),
        chain_id: Some(40204),
        ..Default::default()
    };

    let receipt = executor
        .execute_transaction(&block_at(10), &tx)
        .await
        .expect("the transaction is processed (a failed receipt, not a validation error)");
    assert!(
        !receipt.status,
        "a compute-gas report that overflows the gas total must fail the tx, not wrap and pass"
    );
    assert!(
        receipt.gas_used <= tx.gas_limit,
        "charged gas {} exceeds the tx gas limit {}",
        receipt.gas_used,
        tx.gas_limit
    );
}

// ---------------------------------------------------------------------------
// ParallelExecutor: all-or-nothing
// ---------------------------------------------------------------------------

fn pubkey(seed: u8) -> PublicKey {
    let mut b = [0u8; 32];
    b[0] = seed;
    PublicKey::new(b)
}

fn transfer(from: PublicKey, to: PublicKey, value: u128, hash_seed: u8) -> Transaction {
    let mut h = [0u8; 32];
    h[0] = hash_seed;
    h[1] = from.0[0];
    Transaction {
        hash: Hash::new(h),
        nonce: 0,
        from,
        to: Some(to),
        value,
        gas_limit: 100_000,
        gas_price: 1,
        data: vec![],
        signature: Signature::new([0u8; 64]),
        ..Default::default()
    }
}

#[tokio::test]
async fn parallel_batch_fails_whole_batch_when_one_tx_errors() {
    let state = Arc::new(StateDB::new());
    let executor = Arc::new(Executor::new(state));
    let funded = pubkey(1);
    let unfunded = pubkey(3);
    executor.set_balance(
        &address_utils::normalize_address(&funded),
        U256::from(10_000_000u64),
    );

    let batch = vec![
        transfer(funded, pubkey(2), 100, 0xA1),
        // No balance for gas: `execute_transaction` returns an error.
        transfer(unfunded, pubkey(4), 100, 0xB2),
    ];

    let res = ParallelExecutor::new()
        .execute_batch_with(executor.clone(), &block_at(1), batch)
        .await;
    match res {
        Err(e) => assert!(
            e.to_string().contains("batch transaction"),
            "error should name the failing batch transaction, got: {e}"
        ),
        Ok(receipts) => panic!(
            "a batch with a failing tx must fail as a whole, got {} receipt(s)",
            receipts.len()
        ),
    }
}
