// Model-access fee accounting across the supply-hardening activation height.
//
// From `supply_hardening_height`, the `AccessPolicy::PayPerUse` fee split
// (owner + treasury) and the inference provider fee move value through the
// per-transaction journal, so the payer debit and the credits commit together
// on success and are discarded together on revert. Below the height the legacy
// accounting is kept byte-for-byte so historical blocks replay unchanged.
//
// The activation height is process-wide, so every test here takes `GATE` and
// publishes the height it needs before touching the executor.

use async_trait::async_trait;
use citrate_consensus::types::{
    Block, BlockBuilder, Hash, PublicKey, Signature, Transaction as ConsensusTransaction,
};
use citrate_execution::supply_hardening::set_supply_hardening_height;
use citrate_execution::{address_utils, types::*, Executor, InferenceService, StateDB};
use primitive_types::U256;
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard};

const FUND: u128 = 1_000_000_000_000_000;
const GAS_PRICE: u64 = 1_000_000_000;
const GAS_LIMIT: u64 = 400_000;
const BLOCK_HEIGHT: u64 = 100;
const FEE: u64 = 1_000_000_000_000;
const TREASURY: Address = Address([0x11; 20]);

static GATE: Mutex<()> = Mutex::const_new(());

/// Serialise on the process-wide height and publish `height`.
async fn gate(height: Option<u64>) -> MutexGuard<'static, ()> {
    let g = GATE.lock().await;
    set_supply_hardening_height(height);
    g
}

fn pk(seed: u8) -> PublicKey {
    let mut b = [0u8; 32];
    b[0] = seed;
    PublicKey::new(b)
}

fn addr(seed: u8) -> Address {
    address_utils::normalize_address(&pk(seed))
}

fn block_at(height: u64) -> Block {
    BlockBuilder::new()
        .height(height)
        .timestamp(1_000_000)
        .build_unhashed()
}

fn register_tx(
    owner: PublicKey,
    model_hash: [u8; 32],
    fee: U256,
    nonce: u64,
) -> ConsensusTransaction {
    let metadata = serde_json::json!({
        "name": "Fee Model",
        "version": "1.0.0",
        "description": "PayPerUse test model",
        "framework": "onnx",
        "input_shape": [1, 4],
        "output_shape": [1],
        "size_bytes": 1024
    });
    let meta = serde_json::to_vec(&metadata).expect("metadata serializes");
    let mut data = vec![0x01, 0x00, 0x00, 0x00];
    data.extend_from_slice(&model_hash);
    data.extend_from_slice(&(meta.len() as u32).to_be_bytes());
    data.extend_from_slice(&meta);
    data.push(3); // AccessPolicy::PayPerUse
    let mut fee_bytes = [0u8; 32];
    fee.to_big_endian(&mut fee_bytes);
    data.extend_from_slice(&fee_bytes);
    ConsensusTransaction {
        hash: Hash::new([0x10 + nonce as u8; 32]),
        nonce,
        from: owner,
        to: Some(pk(0x10)),
        value: 0,
        gas_limit: GAS_LIMIT,
        gas_price: GAS_PRICE,
        data,
        signature: Signature::new([0; 64]),
        tx_type: None,
        ..Default::default()
    }
}

fn inference_tx(payer: PublicKey, model_hash: [u8; 32], nonce: u64) -> ConsensusTransaction {
    let mut data = vec![0x02, 0x00, 0x00, 0x00];
    data.extend_from_slice(&model_hash);
    data.extend_from_slice(&[1, 2, 3, 4]);
    ConsensusTransaction {
        hash: Hash::new([0xF0u8.wrapping_add(nonce as u8); 32]),
        nonce,
        from: payer,
        to: Some(pk(0x10)),
        value: 0,
        gas_limit: GAS_LIMIT,
        gas_price: GAS_PRICE,
        data,
        signature: Signature::new([0; 64]),
        tx_type: None,
        ..Default::default()
    }
}

struct ProviderFee {
    provider: Address,
    fee: U256,
}

#[async_trait]
impl InferenceService for ProviderFee {
    async fn run_inference(
        &self,
        _model_id: ModelId,
        _input: Vec<u8>,
        _max_gas: u64,
    ) -> Result<(Vec<u8>, u64, Address, U256, Option<Vec<u8>>), ExecutionError> {
        Ok((vec![0xAA], 0, self.provider, self.fee, None))
    }
}

/// Fails after the executor has already recorded the fee split.
struct Failing;

#[async_trait]
impl InferenceService for Failing {
    async fn run_inference(
        &self,
        _model_id: ModelId,
        _input: Vec<u8>,
        _max_gas: u64,
    ) -> Result<(Vec<u8>, u64, Address, U256, Option<Vec<u8>>), ExecutionError> {
        Err(ExecutionError::InvalidInput)
    }
}

struct Fixture {
    state: Arc<StateDB>,
    exec: Executor,
    owner: PublicKey,
    payer: PublicKey,
    model_hash: [u8; 32],
    fee: U256,
}

impl Fixture {
    /// A PayPerUse model owned by `owner`, registered at `BLOCK_HEIGHT`.
    async fn new(svc: Option<Arc<dyn InferenceService>>, payer_funds: U256, fee: U256) -> Self {
        let state = Arc::new(StateDB::new());
        let exec = match svc {
            Some(s) => Executor::new(state.clone()).with_inference_service(s),
            None => Executor::new(state.clone()),
        };
        let (owner, payer) = (pk(0xBB), pk(0xAA));
        state.accounts.set_balance(addr(0xBB), U256::from(FUND));
        state.accounts.set_balance(addr(0xAA), payer_funds);
        let model_hash = [0x77u8; 32];
        let r = exec
            .execute_transaction(
                &block_at(BLOCK_HEIGHT),
                &register_tx(owner, model_hash, fee, 0),
            )
            .await
            .expect("register executes");
        assert!(r.status, "model registration succeeds");
        Self {
            state,
            exec,
            owner,
            payer,
            model_hash,
            fee,
        }
    }

    fn bal(&self, a: &Address) -> U256 {
        self.state.accounts.get_balance(a)
    }

    fn sum(&self, extra: &[Address]) -> U256 {
        let mut s = self.bal(&addr(0xBB)) + self.bal(&addr(0xAA)) + self.bal(&TREASURY);
        for a in extra {
            s += self.bal(a);
        }
        s
    }

    async fn infer(&self, nonce: u64) -> TransactionReceipt {
        self.exec
            .execute_transaction(
                &block_at(BLOCK_HEIGHT),
                &inference_tx(self.payer, self.model_hash, nonce),
            )
            .await
            .expect("inference tx completes")
    }
}

fn gas_wei(r: &TransactionReceipt) -> U256 {
    U256::from(r.gas_used) * U256::from(GAS_PRICE)
}

/// Active: the payer pays the full fee plus gas, the owner gets 90%, the
/// treasury 10%, and only gas leaves the tracked accounts.
#[tokio::test]
async fn active_fee_split_conserves_supply() {
    let _g = gate(Some(1)).await;
    let f = Fixture::new(None, U256::from(FUND), U256::from(FEE)).await;
    let _ = f.owner;
    let (owner0, payer0, treas0, sum0) = (
        f.bal(&addr(0xBB)),
        f.bal(&addr(0xAA)),
        f.bal(&TREASURY),
        f.sum(&[]),
    );
    let r = f.infer(0).await;
    assert!(r.status, "inference succeeds");
    let gas = gas_wei(&r);
    let treasury_cut = f.fee / U256::from(10u8);
    assert_eq!(f.bal(&addr(0xBB)) - owner0, f.fee - treasury_cut);
    assert_eq!(f.bal(&TREASURY) - treas0, treasury_cut);
    assert_eq!(
        payer0 - f.bal(&addr(0xAA)),
        f.fee + gas,
        "payer pays fee + gas"
    );
    assert_eq!(f.sum(&[]) + gas, sum0, "only gas leaves the tracked set");
}

/// Active: the provider fee is journalled with the rest of the transaction.
#[tokio::test]
async fn active_provider_fee_conserves_supply() {
    let _g = gate(Some(1)).await;
    let provider = addr(0xCC);
    let pfee = U256::from(500_000_000_000u64);
    let f = Fixture::new(
        Some(Arc::new(ProviderFee {
            provider,
            fee: pfee,
        })),
        U256::from(FUND),
        U256::from(FEE),
    )
    .await;
    let (payer0, prov0, sum0) = (f.bal(&addr(0xAA)), f.bal(&provider), f.sum(&[provider]));
    let r = f.infer(0).await;
    assert!(r.status, "inference succeeds");
    let gas = gas_wei(&r);
    assert_eq!(f.bal(&provider) - prov0, pfee, "provider credited");
    assert_eq!(
        payer0 - f.bal(&addr(0xAA)),
        f.fee + pfee + gas,
        "payer pays fee + provider fee + gas"
    );
    assert_eq!(
        f.sum(&[provider]) + gas,
        sum0,
        "only gas leaves the tracked set"
    );
}

/// Active: a transaction that reverts after the split was recorded credits
/// nobody; only gas is burned.
#[tokio::test]
async fn active_reverted_call_discards_fee_split() {
    let _g = gate(Some(1)).await;
    let f = Fixture::new(Some(Arc::new(Failing)), U256::from(FUND), U256::from(FEE)).await;
    let (owner0, treas0, payer0, sum0) = (
        f.bal(&addr(0xBB)),
        f.bal(&TREASURY),
        f.bal(&addr(0xAA)),
        f.sum(&[]),
    );
    let r = f.infer(0).await;
    assert!(!r.status, "inference reverts");
    let gas = U256::from(GAS_LIMIT) * U256::from(GAS_PRICE);
    assert_eq!(f.bal(&addr(0xBB)), owner0, "owner not credited on revert");
    assert_eq!(f.bal(&TREASURY), treas0, "treasury not credited on revert");
    assert_eq!(payer0 - f.bal(&addr(0xAA)), gas, "payer only burns gas");
    assert_eq!(f.sum(&[]) + gas, sum0, "supply conserved on revert");
}

/// Active: a payer whose balance covers one paid call (plus gas for both)
/// issues two in a row. The fees credited never exceed what the payer was
/// debited, and the total is conserved.
#[tokio::test]
async fn active_second_paid_call_is_limited_to_the_remaining_balance() {
    let _g = gate(Some(1)).await;
    let gas_budget = U256::from(GAS_LIMIT) * U256::from(GAS_PRICE);
    // The fee dwarfs the gas budget, so the payer can afford it exactly once.
    let fee = gas_budget * U256::from(10u8);
    let funds = fee + gas_budget * U256::from(2u8);
    let f = Fixture::new(None, funds, fee).await;
    let (owner0, treas0, sum0) = (f.bal(&addr(0xBB)), f.bal(&TREASURY), f.sum(&[]));
    let r1 = f.infer(0).await;
    let r2 = f.infer(1).await;
    assert!(r1.status, "first paid call succeeds");
    assert!(!r2.status, "second call cannot pay the fee and reverts");
    let burned = gas_wei(&r1) + U256::from(GAS_LIMIT) * U256::from(GAS_PRICE);
    let credited = (f.bal(&addr(0xBB)) - owner0) + (f.bal(&TREASURY) - treas0);
    assert_eq!(credited, fee, "exactly one fee credited");
    assert_eq!(
        f.sum(&[]) + burned,
        sum0,
        "supply conserved across both calls"
    );
}

/// Below the activation height the legacy accounting is reproduced exactly, so
/// blocks produced before the height replay to the same balances.
#[tokio::test]
async fn below_activation_legacy_accounting_is_unchanged() {
    let _g = gate(Some(BLOCK_HEIGHT + 1)).await;
    let f = Fixture::new(None, U256::from(FUND), U256::from(FEE)).await;
    let (owner0, payer0, treas0) = (f.bal(&addr(0xBB)), f.bal(&addr(0xAA)), f.bal(&TREASURY));
    let r = f.infer(0).await;
    assert!(r.status, "inference succeeds");
    let treasury_cut = f.fee / U256::from(10u8);
    assert_eq!(f.bal(&addr(0xBB)) - owner0, f.fee - treasury_cut);
    assert_eq!(f.bal(&TREASURY) - treas0, treasury_cut);
    assert_eq!(
        payer0 - f.bal(&addr(0xAA)),
        gas_wei(&r),
        "legacy accounting reproduced exactly"
    );
}

/// Unset (every chain that has not scheduled the fork) behaves like
/// below-activation.
#[tokio::test]
async fn unset_activation_keeps_legacy_accounting() {
    let _g = gate(None).await;
    let f = Fixture::new(None, U256::from(FUND), U256::from(FEE)).await;
    let payer0 = f.bal(&addr(0xAA));
    let r = f.infer(0).await;
    assert!(r.status);
    assert_eq!(payer0 - f.bal(&addr(0xAA)), gas_wei(&r));
}
