// WP-R-B001 — Tripwire regression tests for audit finding CHAIN-B-B001.
//
// CHAIN-B-B001 (CRITICAL, money-mint): the `AccessPolicy::PayPerUse` inference
// fee was debited from the payer with a DIRECT `state_db.accounts.transfer`,
// which is invisible to the per-tx MVCC journal. At `drain_journal` time the
// journal OVERWRITES the payer's balance with its pending (pre-fee) value, so
// the payer debit is silently un-done while the model owner and protocol
// treasury keep their credits — minting `fee` SALT on every PayPerUse call.
//
// The fix routes the whole fee split (owner + treasury) and the provider fee
// through `journal_transfer`, so the debit and credits live in one journal and
// drain (on success) or discard (on revert) atomically.
//
// These tests assert conservation of supply across a PayPerUse inference call
// and discard-on-revert. They are RED against the pre-fix executor and GREEN
// after. Built entirely on the public `Executor` API.

use async_trait::async_trait;
use citrate_consensus::types::{
    Block, BlockBuilder, Hash, PublicKey, Signature, Transaction as ConsensusTransaction,
};
use citrate_execution::{address_utils, types::*, Executor, InferenceService, StateDB};
use primitive_types::U256;
use std::sync::Arc;

const FUND: u128 = 1_000_000_000_000_000;
const GAS_PRICE: u64 = 1_000_000_000;
const GAS_LIMIT: u64 = 400_000;

fn addr_from_seed(seed: u8) -> Address {
    let mut pk = [0u8; 32];
    pk[0] = seed;
    address_utils::normalize_address(&PublicKey::new(pk))
}

fn pk_from_seed(seed: u8) -> PublicKey {
    let mut pk = [0u8; 32];
    pk[0] = seed;
    PublicKey::new(pk)
}

fn test_block() -> Block {
    BlockBuilder::new()
        .height(100)
        .timestamp(1_000_000)
        .build_unhashed()
}

/// Register a PayPerUse model (magic selector `01 00 00 00`) owned by `owner`.
fn register_payperuse_tx(
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
    let meta_bytes = serde_json::to_vec(&metadata).expect("metadata serializes");

    let mut data = Vec::new();
    data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // registerModel selector
    data.extend_from_slice(&model_hash);
    data.extend_from_slice(&(meta_bytes.len() as u32).to_be_bytes());
    data.extend_from_slice(&meta_bytes);
    data.push(3); // AccessPolicy::PayPerUse
    let mut fee_bytes = [0u8; 32];
    fee.to_big_endian(&mut fee_bytes);
    data.extend_from_slice(&fee_bytes);
    // No artifact CID appended.

    ConsensusTransaction {
        hash: Hash::new([0x10 + nonce as u8; 32]),
        nonce,
        from: owner,
        to: Some(pk_from_seed(0x10)), // ignored by the magic-selector path
        value: 0,
        gas_limit: GAS_LIMIT,
        gas_price: GAS_PRICE,
        data,
        signature: Signature::new([0; 64]),
        tx_type: None,
        ..Default::default()
    }
}

/// Inference request (magic selector `02 00 00 00`) against `model_hash`.
fn inference_tx(payer: PublicKey, model_hash: [u8; 32], nonce: u64) -> ConsensusTransaction {
    let mut data = Vec::new();
    data.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // executeInference selector
    data.extend_from_slice(&model_hash);
    data.extend_from_slice(&[1, 2, 3, 4]); // input bytes

    ConsensusTransaction {
        hash: Hash::new([0xF0 + nonce as u8; 32]),
        nonce,
        from: payer,
        to: Some(pk_from_seed(0x10)),
        value: 0,
        gas_limit: GAS_LIMIT,
        gas_price: GAS_PRICE,
        data,
        signature: Signature::new([0; 64]),
        tx_type: None,
        ..Default::default()
    }
}

/// Inference service that credits a provider fee on success.
struct ProviderFeeInference {
    provider: Address,
    fee: U256,
}

#[async_trait]
impl InferenceService for ProviderFeeInference {
    async fn run_inference(
        &self,
        _model_id: ModelId,
        _input: Vec<u8>,
        _max_gas: u64,
    ) -> Result<(Vec<u8>, u64, Address, U256, Option<Vec<u8>>), ExecutionError> {
        Ok((vec![0xAA], 0, self.provider, self.fee, None))
    }
}

/// Inference service that fails AFTER the executor has recorded the fee split.
struct FailingInference;

#[async_trait]
impl InferenceService for FailingInference {
    async fn run_inference(
        &self,
        _model_id: ModelId,
        _input: Vec<u8>,
        _max_gas: u64,
    ) -> Result<(Vec<u8>, u64, Address, U256, Option<Vec<u8>>), ExecutionError> {
        Err(ExecutionError::InvalidInput)
    }
}

/// Core conservation invariant: after a successful PayPerUse inference the only
/// value that leaves the tracked accounts is the burned gas. Owner gets 90% of
/// the fee, treasury gets 10%, and the payer is debited the FULL fee plus gas.
#[tokio::test]
async fn payperuse_fee_split_conserves_supply() {
    let state_db = Arc::new(StateDB::new());
    let executor = Executor::new(state_db.clone());

    let owner = pk_from_seed(0xBB);
    let owner_addr = addr_from_seed(0xBB);
    let payer = pk_from_seed(0xAA);
    let payer_addr = addr_from_seed(0xAA);
    let treasury_addr = Address([0x11; 20]);

    let fee = U256::from(1_000_000u64);
    let model_hash = [0x77u8; 32];

    state_db.accounts.set_balance(owner_addr, U256::from(FUND));
    state_db.accounts.set_balance(payer_addr, U256::from(FUND));

    let block = test_block();

    let reg = register_payperuse_tx(owner, model_hash, fee, 0);
    let r = executor
        .execute_transaction(&block, &reg)
        .await
        .expect("register executes");
    assert!(r.status, "model registration should succeed");

    let model = state_db
        .get_model(&ModelId(Hash::new(model_hash)))
        .expect("model stored");
    assert_eq!(model.owner, owner_addr);
    assert!(matches!(
        model.access_policy,
        AccessPolicy::PayPerUse { .. }
    ));

    // Snapshot AFTER registration — registration only burned the owner's gas.
    let owner_before = state_db.accounts.get_balance(&owner_addr);
    let payer_before = state_db.accounts.get_balance(&payer_addr);
    let treasury_before = state_db.accounts.get_balance(&treasury_addr);
    let sum_before = owner_before + payer_before + treasury_before;

    let inf = inference_tx(payer, model_hash, 0);
    let receipt = executor
        .execute_transaction(&block, &inf)
        .await
        .expect("inference executes");
    assert!(receipt.status, "inference should succeed");

    let gas_wei = U256::from(receipt.gas_used) * U256::from(GAS_PRICE);

    let owner_after = state_db.accounts.get_balance(&owner_addr);
    let payer_after = state_db.accounts.get_balance(&payer_addr);
    let treasury_after = state_db.accounts.get_balance(&treasury_addr);
    let sum_after = owner_after + payer_after + treasury_after;

    let treasury_cut = fee / U256::from(10u8);
    let owner_cut = fee - treasury_cut;

    assert_eq!(
        owner_after - owner_before,
        owner_cut,
        "owner credited 90% of the fee"
    );
    assert_eq!(
        treasury_after - treasury_before,
        treasury_cut,
        "treasury credited 10% of the fee"
    );
    // The mint bug left the payer paying only gas; the fix debits fee + gas.
    assert_eq!(
        payer_before - payer_after,
        fee + gas_wei,
        "payer debited the full fee plus gas"
    );
    // Supply conservation: only gas left the tracked set. Under CHAIN-B-B001
    // this failed by exactly `fee`.
    assert_eq!(
        sum_after + gas_wei,
        sum_before,
        "total supply conserved (only gas burned)"
    );
}

/// The provider fee (:3787-3790) is on the same journal path and must conserve
/// supply too.
#[tokio::test]
async fn payperuse_provider_fee_conserves_supply() {
    let state_db = Arc::new(StateDB::new());
    let provider_addr = addr_from_seed(0xCC);
    let provider_fee = U256::from(500_000u64);
    let svc = Arc::new(ProviderFeeInference {
        provider: provider_addr,
        fee: provider_fee,
    });
    let executor = Executor::new(state_db.clone()).with_inference_service(svc);

    let owner = pk_from_seed(0xBB);
    let owner_addr = addr_from_seed(0xBB);
    let payer = pk_from_seed(0xAA);
    let payer_addr = addr_from_seed(0xAA);
    let treasury_addr = Address([0x11; 20]);
    let fee = U256::from(1_000_000u64);
    let model_hash = [0x88u8; 32];

    state_db.accounts.set_balance(owner_addr, U256::from(FUND));
    state_db.accounts.set_balance(payer_addr, U256::from(FUND));

    let block = test_block();
    assert!(
        executor
            .execute_transaction(&block, &register_payperuse_tx(owner, model_hash, fee, 0))
            .await
            .expect("register executes")
            .status
    );

    let owner_before = state_db.accounts.get_balance(&owner_addr);
    let payer_before = state_db.accounts.get_balance(&payer_addr);
    let treasury_before = state_db.accounts.get_balance(&treasury_addr);
    let provider_before = state_db.accounts.get_balance(&provider_addr);
    let sum_before = owner_before + payer_before + treasury_before + provider_before;

    let inf = inference_tx(payer, model_hash, 0);
    let receipt = executor
        .execute_transaction(&block, &inf)
        .await
        .expect("inference executes");
    assert!(receipt.status, "inference should succeed");
    let gas_wei = U256::from(receipt.gas_used) * U256::from(GAS_PRICE);

    let owner_after = state_db.accounts.get_balance(&owner_addr);
    let payer_after = state_db.accounts.get_balance(&payer_addr);
    let treasury_after = state_db.accounts.get_balance(&treasury_addr);
    let provider_after = state_db.accounts.get_balance(&provider_addr);
    let sum_after = owner_after + payer_after + treasury_after + provider_after;

    let treasury_cut = fee / U256::from(10u8);
    let owner_cut = fee - treasury_cut;

    assert_eq!(
        provider_after - provider_before,
        provider_fee,
        "provider credited its fee"
    );
    assert_eq!(owner_after - owner_before, owner_cut, "owner credited 90%");
    assert_eq!(
        treasury_after - treasury_before,
        treasury_cut,
        "treasury credited 10%"
    );
    assert_eq!(
        payer_before - payer_after,
        fee + provider_fee + gas_wei,
        "payer debited fee + provider fee + gas"
    );
    assert_eq!(
        sum_after + gas_wei,
        sum_before,
        "total supply conserved (only gas burned)"
    );
}

/// Discard-on-revert: when inference fails AFTER the fee split is recorded, the
/// whole journalled split is discarded — owner and treasury are NOT credited,
/// and only gas is burned. Under CHAIN-B-B001 the DIRECT owner/treasury credits
/// survived the revert (they never lived in the journal), keeping the fee.
#[tokio::test]
async fn payperuse_failed_inference_discards_fee_split() {
    let state_db = Arc::new(StateDB::new());
    let executor =
        Executor::new(state_db.clone()).with_inference_service(Arc::new(FailingInference));

    let owner = pk_from_seed(0xBB);
    let owner_addr = addr_from_seed(0xBB);
    let payer = pk_from_seed(0xAA);
    let payer_addr = addr_from_seed(0xAA);
    let treasury_addr = Address([0x11; 20]);
    let fee = U256::from(1_000_000u64);
    let model_hash = [0x99u8; 32];

    state_db.accounts.set_balance(owner_addr, U256::from(FUND));
    state_db.accounts.set_balance(payer_addr, U256::from(FUND));

    let block = test_block();
    assert!(
        executor
            .execute_transaction(&block, &register_payperuse_tx(owner, model_hash, fee, 0))
            .await
            .expect("register executes")
            .status
    );

    let owner_before = state_db.accounts.get_balance(&owner_addr);
    let payer_before = state_db.accounts.get_balance(&payer_addr);
    let treasury_before = state_db.accounts.get_balance(&treasury_addr);
    let sum_before = owner_before + payer_before + treasury_before;

    let inf = inference_tx(payer, model_hash, 0);
    let receipt = executor
        .execute_transaction(&block, &inf)
        .await
        .expect("tx completes");
    assert!(!receipt.status, "inference tx should revert");

    // A reverted tx burns the full gas budget (no refund) and bumps the nonce.
    let gas_full = U256::from(GAS_LIMIT) * U256::from(GAS_PRICE);

    let owner_after = state_db.accounts.get_balance(&owner_addr);
    let payer_after = state_db.accounts.get_balance(&payer_addr);
    let treasury_after = state_db.accounts.get_balance(&treasury_addr);
    let sum_after = owner_after + payer_after + treasury_after;

    assert_eq!(owner_after, owner_before, "owner not credited on revert");
    assert_eq!(
        treasury_after, treasury_before,
        "treasury not credited on revert"
    );
    assert_eq!(
        payer_before - payer_after,
        gas_full,
        "payer only burned gas on revert"
    );
    assert_eq!(
        sum_after + gas_full,
        sum_before,
        "total supply conserved on revert"
    );
}
