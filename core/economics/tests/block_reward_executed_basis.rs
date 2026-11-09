// Block reward bonus arms across the supply-hardening activation.
//
// With `executed_basis = true` (at/after `supply_hardening_height`) the bonus
// arms count only transactions that EXECUTED successfully as the qualifying
// operation (from the block's receipts), decay on the base subsidy's halving
// schedule, and are capped at the base subsidy. With `executed_basis = false`
// the legacy rule is kept exactly, so historical blocks replay unchanged.

use citrate_consensus::types::{Block, BlockBuilder, PublicKey, Transaction};
use citrate_economics::rewards::RewardError;
use citrate_economics::{RewardCalculator, RewardConfig, DECIMALS};
use citrate_execution::types::{Address, TransactionReceipt};
use primitive_types::U256;

const INTERVAL: u64 = 2_100_000;

fn wei(n: u64) -> U256 {
    U256::from(n) * U256::from(10).pow(U256::from(DECIMALS))
}

/// The live 40204 bonus parameters: 0.01 SALT per inference, 1 SALT per
/// deployment block, 10 SALT base.
fn calc() -> RewardCalculator {
    RewardCalculator::new(RewardConfig {
        block_reward: 10,
        halving_interval: INTERVAL,
        inference_bonus: 1,
        model_deployment_bonus: 1,
        treasury_percentage: 10,
        treasury_address: Address([0x11; 20]),
    })
}

fn to_pk(seed: u8) -> Option<PublicKey> {
    Some(PublicKey::new([seed; 32]))
}

fn tx(to: Option<PublicKey>, data: Vec<u8>) -> Transaction {
    Transaction {
        to,
        data,
        ..Default::default()
    }
}

fn inference_prefixed(seed: u8) -> Transaction {
    let mut d = vec![0x02, 0x00, 0x00, 0x00];
    d.extend_from_slice(&[seed; 36]);
    tx(to_pk(seed), d)
}

fn receipt(status: bool, to: Option<Address>) -> TransactionReceipt {
    TransactionReceipt {
        tx_hash: Default::default(),
        block_hash: Default::default(),
        block_number: 0,
        from: Address([0xAA; 20]),
        to,
        gas_used: 21_000,
        status,
        logs: vec![],
        output: vec![],
        eth_tx_type: 0,
        effective_gas_price: 0,
        revert_reason: None,
    }
}

fn block(height: u64, txs: Vec<Transaction>) -> Block {
    BlockBuilder::new()
        .height(height)
        .transactions(txs)
        .build_unhashed()
}

/// A plain value transfer: never a bonus.
fn transfer() -> Transaction {
    tx(to_pk(0x42), vec![])
}

#[test]
fn prefixed_calls_that_revert_earn_no_bonus() {
    let txs: Vec<_> = (0..50u8).map(inference_prefixed).collect();
    let rcpts: Vec<_> = txs
        .iter()
        .map(|_| receipt(false, Some(Address([7; 20]))))
        .collect();
    let b = block(10, txs);
    let r = calc()
        .calculate_block_reward(&b, &rcpts, true)
        .expect("valid");
    assert_eq!(r.total_reward, wei(10), "reverted calls earn nothing");
    assert_eq!(r.validator_reward + r.treasury_reward, r.total_reward);
}

#[test]
fn successful_calls_to_inference_precompile_addresses_without_the_operation_earn_nothing() {
    // A successful call to an inference precompile ADDRESS is not an executed
    // inference: it is a plain call. Only the executor's inference operation
    // counts.
    let mut pc = [0u8; 20];
    pc[18] = 0x01;
    pc[19] = 0x01;
    let txs: Vec<_> = (0..20).map(|_| tx(to_pk(0x01), vec![0xde, 0xad])).collect();
    let rcpts: Vec<_> = txs
        .iter()
        .map(|_| receipt(true, Some(Address(pc))))
        .collect();
    let b = block(10, txs);
    let r = calc()
        .calculate_block_reward(&b, &rcpts, true)
        .expect("valid");
    assert_eq!(r.total_reward, wei(10));
}

#[test]
fn reverted_contract_creation_earns_no_deployment_bonus() {
    let txs = vec![tx(None, vec![0x60, 0x00]), transfer()];
    let rcpts = vec![
        receipt(false, None),
        receipt(true, Some(Address([0x42; 20]))),
    ];
    let b = block(10, txs);
    let r = calc()
        .calculate_block_reward(&b, &rcpts, true)
        .expect("valid");
    assert_eq!(r.total_reward, wei(10));
}

#[test]
fn executed_inference_and_deployment_still_earn_their_bonus() {
    let txs = vec![
        inference_prefixed(1),
        inference_prefixed(2),
        tx(None, vec![0x60, 0x00]),
    ];
    let rcpts = vec![
        receipt(true, None),
        receipt(true, None),
        receipt(true, None),
    ];
    let b = block(10, txs);
    let r = calc()
        .calculate_block_reward(&b, &rcpts, true)
        .expect("valid");
    let centi = U256::from(10).pow(U256::from(DECIMALS - 2));
    assert_eq!(r.total_reward, wei(10) + wei(1) + centi * U256::from(2u8));
}

#[test]
fn busy_block_bonus_is_capped_at_the_base_subsidy() {
    // 5,000 successful inferences = 50 SALT of uncapped bonus.
    let txs: Vec<_> = (0..5_000u32).map(|i| inference_prefixed(i as u8)).collect();
    let rcpts: Vec<_> = txs.iter().map(|_| receipt(true, None)).collect();
    let b = block(10, txs);
    let r = calc()
        .calculate_block_reward(&b, &rcpts, true)
        .expect("valid");
    assert_eq!(r.total_reward, wei(20), "total issuance <= 2x base");
}

#[test]
fn bonus_follows_the_halving_schedule_and_ends_with_the_subsidy() {
    let txs = vec![tx(None, vec![0x60, 0x00])];
    let rcpts = vec![receipt(true, None)];
    // One halving: base 5 SALT, deployment bonus 0.5 SALT.
    let r = calc()
        .calculate_block_reward(&block(INTERVAL, txs.clone()), &rcpts, true)
        .expect("valid");
    assert_eq!(r.total_reward, wei(5) + wei(1) / U256::from(2u8));
    // Base halved out (10 >> 4 == 0): nothing is minted, bonus included.
    let r = calc()
        .calculate_block_reward(&block(INTERVAL * 4, txs.clone()), &rcpts, true)
        .expect("valid");
    assert_eq!(r.total_reward, U256::zero());
    let r = calc()
        .calculate_block_reward(&block(INTERVAL * 64, txs), &rcpts, true)
        .expect("valid");
    assert_eq!(r.total_reward, U256::zero());
}

#[test]
fn receipts_that_do_not_match_the_block_are_rejected() {
    let b = block(10, vec![inference_prefixed(1), transfer()]);
    let r = calc().calculate_block_reward(&b, &[receipt(true, None)], true);
    assert_eq!(
        r.map(|r| r.total_reward),
        Err(RewardError::ReceiptMismatch {
            txs: 2,
            receipts: 1
        }),
        "a receipt list that does not match the block must reject it"
    );
}

#[test]
fn below_activation_the_legacy_rule_is_unchanged() {
    // Same reverted-prefix block: the legacy rule (calldata based, uncapped)
    // is what historical blocks were produced with, so it must not move.
    let txs: Vec<_> = (0..50u8).map(inference_prefixed).collect();
    let rcpts: Vec<_> = txs.iter().map(|_| receipt(false, None)).collect();
    let b = block(10, txs);
    let legacy = calc().calculate_reward(&b).expect("valid");
    let gated = calc()
        .calculate_block_reward(&b, &rcpts, false)
        .expect("valid");
    assert_eq!(gated.total_reward, legacy.total_reward);
    assert_eq!(gated.validator_reward, legacy.validator_reward);
    assert_eq!(gated.treasury_reward, legacy.treasury_reward);
    let centi = U256::from(10).pow(U256::from(DECIMALS - 2));
    assert_eq!(legacy.total_reward, wei(10) + centi * U256::from(50u8));
}

#[test]
fn empty_block_reward_is_identical_under_both_rules() {
    let b = block(12_345, vec![]);
    let a = calc()
        .calculate_block_reward(&b, &[], false)
        .expect("valid");
    let c = calc().calculate_block_reward(&b, &[], true).expect("valid");
    assert_eq!(a.total_reward, c.total_reward);
    assert_eq!(a.validator_reward, c.validator_reward);
}
