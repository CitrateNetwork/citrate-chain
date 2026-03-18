// Sprint KK/LL: Economics simulation integration tests
//
// These tests exercise the reward calculator, token economics, and dynamic
// pricing under stress and edge conditions: overflow safety, supply
// conservation, and base fee adjustments under varying load.

use primitive_types::U256;

use citrate_consensus::types::*;
use citrate_economics::rewards::{RewardCalculator, RewardConfig};
use citrate_economics::token::{Token, TokenConfig};
use citrate_economics::dynamic_pricing::{
    DynamicPricingConfig, DynamicPricingManager, UtilizationMetrics,
};
use citrate_execution::types::Address;

// ---------------------------------------------------------------------------
// Helper: create a minimal test block at a given height with optional txs
// ---------------------------------------------------------------------------
fn make_block(height: u64, transactions: Vec<Transaction>) -> Block {
    Block {
        header: BlockHeader {
            version: 1,
            block_hash: Hash::new([0; 32]),
            selected_parent_hash: Hash::default(),
            merge_parent_hashes: vec![],
            timestamp: 0,
            height,
            blue_score: 0,
            blue_work: 0,
            pruning_point: Hash::default(),
            proposer_pubkey: PublicKey::new([0; 32]),
            vrf_reveal: VrfProof {
                proof: vec![],
                output: Hash::default(),
            },
            base_fee_per_gas: 0,
            gas_used: 0,
            gas_limit: 30_000_000,
        },
        state_root: Hash::default(),
        tx_root: Hash::default(),
        receipt_root: Hash::default(),
        artifact_root: Hash::default(),
        ghostdag_params: GhostDagParams::default(),
        transactions,
        signature: Signature::new([0; 64]),
        embedded_models: vec![],
        required_pins: vec![],
        learning_embedding: None,
        learning_confidence: None,
        gradient_commitment: None,
    }
}

// ============================================================================
// 1. test_reward_calculation_no_overflow_max_values
// ============================================================================
#[test]
fn test_reward_calculation_no_overflow_max_values() {
    let config = RewardConfig::default();
    let calculator = RewardCalculator::new(config.clone());

    // Height that would cause 64+ halvings
    let extreme_height = config.halving_interval * 65;
    let block = make_block(extreme_height, vec![]);
    let reward = calculator.calculate_reward(&block);

    assert_eq!(reward.total_reward, U256::zero(), "Reward after 64 halvings must be zero");
    assert_eq!(reward.validator_reward, U256::zero());
    assert_eq!(reward.treasury_reward, U256::zero());

    // u64::MAX height — should not panic
    let block_max = make_block(u64::MAX, vec![]);
    let reward_max = calculator.calculate_reward(&block_max);
    assert_eq!(reward_max.total_reward, U256::zero());
}

// ============================================================================
// 2. test_total_supply_conservation
// ============================================================================
#[test]
fn test_total_supply_conservation() {
    let token_config = TokenConfig::default();
    let mut token = Token::new(token_config);
    let validator = Address([1; 20]);

    let reward_config = RewardConfig::default();
    let calculator = RewardCalculator::new(reward_config);

    let mut expected_total_minted = U256::zero();

    // Simulate 100 reward distributions
    for i in 0u64..100 {
        let block = make_block(i, vec![]);
        let reward = calculator.calculate_reward(&block);
        token.mint(&validator, reward.total_reward).unwrap();
        expected_total_minted += reward.total_reward;
    }

    assert_eq!(token.total_minted, expected_total_minted, "Total minted must equal sum of all rewards");
    assert_eq!(token.circulating_supply(), expected_total_minted, "Circulating supply must equal total minted when no burns");
    assert_eq!(token.balance_of(&validator), expected_total_minted, "Validator balance must equal total minted");
}

// ============================================================================
// 3. test_base_fee_adjustment_under_load
// ============================================================================
#[test]
fn test_base_fee_adjustment_under_load() {
    let config = DynamicPricingConfig::default();
    let initial_price = config.base_gas_price;
    let mut pricing = DynamicPricingManager::new(config);

    // Submit several blocks at high utilization (90%)
    for i in 0u64..10 {
        let metrics = UtilizationMetrics {
            block_height: i,
            gas_used: 9_000_000,
            gas_limit: 10_000_000,
            transaction_count: 200,
            ai_operations: 0,
            compute_intensity: 0.0,
        };
        pricing.update_pricing(metrics).unwrap();
    }

    let after_load = pricing.current_gas_price();
    assert!(
        after_load > initial_price,
        "Gas price should increase under sustained high utilization: initial={}, after={}",
        initial_price, after_load
    );

    // Now submit several blocks at low utilization (10%)
    let price_before_low = pricing.current_gas_price();
    for i in 10u64..20 {
        let metrics = UtilizationMetrics {
            block_height: i,
            gas_used: 1_000_000,
            gas_limit: 10_000_000,
            transaction_count: 10,
            ai_operations: 0,
            compute_intensity: 0.0,
        };
        pricing.update_pricing(metrics).unwrap();
    }

    let after_low = pricing.current_gas_price();
    assert!(
        after_low < price_before_low,
        "Gas price should decrease under sustained low utilization: before={}, after={}",
        price_before_low, after_low
    );
}

// ============================================================================
// 4. test_zero_gas_block_decreases_fee
// ============================================================================
#[test]
fn test_zero_gas_block_decreases_fee() {
    let config = DynamicPricingConfig::default();
    let mut pricing = DynamicPricingManager::new(config);

    // Set a baseline with moderate-utilization blocks
    for i in 0u64..5 {
        let metrics = UtilizationMetrics {
            block_height: i,
            gas_used: 7_000_000,
            gas_limit: 10_000_000,
            transaction_count: 100,
            ai_operations: 0,
            compute_intensity: 0.0,
        };
        pricing.update_pricing(metrics).unwrap();
    }

    let price_before = pricing.current_gas_price();

    // Submit an empty block (zero gas used)
    let empty_metrics = UtilizationMetrics {
        block_height: 5,
        gas_used: 0,
        gas_limit: 10_000_000,
        transaction_count: 0,
        ai_operations: 0,
        compute_intensity: 0.0,
    };
    pricing.update_pricing(empty_metrics).unwrap();

    let price_after = pricing.current_gas_price();
    assert!(
        price_after <= price_before,
        "Empty block should not increase gas price: before={}, after={}",
        price_before, price_after
    );
}

// ============================================================================
// 5. test_full_gas_block_increases_fee
// ============================================================================
#[test]
fn test_full_gas_block_increases_fee() {
    let config = DynamicPricingConfig::default();
    let mut pricing = DynamicPricingManager::new(config);

    // Fill the sliding window with full blocks so the average utilization
    // is consistently above the target (70%). The pricing manager uses a
    // windowed average, so a single full block among moderate blocks may
    // not push the average above target.
    for i in 0u64..20 {
        let metrics = UtilizationMetrics {
            block_height: i,
            gas_used: 10_000_000,
            gas_limit: 10_000_000,
            transaction_count: 500,
            ai_operations: 0,
            compute_intensity: 0.0,
        };
        pricing.update_pricing(metrics).unwrap();
    }

    let price_after_full = pricing.current_gas_price();
    let initial_base = DynamicPricingConfig::default().base_gas_price;

    assert!(
        price_after_full > initial_base,
        "Sustained full blocks should increase gas price above initial: initial={}, after={}",
        initial_base, price_after_full
    );
}
