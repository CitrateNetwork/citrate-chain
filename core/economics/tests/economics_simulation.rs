// Sprint KK/LL/LAUNCH: Economics simulation integration tests
//
// These tests exercise the reward calculator, token economics, and dynamic
// pricing under stress and edge conditions: overflow safety, supply
// conservation, and base fee adjustments under varying load.
//
// WP-L.10 adds a comprehensive 10,000-block simulation that verifies:
//   1. total_supply = genesis_supply + minted (conservation)
//   2. base_fee adjusts per EIP-1559 under load
//   3. no overflow at max U256 values
//   4. validator rewards are positive and proportional

use primitive_types::U256;

use citrate_consensus::types::*;
use citrate_economics::rewards::{RewardCalculator, RewardConfig};
use citrate_economics::token::{Token, TokenConfig};
use citrate_economics::dynamic_pricing::{
    DynamicPricingConfig, DynamicPricingManager, UtilizationMetrics,
};
use citrate_economics::genesis::GenesisConfig;
use citrate_economics::latt_to_wei;
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

// ============================================================================
// 6. economic_simulation — Comprehensive 10,000-block simulation (WP-L.10)
//
// Creates an executor-free simulation using Token + RewardCalculator +
// DynamicPricingManager directly. Varying tx load per block (0-100 txs)
// with sinusoidal demand pattern to exercise fee adjustment in both
// directions.
//
// Verifies all four invariants:
//   (a) Supply conservation: total_supply = genesis_supply + minted
//   (b) Base fee adjustment: fee rises under sustained load, drops when load
//       abates — the EIP-1559 property.
//   (c) No overflow: minted total fits U256; heights up to 10,000 are safe.
//   (d) Validator rewards are positive and proportional to treasury share.
// ============================================================================

/// Helper: create N dummy transactions (value-only, no contract deployment or
/// inference markers) to include in a block.
fn make_transactions(count: usize) -> Vec<Transaction> {
    (0..count)
        .map(|i| Transaction {
            nonce: i as u64,
            from: PublicKey::new([0x01; 32]),
            to: Some(PublicKey::new([0x02; 32])),
            value: 1_000,
            data: vec![],
            gas_price: 1_000_000_000,
            gas_limit: 21_000,
            signature: Signature::new([0; 64]),
            hash: Hash::new([i as u8; 32]),
            chain_id: Some(40204),
            tx_type: None,
            eth_tx_type: 0,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list: None,
            ecdsa_verified: false,
        })
        .collect()
}

#[test]
fn economic_simulation_10k_blocks_supply_conservation() {
    // --- Setup genesis supply ---
    let genesis = GenesisConfig::testnet_beta();
    let genesis_supply = genesis.total_preallocation();

    // --- Create token with genesis pre-allocations ---
    let token_config = TokenConfig::default();
    let mut token = Token::new(token_config);

    // Mint the genesis pre-allocation to a genesis address so the
    // token ledger tracks the full supply.
    let genesis_addr = Address([0xFF; 20]);
    token.mint(&genesis_addr, genesis_supply).unwrap();

    // --- Reward calculator & pricing manager ---
    let reward_config = RewardConfig::default();
    let calculator = RewardCalculator::new(reward_config);

    let pricing_config = DynamicPricingConfig::default();
    let initial_gas_price = pricing_config.base_gas_price;
    let mut pricing = DynamicPricingManager::new(pricing_config);

    // --- Validator & treasury addresses ---
    let validator = Address([0xAA; 20]);
    let treasury = Address([0xBB; 20]);

    // --- Simulation parameters ---
    const NUM_BLOCKS: u64 = 10_000;
    const GAS_LIMIT: u64 = 10_000_000;
    const GAS_PER_TX: u64 = 90_000; // contract-call-ish txs to drive meaningful utilization

    let mut total_minted = U256::zero();
    let mut total_validator_reward = U256::zero();
    let mut total_treasury_reward = U256::zero();

    // Track gas price at intervals to verify EIP-1559 behavior
    let mut price_at_2000 = U256::zero(); // during high-load phase
    let mut price_at_5000 = U256::zero(); // transitioning to low-load
    let mut price_at_8000 = U256::zero(); // during low-load phase

    for height in 0..NUM_BLOCKS {
        // --- Sinusoidal tx load: oscillates between 0 and 100 ---
        // Period = 2000 blocks. Peak at height % 2000 == 500, trough at 1500.
        let phase = (height % 2000) as f64 * std::f64::consts::PI * 2.0 / 2000.0;
        let tx_count = ((phase.sin() + 1.0) / 2.0 * 100.0) as usize; // 0..100

        let transactions = make_transactions(tx_count);
        let block = make_block(height, transactions);

        // --- Calculate and distribute reward ---
        let reward = calculator.calculate_reward(&block);

        // Invariant (c): no overflow — if mint would exceed supply, that's
        // fine for the simulation because 10k blocks at 10 SALT/block is only
        // 100k SALT, well within 1B cap. We still check the mint succeeds.
        token.mint(&validator, reward.validator_reward).unwrap();
        token.mint(&treasury, reward.treasury_reward).unwrap();

        total_minted += reward.total_reward;
        total_validator_reward += reward.validator_reward;
        total_treasury_reward += reward.treasury_reward;

        // --- Update dynamic pricing ---
        let gas_used = (tx_count as u64) * GAS_PER_TX;
        let metrics = UtilizationMetrics {
            block_height: height,
            gas_used,
            gas_limit: GAS_LIMIT,
            transaction_count: tx_count as u32,
            ai_operations: 0,
            compute_intensity: 0.0,
        };
        pricing.update_pricing(metrics).unwrap();

        // --- Snapshot gas prices at key points ---
        if height == 2000 {
            price_at_2000 = pricing.current_gas_price();
        }
        if height == 5000 {
            price_at_5000 = pricing.current_gas_price();
        }
        if height == 8000 {
            price_at_8000 = pricing.current_gas_price();
        }
    }

    // ===== Invariant (a): Supply conservation =====
    // total in ledger = genesis_supply + total_minted
    let expected_total = genesis_supply + total_minted;
    let actual_total = token.circulating_supply();
    assert_eq!(
        actual_total, expected_total,
        "Supply conservation violated: circulating={}, expected (genesis+minted)={}",
        actual_total, expected_total
    );

    // Cross-check: sum of all balances equals circulating supply
    let balance_sum = token.balance_of(&genesis_addr)
        + token.balance_of(&validator)
        + token.balance_of(&treasury);
    assert_eq!(
        balance_sum, actual_total,
        "Balance sum ({}) != circulating supply ({})",
        balance_sum, actual_total
    );

    // ===== Invariant (b): Base fee adjusts under load (EIP-1559) =====
    // The sinusoidal pattern means load is high around block 500 in each
    // 2000-block cycle. At block 2000 (start of second cycle), the
    // pricing manager has just processed a full cycle of varying load.
    // We verify that gas price is NOT stuck at the initial value — it has
    // responded to demand. Additionally, the price should differ between
    // the high-demand and low-demand snapshots.
    assert_ne!(
        price_at_2000, initial_gas_price,
        "Gas price at block 2000 should differ from genesis price (EIP-1559 adjustment)"
    );
    // At block 5000 vs 8000, there should be observable price variation
    // as the load oscillates. We just check they are not all identical.
    let prices_vary = price_at_2000 != price_at_5000
        || price_at_5000 != price_at_8000
        || price_at_2000 != price_at_8000;
    assert!(
        prices_vary,
        "Gas prices should vary across demand cycles: @2000={}, @5000={}, @8000={}",
        price_at_2000, price_at_5000, price_at_8000
    );

    // ===== Invariant (c): No overflow at large values =====
    // total_minted must be representable (we already proved this by not
    // panicking above). Also verify that the values are reasonable:
    // 10k blocks * 10 SALT/block = 100,000 SALT = 100,000e18 wei.
    let expected_minted_approx = latt_to_wei(100_000);
    assert_eq!(
        total_minted, expected_minted_approx,
        "Total minted should be ~100,000 SALT (10k blocks * 10 SALT): got {}",
        total_minted
    );
    // Verify the U256 max boundary is nowhere near breached
    assert!(
        total_minted < U256::MAX / U256::from(1_000_000),
        "Total minted should be astronomically below U256::MAX"
    );

    // ===== Invariant (d): Validator rewards are positive and proportional =====
    assert!(
        total_validator_reward > U256::zero(),
        "Validator rewards must be positive over 10k blocks"
    );
    assert!(
        total_treasury_reward > U256::zero(),
        "Treasury rewards must be positive over 10k blocks"
    );

    // Treasury is 10% of total. Validator is 90%.
    // validator_reward / total_minted should be ~0.9
    // We verify: validator_reward * 100 / total_minted == 90
    let validator_pct = (total_validator_reward * U256::from(100)) / total_minted;
    assert_eq!(
        validator_pct,
        U256::from(90),
        "Validator should receive 90% of total: got {}%",
        validator_pct
    );
    let treasury_pct = (total_treasury_reward * U256::from(100)) / total_minted;
    assert_eq!(
        treasury_pct,
        U256::from(10),
        "Treasury should receive 10% of total: got {}%",
        treasury_pct
    );

    // Verify validator + treasury == total (exact, no rounding loss for whole SALT)
    assert_eq!(
        total_validator_reward + total_treasury_reward,
        total_minted,
        "Validator + treasury rewards must sum to total minted"
    );
}

#[test]
fn economic_simulation_max_u256_height_no_panic() {
    // Verify that reward calculation at extreme heights does not overflow or
    // panic, regardless of transaction content.
    let config = RewardConfig::default();
    let halving_interval = config.halving_interval;
    let calculator = RewardCalculator::new(config);

    // Heights near u64::MAX boundaries
    let extreme_heights: Vec<u64> = vec![
        u64::MAX,
        u64::MAX - 1,
        u64::MAX / 2,
        u64::MAX / 3,
        0,
        1,
    ];

    for &h in &extreme_heights {
        let block = make_block(h, make_transactions(100));
        let reward = calculator.calculate_reward(&block);

        // At these extreme heights (far past 64 halvings), reward is zero
        if h > halving_interval * 64 {
            assert_eq!(
                reward.total_reward,
                U256::zero(),
                "Reward at height {} should be zero (past all halvings)",
                h
            );
        }

        // The key invariant: validator + treasury == total, always
        assert_eq!(
            reward.validator_reward + reward.treasury_reward,
            reward.total_reward,
            "Reward split invariant violated at height {}",
            h
        );
    }
}

#[test]
fn economic_simulation_fee_rises_then_falls_with_demand() {
    // Simulate a demand spike followed by a demand trough and verify the
    // gas price follows the expected EIP-1559 pattern: rise under high
    // utilization, fall under low utilization.
    let config = DynamicPricingConfig::default();
    let initial_price = config.base_gas_price;
    let mut pricing = DynamicPricingManager::new(config);

    // Phase 1: 200 blocks at 95% utilization (heavy load)
    for i in 0u64..200 {
        let metrics = UtilizationMetrics {
            block_height: i,
            gas_used: 28_500_000, // 95% of 30M
            gas_limit: 30_000_000,
            transaction_count: 100,
            ai_operations: 0,
            compute_intensity: 0.0,
        };
        pricing.update_pricing(metrics).unwrap();
    }
    let price_after_spike = pricing.current_gas_price();

    assert!(
        price_after_spike > initial_price,
        "Fee must rise after 200 blocks at 95%% utilization: initial={}, after_spike={}",
        initial_price, price_after_spike
    );

    // Phase 2: 200 blocks at 5% utilization (demand collapse)
    for i in 200u64..400 {
        let metrics = UtilizationMetrics {
            block_height: i,
            gas_used: 1_500_000, // 5% of 30M
            gas_limit: 30_000_000,
            transaction_count: 5,
            ai_operations: 0,
            compute_intensity: 0.0,
        };
        pricing.update_pricing(metrics).unwrap();
    }
    let price_after_trough = pricing.current_gas_price();

    assert!(
        price_after_trough < price_after_spike,
        "Fee must fall after demand collapse: after_spike={}, after_trough={}",
        price_after_spike, price_after_trough
    );
}

#[test]
fn economic_simulation_reward_proportionality_across_halvings() {
    // Verify that rewards halve correctly and remain proportional across
    // the first several halving boundaries.
    //
    // The reward calculation uses integer right-shift (block_reward >> halvings),
    // so halving is applied to the integer SALT amount before scaling to wei.
    // base_reward=10 => halving 0: 10, 1: 5, 2: 2, 3: 1, 4: 0 (integer division).
    let config = RewardConfig::default();
    let halving_interval = config.halving_interval;
    let base_reward = config.block_reward;
    let calculator = RewardCalculator::new(config);

    let one_salt_wei = U256::from(10u64).pow(U256::from(18u64));

    for halving in 0u64..5 {
        let height = halving_interval * halving;
        let block = make_block(height, vec![]);
        let reward = calculator.calculate_reward(&block);

        // Expected reward: base_reward >> halvings, converted to wei.
        let expected_base = base_reward >> halving;
        let expected_total = U256::from(expected_base) * one_salt_wei;

        assert_eq!(
            reward.total_reward, expected_total,
            "Reward at halving {} (height {}) should be {} SALT ({} wei): got {}",
            halving, height, expected_base, expected_total, reward.total_reward
        );

        // Reward should be positive until integer division floors to zero
        if expected_base > 0 {
            assert!(
                reward.total_reward > U256::zero(),
                "Reward at halving {} (height {}) should be positive",
                halving, height
            );
        }

        // Proportionality: validator gets 90%, treasury gets 10%
        let expected_validator = reward.total_reward * U256::from(90) / U256::from(100);
        let expected_treasury = reward.total_reward - expected_validator;
        assert_eq!(reward.validator_reward, expected_validator,
            "Validator reward mismatch at halving {}", halving);
        assert_eq!(reward.treasury_reward, expected_treasury,
            "Treasury reward mismatch at halving {}", halving);
    }
}
