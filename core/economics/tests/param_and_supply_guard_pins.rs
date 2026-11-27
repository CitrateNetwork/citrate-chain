//! Pins for range, supply and scoring guards in the economics crate, driven
//! through the public entry points (governance parameter update, token mint
//! after a burn, enhanced reward distribution).

use citrate_economics::dynamic_pricing::UtilizationMetrics;
use citrate_economics::enhanced_rewards::{
    EnhancedRewardCalculator, EnhancedRewardConfig, NetworkHealth,
};
use citrate_economics::governance::{GovernanceConfig, GovernanceManager};
use citrate_economics::{Token, TokenConfig};
use citrate_execution::types::Address;
use primitive_types::U256;
use std::collections::HashMap;

#[test]
fn governance_percentages_outside_1_to_100_are_rejected() {
    let mut g = GovernanceManager::new(GovernanceConfig::default());
    for p in ["quorum_percentage", "approval_threshold"] {
        // 256 used to truncate to 0 under `as u8`; 0 and 101 are out of range.
        for bad in [0u64, 101, 255, 256, 512] {
            assert!(
                g.update_config(p, U256::from(bad)).is_err(),
                "{p}={bad} must be rejected"
            );
        }
        for good in [1u64, 50, 100] {
            assert!(
                g.update_config(p, U256::from(good)).is_ok(),
                "{p}={good} must be accepted"
            );
        }
    }
}

#[test]
fn governance_u64_parameters_reject_values_above_u64_max() {
    let mut g = GovernanceManager::new(GovernanceConfig::default());
    let too_big = U256::from(u64::MAX) + U256::one();
    for p in ["voting_period", "execution_delay", "grace_period"] {
        assert!(
            g.update_config(p, too_big).is_err(),
            "{p} > u64::MAX must be rejected"
        );
        assert!(
            g.update_config(p, U256::from(u64::MAX)).is_ok(),
            "{p} = u64::MAX fits"
        );
    }
}

#[test]
fn burn_then_mint_round_trip_stays_within_the_cap() {
    let holder = Address([7; 20]);
    let cap = U256::from(1_000u64);
    let mut init = HashMap::new();
    init.insert(holder, cap);
    let mut t = Token::new(TokenConfig {
        total_supply: cap,
        initial_distribution: init,
        ..TokenConfig::default()
    });
    // Fully minted. Stake (burn) and unstake (mint) the same amount, twice.
    for _ in 0..2 {
        t.burn(&holder, U256::from(400u64)).expect("burn");
        t.mint(&holder, U256::from(400u64))
            .expect("re-mint of a burned amount fits the cap");
    }
    assert_eq!(t.circulating_supply(), cap);
    assert_eq!(t.balance_of(&holder), cap);
    // A genuinely new mint above the cap is still refused.
    assert!(
        t.mint(&holder, U256::one()).is_err(),
        "circulating supply is at the cap"
    );
}

#[test]
fn full_network_health_pays_the_full_health_pool() {
    let config = EnhancedRewardConfig::default();
    let base = config.base_block_reward;
    let pct = config.network_health_pool;
    let mut calc = EnhancedRewardCalculator::new(config);
    let utilization = UtilizationMetrics {
        block_height: 10,
        gas_used: 50,
        gas_limit: 100, // 50%: no activity multiplier
        transaction_count: 0,
        ai_operations: 0,
        compute_intensity: 0.0,
    };
    let health = NetworkHealth {
        total_validators: 4,
        active_validators: 4,
        average_uptime: 1.0,
        consensus_efficiency: 1.0,
        transaction_success_rate: 1.0,
        ai_operation_success_rate: 1.0,
        network_decentralization: 1.0,
        security_incidents: 0,
    };
    let d = calc
        .calculate_rewards(10, &utilization, vec![], vec![], health)
        .expect("distribution");
    assert_eq!(d.total_rewards, base);
    // Weighted mean of all-1.0 components is 1.0, so the whole pool is paid.
    assert_eq!(
        d.network_health_bonus,
        base * U256::from(pct) / U256::from(100)
    );
}

#[test]
fn slash_penalty_is_capped_at_the_base_reward() {
    use citrate_economics::enhanced_rewards::ValidatorPerformance;
    let config = EnhancedRewardConfig::default();
    let stake = config.min_validator_stake;
    let mut calc = EnhancedRewardCalculator::new(config);
    let utilization = UtilizationMetrics {
        block_height: 10,
        gas_used: 50,
        gas_limit: 100,
        transaction_count: 0,
        ai_operations: 0,
        compute_intensity: 0.0,
    };
    let health = NetworkHealth {
        total_validators: 1,
        active_validators: 1,
        average_uptime: 1.0,
        consensus_efficiency: 1.0,
        transaction_success_rate: 1.0,
        ai_operation_success_rate: 1.0,
        network_decentralization: 1.0,
        security_incidents: 0,
    };
    for slashes in [11u64, 20, u64::MAX] {
        let v = Address([3; 20]);
        let perf = ValidatorPerformance {
            address: v,
            blocks_proposed: 10,
            blocks_validated: 10,
            uptime_percentage: 1.0,
            transaction_throughput: 10,
            ai_operations_processed: 0,
            consensus_participation: 1.0,
            stake_amount: stake,
            stake_duration: 100,
            slash_count: slashes,
            quality_score: 1.0,
        };
        let d = calc
            .calculate_rewards(10, &utilization, vec![perf], vec![], health.clone())
            .expect("distribution");
        let r = &d.validator_rewards[&v];
        assert!(r.base_reward > U256::zero());
        assert_eq!(
            r.penalty, r.base_reward,
            "{slashes} slashes: penalty capped at 100% of base"
        );
    }
}
