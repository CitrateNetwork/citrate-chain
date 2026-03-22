// Sprint RR — WP-RR.1: Economics crate coverage push to 98%
//
// Fills every identified coverage gap across all economics modules:
// unified_economics, dynamic_pricing, governance, revenue_sharing,
// enhanced_rewards, rewards, token, slashing, genesis, institutional, estimator.

use citrate_economics::*;
use citrate_economics::dynamic_pricing::DynamicPricingManager;
use citrate_economics::enhanced_rewards::{
    EnhancedRewardCalculator, EnhancedRewardConfig,
};
use citrate_economics::governance::{GovernanceManager, ProposalStatus};
use citrate_economics::revenue_sharing::{
    PerformanceMetrics, RevenueShareManager,
};
use citrate_economics::unified_economics::UnifiedEconomicsManager;
use citrate_execution::types::Address;
use primitive_types::U256;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn salt(n: u64) -> U256 {
    U256::from(n) * U256::from(10).pow(U256::from(DECIMALS))
}

fn addr(b: u8) -> Address {
    Address([b; 20])
}

/// Create a UnifiedEconomicsConfig with initial token distribution for testing.
fn funded_config(funded: &[(u8, u64)]) -> UnifiedEconomicsConfig {
    let mut initial = HashMap::new();
    for &(a, amount) in funded {
        initial.insert(addr(a), salt(amount));
    }
    let mut config = UnifiedEconomicsConfig::default();
    config.token_config.initial_distribution = initial;
    config
}

fn default_utilization(block: u64, gas_used: u64, gas_limit: u64) -> UtilizationMetrics {
    UtilizationMetrics {
        block_height: block,
        gas_used,
        gas_limit,
        transaction_count: 50,
        ai_operations: 5,
        compute_intensity: 0.3,
    }
}

fn good_health() -> NetworkHealth {
    NetworkHealth {
        total_validators: 100,
        active_validators: 95,
        average_uptime: 0.98,
        consensus_efficiency: 0.95,
        transaction_success_rate: 0.99,
        ai_operation_success_rate: 0.97,
        network_decentralization: 0.85,
        security_incidents: 0,
    }
}

fn poor_health() -> NetworkHealth {
    NetworkHealth {
        total_validators: 100,
        active_validators: 50,
        average_uptime: 0.70,
        consensus_efficiency: 0.60,
        transaction_success_rate: 0.80,
        ai_operation_success_rate: 0.70,
        network_decentralization: 0.40,
        security_incidents: 3,
    }
}

fn test_validator(a: Address, stake: U256) -> ValidatorPerformance {
    ValidatorPerformance {
        address: a,
        blocks_proposed: 10,
        blocks_validated: 10,
        uptime_percentage: 0.995,
        transaction_throughput: 1000,
        ai_operations_processed: 5,
        consensus_participation: 0.95,
        stake_amount: stake,
        stake_duration: 500,
        slash_count: 0,
        quality_score: 0.9,
    }
}

fn test_ai_contribution(a: Address) -> AIContribution {
    AIContribution {
        contributor: a,
        models_deployed: 5,
        inferences_served: 1000,
        quality_ratings: vec![0.9, 0.85, 0.95],
        compute_provided: 10000,
        data_contributions: 3,
        successful_trainings: 2,
        peer_reviews_given: 15,
        community_reputation: 0.85,
    }
}

fn make_block(height: u64, txs: Vec<citrate_consensus::types::Transaction>) -> citrate_consensus::types::Block {
    use citrate_consensus::types::*;
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
            vrf_reveal: VrfProof { proof: vec![], output: Hash::default() },
            base_fee_per_gas: 0,
            gas_used: 0,
            gas_limit: 30_000_000,
        },
        state_root: Hash::new([0; 32]),
        tx_root: Hash::new([0; 32]),
        receipt_root: Hash::default(),
        artifact_root: Hash::default(),
        ghostdag_params: GhostDagParams::default(),
        transactions: txs,
        signature: Signature::new([0; 64]),
        embedded_models: vec![],
        required_pins: vec![],
        learning_embedding: None,
        learning_confidence: None,
        gradient_commitment: None,
            learning_root: Hash::default(),
    }
}

// ===========================================================================
// 1. UNIFIED ECONOMICS — process_block, staking, gas fees, reputation, etc.
// ===========================================================================

#[test]
fn test_unified_process_block_full_flow() {
    let config = funded_config(&[(1, 100_000)]);
    let mut mgr = UnifiedEconomicsManager::new(config);

    let utilization = default_utilization(1, 7_000_000, 10_000_000);
    let validators = vec![test_validator(addr(1), salt(50_000))];
    let ai = vec![test_ai_contribution(addr(2))];
    let health = good_health();
    let gas_usage: HashMap<Address, U256> = [(addr(1), U256::from(500_000))].into();

    let update = mgr.process_block(1, utilization, validators, ai, health, gas_usage);
    assert!(update.is_ok());

    let upd = update.unwrap();
    assert_eq!(upd.block_height, 1);
    assert!(upd.economic_state.gas_price > U256::zero());
}

#[test]
fn test_unified_unstake_success_and_failure() {
    let config = funded_config(&[(1, 1000)]);
    let mut mgr = UnifiedEconomicsManager::new(config);

    let a = addr(1);
    mgr.stake_tokens(a, salt(500)).unwrap();

    // Unstake partial
    mgr.unstake_tokens(a, salt(200)).unwrap();
    assert_eq!(mgr.get_staked_balance(&a), salt(300));

    // Unstake too much
    let err = mgr.unstake_tokens(a, salt(500));
    assert!(err.is_err());
}

#[test]
fn test_unified_stake_insufficient_balance() {
    let config = funded_config(&[(1, 100)]);
    let mut mgr = UnifiedEconomicsManager::new(config);

    let err = mgr.stake_tokens(addr(1), salt(200));
    assert!(err.is_err());
}

#[test]
fn test_unified_vote_on_proposal_insufficient_balance() {
    let config = funded_config(&[]); // No tokens
    let mut mgr = UnifiedEconomicsManager::new(config);

    let err = mgr.vote_on_proposal(1, addr(5), VoteType::For, 100);
    assert!(err.is_err());
}

#[test]
fn test_unified_get_operation_cost_all_types() {
    let config = UnifiedEconomicsConfig::default();
    let mgr = UnifiedEconomicsManager::new(config);

    let standard = mgr.get_operation_cost(OperationType::StandardTransaction);
    let contract = mgr.get_operation_cost(OperationType::ContractCall);
    let ai = mgr.get_operation_cost(OperationType::AIInference { compute_units: 100 });
    let deploy = mgr.get_operation_cost(OperationType::ModelDeployment { model_size_mb: 500 });
    let train = mgr.get_operation_cost(OperationType::ModelTraining { dataset_size_gb: 10 });

    assert!(standard > U256::zero());
    assert!(contract > standard);
    assert!(ai > standard);
    assert!(deploy > U256::zero());
    assert!(train > U256::zero());
}

#[test]
fn test_unified_pay_gas_fees() {
    let config = funded_config(&[(1, 1000)]);
    let mut mgr = UnifiedEconomicsManager::new(config);

    mgr.pay_gas_fees(addr(1), salt(100), 50).unwrap();
    assert_eq!(mgr.get_token().balance_of(&addr(1)), salt(900));
}

#[test]
fn test_unified_pay_gas_fees_insufficient() {
    let config = funded_config(&[(1, 10)]);
    let mut mgr = UnifiedEconomicsManager::new(config);

    let err = mgr.pay_gas_fees(addr(1), salt(100), 50);
    assert!(err.is_err());
}

#[test]
fn test_unified_pay_gas_fees_zero_burn() {
    let config = funded_config(&[(1, 1000)]);
    let mut mgr = UnifiedEconomicsManager::new(config);

    mgr.pay_gas_fees(addr(1), salt(100), 0).unwrap();
    // 0% burn → all goes to remainder (which is also burned in current impl)
    assert_eq!(mgr.get_token().balance_of(&addr(1)), salt(900));
}

#[test]
fn test_unified_economic_security_zero_supply() {
    let config = UnifiedEconomicsConfig::default();
    let mgr = UnifiedEconomicsManager::new(config);

    // No staking → 0 security
    assert_eq!(mgr.calculate_economic_security(), 0.0);
    assert!(!mgr.is_economically_secure());
}

#[test]
fn test_unified_update_reputation() {
    let config = UnifiedEconomicsConfig::default();
    let mut mgr = UnifiedEconomicsManager::new(config);

    let a = addr(1);
    assert_eq!(mgr.get_reputation_score(&a), 0.5);

    mgr.update_reputation(a, 0.3);
    assert!((mgr.get_reputation_score(&a) - 0.8).abs() < 0.001);

    // Clamp to 1.0
    mgr.update_reputation(a, 0.5);
    assert!((mgr.get_reputation_score(&a) - 1.0).abs() < 0.001);

    // Clamp to 0.0
    mgr.update_reputation(a, -2.0);
    assert!((mgr.get_reputation_score(&a) - 0.0).abs() < 0.001);
}

#[test]
fn test_unified_register_stakeholder_and_collect_fee() {
    let config = UnifiedEconomicsConfig::default();
    let mut mgr = UnifiedEconomicsManager::new(config);

    mgr.register_stakeholder(addr(1), StakeholderType::Validator).unwrap();
    mgr.collect_fee(RevenuePool::GasFees, salt(500), addr(99)).unwrap();
    assert_eq!(mgr.get_revenue_pool_balance(&RevenuePool::GasFees), salt(500));
}

#[test]
fn test_unified_get_economic_state_none_then_some() {
    let config = funded_config(&[(1, 100_000)]);
    let mut mgr = UnifiedEconomicsManager::new(config);

    assert!(mgr.get_economic_state().is_none());

    let utilization = default_utilization(1, 5_000_000, 10_000_000);
    let _ = mgr.process_block(1, utilization, vec![test_validator(addr(1), salt(50_000))], vec![], good_health(), HashMap::new());

    assert!(mgr.get_economic_state().is_some());
}

#[test]
fn test_unified_revenue_distribution_history_empty() {
    let config = UnifiedEconomicsConfig::default();
    let mgr = UnifiedEconomicsManager::new(config);

    assert!(mgr.get_revenue_distribution_history(None).is_empty());
    assert!(mgr.get_revenue_distribution_history(Some(RevenuePool::GasFees)).is_empty());
}

#[test]
fn test_unified_voting_power_with_staking_and_reputation() {
    let config = funded_config(&[(1, 10_000)]);
    let mut mgr = UnifiedEconomicsManager::new(config);

    let a = addr(1);
    mgr.stake_tokens(a, salt(5_000)).unwrap();
    mgr.update_reputation(a, 0.3);

    let vp = mgr.calculate_voting_power(a, 1).unwrap();
    assert!(vp.token_power > U256::zero());
    assert!(vp.staking_power > U256::zero());
    assert!(vp.reputation_power > U256::zero());
    assert!(vp.quadratic_power > U256::zero());
    assert!(vp.quadratic_power <= vp.total_power);
}

#[test]
fn test_unified_voting_power_zero_balance() {
    let config = UnifiedEconomicsConfig::default();
    let mgr = UnifiedEconomicsManager::new(config);

    let vp = mgr.calculate_voting_power(addr(99), 1).unwrap();
    assert_eq!(vp.token_power, U256::zero());
    assert_eq!(vp.total_power, U256::zero());
    assert_eq!(vp.quadratic_power, U256::zero());
}

#[test]
fn test_unified_get_config() {
    let config = UnifiedEconomicsConfig::default();
    let mgr = UnifiedEconomicsManager::new(config);

    let c = mgr.get_config();
    assert!((c.gas_governance_ratio - 0.1).abs() < 0.001);
}

#[test]
fn test_unified_update_revenue_sharing_config() {
    let config = UnifiedEconomicsConfig::default();
    let mut mgr = UnifiedEconomicsManager::new(config);

    let new_config = RevenueShareConfig {
        validator_share_bps: 2000,
        model_creator_share_bps: 2000,
        infrastructure_share_bps: 2000,
        treasury_share_bps: 2000,
        staker_share_bps: 1500,
        facilitator_share_bps: 500,
        ..RevenueShareConfig::default()
    };
    mgr.update_revenue_sharing_config(new_config).unwrap();
}

#[test]
fn test_unified_stakeholder_revenue_info() {
    let config = UnifiedEconomicsConfig::default();
    let mut mgr = UnifiedEconomicsManager::new(config);

    assert!(mgr.get_stakeholder_revenue_info(&addr(1)).is_none());

    mgr.register_stakeholder(addr(1), StakeholderType::Validator).unwrap();
    assert!(mgr.get_stakeholder_revenue_info(&addr(1)).is_some());
}

// ===========================================================================
// 2. DYNAMIC PRICING — all operation types, history, trends, bounds
// ===========================================================================

#[test]
fn test_pricing_all_five_operation_types() {
    let pricing = DynamicPricingManager::new(DynamicPricingConfig::default());

    let prices = [
        pricing.get_operation_price(OperationType::StandardTransaction),
        pricing.get_operation_price(OperationType::ContractCall),
        pricing.get_operation_price(OperationType::AIInference { compute_units: 50 }),
        pricing.get_operation_price(OperationType::ModelDeployment { model_size_mb: 100 }),
        pricing.get_operation_price(OperationType::ModelTraining { dataset_size_gb: 5 }),
    ];

    for p in &prices {
        assert!(*p > U256::zero());
    }
    assert!(prices[1] > prices[0]);
}

#[test]
fn test_pricing_model_deployment_scales_with_size() {
    let pricing = DynamicPricingManager::new(DynamicPricingConfig::default());

    let small = pricing.get_operation_price(OperationType::ModelDeployment { model_size_mb: 10 });
    let large = pricing.get_operation_price(OperationType::ModelDeployment { model_size_mb: 1000 });
    assert!(large > small);
}

#[test]
fn test_pricing_model_training_scales_with_dataset() {
    let pricing = DynamicPricingManager::new(DynamicPricingConfig::default());

    let small = pricing.get_operation_price(OperationType::ModelTraining { dataset_size_gb: 1 });
    let large = pricing.get_operation_price(OperationType::ModelTraining { dataset_size_gb: 100 });
    assert!(large > small);
}

#[test]
fn test_pricing_history_and_trends() {
    let mut pricing = DynamicPricingManager::new(DynamicPricingConfig::default());

    assert!(pricing.get_price_history(10).is_empty());
    assert!(matches!(pricing.predict_price_trend(10), PriceTrend::Stable));

    for i in 1..=15 {
        let metrics = UtilizationMetrics {
            block_height: i,
            gas_used: 9_000_000,
            gas_limit: 10_000_000,
            transaction_count: 100,
            ai_operations: 5,
            compute_intensity: 0.5,
        };
        pricing.update_pricing(metrics).unwrap();
    }

    let history = pricing.get_price_history(10);
    assert!(!history.is_empty());
    assert!(history.len() <= 10);
}

#[test]
fn test_pricing_low_utilization_decreases_price() {
    let mut pricing = DynamicPricingManager::new(DynamicPricingConfig::default());
    let initial_price = pricing.current_gas_price();

    let metrics = UtilizationMetrics {
        block_height: 1,
        gas_used: 100_000,
        gas_limit: 10_000_000,
        transaction_count: 5,
        ai_operations: 0,
        compute_intensity: 0.0,
    };
    pricing.update_pricing(metrics).unwrap();
    assert!(pricing.current_gas_price() <= initial_price);
}

#[test]
fn test_pricing_update_price_change_increase() {
    let mut pricing = DynamicPricingManager::new(DynamicPricingConfig::default());

    let high = UtilizationMetrics {
        block_height: 1,
        gas_used: 9_500_000,
        gas_limit: 10_000_000,
        transaction_count: 200,
        ai_operations: 20,
        compute_intensity: 0.8,
    };
    let update = pricing.update_pricing(high).unwrap();
    assert!(matches!(update.price_change, PriceChange::Increase { .. }));
}

#[test]
fn test_pricing_utilization_window_trimming() {
    let config = DynamicPricingConfig {
        utilization_window: 5,
        ..DynamicPricingConfig::default()
    };
    let mut pricing = DynamicPricingManager::new(config);

    for i in 1..=10 {
        let metrics = default_utilization(i, 5_000_000, 10_000_000);
        pricing.update_pricing(metrics).unwrap();
    }

    // Should not panic; window trimmed internally
    let history = pricing.get_price_history(20);
    assert!(history.len() <= 10);
}

#[test]
fn test_pricing_ai_inference_compute_units_scaling() {
    let pricing = DynamicPricingManager::new(DynamicPricingConfig::default());

    let low = pricing.get_operation_price(OperationType::AIInference { compute_units: 1 });
    let high = pricing.get_operation_price(OperationType::AIInference { compute_units: 1000 });
    assert!(high > low);
}

// ===========================================================================
// 3. GOVERNANCE — delegation, execution, config updates, state transitions
// ===========================================================================

#[test]
fn test_governance_delegate_vote() {
    let config = GovernanceConfig::default();
    let mut gov = GovernanceManager::new(config.clone());
    let total_supply = salt(1_000_000_000);

    gov.delegate_vote(addr(1), addr(2), salt(1000), 100).unwrap();

    let pid = gov.create_proposal(
        addr(3),
        ProposalType::ParameterChange { parameter: "block_reward".into(), new_value: U256::from(20) },
        "Test".into(), "Desc".into(), 100, config.proposal_threshold,
    ).unwrap();

    let result = gov.vote(pid, addr(2), VoteType::For, 102, total_supply);
    assert!(result.is_ok());

    let proposal = gov.get_proposal(pid).unwrap();
    assert!(proposal.for_votes > U256::zero());
}

#[test]
fn test_governance_execute_proposal() {
    let config = GovernanceConfig {
        voting_period: 10, execution_delay: 5, quorum_percentage: 0,
        approval_threshold: 50, grace_period: 100,
        ..GovernanceConfig::default()
    };
    let mut gov = GovernanceManager::new(config.clone());
    let total_supply = salt(1_000_000_000);

    let pid = gov.create_proposal(
        addr(1),
        ProposalType::TreasurySpend { recipient: addr(10), amount: salt(1000), description: "x".into() },
        "Treasury".into(), "Desc".into(), 100, config.proposal_threshold,
    ).unwrap();

    gov.vote(pid, addr(2), VoteType::For, 102, total_supply).unwrap();
    gov.process_proposals(112, total_supply); // Voting ends → Succeeded
    gov.process_proposals(118, total_supply); // Execution delay → Queued

    let result = gov.execute_proposal(pid);
    assert!(result.is_ok());
    assert_eq!(gov.get_proposal(pid).unwrap().status, ProposalStatus::Executed);
}

#[test]
fn test_governance_execute_non_queued_fails() {
    let config = GovernanceConfig::default();
    let mut gov = GovernanceManager::new(config.clone());

    let pid = gov.create_proposal(
        addr(1), ProposalType::ParameterChange { parameter: "x".into(), new_value: U256::from(1) },
        "Test".into(), "Desc".into(), 100, config.proposal_threshold,
    ).unwrap();

    assert!(gov.execute_proposal(pid).is_err());
}

#[test]
fn test_governance_failed_proposal() {
    let config = GovernanceConfig { voting_period: 10, quorum_percentage: 50, ..GovernanceConfig::default() };
    let mut gov = GovernanceManager::new(config.clone());
    let total_supply = salt(1_000_000_000);

    let pid = gov.create_proposal(
        addr(1), ProposalType::ParameterChange { parameter: "x".into(), new_value: U256::from(1) },
        "Test".into(), "Desc".into(), 100, config.proposal_threshold,
    ).unwrap();

    gov.vote(pid, addr(2), VoteType::For, 102, total_supply).unwrap();

    let updates = gov.process_proposals(112, total_supply);
    assert!(updates.iter().any(|u| matches!(u, ProposalUpdate::Failed(_))));
}

#[test]
fn test_governance_expired_proposal() {
    let config = GovernanceConfig {
        voting_period: 10, execution_delay: 5, grace_period: 5,
        quorum_percentage: 0, approval_threshold: 50,
        ..GovernanceConfig::default()
    };
    let mut gov = GovernanceManager::new(config.clone());
    let total_supply = salt(1_000_000_000);

    let pid = gov.create_proposal(
        addr(1), ProposalType::ParameterChange { parameter: "x".into(), new_value: U256::from(1) },
        "Test".into(), "Desc".into(), 100, config.proposal_threshold,
    ).unwrap();

    gov.vote(pid, addr(2), VoteType::For, 102, total_supply).unwrap();
    gov.process_proposals(112, total_supply); // Succeeded
    gov.process_proposals(118, total_supply); // Queued
    let updates = gov.process_proposals(130, total_supply); // Expired
    assert!(updates.iter().any(|u| matches!(u, ProposalUpdate::Expired(_))));
}

#[test]
fn test_governance_get_active_proposals() {
    let config = GovernanceConfig::default();
    let mut gov = GovernanceManager::new(config.clone());
    let total_supply = salt(1_000_000_000);

    assert!(gov.get_active_proposals().is_empty());

    let _pid = gov.create_proposal(
        addr(1), ProposalType::ParameterChange { parameter: "x".into(), new_value: U256::from(1) },
        "Test".into(), "Desc".into(), 100, config.proposal_threshold,
    ).unwrap();

    gov.process_proposals(102, total_supply); // Pending → Active
    assert_eq!(gov.get_active_proposals().len(), 1);
}

#[test]
fn test_governance_update_config() {
    let mut gov = GovernanceManager::new(GovernanceConfig::default());

    gov.update_config("proposal_threshold", salt(5000)).unwrap();
    gov.update_config("vote_threshold", salt(10)).unwrap();
    gov.update_config("voting_period", U256::from(100_000)).unwrap();
    gov.update_config("execution_delay", U256::from(500)).unwrap();
    gov.update_config("quorum_percentage", U256::from(20)).unwrap();
    gov.update_config("approval_threshold", U256::from(55)).unwrap();
    gov.update_config("grace_period", U256::from(10_000)).unwrap();

    assert!(gov.update_config("nonexistent", U256::from(1)).is_err());
}

#[test]
fn test_governance_vote_before_start_rejected() {
    let config = GovernanceConfig::default();
    let mut gov = GovernanceManager::new(config.clone());
    let total_supply = salt(1_000_000_000);

    let pid = gov.create_proposal(
        addr(1), ProposalType::ParameterChange { parameter: "x".into(), new_value: U256::from(1) },
        "Test".into(), "Desc".into(), 100, config.proposal_threshold,
    ).unwrap();

    assert!(gov.vote(pid, addr(2), VoteType::For, 100, total_supply).is_err());
}

#[test]
fn test_governance_vote_after_end_rejected() {
    let config = GovernanceConfig { voting_period: 10, ..GovernanceConfig::default() };
    let mut gov = GovernanceManager::new(config.clone());
    let total_supply = salt(1_000_000_000);

    let pid = gov.create_proposal(
        addr(1), ProposalType::ParameterChange { parameter: "x".into(), new_value: U256::from(1) },
        "Test".into(), "Desc".into(), 100, config.proposal_threshold,
    ).unwrap();

    assert!(gov.vote(pid, addr(2), VoteType::For, 112, total_supply).is_err());
}

#[test]
fn test_governance_abstain_and_against_votes() {
    let config = GovernanceConfig::default();
    let mut gov = GovernanceManager::new(config.clone());
    let total_supply = salt(1_000_000_000);

    let pid = gov.create_proposal(
        addr(1), ProposalType::ParameterChange { parameter: "x".into(), new_value: U256::from(1) },
        "Test".into(), "Desc".into(), 100, config.proposal_threshold,
    ).unwrap();

    gov.vote(pid, addr(2), VoteType::Abstain, 102, total_supply).unwrap();
    gov.vote(pid, addr(3), VoteType::Against, 102, total_supply).unwrap();

    let p = gov.get_proposal(pid).unwrap();
    assert!(p.abstain_votes > U256::zero());
    assert!(p.against_votes > U256::zero());
}

#[test]
fn test_governance_get_proposal_nonexistent() {
    let gov = GovernanceManager::new(GovernanceConfig::default());
    assert!(gov.get_proposal(999).is_none());
}

#[test]
fn test_governance_proposal_types() {
    let config = GovernanceConfig::default();
    let mut gov = GovernanceManager::new(config.clone());

    // NetworkUpgrade
    gov.create_proposal(
        addr(1), ProposalType::NetworkUpgrade { version: "2.0".into(), upgrade_block: 100_000 },
        "Upgrade".into(), "Desc".into(), 100, config.proposal_threshold,
    ).unwrap();

    // Emergency
    gov.create_proposal(
        addr(1), ProposalType::Emergency { action: "halt".into(), reason: "bug".into() },
        "Emergency".into(), "Desc".into(), 100, config.proposal_threshold,
    ).unwrap();

    // MarketplaceGovernance
    gov.create_proposal(
        addr(1),
        ProposalType::MarketplaceGovernance { action: MarketplaceAction::SetMinModelStake(salt(100)) },
        "MP".into(), "Desc".into(), 100, config.proposal_threshold,
    ).unwrap();
}

// ===========================================================================
// 4. REVENUE SHARING — all pool types, getters, edge cases
// ===========================================================================

#[test]
fn test_revenue_all_pool_types_distribution() {
    let mut mgr = RevenueShareManager::new(RevenueShareConfig::default());

    mgr.register_stakeholder(addr(1), StakeholderType::Validator).unwrap();
    mgr.register_stakeholder(addr(2), StakeholderType::ModelCreator).unwrap();
    mgr.register_stakeholder(addr(3), StakeholderType::Infrastructure).unwrap();
    mgr.register_stakeholder(addr(4), StakeholderType::Staker).unwrap();
    mgr.register_stakeholder(addr(5), StakeholderType::Treasury).unwrap();
    mgr.register_stakeholder(addr(6), StakeholderType::Facilitator).unwrap();

    let amount = salt(5000);
    let pools = [
        RevenuePool::GasFees, RevenuePool::AIInference, RevenuePool::ModelDeployment,
        RevenuePool::ModelTraining, RevenuePool::MarketplaceFees,
        RevenuePool::SlashingRedistribution, RevenuePool::FacilitatorFees,
    ];

    for pool in &pools {
        mgr.collect_revenue(pool.clone(), amount, addr(99)).unwrap();
    }

    let distributions = mgr.process_distributions(10_000).unwrap();
    assert_eq!(distributions.len(), 7);

    for dist in &distributions {
        assert!(!dist.distributions.is_empty());
        assert_eq!(dist.total_revenue, amount);
    }
}

#[test]
fn test_revenue_below_threshold_no_distribution() {
    let mut mgr = RevenueShareManager::new(RevenueShareConfig::default());
    mgr.register_stakeholder(addr(1), StakeholderType::Validator).unwrap();
    mgr.collect_revenue(RevenuePool::GasFees, salt(500), addr(99)).unwrap();

    assert!(mgr.distribute_revenue(RevenuePool::GasFees, 10_000).unwrap().is_none());
}

#[test]
fn test_revenue_too_frequent_no_distribution() {
    let mut mgr = RevenueShareManager::new(RevenueShareConfig::default());
    mgr.register_stakeholder(addr(1), StakeholderType::Validator).unwrap();
    mgr.collect_revenue(RevenuePool::GasFees, salt(5000), addr(99)).unwrap();

    assert!(mgr.distribute_revenue(RevenuePool::GasFees, 7200).unwrap().is_some());

    mgr.collect_revenue(RevenuePool::GasFees, salt(5000), addr(99)).unwrap();
    assert!(mgr.distribute_revenue(RevenuePool::GasFees, 7201).unwrap().is_none());
}

#[test]
fn test_revenue_pool_balance_and_stakeholder_contribution() {
    let mut mgr = RevenueShareManager::new(RevenueShareConfig::default());

    assert_eq!(mgr.get_pool_balance(&RevenuePool::GasFees), U256::zero());
    assert!(mgr.get_stakeholder_contribution(&addr(1)).is_none());

    mgr.register_stakeholder(addr(1), StakeholderType::Validator).unwrap();
    mgr.collect_revenue(RevenuePool::GasFees, salt(100), addr(1)).unwrap();

    assert_eq!(mgr.get_pool_balance(&RevenuePool::GasFees), salt(100));
    assert!(mgr.get_stakeholder_contribution(&addr(1)).is_some());
}

#[test]
fn test_revenue_distribution_history_filter() {
    let mut mgr = RevenueShareManager::new(RevenueShareConfig::default());
    mgr.register_stakeholder(addr(1), StakeholderType::Validator).unwrap();
    mgr.register_stakeholder(addr(2), StakeholderType::ModelCreator).unwrap();

    mgr.collect_revenue(RevenuePool::GasFees, salt(5000), addr(99)).unwrap();
    mgr.collect_revenue(RevenuePool::AIInference, salt(5000), addr(99)).unwrap();

    mgr.distribute_revenue(RevenuePool::GasFees, 8000).unwrap();
    mgr.distribute_revenue(RevenuePool::AIInference, 8000).unwrap();

    assert_eq!(mgr.get_distribution_history(None).len(), 2);
    assert_eq!(mgr.get_distribution_history(Some(RevenuePool::GasFees)).len(), 1);
    assert!(mgr.get_distribution_history(Some(RevenuePool::MarketplaceFees)).is_empty());
}

#[test]
fn test_revenue_get_recent_events() {
    let mut mgr = RevenueShareManager::new(RevenueShareConfig::default());
    mgr.register_stakeholder(addr(1), StakeholderType::Validator).unwrap();
    mgr.collect_revenue(RevenuePool::GasFees, salt(100), addr(99)).unwrap();
    mgr.collect_revenue(RevenuePool::GasFees, salt(200), addr(99)).unwrap();

    assert_eq!(mgr.get_recent_events(2).len(), 2);
    assert_eq!(mgr.get_recent_events(100).len(), 3); // 1 register + 2 collects
}

#[test]
fn test_revenue_update_performance() {
    let mut mgr = RevenueShareManager::new(RevenueShareConfig::default());
    mgr.register_stakeholder(addr(1), StakeholderType::Validator).unwrap();

    let perf = PerformanceMetrics {
        uptime_percentage: 99.5, response_time_ms: 50.0,
        success_rate: 0.99, user_satisfaction: 0.95, network_contribution: 0.8,
    };
    mgr.update_performance(addr(1), perf).unwrap();
    // Unregistered — no-op
    mgr.update_performance(addr(99), PerformanceMetrics::default()).unwrap();
}

#[test]
fn test_revenue_config_exactly_100_percent() {
    let mut mgr = RevenueShareManager::new(RevenueShareConfig::default());
    let config = RevenueShareConfig {
        validator_share_bps: 2000, model_creator_share_bps: 2000,
        infrastructure_share_bps: 2000, treasury_share_bps: 2000,
        staker_share_bps: 1500, facilitator_share_bps: 500,
        ..RevenueShareConfig::default()
    };
    assert!(mgr.update_config(config).is_ok());
}

#[test]
fn test_revenue_equal_distribution_no_contributions() {
    let mut mgr = RevenueShareManager::new(RevenueShareConfig::default());
    mgr.register_stakeholder(addr(1), StakeholderType::Validator).unwrap();
    mgr.register_stakeholder(addr(2), StakeholderType::Validator).unwrap();
    mgr.register_stakeholder(addr(3), StakeholderType::Treasury).unwrap();
    mgr.register_stakeholder(addr(4), StakeholderType::Staker).unwrap();

    mgr.collect_revenue(RevenuePool::GasFees, salt(10_000), addr(99)).unwrap();
    let dist = mgr.distribute_revenue(RevenuePool::GasFees, 8000).unwrap().unwrap();

    let v1 = dist.distributions.get(&addr(1)).copied().unwrap_or(U256::zero());
    let v2 = dist.distributions.get(&addr(2)).copied().unwrap_or(U256::zero());
    assert_eq!(v1, v2, "Equal distribution when no contribution scores");
}

// ===========================================================================
// 5. ENHANCED REWARDS — multiple validators, empty inputs, burn rates
// ===========================================================================

#[test]
fn test_enhanced_empty_validators_and_ai() {
    let mut calc = EnhancedRewardCalculator::new(EnhancedRewardConfig::default());
    let metrics = default_utilization(1, 5_000_000, 10_000_000);
    let result = calc.calculate_rewards(1, &metrics, vec![], vec![], good_health()).unwrap();

    assert!(result.total_rewards > U256::zero());
    assert!(result.validator_rewards.is_empty());
    assert!(result.ai_contributor_rewards.is_empty());
    assert!(result.treasury_allocation > U256::zero());
}

#[test]
fn test_enhanced_multiple_validators() {
    let mut calc = EnhancedRewardCalculator::new(EnhancedRewardConfig::default());
    let metrics = default_utilization(1, 7_000_000, 10_000_000);

    let validators = vec![
        test_validator(addr(1), salt(50_000)),
        test_validator(addr(2), salt(100_000)),
    ];
    let result = calc.calculate_rewards(1, &metrics, validators, vec![], good_health()).unwrap();

    assert_eq!(result.validator_rewards.len(), 2);
    let r1 = result.validator_rewards.get(&addr(1)).unwrap();
    let r2 = result.validator_rewards.get(&addr(2)).unwrap();
    assert!(r2.total_reward >= r1.total_reward);
}

#[test]
fn test_enhanced_validator_below_min_stake_skipped() {
    let mut calc = EnhancedRewardCalculator::new(EnhancedRewardConfig::default());
    let metrics = default_utilization(1, 5_000_000, 10_000_000);
    let validators = vec![test_validator(addr(1), salt(1000))]; // Below 32k min

    let result = calc.calculate_rewards(1, &metrics, validators, vec![], good_health()).unwrap();
    assert!(result.validator_rewards.is_empty());
}

#[test]
fn test_enhanced_validator_with_slashes() {
    let mut calc = EnhancedRewardCalculator::new(EnhancedRewardConfig::default());
    let metrics = default_utilization(1, 5_000_000, 10_000_000);
    let mut validator = test_validator(addr(1), salt(50_000));
    validator.slash_count = 3;

    let result = calc.calculate_rewards(1, &metrics, vec![validator], vec![], good_health()).unwrap();
    let reward = result.validator_rewards.get(&addr(1)).unwrap();
    assert!(reward.penalty > U256::zero());
}

#[test]
fn test_enhanced_validator_low_uptime_no_performance_bonus() {
    let mut calc = EnhancedRewardCalculator::new(EnhancedRewardConfig::default());
    let metrics = default_utilization(1, 5_000_000, 10_000_000);
    let mut validator = test_validator(addr(1), salt(50_000));
    validator.uptime_percentage = 0.80;

    let result = calc.calculate_rewards(1, &metrics, vec![validator], vec![], good_health()).unwrap();
    let reward = result.validator_rewards.get(&addr(1)).unwrap();
    assert_eq!(reward.performance_bonus, U256::zero());
}

#[test]
fn test_enhanced_validator_high_uptime_gets_uptime_bonus() {
    let mut calc = EnhancedRewardCalculator::new(EnhancedRewardConfig::default());
    let metrics = default_utilization(1, 5_000_000, 10_000_000);
    let mut validator = test_validator(addr(1), salt(50_000));
    validator.uptime_percentage = 0.995;

    let result = calc.calculate_rewards(1, &metrics, vec![validator], vec![], good_health()).unwrap();
    let reward = result.validator_rewards.get(&addr(1)).unwrap();
    assert!(reward.uptime_bonus > U256::zero());
}

#[test]
fn test_enhanced_ai_quality_below_threshold() {
    let mut calc = EnhancedRewardCalculator::new(EnhancedRewardConfig::default());
    let metrics = default_utilization(1, 5_000_000, 10_000_000);
    let mut ai = test_ai_contribution(addr(2));
    ai.quality_ratings = vec![0.5, 0.6, 0.7];

    let result = calc.calculate_rewards(1, &metrics, vec![], vec![ai], good_health()).unwrap();
    let reward = result.ai_contributor_rewards.get(&addr(2)).unwrap();
    assert_eq!(reward.quality_bonus, U256::zero());
}

#[test]
fn test_enhanced_ai_compute_tiers() {
    let mut calc = EnhancedRewardCalculator::new(EnhancedRewardConfig::default());
    let metrics = default_utilization(1, 5_000_000, 10_000_000);

    let mut ai_low = test_ai_contribution(addr(2));
    ai_low.compute_provided = 500;
    let r_low = calc.calculate_rewards(1, &metrics, vec![], vec![ai_low], good_health()).unwrap();

    let mut ai_high = test_ai_contribution(addr(3));
    ai_high.compute_provided = 200_000;
    let r_high = calc.calculate_rewards(2, &metrics, vec![], vec![ai_high], good_health()).unwrap();

    let low_bonus = r_low.ai_contributor_rewards.get(&addr(2)).unwrap().compute_bonus;
    let high_bonus = r_high.ai_contributor_rewards.get(&addr(3)).unwrap().compute_bonus;
    assert!(high_bonus > low_bonus);
}

#[test]
fn test_enhanced_ai_community_bonus() {
    let mut calc = EnhancedRewardCalculator::new(EnhancedRewardConfig::default());
    let metrics = default_utilization(1, 5_000_000, 10_000_000);

    let mut ai = test_ai_contribution(addr(2));
    ai.community_reputation = 0.9;
    ai.peer_reviews_given = 20;
    let r = calc.calculate_rewards(1, &metrics, vec![], vec![ai], good_health()).unwrap();
    assert!(r.ai_contributor_rewards.get(&addr(2)).unwrap().community_bonus > U256::zero());

    let mut ai_low = test_ai_contribution(addr(3));
    ai_low.community_reputation = 0.5;
    ai_low.peer_reviews_given = 2;
    let r2 = calc.calculate_rewards(2, &metrics, vec![], vec![ai_low], good_health()).unwrap();
    assert_eq!(r2.ai_contributor_rewards.get(&addr(3)).unwrap().community_bonus, U256::zero());
}

#[test]
fn test_enhanced_burn_rate_healthy_vs_poor() {
    let mut calc = EnhancedRewardCalculator::new(EnhancedRewardConfig::default());
    let metrics = default_utilization(1, 5_000_000, 10_000_000);

    let r_healthy = calc.calculate_rewards(1, &metrics, vec![], vec![], good_health()).unwrap();
    let r_poor = calc.calculate_rewards(2, &metrics, vec![], vec![], poor_health()).unwrap();
    assert!(r_healthy.burn_amount > r_poor.burn_amount);
}

#[test]
fn test_enhanced_halving_reduces_pool() {
    let mut calc = EnhancedRewardCalculator::new(EnhancedRewardConfig::default());

    let r_early = calc.calculate_rewards(1, &default_utilization(1, 5_000_000, 10_000_000), vec![], vec![], good_health()).unwrap();
    let r_late = calc.calculate_rewards(2_200_000, &default_utilization(2_200_000, 5_000_000, 10_000_000), vec![], vec![], good_health()).unwrap();
    assert!(r_late.total_rewards < r_early.total_rewards);
}

#[test]
fn test_enhanced_high_vs_low_utilization() {
    let mut calc = EnhancedRewardCalculator::new(EnhancedRewardConfig::default());

    let low = UtilizationMetrics { block_height: 1, gas_used: 1_000_000, gas_limit: 10_000_000, transaction_count: 10, ai_operations: 0, compute_intensity: 0.0 };
    let high = UtilizationMetrics { block_height: 2, gas_used: 9_000_000, gas_limit: 10_000_000, transaction_count: 200, ai_operations: 20, compute_intensity: 0.8 };

    let r_low = calc.calculate_rewards(1, &low, vec![], vec![], good_health()).unwrap();
    let r_high = calc.calculate_rewards(2, &high, vec![], vec![], good_health()).unwrap();
    assert!(r_high.total_rewards > r_low.total_rewards);
}

// ===========================================================================
// 6. REWARDS — inference counting, model deployment, supply calculation
// ===========================================================================

#[test]
fn test_rewards_with_inferences() {
    use citrate_consensus::types::*;

    let config = RewardConfig { inference_bonus: 1, ..RewardConfig::default() };
    let calc = RewardCalculator::new(config);

    let tx = Transaction {
        data: vec![0x02, 0x00, 0x00, 0x00, 0xFF],
        ..Transaction::default()
    };
    let block = make_block(0, vec![tx.clone(), tx]);
    let reward = calc.calculate_reward(&block);

    assert!(reward.total_reward > salt(10)); // 10 SALT base + inference bonuses
}

#[test]
fn test_rewards_with_model_deployment() {
    use citrate_consensus::types::*;

    let calc = RewardCalculator::new(RewardConfig::default());
    let tx = Transaction { to: None, data: vec![0x60, 0x80], ..Transaction::default() };
    let block = make_block(0, vec![tx]);
    let reward = calc.calculate_reward(&block);

    assert_eq!(reward.total_reward, salt(11)); // 10 base + 1 deployment
}

#[test]
fn test_rewards_with_model_registration_call() {
    use citrate_consensus::types::*;

    let calc = RewardCalculator::new(RewardConfig::default());
    let tx = Transaction {
        to: Some(PublicKey::new([2; 32])),
        data: vec![0x01, 0x00, 0x00, 0x00, 0xAB],
        ..Transaction::default()
    };
    let block = make_block(0, vec![tx]);
    let reward = calc.calculate_reward(&block);

    assert_eq!(reward.total_reward, salt(11)); // 10 base + 1 model bonus
}

#[test]
fn test_rewards_no_bonuses_with_regular_tx() {
    use citrate_consensus::types::*;

    let calc = RewardCalculator::new(RewardConfig::default());
    let tx = Transaction {
        to: Some(PublicKey::new([2; 32])),
        data: vec![0xFF, 0xAB, 0xCD, 0xEF],
        ..Transaction::default()
    };
    let block = make_block(0, vec![tx]);
    assert_eq!(calc.calculate_reward(&block).total_reward, salt(10));
}

#[test]
fn test_rewards_beyond_64_halvings() {
    let config = RewardConfig::default();
    let calc = RewardCalculator::new(config.clone());
    let block = make_block(config.halving_interval * 65, vec![]);
    assert_eq!(calc.calculate_reward(&block).total_reward, U256::zero());
}

#[test]
fn test_total_supply_at_height_across_halvings() {
    let config = RewardConfig::default();
    let calc = RewardCalculator::new(config.clone());

    assert_eq!(calc.total_supply_at_height(0), U256::zero());
    assert_eq!(calc.total_supply_at_height(1), salt(10));
    assert_eq!(calc.total_supply_at_height(100), salt(1000));

    let at_halving = calc.total_supply_at_height(config.halving_interval);
    assert_eq!(at_halving, salt(config.block_reward * config.halving_interval));

    let past_halving = calc.total_supply_at_height(config.halving_interval + 10);
    assert!(past_halving > at_halving);
}

// ===========================================================================
// 7. TOKEN — additional edge cases
// ===========================================================================

#[test]
fn test_token_initial_distribution() {
    let mut initial = HashMap::new();
    initial.insert(addr(1), salt(100));
    initial.insert(addr(2), salt(200));

    let config = TokenConfig { initial_distribution: initial, ..TokenConfig::default() };
    let token = Token::new(config);

    assert_eq!(token.balance_of(&addr(1)), salt(100));
    assert_eq!(token.balance_of(&addr(2)), salt(200));
    assert_eq!(token.total_minted, salt(300));
}

#[test]
fn test_token_self_transfer() {
    let mut token = Token::new(TokenConfig::default());
    token.mint(&addr(1), salt(100)).unwrap();
    token.transfer(&addr(1), &addr(1), salt(50)).unwrap();
    assert_eq!(token.balance_of(&addr(1)), salt(100));
}

// ===========================================================================
// 8. SLASHING — additional coverage
// ===========================================================================

#[test]
fn test_slashing_censorship_penalty() {
    let mgr = InstitutionalSlashingManager::new(InstitutionalSlashingConfig::default());
    let mut state = OperatorSlashingState::new(addr(1));

    let record = mgr.process_offense(&mut state, SlashingOffense::TransactionCensorship, salt(10_000), 10, [0xAA; 32]);
    assert_eq!(record.penalty_wei, salt(10_000) * U256::from(5) / U256::from(100));
}

#[test]
fn test_slashing_cumulative_under_threshold() {
    let mgr = InstitutionalSlashingManager::new(InstitutionalSlashingConfig::default());
    let mut state = OperatorSlashingState::new(addr(1));

    for i in 0..3 {
        mgr.process_offense(&mut state, SlashingOffense::Equivocation, salt(10_000), 10 + i * 2, [i as u8; 32]);
        state.in_cooldown = false;
    }
    assert!(!state.is_deactivated);
    assert_eq!(state.offense_count, 3);
}

#[test]
fn test_slashing_downtime_configurable() {
    let config = InstitutionalSlashingConfig {
        penalize_downtime: true,
        ..InstitutionalSlashingConfig::default()
    };
    assert!(InstitutionalSlashingManager::new(config).should_penalize_downtime());
}

// ===========================================================================
// 9. GENESIS — additional edge cases
// ===========================================================================

#[test]
fn test_genesis_empty_accounts_valid() {
    let config = GenesisConfig {
        chain_id: 1337, accounts: vec![],
        treasury_address: addr(0x11), team_allocations: HashMap::new(),
        ecosystem_fund: addr(0x22), mining_pool_max: salt(500_000_000),
    };
    assert!(config.validate().is_ok());
    assert_eq!(config.total_preallocation(), U256::zero());
}

// ===========================================================================
// 10. ESTIMATOR — edge cases
// ===========================================================================

#[test]
fn test_estimator_zero_months() {
    let est = InstitutionalRewardEstimator::new(InstitutionalRewardConfig::default());
    let result = est.estimate(&EstimationParams { projection_months: 0, ..Default::default() });
    assert!(result.monthly_projections.is_empty());
    assert_eq!(result.total_projected_salt, 0.0);
    assert_eq!(result.average_monthly_salt, 0.0);
    assert_eq!(result.min_monthly_salt, 0.0);
}

#[test]
fn test_estimator_single_month() {
    let est = InstitutionalRewardEstimator::new(InstitutionalRewardConfig::default());
    let result = est.estimate(&EstimationParams { projection_months: 1, ..Default::default() });
    assert_eq!(result.monthly_projections.len(), 1);
    assert_eq!(result.min_monthly_salt, result.max_monthly_salt);
}

// ===========================================================================
// 11. INSTITUTIONAL — additional edge cases
// ===========================================================================

#[test]
fn test_institutional_adapter_cap() {
    let config = InstitutionalRewardConfig::default();
    let calc = InstitutionalRewardCalculator::new(config);

    let mut profile = InstitutionalOperatorProfile::new(addr(1), "Test".into(), "t@t.com".into(), 0);
    profile.uptime_ratio = 0.995;
    profile.adapters_created = 100; // Cap = 20

    let b = calc.calculate_epoch_rewards(&profile);
    let wei = U256::from(10).pow(U256::from(DECIMALS));
    assert_eq!(b.adapter_creation_wei, U256::from(200u64) * wei);
}

#[test]
fn test_institutional_dataset_cap() {
    let config = InstitutionalRewardConfig::default();
    let calc = InstitutionalRewardCalculator::new(config);

    let mut profile = InstitutionalOperatorProfile::new(addr(1), "Test".into(), "t@t.com".into(), 0);
    profile.uptime_ratio = 0.995;
    profile.datasets_contributed = 200; // Cap = 50

    let b = calc.calculate_epoch_rewards(&profile);
    let wei = U256::from(10).pow(U256::from(DECIMALS));
    assert_eq!(b.data_provision_wei, U256::from(250u64) * wei);
}

#[test]
fn test_institutional_proportional_uptime_bonus() {
    let calc = InstitutionalRewardCalculator::new(InstitutionalRewardConfig::default());

    let mut profile = InstitutionalOperatorProfile::new(addr(1), "Test".into(), "t@t.com".into(), 0);
    profile.uptime_ratio = 0.95;
    profile.is_active = true;
    profile.current_epoch = 1;

    let b = calc.calculate_epoch_rewards(&profile);
    assert!(b.block_validation_wei > U256::zero());
}

// ===========================================================================
// 12. LIB.RS helpers
// ===========================================================================

#[test]
fn test_latt_wei_conversion_roundtrip() {
    let original = 12345u64;
    assert_eq!(wei_to_latt(latt_to_wei(original)), original);
}

#[test]
fn test_latt_to_wei_zero() {
    assert_eq!(latt_to_wei(0), U256::zero());
}

#[test]
fn test_wei_to_latt_truncates() {
    let wei = latt_to_wei(100) + U256::from(999);
    assert_eq!(wei_to_latt(wei), 100);
}
