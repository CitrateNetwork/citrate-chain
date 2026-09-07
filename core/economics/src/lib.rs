// citrate/core/economics/src/lib.rs

pub mod genesis;
pub mod rewards;
pub mod token;
pub mod governance;
pub mod dynamic_pricing;
pub mod enhanced_rewards;
pub mod revenue_sharing;
pub mod unified_economics;
pub mod institutional;
pub mod slashing;
pub mod estimator;

pub use genesis::{GenesisAccount, GenesisConfig};
pub use rewards::{BlockReward, RewardCalculator, RewardConfig};
pub use token::{Token, TokenConfig, DECIMALS};
pub use governance::{
    GovernanceConfig, GovernanceManager, Proposal, ProposalType, Vote, VoteType,
    VotingDelegation, ProposalStatus, ProposalUpdate, MarketplaceAction,
};
pub use dynamic_pricing::{
    DynamicPricingConfig, DynamicPricingManager, UtilizationMetrics, PricingUpdate,
    PriceChange, OperationType, PriceTrend,
};
pub use enhanced_rewards::{
    EnhancedRewardConfig, ValidatorPerformance, AIContribution,
    NetworkHealth,
};
pub use revenue_sharing::{
    RevenueShareConfig, RevenueShareManager, RevenuePool, StakeholderType,
    RevenueDistribution, StakeholderContribution, PerformanceMetrics, RevenueEvent,
};
pub use unified_economics::{
    UnifiedEconomicsConfig, UnifiedEconomicsManager, VotingPower, EconomicState,
    BlockEconomicUpdate,
};
pub use institutional::{
    InstitutionalRewardType, InstitutionalRewardConfig, InstitutionalOperatorProfile,
    InstitutionalRewardBreakdown, InstitutionalRewardCalculator,
};
pub use slashing::{
    SlashingOffense, InstitutionalSlashingConfig, SlashingRecord,
    OperatorSlashingState, InstitutionalSlashingManager,
};
pub use estimator::{
    EstimationParams, MonthlyProjection, RewardEstimation, InstitutionalRewardEstimator,
};

use primitive_types::U256;

/// Native token symbol
pub const TOKEN_SYMBOL: &str = "SALT";

/// Native token name
pub const TOKEN_NAME: &str = "Citrate";

/// Total supply cap: 1 trillion SALT (reroll 2026-09: scaled 1000× from the
/// former 1B cap, with the testnet_beta genesis distribution scaled in step).
/// This is the single source of truth — `TokenConfig::default` and
/// `GenesisConfig::validate` derive the wei cap from it.
pub const TOTAL_SUPPLY: u128 = 1_000_000_000_000;

/// Convert SALT amount to wei (smallest unit)
pub fn latt_to_wei(latt: u64) -> U256 {
    U256::from(latt) * U256::from(10).pow(U256::from(DECIMALS))
}

/// Convert wei to SALT
pub fn wei_to_latt(wei: U256) -> u64 {
    (wei / U256::from(10).pow(U256::from(DECIMALS))).as_u64()
}
