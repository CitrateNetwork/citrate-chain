// citrate/core/economics/src/lib.rs

pub mod dynamic_pricing;
pub mod enhanced_rewards;
pub mod estimator;
pub mod genesis;
pub mod governance;
pub mod institutional;
pub mod revenue_sharing;
pub mod rewards;
pub mod slashing;
pub mod token;
pub mod unified_economics;

pub use dynamic_pricing::{
    DynamicPricingConfig, DynamicPricingManager, OperationType, PriceChange, PriceTrend,
    PricingUpdate, UtilizationMetrics,
};
pub use enhanced_rewards::{
    AIContribution, EnhancedRewardConfig, NetworkHealth, ValidatorPerformance,
};
pub use estimator::{
    EstimationParams, InstitutionalRewardEstimator, MonthlyProjection, RewardEstimation,
};
pub use genesis::{GenesisAccount, GenesisConfig};
pub use governance::{
    GovernanceConfig, GovernanceManager, MarketplaceAction, Proposal, ProposalStatus, ProposalType,
    ProposalUpdate, Vote, VoteType, VotingDelegation,
};
pub use institutional::{
    InstitutionalOperatorProfile, InstitutionalRewardBreakdown, InstitutionalRewardCalculator,
    InstitutionalRewardConfig, InstitutionalRewardType,
};
pub use revenue_sharing::{
    PerformanceMetrics, RevenueDistribution, RevenueEvent, RevenuePool, RevenueShareConfig,
    RevenueShareManager, StakeholderContribution, StakeholderType,
};
pub use rewards::{BlockReward, RewardCalculator, RewardConfig};
pub use slashing::{
    InstitutionalSlashingConfig, InstitutionalSlashingManager, OperatorSlashingState,
    SlashingOffense, SlashingRecord,
};
pub use token::{Token, TokenConfig, DECIMALS};
pub use unified_economics::{
    BlockEconomicUpdate, EconomicState, UnifiedEconomicsConfig, UnifiedEconomicsManager,
    VotingPower,
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

/// 10^DECIMALS: wei per SALT.
#[cfg_attr(
    not(test),
    deny(
        clippy::arithmetic_side_effects,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic
    )
)]
pub fn wei_per_salt() -> U256 {
    // 10^18 < 2^60: the checked form cannot fail; it just keeps that a proof.
    U256::from(10u8)
        .checked_pow(U256::from(DECIMALS))
        .unwrap_or(U256::MAX)
}

/// Convert SALT amount to wei (smallest unit).
///
/// Total: u64::MAX * 10^18 < 2^124, far below U256::MAX, so the multiply can
/// never overflow for any `u64` input.
#[cfg_attr(
    not(test),
    deny(
        clippy::arithmetic_side_effects,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic
    )
)]
pub fn latt_to_wei(latt: u64) -> U256 {
    U256::from(latt)
        .checked_mul(wei_per_salt())
        .unwrap_or(U256::MAX)
}

/// Convert wei to whole SALT, or `None` if the SALT amount does not fit a `u64`
/// (above ~1.8e19 SALT, far beyond the 1e12 SALT total supply). PANIC-S1: the
/// old `as_u64()` panicked on such input; callers must now handle it.
#[cfg_attr(
    not(test),
    deny(
        clippy::arithmetic_side_effects,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic
    )
)]
pub fn wei_to_latt(wei: U256) -> Option<u64> {
    let salt = wei.checked_div(wei_per_salt())?;
    u64::try_from(salt).ok()
}

#[cfg(test)]
mod panic_s1_tests {
    use super::*;

    #[test]
    fn wei_to_latt_is_total() {
        assert_eq!(wei_to_latt(latt_to_wei(12_345)), Some(12_345));
        assert_eq!(wei_to_latt(U256::zero()), Some(0));
        assert_eq!(
            wei_to_latt(U256::MAX),
            None,
            "beyond u64 SALT is None, never a panic"
        );
        assert_eq!(latt_to_wei(u64::MAX), U256::from(u64::MAX) * wei_per_salt());
    }
}
