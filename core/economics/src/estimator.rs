// citrate/core/economics/src/estimator.rs
//
// Monthly projection calculator for institutional operators.
// Estimates rewards based on current activity levels and network conditions.

use primitive_types::U256;
use serde::{Deserialize, Serialize};

use crate::institutional::{
    InstitutionalOperatorProfile, InstitutionalRewardCalculator, InstitutionalRewardConfig,
};
use crate::token::DECIMALS;

/// CHAIN-B-F002: hard ceiling on the projection horizon. `estimate()` loops
/// once per month and pushes a `MonthlyProjection` each iteration; the
/// unauthenticated `citrate_estimateInstitutionalRewards` RPC took
/// `projection_months` straight from the caller with no clamp, so a single
/// request with `projection_months = u32::MAX` demanded ~315 GB / ~28,741 s of
/// CPU. 120 months (10 years) is well beyond any real projection horizon.
pub const MAX_PROJECTION_MONTHS: u32 = 120;

/// CHAIN-B-F002: hard ceiling on the per-month activity counts, so the reward
/// arithmetic cannot be driven with absurd inputs either.
pub const MAX_ESTIMATION_UNITS: u32 = 100_000;

/// Input parameters for reward estimation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EstimationParams {
    /// Expected uptime ratio (0.0-1.0)
    pub expected_uptime: f64,
    /// Number of models to host
    pub models_to_host: u32,
    /// Adapters expected to create per month
    pub adapters_per_month: u32,
    /// Datasets expected to contribute per month
    pub datasets_per_month: u32,
    /// Number of months to project
    pub projection_months: u32,
}

impl Default for EstimationParams {
    fn default() -> Self {
        Self {
            expected_uptime: 0.95,
            models_to_host: 2,
            adapters_per_month: 3,
            datasets_per_month: 5,
            projection_months: 12,
        }
    }
}

/// Monthly projection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonthlyProjection {
    pub month: u32,
    pub block_validation_salt: f64,
    pub model_hosting_salt: f64,
    pub adapter_creation_salt: f64,
    pub data_provision_salt: f64,
    pub total_salt: f64,
    pub cumulative_salt: f64,
}

/// Full estimation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardEstimation {
    pub monthly_projections: Vec<MonthlyProjection>,
    pub total_projected_salt: f64,
    pub average_monthly_salt: f64,
    pub min_monthly_salt: f64,
    pub max_monthly_salt: f64,
}

/// Reward estimator for institutional operators
pub struct InstitutionalRewardEstimator {
    reward_config: InstitutionalRewardConfig,
}

impl InstitutionalRewardEstimator {
    pub fn new(reward_config: InstitutionalRewardConfig) -> Self {
        Self { reward_config }
    }

    /// Project monthly rewards over a period
    pub fn estimate(&self, params: &EstimationParams) -> RewardEstimation {
        let calc = InstitutionalRewardCalculator::new(self.reward_config.clone());
        let wei_per_salt = U256::from(10).pow(U256::from(DECIMALS));

        // CHAIN-B-F002: clamp every attacker-controllable size before it drives
        // a loop / allocation or the reward arithmetic. This is the load-bearing
        // bound — it protects the RPC handler and every other caller.
        let projection_months = params.projection_months.min(MAX_PROJECTION_MONTHS);
        let models_to_host = params.models_to_host.min(MAX_ESTIMATION_UNITS);
        let adapters_per_month = params.adapters_per_month.min(MAX_ESTIMATION_UNITS);
        let datasets_per_month = params.datasets_per_month.min(MAX_ESTIMATION_UNITS);

        let mut projections = Vec::with_capacity(projection_months as usize);
        let mut cumulative = 0.0f64;
        let mut min_monthly = f64::MAX;
        let mut max_monthly = 0.0f64;

        for month in 1..=projection_months {
            // Build a synthetic profile for this month
            let mut profile = InstitutionalOperatorProfile::new(
                citrate_execution::types::Address([0; 20]),
                String::new(),
                String::new(),
                0,
            );
            profile.uptime_ratio = params.expected_uptime;
            profile.models_hosted = models_to_host;
            profile.adapters_created = adapters_per_month;
            profile.datasets_contributed = datasets_per_month;
            profile.is_active = true;
            profile.current_epoch = month as u64;

            let breakdown = calc.calculate_epoch_rewards(&profile);

            let to_salt = |wei_val: U256| -> f64 {
                if wei_per_salt.is_zero() {
                    return 0.0;
                }
                let whole = wei_val / wei_per_salt;
                let frac = wei_val % wei_per_salt;
                whole.as_u64() as f64 + (frac.as_u64() as f64 / wei_per_salt.as_u64() as f64)
            };

            let block_salt = to_salt(breakdown.block_validation_wei);
            let model_salt = to_salt(breakdown.model_hosting_wei);
            let adapter_salt = to_salt(breakdown.adapter_creation_wei);
            let data_salt = to_salt(breakdown.data_provision_wei);
            let total = block_salt + model_salt + adapter_salt + data_salt;

            cumulative += total;
            min_monthly = min_monthly.min(total);
            max_monthly = max_monthly.max(total);

            projections.push(MonthlyProjection {
                month,
                block_validation_salt: block_salt,
                model_hosting_salt: model_salt,
                adapter_creation_salt: adapter_salt,
                data_provision_salt: data_salt,
                total_salt: total,
                cumulative_salt: cumulative,
            });
        }

        let avg = if projection_months > 0 {
            cumulative / projection_months as f64
        } else {
            0.0
        };

        RewardEstimation {
            monthly_projections: projections,
            total_projected_salt: cumulative,
            average_monthly_salt: avg,
            min_monthly_salt: if min_monthly == f64::MAX {
                0.0
            } else {
                min_monthly
            },
            max_monthly_salt: max_monthly,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_estimation() {
        let estimator = InstitutionalRewardEstimator::new(InstitutionalRewardConfig::default());
        let params = EstimationParams::default();

        let result = estimator.estimate(&params);

        assert_eq!(result.monthly_projections.len(), 12);
        assert!(result.total_projected_salt > 0.0);
        assert!(result.average_monthly_salt > 0.0);
    }

    /// CHAIN-B-F002 tripwire: an absurd `projection_months` must be clamped, so
    /// the loop and the projections Vec cannot be driven to ~315 GB / hours of
    /// CPU by a single unauthenticated RPC. RED before the clamp (the Vec would
    /// hold u32::MAX entries — an OOM, so we assert the bound rather than run
    /// the unclamped path); GREEN after (capped at MAX_PROJECTION_MONTHS).
    #[test]
    fn f002_projection_months_is_clamped() {
        let estimator = InstitutionalRewardEstimator::new(InstitutionalRewardConfig::default());
        let params = EstimationParams {
            projection_months: u32::MAX,
            ..Default::default()
        };

        let result = estimator.estimate(&params);
        assert_eq!(
            result.monthly_projections.len(),
            MAX_PROJECTION_MONTHS as usize,
            "projection_months must be clamped to MAX_PROJECTION_MONTHS"
        );
    }

    /// CHAIN-B-F002: the per-month activity counts are clamped too, so the
    /// reward arithmetic cannot be driven with absurd inputs.
    #[test]
    fn f002_activity_counts_are_clamped() {
        let estimator = InstitutionalRewardEstimator::new(InstitutionalRewardConfig::default());
        let result = estimator.estimate(&EstimationParams {
            models_to_host: u32::MAX,
            adapters_per_month: u32::MAX,
            datasets_per_month: u32::MAX,
            projection_months: 1,
            ..Default::default()
        });
        assert_eq!(result.monthly_projections.len(), 1);
    }

    #[test]
    fn test_twelve_month_projection_count() {
        let estimator = InstitutionalRewardEstimator::new(InstitutionalRewardConfig::default());
        let params = EstimationParams {
            projection_months: 6,
            ..Default::default()
        };

        let result = estimator.estimate(&params);
        assert_eq!(result.monthly_projections.len(), 6);
    }

    #[test]
    fn test_cumulative_increases() {
        let estimator = InstitutionalRewardEstimator::new(InstitutionalRewardConfig::default());
        let params = EstimationParams::default();
        let result = estimator.estimate(&params);

        for i in 1..result.monthly_projections.len() {
            assert!(
                result.monthly_projections[i].cumulative_salt
                    >= result.monthly_projections[i - 1].cumulative_salt
            );
        }
    }

    #[test]
    fn test_zero_uptime_gives_zero() {
        let estimator = InstitutionalRewardEstimator::new(InstitutionalRewardConfig::default());
        let params = EstimationParams {
            expected_uptime: 0.5, // Below 90% threshold
            ..Default::default()
        };

        let result = estimator.estimate(&params);
        assert_eq!(result.total_projected_salt, 0.0);
    }

    #[test]
    fn test_more_models_more_rewards() {
        let estimator = InstitutionalRewardEstimator::new(InstitutionalRewardConfig::default());

        let low = estimator.estimate(&EstimationParams {
            models_to_host: 1,
            projection_months: 1,
            ..Default::default()
        });

        let high = estimator.estimate(&EstimationParams {
            models_to_host: 5,
            projection_months: 1,
            ..Default::default()
        });

        assert!(high.total_projected_salt > low.total_projected_salt);
    }

    #[test]
    fn test_monthly_breakdown_sums_to_total() {
        let estimator = InstitutionalRewardEstimator::new(InstitutionalRewardConfig::default());
        let params = EstimationParams::default();
        let result = estimator.estimate(&params);

        for proj in &result.monthly_projections {
            let sum = proj.block_validation_salt
                + proj.model_hosting_salt
                + proj.adapter_creation_salt
                + proj.data_provision_salt;
            assert!((sum - proj.total_salt).abs() < 0.01);
        }
    }
}
