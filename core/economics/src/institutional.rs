// citrate/core/economics/src/institutional.rs
//
// Institutional operator profiles and reward calculations for school node pilots.
// Defines 4 reward types: block validation, model hosting, adapter creation, data provision.

use citrate_execution::types::Address;
use primitive_types::U256;
use serde::{Deserialize, Serialize};

use crate::token::DECIMALS;

/// Reward type categories for institutional operators
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InstitutionalRewardType {
    /// Block validation rewards (base + uptime bonus)
    BlockValidation,
    /// Model hosting rewards (per-model per-epoch)
    ModelHosting,
    /// Adapter creation rewards (per-adapter published)
    AdapterCreation,
    /// Data provision rewards (per-dataset contributed)
    DataProvision,
}

/// Configuration for institutional reward rates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstitutionalRewardConfig {
    /// Block validation: base monthly SALT (before halving)
    pub block_validation_monthly_salt: u64,
    /// Uptime bonus multiplier (e.g., 1.2 = 20% bonus at 100% uptime)
    pub uptime_bonus_multiplier: f64,
    /// Model hosting: SALT per model per 30-day epoch
    pub model_hosting_per_model_salt: u64,
    /// Adapter creation: SALT per adapter published
    pub adapter_creation_salt: u64,
    /// Data provision: SALT per dataset contributed per epoch
    pub data_provision_per_dataset_salt: u64,
    /// Minimum uptime percentage to qualify for any rewards (0.0-1.0)
    pub min_uptime_threshold: f64,
    /// Maximum models that earn hosting rewards per operator
    pub max_rewarded_models: u32,
    /// Maximum adapters that earn creation rewards per epoch
    pub max_rewarded_adapters_per_epoch: u32,
    /// Maximum datasets that earn provision rewards per epoch
    pub max_rewarded_datasets_per_epoch: u32,
}

impl Default for InstitutionalRewardConfig {
    fn default() -> Self {
        Self {
            block_validation_monthly_salt: 150,
            uptime_bonus_multiplier: 1.2,
            model_hosting_per_model_salt: 25,
            adapter_creation_salt: 10,
            data_provision_per_dataset_salt: 5,
            min_uptime_threshold: 0.90,
            max_rewarded_models: 10,
            max_rewarded_adapters_per_epoch: 20,
            max_rewarded_datasets_per_epoch: 50,
        }
    }
}

/// Operator profile tracking institutional node activity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstitutionalOperatorProfile {
    /// Operator address
    pub address: Address,
    /// Human-readable institution name
    pub institution_name: String,
    /// Contact email (for pilot coordination)
    pub contact_email: String,
    /// Blocks validated this epoch
    pub blocks_validated: u64,
    /// Uptime ratio for current epoch (0.0-1.0)
    pub uptime_ratio: f64,
    /// Number of models currently hosted
    pub models_hosted: u32,
    /// Adapters created this epoch
    pub adapters_created: u32,
    /// Datasets contributed this epoch
    pub datasets_contributed: u32,
    /// Epoch number (30-day periods from genesis)
    pub current_epoch: u64,
    /// Total SALT earned lifetime (in wei)
    pub total_earned_wei: U256,
    /// Whether operator is currently active
    pub is_active: bool,
    /// Registration timestamp (unix seconds)
    pub registered_at: u64,
}

impl InstitutionalOperatorProfile {
    pub fn new(address: Address, institution_name: String, contact_email: String, registered_at: u64) -> Self {
        Self {
            address,
            institution_name,
            contact_email,
            blocks_validated: 0,
            uptime_ratio: 1.0,
            models_hosted: 0,
            adapters_created: 0,
            datasets_contributed: 0,
            current_epoch: 0,
            total_earned_wei: U256::zero(),
            is_active: true,
            registered_at,
        }
    }

    /// Reset per-epoch counters (called at epoch boundary)
    pub fn reset_epoch(&mut self, new_epoch: u64) {
        self.blocks_validated = 0;
        self.uptime_ratio = 1.0;
        self.adapters_created = 0;
        self.datasets_contributed = 0;
        self.current_epoch = new_epoch;
    }
}

/// Breakdown of rewards by type for a single epoch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstitutionalRewardBreakdown {
    pub block_validation_wei: U256,
    pub model_hosting_wei: U256,
    pub adapter_creation_wei: U256,
    pub data_provision_wei: U256,
    pub total_wei: U256,
    pub epoch: u64,
}

/// Calculator for institutional operator rewards
pub struct InstitutionalRewardCalculator {
    config: InstitutionalRewardConfig,
}

impl InstitutionalRewardCalculator {
    pub fn new(config: InstitutionalRewardConfig) -> Self {
        Self { config }
    }

    /// Calculate rewards for an operator for the current epoch
    pub fn calculate_epoch_rewards(&self, profile: &InstitutionalOperatorProfile) -> InstitutionalRewardBreakdown {
        let wei_per_salt = U256::from(10).pow(U256::from(DECIMALS));

        // Check minimum uptime threshold
        if profile.uptime_ratio < self.config.min_uptime_threshold || !profile.is_active {
            return InstitutionalRewardBreakdown {
                block_validation_wei: U256::zero(),
                model_hosting_wei: U256::zero(),
                adapter_creation_wei: U256::zero(),
                data_provision_wei: U256::zero(),
                total_wei: U256::zero(),
                epoch: profile.current_epoch,
            };
        }

        // 1. Block validation reward (base + uptime bonus)
        let base_validation = U256::from(self.config.block_validation_monthly_salt) * wei_per_salt;
        let uptime_bonus = if profile.uptime_ratio >= 0.99 {
            // Full uptime bonus for 99%+ uptime
            let bonus_bps = ((self.config.uptime_bonus_multiplier - 1.0) * 10000.0).round() as u64;
            base_validation * U256::from(bonus_bps) / U256::from(10000)
        } else {
            // Proportional bonus scaled by uptime
            let uptime_bps = (profile.uptime_ratio * 10000.0).round() as u64;
            let max_bonus_bps = ((self.config.uptime_bonus_multiplier - 1.0) * 10000.0).round() as u64;
            let scaled_bps = max_bonus_bps * uptime_bps / 10000;
            base_validation * U256::from(scaled_bps) / U256::from(10000)
        };
        let block_validation_wei = base_validation + uptime_bonus;

        // 2. Model hosting reward (capped)
        let rewarded_models = profile.models_hosted.min(self.config.max_rewarded_models);
        let model_hosting_wei = U256::from(self.config.model_hosting_per_model_salt)
            * U256::from(rewarded_models)
            * wei_per_salt;

        // 3. Adapter creation reward (capped)
        let rewarded_adapters = profile.adapters_created.min(self.config.max_rewarded_adapters_per_epoch);
        let adapter_creation_wei = U256::from(self.config.adapter_creation_salt)
            * U256::from(rewarded_adapters)
            * wei_per_salt;

        // 4. Data provision reward (capped)
        let rewarded_datasets = profile.datasets_contributed.min(self.config.max_rewarded_datasets_per_epoch);
        let data_provision_wei = U256::from(self.config.data_provision_per_dataset_salt)
            * U256::from(rewarded_datasets)
            * wei_per_salt;

        let total_wei = block_validation_wei + model_hosting_wei + adapter_creation_wei + data_provision_wei;

        InstitutionalRewardBreakdown {
            block_validation_wei,
            model_hosting_wei,
            adapter_creation_wei,
            data_provision_wei,
            total_wei,
            epoch: profile.current_epoch,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_address() -> Address {
        Address([0x11; 20])
    }

    fn test_profile() -> InstitutionalOperatorProfile {
        let mut p = InstitutionalOperatorProfile::new(
            test_address(),
            "Test School".to_string(),
            "admin@test.edu".to_string(),
            1700000000,
        );
        p.uptime_ratio = 0.995;
        p.models_hosted = 3;
        p.adapters_created = 5;
        p.datasets_contributed = 10;
        p.current_epoch = 1;
        p
    }

    #[test]
    fn test_default_config() {
        let config = InstitutionalRewardConfig::default();
        assert_eq!(config.block_validation_monthly_salt, 150);
        assert_eq!(config.model_hosting_per_model_salt, 25);
        assert_eq!(config.adapter_creation_salt, 10);
        assert_eq!(config.data_provision_per_dataset_salt, 5);
        assert!((config.min_uptime_threshold - 0.90).abs() < f64::EPSILON);
    }

    #[test]
    fn test_block_validation_reward_with_uptime_bonus() {
        let config = InstitutionalRewardConfig::default();
        let calc = InstitutionalRewardCalculator::new(config);
        let profile = test_profile();

        let breakdown = calc.calculate_epoch_rewards(&profile);
        let wei = U256::from(10).pow(U256::from(DECIMALS));

        // Base: 150 SALT + 20% bonus (99%+ uptime) = 180 SALT
        let expected_base = U256::from(150u64) * wei;
        let expected_bonus = expected_base * U256::from(2000u64) / U256::from(10000u64); // 20%
        let expected = expected_base + expected_bonus;
        assert_eq!(breakdown.block_validation_wei, expected);
    }

    #[test]
    fn test_model_hosting_reward() {
        let config = InstitutionalRewardConfig::default();
        let calc = InstitutionalRewardCalculator::new(config);
        let profile = test_profile();

        let breakdown = calc.calculate_epoch_rewards(&profile);
        let wei = U256::from(10).pow(U256::from(DECIMALS));

        // 3 models * 25 SALT = 75 SALT
        let expected = U256::from(75u64) * wei;
        assert_eq!(breakdown.model_hosting_wei, expected);
    }

    #[test]
    fn test_adapter_creation_reward() {
        let config = InstitutionalRewardConfig::default();
        let calc = InstitutionalRewardCalculator::new(config);
        let profile = test_profile();

        let breakdown = calc.calculate_epoch_rewards(&profile);
        let wei = U256::from(10).pow(U256::from(DECIMALS));

        // 5 adapters * 10 SALT = 50 SALT
        let expected = U256::from(50u64) * wei;
        assert_eq!(breakdown.adapter_creation_wei, expected);
    }

    #[test]
    fn test_data_provision_reward() {
        let config = InstitutionalRewardConfig::default();
        let calc = InstitutionalRewardCalculator::new(config);
        let profile = test_profile();

        let breakdown = calc.calculate_epoch_rewards(&profile);
        let wei = U256::from(10).pow(U256::from(DECIMALS));

        // 10 datasets * 5 SALT = 50 SALT
        let expected = U256::from(50u64) * wei;
        assert_eq!(breakdown.data_provision_wei, expected);
    }

    #[test]
    fn test_total_reward_sum() {
        let config = InstitutionalRewardConfig::default();
        let calc = InstitutionalRewardCalculator::new(config);
        let profile = test_profile();

        let breakdown = calc.calculate_epoch_rewards(&profile);
        let sum = breakdown.block_validation_wei
            + breakdown.model_hosting_wei
            + breakdown.adapter_creation_wei
            + breakdown.data_provision_wei;
        assert_eq!(breakdown.total_wei, sum);
    }

    #[test]
    fn test_below_uptime_threshold_gets_zero() {
        let config = InstitutionalRewardConfig::default();
        let calc = InstitutionalRewardCalculator::new(config);
        let mut profile = test_profile();
        profile.uptime_ratio = 0.80; // Below 90% threshold

        let breakdown = calc.calculate_epoch_rewards(&profile);
        assert_eq!(breakdown.total_wei, U256::zero());
    }

    #[test]
    fn test_inactive_operator_gets_zero() {
        let config = InstitutionalRewardConfig::default();
        let calc = InstitutionalRewardCalculator::new(config);
        let mut profile = test_profile();
        profile.is_active = false;

        let breakdown = calc.calculate_epoch_rewards(&profile);
        assert_eq!(breakdown.total_wei, U256::zero());
    }

    #[test]
    fn test_model_cap_enforced() {
        let config = InstitutionalRewardConfig::default();
        let calc = InstitutionalRewardCalculator::new(config.clone());
        let mut profile = test_profile();
        profile.models_hosted = 50; // Way above cap of 10

        let breakdown = calc.calculate_epoch_rewards(&profile);
        let wei = U256::from(10).pow(U256::from(DECIMALS));

        // Capped at 10 models * 25 SALT = 250 SALT
        let expected = U256::from(250u64) * wei;
        assert_eq!(breakdown.model_hosting_wei, expected);
    }

    #[test]
    fn test_epoch_reset() {
        let mut profile = test_profile();
        profile.blocks_validated = 100;
        profile.adapters_created = 10;
        profile.datasets_contributed = 20;

        profile.reset_epoch(5);
        assert_eq!(profile.blocks_validated, 0);
        assert_eq!(profile.adapters_created, 0);
        assert_eq!(profile.datasets_contributed, 0);
        assert_eq!(profile.current_epoch, 5);
        assert!((profile.uptime_ratio - 1.0).abs() < f64::EPSILON);
    }
}
