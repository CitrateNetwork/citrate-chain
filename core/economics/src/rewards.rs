// citrate/core/economics/src/rewards.rs

use crate::token::DECIMALS;
use citrate_consensus::types::Block;
use citrate_execution::types::Address;
use primitive_types::U256;
use serde::{Deserialize, Serialize};

/// Block reward configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardConfig {
    /// Base block reward in SALT
    pub block_reward: u64,

    /// Halving interval (number of blocks)
    pub halving_interval: u64,

    /// Inference bonus per inference in block (in SALT)
    pub inference_bonus: u64,

    /// Model deployment bonus (in SALT)
    pub model_deployment_bonus: u64,

    /// Treasury allocation percentage (0-100)
    pub treasury_percentage: u8,

    /// Treasury address
    pub treasury_address: Address,
}

impl Default for RewardConfig {
    fn default() -> Self {
        Self {
            block_reward: 10,                   // 10 SALT per block
            // 2_100_000 blocks × 2s ≈ 48.6 days (NOT "~4 years"; the old comment
            // was off by ~30×). A true 4-year interval would need ~63M blocks —
            // changing it alters emission and is an OWNER/reroll decision.
            halving_interval: 2_100_000,
            inference_bonus: 0,                 // 0.01 SALT per inference
            model_deployment_bonus: 1,          // 1 SALT per model deployment
            treasury_percentage: 10,            // 10% to treasury
            treasury_address: Address([0; 20]), // Will be set in genesis
        }
    }
}

/// Block reward calculation
#[derive(Debug, Clone)]
pub struct BlockReward {
    pub validator_reward: U256,
    pub treasury_reward: U256,
    pub total_reward: U256,
}

/// Reward calculator
pub struct RewardCalculator {
    config: RewardConfig,
}

impl RewardCalculator {
    pub fn new(config: RewardConfig) -> Self {
        Self { config }
    }

    /// Calculate block reward for a given block
    pub fn calculate_reward(&self, block: &Block) -> BlockReward {
        // Calculate base reward with halving.
        //
        // The halving is applied to the *wei-denominated* subsidy, not to the
        // whole-SALT `block_reward` field. Halving the whole-SALT u64 first
        // (`block_reward >> halvings`) truncated 2.5 SALT to 2 and reached a
        // permanent 0 after only four halvings, collapsing the security budget.
        // Scaling to wei before the shift keeps fractional-SALT emission
        // (10 -> 5 -> 2.5 -> 1.25 -> …) representable.
        let halvings = block.header.height / self.config.halving_interval;
        let base_reward_wei = if halvings >= 64 {
            U256::zero() // No more rewards after 64 halvings
        } else {
            let full = U256::from(self.config.block_reward) * U256::from(10).pow(U256::from(DECIMALS));
            full / U256::from(2).pow(U256::from(halvings))
        };

        let mut total_reward = base_reward_wei;

        // Add inference bonuses
        let inference_count = self.count_inferences(block);
        if inference_count > 0 {
            let inference_reward = U256::from(self.config.inference_bonus)
                * U256::from(inference_count)
                * U256::from(10).pow(U256::from(DECIMALS - 2)); // 0.01 SALT units
            total_reward += inference_reward;
        }

        // Add model deployment bonus
        if self.has_model_deployment(block) {
            let model_reward = U256::from(self.config.model_deployment_bonus)
                * U256::from(10).pow(U256::from(DECIMALS));
            total_reward += model_reward;
        }

        // Calculate treasury allocation
        let treasury_reward =
            total_reward * U256::from(self.config.treasury_percentage) / U256::from(100);
        let validator_reward = total_reward - treasury_reward;

        BlockReward {
            validator_reward,
            treasury_reward,
            total_reward,
        }
    }

    /// Count inference transactions in block
    fn count_inferences(&self, block: &Block) -> u64 {
        // Heuristic based on execution encoding:
        // Inference requests are marked with first 4 data bytes [0x02, 0x00, 0x00, 0x00]
        let mut count = 0u64;
        for tx in &block.transactions {
            if tx.data.len() >= 4 && tx.data[0..4] == [0x02, 0x00, 0x00, 0x00] {
                count += 1;
            }
        }
        count
    }

    /// Check if block contains model deployment
    fn has_model_deployment(&self, block: &Block) -> bool {
        // Consider either a contract deployment (tx.to == None) or
        // a model registration call (selector [0x01, 0x00, 0x00, 0x00]) as a deployment event.
        for tx in &block.transactions {
            if tx.to.is_none() {
                return true;
            }
            if tx.data.len() >= 4 && tx.data[0..4] == [0x01, 0x00, 0x00, 0x00] {
                return true;
            }
        }
        false
    }

    /// Calculate total supply at a given block height.
    ///
    /// Projection only (drives RPC/economics estimates, not consensus). Kept in
    /// lockstep with `calculate_reward`: the per-period subsidy is halved in
    /// wei, so the projection tracks the fractional-SALT schedule instead of the
    /// truncated `current_reward /= 2` (whole-SALT) figure it used before.
    pub fn total_supply_at_height(&self, height: u64) -> U256 {
        let mut total = U256::zero();
        let mut current_reward_wei =
            U256::from(self.config.block_reward) * U256::from(10).pow(U256::from(DECIMALS));
        let mut blocks_processed = 0u64;

        for halving in 0..64 {
            let blocks_in_period = if halving == 0 {
                self.config.halving_interval.min(height)
            } else {
                let start = halving * self.config.halving_interval;
                let end = ((halving + 1) * self.config.halving_interval).min(height);
                if start >= height {
                    break;
                }
                end - start
            };

            let period_reward = current_reward_wei * U256::from(blocks_in_period);
            total += period_reward;

            blocks_processed += blocks_in_period;
            if blocks_processed >= height {
                break;
            }

            current_reward_wei /= U256::from(2);
            if current_reward_wei.is_zero() {
                break;
            }
        }

        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_consensus::types::BlockBuilder;

    #[test]
    fn test_block_reward_calculation() {
        let config = RewardConfig::default();
        let calculator = RewardCalculator::new(config);

        // Create a test block at height 0
        let block = BlockBuilder::new().build_unhashed();

        let reward = calculator.calculate_reward(&block);

        // 10 SALT = 10 * 10^18 wei
        let expected_total = U256::from(10) * U256::from(10).pow(U256::from(18));
        assert_eq!(reward.total_reward, expected_total);

        // 10% to treasury
        let expected_treasury = expected_total / 10;
        assert_eq!(reward.treasury_reward, expected_treasury);
    }

    #[test]
    fn test_halving() {
        let config = RewardConfig::default();
        let calculator = RewardCalculator::new(config);

        // Test block after first halving
        let block = BlockBuilder::new()
            .height(2_100_000)
            .build_unhashed();

        let reward = calculator.calculate_reward(&block);

        // After halving: 5 SALT = 5 * 10^18 wei
        let expected_total = U256::from(5) * U256::from(10).pow(U256::from(18));
        assert_eq!(reward.total_reward, expected_total);
    }

    // RC-8: the buggy schedule truncated the whole-SALT subsidy and hit a
    // permanent 0 after four halvings (10→5→2→1→0). The corrected schedule
    // halves in wei, so fractional-SALT emission stays representable and does
    // not collapse to 0 within 64 halvings.
    #[test]
    fn test_halving_no_whole_salt_truncation() {
        let config = RewardConfig::default();
        let calculator = RewardCalculator::new(config.clone());
        let one_salt = U256::from(10).pow(U256::from(18));

        // Third halving → 1.25 SALT (was truncated to 1 SALT before the fix).
        let block = BlockBuilder::new()
            .height(3 * config.halving_interval)
            .build_unhashed();
        let reward = calculator.calculate_reward(&block);
        assert_eq!(reward.total_reward, one_salt * U256::from(125) / U256::from(100));

        // Fourth halving → 0.625 SALT (was 0 before the fix: the bug's smoking gun).
        let block = BlockBuilder::new()
            .height(4 * config.halving_interval)
            .build_unhashed();
        let reward = calculator.calculate_reward(&block);
        assert_eq!(reward.total_reward, one_salt * U256::from(625) / U256::from(1000));
        assert!(!reward.total_reward.is_zero());
    }
}
