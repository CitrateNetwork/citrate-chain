// citrate/core/economics/src/rewards.rs
// PANIC-S1 G2: this module is on the block/genesis path (T1). Production code here
// may not panic; money math returns errors (D3 = reject).
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::string_slice
    )
)]

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
            halving_interval: 2_100_000,        // ~4 years at 2s blocks
            inference_bonus: 0,                 // 0.01 SALT per inference
            model_deployment_bonus: 1,          // 1 SALT per model deployment
            treasury_percentage: 10,            // 10% to treasury
            treasury_address: Address([0; 20]), // Will be set in genesis
        }
    }
}

/// Why a block reward could not be computed.
///
/// PANIC-S1 / owner decision D3 = REJECT: reward and supply math never panics
/// and never saturates. Any overflow, or a config that would make the math
/// meaningless, is an error, and the block that would mint it is rejected
/// (`ExecutionError::RewardSettlement`). A wrong reward credited silently is a
/// consensus fork; a rejected block is not.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RewardError {
    #[error("invalid reward config: {0}")]
    InvalidConfig(&'static str),
    #[error("reward arithmetic overflow in {0}")]
    Overflow(&'static str),
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

/// Selector (first 4 data bytes) marking an inference request.
const INFERENCE_SELECTOR: [u8; 4] = [0x02, 0x00, 0x00, 0x00];
/// Selector (first 4 data bytes) marking a model registration.
const MODEL_REGISTER_SELECTOR: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

/// 10^exp as U256. Every call site passes DECIMALS or DECIMALS - 2 (<= 18),
/// so this never overflows; the checked form keeps that a proof, not a hope.
fn pow10(exp: u32, what: &'static str) -> Result<U256, RewardError> {
    U256::from(10u8)
        .checked_pow(U256::from(exp))
        .ok_or(RewardError::Overflow(what))
}

impl RewardCalculator {
    pub fn new(config: RewardConfig) -> Self {
        Self { config }
    }

    fn validate(&self) -> Result<(), RewardError> {
        if self.config.halving_interval == 0 {
            return Err(RewardError::InvalidConfig("halving_interval must be > 0"));
        }
        if self.config.treasury_percentage > 100 {
            return Err(RewardError::InvalidConfig(
                "treasury_percentage must be <= 100",
            ));
        }
        Ok(())
    }

    /// Calculate block reward for a given block.
    ///
    /// Errors (never panics, never saturates) on an invalid config or on overflow;
    /// the caller rejects the block.
    pub fn calculate_reward(&self, block: &Block) -> Result<BlockReward, RewardError> {
        self.validate()?;
        let over = RewardError::Overflow;

        // Calculate base reward with halving
        let halvings = block
            .header
            .height
            .checked_div(self.config.halving_interval)
            .ok_or(RewardError::InvalidConfig("halving_interval must be > 0"))?;
        let base_reward = if halvings >= 64 {
            0 // No more rewards after 64 halvings
        } else {
            self.config.block_reward >> halvings // Divide by 2^halvings (halvings < 64)
        };

        // Convert to wei
        let mut total_reward = U256::from(base_reward)
            .checked_mul(pow10(DECIMALS, "base reward scale")?)
            .ok_or(over("base reward"))?;

        // Add inference bonuses
        let inference_count = self.count_inferences(block);
        if inference_count > 0 {
            let inference_reward = U256::from(self.config.inference_bonus)
                .checked_mul(U256::from(inference_count))
                .and_then(|v| {
                    v.checked_mul(pow10(DECIMALS.saturating_sub(2), "inference scale").ok()?)
                })
                .ok_or(over("inference bonus"))?; // 0.01 SALT units
            total_reward = total_reward
                .checked_add(inference_reward)
                .ok_or(over("total + inference bonus"))?;
        }

        // Add model deployment bonus
        if self.has_model_deployment(block) {
            let model_reward = U256::from(self.config.model_deployment_bonus)
                .checked_mul(pow10(DECIMALS, "model bonus scale")?)
                .ok_or(over("model deployment bonus"))?;
            total_reward = total_reward
                .checked_add(model_reward)
                .ok_or(over("total + model bonus"))?;
        }

        // Calculate treasury allocation (treasury_percentage <= 100, validated above,
        // so treasury_reward <= total_reward and the subtraction cannot underflow).
        let treasury_reward = total_reward
            .checked_mul(U256::from(self.config.treasury_percentage))
            .ok_or(over("treasury share"))?
            .checked_div(U256::from(100u8))
            .ok_or(over("treasury share"))?;
        let validator_reward = total_reward
            .checked_sub(treasury_reward)
            .ok_or(over("validator share"))?;

        Ok(BlockReward {
            validator_reward,
            treasury_reward,
            total_reward,
        })
    }

    /// Count inference transactions in block
    fn count_inferences(&self, block: &Block) -> u64 {
        // Heuristic based on execution encoding:
        // Inference requests are marked with first 4 data bytes [0x02, 0x00, 0x00, 0x00]
        let mut count = 0u64;
        for tx in &block.transactions {
            if tx.data.starts_with(&INFERENCE_SELECTOR) {
                count = count.saturating_add(1); // bounded by the block's tx count
            }
        }
        count
    }

    /// Check if block contains model deployment
    fn has_model_deployment(&self, block: &Block) -> bool {
        // Consider either a contract deployment (tx.to == None) or
        // a model registration call (selector [0x01, 0x00, 0x00, 0x00]) as a deployment event.
        block
            .transactions
            .iter()
            .any(|tx| tx.to.is_none() || tx.data.starts_with(&MODEL_REGISTER_SELECTOR))
    }

    /// Calculate total supply at a given block height.
    ///
    /// Errors (never panics, never saturates) on an invalid config or overflow.
    pub fn total_supply_at_height(&self, height: u64) -> Result<U256, RewardError> {
        self.validate()?;
        let over = RewardError::Overflow;
        let interval = self.config.halving_interval;
        let wei = pow10(DECIMALS, "supply scale")?;
        let mut total = U256::zero();
        let mut current_reward = self.config.block_reward;
        let mut blocks_processed = 0u64;

        for halving in 0u64..64 {
            let blocks_in_period = if halving == 0 {
                interval.min(height)
            } else {
                let start = halving.checked_mul(interval).ok_or(over("period start"))?;
                if start >= height {
                    break;
                }
                let end = halving
                    .checked_add(1)
                    .and_then(|h| h.checked_mul(interval))
                    .ok_or(over("period end"))?
                    .min(height);
                end.checked_sub(start).ok_or(over("period length"))?
            };

            let period_reward = U256::from(current_reward)
                .checked_mul(U256::from(blocks_in_period))
                .and_then(|v| v.checked_mul(wei))
                .ok_or(over("period reward"))?;
            total = total
                .checked_add(period_reward)
                .ok_or(over("total supply"))?;

            blocks_processed = blocks_processed
                .checked_add(blocks_in_period)
                .ok_or(over("blocks processed"))?;
            if blocks_processed >= height {
                break;
            }

            current_reward /= 2;
            if current_reward == 0 {
                break;
            }
        }

        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_consensus::types::BlockBuilder;

    fn salt(n: u64) -> U256 {
        U256::from(n) * U256::from(10).pow(U256::from(18))
    }

    #[test]
    fn panic_s1_total_supply_crosses_halvings_exactly() {
        // interval 10, 10 SALT: blocks 0..10 at 10, 10..20 at 5, 20..25 at 2 (5 >> 1).
        let calc = RewardCalculator::new(RewardConfig {
            halving_interval: 10,
            ..RewardConfig::default()
        });
        assert_eq!(calc.total_supply_at_height(10).expect("valid"), salt(100));
        assert_eq!(calc.total_supply_at_height(20).expect("valid"), salt(150));
        assert_eq!(calc.total_supply_at_height(25).expect("valid"), salt(160));
        assert_eq!(calc.total_supply_at_height(0).expect("valid"), U256::zero());
    }

    #[test]
    fn panic_s1_invalid_config_is_rejected_not_panicked() {
        let block = BlockBuilder::new().height(5).build_unhashed();
        let zero_halving = RewardCalculator::new(RewardConfig {
            halving_interval: 0,
            ..RewardConfig::default()
        });
        assert!(matches!(
            zero_halving.calculate_reward(&block),
            Err(RewardError::InvalidConfig(_))
        ));
        assert!(matches!(
            zero_halving.total_supply_at_height(10),
            Err(RewardError::InvalidConfig(_))
        ));
        let over_100 = RewardCalculator::new(RewardConfig {
            treasury_percentage: 101,
            ..RewardConfig::default()
        });
        assert!(matches!(
            over_100.calculate_reward(&block),
            Err(RewardError::InvalidConfig(_))
        ));
        // Boundary: exactly 100% to treasury is valid (validator gets 0, no underflow).
        let all = RewardCalculator::new(RewardConfig {
            treasury_percentage: 100,
            ..RewardConfig::default()
        });
        let r = all.calculate_reward(&block).expect("100% is valid");
        assert_eq!(r.validator_reward, U256::zero());
        assert_eq!(r.treasury_reward, r.total_reward);
    }

    #[test]
    fn panic_s1_extreme_inputs_compute_exactly_without_wrapping() {
        // The reward inputs are u64, so the U256 math CANNOT overflow: even
        // u64::MAX * (txs in a block) * 1e16 is ~1e36-scale, far below U256::MAX (~1e77).
        // The checked_* Err arms in calculate_reward are therefore unreachable
        // defence-in-depth; what IS reachable under D3 is invalid-config rejection
        // (see panic_s1_invalid_config_is_rejected_not_panicked). This test pins that
        // the most extreme u64 inputs still compute EXACTLY (no wrap, no cap).
        let cfg = RewardConfig {
            inference_bonus: u64::MAX,
            block_reward: u64::MAX,
            ..RewardConfig::default()
        };
        let calc = RewardCalculator::new(cfg);
        let tx = citrate_consensus::types::Transaction {
            data: vec![0x02, 0, 0, 0],
            ..Default::default()
        };
        let txs: Vec<_> = std::iter::repeat_n(tx, 4).collect();
        let block = BlockBuilder::new().transactions(txs).build_unhashed();
        let ok = calc.calculate_reward(&block).expect("fits in U256");
        let wei = U256::from(10).pow(U256::from(18));
        // base + 4 inferences + the model-deployment bonus (default txs have `to: None`,
        // which counts as a contract deployment: +model_deployment_bonus SALT).
        let expect_total = U256::from(u64::MAX) * wei
            + U256::from(u64::MAX) * U256::from(4) * U256::from(10).pow(U256::from(16))
            + U256::from(RewardConfig::default().model_deployment_bonus) * wei;
        assert_eq!(
            ok.total_reward, expect_total,
            "exact, not wrapped or capped"
        );
        assert_eq!(ok.validator_reward + ok.treasury_reward, ok.total_reward);
        // The supply projection at the extreme is also exact-or-error, never a panic.
        let proj = RewardCalculator::new(RewardConfig {
            block_reward: u64::MAX,
            halving_interval: u64::MAX,
            ..RewardConfig::default()
        });
        assert!(proj.total_supply_at_height(u64::MAX).is_ok());
    }

    #[test]
    fn panic_s1_valid_config_math_is_unchanged() {
        let calc = RewardCalculator::new(RewardConfig {
            inference_bonus: 1,
            ..RewardConfig::default()
        });
        let to = Some(citrate_consensus::types::PublicKey::new([1; 32]));
        let inf = citrate_consensus::types::Transaction {
            data: vec![0x02, 0, 0, 0, 0xff],
            to,
            ..Default::default()
        };
        // < 4 bytes: not an inference, never indexed
        let short = citrate_consensus::types::Transaction {
            data: vec![0x02, 0, 0],
            to,
            ..Default::default()
        };
        let block = BlockBuilder::new()
            .transactions(vec![inf, short])
            .build_unhashed();
        let r = calc.calculate_reward(&block).expect("valid");
        // 10 SALT base + 1 inference * 0.01 SALT; 10% treasury.
        let total = salt(10) + U256::from(10).pow(U256::from(16));
        assert_eq!(r.total_reward, total);
        assert_eq!(r.treasury_reward, total * U256::from(10) / U256::from(100));
        assert_eq!(r.validator_reward, total - r.treasury_reward);
        assert_eq!(calc.total_supply_at_height(100).expect("valid"), salt(1000));
    }

    #[test]
    fn test_block_reward_calculation() {
        let config = RewardConfig::default();
        let calculator = RewardCalculator::new(config);

        // Create a test block at height 0
        let block = BlockBuilder::new().build_unhashed();

        let reward = calculator.calculate_reward(&block).expect("valid config");

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
        let block = BlockBuilder::new().height(2_100_000).build_unhashed();

        let reward = calculator.calculate_reward(&block).expect("valid config");

        // After halving: 5 SALT = 5 * 10^18 wei
        let expected_total = U256::from(5) * U256::from(10).pow(U256::from(18));
        assert_eq!(reward.total_reward, expected_total);
    }
}
