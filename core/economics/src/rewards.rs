// citrate/core/economics/src/rewards.rs

use crate::token::DECIMALS;
use citrate_execution::precompiles::inference::addresses::{
    BATCH_INFERENCE, MODEL_DEPLOY, MODEL_INFERENCE,
};
use citrate_execution::precompiles::q16::routing::ROUTING_INFERENCE;
use citrate_execution::types::{Address, TransactionReceipt};
use primitive_types::U256;
use serde::{Deserialize, Serialize};

/// The AI-inference precompile addresses whose SUCCESSFUL, gas-charged invocation
/// (as observed in a block's receipts) earns the per-inference reward bonus.
/// CHAIN-B-F001: the bonus is grounded in EXECUTED state — a receipt whose top
/// call target is one of these and whose `status` is `true` — never in a byte
/// prefix on unexecuted calldata. Mirrors the canonical precompile table in
/// `citrate_execution::precompiles`; the `inference_precompile_addrs_track_execution`
/// test fails if these ever drift from the execution crate's constants.
const INFERENCE_PRECOMPILES: [[u8; 20]; 3] = [MODEL_INFERENCE, BATCH_INFERENCE, ROUTING_INFERENCE];

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

/// Block reward calculation
#[derive(Debug, Clone)]
pub struct BlockReward {
    pub validator_reward: U256,
    pub treasury_reward: U256,
    pub total_reward: U256,
}

/// Reward calculator
#[derive(Clone)]
pub struct RewardCalculator {
    config: RewardConfig,
}

impl RewardCalculator {
    pub fn new(config: RewardConfig) -> Self {
        Self { config }
    }

    /// Calculate the block reward for a block at `height` from its EXECUTED
    /// `receipts`.
    ///
    /// CHAIN-B-F001 (unbounded-mint fix). The reward is a PURE, DETERMINISTIC
    /// function of `(height, receipts)` — never of unexecuted calldata — so every
    /// node that executes the same block computes the identical value and no fork
    /// is introduced. Three invariants close the mint:
    ///
    /// 1. **Executed, not asserted.** The inference bonus counts only receipts
    ///    whose top-level call SUCCEEDED (`status == true`) against a real
    ///    inference precompile (gas was actually charged). A transaction that
    ///    merely *begins* with a magic byte prefix, or that reverts, earns
    ///    nothing. The model-deployment bonus likewise requires a SUCCESSFUL
    ///    contract creation or model-registration precompile call.
    /// 2. **Halved.** Every bonus arm decays on the SAME halving schedule as the
    ///    base subsidy (`>> halvings`), so issuance cannot outlive the schedule.
    /// 3. **Capped.** The sum of all bonuses is clamped to at most the base
    ///    subsidy for this height, so a block's total issuance never exceeds
    ///    TWICE the published emission schedule and, once the base halves to
    ///    zero, the bonus is zero too — issuance is bounded in both magnitude and
    ///    time.
    pub fn calculate_reward(&self, height: u64, receipts: &[TransactionReceipt]) -> BlockReward {
        let halvings = height / self.config.halving_interval;
        let one_salt = U256::from(10).pow(U256::from(DECIMALS));

        // Base subsidy: whole-SALT halving, byte-for-byte the pre-fix schedule.
        // (The whole-SALT truncation is CHAIN-B-F003's concern and is deliberately
        // left intact here so this fix changes ONLY the bonus arms.)
        let base_salt = if halvings >= 64 {
            0
        } else {
            self.config.block_reward >> halvings
        };
        let base_reward = U256::from(base_salt) * one_salt;

        // Every bonus arm decays on the SAME halving schedule as the base (in wei),
        // so a bonus can never outlive the subsidy. After 64 halvings it is zero.
        let halve_bonus = |wei: U256| -> U256 {
            if halvings >= 64 {
                U256::zero()
            } else {
                wei >> (halvings as usize)
            }
        };

        // Inference bonus — grounded in receipts (executed + gas-charged), halved.
        let inference_count = Self::count_inferences(receipts);
        let inference_bonus = halve_bonus(
            U256::from(self.config.inference_bonus)
                * U256::from(inference_count)
                * U256::from(10).pow(U256::from(DECIMALS - 2)), // 0.01 SALT units
        );

        // Model-deployment bonus — grounded in receipts, halved.
        let model_bonus = if Self::has_model_deployment(receipts) {
            halve_bonus(U256::from(self.config.model_deployment_bonus) * one_salt)
        } else {
            U256::zero()
        };

        // Per-block issuance ceiling: the combined bonus may never exceed the base
        // subsidy for this height. Total issuance is therefore <= 2 * base and
        // decays to exactly zero once the base subsidy halves out.
        let bonus = inference_bonus.saturating_add(model_bonus).min(base_reward);
        let total_reward = base_reward.saturating_add(bonus);

        let treasury_reward =
            total_reward * U256::from(self.config.treasury_percentage) / U256::from(100);
        let validator_reward = total_reward - treasury_reward;

        BlockReward {
            validator_reward,
            treasury_reward,
            total_reward,
        }
    }

    /// Count SUCCESSFUL inference-precompile calls in the block's receipts.
    ///
    /// A receipt qualifies only when its top-level call target is one of the
    /// canonical inference precompiles AND it executed successfully (`status`),
    /// meaning gas was actually charged for real work. A reverted call
    /// (`status == false`) or a call to any other address earns nothing — the
    /// prefix-on-calldata heuristic that CHAIN-B-F001 exploited is gone.
    fn count_inferences(receipts: &[TransactionReceipt]) -> u64 {
        receipts
            .iter()
            .filter(|r| r.status)
            .filter(|r| r.to.is_some_and(|to| INFERENCE_PRECOMPILES.contains(&to.0)))
            .count() as u64
    }

    /// Whether the block's receipts contain a SUCCESSFUL model-deployment event:
    /// a contract creation (`to == None`) or a call to the model-registration
    /// precompile (0x0100), in either case with `status == true`. A reverted
    /// creation, or unexecuted calldata beginning with a magic prefix, does not
    /// count (CHAIN-B-F001).
    fn has_model_deployment(receipts: &[TransactionReceipt]) -> bool {
        receipts.iter().filter(|r| r.status).any(|r| match r.to {
            None => true,
            Some(to) => to.0 == MODEL_DEPLOY,
        })
    }

    /// Calculate total supply at a given block height
    pub fn total_supply_at_height(&self, height: u64) -> U256 {
        let mut total = U256::zero();
        let mut current_reward = self.config.block_reward;
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

            let period_reward = U256::from(current_reward)
                * U256::from(blocks_in_period)
                * U256::from(10).pow(U256::from(DECIMALS));
            total += period_reward;

            blocks_processed += blocks_in_period;
            if blocks_processed >= height {
                break;
            }

            current_reward /= 2;
            if current_reward == 0 {
                break;
            }
        }

        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_salt() -> U256 {
        U256::from(10).pow(U256::from(DECIMALS))
    }
    fn salt(n: u64) -> U256 {
        U256::from(n) * one_salt()
    }

    /// Minimal executed receipt: `status` = success/revert, `to` = the top-level
    /// call target (`None` = contract creation).
    fn rcpt(status: bool, to: Option<[u8; 20]>) -> TransactionReceipt {
        TransactionReceipt {
            tx_hash: Default::default(),
            block_hash: Default::default(),
            block_number: 0,
            from: Address([0u8; 20]),
            to: to.map(Address),
            gas_used: 21_000,
            status,
            logs: vec![],
            output: vec![],
            eth_tx_type: 0,
            effective_gas_price: 0,
            revert_reason: None,
        }
    }

    /// Config that pays a bonus — mirrors the live `canonical_reward_config`.
    fn bonus_cfg() -> RewardConfig {
        RewardConfig {
            inference_bonus: 1,
            model_deployment_bonus: 1,
            ..RewardConfig::default()
        }
    }

    #[test]
    fn test_block_reward_calculation() {
        let calculator = RewardCalculator::new(RewardConfig::default());
        let reward = calculator.calculate_reward(0, &[]);
        assert_eq!(reward.total_reward, salt(10));
        assert_eq!(reward.treasury_reward, salt(10) / 10);
    }

    #[test]
    fn test_halving() {
        let calculator = RewardCalculator::new(RewardConfig::default());
        let reward = calculator.calculate_reward(2_100_000, &[]);
        assert_eq!(reward.total_reward, salt(5));
    }

    // ── CHAIN-B-F001 tripwire: the reward is grounded in EXECUTED receipts, and
    //    every bonus arm is halved + capped so issuance is bounded. ──────────────

    /// A block whose transactions "look like" inferences/model calls but never
    /// executed successfully MUST earn no bonus. This is the core of the fix:
    /// the pre-fix code paid a bonus off a calldata byte prefix on UNEXECUTED
    /// (or reverting) transactions.
    #[test]
    fn prefix_without_execution_earns_nothing() {
        let calc = RewardCalculator::new(bonus_cfg());

        // (a) no receipts at all → base only.
        assert_eq!(calc.calculate_reward(0, &[]).total_reward, salt(10));

        // (b) a REVERTED call to the inference precompile (and a reverted
        //     creation) earns nothing — the tx was included but did no work.
        let reverted = vec![rcpt(false, Some(MODEL_INFERENCE)), rcpt(false, None)];
        assert_eq!(calc.calculate_reward(0, &reverted).total_reward, salt(10));

        // (c) SUCCESSFUL calls to unrelated addresses earn nothing.
        let unrelated = vec![
            rcpt(true, Some([0x42u8; 20])),
            rcpt(true, Some([0x99u8; 20])),
        ];
        assert_eq!(calc.calculate_reward(0, &unrelated).total_reward, salt(10));
    }

    #[test]
    fn successful_inference_receipt_earns_bonus() {
        let calc = RewardCalculator::new(bonus_cfg());
        let receipts = vec![
            rcpt(true, Some(MODEL_INFERENCE)),
            rcpt(true, Some(BATCH_INFERENCE)),
            rcpt(true, Some(ROUTING_INFERENCE)),
        ];
        // 3 executed inferences * 0.01 SALT on top of the 10 SALT base.
        let r = calc.calculate_reward(0, &receipts);
        assert_eq!(r.total_reward, salt(10) + salt(3) / 100);
    }

    #[test]
    fn successful_contract_creation_earns_model_bonus() {
        let calc = RewardCalculator::new(bonus_cfg());
        // status=true, to=None => a real contract creation.
        assert_eq!(
            calc.calculate_reward(0, &[rcpt(true, None)]).total_reward,
            salt(11)
        );
        // model-registration precompile (0x0100) also counts.
        assert_eq!(
            calc.calculate_reward(0, &[rcpt(true, Some(MODEL_DEPLOY))])
                .total_reward,
            salt(11)
        );
        // a reverted creation earns nothing.
        assert_eq!(
            calc.calculate_reward(0, &[rcpt(false, None)]).total_reward,
            salt(10)
        );
    }

    #[test]
    fn bonus_is_halved_with_the_schedule() {
        let calc = RewardCalculator::new(bonus_cfg());
        let receipts = vec![rcpt(true, Some(MODEL_INFERENCE))];
        let at0 = calc.calculate_reward(0, &receipts).total_reward;
        let at1 = calc.calculate_reward(2_100_000, &receipts).total_reward;
        assert_eq!(at0, salt(10) + salt(1) / 100); // 10.01 SALT
        assert_eq!(at1, salt(5) + (salt(1) / 100) / 2); // base 5 + HALVED bonus
    }

    #[test]
    fn bonus_is_capped_at_the_base_subsidy() {
        let calc = RewardCalculator::new(bonus_cfg());
        // 5000 executed inferences => raw bonus 50 SALT, clamped to the base (10).
        let receipts: Vec<_> = (0..5000)
            .map(|_| rcpt(true, Some(MODEL_INFERENCE)))
            .collect();
        assert_eq!(calc.calculate_reward(0, &receipts).total_reward, salt(20));
    }

    /// CHAIN-B-F001b: on the buggy code a full block still minted pure,
    /// never-halved bonus at height 8.4M and forever after (unbounded in time).
    /// With the fix the base is zero, the cap is zero, and the block mints
    /// NOTHING.
    #[test]
    fn issuance_is_bounded_in_time_deep_halving_mints_zero() {
        let calc = RewardCalculator::new(bonus_cfg());
        let receipts: Vec<_> = (0..5000)
            .map(|_| rcpt(true, Some(MODEL_INFERENCE)))
            .chain(std::iter::once(rcpt(true, None)))
            .collect();
        assert_eq!(
            calc.calculate_reward(8_400_000, &receipts).total_reward,
            U256::zero()
        );
        assert_eq!(
            calc.calculate_reward(u64::MAX, &receipts).total_reward,
            U256::zero()
        );
    }

    /// The ceiling invariant swept across the halving schedule: no receipt
    /// content can push a block's issuance above 2x the published schedule, and
    /// issuance never drops below the base subsidy.
    #[test]
    fn total_issuance_never_exceeds_twice_the_schedule() {
        let calc = RewardCalculator::new(bonus_cfg());
        let full: Vec<_> = (0..1000)
            .map(|_| rcpt(true, Some(MODEL_INFERENCE)))
            .chain(std::iter::once(rcpt(true, None)))
            .collect();
        for &h in &[
            0u64,
            1,
            2_100_000,
            4_200_000,
            6_300_000,
            8_400_000,
            u64::MAX,
        ] {
            let base = calc.calculate_reward(h, &[]).total_reward;
            let full_r = calc.calculate_reward(h, &full).total_reward;
            assert!(
                full_r <= base.saturating_mul(U256::from(2)),
                "issuance exceeded 2x schedule at height {h}"
            );
            assert!(
                full_r >= base,
                "bonus reduced issuance below schedule at height {h}"
            );
        }
    }

    /// Drift guard: the reward path's inference-precompile set must stay in
    /// lock-step with the execution crate's canonical constants.
    #[test]
    fn inference_precompile_addrs_track_execution() {
        use citrate_execution::precompiles::inference::addresses;
        use citrate_execution::precompiles::q16::routing;
        assert!(INFERENCE_PRECOMPILES.contains(&addresses::MODEL_INFERENCE));
        assert!(INFERENCE_PRECOMPILES.contains(&addresses::BATCH_INFERENCE));
        assert!(INFERENCE_PRECOMPILES.contains(&routing::ROUTING_INFERENCE));
        assert_eq!(INFERENCE_PRECOMPILES.len(), 3);
    }
}
