// citrate/core/economics/src/slashing.rs
//
// Institutional slashing policy. Schools get lenient treatment:
// - 10% slash for equivocation (double-signing)
// - No downtime penalty (schools have irregular schedules)
// - Grace period for first offense
// - Configurable recovery path

use citrate_execution::types::Address;
use primitive_types::U256;
use serde::{Deserialize, Serialize};

/// Slashing offense types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlashingOffense {
    /// Double-signing (equivocation) — proposing two blocks at the same height
    Equivocation,
    /// Submitting invalid state transitions
    InvalidStateTransition,
    /// Censoring transactions
    TransactionCensorship,
}

/// Slashing configuration for institutional operators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstitutionalSlashingConfig {
    /// Equivocation penalty: percentage of stake (e.g., 10 = 10%)
    pub equivocation_penalty_pct: u8,
    /// Invalid state transition penalty percentage
    pub invalid_state_penalty_pct: u8,
    /// Censorship penalty percentage
    pub censorship_penalty_pct: u8,
    /// Grace period (epochs) before first offense is penalized
    pub first_offense_grace_epochs: u64,
    /// Cooldown period (epochs) after a slash before operator can resume
    pub cooldown_epochs: u64,
    /// Maximum cumulative slash before forced deactivation (percentage)
    pub max_cumulative_slash_pct: u8,
    /// Whether downtime is penalized (false for institutional operators)
    pub penalize_downtime: bool,
}

impl Default for InstitutionalSlashingConfig {
    fn default() -> Self {
        Self {
            equivocation_penalty_pct: 10,
            invalid_state_penalty_pct: 15,
            censorship_penalty_pct: 5,
            first_offense_grace_epochs: 2,
            cooldown_epochs: 1,
            max_cumulative_slash_pct: 50,
            penalize_downtime: false,
        }
    }
}

/// Record of a slashing event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingRecord {
    pub operator: Address,
    pub offense: SlashingOffense,
    pub penalty_wei: U256,
    pub epoch: u64,
    pub evidence_hash: [u8; 32],
    pub is_grace_period: bool,
}

/// Slashing state for an institutional operator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorSlashingState {
    pub address: Address,
    pub offense_count: u32,
    pub cumulative_slashed_wei: U256,
    pub in_cooldown: bool,
    pub cooldown_until_epoch: u64,
    pub is_deactivated: bool,
    pub records: Vec<SlashingRecord>,
}

impl OperatorSlashingState {
    pub fn new(address: Address) -> Self {
        Self {
            address,
            offense_count: 0,
            cumulative_slashed_wei: U256::zero(),
            in_cooldown: false,
            cooldown_until_epoch: 0,
            is_deactivated: false,
            records: Vec::new(),
        }
    }
}

/// Institutional slashing calculator
pub struct InstitutionalSlashingManager {
    config: InstitutionalSlashingConfig,
}

impl InstitutionalSlashingManager {
    pub fn new(config: InstitutionalSlashingConfig) -> Self {
        Self { config }
    }

    /// Calculate and apply a slashing penalty
    pub fn process_offense(
        &self,
        state: &mut OperatorSlashingState,
        offense: SlashingOffense,
        stake_wei: U256,
        current_epoch: u64,
        evidence_hash: [u8; 32],
    ) -> SlashingRecord {
        // Check if operator is in cooldown
        if state.in_cooldown && current_epoch < state.cooldown_until_epoch {
            // During cooldown, record but don't compound
            let record = SlashingRecord {
                operator: state.address,
                offense,
                penalty_wei: U256::zero(),
                epoch: current_epoch,
                evidence_hash,
                is_grace_period: true,
            };
            state.records.push(record.clone());
            return record;
        }

        state.offense_count += 1;

        // Grace period for first offense
        let is_grace = state.offense_count <= 1
            && current_epoch < self.config.first_offense_grace_epochs;

        let penalty_pct = if is_grace {
            0
        } else {
            match offense {
                SlashingOffense::Equivocation => self.config.equivocation_penalty_pct,
                SlashingOffense::InvalidStateTransition => self.config.invalid_state_penalty_pct,
                SlashingOffense::TransactionCensorship => self.config.censorship_penalty_pct,
            }
        };

        let penalty_wei = stake_wei * U256::from(penalty_pct) / U256::from(100);

        state.cumulative_slashed_wei += penalty_wei;
        state.in_cooldown = true;
        state.cooldown_until_epoch = current_epoch + self.config.cooldown_epochs;

        // Check for forced deactivation
        let max_slash = stake_wei * U256::from(self.config.max_cumulative_slash_pct) / U256::from(100);
        if state.cumulative_slashed_wei >= max_slash {
            state.is_deactivated = true;
        }

        let record = SlashingRecord {
            operator: state.address,
            offense,
            penalty_wei,
            epoch: current_epoch,
            evidence_hash,
            is_grace_period: is_grace,
        };
        state.records.push(record.clone());
        record
    }

    /// Check if downtime should be penalized (always false for institutional)
    pub fn should_penalize_downtime(&self) -> bool {
        self.config.penalize_downtime
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::DECIMALS;

    fn test_address() -> Address {
        Address([0x22; 20])
    }

    fn stake() -> U256 {
        U256::from(10_000u64) * U256::from(10).pow(U256::from(DECIMALS))
    }

    #[test]
    fn test_equivocation_slashes_10_percent() {
        let config = InstitutionalSlashingConfig::default();
        let mgr = InstitutionalSlashingManager::new(config);
        let mut state = OperatorSlashingState::new(test_address());

        // First offense at epoch 5 (past grace period)
        let record = mgr.process_offense(
            &mut state,
            SlashingOffense::Equivocation,
            stake(),
            5,
            [0xAA; 32],
        );

        let expected = stake() * U256::from(10u64) / U256::from(100u64);
        assert_eq!(record.penalty_wei, expected);
        assert!(!record.is_grace_period);
    }

    #[test]
    fn test_first_offense_grace_period() {
        let config = InstitutionalSlashingConfig::default();
        let mgr = InstitutionalSlashingManager::new(config);
        let mut state = OperatorSlashingState::new(test_address());

        // First offense at epoch 0 (within grace period of 2 epochs)
        let record = mgr.process_offense(
            &mut state,
            SlashingOffense::Equivocation,
            stake(),
            0,
            [0xBB; 32],
        );

        assert_eq!(record.penalty_wei, U256::zero());
        assert!(record.is_grace_period);
    }

    #[test]
    fn test_no_downtime_penalty() {
        let config = InstitutionalSlashingConfig::default();
        let mgr = InstitutionalSlashingManager::new(config);
        assert!(!mgr.should_penalize_downtime());
    }

    #[test]
    fn test_forced_deactivation_at_50_percent() {
        let config = InstitutionalSlashingConfig::default();
        let mgr = InstitutionalSlashingManager::new(config);
        let mut state = OperatorSlashingState::new(test_address());

        // Slash 5 times at 10% each = 50% cumulative → deactivated
        for i in 0..5 {
            mgr.process_offense(
                &mut state,
                SlashingOffense::Equivocation,
                stake(),
                10 + i * 2, // Past grace, past cooldown
                [i as u8; 32],
            );
            state.in_cooldown = false; // Reset cooldown for test
        }

        assert!(state.is_deactivated);
    }

    #[test]
    fn test_cooldown_suppresses_penalty() {
        let config = InstitutionalSlashingConfig::default();
        let mgr = InstitutionalSlashingManager::new(config);
        let mut state = OperatorSlashingState::new(test_address());

        // First offense
        mgr.process_offense(
            &mut state,
            SlashingOffense::Equivocation,
            stake(),
            5,
            [0xCC; 32],
        );

        // Second offense during cooldown (epoch 5, cooldown until 6)
        let record = mgr.process_offense(
            &mut state,
            SlashingOffense::Equivocation,
            stake(),
            5,
            [0xDD; 32],
        );

        assert_eq!(record.penalty_wei, U256::zero());
        assert!(record.is_grace_period);
    }

    #[test]
    fn test_invalid_state_transition_penalty() {
        let config = InstitutionalSlashingConfig::default();
        let mgr = InstitutionalSlashingManager::new(config);
        let mut state = OperatorSlashingState::new(test_address());

        let record = mgr.process_offense(
            &mut state,
            SlashingOffense::InvalidStateTransition,
            stake(),
            10,
            [0xEE; 32],
        );

        let expected = stake() * U256::from(15u64) / U256::from(100u64);
        assert_eq!(record.penalty_wei, expected);
    }
}
