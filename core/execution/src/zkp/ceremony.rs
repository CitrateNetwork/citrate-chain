// citrate/core/execution/src/zkp/ceremony.rs

//! Trusted Setup Ceremony Infrastructure
//!
//! Groth16 requires a Structured Reference String (SRS) produced by a
//! multi-party computation (MPC) ceremony. The security guarantee:
//! if at least ONE participant is honest, the toxic waste is destroyed.
//!
//! ## Current State
//!
//! Development parameters use `OsRng` (secure for testnet, NOT for mainnet).
//! Mainnet requires running the ceremony with multiple independent participants.
//!
//! ## Protocol Overview
//!
//! 1. **Initialization**: Coordinator publishes `CeremonyConfig` specifying
//!    circuit types, minimum participants, and domain separator.
//!
//! 2. **Contribution Phase**: Each participant:
//!    - Downloads the current parameters
//!    - Samples random toxic waste locally
//!    - Applies their randomness to the parameters
//!    - Publishes their contribution hash and attestation
//!    - Destroys their local randomness
//!
//! 3. **Chain Integrity**: Each contribution records the hash of the previous
//!    contribution, forming a hash chain. Any break in the chain invalidates
//!    all subsequent contributions.
//!
//! 4. **Finalization**: Once `min_participants` contributions are collected,
//!    the coordinator finalizes the ceremony. The final SRS is the result of
//!    all sequential contributions.
//!
//! 5. **Verification**: Anyone can verify the contribution chain by checking
//!    hash links and timestamp ordering.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Ceremony configuration — defines the parameters for a trusted setup ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonyConfig {
    /// Minimum number of participants required for finalization.
    /// Security guarantee: if at least ONE of these participants is honest
    /// and properly destroys their toxic waste, the SRS is secure.
    pub min_participants: usize,
    /// Circuit types to generate parameters for. Each circuit type
    /// (e.g., ModelExecution, StateTransition) requires its own SRS.
    pub circuit_types: Vec<String>,
    /// Domain separator for this ceremony. Prevents cross-ceremony replay
    /// attacks by binding contributions to a specific ceremony instance.
    pub domain: String,
    /// Ceremony version — increment when the circuit definitions change
    /// and a new ceremony is required.
    pub version: u32,
}

impl Default for CeremonyConfig {
    fn default() -> Self {
        Self {
            min_participants: 3,
            circuit_types: vec![
                "ModelExecution".to_string(),
                "GradientSubmission".to_string(),
                "StateTransition".to_string(),
                "DataIntegrity".to_string(),
            ],
            domain: "citrate_mainnet_ceremony_v1".to_string(),
            version: 1,
        }
    }
}

/// A single participant's contribution to the ceremony.
///
/// Contributions form a hash chain: each contribution records the hash of
/// the previous contribution, allowing anyone to verify chain integrity
/// without access to the actual SRS parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonyContribution {
    /// Participant identifier (SHA3-256 hash of their public key).
    pub participant_id: [u8; 32],
    /// SHA3-256 hash of the new parameters after this contribution.
    pub contribution_hash: [u8; 32],
    /// Hash of the previous contribution (chain integrity link).
    /// For the first contribution, this must be `[0u8; 32]`.
    pub previous_hash: [u8; 32],
    /// Unix timestamp (seconds since epoch) of when the contribution was made.
    pub timestamp: u64,
    /// Human-readable attestation message signed by the participant,
    /// typically describing the environment and randomness source used.
    pub attestation: String,
}

/// State machine for a trusted setup ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CeremonyState {
    /// Ceremony has not started yet.
    NotStarted,
    /// Ceremony is accepting contributions from participants.
    Accepting {
        contributions: Vec<CeremonyContribution>,
    },
    /// Ceremony is finalized. The SRS parameters are ready for use.
    Finalized {
        contributions: Vec<CeremonyContribution>,
        /// SHA3-256 hash of `domain || contribution_hash_0 || ... || contribution_hash_n`.
        final_hash: [u8; 32],
    },
}

impl CeremonyState {
    /// Create a new ceremony in the `NotStarted` state.
    pub fn new() -> Self {
        Self::NotStarted
    }

    /// Transition from `NotStarted` to `Accepting`.
    pub fn begin(&mut self) -> Result<(), String> {
        match self {
            Self::NotStarted => {
                *self = Self::Accepting {
                    contributions: vec![],
                };
                Ok(())
            }
            Self::Accepting { .. } => Err("Ceremony is already accepting contributions".to_string()),
            Self::Finalized { .. } => Err("Ceremony is already finalized".to_string()),
        }
    }

    /// Add a contribution to the ceremony.
    ///
    /// Validates chain integrity: the contribution's `previous_hash` must match
    /// the `contribution_hash` of the last contribution (or `[0u8; 32]` if first).
    pub fn add_contribution(&mut self, contribution: CeremonyContribution) -> Result<(), String> {
        match self {
            Self::Accepting { contributions } => {
                // Verify chain integrity
                let expected_prev = if let Some(last) = contributions.last() {
                    last.contribution_hash
                } else {
                    [0u8; 32]
                };

                if contribution.previous_hash != expected_prev {
                    return Err(format!(
                        "Chain integrity violation: contribution previous_hash does not match \
                         last contribution_hash (expected {:?}, got {:?})",
                        &expected_prev[..4],
                        &contribution.previous_hash[..4]
                    ));
                }

                // Verify timestamp ordering
                if let Some(last) = contributions.last() {
                    if contribution.timestamp <= last.timestamp {
                        return Err(format!(
                            "Timestamp must be strictly increasing (last: {}, got: {})",
                            last.timestamp, contribution.timestamp
                        ));
                    }
                }

                // Verify participant_id is non-zero
                if contribution.participant_id == [0u8; 32] {
                    return Err("Participant ID must be non-zero".to_string());
                }

                contributions.push(contribution);
                Ok(())
            }
            Self::NotStarted => Err("Ceremony has not started yet".to_string()),
            Self::Finalized { .. } => Err("Ceremony is already finalized".to_string()),
        }
    }

    /// Finalize the ceremony, producing the final hash.
    ///
    /// Requires at least `config.min_participants` contributions.
    /// The final hash is `SHA3-256(domain || c0.hash || c1.hash || ... || cn.hash)`.
    pub fn finalize(&mut self, config: &CeremonyConfig) -> Result<(), String> {
        match self {
            Self::Accepting { contributions } => {
                if contributions.len() < config.min_participants {
                    return Err(format!(
                        "Need at least {} participants, got {}",
                        config.min_participants,
                        contributions.len()
                    ));
                }

                // Compute final hash from domain separator + all contribution hashes
                let mut hasher = Sha3_256::new();
                hasher.update(config.domain.as_bytes());
                for c in contributions.iter() {
                    hasher.update(c.contribution_hash);
                }
                let mut final_hash = [0u8; 32];
                final_hash.copy_from_slice(hasher.finalize().as_slice());

                *self = Self::Finalized {
                    contributions: contributions.clone(),
                    final_hash,
                };
                Ok(())
            }
            Self::NotStarted => Err("Ceremony has not started yet".to_string()),
            Self::Finalized { .. } => Err("Ceremony is already finalized".to_string()),
        }
    }

    /// Check if ceremony is finalized and ready for parameter extraction.
    pub fn is_finalized(&self) -> bool {
        matches!(self, Self::Finalized { .. })
    }

    /// Get the number of contributions received so far.
    pub fn contribution_count(&self) -> usize {
        match self {
            Self::NotStarted => 0,
            Self::Accepting { contributions } => contributions.len(),
            Self::Finalized { contributions, .. } => contributions.len(),
        }
    }

    /// Get the final hash (only available after finalization).
    pub fn final_hash(&self) -> Option<[u8; 32]> {
        match self {
            Self::Finalized { final_hash, .. } => Some(*final_hash),
            _ => None,
        }
    }
}

impl Default for CeremonyState {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify a contribution's integrity against the previous contribution in the chain.
///
/// Checks:
/// 1. Hash chain link: `contribution.previous_hash == previous.contribution_hash`
///    (or `[0u8; 32]` if this is the first contribution).
/// 2. Timestamp ordering: strictly increasing.
/// 3. Non-zero participant ID.
pub fn verify_contribution(
    contribution: &CeremonyContribution,
    previous: Option<&CeremonyContribution>,
) -> Result<bool, String> {
    // Check chain link
    if let Some(prev) = previous {
        if contribution.previous_hash != prev.contribution_hash {
            return Ok(false);
        }
    } else {
        // First contribution — previous_hash must be zero
        if contribution.previous_hash != [0u8; 32] {
            return Ok(false);
        }
    }

    // Check timestamp ordering
    if let Some(prev) = previous {
        if contribution.timestamp <= prev.timestamp {
            return Ok(false);
        }
    }

    // Check participant_id is non-zero
    if contribution.participant_id == [0u8; 32] {
        return Ok(false);
    }

    // Check contribution_hash is non-zero (a zero hash likely indicates corruption)
    if contribution.contribution_hash == [0u8; 32] {
        return Ok(false);
    }

    Ok(true)
}

/// Verify the integrity of an entire contribution chain.
///
/// Validates every link in the chain and returns the number of valid contributions.
/// If any contribution is invalid, returns an error describing which one failed.
pub fn verify_contribution_chain(contributions: &[CeremonyContribution]) -> Result<usize, String> {
    for (i, contribution) in contributions.iter().enumerate() {
        let previous = if i > 0 {
            Some(&contributions[i - 1])
        } else {
            None
        };

        let valid = verify_contribution(contribution, previous)
            .map_err(|e| format!("Error verifying contribution {}: {}", i, e))?;

        if !valid {
            return Err(format!(
                "Invalid contribution at index {} (participant {:?})",
                i,
                &contribution.participant_id[..4]
            ));
        }
    }

    Ok(contributions.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_contribution(
        participant_id: u8,
        contribution_hash: [u8; 32],
        previous_hash: [u8; 32],
        timestamp: u64,
    ) -> CeremonyContribution {
        let mut pid = [0u8; 32];
        pid[0] = participant_id;
        CeremonyContribution {
            participant_id: pid,
            contribution_hash,
            previous_hash,
            timestamp,
            attestation: format!("Participant {} attestation", participant_id),
        }
    }

    fn hash_for_index(i: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = i + 1; // non-zero
        h[31] = i + 1;
        h
    }

    #[test]
    fn test_ceremony_default_config() {
        let config = CeremonyConfig::default();
        assert_eq!(config.min_participants, 3);
        assert_eq!(config.circuit_types.len(), 4);
        assert_eq!(config.domain, "citrate_mainnet_ceremony_v1");
        assert_eq!(config.version, 1);
    }

    #[test]
    fn test_ceremony_lifecycle() {
        let config = CeremonyConfig::default();
        let mut state = CeremonyState::new();
        assert_eq!(state.contribution_count(), 0);
        assert!(!state.is_finalized());
        assert!(state.final_hash().is_none());

        // Start
        state.begin().unwrap();

        // Add 3 contributions with proper chain
        let c0 = make_contribution(1, hash_for_index(0), [0u8; 32], 1000);
        state.add_contribution(c0).unwrap();
        assert_eq!(state.contribution_count(), 1);

        let c1 = make_contribution(2, hash_for_index(1), hash_for_index(0), 2000);
        state.add_contribution(c1).unwrap();
        assert_eq!(state.contribution_count(), 2);

        let c2 = make_contribution(3, hash_for_index(2), hash_for_index(1), 3000);
        state.add_contribution(c2).unwrap();
        assert_eq!(state.contribution_count(), 3);

        // Finalize
        state.finalize(&config).unwrap();
        assert!(state.is_finalized());
        assert!(state.final_hash().is_some());
        assert_eq!(state.contribution_count(), 3);
    }

    #[test]
    fn test_ceremony_begin_twice_fails() {
        let mut state = CeremonyState::new();
        state.begin().unwrap();
        assert!(state.begin().is_err());
    }

    #[test]
    fn test_ceremony_begin_after_finalized_fails() {
        let config = CeremonyConfig {
            min_participants: 1,
            ..Default::default()
        };
        let mut state = CeremonyState::new();
        state.begin().unwrap();

        let c0 = make_contribution(1, hash_for_index(0), [0u8; 32], 1000);
        state.add_contribution(c0).unwrap();
        state.finalize(&config).unwrap();

        assert!(state.begin().is_err());
    }

    #[test]
    fn test_contribution_chain_integrity_violation() {
        let mut state = CeremonyState::new();
        state.begin().unwrap();

        let c0 = make_contribution(1, hash_for_index(0), [0u8; 32], 1000);
        state.add_contribution(c0).unwrap();

        // Wrong previous_hash — should fail
        let c1 = make_contribution(2, hash_for_index(1), [0u8; 32], 2000);
        let result = state.add_contribution(c1);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Chain integrity violation"));
    }

    #[test]
    fn test_contribution_timestamp_ordering() {
        let mut state = CeremonyState::new();
        state.begin().unwrap();

        let c0 = make_contribution(1, hash_for_index(0), [0u8; 32], 2000);
        state.add_contribution(c0).unwrap();

        // Timestamp not strictly increasing — should fail
        let c1 = make_contribution(2, hash_for_index(1), hash_for_index(0), 1000);
        let result = state.add_contribution(c1);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Timestamp"));
    }

    #[test]
    fn test_contribution_timestamp_equal_fails() {
        let mut state = CeremonyState::new();
        state.begin().unwrap();

        let c0 = make_contribution(1, hash_for_index(0), [0u8; 32], 1000);
        state.add_contribution(c0).unwrap();

        // Equal timestamp — should fail (must be strictly increasing)
        let c1 = make_contribution(2, hash_for_index(1), hash_for_index(0), 1000);
        let result = state.add_contribution(c1);
        assert!(result.is_err());
    }

    #[test]
    fn test_contribution_zero_participant_id_rejected() {
        let mut state = CeremonyState::new();
        state.begin().unwrap();

        let c0 = CeremonyContribution {
            participant_id: [0u8; 32],
            contribution_hash: hash_for_index(0),
            previous_hash: [0u8; 32],
            timestamp: 1000,
            attestation: "test".to_string(),
        };
        let result = state.add_contribution(c0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("non-zero"));
    }

    #[test]
    fn test_add_contribution_before_begin_fails() {
        let mut state = CeremonyState::new();
        let c0 = make_contribution(1, hash_for_index(0), [0u8; 32], 1000);
        let result = state.add_contribution(c0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not started"));
    }

    #[test]
    fn test_add_contribution_after_finalized_fails() {
        let config = CeremonyConfig {
            min_participants: 1,
            ..Default::default()
        };
        let mut state = CeremonyState::new();
        state.begin().unwrap();

        let c0 = make_contribution(1, hash_for_index(0), [0u8; 32], 1000);
        state.add_contribution(c0).unwrap();
        state.finalize(&config).unwrap();

        let c1 = make_contribution(2, hash_for_index(1), hash_for_index(0), 2000);
        let result = state.add_contribution(c1);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("finalized"));
    }

    #[test]
    fn test_ceremony_requires_min_participants() {
        let config = CeremonyConfig {
            min_participants: 3,
            ..Default::default()
        };
        let mut state = CeremonyState::new();
        state.begin().unwrap();

        // Only add 2 contributions
        let c0 = make_contribution(1, hash_for_index(0), [0u8; 32], 1000);
        state.add_contribution(c0).unwrap();

        let c1 = make_contribution(2, hash_for_index(1), hash_for_index(0), 2000);
        state.add_contribution(c1).unwrap();

        // Try to finalize with only 2 — should fail
        let result = state.finalize(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Need at least 3"));
    }

    #[test]
    fn test_finalize_not_started_fails() {
        let config = CeremonyConfig::default();
        let mut state = CeremonyState::new();
        let result = state.finalize(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not started"));
    }

    #[test]
    fn test_finalize_already_finalized_fails() {
        let config = CeremonyConfig {
            min_participants: 1,
            ..Default::default()
        };
        let mut state = CeremonyState::new();
        state.begin().unwrap();

        let c0 = make_contribution(1, hash_for_index(0), [0u8; 32], 1000);
        state.add_contribution(c0).unwrap();
        state.finalize(&config).unwrap();

        let result = state.finalize(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("finalized"));
    }

    #[test]
    fn test_final_hash_deterministic() {
        let config = CeremonyConfig {
            min_participants: 1,
            ..Default::default()
        };

        // Run ceremony twice with same contributions
        let mut state1 = CeremonyState::new();
        state1.begin().unwrap();
        let c0 = make_contribution(1, hash_for_index(0), [0u8; 32], 1000);
        state1.add_contribution(c0).unwrap();
        state1.finalize(&config).unwrap();

        let mut state2 = CeremonyState::new();
        state2.begin().unwrap();
        let c0 = make_contribution(1, hash_for_index(0), [0u8; 32], 1000);
        state2.add_contribution(c0).unwrap();
        state2.finalize(&config).unwrap();

        assert_eq!(state1.final_hash(), state2.final_hash());
    }

    #[test]
    fn test_final_hash_changes_with_different_contributions() {
        let config = CeremonyConfig {
            min_participants: 1,
            ..Default::default()
        };

        let mut state1 = CeremonyState::new();
        state1.begin().unwrap();
        let c0 = make_contribution(1, hash_for_index(0), [0u8; 32], 1000);
        state1.add_contribution(c0).unwrap();
        state1.finalize(&config).unwrap();

        let mut state2 = CeremonyState::new();
        state2.begin().unwrap();
        let c0 = make_contribution(2, hash_for_index(5), [0u8; 32], 1000);
        state2.add_contribution(c0).unwrap();
        state2.finalize(&config).unwrap();

        assert_ne!(state1.final_hash(), state2.final_hash());
    }

    #[test]
    fn test_verify_contribution_valid_first() {
        let c0 = make_contribution(1, hash_for_index(0), [0u8; 32], 1000);
        assert_eq!(verify_contribution(&c0, None), Ok(true));
    }

    #[test]
    fn test_verify_contribution_valid_chained() {
        let c0 = make_contribution(1, hash_for_index(0), [0u8; 32], 1000);
        let c1 = make_contribution(2, hash_for_index(1), hash_for_index(0), 2000);
        assert_eq!(verify_contribution(&c1, Some(&c0)), Ok(true));
    }

    #[test]
    fn test_verify_contribution_bad_chain_link() {
        let c0 = make_contribution(1, hash_for_index(0), [0u8; 32], 1000);
        let c1 = make_contribution(2, hash_for_index(1), [0u8; 32], 2000);
        assert_eq!(verify_contribution(&c1, Some(&c0)), Ok(false));
    }

    #[test]
    fn test_verify_contribution_bad_timestamp() {
        let c0 = make_contribution(1, hash_for_index(0), [0u8; 32], 2000);
        let c1 = make_contribution(2, hash_for_index(1), hash_for_index(0), 1000);
        assert_eq!(verify_contribution(&c1, Some(&c0)), Ok(false));
    }

    #[test]
    fn test_verify_contribution_zero_participant() {
        let c0 = CeremonyContribution {
            participant_id: [0u8; 32],
            contribution_hash: hash_for_index(0),
            previous_hash: [0u8; 32],
            timestamp: 1000,
            attestation: "test".to_string(),
        };
        assert_eq!(verify_contribution(&c0, None), Ok(false));
    }

    #[test]
    fn test_verify_contribution_zero_hash() {
        let mut pid = [0u8; 32];
        pid[0] = 1;
        let c0 = CeremonyContribution {
            participant_id: pid,
            contribution_hash: [0u8; 32],
            previous_hash: [0u8; 32],
            timestamp: 1000,
            attestation: "test".to_string(),
        };
        assert_eq!(verify_contribution(&c0, None), Ok(false));
    }

    #[test]
    fn test_verify_contribution_first_with_nonzero_previous_fails() {
        let c0 = make_contribution(1, hash_for_index(0), hash_for_index(5), 1000);
        assert_eq!(verify_contribution(&c0, None), Ok(false));
    }

    #[test]
    fn test_verify_contribution_chain_valid() {
        let c0 = make_contribution(1, hash_for_index(0), [0u8; 32], 1000);
        let c1 = make_contribution(2, hash_for_index(1), hash_for_index(0), 2000);
        let c2 = make_contribution(3, hash_for_index(2), hash_for_index(1), 3000);

        let chain = vec![c0, c1, c2];
        assert_eq!(verify_contribution_chain(&chain), Ok(3));
    }

    #[test]
    fn test_verify_contribution_chain_broken() {
        let c0 = make_contribution(1, hash_for_index(0), [0u8; 32], 1000);
        // c1 has wrong previous_hash
        let c1 = make_contribution(2, hash_for_index(1), [0u8; 32], 2000);
        let c2 = make_contribution(3, hash_for_index(2), hash_for_index(1), 3000);

        let chain = vec![c0, c1, c2];
        let result = verify_contribution_chain(&chain);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("index 1"));
    }

    #[test]
    fn test_verify_contribution_chain_empty() {
        let chain: Vec<CeremonyContribution> = vec![];
        assert_eq!(verify_contribution_chain(&chain), Ok(0));
    }

    #[test]
    fn test_ceremony_state_default() {
        let state = CeremonyState::default();
        assert!(!state.is_finalized());
        assert_eq!(state.contribution_count(), 0);
    }

    #[test]
    fn test_ceremony_serialization_roundtrip() {
        let config = CeremonyConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: CeremonyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.min_participants, config.min_participants);
        assert_eq!(deserialized.domain, config.domain);
        assert_eq!(deserialized.version, config.version);
        assert_eq!(deserialized.circuit_types, config.circuit_types);
    }

    #[test]
    fn test_contribution_serialization_roundtrip() {
        let c = make_contribution(42, hash_for_index(7), [0u8; 32], 9999);
        let json = serde_json::to_string(&c).unwrap();
        let deserialized: CeremonyContribution = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.participant_id, c.participant_id);
        assert_eq!(deserialized.contribution_hash, c.contribution_hash);
        assert_eq!(deserialized.previous_hash, c.previous_hash);
        assert_eq!(deserialized.timestamp, c.timestamp);
        assert_eq!(deserialized.attestation, c.attestation);
    }
}
