//! Oracle attestation system.
//!
//! M-of-N multi-oracle attestation for cross-chain event verification.
//! Oracles independently verify Ethereum events and sign attestations.
//! The bridge relay only processes events once M attestations are collected.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::errors::BridgeError;
use crate::events::EventId;

/// Oracle identity (public key, 32 bytes).
pub type OracleId = [u8; 32];

/// Oracle attestation — a signed statement that an oracle has verified an event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OracleAttestation {
    /// ID of the oracle providing the attestation.
    pub oracle_id: OracleId,

    /// Event being attested to.
    pub event_id: EventId,

    /// Hash of the event data (for integrity check).
    pub event_hash: [u8; 32],

    /// Oracle's signature over (event_id || event_hash).
    pub signature: Vec<u8>,

    /// Timestamp when the attestation was created.
    pub timestamp: u64,
}

/// Registered oracle with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredOracle {
    /// Oracle public key.
    pub id: OracleId,

    /// Human-readable name.
    pub name: String,

    /// Whether this oracle is currently active.
    pub active: bool,

    /// When this oracle was registered.
    pub registered_at: u64,

    /// Last attestation timestamp (0 if never attested).
    pub last_attestation: u64,

    /// Total attestations provided.
    pub total_attestations: u64,
}

/// Oracle registry — manages the set of trusted oracles and their attestations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleRegistry {
    /// Registered oracles.
    oracles: HashMap<OracleId, RegisteredOracle>,

    /// Minimum attestations required (M in M-of-N).
    threshold: usize,

    /// Collected attestations per event.
    attestations: HashMap<EventId, Vec<OracleAttestation>>,
}

impl OracleRegistry {
    /// Create a new oracle registry with the given M-of-N threshold.
    pub fn new(threshold: usize) -> Self {
        Self {
            oracles: HashMap::new(),
            threshold,
            attestations: HashMap::new(),
        }
    }

    /// Register a new oracle.
    pub fn register_oracle(
        &mut self,
        id: OracleId,
        name: String,
    ) -> Result<(), BridgeError> {
        if self.oracles.contains_key(&id) {
            return Err(BridgeError::OracleAlreadyRegistered {
                oracle_id: hex::encode(id),
            });
        }
        let now = chrono::Utc::now().timestamp() as u64;
        self.oracles.insert(
            id,
            RegisteredOracle {
                id,
                name,
                active: true,
                registered_at: now,
                last_attestation: 0,
                total_attestations: 0,
            },
        );
        Ok(())
    }

    /// Remove an oracle from the registry.
    pub fn remove_oracle(&mut self, id: &OracleId) -> Result<(), BridgeError> {
        if self.oracles.remove(id).is_none() {
            return Err(BridgeError::OracleNotFound {
                oracle_id: hex::encode(id),
            });
        }
        Ok(())
    }

    /// Deactivate an oracle without removing it.
    pub fn deactivate_oracle(&mut self, id: &OracleId) -> Result<(), BridgeError> {
        let oracle = self
            .oracles
            .get_mut(id)
            .ok_or_else(|| BridgeError::OracleNotFound {
                oracle_id: hex::encode(id),
            })?;
        oracle.active = false;
        Ok(())
    }

    /// Get the number of active oracles.
    pub fn active_oracle_count(&self) -> usize {
        self.oracles.values().filter(|o| o.active).count()
    }

    /// Get the current threshold.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Update the threshold.
    pub fn set_threshold(&mut self, threshold: usize) {
        self.threshold = threshold;
    }

    /// Submit an attestation from an oracle.
    ///
    /// Returns the current attestation count for this event.
    pub fn submit_attestation(
        &mut self,
        attestation: OracleAttestation,
    ) -> Result<usize, BridgeError> {
        // Verify oracle is registered and active
        let oracle = self
            .oracles
            .get_mut(&attestation.oracle_id)
            .ok_or_else(|| BridgeError::OracleNotFound {
                oracle_id: hex::encode(attestation.oracle_id),
            })?;

        if !oracle.active {
            return Err(BridgeError::OracleInactive {
                oracle_id: hex::encode(attestation.oracle_id),
            });
        }

        // Check for duplicate attestation from same oracle
        let event_attestations = self
            .attestations
            .entry(attestation.event_id)
            .or_default();

        if event_attestations
            .iter()
            .any(|a| a.oracle_id == attestation.oracle_id)
        {
            return Err(BridgeError::DuplicateAttestation {
                oracle_id: hex::encode(attestation.oracle_id),
                event_id: hex::encode(attestation.event_id),
            });
        }

        // Update oracle stats
        oracle.last_attestation = attestation.timestamp;
        oracle.total_attestations += 1;

        // Store attestation
        event_attestations.push(attestation);
        Ok(event_attestations.len())
    }

    /// Check if an event has met the attestation threshold.
    pub fn is_threshold_met(&self, event_id: &EventId) -> bool {
        self.attestations
            .get(event_id)
            .map(|a| a.len() >= self.threshold)
            .unwrap_or(false)
    }

    /// Get attestation count for an event.
    pub fn attestation_count(&self, event_id: &EventId) -> usize {
        self.attestations
            .get(event_id)
            .map(|a| a.len())
            .unwrap_or(0)
    }

    /// Get all attestations for an event.
    pub fn get_attestations(&self, event_id: &EventId) -> Option<&Vec<OracleAttestation>> {
        self.attestations.get(event_id)
    }

    /// Verify that all attestations for an event have matching event hashes.
    pub fn verify_attestation_consistency(&self, event_id: &EventId) -> bool {
        if let Some(attestations) = self.attestations.get(event_id) {
            if attestations.is_empty() {
                return true;
            }
            let first_hash = &attestations[0].event_hash;
            attestations.iter().all(|a| &a.event_hash == first_hash)
        } else {
            true
        }
    }

    /// Get the set of oracle IDs that have attested to an event.
    pub fn attesting_oracles(&self, event_id: &EventId) -> HashSet<OracleId> {
        self.attestations
            .get(event_id)
            .map(|atts| atts.iter().map(|a| a.oracle_id).collect())
            .unwrap_or_default()
    }

    /// List all registered oracles.
    pub fn list_oracles(&self) -> Vec<&RegisteredOracle> {
        self.oracles.values().collect()
    }
}

/// Compute the event hash for attestation signing.
pub fn compute_event_hash(event_id: &EventId, data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(event_id);
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_attestation(oracle_id: OracleId, event_id: EventId) -> OracleAttestation {
        let event_hash = compute_event_hash(&event_id, b"test_deposit_data");
        OracleAttestation {
            oracle_id,
            event_id,
            event_hash,
            signature: vec![0u8; 64],
            timestamp: 1000,
        }
    }

    #[test]
    fn test_oracle_registration() {
        let mut registry = OracleRegistry::new(2);
        let oracle_id = [1u8; 32];

        registry
            .register_oracle(oracle_id, "Oracle-1".to_string())
            .unwrap();
        assert_eq!(registry.active_oracle_count(), 1);

        // Duplicate registration fails
        let err = registry
            .register_oracle(oracle_id, "Oracle-1".to_string())
            .unwrap_err();
        assert!(matches!(err, BridgeError::OracleAlreadyRegistered { .. }));
    }

    #[test]
    fn test_oracle_removal() {
        let mut registry = OracleRegistry::new(1);
        let oracle_id = [1u8; 32];

        registry
            .register_oracle(oracle_id, "Oracle-1".to_string())
            .unwrap();
        registry.remove_oracle(&oracle_id).unwrap();
        assert_eq!(registry.active_oracle_count(), 0);

        // Remove unknown oracle fails
        let err = registry.remove_oracle(&[99u8; 32]).unwrap_err();
        assert!(matches!(err, BridgeError::OracleNotFound { .. }));
    }

    #[test]
    fn test_oracle_threshold_verification() {
        let mut registry = OracleRegistry::new(2);
        let event_id = [10u8; 32];

        // Register 3 oracles
        for i in 1..=3u8 {
            let id = [i; 32];
            registry
                .register_oracle(id, format!("Oracle-{i}"))
                .unwrap();
        }

        // 1 attestation — below threshold
        registry
            .submit_attestation(make_attestation([1u8; 32], event_id))
            .unwrap();
        assert!(!registry.is_threshold_met(&event_id));
        assert_eq!(registry.attestation_count(&event_id), 1);

        // 2 attestations — meets threshold
        registry
            .submit_attestation(make_attestation([2u8; 32], event_id))
            .unwrap();
        assert!(registry.is_threshold_met(&event_id));
        assert_eq!(registry.attestation_count(&event_id), 2);
    }

    #[test]
    fn test_duplicate_attestation_rejected() {
        let mut registry = OracleRegistry::new(2);
        let oracle_id = [1u8; 32];
        let event_id = [10u8; 32];

        registry
            .register_oracle(oracle_id, "Oracle-1".to_string())
            .unwrap();

        registry
            .submit_attestation(make_attestation(oracle_id, event_id))
            .unwrap();

        // Same oracle, same event → duplicate
        let err = registry
            .submit_attestation(make_attestation(oracle_id, event_id))
            .unwrap_err();
        assert!(matches!(err, BridgeError::DuplicateAttestation { .. }));
    }

    #[test]
    fn test_inactive_oracle_rejected() {
        let mut registry = OracleRegistry::new(1);
        let oracle_id = [1u8; 32];
        let event_id = [10u8; 32];

        registry
            .register_oracle(oracle_id, "Oracle-1".to_string())
            .unwrap();
        registry.deactivate_oracle(&oracle_id).unwrap();

        let err = registry
            .submit_attestation(make_attestation(oracle_id, event_id))
            .unwrap_err();
        assert!(matches!(err, BridgeError::OracleInactive { .. }));
    }

    #[test]
    fn test_unregistered_oracle_rejected() {
        let mut registry = OracleRegistry::new(1);
        let event_id = [10u8; 32];

        let err = registry
            .submit_attestation(make_attestation([99u8; 32], event_id))
            .unwrap_err();
        assert!(matches!(err, BridgeError::OracleNotFound { .. }));
    }

    #[test]
    fn test_attestation_consistency_check() {
        let mut registry = OracleRegistry::new(2);
        let event_id = [10u8; 32];

        for i in 1..=2u8 {
            registry
                .register_oracle([i; 32], format!("Oracle-{i}"))
                .unwrap();
        }

        // Both oracles attest with same event_hash → consistent
        registry
            .submit_attestation(make_attestation([1u8; 32], event_id))
            .unwrap();
        registry
            .submit_attestation(make_attestation([2u8; 32], event_id))
            .unwrap();

        assert!(registry.verify_attestation_consistency(&event_id));
    }

    #[test]
    fn test_oracle_timeout_handling() {
        let mut registry = OracleRegistry::new(3);
        let event_id = [10u8; 32];

        // Only register 2 oracles (threshold = 3)
        for i in 1..=2u8 {
            registry
                .register_oracle([i; 32], format!("Oracle-{i}"))
                .unwrap();
        }

        // Both attest but threshold not met (need 3)
        registry
            .submit_attestation(make_attestation([1u8; 32], event_id))
            .unwrap();
        registry
            .submit_attestation(make_attestation([2u8; 32], event_id))
            .unwrap();

        assert!(!registry.is_threshold_met(&event_id));
        assert_eq!(registry.attestation_count(&event_id), 2);
    }

    #[test]
    fn test_compute_event_hash_deterministic() {
        let event_id = [5u8; 32];
        let h1 = compute_event_hash(&event_id, b"deposit_data");
        let h2 = compute_event_hash(&event_id, b"deposit_data");
        assert_eq!(h1, h2);

        // Different data → different hash
        let h3 = compute_event_hash(&event_id, b"different_data");
        assert_ne!(h1, h3);
    }
}
