//! Oracle attestation system.
//!
//! M-of-N multi-oracle attestation for cross-chain event verification.
//! Oracles independently verify Ethereum events and sign attestations.
//! The bridge relay only processes events once M attestations are collected.

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::errors::BridgeError;
use crate::events::EventId;

/// Maximum age in seconds for an attestation timestamp (5 minutes).
const ATTESTATION_MAX_AGE_SECS: u64 = 300;

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

    /// SECREM-01 BRG-3: chain id bound into every attestation message.
    /// Without it, an oracle's signature for deployment A replays
    /// verbatim against deployment B wherever oracle keys are shared.
    #[serde(default)]
    chain_id: u64,

    /// SECREM-01 BRG-3: bridge-instance binding (derived from the bridge
    /// contract address by the relay), same replay rationale as chain_id.
    #[serde(default)]
    bridge_instance: [u8; 32],
}

/// SECREM-01 BRG-3: the canonical attestation signing message — the ONE
/// constructor shared by verification, tests, and oracle clients (Rule 9).
///
/// `"citrate-bridge-v2" || chain_id(8 LE) || bridge_instance(32) ||
/// event_id(32) || event_hash(32) || timestamp(8 LE)`.
///
/// v2 supersedes v1 (which lacked the chain/instance binding). v1
/// signatures are NOT accepted anywhere — the bridge is pre-production
/// (ETH release stubbed), so the format break is deliberate and clean.
pub fn attestation_message(
    chain_id: u64,
    bridge_instance: &[u8; 32],
    event_id: &EventId,
    event_hash: &[u8; 32],
    timestamp: u64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(17 + 8 + 32 + 32 + 32 + 8);
    message.extend_from_slice(b"citrate-bridge-v2");
    message.extend_from_slice(&chain_id.to_le_bytes());
    message.extend_from_slice(bridge_instance);
    message.extend_from_slice(event_id);
    message.extend_from_slice(event_hash);
    message.extend_from_slice(&timestamp.to_le_bytes());
    message
}

/// Verify an attestation signature cryptographically (ed25519) over the
/// domain-separated v2 message (see [`attestation_message`]).
fn verify_attestation_signature(
    attestation: &OracleAttestation,
    chain_id: u64,
    bridge_instance: &[u8; 32],
) -> Result<(), BridgeError> {
    let message = attestation_message(
        chain_id,
        bridge_instance,
        &attestation.event_id,
        &attestation.event_hash,
        attestation.timestamp,
    );

    let pubkey = VerifyingKey::from_bytes(&attestation.oracle_id).map_err(|_| {
        BridgeError::InvalidSignature {
            oracle_id: hex::encode(attestation.oracle_id),
        }
    })?;

    let sig = DalekSignature::from_slice(&attestation.signature).map_err(|_| {
        BridgeError::InvalidSignature {
            oracle_id: hex::encode(attestation.oracle_id),
        }
    })?;

    pubkey.verify(&message, &sig).map_err(|_| {
        BridgeError::InvalidSignature {
            oracle_id: hex::encode(attestation.oracle_id),
        }
    })
}

/// Check if an attestation timestamp is within the acceptable freshness window.
fn verify_attestation_freshness(attestation: &OracleAttestation) -> Result<(), BridgeError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let age = now.saturating_sub(attestation.timestamp);
    if age > ATTESTATION_MAX_AGE_SECS {
        return Err(BridgeError::StaleAttestation {
            timestamp: attestation.timestamp,
        });
    }

    // Also reject attestations from the future (clock skew > 60s)
    if attestation.timestamp > now + 60 {
        return Err(BridgeError::StaleAttestation {
            timestamp: attestation.timestamp,
        });
    }

    Ok(())
}

impl OracleRegistry {
    /// Create a new oracle registry with the given M-of-N threshold.
    ///
    /// Uses the zero signing domain (chain_id 0, zero instance) — suitable
    /// for unit tests only. Production paths construct via
    /// [`Self::with_domain`] so attestations are bound to one deployment
    /// (SECREM-01 BRG-3).
    pub fn new(threshold: usize) -> Self {
        Self::with_domain(threshold, 0, [0u8; 32])
    }

    /// Create a registry whose attestations are domain-bound to a specific
    /// chain + bridge instance (SECREM-01 BRG-3).
    pub fn with_domain(threshold: usize, chain_id: u64, bridge_instance: [u8; 32]) -> Self {
        Self {
            oracles: HashMap::new(),
            threshold,
            attestations: HashMap::new(),
            chain_id,
            bridge_instance,
        }
    }

    /// The signing domain `(chain_id, bridge_instance)` attestations must
    /// be bound to. Exposed so oracle clients and tests build messages via
    /// [`attestation_message`] with the exact verifier domain.
    pub fn domain(&self) -> (u64, [u8; 32]) {
        (self.chain_id, self.bridge_instance)
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
    ///
    /// CHAIN-B-D020: reject `0` (which would degrade the M-of-N gate to
    /// 0-of-N — every event mints with zero attestations) and any value above
    /// the active-oracle count (unreachable, so nothing would ever mint).
    /// Previously this was an unbounded, unauthenticated setter.
    pub fn set_threshold(&mut self, threshold: usize) -> Result<(), BridgeError> {
        let active = self.active_oracle_count();
        if threshold == 0 || threshold > active {
            return Err(BridgeError::InvalidThreshold { threshold, active });
        }
        self.threshold = threshold;
        Ok(())
    }

    /// Submit an attestation from an oracle.
    ///
    /// Performs full verification:
    /// 1. Oracle is registered and active
    /// 2. Not a duplicate attestation
    /// 3. Attestation timestamp is within freshness window
    /// 4. Ed25519 signature over domain-separated message is valid
    ///
    /// Returns the current attestation count for this event.
    pub fn submit_attestation(
        &mut self,
        attestation: OracleAttestation,
    ) -> Result<usize, BridgeError> {
        // SECREM-01 BRG-3: capture the signing domain before field borrows.
        let (chain_id, bridge_instance) = (self.chain_id, self.bridge_instance);
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

        // Verify attestation timestamp is within freshness window
        verify_attestation_freshness(&attestation)?;

        // Cryptographic ed25519 signature verification
        verify_attestation_signature(&attestation, chain_id, &bridge_instance)?;

        // Update oracle stats
        oracle.last_attestation = attestation.timestamp;
        oracle.total_attestations += 1;

        // Store attestation
        event_attestations.push(attestation);
        Ok(event_attestations.len())
    }

    /// Check if an event has met the attestation threshold BY RAW COUNT.
    ///
    /// SECREM-01 BRG-1: this is a LIVENESS signal only ("are enough
    /// attestations in to bother evaluating?"), NOT a security gate — it
    /// counts attestations that may disagree about the event contents.
    /// Every mint/release decision must use [`Self::is_threshold_met_for`],
    /// which counts only active-oracle attestations binding the exact
    /// canonical event hash.
    pub fn is_threshold_met(&self, event_id: &EventId) -> bool {
        self.attestations
            .get(event_id)
            .map(|a| a.len() >= self.threshold)
            .unwrap_or(false)
    }

    /// SECREM-01 BRG-1 + BRG-4: count attestations that actually vouch for
    /// `expected_hash` — submitted by a CURRENTLY registered AND active
    /// oracle (an oracle deactivated/removed after submitting no longer
    /// counts), with `event_hash` exactly equal to the canonical hash the
    /// relay recomputed from the presented event. Disagreeing attestations
    /// are logged (a signed disagreement is evidence of a faulty or
    /// malicious oracle) and NOT counted — but they also cannot veto the
    /// honest quorum, so one bad oracle can't grief deposits.
    pub fn matching_attestation_count(
        &self,
        event_id: &EventId,
        expected_hash: &[u8; 32],
    ) -> usize {
        let Some(attestations) = self.attestations.get(event_id) else {
            return 0;
        };
        let mut matching = 0usize;
        for att in attestations {
            let oracle_live = self
                .oracles
                .get(&att.oracle_id)
                .map(|o| o.active)
                .unwrap_or(false);
            if !oracle_live {
                tracing::warn!(
                    event_id = hex::encode(event_id),
                    oracle = hex::encode(att.oracle_id),
                    "attestation from inactive/removed oracle excluded from threshold"
                );
                continue;
            }
            if &att.event_hash != expected_hash {
                tracing::warn!(
                    event_id = hex::encode(event_id),
                    oracle = hex::encode(att.oracle_id),
                    attested = hex::encode(att.event_hash),
                    expected = hex::encode(expected_hash),
                    "oracle attested a DIFFERENT event hash — excluded from \
                     threshold and flagged (possible compromise)"
                );
                continue;
            }
            matching += 1;
        }
        matching
    }

    /// SECREM-01 BRG-1: the security-gating threshold check — M-of-N where
    /// every counted attestation binds `expected_hash` exactly and comes
    /// from an active oracle. This is what makes M independent oracles
    /// attest the SAME event, instead of M signatures over possibly
    /// different events (which silently degraded to 1-of-N for the
    /// integrity-critical fields).
    pub fn is_threshold_met_for(&self, event_id: &EventId, expected_hash: &[u8; 32]) -> bool {
        // CHAIN-B-D020: fail closed on a zero threshold. `matching_attestation_count`
        // returns 0 for an event with no attestations, and `0 >= 0` is `true` —
        // so a threshold of 0 would mint every event with zero attestations.
        // A mint gate must never be satisfiable by the absence of attestations.
        if self.threshold == 0 {
            return false;
        }
        self.matching_attestation_count(event_id, expected_hash) >= self.threshold
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
    use ed25519_dalek::{Signer, SigningKey};

    /// Generate a deterministic ed25519 signing key from a seed byte.
    fn make_signing_key(id: u8) -> SigningKey {
        let mut seed = [0u8; 32];
        seed[0] = id;
        SigningKey::from_bytes(&seed)
    }

    /// Get the OracleId (public key bytes) for a given seed byte.
    fn make_oracle_id(id: u8) -> OracleId {
        let sk = make_signing_key(id);
        sk.verifying_key().to_bytes()
    }

    /// Create a properly signed attestation.
    fn make_signed_attestation(id: u8, event_id: EventId) -> OracleAttestation {
        let sk = make_signing_key(id);
        let oracle_id = sk.verifying_key().to_bytes();
        let event_hash = compute_event_hash(&event_id, b"test_deposit_data");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Sign the domain-separated v2 message via the shared constructor
        // (registry built with OracleRegistry::new → zero domain).
        let message = attestation_message(0, &[0u8; 32], &event_id, &event_hash, now);
        let sig = sk.sign(&message);

        OracleAttestation {
            oracle_id,
            event_id,
            event_hash,
            signature: sig.to_bytes().to_vec(),
            timestamp: now,
        }
    }

    #[test]
    fn test_oracle_registration() {
        let mut registry = OracleRegistry::new(2);
        let oracle_id = make_oracle_id(1);

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
        let oracle_id = make_oracle_id(1);

        registry
            .register_oracle(oracle_id, "Oracle-1".to_string())
            .unwrap();
        registry.remove_oracle(&oracle_id).unwrap();
        assert_eq!(registry.active_oracle_count(), 0);

        // Remove unknown oracle fails
        let err = registry.remove_oracle(&make_oracle_id(99)).unwrap_err();
        assert!(matches!(err, BridgeError::OracleNotFound { .. }));
    }

    #[test]
    fn test_oracle_threshold_verification() {
        let mut registry = OracleRegistry::new(2);
        let event_id = [10u8; 32];

        // Register 3 oracles
        for i in 1..=3u8 {
            registry
                .register_oracle(make_oracle_id(i), format!("Oracle-{i}"))
                .unwrap();
        }

        // 1 attestation — below threshold
        registry
            .submit_attestation(make_signed_attestation(1, event_id))
            .unwrap();
        assert!(!registry.is_threshold_met(&event_id));
        assert_eq!(registry.attestation_count(&event_id), 1);

        // 2 attestations — meets threshold
        registry
            .submit_attestation(make_signed_attestation(2, event_id))
            .unwrap();
        assert!(registry.is_threshold_met(&event_id));
        assert_eq!(registry.attestation_count(&event_id), 2);
    }

    #[test]
    fn test_duplicate_attestation_rejected() {
        let mut registry = OracleRegistry::new(2);
        let oracle_id = make_oracle_id(1);
        let event_id = [10u8; 32];

        registry
            .register_oracle(oracle_id, "Oracle-1".to_string())
            .unwrap();

        registry
            .submit_attestation(make_signed_attestation(1, event_id))
            .unwrap();

        // Same oracle, same event → duplicate
        let err = registry
            .submit_attestation(make_signed_attestation(1, event_id))
            .unwrap_err();
        assert!(matches!(err, BridgeError::DuplicateAttestation { .. }));
    }

    #[test]
    fn test_inactive_oracle_rejected() {
        let mut registry = OracleRegistry::new(1);
        let oracle_id = make_oracle_id(1);
        let event_id = [10u8; 32];

        registry
            .register_oracle(oracle_id, "Oracle-1".to_string())
            .unwrap();
        registry.deactivate_oracle(&oracle_id).unwrap();

        let err = registry
            .submit_attestation(make_signed_attestation(1, event_id))
            .unwrap_err();
        assert!(matches!(err, BridgeError::OracleInactive { .. }));
    }

    #[test]
    fn test_unregistered_oracle_rejected() {
        let mut registry = OracleRegistry::new(1);
        let event_id = [10u8; 32];

        let err = registry
            .submit_attestation(make_signed_attestation(99, event_id))
            .unwrap_err();
        assert!(matches!(err, BridgeError::OracleNotFound { .. }));
    }

    #[test]
    fn test_attestation_consistency_check() {
        let mut registry = OracleRegistry::new(2);
        let event_id = [10u8; 32];

        for i in 1..=2u8 {
            registry
                .register_oracle(make_oracle_id(i), format!("Oracle-{i}"))
                .unwrap();
        }

        // Both oracles attest with same event_hash → consistent
        registry
            .submit_attestation(make_signed_attestation(1, event_id))
            .unwrap();
        registry
            .submit_attestation(make_signed_attestation(2, event_id))
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
                .register_oracle(make_oracle_id(i), format!("Oracle-{i}"))
                .unwrap();
        }

        // Both attest but threshold not met (need 3)
        registry
            .submit_attestation(make_signed_attestation(1, event_id))
            .unwrap();
        registry
            .submit_attestation(make_signed_attestation(2, event_id))
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

    /// Invalid (tampered) attestation signature is rejected.
    #[test]
    fn test_invalid_signature_rejected() {
        let mut registry = OracleRegistry::new(1);
        let oracle_id = make_oracle_id(1);
        let event_id = [10u8; 32];

        registry
            .register_oracle(oracle_id, "Oracle-1".to_string())
            .unwrap();

        // Create attestation with tampered signature
        let mut att = make_signed_attestation(1, event_id);
        att.signature = vec![0xAB; 64]; // Invalid signature

        let err = registry.submit_attestation(att).unwrap_err();
        assert!(matches!(err, BridgeError::InvalidSignature { .. }));
    }

    /// Stale attestation (old timestamp) is rejected.
    #[test]
    fn test_stale_attestation_rejected() {
        let mut registry = OracleRegistry::new(1);
        let oracle_id = make_oracle_id(1);
        let event_id = [10u8; 32];

        registry
            .register_oracle(oracle_id, "Oracle-1".to_string())
            .unwrap();

        // Create attestation with a timestamp from 10 minutes ago
        let sk = make_signing_key(1);
        let event_hash = compute_event_hash(&event_id, b"test_deposit_data");
        let old_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 600; // 10 minutes ago

        let message =
            attestation_message(0, &[0u8; 32], &event_id, &event_hash, old_timestamp);
        let sig = sk.sign(&message);

        let att = OracleAttestation {
            oracle_id,
            event_id,
            event_hash,
            signature: sig.to_bytes().to_vec(),
            timestamp: old_timestamp,
        };

        let err = registry.submit_attestation(att).unwrap_err();
        assert!(matches!(err, BridgeError::StaleAttestation { .. }));
    }
}
