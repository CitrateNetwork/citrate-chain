// Sprint MM: Bridge adversarial tests
// Tests oracle attestation security, double-processing prevention,
// threshold enforcement, and malicious oracle scenarios.

use citrate_bridge::oracle::{OracleAttestation, OracleRegistry};
use citrate_bridge::events::EventId;
use ed25519_dalek::{SigningKey, Signer};

/// Helper: create a deterministic signing key from a seed byte
fn test_signing_key(seed: u8) -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    bytes[1] = seed.wrapping_mul(37);
    bytes[2] = seed.wrapping_mul(73);
    SigningKey::from_bytes(&bytes)
}

/// Helper: create a signed attestation from a given signing key
fn create_signed_attestation(
    signing_key: &SigningKey,
    event_id: EventId,
    event_hash: [u8; 32],
) -> OracleAttestation {
    let oracle_id: [u8; 32] = signing_key.verifying_key().to_bytes();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_secs();

    // Domain-separated message: "citrate-bridge-v1" || event_id || event_hash || timestamp
    let mut message = Vec::with_capacity(89);
    message.extend_from_slice(b"citrate-bridge-v1");
    message.extend_from_slice(&event_id);
    message.extend_from_slice(&event_hash);
    message.extend_from_slice(&timestamp.to_le_bytes());

    let signature = signing_key.sign(&message);

    OracleAttestation {
        oracle_id,
        event_id,
        event_hash,
        signature: signature.to_bytes().to_vec(),
        timestamp,
    }
}

// ============================================================
// Oracle Registry Security Tests
// ============================================================

#[test]
fn test_threshold_not_met_with_insufficient_attestations() {
    let mut registry = OracleRegistry::new(3); // Need 3 of N

    // Register 5 oracles
    let keys: Vec<SigningKey> = (0..5).map(|i| test_signing_key(i as u8)).collect();
    for key in &keys {
        let id = key.verifying_key().to_bytes();
        registry.register_oracle(id, "oracle".to_string()).unwrap();
    }

    let event_id = [1u8; 32];
    let event_hash = [2u8; 32];

    // Submit only 2 attestations — threshold is 3
    for key in &keys[..2] {
        let att = create_signed_attestation(key, event_id, event_hash);
        registry.submit_attestation(att).unwrap();
    }

    assert!(!registry.is_threshold_met(&event_id), "2/3 should not meet threshold");
    assert_eq!(registry.attestation_count(&event_id), 2);
}

#[test]
fn test_threshold_met_with_sufficient_attestations() {
    let mut registry = OracleRegistry::new(2); // Need 2 of N

    let keys: Vec<SigningKey> = (0..3).map(|i| test_signing_key(i as u8 + 10)).collect();
    for key in &keys {
        let id = key.verifying_key().to_bytes();
        registry.register_oracle(id, "oracle".to_string()).unwrap();
    }

    let event_id = [3u8; 32];
    let event_hash = [4u8; 32];

    for key in &keys[..2] {
        let att = create_signed_attestation(key, event_id, event_hash);
        registry.submit_attestation(att).unwrap();
    }

    assert!(registry.is_threshold_met(&event_id), "2/2 should meet threshold");
}

#[test]
fn test_duplicate_attestation_from_same_oracle_rejected() {
    let mut registry = OracleRegistry::new(2);
    let key = test_signing_key(30);
    let id = key.verifying_key().to_bytes();
    registry.register_oracle(id, "oracle".to_string()).unwrap();

    let event_id = [5u8; 32];
    let event_hash = [6u8; 32];

    // First attestation succeeds
    let att1 = create_signed_attestation(&key, event_id, event_hash);
    assert!(registry.submit_attestation(att1).is_ok());

    // Second from same oracle fails
    let att2 = create_signed_attestation(&key, event_id, event_hash);
    let result = registry.submit_attestation(att2);
    assert!(result.is_err(), "Duplicate attestation must be rejected");
}

#[test]
fn test_unregistered_oracle_attestation_rejected() {
    let mut registry = OracleRegistry::new(1);
    // Don't register the oracle
    let key = test_signing_key(31);

    let event_id = [7u8; 32];
    let event_hash = [8u8; 32];
    let att = create_signed_attestation(&key, event_id, event_hash);

    let result = registry.submit_attestation(att);
    assert!(result.is_err(), "Unregistered oracle must be rejected");
}

#[test]
fn test_inactive_oracle_attestation_rejected() {
    let mut registry = OracleRegistry::new(1);
    let key = test_signing_key(32);
    let id = key.verifying_key().to_bytes();
    registry.register_oracle(id, "oracle".to_string()).unwrap();
    registry.deactivate_oracle(&id).unwrap();

    let event_id = [9u8; 32];
    let event_hash = [10u8; 32];
    let att = create_signed_attestation(&key, event_id, event_hash);

    let result = registry.submit_attestation(att);
    assert!(result.is_err(), "Inactive oracle must be rejected");
}

#[test]
fn test_forged_signature_rejected() {
    let mut registry = OracleRegistry::new(1);
    let real_key = test_signing_key(33);
    let fake_key = test_signing_key(34);
    let id = real_key.verifying_key().to_bytes();
    registry.register_oracle(id, "oracle".to_string()).unwrap();

    let event_id = [11u8; 32];
    let event_hash = [12u8; 32];

    // Sign with the wrong key but use the real oracle's ID
    let mut att = create_signed_attestation(&fake_key, event_id, event_hash);
    att.oracle_id = id; // Forge the oracle ID

    let result = registry.submit_attestation(att);
    assert!(result.is_err(), "Forged signature must be rejected");
}

#[test]
fn test_attestation_consistency_check() {
    let mut registry = OracleRegistry::new(2);
    let keys: Vec<SigningKey> = (0..2).map(|i| test_signing_key(i as u8 + 20)).collect();
    for key in &keys {
        let id = key.verifying_key().to_bytes();
        registry.register_oracle(id, "oracle".to_string()).unwrap();
    }

    let event_id = [13u8; 32];

    // Two oracles attest to DIFFERENT event hashes — inconsistency
    let att1 = create_signed_attestation(&keys[0], event_id, [0xAA; 32]);
    let att2 = create_signed_attestation(&keys[1], event_id, [0xBB; 32]);

    registry.submit_attestation(att1).unwrap();
    registry.submit_attestation(att2).unwrap();

    assert!(
        !registry.verify_attestation_consistency(&event_id),
        "Inconsistent event hashes should be detected"
    );
}

#[test]
fn test_consistent_attestations_pass_check() {
    let mut registry = OracleRegistry::new(2);
    let keys: Vec<SigningKey> = (0..2).map(|i| test_signing_key(i as u8 + 20)).collect();
    for key in &keys {
        let id = key.verifying_key().to_bytes();
        registry.register_oracle(id, "oracle".to_string()).unwrap();
    }

    let event_id = [14u8; 32];
    let event_hash = [0xCC; 32];

    let att1 = create_signed_attestation(&keys[0], event_id, event_hash);
    let att2 = create_signed_attestation(&keys[1], event_id, event_hash);

    registry.submit_attestation(att1).unwrap();
    registry.submit_attestation(att2).unwrap();

    assert!(
        registry.verify_attestation_consistency(&event_id),
        "Consistent attestations should pass"
    );
}

#[test]
fn test_oracle_removal_prevents_future_attestations() {
    let mut registry = OracleRegistry::new(1);
    let key = test_signing_key(35);
    let id = key.verifying_key().to_bytes();
    registry.register_oracle(id, "oracle".to_string()).unwrap();
    registry.remove_oracle(&id).unwrap();

    let event_id = [15u8; 32];
    let event_hash = [16u8; 32];
    let att = create_signed_attestation(&key, event_id, event_hash);

    let result = registry.submit_attestation(att);
    assert!(result.is_err(), "Removed oracle must be rejected");
}

#[test]
fn test_zero_threshold_unseen_event_not_met() {
    // With threshold 0, is_threshold_met still requires the event to exist in
    // the attestations map. An unseen event returns false because
    // attestations.get() returns None. This is correct: we don't auto-process
    // events we've never received attestations for.
    let registry = OracleRegistry::new(0);
    let event_id = [17u8; 32];
    assert!(
        !registry.is_threshold_met(&event_id),
        "Unseen event should not be met even with threshold=0"
    );
}

#[test]
fn test_multiple_events_tracked_independently() {
    let mut registry = OracleRegistry::new(1);
    let key = test_signing_key(36);
    let id = key.verifying_key().to_bytes();
    registry.register_oracle(id, "oracle".to_string()).unwrap();

    let event_a = [0xA0; 32];
    let event_b = [0xB0; 32];
    let event_hash = [0xFF; 32];

    // Attest to event A only
    let att = create_signed_attestation(&key, event_a, event_hash);
    registry.submit_attestation(att).unwrap();

    assert!(registry.is_threshold_met(&event_a), "Event A should be met");
    assert!(!registry.is_threshold_met(&event_b), "Event B should NOT be met");
}
