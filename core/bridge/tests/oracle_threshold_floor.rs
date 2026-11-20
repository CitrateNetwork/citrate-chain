// The M-of-N mint gate fails closed when the registry's threshold is zero.
//
// `set_threshold` refuses 0, and the relay refuses a zero `oracle_threshold`
// at construction, but `OracleRegistry::with_domain` is public and takes any
// threshold. `is_threshold_met_for` is the gate the relay consults before a
// mint, so it must never be satisfied by an empty attestation set.
//
// In-process only: no network, no files.

use citrate_bridge::oracle::{attestation_message, OracleAttestation, OracleRegistry};
use ed25519_dalek::{Signer, SigningKey};
use std::time::{SystemTime, UNIX_EPOCH};

fn key(seed: u8) -> SigningKey {
    let mut b = [0u8; 32];
    b[0] = seed;
    b[1] = seed.wrapping_mul(41);
    SigningKey::from_bytes(&b)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn signed_att(
    sk: &SigningKey,
    domain: (u64, [u8; 32]),
    event_id: [u8; 32],
    event_hash: [u8; 32],
    ts: u64,
) -> OracleAttestation {
    let msg = attestation_message(domain.0, &domain.1, &event_id, &event_hash, ts);
    OracleAttestation {
        oracle_id: sk.verifying_key().to_bytes(),
        event_id,
        event_hash,
        signature: sk.sign(&msg).to_bytes().to_vec(),
        timestamp: ts,
    }
}

#[test]
fn a_zero_threshold_registry_never_meets_the_gate_with_no_attestations() {
    let mut reg = OracleRegistry::with_domain(0, 40204, [7u8; 32]);
    reg.register_oracle(key(1).verifying_key().to_bytes(), "o1".into())
        .expect("register");
    let event_id = [0x51u8; 32];
    let event_hash = [0x52u8; 32];
    assert_eq!(reg.matching_attestation_count(&event_id, &event_hash), 0);
    assert!(
        !reg.is_threshold_met_for(&event_id, &event_hash),
        "a zero threshold must not let an unattested event through the mint gate"
    );
}

#[test]
fn a_zero_threshold_registry_stays_closed_even_with_an_attestation() {
    let domain = (40204u64, [7u8; 32]);
    let mut reg = OracleRegistry::with_domain(0, domain.0, domain.1);
    let sk = key(2);
    reg.register_oracle(sk.verifying_key().to_bytes(), "o2".into())
        .expect("register");
    let event_id = [0x61u8; 32];
    let event_hash = [0x62u8; 32];
    reg.submit_attestation(signed_att(&sk, domain, event_id, event_hash, now_secs()))
        .expect("attestation");
    assert!(
        !reg.is_threshold_met_for(&event_id, &event_hash),
        "a zero threshold is a misconfiguration; the gate must fail closed"
    );
}

#[test]
fn a_one_of_one_registry_meets_the_gate_with_its_attestation() {
    // Control: the gate does open for a valid threshold, so the tests above
    // are not passing on a gate that never opens.
    let domain = (40204u64, [7u8; 32]);
    let mut reg = OracleRegistry::with_domain(1, domain.0, domain.1);
    let sk = key(3);
    reg.register_oracle(sk.verifying_key().to_bytes(), "o3".into())
        .expect("register");
    let event_id = [0x71u8; 32];
    let event_hash = [0x72u8; 32];
    assert!(!reg.is_threshold_met_for(&event_id, &event_hash));
    reg.submit_attestation(signed_att(&sk, domain, event_id, event_hash, now_secs()))
        .expect("attestation");
    assert!(reg.is_threshold_met_for(&event_id, &event_hash));
}
