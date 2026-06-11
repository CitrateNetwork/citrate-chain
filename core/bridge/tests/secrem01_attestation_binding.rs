//! SECREM-01 BRG-1/2/3/4 regression suite (pre-audit 2026-06-09).
//!
//! The finding class: M-of-N oracle agreement was never enforced — the
//! threshold was a raw signature count (`len() >= threshold`) while only
//! the FIRST stored attestation bound the mint-critical fields, so the
//! intended "M independent oracles attest the SAME event" collapsed to
//! 1-of-N (BRG-1). Withdrawals bound nothing at all (BRG-2). Attestation
//! messages lacked chain/instance domain separation, so signatures
//! replayed across deployments sharing oracle keys (BRG-3). And a
//! deactivated or removed oracle's prior attestations kept counting
//! toward the threshold (BRG-4).
//!
//! Red state (pre-fix): every "*_refused"/"*_rejected" scenario below
//! minted or verified successfully.

use citrate_bridge::config::BridgeConfig;
use citrate_bridge::events::{BridgeEvent, DepositEvent, EventStatus, WithdrawalEvent};
use citrate_bridge::oracle::{attestation_message, OracleAttestation, OracleRegistry};
use citrate_bridge::relay::{BridgeRelay, MockEventSource};
use ed25519_dalek::{Signer, SigningKey};
use std::time::{SystemTime, UNIX_EPOCH};

/// Drive one event through the relay's public poll cycle.
async fn process_one(relay: &BridgeRelay, event: BridgeEvent) -> citrate_bridge::relay::ProcessingResult {
    let source = MockEventSource::new();
    source.add_event(event);
    let mut results = relay.poll_cycle(&source).await.expect("poll cycle");
    assert_eq!(results.len(), 1, "exactly one event processed");
    results.remove(0)
}

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
    let sig = sk.sign(&msg);
    OracleAttestation {
        oracle_id: sk.verifying_key().to_bytes(),
        event_id,
        event_hash,
        signature: sig.to_bytes().to_vec(),
        timestamp: ts,
    }
}

fn test_relay(threshold: usize) -> BridgeRelay {
    BridgeRelay::new(BridgeConfig {
        confirmation_depth: 0,
        oracle_threshold: threshold,
        ..Default::default()
    })
}

fn honest_deposit(seed: u8) -> DepositEvent {
    let eth_tx = [seed; 32];
    DepositEvent {
        event_id: DepositEvent::compute_event_id(&eth_tx, 0),
        eth_tx_hash: eth_tx,
        log_index: 0,
        eth_block_number: 64,
        depositor: [seed; 20],
        recipient: [seed.wrapping_add(1); 20],
        amount_wei: 1_000_000_000_000_000_000,
        amount_eth: 1.0,
        timestamp: 1_000,
    }
}

fn honest_withdrawal(seed: u8) -> WithdrawalEvent {
    let tx = [seed; 32];
    WithdrawalEvent {
        event_id: WithdrawalEvent::compute_event_id(&tx, 200),
        citrate_tx_hash: tx,
        citrate_block_height: 200,
        sender: [seed; 20],
        eth_recipient: [seed.wrapping_add(2); 20],
        salt_amount: 5_000,
        eth_amount_wei: 500_000_000_000_000_000,
        timestamp: 2_000,
    }
}

/// BRG-1, the exact reported attack: with threshold 2, a malicious oracle
/// lands FIRST binding a tampered hash; an honest oracle attests the
/// honest hash. Raw count = 2 ≥ threshold — pre-fix the TAMPERED deposit
/// minted. Post-fix: only attestations matching the presented deposit's
/// canonical hash count, so the tampered deposit is explicitly rejected.
#[tokio::test]
async fn brg1_first_attestation_no_longer_binds_alone() {
    let relay = test_relay(2);
    let (sk_evil, sk_honest) = (key(1), key(2));
    {
        let mut reg = relay.oracle_registry().write();
        reg.register_oracle(sk_evil.verifying_key().to_bytes(), "evil".into())
            .expect("register");
        reg.register_oracle(sk_honest.verifying_key().to_bytes(), "honest".into())
            .expect("register");
    }
    let domain = relay.oracle_registry().read().domain();

    let honest = honest_deposit(9);
    let tampered = DepositEvent {
        recipient: [0xAA; 20],
        amount_wei: 50 * 1_000_000_000_000_000_000,
        amount_eth: 50.0,
        ..honest.clone()
    };
    let event_id = honest.event_id;

    // Malicious oracle attests the TAMPERED hash first; honest oracle
    // attests the honest hash second. Both signatures are individually
    // valid — the disagreement is the attack.
    let ts = now_secs();
    relay
        .oracle_registry()
        .write()
        .submit_attestation(signed_att(&sk_evil, domain, event_id, tampered.canonical_hash(), ts))
        .expect("evil att accepted (signature is valid)");
    relay
        .oracle_registry()
        .write()
        .submit_attestation(signed_att(
            &sk_honest,
            domain,
            event_id,
            honest.canonical_hash(),
            ts + 1,
        ))
        .expect("honest att accepted");

    // Raw count meets threshold — but neither hash has 2 matching votes.
    assert!(relay.oracle_registry().read().is_threshold_met(&event_id));
    assert!(!relay
        .oracle_registry()
        .read()
        .is_threshold_met_for(&event_id, &tampered.canonical_hash()));
    assert!(!relay
        .oracle_registry()
        .read()
        .is_threshold_met_for(&event_id, &honest.canonical_hash()));

    // The tampered deposit must NOT mint.
    let result = process_one(&relay, BridgeEvent::Deposit(tampered)).await;
    assert_eq!(result.status, EventStatus::Rejected, "BRG-1 regression: 1-of-N minted");
    assert!(result.salt_amount.is_none());
}

/// BRG-1 liveness counterpart: when M oracles DO agree on the honest
/// hash, the deposit mints — disagreeing extras can't veto.
#[tokio::test]
async fn brg1_honest_quorum_still_mints_despite_one_liar() {
    let relay = test_relay(2);
    let (sk_evil, sk_h1, sk_h2) = (key(3), key(4), key(5));
    {
        let mut reg = relay.oracle_registry().write();
        for (sk, name) in [(&sk_evil, "evil"), (&sk_h1, "h1"), (&sk_h2, "h2")] {
            reg.register_oracle(sk.verifying_key().to_bytes(), name.to_string())
                .expect("register");
        }
    }
    let domain = relay.oracle_registry().read().domain();

    let honest = honest_deposit(11);
    let event_id = honest.event_id;
    let lie = [0xEE; 32];

    let ts = now_secs();
    // Scope the write guard so it is dropped before the await below
    // (clippy::await_holding_lock — a parking_lot guard must not be live
    // across an .await).
    {
        let mut reg = relay.oracle_registry().write();
        reg.submit_attestation(signed_att(&sk_evil, domain, event_id, lie, ts))
            .expect("liar's att stored");
        reg.submit_attestation(signed_att(&sk_h1, domain, event_id, honest.canonical_hash(), ts + 1))
            .expect("h1");
        reg.submit_attestation(signed_att(&sk_h2, domain, event_id, honest.canonical_hash(), ts + 2))
            .expect("h2");
    }

    let result = process_one(&relay, BridgeEvent::Deposit(honest)).await;
    assert_eq!(
        result.status,
        EventStatus::Processed,
        "honest 2-of-3 quorum must mint; a single liar cannot grief"
    );
    assert!(result.salt_amount.is_some());
}

/// BRG-2: withdrawals now require field-bound attestations. An
/// unattested (or wrongly-attested) withdrawal must not process.
#[tokio::test]
async fn brg2_withdrawal_requires_bound_attestations() {
    let relay = test_relay(1);
    let sk = key(6);
    relay
        .oracle_registry()
        .write()
        .register_oracle(sk.verifying_key().to_bytes(), "o".into())
        .expect("register");
    let domain = relay.oracle_registry().read().domain();

    let w = honest_withdrawal(13);
    let event_id = w.event_id;

    // No attestations → parked awaiting.
    let r = process_one(&relay, BridgeEvent::Withdrawal(w.clone())).await;
    assert_eq!(r.status, EventStatus::AwaitingAttestations);

    // Attestation over a DIFFERENT (tampered-recipient) withdrawal hash →
    // explicit rejection, never processing.
    let tampered = WithdrawalEvent {
        eth_recipient: [0xBB; 20],
        ..w.clone()
    };
    relay
        .oracle_registry()
        .write()
        .submit_attestation(signed_att(&sk, domain, event_id, tampered.canonical_hash(), now_secs()))
        .expect("att stored");
    // Note: relay dedupes processed event_ids; use a fresh relay to
    // re-present the honest withdrawal against the tampered attestation.
    let relay2 = test_relay(1);
    relay2
        .oracle_registry()
        .write()
        .register_oracle(sk.verifying_key().to_bytes(), "o".into())
        .expect("register");
    let domain2 = relay2.oracle_registry().read().domain();
    relay2
        .oracle_registry()
        .write()
        .submit_attestation(signed_att(&sk, domain2, event_id, tampered.canonical_hash(), now_secs()))
        .expect("att stored");
    let r2 = process_one(&relay2, BridgeEvent::Withdrawal(w.clone())).await;
    assert_eq!(
        r2.status,
        EventStatus::Rejected,
        "BRG-2 regression: withdrawal processed without field-bound attestation"
    );

    // Properly bound attestation → processed.
    let relay3 = test_relay(1);
    relay3
        .oracle_registry()
        .write()
        .register_oracle(sk.verifying_key().to_bytes(), "o".into())
        .expect("register");
    let domain3 = relay3.oracle_registry().read().domain();
    relay3
        .oracle_registry()
        .write()
        .submit_attestation(signed_att(&sk, domain3, event_id, w.canonical_hash(), now_secs()))
        .expect("att stored");
    let r3 = process_one(&relay3, BridgeEvent::Withdrawal(w)).await;
    assert_eq!(r3.status, EventStatus::Processed);
}

/// BRG-3: an attestation signed for one deployment domain fails
/// verification on another (different chain id OR different instance),
/// even with identical oracle keys and event contents.
#[test]
fn brg3_cross_domain_replay_rejected() {
    let sk = key(7);
    let oracle_id = sk.verifying_key().to_bytes();
    let event_id = [21u8; 32];
    let event_hash = [22u8; 32];
    let ts = now_secs();

    let domain_a = (40204u64, [0xA0u8; 32]);
    let att = signed_att(&sk, domain_a, event_id, event_hash, ts);

    // Registry on domain A accepts.
    let mut reg_a = OracleRegistry::with_domain(1, domain_a.0, domain_a.1);
    reg_a.register_oracle(oracle_id, "o".into()).expect("register");
    reg_a
        .submit_attestation(att.clone())
        .expect("valid on its own domain");

    // Same attestation on a different chain id → rejected.
    let mut reg_b = OracleRegistry::with_domain(1, 1, domain_a.1);
    reg_b.register_oracle(oracle_id, "o".into()).expect("register");
    assert!(
        reg_b.submit_attestation(att.clone()).is_err(),
        "BRG-3 regression: attestation replayed across chain ids"
    );

    // Same attestation on a different bridge instance → rejected.
    let mut reg_c = OracleRegistry::with_domain(1, domain_a.0, [0xC0u8; 32]);
    reg_c.register_oracle(oracle_id, "o".into()).expect("register");
    assert!(
        reg_c.submit_attestation(att).is_err(),
        "BRG-3 regression: attestation replayed across bridge instances"
    );
}

/// BRG-4: an oracle deactivated (or removed) AFTER submitting no longer
/// counts toward the threshold.
#[test]
fn brg4_inactive_oracle_attestation_not_counted() {
    let domain = (0u64, [0u8; 32]);
    let mut reg = OracleRegistry::with_domain(2, domain.0, domain.1);
    let (sk1, sk2) = (key(8), key(9));
    let (o1, o2) = (sk1.verifying_key().to_bytes(), sk2.verifying_key().to_bytes());
    reg.register_oracle(o1, "o1".into()).expect("register");
    reg.register_oracle(o2, "o2".into()).expect("register");

    let event_id = [31u8; 32];
    let event_hash = [32u8; 32];
    let ts = now_secs();
    reg.submit_attestation(signed_att(&sk1, domain, event_id, event_hash, ts))
        .expect("o1 att");
    reg.submit_attestation(signed_att(&sk2, domain, event_id, event_hash, ts + 1))
        .expect("o2 att");
    assert!(reg.is_threshold_met_for(&event_id, &event_hash));

    // Deactivate o1 — its attestation must stop counting.
    reg.deactivate_oracle(&o1).expect("deactivate");
    assert!(
        !reg.is_threshold_met_for(&event_id, &event_hash),
        "BRG-4 regression: deactivated oracle still counted toward threshold"
    );

    // Remove o2 entirely — count drops to zero.
    reg.remove_oracle(&o2).expect("remove");
    assert_eq!(reg.matching_attestation_count(&event_id, &event_hash), 0);
}
