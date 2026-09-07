// WP-RR.6: Coverage gap tests for citrate-bridge — target 98%.
//
// This file exercises untested branches, error variants, edge cases, and
// accessor methods across all bridge modules to close the ~5% gap between
// the current ~93% coverage and the 98% target.

use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use citrate_bridge::config::{BondingCurveConfig, BridgeConfig};
use citrate_bridge::errors::BridgeError;
use citrate_bridge::events::{
    BridgeEvent, DepositEvent, EventStatus, OracleUpdateEvent, TrackedEvent, WithdrawalEvent,
};
use citrate_bridge::metrics::BridgeMetrics;
use citrate_bridge::mint::SnapMinter;
use citrate_bridge::oracle::{compute_event_hash, OracleAttestation, OracleRegistry};
use citrate_bridge::relay::{BridgeRelay, MockEventSource};
use citrate_bridge::state::RelayState;

use ed25519_dalek::{Signer, SigningKey};

// ============================================================
// Helpers
// ============================================================

fn test_signing_key(seed: u8) -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    bytes[1] = seed.wrapping_mul(37);
    bytes[2] = seed.wrapping_mul(73);
    SigningKey::from_bytes(&bytes)
}

fn default_oracle_key() -> SigningKey {
    test_signing_key(42)
}

fn setup_relay() -> BridgeRelay {
    let config = BridgeConfig {
        confirmation_depth: 0,
        oracle_threshold: 1,
        ..Default::default()
    };
    let relay = BridgeRelay::new(config);
    let sk = default_oracle_key();
    {
        let mut reg = relay.oracle_registry().write();
        reg.register_oracle(sk.verifying_key().to_bytes(), "TestOracle".to_string())
            .unwrap();
    }
    relay
}

fn attest_event(relay: &BridgeRelay, event: &BridgeEvent) {
    let event_id = *event.event_id();
    // Post-RM-A: deposits are attested with their canonical field-binding hash
    // so the relay's binding gate accepts the honest deposit.
    let event_hash = match event {
        BridgeEvent::Deposit(d) => d.canonical_hash(),
        // SECREM-01 BRG-2: withdrawals are field-bound too.
        BridgeEvent::Withdrawal(w) => w.canonical_hash(),
        _ => compute_event_hash(&event_id, b"deposit"),
    };
    let sk = default_oracle_key();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // SECREM-01 BRG-3: sign the v2 message bound to the relay's domain.
    let (cid, inst) = relay.oracle_registry().read().domain();
    let message =
        citrate_bridge::oracle::attestation_message(cid, &inst, &event_id, &event_hash, timestamp);
    let sig = sk.sign(&message);

    let att = OracleAttestation {
        oracle_id: sk.verifying_key().to_bytes(),
        event_id,
        event_hash,
        signature: sig.to_bytes().to_vec(),
        timestamp,
    };
    relay
        .oracle_registry()
        .write()
        .submit_attestation(att)
        .unwrap();
}

fn make_deposit_event(id: u8, amount_eth: f64) -> BridgeEvent {
    let event_id = DepositEvent::compute_event_id(&[id; 32], 0);
    BridgeEvent::Deposit(DepositEvent {
        event_id,
        eth_tx_hash: [id; 32],
        log_index: 0,
        eth_block_number: 50,
        depositor: [id; 20],
        recipient: [id + 100; 20],
        amount_wei: (amount_eth * 1e18) as u128,
        amount_eth,
        timestamp: 1000,
    })
}

fn make_withdrawal_event(id: u8, salt_amount: u64) -> BridgeEvent {
    let event_id = WithdrawalEvent::compute_event_id(&[id; 32], 200);
    BridgeEvent::Withdrawal(WithdrawalEvent {
        event_id,
        citrate_tx_hash: [id; 32],
        citrate_block_height: 200,
        sender: [id; 20],
        eth_recipient: [id + 100; 20],
        salt_amount,
        eth_amount_wei: (salt_amount as u128) * 100_000_000_000_000,
        timestamp: 2000,
    })
}

fn make_oracle_update_event(id: u8, is_addition: bool) -> BridgeEvent {
    let mut event_id = [0u8; 32];
    event_id[0] = id;
    event_id[31] = 0xEE;
    BridgeEvent::OracleUpdate(OracleUpdateEvent {
        event_id,
        oracle_pubkey: [id; 32],
        is_addition,
        timestamp: 3000,
    })
}

// ============================================================
// 1. BridgeEvent::source_block for Withdrawal and OracleUpdate
// ============================================================

#[test]
fn test_bridge_event_source_block_withdrawal() {
    let event = make_withdrawal_event(1, 5000);
    assert_eq!(event.source_block(), 200, "Withdrawal source_block = citrate_block_height");
}

#[test]
fn test_bridge_event_source_block_oracle_update() {
    let event = make_oracle_update_event(1, true);
    assert_eq!(event.source_block(), 0, "OracleUpdate source_block should be 0");
}

#[test]
fn test_bridge_event_event_id_oracle_update() {
    let event = make_oracle_update_event(7, false);
    let id = event.event_id();
    assert_eq!(id[0], 7);
    assert_eq!(id[31], 0xEE);
}

// ============================================================
// 2. WithdrawalEvent::compute_event_id uniqueness
// ============================================================

#[test]
fn test_withdrawal_event_id_different_heights() {
    let tx = [0xAA; 32];
    let id1 = WithdrawalEvent::compute_event_id(&tx, 100);
    let id2 = WithdrawalEvent::compute_event_id(&tx, 101);
    assert_ne!(id1, id2, "Different block heights must produce different event IDs");
}

#[test]
fn test_withdrawal_event_id_different_tx_hashes() {
    let id1 = WithdrawalEvent::compute_event_id(&[1u8; 32], 100);
    let id2 = WithdrawalEvent::compute_event_id(&[2u8; 32], 100);
    assert_ne!(id1, id2, "Different tx hashes must produce different event IDs");
}

// ============================================================
// 3. Error display strings coverage
// ============================================================

#[test]
fn test_error_display_strings() {
    let errors: Vec<BridgeError> = vec![
        BridgeError::EventAlreadyProcessed {
            event_id: "abc".to_string(),
        },
        BridgeError::EventNotFound {
            event_id: "def".to_string(),
        },
        BridgeError::InsufficientAttestations { got: 1, need: 3 },
        BridgeError::OracleAlreadyRegistered {
            oracle_id: "orc1".to_string(),
        },
        BridgeError::OracleNotFound {
            oracle_id: "orc2".to_string(),
        },
        BridgeError::OracleInactive {
            oracle_id: "orc3".to_string(),
        },
        BridgeError::DuplicateAttestation {
            oracle_id: "orc4".to_string(),
            event_id: "ev1".to_string(),
        },
        BridgeError::AttestationInconsistency {
            event_id: "ev2".to_string(),
        },
        BridgeError::EventNotConfirmed {
            block: 100,
            confirmations: 12,
            current: 5,
        },
        BridgeError::DepositTooSmall {
            amount_wei: 100,
            min_wei: 200,
        },
        BridgeError::DepositExceedsCap {
            amount_wei: 999,
            max_wei: 500,
        },
        BridgeError::ConversionError {
            reason: "zero".to_string(),
        },
        BridgeError::RelayStateError {
            reason: "corrupt".to_string(),
        },
        BridgeError::RetryExhausted {
            attempts: 5,
            reason: "timeout".to_string(),
        },
        BridgeError::ChainReorg {
            block: 50,
            expected: "0xaa".to_string(),
            actual: "0xbb".to_string(),
        },
        BridgeError::BridgePaused {
            reason: "upgrade".to_string(),
        },
        BridgeError::InvalidEventData {
            reason: "bad format".to_string(),
        },
        BridgeError::SerializationError("json fail".to_string()),
        BridgeError::InvalidSignature {
            oracle_id: "orc5".to_string(),
        },
        BridgeError::InvalidConfig {
            reason: "missing field".to_string(),
        },
        BridgeError::StaleAttestation { timestamp: 12345 },
    ];

    for err in &errors {
        let display = format!("{}", err);
        assert!(!display.is_empty(), "Error display must not be empty: {:?}", err);
        // Also test Debug
        let debug = format!("{:?}", err);
        assert!(!debug.is_empty());
    }
}

// ============================================================
// 4. BridgeConfig serialization roundtrip
// ============================================================

#[test]
fn test_bridge_config_serde_roundtrip() {
    let config = BridgeConfig::default();
    let json = serde_json::to_string(&config).expect("serialize config");
    let restored: BridgeConfig = serde_json::from_str(&json).expect("deserialize config");

    assert_eq!(restored.confirmation_depth, config.confirmation_depth);
    assert_eq!(restored.oracle_threshold, config.oracle_threshold);
    assert_eq!(restored.max_retries, config.max_retries);
    assert_eq!(restored.poll_interval_ms, config.poll_interval_ms);
    assert_eq!(
        restored.bonding_curve.salt_per_eth,
        config.bonding_curve.salt_per_eth
    );
    assert_eq!(restored.ethereum_rpc, config.ethereum_rpc);
    assert_eq!(restored.bridge_contract, config.bridge_contract);
}

// ============================================================
// 5. BondingCurveConfig edge cases
// ============================================================

#[test]
fn test_bonding_curve_zero_deposit() {
    let curve = BondingCurveConfig::default();
    let salt = curve.calculate_salt_amount(0.0, 0.0);
    assert_eq!(salt, 0, "Zero ETH deposit should yield zero SALT");
}

#[test]
fn test_bonding_curve_tiny_deposit() {
    let curve = BondingCurveConfig::default();
    // 0.0001 ETH should yield 1 SALT (10000 * 0.0001 = 1)
    let salt = curve.calculate_salt_amount(0.0001, 0.0);
    assert_eq!(salt, 1);
}

#[test]
fn test_bonding_curve_at_exact_cap() {
    // When total_deposited is exactly where multiplier hits max_multiplier
    let curve = BondingCurveConfig {
        base_multiplier: 1.0,
        slope: 1.0,
        scale_factor: 1.0,
        max_multiplier: 2.0,
        salt_per_eth: 10_000,
    };
    // multiplier = 1.0 + 1.0 * 1.0 / 1.0 = 2.0 (exactly at cap)
    let salt = curve.calculate_salt_amount(1.0, 1.0);
    assert_eq!(salt, 5000); // 10000 / 2.0

    // multiplier = 1.0 + 1.0 * 10.0 / 1.0 = 11.0 -> capped at 2.0
    let salt2 = curve.calculate_salt_amount(1.0, 10.0);
    assert_eq!(salt2, 5000); // still 10000 / 2.0
}

// ============================================================
// 6. Metrics: all setters and getters exercised
// ============================================================

#[test]
fn test_metrics_attestation_recording() {
    let metrics = BridgeMetrics::new();
    metrics.record_attestation();
    metrics.record_attestation();
    metrics.record_attestation();
    assert_eq!(metrics.attestations_received.load(Ordering::Relaxed), 3);
}

#[test]
fn test_metrics_events_pending() {
    let metrics = BridgeMetrics::new();
    metrics.set_events_pending(42);
    assert_eq!(metrics.events_pending.load(Ordering::Relaxed), 42);
    metrics.set_events_pending(0);
    assert_eq!(metrics.events_pending.load(Ordering::Relaxed), 0);
}

#[test]
fn test_metrics_last_eth_block() {
    let metrics = BridgeMetrics::new();
    metrics.set_last_eth_block(123456);
    assert_eq!(metrics.last_eth_block.load(Ordering::Relaxed), 123456);
}

#[test]
fn test_metrics_relay_lag() {
    let metrics = BridgeMetrics::new();
    metrics.set_relay_lag(99);
    assert_eq!(metrics.relay_lag_blocks.load(Ordering::Relaxed), 99);
}

#[test]
fn test_metrics_default_is_new() {
    let m1 = BridgeMetrics::default();
    let m2 = BridgeMetrics::new();
    assert_eq!(
        m1.deposits_processed.load(Ordering::Relaxed),
        m2.deposits_processed.load(Ordering::Relaxed)
    );
}

#[test]
fn test_metrics_health_stale_heartbeat() {
    let metrics = BridgeMetrics::new();
    // Set heartbeat far in the past (> 60 seconds ago)
    metrics
        .last_heartbeat
        .store(1_000_000, Ordering::Relaxed);
    assert!(!metrics.is_healthy(), "Stale heartbeat should not be healthy");
}

#[test]
fn test_metrics_health_json_not_healthy() {
    let metrics = BridgeMetrics::new();
    // No heartbeat set
    let json = metrics.health_json();
    assert!(json.contains("\"healthy\":false"));
}

#[test]
fn test_metrics_prometheus_all_fields() {
    let metrics = BridgeMetrics::new();
    metrics.record_deposit(100);
    metrics.record_deposit_failure();
    metrics.record_withdrawal(200);
    metrics.record_withdrawal_failure();
    metrics.set_relay_lag(3);
    metrics.set_active_oracles(5);
    metrics.set_events_pending(10);
    metrics.set_last_eth_block(9999);

    let output = metrics.to_prometheus();
    assert!(output.contains("citrate_bridge_deposits_total 1"));
    assert!(output.contains("citrate_bridge_deposits_failed_total 1"));
    assert!(output.contains("citrate_bridge_withdrawals_total 1"));
    assert!(output.contains("citrate_bridge_salt_credited_total 100"));
    assert!(output.contains("citrate_bridge_relay_lag_blocks 3"));
    assert!(output.contains("citrate_bridge_active_oracles 5"));
    assert!(output.contains("citrate_bridge_events_pending 10"));
    assert!(output.contains("citrate_bridge_last_eth_block 9999"));
}

// ============================================================
// 7. OracleRegistry: threshold update, list_oracles, attesting_oracles
// ============================================================

#[test]
fn test_oracle_registry_set_threshold() {
    let mut registry = OracleRegistry::new(2);
    assert_eq!(registry.threshold(), 2);

    // CHAIN-B-D020: set_threshold now validates against the active-oracle count.
    // A threshold of 0 (0-of-N mints every event with no attestations) and any
    // value above the active-oracle count are rejected, and a rejected update
    // must not mutate the threshold.
    assert!(registry.set_threshold(5).is_err(), "no oracles => 5 rejected");
    assert!(registry.set_threshold(0).is_err(), "0-of-N must be rejected");
    assert_eq!(
        registry.threshold(),
        2,
        "a rejected update must not change the threshold"
    );

    // Register enough active oracles, then a valid update succeeds.
    for i in 0..5u8 {
        let k = test_signing_key(60 + i);
        registry
            .register_oracle(k.verifying_key().to_bytes(), format!("O{i}"))
            .expect("register oracle");
    }
    registry
        .set_threshold(5)
        .expect("threshold within active-oracle count is accepted");
    assert_eq!(registry.threshold(), 5);
    assert!(
        registry.set_threshold(6).is_err(),
        "threshold above active-oracle count is rejected"
    );
}

#[test]
fn test_oracle_registry_list_oracles() {
    let mut registry = OracleRegistry::new(1);
    let k1 = test_signing_key(50);
    let k2 = test_signing_key(51);

    registry
        .register_oracle(k1.verifying_key().to_bytes(), "A".to_string())
        .unwrap();
    registry
        .register_oracle(k2.verifying_key().to_bytes(), "B".to_string())
        .unwrap();

    let oracles = registry.list_oracles();
    assert_eq!(oracles.len(), 2);
}

#[test]
fn test_oracle_registry_attesting_oracles_empty() {
    let registry = OracleRegistry::new(1);
    let set = registry.attesting_oracles(&[0xAA; 32]);
    assert!(set.is_empty());
}

#[test]
fn test_oracle_registry_get_attestations_none() {
    let registry = OracleRegistry::new(1);
    assert!(registry.get_attestations(&[0xBB; 32]).is_none());
}

#[test]
fn test_oracle_registry_verify_consistency_no_event() {
    let registry = OracleRegistry::new(1);
    // No attestations for this event -> vacuously true
    assert!(registry.verify_attestation_consistency(&[0xCC; 32]));
}

#[test]
fn test_oracle_registry_attestation_count_unknown_event() {
    let registry = OracleRegistry::new(1);
    assert_eq!(registry.attestation_count(&[0xDD; 32]), 0);
}

#[test]
fn test_oracle_deactivate_not_found() {
    let mut registry = OracleRegistry::new(1);
    let result = registry.deactivate_oracle(&[0xFF; 32]);
    assert!(matches!(result, Err(BridgeError::OracleNotFound { .. })));
}

// ============================================================
// 8. RelayState: constructor, events_by_status, count_by_status,
//    update_event_status with error, add_attestation, serialization
//    with events
// ============================================================

#[test]
fn test_relay_state_new_with_start_block() {
    let state = RelayState::new(5000);
    assert_eq!(state.last_eth_block, 5000);
    assert_eq!(state.total_deposits, 0);
    assert_eq!(state.total_withdrawals, 0);
}

#[test]
fn test_relay_state_update_status_with_error() {
    let mut state = RelayState::default();
    let event_id = [0x10; 32];
    let tracked = TrackedEvent {
        event: BridgeEvent::Deposit(DepositEvent {
            event_id,
            eth_tx_hash: [1u8; 32],
            log_index: 0,
            eth_block_number: 100,
            depositor: [2u8; 20],
            recipient: [3u8; 20],
            amount_wei: 1_000_000_000_000_000_000,
            amount_eth: 1.0,
            timestamp: 1000,
        }),
        status: EventStatus::Pending,
        attestation_count: 0,
        retry_count: 0,
        detected_at: 1000,
        updated_at: 1000,
        error: None,
    };
    state.track_event(tracked);

    // Update with an error message
    state.update_event_status(&event_id, EventStatus::Failed, Some("mint failed".to_string()));

    let te = state.events.get(&event_id).unwrap();
    assert_eq!(te.status, EventStatus::Failed);
    assert_eq!(te.error.as_deref(), Some("mint failed"));
}

#[test]
fn test_relay_state_update_nonexistent_event() {
    let mut state = RelayState::default();
    // Updating a non-existent event returns false
    let result = state.update_event_status(&[0xFF; 32], EventStatus::Processed, None);
    assert!(!result);
}

#[test]
fn test_relay_state_events_by_status_and_count() {
    let mut state = RelayState::default();

    // Add 3 pending events
    for i in 0..3u8 {
        let mut event_id = [0u8; 32];
        event_id[0] = i;
        state.track_event(TrackedEvent {
            event: BridgeEvent::Deposit(DepositEvent {
                event_id,
                eth_tx_hash: [i; 32],
                log_index: 0,
                eth_block_number: 100,
                depositor: [2u8; 20],
                recipient: [3u8; 20],
                amount_wei: 1_000_000_000_000_000_000,
                amount_eth: 1.0,
                timestamp: 1000,
            }),
            status: EventStatus::Pending,
            attestation_count: 0,
            retry_count: 0,
            detected_at: 1000,
            updated_at: 1000,
            error: None,
        });
    }

    // Mark one as Processed, one as Failed
    let mut id0 = [0u8; 32];
    id0[0] = 0;
    let mut id1 = [0u8; 32];
    id1[0] = 1;
    state.update_event_status(&id0, EventStatus::Processed, None);
    state.update_event_status(&id1, EventStatus::Failed, Some("err".to_string()));

    assert_eq!(state.count_by_status(EventStatus::Pending), 1);
    assert_eq!(state.count_by_status(EventStatus::Processed), 1);
    assert_eq!(state.count_by_status(EventStatus::Failed), 1);
    assert_eq!(state.count_by_status(EventStatus::Rejected), 0);

    let pending = state.events_by_status(EventStatus::Pending);
    assert_eq!(pending.len(), 1);

    let failed = state.events_by_status(EventStatus::Failed);
    assert_eq!(failed.len(), 1);
    assert!(failed[0].error.is_some());
}

#[test]
fn test_relay_state_is_processed_unknown() {
    let state = RelayState::default();
    assert!(!state.is_processed(&[0xEE; 32]));
}

#[test]
fn test_relay_state_withdrawal_recording() {
    let mut state = RelayState::default();
    state.record_withdrawal(3000);
    state.record_withdrawal(7000);
    assert_eq!(state.total_withdrawals, 2);
    assert_eq!(state.total_salt_burned, 10_000);
}

#[test]
fn test_relay_state_heartbeat() {
    let mut state = RelayState::default();
    let old = state.last_heartbeat;
    // Small sleep not needed; just call heartbeat
    state.heartbeat();
    assert!(state.last_heartbeat >= old);
}

#[test]
fn test_relay_state_serialization_with_events() {
    let mut state = RelayState::new(100);
    let event_id = [0xAB; 32];
    state.track_event(TrackedEvent {
        event: BridgeEvent::Deposit(DepositEvent {
            event_id,
            eth_tx_hash: [1u8; 32],
            log_index: 3,
            eth_block_number: 100,
            depositor: [2u8; 20],
            recipient: [3u8; 20],
            amount_wei: 5_000_000_000_000_000_000,
            amount_eth: 5.0,
            timestamp: 9999,
        }),
        status: EventStatus::Processed,
        attestation_count: 2,
        retry_count: 1,
        detected_at: 9000,
        updated_at: 9999,
        error: Some("initial fail".to_string()),
    });
    state.record_deposit(50_000);

    let json = state.to_json().unwrap();
    let restored = RelayState::from_json(&json).unwrap();

    assert_eq!(restored.last_eth_block, 100);
    assert_eq!(restored.total_deposits, 1);
    assert_eq!(restored.total_salt_credited, 50_000);
    assert!(restored.is_known_event(&event_id));
    assert!(restored.is_processed(&event_id));

    let te = restored.events.get(&event_id).unwrap();
    assert_eq!(te.attestation_count, 2);
    assert_eq!(te.retry_count, 1);
    assert_eq!(te.error.as_deref(), Some("initial fail"));
}

// ============================================================
// 9. Mint: current_multiplier after deposits, preview stability
// ============================================================

#[test]
fn test_minter_current_multiplier_after_deposits() {
    let mut minter = SnapMinter::new(BondingCurveConfig::default());
    assert_eq!(minter.current_multiplier(), 1.0);

    // Process a deposit to change total_deposited
    let deposit = DepositEvent {
        event_id: [1u8; 32],
        eth_tx_hash: [2u8; 32],
        log_index: 0,
        eth_block_number: 100,
        depositor: [3u8; 20],
        recipient: [4u8; 20],
        amount_wei: 1_000_000_000_000_000_000,
        amount_eth: 1.0,
        timestamp: 1000,
    };
    minter.process_deposit(&deposit).unwrap();

    // After 1 ETH deposited: multiplier = 1.0 + 0.001 * 1.0 / 1000.0 = 1.000001
    let m = minter.current_multiplier();
    assert!(m > 1.0, "Multiplier should increase after deposits");
    assert!(m < 1.01, "Multiplier should still be close to 1.0 after 1 ETH");
}

#[test]
fn test_minter_preview_does_not_change_multiplier() {
    let minter = SnapMinter::new(BondingCurveConfig::default());
    let before = minter.current_multiplier();
    let _preview = minter.preview_conversion(5.0);
    let after = minter.current_multiplier();
    assert_eq!(before, after, "preview_conversion must not change multiplier");
}

#[test]
fn test_minter_multiple_deposits_increment_totals() {
    let mut minter = SnapMinter::new(BondingCurveConfig::default());

    for i in 1..=5u8 {
        let deposit = DepositEvent {
            event_id: [i; 32],
            eth_tx_hash: [i; 32],
            log_index: 0,
            eth_block_number: 100,
            depositor: [3u8; 20],
            recipient: [4u8; 20],
            amount_wei: 500_000_000_000_000_000, // 0.5 ETH
            amount_eth: 0.5,
            timestamp: 1000 + i as u64,
        };
        minter.process_deposit(&deposit).unwrap();
    }

    assert_eq!(minter.total_deposited_eth(), 2.5);
    assert!(minter.total_salt_minted() > 0);
}

// ============================================================
// 10. Relay: OracleUpdate event processing
// ============================================================

#[tokio::test]
async fn test_relay_processes_oracle_update_event() {
    let relay = setup_relay();
    let source = MockEventSource::new();

    let event = make_oracle_update_event(1, true);
    attest_event(&relay, &event);
    source.add_event(event);

    let results = relay.poll_cycle(&source).await.unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status, EventStatus::Processed);
    assert!(results[0].salt_amount.is_none(), "OracleUpdate has no SALT amount");
    assert!(results[0].error.is_none());
}

// ============================================================
// 11. Relay: mixed event types in a single cycle
// ============================================================

#[tokio::test]
async fn test_relay_mixed_event_types_in_one_cycle() {
    let relay = setup_relay();
    let source = MockEventSource::new();

    let dep = make_deposit_event(10, 1.0);
    let wdl = make_withdrawal_event(11, 3000);
    let orc = make_oracle_update_event(12, false);

    // Attest all
    attest_event(&relay, &dep);
    attest_event(&relay, &wdl);
    attest_event(&relay, &orc);

    source.add_event(dep);
    source.add_event(wdl);
    source.add_event(orc);

    let results = relay.poll_cycle(&source).await.unwrap();
    assert_eq!(results.len(), 3);

    // All should be processed
    for r in &results {
        assert_eq!(r.status, EventStatus::Processed);
    }

    // Deposit credited SALT
    assert!(results[0].salt_amount.is_some());
    // Withdrawal recorded SALT
    assert_eq!(results[1].salt_amount, Some(3000));
    // OracleUpdate has no SALT
    assert!(results[2].salt_amount.is_none());

    let state = relay.state().read();
    assert_eq!(state.total_deposits, 1);
    assert_eq!(state.total_withdrawals, 1);
}

// ============================================================
// 12. Relay: metrics after withdrawal
// ============================================================

#[tokio::test]
async fn test_relay_metrics_after_withdrawal() {
    let relay = setup_relay();
    let source = MockEventSource::new();
    let event = make_withdrawal_event(20, 8000);
    attest_event(&relay, &event);
    source.add_event(event);

    relay.poll_cycle(&source).await.unwrap();

    let metrics = relay.metrics();
    assert_eq!(
        metrics.withdrawals_processed.load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        metrics.total_salt_burned.load(Ordering::Relaxed),
        8000
    );
}

// ============================================================
// 13. Relay: retry_event — event not found
// ============================================================

#[tokio::test]
async fn test_relay_retry_event_not_found() {
    let relay = setup_relay();
    let source = MockEventSource::new();

    let result = relay.retry_event(&[0xFF; 32], &source).await;
    assert!(matches!(result, Err(BridgeError::EventNotFound { .. })));
}

// ============================================================
// 14. Relay: retry_event — cannot retry non-failed event
// ============================================================

#[tokio::test]
async fn test_relay_retry_non_failed_event_rejected() {
    let relay = setup_relay();
    let source = MockEventSource::new();

    let event = make_deposit_event(30, 1.0);
    let event_id = *event.event_id();
    attest_event(&relay, &event);
    source.add_event(event);

    // Process it successfully
    relay.poll_cycle(&source).await.unwrap();

    // Try to retry a Processed event
    let result = relay.retry_event(&event_id, &source).await;
    assert!(matches!(result, Err(BridgeError::InvalidEventData { .. })));
}

// ============================================================
// 15. Relay: retry_event — retries exhausted
// ============================================================

#[tokio::test]
async fn test_relay_retry_exhausted() {
    let relay = setup_relay();
    let source = MockEventSource::new();

    // Create a deposit that will fail (below minimum)
    let event_id = DepositEvent::compute_event_id(&[40; 32], 0);
    let event = BridgeEvent::Deposit(DepositEvent {
        event_id,
        eth_tx_hash: [40; 32],
        log_index: 0,
        eth_block_number: 50,
        depositor: [40; 20],
        recipient: [140; 20],
        amount_wei: 10_000_000_000_000_000, // 0.01 ETH, below minimum
        amount_eth: 0.01,
        timestamp: 1000,
    });
    attest_event(&relay, &event);
    source.add_event(event);

    // Process — will fail due to deposit too small
    let results = relay.poll_cycle(&source).await.unwrap();
    assert_eq!(results[0].status, EventStatus::Failed);

    // Manually set retry_count to max_retries (5)
    {
        let mut state = relay.state().write();
        if let Some(te) = state.events.get_mut(&event_id) {
            te.retry_count = 5;
        }
    }

    // Retry should fail with RetryExhausted
    let result = relay.retry_event(&event_id, &source).await;
    assert!(matches!(result, Err(BridgeError::RetryExhausted { .. })));
}

// ============================================================
// 16. MockEventSource: set_head_block, default trait
// ============================================================

#[tokio::test]
async fn test_mock_event_source_default() {
    let source = MockEventSource::default();
    let block = source.current_block().await.unwrap();
    assert_eq!(block, 100, "Default MockEventSource head block should be 100");
}

#[tokio::test]
async fn test_mock_event_source_clears_after_fetch() {
    let source = MockEventSource::new();
    source.add_event(make_deposit_event(1, 1.0));

    // First fetch returns the event
    let events = source.fetch_events(0, 100).await.unwrap();
    assert_eq!(events.len(), 1);

    // Second fetch returns empty (events cleared)
    let events2 = source.fetch_events(0, 100).await.unwrap();
    assert!(events2.is_empty());
}

// ============================================================
// 17. Event serde roundtrips
// ============================================================

#[test]
fn test_deposit_event_serde_roundtrip() {
    let event = DepositEvent {
        event_id: [0xAA; 32],
        eth_tx_hash: [0xBB; 32],
        log_index: 42,
        eth_block_number: 999999,
        depositor: [0x11; 20],
        recipient: [0x22; 20],
        amount_wei: 5_000_000_000_000_000_000,
        amount_eth: 5.0,
        timestamp: 1234567890,
    };

    let json = serde_json::to_string(&event).unwrap();
    let restored: DepositEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(restored, event);
}

#[test]
fn test_withdrawal_event_serde_roundtrip() {
    let event = WithdrawalEvent {
        event_id: [0xCC; 32],
        citrate_tx_hash: [0xDD; 32],
        citrate_block_height: 500,
        sender: [0x33; 20],
        eth_recipient: [0x44; 20],
        salt_amount: 50000,
        eth_amount_wei: 5_000_000_000_000_000_000,
        timestamp: 9876543210,
    };

    let json = serde_json::to_string(&event).unwrap();
    let restored: WithdrawalEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(restored, event);
}

#[test]
fn test_oracle_update_event_serde_roundtrip() {
    let event = OracleUpdateEvent {
        event_id: [0xEE; 32],
        oracle_pubkey: [0xFF; 32],
        is_addition: true,
        timestamp: 555555,
    };

    let json = serde_json::to_string(&event).unwrap();
    let restored: OracleUpdateEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(restored, event);
}

#[test]
fn test_bridge_event_enum_serde_roundtrip() {
    let deposit = make_deposit_event(1, 1.0);
    let json = serde_json::to_string(&deposit).unwrap();
    let restored: BridgeEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(restored, deposit);

    let withdrawal = make_withdrawal_event(2, 5000);
    let json2 = serde_json::to_string(&withdrawal).unwrap();
    let restored2: BridgeEvent = serde_json::from_str(&json2).unwrap();
    assert_eq!(restored2, withdrawal);
}

// ============================================================
// 18. TrackedEvent: exercise all fields
// ============================================================

#[test]
fn test_tracked_event_all_statuses() {
    let statuses = [
        EventStatus::Pending,
        EventStatus::AwaitingAttestations,
        EventStatus::Attested,
        EventStatus::Processed,
        EventStatus::Rejected,
        EventStatus::Failed,
    ];

    for status in &statuses {
        let tracked = TrackedEvent {
            event: BridgeEvent::Deposit(DepositEvent {
                event_id: [0u8; 32],
                eth_tx_hash: [1u8; 32],
                log_index: 0,
                eth_block_number: 0,
                depositor: [0u8; 20],
                recipient: [0u8; 20],
                amount_wei: 0,
                amount_eth: 0.0,
                timestamp: 0,
            }),
            status: *status,
            attestation_count: 0,
            retry_count: 0,
            detected_at: 0,
            updated_at: 0,
            error: None,
        };
        // Verify serde works for all statuses
        let json = serde_json::to_string(&tracked).unwrap();
        let restored: TrackedEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.status, *status);
    }
}

#[test]
fn test_event_status_equality() {
    assert_eq!(EventStatus::Pending, EventStatus::Pending);
    assert_ne!(EventStatus::Pending, EventStatus::Processed);
    assert_ne!(EventStatus::Failed, EventStatus::Rejected);

    // Clone
    let s = EventStatus::Attested;
    let s2 = s;
    assert_eq!(s, s2);
}

// ============================================================
// 19. Relay accessors: state, oracle_registry, minter, metrics
// ============================================================

#[test]
fn test_relay_accessors() {
    let relay = setup_relay();

    // All accessors should return valid Arc references
    let _state = relay.state().read();
    let _oracle = relay.oracle_registry().read();
    let _minter = relay.minter().read();
    let _metrics = relay.metrics();

    // Verify minter through relay
    let preview = relay.minter().read().preview_conversion(1.0);
    assert_eq!(preview, 10_000);
}

// ============================================================
// 20. Relay: no new confirmed blocks yields empty results
// ============================================================

#[tokio::test]
async fn test_relay_no_new_blocks_yields_empty() {
    let config = BridgeConfig {
        confirmation_depth: 50,
        oracle_threshold: 1,
        ..Default::default()
    };
    let relay = BridgeRelay::new(config);
    let sk = default_oracle_key();
    relay
        .oracle_registry()
        .write()
        .register_oracle(sk.verifying_key().to_bytes(), "T".to_string())
        .unwrap();

    let source = MockEventSource::new();
    // Head block is 100, confirmation depth 50, safe = 50
    // First poll scans 1..50
    source.set_head_block(100);
    let r1 = relay.poll_cycle(&source).await.unwrap();
    assert!(r1.is_empty()); // No events added

    // Second poll: head still at 100, last_processed = 50, safe = 50
    // safe <= last_processed -> empty
    let r2 = relay.poll_cycle(&source).await.unwrap();
    assert!(r2.is_empty());
}

// ============================================================
// 21. compute_event_hash with different data lengths
// ============================================================

#[test]
fn test_compute_event_hash_different_data() {
    let event_id = [0x42; 32];
    let h1 = compute_event_hash(&event_id, b"");
    let h2 = compute_event_hash(&event_id, b"x");
    let h3 = compute_event_hash(&event_id, &[0u8; 1000]);

    assert_ne!(h1, h2);
    assert_ne!(h2, h3);
    assert_ne!(h1, h3);

    // All should be non-zero
    assert_ne!(h1, [0u8; 32]);
    assert_ne!(h2, [0u8; 32]);
    assert_ne!(h3, [0u8; 32]);
}

// ============================================================
// 22. Relay: deposit exceeds cap error path through relay
// ============================================================

#[tokio::test]
async fn test_relay_deposit_exceeds_cap() {
    let relay = setup_relay();
    let source = MockEventSource::new();

    let event_id = DepositEvent::compute_event_id(&[50; 32], 0);
    let event = BridgeEvent::Deposit(DepositEvent {
        event_id,
        eth_tx_hash: [50; 32],
        log_index: 0,
        eth_block_number: 50,
        depositor: [50; 20],
        recipient: [150; 20],
        amount_wei: 11_000_000_000_000_000_000, // 11 ETH > 10 ETH cap
        amount_eth: 11.0,
        timestamp: 1000,
    });
    attest_event(&relay, &event);
    source.add_event(event);

    let results = relay.poll_cycle(&source).await.unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status, EventStatus::Failed);
    assert!(results[0].error.as_ref().unwrap().contains("exceeds"));

    // Deposit failure should be recorded in metrics
    assert_eq!(
        relay.metrics().deposits_failed.load(Ordering::Relaxed),
        1
    );
}

// ============================================================
// 23. BondingCurveConfig serde roundtrip
// ============================================================

#[test]
fn test_bonding_curve_config_serde() {
    let curve = BondingCurveConfig {
        base_multiplier: 1.5,
        slope: 0.002,
        scale_factor: 500.0,
        max_multiplier: 5.0,
        salt_per_eth: 20_000,
    };
    let json = serde_json::to_string(&curve).unwrap();
    let restored: BondingCurveConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.base_multiplier, curve.base_multiplier);
    assert_eq!(restored.slope, curve.slope);
    assert_eq!(restored.scale_factor, curve.scale_factor);
    assert_eq!(restored.max_multiplier, curve.max_multiplier);
    assert_eq!(restored.salt_per_eth, curve.salt_per_eth);
}

// ============================================================
// 24. Relay: failed deposit records deposit_failure metric
// ============================================================

#[tokio::test]
async fn test_relay_failed_deposit_metric() {
    let relay = setup_relay();
    let source = MockEventSource::new();

    // Too-small deposit
    let event_id = DepositEvent::compute_event_id(&[60; 32], 0);
    let event = BridgeEvent::Deposit(DepositEvent {
        event_id,
        eth_tx_hash: [60; 32],
        log_index: 0,
        eth_block_number: 50,
        depositor: [60; 20],
        recipient: [160; 20],
        amount_wei: 1_000_000_000_000_000, // 0.001 ETH
        amount_eth: 0.001,
        timestamp: 1000,
    });
    attest_event(&relay, &event);
    source.add_event(event);

    relay.poll_cycle(&source).await.unwrap();

    assert_eq!(
        relay.metrics().deposits_failed.load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        relay.metrics().deposits_processed.load(Ordering::Relaxed),
        0
    );
}

// ============================================================
// 25. MintReceipt serde roundtrip
// ============================================================

#[test]
fn test_mint_receipt_serde_roundtrip() {
    let mut minter = SnapMinter::new(BondingCurveConfig::default());
    let deposit = DepositEvent {
        event_id: [0x01; 32],
        eth_tx_hash: [0x02; 32],
        log_index: 0,
        eth_block_number: 100,
        depositor: [0x03; 20],
        recipient: [0x04; 20],
        amount_wei: 1_000_000_000_000_000_000,
        amount_eth: 1.0,
        timestamp: 1000,
    };

    let receipt = minter.process_deposit(&deposit).unwrap();
    let json = serde_json::to_string(&receipt).unwrap();
    let restored: citrate_bridge::MintReceipt = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.event_id, receipt.event_id);
    assert_eq!(restored.recipient, receipt.recipient);
    assert_eq!(restored.salt_credited, receipt.salt_credited);
    assert_eq!(restored.deposit_wei, receipt.deposit_wei);
    assert_eq!(restored.receipt_hash, receipt.receipt_hash);
}

// ============================================================
// 26. Use BridgeEventSource trait through MockEventSource
// ============================================================

use citrate_bridge::relay::BridgeEventSource;

#[tokio::test]
async fn test_bridge_event_source_trait_via_mock() {
    let source = MockEventSource::new();
    source.set_head_block(500);

    let block = source.current_block().await.unwrap();
    assert_eq!(block, 500);

    source.add_event(make_deposit_event(1, 1.0));
    source.add_event(make_withdrawal_event(2, 5000));

    let events = source.fetch_events(0, 500).await.unwrap();
    assert_eq!(events.len(), 2);
}
