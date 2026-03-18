// Sprint PP: Bridge end-to-end tests
// Tests relay processing, deduplication, state persistence,
// attestation threshold enforcement, event hashing, withdrawal flow,
// config validation, mint receipts, NFT metadata, and bonding curve pricing.

use citrate_bridge::config::{BondingCurveConfig, BridgeConfig};
use citrate_bridge::events::{
    BridgeEvent, DepositEvent, EventStatus, WithdrawalEvent,
};
use citrate_bridge::mint::{SnapMinter, SnapNftMetadata};
use citrate_bridge::oracle::{compute_event_hash, OracleAttestation};
use citrate_bridge::relay::{BridgeRelay, MockEventSource};
use citrate_bridge::state::RelayState;

use ed25519_dalek::{Signer, SigningKey};

// ============================================================
// Helpers
// ============================================================

/// Integration tests run as a separate binary, so `cfg!(test)` is false
/// inside the bridge crate. oracle_threshold must be >= 1.
/// We use threshold=1 and pre-attest events with a single oracle.
fn test_config() -> BridgeConfig {
    BridgeConfig {
        confirmation_depth: 0,
        oracle_threshold: 1,
        ..Default::default()
    }
}

/// Create a deterministic signing key from a seed byte.
fn test_signing_key(seed: u8) -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    bytes[1] = seed.wrapping_mul(37);
    bytes[2] = seed.wrapping_mul(73);
    SigningKey::from_bytes(&bytes)
}

/// The default oracle key used for threshold=1 tests.
fn default_oracle_key() -> SigningKey {
    test_signing_key(42)
}

/// Set up a relay with threshold=1 and one registered oracle.
fn setup_relay() -> BridgeRelay {
    let relay = BridgeRelay::new(test_config());
    let sk = default_oracle_key();
    {
        let mut reg = relay.oracle_registry().write();
        reg.register_oracle(sk.verifying_key().to_bytes(), "TestOracle".to_string())
            .unwrap();
    }
    relay
}

/// Attest to an event with the default oracle so it passes threshold.
fn attest_event(relay: &BridgeRelay, event_id: &[u8; 32]) {
    let sk = default_oracle_key();
    let event_hash = compute_event_hash(event_id, b"deposit");
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut message = Vec::with_capacity(89);
    message.extend_from_slice(b"citrate-bridge-v1");
    message.extend_from_slice(event_id);
    message.extend_from_slice(&event_hash);
    message.extend_from_slice(&timestamp.to_le_bytes());
    let sig = sk.sign(&message);

    let att = OracleAttestation {
        oracle_id: sk.verifying_key().to_bytes(),
        event_id: *event_id,
        event_hash,
        signature: sig.to_bytes().to_vec(),
        timestamp,
    };
    relay.oracle_registry().write().submit_attestation(att).unwrap();
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

/// Create a signed attestation from a given signing key.
fn create_signed_attestation(
    signing_key: &SigningKey,
    event_id: [u8; 32],
    event_hash: [u8; 32],
) -> OracleAttestation {
    let oracle_id: [u8; 32] = signing_key.verifying_key().to_bytes();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_secs();

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
// 1. Relay processes deposit event
// ============================================================

#[tokio::test]
async fn test_relay_processes_deposit_event() {
    let relay = setup_relay();
    let source = MockEventSource::new();
    let event = make_deposit_event(1, 1.0);
    let event_id = *event.event_id();

    // Pre-attest so threshold is met
    attest_event(&relay, &event_id);
    source.add_event(event);

    let results = relay.poll_cycle(&source).await.unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status, EventStatus::Processed);
    assert!(results[0].salt_amount.is_some());
    assert!(results[0].error.is_none());

    let state = relay.state().read();
    assert_eq!(state.total_deposits, 1);
    assert!(state.total_salt_credited > 0);
}

// ============================================================
// 2. Double-process prevention
// ============================================================

#[tokio::test]
async fn test_relay_double_process_prevention() {
    let relay = setup_relay();
    let source = MockEventSource::new();

    let event = make_deposit_event(2, 1.0);
    let event_id = *event.event_id();

    attest_event(&relay, &event_id);
    source.add_event(event.clone());

    // First poll: event is processed
    let r1 = relay.poll_cycle(&source).await.unwrap();
    assert_eq!(r1.len(), 1);
    assert_eq!(r1[0].status, EventStatus::Processed);

    // Re-add same event and advance head block
    source.add_event(event);
    source.set_head_block(200);

    // Second poll: event is rejected as duplicate
    let r2 = relay.poll_cycle(&source).await.unwrap();
    assert_eq!(r2.len(), 1);
    assert_eq!(r2[0].status, EventStatus::Rejected);
    assert!(r2[0].error.as_ref().unwrap().contains("Duplicate"));

    let state = relay.state().read();
    assert_eq!(state.total_deposits, 1);
}

// ============================================================
// 3. State persistence (serialize/deserialize roundtrip)
// ============================================================

#[tokio::test]
async fn test_relay_state_persistence() {
    let relay = setup_relay();
    let source = MockEventSource::new();
    let event = make_deposit_event(3, 2.0);
    let event_id = *event.event_id();
    attest_event(&relay, &event_id);
    source.add_event(event);

    relay.poll_cycle(&source).await.unwrap();

    // Serialize state to JSON
    let json = relay.state().read().to_json().unwrap();

    // Deserialize into a new RelayState
    let restored = RelayState::from_json(&json).unwrap();

    assert_eq!(restored.total_deposits, 1);
    assert!(restored.total_salt_credited > 0);

    // The processed event should still be marked as known
    let original_state = relay.state().read();
    for eid in original_state.events.keys() {
        assert!(
            restored.is_known_event(eid),
            "Restored state must recognize previously processed event"
        );
        assert!(
            restored.is_processed(eid),
            "Restored state must show event as Processed"
        );
    }
}

// ============================================================
// 4. Insufficient attestations (threshold not met)
// ============================================================

#[tokio::test]
async fn test_relay_with_insufficient_attestations() {
    let config = BridgeConfig {
        confirmation_depth: 0,
        oracle_threshold: 3, // Require 3 attestations
        ..Default::default()
    };
    let relay = BridgeRelay::new(config);
    let source = MockEventSource::new();

    // Register only 2 oracles
    let sk1 = test_signing_key(1);
    let sk2 = test_signing_key(2);
    {
        let mut reg = relay.oracle_registry().write();
        reg.register_oracle(sk1.verifying_key().to_bytes(), "Oracle-1".to_string())
            .unwrap();
        reg.register_oracle(sk2.verifying_key().to_bytes(), "Oracle-2".to_string())
            .unwrap();
    }

    let event = make_deposit_event(4, 1.0);
    let event_id = *event.event_id();
    source.add_event(event);

    // Submit only 2 attestations (threshold is 3)
    let event_hash = compute_event_hash(&event_id, b"deposit");
    {
        let mut reg = relay.oracle_registry().write();
        reg.submit_attestation(create_signed_attestation(&sk1, event_id, event_hash))
            .unwrap();
        reg.submit_attestation(create_signed_attestation(&sk2, event_id, event_hash))
            .unwrap();
    }

    // Poll: event lacks attestations -> AwaitingAttestations
    let results = relay.poll_cycle(&source).await.unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status, EventStatus::AwaitingAttestations);

    // Verify threshold is NOT met with only 2 of 3
    assert!(
        !relay.oracle_registry().read().is_threshold_met(&event_id),
        "2 of 3 attestations should NOT meet threshold"
    );

    let state = relay.state().read();
    assert_eq!(state.total_deposits, 0);
}

// ============================================================
// 5. Deposit event hash is deterministic
// ============================================================

#[test]
fn test_deposit_event_hash_deterministic() {
    let tx_hash = [0xAB; 32];
    let log_index = 42u32;

    let id1 = DepositEvent::compute_event_id(&tx_hash, log_index);
    let id2 = DepositEvent::compute_event_id(&tx_hash, log_index);

    assert_eq!(id1, id2, "Same inputs must produce identical event IDs");
    assert_ne!(id1, [0u8; 32], "Event ID must not be all zeros");
}

// ============================================================
// 6. Withdrawal event creation and field verification
// ============================================================

#[tokio::test]
async fn test_withdrawal_event_creation() {
    let relay = setup_relay();
    let source = MockEventSource::new();

    let salt_amount = 7_500u64;
    let event = make_withdrawal_event(5, salt_amount);
    let event_id = *event.event_id();

    // Verify the event fields before processing
    if let BridgeEvent::Withdrawal(ref w) = event {
        assert_eq!(w.salt_amount, salt_amount);
        assert_eq!(w.sender, [5u8; 20]);
        assert_eq!(w.eth_recipient, [105u8; 20]);
        assert_eq!(w.citrate_block_height, 200);
        assert_eq!(w.timestamp, 2000);
        assert_ne!(w.event_id, [0u8; 32]);
    } else {
        panic!("Expected Withdrawal event");
    }

    // Attest for the withdrawal event too
    attest_event(&relay, &event_id);
    source.add_event(event);

    let results = relay.poll_cycle(&source).await.unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status, EventStatus::Processed);
    assert_eq!(results[0].salt_amount, Some(salt_amount));

    let state = relay.state().read();
    assert_eq!(state.total_withdrawals, 1);
    assert_eq!(state.total_salt_burned, salt_amount);
}

// ============================================================
// 7. Config with zero threshold panics outside cfg(test)
// ============================================================

#[test]
#[should_panic(expected = "oracle_threshold must be > 0")]
fn test_relay_config_validation() {
    // In integration tests, cfg!(test) is false for the bridge crate,
    // so zero threshold should panic.
    let _relay = BridgeRelay::new(BridgeConfig {
        confirmation_depth: 0,
        oracle_threshold: 0,
        ..Default::default()
    });
}

// ============================================================
// 8. MintReceipt fields are fully populated
// ============================================================

#[test]
fn test_mint_receipt_fields() {
    let mut minter = SnapMinter::new(BondingCurveConfig::default());
    let deposit = DepositEvent {
        event_id: [0xAA; 32],
        eth_tx_hash: [0xBB; 32],
        log_index: 0,
        eth_block_number: 100,
        depositor: [0x11; 20],
        recipient: [0x22; 20],
        amount_wei: 1_000_000_000_000_000_000,
        amount_eth: 1.0,
        timestamp: 1234567890,
    };

    let receipt = minter.process_deposit(&deposit).unwrap();

    assert_eq!(receipt.event_id, [0xAA; 32]);
    assert_eq!(receipt.recipient, [0x22; 20]);
    assert_eq!(receipt.deposit_wei, 1_000_000_000_000_000_000);
    assert!(receipt.salt_credited > 0, "SALT credited must be > 0");
    assert!(receipt.curve_multiplier > 0.0, "Curve multiplier must be > 0");
    assert_ne!(receipt.receipt_hash, [0u8; 32], "Receipt hash must not be zero");
    assert_eq!(receipt.timestamp, 1234567890);

    // NFT metadata fields
    assert!(!receipt.nft_metadata.name.is_empty());
    assert!(!receipt.nft_metadata.description.is_empty());
    assert!(receipt.nft_metadata.depositor.starts_with("0x"));
    assert!(receipt.nft_metadata.recipient.starts_with("0x"));
    assert!(receipt.nft_metadata.eth_tx_hash.starts_with("0x"));
    assert_eq!(receipt.nft_metadata.bridge_version, "1.0.0");
}

// ============================================================
// 9. SnapNftMetadata serialization roundtrip
// ============================================================

#[test]
fn test_snap_nft_metadata_serialization() {
    let metadata = SnapNftMetadata {
        name: "SNAP #42".to_string(),
        description: "Test deposit".to_string(),
        depositor: "0xaaaa".to_string(),
        recipient: "0xbbbb".to_string(),
        eth_amount: 2.5,
        salt_amount: 25_000,
        multiplier: 1.05,
        deposit_timestamp: 9999999,
        eth_tx_hash: "0xcccc".to_string(),
        bridge_version: "1.0.0".to_string(),
    };

    let json = serde_json::to_string(&metadata).expect("Serialization must succeed");
    let restored: SnapNftMetadata =
        serde_json::from_str(&json).expect("Deserialization must succeed");

    assert_eq!(restored.name, metadata.name);
    assert_eq!(restored.description, metadata.description);
    assert_eq!(restored.depositor, metadata.depositor);
    assert_eq!(restored.recipient, metadata.recipient);
    assert_eq!(restored.eth_amount, metadata.eth_amount);
    assert_eq!(restored.salt_amount, metadata.salt_amount);
    assert_eq!(restored.multiplier, metadata.multiplier);
    assert_eq!(restored.deposit_timestamp, metadata.deposit_timestamp);
    assert_eq!(restored.eth_tx_hash, metadata.eth_tx_hash);
    assert_eq!(restored.bridge_version, metadata.bridge_version);
}

// ============================================================
// 10. Bonding curve: first mint at base price (1.0x multiplier)
// ============================================================

#[test]
fn test_bonding_curve_first_mint_at_base_price() {
    let curve = BondingCurveConfig::default();
    let mut minter = SnapMinter::new(curve.clone());

    assert_eq!(
        minter.current_multiplier(),
        curve.base_multiplier,
        "First-mint multiplier must equal base_multiplier"
    );

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
    assert_eq!(
        receipt.salt_credited, curve.salt_per_eth,
        "First 1 ETH deposit must yield exactly salt_per_eth ({}) SALT",
        curve.salt_per_eth
    );
    assert_eq!(
        receipt.curve_multiplier, 1.0,
        "First-mint curve multiplier must be 1.0"
    );
}
