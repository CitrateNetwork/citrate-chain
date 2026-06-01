//! Bridge relay service.
//!
//! The relay is the core orchestrator for the Citrate-side bridge.
//! It polls for events from Ethereum (via an event source), collects
//! oracle attestations, and processes deposits/withdrawals.

use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;
use tracing::{debug, error, info, warn};

use crate::config::BridgeConfig;
use crate::errors::{BridgeError, BridgeResult};
use crate::events::{
    BridgeEvent, DepositEvent, EventStatus, TrackedEvent, WithdrawalEvent,
};
use crate::metrics::BridgeMetrics;
use crate::mint::SnapMinter;
use crate::oracle::OracleRegistry;
use crate::state::RelayState;

/// Trait for receiving bridge events from an external source.
///
/// Implementations may connect to Ethereum via RPC, read from a file,
/// or provide mock events for testing.
#[async_trait]
pub trait BridgeEventSource: Send + Sync {
    /// Fetch new events since the given block number.
    async fn fetch_events(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> BridgeResult<Vec<BridgeEvent>>;

    /// Get the current head block number of the source chain.
    async fn current_block(&self) -> BridgeResult<u64>;
}

/// Mock event source for testing.
pub struct MockEventSource {
    events: RwLock<Vec<BridgeEvent>>,
    head_block: RwLock<u64>,
}

impl MockEventSource {
    /// Create a new mock event source.
    pub fn new() -> Self {
        Self {
            events: RwLock::new(Vec::new()),
            head_block: RwLock::new(100),
        }
    }

    /// Add an event to the mock source.
    pub fn add_event(&self, event: BridgeEvent) {
        self.events.write().push(event);
    }

    /// Set the current head block.
    pub fn set_head_block(&self, block: u64) {
        *self.head_block.write() = block;
    }
}

impl Default for MockEventSource {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BridgeEventSource for MockEventSource {
    async fn fetch_events(
        &self,
        _from_block: u64,
        _to_block: u64,
    ) -> BridgeResult<Vec<BridgeEvent>> {
        let events = self.events.read().clone();
        // Clear after fetching (simulate one-time delivery)
        self.events.write().clear();
        Ok(events)
    }

    async fn current_block(&self) -> BridgeResult<u64> {
        Ok(*self.head_block.read())
    }
}

/// Bridge relay — the main orchestrator.
pub struct BridgeRelay {
    config: BridgeConfig,
    state: Arc<RwLock<RelayState>>,
    oracle_registry: Arc<RwLock<OracleRegistry>>,
    minter: Arc<RwLock<SnapMinter>>,
    metrics: Arc<BridgeMetrics>,
    paused: bool,
}

impl BridgeRelay {
    /// Create a new bridge relay.
    ///
    /// # Panics
    /// Panics if `oracle_threshold` is 0 in non-test builds.
    /// Zero-threshold mode allows auto-attesting events without any oracle
    /// verification, which is a critical security risk.
    pub fn new(config: BridgeConfig) -> Self {
        if config.oracle_threshold == 0 && !cfg!(test) {
            panic!(
                "oracle_threshold must be > 0 in production. \
                 Zero-threshold mode auto-attests events without oracle verification."
            );
        }
        let oracle_threshold = config.oracle_threshold;
        Self {
            minter: Arc::new(RwLock::new(SnapMinter::new(
                config.bonding_curve.clone(),
            ))),
            state: Arc::new(RwLock::new(RelayState::default())),
            oracle_registry: Arc::new(RwLock::new(OracleRegistry::new(oracle_threshold))),
            metrics: Arc::new(BridgeMetrics::new()),
            paused: false,
            config,
        }
    }

    /// Get a reference to the relay state.
    pub fn state(&self) -> &Arc<RwLock<RelayState>> {
        &self.state
    }

    /// Get a reference to the oracle registry.
    pub fn oracle_registry(&self) -> &Arc<RwLock<OracleRegistry>> {
        &self.oracle_registry
    }

    /// Get a reference to the minter.
    pub fn minter(&self) -> &Arc<RwLock<SnapMinter>> {
        &self.minter
    }

    /// Get a reference to the metrics.
    pub fn metrics(&self) -> &Arc<BridgeMetrics> {
        &self.metrics
    }

    /// Pause the relay (emergency stop).
    pub fn pause(&mut self, reason: &str) {
        warn!(reason = reason, "Bridge relay PAUSED");
        self.paused = true;
    }

    /// Resume the relay.
    pub fn resume(&mut self) {
        info!("Bridge relay RESUMED");
        self.paused = false;
    }

    /// Check if the relay is paused.
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// Process a single polling cycle: fetch events, validate, process.
    pub async fn poll_cycle(
        &self,
        source: &dyn BridgeEventSource,
    ) -> BridgeResult<Vec<ProcessingResult>> {
        if self.paused {
            return Err(BridgeError::BridgePaused {
                reason: "Relay is paused".to_string(),
            });
        }

        // Get current blocks
        let source_head = source.current_block().await?;
        let last_processed = self.state.read().last_eth_block;

        // Apply confirmation depth
        let safe_block = source_head.saturating_sub(self.config.confirmation_depth);
        if safe_block <= last_processed {
            debug!(
                source_head,
                safe_block, last_processed, "No new confirmed blocks"
            );
            return Ok(vec![]);
        }

        // Fetch events in the confirmed range
        let events = source.fetch_events(last_processed + 1, safe_block).await?;
        info!(
            event_count = events.len(),
            from = last_processed + 1,
            to = safe_block,
            "Fetched bridge events"
        );

        let mut results = Vec::new();

        for event in events {
            let result = self.process_event(event).await;
            results.push(result);
        }

        // Update state
        {
            let mut state = self.state.write();
            state.last_eth_block = safe_block;
            state.heartbeat();
        }

        // Update metrics
        self.metrics.set_last_eth_block(safe_block);
        self.metrics
            .set_relay_lag(source_head.saturating_sub(safe_block));
        self.metrics.heartbeat();

        Ok(results)
    }

    /// Process a single bridge event.
    async fn process_event(&self, event: BridgeEvent) -> ProcessingResult {
        let event_id = *event.event_id();

        // Deduplication check
        if self.state.read().is_known_event(&event_id) {
            debug!(event_id = hex::encode(event_id), "Duplicate event skipped");
            return ProcessingResult {
                event_id,
                status: EventStatus::Rejected,
                salt_amount: None,
                error: Some("Duplicate event".to_string()),
            };
        }

        // Track the event
        let now = chrono::Utc::now().timestamp() as u64;
        let tracked = TrackedEvent {
            event: event.clone(),
            status: EventStatus::Pending,
            attestation_count: 0,
            retry_count: 0,
            detected_at: now,
            updated_at: now,
            error: None,
        };
        self.state.write().track_event(tracked);

        // Check oracle attestations
        let oracle_met = self.oracle_registry.read().is_threshold_met(&event_id);
        if !oracle_met {
            // In testing / 0-threshold mode, auto-proceed
            if self.config.oracle_threshold == 0 {
                info!("Zero-threshold mode: auto-attesting event");
            } else {
                self.state.write().update_event_status(
                    &event_id,
                    EventStatus::AwaitingAttestations,
                    None,
                );
                return ProcessingResult {
                    event_id,
                    status: EventStatus::AwaitingAttestations,
                    salt_amount: None,
                    error: None,
                };
            }
        }

        // Process based on event type
        match event {
            BridgeEvent::Deposit(deposit) => self.process_deposit(deposit).await,
            BridgeEvent::Withdrawal(withdrawal) => {
                self.process_withdrawal(withdrawal).await
            }
            BridgeEvent::OracleUpdate(update) => {
                info!(
                    oracle = hex::encode(update.oracle_pubkey),
                    is_addition = update.is_addition,
                    "Oracle update processed"
                );
                self.state.write().update_event_status(
                    &event_id,
                    EventStatus::Processed,
                    None,
                );
                ProcessingResult {
                    event_id,
                    status: EventStatus::Processed,
                    salt_amount: None,
                    error: None,
                }
            }
        }
    }

    /// Process a deposit event.
    async fn process_deposit(&self, deposit: DepositEvent) -> ProcessingResult {
        let event_id = deposit.event_id;

        // RM-A WP-CHAIN-001 (CRITICAL): bind the threshold attestation to the
        // deposit's mint-critical fields. Oracles sign
        // `event_hash = deposit.canonical_hash()`; an attacker presenting a
        // different amount/recipient/depositor (or source coordinate) under the
        // same `event_id` produces a different canonical hash and is rejected
        // here, before any mint. Zero-threshold mode (test/dev only) has no
        // attestations to bind against and is unaffected; production runs with
        // `oracle_threshold >= 1`. Attestation-hash consistency across oracles
        // is already enforced in `submit_attestation`/`is_threshold_met`.
        if self.config.oracle_threshold > 0 {
            let expected = deposit.canonical_hash();
            let attested = self
                .oracle_registry
                .read()
                .get_attestations(&event_id)
                .and_then(|atts| atts.first().map(|a| a.event_hash));
            if !matches!(attested, Some(h) if h == expected) {
                let err = BridgeError::AttestationFieldMismatch {
                    event_id: hex::encode(event_id),
                };
                warn!(
                    event_id = hex::encode(event_id),
                    "Deposit rejected: attestation does not bind deposit fields"
                );
                self.state.write().update_event_status(
                    &event_id,
                    EventStatus::Rejected,
                    Some(err.to_string()),
                );
                self.metrics.record_deposit_failure();
                return ProcessingResult {
                    event_id,
                    status: EventStatus::Rejected,
                    salt_amount: None,
                    error: Some(err.to_string()),
                };
            }
        }

        match self.minter.write().process_deposit(&deposit) {
            Ok(receipt) => {
                let salt = receipt.salt_credited;
                info!(
                    event_id = hex::encode(event_id),
                    salt = salt,
                    depositor = hex::encode(deposit.depositor),
                    "Deposit processed successfully"
                );

                // Update state
                {
                    let mut state = self.state.write();
                    state.update_event_status(&event_id, EventStatus::Processed, None);
                    state.record_deposit(salt);
                }

                // Update metrics
                self.metrics.record_deposit(salt);

                ProcessingResult {
                    event_id,
                    status: EventStatus::Processed,
                    salt_amount: Some(salt),
                    error: None,
                }
            }
            Err(e) => {
                error!(
                    event_id = hex::encode(event_id),
                    error = %e,
                    "Deposit processing failed"
                );
                self.state.write().update_event_status(
                    &event_id,
                    EventStatus::Failed,
                    Some(e.to_string()),
                );
                self.metrics.record_deposit_failure();

                ProcessingResult {
                    event_id,
                    status: EventStatus::Failed,
                    salt_amount: None,
                    error: Some(e.to_string()),
                }
            }
        }
    }

    /// Process a withdrawal event.
    async fn process_withdrawal(&self, withdrawal: WithdrawalEvent) -> ProcessingResult {
        let event_id = withdrawal.event_id;
        info!(
            event_id = hex::encode(event_id),
            salt = withdrawal.salt_amount,
            recipient = hex::encode(withdrawal.eth_recipient),
            "Withdrawal processed — Ethereum tx prepared"
        );

        // Update state
        {
            let mut state = self.state.write();
            state.update_event_status(&event_id, EventStatus::Processed, None);
            state.record_withdrawal(withdrawal.salt_amount);
        }

        // Update metrics
        self.metrics.record_withdrawal(withdrawal.salt_amount);

        ProcessingResult {
            event_id,
            status: EventStatus::Processed,
            salt_amount: Some(withdrawal.salt_amount),
            error: None,
        }
    }

    /// Retry a failed event.
    pub async fn retry_event(
        &self,
        event_id: &[u8; 32],
        source: &dyn BridgeEventSource,
    ) -> BridgeResult<ProcessingResult> {
        let tracked = self
            .state
            .read()
            .events
            .get(event_id)
            .cloned()
            .ok_or_else(|| BridgeError::EventNotFound {
                event_id: hex::encode(event_id),
            })?;

        if tracked.status != EventStatus::Failed {
            return Err(BridgeError::InvalidEventData {
                reason: format!(
                    "Cannot retry event in {:?} status",
                    tracked.status
                ),
            });
        }

        if tracked.retry_count >= self.config.max_retries {
            return Err(BridgeError::RetryExhausted {
                attempts: tracked.retry_count,
                reason: tracked.error.unwrap_or_default(),
            });
        }

        // Increment retry count
        if let Some(t) = self.state.write().events.get_mut(event_id) {
            t.retry_count += 1;
            t.status = EventStatus::Pending;
        }

        let _source_head = source.current_block().await?;
        Ok(self.process_event(tracked.event).await)
    }
}

/// Result of processing a single bridge event.
#[derive(Debug, Clone)]
pub struct ProcessingResult {
    /// Event ID that was processed.
    pub event_id: [u8; 32],

    /// Final status after processing.
    pub status: EventStatus,

    /// SALT amount credited/burned (if applicable).
    pub salt_amount: Option<u64>,

    /// Error message (if failed).
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BridgeConfig;
    use crate::events::DepositEvent;
    use crate::oracle::{compute_event_hash, OracleAttestation};

    fn test_config() -> BridgeConfig {
        BridgeConfig {
            confirmation_depth: 0, // No confirmation needed in tests
            oracle_threshold: 0,   // No oracle needed in tests
            ..Default::default()
        }
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
            eth_amount_wei: (salt_amount as u128) * 100_000_000_000_000, // simplified
            timestamp: 2000,
        })
    }

    #[tokio::test]
    async fn test_deposit_flow_e2e() {
        let relay = BridgeRelay::new(test_config());
        let source = MockEventSource::new();
        source.add_event(make_deposit_event(1, 1.0));

        let results = relay.poll_cycle(&source).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, EventStatus::Processed);
        assert_eq!(results[0].salt_amount, Some(10_000));

        // Verify state updated
        let state = relay.state().read();
        assert_eq!(state.total_deposits, 1);
        assert_eq!(state.total_salt_credited, 10_000);
    }

    #[tokio::test]
    async fn test_deduplication_prevents_double_deposit() {
        let relay = BridgeRelay::new(test_config());
        let source = MockEventSource::new();

        let event = make_deposit_event(1, 1.0);
        source.add_event(event.clone());

        // First poll processes the event
        let r1 = relay.poll_cycle(&source).await.unwrap();
        assert_eq!(r1.len(), 1);
        assert_eq!(r1[0].status, EventStatus::Processed);

        // Add same event again and advance head so there are new blocks to scan
        source.add_event(event);
        source.set_head_block(200);

        // Second poll rejects as duplicate
        let r2 = relay.poll_cycle(&source).await.unwrap();
        assert_eq!(r2.len(), 1);
        assert_eq!(r2[0].status, EventStatus::Rejected);

        // Only 1 deposit recorded
        assert_eq!(relay.state().read().total_deposits, 1);
    }

    #[tokio::test]
    async fn test_withdrawal_flow() {
        let relay = BridgeRelay::new(test_config());
        let source = MockEventSource::new();
        source.add_event(make_withdrawal_event(1, 5_000));

        let results = relay.poll_cycle(&source).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, EventStatus::Processed);
        assert_eq!(results[0].salt_amount, Some(5_000));

        let state = relay.state().read();
        assert_eq!(state.total_withdrawals, 1);
        assert_eq!(state.total_salt_burned, 5_000);
    }

    #[tokio::test]
    async fn test_insufficient_deposit_rejected() {
        let relay = BridgeRelay::new(test_config());
        let source = MockEventSource::new();

        // 0.01 ETH < 0.02 ETH minimum
        let event_id = DepositEvent::compute_event_id(&[1; 32], 0);
        source.add_event(BridgeEvent::Deposit(DepositEvent {
            event_id,
            eth_tx_hash: [1; 32],
            log_index: 0,
            eth_block_number: 50,
            depositor: [1; 20],
            recipient: [2; 20],
            amount_wei: 10_000_000_000_000_000, // 0.01 ETH
            amount_eth: 0.01,
            timestamp: 1000,
        }));

        let results = relay.poll_cycle(&source).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, EventStatus::Failed);
        assert!(results[0].error.as_ref().unwrap().contains("too small"));
    }

    #[tokio::test]
    async fn test_oracle_attestation_requirement() {
        use ed25519_dalek::{Signer, SigningKey};
        use std::time::{SystemTime, UNIX_EPOCH};

        // Helper: deterministic signing key from seed byte
        fn test_signing_key(id: u8) -> SigningKey {
            let mut seed = [0u8; 32];
            seed[0] = id;
            SigningKey::from_bytes(&seed)
        }

        let config = BridgeConfig {
            confirmation_depth: 0,
            oracle_threshold: 2, // Require 2 attestations
            ..Default::default()
        };
        let relay = BridgeRelay::new(config);
        let source = MockEventSource::new();

        // Register 2 oracles with real ed25519 public keys
        let sk1 = test_signing_key(1);
        let sk2 = test_signing_key(2);
        let oracle_id_1 = sk1.verifying_key().to_bytes();
        let oracle_id_2 = sk2.verifying_key().to_bytes();
        {
            let mut reg = relay.oracle_registry().write();
            reg.register_oracle(oracle_id_1, "Oracle-1".to_string())
                .unwrap();
            reg.register_oracle(oracle_id_2, "Oracle-2".to_string())
                .unwrap();
        }

        let event = make_deposit_event(1, 1.0);
        let event_id = *event.event_id();
        source.add_event(event);

        // Poll without attestations — should be awaiting
        let results = relay.poll_cycle(&source).await.unwrap();
        assert_eq!(results[0].status, EventStatus::AwaitingAttestations);

        // Submit properly signed attestations
        {
            let mut reg = relay.oracle_registry().write();
            let event_hash = compute_event_hash(&event_id, b"deposit");
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // Sign attestation 1
            let mut msg1 = Vec::with_capacity(89);
            msg1.extend_from_slice(b"citrate-bridge-v1");
            msg1.extend_from_slice(&event_id);
            msg1.extend_from_slice(&event_hash);
            msg1.extend_from_slice(&now.to_le_bytes());
            let sig1 = sk1.sign(&msg1);

            reg.submit_attestation(OracleAttestation {
                oracle_id: oracle_id_1,
                event_id,
                event_hash,
                signature: sig1.to_bytes().to_vec(),
                timestamp: now,
            })
            .unwrap();

            // Sign attestation 2
            let now2 = now + 1;
            let mut msg2 = Vec::with_capacity(89);
            msg2.extend_from_slice(b"citrate-bridge-v1");
            msg2.extend_from_slice(&event_id);
            msg2.extend_from_slice(&event_hash);
            msg2.extend_from_slice(&now2.to_le_bytes());
            let sig2 = sk2.sign(&msg2);

            reg.submit_attestation(OracleAttestation {
                oracle_id: oracle_id_2,
                event_id,
                event_hash,
                signature: sig2.to_bytes().to_vec(),
                timestamp: now2,
            })
            .unwrap();
        }

        // Verify threshold is now met
        assert!(relay.oracle_registry().read().is_threshold_met(&event_id));
    }

    // ── RM-A WP-CHAIN-001 tripwires (red on the unfixed relay) ──
    fn rm_a_register_oracles(
        relay: &BridgeRelay,
        sk1: &ed25519_dalek::SigningKey,
        sk2: &ed25519_dalek::SigningKey,
    ) -> ([u8; 32], [u8; 32]) {
        let o1 = sk1.verifying_key().to_bytes();
        let o2 = sk2.verifying_key().to_bytes();
        let mut reg = relay.oracle_registry().write();
        reg.register_oracle(o1, "O1".to_string()).expect("register o1");
        reg.register_oracle(o2, "O2".to_string()).expect("register o2");
        (o1, o2)
    }

    fn rm_a_attest_hash(
        relay: &BridgeRelay,
        event_id: &[u8; 32],
        bound_hash: [u8; 32],
        keys: &[(&ed25519_dalek::SigningKey, [u8; 32])],
    ) {
        use ed25519_dalek::Signer;
        use std::time::{SystemTime, UNIX_EPOCH};
        let base = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_secs();
        for (i, (sk, oid)) in keys.iter().enumerate() {
            let ts = base + i as u64;
            let mut msg = Vec::with_capacity(89);
            msg.extend_from_slice(b"citrate-bridge-v1");
            msg.extend_from_slice(event_id);
            msg.extend_from_slice(&bound_hash);
            msg.extend_from_slice(&ts.to_le_bytes());
            let sig = sk.sign(&msg);
            relay
                .oracle_registry()
                .write()
                .submit_attestation(OracleAttestation {
                    oracle_id: *oid,
                    event_id: *event_id,
                    event_hash: bound_hash,
                    signature: sig.to_bytes().to_vec(),
                    timestamp: ts,
                })
                .expect("submit attestation");
        }
    }

    #[tokio::test]
    async fn tripwire_deposit_rejected_when_attestation_unbound_to_fields() {
        use ed25519_dalek::SigningKey;
        let config = BridgeConfig {
            confirmation_depth: 0,
            oracle_threshold: 2,
            ..Default::default()
        };
        let relay = BridgeRelay::new(config);
        let sk1 = SigningKey::from_bytes(&[11u8; 32]);
        let sk2 = SigningKey::from_bytes(&[12u8; 32]);
        let (o1, o2) = rm_a_register_oracles(&relay, &sk1, &sk2);

        let eth_tx = [7u8; 32];
        let event_id = DepositEvent::compute_event_id(&eth_tx, 0);
        let honest = DepositEvent {
            event_id,
            eth_tx_hash: eth_tx,
            log_index: 0,
            eth_block_number: 50,
            depositor: [7u8; 20],
            recipient: [70u8; 20],
            amount_wei: 1_000_000_000_000_000_000,
            amount_eth: 1.0,
            timestamp: 1000,
        };
        // Oracles attest to the HONEST deposit's canonical hash.
        rm_a_attest_hash(&relay, &event_id, honest.canonical_hash(), &[(&sk1, o1), (&sk2, o2)]);
        assert!(relay.oracle_registry().read().is_threshold_met(&event_id));

        // Attacker presents a TAMPERED deposit under the same event_id.
        let tampered = DepositEvent {
            recipient: [0xAAu8; 20],
            amount_wei: 5_000_000_000_000_000_000,
            amount_eth: 5.0,
            ..honest.clone()
        };
        let rejected = relay.process_event(BridgeEvent::Deposit(tampered)).await;
        assert_eq!(
            rejected.status,
            EventStatus::Rejected,
            "tampered deposit must be rejected, not minted"
        );
        assert!(
            rejected.salt_amount.is_none(),
            "no SALT may be minted for an unbound deposit"
        );
        assert!(
            rejected
                .error
                .as_deref()
                .unwrap_or_default()
                .to_lowercase()
                .contains("bind"),
            "rejection must cite the attestation-binding failure"
        );
    }

    #[tokio::test]
    async fn tripwire_deposit_accepted_when_attestation_binds_fields() {
        use ed25519_dalek::SigningKey;
        let config = BridgeConfig {
            confirmation_depth: 0,
            oracle_threshold: 2,
            ..Default::default()
        };
        let relay = BridgeRelay::new(config);
        let sk1 = SigningKey::from_bytes(&[21u8; 32]);
        let sk2 = SigningKey::from_bytes(&[22u8; 32]);
        let (o1, o2) = rm_a_register_oracles(&relay, &sk1, &sk2);

        let eth_tx = [9u8; 32];
        let event_id = DepositEvent::compute_event_id(&eth_tx, 0);
        let honest = DepositEvent {
            event_id,
            eth_tx_hash: eth_tx,
            log_index: 0,
            eth_block_number: 50,
            depositor: [9u8; 20],
            recipient: [90u8; 20],
            amount_wei: 1_000_000_000_000_000_000,
            amount_eth: 1.0,
            timestamp: 1000,
        };
        rm_a_attest_hash(&relay, &event_id, honest.canonical_hash(), &[(&sk1, o1), (&sk2, o2)]);

        let ok = relay.process_event(BridgeEvent::Deposit(honest)).await;
        assert_eq!(
            ok.status,
            EventStatus::Processed,
            "a deposit whose fields the attestation binds must mint"
        );
        assert!(ok.salt_amount.is_some(), "bound deposit must credit SALT");
    }

    #[tokio::test]
    async fn test_chain_reorg_confirmation_depth() {
        let config = BridgeConfig {
            confirmation_depth: 12,
            oracle_threshold: 0,
            ..Default::default()
        };
        let relay = BridgeRelay::new(config);
        let source = MockEventSource::new();

        // Source is at block 100, confirmation depth = 12, safe = 88
        // Last processed = 0, so we scan 1..88
        source.set_head_block(100);
        source.add_event(make_deposit_event(1, 1.0));

        let results = relay.poll_cycle(&source).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(relay.state().read().last_eth_block, 88);

        // Source still at 100 — no new blocks
        let results2 = relay.poll_cycle(&source).await.unwrap();
        assert_eq!(results2.len(), 0);
    }

    #[tokio::test]
    async fn test_bridge_pause_and_resume() {
        let mut relay = BridgeRelay::new(test_config());
        let source = MockEventSource::new();
        source.add_event(make_deposit_event(1, 1.0));

        // Pause the relay
        relay.pause("maintenance");
        assert!(relay.is_paused());

        // Poll while paused → error
        let err = relay.poll_cycle(&source).await.unwrap_err();
        assert!(matches!(err, BridgeError::BridgePaused { .. }));

        // Resume
        relay.resume();
        assert!(!relay.is_paused());

        // Now poll works
        let results = relay.poll_cycle(&source).await.unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn test_metrics_updated_on_deposit() {
        let relay = BridgeRelay::new(test_config());
        let source = MockEventSource::new();
        source.add_event(make_deposit_event(1, 1.0));

        relay.poll_cycle(&source).await.unwrap();

        let metrics = relay.metrics();
        assert_eq!(
            metrics
                .deposits_processed
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics
                .total_salt_credited
                .load(std::sync::atomic::Ordering::Relaxed),
            10_000
        );
    }

    #[tokio::test]
    async fn test_multiple_deposits_in_one_cycle() {
        let relay = BridgeRelay::new(test_config());
        let source = MockEventSource::new();
        source.add_event(make_deposit_event(1, 1.0));
        source.add_event(make_deposit_event(2, 2.0));
        source.add_event(make_deposit_event(3, 0.5));

        let results = relay.poll_cycle(&source).await.unwrap();
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.status == EventStatus::Processed));

        let state = relay.state().read();
        assert_eq!(state.total_deposits, 3);
    }

    #[tokio::test]
    async fn test_relay_state_persistence() {
        let relay = BridgeRelay::new(test_config());
        let source = MockEventSource::new();
        source.add_event(make_deposit_event(1, 1.0));

        relay.poll_cycle(&source).await.unwrap();

        // Serialize and deserialize state
        let json = relay.state().read().to_json().unwrap();
        let restored = RelayState::from_json(&json).unwrap();
        assert_eq!(restored.total_deposits, 1);
        assert_eq!(restored.total_salt_credited, 10_000);
    }
}
