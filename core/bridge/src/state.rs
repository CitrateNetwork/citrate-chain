//! Bridge relay state persistence.
//!
//! Tracks the relay's progress: last processed Ethereum block,
//! event processing log, and relay health status.

use std::collections::HashMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::events::{EventId, EventStatus, TrackedEvent};

/// Serialize HashMap<[u8;32], V> with hex-encoded keys for JSON compatibility.
fn serialize_event_map<S>(
    map: &HashMap<EventId, TrackedEvent>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    use serde::ser::SerializeMap;
    let mut ser_map = serializer.serialize_map(Some(map.len()))?;
    for (k, v) in map {
        ser_map.serialize_entry(&hex::encode(k), v)?;
    }
    ser_map.end()
}

/// Deserialize HashMap<[u8;32], V> from hex-encoded keys.
fn deserialize_event_map<'de, D>(
    deserializer: D,
) -> Result<HashMap<EventId, TrackedEvent>, D::Error>
where
    D: Deserializer<'de>,
{
    let str_map: HashMap<String, TrackedEvent> = HashMap::deserialize(deserializer)?;
    let mut result = HashMap::new();
    for (k, v) in str_map {
        let bytes = hex::decode(&k).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("event ID must be 32 bytes"));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        result.insert(id, v);
    }
    Ok(result)
}

/// Persisted relay state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayState {
    /// Last Ethereum block number that was fully scanned.
    pub last_eth_block: u64,

    /// Last Citrate block height that was fully scanned.
    pub last_citrate_height: u64,

    /// Map of event ID → tracked event for deduplication and status tracking.
    #[serde(serialize_with = "serialize_event_map", deserialize_with = "deserialize_event_map")]
    pub events: HashMap<EventId, TrackedEvent>,

    /// Total deposits processed since relay start.
    pub total_deposits: u64,

    /// Total withdrawals processed since relay start.
    pub total_withdrawals: u64,

    /// Total SALT credited via bridge.
    pub total_salt_credited: u64,

    /// Total SALT burned via bridge withdrawals.
    pub total_salt_burned: u64,

    /// Relay start timestamp.
    pub started_at: u64,

    /// Last heartbeat timestamp.
    pub last_heartbeat: u64,
}

impl Default for RelayState {
    fn default() -> Self {
        let now = chrono::Utc::now().timestamp() as u64;
        Self {
            last_eth_block: 0,
            last_citrate_height: 0,
            events: HashMap::new(),
            total_deposits: 0,
            total_withdrawals: 0,
            total_salt_credited: 0,
            total_salt_burned: 0,
            started_at: now,
            last_heartbeat: now,
        }
    }
}

impl RelayState {
    /// Create a new relay state starting from the given Ethereum block.
    pub fn new(start_eth_block: u64) -> Self {
        Self {
            last_eth_block: start_eth_block,
            ..Default::default()
        }
    }

    /// Check if an event has already been processed or is being tracked.
    pub fn is_known_event(&self, event_id: &EventId) -> bool {
        self.events.contains_key(event_id)
    }

    /// Check if an event has been fully processed (Processed status).
    pub fn is_processed(&self, event_id: &EventId) -> bool {
        self.events
            .get(event_id)
            .map(|e| e.status == EventStatus::Processed)
            .unwrap_or(false)
    }

    /// Record a new tracked event. Returns false if already exists (dedup).
    pub fn track_event(&mut self, tracked: TrackedEvent) -> bool {
        let event_id = *tracked.event.event_id();
        if self.events.contains_key(&event_id) {
            return false;
        }
        self.events.insert(event_id, tracked);
        true
    }

    /// Update the status of a tracked event.
    pub fn update_event_status(
        &mut self,
        event_id: &EventId,
        status: EventStatus,
        error: Option<String>,
    ) -> bool {
        if let Some(tracked) = self.events.get_mut(event_id) {
            tracked.status = status;
            tracked.updated_at = chrono::Utc::now().timestamp() as u64;
            if let Some(err) = error {
                tracked.error = Some(err);
            }
            true
        } else {
            false
        }
    }

    /// Increment attestation count for an event.
    pub fn add_attestation(&mut self, event_id: &EventId) -> Option<usize> {
        if let Some(tracked) = self.events.get_mut(event_id) {
            tracked.attestation_count += 1;
            Some(tracked.attestation_count)
        } else {
            None
        }
    }

    /// Record a successful deposit.
    pub fn record_deposit(&mut self, salt_amount: u64) {
        self.total_deposits += 1;
        self.total_salt_credited += salt_amount;
    }

    /// Record a successful withdrawal.
    pub fn record_withdrawal(&mut self, salt_amount: u64) {
        self.total_withdrawals += 1;
        self.total_salt_burned += salt_amount;
    }

    /// Update the heartbeat timestamp.
    pub fn heartbeat(&mut self) {
        self.last_heartbeat = chrono::Utc::now().timestamp() as u64;
    }

    /// Get events by status.
    pub fn events_by_status(&self, status: EventStatus) -> Vec<&TrackedEvent> {
        self.events
            .values()
            .filter(|e| e.status == status)
            .collect()
    }

    /// Count events by status.
    pub fn count_by_status(&self, status: EventStatus) -> usize {
        self.events.values().filter(|e| e.status == status).count()
    }

    /// Serialize state to JSON for persistence.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize state from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{BridgeEvent, DepositEvent};

    fn make_deposit(event_id: EventId) -> TrackedEvent {
        TrackedEvent {
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
        }
    }

    #[test]
    fn test_relay_state_deduplication() {
        let mut state = RelayState::default();
        let event_id = [42u8; 32];
        let tracked = make_deposit(event_id);

        // First insert succeeds
        assert!(state.track_event(tracked.clone()));

        // Duplicate insert fails (dedup)
        assert!(!state.track_event(tracked));

        assert!(state.is_known_event(&event_id));
    }

    #[test]
    fn test_relay_state_event_status_update() {
        let mut state = RelayState::default();
        let event_id = [43u8; 32];
        state.track_event(make_deposit(event_id));

        assert!(state.update_event_status(
            &event_id,
            EventStatus::AwaitingAttestations,
            None
        ));

        let tracked = state.events.get(&event_id).unwrap();
        assert_eq!(tracked.status, EventStatus::AwaitingAttestations);
    }

    #[test]
    fn test_relay_state_attestation_counting() {
        let mut state = RelayState::default();
        let event_id = [44u8; 32];
        state.track_event(make_deposit(event_id));

        assert_eq!(state.add_attestation(&event_id), Some(1));
        assert_eq!(state.add_attestation(&event_id), Some(2));
        assert_eq!(state.add_attestation(&event_id), Some(3));

        // Unknown event returns None
        assert_eq!(state.add_attestation(&[99u8; 32]), None);
    }

    #[test]
    fn test_relay_state_deposit_recording() {
        let mut state = RelayState::default();
        state.record_deposit(10_000);
        state.record_deposit(5_000);

        assert_eq!(state.total_deposits, 2);
        assert_eq!(state.total_salt_credited, 15_000);
    }

    #[test]
    fn test_relay_state_serialization() {
        let mut state = RelayState::new(12345);
        state.record_deposit(10_000);

        let json = state.to_json().unwrap();
        let restored = RelayState::from_json(&json).unwrap();

        assert_eq!(restored.last_eth_block, 12345);
        assert_eq!(restored.total_deposits, 1);
        assert_eq!(restored.total_salt_credited, 10_000);
    }

    #[test]
    fn test_relay_state_events_by_status() {
        let mut state = RelayState::default();
        state.track_event(make_deposit([1u8; 32]));
        state.track_event(make_deposit([2u8; 32]));
        state.track_event(make_deposit([3u8; 32]));

        state.update_event_status(&[2u8; 32], EventStatus::Processed, None);

        assert_eq!(state.count_by_status(EventStatus::Pending), 2);
        assert_eq!(state.count_by_status(EventStatus::Processed), 1);
        assert!(state.is_processed(&[2u8; 32]));
        assert!(!state.is_processed(&[1u8; 32]));
    }
}
