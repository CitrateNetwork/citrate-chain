//! Bridge event types.
//!
//! Defines the cross-chain events that the bridge relay processes:
//! deposits (Ethereum → Citrate), withdrawals (Citrate → Ethereum),
//! and oracle updates.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Unique event identifier (SHA3-256 of tx_hash + log_index).
pub type EventId = [u8; 32];

/// Bridge event — the core unit of cross-chain communication.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BridgeEvent {
    /// ETH deposited on Sepolia → triggers SALT credit on Citrate.
    Deposit(DepositEvent),

    /// SALT burned on Citrate → triggers ETH release on Sepolia.
    Withdrawal(WithdrawalEvent),

    /// Oracle set updated (add/remove oracle).
    OracleUpdate(OracleUpdateEvent),
}

/// Deposit event from Ethereum Sepolia.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DepositEvent {
    /// Unique event ID (hash of tx_hash + log_index).
    pub event_id: EventId,

    /// Ethereum transaction hash that triggered this deposit.
    pub eth_tx_hash: [u8; 32],

    /// Log index within the Ethereum transaction.
    pub log_index: u32,

    /// Ethereum block number where the deposit occurred.
    pub eth_block_number: u64,

    /// Depositor's Ethereum address (20 bytes).
    pub depositor: [u8; 20],

    /// Citrate recipient address (20 bytes).
    pub recipient: [u8; 20],

    /// Deposit amount in wei (ETH * 10^18).
    pub amount_wei: u128,

    /// Deposit amount in ETH (floating point for display).
    pub amount_eth: f64,

    /// Timestamp of the Ethereum block.
    pub timestamp: u64,
}

/// Withdrawal event from Citrate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WithdrawalEvent {
    /// Unique event ID.
    pub event_id: EventId,

    /// Citrate transaction hash that triggered this withdrawal.
    pub citrate_tx_hash: [u8; 32],

    /// Citrate block height where the withdrawal occurred.
    pub citrate_block_height: u64,

    /// Citrate sender address (20 bytes).
    pub sender: [u8; 20],

    /// Ethereum recipient address (20 bytes).
    pub eth_recipient: [u8; 20],

    /// SALT amount to burn (in base units).
    pub salt_amount: u64,

    /// Equivalent ETH amount in wei to release.
    pub eth_amount_wei: u128,

    /// Timestamp.
    pub timestamp: u64,
}

/// Oracle set update event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OracleUpdateEvent {
    /// Event ID.
    pub event_id: EventId,

    /// Oracle public key (32 bytes).
    pub oracle_pubkey: [u8; 32],

    /// Whether this oracle is being added (true) or removed (false).
    pub is_addition: bool,

    /// Timestamp.
    pub timestamp: u64,
}

/// Processing status of a bridge event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventStatus {
    /// Event detected but not yet confirmed (waiting for block depth).
    Pending,

    /// Event confirmed, waiting for oracle attestations.
    AwaitingAttestations,

    /// Sufficient attestations received, ready to process.
    Attested,

    /// Event fully processed (SALT credited or ETH released).
    Processed,

    /// Event rejected (invalid, duplicate, or insufficient attestations).
    Rejected,

    /// Event failed to process (will be retried).
    Failed,
}

/// Tracked event with its current processing status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedEvent {
    /// The bridge event.
    pub event: BridgeEvent,

    /// Current processing status.
    pub status: EventStatus,

    /// Number of oracle attestations received.
    pub attestation_count: usize,

    /// Number of processing attempts.
    pub retry_count: u32,

    /// When this event was first detected.
    pub detected_at: u64,

    /// When this event was last updated.
    pub updated_at: u64,

    /// Error message if status is Failed or Rejected.
    pub error: Option<String>,
}

impl BridgeEvent {
    /// Get the event ID.
    pub fn event_id(&self) -> &EventId {
        match self {
            BridgeEvent::Deposit(d) => &d.event_id,
            BridgeEvent::Withdrawal(w) => &w.event_id,
            BridgeEvent::OracleUpdate(o) => &o.event_id,
        }
    }

    /// Get the block number / height where this event originated.
    pub fn source_block(&self) -> u64 {
        match self {
            BridgeEvent::Deposit(d) => d.eth_block_number,
            BridgeEvent::Withdrawal(w) => w.citrate_block_height,
            BridgeEvent::OracleUpdate(_) => 0,
        }
    }
}

impl DepositEvent {
    /// Canonical attestation digest binding every mint-critical field.
    ///
    /// Oracles MUST sign `event_hash = deposit.canonical_hash()`. The relay
    /// recomputes this from the presented deposit and rejects the mint unless
    /// the attested hash matches — so a tampered amount/recipient/depositor or
    /// source coordinate (under any `event_id`) cannot pass. `amount_eth` is
    /// deliberately excluded: it is display-only and unbound at the source;
    /// minting derives value from the integer `amount_wei` and the minter
    /// independently rejects an `amount_eth` inconsistent with it.
    ///
    /// Domain-separated: `"citrate-bridge-deposit-v1" || eth_tx_hash(32) ||
    /// log_index(4 LE) || eth_block_number(8 LE) || depositor(20) ||
    /// recipient(20) || amount_wei(16 LE)`.
    pub fn canonical_hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"citrate-bridge-deposit-v1");
        hasher.update(self.eth_tx_hash);
        hasher.update(self.log_index.to_le_bytes());
        hasher.update(self.eth_block_number.to_le_bytes());
        hasher.update(self.depositor);
        hasher.update(self.recipient);
        hasher.update(self.amount_wei.to_le_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Compute the event ID from tx_hash and log_index.
    pub fn compute_event_id(eth_tx_hash: &[u8; 32], log_index: u32) -> EventId {
        let mut hasher = Sha3_256::new();
        hasher.update(eth_tx_hash);
        hasher.update(log_index.to_le_bytes());
        hasher.update(b"deposit");
        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        id
    }
}

impl WithdrawalEvent {
    /// Compute the event ID from Citrate tx hash.
    pub fn compute_event_id(citrate_tx_hash: &[u8; 32], block_height: u64) -> EventId {
        let mut hasher = Sha3_256::new();
        hasher.update(citrate_tx_hash);
        hasher.update(block_height.to_le_bytes());
        hasher.update(b"withdrawal");
        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        id
    }

    /// SECREM-01 BRG-2: canonical attestation digest binding every
    /// release-critical field — the withdrawal mirror of
    /// `DepositEvent::canonical_hash`. Oracles MUST sign
    /// `event_hash = withdrawal.canonical_hash()`; the relay refuses to
    /// process a withdrawal unless ≥ threshold active oracles attested
    /// exactly this hash. Pre-fix, withdrawal processing bound NO fields
    /// to attestations (mitigated only by the stubbed ETH-release path).
    ///
    /// Domain-separated: `"citrate-bridge-withdrawal-v1" ||
    /// citrate_tx_hash(32) || citrate_block_height(8 LE) || sender(20) ||
    /// eth_recipient(20) || salt_amount(8 LE) || eth_amount_wei(16 LE)`.
    pub fn canonical_hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"citrate-bridge-withdrawal-v1");
        hasher.update(self.citrate_tx_hash);
        hasher.update(self.citrate_block_height.to_le_bytes());
        hasher.update(self.sender);
        hasher.update(self.eth_recipient);
        hasher.update(self.salt_amount.to_le_bytes());
        hasher.update(self.eth_amount_wei.to_le_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deposit_event_id_computation() {
        let tx_hash = [1u8; 32];
        let id1 = DepositEvent::compute_event_id(&tx_hash, 0);
        let id2 = DepositEvent::compute_event_id(&tx_hash, 1);
        // Different log indices produce different IDs
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_deposit_event_id_deterministic() {
        let tx_hash = [42u8; 32];
        let id1 = DepositEvent::compute_event_id(&tx_hash, 5);
        let id2 = DepositEvent::compute_event_id(&tx_hash, 5);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_withdrawal_event_id_computation() {
        let tx_hash = [2u8; 32];
        let id = WithdrawalEvent::compute_event_id(&tx_hash, 100);
        assert_ne!(id, [0u8; 32]);
    }

    #[test]
    fn test_bridge_event_accessors() {
        let deposit = BridgeEvent::Deposit(DepositEvent {
            event_id: [1u8; 32],
            eth_tx_hash: [2u8; 32],
            log_index: 0,
            eth_block_number: 12345,
            depositor: [3u8; 20],
            recipient: [4u8; 20],
            amount_wei: 1_000_000_000_000_000_000,
            amount_eth: 1.0,
            timestamp: 1000,
        });

        assert_eq!(*deposit.event_id(), [1u8; 32]);
        assert_eq!(deposit.source_block(), 12345);
    }

    #[test]
    fn test_event_status_transitions() {
        let tracked = TrackedEvent {
            event: BridgeEvent::Deposit(DepositEvent {
                event_id: [1u8; 32],
                eth_tx_hash: [2u8; 32],
                log_index: 0,
                eth_block_number: 100,
                depositor: [3u8; 20],
                recipient: [4u8; 20],
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

        assert_eq!(tracked.status, EventStatus::Pending);
        assert_eq!(tracked.attestation_count, 0);
    }
}
