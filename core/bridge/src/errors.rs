//! Bridge error types.

use thiserror::Error;

/// Bridge-specific errors.
#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("Event already processed: {event_id}")]
    EventAlreadyProcessed { event_id: String },

    #[error("Event not found: {event_id}")]
    EventNotFound { event_id: String },

    #[error("Insufficient oracle attestations: got {got}, need {need}")]
    InsufficientAttestations { got: usize, need: usize },

    #[error("Oracle already registered: {oracle_id}")]
    OracleAlreadyRegistered { oracle_id: String },

    #[error("Oracle not found: {oracle_id}")]
    OracleNotFound { oracle_id: String },

    #[error("Oracle inactive: {oracle_id}")]
    OracleInactive { oracle_id: String },

    #[error("Duplicate attestation from oracle {oracle_id} for event {event_id}")]
    DuplicateAttestation { oracle_id: String, event_id: String },

    #[error("Attestation consistency error: oracles disagree on event hash for {event_id}")]
    AttestationInconsistency { event_id: String },

    #[error("Event not confirmed: block {block} needs {confirmations} confirmations, only {current} available")]
    EventNotConfirmed {
        block: u64,
        confirmations: u64,
        current: u64,
    },

    #[error("Deposit too small: {amount_wei} wei (minimum: {min_wei} wei)")]
    DepositTooSmall { amount_wei: u128, min_wei: u128 },

    #[error("Deposit exceeds cap: {amount_wei} wei (max: {max_wei} wei)")]
    DepositExceedsCap { amount_wei: u128, max_wei: u128 },

    #[error("Conversion error: {reason}")]
    ConversionError { reason: String },

    #[error("Relay state error: {reason}")]
    RelayStateError { reason: String },

    #[error("Retry exhausted after {attempts} attempts: {reason}")]
    RetryExhausted { attempts: u32, reason: String },

    #[error("Chain reorg detected at block {block}: expected {expected}, got {actual}")]
    ChainReorg {
        block: u64,
        expected: String,
        actual: String,
    },

    #[error("Bridge paused: {reason}")]
    BridgePaused { reason: String },

    #[error("Invalid event data: {reason}")]
    InvalidEventData { reason: String },

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Bridge result type alias.
pub type BridgeResult<T> = Result<T, BridgeError>;
