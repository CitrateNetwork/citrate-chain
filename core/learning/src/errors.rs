//! Error types for the learning crate.

use thiserror::Error;

/// Errors that can occur in the Paraconsensus learning layer.
#[derive(Error, Debug)]
pub enum LearningError {
    /// Embedding dimension does not match the expected space dimension.
    #[error("dimension mismatch: expected {expected}, got {got}")]
    DimensionMismatch { expected: usize, got: usize },

    /// Embedding contains invalid values (NaN, Inf).
    #[error("invalid embedding: {reason}")]
    InvalidEmbedding { reason: String },

    /// Aggregation failed.
    #[error("aggregation failed: {reason}")]
    AggregationFailed { reason: String },

    /// Phase timeout elapsed before transition condition was met.
    #[error("phase timeout: {phase} after {elapsed_ms}ms")]
    PhaseTimeout { phase: String, elapsed_ms: u64 },

    /// Invalid phase transition attempted.
    #[error("invalid phase transition: {from} -> {to}")]
    InvalidPhaseTransition { from: String, to: String },

    /// Routing model failed.
    #[error("routing failed: {reason}")]
    RoutingFailed { reason: String },

    /// Adapter operation failed.
    #[error("adapter error: {reason}")]
    AdapterError { reason: String },

    /// Expected checkpoint not found.
    #[error("checkpoint missing at height {expected_height}")]
    CheckpointMissing { expected_height: u64 },

    /// Safety invariant violated — this is a critical error.
    #[error("SAFETY VIOLATION: {details}")]
    SafetyViolation { details: String },

    /// Configuration is invalid.
    #[error("invalid config: field '{field}' — {reason}")]
    ConfigInvalid { field: String, reason: String },

    /// Participant not found.
    #[error("participant not found: {id}")]
    ParticipantNotFound { id: String },

    /// Byzantine behavior detected.
    #[error("byzantine behavior detected from {participant}: {reason}")]
    ByzantineBehavior { participant: String, reason: String },

    /// Serialization/deserialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Storage error.
    #[error("storage error: {0}")]
    Storage(String),
}

/// Result type alias for learning operations.
pub type LearningResult<T> = Result<T, LearningError>;
