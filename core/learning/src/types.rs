//! Core types for the learning layer.
//!
//! Implements Data Structures 1-2 from Gradient Papers No. II.

use crate::belnap::BelnapValue;
use crate::embeddings::EmbeddingVector;
use crate::phases::OodaPhase;
use serde::{Deserialize, Serialize};

/// A 32-byte hash type (matches consensus primitives).
pub type Hash = [u8; 32];

/// A 32-byte public key type (matches consensus primitives).
pub type PublicKey = [u8; 32];

/// A 64-byte signature type.
///
/// Note: We use Vec<u8> instead of [u8; 64] for serde compatibility
/// (serde doesn't implement Serialize/Deserialize for arrays > 32 by default).
pub type Signature = Vec<u8>;

/// A participant in the learning protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Participant {
    /// Participant's public key.
    pub pubkey: PublicKey,

    /// Participant role.
    pub role: ParticipantRole,

    /// Stake weight (derived from blue score).
    pub stake_weight: f32,

    /// Current embedding (if submitted).
    pub current_embedding: Option<EmbeddingVector>,

    /// Belnap confidence per embedding dimension.
    pub confidence: Vec<BelnapValue>,

    /// Last round this participant submitted an embedding.
    pub last_active_round: u64,

    /// Number of byzantine flags accumulated.
    pub byzantine_flags: usize,

    /// Whether this participant is currently excluded.
    pub excluded: bool,

    /// Round at which exclusion started (for cool-down).
    pub excluded_since: Option<u64>,
}

/// Participant role in the learning protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParticipantRole {
    /// Full participant: submits embeddings and receives adapters.
    Full,
    /// Observer: receives aggregated results but doesn't submit.
    Observer,
    /// Validator: validates adapters and provenance chains.
    Validator,
}

/// A single learning round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningRound {
    /// Round number.
    pub round: u64,

    /// Current phase.
    pub phase: OodaPhase,

    /// Participant public keys in this round.
    pub participants: Vec<PublicKey>,

    /// Checkpoint height that triggered this round.
    pub checkpoint_height: u64,

    /// Round start timestamp.
    pub started_at: u64,

    /// Round end timestamp (if completed).
    pub completed_at: Option<u64>,

    /// Aggregated embedding result (if Orient phase complete).
    pub aggregated_embedding: Option<EmbeddingVector>,
}

/// A timestamped embedding for storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampedEmbedding {
    /// The embedding vector.
    pub embedding: EmbeddingVector,

    /// Round when this was submitted.
    pub round: u64,

    /// Timestamp of submission.
    pub timestamp: u64,

    /// Submitter public key.
    pub submitter: PublicKey,
}

// PC-T11: Serialization roundtrip
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_participant_serialization_roundtrip() {
        let participant = Participant {
            pubkey: [1u8; 32],
            role: ParticipantRole::Full,
            stake_weight: 0.5,
            current_embedding: Some(EmbeddingVector::zeros(4)),
            confidence: vec![BelnapValue::True, BelnapValue::Neither],
            last_active_round: 42,
            byzantine_flags: 0,
            excluded: false,
            excluded_since: None,
        };

        let json = serde_json::to_string(&participant).unwrap();
        let deserialized: Participant = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.pubkey, participant.pubkey);
        assert_eq!(deserialized.role, participant.role);
        assert_eq!(deserialized.last_active_round, 42);
    }

    #[test]
    fn test_learning_round_serialization() {
        let round = LearningRound {
            round: 1,
            phase: OodaPhase::Observe,
            participants: vec![[1u8; 32], [2u8; 32]],
            checkpoint_height: 100,
            started_at: 1000,
            completed_at: None,
            aggregated_embedding: None,
        };

        let json = serde_json::to_string(&round).unwrap();
        let deserialized: LearningRound = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.round, 1);
        assert_eq!(deserialized.participants.len(), 2);
    }

    #[test]
    fn test_timestamped_embedding_serialization() {
        let te = TimestampedEmbedding {
            embedding: EmbeddingVector::zeros(3),
            round: 5,
            timestamp: 12345,
            submitter: [99u8; 32],
        };

        let bytes = bincode::serialize(&te).unwrap();
        let deserialized: TimestampedEmbedding = bincode::deserialize(&bytes).unwrap();
        assert_eq!(deserialized.round, 5);
        assert_eq!(deserialized.submitter, [99u8; 32]);
    }
}
