//! Wire types shared across the daemon's modules.
//!
//! Kept narrow on purpose — the daemon is a thin orchestrator over
//! existing chain primitives; we don't redefine what already lives
//! in `citrate-execution` / `citrate-learning`. What's here is the
//! bridge between chain events (decoded from logs) and daemon-side
//! state.

use ethereum_types::{H160, H256};
use serde::{Deserialize, Serialize};

/// Citrate block number. Chain-finalized only — the daemon never
/// processes pending blocks.
pub type BlockNumber = u64;

/// On-chain cycle identifier. Matches `LearningCycleManager.cycleId`
/// (`uint256` on chain; we narrow to `u64` because the planset's
/// 100-cycle-per-experiment scope leaves 14 orders of magnitude of
/// headroom).
pub type CycleId = u64;

/// A single embedding submission as observed in a `EmbeddingSubmitted`
/// event log. The 32-byte commitment is the Keccak256 of the actual
/// embedding bytes (the embedding itself is too large to fit in an
/// event); the daemon retrieves the underlying bytes from a side
/// channel (IPFS pin, RPC view call, or local cache) when needed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddingSubmission {
    /// Cycle this submission belongs to.
    pub cycle_id: CycleId,
    /// Submitter's address (an on-chain validator's reward address).
    pub submitter: H160,
    /// Keccak256 commitment hash of the embedding bytes.
    pub commitment: H256,
    /// Block number that finalized the submission.
    pub block_number: BlockNumber,
    /// Log index within the block (used for stable de-duplication
    /// during reorg handling).
    pub log_index: u32,
}

/// Routing-model weights bundle as published by the daemon's trainer.
/// At WP-3.7 this becomes a concrete struct holding the layer
/// matrices. For WP-3.5 it's a placeholder so the orchestrator's
/// types compose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingWeights {
    /// Cycle this weights bundle was trained at.
    pub cycle_id: CycleId,
    /// IPFS CID where the actual Q16 weights bytes are pinned.
    pub ipfs_cid: String,
    /// SHA256 of the published bytes — committed on chain so the
    /// daemon can detect tampering before consuming them via 0x0111.
    pub content_sha256: H256,
}

/// A single mentor assignment dispatched at cycle close.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MentorAssignment {
    /// The mentee receiving the assignment.
    pub mentee: H160,
    /// The mentor address selected for this mentee.
    pub mentor: H160,
    /// Cycle this assignment is for.
    pub cycle_id: CycleId,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_number_is_u64() {
        let _: BlockNumber = u64::MAX;
    }

    #[test]
    fn cycle_id_is_u64() {
        let _: CycleId = u64::MAX;
    }

    #[test]
    fn embedding_submission_serializes_round_trip() {
        let original = EmbeddingSubmission {
            cycle_id: 42,
            submitter: H160::from_low_u64_be(0xdeadbeef),
            commitment: H256::repeat_byte(0x11),
            block_number: 1234,
            log_index: 7,
        };
        let bytes = bincode::serialize(&original).expect("serializes");
        let decoded: EmbeddingSubmission =
            bincode::deserialize(&bytes).expect("decodes");
        assert_eq!(original, decoded);
    }

    #[test]
    fn routing_weights_serializes_round_trip() {
        let original = RoutingWeights {
            cycle_id: 5,
            ipfs_cid: "QmExample".to_string(),
            content_sha256: H256::repeat_byte(0xab),
        };
        let bytes = bincode::serialize(&original).expect("serializes");
        let decoded: RoutingWeights = bincode::deserialize(&bytes).expect("decodes");
        assert_eq!(original, decoded);
    }
}
