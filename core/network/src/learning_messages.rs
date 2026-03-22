// citrate/core/network/src/learning_messages.rs
//
// P2P message types for the paraconsensus learning layer (WP-F.2).
//
// These messages are gossiped at BFT checkpoint boundaries so that
// validators can share local embeddings, confidence vectors, and
// LoRA adapter deltas without affecting consensus state.

use citrate_consensus::types::{Hash, PublicKey, Signature};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Belnap confidence (network-local mirror of citrate_learning::BelnapValue)
// ---------------------------------------------------------------------------

/// Belnap four-valued confidence classification.
///
/// This is a self-contained network-layer copy of
/// `citrate_learning::BelnapValue` so that the network crate does not need a
/// direct dependency on `citrate-learning`.  The two enums are wire-compatible
/// (same serde tag values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BelnapConfidence {
    /// Unknown / no information.
    Neither,
    /// Known true.
    True,
    /// Known false.
    False,
    /// Both true and false (paraconsistent).
    Both,
}

// ---------------------------------------------------------------------------
// Performance profile
// ---------------------------------------------------------------------------

/// Performance profile attached to a `LearningEmbedding` for mentor selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceProfile {
    /// Average inference accuracy (0.0 -- 1.0).
    pub accuracy: f64,
    /// Average inference latency in milliseconds.
    pub latency_ms: u64,
    /// Model domains this node serves (e.g. `["nlp", "vision"]`).
    pub domains: Vec<String>,
    /// Uptime percentage over the last 1 000 blocks (0.0 -- 1.0).
    pub uptime: f64,
    /// Number of adapters this node has contributed to the network.
    pub adapter_count: u32,
}

// ---------------------------------------------------------------------------
// LearningEmbedding
// ---------------------------------------------------------------------------

/// Learning embedding broadcast at checkpoint boundaries.
///
/// Each validator shares its local embedding vector together with a per-dimension
/// Belnap confidence classification so that the aggregation layer can weight
/// contributions according to epistemic certainty.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningEmbedding {
    /// BFT checkpoint height this embedding corresponds to.
    pub checkpoint_height: u64,
    /// Validator who produced this embedding.
    pub participant: PublicKey,
    /// Aggregated embedding vector (`f32` for compactness over the wire).
    pub embedding: Vec<f32>,
    /// Per-dimension Belnap confidence classification.
    pub confidence: Vec<BelnapConfidence>,
    /// Performance profile for mentor selection.
    pub profile: PerformanceProfile,
    /// Ed25519 signature over `(checkpoint_height || embedding || confidence)`.
    pub signature: Signature,
}

impl LearningEmbedding {
    /// Validate the embedding message for structural correctness.
    ///
    /// This does **not** verify the cryptographic signature — that requires
    /// access to the validator set and is handled at a higher layer.
    pub fn validate(&self) -> Result<(), String> {
        // 1. Embedding must be non-empty.
        if self.embedding.is_empty() {
            return Err("Empty embedding vector".to_string());
        }

        // 2. Confidence vector must match embedding dimension.
        if self.confidence.len() != self.embedding.len() {
            return Err(format!(
                "Confidence length {} != embedding length {}",
                self.confidence.len(),
                self.embedding.len()
            ));
        }

        // 3. All embedding values must be finite (no NaN / Inf).
        for (i, &v) in self.embedding.iter().enumerate() {
            if !v.is_finite() {
                return Err(format!("Non-finite value at index {}", i));
            }
        }

        // 4. Accuracy must be in [0, 1].
        if !(0.0..=1.0).contains(&self.profile.accuracy) {
            return Err("Accuracy out of range [0, 1]".to_string());
        }

        // 5. Uptime must be in [0, 1].
        if !(0.0..=1.0).contains(&self.profile.uptime) {
            return Err("Uptime out of range [0, 1]".to_string());
        }

        // 6. Reasonable embedding size limit (16k dimensions).
        const MAX_EMBEDDING_DIM: usize = 16_384;
        if self.embedding.len() > MAX_EMBEDDING_DIM {
            return Err(format!(
                "Embedding dimension {} exceeds limit {}",
                self.embedding.len(),
                MAX_EMBEDDING_DIM
            ));
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AdapterOffer
// ---------------------------------------------------------------------------

/// LoRA adapter offer from a mentor to a mentee.
///
/// After embeddings are aggregated and mentor-mentee pairs determined, the
/// mentor pushes a small LoRA delta via this message.  The `adapter_cid` is an
/// IPFS content identifier that the mentee can fetch out-of-band.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterOffer {
    /// Checkpoint height when this adapter was generated.
    pub checkpoint_height: u64,
    /// Mentor who generated the adapter.
    pub mentor: PublicKey,
    /// Intended mentee.
    pub mentee: PublicKey,
    /// IPFS CID of the LoRA adapter delta.
    pub adapter_cid: String,
    /// Hash of the adapter data (for integrity verification).
    pub adapter_hash: Hash,
    /// Provenance chain: parent adapter hashes (empty for root adapters).
    pub provenance: Vec<Hash>,
    /// Mentor's ed25519 signature.
    pub signature: Signature,
}

impl AdapterOffer {
    /// Validate the adapter offer for structural correctness.
    pub fn validate(&self) -> Result<(), String> {
        // 1. CID must be present.
        if self.adapter_cid.is_empty() {
            return Err("Empty adapter CID".to_string());
        }

        // 2. Self-mentoring is not allowed.
        if self.mentor == self.mentee {
            return Err("Mentor cannot be own mentee".to_string());
        }

        // 3. CID should look like a valid IPFS CID (starts with Qm or ba).
        // We check a minimal length rather than a full multibase parse to
        // keep the network crate dependency-light.
        if self.adapter_cid.len() < 2 {
            return Err("Adapter CID too short".to_string());
        }

        // 4. Provenance chain must not be unreasonably long.
        const MAX_PROVENANCE_DEPTH: usize = 256;
        if self.provenance.len() > MAX_PROVENANCE_DEPTH {
            return Err(format!(
                "Provenance chain length {} exceeds limit {}",
                self.provenance.len(),
                MAX_PROVENANCE_DEPTH
            ));
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// LearningMessage wrapper enum
// ---------------------------------------------------------------------------

/// Wrapper enum for all learning-related P2P messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LearningMessage {
    /// Embedding broadcast at a checkpoint boundary.
    Embedding(LearningEmbedding),
    /// LoRA adapter offer from mentor to mentee.
    Adapter(AdapterOffer),
}

impl LearningMessage {
    /// Validate the inner message.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Embedding(e) => e.validate(),
            Self::Adapter(a) => a.validate(),
        }
    }

    /// Return the checkpoint height this message pertains to.
    pub fn checkpoint_height(&self) -> u64 {
        match self {
            Self::Embedding(e) => e.checkpoint_height,
            Self::Adapter(a) => a.checkpoint_height,
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a valid `LearningEmbedding`.
    fn make_valid_embedding() -> LearningEmbedding {
        LearningEmbedding {
            checkpoint_height: 100,
            participant: PublicKey::new([1u8; 32]),
            embedding: vec![0.1, 0.2, 0.3, 0.4],
            confidence: vec![
                BelnapConfidence::True,
                BelnapConfidence::Neither,
                BelnapConfidence::False,
                BelnapConfidence::Both,
            ],
            profile: PerformanceProfile {
                accuracy: 0.95,
                latency_ms: 42,
                domains: vec!["nlp".to_string()],
                uptime: 0.99,
                adapter_count: 3,
            },
            signature: Signature::default(),
        }
    }

    /// Helper: create a valid `AdapterOffer`.
    fn make_valid_adapter_offer() -> AdapterOffer {
        AdapterOffer {
            checkpoint_height: 100,
            mentor: PublicKey::new([1u8; 32]),
            mentee: PublicKey::new([2u8; 32]),
            adapter_cid: "QmTestCid123456789".to_string(),
            adapter_hash: Hash::new([0xAA; 32]),
            provenance: vec![],
            signature: Signature::default(),
        }
    }

    // -----------------------------------------------------------------------
    // LearningEmbedding validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_learning_embedding_validation_valid() {
        let emb = make_valid_embedding();
        assert!(emb.validate().is_ok());
    }

    #[test]
    fn test_learning_embedding_validation_empty() {
        let mut emb = make_valid_embedding();
        emb.embedding = vec![];
        emb.confidence = vec![];
        let err = emb.validate().unwrap_err();
        assert!(err.contains("Empty embedding vector"), "got: {err}");
    }

    #[test]
    fn test_learning_embedding_validation_dimension_mismatch() {
        let mut emb = make_valid_embedding();
        emb.confidence.pop(); // 4 dims vs 3 confidence => mismatch
        let err = emb.validate().unwrap_err();
        assert!(err.contains("Confidence length"), "got: {err}");
    }

    #[test]
    fn test_learning_embedding_validation_nan() {
        let mut emb = make_valid_embedding();
        emb.embedding[2] = f32::NAN;
        let err = emb.validate().unwrap_err();
        assert!(err.contains("Non-finite value at index 2"), "got: {err}");
    }

    #[test]
    fn test_learning_embedding_validation_inf() {
        let mut emb = make_valid_embedding();
        emb.embedding[0] = f32::INFINITY;
        let err = emb.validate().unwrap_err();
        assert!(err.contains("Non-finite value at index 0"), "got: {err}");
    }

    #[test]
    fn test_learning_embedding_validation_neg_inf() {
        let mut emb = make_valid_embedding();
        emb.embedding[1] = f32::NEG_INFINITY;
        let err = emb.validate().unwrap_err();
        assert!(err.contains("Non-finite value at index 1"), "got: {err}");
    }

    #[test]
    fn test_learning_embedding_validation_accuracy_too_high() {
        let mut emb = make_valid_embedding();
        emb.profile.accuracy = 1.01;
        let err = emb.validate().unwrap_err();
        assert!(err.contains("Accuracy out of range"), "got: {err}");
    }

    #[test]
    fn test_learning_embedding_validation_accuracy_negative() {
        let mut emb = make_valid_embedding();
        emb.profile.accuracy = -0.1;
        let err = emb.validate().unwrap_err();
        assert!(err.contains("Accuracy out of range"), "got: {err}");
    }

    #[test]
    fn test_learning_embedding_validation_uptime_too_high() {
        let mut emb = make_valid_embedding();
        emb.profile.uptime = 1.5;
        let err = emb.validate().unwrap_err();
        assert!(err.contains("Uptime out of range"), "got: {err}");
    }

    #[test]
    fn test_learning_embedding_validation_uptime_negative() {
        let mut emb = make_valid_embedding();
        emb.profile.uptime = -0.01;
        let err = emb.validate().unwrap_err();
        assert!(err.contains("Uptime out of range"), "got: {err}");
    }

    #[test]
    fn test_learning_embedding_validation_oversized() {
        let mut emb = make_valid_embedding();
        emb.embedding = vec![0.0; 20_000];
        emb.confidence = vec![BelnapConfidence::Neither; 20_000];
        let err = emb.validate().unwrap_err();
        assert!(err.contains("exceeds limit"), "got: {err}");
    }

    #[test]
    fn test_learning_embedding_boundary_accuracy_zero() {
        let mut emb = make_valid_embedding();
        emb.profile.accuracy = 0.0;
        assert!(emb.validate().is_ok());
    }

    #[test]
    fn test_learning_embedding_boundary_accuracy_one() {
        let mut emb = make_valid_embedding();
        emb.profile.accuracy = 1.0;
        assert!(emb.validate().is_ok());
    }

    // -----------------------------------------------------------------------
    // AdapterOffer validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_adapter_offer_validation_valid() {
        let offer = make_valid_adapter_offer();
        assert!(offer.validate().is_ok());
    }

    #[test]
    fn test_adapter_offer_validation_empty_cid() {
        let mut offer = make_valid_adapter_offer();
        offer.adapter_cid = String::new();
        let err = offer.validate().unwrap_err();
        assert!(err.contains("Empty adapter CID"), "got: {err}");
    }

    #[test]
    fn test_adapter_offer_validation_self_mentor() {
        let mut offer = make_valid_adapter_offer();
        offer.mentee = offer.mentor; // same key => self-mentoring
        let err = offer.validate().unwrap_err();
        assert!(err.contains("Mentor cannot be own mentee"), "got: {err}");
    }

    #[test]
    fn test_adapter_offer_validation_short_cid() {
        let mut offer = make_valid_adapter_offer();
        offer.adapter_cid = "Q".to_string();
        let err = offer.validate().unwrap_err();
        assert!(err.contains("CID too short"), "got: {err}");
    }

    #[test]
    fn test_adapter_offer_validation_deep_provenance() {
        let mut offer = make_valid_adapter_offer();
        offer.provenance = vec![Hash::default(); 300];
        let err = offer.validate().unwrap_err();
        assert!(err.contains("Provenance chain length"), "got: {err}");
    }

    // -----------------------------------------------------------------------
    // Serialization round-trips
    // -----------------------------------------------------------------------

    #[test]
    fn test_learning_message_serialization_roundtrip() {
        let embedding = make_valid_embedding();
        let msg = LearningMessage::Embedding(embedding.clone());
        let bytes = bincode::serialize(&msg).expect("serialize LearningMessage");
        let recovered: LearningMessage =
            bincode::deserialize(&bytes).expect("deserialize LearningMessage");
        match recovered {
            LearningMessage::Embedding(e) => {
                assert_eq!(e.checkpoint_height, embedding.checkpoint_height);
                assert_eq!(e.participant, embedding.participant);
                assert_eq!(e.embedding, embedding.embedding);
                assert_eq!(e.confidence, embedding.confidence);
                assert_eq!(e.profile.accuracy, embedding.profile.accuracy);
                assert_eq!(e.profile.latency_ms, embedding.profile.latency_ms);
                assert_eq!(e.profile.uptime, embedding.profile.uptime);
                assert_eq!(e.profile.adapter_count, embedding.profile.adapter_count);
                assert_eq!(e.profile.domains, embedding.profile.domains);
            }
            _ => panic!("Expected LearningMessage::Embedding"),
        }
    }

    #[test]
    fn test_adapter_offer_serialization_roundtrip() {
        let offer = make_valid_adapter_offer();
        let msg = LearningMessage::Adapter(offer.clone());
        let bytes = bincode::serialize(&msg).expect("serialize");
        let recovered: LearningMessage = bincode::deserialize(&bytes).expect("deserialize");
        match recovered {
            LearningMessage::Adapter(a) => {
                assert_eq!(a.checkpoint_height, offer.checkpoint_height);
                assert_eq!(a.mentor, offer.mentor);
                assert_eq!(a.mentee, offer.mentee);
                assert_eq!(a.adapter_cid, offer.adapter_cid);
                assert_eq!(a.adapter_hash, offer.adapter_hash);
                assert_eq!(a.provenance, offer.provenance);
            }
            _ => panic!("Expected LearningMessage::Adapter"),
        }
    }

    // -----------------------------------------------------------------------
    // LearningMessage wrapper
    // -----------------------------------------------------------------------

    #[test]
    fn test_learning_message_checkpoint_height() {
        let emb = make_valid_embedding();
        let msg = LearningMessage::Embedding(emb);
        assert_eq!(msg.checkpoint_height(), 100);

        let offer = make_valid_adapter_offer();
        let msg = LearningMessage::Adapter(offer);
        assert_eq!(msg.checkpoint_height(), 100);
    }

    #[test]
    fn test_learning_message_validate_delegates() {
        let emb = make_valid_embedding();
        let msg = LearningMessage::Embedding(emb);
        assert!(msg.validate().is_ok());

        let mut bad_offer = make_valid_adapter_offer();
        bad_offer.adapter_cid = String::new();
        let msg = LearningMessage::Adapter(bad_offer);
        assert!(msg.validate().is_err());
    }
}
