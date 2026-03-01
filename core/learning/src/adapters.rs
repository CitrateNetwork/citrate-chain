//! Adapter creation and composition.
//!
//! Implements Algorithm 4, Definition 8-9, and Theorem 2 from Gradient Papers No. II.

use crate::embeddings::EmbeddingVector;
use crate::errors::{LearningError, LearningResult};
use crate::types::{Hash, PublicKey, Signature};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// A learning adapter — a lightweight delta with provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningAdapter {
    /// Unique identifier (hash of delta + metadata).
    pub id: Hash,
    /// The embedding delta.
    pub delta: EmbeddingVector,
    /// Adapter metadata.
    pub metadata: AdapterMetadata,
    /// Creator's public key.
    pub creator: PublicKey,
    /// Checkpoint height at which this adapter was produced.
    pub checkpoint_height: u64,
    /// Provenance chain.
    pub provenance: ProvenanceChain,
}

/// Adapter metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterMetadata {
    /// Human-readable name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Learning round that produced this adapter.
    pub round: u64,
    /// Number of participants in the aggregation.
    pub participant_count: usize,
    /// Creation timestamp.
    pub created_at: u64,
}

/// A provenance chain linking an adapter to its origin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceChain {
    /// Ordered list of provenance entries.
    pub entries: Vec<ProvenanceEntry>,
}

/// A single provenance entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceEntry {
    /// Creator of this entry.
    pub creator: PublicKey,
    /// Learning round.
    pub round: u64,
    /// Checkpoint height.
    pub checkpoint_height: u64,
    /// Hash of the parent adapter (None for root).
    pub parent_adapter_hash: Option<Hash>,
    /// Timestamp.
    pub timestamp: u64,
    /// Signature over this entry.
    pub signature: Signature,
}

impl ProvenanceChain {
    /// Create a new provenance chain with a single root entry.
    pub fn new(entry: ProvenanceEntry) -> Self {
        Self {
            entries: vec![entry],
        }
    }

    /// Append an entry to the chain.
    pub fn append(&mut self, entry: ProvenanceEntry) {
        self.entries.push(entry);
    }

    /// Validate the chain: each entry must link to the previous.
    pub fn validate(&self) -> LearningResult<()> {
        for i in 1..self.entries.len() {
            let prev_hash = compute_entry_hash(&self.entries[i - 1]);
            match &self.entries[i].parent_adapter_hash {
                Some(h) if *h == prev_hash => {}
                Some(_) => {
                    return Err(LearningError::AdapterError {
                        reason: format!("broken provenance chain at entry {}", i),
                    });
                }
                None => {
                    return Err(LearningError::AdapterError {
                        reason: format!("missing parent hash at entry {}", i),
                    });
                }
            }
        }
        Ok(())
    }

    /// Get the length of the chain.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Compute the hash of a provenance entry.
fn compute_entry_hash(entry: &ProvenanceEntry) -> Hash {
    let mut hasher = Sha3_256::new();
    hasher.update(&entry.creator);
    hasher.update(entry.round.to_le_bytes());
    hasher.update(entry.checkpoint_height.to_le_bytes());
    if let Some(ref parent) = entry.parent_adapter_hash {
        hasher.update(parent);
    }
    hasher.update(entry.timestamp.to_le_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Factory for creating learning adapters.
pub struct AdapterFactory;

impl AdapterFactory {
    /// Create a new adapter from an aggregated embedding.
    pub fn create(
        delta: EmbeddingVector,
        metadata: AdapterMetadata,
        creator: PublicKey,
        checkpoint_height: u64,
        signature: Signature,
    ) -> LearningResult<LearningAdapter> {
        let id = Self::compute_id(&delta, &metadata);

        let provenance = ProvenanceChain::new(ProvenanceEntry {
            creator,
            round: metadata.round,
            checkpoint_height,
            parent_adapter_hash: None,
            timestamp: metadata.created_at,
            signature,
        });

        Ok(LearningAdapter {
            id,
            delta,
            metadata,
            creator,
            checkpoint_height,
            provenance,
        })
    }

    /// Compute the unique ID for an adapter.
    pub fn compute_id(delta: &EmbeddingVector, metadata: &AdapterMetadata) -> Hash {
        let mut hasher = Sha3_256::new();
        for v in &delta.data {
            hasher.update(v.to_le_bytes());
        }
        hasher.update(metadata.name.as_bytes());
        hasher.update(metadata.round.to_le_bytes());
        hasher.update(metadata.created_at.to_le_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Verify an adapter's hash matches its content.
    pub fn verify_hash(adapter: &LearningAdapter) -> bool {
        let expected = Self::compute_id(&adapter.delta, &adapter.metadata);
        adapter.id == expected
    }
}

/// Apply an adapter to a base embedding.
pub fn apply_adapter(
    base: &EmbeddingVector,
    adapter: &LearningAdapter,
) -> LearningResult<EmbeddingVector> {
    base.add(&adapter.delta)
}

/// Compose two adapters sequentially.
///
/// Theorem 2: compose(A, B) produces a new adapter whose delta
/// is the sum of A's and B's deltas.
pub fn compose_adapters(
    first: &LearningAdapter,
    second: &LearningAdapter,
) -> LearningResult<EmbeddingVector> {
    first.delta.add(&second.delta)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_metadata(round: u64) -> AdapterMetadata {
        AdapterMetadata {
            name: "test-adapter".to_string(),
            description: "A test adapter".to_string(),
            round,
            participant_count: 5,
            created_at: 12345,
        }
    }

    // PC-T35: Adapter creation
    #[test]
    fn test_adapter_creation() {
        let delta = EmbeddingVector::new(vec![0.1, -0.2, 0.3]).unwrap();
        let adapter = AdapterFactory::create(
            delta.clone(),
            test_metadata(1),
            [1u8; 32],
            100,
            vec![0u8; 64],
        )
        .unwrap();

        assert_eq!(adapter.creator, [1u8; 32]);
        assert_eq!(adapter.checkpoint_height, 100);
        assert_eq!(adapter.provenance.len(), 1);
    }

    // PC-T36: Adapter application
    #[test]
    fn test_adapter_application() {
        let base = EmbeddingVector::new(vec![1.0, 2.0, 3.0]).unwrap();
        let delta = EmbeddingVector::new(vec![0.1, -0.2, 0.3]).unwrap();
        let adapter = AdapterFactory::create(
            delta,
            test_metadata(1),
            [1u8; 32],
            100,
            vec![0u8; 64],
        )
        .unwrap();

        let result = apply_adapter(&base, &adapter).unwrap();
        assert!((result.data[0] - 1.1).abs() < 1e-6);
        assert!((result.data[1] - 1.8).abs() < 1e-6);
        assert!((result.data[2] - 3.3).abs() < 1e-6);
    }

    // PC-T37: Adapter hash verification
    #[test]
    fn test_hash_verification() {
        let delta = EmbeddingVector::new(vec![0.1, -0.2, 0.3]).unwrap();
        let adapter = AdapterFactory::create(
            delta,
            test_metadata(1),
            [1u8; 32],
            100,
            vec![0u8; 64],
        )
        .unwrap();

        assert!(AdapterFactory::verify_hash(&adapter));

        // Tamper with adapter
        let mut tampered = adapter.clone();
        tampered.delta.data[0] = 999.0;
        assert!(!AdapterFactory::verify_hash(&tampered));
    }

    // PC-T38: Adapter composition
    #[test]
    fn test_adapter_composition() {
        let delta1 = EmbeddingVector::new(vec![0.1, 0.2]).unwrap();
        let delta2 = EmbeddingVector::new(vec![0.3, -0.1]).unwrap();

        let a1 = AdapterFactory::create(delta1, test_metadata(1), [1u8; 32], 100, vec![0u8; 64]).unwrap();
        let a2 = AdapterFactory::create(delta2, test_metadata(2), [2u8; 32], 200, vec![0u8; 64]).unwrap();

        let composed = compose_adapters(&a1, &a2).unwrap();
        assert!((composed.data[0] - 0.4).abs() < 1e-6);
        assert!((composed.data[1] - 0.1).abs() < 1e-6);
    }

    // PC-T39: Provenance chain
    #[test]
    fn test_provenance_chain() {
        let entry = ProvenanceEntry {
            creator: [1u8; 32],
            round: 1,
            checkpoint_height: 100,
            parent_adapter_hash: None,
            timestamp: 12345,
            signature: vec![0u8; 64],
        };

        let chain = ProvenanceChain::new(entry);
        assert_eq!(chain.len(), 1);
        assert!(chain.validate().is_ok());
    }

    // PC-T41: Adapter theft rejection
    #[test]
    fn test_provenance_chain_broken() {
        let entry1 = ProvenanceEntry {
            creator: [1u8; 32],
            round: 1,
            checkpoint_height: 100,
            parent_adapter_hash: None,
            timestamp: 12345,
            signature: vec![0u8; 64],
        };

        let entry2 = ProvenanceEntry {
            creator: [2u8; 32],
            round: 2,
            checkpoint_height: 200,
            parent_adapter_hash: Some([0xff; 32]), // Wrong parent hash
            timestamp: 12346,
            signature: vec![0u8; 64],
        };

        let mut chain = ProvenanceChain::new(entry1);
        chain.append(entry2);
        assert!(chain.validate().is_err());
    }
}
