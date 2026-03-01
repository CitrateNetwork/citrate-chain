//! Embedding storage index.
//!
//! Implements Data Structure 4 from Gradient Papers No. II.

use crate::embeddings::EmbeddingVector;
use crate::types::{PublicKey, TimestampedEmbedding};
use dashmap::DashMap;

/// Thread-safe embedding storage index.
pub struct EmbeddingIndex {
    inner: DashMap<PublicKey, TimestampedEmbedding>,
}

impl EmbeddingIndex {
    /// Create a new empty index.
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }

    /// Insert or update an embedding for a participant (no confidence data).
    pub fn insert(
        &self,
        key: PublicKey,
        embedding: EmbeddingVector,
        round: u64,
        timestamp: u64,
    ) {
        self.inner.insert(
            key,
            TimestampedEmbedding {
                embedding,
                round,
                timestamp,
                submitter: key,
                confidence: None,
            },
        );
    }

    /// Insert or update an embedding with per-dimension confidence values.
    pub fn insert_with_confidence(
        &self,
        key: PublicKey,
        embedding: EmbeddingVector,
        confidence: Vec<f32>,
        round: u64,
        timestamp: u64,
    ) {
        self.inner.insert(
            key,
            TimestampedEmbedding {
                embedding,
                round,
                timestamp,
                submitter: key,
                confidence: Some(confidence),
            },
        );
    }

    /// Get the embedding for a participant.
    pub fn get(&self, key: &PublicKey) -> Option<TimestampedEmbedding> {
        self.inner.get(key).map(|r| r.value().clone())
    }

    /// Remove a participant's embedding.
    pub fn remove(&self, key: &PublicKey) -> Option<TimestampedEmbedding> {
        self.inner.remove(key).map(|(_, v)| v)
    }

    /// List all embeddings from a specific round.
    pub fn list_by_round(&self, round: u64) -> Vec<(PublicKey, EmbeddingVector)> {
        self.inner
            .iter()
            .filter(|r| r.value().round == round)
            .map(|r| (*r.key(), r.value().embedding.clone()))
            .collect()
    }

    /// Prune embeddings older than `max_age_rounds` relative to `current_round`.
    ///
    /// Returns the number of entries removed.
    pub fn prune_stale(&self, max_age_rounds: u64, current_round: u64) -> usize {
        let min_round = current_round.saturating_sub(max_age_rounds);
        let stale_keys: Vec<PublicKey> = self
            .inner
            .iter()
            .filter(|r| r.value().round < min_round)
            .map(|r| *r.key())
            .collect();

        let count = stale_keys.len();
        for key in stale_keys {
            self.inner.remove(&key);
        }
        count
    }

    /// Get the number of stored embeddings.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the index is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get all embeddings as a snapshot.
    pub fn snapshot(&self) -> Vec<(PublicKey, TimestampedEmbedding)> {
        self.inner
            .iter()
            .map(|r| (*r.key(), r.value().clone()))
            .collect()
    }
}

impl Default for EmbeddingIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crud_operations() {
        let index = EmbeddingIndex::new();
        let pk = [1u8; 32];
        let emb = EmbeddingVector::zeros(4);

        // Insert
        index.insert(pk, emb.clone(), 1, 100);
        assert_eq!(index.len(), 1);

        // Get
        let retrieved = index.get(&pk).unwrap();
        assert_eq!(retrieved.round, 1);

        // Update
        index.insert(pk, emb, 2, 200);
        let updated = index.get(&pk).unwrap();
        assert_eq!(updated.round, 2);

        // Remove
        index.remove(&pk);
        assert!(index.get(&pk).is_none());
        assert_eq!(index.len(), 0);
    }

    #[test]
    fn test_list_by_round() {
        let index = EmbeddingIndex::new();
        index.insert([1u8; 32], EmbeddingVector::zeros(2), 5, 100);
        index.insert([2u8; 32], EmbeddingVector::zeros(2), 5, 100);
        index.insert([3u8; 32], EmbeddingVector::zeros(2), 6, 200);

        let round_5 = index.list_by_round(5);
        assert_eq!(round_5.len(), 2);

        let round_6 = index.list_by_round(6);
        assert_eq!(round_6.len(), 1);
    }

    #[test]
    fn test_prune_stale() {
        let index = EmbeddingIndex::new();
        index.insert([1u8; 32], EmbeddingVector::zeros(2), 1, 100);
        index.insert([2u8; 32], EmbeddingVector::zeros(2), 5, 200);
        index.insert([3u8; 32], EmbeddingVector::zeros(2), 10, 300);

        // Current round = 12, max_age = 5 → prune round < 7
        let pruned = index.prune_stale(5, 12);
        assert_eq!(pruned, 2); // Rounds 1 and 5 pruned
        assert_eq!(index.len(), 1); // Only round 10 remains
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let index = Arc::new(EmbeddingIndex::new());
        let mut handles = vec![];

        // Spawn 10 threads, each inserting
        for i in 0..10u8 {
            let idx = Arc::clone(&index);
            handles.push(thread::spawn(move || {
                let mut pk = [0u8; 32];
                pk[0] = i;
                idx.insert(pk, EmbeddingVector::zeros(4), i as u64, 100);
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(index.len(), 10);
    }

    #[test]
    fn test_insert_with_confidence() {
        let index = EmbeddingIndex::new();
        let pk = [5u8; 32];
        let emb = EmbeddingVector::new(vec![0.1, 0.2, 0.3]).unwrap();
        let conf = vec![0.9, 0.5, 0.1];

        index.insert_with_confidence(pk, emb, conf.clone(), 3, 500);

        let retrieved = index.get(&pk).unwrap();
        assert_eq!(retrieved.round, 3);
        let rc = retrieved.confidence.unwrap();
        assert_eq!(rc.len(), 3);
        assert!((rc[0] - 0.9).abs() < 1e-6);
        assert!((rc[2] - 0.1).abs() < 1e-6);
    }

    #[test]
    fn test_legacy_insert_no_confidence() {
        let index = EmbeddingIndex::new();
        let pk = [6u8; 32];
        let emb = EmbeddingVector::zeros(4);

        // Legacy insert should set confidence to None
        index.insert(pk, emb, 1, 100);

        let retrieved = index.get(&pk).unwrap();
        assert!(retrieved.confidence.is_none());
    }
}
