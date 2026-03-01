//! Embedding storage index.
//!
//! Implements Data Structure 4 from Gradient Papers No. II.

use crate::embeddings::EmbeddingVector;
use crate::errors::{LearningError, LearningResult};
use crate::phases::{NetworkLearningPhase, OodaPhase, PhaseState};
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

// ---------------------------------------------------------------------------
// Phase State Persistence (WP-N.4, Paper II §4.1)
// ---------------------------------------------------------------------------

/// Thread-safe key-value store for OODA phase state and macro-phase persistence.
///
/// Allows the learning layer to recover its state after node restarts.
/// Stale non-Observe OODA phases are reset on recovery (interrupted round).
pub struct PhaseStore {
    inner: DashMap<String, String>,
}

impl PhaseStore {
    /// Create a new empty phase store.
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }

    /// Save the OODA phase state as JSON.
    ///
    /// On recovery, if the persisted phase is not `Observe`, the phase
    /// is considered interrupted and should be reset.
    pub fn save_phase_state(&self, state: &PhaseState) -> LearningResult<()> {
        let json = serde_json::to_string(state).map_err(|e| LearningError::Storage(e.to_string()))?;
        self.inner.insert("ooda_phase_state".to_string(), json);
        Ok(())
    }

    /// Load the OODA phase state from the store.
    ///
    /// Returns `None` if no state has been saved yet.
    pub fn load_phase_state(&self) -> LearningResult<Option<PhaseState>> {
        match self.inner.get("ooda_phase_state") {
            Some(json) => {
                let state: PhaseState = serde_json::from_str(json.value())
                    .map_err(|e| LearningError::Storage(e.to_string()))?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    /// Load the OODA phase state with interrupted-round recovery.
    ///
    /// If the persisted phase is anything other than `Observe`, the round
    /// was interrupted mid-cycle. In that case, reset the phase to `Observe`
    /// for the same round so that the cycle restarts cleanly.
    pub fn load_phase_state_with_recovery(&self) -> LearningResult<Option<PhaseState>> {
        match self.load_phase_state()? {
            Some(mut state) => {
                if state.phase != OodaPhase::Observe {
                    tracing::warn!(
                        interrupted_phase = %state.phase,
                        round = state.round,
                        "Interrupted OODA phase detected — resetting to Observe"
                    );
                    state.phase = OodaPhase::Observe;
                    state.submissions = 0;
                    state.condition_met = false;
                }
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    /// Save the macro-phase.
    pub fn save_macro_phase(&self, phase: NetworkLearningPhase) -> LearningResult<()> {
        let json = serde_json::to_string(&phase)
            .map_err(|e| LearningError::Storage(e.to_string()))?;
        self.inner.insert("macro_phase".to_string(), json);
        Ok(())
    }

    /// Load the macro-phase from the store.
    pub fn load_macro_phase(&self) -> LearningResult<Option<NetworkLearningPhase>> {
        match self.inner.get("macro_phase") {
            Some(json) => {
                let phase: NetworkLearningPhase = serde_json::from_str(json.value())
                    .map_err(|e| LearningError::Storage(e.to_string()))?;
                Ok(Some(phase))
            }
            None => Ok(None),
        }
    }
}

impl Default for PhaseStore {
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

    // --- WP-N.4: PhaseStore tests ---

    #[test]
    fn test_phase_state_roundtrip() {
        let store = PhaseStore::new();

        // No state initially
        assert!(store.load_phase_state().unwrap().is_none());

        // Save and load
        let state = PhaseState {
            phase: OodaPhase::Orient,
            round: 7,
            submissions: 4,
            condition_met: true,
            started_at_ms: 99999,
        };
        store.save_phase_state(&state).unwrap();

        let loaded = store.load_phase_state().unwrap().unwrap();
        assert_eq!(loaded.phase, OodaPhase::Orient);
        assert_eq!(loaded.round, 7);
        assert_eq!(loaded.submissions, 4);
        assert!(loaded.condition_met);
    }

    #[test]
    fn test_macro_phase_roundtrip() {
        let store = PhaseStore::new();

        assert!(store.load_macro_phase().unwrap().is_none());

        store.save_macro_phase(NetworkLearningPhase::RoutingActive).unwrap();
        let loaded = store.load_macro_phase().unwrap().unwrap();
        assert_eq!(loaded, NetworkLearningPhase::RoutingActive);

        // Overwrite
        store.save_macro_phase(NetworkLearningPhase::FullSystem).unwrap();
        let loaded = store.load_macro_phase().unwrap().unwrap();
        assert_eq!(loaded, NetworkLearningPhase::FullSystem);
    }

    #[test]
    fn test_interrupted_phase_recovery() {
        let store = PhaseStore::new();

        // Simulate a crash during Orient phase
        let state = PhaseState {
            phase: OodaPhase::Orient,
            round: 3,
            submissions: 2,
            condition_met: false,
            started_at_ms: 50000,
        };
        store.save_phase_state(&state).unwrap();

        // Recovery should reset to Observe
        let recovered = store.load_phase_state_with_recovery().unwrap().unwrap();
        assert_eq!(recovered.phase, OodaPhase::Observe);
        assert_eq!(recovered.round, 3); // Same round
        assert_eq!(recovered.submissions, 0);
        assert!(!recovered.condition_met);

        // If already in Observe, no reset needed
        let observe_state = PhaseState {
            phase: OodaPhase::Observe,
            round: 5,
            submissions: 1,
            condition_met: false,
            started_at_ms: 60000,
        };
        store.save_phase_state(&observe_state).unwrap();
        let loaded = store.load_phase_state_with_recovery().unwrap().unwrap();
        assert_eq!(loaded.phase, OodaPhase::Observe);
        assert_eq!(loaded.submissions, 1); // Not reset since already Observe
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
