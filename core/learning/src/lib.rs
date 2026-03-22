//! # citrate-learning
//!
//! Paraconsensus learning layer for the Citrate blockchain.
//!
//! Implements the Paraconsistent Consensus protocol from Gradient Papers No. II,
//! providing checkpoint-synchronized federated learning that never affects
//! consensus state integrity.
//!
//! ## Architecture
//!
//! The learning layer operates alongside the GhostDAG consensus engine:
//!
//! 1. **Belnap FOUR Lattice** — Four-valued logic for paraconsistent reasoning
//! 2. **Embeddings** — Vector representations with similarity metrics
//! 3. **Knowledge States** — Per-participant embedding + Belnap confidence
//! 4. **Aggregation** — Weighted mean at BFT checkpoints
//! 5. **Routing** — MLP-based routing of aggregated embeddings
//! 6. **Phases** — OODA cycle (Observe → Orient → Decide → Act)
//! 7. **Adapters** — LoRA (Low-Rank Adaptation) adapters with provenance chains
//! 8. **Safety** — Invariant: state roots identical ± learning
//!
//! ## Safety Invariant (Theorem 3)
//!
//! For any block B, the state root after executing B's transactions MUST be
//! identical whether learning is enabled or disabled. This is verified by
//! property-based tests in the `safety` module.

pub mod adapters;
pub mod aggregation;
pub mod belnap;
pub mod checkpoint;
pub mod config;
pub mod embeddings;
pub mod errors;
pub mod knowledge;
pub mod mentor;
pub mod metrics;
pub mod orchestration;
pub mod phases;
pub mod profile;
pub mod routing;
pub mod safety;
pub mod storage;
pub mod types;
pub mod verification;

// Re-export primary types for convenient access
pub use adapters::{AdapterFactory, AdapterRegistry, LearningAdapter, LoraAdapter};
pub use aggregation::{
    AggregationInput, AggregationResult, Aggregator, ParaconsistentAggregator,
    WeightedMeanAggregator,
};
pub use belnap::{
    blue_scores_to_trust_weights, classify_belnap, reduce_belnap_states, softmax_weights,
    BelnapValue,
};
pub use checkpoint::LearningCheckpoint;
pub use config::LearningConfig;
pub use embeddings::{EmbeddingSpace, EmbeddingVector};
pub use errors::LearningError;
pub use knowledge::KnowledgeState;
pub use phases::{LearningPipeline, MacroPhaseManager, NetworkLearningPhase, OodaPhase, PhaseManager};
pub use routing::{MlpRouter, Router};
pub use storage::PhaseStore;
pub use orchestration::{
    compute_learning_root, LearningCheckpointResult, LearningOrchestrator,
    LearningOrchestratorConfig, PeerEmbedding, PeerProfileKey, PeerProfileStore,
};
pub use profile::{ProfileComputer, PerformanceProfile as LocalPerformanceProfile};
pub use mentor::{
    generate_adapter_for_mentee, generate_delta_adapter, select_mentors, MentorPairing,
    MAX_MENTEES_PER_MENTOR, MIN_ACCURACY_GAP,
};
pub use safety::{LearningMode, SafetyGuard};
pub use types::{LearningRound, Participant};
