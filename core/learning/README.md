# citrate-learning

Paraconsensus learning layer for Citrate -- Belnap FOUR lattice logic, federated embedding aggregation, OODA phase management, LoRA adapter creation, and consensus-safe Byzantine detection.

## Overview

citrate-learning implements the Paraconsistent Consensus protocol from Gradient Papers No. II. It provides a checkpoint-synchronized federated learning system that operates alongside the GhostDAG consensus engine without ever affecting consensus state integrity (Theorem 3 safety invariant).

The architecture revolves around six key components. The Belnap FOUR lattice provides four-valued logic (True, False, Both, Neither) for paraconsistent reasoning about epistemic states. Participants submit embedding vectors with per-dimension Belnap confidence values, which are aggregated at BFT checkpoint boundaries using either weighted mean or the dual-output paraconsistent aggregator. An MLP-based router directs aggregated embeddings to destinations using the Belnap state vector for paraconsistent awareness. The OODA cycle (Observe, Orient, Decide, Act) governs phase transitions. LoRA (Low-Rank Adaptation) adapters with full provenance chains are produced as the learning output.

A critical safety guard ensures that for any block B, the state root after executing B's transactions is identical whether learning is enabled or disabled. This invariant is enforced by the `SafetyGuard` and verified through property-based tests.

## Modules

| Module | File | Purpose |
|--------|------|---------|
| `lib` | `lib.rs` | Crate root with re-exports |
| `belnap` | `belnap.rs` | `BelnapValue` enum with join/meet/negation; `classify_belnap`, `reduce_belnap_states`, `softmax_weights`, `blue_scores_to_trust_weights` |
| `embeddings` | `embeddings.rs` | `EmbeddingVector` -- L2 norm, normalize, dot product, cosine similarity, euclidean distance; `EmbeddingSpace` for dimension management |
| `knowledge` | `knowledge.rs` | `KnowledgeState` -- embedding + per-dimension Belnap confidence per participant |
| `aggregation` | `aggregation.rs` | `Aggregator` trait, `WeightedMeanAggregator`, `ParaconsistentAggregator` (dual-output: embedding + Belnap state vector) |
| `routing` | `routing.rs` | `Router` trait, `MlpRouter` -- MLP-based routing with Belnap one-hot encoding, train_step support |
| `phases` | `phases.rs` | `OodaPhase` enum, `PhaseManager`, `MacroPhaseManager`, `LearningPipeline`, `NetworkLearningPhase` |
| `adapters` | `adapters.rs` | `LearningAdapter`, `LoraAdapter` (Low-Rank Adaptation), `AdapterFactory`, `AdapterRegistry`, `ProvenanceChain`, `apply_lora`/`remove_lora` |
| `safety` | `safety.rs` | `SafetyGuard` -- Theorem 3 invariant enforcement; `LearningMode` (Disabled/Passive/Active), mode transition audit log |
| `checkpoint` | `checkpoint.rs` | `LearningCheckpoint` -- snapshot of embeddings, aggregation results, Belnap state vectors, routing weights hashes at BFT boundaries |
| `verification` | `verification.rs` | `ByzantineDetector` -- statistical outlier detection, flag history, exclusion logic |
| `config` | `config.rs` | `LearningConfig` -- embedding dimensions, thresholds, LoRA rank, router parameters, Byzantine detection settings |
| `types` | `types.rs` | Core types: `Participant`, `ParticipantRole`, `LearningRound`, `Hash`, `PublicKey`, `Signature`, `TimestampedEmbedding` |
| `errors` | `errors.rs` | `LearningError` enum -- dimension mismatch, safety violation, Byzantine behavior, phase timeout, etc. |
| `metrics` | `metrics.rs` | Prometheus counters/gauges: rounds, aggregations, phase transitions, adapter creations, active participants |
| `storage` | `storage.rs` | `EmbeddingIndex` (DashMap-backed), `PhaseStore` for persisting phase state |

## Public API

### Key Traits

- **`Aggregator`** -- `fn aggregate(&self, embeddings: &[(EmbeddingVector, f32)]) -> LearningResult<EmbeddingVector>`
- **`Router`** -- `fn route(&self, query, e_agg, state_vector) -> LearningResult<RoutingDecision>` and `fn train_step(...)`

### Key Structs

- **`BelnapValue`** -- Four-valued logic with `join`, `meet`, `negation` operations
- **`EmbeddingVector`** -- Vector with `new`, `zeros`, `l2_norm`, `normalize`, `dot`, `cosine_similarity`, `euclidean_distance`
- **`KnowledgeState`** -- Embedding + Belnap confidence per participant
- **`ParaconsistentAggregator`** -- Dual-output aggregation returning `AggregationResult` (embedding + state vector + confidence)
- **`MlpRouter`** -- MLP routing with Belnap state vector awareness
- **`LearningPipeline`** -- Full OODA cycle orchestrator
- **`LoraAdapter`** -- Low-Rank Adaptation with provenance chain
- **`SafetyGuard`** -- Mode management (Disabled/Passive/Active) with state root verification
- **`LearningCheckpoint`** -- Checkpoint data structure with embedding snapshot, aggregation result, routing weights hash
- **`ByzantineDetector`** -- Outlier detection and participant exclusion

### Re-exports

The crate root re-exports the most commonly used types: `BelnapValue`, `EmbeddingVector`, `EmbeddingSpace`, `KnowledgeState`, `LearningConfig`, `LearningError`, `LearningMode`, `SafetyGuard`, `LearningCheckpoint`, `OodaPhase`, `Participant`, `LoraAdapter`, `AdapterFactory`, `AdapterRegistry`, and aggregator/router types.

## Tests

```bash
cargo test -p citrate-learning
```

272 tests (154 unit + 118 integration), all passing. Includes property-based tests via `proptest` for Belnap lattice laws and safety invariant verification.

## Dependencies

| Dependency | Purpose |
|-----------|---------|
| `sha3` | Hashing for adapter IDs and provenance |
| `ed25519-dalek` | Signature types for provenance chains |
| `dashmap` | Lock-free concurrent embedding index |
| `prometheus` | Metrics counters and gauges |
| `parking_lot` | Fast synchronization primitives |
| `chrono` | Timestamps |
| `proptest` (dev) | Property-based testing for lattice laws |
| `criterion` (dev) | Benchmarking |
