//! OODA phase transition protocol.
//!
//! Implements Algorithm 3 and Definition 7 from Gradient Papers No. II.

use crate::aggregation::{AggregationInput, AggregationResult, ParaconsistentAggregator};
use crate::config::LearningConfig;
use crate::embeddings::EmbeddingVector;
use crate::errors::{LearningError, LearningResult};
use crate::routing::{MlpRouter, Router, RoutingDecision};
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// The four phases of the OODA learning cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OodaPhase {
    /// Collect embeddings from participants.
    Observe,
    /// Aggregate and analyze collected embeddings.
    Orient,
    /// Route aggregated results to destinations.
    Decide,
    /// Apply decisions (create adapters, update states).
    Act,
}

impl OodaPhase {
    /// Get the next phase in the OODA cycle.
    pub fn next(self) -> Self {
        match self {
            OodaPhase::Observe => OodaPhase::Orient,
            OodaPhase::Orient => OodaPhase::Decide,
            OodaPhase::Decide => OodaPhase::Act,
            OodaPhase::Act => OodaPhase::Observe,
        }
    }

    /// Get display name.
    pub fn name(&self) -> &'static str {
        match self {
            OodaPhase::Observe => "Observe",
            OodaPhase::Orient => "Orient",
            OodaPhase::Decide => "Decide",
            OodaPhase::Act => "Act",
        }
    }
}

impl std::fmt::Display for OodaPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// State of a learning phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseState {
    /// Current phase.
    pub phase: OodaPhase,

    /// Round number.
    pub round: u64,

    /// Number of participants that have submitted in this phase.
    pub submissions: usize,

    /// Whether the phase's completion condition has been met.
    pub condition_met: bool,

    /// Phase start timestamp (milliseconds since epoch).
    pub started_at_ms: u64,
}

/// Manages phase transitions for the OODA learning cycle.
pub struct PhaseManager {
    state: PhaseState,
    config: LearningConfig,
    /// Instant when the current phase started (not serialized).
    phase_start: Instant,
}

impl PhaseManager {
    /// Create a new phase manager starting at Observe.
    pub fn new(config: LearningConfig) -> Self {
        Self {
            state: PhaseState {
                phase: OodaPhase::Observe,
                round: 0,
                submissions: 0,
                condition_met: false,
                started_at_ms: chrono::Utc::now().timestamp_millis() as u64,
            },
            config,
            phase_start: Instant::now(),
        }
    }

    /// Get the current phase.
    pub fn current_phase(&self) -> OodaPhase {
        self.state.phase
    }

    /// Get the current round.
    pub fn current_round(&self) -> u64 {
        self.state.round
    }

    /// Get time elapsed in current phase.
    pub fn elapsed_ms(&self) -> u64 {
        self.phase_start.elapsed().as_millis() as u64
    }

    /// Record a submission in the current phase.
    pub fn record_submission(&mut self) {
        self.state.submissions += 1;
    }

    /// Mark the current phase's condition as met.
    pub fn mark_condition_met(&mut self) {
        self.state.condition_met = true;
    }

    /// Check if the current phase can transition.
    pub fn can_transition(&self) -> bool {
        // Condition met explicitly
        if self.state.condition_met {
            return true;
        }

        // Timeout
        if self.elapsed_ms() >= self.config.phase_timeout_ms {
            return true;
        }

        // Phase-specific conditions
        match self.state.phase {
            OodaPhase::Observe => {
                self.state.submissions >= self.config.min_participants
            }
            OodaPhase::Orient | OodaPhase::Decide | OodaPhase::Act => {
                self.state.condition_met
            }
        }
    }

    /// Attempt to transition to the next phase.
    pub fn transition(&mut self) -> LearningResult<OodaPhase> {
        if !self.can_transition() {
            return Err(LearningError::InvalidPhaseTransition {
                from: self.state.phase.name().to_string(),
                to: self.state.phase.next().name().to_string(),
            });
        }

        let old_phase = self.state.phase;
        let new_phase = old_phase.next();

        tracing::info!(
            from = %old_phase,
            to = %new_phase,
            round = self.state.round,
            elapsed_ms = self.elapsed_ms(),
            submissions = self.state.submissions,
            "Phase transition"
        );

        // If completing Act → Observe, increment round
        if old_phase == OodaPhase::Act {
            self.state.round += 1;
        }

        self.state.phase = new_phase;
        self.state.submissions = 0;
        self.state.condition_met = false;
        self.state.started_at_ms = chrono::Utc::now().timestamp_millis() as u64;
        self.phase_start = Instant::now();

        Ok(new_phase)
    }

    /// Get the current phase state for serialization.
    pub fn state(&self) -> &PhaseState {
        &self.state
    }

    /// Restore from a serialized phase state.
    pub fn restore(state: PhaseState, config: LearningConfig) -> Self {
        Self {
            state,
            config,
            phase_start: Instant::now(),
        }
    }
}

// ---------------------------------------------------------------------------
// Macro-Phase State Machine (Paper II §5)
// ---------------------------------------------------------------------------

/// Network-level learning phase (macro-phase).
///
/// Distinct from the per-checkpoint OODA micro-cycle. The macro-phase
/// governs what capabilities are active network-wide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkLearningPhase {
    /// Phase 1: Embeddings collected, no routing, no adapters.
    Collection,
    /// Phase 2: Router trained and producing routing decisions.
    RoutingActive,
    /// Phase 3: Adapters generated and applied. Full paraconsensus pipeline.
    FullSystem,
}

impl NetworkLearningPhase {
    /// Display name.
    pub fn name(&self) -> &'static str {
        match self {
            NetworkLearningPhase::Collection => "Collection",
            NetworkLearningPhase::RoutingActive => "RoutingActive",
            NetworkLearningPhase::FullSystem => "FullSystem",
        }
    }
}

impl std::fmt::Display for NetworkLearningPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Manages macro-phase transitions based on checkpoint-level metrics.
///
/// Transition criteria:
/// - Collection → RoutingActive: confidence mean > threshold for N consecutive checkpoints
/// - RoutingActive → FullSystem: router loss < threshold for M consecutive checkpoints
pub struct MacroPhaseManager {
    phase: NetworkLearningPhase,
    /// Consecutive checkpoints meeting the current transition condition.
    consecutive_above: u64,
    config: LearningConfig,
}

impl MacroPhaseManager {
    /// Create a new manager starting at Collection.
    pub fn new(config: LearningConfig) -> Self {
        Self {
            phase: NetworkLearningPhase::Collection,
            consecutive_above: 0,
            config,
        }
    }

    /// Get the current macro-phase.
    pub fn current_phase(&self) -> NetworkLearningPhase {
        self.phase
    }

    /// Whether routing is active (RoutingActive or FullSystem).
    pub fn can_route(&self) -> bool {
        matches!(
            self.phase,
            NetworkLearningPhase::RoutingActive | NetworkLearningPhase::FullSystem
        )
    }

    /// Whether adapters can be generated (FullSystem only).
    pub fn can_adapt(&self) -> bool {
        self.phase == NetworkLearningPhase::FullSystem
    }

    /// Evaluate a checkpoint's metrics and potentially transition macro-phase.
    ///
    /// - `confidence_mean`: mean of the confidence vector from aggregation (0.0-1.0).
    /// - `router_loss`: current router training loss (None if not yet training).
    ///
    /// Returns Some(new_phase) if a transition occurred.
    pub fn evaluate_checkpoint(
        &mut self,
        confidence_mean: f32,
        router_loss: Option<f32>,
    ) -> Option<NetworkLearningPhase> {
        match self.phase {
            NetworkLearningPhase::Collection => {
                if confidence_mean >= self.config.macro_confidence_threshold {
                    self.consecutive_above += 1;
                } else {
                    self.consecutive_above = 0;
                }

                if self.consecutive_above >= self.config.macro_consecutive_checkpoints {
                    tracing::info!(
                        from = %self.phase,
                        to = "RoutingActive",
                        consecutive = self.consecutive_above,
                        confidence_mean,
                        "Macro-phase transition"
                    );
                    self.phase = NetworkLearningPhase::RoutingActive;
                    self.consecutive_above = 0;
                    return Some(NetworkLearningPhase::RoutingActive);
                }
            }
            NetworkLearningPhase::RoutingActive => {
                if let Some(loss) = router_loss {
                    if loss < self.config.macro_loss_threshold {
                        self.consecutive_above += 1;
                    } else {
                        self.consecutive_above = 0;
                    }

                    if self.consecutive_above >= self.config.macro_consecutive_checkpoints {
                        tracing::info!(
                            from = %self.phase,
                            to = "FullSystem",
                            consecutive = self.consecutive_above,
                            router_loss = loss,
                            "Macro-phase transition"
                        );
                        self.phase = NetworkLearningPhase::FullSystem;
                        self.consecutive_above = 0;
                        return Some(NetworkLearningPhase::FullSystem);
                    }
                }
            }
            NetworkLearningPhase::FullSystem => {
                // Terminal phase — no further transitions.
            }
        }
        None
    }

    /// Restore from a persisted state.
    pub fn restore(phase: NetworkLearningPhase, config: LearningConfig) -> Self {
        Self {
            phase,
            consecutive_above: 0,
            config,
        }
    }
}

// ---------------------------------------------------------------------------
// Orient-Decide-Act Pipeline (WP-N.5, Paper II §4)
// ---------------------------------------------------------------------------

/// Result of a pipeline execution cycle.
#[derive(Debug)]
pub struct PipelineResult {
    /// Aggregation output from the Orient phase.
    pub aggregation: AggregationResult,
    /// Routing decision from the Decide phase.
    pub routing: RoutingDecision,
}

/// Lightweight coordinator for the orient → decide → act pipeline.
///
/// Wires the aggregator's dual output into the router:
/// - `orient()` — runs paraconsistent aggregation
/// - `decide()` — feeds (query, e_agg, state_vector) into the router
/// - `execute_cycle()` — runs the full orient-decide-act pipeline
pub struct LearningPipeline {
    aggregator: ParaconsistentAggregator,
    router: MlpRouter,
}

impl LearningPipeline {
    /// Create a pipeline for the given embedding dimension.
    pub fn new(config: &LearningConfig) -> Self {
        Self {
            aggregator: ParaconsistentAggregator::new(config.embedding_dimensions),
            router: MlpRouter::new(
                config.embedding_dimensions,
                config.router_hidden_dim,
                config.router_num_destinations,
                42, // deterministic seed for pipeline
            ),
        }
    }

    /// Orient phase: run paraconsistent aggregation on participant inputs.
    pub fn orient(&self, input: &AggregationInput<'_>) -> LearningResult<AggregationResult> {
        self.aggregator.aggregate_paraconsistent(input)
    }

    /// Decide phase: route the aggregation result.
    pub fn decide(
        &self,
        query: &EmbeddingVector,
        agg_result: &AggregationResult,
    ) -> LearningResult<RoutingDecision> {
        self.router
            .route(query, &agg_result.embedding, &agg_result.state_vector)
    }

    /// Act phase: dispatch the routing decision.
    ///
    /// Currently a stub returning the decision index. Sprint O will add
    /// adapter generation and application here.
    pub fn act(&self, decision: &RoutingDecision) -> LearningResult<usize> {
        Ok(decision.selected)
    }

    /// Execute a full orient → decide → act cycle.
    pub fn execute_cycle(
        &self,
        query: &EmbeddingVector,
        input: &AggregationInput<'_>,
    ) -> LearningResult<PipelineResult> {
        let aggregation = self.orient(input)?;
        let routing = self.decide(query, &aggregation)?;
        let _dest = self.act(&routing)?;
        Ok(PipelineResult {
            aggregation,
            routing,
        })
    }

    /// Get a mutable reference to the router for training.
    pub fn router_mut(&mut self) -> &mut MlpRouter {
        &mut self.router
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> LearningConfig {
        LearningConfig {
            min_participants: 2,
            phase_timeout_ms: 100, // Short timeout for tests
            ..LearningConfig::default()
        }
    }

    // PC-T26: Observe → Orient
    #[test]
    fn test_observe_to_orient() {
        let mut pm = PhaseManager::new(test_config());
        assert_eq!(pm.current_phase(), OodaPhase::Observe);

        // Not enough submissions
        pm.record_submission();
        assert!(!pm.can_transition());

        // Enough submissions
        pm.record_submission();
        assert!(pm.can_transition());

        let next = pm.transition().unwrap();
        assert_eq!(next, OodaPhase::Orient);
    }

    // PC-T27: Orient → Decide
    #[test]
    fn test_orient_to_decide() {
        let mut pm = PhaseManager::new(test_config());
        pm.record_submission();
        pm.record_submission();
        pm.transition().unwrap(); // → Orient

        assert_eq!(pm.current_phase(), OodaPhase::Orient);
        assert!(!pm.can_transition()); // Condition not met

        pm.mark_condition_met();
        assert!(pm.can_transition());

        let next = pm.transition().unwrap();
        assert_eq!(next, OodaPhase::Decide);
    }

    // PC-T28: Decide → Act
    #[test]
    fn test_decide_to_act() {
        let mut pm = PhaseManager::new(test_config());
        // Advance to Decide
        pm.record_submission();
        pm.record_submission();
        pm.transition().unwrap(); // → Orient
        pm.mark_condition_met();
        pm.transition().unwrap(); // → Decide

        assert_eq!(pm.current_phase(), OodaPhase::Decide);
        pm.mark_condition_met();
        let next = pm.transition().unwrap();
        assert_eq!(next, OodaPhase::Act);
    }

    // PC-T29: Full OODA cycle
    #[test]
    fn test_full_ooda_cycle() {
        let mut pm = PhaseManager::new(test_config());
        assert_eq!(pm.current_round(), 0);

        // Observe → Orient
        pm.record_submission();
        pm.record_submission();
        pm.transition().unwrap();

        // Orient → Decide
        pm.mark_condition_met();
        pm.transition().unwrap();

        // Decide → Act
        pm.mark_condition_met();
        pm.transition().unwrap();

        // Act → Observe (new round)
        pm.mark_condition_met();
        pm.transition().unwrap();

        assert_eq!(pm.current_phase(), OodaPhase::Observe);
        assert_eq!(pm.current_round(), 1);
    }

    // PC-T30: Phase timeout
    #[test]
    fn test_phase_timeout() {
        let config = LearningConfig {
            phase_timeout_ms: 1, // 1ms timeout
            ..test_config()
        };
        let mut pm = PhaseManager::new(config);

        // Wait for timeout
        std::thread::sleep(std::time::Duration::from_millis(5));

        assert!(pm.can_transition());
        let next = pm.transition().unwrap();
        assert_eq!(next, OodaPhase::Orient);
    }

    // PC-T34: Phase state serialization
    #[test]
    fn test_phase_state_serialization() {
        let state = PhaseState {
            phase: OodaPhase::Orient,
            round: 5,
            submissions: 3,
            condition_met: true,
            started_at_ms: 12345,
        };

        let json = serde_json::to_string(&state).unwrap();
        let deserialized: PhaseState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.phase, OodaPhase::Orient);
        assert_eq!(deserialized.round, 5);
        assert!(deserialized.condition_met);
    }

    #[test]
    fn test_invalid_transition() {
        let pm = PhaseManager::new(test_config());
        // Can't transition without meeting condition
        assert!(!pm.can_transition());
    }

    // PC-T29a: Macro-phase Collection → RoutingActive
    #[test]
    fn test_macro_phase_collection_to_routing() {
        let config = LearningConfig {
            macro_confidence_threshold: 0.6,
            macro_consecutive_checkpoints: 3,
            ..LearningConfig::default()
        };
        let mut mgr = MacroPhaseManager::new(config);
        assert_eq!(mgr.current_phase(), NetworkLearningPhase::Collection);
        assert!(!mgr.can_route());
        assert!(!mgr.can_adapt());

        // Below threshold — no transition
        assert!(mgr.evaluate_checkpoint(0.4, None).is_none());
        assert_eq!(mgr.current_phase(), NetworkLearningPhase::Collection);

        // Above threshold, but need 3 consecutive
        assert!(mgr.evaluate_checkpoint(0.7, None).is_none());
        assert!(mgr.evaluate_checkpoint(0.8, None).is_none());

        // 3rd consecutive → transition
        let result = mgr.evaluate_checkpoint(0.65, None);
        assert_eq!(result, Some(NetworkLearningPhase::RoutingActive));
        assert!(mgr.can_route());
        assert!(!mgr.can_adapt());
    }

    // PC-T29b: Macro-phase RoutingActive → FullSystem
    #[test]
    fn test_macro_phase_routing_to_full_system() {
        let config = LearningConfig {
            macro_confidence_threshold: 0.5,
            macro_loss_threshold: 0.5,
            macro_consecutive_checkpoints: 2,
            ..LearningConfig::default()
        };
        let mut mgr = MacroPhaseManager::new(config);

        // Fast-forward to RoutingActive
        mgr.evaluate_checkpoint(0.8, None);
        mgr.evaluate_checkpoint(0.8, None);
        assert_eq!(mgr.current_phase(), NetworkLearningPhase::RoutingActive);

        // Loss too high — no transition
        assert!(mgr.evaluate_checkpoint(0.3, Some(0.8)).is_none());

        // Loss below threshold, need 2 consecutive
        assert!(mgr.evaluate_checkpoint(0.3, Some(0.3)).is_none());

        // 2nd consecutive → FullSystem
        let result = mgr.evaluate_checkpoint(0.3, Some(0.2));
        assert_eq!(result, Some(NetworkLearningPhase::FullSystem));
        assert!(mgr.can_route());
        assert!(mgr.can_adapt());
    }

    #[test]
    fn test_macro_phase_reset_on_regression() {
        let config = LearningConfig {
            macro_confidence_threshold: 0.6,
            macro_consecutive_checkpoints: 3,
            ..LearningConfig::default()
        };
        let mut mgr = MacroPhaseManager::new(config);

        // 2 above threshold, then drops below — resets counter
        mgr.evaluate_checkpoint(0.7, None);
        mgr.evaluate_checkpoint(0.8, None);
        mgr.evaluate_checkpoint(0.4, None); // Reset!
        mgr.evaluate_checkpoint(0.7, None);
        assert_eq!(mgr.current_phase(), NetworkLearningPhase::Collection);
    }

    // WP-N.5: Pipeline tests

    #[test]
    fn test_pipeline_aggregation_feeds_router() {
        let config = LearningConfig::default();
        let dim = 4;
        let config = LearningConfig {
            embedding_dimensions: dim,
            ..config
        };
        let pipeline = LearningPipeline::new(&config);

        let e1 = EmbeddingVector::new(vec![1.0, 0.0, 0.5, 0.5]).unwrap();
        let e2 = EmbeddingVector::new(vec![0.8, 0.2, 0.4, 0.6]).unwrap();
        let conf = vec![0.9; dim];
        let input = AggregationInput {
            embeddings: &[&e1, &e2],
            confidences: &[&conf, &conf],
            blue_scores: &[1.0, 1.0],
            temperature: 1.0,
            theta_high: 0.8,
            theta_low: 0.3,
        };

        // Orient produces result
        let agg_result = pipeline.orient(&input).unwrap();
        assert_eq!(agg_result.embedding.dim(), dim);
        assert_eq!(agg_result.state_vector.len(), dim);

        // Decide uses the aggregation result
        let query = EmbeddingVector::new(vec![0.5, 0.5, 0.5, 0.5]).unwrap();
        let decision = pipeline.decide(&query, &agg_result).unwrap();
        assert!(decision.selected < config.router_num_destinations);
    }

    #[test]
    fn test_pipeline_full_cycle() {
        let dim = 4;
        let config = LearningConfig {
            embedding_dimensions: dim,
            ..LearningConfig::default()
        };
        let pipeline = LearningPipeline::new(&config);

        let e1 = EmbeddingVector::new(vec![1.0, 0.0, 0.0, 1.0]).unwrap();
        let e2 = EmbeddingVector::new(vec![0.0, 1.0, 1.0, 0.0]).unwrap();
        let conf = vec![0.9; dim];
        let query = EmbeddingVector::new(vec![0.5, 0.5, 0.5, 0.5]).unwrap();
        let input = AggregationInput {
            embeddings: &[&e1, &e2],
            confidences: &[&conf, &conf],
            blue_scores: &[1.0, 1.0],
            temperature: 1.0,
            theta_high: 0.8,
            theta_low: 0.3,
        };

        let result = pipeline.execute_cycle(&query, &input).unwrap();
        assert_eq!(result.aggregation.embedding.dim(), dim);
        assert!(result.routing.selected < config.router_num_destinations);
    }

    // PC-T31: Concurrent phase transitions
    #[test]
    fn test_concurrent_phase_transitions() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let pm = Arc::new(Mutex::new(PhaseManager::new(LearningConfig {
            min_participants: 1,
            phase_timeout_ms: 100,
            ..LearningConfig::default()
        })));

        let mut handles = vec![];

        // Spawn 10 threads, each attempting to record submissions and transition
        for _ in 0..10 {
            let pm_clone = Arc::clone(&pm);
            handles.push(thread::spawn(move || {
                let mut pm = pm_clone.lock().unwrap();
                pm.record_submission();
                if pm.can_transition() {
                    let _ = pm.transition();
                }
            }));
        }

        for h in handles {
            h.join().unwrap(); // No panics
        }

        // PhaseManager is still in a valid state
        let pm = pm.lock().unwrap();
        let phase = pm.current_phase();
        assert!(
            phase == OodaPhase::Observe
                || phase == OodaPhase::Orient
                || phase == OodaPhase::Decide
                || phase == OodaPhase::Act,
            "phase must be a valid OODA phase"
        );
    }

    #[test]
    fn test_macro_phase_full_system_is_terminal() {
        let config = LearningConfig {
            macro_confidence_threshold: 0.5,
            macro_loss_threshold: 0.5,
            macro_consecutive_checkpoints: 1,
            ..LearningConfig::default()
        };
        let mut mgr = MacroPhaseManager::new(config);

        // Fast-forward to FullSystem
        mgr.evaluate_checkpoint(0.8, None);
        assert_eq!(mgr.current_phase(), NetworkLearningPhase::RoutingActive);
        mgr.evaluate_checkpoint(0.3, Some(0.2));
        assert_eq!(mgr.current_phase(), NetworkLearningPhase::FullSystem);

        // No further transitions possible
        assert!(mgr.evaluate_checkpoint(0.9, Some(0.01)).is_none());
        assert_eq!(mgr.current_phase(), NetworkLearningPhase::FullSystem);
    }
}
