//! OODA phase transition protocol.
//!
//! Implements Algorithm 3 and Definition 7 from Gradient Papers No. II.

use crate::config::LearningConfig;
use crate::errors::{LearningError, LearningResult};
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
}
