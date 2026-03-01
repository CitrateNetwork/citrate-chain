//! Safety module — ensures learning never affects consensus state.
//!
//! Implements the critical invariant from Theorem 3 of Gradient Papers No. II.

use crate::adapters::{apply_lora, remove_lora, LoraAdapter};
use crate::embeddings::EmbeddingVector;
use crate::errors::{LearningError, LearningResult};
use crate::types::Hash;
use serde::{Deserialize, Serialize};
use tracing;

/// Learning mode controls how the learning layer participates.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LearningMode {
    /// Learning is completely disabled. No embeddings collected or aggregated.
    #[default]
    Disabled,
    /// Learning observes only. Collects embeddings but does not create adapters.
    Passive,
    /// Full learning pipeline active. Collects, aggregates, routes, creates adapters.
    Active,
}

impl std::fmt::Display for LearningMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LearningMode::Disabled => write!(f, "disabled"),
            LearningMode::Passive => write!(f, "passive"),
            LearningMode::Active => write!(f, "active"),
        }
    }
}

/// Audit entry for mode transitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeTransition {
    /// Previous mode.
    pub from: LearningMode,
    /// New mode.
    pub to: LearningMode,
    /// Timestamp of transition.
    pub timestamp: u64,
    /// Reason for transition.
    pub reason: String,
}

/// Safety guard that verifies the critical invariant.
///
/// Theorem 3: For any block B, state_root(execute(B, learning=on))
/// must equal state_root(execute(B, learning=off)).
pub struct SafetyGuard {
    mode: LearningMode,
    transition_log: Vec<ModeTransition>,
}

impl SafetyGuard {
    /// Create a new safety guard (defaults to Disabled).
    pub fn new() -> Self {
        Self {
            mode: LearningMode::Disabled,
            transition_log: Vec::new(),
        }
    }

    /// Get the current learning mode.
    pub fn mode(&self) -> LearningMode {
        self.mode
    }

    /// Switch learning mode with audit trail.
    pub fn switch_mode(&mut self, new_mode: LearningMode, reason: &str) {
        let old_mode = self.mode;
        if old_mode == new_mode {
            return;
        }

        let transition = ModeTransition {
            from: old_mode,
            to: new_mode,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            reason: reason.to_string(),
        };

        tracing::info!(
            from = %old_mode,
            to = %new_mode,
            reason = reason,
            "Learning mode transition"
        );

        self.transition_log.push(transition);
        self.mode = new_mode;
    }

    /// Verify the safety invariant: state roots must match.
    ///
    /// This is the MOST CRITICAL check in the entire Paraconsensus system.
    pub fn verify_state_invariant(
        &self,
        state_root_with_learning: Hash,
        state_root_without_learning: Hash,
    ) -> LearningResult<()> {
        if state_root_with_learning != state_root_without_learning {
            let details = format!(
                "state root mismatch: with_learning={} without_learning={}",
                hex::encode(state_root_with_learning),
                hex::encode(state_root_without_learning),
            );

            tracing::error!(
                with = hex::encode(state_root_with_learning),
                without = hex::encode(state_root_without_learning),
                "SAFETY VIOLATION: learning affected consensus state"
            );

            return Err(LearningError::SafetyViolation { details });
        }

        Ok(())
    }

    /// Verify the adapter safety corollary (Theorem 3):
    /// apply(base, adapter) followed by remove(modified, base, adapter) must
    /// return the original base embedding exactly (within floating-point tolerance).
    ///
    /// This ensures LoRA adapters are cleanly reversible and cannot corrupt state.
    pub fn verify_adapter_safety(
        &self,
        base: &EmbeddingVector,
        adapter: &LoraAdapter,
    ) -> LearningResult<()> {
        let modified = apply_lora(base, adapter)?;
        let restored = remove_lora(&modified, base, adapter)?;

        let tolerance = 1e-5;
        for i in 0..base.dim() {
            let diff = (restored.data[i] - base.data[i]).abs();
            if diff > tolerance {
                return Err(LearningError::SafetyViolation {
                    details: format!(
                        "adapter apply+remove not identity at dim {}: base={}, restored={}, diff={}",
                        i, base.data[i], restored.data[i], diff
                    ),
                });
            }
        }

        Ok(())
    }

    /// Get the transition log.
    pub fn transition_log(&self) -> &[ModeTransition] {
        &self.transition_log
    }

    /// Check if learning is enabled (Passive or Active).
    pub fn is_enabled(&self) -> bool {
        self.mode != LearningMode::Disabled
    }

    /// Check if learning is fully active.
    pub fn is_active(&self) -> bool {
        self.mode == LearningMode::Active
    }
}

impl Default for SafetyGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_mode_is_disabled() {
        let guard = SafetyGuard::new();
        assert_eq!(guard.mode(), LearningMode::Disabled);
        assert!(!guard.is_enabled());
        assert!(!guard.is_active());
    }

    #[test]
    fn test_mode_switching() {
        let mut guard = SafetyGuard::new();

        guard.switch_mode(LearningMode::Passive, "testing");
        assert_eq!(guard.mode(), LearningMode::Passive);
        assert!(guard.is_enabled());
        assert!(!guard.is_active());

        guard.switch_mode(LearningMode::Active, "full activation");
        assert_eq!(guard.mode(), LearningMode::Active);
        assert!(guard.is_enabled());
        assert!(guard.is_active());

        assert_eq!(guard.transition_log().len(), 2);
    }

    #[test]
    fn test_redundant_switch_ignored() {
        let mut guard = SafetyGuard::new();
        guard.switch_mode(LearningMode::Disabled, "no-op");
        assert_eq!(guard.transition_log().len(), 0);
    }

    // PC-T43: Safety invariant — matching roots
    #[test]
    fn test_safety_invariant_pass() {
        let guard = SafetyGuard::new();
        let root = [0xABu8; 32];
        assert!(guard.verify_state_invariant(root, root).is_ok());
    }

    // Safety invariant — mismatching roots
    #[test]
    fn test_safety_invariant_fail() {
        let guard = SafetyGuard::new();
        let root_a = [0xABu8; 32];
        let root_b = [0xCDu8; 32];
        let result = guard.verify_state_invariant(root_a, root_b);
        assert!(result.is_err());
        match result {
            Err(LearningError::SafetyViolation { details }) => {
                assert!(details.contains("mismatch"));
            }
            _ => panic!("expected SafetyViolation"),
        }
    }

    #[test]
    fn test_transition_log_audit() {
        let mut guard = SafetyGuard::new();
        guard.switch_mode(LearningMode::Passive, "initial setup");
        guard.switch_mode(LearningMode::Active, "ready for production");
        guard.switch_mode(LearningMode::Disabled, "emergency shutdown");

        let log = guard.transition_log();
        assert_eq!(log.len(), 3);
        assert_eq!(log[0].from, LearningMode::Disabled);
        assert_eq!(log[0].to, LearningMode::Passive);
        assert_eq!(log[2].to, LearningMode::Disabled);
    }

    // ========================================================================
    // Sprint O: Adapter Safety Tests (Theorem 3 corollary)
    // ========================================================================

    fn make_test_adapter(dim: usize) -> LoraAdapter {
        use crate::adapters::{AdapterFactory, AdapterMetadata};
        let embedding = EmbeddingVector::new(vec![1.0; dim]).unwrap();
        AdapterFactory::create_lora(
            &embedding,
            2,
            AdapterMetadata {
                name: "safety-test".to_string(),
                description: "test".to_string(),
                round: 1,
                participant_count: 5,
                created_at: 12345,
            },
            [1u8; 32],
            100,
            vec![0u8; 64],
        )
        .unwrap()
    }

    // PC-T44: Adapter apply+remove = identity (Theorem 3 corollary)
    #[test]
    fn test_adapter_apply_remove_identity() {
        let guard = SafetyGuard::new();
        let base = EmbeddingVector::new(vec![1.0, 2.0, 3.0, 4.0]).unwrap();
        let adapter = make_test_adapter(4);

        // Verify the safety invariant holds
        assert!(guard.verify_adapter_safety(&base, &adapter).is_ok());
    }

    // PC-T45: Mode transitions don't corrupt adapter safety
    #[test]
    fn test_mode_transitions_preserve_adapter_safety() {
        let mut guard = SafetyGuard::new();
        let base = EmbeddingVector::new(vec![0.5, -0.3, 1.2, 0.8]).unwrap();
        let adapter = make_test_adapter(4);

        // Apply in Disabled mode → verify
        assert!(guard.verify_adapter_safety(&base, &adapter).is_ok());

        // Switch to Active → verify still holds
        guard.switch_mode(LearningMode::Active, "activation");
        assert!(guard.verify_adapter_safety(&base, &adapter).is_ok());

        // Switch to Passive → verify still holds
        guard.switch_mode(LearningMode::Passive, "observation only");
        assert!(guard.verify_adapter_safety(&base, &adapter).is_ok());

        // Switch back to Disabled → verify still holds
        guard.switch_mode(LearningMode::Disabled, "shutdown");
        assert!(guard.verify_adapter_safety(&base, &adapter).is_ok());

        assert_eq!(guard.transition_log().len(), 3);
    }

    // Theorem 3: State roots identical with adapter (combined invariant)
    #[test]
    fn test_combined_state_and_adapter_safety() {
        let guard = SafetyGuard::new();

        // State root invariant
        let root = [0xABu8; 32];
        assert!(guard.verify_state_invariant(root, root).is_ok());

        // Adapter reversibility invariant
        let base = EmbeddingVector::new(vec![1.0, 2.0, 3.0]).unwrap();
        let adapter = make_test_adapter(3);
        assert!(guard.verify_adapter_safety(&base, &adapter).is_ok());

        // Both invariants hold simultaneously → Theorem 3 satisfied
    }
}
