// citrate/core/execution/src/precompiles/attestation/always_reject.rs
//
// RM-M3 — `AlwaysReject` is the production default for the
// AttestationGate. Until Phase 2 ships a live MAA+NRAS
// verifier, every inference call gets denied at the gate.

use super::types::{AttestationDecision, AttestationGate};

/// Production-default attestation gate: rejects every call.
///
/// **Why not just remove the gate entirely:** Phase 2 needs to
/// drop in a live verifier without touching `inference.rs`.
/// Trait dispatch through `Arc<dyn AttestationGate>` makes
/// that a one-line swap. The always-reject impl is the safe
/// default during the scaffold period.
#[derive(Debug, Default)]
pub struct AlwaysReject;

impl AlwaysReject {
    pub const fn new() -> Self {
        Self
    }
}

impl AttestationGate for AlwaysReject {
    fn allow_inference(&self, _input: &[u8]) -> AttestationDecision {
        AttestationDecision::Reject {
            reason: "RM-M3 Phase 1: TEE attestation gate denies inference. \
                     Phase 2 (live MAA+NRAS verifier) ships in CM-08. See \
                     runbooks/TEE_ATTESTATION_ENABLE.md."
                .to_string(),
        }
    }

    fn name(&self) -> &'static str {
        "AlwaysReject"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_reject_denies_arbitrary_input() {
        let gate = AlwaysReject::new();
        let inputs: &[&[u8]] = &[
            &[],
            b"random bytes",
            &[0u8; 1024],
            b"this looks like an MAA JWT prefix...",
        ];
        for input in inputs {
            match gate.allow_inference(input) {
                AttestationDecision::Reject { reason } => {
                    assert!(
                        reason.contains("RM-M3"),
                        "reject reason must reference RM-M3: {}",
                        reason
                    );
                }
                AttestationDecision::Allow { .. } => {
                    panic!("AlwaysReject must NEVER allow; got Allow for input {:?}", input);
                }
            }
        }
    }

    #[test]
    fn always_reject_name_is_stable() {
        assert_eq!(AlwaysReject::new().name(), "AlwaysReject");
    }
}
