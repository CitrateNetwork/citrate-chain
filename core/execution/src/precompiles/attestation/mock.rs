// citrate/core/execution/src/precompiles/attestation/mock.rs
//
// RM-M3 — test-only mock attestation gates. ONLY visible under
// `#[cfg(test)]` so production binaries cannot link these in.

#![cfg(test)]

use super::types::{AttestationDecision, AttestationGate};
use crate::types::Address;

/// Test-only gate that allows every call. Use for unit tests
/// of inference logic where attestation is out of scope.
#[derive(Debug, Default)]
pub struct AlwaysAllow;

impl AttestationGate for AlwaysAllow {
    fn allow_inference(&self, _input: &[u8]) -> AttestationDecision {
        AttestationDecision::Allow {
            attested_provider: None,
        }
    }

    fn name(&self) -> &'static str {
        "test::AlwaysAllow"
    }
}

/// Test-only gate that allows iff the input begins with
/// `b"VALID:"`. Lets tests exercise both branches.
#[derive(Debug, Default)]
pub struct PrefixGate;

impl AttestationGate for PrefixGate {
    fn allow_inference(&self, input: &[u8]) -> AttestationDecision {
        const PREFIX: &[u8] = b"VALID:";
        if input.starts_with(PREFIX) {
            AttestationDecision::Allow {
                attested_provider: Some(Address([0xAB; 20])),
            }
        } else {
            AttestationDecision::Reject {
                reason: "test::PrefixGate: input does not begin with VALID:".to_string(),
            }
        }
    }

    fn name(&self) -> &'static str {
        "test::PrefixGate"
    }
}

#[test]
fn prefix_gate_allows_correct_prefix() {
    let gate = PrefixGate;
    let r = gate.allow_inference(b"VALID:hello");
    assert!(matches!(r, AttestationDecision::Allow { .. }));
}

#[test]
fn prefix_gate_rejects_wrong_prefix() {
    let gate = PrefixGate;
    let r = gate.allow_inference(b"INVALID");
    assert!(matches!(r, AttestationDecision::Reject { .. }));
}
