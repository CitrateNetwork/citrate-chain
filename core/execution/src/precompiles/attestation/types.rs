// citrate/core/execution/src/precompiles/attestation/types.rs
//
// RM-M3 — types for the attestation gate.

use crate::types::Address;

/// Decision returned by `AttestationGate::allow_inference`.
#[derive(Debug, Clone)]
pub enum AttestationDecision {
    /// Inference may proceed. `attested_provider` is the
    /// address that the attestation establishes as the
    /// inference origin (Phase 2 sets this from MAA's
    /// `provider_address` claim; Phase 1 always uses None
    /// because there's no live verification yet).
    Allow {
        attested_provider: Option<Address>,
    },

    /// Inference is denied. The `reason` string surfaces in
    /// the precompile's error and is visible to the calling
    /// contract via `staticcall` revert data.
    Reject {
        reason: String,
    },
}

/// Trait that the inference precompile consults to decide
/// whether an inference call may run.
///
/// **Phase 1 (current):** the only impl is `AlwaysReject`,
/// which preserves the C-01 behavior — non-deterministic
/// inference is denied in production until a real attestation
/// path is wired.
///
/// **Phase 2 (future):** add `MaaPlusNras` impl that parses
/// the leading bytes of `input` as a TEE attestation blob,
/// verifies it against the on-chain attestation registry, and
/// returns `Allow` only on a valid + non-revoked attestation.
pub trait AttestationGate: Send + Sync + std::fmt::Debug {
    /// Inspect the inference input and decide whether to allow.
    ///
    /// **Input format expectations:**
    /// - For `AlwaysReject`: input is ignored.
    /// - For `MaaPlusNras` (Phase 2): the first N bytes are
    ///   expected to be a length-prefixed attestation blob;
    ///   the rest is the inference payload. The exact format
    ///   is pinned in `runbooks/TEE_ATTESTATION_ENABLE.md`.
    fn allow_inference(&self, input: &[u8]) -> AttestationDecision;

    /// Human-readable name of this gate impl. Used in logs
    /// and diagnostic error messages.
    fn name(&self) -> &'static str;
}
