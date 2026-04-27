// citrate/core/execution/src/precompiles/attestation/mod.rs
//
// RM-M3 — TEE attestation gate scaffold (Phase 1).
//
// **Purpose:** introduce a trait-based gate that 0x0101
// MODEL_INFERENCE and 0x0102 BATCH_INFERENCE consult before
// running. The gate's decision determines whether the
// non-deterministic FP inference path is allowed in this call
// context.
//
// **Phase 1 (this sprint):** the gate trait + an always-reject
// default + wiring through the inference precompile. NO live
// attestation verification is included. Production behavior
// is unchanged from the C-01 + REM-N-03 fix: in
// `InferenceMode::Strict`, the precompile rejects with a
// C-01-flavored error message.
//
// **Phase 2 (future, blocked on CM-08 hardware delivery):** add
// `MaaPlusNras` impl that verifies Microsoft Azure Attestation
// (MAA) JWTs + NVIDIA Remote Attestation Service (NRAS) claims.
// On valid attestation, the gate returns `Allow {
// attested_provider }` and inference runs against an attested
// TEE-hosted model. Sprint planset:
// `.agentile/sprints/backlog/sprint-rm-m3-phase-2-tee-live.md`
// (pre-written).
//
// **Why this design:**
// 1. **Trait-based, not boolean-flag-based:** the existing
//    `allow_nondeterministic_inference: bool` was a temporary
//    measure during C-01 closure. Trait dispatch lets Phase 2
//    plug in a real verifier without touching the precompile
//    body.
// 2. **Always-reject default:** mainnet validator binaries that
//    don't override the gate get the safe default — inference
//    precompiles refuse to run. No silent allow-by-omission.
// 3. **Test-only mock:** `mock::AlwaysAllow` is gated behind
//    `#[cfg(test)]` so production builds cannot pull it in.

pub mod always_reject;
pub mod types;

#[cfg(test)]
pub mod mock;

pub use always_reject::AlwaysReject;
pub use types::{AttestationDecision, AttestationGate};
