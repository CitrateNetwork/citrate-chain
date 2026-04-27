// citrate/core/execution/src/zkp/halo2/mod.rs
//
// RM-M1b — Halo2-KZG substrate.
//
// This module is the **scaffold** for the Halo2-KZG inference-proof
// migration described in ADR-RM-M1b-1. The full implementation lands
// across WP-M1b.1 → WP-M1b.4. Today (RM-M1 close) it provides:
//
//   1. The module path that the precompile dispatcher will import
//      from once 0x0108 flips from STUB to LIVE.
//   2. Public type stubs for `InferenceProof`, `VerifyingKey`,
//      `Srs` so downstream signatures can be written before the
//      crypto lands.
//   3. A feature-gated zone (`halo2-substrate`) for the actual
//      Halo2 integration. Off by default. When ON, the deps + chips
//      compile in. When OFF, the workspace builds clean.
//
// Why this scaffold exists at RM-M1 close:
//
//   - Saul authorized autonomous progression through RM-M1b
//     (2026-04-27). The first WP, WP-M1b.1, requires picking a
//     specific commit hash for the PSE Halo2 fork. That selection
//     needs verification against the current PSE main + Scroll's
//     latest audited release; that verification is best done in a
//     session with internet access to the PSE GitHub repo.
//
//   - Until the pin is set, this scaffold lets RM-M1b's other
//     downstream WPs (M1b.2 SRS sourcing, M1b.4 precompile wiring,
//     M1b.5 caller migration, M1b.6 audit-prep, M1b.7 testnet
//     enable) be authored against a stable interface. Pin
//     selection unblocks WP-M1b.3 (chip authoring) but doesn't
//     block the surrounding work.
//
// **Anti-rug carry-forward:** the `STUB → LIVE` flip on 0x0108
// happens in WP-M1b.4 by replacing the stub branch in
// `precompiles/verify.rs::execute` with a call into
// `halo2::verify_inference_proof(...)` (signature defined below).
// Until the feature is enabled and the function is implemented,
// the call site is unreachable; until 0x0108 is LIVE, the stub
// message stays in place. The CI verifier
// `check_m1_verification_precompiles.py` enforces this.

// ---------------------------------------------------------------------------
// Always-compiled type stubs.
// ---------------------------------------------------------------------------

/// Versioned identifier for a specific InferenceCircuit deployment.
/// Each new circuit (different topology, different sizes, different
/// commitment-encoding parameters) ships at a new `circuit_version`.
/// Old versions never disappear; commitments anchored to old versions
/// remain verifiable forever.
///
/// `0x...01` reserved for the WP-M1b.3 inference circuit (linear
/// layer + Q16.16). Future circuits get `0x...02`, `0x...03`, ...
pub type CircuitVersion = u32;

/// Reserved circuit version for the first production InferenceCircuit
/// landing in WP-M1b.3 (linear-layer Q16.16).
pub const CIRCUIT_VERSION_LINEAR_Q16: CircuitVersion = 1;

/// Errors that can surface from the verifier path. These are stable
/// across Halo2 backend changes — wrappers above the verifier should
/// pattern-match these, not the underlying `halo2_proofs::Error`.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("input bytes too short: need at least {needed} bytes, got {got}")]
    Truncated { needed: usize, got: usize },

    #[error("unknown circuit_version 0x{0:08x} — no verifying key registered for it")]
    UnknownCircuitVersion(CircuitVersion),

    #[error("proof bytes did not parse as a Halo2-KZG transcript")]
    MalformedProof,

    #[error("public input shape mismatch — circuit expects 3 commitments + version + chain_id")]
    PublicInputShape,

    #[error("verifier rejected the proof (cryptographic failure)")]
    InvalidProof,

    #[error("Halo2 substrate is not built into this binary — compile with --features halo2-substrate")]
    SubstrateAbsent,
}

/// Verify an inference proof against the registered verifying key
/// for `circuit_version`. Returns `Ok(true)` on valid proof,
/// `Ok(false)` on cryptographic rejection, `Err(...)` on structural
/// problems (truncated input, unknown version, etc.).
///
/// The wire format consumed:
///
/// ```text
/// | 32B input_commitment   | 32B model_commitment | 32B output_commitment |
/// | 4B  circuit_version BE | 4B  chain_id BE      |
/// | proof_bytes (variable) |
/// ```
///
/// **WP-M1b.4 implements the actual verification.** Until then this
/// is a stub returning `VerifyError::SubstrateAbsent`.
#[cfg(not(feature = "halo2-substrate"))]
pub fn verify_inference_proof(_input: &[u8]) -> Result<bool, VerifyError> {
    Err(VerifyError::SubstrateAbsent)
}

#[cfg(feature = "halo2-substrate")]
pub fn verify_inference_proof(_input: &[u8]) -> Result<bool, VerifyError> {
    // WP-M1b.4 fills this in. The stub here keeps the type-check on
    // the feature-on path while the chips and SRS land.
    Err(VerifyError::SubstrateAbsent)
}

// ---------------------------------------------------------------------------
// Feature-gated body — Halo2 deps and chips.
// ---------------------------------------------------------------------------
//
// When --features halo2-substrate is on, the modules below pull in
// halo2_proofs + halo2curves and ship the actual chips. When off
// (the default for RM-M1 close), they don't compile and the
// workspace doesn't pull the deps. This lets RM-M1b's pin selection
// happen in a focused follow-up without blocking the rest of the
// workspace.
//
// Pin selection (WP-M1b.1) needs to verify against PSE Halo2's
// recent audited commit AND our `rand = "0.8"` workspace pin. PSE's
// main branch has had transitive `rand 0.9` migrations land at
// various points; using a commit that predates that migration OR
// using a commit that uses the recent `rand 0.9 / 0.8 dual-vendoring`
// pattern is the safest bet. Reference deployments to mirror:
// Scroll's most recent audited release tag, zkSync Era's halo2 pin.
//
// Once the pin is set, this block uncomments (and the
// `[features].halo2-substrate` block in core/execution/Cargo.toml
// gains the dep entries).

#[cfg(feature = "halo2-substrate")]
pub mod canary;

#[cfg(feature = "halo2-substrate")]
pub mod chips;

#[cfg(feature = "halo2-substrate")]
pub mod circuits {
    //! Halo2 circuit compositions — WP-M1b.3.
    //! Empty until the inference circuit lands.
}

#[cfg(feature = "halo2-substrate")]
pub mod srs;

// ---------------------------------------------------------------------------
// Always-compiled tests — verify the scaffolding type-checks today.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substrate_absent_without_feature_flag() {
        // The default workspace build does NOT enable halo2-substrate.
        // Calling verify_inference_proof must return SubstrateAbsent
        // so a contributor who wires it into a precompile prematurely
        // gets a discoverable error rather than a silent success.
        let r = verify_inference_proof(b"any bytes");
        assert!(matches!(r, Err(VerifyError::SubstrateAbsent)));
    }

    #[test]
    fn circuit_version_constant_pinned() {
        // Allocation: CIRCUIT_VERSION_LINEAR_Q16 is reserved as
        // version 1. If this drifts, every proof anchored to v1
        // breaks (or worse — verifies against a different circuit
        // than the prover used).
        assert_eq!(CIRCUIT_VERSION_LINEAR_Q16, 1);
    }
}
