// citrate/core/execution/src/zkp/halo2/mod.rs
//
// RM-M1b — Halo2-KZG substrate.
//
// **LIVE** — the Halo2-KZG inference-proof verifier. ADR-RM-M1b-1
// describes the migration; commits `9c582fbe` through `d44c3450`
// implement it. This module is what the 0x0108 INFERENCE_PROOF_VERIFY
// precompile dispatches to.
//
// Layout:
//   - Always-compiled: `CircuitVersion`, `CIRCUIT_VERSION_LINEAR_Q16`,
//     `VerifyError`, the public `verify_inference_proof` function.
//   - `cfg(feature = "halo2-substrate")`-gated: `chips`, `circuits`,
//     `srs`, `ptau`, `canary`, plus the actual verifier body and the
//     KZG artifact lazy-init (`inference_kzg_artifacts_v1`).
//
// Without `halo2-substrate`, `verify_inference_proof` returns
// `VerifyError::SubstrateAbsent` so a node that ships without the
// feature gets a discoverable error rather than a silent success.

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
pub fn verify_inference_proof(input: &[u8]) -> Result<bool, VerifyError> {
    use halo2_proofs::plonk::verify_proof_multi;
    use halo2_proofs::poly::kzg::commitment::KZGCommitmentScheme;
    use halo2_proofs::poly::kzg::multiopen::VerifierSHPLONK;
    use halo2_proofs::poly::kzg::strategy::SingleStrategy;
    use halo2_proofs::transcript::{Blake2bRead, Challenge255, TranscriptReadBuffer};
    use halo2curves::bn256::{Bn256, Fr as Halo2Fr, G1Affine};
    use halo2curves::ff::PrimeField as _;

    // Wire format:
    //   [0..32]   input_commitment   (big-endian Fr)
    //   [32..64]  model_commitment   (big-endian Fr)
    //   [64..96]  output_commitment  (big-endian Fr)
    //   [96..100] circuit_version    (big-endian u32)
    //   [100..104] chain_id          (big-endian u32)
    //   [104..]   proof_bytes        (variable)
    const HEADER_LEN: usize = 32 * 3 + 4 + 4;
    if input.len() < HEADER_LEN {
        return Err(VerifyError::Truncated {
            needed: HEADER_LEN,
            got: input.len(),
        });
    }

    let input_commit_be: [u8; 32] = input[0..32].try_into().expect("32B");
    let model_commit_be: [u8; 32] = input[32..64].try_into().expect("32B");
    let output_commit_be: [u8; 32] = input[64..96].try_into().expect("32B");
    let circuit_version =
        u32::from_be_bytes(input[96..100].try_into().expect("4B"));
    let _chain_id = u32::from_be_bytes(input[100..104].try_into().expect("4B"));
    let proof_bytes = &input[HEADER_LEN..];

    if circuit_version != CIRCUIT_VERSION_LINEAR_Q16 {
        return Err(VerifyError::UnknownCircuitVersion(circuit_version));
    }

    // Convert big-endian commitment bytes → Halo2 Fr (canonical repr is LE).
    let to_fr = |be: [u8; 32]| -> Result<Halo2Fr, VerifyError> {
        let mut le = be;
        le.reverse();
        Option::<Halo2Fr>::from(Halo2Fr::from_repr(le.into()))
            .ok_or(VerifyError::PublicInputShape)
    };
    let input_commit = to_fr(input_commit_be)?;
    let model_commit = to_fr(model_commit_be)?;
    let output_commit = to_fr(output_commit_be)?;

    // Lazy-init the SRS and v1 verifying key.
    let (params, vk) = inference_kzg_artifacts_v1();

    // Run the Halo2-KZG verifier.
    let public_inputs: Vec<Vec<Halo2Fr>> =
        vec![vec![input_commit, model_commit, output_commit]];
    let verifier_params = params.verifier_params();
    let mut transcript =
        Blake2bRead::<_, G1Affine, Challenge255<_>>::init(proof_bytes);
    let verified = verify_proof_multi::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<Bn256>,
        _,
        _,
        SingleStrategy<_>,
    >(
        &verifier_params,
        vk,
        &[public_inputs],
        &mut transcript,
    );

    Ok(verified)
}

/// RM-E.1 / CHAIN-003 — SRS source policy for the 0x0108 verifier.
///
/// A seeded KZG SRS has reproducible toxic waste, so the deterministic
/// dev seed must NEVER be the source in a production validator. This
/// pure decision is factored out so the fail-closed policy is locked by
/// a unit test (which runs even in builds without `halo2-substrate`).
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(not(feature = "halo2-substrate"), allow(dead_code))]
enum SrsSource {
    /// Load + hash-verify the ceremony `.ptau` at this path (production).
    Ceremony(String),
    /// Deterministic INSECURE dev seed — only when explicitly allowed.
    InsecureDevSeed,
    /// No ceremony params and the dev seed is not allowed → refuse (fail closed).
    Refuse,
}

/// Resolve which SRS the verifier may use. A non-empty `CITRATE_PTAU_PATH`
/// always wins (production). Otherwise the insecure dev seed is permitted
/// ONLY when `insecure_dev_allowed` is set (debug/test builds, or the
/// explicit `insecure-dev-srs` feature); a production release build with
/// neither refuses rather than verifying against reproducible toxic waste.
#[cfg_attr(not(feature = "halo2-substrate"), allow(dead_code))]
fn resolve_srs_source(ptau_path: Option<String>, insecure_dev_allowed: bool) -> SrsSource {
    match ptau_path {
        Some(p) if !p.is_empty() => SrsSource::Ceremony(p),
        _ if insecure_dev_allowed => SrsSource::InsecureDevSeed,
        _ => SrsSource::Refuse,
    }
}

#[cfg(test)]
mod chain_003_srs_policy_tests {
    use super::{resolve_srs_source, SrsSource};

    /// RM-E.1 / CHAIN-003 tripwire: the insecure deterministic dev SRS
    /// must be unreachable unless explicitly allowed. Pre-fix the verifier
    /// unconditionally fell back to the seed whenever CITRATE_PTAU_PATH was
    /// unset — this asserts that path now FAILS CLOSED (Refuse).
    #[test]
    fn tripwire_003_insecure_seed_refused_without_optin() {
        // No ceremony params + dev NOT allowed → refuse (the production
        // forgot-the-env-var case must not silently use toxic-waste SRS).
        assert_eq!(resolve_srs_source(None, false), SrsSource::Refuse);
        assert_eq!(resolve_srs_source(Some(String::new()), false), SrsSource::Refuse);

        // Dev/test opt-in (debug_assertions or insecure-dev-srs) → seed ok.
        assert_eq!(resolve_srs_source(None, true), SrsSource::InsecureDevSeed);

        // A configured ceremony path always wins, regardless of the flag.
        assert_eq!(
            resolve_srs_source(Some("/srs/ppot_0080_18.ptau".into()), false),
            SrsSource::Ceremony("/srs/ppot_0080_18.ptau".into())
        );
        assert_eq!(
            resolve_srs_source(Some("/srs/ppot_0080_18.ptau".into()), true),
            SrsSource::Ceremony("/srs/ppot_0080_18.ptau".into())
        );
    }
}

/// Lazy-init the ParamsKZG (SRS) and VerifyingKey for the v1
/// InferenceCircuit (`CIRCUIT_VERSION_LINEAR_Q16` = 1, out_dim=1,
/// in_dim=2). Called on the first `verify_inference_proof` invocation;
/// subsequent calls reuse the OnceLock-cached values.
///
/// **SRS source resolution (RM-M1b WP-M1b.7):**
///
/// 1. If env var `CITRATE_PTAU_PATH` is set, load the SRS from the
///    .ptau file at that path via `ptau::load_ptau_into_params_kzg`.
///    The loader hash-verifies the file against the embedded
///    PPoT k=18 SHA-256 (`srs::EXPECTED_PTAU_SHA256_K18`) BEFORE
///    parsing; a tampered or wrong file is rejected fail-closed.
///    This is the **production / testnet path**.
///
/// 2. Otherwise, fall back to a deterministic `ParamsKZG::setup`
///    with seed `[0x4D; 32]`. This is INSECURE (toxic waste is
///    reproducible) but DETERMINISTIC across nodes. **Dev / test
///    only.** The fallback emits a one-time stderr warning so an
///    operator who forgets the env var notices.
///
/// **VK derivation:** the VK is reproducibly derived from
/// (ParamsKZG, InferenceCircuit topology) via halo2's `keygen_vk`.
/// Because both inputs are deterministic (under either source), all
/// nodes generate the SAME VK and agree on proof validity — as long
/// as they use the same SRS source. Mixing sources across the
/// network would diverge.
///
/// **Production deployment:** every validator node MUST set
/// `CITRATE_PTAU_PATH` before serving traffic. The runbook at
/// `runbooks/RM_M1B_SOAK.md` covers acquisition, hash verification,
/// and configuration.
#[cfg(feature = "halo2-substrate")]
fn inference_kzg_artifacts_v1() -> (
    &'static halo2_proofs::poly::kzg::commitment::ParamsKZG<halo2curves::bn256::Bn256>,
    &'static halo2_proofs::plonk::VerifyingKey<halo2curves::bn256::G1Affine>,
) {
    use halo2_proofs::circuit::Value;
    use halo2_proofs::plonk::keygen_vk;
    use halo2_proofs::poly::kzg::commitment::ParamsKZG;
    use halo2curves::bn256::Bn256;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::sync::OnceLock;

    static PARAMS: OnceLock<ParamsKZG<Bn256>> = OnceLock::new();
    static VK: OnceLock<
        halo2_proofs::plonk::VerifyingKey<halo2curves::bn256::G1Affine>,
    > = OnceLock::new();

    const V1_K: u32 = 12;

    // RM-E.1 / CHAIN-003: the insecure deterministic dev seed is reachable
    // ONLY in debug builds (tests/local) or under the explicit
    // `insecure-dev-srs` feature. A production release build with neither
    // and no CITRATE_PTAU_PATH refuses to construct an SRS at all, rather
    // than silently using a reproducible-toxic-waste SRS.
    let insecure_dev_allowed =
        cfg!(debug_assertions) || cfg!(feature = "insecure-dev-srs");
    let source = resolve_srs_source(
        std::env::var("CITRATE_PTAU_PATH").ok(),
        insecure_dev_allowed,
    );

    let params = PARAMS.get_or_init(|| {
        match source {
            SrsSource::Ceremony(path) => {
                // Production / testnet: load and hash-verify the .ptau.
                // load_ptau_into_params_kzg returns an SrsLoadError on
                // any failure (NotFound / HashMismatch / Parse). For
                // an in-flight precompile call we have no way to
                // surface a structured error, so log to stderr and
                // panic — the verifier cannot continue without an
                // SRS, and silently falling back to the insecure
                // seed-based path would diverge this node from the
                // network. Fail-closed.
                eprintln!(
                    "[citrate-execution] Loading InferenceCircuit SRS from CITRATE_PTAU_PATH={} (k={})",
                    path, V1_K
                );
                crate::zkp::halo2::ptau::load_ptau_into_params_kzg(&path, V1_K)
                    .unwrap_or_else(|e| {
                        panic!(
                            "[citrate-execution] FATAL: failed to load SRS \
                             from CITRATE_PTAU_PATH={path}: {e}. The node \
                             cannot serve 0x0108 INFERENCE_PROOF_VERIFY \
                             without a valid PPoT .ptau file. See \
                             runbooks/RM_M1B_SOAK.md."
                        )
                    })
            }
            SrsSource::InsecureDevSeed => {
                // Dev / test fallback: deterministic seed. INSECURE.
                eprintln!(
                    "[citrate-execution] WARNING: CITRATE_PTAU_PATH not set; \
                     using deterministic seed-based SRS for InferenceCircuit. \
                     This is DEV/TEST ONLY — production validators must set \
                     CITRATE_PTAU_PATH to a verified PPoT .ptau file. See \
                     runbooks/RM_M1B_SOAK.md."
                );
                let mut rng = StdRng::from_seed([0x4D; 32]);
                ParamsKZG::<Bn256>::setup(V1_K, &mut rng)
            }
            SrsSource::Refuse => {
                // RM-E.1 / CHAIN-003 fail-closed: a production release build
                // with no ceremony .ptau and no explicit dev opt-in must NOT
                // verify proofs against a reproducible-toxic-waste SRS.
                panic!(
                    "[citrate-execution] FATAL (CHAIN-003 fail-closed): 0x0108 \
                     INFERENCE_PROOF_VERIFY requires a ceremony SRS. Set \
                     CITRATE_PTAU_PATH to a verified PPoT .ptau file. The \
                     insecure deterministic dev SRS is NOT available in this \
                     build (rebuild with --features insecure-dev-srs for local \
                     dev ONLY). See runbooks/RM_M1B_SOAK.md."
                );
            }
        }
    });

    let vk = VK.get_or_init(|| {
        let circuit = crate::zkp::halo2::circuits::InferenceCircuit {
            weights: vec![Value::unknown(); 2], // out_dim=1 * in_dim=2
            inputs: vec![Value::unknown(); 2],
            biases: vec![Value::unknown(); 1],
            out_dim: 1,
            in_dim: 2,
        };
        keygen_vk(params, &circuit).expect("VK keygen for InferenceCircuit v1")
    });

    (params, vk)
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
pub mod ptau;

#[cfg(feature = "halo2-substrate")]
pub mod chips;

#[cfg(feature = "halo2-substrate")]
pub mod circuits;

#[cfg(feature = "halo2-substrate")]
pub mod srs;

// ---------------------------------------------------------------------------
// Always-compiled tests — verify the scaffolding type-checks today.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "halo2-substrate"))]
    #[test]
    fn substrate_absent_without_feature_flag() {
        // The default workspace build does NOT enable halo2-substrate.
        // Calling verify_inference_proof must return SubstrateAbsent
        // so a contributor who wires it into a precompile prematurely
        // gets a discoverable error rather than a silent success.
        let r = verify_inference_proof(b"any bytes");
        assert!(matches!(r, Err(VerifyError::SubstrateAbsent)));
    }

    #[cfg(feature = "halo2-substrate")]
    #[test]
    fn substrate_present_with_feature_flag_rejects_truncated() {
        // When the feature IS on, the verifier is LIVE. A short
        // input (< 104B header) must surface as a structured
        // Truncated error, not as silent success.
        let r = verify_inference_proof(b"too short");
        assert!(matches!(r, Err(VerifyError::Truncated { .. })));
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
