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

/// PIN-P1 step (a): circuit version for the **reduced** Stacked-DRG
/// PoRep circuit (`zkp::halo2::porep::PoRepCircuit`, N=4 nodes, L=2
/// layers). Allocated here so a PoRep proof verifies on-chain through
/// 0x0108 with a DIFFERENT verifying key AND a DIFFERENT public-input
/// parsing than the inference circuit — domain separation by version.
///
/// **Size note:** v2 currently uses the *reduced* PoRep circuit's VK.
/// When the full-size PoRep circuit lands (real DRG/expander samplers,
/// Filecoin-scale d_DRG/d_EXP/L), the VK behind v2 swaps to the
/// full-size one. Per ADR-RM-M1-1's versioning rule, if the public
/// input layout or proof semantics change in a way that breaks
/// already-anchored v2 proofs, the full circuit ships at a NEW version
/// (e.g. v4) rather than mutating v2. For the reduced-circuit
/// pre-mainnet phase no v2 proofs are anchored on-chain, so swapping
/// the VK in place is safe.
pub const CIRCUIT_VERSION_POREP_REDUCED: CircuitVersion = 2;

/// PIN-P1 step (b): circuit version for the **reduced** Proof-of-Spacetime
/// (PoSt) circuit (`zkp::halo2::post::PoStCircuit`, same N=4/L=2 topology
/// as PoRep). **ACTIVATED this step** (was RESERVED-but-rejected): a v3
/// proof now verifies on-chain through 0x0108 with the PoSt VK and the
/// 7-input PoSt public-input parsing (NO CommD) — domain-separated from
/// the inference circuit (v1, 3 commitments) and PoRep (v2, 8 inputs).
///
/// PoSt is the recurring, LIGHT proof: it re-derives the challenged node's
/// labels and checks R[v]∈CommR + column(v)∈CommC, but drops PoRep's
/// CommD inclusion and the encoding relation. Per-challenge VK pattern is
/// identical to PoRep (the v=0 labeling-seed copy constraint + Merkle
/// branch directions are fixed topology).
///
/// **Backward-compat alias:** the old `CIRCUIT_VERSION_POST_RESERVED`
/// name is retained (re-exported below) so any caller that referenced the
/// reserved constant keeps compiling; both resolve to 3.
pub const CIRCUIT_VERSION_POST: CircuitVersion = 3;

/// Deprecated alias for `CIRCUIT_VERSION_POST` — PoSt is no longer
/// "reserved", it is live. Kept so the prior name still resolves.
pub const CIRCUIT_VERSION_POST_RESERVED: CircuitVersion = CIRCUIT_VERSION_POST;

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

/// PIN-P1 step (a): **version-dispatching** entry point for the 0x0108
/// precompile. Reads `circuit_version` (bytes 96..100, BE u32) FIRST,
/// then routes to the circuit-specific verifier. Each version selects
/// BOTH the verifying key AND the public-input parsing layout, so a
/// proof + public inputs built for one circuit cannot satisfy another
/// (domain separation by version).
///
/// Routing table (the compiled-in circuit-version registry):
///
/// | version | circuit                 | public-input ABI            | VK source                 |
/// |---------|-------------------------|-----------------------------|---------------------------|
/// | 1       | InferenceCircuit (Q16)  | 3 commitments (existing)    | `inference_kzg_artifacts_v1` |
/// | 2       | reduced PoRepCircuit    | 8 PoRep field elements      | `porep_kzg_artifacts_v2`  |
/// | 3       | reduced PoStCircuit     | 7 PoSt field elements       | `post_kzg_artifacts_v3`   |
/// | other   | unknown                 | — (rejected)                | —                         |
///
/// The **v1 path is behaviorally identical to calling
/// `verify_inference_proof` directly** — this dispatcher peeks the
/// version and, for v1, hands the FULL original `input` (header +
/// proof) to `verify_inference_proof` unchanged. The inference wire
/// format, VK, and result are untouched.
#[cfg(not(feature = "halo2-substrate"))]
pub fn verify_proof_dispatch(_input: &[u8]) -> Result<bool, VerifyError> {
    Err(VerifyError::SubstrateAbsent)
}

#[cfg(feature = "halo2-substrate")]
pub fn verify_proof_dispatch(input: &[u8]) -> Result<bool, VerifyError> {
    // The version field lives at bytes 96..100 in EVERY circuit's wire
    // format (the 3 leading 32-byte words are commitments for v1, or
    // the first 3 of the 8 PoRep field elements for v2 — either way the
    // version is at the same fixed offset). Read it before committing to
    // any layout so an unknown/short input is rejected uniformly.
    const VERSION_OFFSET: usize = 96;
    if input.len() < VERSION_OFFSET + 4 {
        return Err(VerifyError::Truncated {
            needed: VERSION_OFFSET + 4,
            got: input.len(),
        });
    }
    let circuit_version =
        u32::from_be_bytes(input[VERSION_OFFSET..VERSION_OFFSET + 4].try_into().expect("4B"));

    match circuit_version {
        // v1 — UNCHANGED inference path. Hand the original input straight
        // to the existing verifier; it re-parses the 3-commitment layout,
        // re-checks the version == 1, and verifies with the inference VK.
        CIRCUIT_VERSION_LINEAR_Q16 => verify_inference_proof(input),
        // v2 — reduced PoRep. Different VK, different 8-field public-input
        // parsing.
        CIRCUIT_VERSION_POREP_REDUCED => verify_porep_proof(input),
        // v3 — reduced PoSt. Different VK again, different 7-field
        // public-input parsing (NO CommD). Domain-separated from v1/v2.
        CIRCUIT_VERSION_POST => verify_post_proof(input),
        // Everything else: reject as an unknown version (no VK registered).
        other => Err(VerifyError::UnknownCircuitVersion(other)),
    }
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

/// PIN-P1 step (a): verify a **reduced PoRep** proof (circuit_version
/// 2) submitted to 0x0108. Mirrors `verify_inference_proof`'s
/// structure but with the PoRep public-input ABI and the PoRep VK, so
/// the two paths are domain-separated.
///
/// **v2 wire format (the PoRep ABI — documented byte layout):**
///
/// ```text
/// | [0..32)    replicaID       (BE Fr)   — public input slot 0
/// | [32..64)   cid             (BE Fr)   — public input slot 1
/// | [64..96)   sectorIndex     (BE Fr)   — public input slot 2
/// | [96..100)  circuit_version (BE u32)  — MUST be 2 here
/// | [100..104) chain_id        (BE u32)  — advisory (carried, not used)
/// | [104..136) CommD           (BE Fr)   — public input slot 3
/// | [136..168) CommR           (BE Fr)   — public input slot 4
/// | [168..200) CommC           (BE Fr)   — public input slot 5
/// | [200..232) challengeNonce  (BE Fr)   — public input slot 6
/// | [232..264) epoch           (BE Fr)   — public input slot 7
/// | [264..]    proof_bytes     (variable, Halo2-KZG SHPLONK transcript)
/// ```
///
/// The first three 32-byte words double as the version-bearing prefix
/// (`replicaID`/`cid`/`sectorIndex` occupy bytes 0..96), so the version
/// field sits at the SAME offset (96..100) as the inference layout —
/// that is the *only* shared structure; everything after is parsed
/// against the PoRep public-input vector. The public inputs are fed in
/// the exact slot order `porep::pi::{REPLICA_ID, CID, SECTOR_INDEX,
/// COMM_D, COMM_R, COMM_C, CHALLENGE_NONCE, EPOCH}` so the verifier
/// instance column matches what the prover committed.
///
/// **Domain separation:** an inference proof presented as v2 fails
/// because (a) the inference proof has only 3 public inputs but the
/// PoRep VK expects 8, and (b) the PoRep VK is a different key than the
/// inference VK. A PoRep proof presented as v1 fails symmetrically. No
/// proof + public-input pair can satisfy both circuits.
#[cfg(feature = "halo2-substrate")]
pub fn verify_porep_proof(input: &[u8]) -> Result<bool, VerifyError> {
    use halo2_proofs::plonk::verify_proof_multi;
    use halo2_proofs::poly::kzg::commitment::KZGCommitmentScheme;
    use halo2_proofs::poly::kzg::multiopen::VerifierSHPLONK;
    use halo2_proofs::poly::kzg::strategy::SingleStrategy;
    use halo2_proofs::transcript::{Blake2bRead, Challenge255, TranscriptReadBuffer};
    use halo2curves::bn256::{Bn256, Fr as Halo2Fr, G1Affine};
    use halo2curves::ff::PrimeField as _;

    // 8 public-input field elements × 32B + circuit_version(4B) +
    // chain_id(4B). The version/chain_id sit *between* the first three
    // and the last five field elements, matching the documented layout.
    const HEADER_LEN: usize = 32 * 3 + 4 + 4 + 32 * 5;
    if input.len() < HEADER_LEN {
        return Err(VerifyError::Truncated {
            needed: HEADER_LEN,
            got: input.len(),
        });
    }

    let circuit_version = u32::from_be_bytes(input[96..100].try_into().expect("4B"));
    if circuit_version != CIRCUIT_VERSION_POREP_REDUCED {
        return Err(VerifyError::UnknownCircuitVersion(circuit_version));
    }
    let _chain_id = u32::from_be_bytes(input[100..104].try_into().expect("4B"));

    // Big-endian 32-byte word → Halo2 Fr (canonical repr is LE).
    let to_fr = |be: &[u8]| -> Result<Halo2Fr, VerifyError> {
        let mut le: [u8; 32] = be.try_into().map_err(|_| VerifyError::PublicInputShape)?;
        le.reverse();
        Option::<Halo2Fr>::from(Halo2Fr::from_repr(le.into()))
            .ok_or(VerifyError::PublicInputShape)
    };

    // Parse the 8 PoRep public inputs from their fixed offsets.
    let replica_id = to_fr(&input[0..32])?;
    let cid = to_fr(&input[32..64])?;
    let sector_index = to_fr(&input[64..96])?;
    let comm_d = to_fr(&input[104..136])?;
    let comm_r = to_fr(&input[136..168])?;
    let comm_c = to_fr(&input[168..200])?;
    let challenge_nonce = to_fr(&input[200..232])?;
    let epoch = to_fr(&input[232..264])?;
    let proof_bytes = &input[HEADER_LEN..];

    // Assemble the instance column in porep::pi slot order. This MUST
    // match `PoRepCircuit::public_inputs` exactly or the proof fails.
    let mut public_row = vec![Halo2Fr::default(); porep::pi::COUNT];
    public_row[porep::pi::REPLICA_ID] = replica_id;
    public_row[porep::pi::CID] = cid;
    public_row[porep::pi::SECTOR_INDEX] = sector_index;
    public_row[porep::pi::COMM_D] = comm_d;
    public_row[porep::pi::COMM_R] = comm_r;
    public_row[porep::pi::COMM_C] = comm_c;
    public_row[porep::pi::CHALLENGE_NONCE] = challenge_nonce;
    public_row[porep::pi::EPOCH] = epoch;

    // PIN-P1 step (c1): the reduced PoRep circuit is now INDEX-AGNOSTIC —
    // the challenge index is a witness, bit-decomposed in-circuit and bound
    // to the public `challengeNonce`, and the Merkle directions are derived
    // in-circuit via conditional swap. So ONE VK verifies every index
    // (TD-18 killed; no per-index cache). We still range-check the public
    // `challengeNonce` here: an out-of-range nonce (≥ N) has no honest
    // circuit (the witness's bit-decomposition cannot satisfy a value ≥ N
    // with only MERKLE_DEPTH bits), and we reject it early before the VK.
    let challenge_index = {
        // challengeNonce is a small node index in 0..N; read it from the
        // canonical LE repr's low bytes. Anything ≥ N is invalid.
        let repr = challenge_nonce.to_repr();
        let bytes: &[u8] = repr.as_ref();
        // Reject if any high byte is set (the index must fit in usize and
        // be < N); N is tiny so only byte 0 can legitimately be nonzero.
        if bytes[1..].iter().any(|&b| b != 0) {
            return Err(VerifyError::PublicInputShape);
        }
        bytes[0] as usize
    };
    if challenge_index >= porep::N {
        return Err(VerifyError::PublicInputShape);
    }

    let (params, vk) = porep_kzg_artifacts_v2();
    let public_inputs: Vec<Vec<Halo2Fr>> = vec![public_row];
    let verifier_params = params.verifier_params();
    let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(proof_bytes);
    let verified = verify_proof_multi::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<Bn256>,
        _,
        _,
        SingleStrategy<_>,
    >(&verifier_params, vk, &[public_inputs], &mut transcript);

    Ok(verified)
}

/// PIN-P1 step (a): lazy-init the ParamsKZG (SRS) and VerifyingKey for
/// the v2 reduced PoRepCircuit. Mirrors `inference_kzg_artifacts_v1`'s
/// SRS-source policy (CHAIN-003 fail-closed) exactly — the ONLY
/// differences are the circuit (PoRep, not inference) and `k`.
///
/// **k:** the reduced PoRep circuit needs k=13 (see
/// `porep::tests::K`); the inference circuit used k=12. The SRS is
/// sized to the larger of the circuits a node serves; loading the v1
/// k=12 ParamsKZG and the v2 k=13 ParamsKZG independently keeps each
/// circuit's VK derivation deterministic and isolated. (When loading
/// from a real .ptau, `load_ptau_into_params_kzg` is given the v2 `k`.)
///
/// **Single VK (PIN-P1 step c1):** the reduced PoRep circuit is now
/// index-agnostic (the challenge index is a witness, bit-decomposed +
/// conditionally-swapped in-circuit). ONE VK is derived from the
/// `PoRepCircuit::default().without_witnesses()` shape and verifies
/// honest proofs for ALL challenge indices — TD-18 (the per-challenge VK
/// cache) is killed. No `challenge_index` argument remains.
#[cfg(feature = "halo2-substrate")]
fn porep_kzg_artifacts_v2() -> (
    &'static halo2_proofs::poly::kzg::commitment::ParamsKZG<halo2curves::bn256::Bn256>,
    &'static halo2_proofs::plonk::VerifyingKey<halo2curves::bn256::G1Affine>,
) {
    use halo2_proofs::plonk::{keygen_vk, Circuit as _};
    use halo2_proofs::poly::kzg::commitment::ParamsKZG;
    use halo2curves::bn256::Bn256;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::sync::OnceLock;

    static PARAMS: OnceLock<ParamsKZG<Bn256>> = OnceLock::new();
    // A SINGLE VK (no longer one-per-index).
    static VK: OnceLock<halo2_proofs::plonk::VerifyingKey<halo2curves::bn256::G1Affine>> =
        OnceLock::new();

    // Reduced PoRep circuit degree (see porep::tests::K).
    const V2_K: u32 = 14;

    // SAME CHAIN-003 fail-closed policy as the inference path.
    let insecure_dev_allowed = cfg!(debug_assertions) || cfg!(feature = "insecure-dev-srs");
    let source =
        resolve_srs_source(std::env::var("CITRATE_PTAU_PATH").ok(), insecure_dev_allowed);

    let params = PARAMS.get_or_init(|| match source {
        SrsSource::Ceremony(path) => {
            eprintln!(
                "[citrate-execution] Loading reduced-PoRep SRS from CITRATE_PTAU_PATH={} (k={})",
                path, V2_K
            );
            crate::zkp::halo2::ptau::load_ptau_into_params_kzg(&path, V2_K).unwrap_or_else(|e| {
                panic!(
                    "[citrate-execution] FATAL: failed to load SRS from \
                     CITRATE_PTAU_PATH={path}: {e}. The node cannot serve \
                     0x0108 circuit_version=2 (reduced PoRep) without a valid \
                     PPoT .ptau file. See runbooks/RM_M1B_SOAK.md."
                )
            })
        }
        SrsSource::InsecureDevSeed => {
            eprintln!(
                "[citrate-execution] WARNING: CITRATE_PTAU_PATH not set; using \
                 deterministic seed-based SRS for reduced PoRep (circuit_version=2). \
                 DEV/TEST ONLY — production validators must set CITRATE_PTAU_PATH."
            );
            let mut rng = StdRng::from_seed([0x4D; 32]);
            ParamsKZG::<Bn256>::setup(V2_K, &mut rng)
        }
        SrsSource::Refuse => {
            panic!(
                "[citrate-execution] FATAL (CHAIN-003 fail-closed): 0x0108 \
                 circuit_version=2 (reduced PoRep) requires a ceremony SRS. Set \
                 CITRATE_PTAU_PATH to a verified PPoT .ptau file (rebuild with \
                 --features insecure-dev-srs for local dev ONLY). See \
                 runbooks/RM_M1B_SOAK.md."
            );
        }
    });

    let vk = VK.get_or_init(|| {
        // Derive the SINGLE VK from the index-agnostic circuit shape under
        // `without_witnesses()`. The shape is identical for every challenge
        // index, so this one VK verifies all of them.
        let circuit = crate::zkp::halo2::porep::PoRepCircuit::default();
        keygen_vk(params, &circuit.without_witnesses())
            .expect("VK keygen for reduced PoRepCircuit v2")
    });

    (params, vk)
}

/// PIN-P1 step (b): verify a **reduced PoSt** proof (circuit_version 3)
/// submitted to 0x0108. Mirrors `verify_porep_proof`'s structure but with
/// the lighter 7-input PoSt ABI (NO CommD) and the PoSt VK, so all three
/// of v1/v2/v3 are mutually domain-separated.
///
/// **v3 wire format (the PoSt ABI — documented byte layout):**
///
/// ```text
/// | [0..32)    replicaID       (BE Fr)   — public input slot 0
/// | [32..64)   cid             (BE Fr)   — public input slot 1
/// | [64..96)   sectorIndex     (BE Fr)   — public input slot 2
/// | [96..100)  circuit_version (BE u32)  — MUST be 3 here
/// | [100..104) chain_id        (BE u32)  — advisory (carried, not used)
/// | [104..136) CommR           (BE Fr)   — public input slot 3
/// | [136..168) CommC           (BE Fr)   — public input slot 4
/// | [168..200) challengeNonce  (BE Fr)   — public input slot 5
/// | [200..232) epoch           (BE Fr)   — public input slot 6
/// | [232..]    proof_bytes     (variable, Halo2-KZG SHPLONK transcript)
/// ```
///
/// The first three 32-byte words (`replicaID`/`cid`/`sectorIndex`) place
/// the version field at the SAME offset (96..100) as v1/v2 — that is the
/// only shared structure. After the version/chain_id words come the PoSt
/// commitments: **CommR then CommC** (and NO CommD), which is the byte
/// layout that distinguishes v3 from v2 (where bytes [104..136) are CommD
/// and there are five trailing words, not four). The public inputs are
/// fed in `post::pi::{REPLICA_ID, CID, SECTOR_INDEX, COMM_R, COMM_C,
/// CHALLENGE_NONCE, EPOCH}` order to match what the prover committed.
///
/// **Domain separation:** a PoRep proof presented as v3 fails because the
/// PoRep VK expects 8 public inputs but the PoSt VK expects 7 (and the
/// keys differ); a PoSt proof presented as v2 fails symmetrically; an
/// inference proof (3 inputs) fails against either. No proof + public-
/// input pair satisfies more than one circuit.
#[cfg(feature = "halo2-substrate")]
pub fn verify_post_proof(input: &[u8]) -> Result<bool, VerifyError> {
    use halo2_proofs::plonk::verify_proof_multi;
    use halo2_proofs::poly::kzg::commitment::KZGCommitmentScheme;
    use halo2_proofs::poly::kzg::multiopen::VerifierSHPLONK;
    use halo2_proofs::poly::kzg::strategy::SingleStrategy;
    use halo2_proofs::transcript::{Blake2bRead, Challenge255, TranscriptReadBuffer};
    use halo2curves::bn256::{Bn256, Fr as Halo2Fr, G1Affine};
    use halo2curves::ff::PrimeField as _;

    // 7 public-input field elements × 32B + circuit_version(4B) +
    // chain_id(4B). The first 3 field elements precede the version/chain_id
    // words; the last 4 (CommR, CommC, challengeNonce, epoch) follow them.
    const HEADER_LEN: usize = 32 * 3 + 4 + 4 + 32 * 4;
    if input.len() < HEADER_LEN {
        return Err(VerifyError::Truncated {
            needed: HEADER_LEN,
            got: input.len(),
        });
    }

    let circuit_version = u32::from_be_bytes(input[96..100].try_into().expect("4B"));
    if circuit_version != CIRCUIT_VERSION_POST {
        return Err(VerifyError::UnknownCircuitVersion(circuit_version));
    }
    let _chain_id = u32::from_be_bytes(input[100..104].try_into().expect("4B"));

    // Big-endian 32-byte word → Halo2 Fr (canonical repr is LE).
    let to_fr = |be: &[u8]| -> Result<Halo2Fr, VerifyError> {
        let mut le: [u8; 32] = be.try_into().map_err(|_| VerifyError::PublicInputShape)?;
        le.reverse();
        Option::<Halo2Fr>::from(Halo2Fr::from_repr(le.into()))
            .ok_or(VerifyError::PublicInputShape)
    };

    // Parse the 7 PoSt public inputs from their fixed offsets (NO CommD).
    let replica_id = to_fr(&input[0..32])?;
    let cid = to_fr(&input[32..64])?;
    let sector_index = to_fr(&input[64..96])?;
    let comm_r = to_fr(&input[104..136])?;
    let comm_c = to_fr(&input[136..168])?;
    let challenge_nonce = to_fr(&input[168..200])?;
    let epoch = to_fr(&input[200..232])?;
    let proof_bytes = &input[HEADER_LEN..];

    // Assemble the instance column in post::pi slot order. This MUST match
    // `PoStCircuit::public_inputs` exactly or the proof fails.
    let mut public_row = vec![Halo2Fr::default(); post::pi::COUNT];
    public_row[post::pi::REPLICA_ID] = replica_id;
    public_row[post::pi::CID] = cid;
    public_row[post::pi::SECTOR_INDEX] = sector_index;
    public_row[post::pi::COMM_R] = comm_r;
    public_row[post::pi::COMM_C] = comm_c;
    public_row[post::pi::CHALLENGE_NONCE] = challenge_nonce;
    public_row[post::pi::EPOCH] = epoch;

    // PIN-P1 step (c1): like PoRep, the PoSt circuit is now INDEX-AGNOSTIC,
    // so ONE VK verifies every index (TD-18 killed). We still range-check
    // the public `challengeNonce` (≥ N has no honest circuit) before the VK.
    let challenge_index = {
        let repr = challenge_nonce.to_repr();
        let bytes: &[u8] = repr.as_ref();
        if bytes[1..].iter().any(|&b| b != 0) {
            return Err(VerifyError::PublicInputShape);
        }
        bytes[0] as usize
    };
    if challenge_index >= porep::N {
        return Err(VerifyError::PublicInputShape);
    }

    let (params, vk) = post_kzg_artifacts_v3();
    let public_inputs: Vec<Vec<Halo2Fr>> = vec![public_row];
    let verifier_params = params.verifier_params();
    let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(proof_bytes);
    let verified = verify_proof_multi::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<Bn256>,
        _,
        _,
        SingleStrategy<_>,
    >(&verifier_params, vk, &[public_inputs], &mut transcript);

    Ok(verified)
}

/// PIN-P1 step (b): lazy-init the ParamsKZG (SRS) and VerifyingKey for the
/// v3 reduced PoStCircuit. Mirrors `porep_kzg_artifacts_v2` exactly — same
/// CHAIN-003 fail-closed SRS-source policy, same SINGLE index-agnostic VK
/// (PIN-P1 step c1), same `k`. The ONLY difference is the circuit (PoSt).
///
/// **k:** the reduced PoSt circuit is LIGHTER than PoRep (no encoding
/// bridge, no CommD inclusion) but the index-agnostic Merkle + parent
/// inclusion bring it to the same k=14 the PoRep circuit uses; keeping `k`
/// uniform across v2/v3 lets a node size a single SRS for both. (The v3
/// ParamsKZG is built independently of v2's so
/// each VK derivation stays deterministic and isolated.)
///
/// **Single VK (PIN-P1 step c1):** like PoRep, one index-agnostic VK
/// verifies all challenge indices — TD-18 killed. No `challenge_index`
/// argument remains.
#[cfg(feature = "halo2-substrate")]
fn post_kzg_artifacts_v3() -> (
    &'static halo2_proofs::poly::kzg::commitment::ParamsKZG<halo2curves::bn256::Bn256>,
    &'static halo2_proofs::plonk::VerifyingKey<halo2curves::bn256::G1Affine>,
) {
    use halo2_proofs::plonk::{keygen_vk, Circuit as _};
    use halo2_proofs::poly::kzg::commitment::ParamsKZG;
    use halo2curves::bn256::Bn256;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::sync::OnceLock;

    static PARAMS: OnceLock<ParamsKZG<Bn256>> = OnceLock::new();
    // A SINGLE VK (no longer one-per-index).
    static VK: OnceLock<halo2_proofs::plonk::VerifyingKey<halo2curves::bn256::G1Affine>> =
        OnceLock::new();

    // Reduced PoSt circuit degree (matches the PoRep k for uniform SRS).
    const V3_K: u32 = 14;

    // SAME CHAIN-003 fail-closed policy as the inference + PoRep paths.
    let insecure_dev_allowed = cfg!(debug_assertions) || cfg!(feature = "insecure-dev-srs");
    let source =
        resolve_srs_source(std::env::var("CITRATE_PTAU_PATH").ok(), insecure_dev_allowed);

    let params = PARAMS.get_or_init(|| match source {
        SrsSource::Ceremony(path) => {
            eprintln!(
                "[citrate-execution] Loading reduced-PoSt SRS from CITRATE_PTAU_PATH={} (k={})",
                path, V3_K
            );
            crate::zkp::halo2::ptau::load_ptau_into_params_kzg(&path, V3_K).unwrap_or_else(|e| {
                panic!(
                    "[citrate-execution] FATAL: failed to load SRS from \
                     CITRATE_PTAU_PATH={path}: {e}. The node cannot serve \
                     0x0108 circuit_version=3 (reduced PoSt) without a valid \
                     PPoT .ptau file. See runbooks/RM_M1B_SOAK.md."
                )
            })
        }
        SrsSource::InsecureDevSeed => {
            eprintln!(
                "[citrate-execution] WARNING: CITRATE_PTAU_PATH not set; using \
                 deterministic seed-based SRS for reduced PoSt (circuit_version=3). \
                 DEV/TEST ONLY — production validators must set CITRATE_PTAU_PATH."
            );
            let mut rng = StdRng::from_seed([0x4D; 32]);
            ParamsKZG::<Bn256>::setup(V3_K, &mut rng)
        }
        SrsSource::Refuse => {
            panic!(
                "[citrate-execution] FATAL (CHAIN-003 fail-closed): 0x0108 \
                 circuit_version=3 (reduced PoSt) requires a ceremony SRS. Set \
                 CITRATE_PTAU_PATH to a verified PPoT .ptau file (rebuild with \
                 --features insecure-dev-srs for local dev ONLY). See \
                 runbooks/RM_M1B_SOAK.md."
            );
        }
    });

    let vk = VK.get_or_init(|| {
        let circuit = crate::zkp::halo2::post::PoStCircuit::default();
        keygen_vk(params, &circuit.without_witnesses())
            .expect("VK keygen for reduced PoStCircuit v3")
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

/// PIN-P1 — Stacked-DRG PoRep circuit (reduced instance). Additive; does
/// NOT touch the inference circuit or the live 0x0108 verifier.
#[cfg(feature = "halo2-substrate")]
pub mod porep;

/// PIN-P1 step (b) — Proof-of-Spacetime (PoSt) circuit (reduced instance).
/// Additive; reuses `porep`'s native sealing + topology. Does NOT touch
/// the inference (v1) or PoRep (v2) verification paths.
#[cfg(feature = "halo2-substrate")]
pub mod post;

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
