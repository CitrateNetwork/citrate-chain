// citrate/core/execution/src/zkp/halo2/srs.rs
//
// RM-M1b WP-M1b.2 — Powers of Tau SRS loader.
//
// **Operational status (2026-04-27):** the original public PPoT
// mirrors (`https://trusted-setup-halo2kzg.s3.eu-central-1.amazonaws.com/`
// and `https://ppot.blob.core.windows.net/public/`) have gone
// offline / become inaccessible some time in 2025. This module
// ships the PRODUCTION-GRADE LOADER but the SRS file itself is
// a separate ops deliverable. Until a working PPoT-format file is
// staged on the node host:
//   - `load_srs_k18()` returns `ProvenanceNotPinned` (fail-closed)
//   - Halo2 development uses `MockProver` (no real KZG params
//     required); see canary.rs and the inference-circuit chips
//     in WP-M1b.3
//   - Production-deploy of 0x0108 INFERENCE_PROOF_VERIFY is
//     gated on this loader returning Ok with a real, attested
//     hash. The 0x0108 STUB stays in place until then.
//
// The loader is finished and shippable. The hash is not. That
// split is intentional — operations (sourcing the SRS) and
// engineering (consuming it) are separable concerns.
//
// **Stability:** when the hash is pinned, it is FROZEN. Any
// change to the SRS file (including a "drop-in replacement" with
// the same bytes from a different mirror) requires:
//   1. amending ADR-RM-M1b-1 with the new hash + provenance trail
//   2. updating `EXPECTED_SHA256_K18` below
//   3. amending `srs_provenance_v1.json` (the CI-checked fixture)
//   4. rebuilding the verifying key for every active circuit
//      version (which forces a new `circuit_version` allocation;
//      old commitments remain verifiable forever per the
//      versioning rule from ADR-RM-M1-1)
//
// The CI verifier `scripts/ci/check_m1b_srs_provenance.py`
// enforces the EXPECTED_SHA256 ↔ ADR ↔ fixture coupling.

use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2curves::bn256::Bn256;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// k=18 → 2^18 = 262,144 rows. Sized to fit the WP-M1b.3 inference
/// circuit (linear-layer Q16.16 with up to 256×256 matmul +
/// Poseidon hashing of input/model/output commitments, estimated
/// ~100k constraints) with comfortable headroom.
///
/// We deliberately do NOT pin a larger k (e.g. k=20) by default —
/// SRS file size scales linearly with `2^k`, and node-startup load
/// time scales with file size. Larger circuits can opt in to a
/// larger k via `circuit_version`.
pub const SRS_K: u32 = 18;

/// SHA-256 of the canonical PPoT k=18 SRS file (bn256, halo2-kzg
/// raw format).
///
/// **TODO(WP-M1b.2 ops, blocked by SRS mirror availability):**
/// today this is the all-zeros sentinel. When a working PPoT
/// k=18 file is sourced (current public mirrors are 403/offline
/// as of 2026-04-27), update this constant AND the corresponding
/// reference in ADR-RM-M1b-1 AND the
/// `scripts/ci/check_m1b_srs_provenance.py` verifier in the
/// SAME commit. The verifier rejects mismatches between the
/// three; CI will fail on partial updates.
pub const EXPECTED_SHA256_K18: [u8; 32] = [0u8; 32];

/// Recommended on-disk path. Configurable via the
/// `CITRATE_SRS_PATH` env var or the `srs_path` field on
/// `NodeConfig` (added when WP-M1b.4 wires the verifier into the
/// precompile).
pub const DEFAULT_SRS_PATH: &str = "/var/lib/citrate/srs/perpetual-powers-of-tau-raw-18";

#[derive(Debug, thiserror::Error)]
pub enum SrsLoadError {
    #[error("SRS file not found at {path} — see runbooks/SRS_DEPLOY.md (WP-M1b.2 ops)")]
    NotFound { path: String },

    #[error("SRS file I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error(
        "SRS file hash mismatch: expected {expected}, got {actual}. \
         Either the file is wrong (re-fetch from the canonical mirror) \
         or `EXPECTED_SHA256_K18` has drifted from the deployed file \
         (catastrophic — every prior verifying key is invalid)."
    )]
    HashMismatch { expected: String, actual: String },

    #[error("SRS file failed to parse as halo2 ParamsKZG<Bn256>: {0}")]
    Parse(String),

    #[error(
        "SRS provenance not yet pinned — `EXPECTED_SHA256_K18` is the \
         all-zeros sentinel. The PPoT mirrors went offline mid-2025; \
         WP-M1b.2 ops is sourcing a replacement. Until then, \
         `load_srs_k18` fail-closes here so a contributor cannot \
         accidentally ship a verifier with no hash check. See \
         srs.rs operational-status block for the pinning checklist."
    )]
    ProvenanceNotPinned,
}

/// Load the PPoT k=18 SRS from `path`, verifying its SHA-256
/// against the embedded `EXPECTED_SHA256_K18`. Returns a parsed
/// `ParamsKZG<Bn256>` ready for proving / verifying.
///
/// **Fail-closed semantics:**
/// 1. If `EXPECTED_SHA256_K18` is the all-zeros sentinel, returns
///    `ProvenanceNotPinned` without even reading the file. Catches
///    "shipped a verifier without setting the hash."
/// 2. If the file doesn't exist, returns `NotFound` with a
///    runbook pointer.
/// 3. If the file's SHA-256 doesn't match, returns `HashMismatch`
///    BEFORE attempting to parse. The parse path runs only on a
///    file that has already been content-verified.
/// 4. If the parse fails, returns `Parse` with the underlying
///    `halo2_proofs` error.
///
/// On `Ok`, the returned `ParamsKZG<Bn256>` is the trusted SRS
/// the verifier consumes.
pub fn load_srs_k18<P: AsRef<Path>>(path: P) -> Result<ParamsKZG<Bn256>, SrsLoadError> {
    if EXPECTED_SHA256_K18 == [0u8; 32] {
        return Err(SrsLoadError::ProvenanceNotPinned);
    }

    let path_ref = path.as_ref();
    if !path_ref.is_file() {
        return Err(SrsLoadError::NotFound {
            path: path_ref.display().to_string(),
        });
    }

    // Read + hash the entire file before parsing. This is the
    // critical security gate: parse runs ONLY on bytes whose hash
    // matches the pinned constant.
    let bytes = {
        let mut file = BufReader::new(File::open(path_ref)?);
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        buf
    };

    let actual_hash = {
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    };

    if actual_hash != EXPECTED_SHA256_K18 {
        return Err(SrsLoadError::HashMismatch {
            expected: hex::encode(EXPECTED_SHA256_K18),
            actual: hex::encode(actual_hash),
        });
    }

    // Hash matched — safe to parse. The halo2_proofs `ParamsKZG`
    // type implements its own deserialization from the raw-format
    // bytes that PPoT-converted files use.
    use halo2_proofs::SerdeFormat;
    let params = ParamsKZG::<Bn256>::read_custom(&mut bytes.as_slice(), SerdeFormat::RawBytes)
        .map_err(|e| SrsLoadError::Parse(e.to_string()))?;

    Ok(params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_not_pinned_is_explicit() {
        // Until WP-M1b.2 ops sources the SRS file and pins its
        // hash, the loader fails with a discoverable error rather
        // than silently loading or accepting any bytes.
        let r = load_srs_k18("/nonexistent");
        assert!(matches!(r, Err(SrsLoadError::ProvenanceNotPinned)));
    }

    #[test]
    fn srs_k_constant_is_18() {
        // If you change this, you must:
        //   1. update EXPECTED_SHA256_K18 to the hash of the k=N file
        //   2. amend ADR-RM-M1b-1 with the new k value rationale
        //   3. update DEFAULT_SRS_PATH to match
        //   4. inform anyone who has stored verifying keys against
        //      a circuit using the old k — those are now invalid
        // The constant is asserted here so the listed effects are
        // unmissable in PR review.
        assert_eq!(SRS_K, 18);
    }
}
