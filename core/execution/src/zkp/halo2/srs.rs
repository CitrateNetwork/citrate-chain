// citrate/core/execution/src/zkp/halo2/srs.rs
//
// RM-M1b WP-M1b.2 — Powers of Tau SRS loader.
//
// **Operational status (2026-04-27, post-PPoT-source-find):**
// The original PPoT halo2-kzg mirrors are offline (HTTP 403). The
// AUTHORITATIVE upstream — the PSE-hosted .ptau file at
// `https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_18.ptau`
// — IS reachable. SHA-256 of that file is locked in
// `EXPECTED_PTAU_SHA256_K18` below.
//
// Two pieces of the loader land in distinct WPs:
//
// 1. **WP-M1b.2 PHASE 1 (this commit):** lock the .ptau hash.
//    The .ptau file is the public-ceremony output; pinning its
//    hash anchors our trust to the public ceremony directly.
//    Anyone can re-derive the hash by downloading the file from
//    the URL above and running `sha256sum`.
//
// 2. **WP-M1b.2 PHASE 2 (next session):** author the .ptau →
//    halo2_proofs::ParamsKZG parser. The .ptau format is
//    SnarkJS-style binary with sections; we need only sections 2
//    (tauG1, first 2^18+1 points) and 3 (tauG2, first 2 points)
//    plus header section 1 for curve metadata. ~150-200 LoC of
//    careful binary parsing + per-point on-curve validation.
//
//    Why we don't depend on `han0110/halo2-kzg-srs` as a
//    converter: per Saul (2026-04-27) we avoid third-party crate
//    deps for supply-chain reasons on cryptographically-loaded
//    code paths. The .ptau hash is sufficient anchor; the parser
//    is one-time engineering we own.
//
// Until WP-M1b.2 PHASE 2 lands:
//   - `load_srs_k18()` returns `ParserNotImplemented` (fail-closed)
//   - Halo2 development uses `MockProver` (no real KZG params
//     required); see canary.rs and the chip scaffolds
//   - Production-deploy of 0x0108 INFERENCE_PROOF_VERIFY is
//     gated on this loader returning Ok. The 0x0108 STUB stays
//     in place until then.
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

/// SHA-256 of the canonical PPoT k=18 .ptau file
/// (`ppot_0080_18.ptau`, contribution 0080 by Carter Feldman,
/// served by PSE at the URL in `DEFAULT_SRS_PTAU_URL` below).
///
/// File: 302,083,218 bytes (~288 MB).
/// Last-Modified at PSE bucket: 2024-04-10.
/// Hash captured: 2026-04-27 by direct sha256sum of the
/// file fetched from the canonical URL.
///
/// **VERIFICATION:** anyone reading this can re-derive this hash:
///
/// ```bash
/// curl -L -o ppot_0080_18.ptau \
///     https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_18.ptau
/// sha256sum ppot_0080_18.ptau
/// # expect: 9693220206afab749e3d88d4ab5fdf5d36120ea102e7e587ccea0e7a5208e711
/// ```
///
/// **Stability:** any change to this constant requires:
///   1. amending ADR-RM-M1b-1 References with the new hash + a
///      provenance note (why the file changed)
///   2. updating `tests/fixtures/srs_provenance_v1.json`
///   3. landing those updates in the same commit as this change
///   4. consequence: every existing verifying key derived from
///      the prior file is invalid. Old `circuit_version` entries
///      stay verifiable because they're locked to a specific VK
///      derived from a specific .ptau; the new VK ships at a
///      new circuit_version per ADR-RM-M1-1's versioning rule.
pub const EXPECTED_PTAU_SHA256_K18: [u8; 32] = [
    0x96, 0x93, 0x22, 0x02, 0x06, 0xaf, 0xab, 0x74,
    0x9e, 0x3d, 0x88, 0xd4, 0xab, 0x5f, 0xdf, 0x5d,
    0x36, 0x12, 0x0e, 0xa1, 0x02, 0xe7, 0xe5, 0x87,
    0xcc, 0xea, 0x0e, 0x7a, 0x52, 0x08, 0xe7, 0x11,
];

/// Public canonical mirror for the .ptau file. This URL is the
/// PSE-hosted backup of contribution 0080 from the Perpetual
/// Powers of Tau ceremony. If this mirror also goes offline,
/// alternative paths are documented in `runbooks/SRS_DEPLOY.md`.
pub const DEFAULT_SRS_PTAU_URL: &str =
    "https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_18.ptau";

/// Recommended on-disk path. Configurable via the
/// `CITRATE_SRS_PATH` env var or the `srs_path` field on
/// `NodeConfig` (added when WP-M1b.4 wires the verifier into the
/// precompile).
pub const DEFAULT_SRS_PATH: &str = "/var/lib/citrate/srs/ppot_0080_18.ptau";

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
        "SRS .ptau parser not yet implemented — WP-M1b.2 PHASE 2 \
         owes the .ptau → halo2_proofs::ParamsKZG conversion. The \
         hash is locked, the file is reachable; the parser is a \
         focused next-session deliverable. See srs.rs header for \
         the implementation plan."
    )]
    ParserNotImplemented,
}

/// Verify the SHA-256 of the PPoT .ptau file at `path` matches
/// `EXPECTED_PTAU_SHA256_K18`. Returns `Ok(bytes)` on match —
/// the bytes are the raw .ptau file, ready for the WP-M1b.2 PHASE 2
/// parser to consume.
///
/// **Fail-closed semantics:**
/// 1. If the file doesn't exist, returns `NotFound`.
/// 2. If the file's SHA-256 doesn't match, returns `HashMismatch`
///    — the parse path is gated on this.
/// 3. On match, returns the bytes for the parser to consume.
///
/// The actual `.ptau → ParamsKZG<Bn256>` conversion lands in
/// WP-M1b.2 PHASE 2. Today this function returns the verified
/// bytes; the caller can either pass them to the parser (when
/// it lands) or treat the return as proof-of-provenance.
pub fn load_and_verify_ptau<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, SrsLoadError> {
    let path_ref = path.as_ref();
    if !path_ref.is_file() {
        return Err(SrsLoadError::NotFound {
            path: path_ref.display().to_string(),
        });
    }

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

    if actual_hash != EXPECTED_PTAU_SHA256_K18 {
        return Err(SrsLoadError::HashMismatch {
            expected: hex::encode(EXPECTED_PTAU_SHA256_K18),
            actual: hex::encode(actual_hash),
        });
    }

    Ok(bytes)
}

/// Load the PPoT k=18 SRS as a parsed `ParamsKZG<Bn256>` ready
/// for proving / verifying.
///
/// **WP-M1b.2 PHASE 2 owes the parser.** Today this function
/// hash-verifies the .ptau file (load_and_verify_ptau) and then
/// returns `ParserNotImplemented`. A future contributor lands
/// the .ptau-section-2-and-3 parser here. The return type is
/// stable across that change so callers can be authored against
/// this signature today.
pub fn load_srs_k18<P: AsRef<Path>>(path: P) -> Result<ParamsKZG<Bn256>, SrsLoadError> {
    let _bytes = load_and_verify_ptau(path)?;
    // WP-M1b.2 PHASE 2 fills this in:
    //   1. Read .ptau header (magic="ptau", version=1, sections=7)
    //   2. Locate section 1 (header) → verify curve = BN254, n=18
    //   3. Locate section 2 (tauG1) → read first 2^18 G1 affine points
    //      (each = 64 bytes uncompressed; on-curve check per point)
    //   4. Locate section 3 (tauG2) → read first 2 G2 affine points
    //      (each = 128 bytes uncompressed; on-curve + subgroup check)
    //   5. Construct ParamsKZG<Bn256> from the parsed points
    Err(SrsLoadError::ParserNotImplemented)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_reports_not_found() {
        // load_and_verify_ptau on a missing path returns NotFound,
        // not ParserNotImplemented (we never get to the parser
        // path). Discoverable error for ops if the SRS file isn't
        // staged at the expected location.
        let r = load_and_verify_ptau("/nonexistent/ppot_0080_18.ptau");
        assert!(matches!(r, Err(SrsLoadError::NotFound { .. })));
    }

    #[test]
    fn parser_not_implemented_is_explicit() {
        // WP-M1b.2 PHASE 2 owes the .ptau parser. Until it lands,
        // calling load_srs_k18 against a non-existent path returns
        // NotFound (the hash check is the second gate, not the
        // first); against a real file with matching hash, would
        // return ParserNotImplemented. Both are discoverable errors,
        // not silent fall-throughs.
        let r = load_srs_k18("/nonexistent/ppot_0080_18.ptau");
        assert!(
            matches!(r, Err(SrsLoadError::NotFound { .. })),
            "missing-file path returns NotFound; got {:?}",
            r
        );
    }

    #[test]
    fn srs_k_constant_is_18() {
        // If you change this, you must:
        //   1. update EXPECTED_PTAU_SHA256_K18 to the hash of the k=N file
        //   2. amend ADR-RM-M1b-1 with the new k value rationale
        //   3. update DEFAULT_SRS_PATH to match
        //   4. update DEFAULT_SRS_PTAU_URL to point at the right size
        //   5. inform anyone who has stored verifying keys against
        //      a circuit using the old k — those are now invalid
        assert_eq!(SRS_K, 18);
    }

    #[test]
    fn ptau_hash_is_pinned_not_sentinel() {
        // The hash MUST be locked. If somebody ever removes the
        // lock by reverting to the all-zeros sentinel, this test
        // catches it before the binary ships.
        assert_ne!(EXPECTED_PTAU_SHA256_K18, [0u8; 32]);
    }
}
