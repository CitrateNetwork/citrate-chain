// citrate/core/execution/src/zkp/halo2/srs.rs
//
// RM-M1b WP-M1b.2 — Powers of Tau SRS loader.
//
// The SRS file is downloaded out-of-band from the public PPoT
// mirror (per ADR-RM-M1b-1) and stored on the node host. This
// module loads it from disk, verifies the SHA-256 against an
// embedded constant, and parses it into a `halo2_proofs::poly::kzg`
// `ParamsKZG<Bn256>` that the verifier can consume.
//
// **Stability:** the embedded SHA-256 is FROZEN. Any change to
// the SRS file (including a "drop-in replacement" with the same
// bytes from a different mirror) requires:
//   1. amending ADR-RM-M1b-1 with the new hash
//   2. updating `EXPECTED_SHA256_K20` below
//   3. amending `srs_provenance_v1.json` (the CI-checked fixture)
//   4. rebuilding the verifying key for every active circuit
//      version (which forces a new `circuit_version` allocation;
//      old commitments remain verifiable forever per the
//      versioning rule from ADR-RM-M1-1)
//
// The CI verifier `scripts/ci/check_m1b_srs_provenance.py`
// enforces the EXPECTED_SHA256 ↔ ADR ↔ fixture coupling.

use std::path::Path;

/// SHA-256 of the canonical PPoT k=20 SRS file (bn256, halo2-kzg
/// raw format). Locked once the file is downloaded + hashed in
/// WP-M1b.2 deployment.
///
/// Today this is a sentinel "all zeros" value — `load_srs` will
/// reject any real file against it. WP-M1b.2 sets the actual hash
/// after the SRS is fetched + verified.
pub const EXPECTED_SHA256_K20: [u8; 32] = [0u8; 32];

#[derive(Debug, thiserror::Error)]
pub enum SrsLoadError {
    #[error("SRS file not found at {path}")]
    NotFound { path: String },

    #[error("SRS file I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("SRS file hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    #[error("SRS file failed to parse as halo2 ParamsKZG<Bn256>")]
    Parse,

    #[error(
        "SRS provenance not yet pinned — EXPECTED_SHA256_K20 is the \
         all-zeros sentinel. Update srs.rs after WP-M1b.2 fetches the \
         real PPoT file and computes its hash."
    )]
    ProvenanceNotPinned,
}

/// Load the PPoT k=20 SRS from `path`, verifying its SHA-256
/// against the embedded `EXPECTED_SHA256_K20`. Returns a parsed
/// `ParamsKZG<Bn256>` ready for proving / verifying.
///
/// Until WP-M1b.2 finalizes the hash, this function returns
/// `ProvenanceNotPinned` on the all-zeros sentinel — fail-closed
/// so a contributor cannot accidentally ship a verifier with no
/// hash check.
pub fn load_srs_k20<P: AsRef<Path>>(_path: P) -> Result<(), SrsLoadError> {
    if EXPECTED_SHA256_K20 == [0u8; 32] {
        return Err(SrsLoadError::ProvenanceNotPinned);
    }
    // WP-M1b.2 fills this in: read file, hash, compare, parse.
    Err(SrsLoadError::Parse)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_not_pinned_is_explicit() {
        // Until WP-M1b.2 sets a real hash, the loader fails with
        // a discoverable error rather than a silent "loaded fine".
        let r = load_srs_k20("/nonexistent");
        assert!(matches!(r, Err(SrsLoadError::ProvenanceNotPinned)));
    }
}
