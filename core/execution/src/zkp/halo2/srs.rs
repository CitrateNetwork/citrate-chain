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

// ---------------------------------------------------------------------------
// PIN-P1 (f.4) — Multi-`k` PPoT loader infrastructure.
//
// The original single-`k` loader (k=18) is preserved as a thin shim
// around the multi-`k` core. New `k` values are added to the `PINNED`
// table; until a hash is captured + reviewed, the entry's
// `expected_sha256` stays `None` and the loader fails closed with
// `HashNotPinned` (the URL + capture procedure is in the error body).
//
// Ceremony: SAME PSE-hosted Perpetual Powers of Tau (`pot28_0080`)
// that anchors v1 inference. Using larger powers from the SAME chain
// inherits the same 1-of-N trust model — no new ceremony required.
// See `handoffs/PIN_DGX_NEXT_STEPS.md` §(f.4) for rationale.
// ---------------------------------------------------------------------------

/// One ceremony power-of-tau entry: which `k`, what hash to enforce,
/// where the canonical file lives, when the hash was captured.
#[derive(Clone, Debug)]
pub struct PinnedSrsK {
    pub k: u32,
    /// SHA-256 of the canonical .ptau file for this `k`. `None` until
    /// an operator captures + reviews the hash; the loader fails
    /// closed with `HashNotPinned` in that case.
    pub expected_sha256: Option<[u8; 32]>,
    /// Canonical PSE bucket URL — the recommended fetch source.
    pub canonical_url: &'static str,
    /// Recommended on-disk path (overridable via env / config).
    pub default_path: &'static str,
    /// Capture date for `expected_sha256` (ISO 8601, informational).
    pub captured_at: Option<&'static str>,
}

/// Canonical pinned-k table. ADD an entry here when introducing a new
/// circuit size; PIN the hash only after sha256-verifying the file
/// fetched from `canonical_url`.
///
/// **Order matters for human review.** Smallest `k` first; new entries
/// appended.
pub const PINNED: &[PinnedSrsK] = &[
    PinnedSrsK {
        k: 18,
        expected_sha256: Some([
            0x96, 0x93, 0x22, 0x02, 0x06, 0xaf, 0xab, 0x74, 0x9e, 0x3d, 0x88, 0xd4, 0xab, 0x5f,
            0xdf, 0x5d, 0x36, 0x12, 0x0e, 0xa1, 0x02, 0xe7, 0xe5, 0x87, 0xcc, 0xea, 0x0e, 0x7a,
            0x52, 0x08, 0xe7, 0x11,
        ]),
        canonical_url:
            "https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_18.ptau",
        default_path: "/var/lib/citrate/srs/ppot_0080_18.ptau",
        captured_at: Some("2026-04-27"),
    },
    // PIN-P1 (f.4) ADDITIONS — sized for the f.3 aggregation root + leaf
    // circuits. Hash pinning is an OPS task: download from canonical_url,
    // run sha256sum, file a follow-up PR replacing `expected_sha256:
    // None` with `Some([...])` here + an updated `srs_provenance_v1.json`
    // entry + an ADR amendment per the WP-M1b.2 stability rule.
    PinnedSrsK {
        k: 22,
        expected_sha256: None,
        canonical_url:
            "https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_22.ptau",
        default_path: "/var/lib/citrate/srs/ppot_0080_22.ptau",
        captured_at: None,
    },
    PinnedSrsK {
        k: 24,
        expected_sha256: None,
        canonical_url:
            "https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_24.ptau",
        default_path: "/var/lib/citrate/srs/ppot_0080_24.ptau",
        captured_at: None,
    },
    PinnedSrsK {
        k: 25,
        expected_sha256: None,
        canonical_url:
            "https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_25.ptau",
        default_path: "/var/lib/citrate/srs/ppot_0080_25.ptau",
        captured_at: None,
    },
];

/// Look up the pinned-k entry for a given `k`. `None` if the chain
/// hasn't allocated that ceremony power yet.
pub fn pinned_entry_for(k: u32) -> Option<&'static PinnedSrsK> {
    PINNED.iter().find(|p| p.k == k)
}

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
    0x96, 0x93, 0x22, 0x02, 0x06, 0xaf, 0xab, 0x74, 0x9e, 0x3d, 0x88, 0xd4, 0xab, 0x5f, 0xdf, 0x5d,
    0x36, 0x12, 0x0e, 0xa1, 0x02, 0xe7, 0xe5, 0x87, 0xcc, 0xea, 0x0e, 0x7a, 0x52, 0x08, 0xe7, 0x11,
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
        "SRS file hash mismatch for k={k}: expected {expected}, got {actual}. \
         Either the file is wrong (re-fetch from the canonical mirror) \
         or the pinned hash for this k has drifted from the deployed file \
         (catastrophic — every prior verifying key keyed on this k is invalid)."
    )]
    HashMismatch {
        k: u32,
        expected: String,
        actual: String,
    },

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

    /// The requested `k` has no entry in `PINNED`. Add one before
    /// using this `k`.
    #[error(
        "no PPoT entry for k={k} — extend `srs::PINNED` with the canonical \
         URL + a future hash pin before circuits at this size can build."
    )]
    UnsupportedK { k: u32 },

    /// The `k` is in the table but the hash is `None` — operator
    /// hasn't captured + reviewed it yet. Fetch `url` and pin per the
    /// WP-M1b.2 stability rule.
    #[error(
        "SRS hash for k={k} is not yet pinned. \
         Fetch {url} and run `sha256sum`, then edit `srs::PINNED` to \
         pin `expected_sha256` for this k + update \
         `tests/fixtures/srs_provenance_v1.json` + amend the ADR (per \
         the WP-M1b.2 stability rule). Production builds MUST fail \
         closed until this is done."
    )]
    HashNotPinned { k: u32, url: &'static str },
}

/// Verify the SHA-256 of the PPoT .ptau file at `path` matches the
/// hash pinned for `k` in [`PINNED`]. Returns `Ok(bytes)` on match —
/// the bytes are the raw .ptau file, ready for `ptau::parse_ptau_for_kzg`
/// to consume.
///
/// **Fail-closed semantics:**
/// 1. If `k` has no entry in `PINNED`, returns `UnsupportedK` (no I/O).
/// 2. If `k`'s entry has no pinned hash yet, returns `HashNotPinned`
///    (no I/O — the operator hasn't completed the WP-M1b.2 hash
///    capture procedure for this `k`).
/// 3. If the file doesn't exist, returns `NotFound`.
/// 4. If the file's SHA-256 doesn't match, returns `HashMismatch`
///    — the parse path is gated on this.
/// 5. On match, returns the bytes.
pub fn load_and_verify_ptau<P: AsRef<Path>>(path: P, k: u32) -> Result<Vec<u8>, SrsLoadError> {
    let entry = pinned_entry_for(k).ok_or(SrsLoadError::UnsupportedK { k })?;
    let expected = entry.expected_sha256.ok_or(SrsLoadError::HashNotPinned {
        k,
        url: entry.canonical_url,
    })?;
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

    if actual_hash != expected {
        return Err(SrsLoadError::HashMismatch {
            k,
            expected: hex::encode(expected),
            actual: hex::encode(actual_hash),
        });
    }

    Ok(bytes)
}

/// Load the PPoT SRS at `k` as a parsed `ParamsKZG<Bn256>` ready
/// for proving / verifying.
///
/// PIN-P1 (f.4) — multi-`k` loader. Thin wrapper over the pipeline
/// in [`super::ptau::load_ptau_into_params_kzg`] (hash-verify +
/// section parse + on-curve check + construct halo2 params), gated
/// by [`PINNED`] for `k`. New `k` values surface here automatically
/// once an entry + hash is added to `PINNED`.
pub fn load_srs<P: AsRef<Path>>(k: u32, path: P) -> Result<ParamsKZG<Bn256>, SrsLoadError> {
    // Pre-flight the hash gating BEFORE handing to ptau.rs so an
    // UnsupportedK / HashNotPinned is surfaced cleanly (ptau.rs would
    // hit the same error via `load_and_verify_ptau`, but the
    // pre-flight makes the failure mode obvious in callsite traces).
    let _entry = pinned_entry_for(k).ok_or(SrsLoadError::UnsupportedK { k })?;
    super::ptau::load_ptau_into_params_kzg(path, k)
}

/// Backwards-compat shim — `load_srs(18, path)`. Callers should
/// migrate to the parameterised [`load_srs`].
pub fn load_srs_k18<P: AsRef<Path>>(path: P) -> Result<ParamsKZG<Bn256>, SrsLoadError> {
    load_srs(SRS_K, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Existing k=18 behaviour (preserved) ──

    #[test]
    fn missing_file_reports_not_found_at_k18() {
        // load_and_verify_ptau on a missing path returns NotFound for
        // a PINNED + hash-present k. Discoverable error for ops if
        // the SRS file isn't staged at the expected location.
        let r = load_and_verify_ptau("/nonexistent/ppot_0080_18.ptau", 18);
        assert!(matches!(r, Err(SrsLoadError::NotFound { .. })));
    }

    #[test]
    fn srs_k_constant_is_18() {
        // The legacy default k. Larger ks are opt-in via load_srs(k, ..).
        assert_eq!(SRS_K, 18);
    }

    #[test]
    fn legacy_k18_constant_matches_pinned_table() {
        // EXPECTED_PTAU_SHA256_K18 is preserved as the legacy public
        // constant for tests + provenance script + ADR references.
        // It MUST equal the k=18 entry in PINNED — drift here is a
        // catastrophic provenance regression.
        let entry = pinned_entry_for(18).expect("k=18 PINNED entry exists");
        assert_eq!(
            entry.expected_sha256,
            Some(EXPECTED_PTAU_SHA256_K18),
            "PINNED[k=18].expected_sha256 must equal EXPECTED_PTAU_SHA256_K18"
        );
    }

    #[test]
    fn ptau_hash_is_pinned_not_sentinel_at_k18() {
        // The hash MUST be locked. If somebody ever removes the
        // lock by reverting to the all-zeros sentinel, this test
        // catches it before the binary ships.
        assert_ne!(EXPECTED_PTAU_SHA256_K18, [0u8; 32]);
    }

    // ── PIN-P1 (f.4) — multi-k routing ──

    #[test]
    fn unsupported_k_rejects_without_io() {
        // A k with no PINNED entry MUST fail closed BEFORE any I/O —
        // this is the gate that keeps a typo from silently building a
        // VK against an unknown ceremony.
        let r = load_and_verify_ptau("/nonexistent/file.ptau", 99);
        assert!(
            matches!(r, Err(SrsLoadError::UnsupportedK { k: 99 })),
            "k=99 must return UnsupportedK; got {r:?}"
        );

        let r2 = load_srs(99, "/nonexistent/file.ptau");
        assert!(
            matches!(r2, Err(SrsLoadError::UnsupportedK { k: 99 })),
            "load_srs(99, ..) must return UnsupportedK; got {r2:?}"
        );
    }

    #[test]
    fn unpinned_k_rejects_with_url_for_ops() {
        // f.4 adds k=22, k=24, k=25 entries with no hash pinned yet.
        // Loading at those k MUST fail closed with `HashNotPinned` +
        // the canonical URL in the error so an operator can
        // immediately see what file to fetch + sha256sum to capture.
        for k in [22u32, 24, 25] {
            let r = load_and_verify_ptau("/nonexistent/file.ptau", k);
            match r {
                Err(SrsLoadError::HashNotPinned { k: rk, url }) => {
                    assert_eq!(rk, k, "k field in error matches request");
                    assert!(
                        url.starts_with(
                            "https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/"
                        ),
                        "url is the PSE canonical mirror: {url}"
                    );
                    assert!(
                        url.ends_with(&format!("ppot_0080_{k}.ptau")),
                        "url ends with the per-k file name: {url}"
                    );
                }
                other => panic!("k={k} must return HashNotPinned; got {other:?}"),
            }
        }
    }

    #[test]
    fn pinned_table_is_ordered_and_unique() {
        // Catches a stray duplicate or out-of-order entry inserted by
        // future contributors. The order matters for human review of
        // the table; uniqueness matters for `pinned_entry_for` to be
        // deterministic.
        let ks: Vec<u32> = PINNED.iter().map(|p| p.k).collect();
        let mut sorted = ks.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ks, sorted, "PINNED must be in ascending unique k order");
    }

    #[test]
    fn pinned_default_paths_match_per_k_filename() {
        // The default path's basename matches `ppot_0080_<k>.ptau` — a
        // typo in the path constant has caused real ops incidents
        // (wrong file fetched, hash mismatch surfaces too late).
        for entry in PINNED {
            assert!(
                entry
                    .default_path
                    .ends_with(&format!("ppot_0080_{}.ptau", entry.k)),
                "k={} default_path basename mismatch: {}",
                entry.k,
                entry.default_path,
            );
            assert!(
                entry
                    .canonical_url
                    .ends_with(&format!("ppot_0080_{}.ptau", entry.k)),
                "k={} canonical_url basename mismatch: {}",
                entry.k,
                entry.canonical_url,
            );
        }
    }

    #[test]
    fn load_srs_k18_is_thin_shim_over_load_srs() {
        // The legacy entry point is preserved as a backwards-compat
        // shim. It MUST resolve to the same error path as
        // `load_srs(18, _)` on a missing file — discoverable, no
        // silent fall-through.
        let legacy = load_srs_k18("/nonexistent/ppot_0080_18.ptau");
        let modern = load_srs(18, "/nonexistent/ppot_0080_18.ptau");
        match (legacy, modern) {
            (Err(SrsLoadError::NotFound { .. }), Err(SrsLoadError::NotFound { .. })) => {}
            (l, m) => panic!(
                "both paths must surface NotFound on missing file; got legacy={l:?}, modern={m:?}"
            ),
        }
    }
}
