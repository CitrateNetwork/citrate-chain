//! Ceremony fingerprint validator.
//!
//! The config declares the sha256 of the proof bundle. Before a run,
//! this module:
//!
//! 1. computes the sha256 of the on-disk ceremony bundle
//! 2. compares it against the config's declared hash
//! 3. parses `60_manifest.json` and cross-checks chain id
//!
//! Any mismatch is a hard refusal. This is the primary defense against
//! the rehearsal/testnet confusion failure mode: you cannot accidentally
//! benchmark chain 40205 and report it as chain 40204.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    #[serde(rename = "chainId", alias = "chain_id")]
    pub chain_id: u64,
    #[serde(default)]
    pub timestamp: Option<String>,
    #[serde(default, rename = "gitCommit", alias = "git_commit")]
    pub git_commit: Option<String>,
    #[serde(default, rename = "bundleSha256", alias = "bundle_sha256")]
    pub bundle_sha256: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

pub fn load_manifest(path: &Path) -> Result<Manifest> {
    let contents = std::fs::read_to_string(path)?;
    let m: Manifest = serde_json::from_str(&contents)?;
    Ok(m)
}

/// Compute sha256 of the on-disk ceremony bundle and compare to the
/// expected hash. Accepts the `sha256:` prefix on `expected`.
pub fn verify_bundle_sha256(bundle_path: &Path, expected: &str) -> Result<()> {
    let expected = expected.strip_prefix("sha256:").unwrap_or(expected);
    let bytes = std::fs::read(bundle_path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let actual = hex::encode(hasher.finalize());
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(Error::Fingerprint(format!(
            "bundle sha256 mismatch: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

/// Full precondition check: manifest parses, its chain id matches the
/// config's chain id, and (if provided) its `bundle_sha256` matches
/// the config's `ceremony_bundle_sha256`.
pub fn verify_manifest(
    manifest_path: &Path,
    expected_chain_id: u64,
    expected_bundle_sha256: &str,
) -> Result<Manifest> {
    let m = load_manifest(manifest_path)?;
    if m.chain_id != expected_chain_id {
        return Err(Error::Fingerprint(format!(
            "manifest chain_id {} != expected {}",
            m.chain_id, expected_chain_id
        )));
    }
    if let Some(recorded) = &m.bundle_sha256 {
        let expected = expected_bundle_sha256
            .strip_prefix("sha256:")
            .unwrap_or(expected_bundle_sha256);
        let recorded_clean = recorded.strip_prefix("sha256:").unwrap_or(recorded);
        if !recorded_clean.eq_ignore_ascii_case(expected) {
            return Err(Error::Fingerprint(format!(
                "manifest bundle_sha256 mismatch: manifest={recorded_clean} config={expected}"
            )));
        }
    }
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_bytes(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(bytes).expect("write");
        f.flush().expect("flush");
        f
    }

    #[test]
    fn sha256_of_hello_world() {
        let f = write_bytes(b"hello world");
        // Known sha256("hello world") = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
        verify_bundle_sha256(
            f.path(),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        )
        .expect("match");
    }

    #[test]
    fn sha256_accepts_prefix() {
        let f = write_bytes(b"hello world");
        verify_bundle_sha256(
            f.path(),
            "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        )
        .expect("match");
    }

    #[test]
    fn sha256_mismatch_errors() {
        let f = write_bytes(b"hello world");
        assert!(verify_bundle_sha256(
            f.path(),
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .is_err());
    }

    #[test]
    fn manifest_parses_camel_and_snake() {
        let f1 = write_bytes(br#"{"chainId":40204,"bundleSha256":"sha256:abc"}"#);
        let f2 = write_bytes(br#"{"chain_id":40204,"bundle_sha256":"sha256:abc"}"#);
        let a = load_manifest(f1.path()).expect("camel");
        let b = load_manifest(f2.path()).expect("snake");
        assert_eq!(a.chain_id, b.chain_id);
        assert_eq!(a.bundle_sha256, b.bundle_sha256);
    }

    #[test]
    fn verify_manifest_happy_path() {
        let f = write_bytes(
            br#"{"chainId":40204,"bundleSha256":"sha256:0000000000000000000000000000000000000000000000000000000000000001"}"#,
        );
        verify_manifest(
            f.path(),
            40204,
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .expect("match");
    }

    #[test]
    fn verify_manifest_rejects_wrong_chain_id() {
        let f = write_bytes(br#"{"chainId":40205}"#);
        assert!(verify_manifest(f.path(), 40204, "irrelevant").is_err());
    }

    #[test]
    fn verify_manifest_rejects_wrong_bundle_hash() {
        let f = write_bytes(
            br#"{"chainId":40204,"bundleSha256":"aa"}"#,
        );
        assert!(verify_manifest(f.path(), 40204, "bb").is_err());
    }
}
