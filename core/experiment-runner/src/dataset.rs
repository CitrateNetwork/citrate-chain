//! Pinned dataset references.
//!
//! Each hypothesis rig consumes a content-addressed dataset whose
//! CID is pinned in `scripts/h{N}/dataset_cid.txt` and enforced by
//! `check_h{N}_dataset_pinned.py`. The rig loads the CID via this
//! module — never inline-strings the CID in source — so a rotation
//! requires the tripwire-enforced source file to change.

use std::path::PathBuf;
use thiserror::Error;

/// Validated content-addressed dataset reference. `0xbytes32` and
/// CIDv1-base32 are both accepted; the `check_h{N}_dataset_pinned.py`
/// tripwires use the same regex set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetCid(String);

impl DatasetCid {
    /// Parse a single non-comment line from a pinning file. The
    /// rig crate is intentionally lax here — the tripwire is the
    /// canonical validator. We just strip and reject empty.
    pub fn parse(raw: &str) -> Result<Self, DatasetError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(DatasetError::Empty);
        }
        if trimmed.starts_with('#') {
            return Err(DatasetError::CommentLine);
        }
        Ok(Self(trimmed.to_owned()))
    }

    /// Read the active CID from a pinning file. Skips blank lines
    /// and `#` comments; returns the FIRST non-comment line. The
    /// tripwire ensures rotations are documented in comments above
    /// the active line.
    pub fn from_pinning_file(path: &PathBuf) -> Result<Self, DatasetError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| DatasetError::Read(path.clone(), e.to_string()))?;
        for line in text.lines() {
            match Self::parse(line) {
                Ok(cid) => return Ok(cid),
                Err(DatasetError::Empty | DatasetError::CommentLine) => {
                    continue
                }
                Err(e) => return Err(e),
            }
        }
        Err(DatasetError::NoActiveCid(path.clone()))
    }

    /// The wire form (CIDv1 base32 or 0x-bytes32 hex). Pass-through
    /// for IPFS / on-chain hash usage.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Hypothesis-specific dataset metadata, loaded alongside the CID.
/// H1 cares about regions; H2 about test-set partitioning; H3 about
/// validator-set construction. The shared shape captures only what
/// every rig needs to record in its outcome row — everything else
/// stays per-rig.
#[derive(Debug, Clone)]
pub struct DatasetSpec {
    /// Content-addressed reference to the dataset.
    pub cid: DatasetCid,
    /// Human-readable label (e.g. "h1_4region_mnist_v1").
    pub label: String,
    /// Total example count (for sanity checks against IPFS payload).
    pub example_count: usize,
}

/// Errors produced when loading or parsing dataset references.
#[derive(Debug, Error)]
pub enum DatasetError {
    /// The pinning file line was empty after trimming.
    #[error("dataset pinning line was empty")]
    Empty,
    /// The line was a comment; not a CID.
    #[error("dataset pinning line is a comment, not a CID")]
    CommentLine,
    /// File I/O error.
    #[error("could not read pinning file {0:?}: {1}")]
    Read(PathBuf, String),
    /// The file existed but had no non-comment line.
    #[error("no active CID in pinning file {0:?}")]
    NoActiveCid(PathBuf),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_skips_comments_and_blanks() {
        assert!(matches!(
            DatasetCid::parse("# rotation note"),
            Err(DatasetError::CommentLine)
        ));
        assert!(matches!(
            DatasetCid::parse("   "),
            Err(DatasetError::Empty)
        ));
        let ok = DatasetCid::parse("baexamplecidvalue").expect("ok");
        assert_eq!(ok.as_str(), "baexamplecidvalue");
    }

    #[test]
    fn parse_accepts_0x_bytes32_form() {
        let ok = DatasetCid::parse(
            "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        )
        .expect("ok");
        assert!(ok.as_str().starts_with("0x"));
    }
}
