//! Outcome rows.
//!
//! Every rig writes one row per measurement to a CSV under
//! `experiments_2026_XX/h{N}_*.csv`. The shared `Outcome` shape
//! captures the columns every rig needs; per-hypothesis extra
//! columns ride in `extra` (JSON-encoded) so the CSV stays
//! schema-stable across rigs.
//!
//! Schema stability is non-negotiable: H2's analysis script
//! must be able to read H1's CSV (e.g. for cross-experiment
//! aggregate visualization in the dashboard) without a custom
//! adapter per hypothesis.

use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

/// One measurement row. The columns map 1:1 to the Gherkin
/// outcome rows under `hypothesis_h{N}.feature`. New columns
/// require a coordinated change across all three rigs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Outcome {
    /// Which hypothesis: "H1" | "H2" | "H3".
    pub hypothesis: String,
    /// Trial index within the experiment run (0..N).
    pub trial: u32,
    /// Independent variable label (e.g. "K_pct=20" for H3,
    /// "N_adapters=50" for H2, "mislabel_rate=0.25" for H1).
    pub iv_label: String,
    /// Independent variable numeric value.
    pub iv_value: f64,
    /// Measured outcome value (e.g. held-out accuracy in Q16, drift
    /// L2 norm, fitted γ).
    pub outcome_value: f64,
    /// 95% confidence interval half-width on `outcome_value`.
    /// Zero is permitted (single-trial measurement).
    pub ci95_halfwidth: f64,
    /// Dataset CID (or "none" for synthetic-on-rig).
    pub dataset_cid: String,
    /// Random seed used for this trial.
    pub seed: u64,
    /// Per-hypothesis JSON blob for extra columns. H1 might encode
    /// `{"aggregation_method": "belnap", "region": "r4"}`; H3 might
    /// encode `{"checkpoint": 42, "byzantine_set": [...]}`.
    pub extra_json: String,
}

/// CSV-backed outcome writer. Append-only; one file per
/// (hypothesis, run) pair.
pub struct OutcomeWriter {
    inner: csv::Writer<std::fs::File>,
}

impl OutcomeWriter {
    /// Create or truncate `path` and write the header. Use this
    /// once per experiment run; subsequent calls open the file
    /// fresh (the rig is responsible for not concurrently writing
    /// to the same path).
    pub fn create(path: impl AsRef<Path>) -> Result<Self, OutcomeError> {
        let writer = csv::WriterBuilder::new()
            .has_headers(true)
            .from_path(path)
            .map_err(|e| OutcomeError::Open(e.to_string()))?;
        Ok(Self { inner: writer })
    }

    /// Append one outcome row.
    pub fn write(&mut self, row: &Outcome) -> Result<(), OutcomeError> {
        self.inner
            .serialize(row)
            .map_err(|e| OutcomeError::Write(e.to_string()))
    }

    /// Flush + close. The rig must call this before reporting
    /// "experiment complete" — without it, the last few rows may
    /// sit in the writer's buffer and be lost on a panic.
    pub fn finish(mut self) -> Result<(), OutcomeError> {
        self.inner
            .flush()
            .map_err(|e| OutcomeError::Write(e.to_string()))
    }
}

/// Errors for outcome writes.
#[derive(Debug, Error)]
pub enum OutcomeError {
    /// File-open failed.
    #[error("could not open outcome CSV: {0}")]
    Open(String),
    /// Serialization or flush failed.
    #[error("could not write outcome row: {0}")]
    Write(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn roundtrip_one_row() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("h1_test.csv");
        {
            let mut w = OutcomeWriter::create(&path).expect("create");
            w.write(&Outcome {
                hypothesis: "H1".to_owned(),
                trial: 0,
                iv_label: "mislabel_rate".to_owned(),
                iv_value: 0.25,
                outcome_value: 0.873,
                ci95_halfwidth: 0.012,
                dataset_cid: "baexamplecid".to_owned(),
                seed: 42,
                extra_json: r#"{"agg":"belnap"}"#.to_owned(),
            })
            .expect("write");
            w.finish().expect("flush");
        }

        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.contains("H1"));
        assert!(text.contains("baexamplecid"));
        assert!(text.contains("0.873"));
    }
}
