//! The `Rig` trait — the contract every per-hypothesis driver
//! implements.
//!
//! H1, H2, H3 each define their own struct that holds the dataset,
//! seed list, and any rig-specific configuration. The trait gives
//! the orchestrator (and the parallel executor at WP-5.10) one
//! uniform way to drive any rig: call `prepare`, then `run_trial`
//! N times, then `finalize`.
//!
//! Compile-time agreement on the trait is the whole point. A rig
//! that fails to implement `Rig` is not allowed to run.

use crate::dataset::DatasetSpec;
use crate::outcome::Outcome;
use crate::seed::ExperimentSeed;
use async_trait::async_trait;
use thiserror::Error;

/// Errors any rig can produce. Per-hypothesis rigs may add their
/// own variants by wrapping in a sibling enum and converting.
#[derive(Debug, Error)]
pub enum RigError {
    /// The pinning files (CID, seeds) were missing or malformed.
    #[error("rig configuration error: {0}")]
    Config(String),
    /// The chain-side daemon refused or timed out.
    #[error("daemon orchestration error: {0}")]
    Daemon(String),
    /// Outcome writer failed.
    #[error("outcome write error: {0}")]
    Outcome(String),
    /// Generic experiment failure (the rig diagnoses).
    #[error("experiment failure: {0}")]
    Experiment(String),
}

/// Result of one trial. The rig converts this to one or more
/// `Outcome` rows; the caller passes those rows to `OutcomeWriter`.
#[derive(Debug, Clone)]
pub struct TrialResult {
    /// Outcome rows produced by this trial. A single trial may
    /// emit multiple rows (e.g. H2's per-N measurements).
    pub rows: Vec<Outcome>,
}

/// The shared rig contract. Implementors define a per-hypothesis
/// struct holding configuration; `prepare` loads the pinned dataset
/// + seeds; `run_trial` drives one experiment with one seed; `name`
/// returns "H1" / "H2" / "H3".
#[async_trait]
pub trait Rig: Send + Sync {
    /// Identifier — e.g. "H1".
    fn name(&self) -> &str;

    /// Load the pinned dataset + validate any rig-specific config.
    /// Idempotent — calling twice is allowed.
    async fn prepare(&mut self) -> Result<DatasetSpec, RigError>;

    /// Run one trial with a given seed. Returns one or more outcome
    /// rows. The rig MUST be deterministic given (dataset, seed) —
    /// the reproducibility scenarios in `hypothesis_h{N}.feature`
    /// depend on this.
    async fn run_trial(
        &mut self,
        seed: ExperimentSeed,
    ) -> Result<TrialResult, RigError>;

    /// Final cleanup. Releases any held resources; the rig is
    /// allowed to be reused across experiment runs after this
    /// returns successfully.
    async fn finalize(&mut self) -> Result<(), RigError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stub rig that only exists for trait-shape tests. Returns
    /// no rows. NOT a production type — `#[cfg(test)]`-gated per
    /// the no-stubs-in-production rule from CLAUDE.md.
    struct StubRig;

    #[async_trait]
    impl Rig for StubRig {
        fn name(&self) -> &str {
            "STUB"
        }
        async fn prepare(&mut self) -> Result<DatasetSpec, RigError> {
            use crate::dataset::DatasetCid;
            Ok(DatasetSpec {
                cid: DatasetCid::parse("baexamplecidxxxxxxxxx").unwrap(),
                label: "stub".to_owned(),
                example_count: 0,
            })
        }
        async fn run_trial(
            &mut self,
            _seed: ExperimentSeed,
        ) -> Result<TrialResult, RigError> {
            Ok(TrialResult { rows: vec![] })
        }
        async fn finalize(&mut self) -> Result<(), RigError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn stub_rig_implements_trait() {
        let mut rig = StubRig;
        assert_eq!(rig.name(), "STUB");
        let spec = rig.prepare().await.expect("prepare");
        assert_eq!(spec.label, "stub");
        let result = rig.run_trial(ExperimentSeed(1)).await.expect("trial");
        assert!(result.rows.is_empty());
        rig.finalize().await.expect("finalize");
    }
}
