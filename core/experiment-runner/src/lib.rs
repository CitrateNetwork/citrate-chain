// SPDX-License-Identifier: MIT
//
// citrate-experiment-runner — RM-FL-5 / WP-5.9
//
// Shared rig harness for the three hypothesis experiments in
// Paper II §4. The H1/H2/H3 rigs landed at WP-5.3, WP-5.5, and WP-5.7
// share dataset loading, seed management, daemon orchestration, and
// outcome aggregation through this crate. This avoids the divergent-
// harness drift the planset called out as a risk.
//
// Same structural pattern as RM-FL-4's `_validatePairing` extraction:
// the helper IS the protocol. Three rigs reaching for the same
// `ExperimentRunner` API means a change to that API forces all three
// to update together — a desync between H1's rig and H3's rig is now
// a compile error, not a measurement bug.
//
// At kickoff (this commit), only the trait surface and a stub
// implementation land. The H1/H2/H3 specific drivers in `h1.rs`,
// `h2.rs`, `h3.rs` arrive with WP-5.3 / 5.5 / 5.7. Tripwires
// (`check_h1_dataset_pinned.py` etc.) flip from state-A to enforcing
// once the corresponding source-of-truth files appear in
// `scripts/h{1,2,3}/`.

#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Shared rig harness for RM-FL-5 hypothesis experiments.
//!
//! See the [`Outcome`] type for the canonical row format every rig
//! emits, and [`Rig`] for the trait every per-hypothesis driver
//! implements. The crate's job is to keep the three drivers in
//! lockstep — same dataset-loading semantics, same seed handling,
//! same outcome columns, same daemon orchestration entry points.

pub mod dataset;
pub mod outcome;
pub mod rig;
pub mod seed;

pub use dataset::{DatasetCid, DatasetSpec};
pub use outcome::{Outcome, OutcomeWriter};
pub use rig::{Rig, RigError};
pub use seed::{ExperimentSeed, SeededRng};
