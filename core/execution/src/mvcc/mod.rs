//! Multi-Version Concurrency Control (MVCC) primitives for the executor.
//!
//! **Status:** integrated. As of Sprint P950-A-3 (2026-04-21), the
//! `CommitCoordinator` owns the executor's serialization lock and
//! advances per-account versions on each successful tx. The former
//! `execution_guard: tokio::sync::Mutex<()>` field in `executor.rs` has
//! been deleted and the `mvcc` feature flag removed.
//!
//! # Design
//!
//! This module implements the Block-STM / snapshot-versioning primitives
//! proven correct by
//! [`ExecutorMVCC.tla`](../../../../specs/tla/consensus/ExecutorMVCC.tla).
//!
//! Each concurrent worker holds:
//!
//! - A **pinned version** (`ReadVersion`) — the `StateVersion` at worker entry
//! - A **read set** (`ReadSet`) — accounts the worker observed during execution
//! - A **scratch journal** (`ScratchJournal`) — pending writes produced by the tx
//!
//! At commit time, a CAS operation checks whether any account in `ReadSet` has
//! been written since the pinned version. If not, the commit atomically applies
//! the journal and bumps the version. If any read was invalidated, the worker
//! aborts and retries against a fresh pin.
//!
//! # Spec mapping
//!
//! | TLA+ identifier | Rust equivalent |
//! |-----------------|-----------------|
//! | `globalVersion` | [`StateVersion`] |
//! | `workerReadVersion` | [`ReadVersion`] |
//! | `workerReadSet` | [`ReadSet`] |
//! | `workerWriteSet` | [`WriteSet`] (accounts only) / [`ScratchJournal`] (with values) |
//! | `ReadSetValid` | [`ReadSet::is_valid_at`] |
//! | `TryCommit` | (Sprint P950-A-3; scaffolded here as primitives) |
//! | `AbortAndRetry` | (Sprint P950-A-3; scaffolded here as primitives) |
//! | `FallbackToSerial` | (Sprint P950-A-3) |
//!
//! # Sprint
//!
//! `P950-A-2` (Phase A.2 of the executor-MVCC work). See
//! `.agentile/sprints/active/sprint-p950-a-2-executor-mvcc-impl/SPRINT.md`.

pub mod commit;
pub mod read_set;
pub mod retry;
pub mod scratch_journal;
pub mod version;
pub mod version_tracker;
pub mod write_set;

pub use commit::{AbortReason, CommitCoordinator, CommitOutcome};
pub use read_set::ReadSet;
pub use retry::{CommitSuccess, RetryHarness, RetryMetrics, DEFAULT_MAX_RETRIES};
pub use scratch_journal::{PendingWrite, ScratchJournal};
pub use version::{ReadVersion, StateVersion};
pub use version_tracker::AccountVersionTracker;
pub use write_set::WriteSet;

/// Shared handle to a per-tx [`ScratchJournal`] for concurrent use by the
/// executor, the REVM adapter, and the commit drain path.
///
/// Wrapped in `parking_lot::Mutex` (not tokio) because the access pattern
/// is always short: record-write or read-pending lookups, each sub-µs.
/// The outer `Arc` lets the handle be cheaply cloned into the adapter
/// without taking ownership of the journal.
pub type JournalHandle = std::sync::Arc<parking_lot::Mutex<ScratchJournal>>;
