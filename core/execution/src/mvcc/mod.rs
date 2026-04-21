//! Multi-Version Concurrency Control (MVCC) primitives for the executor.
//!
//! **Status:** scaffolded; not yet wired into `Executor::execute_transaction`.
//! Feature-gated behind `mvcc` (default off). When the flag is off, none of
//! this code compiles into the release binary — the existing
//! `execution_guard: tokio::sync::Mutex<()>` path in `executor.rs:85` is
//! unaffected.
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

pub mod read_set;
pub mod scratch_journal;
pub mod version;
pub mod version_tracker;
pub mod write_set;

pub use read_set::ReadSet;
pub use scratch_journal::ScratchJournal;
pub use version::{ReadVersion, StateVersion};
pub use version_tracker::AccountVersionTracker;
pub use write_set::WriteSet;
