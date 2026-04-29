//! Off-chain learning daemon — RM-FL-3.
//!
//! Orchestrates the federated learning loop end-to-end:
//!
//!   1. Watch finalized blocks via the chain RPC; advance HWM
//!      monotonically forward (`watcher.rs`).
//!   2. Decode `LearningCycleManager` events into typed
//!      [`LearningEvent`] instances and dispatch to the orchestrator.
//!   3. At cycle close: aggregate embeddings via precompile `0x0110`
//!      (Belnap, RM-FL-1) and commit the result to chain
//!      (`aggregator.rs`, lands at WP-3.6).
//!   4. Retrain routing-model weights off-chain (candle SGD → Q16
//!      quantize → IPFS pin → CID commit) so precompile `0x0111`
//!      (routing inference, RM-FL-2) can consume them
//!      (`trainer.rs`, lands at WP-3.7).
//!   5. Call `LearningCycleManager.finalizeCycle` exactly once per
//!      cycle; rewards distribute on-chain
//!      (`finalizer.rs`, lands at WP-3.8).
//!   6. Expose a public read-only dashboard API at
//!      `/api/cycles`, `/api/embeddings`, `/api/mentors`
//!      (`dashboard.rs`, lands at WP-3.16).
//!
//! # Design contracts
//!
//! All daemon-side invariants are formalized in
//! [`LearningDaemon.tla`][1] (9 invariants, TLC-clean over 325
//! distinct states):
//!
//!   - `BlockHWMMonotonic` — last_processed_block never decreases
//!   - `BlockHWMBoundedByChain` — never claim to have processed a
//!     block the chain hasn't produced
//!   - `AggregationIdempotent` — re-running aggregation on the same
//!     cycle yields bit-identical output
//!   - `FinalizeAtMostOnce` — `finalizeCycle(c)` called ≤1 time per c
//!   - `FinalizeRequiresCommit` — finalize gated on aggregation
//!     commit being on-chain
//!   - `RestartSafety` — after SIGKILL+restart, RocksDB-backed
//!     state survives in-memory wipe
//!
//! [1]: ../../specs/tla/learning/LearningDaemon.tla
//!
//! # Status (RM-FL-3, WP-3.3 + WP-3.5)
//!
//!   - Types + chain trait + FakeChain + state + watcher: GREEN.
//!   - Aggregator / trainer / finalizer / dashboard: scaffolded as
//!     trait stubs; implementation at WP-3.6 / WP-3.7 / WP-3.8 /
//!     WP-3.16 respectively.
//!   - HttpChainAdapter (production RPC): WP-3.5 slice 2
//!     (this WP ships only the trait + fake impl for unit tests).

#![warn(missing_docs)]

pub mod aggregator;
pub mod chain;
pub mod error;
pub mod finalizer;
pub mod orchestrator;
pub mod state;
pub mod types;
pub mod watcher;

pub use aggregator::{BelnapAggregator, EmbeddingCache, EmbeddingEntry, MemoryEmbeddingCache};
pub use chain::{ChainAdapter, FakeChain, LearningEvent};
pub use error::DaemonError;
pub use finalizer::{try_finalize_cycle, ChainFinalizer};
pub use orchestrator::Orchestrator;
pub use state::{CycleStatus, DaemonState, FinalizeStatus};
pub use types::{BlockNumber, CycleId, EmbeddingSubmission};
pub use watcher::BlockWatcher;
