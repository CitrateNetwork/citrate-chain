// citrate/core/execution/src/lib.rs

// Re-export modules
pub mod address_utils;
pub mod crypto;
pub mod executor;
pub mod inference;
pub mod metrics;
pub mod parallel;
pub mod precompiles;
pub mod revm_adapter;
pub mod state;
pub mod tensor;
pub mod types;
pub mod vm;

// Multi-Version Concurrency Control (MVCC) primitives. Scaffolded in
// Sprint P950-A-2, gated off by default. When the flag is off, the
// existing execution_guard Mutex path in executor.rs is untouched.
// Verified by specs/tla/consensus/ExecutorMVCC.tla.
#[cfg(feature = "mvcc")]
pub mod mvcc;
/// ZK proof circuits (Groth16 + arkworks).
///
/// **EXPERIMENTAL**: Circuit implementations use simplified/placeholder logic.
/// Production Groth16 verification is gated behind the `zkp_production` feature
/// in `core/mcp`. The circuits here (inference proof, state transition, gradient
/// proof) use hardcoded parameters and placeholder commitments.
///
/// See `core/mcp/src/verification.rs` for the feature-gated dispatch.
pub mod zkp;

// Integration tests
#[cfg(test)]
mod address_derivation_integration_test;

pub use types::{
    AccessPolicy, AccountState, Address, ExecutionError, GasSchedule, JobId, JobStatus, Log,
    ModelId, ModelMetadata, ModelState, TrainingJob, TransactionReceipt, TransactionType,
    UsageStats,
};

// Re-export Hash from consensus for MCP to use
pub use citrate_consensus::types::Hash;

pub use state::{AccountManager, StateDB, StateRoot, Trie};

pub use executor::{ExecutionContext, Executor, InferenceService, DEFAULT_CHAIN_ID};
pub use parallel::ParallelExecutor;
pub use precompiles::{PrecompileExecutor, PrecompileResult};
pub use inference::metal_runtime::{MetalRuntime, MetalCapabilities};
