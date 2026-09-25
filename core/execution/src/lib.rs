// citrate/core/execution/src/lib.rs

// Re-export modules
pub mod activation;

/// PBA-L1a-003: consensus-affecting cargo features of THIS build of the
/// execution crate. Dependent binaries assert on these at compile time (a
/// feature can be switched on through `--features citrate-execution/<f>`
/// without touching the binary's own feature list).
pub mod build_features {
    /// `halo2-substrate`: live 0x0108 verifier.
    pub const HALO2_SUBSTRATE: bool = cfg!(feature = "halo2-substrate");
    /// `commd-fold-verify`: live 0x0130 verifier.
    pub const COMMD_FOLD_VERIFY: bool = cfg!(feature = "commd-fold-verify");
}
pub mod address_utils;
pub mod block_rewards;
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

// Multi-Version Concurrency Control (MVCC) primitives. Unconditional
// as of Sprint P950-A-3 (2026-04-21): the former `mvcc` feature flag
// has been removed, and the executor's tokio::sync::Mutex-serialized
// path is deleted. See specs/tla/consensus/ExecutorMVCC.tla for the
// verified design.
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
