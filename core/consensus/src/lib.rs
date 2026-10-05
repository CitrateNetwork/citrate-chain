// PANIC-S1 G2: production code in this crate may not panic. Every panic class is
// denied outside tests; a genuine invariant needs an item-level #[allow] with an
// `// INVARIANT:` comment (enforced by scripts/ci/panic_invariant_tripwire.sh).
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::string_slice
    )
)]
// citrate/core/consensus/src/lib.rs

pub mod block_sidecars;
pub mod chain_selection;
pub mod checkpoint;
pub mod crypto;
pub mod dag_store;
pub mod ecvrf;
pub mod finality;
pub mod ghostdag;
pub mod hardening;
pub mod native_sig;
pub mod ordering;
pub mod tip_selection;
pub mod tx_auth;
pub mod types;
pub mod vrf;

pub use chain_selection::{ChainSelectionError, ChainSelector, ChainState, ReorgEvent};
pub use checkpoint::{CheckpointConfig, CheckpointError, CheckpointManager, CheckpointVote};
pub use dag_store::{DagStats, DagStore, DagStoreError, KvStore};
pub use ecvrf::{EcvrfError, EcvrfProof};
pub use finality::{FinalityConfig, FinalityError, FinalityEvent, FinalityStatus, FinalityTracker};
pub use ghostdag::{GhostDag, GhostDagError};
pub use ordering::{OrderedBlockRange, OrderingError, TotalOrdering, TransactionRef};
pub use tip_selection::{ParentSelector, SelectionStrategy, TipSelectionError, TipSelector};
pub use types::*;
pub use vrf::{LeaderElection, Validator, VrfError, VrfProposerSelector};
