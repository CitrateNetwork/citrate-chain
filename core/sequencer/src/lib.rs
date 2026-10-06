// citrate/core/sequencer/src/lib.rs

// Sequencer module for block building and mempool management

// PANIC-S1 G2: production code in this crate may not panic (tests excepted).
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
pub mod block_builder;
pub mod mempool;
pub mod validator;

pub use block_builder::{BlockBuilder, BlockBuilderConfig, BlockBuilderError};
pub use mempool::{Mempool, MempoolAccess, MempoolConfig, MempoolError, MempoolStats, TxClass};
pub use validator::{TxValidator, ValidationError, ValidationRules};
