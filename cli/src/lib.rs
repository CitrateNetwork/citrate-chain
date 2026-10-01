// citrate/cli/src/lib.rs
// Library interface for CLI commands, allowing the node binary to reuse them.

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

pub mod commands;
pub mod config;
pub mod utils;
