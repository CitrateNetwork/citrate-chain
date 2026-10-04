//! HUP-S6.10 — the **Citrate-aware dry-run fork**.
//!
//! A plain anvil fork of chain 40204 runs Ethereum's precompiles only. A contract that calls a
//! Citrate precompile (for example `0x0110` BELNAP_AGGREGATE) reaches an empty account there
//! and gets success with no data, so a dry run on anvil says nothing about what 40204 would
//! do. This crate runs the same EVM the node runs (REVM with the node's own Citrate precompile
//! bridge, activation heights and value rules, see [`run`]) over state read from a JSON-RPC
//! endpoint at one pinned block: chain 40204 itself, or the local anvil fork the dApp forge
//! previews against. [`table`] says, address by address, which Citrate precompiles the fork
//! runs with the node's code and which it cannot reproduce.
//!
//! Read-only by construction: the only JSON-RPC methods it calls are reads, it holds no key
//! and it never sends a transaction. Everything the dry run writes stays in memory.
pub mod plan;
pub mod run;
pub mod state;
pub mod table;

pub use plan::{Plan, Step, Target};
pub use run::{pinned_hardening, run, ForkConfig, Report, StateSource, ENGINE};
pub use state::{ForkBlock, ForkError, ForkState, RpcState};
