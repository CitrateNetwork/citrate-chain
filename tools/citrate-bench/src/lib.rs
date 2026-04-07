//! citrate-bench library surface.
//!
//! Production-correct TPS benchmark for the Citrate testnet. See
//! `.agentile/quorum/16_POST_CEREMONY_BENCHMARK_HARNESS_SPEC.md` for the
//! full design rationale.
//!
//! Phase 1 (current scope): no-chain components only — config loading,
//! address table parsing, fingerprint validation, keystore decryption,
//! nonce lanes, EIP-155 legacy transaction signing.
//!
//! Phases 2-6 add workload classes, runner, tracker, metrics, and
//! report writing. See the spec for the phase gates.

pub mod address_table;
pub mod config;
pub mod fingerprint;
pub mod nonce;
pub mod runner;
pub mod signers;
pub mod tx;
pub mod workload;

/// Top-level error type for the citrate-bench crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("toml: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("hex: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("config: {0}")]
    Config(String),

    #[error("fingerprint mismatch: {0}")]
    Fingerprint(String),

    #[error("keystore: {0}")]
    Keystore(String),

    #[error("signing: {0}")]
    Signing(String),

    #[error("address table: {0}")]
    AddressTable(String),

    #[error("nonce lane saturated")]
    NonceLaneSaturated,

    #[error("workload: {0}")]
    Workload(String),

    #[error("runner: {0}")]
    Runner(String),
}

pub type Result<T> = std::result::Result<T, Error>;
