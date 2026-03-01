//! Citrate Bridge Relay.
//!
//! Cross-chain bridge between Ethereum Sepolia and Citrate devnet.
//! Implements Paper VI (The Memetic Money Portal) — ERC-6551 bridge
//! architecture with oracle attestation and bonding curve pricing.
//!
//! # Modules
//!
//! - [`config`] — Bridge configuration (RPC, oracle quorum, bonding curve)
//! - [`events`] — Bridge event types (Deposit, Withdrawal, OracleUpdate)
//! - [`state`] — Relay state persistence and event tracking
//! - [`oracle`] — M-of-N oracle attestation system
//! - [`mint`] — $SNAP mint flow (ETH deposit → SALT credit)
//! - [`relay`] — Main relay orchestrator
//! - [`metrics`] — Prometheus-compatible bridge health metrics
//! - [`errors`] — Bridge error types

pub mod config;
pub mod errors;
pub mod events;
pub mod metrics;
pub mod mint;
pub mod oracle;
pub mod relay;
pub mod state;

// Re-exports for convenience.
pub use config::BridgeConfig;
pub use errors::{BridgeError, BridgeResult};
pub use events::{BridgeEvent, DepositEvent, EventStatus, WithdrawalEvent};
pub use metrics::BridgeMetrics;
pub use mint::{MintReceipt, SnapMinter, SnapNftMetadata};
pub use oracle::{OracleAttestation, OracleRegistry};
pub use relay::{BridgeEventSource, BridgeRelay, MockEventSource, ProcessingResult};
pub use state::RelayState;
