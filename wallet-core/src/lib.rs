//! Citrate Universal Wallet Core
//!
//! Shared library for desktop wallet, browser extension, and SDK.
//! Handles key management, transaction signing, credential handling, and DID resolution.
//!
//! This crate imports chain types (PublicKey, Hash, Transaction) from citrate-consensus
//! and citrate-execution as READ-ONLY dependencies. It does NOT modify chain crates.

pub mod address;
pub mod error;
pub mod format;
pub mod keys;
pub mod session;
pub mod types;

#[cfg(feature = "native")]
pub mod chain;

pub use error::WalletError;
pub use keys::KeyManager;
pub use session::{PersistedFailure, SessionManager, SessionStatus};
pub use types::{WalletAccount, WalletConfig};

#[cfg(feature = "native")]
pub use chain::{TransactionBuilder, RpcClient, SignedTransaction};
