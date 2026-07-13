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
// `KeyManager` is the on-disk keystore (Argon2 + AES-GCM). It is
// native-only: it depends on `citrate_security::Aead`, `argon2`, and
// `default_keystore_path` (via `WalletConfig`) which needs `dirs`. The
// lean `crypto` build exposes the stateless primitives below instead.
#[cfg(feature = "native")]
pub use keys::KeyManager;
// BIP44 secp256k1 HD derivation (B1.1.0). Stateless primitives — no
// KeyManager/keystore/disk — for consumers that hold the seed elsewhere
// (e.g. citrate-core's A2 vault, Option A). Available in BOTH the lean
// `crypto` build and the full `native` build.
pub use keys::{secp256k1_from_mnemonic, secp256k1_from_seed, UnifiedKey};
pub use session::{PersistedFailure, SessionManager, SessionStatus};
pub use types::WalletAccount;
// `WalletConfig::default()` calls `default_keystore_path()` (needs
// `dirs`), so the config type is native-only. `NetworkConfig` and the
// other pure types stay available in the lean build via `types::`.
#[cfg(feature = "native")]
pub use types::WalletConfig;

#[cfg(feature = "native")]
pub use chain::{TransactionBuilder, RpcClient, SignedTransaction};
