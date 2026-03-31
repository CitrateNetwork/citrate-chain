//! Citrate Wallet SDK
//!
//! Ergonomic API wrapping `citrate-wallet-core` for application developers.
//! Compiles to both native Rust and wasm32 (with `wasm` feature).
//!
//! # Native Usage
//! ```no_run
//! use citrate_wallet_sdk::Wallet;
//!
//! # tokio_test::block_on(async {
//! let wallet = Wallet::new_default();
//! let account = wallet.create_account("mypassword123", "Primary").await.expect("create account");
//! println!("Address: {}", account.address);
//! println!("Mnemonic: {}", account.mnemonic);
//! # });
//! ```

pub mod wallet;

#[cfg(feature = "wasm")]
pub mod wasm;

pub use wallet::{Wallet, SdkAccount, SdkTransaction, SdkConfig};
