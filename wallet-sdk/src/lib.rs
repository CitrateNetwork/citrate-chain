//! Citrate Wallet SDK
//!
//! Ergonomic API wrapping `citrate-wallet-core` for application developers.
//! Compiles to both native Rust (the default `native` feature) and wasm32
//! (`--no-default-features --features wasm`). The `native` feature pulls
//! tokio and wallet-core's keystore/RPC code, which do not build for wasm32.
//!
//! # Native Usage (feature `native`)
//! ```no_run
//! # #[cfg(feature = "native")]
//! # fn main() {
//! use citrate_wallet_sdk::Wallet;
//!
//! # tokio_test::block_on(async {
//! let wallet = Wallet::new_default();
//! let account = wallet.create_account("mypassword123", "Primary").await.expect("create account");
//! println!("Address: {}", account.address);
//! println!("Mnemonic: {}", account.mnemonic);
//! # });
//! # }
//! # #[cfg(not(feature = "native"))]
//! # fn main() {}
//! ```

#[cfg(feature = "native")]
pub mod wallet;

#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(feature = "native")]
pub use wallet::{SdkAccount, SdkConfig, SdkTransaction, Wallet};
