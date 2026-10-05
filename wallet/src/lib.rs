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

pub mod errors;
pub mod keystore;
pub mod rpc_client;
pub mod transaction;
pub mod wallet;

pub use errors::WalletError;
pub use keystore::{EncryptedKey, KeyStore};
pub use rpc_client::RpcClient;
pub use transaction::{SignedTransaction, TransactionBuilder};
pub use wallet::{Account, Wallet, WalletConfig};
