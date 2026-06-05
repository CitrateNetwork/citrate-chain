//! `citrate-wallet-aa` — off-chain helpers for the Citrate ERC-4337
//! embedded-wallet stack (WP-2 of the EW-S1 sprint).
//!
//! This crate is the canonical Rust side of the
//! `contracts/src/aa/` Solidity surface. It is consumed by:
//!
//! - `citrate-identity` (Node — via a thin FFI / WASM build) to predict
//!   addresses, build init data, and sign the factory permit.
//! - `citrate-gui-native` (Rust) to compute the user's smart-wallet
//!   address offline once it knows the Citrate user id.
//! - `citrate-wallet-extension` (WASM build) — same.
//! - `citrate-sdk-js` — published as a TypeScript binding atop a
//!   `wasm-bindgen` build (in a follow-up crate).
//!
//! Three responsibilities:
//!
//! 1. **Address prediction** — compute the deterministic smart-wallet
//!    address from a Citrate user id, the factory address, and the
//!    Kernel implementation address. Matches Solady's
//!    `LibClone::predictDeterministicAddressERC1967` byte-for-byte.
//!
//! 2. **Kernel init data** — encode the call data the factory will
//!    delegatecall into the freshly-deployed proxy. The shape mirrors
//!    Kernel v3's `initialize(...)` ABI.
//!
//! 3. **Permit digest** — recompute the digest the factory's
//!    `identitySigner` signs to authorise a deploy. Used by
//!    auth.citrate.ai to construct the signature, and by clients to
//!    verify they're submitting the correct signature offline.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod address;
pub mod init_data;
pub mod permit;

pub use address::{predict_address, AddressError};
pub use init_data::{kernel_initialize_calldata, KernelInitConfig};
pub use permit::{permit_digest, sign_permit, PermitError};

use ethereum_types::Address;

/// Repackaged 20-byte Ethereum address for cross-language transport.
pub type EvmAddress = Address;

/// Repackaged 32-byte hash for cross-language transport.
pub type Bytes32 = [u8; 32];
