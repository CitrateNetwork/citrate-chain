# citrate-wallet-sdk

High-level wallet API wrapping `citrate-wallet-core` for application developers.

## Overview

Thread-safe wallet handle for creating accounts, signing transactions, and
querying balances on the Citrate chain. Compiles to both native Rust (`rlib`)
and WebAssembly (`cdylib` with the `wasm` feature). The `Wallet` struct bundles
a `KeyManager`, `RpcClient`, and `SessionManager` behind `Arc`/`RwLock` for safe
sharing across async tasks.

## Modules

- `wallet` -- `Wallet` handle, `SdkConfig`, `SdkAccount`, `SdkAccountInfo`, `SdkTransaction`
- `wasm` -- WebAssembly bindings via `wasm-bindgen` (enabled with `wasm` feature)

## Features

- Default (no features) -- Native Rust library
- `wasm` -- Enables `wasm-bindgen`, `js-sys`, `serde-wasm-bindgen`, `web-sys`, and `getrandom/js`

## Usage

```rust
use citrate_wallet_sdk::Wallet;

let wallet = Wallet::new_default();
let account = wallet.create_account("password", "Primary").await?;
println!("Address: {}", account.address);

// EVM-compatible account
let evm = wallet.create_evm_account("password", "EVM").await?;

// Recover from mnemonic
let recovered = wallet.recover_account(&mnemonic, "password", "Recovered").await?;

// Import from private key
let imported = wallet.import_account(&hex_key, "password", "Imported").await?;
```

## Tests

```bash
cargo test -p citrate-wallet-sdk
```

Test count: 44 tests (21 unit + 22 integration + 1 doc test) covering account
creation (Ed25519 and secp256k1), mnemonic recovery, private key import, account
listing, session management, balance queries, and configuration roundtrip.
