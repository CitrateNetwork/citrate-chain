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

- `native` (default) -- the `wallet` module: `Wallet`, the on-disk keystore and
  the RPC client. Pulls `citrate-wallet-core` with its `native` feature and
  tokio, so it does not build for wasm32.
- `wasm` -- the `wasm` module (Argon2id KDF, constant-time secp256k1) via
  `wasm-bindgen`, `js-sys`, `serde-wasm-bindgen` and `web-sys`. On
  wasm32-unknown-unknown, `getrandom/js` is always on.

Build the browser bundle with `native` off:

```bash
wasm-pack build wallet-sdk --target no-modules --release --no-opt \
  -- --no-default-features --features wasm
```

`scripts/ci/wallet_sdk_wasm_gate.sh` runs this at the pinned wasm-pack and
wasm-bindgen versions (local-ci and the `wallet-sdk-wasm` CI job), and fails if
a native-only crate enters the wasm build.

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
