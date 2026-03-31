# citrate-wallet-core

Key management, transaction signing, session security, and SALT formatting for Citrate wallets.

## Overview

The shared library powering the desktop wallet, browser extension, and SDK. Handles Ed25519
(native Citrate) and secp256k1 (EVM-compatible) key generation with BIP39 mnemonics, Argon2 +
AES-256-GCM encryption at rest, and Keccak-256 address derivation. Compiles to both native Rust
and wasm32 (core modules are pure Rust with no OS dependencies). Enable the `native` feature
for chain type imports, RPC communication, and filesystem keystore persistence.

## Modules

- `keys` -- `KeyManager` and `UnifiedKey` (Ed25519/secp256k1), BIP39 mnemonic generation, key encryption, address derivation, import/export
- `chain` -- `TransactionBuilder` (fluent API), `RpcClient`, and `SignedTransaction` (native feature only)
- `session` -- `SessionManager` with auto-lock timeout, rate-limited password attempts, and lockout after max failures
- `format` -- `wei_to_salt` and `wei_to_salt_fixed` formatters (1 SALT = 10^18 wei)
- `types` -- `WalletAccount`, `WalletConfig`, `KeyType`, `EncryptedKeyEntry`, `CreateAccountResult`
- `error` -- `WalletError` enum

## Features

- `native` (default) -- Enables `tokio`, `reqwest`, `dirs`, `bincode`, `primitive-types`, and chain crate dependencies
- Without `native` -- Pure Rust core suitable for wasm32 targets

## Usage

```rust
use citrate_wallet_core::KeyManager;
use citrate_wallet_core::format::wei_to_salt;

let km = KeyManager::new(std::path::Path::new("/tmp/keystore"));
let account = km.create_account("password", "Primary")?;
println!("Address: {}", account.address);

let display = wei_to_salt(1_500_000_000_000_000_000);
assert_eq!(display, "1.5");
```

## Tests

```bash
cargo test -p citrate-wallet-core
```

Test count: 173 tests (92 unit + 25 integration + 20 format + 28 session + 8 chain)
covering key generation, encryption/decryption, BIP39 mnemonic recovery, address
derivation, private key import/export, SALT/wei formatting, session timeout and
lockout, transaction building, and RPC client operations.
