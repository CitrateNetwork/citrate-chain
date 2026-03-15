# Wallet

CLI wallet for the Citrate network. Signs transactions with ed25519, builds and submits them via JSON-RPC, and manages local key storage.

## Contents

- `src/main.rs` -- Entry point, interactive wallet commands
- `src/wallet.rs` -- Key generation, storage, and ed25519 signing
- `src/transaction.rs` -- Transaction construction, serialization, and signing
- `examples/` -- Usage examples
- `tests/` -- Wallet unit and integration tests

## Build / Usage

```bash
cargo build --release -p citrate-wallet
cargo run --bin citrate-wallet -- --rpc-url http://localhost:8545
cargo test -p citrate-wallet
```
