# CLI

Command-line interface for interacting with a running Citrate node. Provides subcommands for account management, contract deployment, model operations, governance, and network diagnostics.

## Contents

- `src/main.rs` -- Entry point and argument parsing
- `src/commands/account.rs` -- Account creation, balance queries, transfers
- `src/commands/contract.rs` -- Contract deployment and interaction
- `src/commands/model.rs` -- AI model registration, listing, and inference
- `src/commands/governance.rs` -- On-chain governance proposals and voting
- `src/commands/network.rs` -- Peer info and network diagnostics
- `src/commands/snapshot.rs` -- State snapshot export/import
- `src/commands/wizard.rs` -- Interactive setup wizard
- `src/config.rs` -- CLI configuration (RPC URL, keyfile paths)

## Build / Usage

```bash
cargo build --release -p citrate-cli
cargo run --bin citrate-cli -- --help
cargo run --bin citrate-cli -- account balance --address 0x1111...1111 --rpc-url http://localhost:8545
```
