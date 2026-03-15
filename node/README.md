# Node

Main Citrate node binary. Runs the GhostDAG consensus engine, block producer, JSON-RPC server, and P2P networking on chain ID 40204.

## Contents

- `src/main.rs` -- Entry point, CLI argument parsing, node startup
- `src/producer.rs` -- Block producer: transaction execution, receipt storage, state commitment
- `src/config.rs` -- Node configuration loading (TOML files and CLI flags)
- `src/genesis.rs` -- Genesis block initialization and account funding
- `src/sync/` -- Chain synchronization with peers
- `config/` -- Sample TOML configs for devnet, testnet, and multi-node setups
- `monitoring/` -- Prometheus, Grafana, and docker-compose for metrics
- `tests/` -- Node-level integration tests

## Build / Usage

```bash
cargo build --release -p citrate-node
cargo run --bin citrate-node -- devnet          # Start local devnet (RPC on 127.0.0.1:8545)
cargo run --bin citrate-node -- --config node/config/testnet.toml  # Start with custom config
```
