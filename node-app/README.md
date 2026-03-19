# node-app

Standalone Citrate node binary -- wires storage, executor, mempool, peer manager, and API service into a production-ready RPC node with Prometheus metrics.

## Overview

node-app is the main entry point for running a Citrate blockchain node as a standalone process. It initializes the core infrastructure (RocksDB-backed storage, EVM-compatible executor, mempool, peer manager), configures the JSON-RPC API service, and starts a Prometheus metrics server.

The binary is intentionally slim. All domain logic lives in the workspace crates it depends on (`citrate-api`, `citrate-storage`, `citrate-execution`, `citrate-sequencer`, `citrate-network`). node-app's role is configuration, wiring, and lifecycle management. It reads configuration from environment variables (`CITRATE_DATA_DIR`, `CITRATE_RPC_ADDR`, `CITRATE_METRICS_ADDR`, `RUST_LOG`) with secure defaults (RPC binds to loopback `127.0.0.1:8545` rather than all interfaces).

## Modules

| Module | File | Purpose |
|--------|------|---------|
| `main` | `main.rs` | Application entry point: logging init, storage/executor/mempool/peer wiring, RPC + metrics server startup |

## Public API

This is a binary crate with no library API. The following environment variables control its behavior:

| Variable | Default | Purpose |
|----------|---------|---------|
| `CITRATE_DATA_DIR` | `/data` | RocksDB storage directory |
| `CITRATE_RPC_ADDR` | `127.0.0.1:8545` | JSON-RPC listen address |
| `CITRATE_METRICS_ADDR` | `0.0.0.0:9100` | Prometheus metrics endpoint |
| `RUST_LOG` | `info,citrate=info` | Log level filter |

### Exposed Services

- **JSON-RPC** at `CITRATE_RPC_ADDR` (default `127.0.0.1:8545`) -- standard `eth_*` and custom `citrate_*` methods
- **WebSocket** at `127.0.0.1:8546` -- real-time subscriptions
- **REST API** at `127.0.0.1:3000` -- MCP-compatible endpoints
- **Prometheus metrics** at `CITRATE_METRICS_ADDR/metrics` (default `0.0.0.0:9100/metrics`)

## Tests

```bash
cargo test -p node-app
```

0 tests (binary crate with no unit tests; integration tested via workspace-level E2E tests).

## Dependencies

| Dependency | Purpose |
|-----------|---------|
| `citrate-api` | `ApiService`, `RpcConfig` -- JSON-RPC + WebSocket + REST server |
| `citrate-storage` | `StorageManager`, `PruningConfig` -- RocksDB-backed state/block storage |
| `citrate-execution` | `Executor`, `StateDB` -- EVM-compatible transaction execution |
| `citrate-sequencer` | `Mempool`, `MempoolConfig` -- transaction pool |
| `citrate-network` | `PeerManager`, `PeerManagerConfig` -- P2P peer management |
| `axum` | Prometheus metrics HTTP server |
| `prometheus` | Metrics collection and text encoding |
| `tracing`, `tracing-subscriber` | Structured logging with env filter |
| `tokio` | Multi-threaded async runtime |
