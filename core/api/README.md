# citrate-api

JSON-RPC, WebSocket, and REST API server providing Ethereum-compatible and AI-native RPC endpoints.

## Overview

`citrate-api` exposes the Citrate node's functionality through three transport protocols running concurrently. The JSON-RPC server (port 8545) implements the standard Ethereum `eth_*` namespace for wallet and tooling compatibility, plus custom `citrate_*` methods for DAG queries, AI operations, and economics. The WebSocket server (port 8546) supports `eth_subscribe`/`eth_unsubscribe` for real-time event streaming (newHeads, logs, pendingTransactions, syncing) as well as AI-specific subscriptions (inference results, training jobs, chat streaming). The REST API provides OpenAI/Anthropic-compatible endpoints (`/v1/chat/completions`, `/v1/embeddings`, `/v1/models`) via an Axum-based HTTP server with CORS support and optional Bearer token authentication.

Transaction decoding supports four formats: Citrate-native bincode, legacy RLP (pre-EIP-2718), EIP-2930 access list transactions, and EIP-1559 fee market transactions. The primary decoder (`eth_tx_decoder`) handles all formats with ECDSA signature recovery via `secp256k1`. Three additional decoder modules (eip1559_decoder, enhanced_tx_decoder, unified_tx_decoder) are retained for backward compatibility but are deprecated in favor of the primary decoder.

The server includes production-grade infrastructure: per-client sliding-window rate limiting with IP attribution aware of trusted proxies, per-method cost budgets to prevent DoS via expensive calls (eth_call=10, eth_estimateGas=10), Prometheus metrics for request counts and latencies, and a filter registry for `eth_newFilter`/`eth_getFilterChanges` with automatic 5-minute cleanup.

## Modules

| Module | File | Purpose |
|--------|------|---------|
| `lib` | `src/lib.rs` | Crate root: `ApiService` struct orchestrating RPC + WS + REST, module declarations, re-exports |
| `server` | `src/server.rs` | `RpcServer`: JSON-RPC server setup via `jsonrpc-http-server`, method registration, CORS, rate limiting middleware, IPFS upload helper |
| `eth_rpc` | `src/eth_rpc.rs` | Full Ethereum RPC implementation: `eth_sendRawTransaction`, `eth_getTransactionByHash`, `eth_getTransactionReceipt`, `eth_getTransactionCount` (with pending nonce), EIP-typed field serialization |
| `eth_rpc_simple` | `src/eth_rpc_simple.rs` | Simplified Ethereum RPC subset: `eth_blockNumber`, `eth_getBlockByNumber`, `eth_getBalance`, `eth_chainId` |
| `eth_tx_decoder` | `src/eth_tx_decoder.rs` | Primary transaction decoder: legacy RLP, EIP-2930, EIP-1559, bincode. ECDSA signature recovery, chain ID extraction |
| `eip1559_decoder` | `src/eip1559_decoder.rs` | (Deprecated) Standalone EIP-1559 decoder with validation, gas estimation, and statistics tracking |
| `enhanced_tx_decoder` | `src/enhanced_tx_decoder.rs` | (Deprecated) Multi-type decoder wrapping `Eip1559Decoder` with configurable format support |
| `unified_tx_decoder` | `src/unified_tx_decoder.rs` | (Deprecated) Unified entry point wrapping `EnhancedTransactionDecoder` with fallback logic |
| `eth_subscriptions` | `src/eth_subscriptions.rs` | `EthSubscriptionServer`: Ethereum-compatible WebSocket subscriptions (newHeads, logs, pendingTransactions, syncing) via `tokio-tungstenite` |
| `websocket` | `src/websocket.rs` | `WebSocketServer`: AI-native WebSocket subscriptions (inference results, training jobs, chat streaming, new models) |
| `openai_api` | `src/openai_api.rs` | `OpenAiRestServer`: Axum REST server with OpenAI/Anthropic-compatible routes (`/v1/chat/completions`, `/v1/embeddings`, `/v1/models`, etc.), Bearer auth, CORS |
| `ai_rpc` | `src/ai_rpc.rs` | AI JSON-RPC methods: `citrate_getTextEmbedding`, `citrate_chatCompletion`, `citrate_deployModel`, `citrate_runInference` |
| `economics_rpc` | `src/economics_rpc.rs` | Economics JSON-RPC methods: `citrate_gasPrice`, `citrate_getEconomicState`, reward estimation, slashing config |
| `filter` | `src/filter.rs` | `FilterRegistry`: manages `eth_newFilter`, `eth_newBlockFilter`, `eth_newPendingTransactionFilter` with auto-expiry |
| `rate_limit` | `src/rate_limit.rs` | `RateLimiter`: per-client sliding-window rate limiting with trusted proxy IP attribution, per-method cost budgets |
| `metrics` | `src/metrics.rs` | `RPC_REQUESTS` Prometheus counter, `rpc_request()` helper |
| `metrics_server` | `src/metrics_server.rs` | Prometheus `/metrics` endpoint: RPC duration/count histograms, mempool size gauges, storage read/write durations |
| `methods/mod` | `src/methods/mod.rs` | API method modules root |
| `methods/ai` | `src/methods/ai.rs` | `AiApi`: chat completions, embeddings, model deployment, inference, training jobs, LoRA adapters |
| `methods/chain` | `src/methods/chain.rs` | `ChainApi`: block queries, height, block-by-number, block-by-hash |
| `methods/state` | `src/methods/state.rs` | `StateApi`: balance, nonce, code, storage slot queries |
| `methods/transaction` | `src/methods/transaction.rs` | `TransactionApi`: send transaction, get transaction, get receipt |
| `methods/network` | `src/methods/network.rs` | `NetworkApi`: peer count, listening status, version |
| `methods/mempool` | `src/methods/mempool.rs` | `MempoolApi`: public aggregate stats and operator-only bounded pending summaries |
| `types/mod` | `src/types/mod.rs` | API types module root |
| `types/error` | `src/types/error.rs` | `ApiError` enum with JSON-RPC error codes |
| `types/request` | `src/types/request.rs` | `BlockId`, `BlockTag`, `CallRequest` request types |
| `types/response` | `src/types/response.rs` | Response serialization types |
| `decoder_integration_test` | `src/decoder_integration_test.rs` | Integration tests for transaction decoder stack (test-only) |

## Public API

### Service Entry Point

- **`ApiService`** -- Combines `RpcServer`, `WebSocketServer`, and `OpenAiRestServer`. Call `start()` to launch all three concurrently; blocks until Ctrl-C.
- **`RpcConfig`** -- JSON-RPC server configuration: bind address, CORS origins, rate limit settings.

### JSON-RPC Server

- **`RpcServer`** -- Registers all `eth_*`, `citrate_*`, and economics RPC methods on a `jsonrpc_core::IoHandler`. `spawn()` returns a `(CloseHandle, JoinHandle)` for graceful shutdown.

### Ethereum RPC Methods

| Method | Description |
|--------|-------------|
| `eth_blockNumber` | Latest block height |
| `eth_getBlockByNumber` | Block by number (with/without transactions) |
| `eth_getBlockByHash` | Block by hash |
| `eth_getBalance` | Account balance |
| `eth_getTransactionCount` | Account nonce (supports `"latest"` and `"pending"` tags) |
| `eth_getCode` | Contract bytecode |
| `eth_getStorageAt` | Contract storage slot |
| `eth_sendRawTransaction` | Submit signed transaction (bincode, legacy RLP, EIP-2930, EIP-1559) |
| `eth_getTransactionByHash` | Transaction lookup |
| `eth_getTransactionReceipt` | Transaction receipt |
| `eth_chainId` | Chain ID (default 40204) |
| `eth_newFilter` / `eth_getFilterChanges` / `eth_uninstallFilter` | Log/block/pending-tx filters |
| `eth_call` | Simulate transaction |
| `eth_estimateGas` | Gas estimation |
| `net_version` / `net_peerCount` / `net_listening` | Network status |

### Citrate RPC Methods

| Method | Description |
|--------|-------------|
| `citrate_getMempoolStats` | Public aggregate mempool stats, no per-transaction detail |
| `citrate_getMempoolSnapshot` | Operator-only bounded pending transaction summaries; requires `operator_token` |
| `citrate_getTextEmbedding` | Generate text embeddings |
| `citrate_chatCompletion` | Chat completion (OpenAI-compatible) |
| `citrate_deployModel` | Deploy AI model on-chain |
| `citrate_runInference` | Execute model inference |
| `citrate_gasPrice` | Dynamic gas price |
| `citrate_getEconomicState` | Economic metrics snapshot |
| `citrate_executedHead` | The persisted applied tip `{number, hash}`: the tip `eth_getLogs` serves up to (see below) |
| `citrate_isExecuted` | Whether a block hash is on the executed chain: `{executed, number}` (see below) |
| `citrate_getLogs` | `eth_getLogs` plus `through`, the executed block the answer is complete through (see below) |

#### `citrate_executedHead`

Params: none. Result: `{"number": "0x…", "hash": "0x…"}`, the persisted applied
tip, which is the newest block whose transactions this node executed. It is the
same tip `eth_getLogs` walks from (`canonical_logs::executed_head`), and
`eth_getLogs` serves no log above it.

`eth_blockNumber` reports the stored-header height. It can be ahead of the
executed head while blocks are admitted but not yet applied, so it does not bound
what `eth_getLogs` has served.

In every log query (`eth_getLogs`, `citrate_getLogs`, `eth_newFilter`,
`eth_getFilterChanges`, `eth_getFilterLogs`) the `latest` and `pending` tags,
and an omitted `toBlock`, resolve to the executed head, not to
`eth_blockNumber`. The tag and the walk use one read of the tip, so
`latest..latest` is the executed head's block even while admitted blocks are
ahead of it or the tip moves during the call. A numeric range above the
executed head has nothing executed in it and answers `[]` (for
`citrate_getLogs`, `through` says how far it served). Log filters read the
executed chain too: `eth_getFilterChanges` delivers each applied height once,
starting at `fromBlock` or the executed head at creation, at most 1,001 heights
per poll (`tests/getlogs_latest_applied_tip.rs`).

When no applied tip is persisted, or it cannot be read, the method returns
JSON-RPC error `-32603`. It never falls back to the height index.

`number` and `hash` come from one stored record, so `eth_getBlockByHash(hash)`
returns the executed block at `number`. **Confirm the head by hash, never by
number:** `eth_getBlockByNumber(number)` reads the height index, where the last
block stored at a height wins. A non-executed sibling stored after the executed
block at the head height makes `eth_getBlockByNumber(head.number)` return the
sibling while `citrate_executedHead` and `eth_getLogs` both name the executed
block (`tests/executed_head.rs`,
`executed_head_names_the_executed_block_not_a_later_sibling`).

`citrate_executedHead` is a point-in-time read. Two reads around an
`eth_getLogs` call do not tell how far that call served: the tip can rewind
while the call runs and come back before the second read. Do not persist
scan progress from it; use `citrate_getLogs` below.

#### `citrate_isExecuted`

Params: `[blockHash]` (32-byte `0x` hex). Result: `{"executed": true, "number":
"0x…"}` when the block is on the selected-parent chain of the persisted applied
tip, else `{"executed": false, "number": null}` (never stored, stored above the
tip, a losing sibling or merge parent, or a block a reorg abandoned). It uses the
same resolver as `eth_getLogs`. `eth_getBlockByHash` serves any stored block,
including abandoned ones, so it only proves storage. Errors: `-32602` for a
malformed hash, `-32603` when no applied tip is persisted, `-32002`
(`data.retryable`) while a cold lookup deep below the tip warms the index.
Point-in-time: a later reorg can abandon a block reported executed.

#### `citrate_getLogs`

Params: `[filter]`, the `eth_getLogs` filter (`fromBlock`, `toBlock`, `address`,
`topics`; the same 1,000-block limit and `-32005`) plus an optional
`afterBlockHash`. Result:

```json
{"logs": [ /* exactly as eth_getLogs */ ], "through": {"number": "0x…", "hash": "0x…"} | null}
```

- Every executed block of the answer comes from **one** read of the applied
  tip. `through` is the highest of them: the answer is complete for every
  height from `fromBlock` to `through.number` on `through`'s chain. It is
  below `toBlock` when the executed head is (it never reaches past what this
  call served), and `null` when nothing in the range has executed yet.
- `afterBlockHash` (needs `fromBlock >= 1`) is the caller's previous `through`.
  The call is served only if the executed block at `fromBlock - 1` is that block.
  Otherwise it is `-32001` (`data.reorged: true`): the chain the caller scanned
  was replaced. If the executed head is below `fromBlock - 1`, the result is
  `{"logs": [], "through": null}` and the cursor is checked again once the chain
  is back above it.
- A transaction of an executed block in the range with no receipt recorded for
  that block is `-32002` (`data.retryable: true`, `data.blockNumber`), never
  an answer that claims to be complete. This covers the producer's receipt
  write just after its tip commit (`node/src/producer.rs`:
  `persist_state_changes_with_tip`, then `put_receipts`) and a node that does
  not store receipts for peer blocks. `eth_getLogs` keeps skipping such a
  transaction.
- Never clamped: `CITRATE_RPC_GETLOGS_CLAMP_RANGE` does not apply.

##### Log scanner protocol

A scanner keeps a cursor: the last `through` it persisted (`{number, hash}`),
or none before its first window. `start` is the first height it cares about
(for example a contract's deployment block).

1. Request a window with `citrate_getLogs`: `fromBlock = cursor.number + 1`
   (or `start`), `toBlock` at most 1,000 above it, and
   `afterBlockHash = cursor.hash` when there is a cursor.
2. On success, take the logs and persist `through` as the new cursor
   (with the logs, atomically). If `through` is `null` or below `toBlock`, the
   scanner has reached the executed head: stop this pass.
3. On `-32001`, the scanned chain was replaced: drop the cursor and what was
   found from it, and scan again from `start` (or from an older cursor the
   application kept and still finds executed with `citrate_isExecuted`).
4. On `-32002` with `data.retryable`, retry the same window with back-off. On
   `-32005`, use a smaller window. On any other error, stop and don't advance.
5. Persist nothing derived from `citrate_executedHead`, `eth_blockNumber` or
   `eth_syncing`. Only a `through` says what was served.

Why this never skips a log: every window is complete through its `through` on
`through`'s chain, and each window is served only on a chain that contains the
previous `through`. So the persisted cursor's ancestry is exactly what was
scanned. A rewind during a call shortens that call's `through`. A rewind and
return between calls is checked by `afterBlockHash`. A reorg below the cursor is
`-32001`. No confirmation margin is needed for completeness.

Remaining assumptions:
- Logs are discovery hints. A cursor that is complete now can still be
  abandoned by a later reorg; the next window's `afterBlockHash` check reports
  it. Confirm anything that moves value from contract state.
- A receipt lost in a crash between the producer's tip commit and its receipt
  write keeps that block at `-32002` (the scan does not advance past it). It is
  never answered as complete. That needs operator repair.
- The answer covers what this node executed. A scanner that needs another
  node's view scans that node.

`tests/executed_head.rs` covers this: `citrate_getLogs` under concurrent apply
and reorg (`get_logs_through_is_atomic_under_concurrent_apply`), a later sibling
at the head (`get_logs_through_names_the_executed_block_not_a_later_sibling`),
a rewind mid-scan, including a rewind and return within one call
(`cursor_scan_never_skips_logs_across_a_rewind`), a reorg below the cursor
(`cursor_scan_restarts_on_a_reorg_below_the_cursor`), a node restart with the
tip below the cursor (`cursor_scan_resumes_across_a_node_restart`) and missing
receipts (`get_logs_refuses_a_range_with_missing_receipts`).

**Deploy dependency.** A follower or RPC-only node needs chain#336 (followers
persist receipts for the blocks they apply). Without it, `citrate_getLogs`
answers `-32002` for every peer block with transactions, so a scanner does not
advance there, and `eth_getLogs` returns nothing for those blocks. Merge and
deploy #334, #336 and #337 together on the serving RPC nodes.

### WebSocket

- **`EthSubscriptionServer`** -- `eth_subscribe("newHeads")`, `eth_subscribe("logs", filter)`, `eth_subscribe("newPendingTransactions")`, `eth_subscribe("syncing")`.
- **`WebSocketServer`** -- AI subscriptions: `InferenceResults`, `TrainingJobs`, `NewModels`, `ChatStream`.

### REST API (OpenAI/Anthropic-compatible)

- **`OpenAiRestServer`** -- Axum router at configurable address.
- Routes: `POST /v1/chat/completions`, `POST /v1/embeddings`, `GET /v1/models`, `POST /v1/models` (deploy), `POST /v1/inference`, `POST /v1/training`, `POST /v1/lora`.

### Transaction Decoding

- **`decode_eth_transaction(bytes)`** -- Primary decoder: auto-detects format (type byte 0x01/0x02 for EIP-2930/1559, RLP for legacy, bincode fallback). Returns `Transaction` with recovered sender.
- **`Eip1559Decoder`** / **`EnhancedTransactionDecoder`** / **`UnifiedTransactionDecoder`** -- Deprecated decoders retained for backward compatibility.

### Infrastructure

- **`FilterRegistry`** -- Filter lifecycle management with 5-minute expiry.
- **`RateLimiter`** -- Sliding-window per-IP rate limiting. `check_method_budget()` for per-method cost enforcement.
- **`rpc_request(method)`** -- Prometheus metric recording.

## Usage

```rust
use citrate_api::{ApiService, RpcConfig};
use std::sync::Arc;

// Create dependencies (storage, mempool, peer_manager, executor)
// ...

let api = ApiService::new(
    RpcConfig::default(),                         // JSON-RPC on 127.0.0.1:8545
    "127.0.0.1:8546".parse().unwrap(),            // WebSocket
    "127.0.0.1:3000".parse().unwrap(),            // REST API
    storage,
    mempool,
    peer_manager,
    executor,
    40204,                                        // chain_id
);

// Start all servers (blocks until Ctrl-C)
api.start().await?;
```

## Tests

```bash
cargo test -p citrate-api
```

224 tests passing, 5 ignored, across 13 test binaries. Key test areas: transaction decoding (legacy, EIP-2930, EIP-1559, edge cases), EIP-712 signature verification, rate limiting, filter registry lifecycle, RPC method correctness, AI API request/response serialization, economics RPC, WebSocket subscription types, REST API route matching, and decoder integration tests.

## Dependencies

| Dependency | Purpose |
|-----------|---------|
| `jsonrpc-core` / `jsonrpc-http-server` / `jsonrpc-ws-server` / `jsonrpc-derive` | JSON-RPC 2.0 server infrastructure |
| `axum` / `tower` / `tower-http` | REST API framework with CORS and tracing |
| `tokio-tungstenite` | WebSocket server for subscriptions |
| `citrate-execution` | Executor, StateDB, Address, types |
| `citrate-storage` | StorageManager for block/tx/state queries |
| `citrate-sequencer` | Mempool for pending transactions |
| `citrate-network` | PeerManager for network status |
| `citrate-economics` | Economics manager for gas pricing and rewards |
| `citrate-mcp` | Model Context Protocol integration |
| `secp256k1` | ECDSA signature recovery for transaction decoding |
| `rlp` / `ethereum-types` | RLP decoding and Ethereum primitive types |
| `sha3` | Keccak256 for transaction hashing and address derivation |
| `dashmap` | Concurrent rate limiter state |
| `prometheus` / `once_cell` | Metrics counters and histograms |
| `reqwest` | IPFS upload from RPC handlers |
| `uuid` | Subscription ID generation |
