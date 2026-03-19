# citrate-mcp

Model Context Protocol layer for Citrate -- AI model registry, GGUF inference engine, LRU caching, provider management, and verifiable execution proofs.

## Overview

citrate-mcp implements the Model Context Protocol (MCP) service that makes AI models first-class on-chain assets in the Citrate blockchain. It coordinates model registration, provider selection, inference execution, and cryptographic proof generation.

The crate provides a GGUF-based inference engine that shells out to llama.cpp for text generation and embedding computation. Models are loaded from IPFS (with chunked manifest support), cached in an LRU cache (default 10 GB), and served through a unified `MCPService` coordinator. Execution results are accompanied by commitment-based proofs (with a path to full Groth16 ZK proofs via the `zkp_production` feature flag).

Provider selection uses a reputation-weighted scoring system that considers available capacity, success rate, latency, and uptime. The registry persists model records to RocksDB via the `citrate-storage` crate.

## Modules

| Module | File | Purpose |
|--------|------|---------|
| `lib` | `lib.rs` | `MCPService` coordinator -- wires registry, providers, executor, verifier |
| `types` | `types.rs` | Core types: `ModelId`, `ModelMetadata`, `ComputeRequirements`, `PricingModel`, `ExecutionProof`, `RequestStatus` |
| `registry` | `registry.rs` | `ModelRegistry` -- model registration, lookup, execution request lifecycle, RocksDB persistence |
| `gguf_engine` | `gguf_engine.rs` | `GGUFEngine` -- llama.cpp wrapper for text generation, embeddings, chat completion; `cosine_similarity` utility |
| `cache` | `cache.rs` | `ModelCache` -- LRU eviction cache with size tracking, preload, and access statistics |
| `execution` | `execution.rs` | `ModelExecutor` -- inference and training execution with IPFS model loading, gas estimation, proof generation |
| `provider` | `provider.rs` | `ProviderRegistry` -- provider registration, reputation tracking, capacity-based selection scoring |
| `verification` | `verification.rs` | `ExecutionVerifier` -- model integrity checks, execution proof verification, commitment-based and ZK proof support |

## Public API

### Structs

- **`MCPService`** -- Top-level coordinator; owns `ModelRegistry`, `ProviderRegistry`, `ModelExecutor`, `ExecutionVerifier`. Methods: `register_model`, `update_model_weight`, `execute_inference`.
- **`ModelRegistry`** -- Tracks models and execution requests. Methods: `register`, `get_model`, `get_record`, `update_weight`, `get_providers`, `create_request`, `update_request_status`.
- **`ProviderRegistry`** -- Manages compute providers. Methods: `register_provider`, `register_model_provider`, `select_provider`, `update_reputation`, `get_provider`, `list_providers`.
- **`ModelExecutor`** -- Runs AI inference/training. Methods: `execute_inference`, `execute_training`, `is_ai_available`.
- **`ModelCache`** -- LRU model cache. Methods: `get`, `put`, `remove`, `clear`, `stats`, `preload`.
- **`GGUFEngine`** -- llama.cpp wrapper. Methods: `generate_text`, `generate_embeddings`, `chat_completion`, `load_model_from_bytes`.
- **`ExecutionVerifier`** -- Proof verification. Methods: `verify_model`, `verify_proof`, `verify_io_commitment`.

### Key Types

- `ModelId([u8; 32])`, `RequestId([u8; 32])` -- 32-byte identifiers
- `ModelMetadata` -- Name, version, owner, hash, size, architecture, compute requirements, pricing
- `InferenceResult` -- Output bytes, execution proof, gas used, latency, provider
- `TrainingResult` -- Updated weights, metrics (loss/accuracy/epoch), proof, gas
- `ExecutionProof` -- Model hash, I/O hashes, commitment, statement, proof data, timestamp
- `CacheStats` -- Model count, size, utilization, access count

### Feature Flags

- `zkp_production` -- Enable full Groth16 ZK proof verification via arkworks (off by default)

## Tests

```bash
cargo test -p citrate-mcp
```

203 tests (92 unit + 74 integration + 37 doc/misc), all passing.

## Dependencies

| Dependency | Purpose |
|-----------|---------|
| `citrate-consensus` | Block/transaction types |
| `citrate-execution` | VM, Address, Hash types |
| `citrate-storage` | StorageManager, IPFS service |
| `sha3`, `blake3` | Cryptographic hashing |
| `primitive-types` | U256 for pricing |
| `chrono` | Timestamps |
| `dirs`, `num_cpus` | GGUF engine defaults |
| `bincode` | Model record serialization |
