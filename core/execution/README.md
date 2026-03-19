# citrate-execution

EVM-compatible transaction execution engine with AI precompiles, state management, and zero-knowledge proof infrastructure.

## Overview

`citrate-execution` is the largest core crate in the Citrate blockchain, providing the full execution layer for transaction processing. It wraps [REVM](https://github.com/bluealloy/revm) (the same EVM used by Foundry/Anvil) via a `StateDBAdapter` that bridges Citrate's in-memory state to REVM's `Database` trait, enabling production-grade EVM execution including contract deployment, storage, and EIP-3607 compliance.

Beyond standard EVM execution, the crate extends the virtual machine with AI-native capabilities: a custom opcode range (0xA0-0xDF) for model loading, tensor operations, and proof generation; precompiled contracts at addresses 0x01-0x09 (Ethereum standard) and 0x0100-0x0202 (AI inference and x402 payment protocol); and an inference runtime targeting Apple Silicon Metal GPUs.

The state layer implements a Merkle Patricia Trie (MPT) for account and storage state, a multi-level LRU cache with hit-rate tracking, and dirty-slot tracking for efficient persistence. Cryptographic modules provide AES-256-GCM model encryption, ECIES key exchange on secp256k1, Shamir's Secret Sharing over GF(p), and HD key derivation. The ZKP subsystem offers experimental Groth16 circuits on BLS12-381 via arkworks (production gated behind the `zkp_production` feature in `citrate-mcp`).

## Modules

| Module | File | Purpose |
|--------|------|---------|
| `lib` | `src/lib.rs` | Crate root, module declarations, and public re-exports |
| `executor` | `src/executor.rs` | Main `Executor` struct: transaction execution, gas metering, model registry, REVM dispatch |
| `types` | `src/types.rs` | Core types: `Address`, `AccountState`, `ExecutionError`, `TransactionReceipt`, `GasSchedule`, `ModelState` |
| `revm_adapter` | `src/revm_adapter.rs` | `StateDBAdapter` implementing REVM `Database` + `DatabaseCommit` traits, `BlockContext` for BLOCKHASH |
| `address_utils` | `src/address_utils.rs` | Address normalization, hex parsing, pubkey-to-address conversion |
| `metrics` | `src/metrics.rs` | Prometheus counters/histograms: `VM_EXECUTIONS_TOTAL`, `VM_GAS_USED`, `PRECOMPILE_CALLS_TOTAL` |
| `state/mod` | `src/state/mod.rs` | State management module root |
| `state/state_db` | `src/state/state_db.rs` | `StateDB`: in-memory state database with account manager, storage tries, code storage, dirty tracking |
| `state/account` | `src/state/account.rs` | `AccountManager`: concurrent account state via `DashMap`, balance/nonce/transfer operations |
| `state/trie` | `src/state/trie.rs` | `Trie`/`TrieNode`: Merkle Patricia Trie with Leaf/Branch/Extension nodes, Keccak256 root hashing |
| `state/cache` | `src/state/cache.rs` | `StateCache`: multi-level LRU cache for accounts, storage, and code with `CacheStats` |
| `vm/mod` | `src/vm/mod.rs` | `VM` struct: stack machine with Stack/Memory/Storage, standard + AI opcode dispatch |
| `vm/evm_opcodes` | `src/vm/evm_opcodes.rs` | Standard EVM opcode implementations (ADD, MUL, SUB, DIV, MLOAD, MSTORE, JUMP, etc.) |
| `vm/ai_opcodes` | `src/vm/ai_opcodes.rs` | `AIVMExtension`: custom AI opcodes (LOAD_MODEL, EXEC_MODEL, TENSOR_*, VERIFY_PROOF) |
| `vm/evm_integration` | `src/vm/evm_integration.rs` | `EVMIntegration`: high-level EVM execution bridge |
| `vm/evm_tests` | `src/vm/evm_tests.rs` | EVM opcode test suite (test-only) |
| `precompiles/mod` | `src/precompiles/mod.rs` | `PrecompileExecutor`: Ethereum precompiles 0x01-0x09 (ECRECOVER, SHA256, RIPEMD160, IDENTITY, MODEXP, ECADD, ECMUL, ECPAIRING, BLAKE2F) |
| `precompiles/inference` | `src/precompiles/inference.rs` | `InferencePrecompile`: AI precompiles at 0x0100-0x0106 (model deploy, inference, batch, metadata, proof verify, benchmark, encryption) |
| `precompiles/x402` | `src/precompiles/x402.rs` | x402 payment protocol precompiles at 0x0200-0x0202 (EIP-712 verify, EIP-3009 transferWithAuthorization, batch payment verify) |
| `parallel/mod` | `src/parallel/mod.rs` | Parallel execution module root |
| `parallel/executor` | `src/parallel/executor.rs` | `ParallelExecutor`: concurrent transaction batch execution with conflict-aware scheduling |
| `parallel/conflict` | `src/parallel/conflict.rs` | `ConflictScheduler`, `AccessSet`: read/write dependency analysis for parallel grouping |
| `crypto/mod` | `src/crypto/mod.rs` | Cryptography module root |
| `crypto/encryption` | `src/crypto/encryption.rs` | `ModelEncryption`: AES-256-GCM encryption for model weights with access control |
| `crypto/key_manager` | `src/crypto/key_manager.rs` | `KeyManager`: HD key derivation, key rotation, purpose-based key management |
| `crypto/ecdh` | `src/crypto/ecdh.rs` | `ECIES`: Elliptic Curve Integrated Encryption Scheme on secp256k1 with HKDF-SHA256 |
| `crypto/shamir` | `src/crypto/shamir.rs` | Shamir's Secret Sharing over GF(2^256-189) with threshold reconstruction |
| `crypto/secure_enclave` | `src/crypto/secure_enclave.rs` | `AppleSecureEnclave`: macOS Secure Enclave interface for key attestation |
| `inference/mod` | `src/inference/mod.rs` | AI inference module root |
| `inference/metal_runtime` | `src/inference/metal_runtime.rs` | `MetalRuntime`: Apple Silicon GPU inference (M1-M3), model management, capability detection |
| `inference/coreml_bridge` | `src/inference/coreml_bridge.rs` | `CoreMLInference`: macOS CoreML model bridge (macOS only) |
| `tensor/mod` | `src/tensor/mod.rs` | Tensor operations module root |
| `tensor/engine` | `src/tensor/engine.rs` | `TensorEngine`: tensor computation engine using ndarray |
| `tensor/ops` | `src/tensor/ops.rs` | `TensorOps`: element-wise and matrix operations (add, mul, matmul) |
| `tensor/types` | `src/tensor/types.rs` | `Tensor`, `TensorShape`, `TensorError` type definitions |
| `zkp/mod` | `src/zkp/mod.rs` | Zero-knowledge proof module root (experimental) |
| `zkp/circuits` | `src/zkp/circuits.rs` | R1CS circuits: inference proof, state transition, gradient proof (placeholder constraints) |
| `zkp/prover` | `src/zkp/prover.rs` | `Prover`: Groth16 proof generation on BLS12-381 |
| `zkp/verifier` | `src/zkp/verifier.rs` | `Verifier`: Groth16 proof verification |
| `zkp/backend` | `src/zkp/backend.rs` | `ZKPBackend`: abstraction over proof system backends |
| `zkp/types` | `src/zkp/types.rs` | `Proof`, `ProofType`, `ProvingKey`, `VerifyingKey`, `ZKPError` |
| `address_derivation_integration_test` | `src/address_derivation_integration_test.rs` | Integration tests for dual address derivation (test-only) |

## Public API

### Core Execution

- **`Executor`** -- Main transaction executor. Holds `StateDB`, gas schedule, optional inference/artifact/model services. Executes transactions against blocks, manages chain ID (default 40204).
- **`ExecutionContext`** -- Per-transaction context: block number, gas tracking, origin address, logs, output.
- **`ParallelExecutor`** -- Schedules non-conflicting transactions into parallel groups and executes them concurrently via `ConflictScheduler`.

### State Management

- **`StateDB`** -- In-memory state database: account manager, per-account storage tries, contract code storage, model registry, dirty slot tracking.
- **`AccountManager`** -- Thread-safe account operations via `DashMap`: get/set balance, nonce, transfer, code hash.
- **`Trie` / `TrieNode`** -- Merkle Patricia Trie with insert, get, remove, and root hash computation.
- **`StateCache`** -- Multi-level LRU cache for accounts, storage slots, and contract code.
- **`StateRoot`** -- Type alias for `Hash`, representing the MPT root.

### REVM Integration

- **`StateDBAdapter`** -- Implements `revm::Database` and `revm::DatabaseCommit` for `StateDB`. Bridges Citrate state to REVM's account/storage model.
- **`BlockContext`** -- Block-level context (coinbase, prevrandao, recent block hashes) set before execution.

### Precompiles

- **`PrecompileExecutor`** -- Dispatches to Ethereum standard precompiles (0x01-0x09) and Citrate AI precompiles (0x0100+).
- **`InferencePrecompile`** -- AI model operations: deploy, inference, batch inference, metadata query, proof verification, benchmarking, encryption.
- **x402 precompiles** -- EIP-712 signature verification, EIP-3009 `transferWithAuthorization`, batch payment verification at addresses 0x0200-0x0202.

### Cryptography

- **`ModelEncryption`** / **`EncryptedModel`** -- AES-256-GCM encryption for model weights with access control lists.
- **`KeyManager`** / **`DerivedKey`** -- HD key derivation with purpose-based keys and rotation support.
- **`ECIES`** -- secp256k1 ECDH key exchange with AES-256-GCM and HKDF-SHA256.
- **Shamir's Secret Sharing** -- `FieldElement` arithmetic over GF(p), threshold share generation and reconstruction.

### Types

- **`Address`** -- 20-byte EVM address with dual derivation: embedded EVM addresses (20 bytes + 12 zero bytes) are used directly; full 32-byte public keys are Keccak256-hashed.
- **`AccountState`**, **`TransactionReceipt`**, **`ExecutionError`**, **`GasSchedule`**, **`Log`**
- **`ModelId`**, **`ModelState`**, **`ModelMetadata`**, **`JobId`**, **`JobStatus`**, **`TrainingJob`**

### Traits

- **`StateStoreTrait`** -- Persistence abstraction: `put_account`, `get_account`, `put_code`, `put_storage`, `delete_storage`.
- **`InferenceService`** -- AI inference execution abstraction.
- **`ArtifactService`** -- Model artifact storage/retrieval abstraction.
- **`AccessSetExtractor`** -- Extract read/write dependency sets from transactions for parallel scheduling.

## Usage

```rust
use citrate_execution::{Executor, StateDB, Address, ParallelExecutor};
use std::sync::Arc;

// Create state and executor
let state_db = Arc::new(StateDB::new());
let executor = Arc::new(Executor::new(state_db.clone()));

// Set a balance
state_db.accounts.set_balance(
    Address::from_hex("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEB1").unwrap(),
    primitive_types::U256::from(1_000_000_000_000_000_000u64), // 1 ETH
);

// Execute a transaction against a block
// let receipt = executor.execute_transaction(&block, &tx).await?;

// Parallel execution
let parallel = ParallelExecutor::new();
// let receipts = parallel.execute_batch_with(executor, &block, transactions).await?;
```

## Tests

```bash
cargo test -p citrate-execution
```

406 tests passing across 10 test binaries (unit tests, integration tests, and doc tests). Key test areas: address derivation (dual format, collision resistance), state trie operations, EVM opcode execution, precompile correctness, parallel conflict detection, cryptographic operations, and ZKP circuit validation.

## Dependencies

| Dependency | Purpose |
|-----------|---------|
| `revm` 10 / `revm-primitives` 5 | Production EVM execution engine (same as Foundry/Anvil) |
| `citrate-consensus` | Block/Transaction/Hash types |
| `primitive-types` / `ethereum-types` | U256, H160, H256 EVM primitives |
| `ndarray` / `ndarray-rand` | Tensor operations (matrix math, random init) |
| `ark-groth16` / `ark-bls12-381` / `ark-r1cs-std` | Groth16 ZKP circuits on BLS12-381 (experimental) |
| `ark-bn254` | BN254 curve for ECADD/ECMUL/ECPAIRING precompiles |
| `k256` | secp256k1 ECDSA/ECDH for ECRECOVER and ECIES |
| `aes-gcm` | AES-256-GCM authenticated encryption |
| `argon2` | Password-based key derivation |
| `sha3` / `sha2` / `ripemd` / `blake2` | Keccak256, SHA256, RIPEMD160, BLAKE2F precompiles |
| `dashmap` / `parking_lot` / `lru` | Concurrent data structures and caching |
| `prometheus` | Execution metrics |
| `num-bigint` | MODEXP precompile big integer arithmetic |
