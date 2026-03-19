# citrate-storage

Persistent storage layer with RocksDB backend, IPFS model distribution, quantum-safe encryption, and state pruning.

## Overview

`citrate-storage` provides the complete persistence layer for the Citrate blockchain. At its core is a RocksDB wrapper with 21 column families covering blocks, headers, transactions, receipts, accounts, contract code, contract storage, AI models, training state, DAG relations, DAG tips, finalized blocks, height indices, blue set data, and BFT checkpoints. The database is tuned for blockchain workloads with LZ4 compression, 128 MB write buffers, bloom filters, and parallelism scaled to available CPU cores.

The IPFS subsystem handles distributed storage and retrieval of AI model weights. Large models (>256 MB) are automatically split into chunks with BLAKE3 integrity hashes, stored as individual IPFS objects, and reassembled via a JSON manifest. A pinning incentive manager tracks replica counts and calculates storage rewards based on model size, type (language/vision/multimodal), and pinning duration. An encrypted store layer integrates AES-256-GCM encryption from `citrate-execution` with IPFS, ensuring models can be encrypted before distribution and decrypted only by authorized parties. The IPFS daemon manager handles automatic downloading, installation, and lifecycle management of the kubo daemon.

The Quantum-Safe Storage Protocol (QSSP) implements defense against "Harvest Now, Decrypt Later" attacks using a hybrid classical + post-quantum encryption scheme. It combines CRYSTALS-Kyber (ML-KEM, NIST PQC standard) for key encapsulation with X25519 ECDH for classical key agreement, wrapping data with AES-256-GCM. The crypto-agile envelope format supports algorithm upgrades without re-encrypting existing data, and on-chain key commitment anchoring provides verifiable key lifecycle events.

## Modules

| Module | File | Purpose |
|--------|------|---------|
| `lib` | `src/lib.rs` | Crate root: `StorageManager` struct, `StorageConfig`, module declarations |
| `db/mod` | `src/db/mod.rs` | Database module root |
| `db/rocks_db` | `src/db/rocks_db.rs` | `RocksDB` wrapper: open, get/put/delete with column families, batch writes, iteration, flush, statistics |
| `db/column_families` | `src/db/column_families.rs` | 21 column family constants (blocks, headers, transactions, receipts, accounts, storage, code, models, training, metadata, blue_set, dag_*, checkpoints) |
| `db/optimizations` | `src/db/optimizations.rs` | `DbOptimizations`: tuned RocksDB options (bloom filters, block cache, pipelined writes, direct I/O) |
| `chain/mod` | `src/chain/mod.rs` | Chain storage module root |
| `chain/block_store` | `src/chain/block_store.rs` | `BlockStore`: store/retrieve blocks and headers, height-to-hash index, parent-child DAG relations, blue set mapping |
| `chain/transaction_store` | `src/chain/transaction_store.rs` | `TransactionStore`: store/retrieve transactions and receipts, sender-nonce indexing, batch operations |
| `state/mod` | `src/state/mod.rs` | State storage module root |
| `state/state_store` | `src/state/state_store.rs` | `StateStore`: RocksDB-backed account/code/storage persistence, implements `StateStoreTrait`, model and training state |
| `state/ai_state` | `src/state/ai_state.rs` | `AIStateTree`: in-memory AI state (model registry, training jobs, weight CIDs, inference cache, LoRA adapters), Merkle root computation |
| `state_manager` | `src/state_manager.rs` | `StateManager`: unified state manager combining account state and AI state, calculates composite state root |
| `cache/mod` | `src/cache/mod.rs` | Cache module root |
| `cache/lru_cache` | `src/cache/lru_cache.rs` | `Cache<K,V>`: thread-safe LRU cache via `parking_lot::RwLock`, `BlockCacheEntry`, `StateCacheEntry` |
| `ipfs/mod` | `src/ipfs/mod.rs` | `IPFSService`: model store/retrieve via IPFS HTTP API, chunked upload, pinning, reward calculation, `IPFSOperations` trait |
| `ipfs/chunking` | `src/ipfs/chunking.rs` | `chunk_model`: split large models into BLAKE3-hashed chunks, `ChunkManifest` for reassembly |
| `ipfs/pinning` | `src/ipfs/pinning.rs` | `PinningManager`: pinning incentive accounting, reward calculation by model type/size/duration, `PinningSummary` |
| `ipfs/encrypted_store` | `src/ipfs/encrypted_store.rs` | `EncryptedManifest`: integrates AES-256-GCM encryption with IPFS storage for secure model distribution |
| `ipfs/daemon` | `src/ipfs/daemon.rs` | `IpfsDaemon`: automatic kubo installation, lifecycle management, health checks, `DaemonConfig`/`DaemonStatus` |
| `pruning/mod` | `src/pruning/mod.rs` | Pruning module root |
| `pruning/pruner` | `src/pruning/pruner.rs` | `Pruner`: configurable auto-pruning of old blocks and state, batch deletion, `PruningConfig`/`PruningStats` |
| `crypto/mod` | `src/crypto/mod.rs` | QSSP module root: protocol version, magic bytes, algorithm enums (`PQAlgorithm`, `ClassicalAlgorithm`, `SymmetricAlgorithm`) |
| `crypto/quantum_safe` | `src/crypto/quantum_safe.rs` | `HybridKEM`: hybrid Kyber768/1024 + X25519 key encapsulation, `QuantumSafeConfig`, security levels |
| `crypto/database_encryption` | `src/crypto/database_encryption.rs` | `EncryptedDatabase`: per-column-family encryption keys, `EncryptedValue`/`DecryptedValue`, `EncryptionStats` |
| `crypto/key_derivation` | `src/crypto/key_derivation.rs` | `MasterKeyDerivation`: Argon2id-based master key derivation, `DerivedKey`, `KeyPurpose` |
| `crypto/envelope` | `src/crypto/envelope.rs` | `CryptoAgileEnvelope`: versioned encryption envelope for algorithm-agile encryption at rest |
| `crypto/key_commitment` | `src/crypto/key_commitment.rs` | `KeyCommitment`: on-chain key anchoring, `KeyRotationProof`, `KeyLifecycleEvent` |
| `crypto/benchmarks` | `src/crypto/benchmarks.rs` | QSSP performance benchmarks (test-only) |

## Public API

### Storage Manager

- **`StorageManager`** -- Top-level coordinator holding `RocksDB`, `BlockStore`, `TransactionStore`, `StateStore`, `Pruner`, block/state caches, and optional `EncryptedDatabase`.
- **`StorageConfig`** -- Configuration struct with `PruningConfig` and optional `DatabaseEncryptionConfig`. `maximum_security()` factory for AI model storage.
- **`StorageManager::new(path, pruning_config)`** -- Create with default encryption disabled.
- **`StorageManager::with_config(path, config)`** -- Create with full configuration.
- **`initialize_encryption(password)`** -- Initialize QSSP encryption with password/seed.
- **`start_services()`** -- Launch background auto-pruning task.
- **`flush()`** / **`clear_caches()`** / **`get_statistics()`** -- Maintenance operations.

### Block & Transaction Storage

- **`BlockStore`** -- `put_block`, `get_block`, `get_header`, `get_block_by_height`, `get_children`, `get_tips`. Maintains height index, parent-child DAG relations, and blue score mapping.
- **`TransactionStore`** -- `put_transaction`, `put_transactions` (batch), `get_transaction`, `put_receipt`, `get_receipt`. Indexes by sender-nonce for efficient lookup.

### State Storage

- **`StateStore`** -- Implements `StateStoreTrait` for RocksDB persistence. `put_account`, `get_account`, `put_code`, `put_storage`, `delete_storage`. Also handles model state and training jobs.
- **`StateManager`** -- Unifies `StateStore` and `AIStateTree`. `calculate_state_root()` produces a composite hash of account root + storage root + AI root.
- **`AIStateTree`** -- In-memory tree: model registry, training jobs, weight CIDs, inference cache, LoRA adapters. `calculate_root()` for Merkle commitment.

### IPFS

- **`IPFSService`** -- `store_model`, `retrieve_model`, `list_pinned_models`, `calculate_pin_reward`, `pinning_summary`, `fetch_raw`, `record_external_pin`.
- **`IPFSOperations`** trait -- Async interface: `store`, `retrieve`, `pin`, `unpin`.
- **`IpfsDaemon`** -- `install`, `start`, `stop`, `health_check`, `DaemonConfig`, `DaemonStatus`.
- **`Cid`** -- IPFS Content Identifier wrapper.
- **`ModelMetadata`** / **`ModelFramework`** / **`ModelType`** -- Model metadata types.

### Caching

- **`Cache<K,V>`** -- Thread-safe generic LRU cache. `get`, `put`, `remove`, `contains`, `clear`, `len`.

### Pruning

- **`Pruner`** -- `start_auto_pruning()` runs on a configurable interval. `prune_blocks()`, `prune_state()`.
- **`PruningConfig`** -- `keep_blocks` (100K default), `keep_states` (10K), `interval` (1h), `batch_size`, `auto_prune`.

### Quantum-Safe Encryption

- **`HybridKEM`** -- Hybrid Kyber + X25519 key encapsulation.
- **`EncryptedDatabase`** -- Per-column-family encryption at rest.
- **`MasterKeyDerivation`** -- Argon2id master key derivation.
- **`CryptoAgileEnvelope`** -- Versioned encryption envelope for algorithm upgrades.
- **`KeyCommitment`** -- On-chain key lifecycle anchoring with rotation proofs.

## Usage

```rust
use citrate_storage::{StorageManager, StorageConfig};
use citrate_storage::pruning::PruningConfig;
use std::sync::Arc;

// Basic initialization
let storage = Arc::new(
    StorageManager::new("/tmp/citrate-data", PruningConfig::default()).unwrap()
);

// Store a block
storage.blocks.put_block(&block).unwrap();

// Retrieve by height
let block = storage.blocks.get_block_by_height(42).unwrap();

// Store and retrieve a transaction
storage.transactions.put_transaction(&tx).unwrap();
let receipt = storage.transactions.get_receipt(&tx_hash).unwrap();

// Use cache
storage.block_cache.put(block_hash, serialized_block);
let cached = storage.block_cache.get(&block_hash);

// Start background pruning
let storage_arc = storage.clone();
tokio::spawn(async move { storage_arc.start_services().await });

// Maximum security configuration (quantum-safe encryption)
let config = StorageConfig::maximum_security("node-001".to_string());
let secure_storage = StorageManager::with_config("/tmp/secure-data", config).unwrap();
```

## Tests

```bash
cargo test -p citrate-storage
```

179 tests passing, 3 ignored, across 6 test binaries. Key test areas: RocksDB column family operations, block/transaction store CRUD, state persistence, LRU cache behavior, IPFS service (pinning, rewards, metadata), pruner configuration, quantum-safe encryption (Kyber KEM, key derivation, envelope serialization, key commitment), AI state tree operations, and chunking integrity.

## Dependencies

| Dependency | Purpose |
|-----------|---------|
| `rocksdb` | Persistent key-value storage engine |
| `citrate-consensus` | Block, Transaction, Hash types |
| `citrate-execution` | AccountState, Address, StateStoreTrait, crypto modules |
| `lru` / `parking_lot` / `dashmap` | Thread-safe LRU caching and concurrent maps |
| `reqwest` | IPFS HTTP API client |
| `blake3` | Content integrity hashing for IPFS chunks |
| `zstd` | Zstandard compression for IPFS storage |
| `pqcrypto-kyber` / `pqcrypto-traits` | CRYSTALS-Kyber (ML-KEM) post-quantum KEM |
| `x25519-dalek` | Classical X25519 ECDH key agreement |
| `aes-gcm` | AES-256-GCM symmetric encryption |
| `zeroize` | Secure memory zeroing for key material |
| `dirs` / `flate2` / `tar` / `zip` | IPFS daemon auto-installation |
| `chrono` | Timestamp formatting |
