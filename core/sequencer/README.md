# citrate-sequencer

Mempool management, transaction validation, and block building for the Citrate blockchain.

## Overview

The sequencer crate is responsible for the transaction pipeline between receiving transactions and producing blocks. It manages the mempool (transaction staging area), validates incoming transactions against configurable rules, and assembles candidate blocks for proposers.

The mempool implements priority-based ordering with AI-aware transaction classification. Transactions are categorized into classes (Standard, ModelUpdate, Inference, Training, Storage, System, Compute), each with configurable priority multipliers. The mempool enforces per-sender limits, duplicate detection, gas price minimums, and capacity bounds while providing efficient batch extraction for block building.

The block builder integrates with the execution layer to execute transactions, compute state and receipt roots, and produce complete blocks with EIP-1559-compatible base fee calculations. It supports both sequential and parallel execution modes and handles proper Merkle root computation for consensus validation.

## Modules

| Module | File | Purpose |
|--------|------|---------|
| `mempool` | `src/mempool.rs` | Priority-based transaction pool with AI-aware classification, per-sender tracking, eviction policies, gas price estimation, pending nonce support, and batch extraction |
| `block_builder` | `src/block_builder.rs` | Block assembly: transaction selection from mempool, execution via `Executor`/`ParallelExecutor`, state root computation, receipt root calculation, EIP-1559 base fee, block signing |
| `validator` | `src/validator.rs` | Transaction validation pipeline: signature verification (ed25519 + ECDSA), balance checks, nonce validation, gas price/limit enforcement, data size limits, rate limiting, address blacklisting |
| `mempool_tests` | `src/mempool_tests.rs` | Additional mempool test coverage |
| `lib` | `src/lib.rs` | Module declarations and public re-exports |

## Public API

### Mempool
- **`Mempool::new(config)`** -- Create mempool with `MempoolConfig` (capacity, gas floor, per-sender limit)
- **`Mempool::add_transaction(tx)`** -- Add transaction with validation and priority sorting
- **`Mempool::get_transactions(max)`** -- Extract top-priority transactions for block building
- **`Mempool::get_pending_transactions_for_sender(pubkey)`** -- Get sender's pending transactions (for pending nonce)
- **`Mempool::remove_transactions(hashes)`** -- Remove mined transactions
- **`Mempool::estimate_gas_price()`** -- Estimate current gas price from pool
- **`Mempool::get_stats()`** -- Get `MempoolStats` (size, gas stats, class breakdown)
- **`MempoolAccess` trait** -- Async trait for mempool interaction from other crates

### Transaction Classes
- **`TxClass`** -- Enum: `Standard`, `ModelUpdate`, `Inference`, `Training`, `Storage`, `System`, `Compute`
- Each class has a `priority_multiplier()` affecting ordering (System=1000x, Compute=500x, Training=400x, etc.)

### Block Builder
- **`BlockBuilder::new(config, mempool, dag_store, ghostdag)`** -- Create builder
- **`BlockBuilder::with_executor(executor)`** -- Attach execution engine for state root computation
- **`BlockBuilder::build_block(parent, proposer, vrf_proof)`** -- Build a complete block candidate
- **`BlockBuilderConfig`** -- Configuration: max block size, gas limits, transaction bounds, target block time

### Transaction Validator
- **`TxValidator::new(rules, state_provider)`** -- Create validator with rules and state access
- **`TxValidator::validate(tx)`** -- Full validation: signature, balance, nonce, gas, rate limit, blacklist
- **`TxValidator::validate_batch(txs)`** -- Batch validation
- **`TxValidator::blacklist_address(addr)`** / **`unblacklist_address(addr)`** -- Address management
- **`ValidationRules`** -- Configurable rules: min gas price, max gas limit, max data size, rate limits
- **`ValidationPipeline`** -- Parallel/sequential batch processing, returns (valid, invalid) split

### State Provider
- **`StateProvider` trait** -- Async trait for account lookups: `get_account`, `get_balance`, `get_nonce`
- **`MockStateProvider`** -- In-memory implementation for testing

## Usage

```rust
use citrate_sequencer::*;
use std::sync::Arc;

// Create mempool
let config = MempoolConfig::default(); // 10,000 capacity, 1 Gwei floor
let mempool = Arc::new(Mempool::new(config));

// Add transactions
mempool.add_transaction(tx).await?;

// Validate transactions before adding
let rules = ValidationRules::default();
let validator = TxValidator::new(rules, state_provider);
validator.validate(&tx).await?;

// Build blocks
let builder = BlockBuilder::new(builder_config, mempool.clone(), dag_store, ghostdag);
let block = builder.build_block(parent_hash, proposer_key, vrf_proof).await?;
```

## Tests

```bash
cargo test -p citrate-sequencer
```

94 tests across all modules (all passing), covering mempool operations, priority ordering, eviction, gas estimation, transaction validation rules, rate limiting, blacklisting, and block building.

## Dependencies

| Crate | Purpose |
|-------|---------|
| `citrate-consensus` | Block/transaction types, crypto verification |
| `citrate-execution` | `Executor`, `ParallelExecutor`, `TransactionReceipt`, `Address` |
| `tokio` | Async runtime |
| `priority-queue` | Priority-based mempool ordering |
| `rlp` | RLP encoding for Ethereum-compatible transactions |
| `secp256k1` | ECDSA signature recovery |
| `chrono` | Timestamp handling for rate limiting |
| `thiserror` | Error type derivation |
| `tracing` | Structured logging |
| `proptest` | Property-based testing (dev) |
