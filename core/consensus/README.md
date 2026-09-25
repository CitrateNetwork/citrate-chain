# citrate-consensus

GhostDAG consensus engine for the Citrate BlockDAG blockchain.

## Overview

This crate implements the core consensus layer for Citrate, a DAG-based blockchain using the GhostDAG protocol. Unlike traditional chain-based consensus (GHOST), GhostDAG operates on a directed acyclic graph where blocks can have multiple parents. The protocol partitions blocks into a "blue set" (honest-majority consistent) and a "red set" using a k-cluster rule, then derives a deterministic total ordering over all blocks.

The crate provides the full consensus stack: blue set calculation, tip and parent selection, chain selection with reorganization support, depth-based finality tracking and committee BFT checkpoint types, deterministic total ordering of blocks and transactions, and VRF-based proposer election using ECVRF-P256-SHA256 (RFC 9381).

**Status on the public testnet (chain 40204).** Confirmation is probabilistic: a block gains weight as later blocks build on it. Checkpoint finality is specified, not running: `CheckpointManager` is constructed by the node, but no production code path calls `propose()` yet. `FinalityTracker` and `ChainSelector::with_finality` are exercised only by tests. The testnet runs a single block producer; stake-gated proposer eligibility is off by default and turns on when a validator registry is configured (`CITRATE_VALIDATOR_REGISTRY`). The 100-member committee with a 67 quorum is the target design. The machine-readable record is `verification/claims.json` (`deterministic_checkpoint_finality`, `consensus_ghostdag`).

The DAG store supports both in-memory operation and persistent write-through to a RocksDB backend via the `KvStore` trait, ensuring DAG state survives node restarts without requiring a full re-sync.

## Modules

| Module | File | Purpose |
|--------|------|---------|
| `types` | `src/types.rs` | Core types: `Hash`, `PublicKey`, `Signature`, `Block`, `BlockHeader`, `BlueSet`, `DagRelation`, `Transaction`, `GhostDagParams`, AI model types (`EmbeddedModel`, `RequiredModel`, `ModelId`) |
| `ghostdag` | `src/ghostdag.rs` | GhostDAG consensus engine: blue set calculation, k-cluster rule enforcement, block addition, tip selection by blue score |
| `dag_store` | `src/dag_store.rs` | DAG storage manager with in-memory maps and optional persistent `KvStore` backend, VRF admission gating, pruning, finalization tracking |
| `tip_selection` | `src/tip_selection.rs` | Tip selection strategies (highest blue score, tie-breaking, weighted random) and parent selection for new blocks |
| `chain_selection` | `src/chain_selection.rs` | Chain selection and reorganization manager; finality-aware reorg protection via `with_finality` (not wired in the node today) |
| `finality` | `src/finality.rs` | Depth-based finality tracker with configurable confirmation depth and finality events via broadcast channel (not constructed by the node today) |
| `checkpoint` | `src/checkpoint.rs` | Committee BFT checkpoint system: deterministic committee selection, ed25519-signed checkpoint votes, quorum-based finalization (specified and tested; no production caller proposes checkpoints yet) |
| `ordering` | `src/ordering.rs` | Deterministic total ordering of DAG blocks: selected-parent chain walk with mergeset interleaving, transaction ordering |
| `vrf` | `src/vrf.rs` | VRF-based proposer selection with stake-weighted eligibility (stake gating is off by default in the node), supports both ECVRF and legacy SHA3 proof verification |
| `ecvrf` | `src/ecvrf.rs` | ECVRF-P256-SHA256-TAI implementation per RFC 9381: prove, verify, deterministic nonce generation, proof serialization (114 bytes) |
| `crypto` | `src/crypto.rs` | Cryptographic operations: ed25519 transaction signing/verification, ECDSA bypass protection (C-01 fix), block signing |
| `lib` | `src/lib.rs` | Module declarations and public re-exports |

## Public API

### Core Types
- **`Hash`** -- 32-byte block/transaction identifier with hex display
- **`Block`** / **`BlockHeader`** -- Full block structure with consensus fields, AI learning extensions, `compute_hash()`, `verify_hash()`
- **`GhostDagParams`** -- Consensus parameters (k=18, max_parents=10, finality_depth=100)
- **`BlueSet`** -- Set of blue block hashes with cumulative score
- **`DagRelation`** -- Parent-child-blue_set relationship for a block
- **`Transaction`** -- Transaction with EIP-1559/2930 support, AI transaction types, ECDSA verification flag

### AI Model Artifacts — Three-Tier Commitment Model

The consensus layer treats AI models as first-class artifacts but follows a strict three-tier model for where data lives. The rule: **commitments are on-chain; distribution is off-chain.**

| Tier | Type | On-chain footprint | Where bytes live | Use |
|------|------|---------------------|------------------|-----|
| 1. Metadata + commitment | `EmbeddedModel` | fixed (~544 B per model) | off-chain, addressed by `weights_sha256` | Genesis-era canonical models; bytes bundled in release, pinned on IPFS, or resolved by node |
| 2. Pin declaration | `RequiredModel` | fixed (~140 B per pin) | off-chain (IPFS CID) | Models validators must pin to participate fully; carries SHA-256, size declaration, slash penalty |
| 3. Application-layer registration | `ModelRegistry` contract | variable (Solidity storage) | off-chain | Models deployed by users post-genesis; lives in contract state, not block commitments |

Under this model, **block size is bounded by construction regardless of model size**. A block carrying ten embedded models committed to 10 GB of weights occupies roughly the same on-chain space as a block carrying ten small models — the weights live off-chain, and only fixed-size commitments are replicated to every peer.

#### Integrity and tamper detection

Each `EmbeddedModel` carries a `weights_sha256: Hash` commitment. A node verifying a block's embedded models:

1. Retrieves the bytes from off-chain storage (bundled asset, IPFS, or trusted mirror)
2. Computes `sha256(retrieved_bytes)`
3. Compares to the on-chain `weights_sha256`
4. Accepts the block iff every embedded model's commitment matches

Under SHA-256 collision-resistance, tampering with the off-chain bytes is detectable: the hash changes, and the block's stored commitment fails to match.

The integrity properties are formally verified by [`specs/tla/consensus/EmbeddedModelCommitment.tla`](../../specs/tla/consensus/EmbeddedModelCommitment.tla) — 7 invariants, 7,110 distinct states explored, zero violations.

#### History — why this design

The pre-2026-04-21 design carried raw GGUF bytes in an `EmbeddedModel.weights: Vec<u8>` field, with no size cap at the consensus layer. This permitted arbitrarily large genesis blocks by construction. The [2026-04-21 repo walkthrough audit](../../../.audit/2026-04-21-repo-walkthrough/02_GENESIS_AND_EMBEDDED_MODELS.md) flagged this as a mainnet blocker. Sprint P950-B (April 2026) replaced the field with the `weights_sha256` commitment. See [`ADR-010`](../../../.agentile/planset/architecture/ADR_010_EMBEDDED_MODEL_COMMITMENT.md) for the decision record.

### GhostDAG Engine
- **`GhostDag::new(params, dag_store)`** -- Create engine with parameters and storage
- **`GhostDag::calculate_blue_set(block)`** -- Calculate blue set following k-cluster rule
- **`GhostDag::add_block(block)`** -- Add block to DAG, update relations and tips
- **`GhostDag::select_tip()`** -- Select best tip by blue score
- **`GhostDag::get_tips()`** -- Get current DAG tips

### DAG Storage
- **`DagStore::new()`** -- In-memory store
- **`DagStore::persistent(kv)`** -- Persistent store backed by `KvStore` (loads state on creation)
- **`DagStore::with_strict_vrf(bool)`** -- Enable strict VRF admission gating
- **`KvStore` trait** -- Abstraction for persistent backends (get/put/delete/exists/iter)
- **`store_block(block)`**, **`get_block(hash)`**, **`get_tips()`**, **`finalize_block(hash)`**, **`prune()`**

### Tip & Chain Selection
- **`TipSelector`** -- Configurable tip selection with `SelectionStrategy` enum
- **`ParentSelector`** -- Selects (selected_parent, merge_parents) for new blocks
- **`ChainSelector`** -- Chain selection with reorg detection; finality-aware reorg rejection only when built `with_finality` (tests today)

### Finality
- **`FinalityTracker`** -- Depth-based finality with configurable `FinalityConfig`
- **`FinalityStatus`** -- Enum: `Finalized`, `PendingFinalization`, `Unfinalized { confirmations }`
- **`FinalityEvent`** -- Broadcast event when a block becomes final

### Checkpoints
- **`CheckpointManager`** -- Propose, vote, and finalize committee BFT checkpoints (no production caller of `propose()` yet)
- **`CommitteeSelector::select(validators, height, vrf_seed, size)`** -- Deterministic committee selection
- **`CheckpointVote`** -- ed25519-signed vote over (height || block_hash)

### Ordering
- **`TotalOrdering::get_total_order(tip)`** -- Deterministic block ordering from genesis to tip
- **`TotalOrdering::get_ordered_blocks(from, to)`** -- Block range with transaction order
- **`TotalOrderIterator`** -- Async iterator yielding blocks in consensus order

### VRF & Proposer Election
- **`VrfProposerSelector`** -- Validator registration, VRF proof generation/verification
- **`LeaderElection`** -- Epoch-based leader election using VRF
- **`ecvrf::prove(secret, alpha)`** / **`ecvrf::verify(alpha, proof)`** -- RFC 9381 ECVRF

### Cryptography
- **`crypto::verify_transaction(tx)`** -- Dual ed25519/ECDSA verification with C-01 bypass protection
- **`crypto::sign_transaction(tx, key)`** -- Sign with ed25519
- **`crypto::sign_block(hash, key)`** / **`crypto::verify_block_signature(block)`** -- Block signing

## Usage

```rust
use citrate_consensus::*;
use std::sync::Arc;

// Create DAG components
let dag_store = Arc::new(DagStore::new());
let params = GhostDagParams::default(); // k=18, max_parents=10
let ghostdag = GhostDag::new(params, dag_store.clone());

// Add blocks and query blue scores
dag_store.store_block(genesis_block).await?;
ghostdag.add_block(&child_block).await?;
let blue_set = ghostdag.calculate_blue_set(&child_block).await?;

// Total ordering
let ordering = TotalOrdering::new(dag_store.clone(), Arc::new(ghostdag));
let order = ordering.get_total_order(tip_hash).await?;

// Finality tracking
let tracker = FinalityTracker::with_defaults(dag_store.clone());
let finalized = tracker.update_finality(&tip_hash, tip_height).await?;

// Persistent DAG store (survives restart)
let dag_store = DagStore::persistent(Arc::new(rocksdb_kv_store))?;
```

## Tests

```bash
cargo test -p citrate-consensus
```

314 tests across all modules (all passing), including property-based tests via `proptest` for blue score monotonicity, tip selection correctness, and blue set containment invariants.

## Dependencies

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime, `RwLock` for concurrent DAG access |
| `ed25519-dalek` | ed25519 signature signing and verification |
| `p256` | NIST P-256 elliptic curve for ECVRF |
| `sha3` | SHA3-256 hashing for block hashes and legacy VRF |
| `sha2` | SHA-256 for ECVRF hash-to-curve and committee selection |
| `blake3` | Fast hashing |
| `hmac` | HMAC-SHA256 for RFC 6979 deterministic nonce generation |
| `bincode` | Serialization for persistent storage |
| `serde` | Serialization/deserialization of consensus types |
| `thiserror` | Error type derivation |
| `tracing` | Structured logging |
| `proptest` | Property-based testing (dev) |
