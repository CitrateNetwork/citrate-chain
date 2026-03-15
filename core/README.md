# Core

Rust workspace crates implementing the Citrate blockchain core. Contains consensus, execution, networking, storage, and AI-native subsystems that together form the Layer-1 BlockDAG.

## Contents

- `consensus/` -- GhostDAG consensus engine, tip selection, blue set calculation, finality
- `execution/` -- LVM (EVM-compatible) executor, REVM adapter, precompiles, state DB
- `storage/` -- Merkle Patricia Trie state, RocksDB block store, pruning
- `sequencer/` -- Mempool policy, transaction bundling, parent selection
- `api/` -- JSON-RPC server (eth_* and citrate_* methods), REST endpoints
- `network/` -- P2P networking, block/transaction propagation
- `mcp/` -- Model Context Protocol layer for AI model operations
- `learning/` -- Paraconsensus learning subsystem
- `economics/` -- Reward distribution and tokenomics
- `marketplace/` -- On-chain marketplace integration
- `bridge/` -- Cross-chain bridge attestation
- `genesis/` -- Genesis block construction
- `primitives/` -- Shared types (Hash, PublicKey, Signature, Block, Transaction)
- `security/` -- Rate limiting, operator auth, admission control

## Build / Usage

```bash
cargo build --release                    # Build all core crates
cargo test -p citrate-consensus          # Test a specific crate
cargo clippy --all-targets --all-features  # Lint all crates
```
