# citrate-network

Peer-to-peer networking layer for Citrate -- Noise-encrypted transport, gossip protocol with peer scoring, header/block sync, NAT traversal, relay service, and AI inference distribution.

## Overview

citrate-network implements the P2P networking stack for the Citrate blockchain. It handles peer discovery, encrypted communication, block/transaction propagation, and chain synchronization. The transport layer uses Noise_XX_25519_ChaChaPoly_SHA256 for authenticated, encrypted connections over TCP with length-delimited framing.

The gossip protocol propagates blocks and transactions across the network using DashMap-backed seen-message caches for deduplication. Peers are scored based on their behavior: valid blocks/transactions earn small positive scores, while invalid messages and spam incur penalties. Peers whose cumulative score drops below the threshold are banned and disconnected. Block propagation supports header-first download with source tracking, and the sync manager implements a multi-phase synchronization protocol (header download, block download, verification, applying).

Lock ordering is documented at the crate root across four levels to prevent deadlocks. All concurrent state uses either `DashMap` (lock-free) or `RwLock`/`Mutex` following the defined acquisition hierarchy.

## Modules

| Module | File | Purpose |
|--------|------|---------|
| `lib` | `lib.rs` | Crate root with re-exports and lock ordering documentation |
| `types` | `types.rs` | `NetworkConfig`, `NetworkError` enum (connection, protocol, sync, timeout, transport, IO errors) |
| `noise` | `noise.rs` | `NoiseKeypair` -- X25519 keypair generation; `NoiseSession` -- Noise_XX handshake and encrypted transport over TCP |
| `transport` | `transport.rs` | `NetworkTransport` -- TCP listener/connector with optional Noise encryption, handshake, peer allow-list |
| `peer` | `peer.rs` | `PeerManager` -- peer lifecycle, scoring, banning; `Peer`, `PeerId`, `PeerInfo`, `PeerManagerConfig` |
| `gossip` | `gossip.rs` | `GossipProtocol` -- block/transaction propagation with deduplication, peer scoring (+1/-10/-25), `GossipConfig` |
| `block_propagation` | `block_propagation.rs` | `BlockPropagation` -- header-first block download, source tracking, recent broadcast deduplication |
| `transaction_gossip` | `transaction_gossip.rs` | `TransactionGossip` -- transaction relay, seen-tx cache, peer inventory tracking, pending AI transaction queue |
| `discovery` | `discovery.rs` | `Discovery` -- peer discovery with bootstrap nodes, connected peer tracking; `DiscoveryConfig` |
| `sync` | `sync.rs` | `SyncManager` -- multi-phase sync (headers, blocks, verify, apply), header/block queues, progress tracking; `SyncConfig`, `SyncState` |
| `nat` | `nat.rs` | `NatInfo`, `NatType` -- NAT type detection and traversal information |
| `relay` | `relay.rs` | `RelayService` -- relay sessions for NAT-traversed peers; `RelayError` |
| `protocol` | `protocol.rs` | `NetworkMessage` enum, `Protocol`, `ProtocolVersion`, `ModelMetadata` (network-level) |
| `ai_handler` | `ai_handler.rs` | `AINetworkHandler` -- distributed AI inference requests, active training sessions, model cache; `NetworkInferenceExecutor`, `NetworkInferenceResult` |

## Public API

### Key Structs

- **`NetworkTransport`** -- TCP transport with Noise encryption, peer allow-list, handshake
- **`PeerManager`** -- Peer lifecycle: connect, disconnect, score, ban. Configurable via `PeerManagerConfig`
- **`GossipProtocol`** -- Block/transaction gossip with deduplication and peer scoring
- **`SyncManager`** -- Chain sync: header-first download, block download, verification, state application
- **`Discovery`** -- Bootstrap-based peer discovery
- **`BlockPropagation`** -- Header-first block propagation with source tracking
- **`TransactionGossip`** -- Transaction relay with inventory tracking
- **`AINetworkHandler`** -- Distributed AI inference coordination
- **`NoiseKeypair`** -- X25519 static keypair for Noise protocol identity
- **`RelayService`** -- Session-based relay for NAT-traversed peers

### Key Enums

- `NetworkError` -- ConnectionFailed, ProtocolError, PeerNotFound, SyncError, Timeout, InvalidMessage, Shutdown, TransportError, Io
- `SyncState` -- Idle, DownloadingHeaders, DownloadingBlocks, Verifying, Applying, Complete
- `NatType` -- NAT type classification for traversal

### Re-exports

`AINetworkHandler`, `BlockPropagation`, `Discovery`, `GossipProtocol`, `NatInfo`, `NatType`, `Peer`, `PeerId`, `PeerInfo`, `PeerManager`, `Protocol`, `NetworkMessage`, `RelayService`, `SyncManager`, `SyncState`, `TransactionGossip`, `NetworkTransport`, `NoiseKeypair`, `NetworkConfig`, `NetworkError`.

## Tests

```bash
cargo test -p citrate-network
```

128 tests (31 + 16 + 10 + 56 + 5 + 5 + 2 + 3 across modules), all passing.

## Dependencies

| Dependency | Purpose |
|-----------|---------|
| `citrate-consensus` | Block, Transaction, Hash types |
| `citrate-sequencer` | Mempool integration |
| `citrate-storage` | Block/state storage |
| `citrate-execution` | Executor types |
| `snow` | Noise protocol implementation (XX handshake, ChaCha20-Poly1305) |
| `tokio`, `tokio-util` | Async runtime, length-delimited codec |
| `futures` | Stream/Sink utilities |
| `dashmap` | Lock-free concurrent seen-message caches |
| `parking_lot` | Fast Mutex for Noise transport state |
| `bytes` | Buffer management |
