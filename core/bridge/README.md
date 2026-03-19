# citrate-bridge

Cross-chain bridge relay between Ethereum Sepolia and Citrate devnet -- ERC-6551 bridge with M-of-N oracle attestation, bonding curve pricing, and $SNAP NFT minting.

## Overview

citrate-bridge implements Paper VI (The Memetic Money Portal), providing a cross-chain bridge that converts ETH deposits on Ethereum Sepolia into SALT credits on the Citrate network. The bridge follows a relay architecture: an event source polls Ethereum for deposit/withdrawal events, oracles independently verify and attest to events, and once quorum is reached, the relay processes the deposit through a bonding curve to determine the SALT credit amount.

The oracle system uses M-of-N multi-oracle attestation with ed25519 signatures. Each oracle independently verifies Ethereum events and signs attestations, which include event IDs, event hashes, and timestamps (with a 5-minute freshness window). The bridge relay only processes events once the configured quorum of attestations is collected. Duplicate and inconsistent attestations are detected and rejected.

Deposits flow through a bonding curve that prices SALT relative to cumulative ETH deposits: `price = base_multiplier + (slope * total_deposited / scale_factor)`, capped at a configurable maximum. Per-transaction limits (0.02--10 ETH) and a 2000 ETH hard cap are enforced. Each deposit generates a `MintReceipt` with associated `$SNAP NFT` metadata.

## Modules

| Module | File | Purpose |
|--------|------|---------|
| `lib` | `lib.rs` | Crate root with module doc and re-exports |
| `config` | `config.rs` | `BridgeConfig` -- Ethereum RPC, contract address, confirmation depth, oracle quorum, retry policy, bonding curve parameters |
| `events` | `events.rs` | `BridgeEvent` enum (Deposit, Withdrawal, OracleUpdate), `DepositEvent`, `WithdrawalEvent`, `EventStatus`, `TrackedEvent`, `EventId` |
| `state` | `state.rs` | `RelayState` -- persisted relay progress, event tracking with hex-serialized event IDs, health status |
| `oracle` | `oracle.rs` | `OracleRegistry` -- M-of-N oracle management, `OracleAttestation` with ed25519 signature verification, duplicate/consistency checks |
| `mint` | `mint.rs` | `SnapMinter` -- bonding curve pricing, deposit validation (min/max/cap), `MintReceipt`, `SnapNftMetadata` generation |
| `relay` | `relay.rs` | `BridgeRelay` -- main orchestrator polling for events, collecting attestations, processing deposits/withdrawals; `BridgeEventSource` trait, `MockEventSource` |
| `metrics` | `metrics.rs` | `BridgeMetrics` -- atomic counters for deposits/withdrawals processed/failed, SALT credited/burned, relay lag, active oracles |
| `errors` | `errors.rs` | `BridgeError` enum -- 15+ variants covering event, oracle, deposit, conversion, relay, signature, and timeout errors |

## Public API

### Key Structs

- **`BridgeRelay`** -- Main orchestrator. Constructed with `BridgeConfig`, `BridgeEventSource`, `OracleRegistry`, `SnapMinter`, `RelayState`, `BridgeMetrics`. Polls for events and processes them through the oracle/mint pipeline.
- **`OracleRegistry`** -- Manages oracle identities and attestations. Methods: `register_oracle`, `submit_attestation`, `has_quorum`, `get_attestations`.
- **`SnapMinter`** -- Bonding curve SALT minting. Methods: `mint` (deposit to SALT conversion), `calculate_salt_amount`.
- **`RelayState`** -- Persisted relay state with event tracking log.
- **`BridgeMetrics`** -- Prometheus-compatible atomic counters for all bridge operations.
- **`BridgeConfig`** -- Full configuration including Ethereum RPC, oracle threshold, bonding curve, retry policy.

### Key Types

- `BridgeEvent` -- Deposit | Withdrawal | OracleUpdate
- `DepositEvent` -- ETH tx hash, block number, depositor, recipient, amount (wei + ETH)
- `WithdrawalEvent` -- Citrate tx hash, burner, recipient, SALT amount
- `OracleAttestation` -- Oracle ID, event ID, event hash, ed25519 signature, timestamp
- `MintReceipt` -- Event ID, recipient, deposit amount, SALT credited, curve multiplier, NFT metadata
- `EventStatus` -- Pending, Confirmed, Processing, Completed, Failed, Rejected

### Traits

- **`BridgeEventSource`** -- `async fn fetch_events(from_block, to_block)` and `async fn current_block()`
- **`MockEventSource`** -- Test implementation with `add_event`, `set_head_block`

### Constants

- `MIN_DEPOSIT_WEI` = 0.02 ETH
- `MAX_DEPOSIT_WEI` = 10 ETH
- `HARD_CAP_WEI` = 2000 ETH

## Tests

```bash
cargo test -p citrate-bridge
```

133 tests (49 + 11 + 10 + 58 + 5 across modules), all passing.

## Dependencies

| Dependency | Purpose |
|-----------|---------|
| `ed25519-dalek` | Oracle attestation signature verification |
| `sha3` | Event ID and attestation hashing |
| `parking_lot` | Fast RwLock for relay/oracle state |
| `dashmap` | Lock-free concurrent maps |
| `primitive-types` | H256 for Ethereum types |
| `chrono` | Timestamp handling |
| `proptest` (dev) | Property-based testing |
