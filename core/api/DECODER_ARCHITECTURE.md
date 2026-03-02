# Transaction Decoder Architecture

**WP-Y.6 Audit Artifact** | Created: 2026-03-02

## Overview

The `citrate-api` crate contains five transaction decoder files that evolved over multiple
sprints. This document maps the decoder stack, identifies the production codepath, and marks
deprecated modules that remain in-tree for backward compatibility (post-audit decision: no
deletions until audit is complete).

## File Inventory

| File | Lines | Status | Role |
|------|-------|--------|------|
| `eth_tx_decoder.rs` | 679 | **PRIMARY (production)** | Original decoder; called directly by `eth_rpc.rs` and `server.rs` |
| `eip1559_decoder.rs` | 559 | DEPRECATED (library) | Standalone EIP-1559 decoder; consumed only by `enhanced_tx_decoder` |
| `enhanced_tx_decoder.rs` | 761 | DEPRECATED (library) | Multi-type wrapper around `eip1559_decoder`; consumed by `unified_tx_decoder` |
| `unified_tx_decoder.rs` | 265 | DEPRECATED (facade) | Facade over `enhanced_tx_decoder` with fallback to `eth_tx_decoder`; not used in production RPC |
| `decoder_integration_test.rs` | 197 | DEPRECATED (test-only) | Integration tests exercising `unified_tx_decoder`; `#[cfg(test)]` gated |

## Production Codepath

Both RPC entry points call `eth_tx_decoder::decode_eth_transaction()` directly:

```
eth_rpc.rs:708    -> eth_tx_decoder::decode_eth_transaction(&tx_bytes)
server.rs:908     -> eth_tx_decoder::decode_eth_transaction(&tx_bytes)
```

The unified/enhanced/eip1559 decoder chain is **not invoked** on any production RPC path.
It was built as a future replacement but never wired into `eth_sendRawTransaction`.

### Call Graph

```
Production (active):
  eth_rpc.rs  ──> eth_tx_decoder::decode_eth_transaction()
  server.rs   ──> eth_tx_decoder::decode_eth_transaction()

Unused chain (deprecated):
  unified_tx_decoder.rs
    └── enhanced_tx_decoder.rs
          └── eip1559_decoder.rs
    └── (fallback) eth_tx_decoder.rs
```

## `eth_tx_decoder.rs` — Primary Decoder

Handles all transaction types in a single `decode_eth_transaction()` function:

1. **Type detection**: Inspects first byte for `0x01` (EIP-2930) or `0x02` (EIP-1559)
2. **RLP decoding**: Attempts RLP decode first (critical: RLP before bincode, since RLP
   bytes can pass `bincode::deserialize`)
3. **Signature recovery**: ECDSA `secp256k1` with `RecoverableSignature`
4. **Legacy chain ID extraction**: EIP-155 `v = chain_id * 2 + 35`
5. **Bincode fallback**: If RLP fails, attempts `bincode::deserialize` for native Citrate
   transactions
6. **Address mapping**: Recovered `secp256k1` public key -> Keccak256 -> 20-byte EVM address
   -> padded to 32-byte `PublicKey` field

## Deprecated Decoder Chain

### `eip1559_decoder.rs`

Standalone EIP-1559 decoder with:
- `Eip1559Decoder` struct with configurable chain IDs and fee caps
- `TransactionStats` tracking for decode success/failure counts
- `ValidationResult` with warnings and gas estimation
- Only consumed by `enhanced_tx_decoder.rs`

### `enhanced_tx_decoder.rs`

Multi-type wrapper providing:
- `EnhancedTransactionDecoder` that delegates to `Eip1559Decoder`
- `DecoderConfig` with per-type enable flags
- `DecodedTransaction` with metadata (tx_type, chain_id, sender, effective_gas_price)
- `TransactionDecoderError` enum
- Only consumed by `unified_tx_decoder.rs`

### `unified_tx_decoder.rs`

Top-level facade providing:
- `UnifiedTransactionDecoder` — tries enhanced decoder, falls back to `eth_tx_decoder`
- `GlobalTransactionDecoder` — `Arc`-wrapped singleton pattern
- `DecoderFactory` — production/development/testing presets
- `TransactionValidationResult` for quick pre-decode checks
- **Not wired into any production RPC handler**

### `decoder_integration_test.rs`

Test module (`#[cfg(test)]`) exercising the unified decoder chain. Tests mock EIP-1559
transactions, invalid data fallback, and the global decoder singleton.

## Deprecation Status

All four non-primary files have been marked with deprecation comments at the top of each
file (added as part of WP-Y.6). The comments reference this document.

Files marked:
- `eip1559_decoder.rs` — `// DEPRECATED: See core/api/DECODER_ARCHITECTURE.md`
- `enhanced_tx_decoder.rs` — `// DEPRECATED: See core/api/DECODER_ARCHITECTURE.md`
- `unified_tx_decoder.rs` — `// DEPRECATED: See core/api/DECODER_ARCHITECTURE.md`
- `decoder_integration_test.rs` — `// DEPRECATED: See core/api/DECODER_ARCHITECTURE.md`

## Post-Audit Recommendation

After the security audit concludes, the deprecated files can be safely removed:

1. Delete `eip1559_decoder.rs`, `enhanced_tx_decoder.rs`, `unified_tx_decoder.rs`,
   `decoder_integration_test.rs`
2. Remove corresponding `pub mod` declarations and `pub use` re-exports from `lib.rs`
3. This would reduce the decoder surface from 2,461 lines to 679 lines (72% reduction)

Alternatively, if the unified decoder chain is needed for future EIP-4844 blob transaction
support, it should be wired into the production RPC handlers to replace direct
`eth_tx_decoder` calls.
