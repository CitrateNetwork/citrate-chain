# Consensus Layer Safety Audit: `.unwrap()` Refactoring

**Date**: 2026-03-02
**Scope**: `citrate_v0.01.1/core/consensus/src/`
**Sprint**: Y (WP-Y.5)

## Summary

| Metric | Count |
|--------|-------|
| Total `.unwrap()` before refactoring (non-test) | **16** |
| Replaced with `map_err()?` | **8** |
| Replaced with `.expect("reason")` | **8** |
| Remaining `.unwrap()` in non-test code | **0** |
| Test-only `.unwrap()` (acceptable, untouched) | ~130 |
| All tests passing after changes | **71/71** |

## Changes by File

### `dag_store.rs` — 6 unwraps replaced

**Location**: `load_from_persistent()` (lines 195-200)

**Before**:
```rust
*self.blocks.try_write().unwrap() = blocks;
*self.blocks_by_height.try_write().unwrap() = blocks_by_height;
*self.children.try_write().unwrap() = children;
*self.tips.try_write().unwrap() = tips;
*self.finalized.try_write().unwrap() = finalized;
*self.pruning_point.try_write().unwrap() = pruning_point;
```

**After**: Each replaced with `.map_err(|_| DagStoreError::StorageError(...))?`

**Rationale**: These `tokio::sync::RwLock::try_write()` calls are made during construction before the `DagStore` is shared across threads. In practice they should never fail, but `try_write()` returns `Err` if the lock is already held. Converting to `Result` propagation ensures that if this invariant is ever violated (e.g., future refactoring introduces concurrent access during construction), the error is surfaced cleanly instead of crashing the node.

**Risk assessment**: Low. Function already returns `Result<(), DagStoreError>`.

### `ecvrf.rs` — 7 unwraps replaced

**Location**: `nonce_generation()` (RFC 6979 HMAC-DRBG)

**Before**: `HmacSha256::new_from_slice(&k).unwrap()` (7 occurrences)

**After**: `HmacSha256::new_from_slice(&k).expect(HMAC_INFALLIBLE)` with constant:
```rust
const HMAC_INFALLIBLE: &str = "HMAC-SHA256 accepts any key length; 32-byte key is always valid";
```

**Rationale**: `Hmac::new_from_slice()` can only fail if the HMAC implementation rejects the key length. HMAC-SHA256 (per RFC 2104) accepts any key length, and the key is always exactly 32 bytes (SHA-256 output). This is mathematically infallible. Using `.expect()` with a documented reason is appropriate here because:
1. The failure mode is impossible by specification
2. Returning `Result` would propagate through `prove()` and all callers for a condition that cannot occur
3. The `expect` message documents exactly why this is safe

### `checkpoint.rs` — 3 unwraps replaced

**Location 1**: `CommitteeSelector::select()` (line 173)

**Before**: `hash[0..8].try_into().unwrap()`

**After**: `hash[0..8].try_into().expect("SHA-256 output is 32 bytes; first 8 always valid")`

**Rationale**: SHA-256 always produces 32 bytes. Slicing `[0..8]` from a 32-byte array always yields exactly 8 bytes, and `try_into::<[u8; 8]>()` on an 8-byte slice is infallible. The `expect()` documents this invariant.

**Location 2**: `CheckpointManager::with_persistence()` (lines 258, 262)

**Before**:
```rust
let mut latest = mgr.latest_finalized_height.try_write().unwrap();
mgr.finalized.try_write().unwrap().insert(cp.height, cp);
```

**After**: Wrapped in `if let Ok(...)` with `warn!()` logging on failure.

**Rationale**: These `tokio::sync::RwLock::try_write()` calls occur during construction before the `CheckpointManager` is shared. They should never fail, but graceful degradation (skip loading that checkpoint + log a warning) is safer than panicking the node during startup. A missing checkpoint at startup is recoverable; a crash is not.

## Remaining `.expect()` Calls (Non-Test)

| File | Line | Expression | Justification |
|------|------|------------|---------------|
| `ecvrf.rs` | 193 | `HmacSha256::new_from_slice(&k).expect(...)` | HMAC-SHA256 accepts any key length |
| `ecvrf.rs` | 201 | same | same |
| `ecvrf.rs` | 206 | same | same |
| `ecvrf.rs` | 214 | same | same |
| `ecvrf.rs` | 220 | same | same |
| `ecvrf.rs` | 233 | same | same |
| `ecvrf.rs` | 238 | same | same |
| `checkpoint.rs` | 174 | `hash[0..8].try_into().expect(...)` | Fixed-size slice from 32-byte SHA-256 |

All `.expect()` calls are on operations that are infallible by mathematical or specification guarantee, with documented reasons explaining why.

## Test-Only `.unwrap()` (Acceptable)

Approximately 130 `.unwrap()` calls remain in `#[cfg(test)] mod tests` blocks across all files. These are standard Rust test idiom where panicking on failure is the desired behavior to surface test failures immediately. No changes were made to test code.

## Files with Zero Non-Test Unwraps (No Changes Needed)

- `lib.rs` - Module declarations only, no logic
- `ghostdag.rs` - All unwraps are in test code
- `vrf.rs` - All unwraps are in test code
- `ordering.rs` - All unwraps are in test code
- `finality.rs` - All unwraps are in test code
- `chain_selection.rs` - All unwraps are in test code
- `tip_selection.rs` - All unwraps are in test code
- `crypto.rs` - All unwraps are in test code
- `types.rs` - All unwraps are in test code

## Verification

```
$ cargo test -p citrate-consensus --lib
running 71 tests
...
test result: ok. 71 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```
