# primitives

Shared primitive types and utilities for the Citrate workspace.

## Overview

This is a minimal crate that provides foundational primitive operations shared across the Citrate workspace. It currently contains basic arithmetic helpers and serves as a placeholder for future shared primitive types that do not belong in any specific domain crate.

The crate has no external dependencies, keeping it lightweight and suitable for use as a leaf dependency throughout the workspace.

## Modules

| Module | File | Purpose |
|--------|------|---------|
| `lib` | `src/lib.rs` | Primitive math operations (`add`) and unit tests |

## Public API

- **`add(left: u64, right: u64) -> u64`** -- Addition of two `u64` values

## Usage

```rust
use primitives::add;

let result = add(2, 2);
assert_eq!(result, 4);
```

## Tests

```bash
cargo test -p primitives
```

1 test (passing).

## Dependencies

None.
