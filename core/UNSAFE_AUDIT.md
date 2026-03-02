# Unsafe Code Audit — `core/` Workspace

**WP-Y.6 Audit Artifact** | Created: 2026-03-02

## Summary

| Category | Count | Files | Verdict |
|----------|-------|-------|---------|
| CoreML FFI | 21 blocks | `execution/src/inference/coreml_bridge.rs` | Justified (platform FFI) |
| EVM transmute | 4 blocks | `execution/src/vm/evm_opcodes.rs` | Justified with caveat |
| **Total** | **25 blocks** | **2 files** | No other unsafe in `core/` |

All unsafe code is confined to the `citrate-execution` crate. The consensus, sequencer,
storage, network, api, economics, mcp, marketplace, and primitives crates contain zero
unsafe blocks.

---

## Category 1: CoreML FFI (21 unsafe blocks)

**File**: `core/execution/src/inference/coreml_bridge.rs`

These are all FFI calls into Apple's CoreML framework via C-linkage extern functions.
The file declares `extern "C"` bindings to CoreML and Foundation frameworks and wraps
them in a safe Rust API (`CoreMLModel` struct).

| Line(s) | Purpose | Justification |
|---------|---------|---------------|
| 121-123 | `MLModelLoad()` — Load CoreML model from path | Required: C FFI call, null-checked on return |
| 127-130 | `NSErrorRelease()` — Release error on load failure | Required: Manual ObjC reference counting |
| 153-155 | `MLModelCompileModelAtURL()` — Compile .mlmodel | Required: C FFI call, null-checked on return |
| 159-162 | `NSErrorRelease()` — Release error on compile failure | Required: Manual ObjC reference counting |
| 167-171 | `CStr::from_ptr()` — Read compiled path string | Required: Converting C string to Rust; pointer validated non-null above |
| 181-188 | `MLMultiArrayCreateWithShape()` — Create input tensor | Required: C FFI call, null-checked on return |
| 192-195 | `NSErrorRelease()` — Release error on array failure | Required: Manual ObjC reference counting |
| 201-209 | `ptr::copy_nonoverlapping()` — Copy input data to tensor | Required: Bulk memory copy into FFI-allocated buffer; pointer null-checked |
| 213 | `MLFeatureProviderCreate()` — Create feature provider | Required: C FFI call, null-checked on return |
| 215 | `MLMultiArrayRelease()` — Cleanup on provider failure | Required: Manual ObjC reference counting |
| 221-227 | `MLFeatureProviderSetMultiArray()` — Set input tensor | Required: C FFI call, all pointers validated |
| 231-238 | `MLModelPredictFromFeatures()` — Run inference | Required: C FFI call, null-checked on return |
| 241-244 | `MLFeatureProviderRelease()` + `MLMultiArrayRelease()` — Cleanup input | Required: Manual ObjC reference counting |
| 248-251 | `NSErrorRelease()` — Release error on prediction failure | Required: Manual ObjC reference counting |
| 258-260 | `MLFeatureProviderGetMultiArray()` — Get output tensor | Required: C FFI call, null-checked on return |
| 263 | `MLFeatureProviderRelease()` — Cleanup on output failure | Required: Manual ObjC reference counting |
| 268 | `MLMultiArrayGetCount()` — Get output element count | Required: C FFI call |
| 271-279 | `ptr::copy_nonoverlapping()` — Copy output data from tensor | Required: Bulk memory copy from FFI buffer; pointer null-checked |
| 283-285 | `MLFeatureProviderRelease()` — Final output cleanup | Required: Manual ObjC reference counting |
| 296-304 | `NSErrorGetLocalizedDescription()` + `CStr::from_ptr()` | Required: Read error message from ObjC NSError |
| 311-314 | `MLModelRelease()` in `Drop` impl | Required: Release model handle when struct is dropped |

### Risk Assessment

- **Memory safety**: All FFI pointers are null-checked before dereference. The `Drop` impl
  ensures the model handle is released. Error objects are released on every failure path.
- **Thread safety**: `CoreMLModel` holds a raw `*mut c_void` (model handle) which is not
  `Send`/`Sync` by default. The struct does not derive or implement these traits, so it
  cannot be shared across threads without explicit wrapping.
- **Platform**: macOS only. The `#[link(name = "CoreML", kind = "framework")]` directive
  means this code will not compile on Linux/Windows. It is gated behind conditional
  compilation in the parent module.

### Elimination Candidates

None. These unsafe blocks are inherent to FFI interaction with Apple's CoreML framework.
A potential improvement would be to use the `objc2` crate for safer Objective-C bindings,
but this would be a significant refactor with no functional benefit.

---

## Category 2: EVM Opcode Transmute (4 unsafe blocks)

**File**: `core/execution/src/vm/evm_opcodes.rs`

| Line | Code | Purpose |
|------|------|---------|
| 1697 | `0x60..=0x7f => Ok(unsafe { std::mem::transmute(value) })` | PUSH1-PUSH32 opcodes |
| 1698 | `0x80..=0x8f => Ok(unsafe { std::mem::transmute(value) })` | DUP1-DUP16 opcodes |
| 1699 | `0x90..=0x9f => Ok(unsafe { std::mem::transmute(value) })` | SWAP1-SWAP16 opcodes |
| 1700 | `0xa0..=0xa4 => Ok(unsafe { std::mem::transmute(value) })` | LOG0-LOG4 opcodes |

### Context

The `EVMOpcode` enum is annotated `#[repr(u8)]` and each variant has an explicit
discriminant matching the EVM specification byte value. The `TryFrom<u8>` implementation
uses `std::mem::transmute` for contiguous opcode ranges (PUSH, DUP, SWAP, LOG) instead
of matching each variant individually.

### Safety Argument

The transmute is sound **if and only if** every `u8` value in the matched range has a
corresponding enum variant with that exact discriminant. This is currently true:

- `0x60..=0x7f` maps to `PUSH1 = 0x60` through `PUSH32 = 0x7f` (32 variants)
- `0x80..=0x8f` maps to `DUP1 = 0x80` through `DUP16 = 0x8f` (16 variants)
- `0x90..=0x9f` maps to `SWAP1 = 0x90` through `SWAP16 = 0x9f` (16 variants)
- `0xa0..=0xa4` maps to `LOG0 = 0xa0` through `LOG4 = 0xa4` (5 variants)

### Risk Assessment

- **Correctness**: Sound today. The ranges are guarded by match arms, so only values
  within the defined range reach the transmute.
- **Fragility**: If a variant is ever removed from the enum or its discriminant changed
  without updating this match, undefined behavior would result. There is no compile-time
  check that the enum variants cover the full range.
- **Performance**: The transmute avoids 69 individual match arms, which is a meaningful
  optimization for hot-path opcode dispatch.

### Elimination Candidate: YES (low priority)

These could be replaced with a macro-generated match or a `const` lookup table:

```rust
// Safe alternative using a const array
const OPCODES: [Option<EVMOpcode>; 256] = { /* ... */ };

fn try_from(value: u8) -> Result<EVMOpcode, ()> {
    OPCODES[value as usize].ok_or(())
}
```

This would eliminate all four unsafe blocks with equivalent performance (the lookup table
would be a single array index). Recommended for a future cleanup sprint but not
blocking for audit.

---

## Stale Artifacts

The following directories at the repository root are safe to remove but are being retained
until after the audit completes:

| Path | Size | Description |
|------|------|-------------|
| `citrate/citrate/` | ~23 GB | Old workspace copy from before repo reorganization. Contains stale `target/`, `node_modules/`, and source duplicates. Not referenced by any build or CI configuration. |
| `citrate/.git-corrupted/` | 4 KB | Residual directory from a previous git corruption recovery. Contains no useful data. |

### Recommendation

After the audit concludes:

```bash
# Remove old workspace (recovers ~23 GB)
rm -rf citrate/citrate/

# Remove corrupted git artifacts
rm -rf citrate/.git-corrupted/
```

These directories are not tracked by git (listed in `.gitignore` or untracked) and their
removal has no effect on the build or test suite.
