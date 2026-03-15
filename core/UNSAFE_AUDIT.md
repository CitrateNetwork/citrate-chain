# Unsafe Block Audit — Execution Crate

**Date**: 2026-03-14
**Scope**: `core/execution/src/`
**Total unsafe blocks**: 25

## Summary

| Category | Count | Risk | Notes |
|----------|-------|------|-------|
| Enum transmute | 4 | Medium | evm_opcodes.rs — contiguous discriminant ranges |
| FFI (CoreML) | 21 | Low | coreml_bridge.rs — feature-gated `coreml`, macOS only |

All unsafe code is confined to the `citrate-execution` crate. The consensus, sequencer,
storage, network, api, economics, mcp, marketplace, and primitives crates contain zero
unsafe blocks.

All 25 unsafe blocks now have inline `// SAFETY:` comments documenting the invariants
relied upon.

---

## Inventory

### evm_opcodes.rs (4 blocks)

**File**: `core/execution/src/vm/evm_opcodes.rs`

| # | Line | Operation | Invariant | Can be made safe? |
|---|------|-----------|-----------|-------------------|
| 1 | ~1707 | `transmute u8 -> EVMOpcode` (PUSH1-PUSH32) | Discriminants 0x60-0x7f are contiguous; match arm restricts input range | Yes, but verbose (32 match arms) |
| 2 | ~1709 | `transmute u8 -> EVMOpcode` (DUP1-DUP16) | Discriminants 0x80-0x8f are contiguous; match arm restricts input range | Yes, but verbose (16 match arms) |
| 3 | ~1711 | `transmute u8 -> EVMOpcode` (SWAP1-SWAP16) | Discriminants 0x90-0x9f are contiguous; match arm restricts input range | Yes, but verbose (16 match arms) |
| 4 | ~1714 | `transmute u8 -> EVMOpcode` (LOG0-LOG4) | Discriminants 0xa0-0xa4 are contiguous; match arm restricts input range | Yes -- only 5 values, should replace |

**Safety Argument**: The `EVMOpcode` enum is `#[repr(u8)]` with explicit discriminants
matching EVM spec byte values. Each transmute is guarded by a match arm that restricts
the input to exactly the valid range. Sound if and only if every `u8` in the range has a
corresponding variant.

**Fragility Warning**: If a variant is removed or its discriminant changed without
updating this match, undefined behavior results. No compile-time check covers this.

### coreml_bridge.rs (21 blocks)

**File**: `core/execution/src/inference/coreml_bridge.rs`

| # | Line | Operation | Invariant | Risk |
|---|------|-----------|-----------|------|
| 1 | 124 | `MLModelLoad()` | `c_path` is valid CString; `error` is valid out-pointer; null return checked | Low |
| 2 | 132 | `NSErrorRelease()` (load error) | `error` checked non-null before release | Low |
| 3 | 160 | `MLModelCompileModelAtURL()` | `c_path` is valid CString; `error` is valid out-pointer; null return checked | Low |
| 4 | 168 | `NSErrorRelease()` (compile error) | `error` checked non-null before release | Low |
| 5 | 179 | `CStr::from_ptr()` (compiled path) | `compiled_path` checked non-null; framework guarantees null-terminated string | Low |
| 6 | 196 | `MLMultiArrayCreateWithShape()` | `input_shape` slice valid for call; `error` is valid out-pointer; null return checked | Low |
| 7 | 209 | `NSErrorRelease()` (array error) | `error` checked non-null before release | Low |
| 8 | 222 | `MLMultiArrayGetDataPointer()` + `copy_nonoverlapping` | Array non-null; data pointer null-checked; caller must match input length to shape | Medium |
| 9 | 236 | `MLFeatureProviderCreate()` | No args; null return checked | Low |
| 10 | 239 | `MLMultiArrayRelease()` (provider failure cleanup) | `input_array` non-null, not yet released | Low |
| 11 | 248 | `MLFeatureProviderSetMultiArray()` | All pointers verified non-null; CString kept alive | Low |
| 12 | 261 | `MLModelPredictFromFeatures()` | Model non-null (from construction); provider non-null; null options = defaults | Low |
| 13 | 274 | `MLFeatureProviderRelease()` + `MLMultiArrayRelease()` | Both non-null, released exactly once | Low |
| 14 | 283 | `NSErrorRelease()` (prediction error) | `pred_error` checked non-null before release | Low |
| 15 | 296 | `MLFeatureProviderGetMultiArray()` | `output_provider` non-null; CString kept alive; null return checked | Low |
| 16 | 303 | `MLFeatureProviderRelease()` (output error path) | `output_provider` non-null, released once on error path | Low |
| 17 | 310 | `MLMultiArrayGetCount()` | `output_array` verified non-null | Low |
| 18 | 317 | `MLMultiArrayGetDataPointer()` + `copy_nonoverlapping` (output) | Array non-null; pointer null-checked; output vec pre-allocated to exact count | Medium |
| 19 | 331 | `MLFeatureProviderRelease()` (final cleanup) | `output_provider` non-null, released once on success path | Low |
| 20 | 349 | `NSErrorGetLocalizedDescription()` + `CStr::from_ptr()` | `error` verified non-null by caller guard; desc pointer null-checked | Low |
| 21 | 368 | `MLModelRelease()` (Drop impl) | `self.model` checked non-null; sole release point; Drop runs once | Low |

### Risk Assessment

- **Memory safety**: All FFI pointers are null-checked before dereference. The `Drop` impl
  ensures the model handle is released. Error objects are released on every failure path.
- **Thread safety**: `CoreMLModel` holds a raw `*mut c_void` (model handle) which is not
  `Send`/`Sync` by default. The struct does not derive or implement these traits, so it
  cannot be shared across threads without explicit wrapping.
- **Platform**: macOS only. The `#[link(name = "CoreML", kind = "framework")]` directive
  means this code will not compile on Linux/Windows. It is gated behind conditional
  compilation in the parent module.

---

## Recommendations

1. **Replace LOG0-LOG4 transmute with explicit match arms** (only 5 values) -- low effort, eliminates one unsafe block
2. **Consider const lookup table** for all opcode transmutes -- eliminates all 4 unsafe blocks with equivalent performance
3. **All FFI blocks are inherently unsafe** but properly guarded with null checks -- no action needed
4. **Consider RAII wrapper for CoreML pointers** to reduce manual release calls and eliminate leak risk on early returns
5. **Consider `objc2` crate** for safer Objective-C bindings in a future refactor

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
