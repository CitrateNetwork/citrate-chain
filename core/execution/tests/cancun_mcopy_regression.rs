//! DPF-VM-1 WP-7 — regression tests for the CANCUN spec bump.
//!
//! Sprint context: DPF-VM-1 (2026-05-12). Before this fix, the
//! Citrate VM was configured with `SpecId::SHANGHAI`. Solidity
//! 0.8.25+ defaults to `evmVersion = cancun` and emits the
//! **MCOPY** opcode (EIP-5656, introduced in Cancun) for memory-
//! to-memory copies during ABI return encoding of dynamic byte
//! arrays. SHANGHAI doesn't include MCOPY; REVM halts with
//! `InvalidOpcode`. The executor's error path silently swallowed
//! the halt as `Ok(receipt{ status: false, output: vec![] })` and
//! `eth_call` hex-encoded the empty bytes to `"0x"` — every DPF
//! view function returning a struct with a `string` field looked
//! like it was returning nothing.
//!
//! These tests guard against any future REVM downgrade that would
//! re-introduce the bug. They exercise the opcode directly (not
//! via Solidity compilation, so they don't depend on a toolchain
//! version) by hand-crafting minimal EVM bytecode that uses MCOPY.
//!
//! Diagnosis + planset:
//! - `.agentile/sprints/active/2026-05-12-dpf-vm-1-dynamic-returns/SPRINT.md`
//! - `.agentile/planset/2026-05-12-cancun-vm-bump/00_PLANSET.md`

use citrate_execution::revm_adapter::execute_contract_call;
use citrate_execution::state::StateDB;
use citrate_execution::types::Address;
use primitive_types::U256;
use std::sync::Arc;

fn caller() -> Address {
    Address([1u8; 20])
}

fn contract() -> Address {
    Address([2u8; 20])
}

fn fund_caller(db: &Arc<StateDB>) {
    db.accounts.set_balance(
        caller(),
        U256::from(10u64).pow(U256::from(18u64)), // 1 ETH-equivalent
    );
}

/// Run the given runtime bytecode at the test contract address and
/// return REVM's `(output, gas_used)` result.
fn call(runtime_code: Vec<u8>) -> Result<(Vec<u8>, u64), citrate_execution::types::ExecutionError> {
    let db = Arc::new(StateDB::new());
    fund_caller(&db);
    db.set_code(contract(), runtime_code);
    execute_contract_call(
        db,
        caller(),
        contract(),
        Vec::new(),
        U256::zero(),
        1_000_000,
        U256::from(1_000_000_000u64),
        40204,
        1,
        1_000_000,
    )
}

// ──────────────────────────────────────────────────────────────────
// 1. MCOPY executes under CANCUN (was: halts under SHANGHAI)
// ──────────────────────────────────────────────────────────────────

/// Minimal MCOPY exercise: write `0x41` ('A') at memory[0], MCOPY
/// 1 byte from offset 0 to offset 64, return 32 bytes from offset 64.
///
/// Under `SpecId::SHANGHAI`, opcode `0x5e` (MCOPY) is unrecognized
/// and REVM halts with `InstructionResult::OpcodeNotFound`. With
/// `SpecId::CANCUN` the opcode executes and the call returns the
/// 32-byte chunk where the first byte is `0x41` and the rest are 0.
#[test]
fn mcopy_executes_under_cancun() {
    #[rustfmt::skip]
    let bytecode = vec![
        // mem[0] = 0x41
        0x60, 0x41,       // PUSH1 0x41
        0x60, 0x00,       // PUSH1 0x00
        0x53,             // MSTORE8

        // MCOPY(dest=64, src=0, length=1)  →  mem[64] = mem[0] = 0x41
        0x60, 0x01,       // PUSH1 0x01  (length)
        0x60, 0x00,       // PUSH1 0x00  (src)
        0x60, 0x40,       // PUSH1 0x40  (dest = 64)
        0x5e,             // MCOPY        ← Cancun-only opcode

        // RETURN(offset=64, length=32)
        0x60, 0x20,       // PUSH1 0x20
        0x60, 0x40,       // PUSH1 0x40
        0xf3,             // RETURN
    ];

    let (output, gas_used) = call(bytecode).expect(
        "MCOPY-using contract must execute under SpecId::CANCUN. \
         If this assertion fires after a future REVM/spec change, \
         double-check that core/execution/src/revm_adapter.rs:386 + :519 \
         haven't been downgraded from CANCUN.",
    );

    assert_eq!(output.len(), 32, "RETURN(offset=64, length=32) → 32 bytes");
    assert_eq!(
        output[0], 0x41,
        "MCOPY should have copied 0x41 from mem[0] to mem[64]"
    );
    // The remaining 31 bytes are uninitialised memory, which the EVM
    // guarantees to be zero.
    assert!(
        output[1..].iter().all(|&b| b == 0),
        "uninitialised memory must read as zero per EVM spec"
    );
    assert!(gas_used > 21_000, "real execution must consume more than the base tx cost");
}

/// MCOPY zero-length is a no-op (per EIP-5656). Verifies the opcode
/// handles edge cases — protects against a partial MCOPY impl.
#[test]
fn mcopy_zero_length_is_noop_under_cancun() {
    #[rustfmt::skip]
    let bytecode = vec![
        // MCOPY(dest=64, src=0, length=0)  →  no-op
        0x60, 0x00,       // PUSH1 0x00  (length=0)
        0x60, 0x00,       // PUSH1 0x00  (src)
        0x60, 0x40,       // PUSH1 0x40  (dest)
        0x5e,             // MCOPY

        // Return a single byte 0x00 to prove execution reached the end
        0x60, 0x01,       // PUSH1 0x01
        0x60, 0x00,       // PUSH1 0x00
        0xf3,             // RETURN
    ];

    let (output, _gas_used) = call(bytecode).expect("zero-length MCOPY must not halt");
    assert_eq!(output.len(), 1);
    assert_eq!(output[0], 0x00, "uninitialised memory reads as zero");
}

// ──────────────────────────────────────────────────────────────────
// 2. Dynamic-bytes return round-trips through REVM
// ──────────────────────────────────────────────────────────────────

/// Hand-build the exact byte sequence Solidity emits for
/// `function getString() returns (string memory) { return "abc"; }`:
///
///   [0x00..0x20]  offset to data = 0x20 (32)
///   [0x20..0x40]  length = 0x03 (3)
///   [0x40..0x60]  "abc" left-aligned and zero-padded
///
/// Total: 96 bytes. The function uses MCOPY to copy the literal
/// string into the return buffer; this test reproduces the same
/// shape directly so the REVM dynamic-return path is exercised
/// even without a Solidity toolchain.
#[test]
fn dynamic_string_return_via_mcopy() {
    // Layout: write the three return chunks into memory[0..96] using
    // MSTOREs + MCOPY for the string body, then RETURN(0, 96).
    #[rustfmt::skip]
    let bytecode = vec![
        // chunk 0: mem[0..32] = 0x20 (offset)
        0x60, 0x20,       // PUSH1 0x20
        0x60, 0x00,       // PUSH1 0x00
        0x52,             // MSTORE

        // chunk 1: mem[32..64] = 0x03 (length)
        0x60, 0x03,       // PUSH1 0x03
        0x60, 0x20,       // PUSH1 0x20
        0x52,             // MSTORE

        // Now stage "abc" left-aligned at mem[64..96]. We store the
        // three bytes individually via MSTORE8 then use MCOPY as a
        // no-op self-copy to prove the opcode is functional in the
        // same call frame as the dynamic return shape.
        0x60, 0x61,       // PUSH1 'a'
        0x60, 0x40,       // PUSH1 0x40
        0x53,             // MSTORE8         mem[64] = 0x61
        0x60, 0x62,       // PUSH1 'b'
        0x60, 0x41,       // PUSH1 0x41
        0x53,             // MSTORE8         mem[65] = 0x62
        0x60, 0x63,       // PUSH1 'c'
        0x60, 0x42,       // PUSH1 0x42
        0x53,             // MSTORE8         mem[66] = 0x63

        // MCOPY(dest=64, src=64, length=32) — self-copy is a no-op
        // but proves the opcode executes alongside the dynamic-
        // return shape.
        0x60, 0x20,       // PUSH1 0x20
        0x60, 0x40,       // PUSH1 0x40
        0x60, 0x40,       // PUSH1 0x40
        0x5e,             // MCOPY

        // RETURN(offset=0, length=96)
        0x60, 0x60,       // PUSH1 0x60
        0x60, 0x00,       // PUSH1 0x00
        0xf3,             // RETURN
    ];

    let (output, gas_used) =
        call(bytecode).expect("dynamic-string return shape must round-trip under CANCUN");

    assert_eq!(
        output.len(),
        96,
        "expected 96-byte ABI-encoded `string` return (3 × 32-byte chunks)"
    );

    // Decode chunk 0: offset-to-data = 0x20 (32)
    let offset = U256::from_big_endian(&output[0..32]);
    assert_eq!(offset, U256::from(32u64), "ABI offset chunk must be 0x20");

    // Decode chunk 1: length = 3
    let length = U256::from_big_endian(&output[32..64]);
    assert_eq!(length, U256::from(3u64), "ABI length chunk must be 3");

    // Decode chunk 2: bytes 0..3 = "abc", rest padding
    assert_eq!(&output[64..67], b"abc", "first 3 bytes of data chunk must be 'abc'");
    assert!(
        output[67..96].iter().all(|&b| b == 0),
        "remaining 29 bytes of data chunk must be zero-padded"
    );
    assert!(gas_used > 21_000);
}

// ──────────────────────────────────────────────────────────────────
// 3. Pure-scalar return continues to work (control)
// ──────────────────────────────────────────────────────────────────

/// Control case: scalar `uint256` return must still work after the
/// spec bump. This was never broken; we include it so a future
/// regression that broke scalar returns under CANCUN would surface
/// alongside the MCOPY tests.
#[test]
fn scalar_uint_return_still_works_under_cancun() {
    #[rustfmt::skip]
    let bytecode = vec![
        // mem[0..32] = 0x42
        0x60, 0x42,       // PUSH1 0x42
        0x60, 0x00,       // PUSH1 0x00
        0x52,             // MSTORE

        // RETURN(offset=0, length=32)
        0x60, 0x20,       // PUSH1 0x20
        0x60, 0x00,       // PUSH1 0x00
        0xf3,             // RETURN
    ];

    let (output, _gas_used) = call(bytecode).expect("scalar uint return must still work");
    assert_eq!(output.len(), 32);
    assert_eq!(
        U256::from_big_endian(&output),
        U256::from(0x42u64),
        "scalar uint return value must be 0x42"
    );
}
