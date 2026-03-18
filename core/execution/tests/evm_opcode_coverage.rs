// Tests for EVM opcode coverage: vm/evm_opcodes.rs and vm/mod.rs

use citrate_execution::types::ExecutionError;
use citrate_execution::vm::evm_opcodes::{EVMContext, EVMExecutor, EVMOpcode, EVMState};
use primitive_types::U256;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Helper: create a default EVMContext suitable for tests
// ---------------------------------------------------------------------------
fn test_context() -> EVMContext {
    test_context_with_code(vec![])
}

fn test_context_with_code(code: Vec<u8>) -> EVMContext {
    EVMContext {
        block_number: 100,
        block_timestamp: 1700000000,
        block_hash: [0xAB; 32],
        coinbase: [0x42; 20],
        prevrandao: U256::from(12345),
        gas_limit: 30_000_000,
        chain_id: 1337,
        base_fee: U256::from(1_000_000_000u64),
        blob_base_fee: U256::zero(),
        origin: [0x01; 20],
        caller: [0x02; 20],
        call_value: U256::from(1000),
        gas_price: U256::from(20_000_000_000u64),
        calldata: vec![],
        address: [0x03; 20],
        code,
        get_balance: Box::new(|_addr| U256::from(1_000_000)),
        get_code_size: Box::new(|_addr| 0),
        get_code_hash: Box::new(|_addr| [0u8; 32]),
        get_code: Box::new(|_addr| vec![]),
    }
}

const GAS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// 1. test_stop_opcode — STOP halts execution
// ---------------------------------------------------------------------------
#[test]
fn test_stop_opcode() {
    let mut executor = EVMExecutor::new();
    let mut state = EVMState::new(GAS);
    let context = test_context();

    let result = executor.execute_opcode(0x00, &mut state, &context);
    assert!(result.is_ok());
    assert!(state.stopped, "STOP should set stopped=true");
}

// ---------------------------------------------------------------------------
// 2. test_invalid_opcode_0xfe — INVALID reverts
// ---------------------------------------------------------------------------
#[test]
fn test_invalid_opcode_0xfe() {
    let mut executor = EVMExecutor::new();
    let mut state = EVMState::new(GAS);
    let context = test_context();

    let result = executor.execute_opcode(0xFE, &mut state, &context);
    assert!(result.is_err());
    match result.unwrap_err() {
        ExecutionError::InvalidOpcode(op) => assert_eq!(op, 0xFE),
        other => panic!("expected InvalidOpcode, got: {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 3. test_push_pop_stack_operations
// ---------------------------------------------------------------------------
#[test]
fn test_push_pop_stack_operations() {
    let mut executor = EVMExecutor::new();
    let mut state = EVMState::new(GAS);
    // Code: PUSH1 0x42
    let code = vec![0x60, 0x42, 0x00]; // PUSH1 0x42, STOP
    let context = test_context_with_code(code.clone());

    // Execute PUSH1 (opcode 0x60)
    let result = executor.execute_opcode(0x60, &mut state, &context);
    assert!(result.is_ok());
    assert_eq!(state.stack.len(), 1);
    assert_eq!(state.stack[0], U256::from(0x42));

    // PUSH0 (EIP-3855)
    let result = executor.execute_opcode(0x5F, &mut state, &context);
    assert!(result.is_ok());
    assert_eq!(state.stack.len(), 2);
    assert_eq!(state.stack[1], U256::zero());

    // POP
    let result = executor.execute_opcode(0x50, &mut state, &context);
    assert!(result.is_ok());
    assert_eq!(state.stack.len(), 1);
}

// ---------------------------------------------------------------------------
// 4. test_dup_swap_operations
// ---------------------------------------------------------------------------
#[test]
fn test_dup_swap_operations() {
    let mut executor = EVMExecutor::new();
    let mut state = EVMState::new(GAS);
    let context = test_context();

    // Push two values
    state.stack_push(U256::from(10)).unwrap();
    state.stack_push(U256::from(20)).unwrap();

    // DUP1 (0x80) — duplicate top
    executor.execute_opcode(0x80, &mut state, &context).unwrap();
    assert_eq!(state.stack.len(), 3);
    assert_eq!(state.stack[2], U256::from(20));

    // DUP2 (0x81) — duplicate second from top
    executor.execute_opcode(0x81, &mut state, &context).unwrap();
    assert_eq!(state.stack.len(), 4);
    assert_eq!(state.stack[3], U256::from(20)); // second from previous top

    // Reset stack for SWAP test
    state.stack.clear();
    state.stack_push(U256::from(100)).unwrap();
    state.stack_push(U256::from(200)).unwrap();

    // SWAP1 (0x90) — swap top two
    executor.execute_opcode(0x90, &mut state, &context).unwrap();
    assert_eq!(state.stack[0], U256::from(200));
    assert_eq!(state.stack[1], U256::from(100));
}

// ---------------------------------------------------------------------------
// 5. test_memory_operations — MLOAD, MSTORE, MSTORE8, MSIZE
// ---------------------------------------------------------------------------
#[test]
fn test_memory_operations() {
    let mut executor = EVMExecutor::new();
    let mut state = EVMState::new(GAS);
    let context = test_context();

    // MSTORE: store value at offset 0
    state.stack_push(U256::from(0xDEADBEEFu64)).unwrap(); // value
    state.stack_push(U256::from(0)).unwrap();               // offset
    executor.execute_opcode(0x52, &mut state, &context).unwrap();
    assert!(state.memory.len() >= 32);

    // MLOAD: load from offset 0
    state.stack_push(U256::from(0)).unwrap(); // offset
    executor.execute_opcode(0x51, &mut state, &context).unwrap();
    let loaded = state.stack_pop().unwrap();
    assert_eq!(loaded, U256::from(0xDEADBEEFu64));

    // MSTORE8: store single byte at offset 64
    state.stack_push(U256::from(0xABu64)).unwrap(); // value (only low byte used)
    state.stack_push(U256::from(64)).unwrap();        // offset
    executor.execute_opcode(0x53, &mut state, &context).unwrap();
    assert_eq!(state.memory[64], 0xAB);

    // MSIZE: memory size
    executor.execute_opcode(0x59, &mut state, &context).unwrap();
    let msize = state.stack_pop().unwrap();
    assert!(msize >= U256::from(65));
}

// ---------------------------------------------------------------------------
// 6. test_stack_underflow — POP on empty stack
// ---------------------------------------------------------------------------
#[test]
fn test_stack_underflow() {
    let mut executor = EVMExecutor::new();
    let mut state = EVMState::new(GAS);
    let context = test_context();

    // POP with empty stack
    let result = executor.execute_opcode(0x50, &mut state, &context);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ExecutionError::StackUnderflow));
}

// ---------------------------------------------------------------------------
// 7. test_stack_overflow — Push 1025 items
// ---------------------------------------------------------------------------
#[test]
fn test_stack_overflow() {
    let mut state = EVMState::new(GAS);

    // Fill to max (1024)
    for i in 0..1024 {
        state.stack_push(U256::from(i)).unwrap();
    }
    // The 1025th push should overflow
    let result = state.stack_push(U256::from(9999));
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ExecutionError::StackOverflow));
}

// ---------------------------------------------------------------------------
// 8. test_arithmetic_overflow — ADD with MAX values
// ---------------------------------------------------------------------------
#[test]
fn test_arithmetic_overflow() {
    let mut executor = EVMExecutor::new();
    let mut state = EVMState::new(GAS);
    let context = test_context();

    state.stack_push(U256::MAX).unwrap();
    state.stack_push(U256::from(1)).unwrap();

    // ADD wraps around (EVM spec)
    executor.execute_opcode(0x01, &mut state, &context).unwrap();
    let result = state.stack_pop().unwrap();
    assert_eq!(result, U256::zero(), "MAX + 1 should wrap to 0");
}

// ---------------------------------------------------------------------------
// 9. test_division_by_zero — DIV by 0 returns 0
// ---------------------------------------------------------------------------
#[test]
fn test_division_by_zero() {
    let mut executor = EVMExecutor::new();
    let mut state = EVMState::new(GAS);
    let context = test_context();

    state.stack_push(U256::from(0)).unwrap(); // divisor (b)
    state.stack_push(U256::from(42)).unwrap(); // dividend (a)

    executor.execute_opcode(0x04, &mut state, &context).unwrap(); // DIV
    let result = state.stack_pop().unwrap();
    assert_eq!(result, U256::zero(), "DIV by zero should return 0");

    // SDIV by zero
    state.stack_push(U256::from(0)).unwrap();
    state.stack_push(U256::from(42)).unwrap();
    executor.execute_opcode(0x05, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::zero());
}

// ---------------------------------------------------------------------------
// 10. test_modulo_by_zero — MOD by 0 returns 0
// ---------------------------------------------------------------------------
#[test]
fn test_modulo_by_zero() {
    let mut executor = EVMExecutor::new();
    let mut state = EVMState::new(GAS);
    let context = test_context();

    // MOD
    state.stack_push(U256::from(0)).unwrap(); // modulus
    state.stack_push(U256::from(42)).unwrap(); // value
    executor.execute_opcode(0x06, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::zero());

    // SMOD by zero
    state.stack_push(U256::from(0)).unwrap();
    state.stack_push(U256::from(42)).unwrap();
    executor.execute_opcode(0x07, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::zero());

    // ADDMOD with N=0
    state.stack_push(U256::from(0)).unwrap(); // n
    state.stack_push(U256::from(3)).unwrap(); // b
    state.stack_push(U256::from(5)).unwrap(); // a
    executor.execute_opcode(0x08, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::zero());

    // MULMOD with N=0
    state.stack_push(U256::from(0)).unwrap(); // n
    state.stack_push(U256::from(3)).unwrap(); // b
    state.stack_push(U256::from(5)).unwrap(); // a
    executor.execute_opcode(0x09, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::zero());
}

// ---------------------------------------------------------------------------
// 11. test_comparison_ops — LT, GT, EQ, ISZERO, SLT, SGT
// ---------------------------------------------------------------------------
#[test]
fn test_comparison_ops() {
    let mut executor = EVMExecutor::new();
    let mut state = EVMState::new(GAS);
    let context = test_context();

    // LT: 3 < 5 = 1
    state.stack_push(U256::from(5)).unwrap();
    state.stack_push(U256::from(3)).unwrap();
    executor.execute_opcode(0x10, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::one());

    // GT: 5 > 3 = 1
    state.stack_push(U256::from(3)).unwrap();
    state.stack_push(U256::from(5)).unwrap();
    executor.execute_opcode(0x11, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::one());

    // EQ: 7 == 7 = 1
    state.stack_push(U256::from(7)).unwrap();
    state.stack_push(U256::from(7)).unwrap();
    executor.execute_opcode(0x14, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::one());

    // EQ: 7 == 8 = 0
    state.stack_push(U256::from(8)).unwrap();
    state.stack_push(U256::from(7)).unwrap();
    executor.execute_opcode(0x14, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::zero());

    // ISZERO: 0 => 1
    state.stack_push(U256::zero()).unwrap();
    executor.execute_opcode(0x15, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::one());

    // ISZERO: 42 => 0
    state.stack_push(U256::from(42)).unwrap();
    executor.execute_opcode(0x15, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::zero());

    // SLT: signed comparison — negative < positive
    // U256::MAX represents -1 in two's complement
    state.stack_push(U256::from(1)).unwrap(); // b
    state.stack_push(U256::MAX).unwrap();      // a (= -1 signed)
    executor.execute_opcode(0x12, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::one(), "-1 < 1 should be true");

    // SGT: positive > negative
    state.stack_push(U256::MAX).unwrap();      // b (= -1)
    state.stack_push(U256::from(1)).unwrap(); // a
    executor.execute_opcode(0x13, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::one(), "1 > -1 should be true");
}

// ---------------------------------------------------------------------------
// 12. test_bitwise_ops — AND, OR, XOR, NOT, BYTE, SHL, SHR, SAR
// ---------------------------------------------------------------------------
#[test]
fn test_bitwise_ops() {
    let mut executor = EVMExecutor::new();
    let mut state = EVMState::new(GAS);
    let context = test_context();

    // AND: 0xFF & 0x0F = 0x0F
    state.stack_push(U256::from(0x0Fu64)).unwrap();
    state.stack_push(U256::from(0xFFu64)).unwrap();
    executor.execute_opcode(0x16, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::from(0x0F));

    // OR: 0xF0 | 0x0F = 0xFF
    state.stack_push(U256::from(0x0Fu64)).unwrap();
    state.stack_push(U256::from(0xF0u64)).unwrap();
    executor.execute_opcode(0x17, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::from(0xFF));

    // XOR: 0xFF ^ 0xFF = 0
    state.stack_push(U256::from(0xFFu64)).unwrap();
    state.stack_push(U256::from(0xFFu64)).unwrap();
    executor.execute_opcode(0x18, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::zero());

    // NOT: ~0 = MAX
    state.stack_push(U256::zero()).unwrap();
    executor.execute_opcode(0x19, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::MAX);

    // BYTE: extract byte 31 (least significant) of value 0xAB
    state.stack_push(U256::from(0xABu64)).unwrap(); // value
    state.stack_push(U256::from(31u64)).unwrap();    // index (big-endian byte 31 = LSB)
    executor.execute_opcode(0x1A, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::from(0xAB));

    // BYTE: out-of-range index returns 0
    state.stack_push(U256::from(0xABu64)).unwrap();
    state.stack_push(U256::from(32u64)).unwrap();
    executor.execute_opcode(0x1A, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::zero());

    // SHL: 1 << 8 = 256
    state.stack_push(U256::from(1u64)).unwrap();  // value
    state.stack_push(U256::from(8u64)).unwrap();  // shift
    executor.execute_opcode(0x1B, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::from(256));

    // SHL: shift >= 256 returns 0
    state.stack_push(U256::from(1u64)).unwrap();
    state.stack_push(U256::from(256u64)).unwrap();
    executor.execute_opcode(0x1B, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::zero());

    // SHR: 256 >> 8 = 1
    state.stack_push(U256::from(256u64)).unwrap(); // value
    state.stack_push(U256::from(8u64)).unwrap();   // shift
    executor.execute_opcode(0x1C, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::from(1));

    // SHR: shift >= 256 returns 0
    state.stack_push(U256::from(1u64)).unwrap();
    state.stack_push(U256::from(256u64)).unwrap();
    executor.execute_opcode(0x1C, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::zero());

    // SAR: positive value >> 4
    state.stack_push(U256::from(0x100u64)).unwrap();
    state.stack_push(U256::from(4u64)).unwrap();
    executor.execute_opcode(0x1D, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::from(0x10));

    // SAR: shift >= 256 with sign bit set returns MAX
    state.stack_push(U256::MAX).unwrap(); // negative number (sign bit set)
    state.stack_push(U256::from(256u64)).unwrap();
    executor.execute_opcode(0x1D, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::MAX);

    // SAR: shift >= 256 with sign bit clear returns 0
    state.stack_push(U256::from(42u64)).unwrap(); // positive
    state.stack_push(U256::from(256u64)).unwrap();
    executor.execute_opcode(0x1D, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::zero());
}

// ---------------------------------------------------------------------------
// 13. test_sha3_opcode — SHA3/KECCAK256 on known input
// ---------------------------------------------------------------------------
#[test]
fn test_sha3_opcode() {
    let mut executor = EVMExecutor::new();
    let mut state = EVMState::new(GAS);
    let context = test_context();

    // Write 0x00 to memory at offset 0 (already zeroed by expand)
    state.memory_expand(0, 32).unwrap();

    // SHA3(offset=0, size=0) — hash of empty input
    state.stack_push(U256::from(0u64)).unwrap(); // size
    state.stack_push(U256::from(0u64)).unwrap(); // offset
    executor.execute_opcode(0x20, &mut state, &context).unwrap();

    let hash = state.stack_pop().unwrap();
    // keccak256("") = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    let expected = U256::from_big_endian(
        &hex::decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
            .unwrap(),
    );
    assert_eq!(hash, expected, "keccak256 of empty input should match known hash");
}

// ---------------------------------------------------------------------------
// 14. test_address_balance_origin — ADDRESS, BALANCE, ORIGIN
// ---------------------------------------------------------------------------
#[test]
fn test_address_balance_origin() {
    let mut executor = EVMExecutor::new();
    let mut state = EVMState::new(GAS);
    let context = test_context();

    // ADDRESS (0x30)
    executor.execute_opcode(0x30, &mut state, &context).unwrap();
    let addr = state.stack_pop().unwrap();
    // address is [0x03; 20] placed in low 20 bytes of U256
    let mut expected_bytes = [0u8; 32];
    expected_bytes[12..].copy_from_slice(&[0x03u8; 20]);
    assert_eq!(addr, U256::from_big_endian(&expected_bytes));

    // BALANCE (0x31) — push address then call BALANCE
    state.stack_push(addr).unwrap();
    executor.execute_opcode(0x31, &mut state, &context).unwrap();
    let balance = state.stack_pop().unwrap();
    assert_eq!(balance, U256::from(1_000_000)); // from get_balance closure

    // ORIGIN (0x32)
    executor.execute_opcode(0x32, &mut state, &context).unwrap();
    let origin = state.stack_pop().unwrap();
    let mut origin_expected = [0u8; 32];
    origin_expected[12..].copy_from_slice(&[0x01u8; 20]);
    assert_eq!(origin, U256::from_big_endian(&origin_expected));
}

// ---------------------------------------------------------------------------
// 15. test_callvalue_calldataload — CALLVALUE, CALLDATALOAD, CALLDATASIZE, CALLDATACOPY
// ---------------------------------------------------------------------------
#[test]
fn test_callvalue_calldataload() {
    let mut executor = EVMExecutor::new();
    let mut state = EVMState::new(GAS);
    let mut context = test_context();
    context.calldata = vec![0xAA; 64]; // 64 bytes of calldata

    // CALLVALUE (0x34)
    executor.execute_opcode(0x34, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::from(1000));

    // CALLDATASIZE (0x36)
    executor.execute_opcode(0x36, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::from(64));

    // CALLDATALOAD (0x35) — load 32 bytes from offset 0
    state.stack_push(U256::from(0u64)).unwrap();
    executor.execute_opcode(0x35, &mut state, &context).unwrap();
    let loaded = state.stack_pop().unwrap();
    // First 32 bytes are all 0xAA
    let expected = U256::from_big_endian(&[0xAA; 32]);
    assert_eq!(loaded, expected);

    // CALLDATALOAD beyond bounds — pads with zeros
    state.stack_push(U256::from(60u64)).unwrap(); // only 4 bytes available
    executor.execute_opcode(0x35, &mut state, &context).unwrap();
    let loaded = state.stack_pop().unwrap();
    let mut expected_bytes = [0u8; 32];
    expected_bytes[..4].copy_from_slice(&[0xAA; 4]);
    assert_eq!(loaded, U256::from_big_endian(&expected_bytes));

    // CALLDATACOPY (0x37) — copy 16 bytes from offset 0 to memory offset 0
    state.stack_push(U256::from(16u64)).unwrap(); // size
    state.stack_push(U256::from(0u64)).unwrap();  // offset
    state.stack_push(U256::from(0u64)).unwrap();  // destOffset
    executor.execute_opcode(0x37, &mut state, &context).unwrap();
    assert_eq!(&state.memory[..16], &[0xAA; 16]);
}

// ---------------------------------------------------------------------------
// Extra: test_exp_opcode
// ---------------------------------------------------------------------------
#[test]
fn test_exp_opcode() {
    let mut executor = EVMExecutor::new();
    let mut state = EVMState::new(GAS);
    let context = test_context();

    // 2^10 = 1024
    state.stack_push(U256::from(10u64)).unwrap(); // exponent
    state.stack_push(U256::from(2u64)).unwrap();  // base
    executor.execute_opcode(0x0A, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::from(1024));

    // x^0 = 1
    state.stack_push(U256::from(0u64)).unwrap();
    state.stack_push(U256::from(42u64)).unwrap();
    executor.execute_opcode(0x0A, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::one());

    // 0^n = 0
    state.stack_push(U256::from(5u64)).unwrap();
    state.stack_push(U256::from(0u64)).unwrap();
    executor.execute_opcode(0x0A, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::zero());
}

// ---------------------------------------------------------------------------
// Extra: test_signextend
// ---------------------------------------------------------------------------
#[test]
fn test_signextend() {
    let mut executor = EVMExecutor::new();
    let mut state = EVMState::new(GAS);
    let context = test_context();

    // SIGNEXTEND byte 0: extend from 8 bits. 0x80 (negative in i8) -> all 1s in upper bits
    state.stack_push(U256::from(0x80u64)).unwrap();
    state.stack_push(U256::from(0u64)).unwrap(); // extend from byte 0
    executor.execute_opcode(0x0B, &mut state, &context).unwrap();
    let result = state.stack_pop().unwrap();
    // bit 7 is set, so upper 248 bits should be 1s
    assert!(result.bit(255), "sign bit should be extended");
    assert_eq!(result & U256::from(0xFF), U256::from(0x80));

    // SIGNEXTEND with i >= 32 should return value unchanged
    state.stack_push(U256::from(0x42u64)).unwrap();
    state.stack_push(U256::from(32u64)).unwrap();
    executor.execute_opcode(0x0B, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::from(0x42));
}

// ---------------------------------------------------------------------------
// Extra: test_block_info_opcodes
// ---------------------------------------------------------------------------
#[test]
fn test_block_info_opcodes() {
    let mut executor = EVMExecutor::new();
    let mut state = EVMState::new(GAS);
    let context = test_context();

    // BLOCKHASH (0x40)
    state.stack_push(U256::from(99u64)).unwrap();
    executor.execute_opcode(0x40, &mut state, &context).unwrap();
    let _ = state.stack_pop().unwrap(); // returns zero in stub

    // COINBASE (0x41)
    executor.execute_opcode(0x41, &mut state, &context).unwrap();
    let coinbase = state.stack_pop().unwrap();
    let mut expected = [0u8; 32];
    expected[12..].copy_from_slice(&[0x42u8; 20]);
    assert_eq!(coinbase, U256::from_big_endian(&expected));

    // TIMESTAMP (0x42)
    executor.execute_opcode(0x42, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::from(1700000000u64));

    // NUMBER (0x43)
    executor.execute_opcode(0x43, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::from(100));

    // PREVRANDAO (0x44)
    executor.execute_opcode(0x44, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::from(12345));

    // GASLIMIT (0x45)
    executor.execute_opcode(0x45, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::from(30_000_000u64));

    // CHAINID (0x46)
    executor.execute_opcode(0x46, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::from(1337));

    // BASEFEE (0x48)
    executor.execute_opcode(0x48, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::from(1_000_000_000u64));
}

// ---------------------------------------------------------------------------
// Extra: test_sload_sstore
// ---------------------------------------------------------------------------
#[test]
fn test_sload_sstore() {
    let mut executor = EVMExecutor::new();
    let mut state = EVMState::new(GAS);
    let context = test_context();

    // SSTORE key=1, value=42
    state.stack_push(U256::from(42u64)).unwrap(); // value
    state.stack_push(U256::from(1u64)).unwrap();  // key
    executor.execute_opcode(0x55, &mut state, &context).unwrap();

    // SLOAD key=1
    state.stack_push(U256::from(1u64)).unwrap();
    executor.execute_opcode(0x54, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::from(42));

    // SLOAD non-existent key returns 0
    state.stack_push(U256::from(999u64)).unwrap();
    executor.execute_opcode(0x54, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::zero());
}

// ---------------------------------------------------------------------------
// Extra: test_tload_tstore (EIP-1153)
// ---------------------------------------------------------------------------
#[test]
fn test_tload_tstore() {
    let mut executor = EVMExecutor::new();
    let mut state = EVMState::new(GAS);
    let context = test_context();

    // TSTORE key=5, value=99
    state.stack_push(U256::from(99u64)).unwrap();
    state.stack_push(U256::from(5u64)).unwrap();
    executor.execute_opcode(0x5D, &mut state, &context).unwrap();

    // TLOAD key=5
    state.stack_push(U256::from(5u64)).unwrap();
    executor.execute_opcode(0x5C, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::from(99));
}

// ---------------------------------------------------------------------------
// Extra: test_return_revert
// ---------------------------------------------------------------------------
#[test]
fn test_return_revert() {
    let mut executor = EVMExecutor::new();
    let mut state = EVMState::new(GAS);
    let context = test_context();

    // Write some data to memory first
    state.memory_expand(0, 4).unwrap();
    state.memory_write(0, &[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();

    // RETURN: offset=0, size=4
    state.stack_push(U256::from(4u64)).unwrap();
    state.stack_push(U256::from(0u64)).unwrap();
    executor.execute_opcode(0xF3, &mut state, &context).unwrap();
    assert!(state.stopped);
    assert!(!state.reverted);
    assert_eq!(state.return_data, vec![0xDE, 0xAD, 0xBE, 0xEF]);

    // REVERT
    let mut state2 = EVMState::new(GAS);
    state2.memory_expand(0, 2).unwrap();
    state2.memory_write(0, &[0xCA, 0xFE]).unwrap();
    state2.stack_push(U256::from(2u64)).unwrap();
    state2.stack_push(U256::from(0u64)).unwrap();
    executor.execute_opcode(0xFD, &mut state2, &context).unwrap();
    assert!(state2.stopped);
    assert!(state2.reverted);
    assert_eq!(state2.return_data, vec![0xCA, 0xFE]);
}

// ---------------------------------------------------------------------------
// Extra: test_pc_gas_jumpdest
// ---------------------------------------------------------------------------
#[test]
fn test_pc_gas_jumpdest() {
    let mut executor = EVMExecutor::new();
    let mut state = EVMState::new(GAS);
    let context = test_context();

    // PC
    state.pc = 42;
    executor.execute_opcode(0x58, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::from(42));

    // GAS
    let gas_before = state.gas_remaining;
    executor.execute_opcode(0x5A, &mut state, &context).unwrap();
    let reported_gas = state.stack_pop().unwrap();
    // gas_remaining after consuming base cost for GAS opcode
    assert!(reported_gas < U256::from(gas_before));

    // JUMPDEST (0x5B) — noop marker
    executor.execute_opcode(0x5B, &mut state, &context).unwrap();
    // Should not panic or change stack
}

// ---------------------------------------------------------------------------
// Extra: test_caller_gasprice_codesize
// ---------------------------------------------------------------------------
#[test]
fn test_caller_gasprice_codesize() {
    let mut executor = EVMExecutor::new();
    let mut state = EVMState::new(GAS);
    let code = vec![0x00, 0x01, 0x02]; // 3 bytes of code
    let context = test_context_with_code(code);

    // CALLER (0x33)
    executor.execute_opcode(0x33, &mut state, &context).unwrap();
    let caller = state.stack_pop().unwrap();
    let mut expected = [0u8; 32];
    expected[12..].copy_from_slice(&[0x02u8; 20]);
    assert_eq!(caller, U256::from_big_endian(&expected));

    // GASPRICE (0x3A)
    executor.execute_opcode(0x3A, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::from(20_000_000_000u64));

    // CODESIZE (0x38)
    executor.execute_opcode(0x38, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::from(3));
}

// ---------------------------------------------------------------------------
// Extra: test_selfbalance
// ---------------------------------------------------------------------------
#[test]
fn test_selfbalance() {
    let mut executor = EVMExecutor::new();
    let mut state = EVMState::new(GAS);
    let context = test_context();

    // SELFBALANCE (0x47)
    executor.execute_opcode(0x47, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::from(1_000_000));
}

// ---------------------------------------------------------------------------
// Extra: test_returndatasize
// ---------------------------------------------------------------------------
#[test]
fn test_returndatasize() {
    let mut executor = EVMExecutor::new();
    let mut state = EVMState::new(GAS);
    let context = test_context();

    state.return_data = vec![1, 2, 3, 4, 5];

    // RETURNDATASIZE (0x3D)
    executor.execute_opcode(0x3D, &mut state, &context).unwrap();
    assert_eq!(state.stack_pop().unwrap(), U256::from(5));
}

// ---------------------------------------------------------------------------
// Extra: test_log0
// ---------------------------------------------------------------------------
#[test]
fn test_log0() {
    let mut executor = EVMExecutor::new();
    let mut state = EVMState::new(GAS);
    let context = test_context();

    // Write data to memory
    state.memory_expand(0, 4).unwrap();
    state.memory_write(0, &[0xAA, 0xBB, 0xCC, 0xDD]).unwrap();

    // LOG0: offset=0, size=4
    state.stack_push(U256::from(4u64)).unwrap(); // size
    state.stack_push(U256::from(0u64)).unwrap(); // offset
    executor.execute_opcode(0xA0, &mut state, &context).unwrap();
    // Should succeed without panic (LOG0 has 0 topics)
}

// ---------------------------------------------------------------------------
// Extra: test_vm_execute_stop
// ---------------------------------------------------------------------------
#[test]
fn test_vm_execute_stop() {
    use citrate_execution::vm::VM;
    let mut vm = VM::new(100_000);
    let code = vec![0x00]; // STOP
    let result = vm.execute(&code);
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// Extra: test_vm_execute_with_input
// ---------------------------------------------------------------------------
#[test]
fn test_vm_execute_with_input() {
    use citrate_execution::vm::VM;
    let mut vm = VM::new(100_000);
    let code = vec![0x00]; // STOP
    let input = vec![0u8; 64]; // 64 bytes: model_id + input_id
    let result = vm.execute_with_input(&code, &input);
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// Extra: test_vm_invalid_opcode
// ---------------------------------------------------------------------------
#[test]
fn test_vm_invalid_opcode() {
    use citrate_execution::vm::VM;
    let mut vm = VM::new(100_000);
    let code = vec![0xEE]; // not a valid opcode in the simple VM dispatcher
    let result = vm.execute(&code);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Extra: test_vm_stack_and_memory
// ---------------------------------------------------------------------------
#[test]
fn test_vm_stack_memory_storage() {
    use citrate_execution::vm::{Memory, Stack, Storage};

    // Stack
    let mut stack = Stack::new();
    stack.push(U256::from(42)).unwrap();
    assert_eq!(stack.pop().unwrap(), U256::from(42));
    assert!(stack.pop().is_err()); // underflow

    let mut stack_default = Stack::default();
    assert!(matches!(stack_default.pop(), Err(ExecutionError::StackUnderflow)));

    // Memory
    let mut mem = Memory::new();
    mem.set(0, &[1, 2, 3, 4]).unwrap();
    assert_eq!(mem.get(0, 4).unwrap(), vec![1, 2, 3, 4]);
    assert_eq!(mem.get(100, 4).unwrap(), vec![0, 0, 0, 0]); // uninitialized returns zeros
    mem.set_word(0, U256::from(0xABCDu64)).unwrap();
    assert_eq!(mem.get_word(0).unwrap(), U256::from(0xABCDu64));
    let _mem_default = Memory::default();

    // Storage
    let mut storage = Storage::new();
    assert_eq!(storage.get(&U256::from(1)), U256::zero());
    storage.set(U256::from(1), U256::from(99));
    assert_eq!(storage.get(&U256::from(1)), U256::from(99));
    storage.set(U256::from(1), U256::zero()); // deletes
    assert_eq!(storage.get(&U256::from(1)), U256::zero());
    let _storage_default = Storage::default();
}

// ---------------------------------------------------------------------------
// Extra: test_evmstate_methods
// ---------------------------------------------------------------------------
#[test]
fn test_evmstate_methods() {
    let mut state = EVMState::new(1000);

    // stack_peek
    state.stack_push(U256::from(10)).unwrap();
    state.stack_push(U256::from(20)).unwrap();
    assert_eq!(state.stack_peek(0).unwrap(), U256::from(20));
    assert_eq!(state.stack_peek(1).unwrap(), U256::from(10));
    assert!(state.stack_peek(2).is_err());

    // stack_swap
    state.stack_swap(1).unwrap();
    assert_eq!(state.stack_peek(0).unwrap(), U256::from(10));
    assert_eq!(state.stack_peek(1).unwrap(), U256::from(20));

    // memory_read from empty
    assert_eq!(state.memory_read(0, 4), vec![0; 4]);

    // memory_write + read
    state.memory_expand(0, 8).unwrap();
    state.memory_write(0, &[1, 2, 3, 4]).unwrap();
    assert_eq!(state.memory_read(0, 4), vec![1, 2, 3, 4]);

    // consume_gas
    let initial = state.gas_remaining;
    state.consume_gas(100).unwrap();
    assert_eq!(state.gas_remaining, initial - 100);
    assert!(state.consume_gas(initial).is_err()); // would underflow

    // tload/tstore
    assert_eq!(state.tload(U256::from(1)), U256::zero());
    state.tstore(U256::from(1), U256::from(42));
    assert_eq!(state.tload(U256::from(1)), U256::from(42));
    state.tstore(U256::from(1), U256::zero()); // removes
    assert_eq!(state.tload(U256::from(1)), U256::zero());

    // storage_load / storage_store
    let mut accessed = HashMap::new();
    assert_eq!(state.storage_load(U256::from(5), &mut accessed), U256::zero());
    let gas = state.storage_store(U256::from(5), U256::from(100), &mut accessed);
    assert!(gas > 0); // set storage cost
    assert_eq!(state.storage_load(U256::from(5), &mut accessed), U256::from(100));

    // storage_store same value => noop cost
    let gas = state.storage_store(U256::from(5), U256::from(100), &mut accessed);
    assert_eq!(gas, 100); // noop

    // storage_store delete => 2300
    let gas = state.storage_store(U256::from(5), U256::zero(), &mut accessed);
    assert_eq!(gas, 2300);
}

// ---------------------------------------------------------------------------
// Extra: test_opcode_try_from
// ---------------------------------------------------------------------------
#[test]
fn test_opcode_try_from() {
    assert_eq!(EVMOpcode::try_from(0x00), Ok(EVMOpcode::STOP));
    assert_eq!(EVMOpcode::try_from(0x01), Ok(EVMOpcode::ADD));
    assert_eq!(EVMOpcode::try_from(0xFE), Ok(EVMOpcode::INVALID));
    assert_eq!(EVMOpcode::try_from(0xFF), Ok(EVMOpcode::SELFDESTRUCT));
    // Invalid byte (not mapped)
    assert!(EVMOpcode::try_from(0xC0).is_err());
}

// ---------------------------------------------------------------------------
// Extra: test_create_call_unsupported
// ---------------------------------------------------------------------------
#[test]
fn test_create_call_unsupported() {
    let mut executor = EVMExecutor::new();
    let context = test_context();

    // CREATE (0xF0) — requires 3 stack items, then errors
    let mut state = EVMState::new(GAS);
    state.stack_push(U256::from(0u64)).unwrap(); // size
    state.stack_push(U256::from(0u64)).unwrap(); // offset
    state.stack_push(U256::from(0u64)).unwrap(); // value
    let result = executor.execute_opcode(0xF0, &mut state, &context);
    assert!(matches!(result, Err(ExecutionError::Reverted(_))));

    // CALL (0xF1) — requires 7 stack items
    let mut state = EVMState::new(GAS);
    for _ in 0..7 {
        state.stack_push(U256::from(0u64)).unwrap();
    }
    let result = executor.execute_opcode(0xF1, &mut state, &context);
    assert!(matches!(result, Err(ExecutionError::Reverted(_))));

    // STATICCALL (0xFA) — requires 6 stack items
    let mut state = EVMState::new(GAS);
    for _ in 0..6 {
        state.stack_push(U256::from(0u64)).unwrap();
    }
    let result = executor.execute_opcode(0xFA, &mut state, &context);
    assert!(matches!(result, Err(ExecutionError::Reverted(_))));

    // DELEGATECALL (0xF4) — requires 6 stack items
    let mut state = EVMState::new(GAS);
    for _ in 0..6 {
        state.stack_push(U256::from(0u64)).unwrap();
    }
    let result = executor.execute_opcode(0xF4, &mut state, &context);
    assert!(matches!(result, Err(ExecutionError::Reverted(_))));

    // CREATE2 (0xF5) — requires 4 stack items
    let mut state = EVMState::new(GAS);
    for _ in 0..4 {
        state.stack_push(U256::from(0u64)).unwrap();
    }
    let result = executor.execute_opcode(0xF5, &mut state, &context);
    assert!(matches!(result, Err(ExecutionError::Reverted(_))));

    // CALLCODE (0xF2) — requires 7 stack items
    let mut state = EVMState::new(GAS);
    for _ in 0..7 {
        state.stack_push(U256::from(0u64)).unwrap();
    }
    let result = executor.execute_opcode(0xF2, &mut state, &context);
    assert!(matches!(result, Err(ExecutionError::Reverted(_))));
}

// ---------------------------------------------------------------------------
// Extra: test_selfdestruct
// ---------------------------------------------------------------------------
#[test]
fn test_selfdestruct() {
    let mut executor = EVMExecutor::new();
    let mut state = EVMState::new(GAS);
    let context = test_context();

    state.stack_push(U256::from(0u64)).unwrap(); // address
    executor.execute_opcode(0xFF, &mut state, &context).unwrap();
    assert!(state.stopped);
}

// ---------------------------------------------------------------------------
// Extra: test_out_of_gas
// ---------------------------------------------------------------------------
#[test]
fn test_out_of_gas() {
    let mut executor = EVMExecutor::new();
    let mut state = EVMState::new(1); // Only 1 gas
    let context = test_context();

    // ADD costs 3 gas
    state.stack_push(U256::from(1u64)).unwrap();
    state.stack_push(U256::from(2u64)).unwrap();
    let result = executor.execute_opcode(0x01, &mut state, &context);
    assert!(matches!(result, Err(ExecutionError::OutOfGas)));
}

// ---------------------------------------------------------------------------
// Extra: test_mcopy (EIP-5656)
// ---------------------------------------------------------------------------
#[test]
fn test_mcopy() {
    let mut executor = EVMExecutor::new();
    let mut state = EVMState::new(GAS);
    let context = test_context();

    // Write data at offset 0
    state.memory_expand(0, 32).unwrap();
    state.memory_write(0, &[0xAA; 16]).unwrap();

    // MCOPY: dst=32, src=0, size=16
    state.stack_push(U256::from(16u64)).unwrap(); // size
    state.stack_push(U256::from(0u64)).unwrap();  // src
    state.stack_push(U256::from(32u64)).unwrap(); // dst
    executor.execute_opcode(0x5E, &mut state, &context).unwrap();

    assert_eq!(&state.memory[32..48], &[0xAA; 16]);
}
