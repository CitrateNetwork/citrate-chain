// Property-based tests for citrate-execution EVM opcode engine.
// Tests invariants of the EVMOpcode, EVMState, and related types
// using the proptest framework.

use proptest::prelude::*;
use std::collections::HashMap;

use citrate_execution::vm::evm_opcodes::{EVMOpcode, EVMState};
use primitive_types::U256;

proptest! {
    // -----------------------------------------------------------------------
    // 1. Opcode TryFrom<u8> round-trip — valid bytes convert and match.
    // -----------------------------------------------------------------------
    #[test]
    fn opcode_tryfrom_roundtrip(
        byte in prop::sample::select(vec![
            0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x20,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
            0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
            0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4,
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xfa, 0xfd, 0xfe, 0xff,
        ])
    ) {
        let opcode = EVMOpcode::try_from(byte);
        prop_assert!(opcode.is_ok(), "Byte 0x{:02x} should be a valid opcode", byte);
        let op = opcode.unwrap();
        // The opcode discriminant should match the original byte
        prop_assert_eq!(op as u8, byte, "Opcode discriminant mismatch for 0x{:02x}", byte);
    }

    // -----------------------------------------------------------------------
    // 2. Opcode invalid bytes — gaps in opcode table return Err.
    // -----------------------------------------------------------------------
    #[test]
    fn opcode_invalid_bytes(
        byte in prop::sample::select(vec![
            0x0cu8, 0x0d, 0x0e, 0x0f,
            0x1e, 0x1f,
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
            0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
            0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
            0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
            0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
            0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
            0xf6, 0xf7, 0xf8, 0xf9, 0xfb, 0xfc,
        ])
    ) {
        let result = EVMOpcode::try_from(byte);
        prop_assert!(result.is_err(), "Byte 0x{:02x} should NOT be a valid opcode", byte);
    }

    // -----------------------------------------------------------------------
    // 3. Stack push/pop identity — push N, pop -> get N back.
    // -----------------------------------------------------------------------
    #[test]
    fn stack_push_pop_identity(val_bytes in prop::collection::vec(any::<u8>(), 32)) {
        let mut state = EVMState::new(1_000_000);
        let val = U256::from_big_endian(&val_bytes);
        state.stack_push(val).expect("push must succeed");
        let popped = state.stack_pop().expect("pop must succeed");
        prop_assert_eq!(popped, val, "Popped value must equal pushed value");
    }

    // -----------------------------------------------------------------------
    // 4. Stack overflow at 1024 — pushing 1025 elements fails.
    // -----------------------------------------------------------------------
    #[test]
    fn stack_overflow_at_1024(extra in 1u32..10) {
        let mut state = EVMState::new(1_000_000_000);
        // Fill the stack to exactly 1024
        for i in 0..1024u32 {
            state.stack_push(U256::from(i)).expect("push within limit must succeed");
        }
        prop_assert_eq!(state.stack.len(), 1024);
        // The 1025th push (and beyond) must fail
        for _ in 0..extra {
            let result = state.stack_push(U256::from(9999u64));
            prop_assert!(result.is_err(), "Push beyond 1024 must fail");
        }
    }

    // -----------------------------------------------------------------------
    // 5. Memory expand cost monotonicity — larger expansion costs more gas.
    // -----------------------------------------------------------------------
    #[test]
    fn memory_expand_cost_monotonicity(
        small_size in 32usize..256,
        delta in 32usize..512,
    ) {
        let large_size = small_size + delta;
        let mut state_small = EVMState::new(100_000_000);
        let mut state_large = EVMState::new(100_000_000);

        let cost_small = state_small.memory_expand(0, small_size).expect("expand small");
        let cost_large = state_large.memory_expand(0, large_size).expect("expand large");

        prop_assert!(
            cost_large >= cost_small,
            "Larger expansion (size={}) must cost >= smaller (size={}): {} vs {}",
            large_size, small_size, cost_large, cost_small
        );
    }

    // -----------------------------------------------------------------------
    // 6. Memory write/read round-trip — write data, read same offset/size -> same data.
    // -----------------------------------------------------------------------
    #[test]
    fn memory_write_read_roundtrip(
        offset in 0usize..128,
        data in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        let mut state = EVMState::new(100_000_000);
        // Expand first to avoid issues
        state.memory_expand(offset, data.len()).expect("expand");
        state.memory_write(offset, &data).expect("write");
        let read_back = state.memory_read(offset, data.len());
        prop_assert_eq!(read_back, data, "Read-back must equal written data");
    }

    // -----------------------------------------------------------------------
    // 7. Gas consumption correctness — consume_gas decrements remaining gas exactly.
    // -----------------------------------------------------------------------
    #[test]
    fn gas_consumption_exact(
        gas_limit in 1_000u64..10_000_000,
        amount in 0u64..1_000,
    ) {
        let mut state = EVMState::new(gas_limit);
        let before = state.gas_remaining;
        let result = state.consume_gas(amount);
        if amount <= gas_limit {
            prop_assert!(result.is_ok());
            prop_assert_eq!(
                state.gas_remaining, before - amount,
                "Gas remaining must decrease by exactly the consumed amount"
            );
        } else {
            prop_assert!(result.is_err());
        }
    }

    // -----------------------------------------------------------------------
    // 8. Gas overflow — consuming more than remaining fails with OutOfGas.
    // -----------------------------------------------------------------------
    #[test]
    fn gas_overflow(gas_limit in 0u64..1_000) {
        let mut state = EVMState::new(gas_limit);
        let over = gas_limit.saturating_add(1);
        let result = state.consume_gas(over);
        prop_assert!(result.is_err(), "Consuming more gas than remaining must fail");
    }

    // -----------------------------------------------------------------------
    // 9. Storage store/load round-trip — store value, load -> get same value.
    // -----------------------------------------------------------------------
    #[test]
    fn storage_store_load_roundtrip(
        key_u64 in any::<u64>(),
        val_u64 in 1u64..u64::MAX,  // non-zero to avoid removal
    ) {
        let mut state = EVMState::new(1_000_000);
        let mut accessed = HashMap::new();
        let key = U256::from(key_u64);
        let value = U256::from(val_u64);

        state.storage_store(key, value, &mut accessed);
        let loaded = state.storage_load(key, &mut accessed);
        prop_assert_eq!(loaded, value, "Loaded value must equal stored value");
    }

    // -----------------------------------------------------------------------
    // 10. Transient storage isolation — tstore/tload round-trip, default is zero.
    // -----------------------------------------------------------------------
    #[test]
    fn transient_storage_roundtrip(
        key_u64 in any::<u64>(),
        val_u64 in 1u64..u64::MAX,
    ) {
        let mut state = EVMState::new(1_000_000);
        let key = U256::from(key_u64);
        let value = U256::from(val_u64);

        // Default value should be zero
        let default = state.tload(key);
        prop_assert_eq!(default, U256::zero(), "Default transient storage value must be zero");

        // Store and load back
        state.tstore(key, value);
        let loaded = state.tload(key);
        prop_assert_eq!(loaded, value, "tload must return value set by tstore");

        // Store zero should clear
        state.tstore(key, U256::zero());
        let cleared = state.tload(key);
        prop_assert_eq!(cleared, U256::zero(), "tstore(key, 0) must clear the entry");
    }
}
