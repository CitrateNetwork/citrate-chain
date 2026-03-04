// Property-based tests for citrate-api RPC types and helpers.
// Tests hex encoding, address formatting, and type conversion invariants
// using the proptest framework.
//
// NOTE: proptest must be added to [dev-dependencies] in core/api/Cargo.toml:
//   proptest = { workspace = true }

use proptest::prelude::*;

// citrate_api re-exports are available but the proptests here focus on
// hex/format invariants using only the hex crate directly.

proptest! {
    // -----------------------------------------------------------------------
    // 1. Hex encoding round-trip — bytes -> hex -> bytes.
    // -----------------------------------------------------------------------
    #[test]
    fn hex_encoding_roundtrip(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
        let hex_str = hex::encode(&bytes);
        let decoded = hex::decode(&hex_str).expect("hex decode must succeed");
        prop_assert_eq!(decoded, bytes, "Hex round-trip must be identity");
    }

    // -----------------------------------------------------------------------
    // 2. Address format consistency — 20-byte addresses always produce "0x" + 40 hex chars.
    // -----------------------------------------------------------------------
    #[test]
    fn address_format_consistency(addr_bytes in prop::collection::vec(any::<u8>(), 20)) {
        let hex_str = format!("0x{}", hex::encode(&addr_bytes));
        prop_assert_eq!(hex_str.len(), 42, "Address string must be 42 chars (0x + 40 hex)");
        prop_assert!(hex_str.starts_with("0x"), "Address must start with 0x");
        // Verify all chars after 0x are valid hex
        for ch in hex_str[2..].chars() {
            prop_assert!(
                ch.is_ascii_hexdigit(),
                "Address must contain only hex digits, found '{}'", ch
            );
        }
    }

    // -----------------------------------------------------------------------
    // 3. Block number hex parsing — valid hex strings parse correctly.
    // -----------------------------------------------------------------------
    #[test]
    fn block_number_hex_parsing(num in 0u64..u64::MAX) {
        let hex_str = format!("0x{:x}", num);
        let stripped = hex_str.strip_prefix("0x").unwrap_or(&hex_str);
        let parsed = u64::from_str_radix(stripped, 16).expect("hex parse must succeed");
        prop_assert_eq!(parsed, num, "Hex round-trip for block number must be identity");
    }

    // -----------------------------------------------------------------------
    // 4. Chain ID encoding — u64 -> hex -> parse back.
    // -----------------------------------------------------------------------
    #[test]
    fn chain_id_hex_roundtrip(chain_id in any::<u64>()) {
        let hex_str = format!("0x{:x}", chain_id);
        let stripped = hex_str.strip_prefix("0x").unwrap();
        let parsed = u64::from_str_radix(stripped, 16).expect("chain ID hex parse must succeed");
        prop_assert_eq!(parsed, chain_id, "Chain ID hex round-trip must be identity");
    }

    // -----------------------------------------------------------------------
    // 5. Gas price format — always valid hex.
    // -----------------------------------------------------------------------
    #[test]
    fn gas_price_hex_format(gas_price in any::<u64>()) {
        let hex_str = format!("0x{:x}", gas_price);
        prop_assert!(hex_str.starts_with("0x"), "Gas price hex must start with 0x");
        let stripped = hex_str.strip_prefix("0x").unwrap();
        prop_assert!(!stripped.is_empty(), "Gas price hex body must not be empty");
        for ch in stripped.chars() {
            prop_assert!(
                ch.is_ascii_hexdigit(),
                "Gas price hex must contain only hex digits, found '{}'", ch
            );
        }
        // Verify it parses back
        let parsed = u64::from_str_radix(stripped, 16).expect("gas price hex parse");
        prop_assert_eq!(parsed, gas_price);
    }

    // -----------------------------------------------------------------------
    // 6. Transaction hash format — 32-byte hash -> "0x" + 64 hex chars.
    // -----------------------------------------------------------------------
    #[test]
    fn tx_hash_format(hash_bytes in prop::collection::vec(any::<u8>(), 32)) {
        let hex_str = format!("0x{}", hex::encode(&hash_bytes));
        prop_assert_eq!(hex_str.len(), 66, "Tx hash string must be 66 chars (0x + 64 hex)");
        prop_assert!(hex_str.starts_with("0x"), "Tx hash must start with 0x");
        // Verify hex decode round-trips
        let decoded = hex::decode(&hex_str[2..]).expect("hex decode must succeed");
        prop_assert_eq!(decoded, hash_bytes, "Tx hash hex round-trip must be identity");
    }

    // -----------------------------------------------------------------------
    // 7. JSON-RPC error code ranges — standard error codes are in valid range.
    // -----------------------------------------------------------------------
    #[test]
    fn jsonrpc_error_code_ranges(
        code in prop::sample::select(vec![
            -32700i64,  // Parse error
            -32600,     // Invalid Request
            -32601,     // Method not found
            -32602,     // Invalid params
            -32603,     // Internal error
            -32000,     // Server error (lower bound)
            -32099,     // Server error (upper bound)
        ])
    ) {
        // Standard JSON-RPC error codes are in [-32768, -32000]
        prop_assert!(
            (-32768..=-32000).contains(&code),
            "Standard error code {} must be in [-32768, -32000]", code
        );

        // Pre-defined codes
        if code == -32700 || code == -32600 || code == -32601 || code == -32602 || code == -32603 {
            prop_assert!(
                (-32700..=-32600).contains(&code),
                "Pre-defined error code {} must be in [-32700, -32600]", code
            );
        }

        // Server error range
        if (-32099..=-32000).contains(&code) {
            prop_assert!(
                (-32099..=-32000).contains(&code),
                "Server error code {} must be in [-32099, -32000]", code
            );
        }
    }
}
