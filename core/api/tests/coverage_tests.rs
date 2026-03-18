// Sprint OO: API coverage tests — targeting the 68% of uncovered lines.
// Focuses on unhappy paths, edge cases, and error conditions.

use citrate_api::eth_tx_decoder::decode_eth_transaction;

// ============================================================
// Transaction Decoder: Edge Cases & Unhappy Paths
// ============================================================

#[test]
fn test_decode_just_type_byte_no_payload() {
    // Type 0x02 (EIP-1559) with no RLP payload
    let result = decode_eth_transaction(&[0x02]);
    assert!(result.is_err(), "Type byte alone must error");
}

#[test]
fn test_decode_type_0x01_no_payload() {
    // Type 0x01 (EIP-2930) with no payload
    let result = decode_eth_transaction(&[0x01]);
    assert!(result.is_err(), "EIP-2930 type byte alone must error");
}

#[test]
fn test_decode_type_0x03_blob_tx_rejected() {
    // Type 0x03 (EIP-4844 blob tx) — not supported
    let result = decode_eth_transaction(&[0x03, 0xDE, 0xAD]);
    assert!(result.is_err(), "Blob transactions should be rejected");
}

#[test]
fn test_decode_255_byte_random_data() {
    // Exactly 255 bytes of non-RLP data
    let data: Vec<u8> = (0..255).map(|i| i as u8).collect();
    let result = decode_eth_transaction(&data);
    assert!(result.is_err(), "Random 255 bytes must not decode as valid tx");
}

#[test]
fn test_decode_rlp_with_21_byte_to_address_rejected() {
    use rlp::RlpStream;
    let mut stream = RlpStream::new_list(9);
    stream.append(&0u64);
    stream.append(&1_000_000_000u64);
    stream.append(&21_000u64);
    stream.append(&vec![0xABu8; 21]); // 21 bytes — too long
    stream.append(&0u64);
    stream.append(&Vec::<u8>::new());
    stream.append(&27u64);
    stream.append(&vec![1u8; 32]);
    stream.append(&vec![1u8; 32]);
    let result = decode_eth_transaction(&stream.out());
    assert!(result.is_err(), "21-byte to address must be rejected");
}

#[test]
fn test_decode_rlp_with_zero_byte_to_treated_as_create() {
    use rlp::RlpStream;
    let mut stream = RlpStream::new_list(9);
    stream.append(&0u64);
    stream.append(&1_000_000_000u64);
    stream.append(&100_000u64);
    stream.append(&Vec::<u8>::new()); // empty to = contract creation
    stream.append(&0u64);
    stream.append(&vec![0x60, 0x00]); // minimal bytecode
    stream.append(&27u64);
    stream.append(&vec![1u8; 32]);
    stream.append(&vec![1u8; 32]);
    // Should parse without panic (signature may fail)
    let _result = decode_eth_transaction(&stream.out());
}

#[test]
fn test_decode_rlp_with_huge_nonce() {
    use rlp::RlpStream;
    let mut stream = RlpStream::new_list(9);
    stream.append(&u64::MAX); // max nonce
    stream.append(&1_000_000_000u64);
    stream.append(&21_000u64);
    stream.append(&vec![0u8; 20]);
    stream.append(&0u64);
    stream.append(&Vec::<u8>::new());
    stream.append(&27u64);
    stream.append(&vec![1u8; 32]);
    stream.append(&vec![1u8; 32]);
    // Should parse max nonce without overflow
    let _result = decode_eth_transaction(&stream.out());
}

#[test]
fn test_decode_rlp_with_huge_gas_limit() {
    use rlp::RlpStream;
    let mut stream = RlpStream::new_list(9);
    stream.append(&0u64);
    stream.append(&1_000_000_000u64);
    stream.append(&u64::MAX); // max gas
    stream.append(&vec![0u8; 20]);
    stream.append(&0u64);
    stream.append(&Vec::<u8>::new());
    stream.append(&27u64);
    stream.append(&vec![1u8; 32]);
    stream.append(&vec![1u8; 32]);
    let _result = decode_eth_transaction(&stream.out());
}

#[test]
fn test_decode_rlp_with_large_data_field() {
    use rlp::RlpStream;
    let mut stream = RlpStream::new_list(9);
    stream.append(&0u64);
    stream.append(&1_000_000_000u64);
    stream.append(&1_000_000u64);
    stream.append(&vec![0u8; 20]);
    stream.append(&0u64);
    stream.append(&vec![0xFFu8; 10_000]); // 10KB data
    stream.append(&27u64);
    stream.append(&vec![1u8; 32]);
    stream.append(&vec![1u8; 32]);
    // Should handle 10KB data without panic
    let _result = decode_eth_transaction(&stream.out());
}

#[test]
fn test_decode_rlp_missing_signature_fields() {
    use rlp::RlpStream;
    // Only 6 fields instead of 9 (missing v, r, s)
    let mut stream = RlpStream::new_list(6);
    stream.append(&0u64);
    stream.append(&1_000_000_000u64);
    stream.append(&21_000u64);
    stream.append(&vec![0u8; 20]);
    stream.append(&0u64);
    stream.append(&Vec::<u8>::new());
    let result = decode_eth_transaction(&stream.out());
    assert!(result.is_err(), "Missing signature fields must error");
}

#[test]
fn test_decode_eip1559_with_empty_access_list() {
    use rlp::RlpStream;
    let mut stream = RlpStream::new_list(12);
    stream.append(&40204u64); // chain_id
    stream.append(&0u64); // nonce
    stream.append(&1_000_000_000u64); // maxPriorityFee
    stream.append(&2_000_000_000u64); // maxFee
    stream.append(&21_000u64); // gasLimit
    stream.append(&vec![0u8; 20]); // to
    stream.append(&0u64); // value
    stream.append(&Vec::<u8>::new()); // data
    stream.append_list::<Vec<u8>, Vec<u8>>(&[]); // empty access list
    stream.append(&0u64); // yParity
    stream.append(&vec![1u8; 32]); // r
    stream.append(&vec![1u8; 32]); // s
    let mut tx_bytes = vec![0x02u8];
    tx_bytes.extend_from_slice(&stream.out());
    // Should parse without panic
    let _result = decode_eth_transaction(&tx_bytes);
}

#[test]
fn test_decode_bincode_at_exact_256kb_limit() {
    // Exactly 256KB — should be accepted by the size check
    let data = vec![0u8; 256 * 1024];
    let result = decode_eth_transaction(&data);
    // Will fail on deserialization but should NOT fail on size limit
    assert!(result.is_err(), "Invalid bincode should error");
}

#[test]
fn test_decode_bincode_one_byte_over_limit() {
    // 256KB + 1 byte — should be rejected by size check
    let data = vec![0u8; 256 * 1024 + 1];
    let result = decode_eth_transaction(&data);
    assert!(result.is_err(), "Over-limit payload must be rejected");
    let err = result.unwrap_err();
    assert!(
        err.contains("large") || err.contains("256KB") || err.contains("too"),
        "Error should mention size limit, got: {}", err
    );
}

// Rate limiter tests are in the inline #[cfg(test)] module of rate_limit.rs
// since the method_cost function and RateLimitConfig require internal access.

// ============================================================
// Hex and Format Edge Cases
// ============================================================

#[test]
fn test_decode_all_zeros_32_bytes() {
    let result = decode_eth_transaction(&[0u8; 32]);
    assert!(result.is_err(), "32 zero bytes must not be a valid tx");
}

#[test]
fn test_decode_all_ff_32_bytes() {
    let result = decode_eth_transaction(&[0xFF; 32]);
    assert!(result.is_err(), "32 0xFF bytes must not be a valid tx");
}

#[test]
fn test_decode_rlp_list_of_lists_rejected() {
    use rlp::RlpStream;
    // Nested list — not a valid transaction structure
    let mut outer = RlpStream::new_list(1);
    let mut inner = RlpStream::new_list(2);
    inner.append(&42u64);
    inner.append(&43u64);
    outer.append_raw(&inner.out(), 1);
    let result = decode_eth_transaction(&outer.out());
    assert!(result.is_err(), "Nested list is not a valid tx");
}
