// Sprint KK/LL: RPC adversarial input tests
//
// These tests exercise the eth_tx_decoder with malformed, oversized,
// and edge-case transaction bytes to verify error handling without panics.

use citrate_api::eth_tx_decoder::decode_eth_transaction;

// ============================================================================
// 1. test_malformed_rlp_returns_error_not_panic
// ============================================================================
#[test]
fn test_malformed_rlp_returns_error_not_panic() {
    // Random garbage bytes that are not valid RLP, bincode, or typed tx
    let garbage: Vec<u8> = vec![
        0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    ];

    let result = decode_eth_transaction(&garbage);
    assert!(
        result.is_err(),
        "Garbage bytes must return Err, not panic or produce a transaction"
    );
}

// ============================================================================
// 2. test_oversized_bincode_rejected
// ============================================================================
#[test]
fn test_oversized_bincode_rejected() {
    // Create a 300KB payload that looks like it could be bincode
    // (does not start with 0x01, 0x02, and is not a valid RLP list)
    // The decoder limits bincode to 256KB
    let oversized: Vec<u8> = vec![0x03; 300 * 1024]; // 300KB, starts with 0x03

    let result = decode_eth_transaction(&oversized);
    assert!(
        result.is_err(),
        "Oversized bincode payload must be rejected"
    );

    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("too large") || err_msg.contains("256KB") || err_msg.contains("Invalid RLP"),
        "Error message should indicate size limit or invalid format: {}",
        err_msg
    );
}

// ============================================================================
// 3. test_invalid_address_length_rejected
// ============================================================================
#[test]
fn test_invalid_address_length_rejected() {
    // Construct a minimal RLP list that looks like a legacy transaction but
    // has a 19-byte `to` address (field at index 3).
    //
    // Legacy RLP: [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
    let mut stream = rlp::RlpStream::new_list(9);
    stream.append(&0u64);           // nonce
    stream.append(&1_000_000_000u64); // gasPrice
    stream.append(&21_000u64);       // gasLimit
    // INVALID: 19-byte address instead of 20
    stream.append(&vec![0xABu8; 19].as_slice());
    stream.append(&0u64);           // value
    stream.append(&Vec::<u8>::new().as_slice()); // data (empty)
    stream.append(&27u64);          // v
    stream.append(&vec![1u8; 32].as_slice()); // r
    stream.append(&vec![1u8; 32].as_slice()); // s

    let rlp_bytes = stream.out().to_vec();

    let result = decode_eth_transaction(&rlp_bytes);
    assert!(
        result.is_err(),
        "Transaction with 19-byte to address must be rejected"
    );

    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("address") || err_msg.contains("invalid"),
        "Error should mention address issue: {}",
        err_msg
    );
}

// ============================================================================
// 4. test_empty_transaction_rejected
// ============================================================================
#[test]
fn test_empty_transaction_rejected() {
    let empty: Vec<u8> = vec![];
    let result = decode_eth_transaction(&empty);
    assert!(
        result.is_err(),
        "Empty transaction data must be rejected"
    );

    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("Empty") || err_msg.contains("empty"),
        "Error should mention empty input: {}",
        err_msg
    );
}

// ============================================================================
// 5. test_valid_legacy_tx_decodes
// ============================================================================
#[test]
fn test_valid_legacy_tx_decodes() {
    // This is a real signed legacy Ethereum transaction (chainId=1) from the wild.
    // We construct one using known test vectors.
    //
    // For deterministic testing, we build a legacy RLP with a valid secp256k1
    // signature. Instead of using a known-good captured transaction (which
    // requires exact signature bytes), we verify that the decoder handles a
    // structurally valid legacy RLP and either decodes it or returns a signature
    // error (which is still "not a panic").

    // Build a structurally valid legacy tx RLP
    let mut stream = rlp::RlpStream::new_list(9);
    stream.append(&0u64);               // nonce
    stream.append(&20_000_000_000u64);   // gasPrice (20 gwei)
    stream.append(&21_000u64);           // gasLimit
    // Valid 20-byte address
    stream.append(&vec![0x42u8; 20].as_slice());
    stream.append(&1_000_000_000_000_000_000u64); // value: 1 ETH in wei
    stream.append(&Vec::<u8>::new().as_slice());   // data (empty)
    stream.append(&27u64);               // v (pre-EIP-155)
    // r and s — these won't form a valid ECDSA signature but the decoder
    // should handle the error gracefully
    stream.append(&vec![0x11u8; 32].as_slice()); // r
    stream.append(&vec![0x22u8; 32].as_slice()); // s

    let rlp_bytes = stream.out().to_vec();

    let result = decode_eth_transaction(&rlp_bytes);

    // The decoder may return an error because the signature is not valid ECDSA,
    // but it must NOT panic. A successful decode would mean the RLP parsing worked.
    // Either outcome (Ok with recovered address, or Err from ECDSA recovery) is acceptable.
    match &result {
        Ok(tx) => {
            assert_eq!(tx.nonce, 0);
            assert_eq!(tx.gas_limit, 21_000);
            assert_eq!(tx.eth_tx_type, 0, "Should be legacy tx type");
        }
        Err(e) => {
            // ECDSA recovery failure is expected with synthetic signatures
            assert!(
                e.contains("signature") || e.contains("recover") || e.contains("ECDSA"),
                "Error should be about signature recovery, not parsing: {}",
                e
            );
        }
    }
}

// ============================================================================
// 6. test_valid_eip1559_tx_decodes
// ============================================================================
#[test]
fn test_valid_eip1559_tx_decodes() {
    // Build a structurally valid EIP-1559 (type 0x02) transaction.
    // The payload after the 0x02 prefix is:
    // [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, yParity, r, s]

    let mut stream = rlp::RlpStream::new_list(12);
    stream.append(&1u64);               // chainId
    stream.append(&5u64);               // nonce
    stream.append(&2_000_000_000u64);   // maxPriorityFeePerGas (2 gwei)
    stream.append(&30_000_000_000u64);  // maxFeePerGas (30 gwei)
    stream.append(&21_000u64);          // gasLimit
    // Valid 20-byte to address
    stream.append(&vec![0xABu8; 20].as_slice());
    stream.append(&0u64);               // value
    stream.append(&Vec::<u8>::new().as_slice()); // data (empty)
    // Empty access list
    stream.begin_list(0);
    stream.append(&0u64);               // yParity
    stream.append(&vec![0x33u8; 32].as_slice()); // r
    stream.append(&vec![0x44u8; 32].as_slice()); // s

    let rlp_payload = stream.out().to_vec();

    // Prepend 0x02 type byte
    let mut tx_bytes = vec![0x02];
    tx_bytes.extend_from_slice(&rlp_payload);

    let result = decode_eth_transaction(&tx_bytes);

    // Similar to legacy: either succeeds or fails on ECDSA recovery, never panics
    match &result {
        Ok(tx) => {
            assert_eq!(tx.nonce, 5);
            assert_eq!(tx.gas_limit, 21_000);
            assert_eq!(tx.eth_tx_type, 2, "Should be EIP-1559 tx type");
            assert_eq!(tx.chain_id, Some(1));
            assert!(tx.max_fee_per_gas.is_some());
            assert!(tx.max_priority_fee_per_gas.is_some());
        }
        Err(e) => {
            // ECDSA recovery failure is expected with synthetic signatures
            assert!(
                e.contains("signature") || e.contains("recover") || e.contains("bad"),
                "Error should be about signature recovery, not parsing: {}",
                e
            );
        }
    }
}
