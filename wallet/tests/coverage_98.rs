//! Coverage-98 tests for wallet crate
//!
//! Targets remaining uncovered branches in rpc_client.rs and wallet.rs to push
//! coverage from ~85% to 98%+.
//!
//! Strategy:
//! - For rpc_client.rs: spawn a lightweight TCP mock server that returns crafted
//!   JSON-RPC responses so we exercise every parsing branch (valid hex, invalid
//!   hex, non-string, null, short hashes, etc.) without needing a real node.
//! - For wallet.rs: test format_latt indirectly via InsufficientBalance error
//!   messages, and cover remaining account-management edge cases.

use citrate_consensus::types::{Hash, PublicKey};
use citrate_execution::types::Address;
use citrate_wallet::errors::WalletError;
use citrate_wallet::rpc_client::RpcClient;
use citrate_wallet::transaction::TransactionBuilder;
use citrate_wallet::wallet::{Account, Wallet, WalletConfig};
use ed25519_dalek::SigningKey;
use primitive_types::U256;
use std::path::PathBuf;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ============================================================================
// Helpers
// ============================================================================

fn temp_wallet() -> (TempDir, Wallet) {
    let dir = TempDir::new().unwrap();
    let config = WalletConfig {
        keystore_path: dir.path().join("keystore.json"),
        rpc_url: "http://localhost:8545".to_string(),
        chain_id: 40204,
        default_gas_price: 1_000_000_000,
        default_gas_limit: 21_000,
    };
    let wallet = Wallet::new(config).unwrap();
    (dir, wallet)
}

fn temp_wallet_at(url: &str) -> (TempDir, Wallet) {
    let dir = TempDir::new().unwrap();
    let config = WalletConfig {
        keystore_path: dir.path().join("keystore.json"),
        rpc_url: url.to_string(),
        chain_id: 40204,
        default_gas_price: 1_000_000_000,
        default_gas_limit: 21_000,
    };
    let wallet = Wallet::new(config).unwrap();
    (dir, wallet)
}

fn test_signing_key() -> (SigningKey, PublicKey) {
    let secret = [42u8; 32];
    let signing_key = SigningKey::from_bytes(&secret);
    let public_key = PublicKey::new(signing_key.verifying_key().to_bytes());
    (signing_key, public_key)
}

/// Spawn a one-shot TCP server that reads one HTTP request and replies with
/// the given JSON body.  Returns the local address (e.g. "127.0.0.1:PORT").
async fn mock_rpc_server(response_body: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let body = response_body.to_string();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 8192];
        let _ = socket.read(&mut buf).await.unwrap();

        let http_response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = socket.write_all(http_response.as_bytes()).await;
        let _ = socket.shutdown().await;
    });

    format!("http://{}", addr)
}

/// Spawn a multi-request TCP server that handles N sequential requests,
/// each with its own response body.
async fn mock_rpc_server_multi(responses: Vec<String>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        for body in responses {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let _ = socket.read(&mut buf).await.unwrap();

            let http_response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = socket.write_all(http_response.as_bytes()).await;
            let _ = socket.shutdown().await;
        }
    });

    format!("http://{}", addr)
}

fn jsonrpc_ok(result: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","result":{},"id":1}}"#, result)
}

fn jsonrpc_ok_str(result: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","result":"{}","id":1}}"#, result)
}

fn jsonrpc_error(code: i32, message: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","error":{{"code":{},"message":"{}"}},"id":1}}"#,
        code, message
    )
}

// ============================================================================
// RPC Client: get_balance parsing tests
// ============================================================================

#[tokio::test]
async fn test_rpc_balance_valid_hex() {
    let url = mock_rpc_server(&jsonrpc_ok_str("0xde0b6b3a7640000")).await;
    let client = RpcClient::new(&url);
    let balance = client.get_balance(&Address([0x11; 20])).await.unwrap();
    assert_eq!(balance, U256::from(10u64.pow(18))); // 1 ETH in wei
}

#[tokio::test]
async fn test_rpc_balance_zero() {
    let url = mock_rpc_server(&jsonrpc_ok_str("0x0")).await;
    let client = RpcClient::new(&url);
    let balance = client.get_balance(&Address([0x11; 20])).await.unwrap();
    assert_eq!(balance, U256::zero());
}

#[tokio::test]
async fn test_rpc_balance_large_value() {
    // 1000 ETH = 0x3635c9adc5dea00000
    let url = mock_rpc_server(&jsonrpc_ok_str("0x3635c9adc5dea00000")).await;
    let client = RpcClient::new(&url);
    let balance = client.get_balance(&Address([0x11; 20])).await.unwrap();
    let expected = U256::from(1000u64) * U256::from(10u64.pow(18));
    assert_eq!(balance, expected);
}

#[tokio::test]
async fn test_rpc_balance_no_0x_prefix() {
    // Should still work because trim_start_matches("0x") is a no-op on "de0b6b3a7640000"
    let url = mock_rpc_server(&jsonrpc_ok_str("de0b6b3a7640000")).await;
    let client = RpcClient::new(&url);
    let balance = client.get_balance(&Address([0x11; 20])).await.unwrap();
    assert_eq!(balance, U256::from(10u64.pow(18)));
}

#[tokio::test]
async fn test_rpc_balance_invalid_hex_chars() {
    let url = mock_rpc_server(&jsonrpc_ok_str("0xZZZZZZ")).await;
    let client = RpcClient::new(&url);
    let err = client.get_balance(&Address([0x11; 20])).await.unwrap_err();
    match err {
        WalletError::Rpc(msg) => assert!(
            msg.contains("Failed to parse balance"),
            "Expected parse error, got: {}",
            msg
        ),
        e => panic!("Expected Rpc error, got {:?}", e),
    }
}

#[tokio::test]
async fn test_rpc_balance_non_string_response() {
    // Result is a number instead of a string
    let url = mock_rpc_server(&jsonrpc_ok("42")).await;
    let client = RpcClient::new(&url);
    let err = client.get_balance(&Address([0x11; 20])).await.unwrap_err();
    match err {
        WalletError::Rpc(msg) => assert!(
            msg.contains("Invalid balance response"),
            "Expected 'Invalid balance response', got: {}",
            msg
        ),
        e => panic!("Expected Rpc error, got {:?}", e),
    }
}

#[tokio::test]
async fn test_rpc_balance_null_response() {
    let url = mock_rpc_server(&jsonrpc_ok("null")).await;
    let client = RpcClient::new(&url);
    let err = client.get_balance(&Address([0x11; 20])).await.unwrap_err();
    match err {
        WalletError::Rpc(msg) => assert!(msg.contains("Invalid balance response")),
        e => panic!("Expected Rpc error, got {:?}", e),
    }
}

// ============================================================================
// RPC Client: get_nonce parsing tests
// ============================================================================

#[tokio::test]
async fn test_rpc_nonce_valid_hex() {
    let url = mock_rpc_server(&jsonrpc_ok_str("0xa")).await;
    let client = RpcClient::new(&url);
    let nonce = client.get_nonce(&Address([0x22; 20])).await.unwrap();
    assert_eq!(nonce, 10);
}

#[tokio::test]
async fn test_rpc_nonce_zero() {
    let url = mock_rpc_server(&jsonrpc_ok_str("0x0")).await;
    let client = RpcClient::new(&url);
    let nonce = client.get_nonce(&Address([0x22; 20])).await.unwrap();
    assert_eq!(nonce, 0);
}

#[tokio::test]
async fn test_rpc_nonce_large_value() {
    // u64::MAX = 0xffffffffffffffff
    let url = mock_rpc_server(&jsonrpc_ok_str("0xffffffffffffffff")).await;
    let client = RpcClient::new(&url);
    let nonce = client.get_nonce(&Address([0x22; 20])).await.unwrap();
    assert_eq!(nonce, u64::MAX);
}

#[tokio::test]
async fn test_rpc_nonce_invalid_hex() {
    let url = mock_rpc_server(&jsonrpc_ok_str("0xGGGG")).await;
    let client = RpcClient::new(&url);
    let err = client.get_nonce(&Address([0x22; 20])).await.unwrap_err();
    match err {
        WalletError::Rpc(msg) => assert!(msg.contains("Failed to parse nonce")),
        e => panic!("Expected Rpc error, got {:?}", e),
    }
}

#[tokio::test]
async fn test_rpc_nonce_non_string_response() {
    let url = mock_rpc_server(&jsonrpc_ok("123")).await;
    let client = RpcClient::new(&url);
    let err = client.get_nonce(&Address([0x22; 20])).await.unwrap_err();
    match err {
        WalletError::Rpc(msg) => assert!(msg.contains("Invalid nonce response")),
        e => panic!("Expected Rpc error, got {:?}", e),
    }
}

#[tokio::test]
async fn test_rpc_nonce_overflow() {
    // One more than u64::MAX in hex: 0x10000000000000000 (17 hex digits)
    let url = mock_rpc_server(&jsonrpc_ok_str("0x10000000000000000")).await;
    let client = RpcClient::new(&url);
    let err = client.get_nonce(&Address([0x22; 20])).await.unwrap_err();
    match err {
        WalletError::Rpc(msg) => assert!(msg.contains("Failed to parse nonce")),
        e => panic!("Expected Rpc error, got {:?}", e),
    }
}

// ============================================================================
// RPC Client: get_block_number parsing tests
// ============================================================================

#[tokio::test]
async fn test_rpc_block_number_valid() {
    let url = mock_rpc_server(&jsonrpc_ok_str("0x10")).await;
    let client = RpcClient::new(&url);
    let block = client.get_block_number().await.unwrap();
    assert_eq!(block, 16);
}

#[tokio::test]
async fn test_rpc_block_number_non_string() {
    let url = mock_rpc_server(&jsonrpc_ok("999")).await;
    let client = RpcClient::new(&url);
    let err = client.get_block_number().await.unwrap_err();
    match err {
        WalletError::Rpc(msg) => assert!(msg.contains("Invalid block number response")),
        e => panic!("Expected Rpc error, got {:?}", e),
    }
}

#[tokio::test]
async fn test_rpc_block_number_invalid_hex() {
    let url = mock_rpc_server(&jsonrpc_ok_str("0xNOPE")).await;
    let client = RpcClient::new(&url);
    let err = client.get_block_number().await.unwrap_err();
    match err {
        WalletError::Rpc(msg) => assert!(msg.contains("Failed to parse block number")),
        e => panic!("Expected Rpc error, got {:?}", e),
    }
}

// ============================================================================
// RPC Client: get_chain_id parsing tests
// ============================================================================

#[tokio::test]
async fn test_rpc_chain_id_valid() {
    // 40204 = 0x9d0c
    let url = mock_rpc_server(&jsonrpc_ok_str("0x9d0c")).await;
    let client = RpcClient::new(&url);
    let chain_id = client.get_chain_id().await.unwrap();
    assert_eq!(chain_id, 40204);
}

#[tokio::test]
async fn test_rpc_chain_id_non_string() {
    let url = mock_rpc_server(&jsonrpc_ok("40204")).await;
    let client = RpcClient::new(&url);
    let err = client.get_chain_id().await.unwrap_err();
    match err {
        WalletError::Rpc(msg) => assert!(msg.contains("Invalid chain ID response")),
        e => panic!("Expected Rpc error, got {:?}", e),
    }
}

#[tokio::test]
async fn test_rpc_chain_id_invalid_hex() {
    let url = mock_rpc_server(&jsonrpc_ok_str("0xXYZ")).await;
    let client = RpcClient::new(&url);
    let err = client.get_chain_id().await.unwrap_err();
    match err {
        WalletError::Rpc(msg) => assert!(msg.contains("Failed to parse chain ID")),
        e => panic!("Expected Rpc error, got {:?}", e),
    }
}

// ============================================================================
// RPC Client: get_gas_price parsing tests
// ============================================================================

#[tokio::test]
async fn test_rpc_gas_price_valid() {
    // 1 gwei = 0x3b9aca00
    let url = mock_rpc_server(&jsonrpc_ok_str("0x3b9aca00")).await;
    let client = RpcClient::new(&url);
    let gas_price = client.get_gas_price().await.unwrap();
    assert_eq!(gas_price, 1_000_000_000);
}

#[tokio::test]
async fn test_rpc_gas_price_non_string() {
    let url = mock_rpc_server(&jsonrpc_ok("[1,2,3]")).await;
    let client = RpcClient::new(&url);
    let err = client.get_gas_price().await.unwrap_err();
    match err {
        WalletError::Rpc(msg) => assert!(msg.contains("Invalid gas price response")),
        e => panic!("Expected Rpc error, got {:?}", e),
    }
}

#[tokio::test]
async fn test_rpc_gas_price_invalid_hex() {
    let url = mock_rpc_server(&jsonrpc_ok_str("0xBADHEX")).await;
    let client = RpcClient::new(&url);
    let err = client.get_gas_price().await.unwrap_err();
    match err {
        WalletError::Rpc(msg) => assert!(msg.contains("Failed to parse gas price")),
        e => panic!("Expected Rpc error, got {:?}", e),
    }
}

// ============================================================================
// RPC Client: estimate_gas parameter building + parsing tests
// ============================================================================

#[tokio::test]
async fn test_rpc_estimate_gas_with_to_and_data() {
    let url = mock_rpc_server(&jsonrpc_ok_str("0x5208")).await; // 21000
    let client = RpcClient::new(&url);
    let gas = client
        .estimate_gas(
            &Address([0x11; 20]),
            Some(&Address([0x22; 20])),
            U256::from(100),
            vec![0xDE, 0xAD],
        )
        .await
        .unwrap();
    assert_eq!(gas, 21000);
}

#[tokio::test]
async fn test_rpc_estimate_gas_without_to() {
    // Contract deploy: no "to" field
    let url = mock_rpc_server(&jsonrpc_ok_str("0xf4240")).await; // 1000000
    let client = RpcClient::new(&url);
    let gas = client
        .estimate_gas(
            &Address([0x11; 20]),
            None,
            U256::from(0),
            vec![0x60, 0x80],
        )
        .await
        .unwrap();
    assert_eq!(gas, 1_000_000);
}

#[tokio::test]
async fn test_rpc_estimate_gas_without_data() {
    let url = mock_rpc_server(&jsonrpc_ok_str("0x5208")).await;
    let client = RpcClient::new(&url);
    let gas = client
        .estimate_gas(
            &Address([0x11; 20]),
            Some(&Address([0x22; 20])),
            U256::from(100),
            vec![], // empty data
        )
        .await
        .unwrap();
    assert_eq!(gas, 21000);
}

#[tokio::test]
async fn test_rpc_estimate_gas_non_string_response() {
    let url = mock_rpc_server(&jsonrpc_ok("true")).await;
    let client = RpcClient::new(&url);
    let err = client
        .estimate_gas(
            &Address([0x11; 20]),
            Some(&Address([0x22; 20])),
            U256::from(100),
            vec![],
        )
        .await
        .unwrap_err();
    match err {
        WalletError::Rpc(msg) => assert!(msg.contains("Invalid gas estimate response")),
        e => panic!("Expected Rpc error, got {:?}", e),
    }
}

#[tokio::test]
async fn test_rpc_estimate_gas_invalid_hex() {
    let url = mock_rpc_server(&jsonrpc_ok_str("0xNOT_HEX")).await;
    let client = RpcClient::new(&url);
    let err = client
        .estimate_gas(
            &Address([0x11; 20]),
            Some(&Address([0x22; 20])),
            U256::from(100),
            vec![],
        )
        .await
        .unwrap_err();
    match err {
        WalletError::Rpc(msg) => assert!(msg.contains("Failed to parse gas estimate")),
        e => panic!("Expected Rpc error, got {:?}", e),
    }
}

// ============================================================================
// RPC Client: send_transaction hash validation tests
// ============================================================================

#[tokio::test]
async fn test_rpc_send_tx_valid_hash() {
    let hash_hex = format!("0x{}", hex::encode([0xAA; 32]));
    let url = mock_rpc_server(&jsonrpc_ok_str(&hash_hex)).await;
    let client = RpcClient::new(&url);

    let (sk, pk) = test_signing_key();
    let tx = TransactionBuilder::new()
        .from(pk)
        .to(Some(Address([0x11; 20])))
        .value(U256::from(100))
        .build_and_sign(&sk)
        .unwrap();

    let result = client.send_transaction(tx).await.unwrap();
    assert_eq!(result.as_bytes(), &[0xAA; 32]);
}

#[tokio::test]
async fn test_rpc_send_tx_short_hash() {
    // Only 16 bytes instead of 32
    let short_hash = format!("0x{}", hex::encode([0xBB; 16]));
    let url = mock_rpc_server(&jsonrpc_ok_str(&short_hash)).await;
    let client = RpcClient::new(&url);

    let (sk, pk) = test_signing_key();
    let tx = TransactionBuilder::new()
        .from(pk)
        .to(Some(Address([0x11; 20])))
        .value(U256::from(100))
        .build_and_sign(&sk)
        .unwrap();

    let err = client.send_transaction(tx).await.unwrap_err();
    match err {
        WalletError::Rpc(msg) => assert!(
            msg.contains("Invalid transaction hash length"),
            "Expected hash length error, got: {}",
            msg
        ),
        e => panic!("Expected Rpc error, got {:?}", e),
    }
}

#[tokio::test]
async fn test_rpc_send_tx_long_hash() {
    // 33 bytes instead of 32
    let long_hash = format!("0x{}", hex::encode([0xCC; 33]));
    let url = mock_rpc_server(&jsonrpc_ok_str(&long_hash)).await;
    let client = RpcClient::new(&url);

    let (sk, pk) = test_signing_key();
    let tx = TransactionBuilder::new()
        .from(pk)
        .to(Some(Address([0x11; 20])))
        .value(U256::from(100))
        .build_and_sign(&sk)
        .unwrap();

    let err = client.send_transaction(tx).await.unwrap_err();
    match err {
        WalletError::Rpc(msg) => assert!(msg.contains("Invalid transaction hash length")),
        e => panic!("Expected Rpc error, got {:?}", e),
    }
}

#[tokio::test]
async fn test_rpc_send_tx_non_string_response() {
    let url = mock_rpc_server(&jsonrpc_ok("12345")).await;
    let client = RpcClient::new(&url);

    let (sk, pk) = test_signing_key();
    let tx = TransactionBuilder::new()
        .from(pk)
        .to(Some(Address([0x11; 20])))
        .value(U256::from(100))
        .build_and_sign(&sk)
        .unwrap();

    let err = client.send_transaction(tx).await.unwrap_err();
    match err {
        WalletError::Rpc(msg) => assert!(msg.contains("Invalid transaction hash response")),
        e => panic!("Expected Rpc error, got {:?}", e),
    }
}

#[tokio::test]
async fn test_rpc_send_tx_invalid_hex_in_hash() {
    let url = mock_rpc_server(&jsonrpc_ok_str("0xZZZZZZZZ")).await;
    let client = RpcClient::new(&url);

    let (sk, pk) = test_signing_key();
    let tx = TransactionBuilder::new()
        .from(pk)
        .to(Some(Address([0x11; 20])))
        .value(U256::from(100))
        .build_and_sign(&sk)
        .unwrap();

    let err = client.send_transaction(tx).await.unwrap_err();
    match err {
        WalletError::Rpc(msg) => assert!(msg.contains("Failed to parse tx hash")),
        e => panic!("Expected Rpc error, got {:?}", e),
    }
}

// ============================================================================
// RPC Client: get_transaction_receipt parsing tests
// ============================================================================

#[tokio::test]
async fn test_rpc_receipt_null_returns_none() {
    let url = mock_rpc_server(&jsonrpc_ok("null")).await;
    let client = RpcClient::new(&url);
    let result = client
        .get_transaction_receipt(&Hash::new([0x11; 32]))
        .await
        .unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_rpc_receipt_object_returns_some() {
    let url = mock_rpc_server(&jsonrpc_ok(r#"{"status":"0x1","blockNumber":"0x10"}"#)).await;
    let client = RpcClient::new(&url);
    let result = client
        .get_transaction_receipt(&Hash::new([0x11; 32]))
        .await
        .unwrap();
    assert!(result.is_some());
    let receipt = result.unwrap();
    assert_eq!(receipt["status"], "0x1");
    assert_eq!(receipt["blockNumber"], "0x10");
}

// ============================================================================
// RPC Client: JSON-RPC error handling
// ============================================================================

#[tokio::test]
async fn test_rpc_error_response_returns_error() {
    let url = mock_rpc_server(&jsonrpc_error(-32000, "execution reverted")).await;
    let client = RpcClient::new(&url);
    let err = client.get_balance(&Address([0x11; 20])).await.unwrap_err();
    match err {
        WalletError::Rpc(msg) => {
            assert!(msg.contains("-32000"), "Expected error code, got: {}", msg);
            assert!(
                msg.contains("execution reverted"),
                "Expected error message, got: {}",
                msg
            );
        }
        e => panic!("Expected Rpc error, got {:?}", e),
    }
}

#[tokio::test]
async fn test_rpc_error_method_not_found() {
    let url = mock_rpc_server(&jsonrpc_error(-32601, "Method not found")).await;
    let client = RpcClient::new(&url);
    let err = client.get_chain_id().await.unwrap_err();
    match err {
        WalletError::Rpc(msg) => assert!(msg.contains("Method not found")),
        e => panic!("Expected Rpc error, got {:?}", e),
    }
}

// ============================================================================
// RPC Client: empty-string hex edge case
// ============================================================================

#[tokio::test]
async fn test_rpc_balance_empty_string() {
    // Empty string -> trim_start_matches("0x") -> "" -> from_str_radix("", 16) => Ok(0)
    let url = mock_rpc_server(&jsonrpc_ok_str("")).await;
    let client = RpcClient::new(&url);
    let balance = client.get_balance(&Address([0x11; 20])).await.unwrap();
    assert_eq!(balance, U256::zero());
}

#[tokio::test]
async fn test_rpc_nonce_empty_string() {
    // Empty string -> trim_start_matches("0x") -> "" -> u64::from_str_radix("", 16) => Err
    let url = mock_rpc_server(&jsonrpc_ok_str("")).await;
    let client = RpcClient::new(&url);
    let err = client.get_nonce(&Address([0x11; 20])).await.unwrap_err();
    match err {
        WalletError::Rpc(msg) => assert!(msg.contains("Failed to parse nonce")),
        e => panic!("Expected Rpc error, got {:?}", e),
    }
}

// ============================================================================
// Wallet: format_latt tested indirectly via InsufficientBalance error
// ============================================================================

#[tokio::test]
async fn test_insufficient_balance_formats_whole_numbers() {
    let (_dir, mut wallet) = temp_wallet();
    wallet.create_account("pw", None).unwrap();
    wallet.unlock("pw").unwrap();

    // Account has zero balance; sending 1 wei + gas cost triggers error
    let err = wallet
        .send_transaction(0, Address([0x11; 20]), U256::from(1), vec![], None, None)
        .await
        .unwrap_err();

    match err {
        WalletError::InsufficientBalance { need, have } => {
            // have should be "0" (zero balance)
            assert_eq!(have, "0");
            // need should be > 0 (value + gas cost)
            assert!(!need.is_empty());
        }
        e => panic!("Expected InsufficientBalance, got {:?}", e),
    }
}

#[tokio::test]
async fn test_insufficient_balance_with_custom_gas() {
    let (_dir, mut wallet) = temp_wallet();
    wallet.create_account("pw", None).unwrap();
    wallet.unlock("pw").unwrap();

    let err = wallet
        .send_transaction(
            0,
            Address([0x11; 20]),
            U256::from(0),
            vec![],
            Some(2_000_000_000), // custom gas price
            Some(50_000),        // custom gas limit
        )
        .await
        .unwrap_err();

    match err {
        WalletError::InsufficientBalance { need, have } => {
            assert_eq!(have, "0");
            // gas_cost = 2e9 * 50000 = 1e14 = 0.0001 SALT
            assert!(need.contains("0.0001"), "Expected 0.0001, got: {}", need);
        }
        e => panic!("Expected InsufficientBalance, got {:?}", e),
    }
}

// ============================================================================
// Wallet: update_balances with mock server
// ============================================================================

#[tokio::test]
async fn test_wallet_update_balances_from_rpc() {
    // Server needs to respond to get_balance and get_nonce for one account
    let responses = vec![
        jsonrpc_ok_str("0xde0b6b3a7640000"), // balance = 1 ETH
        jsonrpc_ok_str("0x5"),                // nonce = 5
    ];
    let url = mock_rpc_server_multi(responses).await;
    let (_dir, mut wallet) = temp_wallet_at(&url);
    wallet.create_account("pw", None).unwrap();

    wallet.update_balances().await.unwrap();

    let account = wallet.get_account(0).unwrap();
    assert_eq!(account.balance, U256::from(10u64.pow(18)));
    assert_eq!(account.nonce, 5);
}

#[tokio::test]
async fn test_wallet_update_balances_empty_accounts() {
    // No accounts => no RPC calls needed, should succeed trivially
    let (_dir, mut wallet) = temp_wallet();
    wallet.update_balances().await.unwrap();
    assert!(wallet.list_accounts().is_empty());
}

// ============================================================================
// Wallet: account management edge cases
// ============================================================================

#[test]
fn test_wallet_create_multiple_then_get_by_address() {
    let (_dir, mut wallet) = temp_wallet();
    let a0 = wallet.create_account("pw", Some("first".into())).unwrap();
    let a1 = wallet.create_account("pw", Some("second".into())).unwrap();
    let a2 = wallet.create_account("pw", None).unwrap();

    // Get each by address
    let found0 = wallet.get_account_by_address(&a0.address).unwrap();
    assert_eq!(found0.alias, Some("first".into()));
    let found1 = wallet.get_account_by_address(&a1.address).unwrap();
    assert_eq!(found1.alias, Some("second".into()));
    let found2 = wallet.get_account_by_address(&a2.address).unwrap();
    assert!(found2.alias.is_none());
}

#[test]
fn test_wallet_get_account_out_of_range_large_index() {
    let (_dir, mut wallet) = temp_wallet();
    wallet.create_account("pw", None).unwrap();
    assert!(wallet.get_account(usize::MAX).is_none());
}

#[test]
fn test_wallet_config_fields_accessible() {
    let (_dir, wallet) = temp_wallet();
    let cfg = wallet.config();
    assert_eq!(cfg.chain_id, 40204);
    assert_eq!(cfg.default_gas_price, 1_000_000_000);
    assert_eq!(cfg.default_gas_limit, 21_000);
    assert!(cfg.keystore_path.to_string_lossy().contains("keystore.json"));
}

#[test]
fn test_wallet_rpc_client_url() {
    let (_dir, wallet) = temp_wallet();
    // Just verify rpc_client() does not panic and returns a reference
    let _rpc = wallet.rpc_client();
}

// ============================================================================
// Wallet: transfer is alias for send_transaction
// ============================================================================

#[tokio::test]
async fn test_wallet_transfer_account_not_found() {
    let (_dir, wallet) = temp_wallet();
    let err = wallet
        .transfer(0, Address([0x11; 20]), U256::from(100))
        .await
        .unwrap_err();
    match err {
        WalletError::AccountNotFound(_) => {}
        e => panic!("Expected AccountNotFound, got {:?}", e),
    }
}

#[tokio::test]
async fn test_wallet_transfer_insufficient_balance() {
    let (_dir, mut wallet) = temp_wallet();
    wallet.create_account("pw", None).unwrap();
    wallet.unlock("pw").unwrap();

    let err = wallet
        .transfer(0, Address([0x11; 20]), U256::from(1))
        .await
        .unwrap_err();
    match err {
        WalletError::InsufficientBalance { .. } => {}
        e => panic!("Expected InsufficientBalance, got {:?}", e),
    }
}

// ============================================================================
// Wallet: get_transaction_receipt delegates to rpc_client
// ============================================================================

#[tokio::test]
async fn test_wallet_get_receipt_delegates() {
    let url = mock_rpc_server(&jsonrpc_ok("null")).await;
    let (_dir, wallet) = temp_wallet_at(&url);
    let result = wallet
        .get_transaction_receipt(&Hash::new([0xAA; 32]))
        .await
        .unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_wallet_get_receipt_with_data() {
    let url =
        mock_rpc_server(&jsonrpc_ok(r#"{"status":"0x1","gasUsed":"0x5208"}"#)).await;
    let (_dir, wallet) = temp_wallet_at(&url);
    let result = wallet
        .get_transaction_receipt(&Hash::new([0xBB; 32]))
        .await
        .unwrap();
    assert!(result.is_some());
}

// ============================================================================
// Wallet: send_transaction locked wallet path
// ============================================================================

#[tokio::test]
async fn test_wallet_send_tx_while_locked() {
    let (_dir, mut wallet) = temp_wallet();
    wallet.create_account("pw", None).unwrap();
    // Do NOT unlock => sending should fail at get_signing_key
    // But first it hits the balance check (account balance=0, value=0, gas cost > 0)
    let err = wallet
        .send_transaction(0, Address([0x11; 20]), U256::from(0), vec![], None, None)
        .await
        .unwrap_err();
    // Gas cost makes total_cost > 0 > account.balance(0)
    match err {
        WalletError::InsufficientBalance { .. } => {}
        e => panic!("Expected InsufficientBalance, got {:?}", e),
    }
}

// ============================================================================
// Account struct additional tests
// ============================================================================

#[test]
fn test_account_debug_format() {
    let account = Account {
        index: 0,
        address: Address([0x11; 20]),
        public_key: PublicKey::new([0x22; 32]),
        alias: Some("debug-test".into()),
        balance: U256::from(42),
        nonce: 7,
    };
    let debug = format!("{:?}", account);
    assert!(debug.contains("debug-test"));
    assert!(debug.contains("42"));
    assert!(debug.contains("7"));
}

#[test]
fn test_account_clone() {
    let account = Account {
        index: 5,
        address: Address([0x33; 20]),
        public_key: PublicKey::new([0x44; 32]),
        alias: Some("clone-test".into()),
        balance: U256::from(999),
        nonce: 3,
    };
    let cloned = account.clone();
    assert_eq!(cloned.index, 5);
    assert_eq!(cloned.alias, Some("clone-test".into()));
    assert_eq!(cloned.balance, U256::from(999));
    assert_eq!(cloned.nonce, 3);
}

// ============================================================================
// WalletConfig additional tests
// ============================================================================

#[test]
fn test_wallet_config_debug_format() {
    let config = WalletConfig {
        keystore_path: PathBuf::from("/tmp/test.json"),
        rpc_url: "http://localhost:9999".into(),
        chain_id: 40204,
        default_gas_price: 5_000_000_000,
        default_gas_limit: 100_000,
    };
    let debug = format!("{:?}", config);
    assert!(debug.contains("40204"));
    assert!(debug.contains("9999"));
}

#[test]
fn test_wallet_config_clone() {
    let config = WalletConfig {
        keystore_path: PathBuf::from("/tmp/clone.json"),
        rpc_url: "http://example.com:8545".into(),
        chain_id: 42,
        default_gas_price: 3_000_000_000,
        default_gas_limit: 30_000,
    };
    let cloned = config.clone();
    assert_eq!(cloned.chain_id, 42);
    assert_eq!(cloned.rpc_url, "http://example.com:8545");
    assert_eq!(cloned.default_gas_price, 3_000_000_000);
}

// ============================================================================
// RPC Client: request ID increments
// ============================================================================

#[tokio::test]
async fn test_rpc_client_request_id_increments() {
    // Two sequential requests should work (internally incrementing request id)
    let responses = vec![
        jsonrpc_ok_str("0x1"),
        jsonrpc_ok_str("0x2"),
    ];
    let url = mock_rpc_server_multi(responses).await;
    let client = RpcClient::new(&url);

    let block1 = client.get_block_number().await.unwrap();
    assert_eq!(block1, 1);
    let block2 = client.get_block_number().await.unwrap();
    assert_eq!(block2, 2);
}

// ============================================================================
// RPC Client: balance with only "0x" prefix (edge case: "0x" alone)
// ============================================================================

#[tokio::test]
async fn test_rpc_balance_just_0x_prefix() {
    // "0x" with nothing after it => trim to "" => from_str_radix("", 16) => Ok(0)
    let url = mock_rpc_server(&jsonrpc_ok_str("0x")).await;
    let client = RpcClient::new(&url);
    let balance = client.get_balance(&Address([0x11; 20])).await.unwrap();
    assert_eq!(balance, U256::zero());
}
