// WP-Y.7: Adversarial RPC Input Tests
//
// These integration tests exercise JSON-RPC protocol-level error handling for
// malformed, invalid, and adversarial inputs. They use jsonrpc-core's IoHandler
// directly (no full node stack required) to verify that the protocol layer
// rejects bad requests with correct error codes and messages.
//
// JSON-RPC 2.0 error codes:
//   -32700  Parse error
//   -32600  Invalid Request
//   -32601  Method not found
//   -32602  Invalid params
//   -32603  Internal error
//
// Test inventory:
//   1. test_malformed_jsonrpc_missing_method
//   2. test_malformed_jsonrpc_missing_jsonrpc
//   3. test_malformed_jsonrpc_null_id
//   4. test_invalid_hex_odd_length
//   5. test_invalid_hex_non_hex_chars
//   6. test_invalid_hex_missing_prefix
//   7. test_empty_params
//   8. test_unknown_method

use jsonrpc_core::{IoHandler, Params, Value};
use serde_json::json;

// ---------------------------------------------------------------------------
// Helper: Build an IoHandler with a synthetic "test_echo" method that validates
// hex-encoded params and echoes them back. This lets us test protocol-level
// behavior without standing up the full Citrate RPC stack.
// ---------------------------------------------------------------------------

fn build_test_handler() -> IoHandler {
    let mut handler = IoHandler::new();

    // "test_echo" — expects a single hex-encoded string param (0x-prefixed).
    // Returns the decoded byte length on success, or a JSON-RPC error on
    // invalid input.
    handler.add_sync_method("test_echo", |params: Params| {
        let values: Vec<Value> = params.parse().map_err(|_| {
            jsonrpc_core::Error {
                code: jsonrpc_core::ErrorCode::InvalidParams,
                message: "Expected array of params".into(),
                data: None,
            }
        })?;

        if values.is_empty() {
            return Ok(Value::String("no params".into()));
        }

        let hex_str = values[0].as_str().ok_or_else(|| jsonrpc_core::Error {
            code: jsonrpc_core::ErrorCode::InvalidParams,
            message: "Param must be a string".into(),
            data: None,
        })?;

        // Require 0x prefix
        let stripped = hex_str.strip_prefix("0x").ok_or_else(|| jsonrpc_core::Error {
            code: jsonrpc_core::ErrorCode::InvalidParams,
            message: "Hex param must start with 0x".into(),
            data: None,
        })?;

        // Reject odd-length hex
        if stripped.len() % 2 != 0 {
            return Err(jsonrpc_core::Error {
                code: jsonrpc_core::ErrorCode::InvalidParams,
                message: "Hex string has odd length".into(),
                data: None,
            });
        }

        // Decode hex — will fail on non-hex characters
        let bytes = hex::decode(stripped).map_err(|e| jsonrpc_core::Error {
            code: jsonrpc_core::ErrorCode::InvalidParams,
            message: format!("Invalid hex: {}", e),
            data: None,
        })?;

        Ok(Value::Number(serde_json::Number::from(bytes.len())))
    });

    handler
}

/// Sends a raw JSON string to the handler and returns the parsed response.
fn send_raw(handler: &IoHandler, request: &str) -> Option<serde_json::Value> {
    let response = handler.handle_request_sync(request)?;
    serde_json::from_str(&response).ok()
}

// ===========================================================================
// Test 1: Missing "method" field
// ===========================================================================
#[test]
fn test_malformed_jsonrpc_missing_method() {
    let handler = build_test_handler();

    // A JSON-RPC request MUST have a "method" field. Omitting it should
    // produce an "Invalid Request" error (-32600).
    let request = r#"{"jsonrpc":"2.0","id":1,"params":[]}"#;
    let resp = send_raw(&handler, request).expect("should return a response");

    let error = resp.get("error").expect("response should contain error");
    let code = error.get("code").and_then(|c| c.as_i64()).unwrap();
    assert_eq!(code, -32600, "Missing method should produce Invalid Request (-32600)");
}

// ===========================================================================
// Test 2: Missing "jsonrpc" version field
// ===========================================================================
#[test]
fn test_malformed_jsonrpc_missing_jsonrpc() {
    let handler = build_test_handler();

    // Omitting the "jsonrpc":"2.0" field violates the protocol spec.
    // jsonrpc-core 18 still processes it but the behavior is implementation-defined.
    let request = r#"{"method":"test_echo","id":1,"params":["0xabcd"]}"#;
    let resp = send_raw(&handler, request).expect("should return a response");

    // jsonrpc-core 18 accepts requests without the jsonrpc field but may set
    // the response version to None. We verify it either returns a result
    // (lenient parsing) or an error — both are acceptable as long as no panic.
    assert!(
        resp.get("result").is_some() || resp.get("error").is_some(),
        "Response must contain either result or error, got: {:?}",
        resp
    );
}

// ===========================================================================
// Test 3: Null id field
// ===========================================================================
#[test]
fn test_malformed_jsonrpc_null_id() {
    let handler = build_test_handler();

    // JSON-RPC allows id to be null (it becomes a notification if absent,
    // but null id is technically valid for requests). jsonrpc-core should
    // still process the request and return a response with id: null.
    let request = r#"{"jsonrpc":"2.0","method":"test_echo","id":null,"params":["0xabcd"]}"#;
    let resp = send_raw(&handler, request).expect("should return a response");

    // Should successfully process since test_echo is registered
    assert!(
        resp.get("result").is_some(),
        "Null id request should still be processed; got: {:?}",
        resp
    );

    // The response id should be null to match the request
    let resp_id = resp.get("id").expect("response should have id field");
    assert!(resp_id.is_null(), "Response id should be null, got: {:?}", resp_id);
}

// ===========================================================================
// Test 4: Odd-length hex string
// ===========================================================================
#[test]
fn test_invalid_hex_odd_length() {
    let handler = build_test_handler();

    // "0xabc" is 3 hex chars — odd length, cannot decode to whole bytes.
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "test_echo",
        "params": ["0xabc"]
    })
    .to_string();

    let resp = send_raw(&handler, &request).expect("should return a response");
    let error = resp.get("error").expect("should return an error for odd-length hex");
    let code = error.get("code").and_then(|c| c.as_i64()).unwrap();
    assert_eq!(code, -32602, "Odd-length hex should produce Invalid Params (-32602)");

    let message = error.get("message").and_then(|m| m.as_str()).unwrap();
    assert!(
        message.contains("odd length"),
        "Error message should mention odd length, got: {}",
        message
    );
}

// ===========================================================================
// Test 5: Non-hex characters in hex param
// ===========================================================================
#[test]
fn test_invalid_hex_non_hex_chars() {
    let handler = build_test_handler();

    // "0xGGGG" contains 'G' which is not a valid hex digit.
    let request = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "test_echo",
        "params": ["0xGGGG"]
    })
    .to_string();

    let resp = send_raw(&handler, &request).expect("should return a response");
    let error = resp.get("error").expect("should return an error for non-hex chars");
    let code = error.get("code").and_then(|c| c.as_i64()).unwrap();
    assert_eq!(code, -32602, "Non-hex chars should produce Invalid Params (-32602)");

    let message = error.get("message").and_then(|m| m.as_str()).unwrap();
    assert!(
        message.contains("Invalid hex"),
        "Error message should mention invalid hex, got: {}",
        message
    );
}

// ===========================================================================
// Test 6: Hex param without 0x prefix
// ===========================================================================
#[test]
fn test_invalid_hex_missing_prefix() {
    let handler = build_test_handler();

    // "abcd" is valid hex but lacks the required "0x" prefix.
    let request = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "test_echo",
        "params": ["abcd"]
    })
    .to_string();

    let resp = send_raw(&handler, &request).expect("should return a response");
    let error = resp.get("error").expect("should return an error for missing 0x prefix");
    let code = error.get("code").and_then(|c| c.as_i64()).unwrap();
    assert_eq!(code, -32602, "Missing 0x prefix should produce Invalid Params (-32602)");

    let message = error.get("message").and_then(|m| m.as_str()).unwrap();
    assert!(
        message.contains("0x"),
        "Error message should mention 0x prefix requirement, got: {}",
        message
    );
}

// ===========================================================================
// Test 7: Empty params array
// ===========================================================================
#[test]
fn test_empty_params() {
    let handler = build_test_handler();

    // Calling test_echo with an empty params array should be handled
    // gracefully — not crash or produce a protocol error.
    let request = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "test_echo",
        "params": []
    })
    .to_string();

    let resp = send_raw(&handler, &request).expect("should return a response");

    // Our test_echo handler returns "no params" for empty arrays.
    let result = resp.get("result").expect("empty params should produce a result, not an error");
    assert_eq!(
        result.as_str().unwrap(),
        "no params",
        "Empty params should return 'no params' sentinel"
    );
}

// ===========================================================================
// Test 8: Unknown / nonexistent method
// ===========================================================================
#[test]
fn test_unknown_method() {
    let handler = build_test_handler();

    // Calling a method that does not exist on the handler should return
    // "Method not found" error (-32601).
    let request = json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "eth_totallyFakeMethod",
        "params": []
    })
    .to_string();

    let resp = send_raw(&handler, &request).expect("should return a response");
    let error = resp.get("error").expect("unknown method should return an error");
    let code = error.get("code").and_then(|c| c.as_i64()).unwrap();
    assert_eq!(code, -32601, "Unknown method should produce Method Not Found (-32601)");
}
