//! Typed JSON-RPC client.
//!
//! Thin wrapper over `reqwest::Client` that exposes the handful of
//! eth_* methods citrate-bench actually uses. Returning typed values
//! (instead of `serde_json::Value`) keeps the runner and tracker
//! honest about the shape of what they're consuming.
//!
//! Cheap to clone: the underlying `reqwest::Client` is Arc-backed.

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::{Error, Result};

/// What the RPC told us about a submission.
#[derive(Debug, Clone)]
pub enum SendRawOutcome {
    /// Transaction accepted into the mempool. Hash returned by the
    /// node is the 32-byte tx hash (hex-encoded, 0x-prefixed).
    Accepted(String),
    /// RPC returned a JSON-RPC error. The string is a compact
    /// classification suitable for the "by_reason" histogram.
    Rejected { code: i64, message: String },
}

/// Receipt summary. Fields we care about for benchmarking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptSummary {
    #[serde(rename = "transactionHash")]
    pub tx_hash: String,
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    #[serde(rename = "status")]
    pub status: Option<String>,
    #[serde(rename = "gasUsed")]
    pub gas_used: Option<String>,
}

impl ReceiptSummary {
    /// Parse `blockNumber` (hex) as a u64. Unparseable → 0.
    pub fn block_number_u64(&self) -> u64 {
        parse_hex_u64(&self.block_number).unwrap_or(0)
    }

    /// True if `status` equals `"0x1"`. Missing status (pre-Byzantium
    /// nodes) defaults to true because Citrate always sets it.
    pub fn succeeded(&self) -> bool {
        match self.status.as_deref() {
            None => true,
            Some(s) => s.eq_ignore_ascii_case("0x1"),
        }
    }
}

#[derive(Clone)]
pub struct RpcClient {
    http: reqwest::Client,
    url: String,
}

impl RpcClient {
    pub fn new(url: impl Into<String>, timeout: Duration) -> Result<Self> {
        let http = reqwest::Client::builder()
            .pool_max_idle_per_host(256)
            .tcp_keepalive(Duration::from_secs(30))
            .timeout(timeout)
            .build()
            .map_err(|e| Error::RpcHttp(format!("build client: {e}")))?;
        Ok(Self {
            http,
            url: url.into(),
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    async fn call_raw(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let resp = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::RpcHttp(format!("{method} send: {e}")))?;
        if !resp.status().is_success() {
            return Err(Error::RpcHttp(format!(
                "{method}: HTTP {}",
                resp.status()
            )));
        }
        let val: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| Error::RpcHttp(format!("{method} parse body: {e}")))?;
        Ok(val)
    }

    /// Generic JSON-RPC call. Returns `Ok(result)` on success, or
    /// `Err(Error::Rpc(...))` on a JSON-RPC error object.
    async fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let val = self.call_raw(method, params).await?;
        if let Some(err) = val.get("error") {
            let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
            let msg = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown")
                .to_string();
            return Err(Error::Rpc(format!("{method} (code {code}): {msg}")));
        }
        val.get("result")
            .cloned()
            .ok_or_else(|| Error::Rpc(format!("{method}: no result field")))
    }

    pub async fn chain_id(&self) -> Result<u64> {
        let v = self.call("eth_chainId", serde_json::json!([])).await?;
        let s = v
            .as_str()
            .ok_or_else(|| Error::Rpc("eth_chainId: result not string".into()))?;
        parse_hex_u64(s)
            .ok_or_else(|| Error::Rpc(format!("eth_chainId: unparseable hex: {s}")))
    }

    pub async fn block_number(&self) -> Result<u64> {
        let v = self.call("eth_blockNumber", serde_json::json!([])).await?;
        let s = v
            .as_str()
            .ok_or_else(|| Error::Rpc("eth_blockNumber: result not string".into()))?;
        parse_hex_u64(s)
            .ok_or_else(|| Error::Rpc(format!("eth_blockNumber: unparseable hex: {s}")))
    }

    pub async fn get_transaction_count(&self, address_hex: &str, tag: &str) -> Result<u64> {
        let v = self
            .call(
                "eth_getTransactionCount",
                serde_json::json!([address_hex, tag]),
            )
            .await?;
        let s = v
            .as_str()
            .ok_or_else(|| Error::Rpc("eth_getTransactionCount: result not string".into()))?;
        parse_hex_u64(s)
            .ok_or_else(|| Error::Rpc(format!("eth_getTransactionCount: unparseable hex: {s}")))
    }

    pub async fn get_balance(&self, address_hex: &str, tag: &str) -> Result<u128> {
        let v = self
            .call("eth_getBalance", serde_json::json!([address_hex, tag]))
            .await?;
        let s = v
            .as_str()
            .ok_or_else(|| Error::Rpc("eth_getBalance: result not string".into()))?;
        parse_hex_u128(s).ok_or_else(|| Error::Rpc(format!("eth_getBalance: unparseable hex: {s}")))
    }

    /// Submit a signed transaction. Returns a `SendRawOutcome` instead
    /// of propagating RPC errors up as `Error`, because a rejection
    /// is a normal outcome the runner wants to classify.
    pub async fn send_raw_transaction(&self, raw_hex: &str) -> Result<SendRawOutcome> {
        let val = self
            .call_raw("eth_sendRawTransaction", serde_json::json!([raw_hex]))
            .await?;
        if let Some(err) = val.get("error") {
            let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
            let msg = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown")
                .to_string();
            return Ok(SendRawOutcome::Rejected { code, message: msg });
        }
        let hash = val
            .get("result")
            .and_then(|r| r.as_str())
            .ok_or_else(|| Error::Rpc("eth_sendRawTransaction: no result".into()))?
            .to_string();
        Ok(SendRawOutcome::Accepted(hash))
    }

    /// Fetch the receipt for a transaction. `Ok(None)` when the node
    /// returns `result: null` (not yet mined); `Ok(Some)` when mined;
    /// `Err` only on transport or decode failure.
    pub async fn get_transaction_receipt(&self, hash: &str) -> Result<Option<ReceiptSummary>> {
        let val = self
            .call_raw("eth_getTransactionReceipt", serde_json::json!([hash]))
            .await?;
        if let Some(err) = val.get("error") {
            let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
            let msg = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown")
                .to_string();
            return Err(Error::Rpc(format!(
                "eth_getTransactionReceipt (code {code}): {msg}"
            )));
        }
        let result = val.get("result").cloned().unwrap_or(serde_json::Value::Null);
        if result.is_null() {
            return Ok(None);
        }
        let summary: ReceiptSummary = serde_json::from_value(result)?;
        Ok(Some(summary))
    }
}

fn parse_hex_u64(s: &str) -> Option<u64> {
    let stripped = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if stripped.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(stripped, 16).ok()
}

fn parse_hex_u128(s: &str) -> Option<u128> {
    let stripped = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if stripped.is_empty() {
        return Some(0);
    }
    u128::from_str_radix(stripped, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn body_method(req: &mockito::Request) -> Option<String> {
        let body = req.body().map(|b| b.to_vec()).unwrap_or_default();
        let v: serde_json::Value = serde_json::from_slice(&body).ok()?;
        v.get("method").and_then(|m| m.as_str()).map(String::from)
    }

    async fn fresh_client(url: &str) -> RpcClient {
        RpcClient::new(url, Duration::from_secs(5)).expect("client")
    }

    #[tokio::test]
    async fn chain_id_parses_hex() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::PartialJson(json!({"method": "eth_chainId"})))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"jsonrpc":"2.0","id":1,"result":"0x9d0c"}"#)
            .create_async()
            .await;
        let client = fresh_client(&server.url()).await;
        assert_eq!(client.chain_id().await.expect("chain_id"), 0x9d0c);
    }

    #[tokio::test]
    async fn block_number_parses_hex() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::PartialJson(json!({"method": "eth_blockNumber"})))
            .with_status(200)
            .with_body(r#"{"jsonrpc":"2.0","id":1,"result":"0x2a"}"#)
            .create_async()
            .await;
        let client = fresh_client(&server.url()).await;
        assert_eq!(client.block_number().await.expect("bn"), 42);
    }

    #[tokio::test]
    async fn get_transaction_count_parses() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::PartialJson(
                json!({"method": "eth_getTransactionCount"}),
            ))
            .with_status(200)
            .with_body(r#"{"jsonrpc":"2.0","id":1,"result":"0x7"}"#)
            .create_async()
            .await;
        let client = fresh_client(&server.url()).await;
        assert_eq!(
            client
                .get_transaction_count("0x0000000000000000000000000000000000000001", "latest")
                .await
                .expect("nonce"),
            7
        );
    }

    #[tokio::test]
    async fn send_raw_accepted_returns_hash() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(r#"{"jsonrpc":"2.0","id":1,"result":"0xabcdef"}"#)
            .create_async()
            .await;
        let client = fresh_client(&server.url()).await;
        match client.send_raw_transaction("0xdeadbeef").await.expect("send") {
            SendRawOutcome::Accepted(h) => assert_eq!(h, "0xabcdef"),
            other => panic!("expected Accepted, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_raw_rejected_classified() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"nonce too low"}}"#,
            )
            .create_async()
            .await;
        let client = fresh_client(&server.url()).await;
        match client.send_raw_transaction("0xdeadbeef").await.expect("send") {
            SendRawOutcome::Rejected { code, message } => {
                assert_eq!(code, -32000);
                assert!(message.contains("nonce too low"));
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_receipt_null_returns_none() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(r#"{"jsonrpc":"2.0","id":1,"result":null}"#)
            .create_async()
            .await;
        let client = fresh_client(&server.url()).await;
        assert!(client
            .get_transaction_receipt("0xaa")
            .await
            .expect("receipt")
            .is_none());
    }

    #[tokio::test]
    async fn get_receipt_success_parses() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(
                r#"{"jsonrpc":"2.0","id":1,"result":{"transactionHash":"0xaa","blockNumber":"0x15","status":"0x1","gasUsed":"0x5208"}}"#,
            )
            .create_async()
            .await;
        let client = fresh_client(&server.url()).await;
        let r = client
            .get_transaction_receipt("0xaa")
            .await
            .expect("receipt")
            .expect("some");
        assert_eq!(r.tx_hash, "0xaa");
        assert_eq!(r.block_number_u64(), 0x15);
        assert!(r.succeeded());
    }

    #[tokio::test]
    async fn http_error_propagates() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/")
            .with_status(500)
            .with_body("internal server error")
            .create_async()
            .await;
        let client = fresh_client(&server.url()).await;
        assert!(client.chain_id().await.is_err());
    }

    #[test]
    fn parse_hex_helpers() {
        assert_eq!(parse_hex_u64("0x1a"), Some(26));
        assert_eq!(parse_hex_u64("1a"), Some(26));
        assert_eq!(parse_hex_u64("0x"), Some(0));
        assert_eq!(parse_hex_u64("0xzz"), None);
        assert_eq!(parse_hex_u128("0xffffffffffffffffffffffffffffffff"), Some(u128::MAX));
    }

    // Unused helper kept only to silence warnings if mockito versions change.
    #[allow(dead_code)]
    fn _body_method_helper(req: &mockito::Request) -> Option<String> {
        body_method(req)
    }
}
