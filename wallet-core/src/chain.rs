//! Blockchain transaction building, signing, and RPC communication.
//!
//! Imports types from citrate-consensus (PublicKey, Hash, Transaction, Signature)
//! as read-only dependencies. Does NOT modify chain crates.

use crate::error::WalletError;
use ed25519_dalek::SigningKey;
use sha3::{Digest, Keccak256};
use std::sync::atomic::{AtomicU64, Ordering};

/// Transaction builder with fluent API.
pub struct TransactionBuilder {
    to: Option<String>,
    value: u128,
    data: Vec<u8>,
    nonce: Option<u64>,
    gas_price: u64,
    gas_limit: u64,
    chain_id: u64,
}

impl TransactionBuilder {
    pub fn new() -> Self {
        Self {
            to: None,
            value: 0,
            data: Vec::new(),
            nonce: None,
            gas_price: 1_000_000_000, // 1 Gwei
            gas_limit: 21_000,
            chain_id: 40204,
        }
    }

    pub fn to(mut self, address: &str) -> Self {
        self.to = Some(address.to_string());
        self
    }

    pub fn value(mut self, wei: u128) -> Self {
        self.value = wei;
        self
    }

    pub fn data(mut self, payload: Vec<u8>) -> Self {
        self.data = payload;
        self
    }

    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = Some(nonce);
        self
    }

    pub fn gas_price(mut self, gwei: u64) -> Self {
        self.gas_price = gwei;
        self
    }

    pub fn gas_limit(mut self, limit: u64) -> Self {
        self.gas_limit = limit;
        self
    }

    pub fn chain_id(mut self, id: u64) -> Self {
        self.chain_id = id;
        self
    }

    /// RLP-encode the unsigned legacy transaction per EIP-155:
    /// [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0].
    ///
    /// B1.4.0: production secp256k1 signing now routes through the lean
    /// [`crate::tx`] module. This helper is retained only for the pinned
    /// spec-vector test that validates the native builder's payload
    /// construction, hence `#[cfg(test)]`.
    #[cfg(test)]
    fn eip155_signing_payload(&self, nonce: u64) -> Result<Vec<u8>, WalletError> {
        let mut stream = rlp::RlpStream::new_list(9);
        stream.append(&nonce);
        stream.append(&self.gas_price);
        stream.append(&self.gas_limit);
        self.append_to_address(&mut stream)?;
        stream.append(&self.value);
        stream.append(&self.data.as_slice());
        stream.append(&self.chain_id);
        stream.append(&0u8);
        stream.append(&0u8);
        Ok(stream.out().to_vec())
    }

    /// Build the canonical EIP-155 signing hash. `#[cfg(test)]`: see
    /// `eip155_signing_payload`.
    #[cfg(test)]
    fn eip155_signing_hash(&self, nonce: u64) -> Result<[u8; 32], WalletError> {
        let signing_payload = self.eip155_signing_payload(nonce)?;
        let mut hasher = Keccak256::new();
        hasher.update(signing_payload);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        Ok(hash)
    }

    /// RLP-append the `to` field. `#[cfg(test)]`: only the retained
    /// spec-vector test exercises the native builder's own payload path
    /// now; production goes through [`crate::tx`].
    #[cfg(test)]
    fn append_to_address(&self, stream: &mut rlp::RlpStream) -> Result<(), WalletError> {
        if let Some(ref to) = self.to {
            let to_clean = to.strip_prefix("0x").unwrap_or(to);
            let to_bytes = hex::decode(to_clean)
                .map_err(|e| WalletError::InvalidAddress(format!("invalid hex: {}", e)))?;
            if to_bytes.len() != 20 {
                return Err(WalletError::InvalidAddress(format!(
                    "expected 20-byte EVM address, got {} bytes",
                    to_bytes.len()
                )));
            }
            stream.append(&to_bytes.as_slice());
        } else {
            stream.append(&Vec::<u8>::new().as_slice());
        }
        Ok(())
    }

    /// Parse `self.to` into a fixed 20-byte EVM address, or `None` for
    /// contract creation. Rejects a present-but-malformed address (same
    /// validation as `append_to_address`).
    fn to_address_bytes(&self) -> Result<Option<[u8; 20]>, WalletError> {
        match self.to {
            Some(ref to) => {
                let to_clean = to.strip_prefix("0x").unwrap_or(to);
                let to_bytes = hex::decode(to_clean)
                    .map_err(|e| WalletError::InvalidAddress(format!("invalid hex: {}", e)))?;
                if to_bytes.len() != 20 {
                    return Err(WalletError::InvalidAddress(format!(
                        "expected 20-byte EVM address, got {} bytes",
                        to_bytes.len()
                    )));
                }
                let mut addr = [0u8; 20];
                addr.copy_from_slice(&to_bytes);
                Ok(Some(addr))
            }
            None => Ok(None),
        }
    }

    /// Sign the transaction with a secp256k1 key (EVM-compatible ECDSA).
    /// Produces EIP-155 compliant v/r/s signature.
    ///
    /// B1.4.0: delegates the pure EIP-155 signing to the lean
    /// [`crate::tx::sign_eip155_legacy_tx`] primitive so the RLP + v/r/s
    /// logic has a single source of truth shared with the lean `crypto`
    /// build. This method only adds the native builder's `from`-address
    /// derivation and the `SignedTransaction` wrapper.
    pub fn sign_secp256k1(
        self,
        signing_key: &k256::ecdsa::SigningKey,
        nonce: u64,
    ) -> Result<SignedTransaction, WalletError> {
        let fields = crate::tx::LegacyTxFields {
            nonce,
            gas_price: self.gas_price,
            gas_limit: self.gas_limit,
            to: self.to_address_bytes()?,
            value: self.value,
            data: self.data.clone(),
        };

        let signed = crate::tx::sign_eip155_legacy_tx(signing_key, &fields, self.chain_id)?;

        // Derive the EVM address from the public key (display only).
        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes = k256::EncodedPoint::from(verifying_key);
        let pubkey_uncompressed = pubkey_bytes.as_bytes();
        // EVM address = Keccak256(pubkey[1..65])[12..32]
        let mut address_hasher = Keccak256::new();
        address_hasher.update(&pubkey_uncompressed[1..]); // Skip 0x04 prefix
        let address_hash = address_hasher.finalize();
        let from_addr = hex::encode(&address_hash[12..]);

        Ok(SignedTransaction {
            hash: hex::encode(signed.hash),
            from: format!("0x{}", from_addr),
            to: self.to.clone(),
            value: self.value,
            nonce,
            gas_price: self.gas_price,
            gas_limit: self.gas_limit,
            chain_id: self.chain_id,
            data: self.data.clone(),
            signature: format!(
                "v={} r={} s={}",
                signed.v,
                hex::encode(signed.r),
                hex::encode(signed.s)
            ),
            raw: signed.raw,
        })
    }

    /// Sign the transaction with an Ed25519 key. Returns the signed raw bytes.
    ///
    /// The `raw` output is a bincode-serialized `citrate_consensus::types::Transaction`
    /// — the exact format the chain's `eth_tx_decoder` recognizes in its
    /// bincode fallback path. Earlier versions of this function produced a
    /// hand-rolled layout that matched neither RLP nor bincode, so every
    /// ed25519 `eth_sendRawTransaction` call returned "failed to parse
    /// transaction".
    pub fn sign(
        self,
        signing_key: &SigningKey,
        nonce: u64,
    ) -> Result<SignedTransaction, WalletError> {
        self.sign_native(signing_key, nonce, false)
    }

    /// PBA-L4-002: sign with the V2 native preimage, which binds `chain_id`
    /// (and every fee/type field) under a domain tag, so the signature cannot
    /// be replayed on a network with a different chain id. Nodes accept V2
    /// from this release on; the legacy [`Self::sign`] (V1) stays the default
    /// until every supported node version verifies V2, after which the fleet
    /// schedules the V1 sunset.
    pub fn sign_v2(
        self,
        signing_key: &SigningKey,
        nonce: u64,
    ) -> Result<SignedTransaction, WalletError> {
        self.sign_native(signing_key, nonce, true)
    }

    fn sign_native(
        self,
        signing_key: &SigningKey,
        nonce: u64,
        v2: bool,
    ) -> Result<SignedTransaction, WalletError> {
        use citrate_consensus::types as cc_types;

        // Build the chain's Transaction struct.
        let from_pubkey_bytes = signing_key.verifying_key().to_bytes();
        let from_pk = cc_types::PublicKey::new(from_pubkey_bytes);

        let to_pk = if let Some(ref to_hex) = self.to {
            let to_clean = to_hex.strip_prefix("0x").unwrap_or(to_hex);
            let decoded = hex::decode(to_clean)
                .map_err(|e| WalletError::SigningFailed(format!("Invalid 'to' hex: {}", e)))?;
            if decoded.is_empty() {
                None
            } else {
                // 20-byte EVM address → embed in first 20 bytes, zero-pad to 32.
                // 32-byte native pubkey → copy as-is.
                // PBA-L4-004: any other length used to be silently zero-padded
                // (short) or truncated (long) into a DIFFERENT destination and
                // signed. Reject it, exactly like the secp256k1 path does.
                if decoded.len() != 20 && decoded.len() != 32 {
                    return Err(WalletError::InvalidAddress(format!(
                        "recipient must be a 20-byte EVM address or a 32-byte native key, \
                         got {} bytes",
                        decoded.len()
                    )));
                }
                let mut pk_bytes = [0u8; 32];
                pk_bytes[..decoded.len()].copy_from_slice(&decoded);
                Some(cc_types::PublicKey::new(pk_bytes))
            }
        } else {
            None
        };

        let mut tx = cc_types::Transaction {
            hash: cc_types::Hash::default(),
            nonce,
            from: from_pk,
            to: to_pk,
            value: self.value,
            gas_limit: self.gas_limit,
            gas_price: self.gas_price,
            data: self.data.clone(),
            signature: cc_types::Signature::default(),
            tx_type: None,
            eth_tx_type: 0,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list: None,
            chain_id: Some(self.chain_id),
            ecdsa_verified: false,
        };

        // Sign via the chain's canonical byte format so `verify_transaction`
        // on the node side accepts the signature. `sign_transaction` also
        // refreshes `tx.from` from the signing key (defensive).
        if v2 {
            citrate_consensus::crypto::sign_transaction_v2(&mut tx, signing_key)
        } else {
            citrate_consensus::crypto::sign_transaction(&mut tx, signing_key)
        }
        .map_err(|e| WalletError::SigningFailed(format!("ed25519 sign failed: {:?}", e)))?;

        // Hash the signed transaction so `hash` is populated for UI display.
        // The chain may recompute this; it's not authoritative here.
        let mut hasher = Keccak256::new();
        let canonical = bincode::serialize(&tx)
            .map_err(|e| WalletError::SigningFailed(format!("bincode serialize: {}", e)))?;
        hasher.update(&canonical);
        let hash = hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&hash);
        tx.hash = cc_types::Hash::new(hash_bytes);

        // Re-serialize with the populated hash. `raw` is the exact payload
        // fed to `eth_sendRawTransaction`.
        let raw = bincode::serialize(&tx)
            .map_err(|e| WalletError::SigningFailed(format!("bincode serialize: {}", e)))?;

        Ok(SignedTransaction {
            hash: hex::encode(hash_bytes),
            from: hex::encode(from_pubkey_bytes),
            to: self.to.clone(),
            value: self.value,
            nonce,
            gas_price: self.gas_price,
            gas_limit: self.gas_limit,
            chain_id: self.chain_id,
            data: self.data.clone(),
            signature: hex::encode(tx.signature.as_bytes()),
            raw,
        })
    }
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A signed transaction ready for submission.
#[derive(Debug, Clone)]
pub struct SignedTransaction {
    pub hash: String,
    pub from: String,
    pub to: Option<String>,
    pub value: u128,
    pub nonce: u64,
    pub gas_price: u64,
    pub gas_limit: u64,
    pub chain_id: u64,
    pub data: Vec<u8>,
    pub signature: String,
    pub raw: Vec<u8>,
}

/// JSON-RPC client for chain interaction.
pub struct RpcClient {
    url: String,
    client: reqwest::Client,
    request_id: AtomicU64,
}

impl RpcClient {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            client: reqwest::Client::new(),
            request_id: AtomicU64::new(1),
        }
    }

    fn next_id(&self) -> u64 {
        self.request_id.fetch_add(1, Ordering::SeqCst)
    }

    async fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, WalletError> {
        let id = self.next_id();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": id,
        });

        let response = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| WalletError::Rpc(format!("Request failed: {}", e)))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| WalletError::Rpc(format!("Response parse failed: {}", e)))?;

        if let Some(error) = json.get("error") {
            let msg = error
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("Unknown RPC error");
            return Err(WalletError::Rpc(msg.to_string()));
        }

        json.get("result")
            .cloned()
            .ok_or_else(|| WalletError::Rpc("No result in response".to_string()))
    }

    /// Get the balance of an address (in wei).
    pub async fn get_balance(&self, address: &str) -> Result<u128, WalletError> {
        let result = self
            .call("eth_getBalance", serde_json::json!([address, "latest"]))
            .await?;
        parse_hex_u128(&result)
    }

    /// Get the transaction count (nonce) for an address.
    pub async fn get_nonce(&self, address: &str) -> Result<u64, WalletError> {
        let result = self
            .call(
                "eth_getTransactionCount",
                serde_json::json!([address, "pending"]),
            )
            .await?;
        parse_hex_u64(&result)
    }

    /// Submit a signed transaction.
    pub async fn send_raw_transaction(&self, raw_tx: &[u8]) -> Result<String, WalletError> {
        let hex_tx = format!("0x{}", hex::encode(raw_tx));
        let result = self
            .call("eth_sendRawTransaction", serde_json::json!([hex_tx]))
            .await?;
        result
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| WalletError::Rpc("Invalid tx hash response".to_string()))
    }

    /// Get the current block number.
    pub async fn get_block_number(&self) -> Result<u64, WalletError> {
        let result = self.call("eth_blockNumber", serde_json::json!([])).await?;
        parse_hex_u64(&result)
    }

    /// Get the chain ID.
    pub async fn get_chain_id(&self) -> Result<u64, WalletError> {
        let result = self.call("eth_chainId", serde_json::json!([])).await?;
        parse_hex_u64(&result)
    }

    /// Estimate gas for a transaction.
    pub async fn estimate_gas(
        &self,
        from: &str,
        to: &str,
        value: u128,
    ) -> Result<u64, WalletError> {
        let result = self
            .call(
                "eth_estimateGas",
                serde_json::json!([{
                    "from": from,
                    "to": to,
                    "value": format!("0x{:x}", value),
                }]),
            )
            .await?;
        parse_hex_u64(&result)
    }

    /// Issue an `eth_call` against a contract address with raw calldata.
    ///
    /// Returns the contract's return-data bytes. Used by typed binding
    /// crates (e.g., `citrate-rbac-bindings`) to call deployed contract
    /// view functions without bringing in `ethabi`/`alloy` dependencies.
    ///
    /// # Arguments
    ///
    /// - `to` — 0x-prefixed 20-byte EVM address (e.g., `"0xABC..."`).
    /// - `data` — raw calldata: 4-byte selector + ABI-encoded args.
    ///
    /// # Errors
    ///
    /// - [`WalletError::Rpc`] if the JSON-RPC call fails.
    /// - [`WalletError::Rpc`] if the response is not a hex string.
    /// - [`WalletError::Rpc`] if the hex decode fails.
    pub async fn eth_call(&self, to: &str, data: &[u8]) -> Result<Vec<u8>, WalletError> {
        let hex_data = format!("0x{}", hex::encode(data));
        let result = self
            .call(
                "eth_call",
                serde_json::json!([
                    {
                        "to": to,
                        "data": hex_data,
                    },
                    "latest",
                ]),
            )
            .await?;
        let s = result
            .as_str()
            .ok_or_else(|| WalletError::Rpc("Expected hex string from eth_call".into()))?;
        let s = s.strip_prefix("0x").unwrap_or(s);
        hex::decode(s).map_err(|e| WalletError::Rpc(format!("Invalid hex from eth_call: {}", e)))
    }

    /// Get a transaction receipt.
    pub async fn get_transaction_receipt(
        &self,
        tx_hash: &str,
    ) -> Result<Option<serde_json::Value>, WalletError> {
        let result = self
            .call("eth_getTransactionReceipt", serde_json::json!([tx_hash]))
            .await?;
        if result.is_null() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }
}

fn parse_hex_u64(value: &serde_json::Value) -> Result<u64, WalletError> {
    let s = value
        .as_str()
        .ok_or_else(|| WalletError::Rpc("Expected hex string".into()))?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).map_err(|e| WalletError::Rpc(format!("Invalid hex u64: {}", e)))
}

fn parse_hex_u128(value: &serde_json::Value) -> Result<u128, WalletError> {
    let s = value
        .as_str()
        .ok_or_else(|| WalletError::Rpc("Expected hex string".into()))?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    u128::from_str_radix(s, 16).map_err(|e| WalletError::Rpc(format!("Invalid hex u128: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_builder_defaults() {
        let builder = TransactionBuilder::new();
        assert_eq!(builder.chain_id, 40204);
        assert_eq!(builder.gas_limit, 21_000);
        assert_eq!(builder.gas_price, 1_000_000_000);
        assert_eq!(builder.value, 0);
        assert!(builder.to.is_none());
    }

    #[test]
    fn test_transaction_builder_fluent() {
        let builder = TransactionBuilder::new()
            .to("0xb5ddd4eb356ddf3bf51eb3aec1ed28213be59129")
            .value(1_000_000_000_000_000_000) // 1 SALT
            .gas_limit(21_000)
            .gas_price(2_000_000_000)
            .chain_id(40204);

        assert_eq!(
            builder.to.as_deref(),
            Some("0xb5ddd4eb356ddf3bf51eb3aec1ed28213be59129")
        );
        assert_eq!(builder.value, 1_000_000_000_000_000_000);
    }

    #[test]
    fn test_sign_transaction() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let tx = TransactionBuilder::new()
            .to("0xb5ddd4eb356ddf3bf51eb3aec1ed28213be59129")
            .value(1000)
            .sign(&key, 0)
            .expect("sign transaction");

        assert!(!tx.hash.is_empty());
        assert!(!tx.signature.is_empty());
        assert_eq!(tx.signature.len(), 128); // 64 bytes hex
        assert!(!tx.raw.is_empty());
        assert_eq!(tx.nonce, 0);
        assert_eq!(tx.chain_id, 40204);
    }

    #[test]
    fn test_sign_deterministic() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let tx1 = TransactionBuilder::new()
            .to("0xb5ddd4eb356ddf3bf51eb3aec1ed28213be59129")
            .value(1000)
            .sign(&key, 5)
            .expect("sign 1");
        let tx2 = TransactionBuilder::new()
            .to("0xb5ddd4eb356ddf3bf51eb3aec1ed28213be59129")
            .value(1000)
            .sign(&key, 5)
            .expect("sign 2");

        assert_eq!(tx1.hash, tx2.hash);
        assert_eq!(tx1.signature, tx2.signature);
    }

    #[test]
    fn test_different_nonce_different_hash() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let tx1 = TransactionBuilder::new()
            .to("0xb5ddd4eb356ddf3bf51eb3aec1ed28213be59129")
            .value(1000)
            .sign(&key, 0)
            .expect("sign nonce 0");
        let tx2 = TransactionBuilder::new()
            .to("0xb5ddd4eb356ddf3bf51eb3aec1ed28213be59129")
            .value(1000)
            .sign(&key, 1)
            .expect("sign nonce 1");

        assert_ne!(tx1.hash, tx2.hash);
    }

    #[test]
    fn test_different_chain_id_different_hash() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let tx1 = TransactionBuilder::new()
            .chain_id(1)
            .value(1000)
            .sign(&key, 0)
            .expect("chain 1");
        let tx2 = TransactionBuilder::new()
            .chain_id(40204)
            .value(1000)
            .sign(&key, 0)
            .expect("chain 40204");
        assert_ne!(
            tx1.hash, tx2.hash,
            "Different chain IDs should produce different hashes (replay protection)"
        );
    }

    #[test]
    fn test_contract_deploy_no_to() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let tx = TransactionBuilder::new()
            .data(vec![0x60, 0x80, 0x60, 0x40]) // minimal bytecode
            .gas_limit(1_000_000)
            .sign(&key, 0)
            .expect("deploy");

        assert!(tx.to.is_none());
        assert!(!tx.data.is_empty());
    }

    #[test]
    fn test_parse_hex_u64_values() {
        let val = serde_json::json!("0x1");
        assert_eq!(parse_hex_u64(&val).expect("parse"), 1);

        let val = serde_json::json!("0xff");
        assert_eq!(parse_hex_u64(&val).expect("parse"), 255);

        let val = serde_json::json!("0x9d0c");
        assert_eq!(parse_hex_u64(&val).expect("parse"), 40204);
    }

    #[test]
    fn test_parse_hex_u128_values() {
        let val = serde_json::json!("0xde0b6b3a7640000"); // 1 ETH in wei
        assert_eq!(
            parse_hex_u128(&val).expect("parse"),
            1_000_000_000_000_000_000
        );
    }

    #[test]
    fn test_parse_hex_invalid() {
        let val = serde_json::json!(42);
        assert!(parse_hex_u64(&val).is_err());

        let val = serde_json::json!("not_hex");
        assert!(parse_hex_u64(&val).is_err());
    }

    #[test]
    fn test_rpc_client_creation() {
        let client = RpcClient::new("https://rpc.citrate.ai");
        assert_eq!(client.url, "https://rpc.citrate.ai");
    }

    #[test]
    fn test_rpc_client_id_increments() {
        let client = RpcClient::new("http://localhost:8545");
        let id1 = client.next_id();
        let id2 = client.next_id();
        assert_eq!(id2, id1 + 1);
    }

    #[tokio::test]
    async fn test_eth_call_constructs_request_body() {
        // Spin up a tiny mock server that captures the request body and
        // replies with a known hex string. This validates the request
        // shape without depending on a real chain.
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let port = listener.local_addr().expect("local addr").port();
        let captured: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
        let captured_clone = captured.clone();

        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).expect("read");
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            // Strip headers, keep body.
            if let Some(idx) = req.find("\r\n\r\n") {
                let body = &req[idx + 4..];
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
                    *captured_clone.lock().expect("capture lock") = Some(v);
                }
            }
            // Reply with a 32-byte hex value.
            let response_body = r#"{"jsonrpc":"2.0","id":1,"result":"0x000000000000000000000000000000000000000000000000000000000000002a"}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream.write_all(resp.as_bytes()).expect("write");
            stream.flush().expect("flush");
        });

        let client = RpcClient::new(&format!("http://127.0.0.1:{}", port));
        let result = client
            .eth_call(
                "0xdead000000000000000000000000000000000000",
                &[0xde, 0xad, 0xbe, 0xef],
            )
            .await
            .expect("eth_call should succeed");

        // Returns 32 bytes, last byte == 42.
        assert_eq!(result.len(), 32);
        assert_eq!(result[31], 0x2a);

        // Verify the request body shape.
        let body = captured
            .lock()
            .expect("capture lock")
            .clone()
            .expect("captured request body");
        assert_eq!(body["method"], "eth_call");
        assert_eq!(body["params"][0]["to"], "0xdead000000000000000000000000000000000000");
        assert_eq!(body["params"][0]["data"], "0xdeadbeef");
        assert_eq!(body["params"][1], "latest");
    }

    #[tokio::test]
    async fn test_eth_call_rejects_non_hex_result() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("local addr").port();

        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).expect("read");
            // Reply with a non-string result (boolean).
            let response_body = r#"{"jsonrpc":"2.0","id":1,"result":true}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream.write_all(resp.as_bytes()).expect("write");
            stream.flush().expect("flush");
        });

        let client = RpcClient::new(&format!("http://127.0.0.1:{}", port));
        let err = client
            .eth_call("0x0000000000000000000000000000000000000000", &[])
            .await
            .expect_err("non-hex result must error");
        match err {
            WalletError::Rpc(msg) => assert!(msg.contains("hex string")),
            other => panic!("expected Rpc error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_eth_call_rejects_invalid_hex() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("local addr").port();

        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).expect("read");
            // Odd-length hex (invalid).
            let response_body = r#"{"jsonrpc":"2.0","id":1,"result":"0xabc"}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream.write_all(resp.as_bytes()).expect("write");
            stream.flush().expect("flush");
        });

        let client = RpcClient::new(&format!("http://127.0.0.1:{}", port));
        let err = client
            .eth_call("0x0000000000000000000000000000000000000000", &[])
            .await
            .expect_err("invalid hex must error");
        match err {
            WalletError::Rpc(msg) => assert!(msg.to_lowercase().contains("hex")),
            other => panic!("expected Rpc error, got {:?}", other),
        }
    }

    #[test]
    fn test_signed_tx_has_from() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let expected_from = hex::encode(key.verifying_key().to_bytes());
        let tx = TransactionBuilder::new()
            .value(0)
            .sign(&key, 0)
            .expect("sign");
        assert_eq!(tx.from, expected_from);
    }

    // === secp256k1 / EVM signing tests ===

    #[test]
    fn test_t0_02_eip155_signing_payload_matches_spec_vector() {
        let builder = TransactionBuilder::new()
            .to("0x3535353535353535353535353535353535353535")
            .value(1_000_000_000_000_000_000)
            .gas_price(20_000_000_000)
            .gas_limit(21_000)
            .chain_id(1);

        let payload = builder.eip155_signing_payload(9).expect("EIP-155 payload");
        assert_eq!(
            hex::encode(payload),
            "ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080"
        );

        let hash = builder.eip155_signing_hash(9).expect("EIP-155 hash");
        assert_eq!(
            hex::encode(hash),
            "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
        );
    }

    #[test]
    fn test_t0_02_eip155_signed_transaction_matches_spec_vector() {
        let private_key = [0x46u8; 32];
        let key = k256::ecdsa::SigningKey::from_bytes(&private_key.into())
            .expect("valid EIP-155 vector key");

        let tx = TransactionBuilder::new()
            .to("0x3535353535353535353535353535353535353535")
            .value(1_000_000_000_000_000_000)
            .gas_price(20_000_000_000)
            .gas_limit(21_000)
            .chain_id(1)
            .sign_secp256k1(&key, 9)
            .expect("sign EIP-155 vector");

        assert_eq!(
            hex::encode(&tx.raw),
            "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
        );
        assert_eq!(
            tx.hash,
            "33469b22e9f636356c4160a87eb19df52b7412e8eac32a4a55ffe88ea8350788"
        );
    }

    #[test]
    fn test_t0_02_secp256k1_rejects_non_20_byte_to_address() {
        let key = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let err = TransactionBuilder::new()
            .to("0xabc")
            .value(100)
            .sign_secp256k1(&key, 0)
            .expect_err("odd-length address must not silently become contract creation");

        assert!(matches!(err, WalletError::InvalidAddress(_)));
    }

    #[test]
    fn test_secp256k1_sign_produces_valid_tx() {
        let key = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let tx = TransactionBuilder::new()
            .to("0xdead000000000000000000000000000000000000")
            .value(1_000_000_000_000_000_000) // 1 SALT
            .chain_id(40204)
            .sign_secp256k1(&key, 0)
            .expect("secp256k1 sign");

        assert!(!tx.hash.is_empty());
        assert!(tx.from.starts_with("0x"));
        assert_eq!(tx.from.len(), 42); // 0x + 40 hex chars
        assert!(!tx.raw.is_empty());
        assert!(tx.signature.contains("v="));
        assert!(tx.signature.contains("r="));
        assert!(tx.signature.contains("s="));
    }

    #[test]
    fn test_secp256k1_sign_deterministic() {
        let key = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let tx1 = TransactionBuilder::new()
            .to("0xdead000000000000000000000000000000000000")
            .value(100)
            .chain_id(40204)
            .sign_secp256k1(&key, 5)
            .expect("sign 1");
        let tx2 = TransactionBuilder::new()
            .to("0xdead000000000000000000000000000000000000")
            .value(100)
            .chain_id(40204)
            .sign_secp256k1(&key, 5)
            .expect("sign 2");

        assert_eq!(tx1.hash, tx2.hash);
        assert_eq!(tx1.from, tx2.from);
    }

    #[test]
    fn test_secp256k1_different_keys_different_from() {
        let key1 = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let key2 = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);

        let tx1 = TransactionBuilder::new()
            .value(0)
            .sign_secp256k1(&key1, 0)
            .expect("sign 1");
        let tx2 = TransactionBuilder::new()
            .value(0)
            .sign_secp256k1(&key2, 0)
            .expect("sign 2");

        assert_ne!(tx1.from, tx2.from);
    }

    #[test]
    fn test_secp256k1_eip155_v_value() {
        let key = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let tx = TransactionBuilder::new()
            .chain_id(40204)
            .sign_secp256k1(&key, 0)
            .expect("sign");

        // EIP-155: v = recovery_id + chain_id * 2 + 35
        // recovery_id is 0 or 1, so v is either 80443 or 80444 for chain_id 40204
        let v_str = tx
            .signature
            .split("v=")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .expect("v value");
        let v: u64 = v_str.parse().expect("parse v");
        assert!(v == 40204 * 2 + 35 || v == 40204 * 2 + 36);
    }

    #[test]
    fn test_secp256k1_rlp_encoded_output() {
        let key = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let tx = TransactionBuilder::new()
            .to("0xdead000000000000000000000000000000000000")
            .value(1000)
            .chain_id(40204)
            .sign_secp256k1(&key, 42)
            .expect("sign");

        // RLP output should be parseable
        assert!(!tx.raw.is_empty());
        // First byte should indicate a list (0xc0+)
        assert!(
            tx.raw[0] >= 0xc0 || tx.raw[0] >= 0xf7,
            "RLP should start with list prefix, got 0x{:02x}",
            tx.raw[0]
        );
    }

    #[test]
    fn test_secp256k1_from_address_is_keccak_derived() {
        let key = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let tx = TransactionBuilder::new()
            .value(0)
            .sign_secp256k1(&key, 0)
            .expect("sign");

        // Independently derive the address
        let vk = key.verifying_key();
        let pubkey_point = k256::EncodedPoint::from(vk);
        let pubkey_bytes = pubkey_point.as_bytes();
        let mut hasher = Keccak256::new();
        hasher.update(&pubkey_bytes[1..]); // Skip 0x04
        let hash = hasher.finalize();
        let expected = format!("0x{}", hex::encode(&hash[12..]));

        assert_eq!(tx.from, expected);
    }

    #[test]
    fn test_secp256k1_contract_creation_empty_to() {
        let key = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let tx = TransactionBuilder::new()
            .value(0)
            .data(vec![0x60, 0x60, 0x60, 0x40]) // Minimal bytecode
            .sign_secp256k1(&key, 0)
            .expect("sign");

        assert!(tx.to.is_none());
        assert!(!tx.raw.is_empty());
    }
}
