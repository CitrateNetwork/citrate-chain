use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use dashmap::DashMap;
use ed25519_dalek::SigningKey;
use citrate_consensus::types::{Hash, PublicKey, Signature, Transaction};
use citrate_execution::types::Address;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;
use tracing::{error, info, warn};

#[derive(Clone)]
struct FaucetState {
    signing_key: Arc<SigningKey>,
    rpc_url: String,
    api_key: Option<String>,
    nonce: Arc<Mutex<u64>>,
    chain_id: u64,
    faucet_address: Address,
    /// Per-IP rate limit: tracks last request time
    ip_rate_limit: Arc<DashMap<String, Instant>>,
    /// Per-address cooldown: tracks last request time (24h between requests)
    address_cooldown: Arc<DashMap<String, Instant>>,
    /// Address whitelist: only these addresses can claim. Empty = no whitelist.
    address_whitelist: Arc<HashSet<String>>,
}

#[derive(Debug, Deserialize)]
struct FaucetRequest {
    address: String,
}

#[derive(Debug, Serialize)]
struct FaucetResponse {
    success: bool,
    tx_hash: Option<String>,
    message: String,
    amount: String,
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    info!("Starting Citrate Faucet Service");

    // Configuration from environment
    let rpc_url = std::env::var("CITRATE_RPC_URL")
        .unwrap_or_else(|_| "http://localhost:8545".to_string());
    let api_key = std::env::var("CITRATE_API_KEY").ok().filter(|k| !k.is_empty());
    let chain_id = std::env::var("CITRATE_CHAIN_ID")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(40204);

    // Faucet private key from env or default test key
    let faucet_key_hex = std::env::var("FAUCET_PRIVATE_KEY")
        .unwrap_or_else(|_| {
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()
        });
    let faucet_key_bytes = hex::decode(&faucet_key_hex).expect("Invalid faucet key hex");
    let signing_key = SigningKey::from_bytes(&faucet_key_bytes.try_into().expect("Key must be 32 bytes"));

    // Calculate faucet address from public key
    let public_key = signing_key.verifying_key();
    let mut hasher = Sha3_256::new();
    hasher.update(public_key.as_bytes());
    let hash = hasher.finalize();
    let mut addr_bytes = [0u8; 20];
    addr_bytes.copy_from_slice(&hash[12..32]);
    let faucet_address = Address(addr_bytes);

    info!("Faucet address: 0x{}", hex::encode(faucet_address.0));
    info!("RPC endpoint: {}", rpc_url);
    info!("Chain ID: {}", chain_id);
    if api_key.is_some() {
        info!("API key authentication enabled for RPC calls");
    }

    // Address whitelist from env (comma-separated)
    let address_whitelist: HashSet<String> = std::env::var("FAUCET_WHITELIST")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_lowercase().trim_start_matches("0x").to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if !address_whitelist.is_empty() {
        info!("Address whitelist enabled: {} addresses", address_whitelist.len());
    }

    let state = FaucetState {
        signing_key: Arc::new(signing_key),
        rpc_url,
        api_key,
        nonce: Arc::new(Mutex::new(0)),
        chain_id,
        faucet_address,
        ip_rate_limit: Arc::new(DashMap::new()),
        address_cooldown: Arc::new(DashMap::new()),
        address_whitelist: Arc::new(address_whitelist),
    };

    // Build router
    let app = Router::new()
        .route("/", get(root))
        .route("/faucet", post(request_tokens))
        .route("/status", get(status))
        .route("/health", get(health))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001").await.expect("cannot bind faucet to port 3001");

    info!("Faucet listening on http://0.0.0.0:3001");
    info!("Request test tokens: POST /faucet with {{\"address\": \"0x...\"}}");

    if let Err(e) = axum::serve(listener, app).await {
        error!("Faucet server exited with error: {}", e);
    }
}

async fn root() -> &'static str {
    "Citrate Testnet Faucet - POST /faucet with {\"address\": \"0x...\"}"
}

async fn status() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "online",
        "network": "citrate-testnet-beta",
        "amount_per_request": "10 SALT"
    }))
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn request_tokens(
    State(state): State<FaucetState>,
    Json(payload): Json<FaucetRequest>,
) -> Result<Json<FaucetResponse>, StatusCode> {
    // Parse recipient address
    let recipient_hex = payload.address.trim_start_matches("0x").to_lowercase();
    let recipient_bytes = match hex::decode(&recipient_hex) {
        Ok(b) if b.len() == 20 => b,
        _ => {
            return Ok(Json(FaucetResponse {
                success: false,
                tx_hash: None,
                message: "Invalid address format".to_string(),
                amount: "0".to_string(),
            }));
        }
    };

    // Address whitelist check
    if !state.address_whitelist.is_empty() && !state.address_whitelist.contains(&recipient_hex) {
        warn!("Faucet request rejected: address {} not in whitelist", recipient_hex);
        return Ok(Json(FaucetResponse {
            success: false,
            tx_hash: None,
            message: "Address not whitelisted for testnet beta".to_string(),
            amount: "0".to_string(),
        }));
    }

    // Per-address cooldown: 24h between requests
    let cooldown_secs = 24 * 3600; // 24 hours
    if let Some(last_request) = state.address_cooldown.get(&recipient_hex) {
        let elapsed = last_request.elapsed().as_secs();
        if elapsed < cooldown_secs {
            let remaining = cooldown_secs - elapsed;
            let hours = remaining / 3600;
            let minutes = (remaining % 3600) / 60;
            return Ok(Json(FaucetResponse {
                success: false,
                tx_hash: None,
                message: format!(
                    "Rate limited: {}h {}m remaining before next claim",
                    hours, minutes
                ),
                amount: "0".to_string(),
            }));
        }
    }

    let mut recipient_addr = [0u8; 20];
    recipient_addr.copy_from_slice(&recipient_bytes);
    let recipient = Address(recipient_addr);

    info!("Faucet request for address: 0x{}", hex::encode(recipient.0));

    // Create transaction
    let mut nonce_guard = state.nonce.lock().await;
    let nonce = *nonce_guard;

    // Convert recipient address to PublicKey format for transaction
    let mut to_pk_bytes = [0u8; 32];
    to_pk_bytes[..20].copy_from_slice(&recipient.0);
    let to_pubkey = PublicKey::new(to_pk_bytes);

    // Convert faucet address to PublicKey for transaction
    let mut from_pk_bytes = [0u8; 32];
    from_pk_bytes[..20].copy_from_slice(&state.faucet_address.0);
    let from_pubkey = PublicKey::new(from_pk_bytes);

    // Build transaction
    let mut tx = Transaction {
        hash: Hash::default(),
        from: from_pubkey,
        to: Some(to_pubkey),
        value: 10_000_000_000_000_000_000u128, // 10 SALT
        data: vec![],
        nonce,
        gas_price: 1_000_000_000, // 1 gwei
        gas_limit: 21000,
        signature: Signature::new([0; 64]),
        tx_type: None,
        ..Default::default()
    };

    // Calculate transaction hash
    tx.hash = calculate_tx_hash(&tx, state.chain_id);

    // Sign transaction
    use ed25519_dalek::Signer;
    let signature = state.signing_key.as_ref().sign(tx.hash.as_bytes());
    tx.signature = Signature::new(signature.to_bytes());

    // Serialize transaction
    let tx_bytes = match bincode::serialize(&tx) {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to serialize transaction: {}", e);
            return Ok(Json(FaucetResponse {
                success: false,
                tx_hash: None,
                message: "Failed to create transaction".to_string(),
                amount: "0".to_string(),
            }));
        }
    };

    let tx_hex = format!("0x{}", hex::encode(&tx_bytes));

    // Send transaction via RPC (with API key if configured)
    let client = reqwest::Client::new();
    let mut request = client
        .post(&state.rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [tx_hex],
            "id": 1
        }));

    // Add API key header for authenticated RPC
    if let Some(ref key) = state.api_key {
        request = request.header("X-API-Key", key.as_str());
    }

    let response = request.send().await;

    match response {
        Ok(res) => {
            let json: serde_json::Value = res.json().await.unwrap_or_default();

            if let Some(result) = json.get("result").and_then(|r| r.as_str()) {
                // Success - increment nonce and record cooldown
                *nonce_guard += 1;
                state.address_cooldown.insert(recipient_hex, Instant::now());

                info!(
                    "Faucet sent 10 SALT to {} - tx: {}",
                    payload.address, result
                );

                Ok(Json(FaucetResponse {
                    success: true,
                    tx_hash: Some(result.to_string()),
                    message: "Successfully sent 10 SALT".to_string(),
                    amount: "10000000000000000000".to_string(),
                }))
            } else if let Some(error) = json.get("error") {
                error!("RPC error: {:?}", error);
                Ok(Json(FaucetResponse {
                    success: false,
                    tx_hash: None,
                    message: format!("Transaction failed: {:?}", error),
                    amount: "0".to_string(),
                }))
            } else {
                Ok(Json(FaucetResponse {
                    success: false,
                    tx_hash: None,
                    message: "Unknown RPC response".to_string(),
                    amount: "0".to_string(),
                }))
            }
        }
        Err(e) => {
            error!("Failed to send transaction: {}", e);
            Ok(Json(FaucetResponse {
                success: false,
                tx_hash: None,
                message: "Failed to connect to node".to_string(),
                amount: "0".to_string(),
            }))
        }
    }
}

/// Validate a faucet request address string.
/// Returns the normalized lowercase hex (without 0x) and the 20-byte address,
/// or an error message string.
fn validate_address(address: &str) -> Result<(String, [u8; 20]), &'static str> {
    let hex_str = address.trim_start_matches("0x").to_lowercase();
    let bytes = hex::decode(&hex_str).map_err(|_| "Invalid hex encoding")?;
    if bytes.len() != 20 {
        return Err("Address must be 20 bytes");
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes);
    Ok((hex_str, addr))
}

/// Check whether an address is whitelisted.
/// Returns true if the whitelist is empty (no filtering) or the address is in it.
fn is_whitelisted(whitelist: &HashSet<String>, address_hex: &str) -> bool {
    whitelist.is_empty() || whitelist.contains(address_hex)
}

/// Check cooldown status. Returns Ok(()) if no cooldown active, or Err with
/// a message containing hours/minutes remaining.
fn check_cooldown(last_request_elapsed_secs: Option<u64>, cooldown_secs: u64) -> Result<(), String> {
    if let Some(elapsed) = last_request_elapsed_secs {
        if elapsed < cooldown_secs {
            let remaining = cooldown_secs - elapsed;
            let hours = remaining / 3600;
            let minutes = (remaining % 3600) / 60;
            return Err(format!("Rate limited: {}h {}m remaining before next claim", hours, minutes));
        }
    }
    Ok(())
}

/// The drip amount in wei (10 SALT = 10 * 10^18)
const DRIP_AMOUNT: u128 = 10_000_000_000_000_000_000;

fn calculate_tx_hash(tx: &Transaction, chain_id: u64) -> Hash {
    let mut hasher = Sha3_256::new();

    // Hash transaction fields (EIP-155 style)
    hasher.update(tx.nonce.to_le_bytes());
    hasher.update(tx.gas_price.to_le_bytes());
    hasher.update(tx.gas_limit.to_le_bytes());

    if let Some(to) = &tx.to {
        hasher.update(to.0);
    }

    hasher.update(tx.value.to_le_bytes());
    hasher.update(&tx.data);
    hasher.update(chain_id.to_le_bytes());
    hasher.update([0u8; 8]); // r placeholder
    hasher.update([0u8; 8]); // s placeholder

    let result = hasher.finalize();
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&result);
    Hash::new(hash_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_address_valid_with_prefix() {
        let addr = "0x1111111111111111111111111111111111111111";
        let (hex_str, bytes) = validate_address(addr).expect("valid");
        assert_eq!(hex_str, "1111111111111111111111111111111111111111");
        assert_eq!(bytes, [0x11; 20]);
    }

    #[test]
    fn test_validate_address_valid_without_prefix() {
        let addr = "aabbccddee11223344556677889900aabbccddee";
        let (hex_str, _bytes) = validate_address(addr).expect("valid");
        assert_eq!(hex_str, addr);
    }

    #[test]
    fn test_validate_address_invalid_hex() {
        let result = validate_address("0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_address_wrong_length() {
        // Too short (19 bytes)
        let result = validate_address("0xaabbccddee112233445566778899aabbccddee");
        assert!(result.is_err());
        // Too long (21 bytes)
        let result = validate_address("0xaabbccddee11223344556677889900aabbccddeeff");
        assert!(result.is_err());
    }

    #[test]
    fn test_is_whitelisted_empty_whitelist_allows_all() {
        let whitelist = HashSet::new();
        assert!(is_whitelisted(&whitelist, "any_address"));
    }

    #[test]
    fn test_is_whitelisted_with_entries() {
        let mut whitelist = HashSet::new();
        whitelist.insert("abcd".to_string());
        assert!(is_whitelisted(&whitelist, "abcd"));
        assert!(!is_whitelisted(&whitelist, "1234"));
    }

    #[test]
    fn test_check_cooldown_no_prior_request() {
        assert!(check_cooldown(None, 86400).is_ok());
    }

    #[test]
    fn test_check_cooldown_within_window() {
        // 1 hour elapsed out of 24h cooldown
        let result = check_cooldown(Some(3600), 86400);
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("Rate limited"));
        assert!(msg.contains("23h")); // ~23 hours remaining
    }

    #[test]
    fn test_check_cooldown_expired() {
        // 25 hours elapsed, cooldown is 24h
        assert!(check_cooldown(Some(90000), 86400).is_ok());
    }

    #[test]
    fn test_drip_amount_is_10_salt() {
        // 10 SALT = 10 * 10^18 wei
        assert_eq!(DRIP_AMOUNT, 10_000_000_000_000_000_000u128);
    }

    #[test]
    fn test_calculate_tx_hash_deterministic() {
        let tx = Transaction {
            hash: Hash::default(),
            from: PublicKey::new([0u8; 32]),
            to: Some(PublicKey::new([1u8; 32])),
            value: 1000,
            data: vec![],
            nonce: 0,
            gas_price: 1_000_000_000,
            gas_limit: 21000,
            signature: Signature::new([0; 64]),
            tx_type: None,
            ..Default::default()
        };
        let hash1 = calculate_tx_hash(&tx, 40204);
        let hash2 = calculate_tx_hash(&tx, 40204);
        assert_eq!(hash1.as_bytes(), hash2.as_bytes());
    }

    #[test]
    fn test_calculate_tx_hash_different_chain_id() {
        let tx = Transaction {
            hash: Hash::default(),
            from: PublicKey::new([0u8; 32]),
            to: Some(PublicKey::new([1u8; 32])),
            value: 1000,
            data: vec![],
            nonce: 0,
            gas_price: 1_000_000_000,
            gas_limit: 21000,
            signature: Signature::new([0; 64]),
            tx_type: None,
            ..Default::default()
        };
        let hash_a = calculate_tx_hash(&tx, 1);
        let hash_b = calculate_tx_hash(&tx, 40204);
        assert_ne!(hash_a.as_bytes(), hash_b.as_bytes());
    }
}
