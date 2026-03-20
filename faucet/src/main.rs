use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use dashmap::DashMap;
use citrate_execution::types::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;
use tower_http::cors::CorsLayer;
use tracing::{error, info, warn};

#[derive(Clone)]
struct FaucetState {
    rpc_url: String,
    api_key: Option<String>,
    chain_id: u64,
    faucet_address: Address,
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

    // Faucet source address: use genesis-funded address (0x33..33 by default)
    // Override with FAUCET_ADDRESS env var if needed.
    let faucet_address_hex = std::env::var("FAUCET_ADDRESS")
        .unwrap_or_else(|_| "3333333333333333333333333333333333333333".to_string());
    let faucet_addr_bytes = hex::decode(faucet_address_hex.trim_start_matches("0x"))
        .expect("Invalid FAUCET_ADDRESS hex");
    let mut addr_bytes = [0u8; 20];
    addr_bytes.copy_from_slice(&faucet_addr_bytes);
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
        rpc_url,
        api_key,
        chain_id,
        faucet_address,
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

    let faucet_port = std::env::var("FAUCET_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(3002);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", faucet_port)).await
        .unwrap_or_else(|_| panic!("cannot bind faucet to port {}", faucet_port));

    info!("Faucet listening on http://0.0.0.0:{}", faucet_port);
    info!("Request test tokens: POST /faucet with {{\"address\": \"0x...\"}}");

    if let Err(e) = axum::serve(listener, app).await {
        error!("Faucet server exited with error: {}", e);
    }
}

async fn root() -> axum::response::Html<&'static str> {
    axum::response::Html(r#"<!DOCTYPE html>
<html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Citrate Faucet</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,system-ui,sans-serif;background:#0a0a1a;color:#f9fafb;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#1e1e2e;border:1px solid #374151;border-radius:12px;padding:32px;max-width:440px;width:100%}
h1{font-size:24px;margin-bottom:4px}
.sub{color:#9ca3af;font-size:14px;margin-bottom:24px}
label{font-size:13px;color:#9ca3af;display:block;margin-bottom:6px}
input{width:100%;padding:10px 12px;background:#0f0f23;border:1px solid #374151;border-radius:6px;color:#f9fafb;font-size:14px;font-family:monospace;outline:none}
input:focus{border-color:#6366f1}
button{width:100%;padding:12px;background:#6366f1;color:#fff;border:none;border-radius:6px;font-size:15px;font-weight:600;cursor:pointer;margin-top:16px;transition:background .2s}
button:hover{background:#818cf8}
button:disabled{opacity:.5;cursor:not-allowed}
.msg{margin-top:16px;padding:10px;border-radius:6px;font-size:13px}
.msg.ok{background:#064e3b;border:1px solid #10b981}
.msg.err{background:#7f1d1d;border:1px solid #ef4444}
.info{margin-top:20px;font-size:12px;color:#6b7280;text-align:center}
</style>
</head><body>
<div class="card">
<h1>Citrate Faucet</h1>
<p class="sub">Get test SALT tokens for the Citrate testnet</p>
<label for="addr">Wallet Address (0x...)</label>
<input id="addr" placeholder="0x0000000000000000000000000000000000000000" spellcheck="false">
<button id="btn" onclick="claim()">Request 10 SALT</button>
<div id="msg" class="msg" style="display:none"></div>
<p class="info">Chain ID: 40204 &middot; 10 SALT per request &middot; 24h cooldown</p>
</div>
<script>
async function claim(){
  const addr=document.getElementById('addr').value.trim();
  const btn=document.getElementById('btn');
  const msg=document.getElementById('msg');
  if(!addr||!addr.match(/^0x[0-9a-fA-F]{40}$/)){
    msg.className='msg err';msg.style.display='block';
    msg.textContent='Please enter a valid 0x address (40 hex chars)';return;
  }
  btn.disabled=true;btn.textContent='Sending...';
  try{
    const r=await fetch('/faucet',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({address:addr})});
    const d=await r.json();
    msg.style.display='block';
    if(d.success){msg.className='msg ok';msg.textContent='Sent 10 SALT! TX: '+d.tx_hash;}
    else{msg.className='msg err';msg.textContent=d.message;}
  }catch(e){msg.className='msg err';msg.style.display='block';msg.textContent='Error: '+e.message;}
  btn.disabled=false;btn.textContent='Request 10 SALT';
}
document.getElementById('addr').addEventListener('keydown',e=>{if(e.key==='Enter')claim()});
</script>
</body></html>"#)
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

    // Use eth_sendTransaction (unsigned, devnet mode) from the genesis faucet address.
    // The genesis faucet at 0x3333...33 is pre-funded with 10M SALT.
    let from_hex = format!("0x{}", hex::encode(state.faucet_address.0));
    let to_hex = format!("0x{}", hex::encode(recipient.0));

    let client = reqwest::Client::new();
    let mut request = client
        .post(&state.rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_sendTransaction",
            "params": [{
                "from": from_hex,
                "to": to_hex,
                "value": format!("0x{:x}", DRIP_AMOUNT),
                "gas": "0x5208",
                "gasPrice": "0x3b9aca00"
            }],
            "id": 1
        }));

    if let Some(ref key) = state.api_key {
        request = request.header("X-API-Key", key.as_str());
    }

    let response = request.send().await;

    match response {
        Ok(res) => {
            let json: serde_json::Value = res.json().await.unwrap_or_default();

            if let Some(result) = json.get("result").and_then(|r| r.as_str()) {
                // Success - record cooldown
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

// calculate_tx_hash removed — faucet now uses eth_sendTransaction (unsigned)

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

    // tx_hash tests removed — faucet now uses eth_sendTransaction (unsigned)
}
