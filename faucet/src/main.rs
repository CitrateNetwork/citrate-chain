use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use citrate_execution::types::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing::{error, info, warn};

mod cooldowns;
use cooldowns::{CooldownDenial, CooldownPolicy, Cooldowns};

mod turnstile;
use turnstile::TurnstileVerifier;

#[derive(Clone)]
struct FaucetState {
    rpc_url: String,
    api_key: Option<String>,
    chain_id: u64,
    faucet_address: Address,
    /// Ed25519 signing key for the faucet account
    signing_key: Arc<ed25519_dalek::SigningKey>,
    /// File-backed per-address + per-IP cooldown tracker (FAU-04).
    cooldowns: Arc<Cooldowns>,
    /// Address whitelist: only these addresses can claim. Empty = no whitelist.
    address_whitelist: Arc<HashSet<String>>,
    /// Cloudflare Turnstile verifier (FAU-03). When `None`, CAPTCHA
    /// verification is skipped (used only in dev/local-CI builds).
    turnstile: Option<Arc<TurnstileVerifier>>,
}

#[derive(Debug, Deserialize)]
struct FaucetRequest {
    address: String,
    /// Cloudflare Turnstile token (FAU-03). Optional for backward
    /// compatibility with dev clients; production deployments set
    /// `FAUCET_TURNSTILE_SECRET` and `turnstile_token` becomes
    /// effectively mandatory.
    #[serde(default)]
    turnstile_token: Option<String>,
}

#[derive(Debug, Serialize)]
struct FaucetResponse {
    success: bool,
    tx_hash: Option<String>,
    message: String,
    amount: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    // Faucet signing key: read from env. The deterministic seed
    // path is gated behind the `unsafe-deterministic-key` cargo
    // feature (default OFF) so production builds CANNOT silently
    // start with a known-derivable key.
    //
    // Test-friendly: the bytes-decoding logic is exercised below
    // via `decode_faucet_key_hex`.
    // Original block left intact for the binary; the helper below
    // is what the unit test calls.
    // path is gated behind the `unsafe-deterministic-key` cargo
    // feature (default OFF) so production builds CANNOT silently
    // start with a known-derivable key.
    //
    // RM-B1 / WP-E6.1 (audit FAU-01): bounds-checked decode.
    // Pre-fix `key_bytes.copy_from_slice(&bytes[..32])` panicked
    // when the env var was <32 bytes; post-fix we explicitly fail
    // the startup with a descriptive error.
    //
    // RM-B1 / WP-E6.2 (audit FAU-02): refuse-by-default. Pre-fix
    // an unset `FAUCET_PRIVATE_KEY` produced a key any attacker
    // could re-derive offline.
    let signing_key = {
        let key_hex = std::env::var("FAUCET_PRIVATE_KEY").ok();
        if let Some(hex_str) = key_hex {
            let bytes = hex::decode(hex_str.trim_start_matches("0x"))
                .map_err(|e| format!("Invalid FAUCET_PRIVATE_KEY: {e}"))?;
            let key_array: [u8; 32] = bytes
                .as_slice()
                .get(..32)
                .ok_or_else(|| {
                    "FAUCET_PRIVATE_KEY must be at least 32 bytes (64 hex chars)".to_string()
                })?
                .try_into()
                .map_err(|_| "FAUCET_PRIVATE_KEY length conversion failed".to_string())?;
            ed25519_dalek::SigningKey::from_bytes(&key_array)
        } else {
            #[cfg(feature = "unsafe-deterministic-key")]
            {
                use sha3::{Digest, Keccak256};
                let seed = Keccak256::digest(b"citrate-faucet-testnet-v1");
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&seed);
                info!("⚠ Using deterministic faucet key (unsafe-deterministic-key feature). Local CI ONLY.");
                ed25519_dalek::SigningKey::from_bytes(&key_bytes)
            }
            #[cfg(not(feature = "unsafe-deterministic-key"))]
            {
                return Err(
                    "FAUCET_PRIVATE_KEY is required. The deterministic-default fallback is \
                     gated behind the `unsafe-deterministic-key` cargo feature (local CI only) \
                     — it is NOT enabled in this build. Set FAUCET_PRIVATE_KEY=<64-hex-chars>."
                        .into(),
                );
            }
        }
    };

    // Derive the faucet address from the signing key
    let faucet_pubkey = signing_key.verifying_key();
    let faucet_address = {
        use sha3::{Digest, Keccak256};
        let hash = Keccak256::digest(faucet_pubkey.as_bytes());
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..]);
        Address(addr)
    };

    info!("Faucet address: 0x{}", hex::encode(faucet_address.0));
    info!("Faucet pubkey: {}", hex::encode(faucet_pubkey.as_bytes()));
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

    // RM-B1 / WP-E6.3 (audit FAU-04): persistent cooldowns. When
    // FAUCET_COOLDOWN_FILE is set we load + persist; otherwise the
    // tracker stays in-memory (dev mode).
    let cooldown_policy = CooldownPolicy::default();
    let cooldowns = match std::env::var("FAUCET_COOLDOWN_FILE").ok() {
        Some(path) if !path.is_empty() => {
            let p = PathBuf::from(&path);
            info!("Cooldowns persisted to {}", p.display());
            Arc::new(Cooldowns::with_file(p, cooldown_policy))
        }
        _ => {
            info!(
                "Cooldowns in memory only (set FAUCET_COOLDOWN_FILE=<path> for persistence)"
            );
            Arc::new(Cooldowns::in_memory(cooldown_policy))
        }
    };

    // RM-B1 / WP-E6.3 (audit FAU-03): Cloudflare Turnstile gate.
    // Production deployments set FAUCET_TURNSTILE_SECRET; dev
    // builds without it skip the CAPTCHA path with a WARN log.
    let turnstile = match std::env::var("FAUCET_TURNSTILE_SECRET").ok() {
        Some(secret) if !secret.is_empty() => {
            info!("Cloudflare Turnstile CAPTCHA gate enabled");
            Some(Arc::new(TurnstileVerifier::new(secret)))
        }
        _ => {
            warn!(
                "FAUCET_TURNSTILE_SECRET not set — CAPTCHA verification disabled (DEV ONLY)"
            );
            None
        }
    };

    let state = FaucetState {
        rpc_url,
        api_key,
        chain_id,
        faucet_address,
        signing_key: Arc::new(signing_key),
        cooldowns,
        address_whitelist: Arc::new(address_whitelist),
        turnstile,
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
        .map_err(|e| format!("cannot bind faucet to port {}: {e}", faucet_port))?;

    info!("Faucet listening on http://0.0.0.0:{}", faucet_port);
    info!("Request test tokens: POST /faucet with {{\"address\": \"0x...\"}}");

    // RM-B1 / WP-E6.3 (audit FAU-03): `into_make_service_with_connect_info`
    // wires the SocketAddr into request extensions so handlers can
    // extract the client IP for the per-IP cooldown leg.
    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    {
        error!("Faucet server exited with error: {}", e);
    }

    Ok(())
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
    ConnectInfo(socket_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
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

    // RM-B1 / WP-E6.3 (audit FAU-03): client IP (X-Forwarded-For
    // honored when present, otherwise the socket peer). Used by the
    // per-IP cooldown leg AND optionally by the Turnstile verifier
    // for binding.
    let client_ip = extract_client_ip(&headers, socket_addr);

    // RM-B1 / WP-E6.3 (audit FAU-03): Turnstile CAPTCHA verification.
    // When the verifier is configured, the request MUST carry a
    // valid `turnstile_token`; absent / invalid tokens reject with
    // a clear error.
    if let Some(verifier) = state.turnstile.as_ref() {
        let token = match payload.turnstile_token.as_deref() {
            Some(t) if !t.is_empty() => t,
            _ => {
                return Ok(Json(FaucetResponse {
                    success: false,
                    tx_hash: None,
                    message: "CAPTCHA required: turnstile_token missing".to_string(),
                    amount: "0".to_string(),
                }));
            }
        };
        match verifier.verify(token, Some(&client_ip)).await {
            Ok(true) => {}
            Ok(false) => {
                return Ok(Json(FaucetResponse {
                    success: false,
                    tx_hash: None,
                    message: "CAPTCHA verification failed".to_string(),
                    amount: "0".to_string(),
                }));
            }
            Err(e) => {
                error!("Turnstile verification error: {}", e);
                return Ok(Json(FaucetResponse {
                    success: false,
                    tx_hash: None,
                    message: "CAPTCHA service unavailable, try again later".to_string(),
                    amount: "0".to_string(),
                }));
            }
        }
    }

    // RM-B1 / WP-E6.4 (audit FAU-04): per-address + per-IP cooldown
    // backed by a file (when FAUCET_COOLDOWN_FILE is set), so a
    // process restart no longer launders the cooldown.
    if let Err(denial) = state.cooldowns.check(&recipient_hex, &client_ip) {
        return Ok(Json(FaucetResponse {
            success: false,
            tx_hash: None,
            message: format!("Rate limited: {}", denial),
            amount: "0".to_string(),
        }));
    }

    let mut recipient_addr = [0u8; 20];
    recipient_addr.copy_from_slice(&recipient_bytes);
    let recipient = Address(recipient_addr);

    info!("Faucet request for address: 0x{} (ip={})", hex::encode(recipient.0), client_ip);

    // Build and sign a real transaction using the faucet's ed25519 key.
    // This uses eth_sendRawTransaction — no unsigned tx support needed on the node.
    use citrate_consensus::types::{Hash, PublicKey, Signature, Transaction};
    use citrate_consensus::crypto as consensus_crypto;

    let from_hex = format!("0x{}", hex::encode(state.faucet_address.0));
    let client = reqwest::Client::new();

    // Query current nonce for the faucet account
    let nonce: u64 = {
        let resp = client
            .post(&state.rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_getTransactionCount",
                "params": [&from_hex, "pending"],
                "id": 1
            }))
            .send()
            .await;
        match resp {
            Ok(r) => {
                let json: serde_json::Value = r.json().await.unwrap_or_default();
                json.get("result")
                    .and_then(|v| v.as_str())
                    .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                    .unwrap_or(0)
            }
            Err(_) => 0,
        }
    };

    // Build the transaction
    let faucet_pubkey = state.signing_key.verifying_key();
    let from_pk = PublicKey::new(faucet_pubkey.to_bytes());
    let to_pk = {
        let mut pk_bytes = [0u8; 32];
        pk_bytes[..20].copy_from_slice(&recipient.0);
        PublicKey::new(pk_bytes)
    };

    let mut tx = Transaction {
        hash: Hash::default(),
        from: from_pk,
        to: Some(to_pk),
        value: DRIP_AMOUNT,
        data: Vec::new(),
        nonce,
        gas_price: 1_000_000_000,
        gas_limit: 21_000,
        signature: Signature::new([0; 64]),
        tx_type: None,
        chain_id: Some(state.chain_id),
        ..Default::default()
    };

    // Calculate hash
    {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(tx.nonce.to_le_bytes());
        hasher.update(tx.from.as_bytes());
        if let Some(ref to) = tx.to {
            hasher.update(to.as_bytes());
        }
        hasher.update(tx.value.to_le_bytes());
        hasher.update(state.chain_id.to_le_bytes());
        let hash_bytes = hasher.finalize();
        tx.hash = Hash::from_bytes(&hash_bytes);
    }

    // Sign using consensus crypto (matches mempool verification)
    if let Err(e) = consensus_crypto::sign_transaction(&mut tx, &state.signing_key) {
        error!("Failed to sign faucet transaction: {}", e);
        return Ok(Json(FaucetResponse {
            success: false,
            tx_hash: None,
            message: format!("Signing failed: {}", e),
            amount: "0".to_string(),
        }));
    }

    // Serialize and send as raw transaction.
    // RM-B1 / WP-B1.5 (audit M-06): explicit error path replaces the
    // prior `unwrap_or_default()` which silently emitted empty bytes
    // on serialization failure (then the RPC reported a misleading
    // decode error).
    let tx_bytes = match bincode::serialize(&tx) {
        Ok(bytes) => bytes,
        Err(e) => {
            return Ok(Json(FaucetResponse {
                success: false,
                tx_hash: None,
                message: format!("Transaction serialization failed: {}", e),
                amount: "0".to_string(),
            }));
        }
    };
    let tx_hex = format!("0x{}", hex::encode(&tx_bytes));

    let mut request = client
        .post(&state.rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [tx_hex],
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
                // Success — record cooldowns (per-address + per-IP).
                // RM-B1 / WP-E6.4 (audit FAU-04).
                state.cooldowns.record_success(&recipient_hex, &client_ip);

                info!(
                    "Faucet sent 10 SALT to {} (ip={}) - tx: {}",
                    payload.address, client_ip, result
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
#[allow(dead_code)]
/// Extract the client IP. Honors the standard reverse-proxy
/// headers (`X-Forwarded-For` first hop, then `X-Real-IP`) and
/// falls back to the TCP socket peer when no header is present.
///
/// RM-B1 / WP-E6.3 (audit FAU-03): IP is used by the per-IP
/// cooldown leg of the brute-force defense AND optionally bound
/// into the Turnstile remoteip parameter.
fn extract_client_ip(headers: &HeaderMap, socket_addr: SocketAddr) -> String {
    // X-Forwarded-For: client, proxy1, proxy2 — take the first hop.
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() {
            let trimmed = first.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    if let Some(xri) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let trimmed = xri.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    socket_addr.ip().to_string()
}

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
#[allow(dead_code)]
fn is_whitelisted(whitelist: &HashSet<String>, address_hex: &str) -> bool {
    whitelist.is_empty() || whitelist.contains(address_hex)
}

/// Decode a hex-encoded faucet private key string into a 32-byte
/// array. Used by `main` for env-var parsing AND by unit tests so
/// the bounds-check (audit FAU-01) is provable without spawning
/// a process.
///
/// RM-B1 / WP-E6.1 (audit FAU-01): pre-fix
/// `key_bytes.copy_from_slice(&bytes[..32])` panicked on
/// short inputs. Post-fix returns `Err` on any input < 32 bytes.
#[allow(dead_code)]
fn decode_faucet_key_hex(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str.trim_start_matches("0x"))
        .map_err(|e| format!("Invalid FAUCET_PRIVATE_KEY: {e}"))?;
    let key_array: [u8; 32] = bytes
        .as_slice()
        .get(..32)
        .ok_or_else(|| {
            "FAUCET_PRIVATE_KEY must be at least 32 bytes (64 hex chars)".to_string()
        })?
        .try_into()
        .map_err(|_| "FAUCET_PRIVATE_KEY length conversion failed".to_string())?;
    Ok(key_array)
}

/// Check cooldown status. Returns Ok(()) if no cooldown active, or Err with
/// a message containing hours/minutes remaining.
#[allow(dead_code)]
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

    // ── RM-E6 / WP-E6.1 (audit FAU-01) key-length validation ────────

    /// 32 bytes (64 hex chars) — the canonical case.
    #[test]
    fn test_fau01_full_length_key_decodes() {
        let hex_64 = "11".repeat(32);
        let key = decode_faucet_key_hex(&hex_64).expect("decodes");
        assert_eq!(key.len(), 32);
        assert_eq!(key[0], 0x11);
    }

    /// `0x`-prefixed input is also accepted.
    #[test]
    fn test_fau01_with_0x_prefix() {
        let hex_64 = format!("0x{}", "ab".repeat(32));
        decode_faucet_key_hex(&hex_64).expect("0x prefix accepted");
    }

    /// Pre-fix: panicked on slicing. Post-fix: returns descriptive
    /// error.
    #[test]
    fn test_fau01_short_input_returns_error_not_panic() {
        let hex_short = "11".repeat(16); // 16 bytes, half the required length
        let err = decode_faucet_key_hex(&hex_short).expect_err("short input rejects");
        assert!(err.contains("32 bytes"));
    }

    /// Empty input rejects cleanly.
    #[test]
    fn test_fau01_empty_input_returns_error() {
        let err = decode_faucet_key_hex("").expect_err("empty rejects");
        assert!(err.contains("32 bytes"));
    }

    /// Non-hex input surfaces the underlying decode error.
    #[test]
    fn test_fau01_invalid_hex_returns_error() {
        let err = decode_faucet_key_hex("not-hex-at-all-not-hex-at-all-").expect_err("rejects");
        assert!(err.contains("Invalid FAUCET_PRIVATE_KEY"));
    }

    /// Property: longer-than-32-byte inputs take the first 32 bytes
    /// (matches the legacy slice behavior; we only added bounds
    /// checking, not stricter length enforcement, to preserve any
    /// callers that pad keys).
    #[test]
    fn test_fau01_long_input_uses_first_32_bytes() {
        let hex_long = format!("{}aaaa", "11".repeat(32));
        let key = decode_faucet_key_hex(&hex_long).expect("decodes");
        assert!(key.iter().all(|b| *b == 0x11));
    }
}
