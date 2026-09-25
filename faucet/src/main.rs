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
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::{error, info, warn};

mod cooldowns;
use cooldowns::{CooldownPolicy, Cooldowns};

mod turnstile;
use turnstile::TurnstileVerifier;

#[derive(Clone)]
struct FaucetState {
    rpc_url: String,
    api_key: Option<String>,
    chain_id: u64,
    faucet_address: Address,
    /// secp256k1 signing key for the faucet account. The faucet account is a
    /// genesis-funded EVM account (0xF4ADb…), so it submits standard EIP-155
    /// ECDSA transactions — the chain's native ed25519 account space can't be
    /// funded via the 20-byte EVM/genesis model (see Address::from_public_key).
    signing_key: Arc<k256::ecdsa::SigningKey>,
    /// File-backed per-address + per-IP cooldown tracker (FAU-04).
    cooldowns: Arc<Cooldowns>,
    /// Address whitelist: only these addresses can claim. Empty = no whitelist.
    address_whitelist: Arc<HashSet<String>>,
    /// Cloudflare Turnstile verifier (FAU-03). When `None`, CAPTCHA
    /// verification is skipped (used only in dev/local-CI builds).
    turnstile: Option<Arc<TurnstileVerifier>>,
    /// SECREM-01 FAUCET-2: reverse proxies whose forwarding headers we
    /// trust (`FAUCET_TRUSTED_PROXIES`, comma-separated IPs). When the
    /// TCP peer is NOT in this set, X-Forwarded-For / X-Real-IP are
    /// IGNORED — pre-fix any direct client could spoof a fresh XFF per
    /// request and launder the per-IP cooldown. Empty set (default) =
    /// trust no headers, use the socket peer (mirrors the RPC layer's
    /// WP-I.1 trust-boundary rule).
    trusted_proxies: Arc<HashSet<std::net::IpAddr>>,
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
            k256::ecdsa::SigningKey::from_slice(&key_array)
                .map_err(|e| format!("FAUCET_PRIVATE_KEY is not a valid secp256k1 key: {e}"))?
        } else {
            #[cfg(feature = "unsafe-deterministic-key")]
            {
                use sha3::{Digest, Keccak256};
                let seed = Keccak256::digest(b"citrate-faucet-testnet-v1");
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&seed);
                info!("⚠ Using deterministic faucet key (unsafe-deterministic-key feature). Local CI ONLY.");
                k256::ecdsa::SigningKey::from_slice(&key_bytes)
                    .map_err(|e| format!("deterministic key invalid: {e}"))?
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

    // Derive the faucet's EVM address from the secp256k1 public key:
    // keccak256(uncompressed_pubkey[1..65])[12..32]. This is the standard
    // Ethereum address — and matches the genesis-funded faucet allocation.
    let faucet_pubkey = signing_key.verifying_key();
    let faucet_address = {
        use sha3::{Digest, Keccak256};
        let point = faucet_pubkey.to_encoded_point(false);
        let hash = Keccak256::digest(&point.as_bytes()[1..]);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..]);
        Address(addr)
    };

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

    // SECREM-01 FAUCET-2: trusted reverse proxies for forwarding headers.
    let trusted_proxies: HashSet<std::net::IpAddr> = std::env::var("FAUCET_TRUSTED_PROXIES")
        .ok()
        .map(|s| {
            s.split(',')
                .filter_map(|p| p.trim().parse().ok())
                .collect()
        })
        .unwrap_or_default();
    if trusted_proxies.is_empty() {
        info!(
            "FAUCET_TRUSTED_PROXIES unset — forwarding headers ignored; \
             per-IP cooldown keys on the TCP peer address"
        );
    }

    let state = FaucetState {
        rpc_url,
        api_key,
        chain_id,
        faucet_address,
        signing_key: Arc::new(signing_key),
        cooldowns,
        address_whitelist: Arc::new(address_whitelist),
        turnstile,
        trusted_proxies: Arc::new(trusted_proxies),
    };

    // Build router
    let app = build_router(state, std::env::var("FAUCET_ALLOWED_ORIGINS").ok().as_deref());

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

/// PBA-L8-017: browser origins allowed to call the faucet cross-origin. The faucet's own page
/// is same-origin and needs no CORS. `FAUCET_ALLOWED_ORIGINS` (comma-separated, exact
/// `https://host` origins) overrides; malformed entries are dropped, and `*` is never accepted.
const DEFAULT_ALLOWED_ORIGINS: &[&str] = &[
    "https://citrate.ai",
    "https://www.citrate.ai",
    "https://docs.citrate.ai",
    "https://explorer.citrate.ai",
];

fn allowed_origins(raw: Option<&str>) -> Vec<axum::http::HeaderValue> {
    let list: Vec<String> = match raw {
        Some(r) if !r.trim().is_empty() => r.split(',').map(|s| s.trim().to_string()).collect(),
        _ => DEFAULT_ALLOWED_ORIGINS
            .iter()
            .map(|s| s.to_string())
            .collect(),
    };
    list.into_iter()
        .filter(|o| {
            (o.starts_with("https://") || o.starts_with("http://localhost"))
                && !o.contains('*')
                && !o.ends_with('/')
        })
        .filter_map(|o| axum::http::HeaderValue::from_str(&o).ok())
        .collect()
}

/// PBA-L8-017: replaces `CorsLayer::permissive()` (which sent `access-control-allow-origin: *`).
fn cors_layer(raw: Option<&str>) -> CorsLayer {
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(allowed_origins(raw)))
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers([axum::http::header::CONTENT_TYPE])
}

/// PBA-L8-017: the faucet served no security headers. Its page loads its script from
/// `/faucet.js` (no inline script or handlers), so the CSP needs no `'unsafe-inline'` for scripts;
/// `style-src 'unsafe-inline'` covers the page's <style> block and style attribute.
const FAUCET_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; \
connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

async fn security_headers(mut res: axum::response::Response) -> axum::response::Response {
    use axum::http::{header, HeaderValue};
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(FAUCET_CSP),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=63072000; includeSubDomains"),
    );
    res
}

fn build_router(state: FaucetState, allowed_origins_env: Option<&str>) -> Router {
    Router::new()
        .route("/", get(root))
        .route("/faucet.js", get(faucet_js))
        .route("/faucet", post(request_tokens))
        .route("/status", get(status))
        .route("/health", get(health))
        .layer(axum::middleware::map_response(security_headers))
        .layer(cors_layer(allowed_origins_env))
        .with_state(state)
}

const FAUCET_JS: &str = r#"async function claim(){
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
document.getElementById('btn').addEventListener('click',claim);
document.getElementById('addr').addEventListener('keydown',e=>{if(e.key==='Enter')claim()});
"#;

async fn faucet_js() -> ([(axum::http::HeaderName, &'static str); 1], &'static str) {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        FAUCET_JS,
    )
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
<button id="btn">Request 10 SALT</button>
<div id="msg" class="msg" style="display:none"></div>
<p class="info">Chain ID: 40204 &middot; 10 SALT per request &middot; 24h cooldown</p>
</div>
<script src="/faucet.js"></script>
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
    let client_ip = extract_client_ip(&headers, socket_addr, &state.trusted_proxies);

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
    //
    // SECREM-01 FAUCET-1: the slot is RESERVED atomically here, not
    // merely checked — pre-fix, `check()` and `record_success()` had an
    // RPC round-trip between them, so N concurrent requests for one
    // address all passed and all dripped. Every failure path below must
    // `release()` the reservation so legitimate users can retry.
    if let Err(denial) = state.cooldowns.try_reserve(&recipient_hex, &client_ip) {
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

    // Build + sign a standard EIP-155 legacy transaction (secp256k1). The
    // faucet account is the genesis-funded EVM account, so it must submit an
    // ECDSA tx that the chain decodes via the eth_tx_decoder / ecrecover path
    // (the native ed25519 path lands on an unfundable 32-byte-pubkey account).
    use sha3::{Digest, Keccak256};

    // Append a uint as a minimal big-endian byte string (leading zeros stripped).
    fn append_uint(s: &mut rlp::RlpStream, be: &[u8]) {
        let i = be.iter().position(|&b| b != 0).unwrap_or(be.len());
        s.append(&be[i..].to_vec());
    }

    let to_vec = recipient.0.to_vec(); // 20-byte EVM address
    let value_be = (DRIP_AMOUNT).to_be_bytes();
    let gas_price: u64 = 1_000_000_000;
    let gas_limit: u64 = 21_000;
    let chain_id = state.chain_id;

    // Signing payload: rlp([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0])
    let mut sp = rlp::RlpStream::new_list(9);
    sp.append(&nonce);
    sp.append(&gas_price);
    sp.append(&gas_limit);
    sp.append(&to_vec);
    append_uint(&mut sp, &value_be);
    sp.append_empty_data();
    sp.append(&chain_id);
    sp.append(&0u8);
    sp.append(&0u8);
    let sighash = Keccak256::digest(sp.out());

    let (sig, recid) = match state.signing_key.sign_prehash_recoverable(&sighash) {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to sign faucet transaction: {}", e);
            // SECREM-01 FAUCET-1: failed before send — return the slot.
            state.cooldowns.release(&recipient_hex, &client_ip);
            return Ok(Json(FaucetResponse {
                success: false,
                tx_hash: None,
                message: format!("Signing failed: {}", e),
                amount: "0".to_string(),
            }));
        }
    };
    let r = sig.r().to_bytes();
    let s_ = sig.s().to_bytes();
    let v = chain_id * 2 + 35 + recid.to_byte() as u64;

    // Full tx: rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s])
    let mut ft = rlp::RlpStream::new_list(9);
    ft.append(&nonce);
    ft.append(&gas_price);
    ft.append(&gas_limit);
    ft.append(&to_vec);
    append_uint(&mut ft, &value_be);
    ft.append_empty_data();
    ft.append(&v);
    append_uint(&mut ft, &r);
    append_uint(&mut ft, &s_);
    let tx_hex = format!("0x{}", hex::encode(ft.out()));

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
                // SECREM-01 FAUCET-1: drip failed — return the slot.
                state.cooldowns.release(&recipient_hex, &client_ip);
                Ok(Json(FaucetResponse {
                    success: false,
                    tx_hash: None,
                    message: format!("Transaction failed: {:?}", error),
                    amount: "0".to_string(),
                }))
            } else {
                // SECREM-01 FAUCET-1: ambiguous RPC response — the tx may
                // or may not have landed. Keep the reservation (do NOT
                // release): the cost of a false hold is one cooldown
                // window; the cost of a false release is a double drip.
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
            // SECREM-01 FAUCET-1: connection failure — the request never
            // reached the node; return the slot.
            state.cooldowns.release(&recipient_hex, &client_ip);
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
/// Extract the client IP for the per-IP cooldown leg + Turnstile remoteip.
///
/// SECREM-01 FAUCET-2 (was RM-B1 / WP-E6.3, audit FAU-03): forwarding
/// headers (`X-Forwarded-For` first hop, then `X-Real-IP`) are honored
/// ONLY when the TCP peer is a configured trusted proxy. Pre-fix the
/// headers were trusted unconditionally, so any direct client could
/// send a fresh spoofed XFF per request and launder the per-IP
/// cooldown entirely. Mirrors the RPC layer's WP-I.1 trust boundary.
fn extract_client_ip(
    headers: &HeaderMap,
    socket_addr: SocketAddr,
    trusted_proxies: &HashSet<std::net::IpAddr>,
) -> String {
    if !trusted_proxies.contains(&socket_addr.ip()) {
        // Direct connection (or untrusted hop): headers are
        // attacker-controlled input — use the socket peer.
        return socket_addr.ip().to_string();
    }
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

// Used by the test suite; the production handler validates inline.
// #[allow] for the restored clippy -D warnings gate (SECREM-01 Phase 0).
#[allow(dead_code)]
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

    // ── PBA-L8-017: CORS allowlist + security headers, over a real socket ──
    async fn spawn_faucet(allowed: Option<&str>) -> String {
        let state = FaucetState {
            rpc_url: "http://127.0.0.1:9".into(),
            api_key: None,
            chain_id: 40204,
            faucet_address: Address([0u8; 20]),
            signing_key: Arc::new(
                k256::ecdsa::SigningKey::from_slice(&[7u8; 32]).expect("test key"),
            ),
            cooldowns: Arc::new(Cooldowns::in_memory(CooldownPolicy::default())),
            address_whitelist: Arc::new(HashSet::new()),
            turnstile: None,
            trusted_proxies: Arc::new(HashSet::new()),
        };
        let app = build_router(state, allowed);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn l8017_security_headers_on_every_route() {
        let base = spawn_faucet(None).await;
        let c = reqwest::Client::new();
        for path in ["/", "/faucet.js", "/status", "/health"] {
            let r = c.get(format!("{base}{path}")).send().await.expect("req");
            let h = r.headers();
            assert_eq!(
                h.get("content-security-policy")
                    .and_then(|v| v.to_str().ok()),
                Some(FAUCET_CSP),
                "{path}"
            );
            assert_eq!(
                h.get("x-content-type-options")
                    .and_then(|v| v.to_str().ok()),
                Some("nosniff"),
                "{path}"
            );
            assert_eq!(
                h.get("x-frame-options").and_then(|v| v.to_str().ok()),
                Some("DENY"),
                "{path}"
            );
            assert_eq!(
                h.get("referrer-policy").and_then(|v| v.to_str().ok()),
                Some("no-referrer"),
                "{path}"
            );
            assert!(h.get("strict-transport-security").is_some(), "{path}");
        }
        assert!(FAUCET_CSP.contains("frame-ancestors 'none'"));
        assert!(!FAUCET_CSP.contains("script-src 'unsafe-inline'"));
    }

    #[tokio::test]
    async fn l8017_page_has_no_inline_script_or_handlers() {
        let base = spawn_faucet(None).await;
        let html = reqwest::get(format!("{base}/"))
            .await
            .expect("req")
            .text()
            .await
            .expect("body");
        assert!(html.contains(r#"<script src="/faucet.js"></script>"#));
        assert!(!html.contains("onclick="));
        assert_eq!(html.matches("<script").count(), 1);
        let js = reqwest::get(format!("{base}/faucet.js"))
            .await
            .expect("req");
        assert_eq!(
            js.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/javascript; charset=utf-8")
        );
        assert!(js
            .text()
            .await
            .expect("js")
            .contains("addEventListener('click',claim)"));
    }

    #[tokio::test]
    async fn l8017_cors_is_an_allowlist_not_star() {
        let base = spawn_faucet(None).await;
        let c = reqwest::Client::new();
        let get = |origin: &'static str| {
            c.get(format!("{base}/status"))
                .header("origin", origin)
                .send()
        };
        let ok = get("https://docs.citrate.ai").await.expect("req");
        assert_eq!(
            ok.headers()
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok()),
            Some("https://docs.citrate.ai")
        );
        let evil = get("https://evil.example").await.expect("req");
        assert!(evil.headers().get("access-control-allow-origin").is_none());
        let pre = c
            .request(reqwest::Method::OPTIONS, format!("{base}/faucet"))
            .header("origin", "https://evil.example")
            .header("access-control-request-method", "POST")
            .send()
            .await
            .expect("req");
        assert!(pre.headers().get("access-control-allow-origin").is_none());
    }

    #[test]
    fn l8017_allowed_origins_env_parsing() {
        let v = |raw: Option<&str>| {
            allowed_origins(raw)
                .into_iter()
                .map(|h| h.to_str().unwrap_or_default().to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(v(None).len(), DEFAULT_ALLOWED_ORIGINS.len());
        assert_eq!(v(Some("  ")).len(), DEFAULT_ALLOWED_ORIGINS.len());
        assert_eq!(v(Some("https://a.example, *, http://evil.example, https://b.example/, http://localhost:3000")), vec!["https://a.example", "http://localhost:3000"]);
        assert!(v(Some("*")).is_empty());
    }

    /// SECREM-01 FAUCET-2 red test: pre-fix, a direct client could spoof
    /// a fresh X-Forwarded-For per request and launder the per-IP
    /// cooldown. Headers are now ignored unless the TCP peer is a
    /// configured trusted proxy.
    #[test]
    fn test_faucet2_xff_ignored_from_untrusted_peer() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "6.6.6.6".parse().expect("hv"));
        let peer: SocketAddr = "203.0.113.9:55555".parse().expect("addr");
        let trusted = HashSet::new();
        assert_eq!(
            extract_client_ip(&headers, peer, &trusted),
            "203.0.113.9",
            "FAUCET-2 regression: spoofed XFF honored from a direct client"
        );
    }

    /// SECREM-01 FAUCET-2: behind a configured trusted proxy the first
    /// XFF hop is honored (legitimate reverse-proxy deployment), and
    /// X-Real-IP works as the fallback.
    #[test]
    fn test_faucet2_xff_honored_from_trusted_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.7, 10.0.0.1".parse().expect("hv"));
        let peer: SocketAddr = "10.0.0.1:443".parse().expect("addr");
        let trusted: HashSet<std::net::IpAddr> =
            ["10.0.0.1".parse().expect("ip")].into_iter().collect();
        assert_eq!(extract_client_ip(&headers, peer, &trusted), "198.51.100.7");

        let mut xri_only = HeaderMap::new();
        xri_only.insert("x-real-ip", "198.51.100.8".parse().expect("hv"));
        assert_eq!(extract_client_ip(&xri_only, peer, &trusted), "198.51.100.8");
        // Trusted proxy, no headers at all → proxy's own address.
        assert_eq!(
            extract_client_ip(&HeaderMap::new(), peer, &trusted),
            "10.0.0.1"
        );
    }

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
