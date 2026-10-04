use axum::{
    extract::{ConnectInfo, Query, State},
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

mod desktop;
mod limits;
mod liveness;
mod membership;
use limits::GlobalCap;
use liveness::ReadinessCache;

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
    /// One HTTP client for every RPC call (connection reuse).
    http: reqwest::Client,
    /// HUP-S6.5: optional faucet-wide hourly drip cap (`FAUCET_MAX_DRIPS_PER_HOUR`). `None` = off.
    global_cap: Option<Arc<GlobalCap>>,
    /// HUP-S6.5 (ADR O-2): optional membership SBT (`FAUCET_MEMBER_SBT`). `None` = no check.
    member_sbt: Option<String>,
    /// HUP-S6.5 (ADR O-3): public Turnstile site key (`FAUCET_TURNSTILE_SITE_KEY`). When set,
    /// the page renders the challenge. `None` = the page is unchanged.
    turnstile_site_key: Option<String>,
    /// HUP-S6.5 (ADR O-3): exact desktop-app origins allowed by CORS (`FAUCET_DESKTOP_ORIGINS`).
    desktop_origins: Arc<Vec<String>>,
    /// HUP-S6.5: cached `/ready` probe.
    readiness: Arc<ReadinessCache>,
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
    /// HUP-S6.5: a stable machine-readable reason on a refusal (absent on success). The desktop
    /// app keys its honest message on this, not on the text.
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'static str>,
    /// HUP-S6.5: which limit refused the request (`address`, `ip` or `global`).
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<&'static str>,
    /// HUP-S6.5: seconds until a retry can succeed, on a rate-limit refusal.
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_secs: Option<u64>,
    /// HUP-S6.5: Unix seconds when the next request can succeed, on a rate-limit refusal.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_eligible_at: Option<u64>,
}

impl FaucetResponse {
    /// A refusal with a stable `code`.
    fn deny(code: &'static str, message: impl Into<String>) -> Self {
        FaucetResponse {
            success: false,
            tx_hash: None,
            message: message.into(),
            amount: "0".to_string(),
            code: Some(code),
            limit: None,
            retry_after_secs: None,
            next_eligible_at: None,
        }
    }

    /// A rate-limit refusal: which limit, and when the next request can succeed.
    fn rate_limited(limit: &'static str, message: String, retry_after_secs: u64, now: u64) -> Self {
        let mut r = Self::deny("rate_limited", message);
        r.limit = Some(limit);
        r.retry_after_secs = Some(retry_after_secs);
        r.next_eligible_at = Some(now.saturating_add(retry_after_secs));
        r
    }
}

/// Map a cooldown denial to (limit, seconds remaining).
fn denial_parts(d: &cooldowns::CooldownDenial) -> (&'static str, u64) {
    match d {
        cooldowns::CooldownDenial::AddressCooldown { remaining_secs } => ("address", *remaining_secs),
        cooldowns::CooldownDenial::IpCooldown { remaining_secs } => ("ip", *remaining_secs),
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One drip plus the gas of its own transfer (21,000 gas at the faucet's fixed 1 gwei).
const MIN_READY_BALANCE_WEI: u128 = DRIP_AMOUNT + 21_000 * 1_000_000_000;

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
    let faucet_address = evm_address_of(&signing_key);

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

    // HUP-S6.5 / F-5: opt-in limits and the desktop path. Every one is off unless the operator
    // sets it; a malformed value stops the faucet at startup instead of being ignored.
    let global_cap = GlobalCap::from_env(std::env::var("FAUCET_MAX_DRIPS_PER_HOUR").ok().as_deref())?;
    match &global_cap {
        Some(c) => info!("Global drip cap: {} per hour", c.max()),
        None => info!("Global drip cap off (set FAUCET_MAX_DRIPS_PER_HOUR to enable)"),
    }
    let member_sbt = membership::parse_sbt_env(std::env::var("FAUCET_MEMBER_SBT").ok().as_deref())?;
    match &member_sbt {
        Some(a) => info!("Membership check on: recipients must hold a token of {}", a),
        None => info!("Membership check off (set FAUCET_MEMBER_SBT to enable)"),
    }
    let turnstile_site_key =
        desktop::parse_site_key(std::env::var("FAUCET_TURNSTILE_SITE_KEY").ok().as_deref())?;
    if turnstile_site_key.is_some() && turnstile.is_none() {
        return Err(
            "FAUCET_TURNSTILE_SITE_KEY is set but FAUCET_TURNSTILE_SECRET is not: the page would \
             show a challenge the server never checks. Set both or neither."
                .into(),
        );
    }
    let (desktop_origins, dropped_desktop) =
        desktop::desktop_origins(std::env::var("FAUCET_DESKTOP_ORIGINS").ok().as_deref());
    for d in &dropped_desktop {
        warn!("FAUCET_DESKTOP_ORIGINS: ignoring {:?} (not a known desktop-app origin)", d);
    }
    if !desktop_origins.is_empty() {
        info!("Desktop-app origins allowed: {}", desktop_origins.join(", "));
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
        http: reqwest::Client::new(),
        global_cap: global_cap.map(Arc::new),
        member_sbt,
        turnstile_site_key,
        desktop_origins: Arc::new(desktop_origins),
        readiness: Arc::new(ReadinessCache::default()),
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

/// The standard EVM address of a secp256k1 key: keccak256(uncompressed_pubkey[1..65])[12..32].
fn evm_address_of(key: &k256::ecdsa::SigningKey) -> Address {
    use sha3::{Digest, Keccak256};
    let point = key.verifying_key().to_encoded_point(false);
    let hash = Keccak256::digest(&point.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    Address(addr)
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
            (o.starts_with("https://") || is_local_dev_origin(o))
                && !o.contains('*')
                && !o.ends_with('/')
        })
        .filter_map(|o| axum::http::HeaderValue::from_str(&o).ok())
        .collect()
}

/// `http://localhost` or `http://localhost:<port>` exactly (operator dev use); nothing that merely
/// starts with that text (e.g. `http://localhost.example`).
fn is_local_dev_origin(o: &str) -> bool {
    match o.strip_prefix("http://localhost") {
        Some("") => true,
        Some(rest) => rest
            .strip_prefix(':')
            .is_some_and(|port| !port.is_empty() && port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit())),
        None => false,
    }
}

/// PBA-L8-017: replaces `CorsLayer::permissive()` (which sent `access-control-allow-origin: *`).
/// HUP-S6.5: plus the exact desktop-app origins the operator opted into (already filtered by
/// `desktop::desktop_origins` to the known set).
fn cors_layer(raw: Option<&str>, desktop: &[String]) -> CorsLayer {
    let mut list = allowed_origins(raw);
    list.extend(
        desktop
            .iter()
            .filter(|o| desktop::KNOWN_DESKTOP_ORIGINS.contains(&o.as_str()))
            .filter_map(|o| axum::http::HeaderValue::from_str(o).ok()),
    );
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(list))
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers([axum::http::header::CONTENT_TYPE])
}

/// PBA-L8-017: the faucet served no security headers. Its page loads its script from
/// `/faucet.js` (no inline script or handlers), so the CSP needs no `'unsafe-inline'` for scripts;
/// `style-src 'unsafe-inline'` covers the page's <style> block and style attribute.
const FAUCET_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; \
connect-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// The CSP every response carries: [`FAUCET_CSP`], or, when the operator turned the CAPTCHA page
/// on (HUP-S6.5), the same policy plus the CAPTCHA provider's script and frame.
fn page_csp(turnstile_site_key: Option<&str>) -> String {
    match turnstile_site_key {
        Some(_) => desktop::csp_with_turnstile(FAUCET_CSP),
        None => FAUCET_CSP.to_string(),
    }
}

async fn security_headers(
    State(csp): State<Arc<axum::http::HeaderValue>>,
    mut res: axum::response::Response,
) -> axum::response::Response {
    use axum::http::{header, HeaderValue};
    let h = res.headers_mut();
    h.insert(header::CONTENT_SECURITY_POLICY, (*csp).clone());
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
    let csp = axum::http::HeaderValue::from_str(&page_csp(state.turnstile_site_key.as_deref()))
        .unwrap_or_else(|_| axum::http::HeaderValue::from_static(FAUCET_CSP));
    let desktop = state.desktop_origins.clone();
    Router::new()
        .route("/", get(root))
        .route("/faucet.js", get(faucet_js))
        .route("/faucet", post(request_tokens))
        .route("/status", get(status))
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/eligibility", get(eligibility))
        .route("/logo.svg", get(logo))
        .route("/fonts/space-grotesk-600.woff2", get(font_grotesk_600))
        .route("/fonts/geist-mono-400.woff2", get(font_mono_400))
        .route("/fonts/geist-mono-500.woff2", get(font_mono_500))
        // CORS inside, security headers outermost: CORS preflight answers (which CorsLayer
        // produces itself) carry the same headers as every other response.
        .layer(cors_layer(allowed_origins_env, &desktop))
        .layer(axum::middleware::map_response_with_state(
            Arc::new(csp),
            security_headers,
        ))
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
  const body={address:addr};
  const tok=document.querySelector('[name="cf-turnstile-response"]');
  if(tok&&tok.value){body.turnstile_token=tok.value;}
  try{
    const r=await fetch('/faucet',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d=await r.json();
    msg.style.display='block';
    if(d.success){msg.className='msg ok';msg.textContent='Sent 10 SALT! TX: '+d.tx_hash;}
    else{msg.className='msg err';msg.textContent=d.message;}
  }catch(e){msg.className='msg err';msg.style.display='block';msg.textContent='Error: '+e.message;}
  btn.disabled=false;btn.textContent='Request 10 SALT';
  if(window.turnstile&&tok){window.turnstile.reset();}
}
(function(){
  const q=new URLSearchParams(window.location.search).get('address');
  if(q&&/^0x[0-9a-fA-F]{40}$/.test(q)){document.getElementById('addr').value=q;}
})();
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

/// HUP-S6.5: the page, with the CAPTCHA widget when the operator turned the CAPTCHA page on.
/// Without a site key it is exactly [`PAGE_HTML`].
fn render_page(turnstile_site_key: Option<&str>) -> String {
    match turnstile_site_key {
        Some(key) => PAGE_HTML.replacen(
            "<button id=\"btn\">",
            &format!("{}\n<button id=\"btn\">", desktop::turnstile_markup(key)),
            1,
        ),
        None => PAGE_HTML.to_string(),
    }
}

async fn root(State(state): State<FaucetState>) -> axum::response::Html<String> {
    axum::response::Html(render_page(state.turnstile_site_key.as_deref()))
}


    // Charter register of the citrate-core / app-layer design system
    // (src/styles/tokens.css + foundation.css): light, civic, document-like.
    // Tokens inlined with concrete values (no CSS build step). Display +
    // mono faces (Space Grotesk, Geist Mono) are the two the app self-hosts;
    // they are served same-origin from /fonts/* so the page matches the app
    // under the strict faucet CSP (font-src 'self'). Body sans falls back to
    // the system stack, exactly as citrate-core does (it self-hosts no sans).
const PAGE_HTML: &str = r##"<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#f4f1ea">
<title>Citrate Faucet</title>
<style>
@font-face{font-family:"Space Grotesk";font-style:normal;font-weight:600;font-display:swap;src:url(/fonts/space-grotesk-600.woff2) format("woff2")}
@font-face{font-family:"Geist Mono";font-style:normal;font-weight:400;font-display:swap;src:url(/fonts/geist-mono-400.woff2) format("woff2")}
@font-face{font-family:"Geist Mono";font-style:normal;font-weight:500;font-display:swap;src:url(/fonts/geist-mono-500.woff2) format("woff2")}
:root{
  --srf-0:#f4f1ea;--srf-1:#faf8f3;--srf-2:#ffffff;
  --tx-1:#0e0f0c;--tx-2:#555851;--tx-3:#84867f;
  --line-1:#d9dad4;--line-2:#c3c4be;
  --accent:#8ecc09;--accent-deep:#5a8205;
  --ok:#4f8a05;--ok-bg:#ecf5d4;--danger:#a72414;--danger-bg:#f6e1de;
  --font-display:"Space Grotesk",system-ui,-apple-system,"Segoe UI",sans-serif;
  --font-sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  --font-mono:"Geist Mono",ui-monospace,"SF Mono",Menlo,monospace;
  --focus-ring:0 0 0 3px rgba(142,204,9,.35);
}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:var(--font-sans);background:var(--srf-0);color:var(--tx-1);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
.card{background:var(--srf-1);border:1px solid var(--line-1);border-radius:12px;padding:32px;max-width:440px;width:100%;box-shadow:0 1px 2px rgba(14,15,12,.04),0 8px 24px rgba(14,15,12,.06)}
.brand{display:flex;align-items:center;margin-bottom:22px}
.brand img{height:26px;width:auto;display:block}
.eyebrow{font-family:var(--font-mono);font-size:11px;font-weight:500;letter-spacing:.14em;text-transform:uppercase;color:var(--tx-3);margin-bottom:10px}
h1{font-family:var(--font-display);font-size:26px;font-weight:600;letter-spacing:-.01em;margin-bottom:6px}
.sub{color:var(--tx-2);font-size:14px;line-height:1.5;margin-bottom:24px}
.lbl{font-family:var(--font-mono);font-size:10px;font-weight:500;letter-spacing:.14em;text-transform:uppercase;color:var(--tx-2);display:block;margin-bottom:6px}
input{width:100%;height:40px;padding:8px 12px;background:var(--srf-2);border:1px solid var(--line-2);border-radius:6px;color:var(--tx-1);font-size:13px;font-family:var(--font-mono);outline:none;transition:border-color .14s cubic-bezier(.2,0,0,1),box-shadow .14s cubic-bezier(.2,0,0,1)}
input:focus{border-color:var(--tx-1);box-shadow:var(--focus-ring)}
input::placeholder{color:var(--tx-3)}
button{width:100%;height:42px;padding:0 18px;background:var(--accent);color:var(--tx-1);border:1px solid var(--accent);border-radius:6px;font-family:var(--font-sans);font-size:14px;font-weight:600;cursor:pointer;margin-top:18px;transition:background .14s cubic-bezier(.2,0,0,1),color .14s cubic-bezier(.2,0,0,1),transform .14s cubic-bezier(.2,0,0,1)}
button:hover{background:var(--accent-deep);border-color:var(--accent-deep);color:#fff}
button:active{transform:translateY(1px)}
button:disabled{opacity:.45;cursor:not-allowed}
.msg{margin-top:16px;padding:10px 12px;border-radius:6px;font-size:13px;line-height:1.45;word-break:break-word}
.msg.ok{background:var(--ok-bg);border:1px solid var(--ok);color:var(--ok)}
.msg.err{background:var(--danger-bg);border:1px solid var(--danger);color:var(--danger)}
.info{margin-top:22px;padding-top:16px;border-top:1px solid var(--line-1);font-family:var(--font-mono);font-size:11px;letter-spacing:.02em;color:var(--tx-3);text-align:center}
@media (prefers-reduced-motion:reduce){*{transition-duration:.01ms!important}}
</style>
</head><body>
<div class="card">
<div class="brand"><img src="/logo.svg" alt="Citrate"></div>
<div class="eyebrow">Testnet &middot; Chain 40204</div>
<h1>Faucet</h1>
<p class="sub">Request test SALT for the Citrate testnet. Ten SALT per address, once every 24&nbsp;hours.</p>
<label class="lbl" for="addr">Wallet address</label>
<input id="addr" placeholder="0x0000000000000000000000000000000000000000" spellcheck="false" autocomplete="off" autocapitalize="off">
<button id="btn">Request 10 SALT</button>
<div id="msg" class="msg" style="display:none"></div>
<p class="info">10 SALT per request &middot; 24h cooldown &middot; Chain ID 40204</p>
</div>
<script src="/faucet.js"></script>
</body></html>"##;

async fn status(State(state): State<FaucetState>) -> Json<serde_json::Value> {
    let policy = state.cooldowns.policy();
    Json(serde_json::json!({
        "status": "online",
        "network": "citrate-testnet-beta",
        "amount_per_request": "10 SALT",
        // HUP-S6.5: machine-readable limits, so a client can explain them without guessing.
        "chain_id": state.chain_id,
        "drip_wei": DRIP_AMOUNT.to_string(),
        "address_cooldown_secs": policy.address_cooldown_secs,
        "ip_cooldown_secs": policy.ip_cooldown_secs,
        "global_cap_per_hour": state.global_cap.as_ref().map(|c| c.max()),
        "global_cap_used": state.global_cap.as_ref().map(|c| c.in_window(unix_now())),
        "captcha": state.turnstile.is_some(),
        "turnstile_site_key": state.turnstile_site_key,
        "membership_check": state.member_sbt.is_some(),
    }))
}

/// Liveness: the process is up and serving. Never touches the RPC.
async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

/// HUP-S6.5 readiness: could a drip succeed now? 200 when ready, 503 when not, with the reason.
/// Cached for [`liveness::CACHE_TTL`], so public callers cannot amplify RPC load.
async fn ready(
    State(state): State<FaucetState>,
) -> (StatusCode, Json<liveness::Readiness>) {
    let r = match state.readiness.fresh(liveness::CACHE_TTL) {
        Some(r) => r,
        None => {
            let r = liveness::probe(
                &state.http,
                &state.rpc_url,
                state.api_key.as_deref(),
                state.chain_id,
                &format!("0x{}", hex::encode(state.faucet_address.0)),
                MIN_READY_BALANCE_WEI,
                unix_now(),
            )
            .await;
            state.readiness.store(r.clone());
            r
        }
    };
    let code = if r.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(r))
}

#[derive(Debug, Deserialize)]
struct EligibilityQuery {
    address: String,
}

/// HUP-S6.5: would a request for `address` from this caller pass the cooldowns right now?
/// Read-only: it reserves nothing. The desktop app uses it to show the next eligible time
/// without spending a request, and to see a drip the member made in the in-app challenge window.
async fn eligibility(
    State(state): State<FaucetState>,
    ConnectInfo(socket_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<EligibilityQuery>,
) -> Json<serde_json::Value> {
    let Ok((recipient_hex, _)) = validate_address(&q.address) else {
        return Json(serde_json::json!({
            "eligible": false,
            "code": "invalid_address",
            "message": "Invalid address format",
        }));
    };
    let client_ip = extract_client_ip(&headers, socket_addr, &state.trusted_proxies);
    let now = unix_now();
    match state.cooldowns.check(&recipient_hex, &client_ip) {
        Ok(()) => Json(serde_json::json!({
            "address": format!("0x{recipient_hex}"),
            "eligible": true,
        })),
        Err(d) => {
            let (limit, remaining) = denial_parts(&d);
            Json(serde_json::json!({
                "address": format!("0x{recipient_hex}"),
                "eligible": false,
                "code": "rate_limited",
                "limit": limit,
                "retry_after_secs": remaining,
                "next_eligible_at": now.saturating_add(remaining),
            }))
        }
    }
}

// Brand assets, embedded at compile time so the faucet stays a single
// self-contained binary and serves everything same-origin (satisfies the
// strict faucet CSP: img-src 'self', font-src 'self').
const MARQUEE_SVG: &str = include_str!("../assets/citrate_marquee_black.svg");
const FONT_GROTESK_600: &[u8] = include_bytes!("../assets/fonts/space-grotesk-600.woff2");
const FONT_MONO_400: &[u8] = include_bytes!("../assets/fonts/geist-mono-400.woff2");
const FONT_MONO_500: &[u8] = include_bytes!("../assets/fonts/geist-mono-500.woff2");

async fn logo() -> impl axum::response::IntoResponse {
    (
        [
            (axum::http::header::CONTENT_TYPE, "image/svg+xml"),
            (axum::http::header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        MARQUEE_SVG,
    )
}

fn woff2(bytes: &'static [u8]) -> ([(axum::http::HeaderName, &'static str); 2], &'static [u8]) {
    (
        [
            (axum::http::header::CONTENT_TYPE, "font/woff2"),
            (
                axum::http::header::CACHE_CONTROL,
                "public, max-age=31536000, immutable",
            ),
        ],
        bytes,
    )
}
async fn font_grotesk_600() -> impl axum::response::IntoResponse {
    woff2(FONT_GROTESK_600)
}
async fn font_mono_400() -> impl axum::response::IntoResponse {
    woff2(FONT_MONO_400)
}
async fn font_mono_500() -> impl axum::response::IntoResponse {
    woff2(FONT_MONO_500)
}

/// Return every slot a request reserved (the drip did not reach the chain).
fn release_slots(state: &FaucetState, recipient_hex: &str, client_ip: &str, cap_taken_at: Option<u64>) {
    state.cooldowns.release(recipient_hex, client_ip);
    if let (Some(cap), Some(at)) = (state.global_cap.as_ref(), cap_taken_at) {
        cap.give_back(at);
    }
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
            return Ok(Json(FaucetResponse::deny(
                "invalid_address",
                "Invalid address format",
            )));
        }
    };
    let mut recipient_addr = [0u8; 20];
    recipient_addr.copy_from_slice(&recipient_bytes);

    // Address whitelist check
    if !state.address_whitelist.is_empty() && !state.address_whitelist.contains(&recipient_hex) {
        warn!("Faucet request rejected: address {} not in whitelist", recipient_hex);
        return Ok(Json(FaucetResponse::deny(
            "not_whitelisted",
            "Address not whitelisted for testnet beta",
        )));
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
                return Ok(Json(FaucetResponse::deny(
                    "captcha_required",
                    "CAPTCHA required: turnstile_token missing",
                )));
            }
        };
        match verifier.verify(token, Some(&client_ip)).await {
            Ok(true) => {}
            Ok(false) => {
                return Ok(Json(FaucetResponse::deny(
                    "captcha_failed",
                    "CAPTCHA verification failed",
                )));
            }
            Err(e) => {
                error!("Turnstile verification error: {}", e);
                return Ok(Json(FaucetResponse::deny(
                    "captcha_unavailable",
                    "CAPTCHA service unavailable, try again later",
                )));
            }
        }
    }

    // HUP-S6.5 (faucet ADR O-2, pending owner sign-off): membership check, when the operator
    // configured one. Fails closed: an RPC failure refuses the drip.
    if let Some(sbt) = state.member_sbt.as_deref() {
        // A caller already inside a cooldown is answered from memory first, so a refused caller
        // cannot make the faucet spend an eth_call per request. Read-only: the atomic
        // reservation below still decides.
        if let Err(denial) = state.cooldowns.check(&recipient_hex, &client_ip) {
            let (limit, remaining) = denial_parts(&denial);
            return Ok(Json(FaucetResponse::rate_limited(
                limit,
                format!("Rate limited: {}", denial),
                remaining,
                unix_now(),
            )));
        }
        match membership::holds_member_sbt(
            &state.http,
            &state.rpc_url,
            state.api_key.as_deref(),
            sbt,
            &recipient_addr,
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => {
                return Ok(Json(FaucetResponse::deny(
                    "not_member",
                    "This faucet drips only to Citrate members: the address holds no membership token",
                )));
            }
            Err(e) => {
                warn!("membership check failed: {}", e);
                return Ok(Json(FaucetResponse::deny(
                    "membership_unavailable",
                    "The membership check is unavailable, try again later",
                )));
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
    let now = unix_now();
    if let Err(denial) = state.cooldowns.try_reserve(&recipient_hex, &client_ip) {
        let (limit, remaining) = denial_parts(&denial);
        return Ok(Json(FaucetResponse::rate_limited(
            limit,
            format!("Rate limited: {}", denial),
            remaining,
            now,
        )));
    }

    // HUP-S6.5: the optional faucet-wide hourly cap, taken after the per-caller reservation
    // (and that reservation returned when the cap refuses).
    let cap_taken_at = match state.global_cap.as_ref() {
        None => None,
        Some(cap) => match cap.try_take(now) {
            Ok(()) => Some(now),
            Err(retry) => {
                state.cooldowns.release(&recipient_hex, &client_ip);
                return Ok(Json(FaucetResponse::rate_limited(
                    "global",
                    "Rate limited: the faucet's hourly limit is reached".to_string(),
                    retry,
                    now,
                )));
            }
        },
    };

    let recipient = Address(recipient_addr);

    info!("Faucet request for address: 0x{} (ip={})", hex::encode(recipient.0), client_ip);

    // Build and sign a real transaction using the faucet's secp256k1 key.
    // This uses eth_sendRawTransaction — no unsigned tx support needed on the node.

    let from_hex = format!("0x{}", hex::encode(state.faucet_address.0));
    let client = &state.http;

    // Query the current nonce for the faucet account. HUP-S6.5: an unreadable nonce refuses the
    // drip (and returns the slots) instead of guessing nonce 0.
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
        let parsed = match resp {
            Ok(r) => r.json::<serde_json::Value>().await.ok().and_then(|json| {
                json.get("result")
                    .and_then(|v| v.as_str())
                    .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            }),
            Err(_) => None,
        };
        match parsed {
            Some(n) => n,
            None => {
                release_slots(&state, &recipient_hex, &client_ip, cap_taken_at);
                return Ok(Json(FaucetResponse::deny(
                    "node_unreachable",
                    "Failed to connect to node",
                )));
            }
        }
    };

    // Build + sign a standard EIP-155 legacy transaction (secp256k1). The
    // faucet account is the genesis-funded EVM account, so it must submit an
    // ECDSA tx that the chain decodes via the eth_tx_decoder / ecrecover path
    // (the native ed25519 path lands on an unfundable 32-byte-pubkey account).
    let tx_hex = match sign_drip_tx(&state.signing_key, state.chain_id, nonce, &recipient.0) {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to sign faucet transaction: {}", e);
            // SECREM-01 FAUCET-1: failed before send — return the slot.
            release_slots(&state, &recipient_hex, &client_ip, cap_taken_at);
            return Ok(Json(FaucetResponse::deny(
                "signing_failed",
                format!("Signing failed: {}", e),
            )));
        }
    };

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
                    code: None,
                    limit: None,
                    retry_after_secs: None,
                    next_eligible_at: None,
                }))
            } else if let Some(error) = json.get("error") {
                error!("RPC error: {:?}", error);
                // SECREM-01 FAUCET-1: drip failed — return the slot.
                release_slots(&state, &recipient_hex, &client_ip, cap_taken_at);
                Ok(Json(FaucetResponse::deny(
                    "rpc_error",
                    format!("Transaction failed: {:?}", error),
                )))
            } else {
                // SECREM-01 FAUCET-1: ambiguous RPC response — the tx may
                // or may not have landed. Keep the reservation (do NOT
                // release): the cost of a false hold is one cooldown
                // window; the cost of a false release is a double drip.
                Ok(Json(FaucetResponse::deny(
                    "unknown_rpc_response",
                    "Unknown RPC response",
                )))
            }
        }
        Err(e) => {
            error!("Failed to send transaction: {}", e);
            // SECREM-01 FAUCET-1: connection failure — the request never
            // reached the node; return the slot.
            release_slots(&state, &recipient_hex, &client_ip, cap_taken_at);
            Ok(Json(FaucetResponse::deny(
                "node_unreachable",
                "Failed to connect to node",
            )))
        }
    }
}

/// Build and sign the drip: an EIP-155 legacy transfer of [`DRIP_AMOUNT`] at 1 gwei, 21,000 gas.
/// Returns the raw transaction as `0x` hex.
fn sign_drip_tx(
    key: &k256::ecdsa::SigningKey,
    chain_id: u64,
    nonce: u64,
    to: &[u8; 20],
) -> Result<String, String> {
    use sha3::{Digest, Keccak256};

    // Append a uint as a minimal big-endian byte string (leading zeros stripped).
    fn append_uint(s: &mut rlp::RlpStream, be: &[u8]) {
        let i = be.iter().position(|&b| b != 0).unwrap_or(be.len());
        s.append(&be[i..].to_vec());
    }

    let to_vec = to.to_vec(); // 20-byte EVM address
    let value_be = (DRIP_AMOUNT).to_be_bytes();
    let gas_price: u64 = 1_000_000_000;
    let gas_limit: u64 = 21_000;

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

    let (sig, recid) = key
        .sign_prehash_recoverable(&sighash)
        .map_err(|e| e.to_string())?;
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
    Ok(format!("0x{}", hex::encode(ft.out())))
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

    /// A throwaway secp256k1 key made at run time, so no key material is a constant in the
    /// source. Unique per call (clock + counter); nothing the tests assert depends on its value.
    fn throwaway_key(label: &str) -> k256::ecdsa::SigningKey {
        use sha3::{Digest, Keccak256};
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(1);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let seed = Keccak256::digest(format!("{label}-{nanos}-{n}").as_bytes());
        k256::ecdsa::SigningKey::from_slice(&seed).expect("scalar")
    }

    // ── PBA-L8-017: CORS allowlist + security headers, over a real socket ──
    fn test_state(rpc_url: &str) -> FaucetState {
        FaucetState {
            rpc_url: rpc_url.into(),
            api_key: None,
            chain_id: 40204,
            faucet_address: Address([0u8; 20]),
            signing_key: Arc::new(throwaway_key("faucet-test-state")),
            cooldowns: Arc::new(Cooldowns::in_memory(CooldownPolicy::default())),
            address_whitelist: Arc::new(HashSet::new()),
            turnstile: None,
            trusted_proxies: Arc::new(HashSet::new()),
            http: reqwest::Client::new(),
            global_cap: None,
            member_sbt: None,
            turnstile_site_key: None,
            desktop_origins: Arc::new(Vec::new()),
            readiness: Arc::new(ReadinessCache::default()),
        }
    }

    async fn spawn_faucet(allowed: Option<&str>) -> String {
        serve(test_state("http://127.0.0.1:9"), allowed).await
    }

    async fn serve(state: FaucetState, allowed: Option<&str>) -> String {
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
        assert_eq!(
            v(Some("http://localhost, http://localhost:8080, http://localhost.evil.com, http://localhostevil.com, http://localhost:, http://localhost:80a, http://localhost:123456")),
            vec!["http://localhost", "http://localhost:8080"]
        );
    }

    fn assert_security_headers(h: &reqwest::header::HeaderMap, what: &str) {
        let get = |k: &str| h.get(k).and_then(|v| v.to_str().ok()).map(str::to_string);
        assert_eq!(get("content-security-policy").as_deref(), Some(FAUCET_CSP), "{what}");
        assert_eq!(get("x-content-type-options").as_deref(), Some("nosniff"), "{what}");
        assert_eq!(get("x-frame-options").as_deref(), Some("DENY"), "{what}");
        assert_eq!(get("referrer-policy").as_deref(), Some("no-referrer"), "{what}");
        assert!(get("strict-transport-security").is_some(), "{what}");
    }

    #[tokio::test]
    async fn l8017_security_headers_on_errors_and_preflight() {
        let base = spawn_faucet(None).await;
        let c = reqwest::Client::new();
        let r404 = c.get(format!("{base}/nope")).send().await.expect("req");
        assert_eq!(r404.status(), 404);
        assert_security_headers(r404.headers(), "404");
        let r405 = c.get(format!("{base}/faucet")).send().await.expect("req");
        assert_eq!(r405.status(), 405);
        assert_security_headers(r405.headers(), "405");
        let r4xx = c
            .post(format!("{base}/faucet"))
            .header("content-type", "application/json")
            .body("{not json")
            .send()
            .await
            .expect("req");
        assert!(r4xx.status().is_client_error());
        assert_security_headers(r4xx.headers(), "bad json");
        for origin in ["https://docs.citrate.ai", "https://evil.example"] {
            let pre = c
                .request(reqwest::Method::OPTIONS, format!("{base}/faucet"))
                .header("origin", origin)
                .header("access-control-request-method", "POST")
                .send()
                .await
                .expect("req");
            assert_security_headers(pre.headers(), origin);
        }
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

    // ── HUP-S6.5 / F-5: liveness, structured refusals, opt-in limits, desktop path ──

    async fn post_drip(
        base: &str,
        address: &str,
        xff: Option<&str>,
    ) -> serde_json::Value {
        let mut req = reqwest::Client::new()
            .post(format!("{base}/faucet"))
            .json(&serde_json::json!({ "address": address }));
        if let Some(ip) = xff {
            req = req.header("x-forwarded-for", ip);
        }
        req.send()
            .await
            .expect("post")
            .json()
            .await
            .expect("json")
    }

    fn addr_of(byte: u8) -> String {
        format!("0x{}", hex::encode([byte; 20]))
    }

    #[tokio::test]
    async fn s65_health_is_liveness_and_ready_reports_a_dead_rpc() {
        let base = spawn_faucet(None).await;
        let h = reqwest::get(format!("{base}/health")).await.expect("health");
        assert_eq!(h.status(), 200);
        let r = reqwest::get(format!("{base}/ready")).await.expect("ready");
        assert_eq!(r.status(), 503);
        let body: serde_json::Value = r.json().await.expect("json");
        assert_eq!(body["ready"], false);
        assert_eq!(body["rpc_reachable"], false);
        assert!(body["reason"].as_str().unwrap_or("").contains("not answering"));
    }

    #[tokio::test]
    async fn s65_status_keeps_old_keys_and_adds_limits() {
        let base = spawn_faucet(None).await;
        let s: serde_json::Value = reqwest::get(format!("{base}/status"))
            .await
            .expect("req")
            .json()
            .await
            .expect("json");
        assert_eq!(s["status"], "online");
        assert_eq!(s["network"], "citrate-testnet-beta");
        assert_eq!(s["amount_per_request"], "10 SALT");
        assert_eq!(s["drip_wei"], "10000000000000000000");
        assert_eq!(s["address_cooldown_secs"], 86_400);
        assert_eq!(s["ip_cooldown_secs"], 3_600);
        assert_eq!(s["chain_id"], 40204);
        assert!(s["global_cap_per_hour"].is_null());
        assert!(s["global_cap_used"].is_null());
        assert_eq!(s["captcha"], false);
        assert_eq!(s["membership_check"], false);
    }

    #[tokio::test]
    async fn s65_refusals_carry_a_stable_code() {
        let base = spawn_faucet(None).await;
        let bad = post_drip(&base, "0x1234", None).await;
        assert_eq!(bad["success"], false);
        assert_eq!(bad["code"], "invalid_address");
        assert!(bad.get("next_eligible_at").is_none());
        // Dead RPC: the nonce cannot be read, so the drip is refused and the slot returned.
        let down = post_drip(&base, &addr_of(0x31), None).await;
        assert_eq!(down["code"], "node_unreachable");
        let again = post_drip(&base, &addr_of(0x31), None).await;
        assert_eq!(again["code"], "node_unreachable", "the slot was returned, not held");
    }

    #[tokio::test]
    async fn s65_a_caller_in_cooldown_costs_no_membership_rpc() {
        // Membership on, RPC dead. A caller already inside the cooldown must be told when to
        // come back without the faucet spending an eth_call on them (no RPC amplification).
        let mut st = test_state("http://127.0.0.1:9");
        st.member_sbt = Some(addr_of(0x71));
        let cooldowns = st.cooldowns.clone();
        let base = serve(st, None).await;
        let a = addr_of(0x41);
        cooldowns
            .try_reserve(a.trim_start_matches("0x"), "127.0.0.1")
            .expect("reserve");
        let r = post_drip(&base, &a, None).await;
        assert_eq!(r["code"], "rate_limited", "{r}");
        assert!(r["next_eligible_at"].as_u64().is_some());
        // A caller outside the cooldown still reaches the (dead) membership check: fail closed.
        let fresh_state = {
            let mut s = test_state("http://127.0.0.1:9");
            s.member_sbt = Some(addr_of(0x71));
            s
        };
        let fresh = serve(fresh_state, None).await;
        let r = post_drip(&fresh, &addr_of(0x42), None).await;
        assert_eq!(r["code"], "membership_unavailable", "{r}");
    }

    #[tokio::test]
    async fn s65_eligibility_is_read_only_and_reports_the_next_time() {
        let state = test_state("http://127.0.0.1:9");
        let cooldowns = state.cooldowns.clone();
        let base = serve(state, None).await;
        let a = addr_of(0x41);
        let get = |q: String| {
            let base = base.clone();
            async move {
                reqwest::get(format!("{base}/eligibility?address={q}"))
                    .await
                    .expect("req")
                    .json::<serde_json::Value>()
                    .await
                    .expect("json")
            }
        };
        let first = get(a.clone()).await;
        assert_eq!(first["eligible"], true);
        let second = get(a.clone()).await;
        assert_eq!(second["eligible"], true, "asking reserves nothing");
        cooldowns.record_success(&a[2..], "10.9.9.9");
        let after = get(a.to_uppercase().replacen("0X", "0x", 1)).await;
        assert_eq!(after["eligible"], false);
        assert_eq!(after["code"], "rate_limited");
        assert_eq!(after["limit"], "address");
        let retry = after["retry_after_secs"].as_u64().expect("retry");
        assert!(retry > 86_000 && retry <= 86_400);
        let next = after["next_eligible_at"].as_u64().expect("next");
        assert!(next >= unix_now() + 86_000);
        let invalid = get("nope".into()).await;
        assert_eq!(invalid["code"], "invalid_address");
    }

    #[tokio::test]
    async fn s65_desktop_origins_are_opt_in_and_exact() {
        let off = spawn_faucet(None).await;
        let c = reqwest::Client::new();
        let r = c
            .get(format!("{off}/status"))
            .header("origin", "tauri://localhost")
            .send()
            .await
            .expect("req");
        assert!(r.headers().get("access-control-allow-origin").is_none());

        let mut st = test_state("http://127.0.0.1:9");
        let (kept, _) = desktop::desktop_origins(Some("tauri://localhost,https://tauri.localhost.evil"));
        st.desktop_origins = Arc::new(kept);
        let on = serve(st, None).await;
        for (origin, allowed) in [
            ("tauri://localhost", true),
            ("https://tauri.localhost.evil", false),
            ("http://tauri.localhost", false),
            ("https://docs.citrate.ai", true),
        ] {
            let r = c
                .get(format!("{on}/status"))
                .header("origin", origin)
                .send()
                .await
                .expect("req");
            assert_eq!(
                r.headers()
                    .get("access-control-allow-origin")
                    .and_then(|v| v.to_str().ok()),
                allowed.then_some(origin),
                "{origin}"
            );
        }
    }

    #[tokio::test]
    async fn s65_captcha_page_is_opt_in() {
        let mut st = test_state("http://127.0.0.1:9");
        st.turnstile_site_key = Some("site-key_123".into());
        let base = serve(st, None).await;
        let r = reqwest::get(format!("{base}/")).await.expect("req");
        let csp = r
            .headers()
            .get("content-security-policy")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .expect("csp");
        assert_eq!(csp, desktop::csp_with_turnstile(FAUCET_CSP));
        let html = r.text().await.expect("body");
        assert!(html.contains(r#"data-sitekey="site-key_123""#));
        assert!(html.contains(desktop::TURNSTILE_ORIGIN));
        assert_eq!(render_page(None), PAGE_HTML, "no site key: the page is unchanged");
        let js = reqwest::get(format!("{base}/faucet.js"))
            .await
            .expect("req")
            .text()
            .await
            .expect("js");
        assert!(js.contains("cf-turnstile-response"));
        assert!(js.contains("/^0x[0-9a-fA-F]{40}$/.test(q)"), "address prefill is validated");
    }

    #[tokio::test]
    async fn s65_membership_check_fails_closed() {
        let mut st = test_state("http://127.0.0.1:9");
        st.member_sbt = Some(addr_of(0x51));
        let base = serve(st, None).await;
        let r = post_drip(&base, &addr_of(0x52), None).await;
        assert_eq!(r["code"], "membership_unavailable");
        assert_eq!(r["success"], false);
    }

    #[test]
    fn s65_drip_tx_is_a_legacy_eip155_transfer() {
        let key = throwaway_key("s65-drip-tx");
        let raw = sign_drip_tx(&key, 40204, 3, &[0x77; 20]).expect("sign");
        let bytes = hex::decode(raw.trim_start_matches("0x")).expect("hex");
        let rlp = rlp::Rlp::new(&bytes);
        assert_eq!(rlp.item_count().expect("list"), 9);
        assert_eq!(rlp.val_at::<u64>(0).expect("nonce"), 3);
        assert_eq!(rlp.val_at::<u64>(1).expect("gas price"), 1_000_000_000);
        assert_eq!(rlp.val_at::<u64>(2).expect("gas"), 21_000);
        assert_eq!(rlp.val_at::<Vec<u8>>(3).expect("to"), vec![0x77; 20]);
        let v = rlp.val_at::<u64>(6).expect("v");
        assert!(v == 40204 * 2 + 35 || v == 40204 * 2 + 36);
    }

    // ── HUP-S6.5: the real drip path against a local anvil chain (40204 id, nothing public) ──

    struct Anvil {
        child: std::process::Child,
        url: String,
    }

    impl Drop for Anvil {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    async fn rpc(url: &str, method: &str, params: serde_json::Value) -> serde_json::Value {
        let v: serde_json::Value = reqwest::Client::new()
            .post(url)
            .json(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send()
            .await
            .expect("rpc send")
            .json()
            .await
            .expect("rpc json");
        v.get("result").cloned().unwrap_or(serde_json::Value::Null)
    }

    /// Start anvil on a free loopback port with chain id 40204. `None` (and a note) when anvil is
    /// not installed, so the suite still runs where Foundry is absent.
    async fn start_anvil() -> Option<Anvil> {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .map(|a| a.port())
            .ok()?;
        let child = match std::process::Command::new("anvil")
            .args([
                "--port",
                &port.to_string(),
                "--chain-id",
                "40204",
                "--base-fee",
                "0",
                "--silent",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => {
                eprintln!("anvil not installed: skipping the live drip test");
                return None;
            }
        };
        let anvil = Anvil {
            child,
            url: format!("http://127.0.0.1:{port}"),
        };
        for _ in 0..100 {
            let ok = reqwest::Client::new()
                .post(&anvil.url)
                .json(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}))
                .send()
                .await
                .is_ok();
            if ok {
                return Some(anvil);
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        eprintln!("anvil did not start: skipping the live drip test");
        None
    }

    /// A throwaway faucet key made at run time and funded on the local anvil only.
    async fn funded_state(anvil: &Anvil) -> FaucetState {
        let key = throwaway_key("s65-anvil-faucet");
        let mut st = test_state(&anvil.url);
        st.faucet_address = evm_address_of(&key);
        st.signing_key = Arc::new(key);
        // Trust loopback as a proxy so each test request can present its own client IP.
        st.trusted_proxies = Arc::new(["127.0.0.1".parse().expect("ip")].into_iter().collect());
        rpc(
            &anvil.url,
            "anvil_setBalance",
            serde_json::json!([format!("0x{}", hex::encode(st.faucet_address.0)), "0x3635c9adc5dea00000"]),
        )
        .await;
        st
    }

    async fn balance(url: &str, addr: &str) -> u128 {
        let v = rpc(url, "eth_getBalance", serde_json::json!([addr, "latest"])).await;
        u128::from_str_radix(v.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16).unwrap_or(0)
    }

    /// The balance once a sent drip is mined. eth_sendRawTransaction returns before anvil has
    /// mined the block, so an immediate read can still see the old balance (a flake seen in
    /// review); this waits up to 5 s for `want`, then returns what it sees.
    async fn mined_balance(url: &str, addr: &str, want: u128) -> u128 {
        let mut seen = balance(url, addr).await;
        for _ in 0..50 {
            if seen == want {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            seen = balance(url, addr).await;
        }
        seen
    }

    #[tokio::test]
    async fn s65_anvil_drip_ready_cap_and_membership() {
        let Some(anvil) = start_anvil().await else {
            return;
        };

        // 1. A real drip: signed by the faucet's own key, mined by anvil, balance moves 10 SALT.
        let mut st = funded_state(&anvil).await;
        st.global_cap = Some(Arc::new(GlobalCap::new(1, limits::WINDOW_SECS)));
        let base = serve(st, None).await;
        let ready: serde_json::Value = reqwest::get(format!("{base}/ready"))
            .await
            .expect("ready")
            .json()
            .await
            .expect("json");
        assert_eq!(ready["ready"], true, "{ready}");
        let a = addr_of(0x61);
        let ok = post_drip(&base, &a, Some("198.51.100.1")).await;
        assert_eq!(ok["success"], true, "{ok}");
        assert!(ok.get("code").is_none());
        assert_eq!(mined_balance(&anvil.url, &a, DRIP_AMOUNT).await, DRIP_AMOUNT);

        // 2. Same address again: refused with the next eligible time, nothing sent.
        let again = post_drip(&base, &a, Some("198.51.100.2")).await;
        assert_eq!(again["code"], "rate_limited");
        assert_eq!(again["limit"], "address");
        assert!(again["next_eligible_at"].as_u64().is_some());
        assert_eq!(balance(&anvil.url, &a).await, DRIP_AMOUNT);

        // 3. A fresh address from a fresh IP: the global cap (1 per hour here) refuses it.
        let b = addr_of(0x62);
        let capped = post_drip(&base, &b, Some("198.51.100.3")).await;
        assert_eq!(capped["code"], "rate_limited");
        assert_eq!(capped["limit"], "global");
        assert_eq!(balance(&anvil.url, &b).await, 0);

        // 4. Membership on: a contract that answers balanceOf with 1 lets the drip through, one
        //    that answers 0 refuses it.
        let member_sbt = addr_of(0x71);
        let non_member_sbt = addr_of(0x72);
        // PUSH1 1 PUSH1 0 MSTORE PUSH1 32 PUSH1 0 RETURN  -> returns uint256(1)
        rpc(&anvil.url, "anvil_setCode", serde_json::json!([member_sbt, "0x600160005260206000f3"])).await;
        // PUSH1 32 PUSH1 0 RETURN -> returns uint256(0)
        rpc(&anvil.url, "anvil_setCode", serde_json::json!([non_member_sbt, "0x60206000f3"])).await;

        let mut yes = funded_state(&anvil).await;
        yes.member_sbt = Some(member_sbt);
        let yes_base = serve(yes, None).await;
        let c = addr_of(0x63);
        let member = post_drip(&yes_base, &c, Some("198.51.100.4")).await;
        assert_eq!(member["success"], true, "{member}");
        assert_eq!(mined_balance(&anvil.url, &c, DRIP_AMOUNT).await, DRIP_AMOUNT);

        let mut no = funded_state(&anvil).await;
        no.member_sbt = Some(non_member_sbt);
        let no_base = serve(no, None).await;
        let d = addr_of(0x64);
        let refused = post_drip(&no_base, &d, Some("198.51.100.5")).await;
        assert_eq!(refused["code"], "not_member");
        assert_eq!(balance(&anvil.url, &d).await, 0);
        // The refusal reserved nothing: the same address is still eligible.
        let elig: serde_json::Value = reqwest::get(format!("{no_base}/eligibility?address={d}"))
            .await
            .expect("req")
            .json()
            .await
            .expect("json");
        assert_eq!(elig["eligible"], true);
    }
}
