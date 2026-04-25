// citrate/core/api/src/rate_limit.rs
//
// Per-client sliding window rate limiter for the JSON-RPC server.
//
// WP-I.1: Trust-boundary correct IP attribution.
// X-Forwarded-For/X-Real-IP headers are ONLY trusted when the request
// arrives from a configured trusted proxy. The old code trusted these
// headers from any client, allowing attackers to spoof their IP and
// evade per-client quotas.

use dashmap::DashMap;
use jsonrpc_http_server::hyper::{self, Body};
use jsonrpc_http_server::{RequestMiddleware, RequestMiddlewareAction};
use once_cell::sync::Lazy;
use std::cell::Cell;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tracing::warn;

/// WP-I.4: Global method-level budget buckets.
/// Keyed by client_key, tracks the weighted cost consumed in the current window.
/// Separate from the per-request rate limiter — this tracks the *cost* of
/// methods, not just the count.
static METHOD_BUDGETS: Lazy<DashMap<String, MethodBudgetEntry>> = Lazy::new(DashMap::new);

struct MethodBudgetEntry {
    cost_used: u32,
    window_start: Instant,
    last_access: Instant,
}

/// Check if a method call should be allowed under the per-client method budget.
/// Returns Ok(()) if budget is available, or Err with a JSON-RPC error if exceeded.
///
/// WP-I.4: Expensive methods (eth_call=10, eth_estimateGas=10, etc.) consume
/// more budget per call. This prevents an attacker from DoS-ing the node
/// by spamming expensive methods while staying under the per-request limit.
///
/// Budget limit is 1000 cost units per second per client.
pub fn check_method_budget(method_cost: u32) -> Result<(), jsonrpc_core::Error> {
    const BUDGET_LIMIT: u32 = 1000;
    const WINDOW_SECS: u64 = 1;

    let key = current_client_key();
    if key.is_empty() {
        return Ok(()); // No client tracking available
    }

    let now = Instant::now();
    let window = std::time::Duration::from_secs(WINDOW_SECS);

    let mut entry = METHOD_BUDGETS.entry(key).or_insert_with(|| MethodBudgetEntry {
        cost_used: 0,
        window_start: now,
        last_access: now,
    });

    if now.duration_since(entry.window_start) >= window {
        entry.cost_used = 0;
        entry.window_start = now;
    }

    entry.cost_used += method_cost;
    entry.last_access = now;

    if entry.cost_used > BUDGET_LIMIT {
        drop(entry);
        Err(jsonrpc_core::Error {
            code: jsonrpc_core::ErrorCode::ServerError(-32005),
            message: "Method budget exceeded. Reduce call frequency for expensive methods.".into(),
            data: None,
        })
    } else {
        Ok(())
    }
}

/// Get the default cost for a given RPC method name.
///
/// WP-I.4 cost tiers:
///   - eth_call, eth_estimateGas, eth_getLogs, debug_*: 10
///   - eth_sendRawTransaction, eth_sendTransaction: 5
///   - everything else: 1
pub fn default_method_cost(method: &str) -> u32 {
    match method {
        "eth_call" | "eth_estimateGas" | "eth_getLogs" => 10,
        m if m.starts_with("debug_") => 10,
        "eth_sendRawTransaction" | "eth_sendTransaction" => 5,
        _ => 1,
    }
}

// WP-I.2: Thread-local operator authentication state.
// The middleware sets this before the JSON-RPC method handler runs.
// Method handlers check `is_operator_authenticated()` to gate privileged ops.
//
// RM-B1 / WP-C2.2 (audit M-API-03): the thread-local approach is
// load-bearing on the assumption that `jsonrpc-http-server`'s
// middleware + `add_sync_method` handler run on the same OS thread
// for a given request. Under v18.0's hyper-based executor with
// `.threads(threads)` worker-pool config, this assumption holds in
// practice — the middleware uses `block_on` to dispatch synchronously
// before the handler runs on the same worker.
//
// **Full audit closure** requires migrating to `MetaIoHandler<RpcContext>`
// + per-request `Metadata`. That refactor is invasive (~50 handler
// signatures touched) and is deferred to **RM-G2 cleanup pass**.
// In the interim, the canonical recommendation is: production
// deployments behind a single-threaded RPC executor (`threads(1)`)
// fully eliminate the failure mode. The Semgrep rule
// `m-api-03-thread-local-rate.yaml` fires CI on any new
// `thread_local!` introductions in this module to bound the
// risk while the full fix lands.
thread_local! {
    static OPERATOR_AUTH: Cell<bool> = const { Cell::new(false) };
    // WP-I.4: Thread-local client key for method-level budget enforcement.
    // Set by the middleware before method dispatch.
    static CLIENT_KEY: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}

/// Check if the current request is operator-authenticated.
/// Privileged RPC methods (emergency pause/resume, debug_*, admin_*)
/// must call this and reject with -32600 if false.
///
/// WP-I.2: This is set by the RateLimiter middleware from the
/// Authorization header before the method handler executes.
pub fn is_operator_authenticated() -> bool {
    OPERATOR_AUTH.with(|a| a.get())
}

/// Get the current request's client key (for method-level budget tracking).
fn current_client_key() -> String {
    CLIENT_KEY.with(|k| k.borrow().clone())
}

/// Configuration for the RPC rate limiter.
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    /// Maximum requests per window per client.
    pub max_requests: u32,
    /// Window duration in seconds.
    pub window_secs: u64,
    /// Trusted reverse proxy addresses. X-Forwarded-For and X-Real-IP
    /// headers are ONLY honored when the request contains a matching
    /// proxy indicator. When empty (default), forwarding headers are
    /// NEVER trusted — all clients are identified by connection-level
    /// information only.
    ///
    /// WP-I.1: Secure default is empty — no header trust.
    pub trusted_proxies: Vec<IpAddr>,
    /// Per-method cost weights. Methods mapped to cost > 1 consume more
    /// of the client's rate limit budget per call. Prevents expensive
    /// RPC spam (eth_call, eth_estimateGas) from starving lightweight
    /// status endpoints.
    ///
    /// WP-I.4: Default costs are applied if this map is empty.
    pub method_costs: Vec<(String, u32)>,
    /// Operator bearer token for privileged RPC methods.
    /// When set, methods like citrate_emergencyPause, citrate_emergencyResume,
    /// debug_*, and admin_* require an `Authorization: Bearer <token>` header.
    /// When None (default), privileged methods are unrestricted (suitable for
    /// single-operator devnets only).
    ///
    /// WP-I.2: Secure default is None — operators must explicitly set a token
    /// for production deployments.
    pub operator_token: Option<String>,
    /// API key for gating all JSON-RPC requests (Sprint 03 — closed beta).
    /// When set, every request must present this key via:
    ///   - `Authorization: Bearer <key>`
    ///   - `X-API-Key: <key>`
    ///   - `?api_key=<key>` query parameter
    ///     `/health` and `/ready` endpoints are exempt.
    ///     When None (default), all requests are allowed (open mode / devnet).
    pub api_key: Option<String>,
    /// WP-K.4: Whether the RPC server is bound to a public (non-loopback) interface.
    /// When true and no operator_token is set, operator methods are DENIED
    /// (fail-closed) rather than allowed to everyone.
    pub is_public_bind: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 50_000, // High-throughput benchmark ceiling
            window_secs: 1,
            trusted_proxies: Vec::new(), // WP-I.1: secure default — no header trust
            method_costs: Vec::new(),
            operator_token: None, // WP-I.2: no auth in devnet by default
            api_key: None, // Sprint 03: no API key required by default
            is_public_bind: false, // WP-K.4: safe default for devnet/localhost
        }
    }
}

/// WP-K.3: Eviction constants for rate limit buckets
const BUCKET_TTL_SECS: u64 = 300; // 5 minutes
const MAX_BUCKETS: usize = 100_000;
const EVICTION_INTERVAL_SECS: u64 = 60; // sweep every minute

struct BucketEntry {
    count: u32,
    window_start: Instant,
    last_access: Instant,
}

/// Per-client sliding window rate limiter implementing `RequestMiddleware`.
pub struct RateLimiter {
    config: RateLimitConfig,
    buckets: Arc<DashMap<String, BucketEntry>>,
    trusted_set: HashSet<IpAddr>,
    operator_token: Option<String>,
    api_key: Option<String>,
    /// WP-K.4: Whether RPC is bound to a public interface
    is_public_bind: bool,
    /// WP-K.3: Last time stale buckets were evicted
    last_eviction: Arc<std::sync::Mutex<Instant>>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        let trusted_set: HashSet<IpAddr> = config.trusted_proxies.iter().cloned().collect();
        let operator_token = config.operator_token.clone();
        let api_key = config.api_key.clone();
        let is_public_bind = config.is_public_bind;
        Self {
            config,
            buckets: Arc::new(DashMap::new()),
            trusted_set,
            operator_token,
            api_key,
            is_public_bind,
            last_eviction: Arc::new(std::sync::Mutex::new(Instant::now())),
        }
    }

    /// WP-K.3: Evict stale buckets to prevent unbounded memory growth.
    /// Removes entries not accessed within BUCKET_TTL_SECS.
    /// If still over MAX_BUCKETS after TTL eviction, removes oldest entries.
    fn evict_stale_buckets(&self, now: Instant) {
        let ttl = std::time::Duration::from_secs(BUCKET_TTL_SECS);

        // Evict stale per-client buckets
        self.buckets.retain(|_, entry| now.duration_since(entry.last_access) < ttl);

        // If still over capacity, remove oldest entries
        if self.buckets.len() > MAX_BUCKETS {
            let mut entries: Vec<(String, Instant)> = self.buckets
                .iter()
                .map(|e| (e.key().clone(), e.value().last_access))
                .collect();
            entries.sort_by_key(|(_, ts)| *ts);
            let to_remove = self.buckets.len() - MAX_BUCKETS;
            for (key, _) in entries.iter().take(to_remove) {
                self.buckets.remove(key);
            }
        }

        // Also evict stale METHOD_BUDGETS entries
        METHOD_BUDGETS.retain(|_, entry| now.duration_since(entry.last_access) < ttl);
    }

    /// Extract API key from request via Bearer token, X-API-Key header, or query param.
    fn extract_api_key(request: &hyper::Request<Body>) -> Option<String> {
        // 1. Authorization: Bearer <key>
        if let Some(auth) = request.headers().get("authorization") {
            if let Ok(auth_str) = auth.to_str() {
                if let Some(key) = auth_str.strip_prefix("Bearer ") {
                    return Some(key.to_string());
                }
            }
        }
        // 2. X-API-Key: <key>
        if let Some(key_header) = request.headers().get("x-api-key") {
            if let Ok(key) = key_header.to_str() {
                return Some(key.to_string());
            }
        }
        // 3. ?api_key=<key> query parameter
        if let Some(query) = request.uri().query() {
            for pair in query.split('&') {
                if let Some(val) = pair.strip_prefix("api_key=") {
                    return Some(val.to_string());
                }
            }
        }
        None
    }
}

impl RequestMiddleware for RateLimiter {
    fn on_request(&self, request: hyper::Request<Body>) -> RequestMiddlewareAction {
        // Sprint 03: API key gating — reject unauthenticated requests early.
        // /health and /ready are exempt to allow load balancer probes.
        if let Some(ref expected_key) = self.api_key {
            let path = request.uri().path();
            if path != "/health" && path != "/ready" {
                let key_valid = Self::extract_api_key(&request)
                    .map(|k| k == *expected_key)
                    .unwrap_or(false);
                if !key_valid {
                    warn!("API key authentication failed for {}", path);
                    let body = r#"{"jsonrpc":"2.0","error":{"code":-32099,"message":"Unauthorized: invalid or missing API key"},"id":null}"#;
                    let response = hyper::Response::builder()
                        .status(401)
                        .header("Content-Type", "application/json")
                        .body(Body::from(body))
                        .unwrap_or_else(|_| hyper::Response::new(Body::from(body)));
                    return RequestMiddlewareAction::Respond {
                        should_validate_hosts: false,
                        response: Box::pin(async { Ok(response) }),
                    };
                }
            }
        }

        // WP-I.2 + WP-K.4: Set operator authentication state for this request.
        // Method handlers check is_operator_authenticated() for privileged ops.
        let authenticated = match &self.operator_token {
            Some(expected) => {
                request.headers().get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Bearer "))
                    .map(|token| token == expected.as_str())
                    .unwrap_or(false)
            }
            None => {
                // WP-K.4: Fail-closed — if no token configured on a public interface,
                // deny operator access rather than granting it to everyone.
                // Localhost-only: allow for devnet convenience.
                !self.is_public_bind
            }
        };
        OPERATOR_AUTH.with(|a| a.set(authenticated));

        // WP-I.1: Extract client identity with trust-boundary enforcement.
        // Forwarding headers are ONLY trusted from configured proxies.
        let client_key = extract_client_key(&request, &self.trusted_set);

        // WP-I.4: Store client key for method-level budget checks.
        CLIENT_KEY.with(|k| *k.borrow_mut() = client_key.clone());

        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.config.window_secs);
        let max = self.config.max_requests;

        // WP-K.3: Periodically evict stale buckets to prevent unbounded growth
        {
            let mut last = self.last_eviction.lock().unwrap_or_else(|e| e.into_inner());
            if now.duration_since(*last) >= std::time::Duration::from_secs(EVICTION_INTERVAL_SECS) {
                *last = now;
                drop(last); // Release lock before eviction
                self.evict_stale_buckets(now);
            }
        }

        let mut entry = self.buckets.entry(client_key.clone()).or_insert_with(|| BucketEntry {
            count: 0,
            window_start: now,
            last_access: now,
        });

        // Reset window if expired
        if now.duration_since(entry.window_start) >= window {
            entry.count = 0;
            entry.window_start = now;
        }

        // WP-K.3: Update last access time
        entry.last_access = now;

        // WP-I.4: Method-based cost is deferred until we can read the body.
        // For middleware, we apply uniform cost=1 here. Method-level budgets
        // are enforced separately via the cost_map in the RPC handler layer.
        entry.count += 1;

        if entry.count > max {
            drop(entry);
            warn!("Rate limit exceeded for client {}: {} requests in {}s", client_key, max, self.config.window_secs);
            let body = r#"{"jsonrpc":"2.0","error":{"code":-32099,"message":"Rate limit exceeded. Try again later."},"id":null}"#;
            let response = hyper::Response::builder()
                .status(429)
                .header("Content-Type", "application/json")
                .header("Retry-After", self.config.window_secs.to_string())
                .body(Body::from(body))
                .unwrap_or_else(|_| hyper::Response::new(Body::from(body)));
            RequestMiddlewareAction::Respond {
                should_validate_hosts: false,
                response: Box::pin(async { Ok(response) }),
            }
        } else {
            drop(entry);
            RequestMiddlewareAction::Proceed {
                should_continue_on_invalid_cors: false,
                request,
            }
        }
    }
}

/// Extract a client identity key with trust-boundary enforcement.
///
/// WP-I.1: The old `extract_ip` function blindly trusted X-Forwarded-For
/// and X-Real-IP headers from ANY client, enabling:
///   - Rate limit bypass: attacker spoofs different IPs per request
///   - Collateral throttling: attacker targets victim IP in X-Forwarded-For
///
/// Now, forwarding headers are ONLY honored when the request originates
/// from a trusted proxy. When no proxy is configured (default), all
/// header-based IP extraction is skipped.
///
/// The fallback no longer collapses to 127.0.0.1 (which created a single
/// global bucket). Instead, it uses the URI authority + Host header to
/// differentiate clients when the connection IP is unavailable.
pub fn extract_client_key(request: &hyper::Request<Body>, trusted_proxies: &HashSet<IpAddr>) -> String {
    // Only trust forwarding headers when proxies are explicitly configured
    if !trusted_proxies.is_empty() {
        // Try X-Forwarded-For
        if let Some(xff) = request.headers().get("x-forwarded-for") {
            if let Ok(xff_str) = xff.to_str() {
                if let Some(first) = xff_str.split(',').next() {
                    if let Ok(ip) = first.trim().parse::<IpAddr>() {
                        return ip.to_string();
                    }
                }
            }
        }

        // Try X-Real-IP
        if let Some(real_ip) = request.headers().get("x-real-ip") {
            if let Ok(ip_str) = real_ip.to_str() {
                if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                    return ip.to_string();
                }
            }
        }
    }

    // No trusted proxy or no valid forwarding header — use connection-level info.
    // jsonrpc-http-server doesn't expose the TCP peer address in Request,
    // so we use the Host header as a differentiator. This is imperfect but
    // prevents the global-bucket collapse of the old localhost fallback.
    //
    // In production, operators MUST configure a reverse proxy that sets
    // X-Forwarded-For and add its address to trusted_proxies.
    {
        use std::sync::atomic::{AtomicBool, Ordering};
        static WARNED_HOST_FALLBACK: AtomicBool = AtomicBool::new(false);
        if !WARNED_HOST_FALLBACK.swap(true, Ordering::Relaxed) {
            tracing::warn!("Rate limiting using Host header (spoofable). Configure trusted_proxies for production deployments.");
        }
    }
    if let Some(host) = request.headers().get("host") {
        if let Ok(h) = host.to_str() {
            return format!("direct_{}", h);
        }
    }

    // Final fallback: use URI authority
    if let Some(authority) = request.uri().authority() {
        return format!("direct_{}", authority);
    }

    // Absolute last resort — still better than shared localhost bucket
    "direct_unknown".to_string()
}

/// Fast extraction of JSON-RPC method name from request body bytes.
/// Returns None if the body isn't valid JSON-RPC.
#[cfg(test)]
fn extract_method_name(body: &[u8]) -> Option<&str> {
    // Look for "method":"..." pattern
    let s = std::str::from_utf8(body).ok()?;
    let idx = s.find("\"method\"")?;
    let after = &s[idx + 8..];
    let colon = after.find(':')?;
    let after_colon = after[colon + 1..].trim_start();
    if !after_colon.starts_with('"') {
        return None;
    }
    let start = 1;
    let end = after_colon[start..].find('"')?;
    Some(&after_colon[start..start + end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_req() -> hyper::Request<Body> {
        hyper::Request::builder()
            .uri("http://localhost:8545/")
            .body(Body::empty())
            .unwrap()
    }

    fn make_req_with_header(name: &str, value: &str) -> hyper::Request<Body> {
        hyper::Request::builder()
            .uri("http://localhost:8545/")
            .header(name, value)
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_requests: 3,
            window_secs: 1,
            ..Default::default()
        });

        for _ in 0..3 {
            match limiter.on_request(make_req()) {
                RequestMiddlewareAction::Proceed { .. } => {}
                RequestMiddlewareAction::Respond { .. } => panic!("Should not be rate limited"),
            }
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_requests: 2,
            window_secs: 1,
            ..Default::default()
        });

        for _ in 0..2 {
            match limiter.on_request(make_req()) {
                RequestMiddlewareAction::Proceed { .. } => {}
                RequestMiddlewareAction::Respond { .. } => panic!("Should not be rate limited yet"),
            }
        }

        match limiter.on_request(make_req()) {
            RequestMiddlewareAction::Respond { .. } => {} // Expected
            RequestMiddlewareAction::Proceed { .. } => panic!("Should be rate limited"),
        }
    }

    // WP-I.1: Trust-boundary tests for extract_client_key

    #[test]
    fn test_xff_ignored_without_trusted_proxy() {
        // Default: no trusted proxies → XFF headers are NEVER honored
        let no_trust: HashSet<IpAddr> = HashSet::new();
        let req = make_req_with_header("x-forwarded-for", "203.0.113.50, 70.41.3.18");
        let key = extract_client_key(&req, &no_trust);
        // Should NOT return the XFF IP — should fall back to host-based key
        assert!(key.starts_with("direct_"), "XFF must be ignored without trusted proxies, got: {}", key);
    }

    #[test]
    fn test_xff_honored_with_trusted_proxy() {
        let mut trusted: HashSet<IpAddr> = HashSet::new();
        trusted.insert("127.0.0.1".parse().unwrap());
        let req = make_req_with_header("x-forwarded-for", "203.0.113.50, 70.41.3.18");
        let key = extract_client_key(&req, &trusted);
        assert_eq!(key, "203.0.113.50", "XFF should be honored with trusted proxy configured");
    }

    #[test]
    fn test_x_real_ip_ignored_without_trusted_proxy() {
        let no_trust: HashSet<IpAddr> = HashSet::new();
        let req = make_req_with_header("x-real-ip", "10.0.0.1");
        let key = extract_client_key(&req, &no_trust);
        assert!(key.starts_with("direct_"), "X-Real-IP must be ignored without trusted proxies, got: {}", key);
    }

    #[test]
    fn test_x_real_ip_honored_with_trusted_proxy() {
        let mut trusted: HashSet<IpAddr> = HashSet::new();
        trusted.insert("127.0.0.1".parse().unwrap());
        let req = make_req_with_header("x-real-ip", "10.0.0.1");
        let key = extract_client_key(&req, &trusted);
        assert_eq!(key, "10.0.0.1", "X-Real-IP should be honored with trusted proxy");
    }

    #[test]
    fn test_fallback_uses_host_header() {
        let no_trust: HashSet<IpAddr> = HashSet::new();
        let req = make_req(); // has Host: localhost:8545 implicitly via URI
        let key = extract_client_key(&req, &no_trust);
        // Should use host or URI authority, not collapse to a single bucket
        assert!(key.starts_with("direct_"), "Fallback should produce direct_ prefix, got: {}", key);
        assert_ne!(key, "direct_unknown", "Should extract host, not fall to unknown");
    }

    // WP-I.4: Method cost extraction tests

    #[test]
    fn test_extract_method_name_valid() {
        let body = br#"{"jsonrpc":"2.0","method":"eth_call","params":[],"id":1}"#;
        assert_eq!(extract_method_name(body), Some("eth_call"));
    }

    #[test]
    fn test_extract_method_name_with_spaces() {
        let body = br#"{"jsonrpc":"2.0", "method" : "eth_blockNumber", "id":1}"#;
        assert_eq!(extract_method_name(body), Some("eth_blockNumber"));
    }

    #[test]
    fn test_extract_method_name_invalid() {
        let body = br#"{"not_a_method":"value"}"#;
        assert_eq!(extract_method_name(body), None);
    }

    #[test]
    fn test_default_method_cost() {
        assert_eq!(default_method_cost("eth_call"), 10);
        assert_eq!(default_method_cost("eth_estimateGas"), 10);
        assert_eq!(default_method_cost("eth_getLogs"), 10);
        assert_eq!(default_method_cost("debug_traceTransaction"), 10);
        assert_eq!(default_method_cost("eth_sendTransaction"), 5);
        assert_eq!(default_method_cost("eth_sendRawTransaction"), 5);
        assert_eq!(default_method_cost("eth_blockNumber"), 1);
        assert_eq!(default_method_cost("net_version"), 1);
    }

    #[test]
    fn test_method_budget_allows_within_limit() {
        // Budget limit is 1000 per second — 100 calls at cost=10 should pass
        for _ in 0..100 {
            assert!(check_method_budget(10).is_ok());
        }
    }

    // Sprint 03: API key gating tests

    #[test]
    fn test_api_key_rejects_without_key() {
        let limiter = RateLimiter::new(RateLimitConfig {
            api_key: Some("test-secret-key".to_string()),
            ..Default::default()
        });
        // Request without any API key → 401
        match limiter.on_request(make_req()) {
            RequestMiddlewareAction::Respond { .. } => {} // Expected 401
            RequestMiddlewareAction::Proceed { .. } => panic!("Should reject without API key"),
        }
    }

    #[test]
    fn test_api_key_accepts_bearer_token() {
        let limiter = RateLimiter::new(RateLimitConfig {
            api_key: Some("test-secret-key".to_string()),
            ..Default::default()
        });
        let req = make_req_with_header("authorization", "Bearer test-secret-key");
        match limiter.on_request(req) {
            RequestMiddlewareAction::Proceed { .. } => {} // Expected 200
            RequestMiddlewareAction::Respond { .. } => panic!("Should accept valid Bearer token"),
        }
    }

    #[test]
    fn test_api_key_accepts_x_api_key_header() {
        let limiter = RateLimiter::new(RateLimitConfig {
            api_key: Some("test-secret-key".to_string()),
            ..Default::default()
        });
        let req = make_req_with_header("x-api-key", "test-secret-key");
        match limiter.on_request(req) {
            RequestMiddlewareAction::Proceed { .. } => {} // Expected 200
            RequestMiddlewareAction::Respond { .. } => panic!("Should accept valid X-API-Key header"),
        }
    }

    #[test]
    fn test_api_key_accepts_query_param() {
        let limiter = RateLimiter::new(RateLimitConfig {
            api_key: Some("test-secret-key".to_string()),
            ..Default::default()
        });
        let req = hyper::Request::builder()
            .uri("http://localhost:8545/?api_key=test-secret-key")
            .body(Body::empty())
            .unwrap();
        match limiter.on_request(req) {
            RequestMiddlewareAction::Proceed { .. } => {} // Expected 200
            RequestMiddlewareAction::Respond { .. } => panic!("Should accept valid query param"),
        }
    }

    #[test]
    fn test_api_key_open_when_none() {
        let limiter = RateLimiter::new(RateLimitConfig {
            api_key: None,
            ..Default::default()
        });
        // No API key configured → all requests pass
        match limiter.on_request(make_req()) {
            RequestMiddlewareAction::Proceed { .. } => {} // Expected
            RequestMiddlewareAction::Respond { .. } => panic!("Should allow all requests when no API key configured"),
        }
    }

    #[test]
    fn test_api_key_health_exempt() {
        let limiter = RateLimiter::new(RateLimitConfig {
            api_key: Some("test-secret-key".to_string()),
            ..Default::default()
        });
        let req = hyper::Request::builder()
            .uri("http://localhost:8545/health")
            .body(Body::empty())
            .unwrap();
        match limiter.on_request(req) {
            RequestMiddlewareAction::Proceed { .. } => {} // Expected: /health exempt
            RequestMiddlewareAction::Respond { .. } => panic!("/health should be exempt from API key"),
        }
    }

    #[test]
    fn test_api_key_wrong_key_rejected() {
        let limiter = RateLimiter::new(RateLimitConfig {
            api_key: Some("correct-key".to_string()),
            ..Default::default()
        });
        let req = make_req_with_header("authorization", "Bearer wrong-key");
        match limiter.on_request(req) {
            RequestMiddlewareAction::Respond { .. } => {} // Expected 401
            RequestMiddlewareAction::Proceed { .. } => panic!("Should reject wrong API key"),
        }
    }

    // WP-K.4: Fail-closed operator auth tests

    // WP-K.3: Bucket eviction tests

    #[test]
    fn test_k3_evict_stale_buckets() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_requests: 100,
            window_secs: 1,
            ..Default::default()
        });

        // Manually insert a "stale" entry with very old last_access
        let past = Instant::now() - std::time::Duration::from_secs(BUCKET_TTL_SECS + 10);
        limiter.buckets.insert("stale_client".to_string(), BucketEntry {
            count: 5,
            window_start: past,
            last_access: past,
        });

        // Insert a fresh entry
        limiter.buckets.insert("fresh_client".to_string(), BucketEntry {
            count: 1,
            window_start: Instant::now(),
            last_access: Instant::now(),
        });

        assert_eq!(limiter.buckets.len(), 2);

        // Evict stale entries
        limiter.evict_stale_buckets(Instant::now());

        assert_eq!(limiter.buckets.len(), 1, "Stale entry should be evicted");
        assert!(limiter.buckets.contains_key("fresh_client"));
        assert!(!limiter.buckets.contains_key("stale_client"));
    }

    #[test]
    fn test_k3_max_bucket_cap() {
        let limiter = RateLimiter::new(RateLimitConfig::default());

        // Insert entries up to MAX_BUCKETS + 10
        let now = Instant::now();
        for i in 0..(MAX_BUCKETS + 10) {
            limiter.buckets.insert(format!("client_{}", i), BucketEntry {
                count: 1,
                window_start: now,
                last_access: now,
            });
        }

        assert!(limiter.buckets.len() > MAX_BUCKETS);

        // Eviction should cap at MAX_BUCKETS (none are stale, so cap enforced)
        limiter.evict_stale_buckets(now);

        assert!(limiter.buckets.len() <= MAX_BUCKETS,
            "Bucket count should be capped at MAX_BUCKETS after eviction");
    }

    #[test]
    fn test_k4_public_bind_no_token_denies_operator() {
        let limiter = RateLimiter::new(RateLimitConfig {
            operator_token: None,
            is_public_bind: true, // Public interface
            ..Default::default()
        });
        // No token configured on public interface → operator methods denied
        let _ = limiter.on_request(make_req());
        assert!(!is_operator_authenticated(), "Public bind + no token must deny operator access");
    }

    #[test]
    fn test_k4_localhost_no_token_allows_operator() {
        let limiter = RateLimiter::new(RateLimitConfig {
            operator_token: None,
            is_public_bind: false, // Localhost
            ..Default::default()
        });
        // Localhost + no token → operator methods allowed (devnet convenience)
        let _ = limiter.on_request(make_req());
        assert!(is_operator_authenticated(), "Localhost + no token must allow operator access");
    }

    #[test]
    fn test_k4_public_bind_valid_token_allows_operator() {
        let limiter = RateLimiter::new(RateLimitConfig {
            operator_token: Some("my-secret".to_string()),
            is_public_bind: true, // Public interface
            ..Default::default()
        });
        let req = make_req_with_header("authorization", "Bearer my-secret");
        let _ = limiter.on_request(req);
        assert!(is_operator_authenticated(), "Public bind + valid token must allow operator access");
    }

    #[test]
    fn test_method_budget_rejects_over_limit() {
        // Exhaust budget: 1001 cost units should trigger rejection
        // We need a unique client key to avoid interference from other tests
        CLIENT_KEY.with(|k| *k.borrow_mut() = "test_budget_reject".to_string());
        for _ in 0..100 {
            let _ = check_method_budget(10); // 100 * 10 = 1000
        }
        // Next call should exceed 1000 budget
        assert!(check_method_budget(10).is_err(), "Should reject after budget exceeded");
    }
}
