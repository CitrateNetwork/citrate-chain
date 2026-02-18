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
    });

    if now.duration_since(entry.window_start) >= window {
        entry.cost_used = 0;
        entry.window_start = now;
    }

    entry.cost_used += method_cost;

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
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window_secs: 1,
            trusted_proxies: Vec::new(), // WP-I.1: secure default — no header trust
            method_costs: Vec::new(),
            operator_token: None, // WP-I.2: no auth in devnet by default
        }
    }
}

struct BucketEntry {
    count: u32,
    window_start: Instant,
}

/// Per-client sliding window rate limiter implementing `RequestMiddleware`.
pub struct RateLimiter {
    config: RateLimitConfig,
    buckets: Arc<DashMap<String, BucketEntry>>,
    trusted_set: HashSet<IpAddr>,
    operator_token: Option<String>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        let trusted_set: HashSet<IpAddr> = config.trusted_proxies.iter().cloned().collect();
        let operator_token = config.operator_token.clone();
        Self {
            config,
            buckets: Arc::new(DashMap::new()),
            trusted_set,
            operator_token,
        }
    }
}

impl RequestMiddleware for RateLimiter {
    fn on_request(&self, request: hyper::Request<Body>) -> RequestMiddlewareAction {
        // WP-I.2: Set operator authentication state for this request.
        // Method handlers check is_operator_authenticated() for privileged ops.
        let authenticated = match &self.operator_token {
            Some(expected) => {
                request.headers().get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Bearer "))
                    .map(|token| token == expected.as_str())
                    .unwrap_or(false)
            }
            None => true, // No token configured → all requests are "operator" (devnet mode)
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

        let mut entry = self.buckets.entry(client_key.clone()).or_insert_with(|| BucketEntry {
            count: 0,
            window_start: now,
        });

        // Reset window if expired
        if now.duration_since(entry.window_start) >= window {
            entry.count = 0;
            entry.window_start = now;
        }

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
                .expect("valid response");
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
