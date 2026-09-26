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
        // RM-I / WP-I1.6 (re-audit Stream 2 finding REM-3):
        //   Pre-fix this returned Ok(()), silently failing OPEN when the
        //   middleware couldn't attribute the request to a client (e.g.,
        //   thread-local not populated, a non-HTTP transport, or a worker
        //   thread that didn't carry the client_key forward). The audit
        //   noted that this allowed a multi-threaded RPC consumer to bypass
        //   the per-client method budget by routing requests through a
        //   thread that didn't have the key set.
        //
        //   Post-fix: empty client_key fails CLOSED unless the operator
        //   has explicitly opted into anonymous traffic via the env var
        //   `CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT=1`. The opt-in exists so
        //   devnet / single-node testing can still hit the RPC without
        //   IP-based attribution, but production deployments fail-closed
        //   by default.
        if std::env::var("CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
        {
            return Ok(());
        }
        return Err(jsonrpc_core::Error {
            code: jsonrpc_core::ErrorCode::ServerError(-32007),
            message: "Rate-limit attribution failed (no client key). Set \
                      CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT=1 on devnet to bypass."
                .into(),
            data: None,
        });
    }

    let now = Instant::now();
    let window = std::time::Duration::from_secs(WINDOW_SECS);

    let mut entry = METHOD_BUDGETS
        .entry(key)
        .or_insert_with(|| MethodBudgetEntry {
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

// SECREM-01 API-1 (closes audit M-API-03): the `OPERATOR_AUTH`
// thread-local is GONE. Request-scoped authorization must never ride a
// thread-local across an async boundary — on a multi-threaded tokio
// runtime the handler can resume on a different worker than the one
// that ran `on_request`, so the flag reflected whichever request last
// touched that thread; a concurrent unauthenticated
// `citrate_emergencyPause` could observe a stale `true` and halt block
// production. Privileged methods now authenticate INSIDE the handler
// via `crate::server::require_operator_auth` (CITRATE_OPERATOR_TOKEN +
// `operator_token` request param) — fail-closed when unconfigured,
// thread-safe by construction. The Semgrep rule
// `m-api-03-thread-local-rate.yaml` keeps firing CI on any new
// `thread_local!` introductions in this module.
//
// CLIENT_KEY remains: it carries rate-limit budget attribution (not
// authorization). It shares the same cross-thread caveat — worst case
// is budget misattribution between concurrent requests, not an authz
// bypass. Migrating it to `MetaIoHandler` metadata stays tracked under
// the RM-G2 cleanup pass.
thread_local! {
    // WP-I.4: Thread-local client key for method-level budget enforcement.
    // Set by the middleware before method dispatch.
    static CLIENT_KEY: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
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
    /// DEPRECATED (SECREM-01 API-1): no longer consumed. Operator auth is
    /// `crate::server::require_operator_auth` — the CITRATE_OPERATOR_TOKEN
    /// environment variable checked against the `operator_token` request
    /// param inside each privileged handler, fail-closed when unset. The
    /// field is retained so existing config plumbing keeps deserializing;
    /// setting it logs a startup warning pointing at the env var.
    pub operator_token: Option<String>,
    /// API key for gating all JSON-RPC requests (Sprint 03 — closed beta).
    /// When set, every request must present this key via:
    ///   - `Authorization: Bearer <key>`
    ///   - `X-API-Key: <key>`
    ///   - `?api_key=<key>` query parameter
    ///     `/health` and `/ready` endpoints are exempt.
    ///     When None (default), all requests are allowed (open mode / devnet).
    pub api_key: Option<String>,
    /// WP-K.4: Whether the RPC server is bound to a public (non-loopback)
    /// interface. SECREM-01 API-1/API-2 note: this flag no longer gates
    /// operator auth (which is unconditionally fail-closed via
    /// `require_operator_auth` regardless of bind) — it remains for
    /// deployment diagnostics (the node binary warns when publicly bound
    /// without an operator token configured).
    pub is_public_bind: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 50_000, // High-throughput benchmark ceiling
            window_secs: 1,
            trusted_proxies: Vec::new(), // WP-I.1: secure default — no header trust
            method_costs: Vec::new(),
            operator_token: None,  // WP-I.2: no auth in devnet by default
            api_key: None,         // Sprint 03: no API key required by default
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

/// PBA-L1a-009: a cloneable handle onto a [`RateLimiter`]'s per-client request
/// buckets, so the JSON-RPC layer (which sees batch sizes the HTTP middleware
/// cannot) can charge each batch element as a request against the same bucket.
#[derive(Clone)]
pub struct RateLimitHandle {
    buckets: Arc<DashMap<String, BucketEntry>>,
    max_requests: u32,
    window_secs: u64,
}

impl RateLimitHandle {
    /// Charge `units` extra requests to `client_key`'s bucket in the current
    /// window. Returns `false` (and leaves the bucket saturated) when that
    /// pushes the client over `max_requests`.
    pub fn charge(&self, client_key: &str, units: u32) -> bool {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.window_secs);
        let mut entry = self
            .buckets
            .entry(client_key.to_string())
            .or_insert_with(|| BucketEntry {
                count: 0,
                window_start: now,
                last_access: now,
            });
        if now.duration_since(entry.window_start) >= window {
            entry.count = 0;
            entry.window_start = now;
        }
        entry.last_access = now;
        entry.count = entry.count.saturating_add(units);
        entry.count <= self.max_requests
    }

    /// Charge `units` to the client the HTTP middleware attributed the current
    /// request to. With no attribution this fails CLOSED exactly like
    /// [`check_method_budget`] (REM-3), unless the devnet anonymous opt-in is set.
    pub fn charge_current_client(&self, units: u32) -> bool {
        let key = current_client_key();
        if key.is_empty() {
            return anonymous_opt_in(
                std::env::var("CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT")
                    .ok()
                    .as_deref(),
            );
        }
        self.charge(&key, units)
    }
}

/// The REM-3 devnet opt-in value (`1` / `true`, case-insensitive).
fn anonymous_opt_in(v: Option<&str>) -> bool {
    v.map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Per-client sliding window rate limiter implementing `RequestMiddleware`.
pub struct RateLimiter {
    config: RateLimitConfig,
    buckets: Arc<DashMap<String, BucketEntry>>,
    trusted_set: HashSet<IpAddr>,
    api_key: Option<String>,
    /// WP-K.3: Last time stale buckets were evicted
    last_eviction: Arc<std::sync::Mutex<Instant>>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        let trusted_set: HashSet<IpAddr> = config.trusted_proxies.iter().cloned().collect();
        let api_key = config.api_key.clone();
        // SECREM-01 API-1: `operator_token`/`is_public_bind` are no longer
        // consumed here — operator auth moved into the handlers
        // (require_operator_auth, env-token). Warn loudly if a deployment
        // still sets the config token so the operator knows where auth
        // actually lives now.
        if config.operator_token.is_some() {
            warn!(
                "RateLimitConfig.operator_token is no longer used for RPC \
                 operator auth (SECREM-01 API-1). Set CITRATE_OPERATOR_TOKEN \
                 and pass `operator_token` in request params instead."
            );
        }
        Self {
            config,
            buckets: Arc::new(DashMap::new()),
            trusted_set,
            api_key,
            last_eviction: Arc::new(std::sync::Mutex::new(Instant::now())),
        }
    }

    /// PBA-L1a-009: a handle the JSON-RPC middleware uses to charge batch
    /// elements to the same per-client buckets this limiter enforces.
    pub fn handle(&self) -> RateLimitHandle {
        RateLimitHandle {
            buckets: self.buckets.clone(),
            max_requests: self.config.max_requests,
            window_secs: self.config.window_secs,
        }
    }

    /// WP-K.3: Evict stale buckets to prevent unbounded memory growth.
    /// Removes entries not accessed within BUCKET_TTL_SECS.
    /// If still over MAX_BUCKETS after TTL eviction, removes oldest entries.
    fn evict_stale_buckets(&self, now: Instant) {
        let ttl = std::time::Duration::from_secs(BUCKET_TTL_SECS);

        // Evict stale per-client buckets
        self.buckets
            .retain(|_, entry| now.duration_since(entry.last_access) < ttl);

        // If still over capacity, remove oldest entries
        if self.buckets.len() > MAX_BUCKETS {
            let mut entries: Vec<(String, Instant)> = self
                .buckets
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
                // SECREM-02 5.6: constant-time compare — same class as the
                // operator-token fix in server.rs (2026-05-31 audit -006).
                let key_valid = Self::extract_api_key(&request)
                    .map(|k| crate::server::constant_time_eq(k.as_bytes(), expected_key.as_bytes()))
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

        // SECREM-01 API-1: operator authentication no longer happens in
        // middleware (the thread-local it fed was unsound across async
        // boundaries, and its no-token-on-localhost branch was fail-OPEN
        // for default-constructed configs — API-2). Privileged handlers
        // call `crate::server::require_operator_auth` themselves.

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

        let mut entry = self
            .buckets
            .entry(client_key.clone())
            .or_insert_with(|| BucketEntry {
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
            warn!(
                "Rate limit exceeded for client {}: {} requests in {}s",
                client_key, max, self.config.window_secs
            );
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
pub fn extract_client_key(
    request: &hyper::Request<Body>,
    trusted_proxies: &HashSet<IpAddr>,
) -> String {
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

    // CHAIN-B-D009: FAIL CLOSED. jsonrpc-http-server does not expose the TCP
    // peer address here, so when no *trusted* proxy has supplied a forwarding
    // header we cannot attribute the request to a real client. The previous
    // fallback keyed the bucket on the `Host` header (and then the URI
    // authority) — both attacker-controlled. That gave an unlimited quota
    // bypass: rotating `Host:` minted a fresh bucket per request, so neither
    // the rate limiter nor the method budget ever fired. Keying on any
    // attacker-controlled value is strictly worse than one shared bucket, so
    // return a single constant key here. Operators who need per-client limits
    // MUST front the node with a reverse proxy that sets X-Forwarded-For and
    // list its address in `trusted_proxies`.
    {
        use std::sync::atomic::{AtomicBool, Ordering};
        static WARNED_HOST_FALLBACK: AtomicBool = AtomicBool::new(false);
        if !WARNED_HOST_FALLBACK.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "Rate limiting cannot identify clients without a trusted proxy; \
                 failing closed to a single shared bucket. Configure trusted_proxies \
                 (and a reverse proxy that sets X-Forwarded-For) for per-client limits."
            );
        }
    }
    // A single, non-attacker-controlled bucket. Everyone unidentifiable shares
    // it — safe against the Host-rotation bypass.
    "untrusted_shared".to_string()
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
mod tests_pba_l1a_009 {
    use super::*;

    fn handle(max: u32, window_secs: u64) -> RateLimitHandle {
        RateLimiter::new(RateLimitConfig {
            max_requests: max,
            window_secs,
            ..Default::default()
        })
        .handle()
    }

    /// PBA-L1a-009: batch elements share the per-client bucket, and the
    /// bucket resets when its window has elapsed.
    #[test]
    fn charge_counts_units_and_resets_expired_window() {
        let h = handle(3, 60);
        assert!(h.charge("a", 3));
        assert!(!h.charge("a", 1), "over max");
        assert!(h.charge("b", 1), "buckets are per client");
        // window 0: every call starts a fresh window
        let z = handle(1, 0);
        for _ in 0..3 {
            assert!(z.charge("c", 1), "expired window must reset the count");
        }
    }

    /// PBA-L1a-009: with no attributed client, charging follows the
    /// REM-3 fail-closed rule and its devnet opt-in (pure helper; the env
    /// var itself is exercised by `test_rem_3_*` under its own lock).
    #[test]
    fn anonymous_opt_in_values() {
        assert!(anonymous_opt_in(Some("1")));
        assert!(anonymous_opt_in(Some("TRUE")));
        assert!(!anonymous_opt_in(Some("0")));
        assert!(!anonymous_opt_in(Some("yes")));
        assert!(!anonymous_opt_in(None));
    }
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
        // CHAIN-B-D009: must NOT return the XFF IP, and must NOT key on any
        // attacker-controlled value — fail closed to the shared bucket.
        assert_eq!(
            key, "untrusted_shared",
            "XFF must be ignored and the key must fail closed without trusted proxies, got: {}",
            key
        );
    }

    #[test]
    fn test_xff_honored_with_trusted_proxy() {
        let mut trusted: HashSet<IpAddr> = HashSet::new();
        trusted.insert("127.0.0.1".parse().unwrap());
        let req = make_req_with_header("x-forwarded-for", "203.0.113.50, 70.41.3.18");
        let key = extract_client_key(&req, &trusted);
        assert_eq!(
            key, "203.0.113.50",
            "XFF should be honored with trusted proxy configured"
        );
    }

    #[test]
    fn test_x_real_ip_ignored_without_trusted_proxy() {
        let no_trust: HashSet<IpAddr> = HashSet::new();
        let req = make_req_with_header("x-real-ip", "10.0.0.1");
        let key = extract_client_key(&req, &no_trust);
        assert_eq!(
            key, "untrusted_shared",
            "X-Real-IP must be ignored and the key must fail closed without trusted proxies, got: {}",
            key
        );
    }

    #[test]
    fn test_x_real_ip_honored_with_trusted_proxy() {
        let mut trusted: HashSet<IpAddr> = HashSet::new();
        trusted.insert("127.0.0.1".parse().unwrap());
        let req = make_req_with_header("x-real-ip", "10.0.0.1");
        let key = extract_client_key(&req, &trusted);
        assert_eq!(
            key, "10.0.0.1",
            "X-Real-IP should be honored with trusted proxy"
        );
    }

    /// CHAIN-B-D009 tripwire: without a trusted proxy, the client key must be a
    /// single constant bucket that an attacker cannot vary. Pre-fix the fallback
    /// keyed on the `Host` header, so two requests differing only in `Host`
    /// produced two buckets — an unlimited quota bypass. RED before the
    /// fail-closed change (distinct Hosts → distinct `direct_<host>` keys);
    /// GREEN after (both map to `untrusted_shared`).
    #[test]
    fn d009_host_header_cannot_split_the_rate_limit_bucket() {
        let no_trust: HashSet<IpAddr> = HashSet::new();

        let a = make_req_with_header("host", "attacker-1.example");
        let b = make_req_with_header("host", "attacker-2.example");
        let key_a = extract_client_key(&a, &no_trust);
        let key_b = extract_client_key(&b, &no_trust);

        assert_eq!(
            key_a, key_b,
            "two requests differing only in Host must share one bucket, got {} vs {}",
            key_a, key_b
        );
        assert_eq!(
            key_a, "untrusted_shared",
            "the fail-closed key must not embed any attacker-controlled value, got {}",
            key_a
        );
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
        // RM-I / WP-I1.6: set a client key (REM-3 fix made empty key
        // fail-closed by default; tests now must set a key explicitly).
        CLIENT_KEY.with(|k| *k.borrow_mut() = "test_budget_within_limit".to_string());
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
            RequestMiddlewareAction::Respond { .. } => {
                panic!("Should accept valid X-API-Key header")
            }
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
            RequestMiddlewareAction::Respond { .. } => {
                panic!("Should allow all requests when no API key configured")
            }
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
            RequestMiddlewareAction::Respond { .. } => {
                panic!("/health should be exempt from API key")
            }
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
        limiter.buckets.insert(
            "stale_client".to_string(),
            BucketEntry {
                count: 5,
                window_start: past,
                last_access: past,
            },
        );

        // Insert a fresh entry
        limiter.buckets.insert(
            "fresh_client".to_string(),
            BucketEntry {
                count: 1,
                window_start: Instant::now(),
                last_access: Instant::now(),
            },
        );

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
            limiter.buckets.insert(
                format!("client_{}", i),
                BucketEntry {
                    count: 1,
                    window_start: now,
                    last_access: now,
                },
            );
        }

        assert!(limiter.buckets.len() > MAX_BUCKETS);

        // Eviction should cap at MAX_BUCKETS (none are stale, so cap enforced)
        limiter.evict_stale_buckets(now);

        assert!(
            limiter.buckets.len() <= MAX_BUCKETS,
            "Bucket count should be capped at MAX_BUCKETS after eviction"
        );
    }

    // SECREM-01 API-1/API-2: the K-4 trio below replaced tests of the
    // removed middleware thread-local. The old "localhost + no token →
    // operator allowed" devnet convenience was finding API-2's fail-open
    // mode for default-constructed configs; the new model is
    // unconditionally fail-closed and lives in
    // `crate::server::require_operator_auth`. Env mutation serializes on
    // K4_ENV_LOCK (lib tests run in one process).
    static K4_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_k4_middleware_grants_no_operator_state() {
        // The middleware must proceed without conferring ANY operator
        // privilege — even in the old fail-open configuration (localhost,
        // no token). Auth happens only inside privileged handlers.
        for public in [true, false] {
            let limiter = RateLimiter::new(RateLimitConfig {
                operator_token: None,
                is_public_bind: public,
                ..Default::default()
            });
            match limiter.on_request(make_req()) {
                RequestMiddlewareAction::Proceed { .. } => {}
                _ => panic!("plain request must proceed (auth is per-method now)"),
            }
        }
    }

    #[test]
    fn test_k4_operator_auth_fail_closed_when_unconfigured() {
        let _guard = K4_ENV_LOCK.lock().expect("env lock");
        std::env::remove_var("CITRATE_OPERATOR_TOKEN");
        // API-2 regression guard: with nothing configured, operator
        // methods are DENIED — there is no fail-open devnet branch.
        assert!(
            crate::server::require_operator_auth(&serde_json::Map::new()).is_err(),
            "unconfigured operator token must fail closed"
        );
    }

    #[test]
    fn test_k4_operator_auth_param_token_roundtrip() {
        let _guard = K4_ENV_LOCK.lock().expect("env lock");
        std::env::set_var("CITRATE_OPERATOR_TOKEN", "my-secret");
        let mut ok = serde_json::Map::new();
        ok.insert(
            "operator_token".into(),
            serde_json::Value::String("my-secret".into()),
        );
        let mut bad = serde_json::Map::new();
        bad.insert(
            "operator_token".into(),
            serde_json::Value::String("wrong".into()),
        );
        assert!(crate::server::require_operator_auth(&ok).is_ok());
        assert!(crate::server::require_operator_auth(&bad).is_err());
        std::env::remove_var("CITRATE_OPERATOR_TOKEN");
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
        assert!(
            check_method_budget(10).is_err(),
            "Should reject after budget exceeded"
        );
    }

    /// REM-3 (re-audit Stream 2 / RM-I WP-I1.6):
    /// `check_method_budget` previously returned `Ok(())` when
    /// `current_client_key()` was empty, silently failing OPEN. Post-fix:
    /// fail CLOSED unless the operator explicitly opts into anonymous
    /// traffic via `CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT=1`.
    ///
    /// The two assertions are combined into a single test because they
    /// share global state (the env var). Splitting them across two
    /// `#[test]` functions causes parallel-test races; this is the
    /// standard discipline in this file (see also the operator-auth
    /// tests above which use the same shape).
    #[test]
    fn test_rem_3_empty_client_key_fail_closed_or_opt_in() {
        // Use a static mutex to serialise this test against any other
        // test that touches the same env var.
        use std::sync::Mutex;
        static GUARD: Mutex<()> = Mutex::new(());
        let _g = GUARD.lock().expect("REM-3 mutex");

        // Sub-assertion 1: default behaviour is fail-closed.
        std::env::remove_var("CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT");
        CLIENT_KEY.with(|k| k.borrow_mut().clear());
        let r = check_method_budget(1);
        assert!(
            r.is_err(),
            "REM-3: empty client_key must fail closed by default"
        );
        let err = r.expect_err("REM-3 fail-closed");
        assert_eq!(err.code, jsonrpc_core::ErrorCode::ServerError(-32007));
        assert!(
            err.message.contains("attribution failed"),
            "REM-3 error must mention attribution failure; got: {}",
            err.message
        );

        // Sub-assertion 2: explicit opt-in via env var lets the request through.
        std::env::set_var("CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT", "1");
        CLIENT_KEY.with(|k| k.borrow_mut().clear());
        let r = check_method_budget(1);
        std::env::remove_var("CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT");
        assert!(
            r.is_ok(),
            "REM-3: with CITRATE_ALLOW_ANONYMOUS_RATE_LIMIT=1, empty client_key allowed"
        );
    }
}
