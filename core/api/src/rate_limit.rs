// citrate/core/api/src/rate_limit.rs
//
// Per-IP sliding window rate limiter for the JSON-RPC server.

use dashmap::DashMap;
use jsonrpc_http_server::hyper::{self, Body};
use jsonrpc_http_server::{RequestMiddleware, RequestMiddlewareAction};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tracing::warn;

/// Configuration for the RPC rate limiter.
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    /// Maximum requests per window per IP.
    pub max_requests: u32,
    /// Window duration in seconds.
    pub window_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window_secs: 1,
        }
    }
}

struct BucketEntry {
    count: u32,
    window_start: Instant,
}

/// Per-IP sliding window rate limiter implementing `RequestMiddleware`.
pub struct RateLimiter {
    config: RateLimitConfig,
    buckets: Arc<DashMap<IpAddr, BucketEntry>>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: Arc::new(DashMap::new()),
        }
    }
}

impl RequestMiddleware for RateLimiter {
    fn on_request(&self, request: hyper::Request<Body>) -> RequestMiddlewareAction {
        // Extract client IP from X-Forwarded-For header or connection info
        let ip = extract_ip(&request);

        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.config.window_secs);
        let max = self.config.max_requests;

        let mut entry = self.buckets.entry(ip).or_insert_with(|| BucketEntry {
            count: 0,
            window_start: now,
        });

        // Reset window if expired
        if now.duration_since(entry.window_start) >= window {
            entry.count = 0;
            entry.window_start = now;
        }

        entry.count += 1;

        if entry.count > max {
            drop(entry); // Release dashmap lock before logging
            warn!("Rate limit exceeded for IP {}: {} requests in {}s", ip, max, self.config.window_secs);
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

/// Extract client IP from request headers or connection info.
fn extract_ip(request: &hyper::Request<Body>) -> IpAddr {
    // Try X-Forwarded-For first (when behind reverse proxy)
    if let Some(xff) = request.headers().get("x-forwarded-for") {
        if let Ok(xff_str) = xff.to_str() {
            // Take first IP in chain
            if let Some(first) = xff_str.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }

    // Try X-Real-IP
    if let Some(real_ip) = request.headers().get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }

    // Fallback to loopback (connection IP is not easily available in hyper)
    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
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

    #[test]
    fn test_extract_ip_from_xff() {
        let req = make_req_with_header("x-forwarded-for", "203.0.113.50, 70.41.3.18");
        let ip = extract_ip(&req);
        assert_eq!(ip, "203.0.113.50".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_extract_ip_from_x_real_ip() {
        let req = make_req_with_header("x-real-ip", "10.0.0.1");
        let ip = extract_ip(&req);
        assert_eq!(ip, "10.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_extract_ip_fallback() {
        let ip = extract_ip(&make_req());
        assert_eq!(ip, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    }
}
