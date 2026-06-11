//! Cloudflare Turnstile siteverify wrapper.
//!
//! RM-B1 / WP-E6.3 (audit FAU-03): pre-fix the faucet had no
//! human-versus-script gate. A motivated attacker could spin up
//! ~thousands of throwaway addresses and pull the faucet dry in
//! minutes. Post-fix Cloudflare Turnstile (or the compatible
//! hCaptcha endpoint) verifies the user solved a challenge before
//! the drip proceeds.
//!
//! Operator config:
//!   FAUCET_TURNSTILE_SECRET=<server-side secret from Cloudflare>
//!   FAUCET_TURNSTILE_VERIFY_URL=<override; defaults to
//!     https://challenges.cloudflare.com/turnstile/v0/siteverify>

use serde::Deserialize;
use std::time::Duration;

/// Default verify endpoint. Cloudflare's documented URL.
const DEFAULT_VERIFY_URL: &str =
    "https://challenges.cloudflare.com/turnstile/v0/siteverify";

/// HTTP timeout for the verify call. Generous enough to absorb
/// transient slowness; short enough that a /drip request doesn't
/// hang for minutes if Turnstile is degraded.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Debug, Deserialize)]
struct VerifyResponse {
    success: bool,
    #[serde(default, rename = "error-codes")]
    error_codes: Vec<String>,
}

/// Server-side Turnstile verifier. Holds the secret and the HTTP
/// client; `verify` POSTs the user's token + (optional) remote IP
/// and returns whether Cloudflare accepted the challenge.
pub struct TurnstileVerifier {
    secret: String,
    verify_url: String,
    client: reqwest::Client,
}

impl TurnstileVerifier {
    pub fn new(secret: impl Into<String>) -> Self {
        let verify_url = std::env::var("FAUCET_TURNSTILE_VERIFY_URL")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_VERIFY_URL.to_string());
        let client = reqwest::Client::builder()
            .timeout(VERIFY_TIMEOUT)
            .build()
            .expect("reqwest client should build");
        Self {
            secret: secret.into(),
            verify_url,
            client,
        }
    }

    /// Verify a user-supplied Turnstile token. `remote_ip` is
    /// optional; when present, Cloudflare uses it to bind the
    /// challenge to the requesting IP (additional defense against
    /// token replay across IPs).
    pub async fn verify(
        &self,
        token: &str,
        remote_ip: Option<&str>,
    ) -> Result<bool, String> {
        let mut form = vec![
            ("secret", self.secret.as_str()),
            ("response", token),
        ];
        if let Some(ip) = remote_ip {
            form.push(("remoteip", ip));
        }
        let resp = self
            .client
            .post(&self.verify_url)
            .form(&form)
            .send()
            .await
            .map_err(|e| format!("turnstile request failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!(
                "turnstile responded with HTTP {}",
                resp.status().as_u16()
            ));
        }

        let body: VerifyResponse = resp
            .json()
            .await
            .map_err(|e| format!("turnstile response not JSON: {}", e))?;

        if !body.success && !body.error_codes.is_empty() {
            tracing::warn!(
                "Turnstile rejected: error-codes = {:?}",
                body.error_codes
            );
        }
        Ok(body.success)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All three tests in this module mutate the process-global env var
    /// `FAUCET_TURNSTILE_VERIFY_URL`. `cargo test` runs tests in a binary
    /// in parallel by default, so without serialization one test can
    /// observe another's set/remove and fail nondeterministically. This
    /// surfaced during RM-M1 sprint-close baseline re-runs (4,967+
    /// workspace tests; turnstile flakes ~10% of the time when target/
    /// is rebuilt from clean and cargo's test schedule changes).
    ///
    /// Mutex acquired at the top of every test so they run one-at-a-time
    /// within this binary. Cross-binary parallelism is unaffected.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[tokio::test]
    async fn test_constructor_uses_env_url_override() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var(
            "FAUCET_TURNSTILE_VERIFY_URL",
            "http://example.invalid/verify",
        );
        let v = TurnstileVerifier::new("test-secret");
        assert_eq!(v.verify_url, "http://example.invalid/verify");
        // Clean up so it doesn't bleed into other tests.
        std::env::remove_var("FAUCET_TURNSTILE_VERIFY_URL");
    }

    #[tokio::test]
    async fn test_constructor_default_url_when_env_empty() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("FAUCET_TURNSTILE_VERIFY_URL");
        let v = TurnstileVerifier::new("test-secret");
        assert_eq!(v.verify_url, DEFAULT_VERIFY_URL);
    }

    /// Hitting an unreachable URL must surface as `Err`, not
    /// `Ok(false)` — the faucet's caller treats those differently
    /// (transient outage vs. user failed CAPTCHA).
    #[tokio::test]
    // The env-lock is intentionally held across the await to serialize
    // env-var access between tests; a tokio Mutex isn't warranted here.
    #[allow(clippy::await_holding_lock)]
    async fn test_unreachable_endpoint_errors() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var(
            "FAUCET_TURNSTILE_VERIFY_URL",
            "http://127.0.0.1:1/verify",
        );
        let v = TurnstileVerifier::new("test-secret");
        let r = v.verify("any-token", Some("1.2.3.4")).await;
        assert!(r.is_err(), "unreachable URL must error");
        std::env::remove_var("FAUCET_TURNSTILE_VERIFY_URL");
    }
}
