//! HUP-S6.5 / federation F-5: the desktop app's path to the faucet (faucet ADR O-3, pending
//! owner sign-off).
//!
//! Two opt-in pieces, both off unless the operator sets them:
//!
//! 1. **Desktop origin allowlist** (`FAUCET_DESKTOP_ORIGINS`). The Citrate Core desktop app's
//!    webview has a fixed, non-https origin (`tauri://localhost` on macOS and Linux,
//!    `http://tauri.localhost` or `https://tauri.localhost` on Windows). The browser CORS
//!    allowlist only accepts `https://` origins, so these are listed separately and only the
//!    exact known values are accepted: nothing else that merely looks like a desktop origin.
//! 2. **CAPTCHA page** (`FAUCET_TURNSTILE_SITE_KEY`, used together with
//!    `FAUCET_TURNSTILE_SECRET`). When set, the faucet's own page renders the Turnstile challenge
//!    and sends its token with the request, and the page's CSP allows the challenge script and
//!    frame. The desktop app opens this page in an in-app window on the faucet's own origin
//!    with the member's address filled in (`/?address=0x…`), so the challenge runs on a host the
//!    CAPTCHA provider already allows, and the member solves it there. The app then reads
//!    `/eligibility` to see the drip.
//!
//! Without the site key the page and its CSP are byte-for-byte what they were.

/// The only desktop origins `FAUCET_DESKTOP_ORIGINS` may name.
pub const KNOWN_DESKTOP_ORIGINS: &[&str] = &[
    "tauri://localhost",
    "http://tauri.localhost",
    "https://tauri.localhost",
];

/// The CAPTCHA provider's script/frame origin.
pub const TURNSTILE_ORIGIN: &str = "https://challenges.cloudflare.com";

/// Parse `FAUCET_DESKTOP_ORIGINS` (comma-separated). Only exact entries of
/// [`KNOWN_DESKTOP_ORIGINS`] are kept; the rest are dropped (and returned so the caller can log
/// them). Unset or blank: none.
pub fn desktop_origins(raw: Option<&str>) -> (Vec<String>, Vec<String>) {
    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    for entry in raw.unwrap_or_default().split(',').map(str::trim) {
        if entry.is_empty() {
            continue;
        }
        if KNOWN_DESKTOP_ORIGINS.contains(&entry) {
            if !kept.iter().any(|k: &String| k == entry) {
                kept.push(entry.to_string());
            }
        } else {
            dropped.push(entry.to_string());
        }
    }
    (kept, dropped)
}

/// Parse `FAUCET_TURNSTILE_SITE_KEY`. A site key is public, but it is written into the page, so
/// only `[A-Za-z0-9_-]`, 1 to 128 characters, is accepted. Unset or blank: `Ok(None)`.
pub fn parse_site_key(raw: Option<&str>) -> Result<Option<String>, String> {
    let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let ok = s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if !ok {
        return Err(
            "FAUCET_TURNSTILE_SITE_KEY must be 1 to 128 characters of A-Z, a-z, 0-9, _ or -"
                .to_string(),
        );
    }
    Ok(Some(s.to_string()))
}

/// The page CSP when the CAPTCHA page is on: the base CSP plus the provider's script and frame.
pub fn csp_with_turnstile(base: &str) -> String {
    base.replace(
        "script-src 'self'",
        &format!("script-src 'self' {TURNSTILE_ORIGIN}"),
    )
    .replace(
        "frame-ancestors 'none'",
        &format!("frame-src {TURNSTILE_ORIGIN}; frame-ancestors 'none'"),
    )
}

/// The widget markup inserted into the page when the CAPTCHA page is on. `site_key` has passed
/// [`parse_site_key`], so it needs no escaping.
pub fn turnstile_markup(site_key: &str) -> String {
    format!(
        "<div class=\"cf-turnstile\" data-sitekey=\"{site_key}\" style=\"margin-top:14px\"></div>\n\
<script src=\"{TURNSTILE_ORIGIN}/turnstile/v0/api.js\" async defer></script>"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_known_desktop_origins_are_kept() {
        let (kept, dropped) = desktop_origins(Some(
            "tauri://localhost, http://tauri.localhost ,https://tauri.localhost.evil.com,tauri://localhost/,tauri://evil, *,tauri://localhost",
        ));
        assert_eq!(kept, vec!["tauri://localhost", "http://tauri.localhost"]);
        assert_eq!(dropped.len(), 4);
        assert!(desktop_origins(None).0.is_empty());
        assert!(desktop_origins(Some(" , ")).0.is_empty());
    }

    #[test]
    fn site_key_charset_is_enforced() {
        assert_eq!(parse_site_key(None).expect("ok"), None);
        assert_eq!(
            parse_site_key(Some(" 0x4AAA_b-c ")).expect("ok"),
            Some("0x4AAA_b-c".to_string())
        );
        for bad in ["a\"b", "<script>", "a b", &"a".repeat(129)] {
            assert!(parse_site_key(Some(bad)).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn turnstile_csp_adds_only_the_provider() {
        let base =
            "default-src 'none'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'";
        let csp = csp_with_turnstile(base);
        assert_eq!(
            csp,
            "default-src 'none'; script-src 'self' https://challenges.cloudflare.com; connect-src 'self'; frame-src https://challenges.cloudflare.com; frame-ancestors 'none'"
        );
        assert!(!csp.contains("unsafe-inline"));
    }
}
