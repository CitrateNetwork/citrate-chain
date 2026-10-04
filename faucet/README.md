# Faucet

Test token faucet for the Citrate network. Drips SALT tokens to requested addresses with per-address rate limiting and cooldown enforcement.

## Contents

- `src/main.rs` -- HTTP server, drip endpoint, rate limiting logic, cooldown tracking
- `src/cooldowns.rs` -- per-address (24 h) and per-IP (1 h) cooldowns, optionally persisted
- `src/limits.rs` -- optional faucet-wide hourly drip cap
- `src/membership.rs` -- optional membership-SBT check (fails closed)
- `src/liveness.rs` -- the `/ready` probe (RPC chain id + faucet balance)
- `src/desktop.rs` -- desktop-app origins and the optional CAPTCHA page

## Build / Usage

```bash
cargo build --release -p citrate-faucet
cargo run --bin citrate-faucet
```

## Browser security

- **CORS** is an allowlist, never `*`. By default it allows `https://citrate.ai`, `https://www.citrate.ai`, `https://docs.citrate.ai` and `https://explorer.citrate.ai`. Override with `FAUCET_ALLOWED_ORIGINS` (comma-separated exact origins; `*` and malformed entries are ignored). The faucet's own page is same-origin and needs no CORS.
- **Every response** carries a CSP (`script-src 'self'`, `frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` and HSTS. The page loads its script from `/faucet.js`; there is no inline script.

## Endpoints

| Route | What it answers |
|---|---|
| `GET /health` | Liveness: the process is up. Never touches the RPC. Always 200. |
| `GET /ready` | Readiness: the RPC answers with the configured chain id and the faucet balance covers one more drip. 200 when ready, 503 with a `reason` when not. Cached for 15 s. |
| `GET /status` | Static facts plus limits: `drip_wei`, cooldowns, `global_cap_per_hour`, `captcha`, `turnstile_site_key`, `membership_check`. |
| `GET /eligibility?address=0x…` | Read-only: would a request for this address, from this caller, pass the cooldowns now? Reserves nothing. On a refusal it gives `retry_after_secs` and `next_eligible_at` (Unix seconds). |
| `POST /faucet` | The drip. A refusal carries a stable `code` (`invalid_address`, `not_whitelisted`, `captcha_required`, `captcha_failed`, `captcha_unavailable`, `not_member`, `membership_unavailable`, `rate_limited`, `signing_failed`, `rpc_error`, `unknown_rpc_response`, `node_unreachable`); a `rate_limited` refusal also names the `limit` (`address`, `ip` or `global`) and the next eligible time. |

## Optional limits and the desktop path (HUP-S6.5)

All off unless the operator sets them; see `.env.example`. They implement the citrate-core
faucet ADR (ADR-2026-10-01-faucet-for-deploy-gas), whose open questions O-1 to O-4 are pending
owner sign-off, so the suggested values are placeholders.

- `FAUCET_MAX_DRIPS_PER_HOUR`: a sliding one-hour cap over all callers, reserved before the send
  and returned if the drip fails.
- `FAUCET_MEMBER_SBT`: drip only to an address holding the membership SBT
  (`balanceOf(recipient) > 0` via `eth_call`). An RPC failure refuses the drip.
- `FAUCET_TURNSTILE_SITE_KEY` (with `FAUCET_TURNSTILE_SECRET`): the page renders the CAPTCHA and
  sends its token; the CSP then allows `https://challenges.cloudflare.com` for scripts and frames
  only. The page accepts `/?address=0x…` to fill the address in, which is how the desktop app
  opens it in an in-app window.
- `FAUCET_DESKTOP_ORIGINS`: the exact desktop-app webview origins allowed by CORS.

Testing: `cargo test -p citrate-faucet` runs one test against a local `anvil` (chain id 40204,
on loopback, with a throwaway key made at run time) when Foundry is installed: a real drip,
the address cooldown, the global cap, and the membership check. Nothing touches a public chain.
