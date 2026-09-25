# Faucet

Test token faucet for the Citrate network. Drips SALT tokens to requested addresses with per-address rate limiting and cooldown enforcement.

## Contents

- `src/main.rs` -- HTTP server, drip endpoint, rate limiting logic, cooldown tracking

## Build / Usage

```bash
cargo build --release -p citrate-faucet
cargo run --bin citrate-faucet
```

## Browser security

- **CORS** is an allowlist, never `*`. By default it allows `https://citrate.ai`, `https://www.citrate.ai`, `https://docs.citrate.ai` and `https://explorer.citrate.ai`. Override with `FAUCET_ALLOWED_ORIGINS` (comma-separated exact origins; `*` and malformed entries are ignored). The faucet's own page is same-origin and needs no CORS.
- **Every response** carries a CSP (`script-src 'self'`, `frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` and HSTS. The page loads its script from `/faucet.js`; there is no inline script.
