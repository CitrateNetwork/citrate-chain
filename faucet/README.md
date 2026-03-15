# Faucet

Test token faucet for the Citrate network. Drips SALT tokens to requested addresses with per-address rate limiting and cooldown enforcement.

## Contents

- `src/main.rs` -- HTTP server, drip endpoint, rate limiting logic, cooldown tracking

## Build / Usage

```bash
cargo build --release -p citrate-faucet
cargo run --bin citrate-faucet
```
