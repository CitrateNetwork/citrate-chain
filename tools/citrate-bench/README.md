---
created: 2026-04-07T20:45:00Z
branch: benchmark-rehearsal
author: Claude (Anthropic, Opus 4.6)
status: active
scope: Post-ceremony Citrate testnet benchmark harness
---

# citrate-bench

Production-correct TPS benchmark for the Citrate testnet. Replaces
`tests/load/src/bin/benchmark_suite.rs` (devnet-only, uses
`eth_sendTransaction` with fake unlocked sender) and supersedes the
narrow proof-of-concept `tests/load/src/bin/bench_signed.rs`.

Design spec: `.agentile/quorum/16_POST_CEREMONY_BENCHMARK_HARNESS_SPEC.md`.

## Status

**Phase 1 — skeleton, no chain required.**

Implemented:
- `config` — bench.toml loader + offline validation
- `address_table` — `30_address_table.json` loader
- `fingerprint` — ceremony bundle sha256 validator
- `nonce` — per-signer `NonceLane` with in-flight cap
- `signers/keystore` — Foundry V3 keystore loader with zeroize-on-drop
- `signers/pool` — `SignerPool` with round-robin lane selection
- `tx/legacy` — EIP-155 legacy RLP signer (cross-checked against the
  canonical EIP-155 test vector)

Not yet implemented (later phases):
- Phase 2: workload classes + runner + `--dry-run`
- Phase 3: real submission via `eth_sendRawTransaction`
- Phase 4: multi-class mix
- Phase 5: finality tracker (depth + checkpoint)
- Phase 6: production run on frozen testnet

## Running (Phase 1 features only)

```bash
cd citrate_v0.01.1/tools/citrate-bench
cargo test                 # unit tests
cargo run -- validate --config examples/bench.toml
cargo run -- show-addresses --table path/to/30_address_table.json
```

## Preconditions for a real run

Cannot run a benchmark until **all** of the following exist:

1. A frozen `30_address_table.json` from a real testnet ceremony
2. A `60_manifest.json` with a matching bundle sha256
3. Dedicated benchmark signers in a Foundry keystore, funded on the
   target chain above the configured floor
4. A reachable RPC endpoint whose `eth_chainId` matches the config

The harness refuses to run if any precondition fails. Reasons are
printed to stderr and no report is emitted.

## Why it is a standalone crate

It is **not** in the main citrate workspace. Two reasons:

1. Dependency churn in a benchmark tool should never block core crate
   work. The older `tests/load` crate is standalone for the same reason.
2. The old `tests/load` binaries (`benchmark-suite`, `live-bench`,
   `bench-signed`) stay in place as historical artifacts. Mixing the
   production-correct binary with legacy devnet tooling invites confusion.

## License

MIT OR Apache-2.0.
