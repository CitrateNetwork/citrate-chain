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

**Phase 2 — dry-run runner, no chain required.**

Implemented (Phase 1):
- `config` — bench.toml loader + offline validation
- `address_table` — `30_address_table.json` loader
- `fingerprint` — ceremony bundle sha256 validator
- `nonce` — per-signer `NonceLane` with in-flight cap
- `signers/keystore` — Foundry V3 keystore loader with zeroize-on-drop
- `signers/pool` — `SignerPool` with round-robin lane selection
- `tx/legacy` — EIP-155 legacy RLP signer (cross-checked against the
  canonical EIP-155 test vector)

Implemented (Phase 2):
- `workload::WorkloadClass` trait + `WorkloadContext`
- `workload::transfer::SimpleTransfer` — native-value transfer class
- `runner::Runner` — deadline-based rate limiter that drives the full
  keystore → pool → signer → signed-tx pipeline at a target TPS
- `runner::RunMode::DryRun` — builds and signs but never broadcasts
- CLI `dry-run` subcommand with keystore-backed multi-signer flow

Not yet implemented (later phases):
- Phase 3: real submission via `eth_sendRawTransaction`
- Phase 4: multi-class mix
- Phase 5: finality tracker (depth + checkpoint)
- Phase 6: production run on frozen testnet

## Running

```bash
cd citrate_v0.01.1/tools/citrate-bench

# All unit + integration tests (no chain required)
cargo test

# Offline config check
cargo run -- validate --config path/to/bench.toml

# Inspect a frozen ceremony address table
cargo run -- show-addresses --table path/to/30_address_table.json

# Verify a ceremony bundle sha256
cargo run -- verify-bundle --bundle 60_proof_bundle.tar.gz --expected sha256:...

# Phase 2 end-to-end dry-run with Foundry keystore accounts
cargo run --release -- dry-run \
  --keystore-dir ~/.foundry/keystores \
  --accounts bench-01,bench-02,bench-03 \
  --passphrase-file ~/.bench-pw \
  --chain-id 40204 \
  --target-tps 5000 \
  --duration-secs 10
```

The dry-run path signs transactions at the target rate and reports the
effective TPS, per-signer counts, and sample hashes. It never touches
the network.

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
