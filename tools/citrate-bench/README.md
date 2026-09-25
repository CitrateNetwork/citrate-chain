# citrate-bench

Production-correct TPS benchmark for the Citrate testnet. Replaces
`tests/load/src/bin/benchmark_suite.rs` (devnet-only, uses
`eth_sendTransaction` with fake unlocked sender) and supersedes the
narrow proof-of-concept `tests/load/src/bin/bench_signed.rs`.

Design spec: `.agentile/quorum/16_POST_CEREMONY_BENCHMARK_HARNESS_SPEC.md`.

## Status

**Phase 3 — broadcast runner validated against local anvil.**

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

Implemented (Phase 3):
- `rpc::RpcClient` — typed JSON-RPC client (eth_chainId, eth_blockNumber,
  eth_getTransactionCount, eth_getBalance, eth_sendRawTransaction,
  eth_getTransactionReceipt) with mockito-based unit tests
- `tracker::Tracker` — receipt polling worker pool with exponential
  backoff, per-tx timeout, atomic counters, bounded mpsc channel
- `runner::RunMode::Broadcast` — submits via `eth_sendRawTransaction`,
  spawns bounded concurrent submission tasks, hands accepted hashes
  to the tracker, computes ground-truth cross-check from on-chain
  nonce deltas
- CLI `bench` subcommand with chain-id + balance + nonce preflight
- Anvil-based integration test (`tests/broadcast_anvil.rs`, `#[ignore]`
  by default, opt in via `CITRATE_BENCH_ANVIL_*` env vars)

Not yet implemented (later phases):
- Phase 4: multi-class mix
- Phase 5: finality tracker (depth + checkpoint)
- Phase 6: production run on frozen testnet

## Running

```bash
cd tools/citrate-bench

# All unit + integration tests (no chain required)
cargo test

# Offline config check
cargo run -- validate --config path/to/bench.toml

# Inspect a frozen ceremony address table
cargo run -- show-addresses --table path/to/30_address_table.json

# Verify a ceremony bundle sha256
cargo run -- verify-bundle --bundle 60_proof_bundle.tar.gz --expected sha256:...

# Phase 2: end-to-end dry-run, no network
cargo run --release -- dry-run \
  --keystore-dir ~/.foundry/keystores \
  --accounts bench-01,bench-02,bench-03 \
  --passphrase-file ~/.bench-pw \
  --chain-id 40204 \
  --target-tps 5000 \
  --duration-secs 10

# Phase 3: real broadcast against a running chain
cargo run --release -- bench \
  --rpc-url http://127.0.0.1:8545 \
  --keystore-dir ~/.foundry/keystores \
  --accounts bench-01,bench-02,bench-03 \
  --passphrase-file ~/.bench-pw \
  --expected-chain-id 40204 \
  --target-tps 5000 \
  --duration-secs 30 \
  --concurrency-cap 500 \
  --tracker-workers 16 \
  --funding-floor-wei 1000000000000000000

# Phase 3 integration test against live anvil (opt-in)
CITRATE_BENCH_ANVIL_RPC=http://127.0.0.1:18546 \
CITRATE_BENCH_ANVIL_CHAIN_ID=31337 \
CITRATE_BENCH_ANVIL_FUNDER_PK=0x... \
cargo test --test broadcast_anvil -- --ignored --nocapture
```

The `bench` subcommand preflights chain id, balance floor, and per-signer
starting nonce against the RPC before running. It then submits signed
transactions via `eth_sendRawTransaction`, tracks receipts, and cross-
checks the included count against on-chain nonce deltas as ground truth.
Exits non-zero if `ground_truth_match` is false.

## Preconditions for a real run

Cannot run a benchmark until **all** of the following exist:

1. A frozen `30_address_table.json` from a real testnet ceremony
2. A `60_manifest.json` with a matching bundle sha256
3. Dedicated benchmark signers in a Foundry keystore, funded on the
   target chain above the configured floor
4. A reachable **bootnode RPC** endpoint whose `eth_chainId` matches
   the config — see the note below on why the bootnode specifically.

The harness refuses to run if any precondition fails. Reasons are
printed to stderr and no report is emitted.

## Target the canonical bootnode, not a peer

For testnet-beta (chain 40204), the `--rpc-url` flag must point at
the **canonical bootnode RPC** (`https://rpc.citrate.ai` or
`https://rpc2.citrate.ai`, both backed by the droplet at
`159.65.227.42`). Do **not** point it at an independent peer node.

Reason: per known limitation **L-001** in
[`.agentile/docs/reference/KNOWN_LIMITATIONS.md`](../../../.agentile/docs/reference/KNOWN_LIMITATIONS.md),
peer nodes on testnet-beta sync block headers but do not execute
received blocks into state. A benchmark run against a peer will:

- see pending transactions accepted by `eth_sendRawTransaction`
  (the peer forwards them over gossip);
- see receipts land eventually from the bootnode's perspective;
- but the peer's own `eth_getTransactionCount("latest")` will
  report nonces that do not match ground truth, because the peer
  never executed those blocks.

That breaks `ground_truth_match` and produces a report that is
neither honest about what was measured nor useful as an auditor
artifact. The harness's own preflight does not detect this — it is
a property of the RPC endpoint, not the harness — so the operator
must make the right choice here. This paragraph is the reminder.

Backlog #116 (`SaulBuilds/citrate#44`) tracks the fix. Once the
sync protocol executes received blocks into state, any peer node
becomes a valid `--rpc-url` target. Until then, stick with the
bootnode.

## Why it is a standalone crate

It is **not** in the main citrate workspace. Two reasons:

1. Dependency churn in a benchmark tool should never block core crate
   work. The older `tests/load` crate is standalone for the same reason.
2. The old `tests/load` binaries (`benchmark-suite`, `live-bench`,
   `bench-signed`) stay in place as historical artifacts. Mixing the
   production-correct binary with legacy devnet tooling invites confusion.

## License

MIT OR Apache-2.0.
