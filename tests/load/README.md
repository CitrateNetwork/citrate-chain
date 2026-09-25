# tests/load — Historical Devnet Load Tools

> **⚠ DEPRECATED FOR TESTNET OR RELEASE CLAIMS.**
>
> The binaries in this crate — `benchmark-suite`, `live-bench`,
> `load-test` — are **devnet rehearsal tools only**. They use
> `eth_sendTransaction` with a fake unlocked sender address
> (`--from 0x3333...3333` or similar) which only works on permissive
> local devnet nodes. **They are not suitable for testnet or release
> benchmark claims** and must not be used to produce evidence for
> auditors, release notes, blog posts, or anything that leaves the
> repository.
>
> The canonical benchmark harness is
> [`tools/citrate-bench/`](../../tools/citrate-bench/).
> It signs transactions client-side via `eth_sendRawTransaction`,
> computes ground truth from on-chain nonce deltas, and produces
> auditable reports.
>
> **Use `citrate-bench` for anything you would put in front of
> another human.** This crate is kept only as a historical
> artifact and for internal devnet smoke testing that does not
> require signed transactions.

## Why this doc exists

Spec [`.agentile/quorum/16_POST_CEREMONY_BENCHMARK_HARNESS_SPEC.md`](../../../.agentile/quorum/16_POST_CEREMONY_BENCHMARK_HARNESS_SPEC.md)
explicitly called for:

> `bench_signed.rs` stays on the `benchmark-rehearsal` branch as a
> historical WIP artifact and is not deleted. It is the demonstration
> that client-side signing works against Citrate.
>
> The old `benchmark_suite.rs` stays as a devnet rehearsal tool only.
> Its README must be updated to say "devnet rehearsal only, not
> suitable for testnet claims". That is a documentation edit, not a
> code edit.

This rewrite closes that documentation lint.

## Contents — historical notes only

### `benchmark-suite` (`src/bin/benchmark_suite.rs`)

Original devnet load generator. Uses `eth_sendTransaction` with a
hardcoded fake sender, relying on the node having an unlocked
account entry. Works against `anvil` (permissive) and old devnet
configurations. Does not work against any citrate-node that rejects
`eth_sendTransaction`.

**Last known honest use**: smoke-testing that an `anvil` devnet
responds to RPC submissions at a target rate. **Not honest** for
measuring Citrate testnet throughput — the submission path does not
exercise the real client signing flow.

### `live-bench` (`src/bin/live_bench.rs`)

Variant with a live progress display. Shares the same
`eth_sendTransaction`-with-fake-sender assumption, so the same
restrictions apply.

### `bench-signed` (`src/bin/bench_signed.rs`)

The production-direction proof-of-concept. Signs EIP-155 legacy
transactions client-side with `k256` + `sha3` + `rlp`, submits via
`eth_sendRawTransaction`, and measures ground truth via nonce delta.
This is the demonstration that client-side signing works against
Citrate. Its logic has since been productionized (and extended) in
`tools/citrate-bench`, which is where all new benchmark work lives.

`bench-signed` is still here because deleting it would lose a clean
reference point for anyone looking at how the early signed-tx proof
was constructed. **Not to be used for new benchmark runs.**

### `load-test` + `load_test.sh`

Bash wrapper around `curl` that sends `eth_sendTransaction` requests
at a configurable rate. Documented in the original README (now
replaced by this notice) as "the load test". Same devnet-only
constraint. Kept for shell-script-style smoke testing against local
anvil only.

## Canonical harness

**[`tools/citrate-bench/`](../../tools/citrate-bench/)**

Production-correct Rust harness. Signs transactions client-side
with a Foundry keystore, runs at a target TPS via deadline-based
rate limiting, tracks receipts in a worker pool, and cross-checks
ground truth against on-chain nonce deltas. All new benchmark work
against the Citrate testnet happens there.

```bash
cd tools/citrate-bench
cargo run --release -- bench \
  --rpc-url https://rpc2.citrate.ai \
  --keystore-dir ~/.foundry/keystores \
  --accounts bench-01,bench-02,bench-03 \
  --passphrase-file ~/.bench-pw \
  --expected-chain-id 40204 \
  --target-tps 5000 \
  --duration-secs 30
```

See [`tools/citrate-bench/README.md`](../../tools/citrate-bench/README.md)
for the full command reference, phase status, and acceptance
criteria.

## If you need the old tool anyway

Only for devnet smoke testing — never for testnet or release claims.

```bash
cd tests/load
cargo build --release
./target/release/benchmark-suite http://127.0.0.1:8545 10000 60 /tmp/
```

Any output this produces is local, unverified, and not to be quoted
outside the repository.
