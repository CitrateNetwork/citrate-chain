---
created: 2026-10-04
branch: hup/n7-chain-precompile-followups
author: Larry Klosowski + Claude Opus 5.5
status: recorded (devnet rehearsal; not a testnet or release claim)
---

# Rule 6 run: agent precompile stack, local devnet, 2026-10-04

Why: the HUP chain stack (PRs 270 to 274) changes `citrate-execution`, a core crate (the agent
precompile fork in PR 273). Rule 6 asks for the daily benchmark after such a change. This is that
run, on the stack head, before the stack merges to `main`.

## What ran

- Node: `citrate` release build of the stack head (`fa7c913d`, the same node code as this branch;
  this branch adds only tests, a script, docs and the bench fix), `citrate devnet`, one node,
  chain id 1337, 2 s blocks, the agent precompile fork height unset (as shipped).
- Harness: `tools/citrate-bench` (`bench`), the canonical signed-transaction harness. The old
  `tests/load` `benchmark-suite` uses `eth_sendTransaction` from an unlocked fake sender, which a
  Citrate node refuses, and its README marks it devnet-only and deprecated. `citrate-bench` did not
  build on `main` (see the `fix(citrate-bench)` commit on this branch).
- Signers: 64 throwaway keys made at run time and funded on the devnet from the prefunded test
  account; the key file was deleted after the run.
- Load: simple transfers, target 300 tx/s for 60 s, at most 16 in flight per signer (the node
  refuses a nonce more than 16 ahead of the committed one).
- Machine: Apple M2 Max, 32 GiB, rustc 1.96.0, with other builds running at the same time.

## Result

| Measure | Value |
|---|---:|
| attempted / signed | 17,999 / 17,999 |
| accepted by RPC | 17,999 |
| included | 17,999 |
| reverted / timed out | 0 / 0 |
| included tx/s | 291.78 |
| average inclusion latency | 1,841 ms |
| ground truth (on-chain nonce deltas) | matches (17,999) |

Reading: every transaction offered at 300 tx/s was included within about one block, so the
offered rate, not the node, was the limit; this is a floor, not a ceiling. A first attempt with 8
signers and no in-flight cap had 29,865 of 30,001 submissions refused by the 16-ahead nonce rule
(136 included), which is the mempool policy working, not a regression; the run above stays inside
it.

## Raw output (signer and sample lines trimmed)

```text
starting bench
  rpc_url               = http://127.0.0.1:18792
  target_tps            = 300
  duration_secs         = 60
  concurrency_cap       = 500
  tracker_workers       = 16
  receipt_timeout_secs  = 60

mode               = Broadcast { rpc_url: "http://127.0.0.1:18792", concurrency_cap: 500, cooldown_secs: 300 }
duration           = 61.686s
attempted          = 17999
signed_ok          = 17999
pool_saturated     = 0
signing_errors     = 0
effective_tps      = 291.78
-- broadcast --
  rpc_accepted             = 17999
  rpc_rejected             = 0
  included                 = 17999
  reverted                 = 0
  inclusion_timeouts       = 0
  tracker_transport_errors = 0
  avg_inclusion_latency_ms = 1841.51
  mined_nonce_delta_total  = 17999
  ground_truth_match       = true
  included_tps             = 291.78
```

## Reproduce

```bash
cargo build --release -p citrate-node --bin citrate
(cd tools/citrate-bench && cargo build --release)
target/release/citrate --data-dir <tmp> --rpc-addr 127.0.0.1:18792 --p2p-addr 127.0.0.1:30792 \
  --coinbase <any devnet address> devnet &
# fund N throwaway keys from the devnet's prefunded test account, one key per line in a 0600 file
tools/citrate-bench/target/release/citrate-bench bench --rpc-url http://127.0.0.1:18792 \
  --private-keys-file <file> --expected-chain-id 1337 --target-tps 300 --duration-secs 60 \
  --cooldown-secs 300 --per-signer-max-inflight 16
```
