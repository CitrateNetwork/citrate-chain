---
created: 2026-11-09
branch: r1007/s3-state-root
author: Larry Klosowski + Claude Opus 5.5 (lane CHAIN-STATEROOT)
status: recorded (devnet and microbenchmarks; not a testnet or release claim)
---

# Rule 6 run and H7 re-measurement: the CV-14 MPT state root, 2026-11-09

Why: CV-14 changes `citrate-execution` and `citrate-storage` (core crates), and H7
(fed `ops/r1007-apply-cost` @ 13830e51) named the per-block legacy state root as 45-48% of
the boot reorg-window rebuild. This records the before/after.

## Host

`cnv-stateroot-bench`, a temporary DO s-4vcpu-8gb in sgp1: DO-Regular x86, AVX2, no SHA-NI,
the class of prod-1 and of `cnv-apply-1` (13830e51). Ubuntu 24.04, rustc 1.96.0, release
builds, nothing else running. Deleted after the run.

## 1. The S1-2 workload's hot path (rebuild per height)

The 13830e51 workload itself (100 real r1006 heights from a copy of prod-1's DB) was not
re-run: it needs a copy of a production data dir, and under the MPT rule the committed
r1006 roots no longer match, so the node's `restore_reorg_window` stops at the tip check.
Instead `reorg_window_rebuild_cost_per_height_legacy_vs_mpt`
(`core/execution/tests/state_root_cost.rs`) times the same per-height work
(`with_pre_images`, then `rooted`, copied from `canonical_apply.rs`) over 100 heights at
r1006's live size (132 accounts, 12 contracts, 737 slots), each height changing 40
balances and 20 slots. Every rebuilt root is checked. 3 runs, ms per height:

| state | legacy | MPT | ratio |
|---|---|---|---|
| r1006 size | 14.5 / 11.4 / 11.3 | 5.0 / 4.2 / 5.0 | 2.9x / 2.7x / 2.3x |
| 10x | 66.0 / 72.9 / 65.2 | 19.8 / 21.3 / 19.0 | 3.3x / 3.4x / 3.4x |

The synthetic legacy figure (11-15 ms) is below the 82-92 ms measured on real data; the
synthetic state is smaller in bytes. The ratio, not the absolute value, is the result.

## 2. The state root alone (per block)

`state_root_cost_per_block_does_not_grow_with_state`, 15 blocks per size, ms per block
(3 runs, median shown):

| state | legacy | MPT incremental | MPT from scratch | persist | node bytes/block |
|---|---|---|---|---|---|
| r1006 size | 8.9 | 0.41 | 2.8 | 0.18 | 26,643 |
| 10x | 52.4 | 0.96 | 40.9 | 0.43 | 49,405 |
| 100x | 543.0 | 1.45 | 398.2 | 0.89 | 82,848 |

Speedup 15-23x at r1006 size, 369-419x at 100x. The incremental root grows 3.5x while the
state grows 100x (gate: at most 4x).

## Reading

- The state root is no longer the cost (H7's 45-48% share goes to ~4.5% of the MPT rebuild
  arm under perf).
- The rebuild is now bound by something else. perf on the MPT arm: ~40% in `Arc::make_mut`
  copying a touched contract's whole storage `Trie` (the legacy `TrieNode` tree plus the
  slot `HashMap`) while a snapshot shares it, and ~27% dropping those copies. That copy is
  O(slots of the contract) per touched contract per block, and it is on the apply path too.
  It is outside the state root: a follow-up.
- Projected on the 13830e51 numbers (labeled, not measured): removing ~46.6% from 82 ms gives
  ~44 ms/height before the copy-on-write residual is addressed.

## 3. Rule 6: local devnet, signed load

One node per arm, `citrate devnet` (chain 1337, 2 s blocks), loopback only.
`tools/citrate-bench`, 64 throwaway keys funded from the devnet's published hardhat test
account (deleted after each run), 300 tx/s for 60 s, 16 in flight per signer.

| arm | binary | included / attempted | included tx/s | avg inclusion | persist p50 / p90 |
|---|---|---|---|---|---|
| before | 28e13057 (genesis candidate) | 18,001 / 18,001 | 292.4 | 2,056 ms | 3.7 / 8.2 ms |
| after, legacy rule | this branch, `CITRATE_MPT_STATE_ROOT_HEIGHT=off` | 18,001 / 18,001 | 286.9 | 1,994 ms | 4.0 / 6.8 ms |
| after, MPT rule | this branch, `CITRATE_MPT_STATE_ROOT_HEIGHT=0` | 18,001 / 18,001 | 291.9 | 1,996 ms | 2.9 / 6.2 ms |

Ground truth (on-chain nonce deltas) matched in every arm, with no rejections and no
timeouts. As on 2026-10-04 the offered rate is the limit, so this is a regression floor,
not a ceiling. The devnet state is small, so the root is not visible at this size.

## Reproduce

```bash
cargo test --release -p citrate-execution --test state_root_cost -- --ignored --nocapture --test-threads=1
cargo build --release -p citrate-node --bin citrate
(cd tools/citrate-bench && cargo build --release)
CITRATE_MPT_STATE_ROOT_HEIGHT=0 target/release/citrate --data-dir <tmp> --rpc-addr 127.0.0.1:18792 \
  --p2p-addr 127.0.0.1:30792 --coinbase <any devnet address> devnet &
# fund N throwaway keys from the devnet's prefunded test account, one key per line in a 0600 file
tools/citrate-bench/target/release/citrate-bench bench --rpc-url http://127.0.0.1:18792 \
  --private-keys-file <file> --expected-chain-id 1337 --target-tps 300 --duration-secs 60 \
  --cooldown-secs 300 --per-signer-max-inflight 16
```
