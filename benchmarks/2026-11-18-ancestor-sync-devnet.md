---
created: 2026-11-18T12:35:00Z
branch: fix/ancestor-sync-reconverge
author: Larry Klosowski
status: recorded (devnet rehearsal; not a testnet or release claim)
---

# Rule 6 run: ancestor sync, local devnet, 2026-11-18

Why: this branch changes core crates (`core/network`: protocol 1.3, peer gating,
inbound routing) and the node's sync path (ADR-2026-11-17). Rule 6 asks for the
benchmark after such a change. It is run against the branch base on the same
host, so that only the code differs.

## What ran

- **Head:** `fix/ancestor-sync-reconverge` (the PR head's node code), release
  build, sha256 `f616c09564069c7e…`.
- **Base:** `f4a0e600` (origin/main, the branch point), release build, sha256
  `5a3809906e6c86c1…`.
- **Node:** `citrate devnet`, one node, chain id 1337, loopback only, fresh data
  dir per run.
- **Harness:** `tools/citrate-bench` (`bench`, signed `eth_sendRawTransaction`,
  ground truth from on-chain nonce deltas). Simple transfers, 300 tx/s offered
  for 60 s, at most 16 in flight per signer, 300 s cooldown.
- **Signers:** throwaway keys made at run time, funded from the devnet's
  prefunded test account (each gets 1/(2n) of its balance); the key file was
  shredded after each run.
- **Machine:** `citrate-cnv-build-2` (16 vCPU, 32 GB, Ubuntu 24.04, rustc
  1.96.0). Runs were sequential; one single-threaded harness test ran beside
  them for every run (load average about 1).

## Result

| Run | Signers | Accepted / offered | Included | Timeouts | Included tx/s | Avg inclusion latency |
|---|---:|---:|---:|---:|---:|---:|
| base | 64 | 18,001 / 18,001 | 18,001 | 0 | 282.28 | 3,842 ms |
| head | 64 | 18,001 / 18,001 | 18,001 | 0 | 278.93 | 3,842 ms |
| base | 256 | 18,001 / 18,001 | 18,001 | 0 | 284.18 | 3,867 ms |
| head | 256 | 18,001 / 18,001 | 18,001 | 0 | 282.28 | 3,868 ms |

Ground truth matched in every run.

## Reading

- 64 signers: −1.2% vs base. 256 signers: −0.7% vs base. Both are inside the
  10% regression bound, and the offered rate, not the node, is the limit.
- Latency is unchanged.
- Expected: on a single node nothing defers and no peer exists, so the
  ancestor-sync driver never starts an episode; the hot path gains one
  version check in `Peer::send` and the per-tick driver call.

## Re-run after review round 1 and the serving-cost fix (2026-11-18, later)

The head now includes the storage change (`hashes_in_height_range` reads the
sibling height index for bounded ranges) and the review-round-1 driver changes.
Same host, harness and settings; both binaries rebuilt (`--locked`), runs
sequential on an otherwise idle host.

- **Head:** `a3965fb5` node code, sha256 `10c691d208e8b1c2…`.
- **Base:** `f4a0e600`, sha256 `6d520ba0a4bc9abe…`.

| Run | Signers | Attempted / included | Timeouts | Included tx/s | Avg inclusion latency |
|---|---:|---:|---:|---:|---:|
| base | 64 | 18,001 / 18,001 | 0 | 278.03 | 3,846 ms |
| head | 64 | 18,000 / 18,000 | 0 | 276.88 | 3,926 ms |
| base | 256 | 18,001 / 18,001 | 0 | 278.07 | 3,543 ms |
| head | 256 | 18,001 / 18,001 | 0 | 285.36 | 3,878 ms |

Ground truth matched in every run; nothing was rejected (the head-64 run's
rate limiter attempted one transaction fewer inside its 60 s deadline).
64 signers: −0.4% vs base. 256 signers: +2.6%. Inside the 10% bound; the
latency differences are within one slot and within run-to-run spread.
