---
created: 2026-11-09
branch: r1007/s3-mergeset-execution
author: Larry Klosowski + Claude Opus 5.5 (MERGESET lane)
status: recorded (devnet rehearsal; not a testnet or release claim)
---

# Rule 6 run: r1007 mergeset execution, local devnet, 2026-11-09

Why: this branch changes core crates (consensus, execution, storage) for r1007 mergeset
execution (ADR CV-4a, spec 06 §3). Rule 6 asks for the benchmark after such a change. It is run
against the branch base on the same host, so that only the code differs.

## What ran

- **Head:** `e6c54a9b`, the head of `r1007/s3-mergeset-execution`.
- **Base:** `28e13057`, `r1007/genesis-candidate`, the branch point before mergeset execution.
- **Node:** `citrate` release build of each commit. `citrate devnet`, one node, chain id 1337,
  fresh data dir per run.
- **Harness:** `tools/citrate-bench` (`bench`, signed `eth_sendRawTransaction`, ground truth from
  on-chain nonce deltas). Settings: simple transfers, 300 tx/s offered for 60 s, at most 16 in
  flight per signer, 300 s cooldown.
- **Signers:** throwaway keys made at run time, funded from the devnet's prefunded test account.
  The key file was shredded after each run.
- **Machine:** `citrate-cnv-build-2` (16 vCPU, 32 GB, Ubuntu 24.04, rustc 1.96.0). The runs were
  sequential and no build was running during them.

## Result

| Run | Signers | Accepted / offered | Included | Timeouts | Included tx/s | Avg inclusion latency |
|---|---:|---:|---:|---:|---:|---:|
| base | 64 | 18,001 / 18,001 | 18,001 | 0 | 289.60 | 2,025 ms |
| head | 64 | 1,997 / 18,001 | 1,163 | 834 | 17.21 | 3,906 ms |
| base | 256 | 18,001 / 18,001 | 18,001 | 0 | 291.33 | 2,029 ms |
| head | 256 | 18,001 / 18,001 | 18,001 | 0 | 277.34 | 3,930 ms |

Ground truth matched in every run.

## Reading

- **Throughput with load spread across senders** (256 signers, about 1.2 tx/s each): the head
  includes everything offered at −4.8% vs base. That is inside the 10% regression bound. The
  offered rate, not the node, is the limit.
- **Latency** is one block longer (about +1.9 s). This is by design (spec 06 D6): a block's own
  transactions are executed by the chain block that accepts it, one slot later.
- **High rate per sender** (64 signers, about 4.7 tx/s each): the head refuses 89% of
  submissions with "nonce N is more than 16 ahead of the sender's committed nonce" (PBA-L1a-001).
  - Cause: the mempool measures the 16-nonce window from the committed (accepted) nonce, which
    now lags inclusion by a block, so the window fills sooner.
  - The 834 timeouts follow from that: a refused nonce leaves a gap, and the sender's later,
    accepted nonces can never execute.
  - **This is a regression for any client that pipelines more than about 16 transactions per two
    slots from one sender. It is outside the 10% bound for that workload.**
  - It comes from mergeset execution itself (0bb5a0a2), not from the T1/T2, disqualification or
    undo changes of this session.
  - Fix options for the lead and the reviewer: measure the window from the sender's
    included-but-not-accepted nonce, or widen it for r1007.
