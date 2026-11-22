---
created: 2026-11-22T19:45:00Z
branch: fix/fd-limit-bounded-rocksdb
author: Larry Klosowski
status: recorded (synthetic storage bench and a local devnet; not a testnet or release claim)
---

# Rule 6 run: bounded RocksDB table cache and the start-up fd-limit raise, 2026-11-22

Why: this branch changes `citrate-storage`, a core crate, and the node's start-up.

- `RocksDB` now sets `max_open_files` from the process's open-file limit. Before, it used the default of -1, which keeps every table file open.
- `main` raises the soft `RLIMIT_NOFILE` before anything else runs.

Bounding the table cache can cost reads, because a table reader that was evicted has to be reopened. Rule 6 asks for the benchmark after such a change.

## Host and binaries

- **Machine:** `citrate-cnv-build-2` (16 vCPU, 32 GB, Ubuntu 24.04, rustc 1.96.0). Runs were sequential, with nothing else running.
- **Head:** `16ec6ee1` node code, release build `--locked`, sha256 `4c4b0524e9a4900624c9…`.
- **Base:** `884555be` (origin/main, the branch point), release build `--locked`, sha256 `8aad54bc6affacee0b30…`.

## 1. Storage: random point reads over a many-SST database

This was a one-off measurement with a throwaway test that is not committed. Setup:

- 100,000 keys of 1 KiB, scattered, compacted into 100 SST files of 1 MiB.
- Opened with the node's table options: a shared 64 MiB LRU block cache, index and filter blocks in the cache, and L0 pinned.
- The block cache holds less than the data, so reads reach the table readers.
- Each run is 200,000 uniformly random `get`s with every value checked, release build, data on tmpfs.

Reads per second, 3 rounds:

| `max_open_files` | When the node uses it | round 0 | round 1 | round 2 |
|---|---|---:|---:|---:|
| -1 (base: keep every file open) | base, always | 204,824 | 220,139 | 219,446 |
| 8192 | head, soft limit >= 21,846 (Linux fleet: 65536) | 213,942 | 210,012 | 211,745 |
| 3840 | head, soft limit 10,240 (macOS `OPEN_MAX` fallback) | 216,692 | 207,363 | 213,322 |
| 64 | head, soft limit 256 and the raise refused | 70,448 | 68,791 | 68,698 |

Open time was 4.5 to 5.3 ms in every arm.

Reading:

- **With the raise in effect, reads do not regress.** The 3840 and 8192 arms are within run-to-run spread of -1 (-3% to +5%). A table cache larger than the file count never evicts.
- **The 64 floor costs about 3x on random reads that span more files than it holds.** It is used only when the soft limit stays at 256 because the OS refused every raise. Base cannot open such a database at all in that case: it fails with EMFILE, which is the crash loop this branch fixes.
- On macOS a GUI-launched process has an unlimited hard limit, so the raise reaches `kern.maxfilesperproc`, or `OPEN_MAX` after a refusal. That gives at least 3840 per database.

## 2. Rule 6: local devnet, signed load

Setup:

- **Node:** one `citrate devnet` node per run (chain 1337), loopback only, fresh data directory per run.
- **Harness:** `tools/citrate-bench` `bench` with simple transfers. It offered 300 tx/s for 60 s, with at most 16 in flight per signer and a 300 s cooldown.
- **Signers:** throwaway keys funded from the devnet's prefunded test account. The key file was shredded after each run.
- **Fd limit:** soft and hard 65536 unless the run says otherwise.
- **"hard 256" runs:** `ulimit -Sn 256; ulimit -Hn 256` before the node starts, so the raise cannot lift the limit. The head node logged `soft 256 -> 256` and `max open files 64` for both of its databases.

| Run | Signers | Attempted / included | Rejected | Timeouts | Included tx/s | Avg inclusion latency |
|---|---:|---:|---:|---:|---:|---:|
| base | 64 | 18,001 / 18,001 | 0 | 0 | 282.87 | 3,861 ms |
| head | 64 | 18,001 / 18,001 | 0 | 0 | 275.84 | 3,856 ms |
| base | 256 | 18,001 / 18,001 | 0 | 0 | 284.50 | 3,813 ms |
| head | 256 | 18,001 / 18,001 | 0 | 0 | 278.42 | 3,829 ms |
| base, hard 256 | 64 | 18,001 / 18,001 | 0 | 0 | 282.84 | 3,854 ms |
| head, hard 256 | 64 | 18,001 / 18,001 | 0 | 0 | 275.84 | 3,846 ms |

Ground truth (on-chain nonce deltas) matched in every run.

Reading:

- Compared with base, head is -2.5% at 64 signers, -2.1% at 256 signers and -2.5% held to 256 fds. All three are inside the 10% regression bound.
- Latency is unchanged, within 16 ms.
- The offered rate is the limit, not the node, so this is a regression floor, not a ceiling.
- A devnet database holds a handful of SSTs, so the table cache never evicts here. The gap is in the range earlier Rule 6 runs on this host saw between identical arms (-1.2% to +2.6%, `2026-11-18-ancestor-sync-devnet.md`).
- The node runs normally under a hard limit of 256 with the table cache bounded to 64.

## Correctness evidence (tests, same host)

- `cargo test --workspace --profile harness --locked`: 6286 passed, 0 failed.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: clean.
- `many_ssts_open_read_write_and_reopen_under_a_256_fd_limit` with base's `max_open_files = -1`: `IO error: While open a file for random read: …/002994.sst: Too many open files` on a 610-SST database. That is the production error. With the fix it passes.
