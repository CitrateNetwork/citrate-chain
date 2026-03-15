# Chaos Testing Framework

Chaos tests for the Citrate node. These scripts exercise failure modes and stress scenarios against a local devnet to verify resilience, recovery, and stability.

## Prerequisites

- **Node binary**: `target/release/citrate` must exist. Build with:
  ```bash
  cargo build --release -p citrate-node
  ```
- **curl**: Required for RPC calls (pre-installed on macOS/Linux)
- **python3**: Required for JSON parsing in response validation
- **Ports**: Tests use ports 8545 (single-node scenarios) and 18545-18546 + 30403-30404 (multi-node scenario). Ensure these are free before running.

## Running

### All scenarios

```bash
cd citrate_v0.01.1
./tests/chaos/run_all.sh
```

### With auto-build

```bash
./tests/chaos/run_all.sh          # builds first, then runs all
./tests/chaos/run_all.sh --skip-build  # skip build step
```

### Single scenario

```bash
./tests/chaos/run_all.sh --scenario 3   # run only mempool flood
# or directly:
./tests/chaos/test_mempool_flood.sh
```

## Scenarios

| # | Script | What it tests | Duration |
|---|--------|---------------|----------|
| 1 | `test_restart_recovery.sh` | SIGKILL node, restart with same data dir, verify block height and balances preserved | ~45s |
| 2 | `test_network_partition.sh` | 2-node cluster, partition one node, verify independent production, heal and check reconvergence | ~90s |
| 3 | `test_mempool_flood.sh` | Send 1000 transactions rapidly, verify node stays responsive and mempool does not OOM | ~60s |
| 4 | `test_concurrent_rpc.sh` | Fire 100 parallel RPC calls (mixed methods), verify all return valid JSON-RPC, no deadlocks | ~30s |
| 5 | `test_large_block.sh` | Submit transactions with 1KB-20KB data payloads, verify blocks produced and gas accounting works | ~45s |

## Output

Each script prints `[PASS]` or `[FAIL]` for individual checks and a final `PASSED` or `FAILED` summary. Exit code is 0 on success, 1 on failure.

`run_all.sh` prints a summary table at the end.

## Data directories

Each scenario uses an isolated data directory under `citrate_v0.01.1/.citrate-chaos-*`. These are cleaned up automatically on exit (via `trap`). If a test is interrupted with Ctrl+C, cleanup still runs.

## Notes

- **Scenario 2 (Network Partition)**: Simulates partition by restarting a node without bootstrap peers rather than using iptables/pfctl, so it works without sudo. This is a functional approximation — for true network-level partition testing, modify the script to use `pfctl` (macOS) or `iptables` (Linux) with appropriate privileges.
- **Scenario 3 (Mempool Flood)**: Uses `eth_sendTransaction` which may be rejected if the node does not support unlocked accounts. The test validates RPC resilience regardless of whether transactions are accepted or rejected.
- **Timeouts**: Each scenario has a 5-minute timeout when run via `run_all.sh`. Individual scripts have internal timeouts for RPC calls (5-15 seconds).
