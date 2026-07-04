# tests/chaos/

Chaos tests for the Citrate node. These shell scripts exercise failure modes and
stress scenarios against a local devnet to verify resilience and recovery.

## Prerequisites

- Node binary at `target/release/citrate` (build with `cargo build --release -p citrate-node`)
- `curl` and `python3` for RPC calls and JSON validation
- Ports 8545/8546 (single-node RPC/WS) and, for multi-node tests, node 2's
  8555/8556 (RPC/WS) + 30303-30304 (P2P) must be free

## Scenarios

| # | Script | What It Tests |
|---|--------|---------------|
| 1 | `01_restart_recovery.sh` | SIGKILL node, restart with same data dir, verify block height and balances survived |
| 2 | `02_network_partition.sh` | 2-node cluster, simulate partition by killing peer connection, verify independent production and reconvergence |
| 3 | `03_mempool_flood.sh` | Blast 10,000 RPC calls in parallel, verify node stays responsive and mempool stays bounded |
| 4 | `04_concurrent_rpc.sh` | Fire 100 parallel curl requests with mixed RPC methods, verify all return valid JSON-RPC |
| 5 | `05_rapid_restart.sh` | Start and stop the node 10 times rapidly, verify no port conflicts, corrupt state, or zombie processes |

## Running

```bash
# All scenarios
./tests/chaos/run_all.sh

# Single scenario
./tests/chaos/01_restart_recovery.sh
```

## Output

Each script prints `[PASS]` or `[FAIL]` per check. `run_all.sh` prints a summary
table with per-scenario results and durations. Exit code 0 on success, 1 on failure.

## Data Directories

Each scenario uses an isolated temp directory (`/tmp/citrate-chaos-*.XXXXXX`)
cleaned up automatically on exit via `trap`, even on Ctrl+C.
