# Citrate Load Test

Sends `eth_sendTransaction` requests at a configurable rate against a running Citrate devnet node, then reports throughput and reliability metrics.

## Prerequisites

- A running Citrate devnet node (the test sends unsigned transactions, which devnet accepts)
- `curl`, `bash` (4+), `awk`, `xxd` (from `vim-common` or similar)

## Quick Start

```bash
# 1. Start a fresh devnet node
cd citrate_v0.01.1
rm -rf .citrate-devnet
./target/release/citrate devnet &

# 2. Wait for the node to initialize
sleep 5

# 3. Run the load test (defaults: 10 TPS for 60 seconds)
bash tests/load/load_test.sh

# 4. Stop the node
pkill -f citrate
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--rpc-url` | `http://127.0.0.1:8545` | JSON-RPC endpoint of the target node |
| `--tps` | `10` | Target transactions per second |
| `--duration` | `60` | Test duration in seconds |
| `--from` | `0x3333...3333` | Sender address (must be funded on devnet) |
| `--value` | `0x1` | Value transferred per transaction (in wei, hex) |
| `--gas` | `0x5208` | Gas limit per transaction (21000 = simple transfer) |
| `--quiet` | off | Suppress per-transaction output |

## Examples

```bash
# Low load — 5 TPS for 20 seconds
bash tests/load/load_test.sh --tps 5 --duration 20

# Stress test — 100 TPS for 120 seconds, quiet mode
bash tests/load/load_test.sh --tps 100 --duration 120 --quiet

# Against a remote node
bash tests/load/load_test.sh --rpc-url http://10.0.0.5:8545 --tps 50 --duration 60
```

## Understanding Results

The summary printed at the end contains these fields:

| Metric | Meaning |
|--------|---------|
| **Duration (wall clock)** | Actual elapsed time of the test |
| **Transactions sent** | Total number of `eth_sendTransaction` calls made |
| **Successful** | Transactions that returned a valid `result` (tx hash) |
| **Failed** | Transactions that returned an `error` or were unreachable |
| **Success rate** | `successful / sent * 100` |
| **Target TPS** | The rate you requested via `--tps` |
| **Actual TPS** | `sent / wall_clock_seconds` — the throughput the script achieved |
| **Avg response time** | Mean round-trip time per RPC call (curl latency) |
| **Block height (start/end)** | Block numbers before and after the test |
| **Blocks produced** | `end - start` — how many blocks the node mined during the test |
| **Avg tx/block** | `sent / blocks_produced` — transaction density |

### Interpreting the Numbers

- **Actual TPS < Target TPS**: The node (or network latency) is the bottleneck. Each transaction is sent sequentially, so high per-request latency caps throughput.
- **Success rate < 100%**: The node rejected some transactions. Common reasons: nonce conflicts, insufficient balance, gas too low, or the node is overloaded.
- **Blocks produced = 0**: The node may not be producing blocks (check logs). On devnet, blocks are typically produced every 1-2 seconds.
- **Avg tx/block is very high**: Good batching, or blocks are infrequent.
- **Avg tx/block is very low**: Blocks are produced faster than transactions arrive, or many transactions failed before inclusion.

### Limitations

- The script sends transactions **sequentially** (one at a time). For TPS targets above ~50, actual throughput will be limited by per-request latency. To exceed this, run multiple instances in parallel.
- Random destination addresses are generated for each transaction. These are not real accounts — the test measures submission throughput, not execution correctness.
- The `--from` account must exist and be funded on the target network for transactions to succeed.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All transactions succeeded |
| `1` | At least one transaction failed, or the node was unreachable |
