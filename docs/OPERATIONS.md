---
created: 2026-06-11T00:00:00Z
branch: main
author: Lane A (Claude Fable 5), directed by Larry Klosowski (@SaulBuilds)
status: active
purpose: Operator runbook for the citrate-node — producer health (PIL-13 WP-13.6)
---

# Citrate Node — Operations

Operator-facing runbook for the production `citrate-node`. First section
covers producer memory health (PIL-13 WP-13.6); extend with further sections
as residual sprints close.

## Producer health (PIL-13)

### Background — what happened and what protects you now

PIL-13 (2026-05-31): the producer's eager DAG-load loop materialised the
cumulative blue ancestry for every persisted block on startup — O(N²) memory.
At 281k blocks the 16 GB RPC droplet hit **15.8 GB RSS and kernel-OOM'd within
~30 s of every restart**, freezing the chain head. The fix (citrate-chain#1,
commit `4c2383c`) loads header-derived scores in O(1) per block; the healthy
producer now sits at **~1.05 GB RSS, stable** (post-fix live measurement).

Three permanent guards:

| Guard | Where | Trips when |
|---|---|---|
| `producer_steady_state` test | `core/sequencer/tests/producer_steady_state.rs` | any change re-materialises cumulative blue ancestry on the eager-load path (CI) |
| `ProducerMemoryHigh` alert | `node/monitoring/alerts/citrate-alerts.yml` | `process_resident_memory_bytes{job="citrate-node"} > 3e9` sustained 2 min |
| RSS gauge sampler | `node/src/main.rs` (15s cadence) | n/a — feeds the alert |

### Thresholds

| RSS | Meaning | Action |
|---|---|---|
| ≤ ~1.2 GB | healthy steady state | none |
| 1.2 – 2 GB | elevated — watch | sample every 15 min; correlate with indexer/beacon load |
| **> 2 GB** | **leak-class behavior** | apply the circuit-breaker below **before** the OOM killer acts |
| > 3 GB | alert fires (`ProducerMemoryHigh`, critical) | circuit-breaker immediately |

### The `mining = false` circuit-breaker

The producer (and its memory-heavy startup path) only runs when mining is
enabled (`node/src/main.rs` gates `BlockProducer` behind
`config.mining.enabled`). With mining off, the node serves RPC reads at ~1 GB
indefinitely — that is the safe degraded mode. **Only writes stop; the public
read surface stays up.**

```sh
# 1. Confirm you are in leak territory (RSS in KiB):
ps -o rss= -p "$(pgrep -f citrate-node | head -1)"

# 2. Trip the breaker — disable mining:
#    /home/citrate/.citrate/node.toml  →  [mining] enabled = false
sed -i 's/^enabled = true/enabled = false/' /home/citrate/.citrate/node.toml   # [mining] section
systemctl restart citrate-node

# 3. Verify degraded-but-healthy: RSS ~1 GB, RPC answering:
ps -o rss= -p "$(pgrep -f citrate-node | head -1)"
curl -s -X POST -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' \
  http://127.0.0.1:8545
```

Re-enable (`enabled = true` + restart) only after the cause is identified —
and watch RSS for the first 5 minutes after restart (the PIL-13 leak fired
*during startup*, within 30 s).

### Post-incident

- Capture `ps`/`smaps` evidence **before** any restart if at all possible —
  see the PIL-49e sprint file for the general hang-state capture discipline.
- File the regression against the `producer_steady_state` test: if RSS leaked
  but the test is green, the leak is on a path the test doesn't cover — extend
  the test, don't just patch the leak (that's how PIL-13 stayed hidden).
- Rollback binary: keep the previous release at
  `/home/citrate/bin/citrate-node.pre-<tag>` (the PIL-13 deploy preserved
  `citrate-node.pre-pil13`; keep that convention).
