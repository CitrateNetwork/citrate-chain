# Monitoring Setup

## Quick Start

### 1. Enable Metrics on the Node

```bash
CITRATE_METRICS_ADDR=127.0.0.1:9090 ./target/release/citrate devnet
```

### 2. Start Prometheus

```bash
# Install
brew install prometheus  # macOS
# or: apt install prometheus  # Ubuntu

# Start with config
prometheus --config.file=monitoring/prometheus.yml
```

Prometheus UI: http://localhost:9091

### 3. Start Grafana

```bash
brew install grafana  # macOS
brew services start grafana
```

1. Open http://localhost:3000 (admin/admin)
2. Add Prometheus data source: http://localhost:9091
3. Import `monitoring/grafana-dashboard.json`

## Key Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `citrate_node_uptime_seconds` | Gauge | Node uptime |
| `citrate_peer_count` | Gauge | Connected peers |
| `citrate_block_height` | Gauge | Current block height |
| `citrate_mempool_size` | Gauge | Transactions in mempool |
| `citrate_dag_tips_count` | Gauge | DAG tip count |
| `citrate_rpc_requests_total` | Counter | RPC requests by method |
| `citrate_rpc_latency_seconds` | Histogram | RPC latency |
| `citrate_ai_requests_total` | Counter | AI inference requests |
| `citrate_ipfs_uploads_total` | Counter | IPFS uploads |

## Alerts (Optional)

Add to Prometheus rules:

```yaml
groups:
  - name: citrate
    rules:
      - alert: NodeDown
        expr: up{job="citrate-node"} == 0
        for: 1m
      - alert: NoBlocks
        expr: increase(citrate_block_height[5m]) == 0
        for: 5m
      - alert: HighMempoolSize
        expr: citrate_mempool_size > 10000
        for: 2m
```
