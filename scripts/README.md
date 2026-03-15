# Scripts

Shell scripts for deployment, testing, orchestration, and development workflows.

## Contents

### Devnet / Testnet
- `start_devnet.sh` -- Start a local single-node devnet
- `start_testnet.sh` -- Start a testnet node
- `launch_testnet.sh`, `launch_simple_testnet.sh`, `launch_10node_testnet.sh` -- Multi-node testnet variants
- `stop_nodes.sh`, `stop-dev.sh` -- Stop running nodes

### Deployment
- `deploy.sh`, `deploy-all.sh`, `fresh_deploy.sh` -- Production deployment scripts
- `deploy_monitoring.sh` -- Deploy Prometheus + Grafana monitoring stack
- `deploy_bootstrap.sh` -- Bootstrap node deployment

### Testing
- `load_test.sh` -- RPC load testing
- `test_multinode_soak.sh` -- Multi-node soak test
- `test_restart_continuity.sh` -- Restart and state continuity validation
- `test_llm_inference.sh`, `test_embedding_inference.sh` -- AI inference tests
- `security_audit.sh` -- Automated security audit checks

### Utilities
- `wallet_helper.sh` -- Wallet creation and funding helpers
- `quick_genesis.sh` -- Generate genesis configuration
- `reset-dev.sh`, `clean_all.sh` -- Reset development environment
- `download-models.sh` -- Download AI models for local inference
- `scaffold-local-peers.sh` -- Set up multi-peer local network

## Build / Usage

```bash
./scripts/start_devnet.sh               # Start local devnet
./scripts/launch_simple_testnet.sh      # Launch 3-node testnet
./scripts/load_test.sh                  # Run load test against localhost:8545
```
