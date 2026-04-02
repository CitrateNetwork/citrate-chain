# Scripts

Operational shell scripts for deployment, testing, and orchestration. We recommend starting with `launch_local_testnet.sh` for local development and `run_all_tests.sh` to validate changes before committing.

## Start Here

| Script | Description |
|--------|-------------|
| `bootstrap.sh` | Canonical one-step bootstrap for developers and agent operators |
| `installers/first_launch.sh` | Prepare local data directories, config profiles, and optional IPFS repo |

## Testnet / Devnet

| Script | Description |
|--------|-------------|
| `team-testnet.sh` | Start the team testnet configuration |
| `launch_local_testnet.sh` | Launch a local multi-node testnet |
| `stop_local_testnet.sh` | Stop running local testnet nodes |
| `launch_seed_node.sh` | Start a seed/bootstrap node |

## Deployment

| Script | Description |
|--------|-------------|
| `deploy_bootstrap.sh` | Deploy a bootstrap node |
| `health_check_bootstrap.sh` | Health check for bootstrap nodes |
| `deploy_testnet.sh` | Deploy to testnet infrastructure |
| `deploy_monitoring.sh` | Deploy Prometheus + Grafana monitoring stack |
| `build-release.sh` | Build release binaries |

## Testing

| Script | Description |
|--------|-------------|
| `run_all_tests.sh` | Run all test suites |
| `e2e_stress_test.sh` | End-to-end stress test |
| `load_test.sh` | RPC load testing |
| `test_genesis.sh` | Genesis configuration validation |
| `test_multinode_soak.sh` | Multi-node soak test |
| `test_restart_continuity.sh` | Restart and state continuity validation |
| `test_llm_inference.sh` | LLM inference smoke test |
| `test_embedding_inference.sh` | Embedding inference smoke test |

## Utilities

| Script | Description |
|--------|-------------|
| `download-models.sh` | Download AI models for local inference |
| `wallet_helper.sh` | Wallet creation and funding helpers |
| `seed_models.sh` | Seed model registry with test models |

## Subdirectories

### `installers/`

| Script | Description |
|--------|-------------|
| `build_linux.sh` | Build Linux installer |
| `bundle_model.sh` | Bundle model weights into installer |
| `first_launch.sh` | First-launch setup script |

Platform-specific installer configs in `installers/linux/`, `installers/macos/`, `installers/windows/`.

### `packaging/`

| Script | Description |
|--------|-------------|
| `linux/create-deb.sh` | Create .deb package |
| `macos/create-dmg.sh` | Create .dmg package |

## Common Workflows

```bash
# Bootstrap a full developer environment from a fresh machine
curl -fsSL https://raw.githubusercontent.com/SaulBuilds/citrate/main/citrate_v0.01.1/scripts/bootstrap.sh | bash -s -- --profile developer

# Bootstrap an agent workstation (best-effort Ollama install included)
curl -fsSL https://raw.githubusercontent.com/SaulBuilds/citrate/main/citrate_v0.01.1/scripts/bootstrap.sh | bash -s -- --profile agent

# Bring up a local testnet, run tests, tear it down
./scripts/launch_local_testnet.sh
./scripts/run_all_tests.sh
./scripts/stop_local_testnet.sh

# Stress test a running node (defaults to localhost:8545)
./scripts/load_test.sh

# Health check a bootstrap node (if deploy fails, check this first)
./scripts/health_check_bootstrap.sh
```
