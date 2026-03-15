# Tests

Workspace-level integration tests, end-to-end tests, and chaos tests for the Citrate blockchain.

## Contents

- `simple_integration.rs` -- Basic node startup and RPC integration tests
- `comprehensive_integration_tests.rs` -- Full-coverage integration tests across subsystems
- `consensus_storage_integration.rs` -- Consensus + storage layer integration
- `persistence_recovery.rs` -- Node restart and state recovery tests
- `e2e/` -- End-to-end test scenarios
- `chaos/` -- Chaos testing (network partitions, node crashes, Byzantine faults)
- `test_inference_e2e.sh` -- AI inference pipeline end-to-end test
- `test_ai_pipeline.sh` -- Full AI model deploy-and-infer pipeline test
- `verify_metal_gpu.py` -- Apple Metal GPU availability check

## Build / Usage

```bash
cargo test --workspace                  # Run all Rust tests
cargo test --test simple_integration    # Run a specific integration test
bash tests/test_inference_e2e.sh        # Run inference E2E (requires running node)
```
