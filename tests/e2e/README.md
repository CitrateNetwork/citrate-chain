# tests/e2e/

End-to-end integration tests that validate complete workflows across multiple
Citrate crates (execution, consensus, wallet, MCP).

## Test Files

| File | What It Tests |
|------|---------------|
| `test_deploy_and_call_contract.rs` | Deploy a counter contract via REVM, call a function, verify receipt and output |
| `test_model_register_and_infer.rs` | Register a model via MCP, run inference, verify proof generation round-trips |
| `test_wallet_to_rpc_pipeline.rs` | Transaction construction, ed25519 signing, bincode serialization, mempool acceptance, executor state changes |

## Running

```bash
# All E2E tests
cargo test --test test_deploy_and_call_contract
cargo test --test test_model_register_and_infer
cargo test --test test_wallet_to_rpc_pipeline

# With output
cargo test --test test_wallet_to_rpc_pipeline -- --nocapture
```

These tests use `tempfile::TempDir` for isolated state and do not require a
running node.
