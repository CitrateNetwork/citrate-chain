# Fuzz

Fuzz testing targets using cargo-fuzz (libfuzzer). Covers critical parsing and deserialization surfaces across the Citrate codebase.

## Contents

- `fuzz_targets/fuzz_tx_decoder.rs` -- Transaction decoder (RLP, bincode, EIP-1559)
- `fuzz_targets/fuzz_rlp_decoder.rs` -- Raw RLP decoding
- `fuzz_targets/fuzz_json_rpc.rs` -- JSON-RPC request parsing
- `fuzz_targets/fuzz_rpc_hex.rs` -- Hex parameter parsing
- `fuzz_targets/fuzz_block_deser.rs` -- Block deserialization
- `fuzz_targets/fuzz_mempool_admission.rs` -- Mempool admission logic
- `fuzz_targets/fuzz_vrf_proof.rs` -- VRF proof verification
- `fuzz_targets/fuzz_config_toml.rs` -- TOML config parsing
- `fuzz_targets/fuzz_precompile_inputs.rs` -- Precompile input handling
- `fuzz_targets/fuzz_bridge_attestation.rs` -- Bridge attestation parsing
- `fuzz_targets/fuzz_checkpoint_vote.rs` -- Checkpoint vote handling
- `fuzz_targets/fuzz_network_message.rs` -- P2P network message parsing
- `fuzz_targets/fuzz_state_key.rs` -- State key construction

## Build / Usage

```bash
cargo install cargo-fuzz
cargo fuzz list                         # List all targets
cargo fuzz run fuzz_tx_decoder          # Run a specific target
cargo fuzz run fuzz_json_rpc -- -max_total_time=300  # Run for 5 minutes
```
