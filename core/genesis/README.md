# core/genesis/

Genesis block configuration and the embedded AI model for the Citrate chain.

## Files

### genesis_model.rs

Defines `GenesisModel`, `GenesisConfig`, and supporting types. The genesis model
is a BERT-tiny architecture (128 hidden, 4 layers, 2 heads) whose ONNX weights
are compiled into the binary via `include_bytes!("../../assets/genesis_model.onnx")`.

Key functionality:
- **Embeddings** -- Deterministic Keccak256-based text embeddings (not neural
  inference) to guarantee identical outputs across all consensus nodes
- **Semantic similarity** -- Cosine similarity between text embeddings
- **Intent classification** -- Classifies transactions by method signature
  (transfer, token transfer, contract creation, model deployment, inference)
- **Genesis config** -- Chain ID, gas limit, initial validators, token allocations

The `GenesisConfig::default()` creates a testnet-beta genesis with chain ID
40204, 30M gas limit, and one initial validator.

Note: this file (`core/genesis/genesis_model.rs`) is a standalone reference
module. Production genesis construction lives in
`core/economics/src/genesis.rs` and `node/src/genesis.rs`.
