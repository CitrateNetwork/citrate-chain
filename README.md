---
created: 2026-05-18T01:00:00Z
branch: main
author: monorepo-split
status: active
split-from-monorepo-at: b3ccd5c7
split-from-monorepo-tag: pre-split-v0.4.0
archived-monorepo: https://github.com/CitrateNetwork/citrate-monorepo-archive
agentile-archive: https://github.com/CitrateNetwork/citrate-agentile-archive
---

# citrate-chain

> The **AI-native Layer-1 BlockDAG blockchain** with GhostDAG consensus, EVM-compatible execution (LVM), and a standardized Model Context Protocol (MCP) layer. Makes AI models first-class on-chain assets — registries, weights, training and eval logs, verifiable provenance.

## What's in this repo

The chain itself — everything that makes Citrate a blockchain:

| Path | Crate | Role |
|---|---|---|
| `core/consensus` | `citrate-consensus` | GhostDAG engine, tip selection, finality, ECVRF proposer election, BFT committee checkpoints |
| `core/execution` | `citrate-execution` | LVM (EVM-compatible via REVM) + AI/ZKP precompiles |
| `core/storage` | `citrate-storage` | State DB (MPT), block store, artifact pinning, RocksDB |
| `core/sequencer` | `citrate-sequencer` | Mempool policy, bundling, parent selection |
| `core/primitives` | `primitives` | Core types and utilities |
| `core/api` | `citrate-api` | JSON-RPC, REST, OpenAI/Anthropic-compatible endpoints |
| `core/network` | `citrate-network` | libp2p networking, block + tx propagation |
| `core/mcp` | `citrate-mcp` | Model Context Protocol layer |
| `core/economics` | `citrate-economics` | Rewards, tokenomics, fee router |
| `core/marketplace` | `citrate-marketplace` | Marketplace contracts integration |
| `core/learning` | `citrate-learning` | Federated learning pool primitives |
| `core/learning-daemon` | `citrate-learning-daemon` | Background learning coordinator |
| `core/experiment-runner` | `citrate-experiment-runner` | Training experiment harness |
| `core/bridge` | `citrate-bridge` | Cross-chain bridge primitives |
| `core/security` | `citrate-security` | Security primitives, attestation gates |
| `core/signing` | `citrate-signing` | Multi-sig + threshold signing |
| `node` | `citrate-node` | Main node binary |
| `node-app` | (node-app) | Node application wrapper |
| `cli` | `citrate-cli` | CLI tools |
| `wallet` | `citrate-wallet` | CLI wallet (ed25519) |
| `wallet-core` | `citrate-wallet-core` | Wallet substrate |
| `wallet-sdk` | `citrate-wallet-sdk` | Higher-level wallet SDK |
| `faucet` | `citrate-faucet` | Test token faucet |
| `crates/citrate-hkdf-chain` | `citrate-hkdf-chain` | HKDF-based chain key derivation |
| `contracts/` | (Solidity, Foundry) | 37+ on-chain contracts |
| `specs/tla/` | TLA+ specs | Formal verification of consensus + safety properties |
| `specs/gherkin/` | BDD scenarios | Behavior-driven specifications |
| `tests/` | Integration tests | Workspace-level + load tests |
| `fuzz/` | Fuzz targets | Continuous fuzzing |
| `tools/` | Operator tooling | Misc CLI tools, devnet helpers |

> **Operators:** the production runbook lives at
> [`docs/OPERATIONS.md`](docs/OPERATIONS.md) — start with "Producer health"
> (PIL-13 memory thresholds + the `mining = false` circuit-breaker).

## Network parameters

- **Chain ID**: `40204` (testnet beta)
- **Token**: SALT (1 trillion supply, 18 decimals)
- **VM**: Lattice Virtual Machine (LVM) — EVM-compatible via REVM
- **Consensus**: GhostDAG with `k=18`, max-parents=10
- **Proposer election**: ECVRF-P256-SHA256 (RFC 9381)
- **Finality**: Committee BFT checkpoints, 100 validators, 67 quorum, 50-block interval
- **Performance**: 5,000 TPS sustained (10,000 ceiling); ≤12 s finality

See [`config/`](config/) for devnet/testnet TOML samples.

## Quick start

```bash
# Build everything
cargo build --release

# Run a local devnet
cargo run --bin citrate-node -- devnet

# Or use the orchestration script
scripts/lattice.sh dev up

# Run all workspace tests
cargo test --workspace --locked

# Build + test Solidity contracts
forge build && forge test

# Run benchmark suite (after node is up)
cd tests/load
./target/release/benchmark-suite http://127.0.0.1:8545 10000 60 ../../benchmarks/
```

For full developer instructions, see [`CLAUDE.md`](CLAUDE.md) — it documents the workspace, commands, and conventions in depth.

## Repository context

This repo was split from the **Citrate monorepo** on 2026-05-18. For the full history of decisions, sprints, audits, remediations, and ADRs that led to the split, see:

- **Monorepo archive**: https://github.com/CitrateNetwork/citrate-monorepo-archive
- **Agentile archive**: https://github.com/CitrateNetwork/citrate-agentile-archive — methodology corpus (rules, planset, sprints, audits)

Other components of the Citrate Network live in sibling repos:

- **`citrate-gui-native`** — Slint desktop wallet + DAG explorer
- **`citrate-learning-center`** — School pilot desktop app
- **`citrate-wallet-extension`** — Browser wallet extension
- **`citrate-agent-runtime`** — Agent execution runtime + capsules
- **`citrate-inference-gateway`** — x402-compatible inference gateway
- **`citrate-compute-pool`** — Training pool coordinator + worker
- **`citrate-buyer-webapp`** — Buyer-side marketplace webapp
- **`citrate-dashboard`** — Network monitoring dashboard
- **`citrate-sdk-js`** / **`citrate-sdk-python`** / **`citrate-sdk-marketplace`** — Client SDKs
- **`citrate-docs`** — User docs, tutorials, public-goods, Gradient Papers v3

## Crates.io publishes (staged — not yet pushed)

When the first audited release tag (`v0.5.0`) ships, these 4 crates publish to crates.io for downstream consumption:

- `citrate-wallet-core` (wallet substrate)
- `citrate-wallet-sdk` (higher-level wrapper)
- `citrate-api` types (JSON-RPC type definitions)
- A rename of `primitives` → `citrate-primitives` is required first (current name is too generic for crates.io)

Internal crates (`consensus`, `execution`, `storage`, `network`, `mcp`, `bridge`, `marketplace`, `learning*`, `economics`, `security`, `signing`) stay path-only inside this workspace. Downstream repos shouldn't depend on implementation internals.

## On-chain contracts

37+ Solidity contracts in [`contracts/src/`](contracts/src/), built with Foundry. Solidity ABIs publish to npm as `@CitrateNetwork/contracts-abi` when a release tag ships.

```bash
cd contracts
forge build
forge test -vvv
```

## Releases

This repo versions **independently** from other CitrateNetwork repos.

- **Current**: `v0.4.0` (pre-split heritage tag; see `pre-split-v0.4.0` on the monorepo archive)
- **Next**: `v0.5.0` (chain-only release after audit pass)

Audit gate: per the CitrateNetwork release policy, **every stable release tag requires a re-audit pass**. Prerelease tags (`v0.5.0-rc.N`) can ship without re-audit; stable tags cannot.

## Contributing

This repo follows the **Agentile methodology**. The 13 non-negotiable rules (CORE_RULES) live in the archive at https://github.com/CitrateNetwork/citrate-agentile-archive/blob/main/rules/CORE_RULES.md. Active sprints for chain work live in this repo's local `.agentile/sprints/` (post-split).

See [`CLAUDE.md`](CLAUDE.md) for the workspace conventions and [`CHANGELOG.md`](CHANGELOG.md) for the change log.

## License

[MIT](LICENSE). See [`LICENSING_FRAMEWORK.md`](LICENSING_FRAMEWORK.md) and [`TRADEMARK_POLICY.md`](TRADEMARK_POLICY.md) for the full licensing posture.
