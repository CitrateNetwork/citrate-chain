<div align="center">
  <img src="docs/assets/citrate-logo.svg" alt="Citrate" width="400"/>

  # Citrate — AI-Native BlockDAG

  [![Release](https://img.shields.io/github/v/release/SaulBuilds/citrate?include_prereleases&label=release)](https://github.com/SaulBuilds/citrate/releases)
  [![License](https://img.shields.io/badge/License-BUSL--1.1%20%2B%20AUG-blue.svg)](../LICENSE)
  [![Rust](https://img.shields.io/badge/Rust-1.75+-orange.svg)](https://www.rust-lang.org/)
  [![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](#testing)
  [![TLA+](https://img.shields.io/badge/TLA%2B-specs-purple.svg)](#formal-verification)
  [![Contracts](https://img.shields.io/badge/contracts-30%2B-blue.svg)](#smart-contracts)

  **High-Performance BlockDAG with Native AI Inference • SALT Token**

  [Contributing](#contributing) | [Quick Start](#quick-start) | [Architecture](#architecture) | [Releases](https://github.com/SaulBuilds/citrate/releases)
</div>

---

> **Contributors (human and AI): Start here.** We use the **Agentile** methodology under the **Cnidarian Foundation** for all development. Read [`.agentile/AGENT_ENTRY.md`](../.agentile/AGENT_ENTRY.md) for the contributor decision tree, and read [`.agentile/SPIRIT.md`](../.agentile/SPIRIT.md), [`.agentile/SOUL.md`](../.agentile/SOUL.md), and [`.agentile/AGENT.md`](../.agentile/AGENT.md) for the institutional rule, value, and cooperation layers before writing code.

---

## Overview

Citrate is an AI-native Layer-1 BlockDAG blockchain combining **GhostDAG consensus** with an **EVM-compatible execution environment** and native **AI model inference**. AI models are first-class on-chain assets with verifiable execution, distributed storage (IPFS), and economic incentives powered by the **SALT** token.

### Key Features

- **High Throughput** — BlockDAG architecture with parallel block processing; 5,000 TPS sustained, 10,000 TPS ceiling ([run `./bench` to verify](#benchmark--can-you-break-it))
- **Fast Finality** — BFT committee checkpoints with optimistic confirmation ≤ 12s
- **Native AI Inference** — On-chain model registry, deployment, and execution
- **EVM Compatible** — Deploy Solidity contracts without modification
- **IPFS Storage** — Distributed model weights with pinning incentives
- **SALT Token** — Native token powering staking, governance, and inference fees
- **RPC API Key Auth** — Bearer token / X-API-Key header authentication
- **P2P Peer Whitelist** — Noise public key based access control

### Live Testnet

| Resource | URL |
|----------|-----|
| **JSON-RPC** | `https://rpc.citrate.ai` (POST) |
| **Block Explorer** | `https://explorer.citrate.ai` |
| **Faucet** | [`https://faucet.citrate.ai`](https://faucet.citrate.ai) |
| **Chain ID** | `40204` |

## Forking and Licensing

- Small private learning networks, classrooms, labs, and research forks are encouraged.
- Commercial use, branded deployments, and public product launches are not granted by default.
- See [../LICENSE](../LICENSE), [docs/guides/forking-and-small-networks.md](docs/guides/forking-and-small-networks.md), [docs/guides/licensing-and-commercial-use.md](docs/guides/licensing-and-commercial-use.md), [LICENSING_FRAMEWORK.md](LICENSING_FRAMEWORK.md), [TRADEMARK_POLICY.md](TRADEMARK_POLICY.md), and [../PATENT_NOTICE.md](../PATENT_NOTICE.md).
- Commercial and partnership inquiries: **Partnerships@Citrate.ai**

## Quick Start

### Option 0: One-Line Bootstrap

```bash
# Developer workstation
curl -fsSL https://raw.githubusercontent.com/SaulBuilds/citrate/main/citrate_v0.01.1/scripts/bootstrap.sh | bash -s -- --profile developer

# Agent workstation
curl -fsSL https://raw.githubusercontent.com/SaulBuilds/citrate/main/citrate_v0.01.1/scripts/bootstrap.sh | bash -s -- --profile agent
```

This is the cleanest terminal-first path for open-source contributors. It installs the common toolchain, clones the repo, prepares current config profiles, and builds the main binaries.

### Option A: Download Binary (Recommended)

Grab the latest release for your platform from [GitHub Releases](https://github.com/SaulBuilds/citrate/releases).

```bash
# macOS / Linux — download, make executable, move to PATH
curl -LO https://github.com/SaulBuilds/citrate/releases/latest/download/citrate-$(uname -s | tr A-Z a-z)-$(uname -m).tar.gz
tar xzf citrate-*.tar.gz
chmod +x citrate
sudo mv citrate /usr/local/bin/

# Generate an EVM-compatible keypair (secp256k1 by default)
citrate keygen

# Start a local development network (RPC on 127.0.0.1:8545)
citrate devnet

# Connect MetaMask: http://localhost:8545
# For localhost profiles, query eth_chainId first instead of assuming 40204
```

### Option B: Build from Source

```bash
git clone https://github.com/SaulBuilds/citrate.git
cd citrate/citrate_v0.01.1

# Build node + wallet + CLI
cargo build --release -p citrate-node -p citrate-wallet -p citrate-cli

# Start devnet
./target/release/citrate devnet
```

### Option C: GUI Desktop App

```bash
cd gui/citrate_gui_native
cargo build --release    # Build native Slint GUI
```

### Option D: Docker

```bash
docker pull citrateai/citrate:latest
docker run -p 8545:8545 -p 30303:30303 citrateai/citrate devnet
```

## Genesis Accounts (Devnet)

| Address | Balance | Purpose |
|---------|---------|---------|
| `0x1111...1111` | 100M SALT | Treasury |
| `0x2222...2222` | 250M SALT | Ecosystem fund |
| `0x3333...3333` | 10M SALT | Faucet |
| `0xf39F...2266` | 100 ETH | Hardhat default deployer |

## Architecture

```
citrate_v0.01.1/
├── core/
│   ├── consensus/       # GhostDAG engine, tip selection, finality
│   ├── execution/       # LVM (EVM-compatible) + precompiles
│   ├── sequencer/       # Mempool, bundling, parent selection
│   ├── storage/         # State DB (MPT), block store, artifact pinning
│   ├── api/             # JSON-RPC + REST (OpenAI/Anthropic-compatible)
│   ├── network/         # P2P networking (Noise protocol)
│   ├── mcp/             # Model Context Protocol layer
│   ├── learning/        # Paraconsensus (Belnap FOUR, LoRA, safety)
│   ├── bridge/          # Cross-chain bridge relay
│   ├── marketplace/     # Model discovery, search, ratings
│   └── economics/       # SALT token, rewards, governance
├── node/                # Main node binary (`citrate`)
├── wallet/              # CLI wallet
├── wallet-core/         # Key management, tx signing (Ed25519+secp256k1)
├── cli/                 # CLI tools
├── faucet/              # Testnet faucet with rate limiting
├── gui/
│   ├── citrate_gui_native/  # Native desktop GUI (Slint 1.9)
│   └── citrate_desktop_app/ # Headless service layer for desktop GUI
├── sdks/
│   ├── javascript/citrate-js/  # JavaScript SDK v0.2.0
│   └── python/                 # Python SDK v0.5.0
├── contracts/           # 30+ Solidity contracts (Foundry)
├── specs/tla/           # TLA+ formal specs (subset; canonical set in .agentile/formal/specs/)
└── scripts/             # Orchestration & deployment
```

### Consensus: GhostDAG

- **k-cluster tolerance**: k=18
- **Block time**: 1-2 seconds
- **Finality**: Committee BFT checkpoints, optimistic confirmation ≤ 12s
- **DAG width**: Supports 100+ parallel blocks

### Token Economics (SALT)

| Parameter | Value |
|-----------|-------|
| Total Supply | 1B SALT |
| Block Reward | 10 SALT (90% validator, 10% treasury) |
| Halving Interval | ~2.1M blocks (~4 years) |
| Min Validator Stake | 32,000 SALT |
| Decimals | 18 |

## Smart Contracts

Foundry-based Solidity contracts across four domains:

| Domain | Contracts |
|--------|-----------|
| **AI & Marketplace** | ModelRegistry, ModelMarketplace, ModelAccessControl, InferenceRouter, LoRAFactory, AgentDecisionRegistry, SpecRegistry |
| **Compute Marketplace** | ComputeMarketplace, ComputeVerifier, ComputePool, HeartbeatMonitor, DisputeResolution |
| **Learning Center** | LearningPool, LearningCycleManager, ClassroomRegistry, ContributionAccounting, NematocystSlashing |
| **Staking & Infra** | LiquidStakingPool, WrappedSALT, IPFSIncentives, MarketMakerAllocation, TreasuryGovernor |

```bash
cd contracts && forge test -vv   # Run all Forge tests
```

## Formal Verification (TLA+ Specs)

The canonical TLA+ spec collection lives in `.agentile/formal/specs/` (101 authored specs today across all domains). A local subset of 46 specs is available in `specs/tla/`, organized into six domains:

| Domain | Description |
|--------|-------------|
| `consensus/` | GhostDAG, VRF, Prevrandao, Mempool, TX execution, VRF chain |
| `zk/` | ZK proof lifecycle, key management (Poseidon, MiMC) |
| `learning/` | Belnap lattice, OODA cycle, Byzantine detection, mentor selection |
| `contracts/` | Staking, slashing, trust scoring, contributions, classroom registry |
| `compute/` | Marketplace lifecycle, verification, provider, dispute, heartbeat |
| `gui/` | Onboarding flow, model lifecycle, SDK connection |

For current counts and verification status, see `.agentile/formal/specs/INDEX.md`.

```bash
cd specs/tla && bash run_all.sh      # Standard run (local subset)
cd specs/tla && bash run_deep.sh     # Deep verification (16 workers, 45min timeout)
```

## SDKs

### JavaScript (citrate-js v0.2.0)

```bash
cd sdks/javascript/citrate-js
npm install && npm run build
```

See [`sdks/javascript/citrate-js/`](sdks/javascript/citrate-js/) for full documentation.

### Python (v0.5.0)

```bash
cd sdks/python
pip install -e .
pytest
```

See [`sdks/python/`](sdks/python/) for full documentation.

## API Endpoints

### JSON-RPC (port 8545)

Standard `eth_*` methods plus:

```bash
# DAG statistics
curl -X POST http://localhost:8545 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"citrate_getDagStats","params":[],"id":1}'

# Mempool snapshot
curl -X POST http://localhost:8545 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"citrate_getMempoolSnapshot","params":[],"id":1}'

# Deploy model, get model, list models, run inference
# See docs/guides/ for full RPC reference
```

### MCP REST API

```
/v1/models              # Model registry
/v1/chat/completions    # OpenAI-compatible
/v1/embeddings          # Embeddings API
```

## Development

```bash
# Build everything
cargo build --release

# Run tests
cargo test --workspace

# Format + lint
cargo fmt --all
cargo clippy --all-targets --all-features

# Smart contracts
cd contracts && forge build && forge test

# GUI (native Slint)
cd gui/citrate_gui_native && cargo build --release
```

## Transaction Signing

```bash
# Devnet (skip signature validation for convenience)
CITRATE_REQUIRE_VALID_SIGNATURE=false citrate devnet

# Production: always use eth_sendRawTransaction with client-side signing
```

Citrate supports legacy, EIP-2930, and EIP-1559 transaction types.

## Benchmark — Can You Break It?

Citrate ships with a live benchmark tool that fires real transactions at the chain and shows every one landing in real time. No simulations, no mocks -- these are actual on-chain state transitions.

### Quick Start

```bash
# Terminal 1: Start a local node
cargo run --release -p citrate-node -- devnet

# Terminal 2: Run the benchmark
./bench
```

You'll see a live dashboard streaming TPS, latency, and success rate every second.

### Push Harder

```bash
./bench 5000                  # 5,000 TPS for 30 seconds
./bench 10000 60              # 10K TPS for 1 minute
./bench 20000 60              # 20K TPS — find the ceiling
```

### Against the Live Testnet

```bash
./bench 2000 30 https://rpc.citrate.ai
```

### What You'll See

```
  ╔══════════════════════════════════════════════════════════╗
  ║  ⛏  CITRATE LIVE BENCHMARK                               ║
  ╚══════════════════════════════════════════════════════════╝

    Time │   Sent │   OK │ Fail │ TPS (now) │ TPS (avg) │ Latency
  ───────┼────────┼──────┼──────┼───────────┼───────────┼────────
      1s │   1042 │ 1038 │    0 │      1038 │      1038 │    4ms  ████░░░░░░░░░░░░░░░░
      2s │   2105 │ 2099 │    0 │      1061 │      1049 │    3ms  ████████░░░░░░░░░░░░
      3s │   3148 │ 3140 │    0 │      1041 │      1046 │    4ms  ████████████░░░░░░░░
      ...
```

The tool grades your run (A+ through F) and challenges you to double the TPS. Our baseline on a single node: **5,000 TPS sustained, 10,000 TPS ceiling**.

### Full Benchmark Suite

For a comprehensive report across 6 test types (transfers, contract deploys, storage writes, state reads, mixed workload, burst test):

```bash
cd tests/load
cargo build --release --bin benchmark-suite
./target/release/benchmark-suite http://127.0.0.1:8545 10000 60 ../../benchmarks/
```

This generates a timestamped Markdown report in `benchmarks/`.

### How It Works

The benchmark is a compiled Rust binary using tokio + reqwest with HTTP connection pooling (500 concurrent connections). It sends real `eth_sendTransaction` calls from the genesis faucet account (`0x3333...3333`), paced to your target TPS with sub-millisecond scheduling. Every transaction creates actual state -- not a dry run.

## Testing

| Suite | Command |
|-------|---------|
| Rust unit + integration | `cargo test --workspace` |
| GUI (Slint native) | `cd gui/citrate_gui_native && cargo test` |
| Desktop app services | `cd gui/citrate_desktop_app && cargo test` |
| Solidity (Forge) | `cd contracts && forge test` |
| Python SDK | `cd sdks/python && pytest` |
| TLA+ Formal Verification | `cd specs/tla && bash run_all.sh` |
| Live benchmark | `./bench [TPS] [DURATION]` |

For current counts, see `.agentile/sprints/CURRENT.md`.

## Community & Support

- **GitHub**: [github.com/SaulBuilds/citrate](https://github.com/SaulBuilds/citrate)
- **Issues**: [github.com/SaulBuilds/citrate/issues](https://github.com/SaulBuilds/citrate/issues)
- **Discord**: [discord.gg/A3Uwe4BvdN](https://discord.gg/A3Uwe4BvdN)

## Author

Built by **Larry Klosowski** ([@Saul_loveman](https://twitter.com/Saul_loveman)) with Claude Code.

## License

Business Source License 1.1 with a project-specific Additional Use Grant. See [../LICENSE](../LICENSE), [../PATENT_NOTICE.md](../PATENT_NOTICE.md), [TRADEMARK_POLICY.md](TRADEMARK_POLICY.md), and [docs/guides/licensing-and-commercial-use.md](docs/guides/licensing-and-commercial-use.md).
