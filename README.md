<div align="center">
  <img src="docs/assets/citrate-logo.svg" alt="Citrate" width="400"/>

  # Citrate — AI-Native BlockDAG

  [![Release](https://img.shields.io/github/v/release/SaulBuilds/citrate?include_prereleases&label=release)](https://github.com/SaulBuilds/citrate/releases)
  [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
  [![Rust](https://img.shields.io/badge/Rust-1.75+-orange.svg)](https://www.rust-lang.org/)
  [![Tests](https://img.shields.io/badge/tests-3%2C146%2B-brightgreen.svg)](#testing)
  [![TLA+](https://img.shields.io/badge/TLA%2B-11_specs-purple.svg)](#formal-verification)

  **High-Performance BlockDAG with Native AI Inference • SALT Token**

  [Contributing](#contributing) | [Quick Start](#quick-start) | [Architecture](#architecture) | [Releases](https://github.com/SaulBuilds/citrate/releases)
</div>

---

> **Contributors (human and AI): Start here.** This repository uses the [Agentile methodology](../.agentile/AGENT_ENTRY.md) for all development. Before writing any code, read [`.agentile/AGENT_ENTRY.md`](../.agentile/AGENT_ENTRY.md) for the full contributor decision tree, rules, and workflows. Every AI coding tool (Claude Code, Cursor, Copilot, Windsurf, Codex, Gemini, etc.) will auto-discover these instructions via `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `.windsurfrules`, and `.github/copilot-instructions.md` in the repo root.

---

## Overview

Citrate is an AI-native Layer-1 BlockDAG blockchain combining **GhostDAG consensus** with an **EVM-compatible execution environment** and native **AI model inference**. The platform makes AI models first-class on-chain assets with verifiable execution, distributed storage (IPFS), and economic incentives powered by the **SALT** token.

### Key Features

- **High Throughput** — BlockDAG architecture with parallel block processing (target: 10,000 TPS)
- **Fast Finality** — BFT committee checkpoints with optimistic confirmation (target: <12s)
- **Native AI Inference** — On-chain model registry, deployment, and execution
- **EVM Compatible** — Deploy Solidity contracts without modification
- **IPFS Storage** — Distributed model weights with pinning incentives
- **SALT Token** — Native token powering staking, governance, and inference fees
- **RPC API Key Auth** — Bearer token / X-API-Key header authentication
- **P2P Peer Whitelist** — Noise public key based access control

## Quick Start

### Option A: Download Binary (Recommended)

Download the latest release for your platform from [GitHub Releases](https://github.com/SaulBuilds/citrate/releases).

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

# Connect MetaMask: http://localhost:8545 • Chain ID 40204
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
cd gui/citrate_gui_v2
npm install
npx tauri dev       # Development
npx tauri build     # Production installer (dmg/msi/AppImage)
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
│   └── economics/       # SALT token, rewards, governance
├── node/                # Main node binary (`citrate`)
├── wallet/              # CLI wallet
├── cli/                 # CLI tools
├── faucet/              # Testnet faucet with rate limiting
├── gui/citrate_gui_v2/  # Tauri desktop app (React + Vite)
├── sdk/javascript/      # @citrate/sdk (TypeScript)
├── contracts/           # Solidity contracts (Foundry)
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

## SDK

```bash
npm install @citrate/sdk
```

```typescript
import CitrateSDK from '@citrate/sdk';

const sdk = new CitrateSDK({ rpcUrl: 'http://localhost:8545' });

// Deploy a model
const model = await sdk.models.deploy({
  name: 'my-model',
  framework: 'onnx',
  modelData: modelBuffer,
});

// Run inference
const result = await sdk.models.infer(model.id, { text: 'hello' });
```

See [`sdk/javascript/`](sdk/javascript/) for full documentation.

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

# GUI (web dev server)
cd gui/citrate_gui_v2 && npm run dev
```

## Transaction Signing

```bash
# Devnet (skip signature validation for convenience)
CITRATE_REQUIRE_VALID_SIGNATURE=false citrate devnet

# Production: always use eth_sendRawTransaction with client-side signing
```

Citrate supports legacy, EIP-2930, and EIP-1559 transaction types.

## Community & Support

- **GitHub**: [github.com/SaulBuilds/citrate](https://github.com/SaulBuilds/citrate)
- **Issues**: [github.com/SaulBuilds/citrate/issues](https://github.com/SaulBuilds/citrate/issues)
- **Discord**: [discord.gg/citrate](https://discord.gg/citrate)

## License

MIT — see [LICENSE](LICENSE) for details.
