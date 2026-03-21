<div align="center">
  <img src="docs/assets/citrate-logo.svg" alt="Citrate" width="400"/>

  # Citrate — AI-Native BlockDAG

  [![Release](https://img.shields.io/github/v/release/SaulBuilds/citrate?include_prereleases&label=release)](https://github.com/SaulBuilds/citrate/releases)
  [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
  [![Rust](https://img.shields.io/badge/Rust-1.75+-orange.svg)](https://www.rust-lang.org/)
  [![Tests](https://img.shields.io/badge/tests-2%2C484%2B-brightgreen.svg)](#testing)
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
| **JSON-RPC** | `https://spark-2e01.tailcbe2ba.ts.net` (POST) |
| **Block Explorer** | `https://spark-2e01.tailcbe2ba.ts.net` (GET) |
| **Faucet** | [`https://spark-2e01.tailcbe2ba.ts.net/faucet`](https://spark-2e01.tailcbe2ba.ts.net/faucet) |
| **Chain ID** | `40204` |

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

## Benchmark — Can You Break It?

Citrate ships with a live benchmark tool that fires real transactions at the chain and shows you every one landing in real time. No simulations, no mocks — these are actual on-chain state transitions.

### Quick Start

```bash
# Terminal 1: Start a local node
cargo run --release -p citrate-node -- devnet

# Terminal 2: Run the benchmark
./bench
```

That's it. You'll see a live dashboard streaming TPS, latency, and success rate every second.

### Push Harder

```bash
./bench 5000                  # 5,000 TPS for 30 seconds
./bench 10000 60              # 10K TPS for 1 minute
./bench 20000 60              # 20K TPS — find the ceiling
```

### Against the Live Testnet

```bash
./bench 2000 30 https://spark-2e01.tailcbe2ba.ts.net
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

The benchmark is a compiled Rust binary using tokio + reqwest with HTTP connection pooling (500 concurrent connections). It sends real `eth_sendTransaction` calls from the genesis faucet account (`0x3333...3333`), paced to your target TPS with sub-millisecond scheduling. Every transaction creates actual state — this is not a dry run.

## Testing

| Suite | Count | Command |
|-------|-------|---------|
| Rust unit + integration | 2,484+ | `cargo test --workspace` |
| GUI (Vitest) | 596 | `cd gui/citrate_gui_v2 && npx vitest run` |
| Solidity (Forge) | 66 | `cd contracts && forge test` |
| Live benchmark | — | `./bench [TPS] [DURATION]` |

## Community & Support

- **GitHub**: [github.com/SaulBuilds/citrate](https://github.com/SaulBuilds/citrate)
- **Issues**: [github.com/SaulBuilds/citrate/issues](https://github.com/SaulBuilds/citrate/issues)
- **Discord**: [discord.gg/citrate](https://discord.gg/citrate)

## License

MIT — see [LICENSE](LICENSE) for details.
