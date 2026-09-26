# citrate-chain

*Part of the **[Citrate Network](https://citrate.ai)** — own the means of computation. · [Docs](https://docs.citrate.ai) · [Run a node](https://citrate.ai/download) · [Contribute → free membership](https://github.com/CitrateNetwork/.github/blob/main/CONTRIBUTING.md)*

> The AI-native Layer-1 BlockDAG at the base of the Citrate Network — GhostDAG
> consensus, EVM-compatible execution (LVM), and the on-chain contract book that
> every other Citrate daemon settles against. This is the anchor of the local stack:
> run a devnet node here first, and everything else points at its JSON-RPC.

## What it is

`citrate-chain` is the chain itself: the `citrate` node binary (GhostDAG engine +
LVM/REVM execution + libp2p networking + JSON-RPC), the `citrate-cli`/wallet
tooling, and the Foundry contract book under `contracts/` (ModelRegistry,
WrappedSALT, the x402 facilitator, the compute marketplace, the ERC-4337 AA stack,
and more). Chain ID is **40204**; the native token is **SALT** (18 decimals).

Everything else in the federation — the [bundler](https://github.com/CitrateNetwork/citrate-bundler),
the [inference gateway](https://github.com/CitrateNetwork/citrate-inference-gateway),
the [node agent](https://github.com/CitrateNetwork/citrate-node-agent), and the
[compute pool](https://github.com/CitrateNetwork/citrate-compute-pool) — reads
chain state and settles through the contracts deployed here. Start here.

- Concept docs: https://docs.citrate.ai/chain · Consensus: https://docs.citrate.ai/consensus
- Contract reference: https://docs.citrate.ai/contracts

## Prerequisites

```bash
# Rust (chain is pinned to the 1.96.0 toolchain; stable 1.96+ works)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup toolchain install 1.96.0

# System packages (Debian/Ubuntu). OpenSSL is vendored & static-linked by the
# build, so you do NOT need a matching system libssl — but you do need a C
# toolchain, clang, and pkg-config for RocksDB and the crypto crates.
sudo apt-get update && sudo apt-get install -y \
  build-essential clang cmake pkg-config git curl python3

# Foundry — only needed to build/deploy the contract book (contracts/)
curl -L https://foundry.paradigm.xyz | bash && foundryup
```

macOS: `brew install cmake pkg-config` and install Xcode command-line tools;
the Rust and Foundry installers above are identical.

## Build from source

```bash
git clone https://github.com/CitrateNetwork/citrate-chain
cd citrate-chain

# Build the node binary (workspace default target). Produces target/release/citrate
cargo build --release -p citrate-node

# Build + test the contract book
cd contracts && forge build && forge test -vv && cd ..
```

Expected artifact: `target/release/citrate` (the node binary is named `citrate`,
crate `citrate-node`). A cold release build with LTO takes ~10–20 min and wants
≥8 GB RAM (the vendored OpenSSL adds ~30s once). `cargo test --workspace` runs the
Rust test suite.

## Run locally

The fastest path is a single self-mining devnet node:

```bash
# One-shot devnet: initializes genesis, mines, serves JSON-RPC on 127.0.0.1:8545
./target/release/citrate devnet
# (equivalently: cargo run --release -p citrate-node -- devnet)
```

Defaults (from `node/config/devnet.toml`): JSON-RPC `127.0.0.1:8545`, WebSocket
`127.0.0.1:8546`, P2P `127.0.0.1:30303`, data dir `.citrate-devnet`, mining on,
chain ID `1337` (the local dev chain id; release networks such as testnet-beta use `40204`). RPC/WS bind to loopback with no TLS/auth by design — front them
with a reverse proxy before exposing.

Explicit form (first-run network selection, custom data dir, mining on):

```bash
./target/release/citrate --network local --mine --data-dir .citrate-devnet
```

Verify it's up — `eth_chainId` returns `0x539` (1337), `eth_blockNumber` climbs:

```bash
curl -s http://localhost:8545 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
# -> {"jsonrpc":"2.0","id":1,"result":"0x539"}

curl -s http://localhost:8545 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

Multi-node local testnet (3 bootstrap nodes on 8545/8555/8565):

```bash
./scripts/launch_local_testnet.sh --clean      # start fresh
./scripts/launch_local_testnet.sh --status     # health/block heights
./scripts/stop_local_testnet.sh                # stop
```

### Deploy the contract book locally

The devnet genesis pre-funds the standard Hardhat/Foundry account #0
(`0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`) so you can deploy immediately with
its well-known dev private key (the same key Anvil/Hardhat print on startup):

```bash
cd contracts
forge build
export PRIVATE_KEY=<hardhat account #0 private key>   # address 0xf39Fd6…2266

# Core book (ModelRegistry, WrappedSALT, X402Facilitator, ModelMarketplace, InferenceRouter)
forge script script/Deploy.s.sol \
  --rpc-url http://localhost:8545 \
  --private-key "$PRIVATE_KEY" \
  --broadcast
```

The script logs each deployed address. For the full federation book use
`script/DeployAll.s.sol` and the domain-specific `Deploy*.s.sol` scripts
(AA stack, compute pool, membership, etc.). Foundry is pinned to solc `0.8.36`,
`evm_version = cancun`, with deterministic CREATE2 settings (`bytecode_hash =
none`, `cbor_metadata = false`) — do not change these; they keep addresses
reroll-stable.

## Connect it locally  ← the differentiator

`citrate-chain` is the root of the local stack — it has no upstreams; every other
program points at **its** RPC and **its** deployed contracts. Bring-up order:

1. **Run the devnet node** (above). Note the RPC URL `http://localhost:8545`.
2. **Deploy the contract book** (above). Record the printed addresses — the
   downstream daemons need them (e.g. the bundler needs the ERC-4337 EntryPoint +
   `CitratePaymaster`; the gateway needs `ModelRegistry`/`InferenceRouter`).
3. Point each daemon's RPC env var at `http://localhost:8545`:
   - bundler → `BUNDLER_NETWORK_RPC=http://localhost:8545`
   - inference gateway → `CITRATE_GATEWAY_RPC_URL=http://localhost:8545`
   - node agent → `CITRATE_RPC_URL=http://localhost:8545`
   - compute pool coordinator → `CITRATE_POOL_RPC_URL=http://localhost:8545`

Minimal end-to-end check: after deploy, `cast call <ModelRegistry> "modelCount()"
--rpc-url http://localhost:8545` returns a value, and a downstream daemon started
against `:8545` logs `chain_id=40204`.

See the full multi-repo bring-up in `LOCAL_STACK.md` (citrate-docs):
https://docs.citrate.ai/local-stack

## Configuration

- Node config: `node/config/*.toml` (`devnet.toml`, `testnet.toml`, …) selected
  with `--config`, or use the `devnet` subcommand / `--network local`.
- Key CLI flags: `--data-dir`, `--rpc-addr`, `--p2p-addr`, `--mine`,
  `--bootstrap-nodes`, `--chain-id` (default 40204), `--coinbase`, `--no-rpc`.
- Env: `RUST_LOG` (log level), `LOG_FORMAT` (`json|pretty|compact`),
  `CITRATE_METRICS_ADDR` (Prometheus bind), `CITRATE_OPERATOR_TOKEN` (required for
  operator RPC methods on a non-loopback bind).
- Foundry: `contracts/foundry.toml` (canonical) and the root `foundry.toml` mirror
  the deterministic CREATE2 settings.

## Links

- Docs: https://docs.citrate.ai/chain
- Consumed by: [citrate-bundler](https://github.com/CitrateNetwork/citrate-bundler) ·
  [citrate-inference-gateway](https://github.com/CitrateNetwork/citrate-inference-gateway) ·
  [citrate-node-agent](https://github.com/CitrateNetwork/citrate-node-agent) ·
  [citrate-compute-pool](https://github.com/CitrateNetwork/citrate-compute-pool)
- Contributing (DCO): CONTRIBUTING.md · Security: SECURITY.md · License: LICENSE

## License

Licensed under the Apache License, Version 2.0 (see [`LICENSE`](LICENSE)). This is the open-source infrastructure tier of Citrate's open-core model. The commercial application layer is source-available under BUSL-1.1. Licensor: Citrate Inc.
