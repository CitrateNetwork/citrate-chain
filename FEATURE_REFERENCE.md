# Citrate Feature Reference

Complete reference of all features, APIs, opcodes, consensus mechanisms, and libraries in the Citrate platform.

---

## 1. Consensus Layer

### GhostDAG Protocol
- **Block structure**: Each block has 1 selected parent + 0-10 merge parents
- **Blue set calculation**: Maximal k-cluster consistent set (k=18)
- **Blue score**: Total ancestry-consistent blue mass for deterministic ordering
- **Total order**: Selected-parent chain + mergeset, topologically sorted by blue score
- **Tie breaking**: Deterministic by block hash (lowest hash wins)
- **DAG width**: Supports 100+ parallel blocks

### ECVRF-P256-SHA256 Proposer Election
- **Curve**: NIST P-256 (secp256r1)
- **Compliance**: RFC 9381
- **Proof format**: 114 bytes = pk_p256(33) + Gamma(33) + c(16) + s(32)
- **Alpha binding**: SHA3(ed25519_pubkey || prev_vrf_output || slot_number)
- **Backward compatible**: Accepts both ECVRF (114-byte) and legacy SHA3 (32-byte) proofs

### BFT Committee Checkpoints
- **Committee size**: 100 validators
- **Quorum**: 67 (2/3 + 1)
- **Checkpoint interval**: 50 blocks (~25s at 0.5s block time)
- **Selection**: Deterministic via VRF seed + validator pubkey + checkpoint height
- **Persistence**: RocksDB `checkpoints` column family
- **Finality override**: Checkpoint finality overrides depth-based finality

### Signature Schemes
- **Native**: ed25519 (block signing, validator identity)
- **EVM**: ECDSA secp256k1 (transaction signing, EVM compatibility)
- **x402**: EIP-712 typed data signatures (payment authorization)

---

## 2. Execution Layer (LVM)

### EVM Compatibility
- **Engine**: REVM (Rust EVM implementation)
- **Opcodes**: Full EVM opcode set (Shanghai/Cancun)
- **Gas metering**: Standard EVM gas costs
- **Transaction types**: Legacy, EIP-2930 (access lists), EIP-1559 (priority fees)
- **Address derivation**: Smart handling — embedded 20-byte EVM addresses used directly, full 32-byte pubkeys Keccak256-hashed

### State Precompiles (Canonical — executor.rs)

These addresses handle on-chain state transitions for AI models and artifacts:

| Address | Name | Function |
|---------|------|----------|
| 0x...1000 | ModelPrecompile | Register/manage on-chain AI models (state-changing) |
| 0x...1002 | ArtifactPrecompile | Store/retrieve model artifacts (state-changing) |
| 0x...1003 | GovernancePrecompile | DAO governance operations (state-changing) |

### Runtime AI Precompiles (inference.rs)

These addresses handle runtime AI operations (inference, ZK proofs):

| Address | Name | Gas Cost | Function |
|---------|------|----------|----------|
| 0x0100 | InferenceDeployPrecompile | 5,000 | Deploy model for inference |
| 0x0101 | InferenceRunPrecompile | 10,000+ | Execute AI inference with ZK proof option |
| 0x0102 | InferenceBatchPrecompile | 8,000 | Batch inference for efficiency |
| 0x0103 | InferenceMetadataPrecompile | 3,000 | Query model metadata |
| 0x0104 | InferenceVerifyPrecompile | 50,000 | Verify inference proof (Groth16, BLS12-381) |
| 0x0105 | InferenceBenchmarkPrecompile | 6,000 | Benchmark model performance |
| 0x0106 | InferenceEncryptPrecompile | 3,000 | Model encryption operations |

### Signature Precompiles

| Address | Name | Gas Cost | Function |
|---------|------|----------|----------|
| 0x0200 | EIP712VerifyPrecompile | 3,450 | EIP-712 typed data signature recovery |
| 0x0201 | TransferAuthVerifyPrecompile | 4,200 | EIP-3009 transfer authorization |
| 0x0202 | BatchPaymentVerifyPrecompile | 2,000+3,800/payment | Batch payment verification |

### Standard Precompiles (EVM)

| Address | Name | Purpose |
|---------|------|---------|
| 0x01 | ecRecover | ECDSA signature recovery |
| 0x02 | SHA256 | SHA-256 hash |
| 0x03 | RIPEMD160 | RIPEMD-160 hash |
| 0x04 | Identity | Data copy |
| 0x05 | ModExp | Modular exponentiation |
| 0x06-0x08 | BN256 | Elliptic curve operations |
| 0x09 | Blake2f | BLAKE2b compression |

---

## 3. JSON-RPC API

### Standard Ethereum Methods (eth_*)

| Method | Description |
|--------|-------------|
| `eth_chainId` | Returns chain ID (40204 testnet) |
| `eth_blockNumber` | Current block height |
| `eth_getBalance` | Account balance in wei |
| `eth_getTransactionCount` | Account nonce (supports "pending" tag) |
| `eth_sendRawTransaction` | Submit signed transaction |
| `eth_sendTransaction` | Submit unsigned transaction (devnet only) |
| `eth_getTransactionByHash` | Transaction details |
| `eth_getTransactionReceipt` | Transaction receipt with logs |
| `eth_getBlockByNumber` | Block by height |
| `eth_getBlockByHash` | Block by hash |
| `eth_call` | Read-only contract call |
| `eth_estimateGas` | Gas estimation |
| `eth_gasPrice` | Current gas price |
| `eth_getCode` | Deployed contract bytecode |
| `eth_getStorageAt` | Contract storage slot |
| `eth_getLogs` | Event log query |
| `eth_newFilter` | Create log filter |
| `eth_newBlockFilter` | Create block filter |
| `eth_newPendingTransactionFilter` | Create pending tx filter |
| `eth_getFilterChanges` | Poll filter changes |
| `eth_getFilterLogs` | Get all filter logs |
| `eth_uninstallFilter` | Remove filter |
| `net_version` | Network version |
| `net_peerCount` | Connected peer count |
| `web3_clientVersion` | Client version string |

### Custom Citrate Methods (citrate_*)

| Method | Description |
|--------|-------------|
| `citrate_getDagStats` | DAG statistics (tips, blue/red blocks, height) |
| `citrate_getDagBlock` | Block with DAG-specific fields (merge parents, blue score) |
| `citrate_getModel` | AI model metadata by ID |
| `citrate_listModels` | List registered models (alias: `citrate_getModels`) |
| `citrate_deployModel` | Deploy AI model |
| `citrate_runInference` | Execute AI inference |
| `citrate_getMempoolSnapshot` | Full mempool visibility |
| `citrate_getPeers` | Connected peer info |
| `citrate_getNodeStatus` | Node status (syncing, height, peers) |

### MCP REST API (OpenAI/Anthropic Compatible)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/models` | GET | List available models |
| `/v1/chat/completions` | POST | Chat completion (OpenAI format) |
| `/v1/embeddings` | POST | Generate embeddings |
| `/v1/jobs` | POST/GET | Async job management |
| `/v1/messages` | POST | Anthropic-compatible messages |

---

## 4. Token Economics

### SALT Token
- **Type**: Native gas token (not ERC-20)
- **Total supply**: 1,000,000,000 (1 billion)
- **Decimals**: 18
- **Distribution**: 50% mining, 25% ecosystem, 10% treasury, 15% team

### Block Rewards
- **Base reward**: 10 SALT/block
- **Halving**: Every 2,100,000 blocks (~4 years)
- **Schedule**: 10 → 5 → 2.5 → 1.25 → 0.625 → ... → 0.1 (tail emission)
- **Bonus**: +1% per inference in block, +0.5% per GB artifacts pinned

### Revenue Distribution (7-way + market maker)
```
Gas Fees → 10% Market Maker (pre-split)
         → 90% × { Validators 23%, Creators 30%, Infra 15%,
                    Treasury 12%, Stakers 15%, x402 Facilitators 5% }
```

### Staking (stSALT)
- **Model**: Lido-style liquid staking with shares
- **Minimum stake**: 32,000 SALT (validators), 100 SALT (delegation)
- **Withdrawal lockup**: 7 days (50,400 blocks)
- **Oracle committee**: 67/100 quorum for reward reporting
- **Provider collateral**: 10% of delegated SALT

### Contribution Weights (Shapley)
| Type | Weight | Description |
|------|--------|-------------|
| Validation | 1.0x | Block proposal + BFT signatures |
| ModelHosting | 1.5x | Inference requests served |
| AdapterCreation | 2.0x | LoRA adapters improving models |
| DataProvision | 1.5x | Training data contributed |
| AppDevelopment | 1.0x | Tools/UIs deployed |
| BridgeInfra | 1.0x | Cross-chain relay operations |
| Governance | 0.5x | Votes cast + proposals |

### Slashing (NematocystSlashing)
| Tier | Name | Penalty | Trigger |
|------|------|---------|---------|
| 1 | Spirocyst | 5% of stake | Latency, missed checkpoints |
| 2 | Mastigophore | 20% of stake | Inconsistency, high Belnap Both |
| 3 | Penetrant | 100% of stake | Byzantine (double-signing), permanent ban |
| — | Correlation | Up to 3x multiplier | Multiple slashes in 50-block window |

### Compute Pricing
- **Oracle**: BFT quorum (67%) updates FLOP/SALT rate
- **Reference**: A100 x8 = ~$20/hr = $0.13/PFLOP-hour
- **BME burn**: 2.5% of every compute job value
- **Treasury fee**: 2.5% of every compute job value
- **Verification multipliers**: Commitment 1.0x, ZKProof 1.5x, TEE 2.0x
- **Staleness**: Oracle prices expire after 7,200 blocks (~1 day)

### Governance
- **Proposal threshold**: 10,000 SALT
- **Quorum**: 10% of supply
- **Approval**: 60% of votes
- **Voting period**: 50,400 blocks (~7 days)
- **Execution delay**: 7,200 blocks (~1 day, timelock)
- **Voting power**: SALT balance + stSALT shares × sharePrice
- **Proposal types**: TreasurySpend, ParameterChange, OracleUpdate, Emergency

---

## 5. Learning Layer

### Federated Learning (Paraconsensus)
- **Logic**: Belnap FOUR-valued (True, False, Both, Neither)
- **Aggregation**: Paraconsistent weighted mean with dual-output
- **Cycle**: OODA phases (Observe → Orient → Decide → Act)
- **Trigger**: BFT checkpoint every ~50 blocks
- **Block header**: Extended with `learning_root` hash

### LoRA Adapters
- **Composition**: Associative — (A∘B)∘C = A∘(B∘C)
- **Provenance**: Hash-linked chain of parent adapters
- **Reversibility**: apply + remove = identity
- **Weight**: 2.0x Shapley contribution (highest weight)

### Mentor-Mentee System
- **Selection**: Byzantine-robust consensus on mentor assignment
- **Graduation**: Mentee converges within threshold rounds
- **Reward split**: 15% to mentor nodes per cycle

### Byzantine Detection
- **Method**: Belnap "Both" fraction monitoring
- **Threshold**: Configurable per-pool
- **Cooldown**: Readmission gated by cooldown period
- **History**: Monotonic flag history (flags never decrease)

---

## 6. Payment Layer (x402)

### Level 2 (EVM Precompiles)
- **EIP-712 verification**: Recover signer from typed data (3,450 gas)
- **EIP-3009 authorization**: Gasless authorized transfers (4,200 gas)
- **Batch payments**: Multi-payment verification (2,000 + 3,800/payment gas)

### Contracts
- **WrappedSALT (wSALT)**: ERC-20 wrapper with `transferWithAuthorization()`
- **X402Facilitator**: Settlement with configurable fee (max 10%), treasury routing
- **X402Paywall**: Resource gating with price-per-resource configuration

### Institutional Compute Credits
- **BulkComputeGateway**: Schools buy credits with USDC/USDT
- **Credit unit**: PFLOP-hours (18 decimals)
- **Pricing**: Via ComputePricingOracle (BFT quorum)
- **Stablecoin treasury**: Accumulates institutional payments for testnet-end distribution

---

## 7. Desktop Application (Slint)

### Dual Mode
- **Explorer Mode**: DAG visualization, contract interaction, terminal, developer tools
- **Learning Mode**: Earnings dashboard, pool browser, model library, staking panel

### Key Features
| Feature | Technology | Description |
|---------|-----------|-------------|
| DAG Visualization | react-force-graph-3d | 3D interactive BlockDAG explorer |
| Code Editor | Monaco Editor | Solidity/Rust editor with syntax highlighting |
| Terminal | xterm.js | Full PTY terminal emulation |
| AI Chat | Custom + react-markdown | Agent conversation with tool approval |
| Real-time Sync | Yjs + y-websocket | Multiplayer collaboration |
| GPU Management | Custom + nvidia-smi/rocm-smi/Metal | 3-platform GPU detection and monitoring |
| Wallet | ethers.js | Account creation, signing, transactions |

### Onboarding (12 steps)
1. Launch check → 2. Identity → 3. Auth (Privy/traditional) → 4. Device binding → 5. Wallet provisioning → 6. Security → 7. Persona selection (Teacher/Student/Developer/Home User) → 8. Environment → 9. Node bootstrap → 10. Model readiness → 11. Interactive lesson → 12. Hello World deploy

---

## 8. GPU Detection

### Supported Platforms
| Platform | Detection Method | Monitoring |
|----------|-----------------|------------|
| NVIDIA (CUDA) | nvidia-smi CSV query | Temperature, power, utilization |
| Apple (Metal) | system_profiler JSON | VRAM only (Apple limitation) |
| AMD (ROCm) | rocm-smi JSON → individual queries → lspci fallback | Temperature, power, utilization (via rocm-smi) |
| Intel | lspci + intel_gpu_top JSON | Frequency, power, engine utilization |
| CPU Fallback | num_cpus + /proc/meminfo | Core count, system memory |

### GPU Pool Modes
| Mode | Scaling | Use Case |
|------|---------|----------|
| InferencePool | Linear | Query routing, round-robin |
| DataParallel | Sub-linear | Federated gradient aggregation |
| PipelineParallel | Latency-limited | Model sharding across GPUs |

---

## 9. ZK Proof System

### Circuit Types
| Circuit | Curve | Hash | Purpose |
|---------|-------|------|---------|
| GradientProof | BLS12-381 | MiMC (220 rounds) | Verify gradient hash = hash(model, dataset, loss, samples) |
| StateTransition | BLS12-381 | MiMC | Verify new_state = apply(old_state, tx) |
| InferenceProof | BLS12-381 | Poseidon | Verify inference output matches committed model+input |
| BatchProof | BLS12-381 | — | Aggregate multiple proofs |

### Parameters
- **Proving system**: Groth16
- **Curve**: BLS12-381
- **RNG**: OsRng (production), StdRng::seed_from_u64(0) (test only)
- **Hash**: MiMC 220-round Miyaguchi-Preneel sponge (3.67x fewer constraints than Poseidon for field arithmetic)

---

## 10. Network Layer

### P2P Protocol
- **Encryption**: Noise protocol framework
- **Discovery**: Peer exchange + bootstrap nodes
- **Gossip**: Block propagation, transaction broadcast, learning gossip
- **Message types**: Block, Transaction, LearningGossip, CheckpointVote

### Configuration
- **Chain ID**: 40204 (testnet)
- **Default ports**: 8545 (RPC), 8546 (WebSocket), 30303 (P2P)
- **Testnet RPC**: https://rpc.citrate.ai
- **Block time**: 2 seconds (testnet), 1 second (devnet)

#### Canonical RPC ports

These are the platform-wide canonical values — treat this section as the
source of truth for any client default, SDK, wallet, or docs:

- **Local node HTTP JSON-RPC**: `8545` (loopback default; binds `0.0.0.0`
  only on fleet/devnet)
- **Local node WebSocket**: `8546`
- **Public HTTP RPC**: `https://rpc.citrate.ai` (443 → Caddy → node
  `127.0.0.1:8545`); **Public WS**: `wss://rpc.citrate.ai` (443 → `:8546`)
- **Co-resident 2nd instance**: apply a **+10000** host-side offset
  (`18545`/`18546`) — this is ONLY for docker host-port maps and multi-node
  test harnesses, never a client default or a server bind. `18545` is
  retired as a client default everywhere.

---

## 11. Storage Layer

### Databases
| Store | Backend | Purpose |
|-------|---------|---------|
| StateDB | Merkle Patricia Trie | Account state (balance, nonce, storage, code) |
| ChainStore | RocksDB | Block storage, transaction indexing |
| DagStore | RocksDB (7 column families) | DAG blocks, children, tips, finalized, height index, metadata, checkpoints |
| TransactionStore | RocksDB | Receipt storage, log indexing |

### Persistence
- **Write-through**: In-memory maps + RocksDB backend
- **Recovery**: DAG state loaded from RocksDB on restart (no full re-sync)
- **Artifacts**: Off-chain (IPFS/Arweave), referenced by CID

---

## 12. Observability

### Structured Logging
- **Format**: JSON with trace ID correlation
- **Trace ID**: `{timestamp_hex}-{counter_hex}-{random_hex}`
- **Levels**: trace, debug, info, warn, error

### Prometheus Metrics
| Metric | Type | Description |
|--------|------|-------------|
| `citrate_node_uptime_seconds` | Gauge | Node uptime |
| `citrate_peer_count` | Gauge | Connected peers |
| `citrate_block_height` | Gauge | Current block height |
| `citrate_mempool_size` | Gauge | Transactions in mempool |
| `citrate_dag_tips_count` | Gauge | DAG tip count |
| `citrate_rpc_requests_total` | Counter | RPC requests by method |
| `citrate_rpc_latency_seconds` | Histogram | RPC latency distribution |
| `citrate_ai_requests_total` | Counter | AI inference requests |

---

## 13. Dependencies

### Rust
- **Edition**: 2021
- **Async**: tokio 1.35
- **Serialization**: serde 1, bincode
- **EVM**: revm
- **Crypto**: ed25519-dalek, k256, sha3, ark-groth16 (ZK)
- **Storage**: rocksdb
- **Networking**: libp2p-compatible
- **Logging**: tracing

### Solidity
- **Compiler**: solc 0.8.36 (pinned; see `contracts/foundry.toml`)
- **EVM target**: Cancun
- **Framework**: Foundry (forge build/test/deploy)

### TypeScript (GUI)
- **Framework**: React 19.1 + Vite 5.4 + SWC
- **Desktop**: Slint 1.9 (Rust-native)
- **Blockchain**: ethers.js 6.15
- **Testing**: Vitest 3.2 + Testing Library

### Python
- **Version**: 3.8+
- **Web3**: web3.py 6.0, eth-account 0.9
- **Crypto**: cryptography 41.0
- **Simulation**: numpy, matplotlib
