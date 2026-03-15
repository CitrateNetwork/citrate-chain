# Formal Verification Coverage Matrix

**Date**: 2026-03-14
**Purpose**: Map every Citrate subsystem to its formal verification status, existing tests, and planned TLA+ specifications.

---

## Coverage Legend

| Symbol | Meaning |
|--------|---------|
| :white_check_mark: | TLA+ spec exists, model-checked, invariants verified |
| :yellow_circle: | TLA+ spec exists, not yet model-checked (no .cfg) |
| :red_circle: | No TLA+ spec, needs one (P0/P1 risk) |
| :black_circle: | No TLA+ spec needed (P3 risk or covered by tests) |
| **Bold** | Critical path — blocks testnet/mainnet |

---

## Core Protocol Layer (~90K LOC Rust)

| Subsystem | LOC | Unit Tests | Panic/Unwrap | TLA+ Status | Spec Name | Invariants | States | Phase |
|-----------|-----|-----------|--------------|-------------|-----------|-----------|--------|-------|
| **GhostDAG Consensus** | 6,862 | 22 | 182 | :white_check_mark: | GhostDAGConsensus | 6 | 115 | 1 (Done) |
| **Mempool Sequencer** | 3,679 | 0 | 86 | :white_check_mark: | MempoolSequencer | 6 | 31.1M | 1 (Done) |
| **VRF Election** | (in consensus) | — | — | :white_check_mark: | VRFElection | 6 | 119K | 1 (Done) |
| **Checkpoint Finality** | (in consensus) | — | — | :white_check_mark: | CheckpointSafety | 3 | 234 | 1 (Done) |
| **Bridge Attestation** | 2,806 | 39 | 51 | :white_check_mark: | BridgeAttestationSafety | 4 | 41K | 1 (Done) |
| **Agent Tool Auth** | (in GUI) | — | — | :white_check_mark: | AgentToolAuthorization | 2 | 5.8K | 1 (Done) |
| **VRF→PREVRANDAO Pipeline** | (producer+executor) | — | — | :red_circle: | VRFPrevrandaoPipeline | ~5 | — | 2 |
| **Transaction Execution** | 18,587 | 152 | 196 | :red_circle: | TransactionExecution | ~5 | — | 2 |
| **Paraconsensus (Belnap)** | 6,493 | 154 | 241 | :red_circle: | ParaconsensusClassification | ~6 | — | 2 |
| **Dual Output Aggregation** | (in learning) | — | — | :red_circle: | DualOutputAggregation | ~4 | — | 2 |
| **State Sync** | (in network) | — | — | :red_circle: | StateSync | ~4 | — | 2 |
| **Block Propagation** | 6,136 | 10 | 63 | :red_circle: | BlockPropagation | ~3 | — | 2 |
| **DAG Pruning** | (in storage) | — | — | :red_circle: | PruningSafety | ~3 | — | 2 |
| **Reward Distribution** | 4,246 | 40 | 32 | :red_circle: | RewardDistribution | ~4 | — | 2 |
| **State DB Concurrency** | 8,099 | 65 | 198 | :red_circle: | StateDatabaseConcurrency | ~3 | — | 2 |
| **VRF Chain Continuity** | (in producer) | — | — | :red_circle: | VRFChainContinuity | ~3 | — | 2 |
| **MCP Model Registry** | 3,939 | 61 | 79 | :black_circle: | — | — | — | — |
| **Marketplace Escrow** | 6,551 | 26 | 47 | :red_circle: | MarketplaceEscrow | ~4 | — | 5 |
| **API Rate Limiting** | 13,764 | 84 | 128 | :black_circle: | — | — | — | — |

---

## GUI Layer (~10K+ LOC TypeScript)

| Subsystem | Component | TLA+ Status | Spec Name | Invariants | Phase |
|-----------|-----------|-------------|-----------|-----------|-------|
| **Auth Flow** | AuthGate.tsx, core/auth.ts | :yellow_circle: | AuthStateMachine | ~3 | 3 |
| **Wallet Session** | WalletContext.tsx, walletService.ts | :yellow_circle: | WalletSession | ~3 | 3 |
| **Agent Chat** | ChatInterface.tsx, ChatContext.tsx | :yellow_circle: | AgentChat | ~3 | 3 |
| **Environment Switch** | EnvironmentContext.tsx | :yellow_circle: | EnvironmentSwitch | ~3 | 3 |
| **Onboarding Flow** | steps/*.tsx (12 steps) | :red_circle: | OnboardingStateMachine | ~3 | 3 |
| **Node Lifecycle** | NodeControl.tsx, block_producer.rs | :red_circle: | NodeLifecycle | ~3 | 3 |
| **Transaction Submission** | WalletContext → IPC → wallet_manager | :red_circle: | TransactionSubmission | ~3 | 3 |
| **IPC Bridge** | adapters/ipc.ts | :red_circle: | IPCBridge | ~2 | 3 |

---

## SDK & Client Layer

| Subsystem | LOC | Tests | TLA+ Status | Spec Name | Phase |
|-----------|-----|-------|-------------|-----------|-------|
| **JS SDK Connection** | ~1,500 | 248 | :red_circle: | SDKConnectionLifecycle | 4 |
| **JS SDK Transactions** | (in SDK) | — | :red_circle: | SDKTransactionLifecycle | 4 |
| **JS SDK Retry** | (in SDK) | — | :red_circle: | SDKRetryPolicy | 4 |
| **Python SDK** | ~1,500 | TBD | :red_circle: | PythonSDKLifecycle | 4 |
| **CLI Wallet** | 1,749 | 0 | :red_circle: | WalletCLIStateMachine | 4 |
| **Faucet** | TBD | 0 | :red_circle: | FaucetRateLimiting | 4 |
| **Explorer** | TBD | 0 | :black_circle: | — | — |

---

## Smart Contracts (Solidity)

| Contract | Tests | TLA+ Status | Spec Name | Phase |
|----------|-------|-------------|-----------|-------|
| **ModelNFT (ERC-721)** | 22 | :red_circle: | ModelNFTOwnership | 5 |
| **WrappedSALT (ERC-20)** | 14 | :red_circle: | TokenEconomics | 5 |
| **ModelMarketplace** | 17 | :red_circle: | MarketplaceEscrow | 5 |
| **InferenceRouter** | 7 | :black_circle: | — | — |
| **X402Facilitator** | 9 | :red_circle: | X402PaymentFlow | 5 |
| **IPFSIncentives** | 2 | :black_circle: | — | — |

---

## Aggregate Metrics

### Current State (Phase 1 Complete)

| Metric | Value |
|--------|-------|
| Total TLA+ specs | 6 |
| Specs model-checked | 6 |
| Specs with .cfg (runnable) | 6 |
| Specs without .cfg | 4 (GUI) |
| Total invariants verified | 27 |
| Total states explored | 31.3M |
| Violations found | 0 |

### Target State (All Phases Complete)

| Metric | Phase 1 | Phase 2 | Phase 3 | Phase 4 | Phase 5 | Total |
|--------|---------|---------|---------|---------|---------|-------|
| New specs | 6 | 8 | 8 | 6 | 4 | **32** |
| New invariants | 27 | ~35 | ~23 | ~18 | ~12 | **~115** |
| Cumulative specs | 6 | 14 | 22 | 28 | 32 | 32 |
| Cumulative invariants | 27 | ~62 | ~85 | ~103 | ~115 | ~115 |

---

## Risk-Weighted Coverage Gaps

### Top 10 Missing Specs by Risk

| Rank | Spec | Subsystem | Risk Level | Blast Radius | Effort |
|------|------|-----------|-----------|-------------|--------|
| 1 | TransactionExecution | Execution | CRITICAL | Fund loss | 8 pts |
| 2 | VRFChainContinuity | Consensus | CRITICAL | Consensus divergence | 8 pts |
| 3 | ParaconsensusClassification | Learning | CRITICAL | State corruption | 8 pts |
| 4 | StateDatabaseConcurrency | Storage | CRITICAL | Data corruption | 5 pts |
| 5 | MarketplaceEscrow | Marketplace | HIGH | Fund lock | 5 pts |
| 6 | WalletCLIStateMachine | Wallet | HIGH | Key loss | 3 pts |
| 7 | SDKTransactionLifecycle | SDK | HIGH | Double-submit | 5 pts |
| 8 | NodeLifecycle | GUI/Node | HIGH | Orphaned process | 3 pts |
| 9 | VRFPrevrandaoPipeline | Producer | HIGH | Zero randomness | 5 pts |
| 10 | FaucetRateLimiting | Faucet | MEDIUM | Token drain | 3 pts |

### Subsystems with Zero Formal Coverage

| Subsystem | LOC | Unit Tests | Why It Needs Coverage |
|-----------|-----|-----------|----------------------|
| Execution | 18,587 | 152 | 25 unsafe blocks, 196 unwraps, fund-handling |
| Storage | 8,099 | 65 | 57 TODOs, state persistence critical path |
| Network | 6,136 | 10 | P2P message ordering, eclipse attacks |
| Economics | 4,246 | 40 | Financial calculations, overflow risk |
| Wallet CLI | 1,749 | 0 | Key management, zero tests |
| Sequencer | 3,679 | 0 | Priority ordering, zero inline tests |
| Node | 7,650 | 0 | Block production orchestration |

---

## Testing Coverage Complement

TLA+ specs verify safety properties. This table shows what other testing exists per subsystem:

| Subsystem | TLA+ | Unit Tests | Integration | Fuzz | Property | E2E |
|-----------|------|-----------|-------------|------|----------|-----|
| Consensus | :white_check_mark: | 22 | Yes | No | No | Shell scripts |
| Execution | :red_circle: | 152 | Yes | 1 target | No | Shell scripts |
| Storage | :red_circle: | 65 | Yes | No | No | No |
| API | :black_circle: | 84 | Yes | 1 target | No | SDK tests |
| Network | :red_circle: | 10 | No | No | No | Shell scripts |
| Sequencer | :white_check_mark: | 0 | Yes | No | No | No |
| Bridge | :white_check_mark: | 39 | No | No | No | No |
| Learning | :red_circle: | 154 | No | No | Some | No |
| MCP | :black_circle: | 61 | No | No | No | No |
| Economics | :red_circle: | 40 | No | No | No | No |
| Marketplace | :red_circle: | 26 | No | No | No | No |
| GUI | :yellow_circle: | 464 | No | No | No | Playwright (configured) |
| JS SDK | :red_circle: | 248 | Yes | No | No | Yes |
| Python SDK | :red_circle: | TBD | TBD | No | No | No |
| Wallet CLI | :red_circle: | 0 | 1 file | No | No | No |
| Contracts | :red_circle: | 65 | No | No | No | No |
