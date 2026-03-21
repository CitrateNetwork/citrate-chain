# Formal Verification Specs

**Last verified**: 2026-03-21
**Update this file every time specs are re-run with TLC.**

## Overview

Citrate uses TLA+ formal verification to model-check critical protocol invariants before they reach production code. All specs are verified with the TLC model checker (part of the [TLA+ tools](https://github.com/tlaplus/tlaplus)).

| Category | Specs | Invariants | Status |
|----------|-------|------------|--------|
| Core protocol | 7 | 41 | All passing |
| GUI state machines | 5 | 37 | All passing |
| Model lifecycle | 1 | 7 | All passing |
| ZK proof pipeline | 2 | 15 | All passing |
| Agent safety & learning | 6 | 50 | All passing |
| Smart contracts | 3 | 28 | All passing |
| Security audit | 3 | 9 | All passing |
| **Total** | **27** | **187** | **All passing** |

## Core Protocol Specs (`specs/tla/`)

| Spec | Invariants | States | Description |
|------|-----------|--------|-------------|
| `GhostDAGConsensus` | 6 | — | DAG consensus: blue set, tip selection, finality |
| `MempoolSequencer` | 6 | — | Mempool admission, eviction, ordering |
| `VRFElection` | 6 | — | ECVRF proposer election, leader uniqueness |
| `VRFChainContinuity` | 5 | — | VRF output chaining across blocks, reorg safety |
| `TransactionExecution` | 5 | — | EVM tx execution: balance conservation, nonce monotonicity, gas limits |
| `PrevrandaoPipeline` | 8 | 204,535 | ECVRF→BlockContext→REVM→Solidity PREVRANDAO pipeline |
| `SDKConnectionLifecycle` | 5 | — | SDK connection state machine: retry, failover, request bounds |

## GUI State Machine Specs (`gui/citrate_gui_v2/specs/`)

| Spec | Invariants | States | Description |
|------|-----------|--------|-------------|
| `AuthStateMachine` | 7 | 23 | Auth/onboarding flow, session management |
| `WalletSession` | 9 | 14 | Wallet lock/unlock, failed attempts, timeout |
| `AgentChat` | 9 | 140 | Chat interface, tool approval, message ordering |
| `EnvironmentSwitch` | 6 | 84 | Network switching (devnet/testnet/mainnet) |
| `OnboardingFlow` | 6 | — | Step sequencing, model-ready gates, auth branch consistency |

## Model Lifecycle Specs (`specs/tla/`)

| Spec | Invariants | States | Description |
|------|-----------|--------|-------------|
| `ModelLifecycle` | 7 | — | Model registration, download-before-use, CID-before-registration |

## ZK Proof Specs (`specs/tla/`)

| Spec | Invariants | States | Description |
|------|-----------|--------|-------------|
| `ZKProofLifecycle` | 8 | — | ZK proof generation/verification state machine |
| `ZKKeyManagement` | 7 | — | Key setup phases with atomic rollback |

## Agent Safety & Learning Specs (`specs/tla/`)

| Spec | Invariants | States | Description |
|------|-----------|--------|-------------|
| `BelnapLattice` | 14 | — | Four-valued Belnap logic exhaustive verification (all lattice axioms) |
| `SafetyInvariant` | 7 | — | Theorem 3: learning never affects consensus state root |
| `OODACycle` | 7 | — | OODA learning phase cycle, timeout enforcement |
| `AdapterProvenance` | 7 | — | LoRA adapter provenance chain integrity, hash determinism |
| `ByzantineDetection` | 8 | — | Participant lifecycle, flag history, readmission gating |
| `ParaconsistentAggregation` | 7 | — | Dual-output aggregation with Belnap lattice join |

## Smart Contract Specs (`specs/tla/`)

| Spec | Invariants | States | Description |
|------|-----------|--------|-------------|
| `TrustScoring` | 9 | — | AgentDecisionRegistry trust scoring, tier correctness, dispute resolution |
| `SpecRegistryLifecycle` | 8 | — | Domain registration, governor authority, version monotonicity |
| `InferenceRequestLifecycle` | 11 | — | Request state machine, payment atomicity, provider registration |

## Security Audit Specs (`.agentile/audits/`)

| Spec | Invariants | States | Description |
|------|-----------|--------|-------------|
| `CheckpointSafety` | 3 | — | BFT checkpoint quorum validation |
| `BridgeAttestationSafety` | 4 | — | Bridge oracle threshold and duplicate prevention |
| `AgentToolAuthorization` | 2 | — | High-risk tool approval gating |

## Running the Specs

### Prerequisites

- Java 11+ (for TLC model checker)
- TLA+ tools: download `tla2tools.jar` from [GitHub releases](https://github.com/tlaplus/tlaplus/releases)

### Run all core specs

```bash
cd specs/tla/
TLA2TOOLS=/path/to/tla2tools.jar ./run_all.sh
```

### Run all GUI specs

```bash
cd gui/citrate_gui_v2/specs/
TLA2TOOLS=/path/to/tla2tools.jar ./run_all.sh
```

### Run a single spec

```bash
java -jar tla2tools.jar -config VRFElection.cfg VRFElection.tla
```

## Adding New Specs

1. Create `NewSpec.tla` with `MODULE NewSpec`
2. Create `NewSpec.cfg` with CONSTANTS, SPECIFICATION, and INVARIANTS
3. Add to the relevant `run_all.sh`
4. Run TLC and verify 0 violations
5. **Update this README** with the new spec's invariant count and state count

## Invariant Categories

| Category | Count | Examples |
|----------|-------|---------|
| Type invariants | 10 | Well-formed state, domain constraints |
| Safety properties | 22 | Balance conservation, no negative balances, nonce monotonicity |
| Liveness/bounds | 14 | Retry bounded, pending bounded, gas limit respected |
| Determinism | 8 | Same inputs → same outputs (VRF, execution, leader) |
| Protocol rules | 10 | No RPC when disconnected, unlock requires session, VRF chain valid |

## Dependency Audit

See `DEPENDENCY_AUDIT.md` for the latest `cargo audit` results. Last run: 2026-03-15.

- 2 advisories (both low-risk, blocked by toolchain/ecosystem constraints)
- 0 critical/high vulnerabilities
- 31 warnings (unmaintained transitive deps, no security impact)

## E2E Test Coverage

See `gui/citrate_gui_v2/E2E_TEST_REPORT.md` for Playwright E2E test assessment.

- 44 E2E tests across 6 spec files
- All mock Tauri IPC (no running devnet needed)
- Ready for CI integration
