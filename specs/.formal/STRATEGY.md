# TLA+ Formal Verification Strategy

**Date**: 2026-03-14
**Status**: Active — Phase 1 Complete, Phases 2-5 Planned

---

## Executive Summary

Citrate's formal verification suite currently covers **6 TLA+ specifications** verifying **27 invariants** across **31.3M states**. This strategy document defines the roadmap to achieve comprehensive formal verification coverage across all critical subsystems: consensus, execution, networking, GUI state machines, SDKs, CLI, explorer, faucet, and smart contracts.

**Goal**: Every safety-critical state machine in Citrate has a corresponding TLA+ specification with model-checked invariants, integrated into CI via `.github/workflows/tla-check.yml`.

---

## Verification Principles

### 1. Risk-Based Prioritization
Specifications are prioritized by **blast radius** (how many users/funds are affected) and **complexity** (number of concurrent state transitions):

| Priority | Blast Radius | Examples |
|----------|-------------|----------|
| **P0 — Critical** | Loss of funds, consensus divergence | DAG ordering, VRF election, bridge attestation, transaction execution |
| **P1 — High** | State corruption, denial of service | Mempool sequencing, checkpoint finality, state sync, pruning |
| **P2 — Medium** | UX degradation, data inconsistency | GUI state machines, SDK connection lifecycle, auth flows |
| **P3 — Low** | Cosmetic, non-blocking | Explorer rendering, marketing site, documentation |

### 2. Specification Scope
Each TLA+ spec must:
- Model the **minimal** state machine that captures the safety property
- Define **TypeInv** as baseline (all variables in declared domains)
- Define at least one **domain-specific safety invariant**
- Use constants small enough for exhaustive TLC exploration (<100M states)
- Include a `.cfg` file with concrete model parameters

### 3. Invariant Categories
Every spec should verify invariants from these categories where applicable:

| Category | Description | Example |
|----------|-------------|---------|
| **Type Safety** | Variables within declared domains | `TypeInv` |
| **No Duplication** | Unique identifiers, no double-spend | `NoDuplicateHashes` |
| **Ordering** | Monotonicity, causality, happens-before | `BlueScoreMonotonicity` |
| **Capacity** | Resource bounds respected | `CapacityRespected` |
| **Authorization** | Access control enforced | `NoHighRiskWithoutApproval` |
| **Liveness** | Progress eventually made | `EventualFinality` (temporal) |
| **Consistency** | Replicas agree | `NoFork`, `ConsensusAgreement` |

---

## Phase Roadmap

### Phase 1: Core Protocol (COMPLETE)

**Status**: 6/6 specs passing, 27 invariants verified

| Spec | Location | Invariants | States |
|------|----------|-----------|--------|
| GhostDAGConsensus | `specs/tla/` | 6 | 115 |
| MempoolSequencer | `specs/tla/` | 6 | 31.1M |
| VRFElection | `specs/tla/` | 6 | 119K |
| CheckpointSafety | `.audit/.../tla/` | 3 | 234 |
| BridgeAttestationSafety | `.audit/.../tla/` | 4 | 41K |
| AgentToolAuthorization | `.audit/.../tla/` | 2 | 5.8K |

### Phase 2: Consensus Upgrades & Execution (Target: Sprint Z+1)

New specs needed for features being built or planned:

| Spec | Purpose | Priority | Est. Invariants |
|------|---------|----------|----------------|
| **VRFPrevrandaoPipeline** | End-to-end VRF→PREVRANDAO data flow | P0 | 5 |
| **ParaconsensusClassification** | Belnap 4-valued logic, φ classification | P0 | 6 |
| **DualOutputAggregation** | Traditional + paraconsistent aggregation merge | P0 | 4 |
| **TransactionExecution** | EVM execution state transitions, gas accounting | P0 | 5 |
| **StateSync** | State synchronization between peers | P1 | 4 |
| **BlockPropagation** | P2P block/tx relay, duplicate suppression | P1 | 3 |
| **PruningStrategy** | DAG pruning without losing finalized state | P1 | 3 |
| **RewardDistribution** | Block rewards, fee distribution correctness | P1 | 4 |

**Key invariants to verify**:
- VRF output chains correctly (each block's alpha includes parent VRF output)
- Paraconsensus φ values are monotonic under aggregation
- Transaction execution is deterministic (same input → same state root)
- State sync converges (no permanent fork)
- Pruning never removes blocks referenced by non-finalized tips

### Phase 3: GUI State Machines (Target: Sprint Z+2)

Four TLA+ specs exist but lack `.cfg` files and have never been model-checked:

| Spec | Location | Status | Action Needed |
|------|----------|--------|--------------|
| **AuthStateMachine** | `gui/.../specs/` | Spec only | Create .cfg, run TLC, add to CI |
| **WalletSession** | `gui/.../specs/` | Spec only | Create .cfg, run TLC, add to CI |
| **AgentChat** | `gui/.../specs/` | Spec only | Create .cfg, run TLC, add to CI |
| **EnvironmentSwitch** | `gui/.../specs/` | Spec only | Create .cfg, run TLC, add to CI |

**New GUI specs needed**:

| Spec | Purpose | Priority |
|------|---------|----------|
| **OnboardingFlow** | 12-step onboarding state machine | P2 |
| **NodeLifecycle** | Start/stop/restart embedded node states | P1 |
| **TransactionSubmission** | GUI tx signing → RPC submission → confirmation | P1 |
| **IPCBridge** | Tauri IPC message ordering and error recovery | P2 |

**Key GUI invariants**:
- Auth state machine: no wallet access without valid authentication
- Wallet session: no transaction signing when session expired
- Environment switch: no requests sent to wrong network during switch
- Onboarding: cannot skip required steps, cannot regress to completed steps
- Node lifecycle: no orphaned processes after crash recovery

### Phase 4: SDK & Client State Machines (Target: Sprint Z+3)

| Spec | SDK | Purpose | Priority |
|------|-----|---------|----------|
| **SDKConnectionLifecycle** | JS/Python | Connect → authenticate → ready → disconnect | P1 |
| **SDKTransactionLifecycle** | JS/Python | Create → sign → submit → poll → confirm/fail | P1 |
| **SDKRetryPolicy** | JS/Python | Retry with backoff, idempotency guarantees | P2 |
| **WalletCLIFlow** | CLI wallet | Key generation → signing → submission | P1 |
| **FaucetRateLimiting** | Faucet | Request rate limiting, balance checking | P2 |
| **ExplorerDataConsistency** | Explorer | Block/tx data consistency with RPC source | P3 |

**Key SDK invariants**:
- No transaction submitted without valid signature
- Retry logic never double-submits (idempotency)
- Connection state machine: no RPC calls in disconnected state
- Faucet: per-address rate limits enforced, balance never goes negative
- Explorer: displayed data matches RPC source of truth

### Phase 5: Smart Contract Verification (Target: Sprint Z+4)

| Spec | Purpose | Priority |
|------|---------|----------|
| **ModelNFTOwnership** | ERC-721 ownership transfer correctness | P1 |
| **TokenEconomics** | SALT minting/burning/transfer invariants | P0 |
| **MarketplaceEscrow** | Escrow lock/release/refund state machine | P0 |
| **GovernanceVoting** | Vote counting, quorum, timelock | P1 |

**Note**: Solidity-level verification may use a combination of TLA+ (for protocol-level properties) and Foundry formal verification (for implementation-level properties via `forge test --ffi`).

---

## CI Integration

### Current: `.github/workflows/tla-check.yml`
- Runs `specs/tla/run_all.sh` on every PR touching `.tla` or `.cfg` files
- Uses OpenJDK 17 + tla2tools.jar
- Fails PR if any invariant violation detected

### Target: Extended CI Pipeline
```yaml
# Trigger on TLA+ file changes
on:
  pull_request:
    paths:
      - 'citrate_v0.01.1/specs/tla/**'
      - 'citrate_v0.01.1/gui/citrate_gui_v2/specs/**'
      - '.audit/**/tla/**'

jobs:
  tla-verify:
    steps:
      - run: specs/tla/run_all.sh          # Core protocol specs
      - run: gui/citrate_gui_v2/specs/run_all.sh  # GUI specs
      - run: .audit/.../tla/run_all.sh      # Security audit specs
```

### Verification Metrics Dashboard
Track these metrics over time:
- Total specifications count
- Total invariants verified
- Total states explored
- Maximum search depth
- Violations found (should always be 0)
- Time to verify (should remain <5 min for CI)

---

## Specification Writing Guidelines

### Template for New Specs
```tla+
--------------------------- MODULE SpecName ----------------------------
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS Param1, Param2, ...

ASSUME Param1 # {}
ASSUME Param2 \in Nat

VARIABLES var1, var2, ...

TypeInv ==
    /\ var1 \in SomeSet
    /\ var2 \subseteq AnotherSet

Init ==
    /\ var1 = InitialValue
    /\ var2 = {}

Action1(param) ==
    /\ precondition
    /\ var1' = newValue
    /\ UNCHANGED <<var2>>

Next ==
    (\E p \in Param1 : Action1(p))
    \/ Action2
    \/ ...

\* Safety Invariants
SafetyProperty1 == \A x \in var1 : SomeCondition(x)
SafetyProperty2 == Cardinality(var2) <= MaxSize

Spec == Init /\ [][Next]_<<var1, var2>>

THEOREM Safety1 == Spec => []TypeInv
THEOREM Safety2 == Spec => []SafetyProperty1
=============================================================================
```

### Common Pitfalls (Learned from Phase 1)
1. **String literals vs model values**: Use CONSTANTS, not `"string"` literals
2. **Nested `\E` scoping**: Always parenthesize disjuncts in `Next` to avoid multiply-defined variables
3. **Range overflow**: If an action increments a counter, ensure TypeInv range accommodates `MaxValue + 1`
4. **macOS grep**: Use `grep -o` (POSIX), not `grep -oP` (GNU-only)
5. **State space explosion**: Keep constant sets small (3-5 elements), reduce cross-products

---

## Success Criteria

| Milestone | Target | Metric |
|-----------|--------|--------|
| Phase 1 Complete | Done | 6 specs, 27 invariants, 0 violations |
| Phase 2 Complete | Sprint Z+1 | 14+ specs, 60+ invariants |
| Phase 3 Complete | Sprint Z+2 | 18+ specs, 75+ invariants |
| Phase 4 Complete | Sprint Z+3 | 24+ specs, 95+ invariants |
| Phase 5 Complete | Sprint Z+4 | 28+ specs, 110+ invariants |
| Full Coverage | Sprint Z+5 | Every P0/P1 subsystem has a spec |

---

## References

- [TLA+ Hyperbook](https://lamport.azurewebsites.net/tla/hyperbook.html) — Leslie Lamport
- [Specifying Systems](https://lamport.azurewebsites.net/tla/book.html) — Leslie Lamport
- [TLC Model Checker](https://github.com/tlaplus/tlaplus)
- [AWS and TLA+](https://lamport.azurewebsites.net/tla/amazon-excerpt.html) — Amazon's use of TLA+ in production systems
- [Ethereum Consensus Spec](https://github.com/ethereum/consensus-specs) — Reference for VRF/RANDAO verification
- [RFC 9381](https://www.rfc-editor.org/rfc/rfc9381) — ECVRF-P256-SHA256 specification
