# TLA+ Formal Verification Strategy

**Date**: 2026-03-15
**Status**: Active — Phases 1-2 Complete, Phase 3 (GUI) Complete, Phases 4-5 Planned

---

## Executive Summary

Citrate's formal verification suite covers **14 TLA+ specifications** verifying **81 invariants** across **42.8M+ states**. Phases 1-3 are complete. This strategy document defines the roadmap for remaining phases.

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
| GhostDAGConsensus | `specs/tla/` | 6 | 86 |
| MempoolSequencer | `specs/tla/` | 6 | 10.5M |
| VRFElection | `specs/tla/` | 6 | 35K |
| CheckpointSafety | `.audit/.../tla/` | 3 | 90 |
| BridgeAttestationSafety | `.audit/.../tla/` | 4 | 8.1K |
| AgentToolAuthorization | `.audit/.../tla/` | 2 | 576 |

### Phase 2: Consensus Upgrades & Execution (COMPLETE)

**Status**: 4 new specs, 23 invariants verified

| Spec | Location | Invariants | States |
|------|----------|-----------|--------|
| VRFChainContinuity | `specs/tla/` | 5 | — |
| TransactionExecution | `specs/tla/` | 5 | — |
| SDKConnectionLifecycle | `specs/tla/` | 5 | — |
| PrevrandaoPipeline | `specs/tla/` | 8 | 204K |

### Phase 3: GUI State Machines (COMPLETE)

**Status**: 4 specs with .cfg files, model-checked, 31 invariants verified

| Spec | Location | Invariants | States |
|------|----------|-----------|--------|
| AuthStateMachine | `gui/.../specs/` | 7 | 23 |
| WalletSession | `gui/.../specs/` | 9 | 14 |
| AgentChat | `gui/.../specs/` | 9 | 140 |
| EnvironmentSwitch | `gui/.../specs/` | 6 | 84 |

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
| Phase 2 Complete | Done | 10 specs, 50 invariants, 0 violations |
| Phase 3 Complete | Done | 14 specs, 81 invariants, 0 violations |
| Phase 4 Complete | Future | 20+ specs, 100+ invariants |
| Phase 5 Complete | Future | 24+ specs, 115+ invariants |
| Full Coverage | Future | Every P0/P1 subsystem has a spec |

---

## References

- [TLA+ Hyperbook](https://lamport.azurewebsites.net/tla/hyperbook.html) — Leslie Lamport
- [Specifying Systems](https://lamport.azurewebsites.net/tla/book.html) — Leslie Lamport
- [TLC Model Checker](https://github.com/tlaplus/tlaplus)
- [AWS and TLA+](https://lamport.azurewebsites.net/tla/amazon-excerpt.html) — Amazon's use of TLA+ in production systems
- [Ethereum Consensus Spec](https://github.com/ethereum/consensus-specs) — Reference for VRF/RANDAO verification
- [RFC 9381](https://www.rfc-editor.org/rfc/rfc9381) — ECVRF-P256-SHA256 specification
