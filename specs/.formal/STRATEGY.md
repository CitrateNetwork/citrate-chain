# TLA+ Formal Verification Strategy

**Date**: 2026-03-22
**Status**: Active — Phases 1-6 Complete, Phase 7 (Mainnet Hardening) Planned

---

## Executive Summary

Citrate's formal verification suite covers **36 TLA+ specifications** organized into **6 domains**, verifying **200+ invariants** across **75M+ states**. Phases 1-6 are complete. This strategy document defines the roadmap, principles, and adversarial modeling approach.

**Goal**: Every safety-critical state machine in Citrate has a corresponding TLA+ specification with model-checked invariants, integrated into CI via `.github/workflows/tla-check.yml`.

---

## Verification Principles

### 1. Risk-Based Prioritization
Specifications are prioritized by **blast radius** (how many users/funds are affected) and **complexity** (number of concurrent state transitions):

| Priority | Blast Radius | Examples |
|----------|-------------|----------|
| **P0 — Critical** | Loss of funds, consensus divergence | DAG ordering, VRF election, bridge attestation, transaction execution, compute escrow |
| **P1 — High** | State corruption, denial of service | Mempool sequencing, checkpoint finality, slashing, dispute resolution |
| **P2 — Medium** | UX degradation, data inconsistency | GUI state machines, SDK connection lifecycle, learning cycles |
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
| **Economic Safety** | No funds lost, no unjust slashing | `NoUnjustSlashing`, `EscrowIntegrity` |

### 4. Adversarial Modeling Approach

Starting with the compute domain (Sprint COMPUTE-1), specifications explicitly model adversarial behavior:

| Attack Vector | Specs Modeling It | Key Invariants |
|---------------|-------------------|----------------|
| **Sybil Attack** | AdversarialCompute | Provider uniqueness, stake-weighted selection |
| **Result Manipulation** | ComputeVerification, AdversarialCompute | Challenge-response integrity |
| **Free-riding** | HeartbeatLiveness, ProviderLifecycle | Heartbeat enforcement, auto-slashing |
| **Escrow Theft** | ComputeMarketplaceLifecycle, DisputeResolution | Escrow release only on verified completion |
| **Collusion** | AdversarialCompute | Independent verification requirement |
| **Griefing** | DisputeResolution, AdversarialCompute | Dispute bond requirement, bounded resolution time |

### 5. Integration Specs

Integration specifications verify cross-domain interactions:

| Spec | Domains Connected | Key Property |
|------|-------------------|-------------|
| **LearningComputeIntegration** | Learning + Compute | Learning cycles correctly delegate compute jobs |
| **ComputeE2E** | Compute (all 5 contracts) | End-to-end flow from job creation to payment |
| **PrevrandaoPipeline** | Consensus + Execution | VRF output correctly flows to smart contracts |

---

## Phase Roadmap

### Phase 1: Core Protocol (COMPLETE)

**Status**: 6/6 specs, 27 invariants verified

| Spec | Location | Invariants | States |
|------|----------|-----------|--------|
| GhostDAGConsensus | `specs/tla/consensus/` | 6 | 86 |
| MempoolSequencer | `specs/tla/consensus/` | 6 | 10.5M |
| VRFElection | `specs/tla/consensus/` | 6 | 35K |
| CheckpointSafety | `.audit/.../tla/` | 3 | 90 |
| BridgeAttestationSafety | `.audit/.../tla/` | 4 | 8.1K |
| AgentToolAuthorization | `.audit/.../tla/` | 2 | 576 |

### Phase 2: Consensus Upgrades & Execution (COMPLETE)

**Status**: 4 new specs, 23 invariants verified

| Spec | Location | Invariants |
|------|----------|-----------|
| VRFChainContinuity | `specs/tla/consensus/` | 5 |
| TransactionExecution | `specs/tla/consensus/` | 5 |
| SDKConnectionLifecycle | `specs/tla/gui/` | 5 |
| PrevrandaoPipeline | `specs/tla/consensus/` | 8 |

### Phase 3: GUI State Machines (COMPLETE)

**Status**: 4 specs, 31 invariants verified

| Spec | Location | Invariants | States |
|------|----------|-----------|--------|
| AuthStateMachine | `gui/.../specs/` | 7 | 23 |
| WalletSession | `gui/.../specs/` | 9 | 14 |
| AgentChat | `gui/.../specs/` | 9 | 140 |
| EnvironmentSwitch | `gui/.../specs/` | 6 | 84 |

### Phase 4: ZK & Learning (COMPLETE)

**Status**: 13 new specs covering ZK proof systems and paraconsistent learning

| Domain | Specs Added | Key Properties |
|--------|------------|----------------|
| ZK (2) | ZKProofLifecycle, ZKKeyManagement | Proof validity, key ceremony safety |
| Learning (11) | BelnapLattice, OODACycle, SafetyInvariant, AdapterProvenance, ByzantineDetection, ParaconsistentAggregation, LearningCycleLifecycle, StrobilationCheckpoint, LearningPool, MentorSelection, LearningComputeIntegration | Lattice ordering, Byzantine tolerance, cycle completion |

### Phase 5: Contract State Machines (COMPLETE)

**Status**: 7 new specs for on-chain contract logic

| Spec | Key Property |
|------|-------------|
| TrustScoring | Trust scores bounded, monotonic under honest behavior |
| InferenceRequestLifecycle | Request state machine completeness |
| SpecRegistryLifecycle | Spec versioning integrity |
| NematocystSlashing | No unjust slashing, appeal window enforced |
| LiquidStaking | stSALT minting/burning conservation |
| ContributionAccounting | Contribution tracking accuracy |
| ClassroomRegistry | Enrollment bounds, graduation requirements |

### Phase 6: Compute Marketplace (COMPLETE)

**Status**: 7 new specs including adversarial modeling

| Spec | Key Property |
|------|-------------|
| ComputeMarketplaceLifecycle | Job state machine, escrow integrity |
| ComputeVerification | Challenge-response correctness |
| ProviderLifecycle | Stake requirements, registration safety |
| DisputeResolution | Dispute state machine, bounded resolution |
| HeartbeatLiveness | Heartbeat enforcement, auto-slashing |
| AdversarialCompute | 6 attack vectors, 17 invariants |
| ComputeE2E | End-to-end integration correctness |

### Phase 7: Mainnet Hardening (Target: Pre-Launch)

| Spec | Purpose | Priority |
|------|---------|----------|
| **TokenEconomics** | SALT minting/burning/transfer invariants | P0 |
| **GovernanceVoting** | Vote counting, quorum, timelock | P1 |
| **NetworkPartition** | Consensus safety under partition | P0 |
| **StateSync** | State synchronization correctness | P1 |
| **CrossDomainSettlement** | Multi-contract transaction atomicity | P1 |

---

## CI Integration

### Current: `.github/workflows/tla-check.yml`
- Runs `specs/tla/run_all.sh` on every PR touching `.tla` or `.cfg` files
- Uses OpenJDK 17 + tla2tools.jar
- Fails PR if any invariant violation detected

### Runners

| Script | Workers | Timeout | Purpose |
|--------|---------|---------|---------|
| `run_all.sh` | 1 | Standard | CI/quick verification |
| `run_all_27.sh` | 1 | Standard | Legacy 27-spec runner |
| `run_deep.sh` | 16 | 45 min | Deep verification, edge cases |

---

## Success Criteria

| Milestone | Target | Status |
|-----------|--------|--------|
| Phase 1 Complete | 6 specs, 27 invariants | DONE |
| Phase 2 Complete | 10 specs, 50 invariants | DONE |
| Phase 3 Complete | 14 specs, 81 invariants | DONE |
| Phase 4 Complete | 27 specs, 150+ invariants | DONE |
| Phase 5 Complete | 34 specs, 180+ invariants | DONE |
| Phase 6 Complete | 36 specs, 200+ invariants | DONE |
| Phase 7 Complete | 40+ specs, 230+ invariants | PLANNED |
| Full Coverage | Every P0/P1 subsystem has a spec | IN PROGRESS |

---

## References

- [TLA+ Hyperbook](https://lamport.azurewebsites.net/tla/hyperbook.html) -- Leslie Lamport
- [Specifying Systems](https://lamport.azurewebsites.net/tla/book.html) -- Leslie Lamport
- [TLC Model Checker](https://github.com/tlaplus/tlaplus)
- [AWS and TLA+](https://lamport.azurewebsites.net/tla/amazon-excerpt.html) -- Amazon's use of TLA+ in production systems
- [Ethereum Consensus Spec](https://github.com/ethereum/consensus-specs) -- Reference for VRF/RANDAO verification
- [RFC 9381](https://www.rfc-editor.org/rfc/rfc9381) -- ECVRF-P256-SHA256 specification
