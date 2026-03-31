# TLA+ Formal Verification Suite (Local Subset)

**46 specifications | 6 domains | 0 violations**

This directory contains a **local subset** of Citrate's TLA+ formal verification suite. The canonical collection (84 specs) lives at `.agentile/formal/specs/`. This local subset is runnable in CI and covers the core protocol domains.

## Directory Structure

```
specs/tla/
├── README.md                      <- This file
├── consensus/                     6 specs — Core protocol
│   ├── GhostDAGConsensus.tla      DAG consensus: blue set, tip selection, acyclicity
│   ├── VRFElection.tla            ECVRF proposer election, leader uniqueness
│   ├── VRFChainContinuity.tla     VRF output chaining, reorg safety
│   ├── PrevrandaoPipeline.tla     ECVRF-to-BlockContext-to-REVM-to-Solidity
│   ├── MempoolSequencer.tla       Mempool admission, eviction, nonce ordering
│   └── TransactionExecution.tla   Balance conservation, nonce monotonicity, gas limits
│
├── zk/                            2 specs — Zero-knowledge proofs
│   ├── ZKProofLifecycle.tla       Proof generation, verification, on-chain settlement
│   └── ZKKeyManagement.tla        Key ceremony, Poseidon/MiMC parameter management
│
├── learning/                      11 specs — Learning Center & paraconsistent logic
│   ├── BelnapLattice.tla          Four-valued logic (T, F, Both, Neither) lattice
│   ├── OODACycle.tla              Observe-Orient-Decide-Act learning cycle
│   ├── SafetyInvariant.tla        Cross-cutting safety properties
│   ├── AdapterProvenance.tla      LoRA adapter provenance chain integrity
│   ├── ByzantineDetection.tla     Byzantine contributor detection
│   ├── ParaconsistentAggregation.tla  Paraconsistent knowledge aggregation
│   ├── LearningCycleLifecycle.tla Learning cycle state machine
│   ├── StrobilationCheckpoint.tla Checkpoint safety for learning state
│   ├── LearningPool.tla           Pool creation, contribution, aggregation
│   ├── MentorSelection.tla        Trust-based mentor assignment
│   └── LearningComputeIntegration.tla  Cross-domain (learning + compute) integration
│
├── contracts/                     7 specs — On-chain contract state machines
│   ├── TrustScoring.tla           Trust score bounded updates
│   ├── InferenceRequestLifecycle.tla  Inference request state machine
│   ├── SpecRegistryLifecycle.tla  Spec registration versioning
│   ├── NematocystSlashing.tla     No unjust slashing, appeal windows
│   ├── LiquidStaking.tla          stSALT minting/burning conservation
│   ├── ContributionAccounting.tla Contribution tracking accuracy
│   └── ClassroomRegistry.tla      Enrollment bounds, graduation
│
├── compute/                       7 specs — Compute marketplace
│   ├── ComputeMarketplaceLifecycle.tla  Job creation, matching, completion, payment
│   ├── ComputeVerification.tla    Challenge-response verification protocol
│   ├── ProviderLifecycle.tla      Provider registration, staking, heartbeat
│   ├── DisputeResolution.tla      Dispute opening, evidence, resolution
│   ├── HeartbeatLiveness.tla      Heartbeat monitoring, auto-slashing
│   ├── AdversarialCompute.tla     6 attack vectors, 17 invariants
│   └── ComputeE2E.tla            End-to-end compute flow integration
│
├── gui/                           3 specs — GUI & SDK state machines
│   ├── OnboardingFlow.tla         12-step onboarding state machine
│   ├── ModelLifecycle.tla         Model deploy-update-inference lifecycle
│   └── SDKConnectionLifecycle.tla Connection state machine, retry, failover
│
├── run_all.sh                     Run all local specs (standard, single worker)
├── run_all_27.sh                  Legacy runner for first 27 specs
├── run_deep.sh                    Deep verification (16 workers, 45-minute timeout)
└── tla2tools.jar                  TLC model checker binary
```

## Running the Specs

### Standard Run (CI)

```bash
bash run_all.sh
```

Runs all local specs with a single TLC worker. Takes approximately 5-8 minutes. Used in CI via `.github/workflows/tla-check.yml`. For the full canonical spec set (84 specs), see `.agentile/formal/specs/`.

### Deep Verification

```bash
bash run_deep.sh
```

Runs all specs with 16 TLC workers and a 45-minute timeout. This explores significantly more of the state space and is recommended before releases or after changes to safety-critical code.

### Single Spec

```bash
java -jar tla2tools.jar -config consensus/GhostDAGConsensus.cfg consensus/GhostDAGConsensus.tla
```

## Domain Summaries

### Consensus (6 specs)
Models the GhostDAG protocol including DAG construction, blue set calculation, VRF-based proposer election, VRF chain continuity across reorgs, mempool sequencing with nonce ordering, and transaction execution with balance conservation.

### ZK (2 specs)
Models the zero-knowledge proof lifecycle from generation through verification to on-chain settlement, including key ceremony safety for Poseidon and MiMC hash functions.

### Learning (11 specs)
Models the Learning Center's paraconsistent logic framework using Belnap's four-valued lattice (True, False, Both, Neither), OODA-based learning cycles, Byzantine contributor detection, and the integration between learning pools and compute resources.

### Contracts (7 specs)
Models on-chain contract state machines including trust scoring, inference request routing, specification registry versioning, liquid staking (stSALT), contribution accounting, classroom management, and the nematocyst slashing mechanism.

### Compute (7 specs)
Models the compute marketplace including job lifecycle, challenge-response verification, provider registration with heartbeat monitoring, dispute resolution, and adversarial attack vectors (Sybil, result manipulation, free-riding, escrow theft, collusion, griefing).

### GUI (3 specs)
Models GUI state machines including the 12-step onboarding flow, model deploy/inference lifecycle, and SDK connection management with retry and failover.

## Invariant Categories

Every spec includes `TypeInv` (type safety) plus domain-specific invariants:

| Category | Example Invariant | Specs Using It |
|----------|-------------------|---------------|
| Type Safety | `TypeInv` | All specs |
| No Duplication | `NoDuplicateHashes` | Mempool, VRF, Compute |
| Ordering | `BlueScoreMonotonicity` | GhostDAG, TX Execution |
| Capacity | `CapacityRespected` | Mempool, ComputePool |
| Authorization | `NoHighRiskWithoutApproval` | Onboarding, Agent |
| Economic Safety | `EscrowIntegrity` | Compute, Staking |
| Liveness | `HeartbeatEnforced` | HeartbeatLiveness |
| Adversarial | `SybilResistance` | AdversarialCompute |

## Related Documents

- [VERIFICATION_REPORT.md](../.formal/VERIFICATION_REPORT.md) -- Full results with state counts and timings
- [STRATEGY.md](../.formal/STRATEGY.md) -- Verification strategy and roadmap
- [COVERAGE_MATRIX.md](../.formal/COVERAGE_MATRIX.md) -- Coverage mapping to source code
- [EDGE_CASES.md](../.formal/EDGE_CASES.md) -- Edge cases and race conditions registry

## Adding a New Spec

1. Choose the correct domain directory (`consensus/`, `zk/`, `learning/`, `contracts/`, `compute/`, `gui/`)
2. Write the `.tla` file with `TypeInv` + domain invariants
3. Write a `.cfg` file with small-but-representative constants
4. Run TLC locally: `java -jar tla2tools.jar -config domain/Spec.cfg domain/Spec.tla`
5. Verify 0 violations
6. Add to `run_all.sh`
7. Update `../.formal/VERIFICATION_REPORT.md` and `../.formal/COVERAGE_MATRIX.md`
