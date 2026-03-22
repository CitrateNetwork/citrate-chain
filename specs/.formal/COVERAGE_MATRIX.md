# Formal Verification Coverage Matrix

**Date**: 2026-03-22
**Purpose**: Map every Citrate subsystem to its formal verification status.

---

## Aggregate Metrics

| Metric | Value |
|--------|-------|
| Total TLA+ specs | 36 |
| Specs model-checked (with .cfg) | 36 |
| Total invariants verified | 200+ |
| Total states explored | 75M+ |
| Violations found | 0 |
| Domains | 6 |

| Domain | Specs | Location |
|--------|-------|----------|
| Consensus | 6 | `specs/tla/consensus/` |
| ZK | 2 | `specs/tla/zk/` |
| Learning | 11 | `specs/tla/learning/` |
| Contracts | 7 | `specs/tla/contracts/` |
| Compute | 7 | `specs/tla/compute/` |
| GUI | 3 | `specs/tla/gui/` |
| **Total** | **36** | |

Additional specs outside `specs/tla/`:
- 3 security audit specs in `.audit/.../tla/`
- 4 GUI state machine specs in `gui/citrate_gui_v2/specs/`

---

## Consensus Specs (`specs/tla/consensus/`)

| Spec | Source Code | Invariants | States | Description |
|------|-----------|-----------|--------|-------------|
| GhostDAGConsensus | `core/consensus/` | 6 | 86 | DAG consensus: blue set, tip selection, acyclicity |
| MempoolSequencer | `core/sequencer/` | 6 | 10.5M | Mempool admission, eviction, nonce ordering |
| VRFElection | `node/src/producer.rs` | 6 | 35K | ECVRF proposer election, leader uniqueness |
| VRFChainContinuity | `node/src/producer.rs` | 5 | — | VRF output chaining, reorg safety |
| TransactionExecution | `core/execution/` | 5 | — | Balance conservation, nonce monotonicity |
| PrevrandaoPipeline | `core/execution/`, `node/` | 8 | 204K | ECVRF-to-BlockContext-to-REVM pipeline |

## ZK Specs (`specs/tla/zk/`)

| Spec | Source Code | Description |
|------|-----------|-------------|
| ZKProofLifecycle | `core/execution/src/zkp/` | Proof generation, verification, on-chain settlement |
| ZKKeyManagement | `core/execution/src/zkp/` | Key ceremony, Poseidon/MiMC parameter management |

## Learning Specs (`specs/tla/learning/`)

| Spec | Source Code | Description |
|------|-----------|-------------|
| BelnapLattice | `core/learning/`, `contracts/src/LearningPool.sol` | Four-valued logic lattice properties |
| OODACycle | `core/learning/`, `contracts/src/LearningCycleManager.sol` | OODA learning cycle ordering |
| SafetyInvariant | `core/learning/` | Cross-cutting safety for learning subsystem |
| AdapterProvenance | `contracts/src/LoRAFactory.sol` | LoRA adapter chain integrity |
| ByzantineDetection | `core/learning/` | Byzantine contributor detection |
| ParaconsistentAggregation | `core/learning/`, `contracts/src/LearningPool.sol` | Paraconsistent knowledge aggregation |
| LearningCycleLifecycle | `contracts/src/LearningCycleManager.sol` | Cycle state machine completeness |
| StrobilationCheckpoint | `core/learning/` | Checkpoint safety for learning state |
| LearningPool | `contracts/src/LearningPool.sol` | Pool creation, contribution, aggregation |
| MentorSelection | `contracts/src/ClassroomRegistry.sol` | Mentor assignment trust-based selection |
| LearningComputeIntegration | Learning + Compute subsystems | Cross-domain integration correctness |

## Contract Specs (`specs/tla/contracts/`)

| Spec | Source Code | Description |
|------|-----------|-------------|
| TrustScoring | `contracts/src/` (trust logic) | Trust score bounded updates |
| InferenceRequestLifecycle | `contracts/src/InferenceRouter.sol` | Inference request state machine |
| SpecRegistryLifecycle | `contracts/src/SpecRegistry.sol` | Spec registration versioning |
| NematocystSlashing | `contracts/src/NematocystSlashing.sol` | No unjust slashing, appeal windows |
| LiquidStaking | `contracts/src/LiquidStakingPool.sol` | stSALT minting/burning conservation |
| ContributionAccounting | `contracts/src/ContributionAccounting.sol` | Contribution tracking accuracy |
| ClassroomRegistry | `contracts/src/ClassroomRegistry.sol` | Enrollment bounds, graduation |

## Compute Specs (`specs/tla/compute/`)

| Spec | Source Code | Description |
|------|-----------|-------------|
| ComputeMarketplaceLifecycle | `contracts/src/ComputeMarketplace.sol` | Job creation, matching, completion, payment |
| ComputeVerification | `contracts/src/ComputeVerifier.sol` | Challenge-response verification |
| ProviderLifecycle | `contracts/src/ComputeMarketplace.sol` | Provider registration, staking |
| DisputeResolution | `contracts/src/DisputeResolution.sol` | Dispute opening, evidence, resolution |
| HeartbeatLiveness | `contracts/src/HeartbeatMonitor.sol` | Heartbeat monitoring, auto-slashing |
| AdversarialCompute | All compute contracts | 6 attack vectors, 17 invariants |
| ComputeE2E | All compute contracts | End-to-end integration |

## GUI Specs (`specs/tla/gui/`)

| Spec | Source Code | Description |
|------|-----------|-------------|
| OnboardingFlow | `gui/citrate_gui_v2/src/features/onboarding/` | 12-step onboarding state machine |
| ModelLifecycle | `gui/citrate_gui_v2/src/features/models/` | Model deploy-update-inference |
| SDKConnectionLifecycle | `sdk/javascript/src/sdk.ts` | Connection state machine, retry, failover |

---

## Subsystem Coverage

| Subsystem | TLA+ Specs | Unit Tests | Integration | Fuzz | Forge Tests |
|-----------|-----------|-----------|-------------|------|-------------|
| Consensus | 6 specs | 87 | Yes | Yes | — |
| Execution | 2 specs | 342 | Yes | Yes | — |
| Storage | — | 65 | Yes | Yes | — |
| API | — | 84 | Yes | Yes | — |
| Network | — | 10 | No | No | — |
| Sequencer | 1 spec | 73 | Yes | No | — |
| Bridge | — | 39 | No | No | — |
| Learning | 11 specs | 154 | No | Some | Yes |
| ZK | 2 specs | 50+ | No | No | — |
| MCP | — | 61 | No | No | — |
| Economics | — | 66 | No | No | — |
| Marketplace | — | 26 | No | No | — |
| Compute | 7 specs | — | Yes | Yes | 67 |
| GUI | 3 specs (+ 4 in gui/specs/) | 596 | No | No | — |
| JS SDK | 1 spec | 248 | Yes | No | — |
| Contracts | 7 specs | — | — | — | 133+ |
| Wallet CLI | — | 68 | Yes | No | — |
| Faucet | — | 12 | No | No | — |
| CLI | — | 42 | No | No | — |

---

## Remaining Gaps (by risk)

| Subsystem | Risk | Reason | Status |
|-----------|------|--------|--------|
| Storage concurrency | HIGH | State DB read/write races | Covered by unit tests + fuzz |
| Network propagation | MEDIUM | P2P message ordering | Covered by chaos tests |
| Economics rewards | MEDIUM | Overflow risk in calculations | Covered by 66 unit tests |
| Token economics | HIGH | Minting/burning invariants | Planned for Phase 7 |
| Governance | MEDIUM | Vote counting correctness | Planned for Phase 7 |
| State sync | HIGH | Sync correctness under partition | Planned for Phase 7 |

---

*Last updated: 2026-03-22*
