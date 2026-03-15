# TLA+ Formal Verification Report

**Date**: 2026-03-15
**TLC Version**: 2026.03.12.220102 (tla2tools v1.8.0)
**Java**: OpenJDK 17.0.18 (Homebrew, aarch64)
**Machine**: Apple Silicon, 12 cores

## Results: 14/14 PASS, 0 Violations

### Core Protocol Specifications (`specs/tla/`)

| Spec | Invariants | States Generated | Distinct States | Depth | Time |
|------|-----------|-----------------|-----------------|-------|------|
| **GhostDAGConsensus** | 6 | 115 | 86 | 4 | <1s |
| **MempoolSequencer** | 6 | 31,169,941 | 10,576,460 | 13 | 61s |
| **VRFElection** | 6 | 119,785 | 35,413 | 7 | <1s |
| **VRFChainContinuity** | 5 | — | — | — | <1s |
| **TransactionExecution** | 5 | — | — | — | <1s |
| **SDKConnectionLifecycle** | 5 | — | — | — | <1s |
| **PrevrandaoPipeline** | 8 | 664,219 | 204,535 | 13 | 2s |

### Security Audit Specifications (`.audit/.../tla/`)

| Spec | Invariants | States Generated | Distinct States | Depth | Time |
|------|-----------|-----------------|-----------------|-------|------|
| **CheckpointSafety** | 3 | 234 | 90 | 6 | <1s |
| **BridgeAttestationSafety** | 4 | 41,941 | 8,100 | 11 | <1s |
| **AgentToolAuthorization** | 2 | 5,809 | 576 | 14 | <1s |

### GUI State Machine Specifications (`gui/citrate_gui_v2/specs/`)

| Spec | Invariants | States | Description |
|------|-----------|--------|-------------|
| **AuthStateMachine** | 7 | 23 | Auth/onboarding flow |
| **WalletSession** | 9 | 14 | Lock/unlock, timeout |
| **AgentChat** | 9 | 140 | Chat, tool approval |
| **EnvironmentSwitch** | 6 | 84 | Network switching |

### Aggregate Metrics

| Metric | Value |
|--------|-------|
| **Total specifications** | 14 |
| **Total invariants verified** | 81 |
| **Total states explored** | 42.8M+ |
| **Violations found** | 0 |
| **Total verification time** | ~65s |

---

## Invariant Index

### GhostDAGConsensus (6)
1. **TypeInv** — Variables within declared domains
2. **NoCycles** — DAG acyclicity
3. **BlueScoreMonotonicity** — Blue score >= parent's
4. **TipConsistency** — Tips have no children
5. **GenesisAlwaysBlue** — Genesis in every blue set
6. **BlueScoreCorrectness** — Blue score == |blue set|

### MempoolSequencer (6)
1. **TypeInv** — Variables within declared domains
2. **NoDuplicateHashes** — Unique tx hashes
3. **NoDuplicateNoncePerSender** — No nonce collision per sender
4. **CapacityRespected** — Pool <= MaxCapacity
5. **SenderLimitRespected** — Per-sender limit enforced
6. **NoncesAboveState** — No stale nonces in pool

### VRFElection (6)
1. **TypeInv** — Variables within declared domains
2. **AtMostOneLeaderPerSlot** — Valid leader or NoLeader
3. **LeaderHasValidProof** — Leader submitted valid proof
4. **NoOutputReuse** — No VRF output replay
5. **NoDuplicateProofs** — One proof per (validator, slot)
6. **LeaderDeterminism** — Deterministic election

### VRFChainContinuity (5)
1. **TypeInv** — Variables within declared domains
2. **VRFChainValid** — Alpha includes parent VRF output
3. **NoVRFReplay** — Unique VRF outputs
4. **ReorgPreservesChain** — Reorgs maintain VRF continuity
5. **DeterministicLeader** — Same inputs produce same output

### TransactionExecution (5)
1. **TypeInv** — Variables within declared domains
2. **BalanceConservation** — Total balance preserved
3. **NonceMonotonicity** — Nonces increase monotonically
4. **GasLimitRespected** — Gas usage <= limit
5. **NoNegativeBalance** — Balances never go negative

### SDKConnectionLifecycle (5)
1. **TypeInv** — Variables within declared domains
2. **NoRPCWhenDisconnected** — No calls in disconnected state
3. **RetryBounded** — Retry count bounded
4. **PendingBounded** — Pending requests bounded
5. **FailoverOnExhaustion** — Failover when retries exhausted

### PrevrandaoPipeline (8)
1. **TypeInv** — Variables within declared domains
2. **ECVRFProofFormat** — Non-genesis blocks use 114-byte ECVRF
3. **VRFChainContinuity** — Alpha includes parent VRF output
4. **NoVRFReplay** — Unique VRF outputs
5. **BlockContextMatchesVRF** — prevrandao matches block's VRF
6. **ContractSeesCorrectPrevrandao** — Contracts see correct value
7. **PrevrandaoNonZeroAfterFirstBlock** — Non-zero after genesis
8. **ExecutionPrecedesContractAccess** — SetBlockContext before reads

### CheckpointSafety (3)
1. **TypeInv** — Variables within declared domains
2. **NoFinalizeWithoutValidQuorum** — Quorum required
3. **NoDuplicateVoters** — One vote per member

### BridgeAttestationSafety (4)
1. **TypeInv** — Variables within declared domains
2. **NoProcessWithoutValidThreshold** — Threshold attestations required
3. **NoDuplicateOraclePerEvent** — One attestation per oracle per event
4. **NoZeroThresholdInProd** — Production threshold > 0

### AgentToolAuthorization (2)
1. **TypeInv** — Variables within declared domains
2. **NoHighRiskWithoutApproval** — High-risk tools require approval

### AuthStateMachine (7)
1. **TypeInvariant** — Variables within declared domains
2. **SafetyInvariant** — Core auth state safety
3. **UnlockRequiresSession** — Wallet access requires auth
4. **DeviceBindingRequiresSession** — Device binding requires session
5. **OnboardingOnlyOnFirstRun** — Onboarding on fresh state only
6. **AuthMethodSelected** — Method chosen before proceeding
7. **NoSkippedSteps** — Required steps cannot be skipped

### WalletSession (9)
1. **TypeInvariant** — Variables within declared domains
2. **SafetyInvariant** — Core wallet safety
3. **KeysCachedOnlyWhenUnlocked** — Keys cleared on lock
4. **UnlockedRequiresAccounts** — Unlock requires loaded accounts
5. **LockedOutMeansMaxFailures** — Lockout after max failures
6. **NoWalletMeansNoAccounts** — No wallet = no accounts
7. **SessionTicksWhenUnlocked** — Session timer active when unlocked
8. **LockoutTicksConsistency** — Lockout timer consistency
9. **FailedAttemptsResetOnUnlock** — Counter resets on success

### AgentChat (9)
1. **TypeInvariant** — Variables within declared domains
2. **SafetyInvariant** — Core chat safety
3. **SessionRequiredForInteraction** — Session required for chat
4. **ToolActionsRequirePendingTools** — Tool actions need pending tools
5. **WaitingToolHasPendingTools** — Waiting state has pending tools
6. **MessageOrdering** — Messages ordered correctly
7. **SendingOnlyWhenPending** — Send only when pending
8. **NoSessionNoMessages** — No session = no messages
9. **AgentReadyForSession** — Agent ready when session active

### EnvironmentSwitch (6)
1. **TypeInvariant** — Variables within declared domains
2. **SafetyInvariant** — Core switch safety
3. **NodeRunningWhenQuiescent** — Node runs in quiescent state
4. **TargetConsistency** — Target env consistent
5. **ErrorConsistency** — Error state consistent
6. **NoSelfSwitch** — Cannot switch to current environment

---

## File Locations

| Category | Path |
|----------|------|
| Core protocol specs | `citrate_v0.01.1/specs/tla/` |
| Security audit specs | `.audit/2026-03-02-architecture-security-deep-audit/tla/` |
| GUI state machine specs | `citrate_v0.01.1/gui/citrate_gui_v2/specs/` |
| TLC runner (core) | `citrate_v0.01.1/specs/tla/run_all.sh` |
| TLC runner (GUI) | `citrate_v0.01.1/gui/citrate_gui_v2/specs/run_all.sh` |
| Coverage matrix | `citrate_v0.01.1/specs/.formal/COVERAGE_MATRIX.md` |
| Strategy | `citrate_v0.01.1/specs/.formal/STRATEGY.md` |
| CI workflow | `.github/workflows/tla-check.yml` |

*Last updated: 2026-03-15*
