# Active Mocks — Must Be Replaced

**Mock budget: 0 for new code. This file tracks existing debt being eliminated.**

When this file is empty, delete it. Zero mocks = no file needed.

**Background:** See `.agentile/docs/case_studies/MOCK_PERSISTENCE.md` for why this registry exists.

---

## Completed (wired to real contract calls)

All 15 learning IPC commands have been wired to real contract calls via `ContractCaller` + `NodeManager::eth_call`. Each command now:
- Checks if the target contract is deployed (returns empty/error if not)
- Encodes the ABI call using `contract_caller.rs` infrastructure
- Decodes the on-chain response into typed Rust structs
- Returns empty/default state (not fake data) when contracts are unavailable

| # | IPC Command | Data Source | Status |
|---|-------------|-------------|--------|
| 1 | `learning_get_pools` | LearningPool.nextPoolId() + getPool(uint256) via eth_call | DONE |
| 2 | `learning_join_pool` | LearningPool.joinPool(uint256) via eth_sendTransaction | DONE |
| 3 | `learning_leave_pool` | LearningPool.leavePool(uint256) via eth_sendTransaction | DONE |
| 4 | `learning_create_pool` | LearningPool.createPool(string,string,uint8,uint256) via eth_sendTransaction | DONE |
| 5 | `learning_get_classroom` | ClassroomRegistry.classrooms(address) via eth_call | DONE |
| 6 | `learning_create_classroom` | ClassroomRegistry.createClassroom(string,uint256,bytes32) via eth_sendTransaction | DONE |
| 7 | `learning_get_students` | Requires event indexer for StudentEnrolled events | DONE (returns empty list — known limitation) |
| 8 | `learning_generate_invite_code` | ClassroomRegistry.rotateInviteCode(bytes32) via eth_sendTransaction | DONE |
| 9 | `learning_join_classroom` | ClassroomRegistry.enrollWithCode(bytes32) via eth_sendTransaction | DONE |
| 10 | `learning_add_whitelisted_model` | ClassroomRegistry.whitelistModel(bytes32) via eth_sendTransaction | DONE |
| 11 | `learning_remove_whitelisted_model` | ClassroomRegistry.removeModel(bytes32) via eth_sendTransaction | DONE |
| 12 | `learning_get_cycle_status` | LearningCycleManager.currentCycleId() + getCycleInfo(uint256) via eth_call | DONE |
| 13 | `learning_get_earnings` | ContributionAccounting.getScore(address) + contributions(address,uint8) via eth_call | DONE |
| 14 | `learning_get_model_catalog` | ModelRegistry.getModel(bytes32) via eth_call | DONE |
| 15 | `learning_start_training` | LoRAFactory.createAdapter(bytes32,string,uint256,uint256) via eth_sendTransaction | DONE |

**Total: 0 mocks remaining.**

## CM-07 training-worker substitute backends (registered S0 substitutions)

These are trait-abstracted backend swaps for Stage-0 development
work. Each is a substitute at a stable trait boundary, not a
disguised production fake. Production builds must NOT wire these
as defaults; they're selected explicitly in tests and the eventual
binary config only.

| Trait | S0 impl | Production impl | Replacement WP | Gate |
|-------|---------|-----------------|----------------|------|
| `ModelBackend` | `DeterministicTinyModel` | `TchGpuBackend` | CM-07 WP-07.2 S2 | GPU pledge available |
| `Transport` | `InProcessTransport` | `LibP2pTransport` | CM-07 WP-07.2 S1 | 3-machine LAN available |
| `ChainClient` | `MockChainClient` | `HttpChainClient` | CM-07 WP-07.2 S1 | Anvil sidecar / testnet RPC |

The `MockChainClient` enforces the following invariants from
`ComputePoolTraining.sol`, each with a parity test in
`training-worker/src/chain.rs::tests`:

| Invariant (contract) | Mock enforcement | Parity test |
|---------------------|------------------|-------------|
| `commitEpoch`: epoch monotonicity | `WrongEpoch` return | `epoch_monotonicity_enforced` |
| `commitEpoch`: coordinator-only | `NotCoordinator` return | `non_coordinator_cannot_commit_epoch` |
| `commitEpoch`: `root != bytes32(0)` (line 367) | `ZeroEpochRoot` return | `f4_commit_epoch_rejects_zero_root` |
| `finalize`: challenge window gate | `ChallengeWindowOpen` return | `full_lifecycle_on_mock` |
| `challengeStep`: `msg.value == CHALLENGE_BOND` (line 537) | `WrongChallengeBond` return | `f4_challenge_step_rejects_wrong_bond` |
| `challengeStep`: `step < stepsPerEpoch` (line 538) | `StepOutOfRange` return | `f4_challenge_step_rejects_step_out_of_range` |
| `challengeStep`: `epoch < epochCount` (line 539) | `ChallengeEpochOutOfRange` return | `f4_challenge_step_rejects_epoch_out_of_range` |

If the contract gains a new `require(...)` and this list isn't
updated, the mock drifts and a worker that passes against the
mock can surprise-fail against the live deployment. Each row is
the regression contract.

Pre-RM-G2.4 the `commitEpoch` zero-root check and all three
`challengeStep` checks were missing. Audit F-4 closed by adding
them along with the parity tests above. Per the CM-07/08 staged
execution plan §4 safe-mock criteria, the mock meets all four
safety conditions.

### Known parity gap — Merkle proof domain separators (RM-I / WP-I1.8)

The 2026-04-25 independent re-audit (Stream 3) caught a parity gap not
listed in the table above:

> **SOL-20 hardened the contract's Merkle proof with leaf and internal
> node domain separators (`keccak256(0x00 || leaf_bytes)` for leaves
> and `keccak256(0x01 || L || R)` for internal nodes) but the mock at
> `training-worker/src/chain.rs::compute_merkle_root` (lines 688-706)
> still does plain sorted-pair concatenation without prefixes.**

A worker that generates a proof against the mock and submits it
on-chain will see the proof rejected: the contract recomputes the
root using prefixed hashes, the worker computed it without prefixes,
the roots disagree, and `verifyChallengeProof` fails.

This is the exact "byte-for-byte" claim the prior table implied but
that did NOT hold post-SOL-20. The status is **known gap**, scoped to
**RM-I WP-I1.8** for closure with a Foundry round-trip test
(`MockParityMerkleProof.t.sol::test_f_4_mock_merkle_proof_accepts_on_chain`)
that constructs a proof in the worker and asserts on-chain
acceptance.

Pending WP-I1.8 closure, downstream consumers should treat the
"parity" claim above as **invariant parity verified by the listed
tests**, not as a byte-for-byte equivalence over the full proof
construction. Any new contract `require(...)` added between now and
WP-I1.8 close needs an explicit row added to the table.

## Known Limitations (not mocks)

These are documented technical limitations, not mocks:

1. **`learning_get_students`**: Returns empty list because on-chain ClassroomRegistry uses a mapping (not iterable array) for enrollments. Full enumeration requires either an event indexer or a `getStudents(address)` view function. Tracked as a backlog item.

2. **`learning_get_earnings` time windows**: `today_earned` and `week_earned` return "0" because the on-chain ContributionAccounting stores cumulative totals, not time-windowed aggregates. Requires an off-chain indexer with block timestamp filtering. Tracked as a backlog item.

3. **`learning_get_classroom` whitelisted models**: Returns empty list for `whitelisted_models` because iterating an on-chain array requires a dedicated `getWhitelistedModels(address)` view function or event scanning. Tracked as a backlog item.

4. **`learning_get_cycle_status` time remaining**: `time_remaining_ms` returns 0 because the on-chain contract doesn't track phase durations. Requires off-chain phase-start timestamp tracking.
