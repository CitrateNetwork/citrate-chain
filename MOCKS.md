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

The `MockChainClient` enforces the same invariants as
`ComputePoolTraining.sol` (epoch monotonicity, coordinator-only
commitEpoch, challenge-window gate) — it IS a substitute backend,
not a behavior mock. A bug caught against it catches the same bug
against a live deployment. Per the CM-07/08 staged execution plan
§4 safe-mock criteria, these meet all four safety conditions.

## Known Limitations (not mocks)

These are documented technical limitations, not mocks:

1. **`learning_get_students`**: Returns empty list because on-chain ClassroomRegistry uses a mapping (not iterable array) for enrollments. Full enumeration requires either an event indexer or a `getStudents(address)` view function. Tracked as a backlog item.

2. **`learning_get_earnings` time windows**: `today_earned` and `week_earned` return "0" because the on-chain ContributionAccounting stores cumulative totals, not time-windowed aggregates. Requires an off-chain indexer with block timestamp filtering. Tracked as a backlog item.

3. **`learning_get_classroom` whitelisted models**: Returns empty list for `whitelisted_models` because iterating an on-chain array requires a dedicated `getWhitelistedModels(address)` view function or event scanning. Tracked as a backlog item.

4. **`learning_get_cycle_status` time remaining**: `time_remaining_ms` returns 0 because the on-chain contract doesn't track phase durations. Requires off-chain phase-start timestamp tracking.
