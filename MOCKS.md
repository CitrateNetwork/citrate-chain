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
| 9 | `learning_join_classroom` | ClassroomRegistry.enrollWithInvite(address,bytes) via eth_sendTransaction (invite key plus the student's signed enrolment proof) | DONE |
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

### Merkle proof domain separators — closed in RM-I / WP-I1.8

The 2026-04-25 independent re-audit (Stream 3) caught a parity gap:

> **SOL-20 hardened the contract's Merkle proof with leaf and internal
> node domain separators (`keccak256(0x00 || leaf_bytes)` for leaves
> and `keccak256(0x01 || L || R)` for internal nodes) but the mock
> at `training-worker/src/chain.rs::verify_merkle_proof` (lines
> 688-706) still did plain sorted-pair concatenation without prefixes.**

**Closed**: RM-I / WP-I1.8 (commit landed 2026-04-26).

The mock's `verify_merkle_proof` now mirrors the contract's
`_verifyMerkleProof` exactly:
- Leaves: `keccak256(0x00 || leaf_bytes)` (`MERKLE_LEAF_PREFIX = 0x00`).
- Internal nodes: `keccak256(0x01 || min(L,R) || max(L,R))` (`MERKLE_INTERNAL_PREFIX = 0x01`).

Parity verified by three new tests in
`training-worker/src/chain.rs::tests`:
- `test_wp_i1_8_two_leaf_proof_verifies_with_prefixes` — a proof
  built with the contract's prefix scheme verifies in the mock.
- `test_wp_i1_8_unprefixed_proof_does_not_verify` — a proof built
  WITHOUT the prefixes is rejected (catches the pre-fix shape).
- `test_wp_i1_8_leaf_internal_collision_rejected` — the
  second-preimage attack the prefixes prevent (a leaf hash treated as
  a root by an attacker with no proof) is rejected.

The "byte-for-byte" claim is now accurate. Any future contract change
to the `_verifyMerkleProof` shape (different prefix bytes, different
sort order, etc.) requires a matching change here.

## Known Limitations (not mocks)

These are documented technical limitations, not mocks:

1. **`learning_get_students`**: Returns empty list because on-chain ClassroomRegistry uses a mapping (not iterable array) for enrollments. Full enumeration requires either an event indexer or a `getStudents(address)` view function. Tracked as a backlog item.

2. **`learning_get_earnings` time windows**: `today_earned` and `week_earned` return "0" because the on-chain ContributionAccounting stores cumulative totals, not time-windowed aggregates. Requires an off-chain indexer with block timestamp filtering. Tracked as a backlog item.

3. **`learning_get_classroom` whitelisted models**: Returns empty list for `whitelisted_models` because iterating an on-chain array requires a dedicated `getWhitelistedModels(address)` view function or event scanning. Tracked as a backlog item.

4. **`learning_get_cycle_status` time remaining**: `time_remaining_ms` returns 0 because the on-chain contract doesn't track phase durations. Requires off-chain phase-start timestamp tracking.

## UI-level synthetic data — none in active GUI (WP-P4-7 disclosure)

The 2026-03-26 internal-final audit (CIF-07) flagged that `MOCKS.md`'s "0 mocks remaining" claim only covered backend IPC mocks and missed UI-level synthetic data — specifically `generateMockPeers` in the retired Tauri/React `gui_v2/` PeerGraph component.

**Status at HEAD (verified 2026-05-06):**

- `citrate_v0.01.1/gui/citrate_gui_v2/` — **retired** (no source files, no CI build path, no workspace member). The `generateMockPeers` and `<PeerGraph peers={generateMockPeers(peers)} />` cited in the audit no longer exist. Same structural-by-replacement closure pattern as CIF-01, CIF-04, CIF-05, CIF-06.
- Active Slint apps (`citrate_gui_native/`, `citrate_learning_center/`, `citrate_edu_app/`, `citrate_desktop_app/`) — no UI-level synthetic peer generators or visualization mocks. Verified by:
  ```bash
  grep -rn "mock_peer\|MockPeer\|generate_mock\|MOCK_DATA\|synthetic_peer" citrate_v0.01.1/gui/
  ```
  returning zero hits.
- DAG / peer visualization in the Slint operator GUI uses real chain state from RPC + the P2P peer list — no synthetic data path.

**Distinction explicit (per CIF-07 recommended fix #2):**

| Layer | Mocks at HEAD |
|---|---|
| Backend contract-call IPC commands (LearningPool, ClassroomRegistry, etc.) | **0** — all 15 wired to real `eth_call`/`eth_sendTransaction` |
| UI-level synthetic visualization data (peer graphs, charts, dashboards) | **0** — Slint apps render real RPC + chain state |
| Trait-boundary backend substitutions (CM-07 training-worker S0) | **3 registered** — explicitly listed above with replacement WPs and gates per Rule 11 |
| AI API placeholder endpoints (CIF-08 scope) | **3 surfaces flagged** — see [`.agentile/audits/AI_ENDPOINT_INVENTORY_2026_05.md`](../.agentile/audits/AI_ENDPOINT_INVENTORY_2026_05.md) for the inventory |

If this distinction grows or shrinks, update this table; the four-row form is the canonical "claim-reality matrix" the audit's recommended fix #3 asked for, indexed alongside the assurance baseline.
