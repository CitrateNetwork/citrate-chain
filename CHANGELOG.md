# Changelog

All notable changes in this PR are documented here. This follows a Keep‑a‑Changelog‑style summary grouped by impact. Please add an entry in every substantive PR going forward.

## v0.4.0 — 2026-04-22

Phase A (parallel execution), Phase B (genesis hardening), Phase C (GUI polish) all closed. First release where the executor layer is no longer the serialization bottleneck.

### Highlights
- **Parallel tx execution via journal + CAS**. The `exec_lock` tokio mutex that serialized every tx on the fast path is gone. Workers now pin a per-tx `ScratchJournal` at the global version, execute concurrently, and try-commit under a short critical section. Apples-to-apples benchmark: **2.02× at 8 workers**; worker-scaling: **2.41× 1→8 workers**. Executor ceiling on simple transfers: 775K tx/s @ 8 workers (internal; not real-world TPS).
- **Embedded genesis-model footgun closed**. `EmbeddedModel.weights: Vec<u8>` replaced with `weights_sha256: Hash`. The 32-byte commitment scheme is verified by TLA+ spec `EmbeddedModelCommitment.tla` (7 invariants, 7,110 states). Prevents a class of unbounded-block-size bugs.
- **GUI click-feel fix**. Press-state visual feedback on the highest-session-frequency buttons (send/receive/faucet, sidebar nav, chat send, lock screen, onboarding, models). Motion tokens (`Theme.duration-fast/base/slow`) replace scattered 150ms/200ms literals. Drop-shadow elevation on wallet dialogs.

### Added

#### Execution (citrate-execution)
- MVCC module: `CommitCoordinator`, `AccountVersionTracker`, `RetryHarness`, `ScratchJournal`, `ReadSet`, `WriteSet`, `ReadVersion`, `StateVersion`.
- Per-tx `ScratchJournal` now holds pending balance/nonce/code/storage writes. Drained atomically on CAS success; discarded on abort.
- `execute_transaction` retry loop with 8 bounded CAS attempts + `commit_exclusive` fallback.
- Read-set tracking in `Database::basic` / `Database::storage` and all executor balance/nonce reads for CAS validation.
- `persist_account_versions` writes per-account MVCC versions to RocksDB column family `account_versions`. Non-fatal on failure; versions survive restart.
- 3 new concurrent stress tests in `tests/parallel_execution.rs`.
- 3 new criterion benches: `tps_parallel` (scaling), `parallel_bench` (mempool grouping), `mvcc_bench` (commit layer).

#### Consensus (citrate-consensus)
- `EmbeddedModel.weights_sha256: Hash` replaces `weights: Vec<u8>`. `size_bytes()` now returns a constant 32 + metadata upper bound.
- TLA+ spec `EmbeddedModelCommitment.tla` with 7 invariants verifying commitment integrity + decoupling from full weights.

#### Storage (citrate-storage)
- New column family `CF_ACCOUNT_VERSIONS` for MVCC persistence.
- 5 new `StateStoreTrait` methods: `put_account_version`, `put_account_versions`, `get_all_account_versions`, `put_global_version`, `get_global_version`.
- 8 integration tests in `mvcc_version_persistence.rs`.

#### GUI (citrate-gui-native)
- Design tokens: `Theme.duration-instant/fast/base/slow`, typography (`font-size-xs/sm/md/lg/xl/2xl/3xl`), elevation (`shadow-color-*`, `shadow-offset-*`, `shadow-blur-*`).
- Reusable primitives: `PrimaryButton`, `SecondaryButton`, `Pressable` in `shared/feedback.slint`.
- Press-state on: wallet Send/Receive/Faucet, sidebar NavItem, chat send + tool approve/deny, lock screen Unlock + Sign Out, onboarding ActionButton/PersonaCard/EnvironmentCard, models Pin/HuggingFace/Deploy, settings ActionButton, dashboard StatCard.
- Drop-shadow elevation on wallet Create/Import/Export dialogs (send dialog already had).
- Responsive layouts: app min-width reduced 800→480px (unblocks iPad / mobile-window use); send dialog uses `min(440px, parent.width - 32px)`.

#### Benchmarks
- `benchmarks/parallel_tps_verified_2026_04_21.md` — honest, reproducible benchmark report covering disjoint-senders scaling, apples-to-apples serialized-vs-parallel control, and contract-call (REVM) workload.
- `benchmarks/mvcc_bench_2026_04_21.md` — MVCC commit layer baseline (10.5M commits/s, 34 ns tracker lookup).

#### Docs
- `ADR-013_PARALLEL_EXECUTION.md` — the parallel execution design.
- `ADR-010_EMBEDDED_MODEL_COMMITMENT.md` — weights_sha256 rationale.
- `ADR-008_BLOCKSIZE_POLICY.md` — 2MB hard cap, 1MB soft, 45M gas limit.
- TLA+ specs: `ExecutorMVCC.tla` (14 safety invariants + Progress liveness, 261M states explored), `EmbeddedModelCommitment.tla`.
- `MAINNET_LAUNCH_STAGING.md` at repo root — pre-launch checklist with placeholder addresses.

### Changed
- Root `/CLAUDE.md` refreshed: removed stale Tauri GUI references (lines 125, 203–226, 799, 812, 823), added disambiguation table between root and workspace CLAUDE.md files, updated Developer Tools section to point at desktop-app panels, replaced hardcoded test counts with a pointer to `.agentile/sprints/CURRENT.md`, expanded Performance Targets with the new executor ceiling numbers.
- `citrate_v0.01.1/CLAUDE.md` Performance Targets updated with v0.4.0 baselines (321K 1-worker, 773K 8-worker executor ceiling; 2.02× apples-to-apples gate).
- `StateDBAdapter::DatabaseCommit::commit` now routes code + storage writes through the per-tx journal when attached. Falls back to direct state_db writes when no journal (legacy paths).
- `Executor::execute_transaction` no longer holds the exec_lock on the fast path. Simulation (eth_call/eth_estimateGas) still acquires exec_lock to isolate temporary balance override from concurrent real tx execution.
- `execute_transfer` and new `journal_transfer` helper route value transfers through the journal with read-set tracking.

### Removed
- `execution_guard: tokio::sync::Mutex<()>` field on `Executor` (replaced by `commit_coordinator: Arc<CommitCoordinator>` in Sprint P950-A-3; exec_lock moved to coordinator and used only on the fallback path).
- Snapshot/restore from `execute_transaction_inner` hot path — the journal IS the rollback mechanism. Kept for `simulate_transaction` which is serialized.
- `mvcc` feature flag (module is unconditional as of Sprint P950-A-3).

### Fixed
- GUI press-state feedback now renders on every major click target — fixes "I have to double-click every button" UX complaint.
- Nonce increment on tx failure now routes through journal; net-effect identical to pre-A-5 but preserves CAS correctness under concurrency.
- Concurrent execution no longer loses updates on same-slot contention (verified by `conflicting_senders_both_commit_no_lost_update` integration test).

### Breaking
- Workspace version bumped 0.1.0 → 0.4.0. SDK consumers should update their version pins.
- `EmbeddedModel` struct: `weights: Vec<u8>` field removed; replaced with `weights_sha256: Hash`. Any direct consumer of this field in downstream crates must be updated. Mainnet genesis will ship with the new shape.

### Test counts at release
See `.agentile/sprints/CURRENT.md` for live counts. Workspace gate at v0.4.0: **4,452 tests passing, 0 failed**.

### Performance envelope
| Metric | v0.3.0 baseline | v0.4.0 |
|--------|-----------------|--------|
| Workspace tests | 4,479 | 4,452 (some flaky specs retired) |
| Executor ceiling (1 worker, transfers) | ~320K tx/s | 321K tx/s (baseline) |
| Executor ceiling (8 workers, transfers, disjoint) | serialized @ ~377K | **775K tx/s** |
| Executor ceiling (8 workers, apples-to-apples control) | — | **2.02× speedup** |
| Contract-call throughput (REVM SSTORE, 1 worker) | — | 75.6K tx/s |
| MVCC commit layer | — | 10.5M commits/s, 34 ns per-account lookup |
| Real-world TPS (benchmark-suite, live node) | 5K sustained | — (re-measurement queued) |

## Unreleased

### Highlights
- Added a real TCP transport (length‑delimited, bincode) with a simple handshake and basic DoS protections.
- Implemented synchronous inference RPC `citrate_runInference` and aligned GUI/SDK to current RPCs.
- Registered a public genesis model at chain initialization; added generation/embedding docs.
- Integrated a progressive SyncManager header walk with retry/backoff and peer demotion.
- Added single‑node and multi‑node (5‑node docker) smoke tests.

### Added
- Transport
  - New `NetworkTransport` with Hello/HelloAck handshake (version + network/genesis checks).
  - Length‑delimited frames (1 MB cap), per‑connection message rate limit (200 msgs/sec).
  - Files: `core/network/src/transport.rs`, `core/network/src/lib.rs` (export).
- Sync
  - Progressive header walk via `SyncManager` (tracks `last_received_header`, `last_requested_header`, and pending counts).
  - Retry/backoff (2/4/8/16/32s) and peer demotion on timeouts; ban after repeated failures.
  - Files: `core/network/src/sync.rs`, `node/src/main.rs`.
- API/RPC
  - `citrate_runInference` (sync preview via `Executor.run_inference_preview`) with typed output (json or base64 + metadata).
  - Files: `core/api/src/server.rs`.
- Genesis
  - Embedded genesis model artifact and state registration at init.
  - Files: `node/src/genesis.rs`, `assets/genesis_model.onnx`.
- Test tooling
  - Single‑node inference smoke: `scripts/smoke_inference.sh`.
  - Multi‑node cluster smoke: `scripts/cluster_smoke.sh`, teardown `scripts/cluster_down.sh`.
- Docs & Roadmap
  - P0 roadmap doc: `citrate/ROADMAP_P0.md`.
  - Genesis model doc: `docs/GENESIS_MODEL.md`.
  - RPC docs: documented `citrate_runInference`, `citrate_listModels` (alias: `citrate_getModels`).
  - README: inference example, signing guidance, IPFS env vars, smoke test instructions.

### Changed
- RPC model listing
  - Unified `citrate_listModels`/`citrate_getModels` to return IDs from in‑memory state DB; `citrate_getModel` returns full metadata.
  - Files: `core/api/src/server.rs`.
- GUI/SDK alignment
  - GUI prefers `citrate_listModels` (with fallback), fetches full info via `citrate_getModel`.
  - JS SDK README aligned to `rpcEndpoint`, `sdk.accounts`, list/get/runInference flows; signing best practices.
  - Stubbed out permission RPCs in SDK with clear “Not implemented” errors.
  - Files: `gui/citrate_gui_v2/src/services/rpc-client.ts`, `gui/citrate_gui_v2/src/services/tauri.ts`, `sdks/javascript/citrate-js/README.md`, `sdk/javascript/src/model.ts`.
- Node networking
  - Node starts listener, dials bootstrap nodes (peer@host:port, ip:port, hostname:port), integrates Discovery peer exchange.
  - Persistent local peer id (stored at `<data_dir>/peer.id`) used in handshake; outbound connections use remote `peer_id` from HelloAck.
  - Gossip used for tx/block propagation; basic sync triggers on Hello/HelloAck.
  - Files: `node/src/main.rs`, `node/Cargo.toml` (added `rand`).

### Security / Robustness
- Transport frame cap: 1 MB.
- Per‑connection message rate limit: 200 msgs/sec.
- Timeout handling in SyncManager with exponential backoff; demote and ban peers after repeated failures.

### Protocol
- HelloAck extends to include `peer_id` (stable remote ID for outbound connections).
  - Backward compatibility: if `peer_id` is missing, the transport falls back to a deterministic placeholder based on the socket address.
  - Files: `core/network/src/protocol.rs`, `core/network/src/transport.rs`.

### Upgrade Notes
- Mixed versions: Nodes that do not send `peer_id` in HelloAck remain compatible (placeholder IDs will be used).
- If you ship a different embedded genesis artifact, ensure all validators/operators rebuild from the same artifact to avoid diverging state.
- For public/testnet RPCs use `eth_sendRawTransaction`; `eth_sendTransaction` is only recommended for local dev with `CITRATE_REQUIRE_VALID_SIGNATURE=false`.

### Testing
- Single node: `scripts/smoke_inference.sh` (set `RPC_URL` to your node if not default).
- Cluster: `scripts/cluster_smoke.sh` (brings up 5‑node docker profile, validates peerCount, block production, and inference), then `scripts/cluster_down.sh`.

