---
created: 2026-06-09T23:15:00Z
branch: main
author: Fable 5 (Claude Code), directed by Larry Klosowski (@SaulBuilds)
status: active
sprint: SECREM-01-preaudit-remediation
---

# SECREM-01 Remediation Log — per-finding evidence chain

Source report: `citrate-labs/handoffs/PREAUDIT_ASSESSMENT_2026-06-09/00_VULNERABILITY_REPORT.md`
(immutable, Rule 3). Sprint file (Rule 4 truth):
`citrate-federation/agentile/sprints/active/2026-06-09-SECREM-01-preaudit-remediation.md`.
Doctrine: `citrate-federation/agentile/adrs/ADR-2026-06-09-untrusted-input-recomputation-gate.md`.

This log records, for every finding: re-verification result, fix commit, test evidence
(the red-then-green test names), and mutation result. A finding is **closed** only when all
columns are filled. Findings determined stale/false-positive are dispositioned with evidence,
never silently dropped.

## Rule-2 / Rule-6 baselines (Phase 0)

| Metric | Baseline | Recorded |
|---|---|---|
| `cargo test --workspace` pass count (citrate-chain) | **3,887 pre-fix** (derived: 3,896 post-Phase-1 − 9 new block_serve tests; pre-fix run was exit-0 green) | 2026-06-09 |
| Post-Phase-1 verification run | **3,896 passed / 0 failed / 9 ignored**, exit 0 | 2026-06-09 |
| Benchmark (Rule 6) | see CLAUDE.md baselines: 5,000 TPS sustained network; 773K tx/s executor ceiling | deferred — needs live node; chain frozen under PIL-13 (see Deviations) |
| citrate-explorer test count | ratchet floor 96; pre-SECREM 155 total / post-WEB-1 164 total (24/24 auth) | 2026-06-09 |
| Other sibling repo counts | recorded at each repo's first SECREM WP | — |

**Deviations.** Rule 6 (benchmark per core-touching session) cannot run against a live local node
this session: `benchmark-suite` requires a running node at :8545 and the testnet chain is frozen
under PIL-13 (mining disabled, producer OOM). The NET-1/2 change is request-handler-path only
(serve loops); its perf characteristics are covered by the new bounded-iteration tests. Benchmark
to be run at first PIL-13/14 coordination point and before the Phase 2 consensus changes merge.

## Findings ledger

Status: `open` → `verified-live` → `red-test` → `fixed` → `mutated` → **`closed`** (or `stale-fp` with evidence).

### Critical

| ID | Location | Status | Fix commit | Tests | Mutation |
|---|---|---|---|---|---|
| NET-1 | node/src/main.rs GetHeaders serve loops | **fixed** (workspace suite green: 3,896 passed / 0 failed) | pending commit | `node/src/block_serve.rs`: `net1_huge_count_past_tip_returns_promptly`, `net1_anchor_at_tip_returns_empty_promptly`, `net1_empty_storage_returns_empty`, `gap_in_height_index_stops_serving`, `unknown_anchor_serves_nothing` | Phase 8 |

### High

| ID | Location | Status | Fix commit | Tests | Mutation |
|---|---|---|---|---|---|
| CONS-1 | core/consensus/src/finality.rs:183-197 | **fixed** — `header.height` is admission-validated (exact `sp.height+1`, inductive from genesis) before any finality call; both `update_finality` call sites documented with the safety chain | pending commit | `secrem01_admission_consistency.rs`: `cons1_forged_height_rejected_at_admission` (the literal 10M-height attack), `cons1_height_must_be_exactly_parent_plus_one` | Phase 8 |
| CONS-2 | core/consensus/src/chain_selection.rs:197,393 | **fixed** — fork-choice baselines (`extend_chain`, `perform_reorg`) now written from RECOMPUTED GhostDAG scores; `blue_work` always derived via canonical `blue_work_for_score`; RocksDB index writes moved AFTER admission (main.rs/efficient_sync reorder) | pending commit | `cons2_u64max_blue_score_rejected_at_admission`, `cons2_blue_score_band_enforced`, `cons2_self_reported_blue_work_rejected`, `cons2_fork_choice_baseline_cannot_be_poisoned` (end-to-end through ChainSelector); c03 suite strengthened | Phase 8 |
| CONS-3 | core/consensus/src/dag_store.rs:370-470 | **fixed** — new `GhostDag::validate_block_consistency` enforced inside `add_block` (single choke point: gossip + sync + efficient-sync all pass it; no future caller can skip it) + explicit pre-persistence call in both main.rs handlers. Checks: parents exist, exact height linkage, merge-parent dedup/cap/selected-parent rule, blue-score feasibility band, canonical work. **Documented residual:** exact k-cluster score equality (vs the feasibility band) deferred to the PIL-13 BlueSet-persistence rework — the producer itself writes the parent+1 approximation; in-band drift is warn-logged telemetry for the strict flip. Inflation now capped at max_parents−1 per VRF-elected block vs unbounded | pending commit | `cons3_missing_selected_parent_rejected`, `cons3_missing_merge_parent_rejected`, `cons3_duplicate_and_aliased_merge_parents_rejected`, `cons3_merge_parent_count_capped`, `cons3_selected_parent_must_be_heaviest` | Phase 8 |
| INFER-1 | core/api/src/server.rs:2089-2102,2226-2240 | **fixed** — `from` is now a CLAIM that only authenticates with a secp256k1 signature over {chain_id, model_id, keccak(input), timestamp} (new `core/api/src/inference_auth.rs`, domain-separated, low-s/EIP-2 via `recover_address`, ±300s freshness); unsigned → anonymous zero address; executor independently denies anonymous callers for all non-Public policies (defense in depth in `run_inference_preview`). Both RPC handlers (`citrate_requestInference`, `citrate_runInference`) wired | pending commit | `inference_auth.rs` tests (6): `unsigned_request_is_anonymous` (the literal spoof), `valid_signature_authenticates_from`, `signature_by_other_key_rejected`, `signature_binds_model_and_input_and_chain`, `stale_timestamp_rejected`, `malformed_signature_is_error_not_anonymous` | Phase 8 |
| API-1 | core/api/src/rate_limit.rs:143-157,347-362 | **fixed** — `OPERATOR_AUTH` thread-local DELETED; emergency pause/resume/status authenticate inside the handler via `require_operator_auth` (env token + request param, fail-closed); middleware no longer computes operator state; `RateLimitConfig.operator_token` deprecated with startup warning. `CLIENT_KEY` TLS retained (budget attribution, not authz) — documented residual under RM-G2 | pending commit | rewritten `adversarial_sprint_i.rs` I.2 suite (5 tests, env-serialized) + in-module K-4 trio (`middleware_grants_no_operator_state`, `fail_closed_when_unconfigured`, `param_token_roundtrip`) | Phase 8 |
| NET-2 | node/src/main.rs:1514-1562 GetBlocks | **fixed** (workspace suite green: 3,896 passed / 0 failed) | pending commit | `net2_count_clamped_to_protocol_max`, `response_fits_byte_budget`, `byte_budget_truncates_before_frame_cap`, `anchored_request_starts_after_anchor` | Phase 8 |
| BRG-1 | core/bridge/src/oracle.rs:262-293, relay.rs:310-337 | **fixed** — new `is_threshold_met_for`/`matching_attestation_count`: threshold counts ONLY active-oracle attestations binding the recomputed canonical hash exactly; disagreeing attestations are flagged + excluded (can't mint, can't veto); relay rejects explicitly when raw-count quorum exists but none binds the presented event; old `is_threshold_met` demoted to documented liveness signal | pending commit | `secrem01_attestation_binding.rs`: `brg1_first_attestation_no_longer_binds_alone` (the literal report attack), `brg1_honest_quorum_still_mints_despite_one_liar` | Phase 8 |
| SVC-1 | citrate-district-registration/lib/bundle/blob.ts:46-51 | **fixed** (subagent) — blobs `access:"private"`; download route streams bytes after JWT check (no redirect, no public URL ever); repo 218→236 tests green, typecheck/lint pass. **OPS ACTION: pre-existing public bundle objects must be deleted/re-uploaded** | pending commit | `lib/bundle/blob.test.ts` + route tests (never-redirects, never-public regression) | Phase 8 |
| WEB-1 | citrate-explorer/src/lib/auth/session.ts:19 | **fixed** — default now fail-closed `oidc`; mock-in-production hard-disabled without `ALLOW_MOCK_AUTH=1`; client default in `config.ts` also flipped | pending commit | `session.web1.test.ts` (9 tests: resolution matrix + end-to-end forged-token rejection incl. dev-header backdoor); full auth suite 24/24 green; typecheck clean. **Ops verification of deployed `NEXT_PUBLIC_AUTH_MODE` still required — needs deploy access (user action).** | Phase 8 |

### Medium

| ID | Location | Status | Fix commit | Tests | Mutation |
|---|---|---|---|---|---|
| CONS-4 | core/sequencer/src/mempool.rs:236,653 | **fixed (subagent)** — `evicted` HashSet replaced with `BoundedHashSet` (FIFO cap 100k); dedup semantics preserved | pending commit | `test_bounded_hashset_caps_size_and_ages_out_oldest`, `test_evicted_tx_still_rejected_after_bounding` | Phase 8 |
| CONS-5 | core/consensus/src/types.rs:266-298 | **fixed (capability shipped, activation deferred)** — `compute_hash` length-prefixes `merge_parent_hashes` (count) + `vrf_reveal.proof` (len), VERSION-GATED: v1 = legacy (existing hashes preserved), v≥2 = unambiguous. **Honest note: with the current field layout the two variable fields are non-adjacent, so no live same-length collision exists — this is latent-malleability hardening that closes the class.** Activation = producer emitting v2 headers, coordinated with PIL-14 (ADR-2026-06-09-cons5-length-prefixed-block-hash) | pending commit | `test_cons5_v2_length_prefixes_participate`, `test_cons5_v1_hash_is_stable` | Phase 8 |
| CONS-6 | core/consensus/src/types.rs:18-22 + storage callers | **fixed** — `Hash::try_from_bytes` returns `Option` on short input; all untrusted/persisted decode sites (`block_store.get_block_by_height`, `get_blocks_by_blue_score`, `get_tips`, `get_latest_height_seek`; `state_store.get_state_root`) use it → corrupt RocksDB value is a gap, not a crash-loop panic | pending commit | `test_cons6_corrupt_height_index_does_not_panic` (writes 5-byte value → Ok(None)) | Phase 8 |
| FAUCET-1 | faucet/src/main.rs:393,520 | **fixed** — `Cooldowns::try_reserve` atomically checks+claims under one write lock before the RPC round-trip; every failure path releases; ambiguous RPC response keeps the hold (double-drip beats false-release) | pending commit | `test_faucet1_concurrent_reservations_only_one_wins` (16 threads, exactly 1 wins), `test_faucet1_release_returns_slot_success_keeps_it` | Phase 8 |
| FAUCET-2 | faucet/src/main.rs:573-590 | **fixed** — XFF/X-Real-IP honored only when TCP peer ∈ `FAUCET_TRUSTED_PROXIES` (mirrors RPC WP-I.1); default = trust nothing, key on socket peer | pending commit | `test_faucet2_xff_ignored_from_untrusted_peer`, `test_faucet2_xff_honored_from_trusted_proxy` | Phase 8 |
| BRG-2 | core/bridge/src/relay.rs:391-416 | **fixed** — `WithdrawalEvent::canonical_hash()` added (all release-critical fields); `process_withdrawal` gates on `is_threshold_met_for` before any processing — gate now exists BEFORE the ETH-release leg un-stubs | pending commit | `brg2_withdrawal_requires_bound_attestations` (unattested → awaiting; tampered-recipient attestation → rejected; bound → processed) | Phase 8 |
| NET-3 | core/network/src/gossip.rs:647-693, peer.rs:371-392 | **fixed (subagent)** — 60s tokio maintenance task in main.rs (~1336) calls the existing cleanup helpers; added hard max-size eviction to `seen_learning` (floodable TTL-only cache) | pending commit | `test_seen_learning_max_size_eviction` + ban-map cleanup test | Phase 8 |
| NET-4 | node/src/main.rs:1300, discovery.rs:231-272, peer.rs:351-368 | **fixed (subagent, code-level)** — subnet diversity in `find_peers` (/24 + /48, max 3 per group); bans now apply to peer-ID AND IP (`banned_ips`/`banned_peer_ids`, `ban_peer_with_id`); add_peer rejects banned ID/IP at the choke point. Topology decentralization out of scope (separate sprint) | pending commit | 6 tests (subnet grouping, cap, ban-by-IP, ban-by-ID, cleanup) | Phase 8 |
| CRY-1 | crates/citrate-hkdf-chain/src/lib.rs:53-79 | **fixed (subagent)** — `derive`/`derive_chain` return `Zeroizing<[u8;32]>`; PRK explicitly zeroized via `Hkdf::extract`; intermediates wiped on re-assignment. (HMAC-internal state is upstream, documented) | pending commit | `derive_returns_zeroizing_key_material` + 9 existing | Phase 8 |
| CFG-1 | node/src/main.rs:1276-1282 | **fixed (subagent)** — Noise key written 0600 (`OpenOptions` create_new + mode), loose perms tightened-on-load with warning, key held in `Zeroizing<Vec<u8>>` to the network-layer handoff. Encrypt-at-rest out of scope (tracked) | pending commit | `generated_noise_key_file_is_0600`, `loose_noise_key_permissions_are_tightened_on_load` | Phase 8 |
| CFG-2 | testnet-config.toml:12-15, devnet-config.toml:13-16 | **fixed (subagent)** — shipped testnet/devnet configs bind 127.0.0.1 with a remote-exposure warning comment; public-bind warning path confirmed intact; Docker repointed to dedicated 0.0.0.0 container configs (deployed droplet untouched) | pending commit | config defaults unchanged (in-code) → existing tests green | Phase 8 |
| BRG-3 | core/bridge/src/oracle.rs:80-104 | **fixed** — attestation message v2 (`citrate-bridge-v2`) binds chain_id + bridge-instance (sha3 of contract address); single shared constructor `oracle::attestation_message` + `BridgeConfig::attestation_domain`; v1 signatures accepted nowhere (pre-production protocol break, deliberate). `BridgeConfig.chain_id` added with serde default 40204 | pending commit | `brg3_cross_domain_replay_rejected` (chain-id and instance dimensions) | Phase 8 |
| WEB-2 | citrate-explorer/src/app/api/relay/route.ts:38-101 | **fixed** (subagent) — sliding-window limiter keyed per-`from` (30/h) AND per-IP (60/h), env-overridable fail-closed, 429 before any chain call; explorer 155→169 tests | pending commit | `src/lib/relay/rateLimit.test.ts` (14 tests) | Phase 8 |
| WEB-3 | citrate-buyer-webapp/app/api/chat/route.ts:28-48 | **fixed** (subagent) — 32KB byte cap + 50-message cap + 20 req/min/IP before any gateway call; malformed bodies now fail closed (400 instead of free inference). **Residual: repo has zero server-side auth infra (Privy is client-only) — server-side token verification tracked as follow-up** | pending commit | `test/chatGuard.test.ts` (12 tests); 122 repo tests green | Phase 8 |
| SVC-2 | citrate-node-agent/crates/executor/src/models.rs:105-159 | **fixed** (subagent) — sha256 recomputed locally before cache/use; mismatch → bytes dropped + hard error; poisoned cache re-verified+deleted; self-verifying CIDv1-raw decoded inline; unverifiable models FAIL CLOSED (no fetch); executor 15→22 tests. **Residuals: ModelRegistry should gain on-chain `weights_sha256` (tracked); CIDv0/dag-pb not locally recomputable → fail closed unless `CITRATE_MODEL_SHA256` set. Also surfaced pre-existing chainio test failure (unrelated, logged)** | pending commit | tampered-bytes/CID/poisoned-cache/zero-fetch suite in executor crate | Phase 8 |
| SVC-3 | citrate-agent-runtime/agent-code/src/tools/shell_exec.rs:30-49 | **fixed** (subagent) — `find` exec/write primitives (`-exec`,`-execdir`,`-ok`,`-okdir`,`-delete`,`-fprint*`,`-fls`) rejected; header rewritten: allowlist = speed bump, enforced control = HITL Critical re-auth (`ApprovalFlow::check`, agent-legacy/src/approval.rs:123-200) via `CodeAgentBridge::execute_tool`; direct-spawn + metachar rejection pre-existed (RM-B1). agent-code 46→50 tests. **Residual flagged: agent-cron sop.rs:143 accepts Option<ApprovalFlow> — None would bypass HITL for cron runs (follow-up)** | pending commit | 4 SVC-3 tests in agent-code/src/lib.rs | Phase 8 |

### Low

| ID | Location | Status | Fix commit | Tests | Mutation |
|---|---|---|---|---|---|
| CONS-7 | genesis default() placeholder validator | **fixed (disposition + doc-gate)** — re-verified: the genesis `default()` ships PUBLIC deterministic testnet keys (Forge deployer, faucet key), NOT the '0xabcd' placeholder the report described and NOT secret material. Added a load-bearing doc comment marking it the testnet-beta/dev genesis that must never be a mainnet config. Not `#[cfg(test)]`-gated because the live testnet boots from exactly this config | pending commit | n/a (doc) | n/a |
| CONS-8 | Transaction::priority() overflow | **fixed** — `saturating_mul`/`saturating_add` in `Transaction::priority()`; with `overflow-checks=true` (Phase 0.6) an extreme gas_price no longer panics the mempool | pending commit | covered by existing priority tests + overflow-checks CI | Phase 8 |
| CONS-9 | core/network/src/protocol.rs:423 bincode no limit | **fixed** — `decode_inbound` uses bincode `Options::with_limit(MAX_INBOUND_MESSAGE_BYTES=1 MiB)` (matching the transport frame cap) so a small hostile frame declaring a giant Vec can't pre-allocate-OOM | pending commit | `decode_inbound_rejects_oversized_length_prefix` | Phase 8 |
| EXEC-1 | tx decode low-s/EIP-2 | **fixed** — `is_high_s` (EIP-2 n/2 check) gates all THREE recovery paths in `eth_tx_decoder` (legacy + EIP-1559 + EIP-2930) before recovery; the `secp256k1` API didn't reject high-s (unlike the precompile's `recover_address`) → signature/hash malleability | pending commit | `secrem01_exec1_tests::low_s_accepted_high_s_rejected` (boundary cases) | Phase 8 |
| API-2 | RateLimitConfig::default() fail-open | **fixed** (by API-1's removal) — the fail-open mode WAS the middleware's "no token + localhost → operator" branch; that branch is deleted and `require_operator_auth` is unconditionally fail-closed regardless of bind or construction | pending commit | `test_k4_operator_auth_fail_closed_when_unconfigured`, `i2_no_token_configured_denies_operators` | Phase 8 |
| ECON-1 | core/economics/src/revenue_sharing.rs f64 | **fixed** — per-stakeholder distribution now integer math: f64 scores quantized once via deterministic `weight_micro` (clamps NaN/inf/neg→0), value split is `total*weight_i/total_weight` in U256, remainder swept to last recipient. No consensus caller currently, but removes the flagged float→int nondeterminism at the money boundary | pending commit | `test_econ1_weight_micro_is_deterministic_and_clamps` + existing distribution suite | Phase 8 |
| NET-5 | NewTransaction pre-validation mempool add | **fixed** — gossip `handle_new_transaction` (basic validity + peer penalty) now runs BEFORE the mempool insert; only a passing tx reaches `add_transaction` | pending commit | covered by existing gossip/mempool suites (reorder verified by workspace green) | Phase 8 |
| NET-6 | latent plaintext peer.rs handshake | **fixed** — `guard_plaintext_p2p` fail-closed gate on `start_listener`/`connect_bootnode_real`: refuses to run unless `CITRATE_ALLOW_PLAINTEXT_P2P=1` (cfg(test)-exempt). The node binary uses the Noise `NetworkTransport`, so the plaintext path can't be accidentally exposed | pending commit | guard covered by workspace green; manual env-gated path | Phase 8 |
| BRG-4 | removed-oracle attestations count | **fixed** — `matching_attestation_count` requires the submitting oracle to be currently registered AND active at evaluation time | pending commit | `brg4_inactive_oracle_attestation_not_counted` (deactivate + remove paths) | Phase 8 |
| CRY-2 | derive_chain(root, &[]) returns root | **fixed** — `derive_chain` rejects empty steps with `HkdfError::EmptyChain` instead of silently returning the master secret (domain-confusion footgun) | pending commit | `derive_empty_chain_is_rejected` (was `derive_empty_chain_returns_root`, inverted) | Phase 8 |
| SVC-4 | unauthenticated KYC clear/start | **fixed** (subagent) — 5 req/10min per-IP limit before any DB/vendor work + 409 on existing CLEAR session (closes unlimited duplicate vendor billing, worse than reported); no registrant-session infra exists (only admin GitHub allowlist) so per-IP is the available control | pending commit | `lib/rate-limit.test.ts` (7) + 2 route regression tests | Phase 8 |
| SVC-5/6/7 | gateway bind / control surfaces / CID URL | **fixed (subagent)** — SVC-5: inference-gateway marketplace bind default flipped 0.0.0.0→127.0.0.1 + non-loopback warning (env override preserved); SVC-6: node-agent control surface already loopback-fail-closed (prior pass) + compute-pool /metrics doc'd; SVC-7: `validate_cid()` at the node-agent call site rejects URL-control chars / bad length/prefix before IPFS URL interpolation (placed at execution.rs since models.rs was SVC-2-locked) | pending commit | gateway config 4/4; node-agent execution 13→16 (3 CID tests); cron 236→242 | Phase 8 |
| SVC-8 | cron secret non-constant-time compare | **fixed (subagent)** — `constantTimeEqual` (crypto.timingSafeEqual + length guard) replaces `!==` on the district-registration cron `Bearer` secret | pending commit | `lib/auth/constant-time.test.ts` (6) | Phase 8 |
| SVC-9 | staging signing material perms | **dispositioned (hygiene, not exposure)** — re-confirmed the staging signing material (`.capsule-signing-key.env`, `.keys/jwks.json`) is GITIGNORED, not committed (the report's own finding). No code fix; OPS note: tighten file perms on the working host, prod signing → HSM per existing plan. Tracked as ops hygiene, not a code vulnerability | n/a | n/a | n/a |
| WEB-4 | citrate-sdk-python http:// defaults | **fixed (subagent)** — `enforce_transport_security()`: https silent, localhost http silent, remote-host http emits UserWarning unless `allow_insecure_http=True`; threaded through client + IPFS constructors. **Residual: pytest not runnable in env (no uv/pytest); logic validated via stdlib** | pending commit | `tests/test_url_security.py` (10) | Phase 8 |
| WEB-5 | unclaimed npm/PyPI package names | **OPS ACTION (cannot fix in code)** — reserve `citrate-js`, `citrate-ai-sdk` (npm) + the PyPI names NOW to prevent dependency-confusion. Requires npm/PyPI account access — flagged for the user in the close-out | n/a | n/a | user action |

### Info

| ID | Location | Status | Notes |
|---|---|---|---|
| CONS-10 | (per report — info-level) | **dispositioned** — info-level item folded into the consensus hardening of Phase 2 (the admission-consistency gate covers the structural-validation gaps CONS-10 noted). No separate code change beyond `validate_block_consistency` | covered by Phase 2 | n/a |
| dependency/registration items | (per report — info) | **dispositioned** — covered by the restored `cargo audit`/`cargo deny` CI (Phase 0) which scans dependency advisories/licenses/bans on every PR + nightly; no separate code change | covered by CI | n/a |

## Phase 8 — class-hardening actions log

**Variant analysis (the core-concern mandate).** A very-thorough sweep of citrate-chain
for the four fixed classes (unbounded attacker-driven loop; self-reported value consumed
without recomputation; identity claim trusted without signature; threshold counted without
content agreement) found:
- **Class A (unbounded loop) — 4 CONFIRMED variants, now FIXED:** the inference RPC surface
  (`citrate_getTextEmbedding`, `citrate_semanticSearch` in `ai_rpc.rs`; `chat_completions`,
  `embeddings` in `methods/ai.rs`) processed unbounded caller-supplied arrays → inference-cost
  DoS. Clamped to `MAX_EMBEDDING_INPUTS`/`MAX_CHAT_MESSAGES = 256`. Same class as NET-1, in a
  different subsystem — exactly what the variant sweep is for.
- **Class B/C/D — NO unfixed variants.** Consensus blue-score recompute, finality height
  (sourced from DAG store), inference `from` signature gate, checkpoint vote content-agreement,
  bridge attestation content-agreement, and Belnap aggregation input validation all confirmed
  to guard correctly. (Several "pattern present" sites were verified LIKELY-SAFE with the named
  guard, e.g. eth_tx_decoder access-list clamps, marketplace search truncate.)

**Semgrep regression rules (class re-entry guard).** Added `tools/semgrep/rules/secrem01-*.yaml`:
NET-1 unbounded serve loop, BRG-1 bare threshold count, CONS-2 header-score baseline, CONS-6
unguarded `Hash::from_bytes`. **Also discovered the 40+ existing rules had NO CI runner** (authored
and orphaned, same gap as the archived workflows) — added a `semgrep` job to `security-audit.yml`
that runs the whole `tools/semgrep/rules/` set, wiring up both the new and the orphaned rules.

**Hostile-input test suites.** The per-finding adversarial suites written across Phases 1–7 ARE
the hostile-input suites the ADR requires at each trust boundary: `block_serve` (P2P serve),
`secrem01_admission_consistency` (block admission), `inference_auth` (RPC identity),
`secrem01_attestation_binding` (bridge intake), `session.web1` (web auth), `adversarial_sprint_i`
(operator auth), faucet/cooldowns (rate-limit reservation), protocol `decode_inbound` (bincode).

**Fuzz expansion.** Phase 0 expanded the nightly fuzz matrix 3→19 targets. Existing targets already
cover the hardened paths: `fuzz_bridge_attestation`/`fuzz_bridge_oracle` (BRG class),
`fuzz_gossip_validation`/`fuzz_network_message` (NET/admission ingress), `fuzz_dag_operations`
(consensus), `fuzz_mempool_admission`. No new target authored this sprint; the matrix restoration
+ the new unit/property suites are the regression guard. (A dedicated GetHeaders/admission
differential fuzz target is a tracked follow-up.)

**Mutation campaign.** `cargo-mutants` is not installed in this environment; a full campaign is a
tracked follow-up for the CI host. The adversarial red-tests were authored red-first (each fails
against the unpatched code, per the WP protocol), which gives the same "the test would catch a
revert" guarantee for the specific fixes; mutation testing would extend that to the surrounding
branches.

## Phase 0 actions log

- 2026-06-09 — Restored `.github/workflows/security-audit.yml` (was `.archived`; removed two
  broken empty `working-directory:` defaults left by the federation split; **added a clippy
  `-D warnings` job** — clippy was documented as a gate in CLAUDE.md but enforced by no workflow).
- 2026-06-09 — Restored `.github/workflows/fuzz.yml` (was `.archived`); expanded matrix from 3 to
  all 19 targets in `fuzz/fuzz_targets/`.
- 2026-06-09 — Restored `.github/workflows/perf-nightly.yml` (was `.archived`, unchanged).
- 2026-06-09 — Added `overflow-checks = true` to `[profile.release]` in workspace `Cargo.toml`.
- 2026-06-09 — Baseline `cargo test --workspace` run completed **EXIT 0 (all green)** at
  pre-fix code. Capture artifact only retained the tail, so the authoritative pre-fix count is
  derived as (post-Phase-1 full-capture count) − 9 new `block_serve` tests; full-capture run in
  flight. Honest-derivation note: the count delta is exact because Phase 1 added exactly the 9
  tests named in the NET-1/NET-2 rows and removed none.
- 2026-06-09 — citrate-explorer baseline: ratchet floor 96 (`.agentile/coverage/baseline.json`);
  pre-SECREM run: 155 total (136 passed, 18 skipped, **1 pre-existing failure** in
  `src/lib/ai/synthesis/explainTransaction.test.ts` "decodes an ERC-20 Transfer…contractLabel
  ModelRegistry" — confirmed failing at clean HEAD via stash, NOT SECREM collateral; tracked for
  Phase 5 explorer WPs). Post-WEB-1: same suite + 9 new tests, auth suites 24/24, typecheck clean.
