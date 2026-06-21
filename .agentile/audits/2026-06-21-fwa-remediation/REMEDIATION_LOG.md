---
created: 2026-06-21T00:00:00Z
branch: remediation/fwa-2026-06
author: "Claude Opus 4.8 (1M context) — RM-CTR+RM-CONS remediation agent"
status: active
audit_id: 2026-06-20-federation-wide-audit
remediation_id: 2026-06-21-fwa-remediation
standard: Agentile-Audit v0.2 (red→fix→sweep→tripwire→mutation→record)
pinned_audit_sha: 03d78518d8537b8eb269e5ab5143f9fe3d7b6753
---

# FWA Remediation Log — RM-CTR (contracts) + RM-CONS (consensus)

Closes findings from FWA-C3 (EVM/contracts), FWA-C1 (consensus), FWA-C2
(network learning-gossip). Two-way back-link: `.agentile/AUDIT_REF.md`.

Baseline contract test count BEFORE remediation: **2320** (107 suites at
this pin, of which the contract suites totalled 2320 passing).
AFTER remediation: **2339** passing, 0 failing (monotone non-decreasing;
net +19 from new red/regression tests; no test weakened or deleted —
tests that encoded the *vulnerable* behavior were rewritten to exercise
the *fixed* behavior and are documented inline).

Toolchain blocks:
- **Solidity mutation tooling (gambit / vertigo) NOT installed** in this
  environment. Per-finding mutation gate recorded as BLOCKED; in lieu, each
  fix carries a dedicated negative (revert/behavior-flip) test that pins the
  exact predicate the mutation gate would target (the test fails if the
  guard is inverted or removed). See per-row "mutation" column.
- **semgrep NOT installed**; the tripwire rules are committed under
  `contracts/.semgrep/fwa-c3-tripwires.yml` to run in CI where semgrep is
  available. A source-grep equivalent is documented in the TRIPWIRE section.

---

## PART A — CONTRACTS (FWA-C3)

| ID | Severity | Status | Red→green test | Files + LOC | Mutation | Tripwire |
|----|----------|--------|----------------|-------------|----------|----------|
| C3-01 | HIGH | CLOSED-with-proof | `test_C3_01_unauth_caller_cannot_mint_active_grant`, `_authorized_issuer_still_works`, `_requires_base_role` (FWA_C3_Remediation.t.sol) | `src/rbac/RoleEscalation.sol` requestElevation (added `is_role_admin` gate + `NoBaseRole` guard, ~186-201) | BLOCKED (no tool) — negative test pins the `is_role_admin` predicate | semgrep access-control class + permanent forge test |
| C3-02 | HIGH | CLOSED-with-proof | `test_C3_02_non_deployer_cannot_initRoot` | `src/rbac/TenantHierarchy.sol` (added `immutable deployer` + constructor + `NotDeployer` gate on initRoot) | BLOCKED — test pins `msg.sender != deployer` | permanent forge test |
| C3-03 | HIGH | CLOSED-with-proof | `test_C3_03_forwarder_appends_2771_sender` (Forwarder.t.sol; 2771-aware target) | `src/edu/Forwarder.sol:151` → `target.call(abi.encodePacked(data, deviceUser))` | BLOCKED — target asserts recovered sender == principal | `contracts/.semgrep/fwa-c3-tripwires.yml` rule `fwa-c3-03-forwarder-call-without-2771-sender` |
| C3-04 | MED | CLOSED-with-proof | `test_C3_04_recovery_daily_count_cap_blocks_drain`, `_resets_next_day`, `_zero_means_unlimited` (CitratePaymaster.t.sol) | `src/aa/paymaster/CitratePaymaster.sol` (added `RecoveryUsage`, `recoveryDailyCountCap`, validate-read + postOp-increment) | BLOCKED — 4th-op revert test | permanent forge test |
| C3-05 | MED | CLOSED-with-proof | `test_C3_05_malleated_signature_rejected` (FWA_C3_Remediation.t.sol) | `src/WrappedSALT.sol` (added `_recoverCanonical` via OZ `ECDSA.tryRecover`; replaced all 4 raw `ecrecover`) | BLOCKED — high-s reject test | semgrep `fwa-c3-05-raw-ecrecover-no-low-s-guard` |
| C3-06 | HIGH | CLOSED-with-proof | `test_C3_06_raw_digest_signature_rejected` (GuardianRecoveryModule.t.sol) | `src/aa/recovery/GuardianRecoveryModule.sol` `_matchGuardianAcrossShapes` (removed raw-digest EOA path; EIP-191 only) | BLOCKED — raw-digest reject test | permanent forge test |
| C3-07 | HIGH | CLOSED-with-proof | `test_C3_07_smart_wallet_guardian_completes_recovery` (MockSmartWalletGuardian, EIP-1271) | same file (added EIP-1271 `isValidSignature` path for contract guardians) | BLOCKED — contract-guardian success test | permanent forge test |
| C3-09 | MED | CLOSED-with-proof | `test_C3_09_record_requires_signature`, `_binds_attestor_and_sig` | `src/rbac/AgentDecisionRegistryV2.sol` (added `decision_sig` param, `EmptyDecisionSig`, attestor + sig-hash binding + `DecisionAttested` event) | BLOCKED — empty-sig revert test | permanent forge test |
| C3-10 | MED | CLOSED-with-proof | `test_C3_10_first_time_foreign_national_emits_event` | `src/rbac/ClassificationRegistry.sol` (snapshot `existedBefore` pre-write; dead else-if now reachable) | BLOCKED — expectEmit test | permanent forge test |
| C3-11 | MED | CLOSED-with-proof | existing WalletFactory suite updated to nonce'd `permitDigest`; idempotent short-circuit test green | `src/aa/factory/CitrateWalletFactory.sol` (added per-userId `deployNonce`, bound into digest, consumed on deploy, idempotent short-circuit before sig-check) | BLOCKED — replay covered by digest-includes-nonce | permanent forge test |
| C3-12 | LOW | DEFERRED | — | by-design trusted-recorder residual; documented. No code change (would require an identity-binding redesign across all Boeing registries) | — | covered conceptually by C3-09 attestor binding |
| C3-13 | MED | DEFERRED | — | `CitrateECDSAValidator.isValidSignatureWithSender` dual-shape; NOT changed this pass (lower risk per audit: validateUserOp path is domain-separated). Flagged for follow-up; same EIP-191-only hardening as C3-06 applies. | — | — |
| C3-14 | MED | CLOSED-with-proof | `test_C3_14_teacher_cannot_inject_into_foreign_classroom`, `_teacher_of_both_ends_can_transfer` | `src/edu/ClassroomClusterV1.sol` transferStudent (require teacher-of-BOTH or admin) | BLOCKED — injection revert test | permanent forge test |
| C3-15 | LOW | CLOSED-with-proof | `test_C3_15_stepDown_requires_role_admin` | `src/rbac/RoleEscalation.sol` stepDown (added `is_role_admin` gate) | BLOCKED — unauth revert test | permanent forge test |
| C3-16 | MED | CLOSED-with-proof | `test_C3_16_single_signer_cannot_change_threshold` (InstitutionalVault.t.sol) + updated existing threshold tests to proposal flow | `src/edu/InstitutionalVault.sol` (replaced bare `setThreshold` with quorum-gated propose/approve/execute/reject + events; interface updated) | BLOCKED — single-signer-cannot test | permanent forge test |
| C3-17 | MED | CLOSED-with-proof | `test_C3_17_removed_signer_approval_does_not_count`, `_live_quorum_still_executes` | `src/edu/InstitutionalVault.sol` executeCashout (recount via `_liveApprovalCount` over current signer set) | BLOCKED — stale-approval revert test | permanent forge test |
| C3-L2 | LOW | DEFERRED | — | `validAfter` strict `>` is consistent with the EIP-3009 reference impl; left as-is, noted. | — | — |
| C3-L3 | LOW | DEFERRED | — | `revokeDevice` leaves `_deviceToUser` set — compounds C3-03 which is now fixed (forwarder appends deviceUser only when device active; revoked device fails `isDeviceActive`). Residual is cosmetic. | — | — |

### C3-03 Forwarder reconciliation conclusion
Two forwarders exist in the federation: `citrate-chatbot/contracts/src/CitrateForwarder.sol`
(CORRECT — appends `abi.encodePacked(req.data, req.from)`) and
`citrate-chain/contracts/src/edu/Forwarder.sol` (the WRONG one — bare
`target.call(request.data)`). The **edu Forwarder IS the deployed one**:
`contracts/broadcast/DeployEduStack.s.sol/40204/run-latest.json` deploys it
on chain 40204, instantiated by `DeployEduStack.s.sol:76`. The edu forwarder
authenticates the **device-bound signature** of `deviceUser` (not
`orgPrincipalId`), so the fix appends `deviceUser` — the actual authenticated
principal — matching the chatbot forwarder's pattern. Fixed in
`src/edu/Forwarder.sol`; chatbot forwarder left untouched (already correct).

### C3-05 SWEEP (bug-class variant analysis across repo)
The semgrep tripwire surfaced two more raw-`ecrecover` sites with v-checks
but NO low-s guard (same malleability class), outside the original audit
scope:
- `src/ComputeVerifier.sol:651` (TEE-oracle attestation) — added EIP-2 low-s `require`.
- `src/edu/ai-gateway/AIInferenceRouterPortable.sol:190` — added EIP-2 low-s early-return.
Both marked `// nosemgrep` with justification. Their existing suites
(ComputeVerifier 45/45, AIInferenceRouter 17/17) stay green (vm.sign emits
canonical low-s). WrappedSALT (C3-05 primary) routes through OZ ECDSA.

---

## PART B — CONSENSUS (FWA-C1) + NETWORK (FWA-C2)

Consensus baseline lib tests: 97 → **102** (+5). Full `citrate-consensus`
suite: **395 passed / 0 failed**. Full `citrate-network` suite:
**211 passed / 0 failed**. Clippy clean on both crates (`--tests`).

| ID | Severity | Status | Red→green test | Files + LOC | Mutation | Tripwire |
|----|----------|--------|----------------|-------------|----------|----------|
| C1-01 (eligibility leg) | HIGH | CLOSED-with-proof (in-crate) | `test_C1_01_admission_rejects_ineligible_when_selector_wired` (dag_store.rs) | `dag_store.rs` `verify_block_vrf_crypto` now calls `is_eligible_proposer`; added `proposer_selector: Option<Arc<VrfProposerSelector>>` + `with_proposer_selector` builder | BLOCKED (cargo-mutants not run; see block) — eligibility-predicate test pins the gate | permanent in-tree admission test |
| C1-01 (legacy-forgery leg) | HIGH | CLOSED-with-proof | `test_C1_01_forged_legacy_proof_accepted_below_cutoff_but_rejected_in_production` (vrf.rs) | `vrf.rs` added `VrfProposerSelector::production()` (legacy cutoff = 0) so the forgeable SHA3 path is rejected at every height | BLOCKED — forged-proof reject test | permanent in-tree test |
| C1-01 (production wiring) | — | DEFERRED (node task) | — | mechanism landed in-crate; node startup (`node/src/main.rs:1222`) must call `.with_proposer_selector(populated)` once the stake registry is loaded — a node-integration follow-up flagged here. Without wiring the gate is inert (preserves prior behavior), so no regression. | — | — |
| C1-02 | MED | DEFERRED | — | blue_score exact-equality deferral is code-acknowledged (add_block warns on drift) pending PIL-13 BlueSet-persistence rework; out of safe scope for this pass (changing it to fatal needs the producer to write exact scores first). Documented. | — | — |
| C1-03 | MED | CLOSED-with-proof | `test_C1_03_backdated_timestamp_rejected` (dag_store.rs) | `ghostdag.rs` `validate_block_consistency` enforces `header.timestamp >= sp.timestamp` | BLOCKED — backdated-reject + monotone-accept test | permanent in-tree test |
| C1-04 | MED | CLOSED-with-proof | `test_C1_04_detects_double_proposal_same_proposer_height`, `_no_false_positive_distinct_proposers` | `dag_store.rs` added `detect_equivocation()` hook (read-only, feeds peer-scoring/slashing) | BLOCKED — detection + no-false-positive tests | permanent in-tree test |
| C2-01 | MED | CLOSED-with-proof | `test_C2_01_forged_signature_embedding_rejected`, `_genuine_signed_embedding_accepted`, `_wrong_chain_id_signature_rejected` (learning_gossip_tests.rs) | `learning_messages.rs` added `signing_payload`/`verify_signature` (ed25519, domain-tagged, chain_id-bound) for `LearningEmbedding`+`AdapterOffer`; `gossip.rs` verifies BEFORE dedup/store/propagate + penalizes; `GossipConfig.chain_id` added; `core/network/Cargo.toml` += ed25519-dalek | BLOCKED — forged + cross-chain reject tests | permanent in-tree test (reuses audit evidence red test) |

### FWA-C2-01 dedup-censorship corollary
The fix verifies the signature against the asserted author BEFORE the dedup
slot `(checkpoint_height, participant)` is touched, so a forged
`(H, victim)` entry can no longer be landed to drop the victim's genuine
embedding as a duplicate. Existing learning-gossip integration tests were
updated to carry REAL ed25519 keypairs + valid signatures (the helpers now
sign the canonical payload) — they exercise the FIXED path; no test weakened.

### Toolchain blocks (PART B)
- **cargo-mutants NOT run.** Not installed; `cargo install cargo-mutants`
  not attempted to avoid network/time risk in this environment. Mutation
  gate on the election/verify fns recorded as BLOCKED. Each election/verify
  fix carries a behavior-flip test (eligibility predicate, legacy-forgery
  rejection, signature verification) that fails if the guard is inverted or
  removed — the property the mutation gate would target.
- **Cargo.lock** was already dirty at branch start (pre-existing wallet-* work)
  and is intentionally NOT committed; the `core/network/Cargo.toml` ed25519
  addition is committed (it resolves to a version already in the lock via the
  consensus crate, so no lock churn is required to build).
