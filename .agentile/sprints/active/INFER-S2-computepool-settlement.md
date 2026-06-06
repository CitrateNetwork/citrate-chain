---
name: INFER-S2-computepool-settlement
description: ComputePool settlement-authority + requester timeout-refund — widen completeJob/failJob to the executor of record (job.dispatchedBy) and add reclaimExpiredJob, with TLA + Foundry invariants. Unblocks gateway-initiated INFER (INFER-S2) and SELL settlement parity.
created: 2026-06-05
branch: feat/infer-computepool-settlement
author: Larry Klosowski (saulbuilds) + Claude (Opus 4.8, 1M context)
status: active
tier: 1
audit_gated: true
---

# INFER-S2 (chain) — ComputePool settlement authority + requester timeout-refund

> **Tier-1 contract change, audit-gated.** Touches the payment/escrow path of
> `contracts/src/ComputePool.sol`. Same invariant treatment PIN got (TLA conjunct +
> Foundry invariant at 128k randomized calls). Spec-first per Agentile.

## Source of truth (link, don't copy — Rule 9)
- **WP / problem statement:** `citrate-labs/handoffs/INFER_COMPUTEPOOL_SETTLEMENT_WP.md`
  (PR #11) — verified at `citrate-chain@e1266e0`; re-verified unchanged at `main@8077149`.
- **Federation gate:** `citrate-federation/.agentile/gtm-spine/features/INFER-S2-gateway-wallet-pool-dispatch.feature`
- **Tech debt:** `citrate-federation/.agentile/gtm-spine/TECH_DEBT.md` TD-24.
- **ADR:** `citrate-federation/.agentile/adrs/ADR-2026-06-03-infer-settlement.md` (Option 3).
- **BDD (this repo):** `specs/gherkin/computepool_settlement.feature`.

## Why (the two gaps, verified in source)
Gateway-initiated INFER (ADR Option 3) cannot settle or refund a pooled job today.

- **G1 — settlement-authority asymmetry.** `completeJob`/`failJob`
  (`ComputePool.sol:410/431`) authorize `governance() || pool.creator`. But the actor
  that actually runs the job is the VRF-elected coordinator recorded in
  `job.dispatchedBy` (set only by `recordDispatch:664`, gated to `coordinatorFor`). The
  executor of record cannot close its own job — an operational centralization bug, not
  just an INFER inconvenience.
- **G2 — no requester refund on non-completion.** `reassignCoordinator:693` slashes a
  stalled coordinator but leaves `job.payment` escrowed forever. There is no
  requester-callable reclaim, so INFER-S2's *refund-on-timeout* gate is unsatisfiable.

The requester (gateway/buyer) is **correctly** not authorized to self-`completeJob`
(it would let a buyer trigger provider payment for work that may not have happened).
That asymmetry stays. We only (a) add the executor of record to the settlement
allow-list, and (b) give the requester a refund-only reclaim after a hard deadline.

## Scope (in)
1. **G1:** widen `completeJob`/`failJob` authorization to also accept `job.dispatchedBy`.
2. **G2:** add `JOB_DEADLINE` constant + `reclaimExpiredJob(uint256 jobId)` —
   requester-only, callable while `Pending|Executing` after `createdAt + JOB_DEADLINE`,
   refund-only (never pays providers), CEI + `nonReentrant`, sets terminal `Failed`,
   emits `JobReclaimed`.
3. **Invariants** (TLA conjunct + Foundry invariant suite, 128k calls, 0 reverts):
   - **NoDoubleSpendEscrow** — a job's payment is paid out XOR refunded XOR still escrowed.
   - **RefundConservation** — `reclaimExpiredJob`/`failJob` return exactly `job.payment`, never more.
   - **TerminalMonotonicity** — once `Completed`/`Failed`, status never transitions again.
   - **ExecutorOnlyCompletion** — `completeJob` succeeds only for `{governance, creator, dispatchedBy}`.
4. **Tripwire** for the settlement-authority bug-class (executor-of-record excluded from
   the settlement allow-list).
5. Adversarial + fuzz on the reclaim/settlement paths (reclaim-after-complete race,
   reentrant refund, double-reclaim, non-requester, not-yet-expired).
6. ABI re-export; bump `citrate-federation/manifest.toml [repos.citrate-chain].rev`;
   notify gateway to wire WP-D.

## Scope (out — do not pull in)
- On-chain `settleJobs(uint256[])` batch (separate ADR-infer-batch-scope; gateway-only MVP).
- Reserved/dedicated capacity escrow (INFER-S7, descoped).
- Changing `requestPoolCompute` openness (correctly open/payable).
- Slashing on reclaim — liveness slashing stays in `reassignCoordinator` (no double-jeopardy).

## Decision (recorded)
`reclaimExpiredJob` is **refund-only**; it does not slash the pool. Liveness slashing
remains in `reassignCoordinator`. Keeps the refund path simple/safe and avoids
double-jeopardy. (Ratified per WP §4b recommendation.)

## Acceptance / definition of done
1. `completeJob`/`failJob` accept `job.dispatchedBy`; all existing creator/governance
   tests still pass; the unauthorized-outsider test still reverts. (Rule 2: count is
   monotone non-decreasing.)
2. `reclaimExpiredJob` exists; Foundry tests prove: request → let `JOB_DEADLINE` pass →
   requester reclaims exactly `payment`; a completed job cannot be reclaimed; a
   non-requester cannot reclaim; a not-yet-expired job cannot be reclaimed.
3. The 4 invariants live as TLA conjuncts (`specs/tla/compute/ComputePoolSettlement.tla`)
   **and** a Foundry invariant suite at 128k randomized calls, 0 reverts.
4. A tripwire guards the bug-class in CI.
5. ABI re-exported; `manifest.toml` rev bumped; gateway notified for WP-D.
6. No Rule-1 violations; zero new `.unwrap()`; benchmark policy N/A (no core-crate change).

## Test plan (spec-first → RED → GREEN)
- New BDD: `specs/gherkin/computepool_settlement.feature` (G1 + G2 scenarios).
- New tests: `contracts/test/ComputePoolSettlement.t.sol` (G1/G2 units),
  `contracts/test/invariant/ComputePoolSettlementInvariant.t.sol` (4 invariants),
  adversarial cases folded into both. Tests authored and confirmed RED before code.

## Status log (Rule 4 — this file is the truth)
- 2026-06-05 — Sprint opened. Source re-verified at `main@8077149` (ComputePool.sol
  unchanged from the pinned `e1266e0`: `completeJob:410`, `failJob:431`,
  `recordDispatch:664`, `PoolJob.dispatchedBy`, `createdAt`). Baseline suite green
  (53 tests). BDD authored.
- 2026-06-05 — Wrote failing tests (`ComputePoolSettlement.t.sol` +
  `invariant/ComputePoolSettlementInvariant.t.sol`); confirmed RED (feature absent:
  `JOB_DEADLINE`/`reclaimExpiredJob` undefined).
- 2026-06-05 — Implemented G1 (allow-list widened to `job.dispatchedBy` on
  `completeJob`/`failJob`) + G2 (`JOB_DEADLINE = 600`, `reclaimExpiredJob`,
  `JobReclaimed`). GREEN: 19 settlement units + fuzz; **306 compute-suite tests pass,
  0 fail** (incl. the 128k invariant + every existing adversarial/fuzz/integration suite).
- 2026-06-05 — Invariants: `specs/tla/compute/ComputePoolSettlement.tla` (+ `.cfg`)
  TLC-verified (676 states, no error); **teeth-checked** — weakening the auth to admit the
  requester makes `ExecutorOnlyCompletion` fail with a 1-step counterexample. Foundry
  invariant suite passes 4/4 at **128,000 calls each, 0 reverts**; **mutation-checked** —
  injecting the requester-self-complete bug makes the suite fail (shrunk to
  `act_request → act_complete(requester)`).
- 2026-06-05 — Tripwire `tools/semgrep/rules/infer-s2-settlement-authority.yaml`
  (3 generic-mode rules) — validated: silent on the clean contract, fires on each of the
  4 regressions (drop `dispatchedBy` from complete/fail; drop requester/deadline guard),
  0 parse errors.
- 2026-06-05 — **Gate met.** Pending: commit/PR (human-gated), then post-merge manifest
  re-pin + gateway WP-D notification. See Retrospective.

## Acceptance check-off
1. ✅ `completeJob`/`failJob` accept `job.dispatchedBy`; all existing creator/governance
   tests pass; unauthorized-outsider still reverts. Test count up (53 → 76 in the pool
   suites; +4 invariants). (Rule 2 ✓)
2. ✅ `reclaimExpiredJob` proven: reclaim exactly `payment` post-deadline; completed/failed
   not reclaimable; non-requester/pre-deadline/double-reclaim all revert; reentrancy blocked.
3. ✅ 4 invariants as TLA conjuncts **and** a 128k-call Foundry invariant suite, 0 reverts.
4. ✅ CI tripwire guards the bug-class (validated firing).
5. ⏳ ABI re-export + manifest re-pin + gateway WP-D — post-merge (see Retrospective §Handoff).
6. ✅ No Rule-1 violations; no new `.unwrap()` (Solidity); no core-crate change (benchmark N/A).

## Retrospective
**What the bug actually was.** Not an INFER inconvenience — a *settlement-authority
asymmetry*. The actor the protocol elects to **run** a job (`job.dispatchedBy`, VRF) was
not in the allow-list to **close** it; settlement was pinned to a fixed
`governance/creator`. In a pool whose creator isn't a live operator, jobs could reach
`Executing` and only governance could ever settle them — an operational centralization
bug that the gateway product merely surfaced. The fix widens *who can close* to the
executor of record, and adds the missing *requester refund* backstop — without letting the
buyer self-pay providers (that asymmetry is correct and preserved).

**What went right.**
- Spec-first held: tests were RED for the right reason (feature absent), then GREEN.
- Two independent teeth-checks (TLA counterexample + Foundry mutation) proved the
  invariant suite isn't vacuous before trusting its green.
- The fuzzer earned its keep by catching a *harness* bug (an external `JOB_DEADLINE()`
  call consuming a `vm.prank`), not a contract bug — exactly the kind of false-green a
  hand-written test would have shipped.

**Decisions recorded.** `reclaimExpiredJob` is refund-only (no slash) — liveness slashing
stays in `reassignCoordinator`; avoids double-jeopardy. `JOB_DEADLINE = 600` blocks (~2h),
distinct from `COORDINATION_TIMEOUT = 20` — product-tunable.

**Handoff (post-merge, not done here — human-gated).**
- Re-pin `citrate-federation/manifest.toml [repos.citrate-chain].rev` to the merged SHA.
- Gateway WP-D (`citrate-inference-gateway`): vendor the new `reclaimExpiredJob` +
  `JobReclaimed` into the ComputePool interface (`gateway/src/queries.rs`/selection),
  poll `JobCompleted`/`JobFailed`, and on `JOB_DEADLINE` elapse call `reclaimExpiredJob`
  **as the requester** to refund the buyer's key balance. `[[drift]]`: buyer-webapp ←
  gateway refund semantics once WP-D lands.
- Discharge `citrate-federation/.agentile/gtm-spine/TECH_DEBT.md` TD-24 referencing the
  chain PR.
