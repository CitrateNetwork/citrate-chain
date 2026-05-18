---
created: 2026-05-18T17:30:00Z
branch: main
author: PSL-11 triage pass
status: active
purpose: Catalogue of the 11 HIGH-severity Slither findings on the citrate-chain Solidity contracts as of 2026-05-18, with first-pass triage and disposition recommendations. NOT an audit report — this is the work product an internal author hands to an external audit firm. Findings must be confirmed and either fixed or explicitly accepted (with rationale) before the citrate-chain Tier 1 audit signs off.
---

# Slither High-Severity Findings — Triage

**Run**: `slither . --solc-remaps @openzeppelin/=lib/openzeppelin-contracts/`
**Solc**: 0.8.26
**Contracts analyzed**: 132
**Total findings**: 661 (438 Informational, 126 Low, 50 Medium, 36 Optimization, 11 **High**)

This document covers only the **11 High** findings. Medium / Low / Informational findings are tracked separately under PSL-11-followup tasks and don't block the Tier-1 audit gate.

## Disposition codes

- 🔴 **FIX-REQUIRED** — real defect, must fix before audit sign-off
- 🟡 **REVIEW-WITH-AUDITOR** — likely false-positive or design-accepted, but Tier-1 auditor must confirm
- 🟢 **FALSE-POSITIVE** — Slither's heuristic doesn't apply here, with rationale

## Findings

### 1. `arbitrary-send-eth` — ComputeMarketplace._distributeJobPayment

- **File**: `src/ComputeMarketplace.sol#1124-1154`
- **Risk**: contract sends ETH to a user-controlled address (`burner`) via low-level `.call{value:}`.
- **Disposition**: 🔴 **FIX-REQUIRED** unless `burner` is validated/whitelisted upstream.
- **Action**: read `_distributeJobPayment` and confirm whether `burner` is one of the bid winners (acceptable) or a free-form `address` argument (not acceptable). If the former, add a comment + a Slither suppression marker (`// slither-disable-next-line arbitrary-send-eth`) with rationale. If the latter, validate the address against an allow-list of registered job participants before calling.

### 2. `weak-prng` — ComputePool.coordinatorFor

- **File**: `src/ComputePool.sol#594-629`, specifically line 614: `target = seed % totalGpus`
- **Risk**: validator-influencable selection of coordinator. If miners can influence `seed`, they can self-select.
- **Disposition**: 🟡 **REVIEW-WITH-AUDITOR**.
- **Action**: Confirm where `seed` originates. If derived from `block.hash`, `block.timestamp`, or any single-validator-controllable source, replace with commit-reveal OR a VRF (e.g., the chain's own ECVRF-P256-SHA256 proposer-election machinery exposed via a precompile). If `seed` is already a commit-reveal or VRF output, document the source and add Slither suppression with rationale.

### 3. `encode-packed-collision` — ComputeVerifier._callZKVerifyPrecompile

- **File**: `src/ComputeVerifier.sol#561-579`
- **Code**: `input = abi.encodePacked(uint256(proof.length), proof, …)`
- **Risk**: when `abi.encodePacked` is called with multiple dynamic-length arguments, two different inputs can produce the same packed bytes (hash collision). If the resulting hash is used as a commitment or signature pre-image, an attacker can forge.
- **Disposition**: 🔴 **FIX-REQUIRED**.
- **Action**: Replace `abi.encodePacked` with `abi.encode` (which always prepends each dynamic argument with its length, eliminating ambiguity). If the precompile expects a specific packed layout (likely, since this is a precompile call, not a hashable commitment), confirm the layout is unambiguous by construction and add a comment + Slither suppression. Likely safe-as-written; needs eyes-on-code.

### 4. `incorrect-exp` — OpenZeppelin Math.mulDiv

- **File**: `lib/openzeppelin-contracts/contracts/utils/math/Math.sol#144-223`
- **Code**: `inverse = (3 * denominator) ^ 2;`
- **Disposition**: 🟢 **FALSE-POSITIVE**.
- **Action**: This is in upstream OpenZeppelin and is a deliberate XOR in their Newton's method for modular inverse — NOT exponentiation. The mulDiv implementation is a well-reviewed reference. No action; this finding is a Slither heuristic limitation.

### 5. `reentrancy-eth` — DisputeResolution.timeoutDispute

- **File**: `src/DisputeResolution.sol#264-279`
- **Risk**: `_payWinner(disputeId)` makes an external `.call{value:}` and state changes happen after.
- **Disposition**: 🔴 **FIX-REQUIRED** unless the function has a `nonReentrant` guard.
- **Action**: Verify whether the function has OpenZeppelin's `nonReentrant` modifier. If yes, document + suppress. If no, either add the modifier OR refactor to CEI pattern (state changes BEFORE external call).

### 6. `reentrancy-eth` — ComputePoolTraining.finalizeTrainingJob

- **File**: `src/ComputePoolTraining.sol#455-513`
- **Risk**: `worker.call{value: amount}()` then state changes.
- **Disposition**: 🔴 **FIX-REQUIRED**. Same pattern as #5.
- **Action**: same as #5 — verify `nonReentrant` or refactor.

### 7. `reentrancy-eth` — DisputeResolution.resolve

- **File**: `src/DisputeResolution.sol#245-260`
- **Disposition**: 🔴 **FIX-REQUIRED**. Same family as #5/#6.

### 8. `reentrancy-eth` — ComputePoolPipeline.terminateJob

- **File**: `src/ComputePoolPipeline.sol#327-347`
- **Code**: `(ok,) = owner.call{value: uint256(stake) + uint256(earned)}()`
- **Disposition**: 🔴 **FIX-REQUIRED**. Same family.

### 9. `reentrancy-eth` — ComputePoolTraining.abortRecruiting

- **File**: `src/ComputePoolTraining.sol#659-694`
- **Disposition**: 🔴 **FIX-REQUIRED**. Same family.

### 10. `reentrancy-eth` — AIInferenceRouterPortable.fulfillInference

- **File**: `src/edu/ai-gateway/AIInferenceRouterPortable.sol#108-135`
- **Code**: `(sent,) = signer.call{value: req.max…}()`
- **Disposition**: 🔴 **FIX-REQUIRED**. Same family.

### 11. `uninitialized-state` — ComputeMarketplace.jobBids

- **File**: `src/ComputeMarketplace.sol#168`
- **Risk**: state variable `jobBids` is declared but never initialized; used in `bidOnJob` and other functions.
- **Disposition**: 🟢 **FALSE-POSITIVE** (likely).
- **Action**: In Solidity, mappings default to zero values at declaration time and are populated via direct assignment (`jobBids[id] = ...`). Slither flags the explicit non-initialization, but for mappings this is the standard pattern. Verify `jobBids` is a `mapping`. If yes: false positive, add suppression. If it's a struct or array, then a real initializer is needed.

## Action items

| # | Action | Owner | Effort |
|---|---|---|---|
| 1 | Read `_distributeJobPayment` and validate `burner` source | Solidity engineer | 30 min |
| 2 | Determine `seed` source in `coordinatorFor` | Solidity engineer + chain-consensus owner | 1 h |
| 3 | Audit `encode-packed` use in `_callZKVerifyPrecompile`, switch to `encode` if hashable | Solidity engineer | 30 min |
| 5–10 | Confirm `nonReentrant` modifier on each function; add if missing OR refactor to CEI | Solidity engineer | 2–3 h |
| 11 | Verify `jobBids` is a mapping | Solidity engineer | 5 min |

Total estimated effort to resolve the 11 highs: **~6–8 hours of focused Solidity work** + ~2 hours of test coverage.

## Why this lives here

The actual fixes are out-of-scope for the post-split punch-list (PSL-11). They require Solidity domain expertise, careful test coverage (each fix needs its own forge test), and explicit auditor sign-off. This document does the **triage**: it tells the auditor where to look and what to expect.

When this work begins:
1. Fork a `psl-11-slither-fixes` branch.
2. Walk down the table above, resolving findings one at a time with a commit per finding.
3. Update this file as each finding is resolved (status: 🔴 → ✅ with commit SHA + reasoning).
4. When all 11 are closed, remove `continue-on-error: true` from `.github/workflows/solidity-ci.yml`'s `slither` job.
5. Re-run Slither in CI and verify it exits 0 (no remaining High findings).

## Medium findings (50) — followup

The 50 Medium findings are NOT enumerated here. They're a separate Sprint-1.5 punch list. Most are likely informational on inspection (e.g., `divide-before-multiply` is often algorithm-intentional, `unused-return` is often safe-by-design). Same triage pattern: catalogue + disposition + suppress-or-fix.
