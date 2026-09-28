---
created: 2026-09-27T22:40:00Z
branch: main
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
status: completed
issue: citrate-security#124
---

# R2 — governance decentralization: move all deployer-held admin to the multisig

Retroactive record (issue/PR-driven; written at close). Goal: after the R2 contract redeploy,
**no contract on chain 40204 may have the deployer EOA (`0x4fAB35c8…`) as governance / owner /
admin**. Evidence gate: `CheckDeployedAdmins` reads DEPLOYER-ADMIN 0.

## Source of truth (link, don't copy — Rule 9)
- Tracking: citrate-security **#124** (redeploy) + **#132** (rescore addendum).
- Gate script: `contracts/script/CheckDeployedAdmins.s.sol` + `lib/AdminChecks.sol` (PR **#246**).
- Address book: `contracts/addresses/40204.json` (PR **#242** merged; Portable re-point **#247**).
- Governance: 2-of-3 `MultisigTimelock2of3` `0xfb97…8c09`, 7200 s timelock.

## What shipped
- **11 deployer-held contracts → multisig.** Of these, **9 moved in place** with no address
  change: 5 via two-step `Governable.transferGovernance`/`acceptGovernance` (Validator/Stablecoin/
  Bulk/Farming registries + Agent/Spec/MarketMaker) and 2 via single-step `Ownable.transferOwnership`
  (CitrateWalletFactory, CitratePaymaster — the latter's transfer is inherited, not redefined, so it
  didn't show in a naive grep). **2 required redeploy** (AIInferenceRouterPortable,
  AILearningCycleCorePortable) because `governance` is constructor-immutable with no transfer path —
  redeployed via a new minimal `RedeployPortableGov.s.sol` with `GOVERNANCE`=multisig, reusing the
  existing `AIModelRegistryPortable`.
- **7 `acceptGovernance` ops** executed through the multisig timelock by a detached `citrate-gov-handoff`
  systemd service (survives harness bg-task kills). Live readback: `governance()`==multisig on all 7.
- **Gate green:** `CheckDeployedAdmins` exits 0 → DEPLOYER-ADMIN 0 / FACTORY-ADMIN 0 / NO-CODE 0 /
  VERIFIER present, against `main` after #247.

## What was hard / what we learned
- **Only 2 of 7 truly needed a redeploy.** The instinct ("redeploy the remaining") would have churned
  9 addresses + every consumer sync for no reason. Reading the transfer surface first (Governable vs
  Ownable vs constructor-immutable) turned a 7-redeploy into a 2-redeploy. Lesson: classify the
  transfer path before reaching for a redeploy.
- **`forge script --skip-simulation` sends CREATE2 with no gas estimate** → Arachnid factory reverts
  (gasUsed 700). Run *without* `--skip-simulation` (or set `--gas-limit`); needs `DEPLOYER_ADDRESS` env.
- **Timelocks compose.** The accept-executor's wait target must be recomputed when new ops are appended,
  or the batch fires before the newest op's timelock elapses. (MAC's 00:56 UTC "nothing moved" check was
  simply ~1 h before the batch's target — the executor fired correctly at 01:54 UTC.)
- **Detached systemd, not harness bg tasks,** for anything that must outlive memory pressure.

## Follow-ons (open)
- Consumer re-sync for the 2 redeployed Portables (node-agent / explorer / sdk-python) after #247.
- Reward-cut (10→1 SALT) via `ValidatorRegistry` governance param — separate workstream, staged.
- KEEP-registry migration onto current contracts (rescore #48).
