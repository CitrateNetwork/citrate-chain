---
created: 2026-04-07T16:15:00Z
branch: benchmark-rehearsal
author: Codex (OpenAI, GPT-5)
status: active
scope: Canonical contract scope for the real testnet ceremony
---

# Contract Scope

## Purpose

This file defines the intended unique contract scope for the canonical testnet ceremony.

It exists to answer one question unambiguously:

`What contracts are we expecting to deploy and catalog in the real ceremony?`

This file is source-derived from the Solidity deploy scripts, not from older deployment markdown.

## Canonical Ceremony Scripts

The real ceremony should use these scripts:

1. `contracts/script/DeployAll.s.sol`
2. `contracts/script/DeployEduStack.s.sol`
3. `contracts/script/DeployAIGateway.s.sol`

`contracts/script/DeployForwarderPilot.s.sol` is explicitly **not** part of the canonical ceremony surface.
It is a parameterized helper for non-canonical pilot experiments.

## Unique Contract Set

### Core Suite — `DeployAll.s.sol` (27)

1. `ModelRegistry`
2. `WrappedSALT`
3. `AgentDecisionRegistry`
4. `SpecRegistry`
5. `IPFSIncentives`
6. `X402Facilitator`
7. `X402Paywall`
8. `LiquidStakingPool`
9. `ContributionAccounting`
10. `NematocystSlashing`
11. `MarketMakerAllocation`
12. `ModelMarketplace`
13. `InferenceRouter`
14. `LoRAFactory`
15. `LearningPool`
16. `LearningCycleManager`
17. `ClassroomRegistry`
18. `ComputeVerifier`
19. `ComputeMarketplace`
20. `ComputePool`
21. `HeartbeatMonitor`
22. `DisputeResolution`
23. `ComputePricingOracle`
24. `StablecoinTreasury`
25. `BulkComputeGateway`
26. `TestnetFarmingAccounting`
27. `TreasuryGovernor`

### Education Suite — `DeployEduStack.s.sol` (5)

28. `InstitutionalVault`
29. `ClassroomClusterV1`
30. `Forwarder`
31. `BudgetAllocation`
32. `CashoutRequest`

### AI Gateway Suite — `DeployAIGateway.s.sol` (3)

33. `AIModelRegistryPortable`
34. `AIInferenceRouterPortable`
35. `AILearningCycleCorePortable`

## Optional Scope Decision

### `ModelAccessControl`

`ModelAccessControl` is referenced in `DeployAll.s.sol` as a separate deployment because of the dependency conflict noted there.

That means the ceremony owner must choose one of two legitimate scopes:

1. `35-contract ceremony`
   `ModelAccessControl` is explicitly excluded from the real ceremony scope.

2. `36-contract ceremony`
   `ModelAccessControl` is deployed by an additional explicit ceremony step and included in the final address table.

Recommended default:
- include `ModelAccessControl`
- run the ceremony as a `36-contract` deploy

This decision must be made before the real ceremony starts if you intentionally want a narrower scope.

## What Must Match The Final Proof Bundle

The final `30_address_table.json` must satisfy all of the following:

- every contract in the chosen scope appears exactly once
- no duplicate `Forwarder` from a pilot-only script is present
- no Hardhat-only or devnet-only addresses appear
- contract count matches either:
  - `35` if `ModelAccessControl` is excluded
  - `36` if `ModelAccessControl` is included

## Operator Note

If the ceremony output count does not match the chosen scope, abort and investigate before propagating any addresses into canonical docs or app constants.
