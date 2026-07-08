---
created: 2026-07-08T21:30:00Z
branch: main
author: Larry Klosowski (@SaulBuilds) + Claude Fable 5
sprint: SFL-04-learning-stack-goes-real
status: active
---

# Starter Learning Cycle — chain 40204

Opens the first federated-learning cycle for the school-fleet summer program
(SFL planset). Executed by `script/OpenStarterCycle.s.sol`.

## Why this script also redeploys two contracts

The 2026-07-05 `DeployAll` run created `LearningCycleManager` and
`ContributionAccounting` via salted CREATE2, so `Governable(msg.sender)`
recorded the deterministic CREATE2 proxy
(`0x4e59b44847b379578588920cA78FbF26c0B4956C`) as governance, and no
post-deploy transfer was performed for them. Governance transfer is two-step
and initiable only by current governance, so those instances are permanently
ungovernable: `openCycle` and `addRecorder` can never be called on them.
Verified on-chain 2026-07-08 (`cast call <addr> "governance()(address)"`).

The script redeploys both with plain CREATE (governance = broadcasting EOA)
and abandons the burned instances. Nine further Governable contracts from
DeployAll share the pattern; remediation is tracked in the SFL-04 sprint
file (`citrate-federation/agentile/sprints/active/2026-07-08-SFL-04-learning-stack-goes-real.md`).

## Cycle parameters

| Param | Value | Rationale |
|---|---|---|
| Cycle id | 1 (first on the governed instance) | — |
| Checkpoint anchor | next multiple of 50 above broadcast block | BFT checkpoint interval on 40204 is 50 blocks |
| Initial recorder | deployer EOA | testnet posture; daemon/worker recorders added in SFL-04 WP-4.5 |
| Reward pool | none at open | funded at `finalizeCycle` (payable), per contract design |
| Target participants | school-fleet nodes + dev machines | SFL-05 needs ≥3 |

## How to run

Dry-run (no key, verified 2026-07-08, simulation green, ~4.02M gas):

```bash
cd citrate-chain/contracts
forge script script/OpenStarterCycle.s.sol \
  --rpc-url https://rpc.citrate.ai \
  --sender 0x4250675F9015E65fC866F3a373F82bb9DFc000c6
```

Broadcast (deployer key holder only):

```bash
forge script script/OpenStarterCycle.s.sol \
  --rpc-url https://rpc.citrate.ai --broadcast --slow \
  --private-key "$CITRATE_DEPLOYER_KEY"
```

## Post-broadcast checklist

1. `scripts/ops/emit-address-table.sh` — regenerate `addresses/40204.json`
   so the federation reads the governed instances.
2. `cast call <new LCM> "currentCycleId()(uint256)"` returns `1`.
3. Update the address table in this repo's `DEPLOYED_ADDRESSES.md` (it still
   shows the 2026-06-08 snapshot).
4. Record tx hashes + new addresses in the SFL-04 sprint daily update.
5. `MentorMatcher.setContributionAccounting(<new address>)` — the matcher
   still points at the burned instance (its governance is the deployer, so
   this call works).

## Status

- 2026-07-08: script written, simulation green against live 40204.
  **Broadcast pending — requires the deployer key holder.**
