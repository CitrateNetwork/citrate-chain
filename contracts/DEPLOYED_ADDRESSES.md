# Deployed Addresses — SUPERSEDED

> ⚠️ **This file is NOT the source of truth. Do NOT reroll or wire anything from it.**
>
> As of 2026-08-27 it was found wholesale stale — pre-rotation deployer (`0x4250675F…`, current is
> `0x4fAB35c8…`), every address disagreed with the live chain, and it omitted five deploy scripts
> (DeployFederatedLearning, DeployValidatorRegistry, DeployCoreMembership, DeployQuorumS6,
> RedeployIPFSIncentivesV3). An operator following it would reroll to wrong addresses.

## Canonical source of truth

- **Chain-40204 contract addresses:** [`contracts/addresses/40204.json`](addresses/40204.json)
  (published as `packages/chain-config`, which the federation imports).
- **BFR / governance suite:** [`contracts/addresses/bfr-40204.json`](addresses/bfr-40204.json)
  (harvested from the `post-reroll-quorum-restore.sh` broadcast each reroll).
- **Deploy scripts (the deterministic set):** `contracts/script/*.s.sol`, salts in
  `contracts/script/Salts.sol`. Reroll runbook: `scripts/ceremony/I64S1_REROLL_RUNBOOK.md`;
  orchestrator: `scripts/ops/reroll-orchestrate.sh`.

Regenerate any address listing from `40204.json` (e.g. `scripts/ops/emit-address-table.sh`), never by
hand.
