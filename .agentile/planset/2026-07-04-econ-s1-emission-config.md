---
created: 2026-07-04T00:00:00Z
branch: main
author: Larry Klosowski (@SaulBuilds) + Claude Fable 5
status: draft
program: NATIVE-R1 companion (chain-side economics)
code: ECON-S1 (emission config) — NOT the federation 2026-06-27 econ-s1-economics-simulation (FEDERATED-METALEARNING WS-4); same code, different program
repo: citrate-chain
companion: ../../../handoffs/CITRATE_NATIVE_REVAMP_MASTER_BRIEF.md (§4 economics, §10 ratified decisions)
ratified: 2026-07-04 (owner decisions 1 + 2 stake-math, brief §10)
---

> **Status (2026-07-04): DRAFT — highest-priority chain sprint of the NATIVE-R1 wave.**
> Source of truth: `handoffs/CITRATE_NATIVE_REVAMP_MASTER_BRIEF.md` §4. The three
> audit-grade findings there (dead halving, no runtime cap, sim tests the wrong path)
> are **pre-declared** so audit week confirms rather than discovers. Emission target is
> **RATIFIED**: 0.00001 SALT per 2s block (1000× down), config-mutable until mainnet,
> multisig-governed after.

# Planset — ECON-S1: emission to runtime config + live-path halving/cap

> **Goal.** The live producer path mints exactly what the configured economics say:
> a runtime-configurable base reward (0.00001 SALT/block), halving that actually
> executes, a mining-pool cap that actually binds, a simulation that tests the path
> that runs in production — deployed to the fleet by producer-binary swap, **no
> re-roll, no state reset**.

## Current truth (verified in brief §4, 2026-07-04)
- `base_block_reward = 0.01 SALT` is a **compile-time const** at
  `core/economics/src/enhanced_rewards.rs:44`; block time 2s (`testnet-beta.toml`);
  producer bonuses (staking +10%, reputation ≤+20%, congestion +5%) in
  `node/src/producer.rs:771–806`. ≈432 SALT/day flat.
- **Finding 1:** halving is dead code on the live path — the producer reads the const
  directly; `distribute_rewards` (which halves) is never called.
- **Finding 2:** no runtime supply cap — 1B total / 415M `mining_pool_max` are
  genesis-time checks only; `producer.rs:799` mints unconditionally.
- **Finding 3:** the 10k-block economic sim
  (`core/economics/tests/economics_simulation.rs`) exercises the basic 10-SALT path,
  not the enhanced/live path.
- Only the sequencer produces blocks; desktop/boot nodes **store without
  re-executing** — which is exactly why this ships as a producer redeploy, not a
  re-roll.

## Scope (in)
Reward-as-config, live-path halving, runtime pool cap, sim fix, min-stake drop
(32,000 → 3,200 SALT, ratified), the post-mainnet multisig governance hook, and the
coordinated producer redeploy runbook.

## Scope (out) — honest boundaries
- **Desktop nodes executing/validating** — VALIDATOR-S1 (this sprint only changes
  what the existing producer mints).
- **The grant program + its funding contract** — VALIDATOR-S1 Phase 3.
- **Dashboard "earned" re-labeling in gui-native** — VALIDATOR-S1 Phase 4 (the brief
  attaches it to the honesty track, not to emission).
- Total-supply (1B) enforcement beyond the mining pool — the 415M pool cap is the
  binding mint-side constraint; broader supply accounting is noted for the audit but
  not rebuilt here.
- Choosing the mainnet multisig signer set — governance/owner decision; WP-6 builds
  the mechanism, not the roster.

## Work packages (riskiest first)

Acceptance criteria name their data source per Rule 11.

| WP | Title | Acceptance (with data source) |
|---|---|---|
| **WP-1** | **`base_block_reward` → runtime config** — replace the const at `enhanced_rewards.rs:44` with a node-config value; set `0.00001 SALT` per 2s block in `testnet-beta.toml`; keep the const only as a documented default | A node booted with the new TOML mints 0.00001 SALT base (± producer bonuses); unit test drives two configs and asserts two different mints. **Source:** minted-reward field of produced blocks read back via RPC / execution state, vs the parsed config struct. |
| **WP-2** | **Wire halving into the live path** — `producer.rs:771–806` must route through the halving schedule (call or inline the `distribute_rewards` logic) instead of reading the base directly | Test producing across a halving-boundary height shows the base reward halve exactly at the boundary; the dead `distribute_rewards`-only path is either the live path or deleted (no second truth). **Source:** `enhanced_rewards` halving schedule + per-block minted amounts in execution state. |
| **WP-3** | **Runtime `mining_pool_max` enforcement** — track cumulative emission in chain state; clamp the mint to the 415M remainder, then zero | Test: force cumulative-emitted near cap → next mint clamps; at cap → mints 0 and block production continues (reward exhaustion must not halt the chain). `producer.rs:799` no longer mints unconditionally. **Source:** the cumulative-emission counter in chain state (new) — not a genesis-time constant. |
| **WP-4** | **Fix the 10k-block sim to test the live path** (§8 item 6, chain half) — port `core/economics/tests/economics_simulation.rs` from the basic 10-SALT config to the enhanced/live config | 10k-block sim runs the SAME code path the producer runs, with the WP-1 config, asserting: total emission matches closed-form expectation, halving boundaries hit, cap clamps. **Source:** the sim's per-block ledger vs the `enhanced_rewards` config — fixture-frozen totals so drift is loud. |
| **WP-5** | **`min_validator_stake` 32,000 → 3,200 SALT** (ratified §10.2 — stake math for the 3.2M-grant / 1000-validator program) | Config value changed; VRF eligibility test admits a 3,200-stake validator and rejects 3,199. Written note in the ADR/changelog that Sybil resistance shifts from stake-cost to the AUTHSPINE KYC gate (enforced in VALIDATOR-S1 Phase 3, not here). **Source:** `enhanced_rewards` config + `core/consensus/src/vrf.rs` `is_eligible_proposer` under test. |
| **WP-6** | **Multisig governance hook** — reward params config-mutable until mainnet; after mainnet, changes only via a multisig-authorized update path (ratified §10.1) | Mechanism merged behind a mainnet flag: a param-update attempt without the multisig authorization is rejected in test; with it, the new value takes effect at a declared activation height. Short ADR records the mechanism + the flag semantics. **Source:** the governance-update transaction/precompile path under test (not config-file edits). |
| **WP-7** | **Coordinated producer redeploy runbook + execution** — binary swap on the producing sequencer + boot fleet; **no re-roll** (desktop/boot nodes store without re-executing, so a producer-side reward change needs no state reset) | Runbook committed (order, health checks, rollback, the reference fleet in `reference_chain_fleet_reroll_ops`); after execution, ≥1000 consecutive live blocks observed at the new emission. **Source:** live testnet-beta blocks via rpc.citrate.ai (`citrate_getDagStats` + block reward fields), logged in the runbook's verification section. |

## Dependency table (cross-planset)

| Edge | Direction | Why |
|---|---|---|
| VALIDATOR-S1 (chain) | **depends on ECON-S1** WP-5 + WP-7 | grants are sized 3,200 SALT/validator; desktop validators must join a network already on the new emission + min-stake |
| VALIDATOR-S1 Phase 4 (honest earnings UX) | depends on WP-1/2/3 | "earned" can only be honest once emission itself is honest |
| NATIVE-R1-S2 (gui QA) | independent | no chain-side coupling; S2's live smoke lane will simply observe the new emission after WP-7 |
| AUDIT-PREP | reads this planset | §4 findings 1–3 pre-declared here are the audit index entries |

## Sequencing
WP-1→WP-2→WP-3 are one coherent producer change (land as one reviewed PR series);
WP-4 lands with them as their proof. WP-5 is independent and small. WP-6 can trail.
WP-7 executes last, once WP-1..5 are on main and the binary is cut.

## Honest sizing
~1–1.5 weeks of chain work + one coordinated redeploy window. The risk is not code
volume but WP-3's state migration (introducing the cumulative-emission counter on a
live chain without a re-roll — it can initialize from genesis-replay or from a
declared checkpoint; the WP must pick one and document it).

## References / rules
- Master brief: `/home/saul/Projects/Citrate-Labs/handoffs/CITRATE_NATIVE_REVAMP_MASTER_BRIEF.md` (§4, §9, §10.1–2)
- `citrate-federation/.agentile/rules/CORE_RULES.md` — Rule 11 (data sources above),
  Rule 12 (`[[drift]]`: gui-native + node-agent consume the new config semantics via
  the pinned chain rev), Rule 13 (the emission flip is a visibility-flip-class change:
  owner sign-off recorded before WP-7 executes).
