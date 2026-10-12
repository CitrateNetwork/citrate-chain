# Reroll 2026-09-28 — Runbook + Address Ledger

**Status:** STAGING (execute only after the pre-reroll gate is green). **Owner:** DGX (chain + deployer, holds all keys). **Coord channel:** citrate-federation#253 (MAC cut protocol).

Goal: cut a fresh genesis for chain 40204 that (a) clears the rpc-1 fork, (b) rebuilds from a fully-hardened `main`, and (c) launches multisig-governed, stake-gated, with `blockSubsidy` cut — while **preserving every merged PR / code hardening / org lockdown**. This runbook doubles as the dim-9 decentralization cut (multi-producer + stake-gating).

## 1. What is preserved vs. reset

| Preserved (untouched by a reroll) | Reset (re-established at genesis) |
|---|---|
| All repos, merged PRs, code hardening, CI, branch protection, CODEOWNERS, app scoping, reviewer lockdown | Chain genesis + all on-chain state (balances, contract deployments, validator set) |
| Node identity (`noise.key`, `IDENTITY`, `proposer.key`, `encryption.meta`), coinbase | The governance handover, the reward-cut steps, address book bindings |

The reroll rebuilds the node binary from `main` — so the hardening is *carried in*, not lost.

## 2. Pre-reroll GATE (must be green before CUT-SCHEDULED)

- [ ] **#126 crash-consistency + producer catch-up gate** merged (chain #251) — *mandatory*: without it a future unclean restart re-forks (this is the whole reason we reroll clean). Prevents recurrence.
- [ ] **#14 gas_used** merged (built on #251; active from the new genesis, no activation dance).
- [ ] finality **Stage 0** merged (#250); Stage 1 is fast-follow (enabled post-reroll with producer #2).
- [ ] Docs/health PRs merged (#248/#249 + identity#28/comms#23/explorer#14/gateway#35).
- [ ] **Dry-run PASS** (§5): every redeployed address diffed vs today's book; address ledger (§4) finalized.
- [ ] ≥2 producers staged (Mac + ≥1 DO fleet node) so finality can finalize and one crash can't split-brain.

## 3. Address strategy — READ THIS (why the dry-run is load-bearing)

Most contracts deploy via **plain `new X()` (nonce-based CREATE)**, not CREATE2 — including the governance multisig (`new MultisigTimelock2of3`). CREATE addresses = `f(deployer, nonce)`; CREATE2 (≈60 deploys) = `f(deployer, salt, initcode)`. Therefore:

- **Addresses are preserved ONLY if we replay the deployer's exact transaction sequence** (same deployer EOA, same order, same nonces, no interleaved txns). Any drift (extra tx, retry, reorder) changes every subsequent CREATE address.
- CREATE2 contracts are stable **iff** same salt + **same initcode** (constructor args included). Baking `governance = multisig` into a constructor that previously took `deployer` **changes the initcode → changes the CREATE2 address** (this is exactly what moved the two Portables in #247).

**Decision (address stability > avoiding re-work):** reproduce the R2 deploy sequence **identically** (governance = deployer in ctors → same addresses), then **re-apply** the governance handover and the reward cut as **post-deploy steps** (scripted; cheap). This keeps the entire address book stable → consumer syncs are no-ops → apps need no re-point. The **dry-run is the gate that proves it** (diffs every address). Exceptions requiring a decision (D-A/D-B below).

## 4. ADDRESS LEDGER — the four generations (so nobody gets confused)

| generation | where | status |
|---|---|---|
| **pre-R2** | `contracts/addresses/dpf-40204.old.json`, `dpf-40204.pre-2026-07-26.json` | **DEAD** — superseded by R2; scrub any lingering refs |
| **R2 redeploy** (H=247436) | `contracts/addresses/40204.json` (PR #242) | canonical base |
| **#247 Portable re-point** | `40204.json` current: AIInferenceRouterPortable `0x2bb2fc09…2c51`, AILearningCycleCorePortable `0x4413a396…0ba3` | canonical; **abandoned** `0x85b04c55…f1d7` / `0x615297a2…925c` are DEAD — must NOT be redeployed |
| **reroll (this)** | regenerated `40204.json` post-cut | **target = identical to the current 40204.json** if §3 replay holds (dry-run confirms); any deltas listed here |

Canonical current pins: deployer `0x4fAB35c8…`, GOVERNANCE `0xfb9774…8c09`, GUARDIAN `0x8889cf…501d`, genesis(block0) hash `0x98e0d72f…0c73` (**changes at cut — new hash goes to #253**). Full set: `contracts/addresses/40204.json` (link, don't copy — Rule 9).

**Cleanup actions:** (1) reroll deploys ONLY the current canonical set — the abandoned Portables + pre-R2 addresses are never re-deployed; (2) post-cut, grep the federation for the dead addresses and purge stray refs; (3) regenerate `40204.json` + `chain-config` snapshot + `federation-contract.json` from the cut and re-run consumer sync **only for addresses the dry-run shows changed**.

## 5. Dry-run (the gate) — on a throwaway devnet, from hardened `main`

1. Build the node + deploy scripts from post-merge `main` (with #126/#14/#250).
2. Bring up a local single-node devnet with a fresh genesis (chainId 40204, hardened config).
3. Run the **exact R2 deploy sequence** with the same deployer + salts (DeployAll → AA stack → coop → P256 (Arachnid salt 0) → Dpf* → multisig → …), in order, no interleaved txns.
4. **Diff every resulting address against `contracts/addresses/40204.json`.** Expected: 100% match. Any mismatch = a nonce/order drift → fix the sequence, or record the delta in §4 + queue its consumer sync.
5. Dry-run the post-deploy steps: governance handover (→ DEPLOYER-ADMIN 0), reward cut (→ subsidy target), stake-gating config, validator registration (proposer pubkey).
6. Gates: `CheckDeployedAdmins` → DEPLOYER-ADMIN 0; `keep_check.sh verify`; genesis hash recorded; hash-linkage sanity across a few heights.

## 6. Decisions for the cut

- **D-A (reward cut):** bake `blockSubsidy = 1 SALT` into the `ValidatorRegistry` constructor (→ **VR address changes** → re-sync VR consumers), OR deploy VR identically (subsidy=10, address preserved) then re-run the staged governance cut. *Lean:* bake `subsidy=1` at genesis (clean, instant) and accept the VR address change (one consumer-sync delta; documented in §4).
- **D-B (governance):** deploy governable contracts with `governance=deployer` (preserve addresses) then re-run the handover to the multisig (DEPLOYER-ADMIN 0), *not* bake `governance=multisig` into ctors (which churns addresses). *Lean:* preserve addresses + re-handover.
- **D-C (validator set):** register the Mac's `proposer.key` pubkey + ≥1 fleet producer in the new `ValidatorRegistry` with stake, and set the genesis/activation so they can produce (mirror `CITRATE_VALIDATOR_ACTIVATION_HEIGHT`). Stake-gating live (rescore #47).

## 7. Cut sequence (with MAC via #253 protocol)

Pre-cut (DGX): dry-run PASS → assemble new genesis + bootnodes → stage deploy + post-deploy scripts.
1. **[DGX→MAC] CUT-SCHEDULED** — new genesis hash, bootnodes, node build, answers to Q1/Q2.
2. MAC **ACK**.
3. **[DGX→MAC] CUT-GO** → Mac runs `stop` (aborts if any citrate proc/port live).
4. DGX: fleet surgical wipe (`scripts/ops/fleet-surgical-wipe.sh`, preserve identity) → new genesis → **rpc-1 first, then boots** → deploy sequence → handover → reward cut → stake-gating → validator registration.
5. MAC: new bootnodes into `node.toml` `bootstrap_nodes` → launch citrate-core → `verify <genesis>` → **STARTED**.
6. **Verify:** `CheckDeployedAdmins` DEPLOYER-ADMIN 0; `keep_check` PASS; all producers report the SAME genesis hash + tip hash (the check that would have caught the fork); finality committee ≥4 before enabling finality.
7. **[DGX→MAC] CONFIRMED** — Mac peered + producing on the new chain (fleet view).
8. Post-cut: regen book + consumer sync (only changed addresses) + app re-point (identity AA, gateway, comms) + flip `rpc.citrate.ai` Caddy from the Mac bridge to the fleet → stop the Mac tunnel.

## 8. MAC Q1/Q2 (definitive answers go in CUT-SCHEDULED)

- **Q1 (encryption.meta):** carry it forward (node-persistent, not chain-state). If the fresh DB rejects it, let the node regenerate. *Confirm against the node data-encryption model before CUT-SCHEDULED.*
- **Q2 (proposer.key):** same key preserved (Mac keeps producer identity; coinbase `0x42e004f1…db94` unchanged). **New registration required** — the reset `ValidatorRegistry` needs the proposer pubkey registered + staked (DGX handles in §6 D-C / the genesis validator set); activation-height behavior specified in CUT-SCHEDULED.

## 9. Rollback / abort

- The old chain DB is archived (`node.bak-<ts>`), not deleted — recoverable.
- Abort criteria: genesis mismatch at verify (auto-ABORT, Mac stops first), `CheckDeployedAdmins` ≠ 0, dry-run address diff unresolved, or any producer reporting a divergent tip hash.
- Reroll tooling: `scripts/ops/{reroll-orchestrate,fleet-surgical-wipe,post-reroll-redeploy}.sh`, `scripts/ceremony/*`, `reset-node.sh` (per-node, preserves identity). Link, don't copy.
