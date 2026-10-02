---
title: "HUP registry redeploy (HUP-S7.1, federation F-4): operator runbook for chain 40204"
created: 2026-10-01
branch: hup/n5-chain-redeploy
author: Larry Klosowski + Claude Opus 5.5
status: READY FOR REHEARSAL. Nothing here has been broadcast. The chain operator runs the broadcast after the next reroll; the admin choice is pending owner sign-off.
chain: 40204
---

# HUP registry redeploy: operator runbook

This runbook deploys the on-chain registries that the Citrate Core "Hermes upskill"
(HUP) features read, after the next 40204 reroll, and puts their addresses in the
canonical book. Agents prepared and rehearsed it on a local anvil. **Only the chain
operator broadcasts, with an operator-held key.** No agent signs, sends or deploys.

Related: the reroll runbook (`scripts/ceremony/`), the address-book rules
(`contracts/addresses/README.md`), and citrate-core's `scripts/sync-addresses.py`.

## 1. What is deployed, and what is only checked

`contracts/script/DeployHupRegistries.s.sol` deploys, each by CREATE2 through the
genesis Arachnid factory `0x4e59…4956C` at `Salts.salt(<book name>)`:

| Book name | Contract | Admin |
|---|---|---|
| `OrganizationSBT` | `src/cit_agent/OrganizationSBT.sol` | born owned by ADMIN |
| `AgentSBT` | `src/cit_agent/AgentSBT.sol` (points at the OrganizationSBT above) | born owned by ADMIN |
| `CapsuleRegistry` | `src/cit_agent/CapsuleRegistry.sol` | born owned by ADMIN |
| `AnchorRegistry` | `src/cit_agent/AnchorRegistry.sol` | none (append-anyone) |
| `BenchmarkRegistry` | `src/cit_agent/BenchmarkRegistry.sol` | none (append-anyone) |
| `SkillRegistry` | `src/SkillRegistry.sol` | none (owner-per-skill) |
| `CitAgentTimelock` (only if no ADMIN is given) | `src/cit_agent/MultisigTimelock2of3.sol` | 2-of-3 owners |

It **does not deploy** the registries owned by the main ceremony, and on 40204 it
refuses to run until the book lists each of them with code on chain:
`ModelRegistry`, `InferenceRouter`, `LoRAFactory`, `X402Facilitator`,
`IPFSIncentivesV3`, `AgentDecisionRegistryV2` (`DeployAll`, `DeployDpf02Rbac`,
`RedeployIPFSIncentivesV3`).

Properties the script and its tests (`test/cit_agent/DeployHupRegistries.t.sol`) pin:

- Every address equals `keccak256(0xff ++ 0x4e59… ++ salt ++ keccak256(init_code))[12:]`.
- Admin-gated contracts take the admin as a constructor argument, so the deployer
  never holds admin and no ownership transfer happens. `InitialAdmin.check` refuses
  the zero address and the CREATE2 factory.
- On chain id 40204 the admin must have code (a deployed multisig) and must not be
  the deployer.
- A rerun skips any registry that already has code at its projection (idempotent).
- After deploying, it reads back `owner()`, `AgentSBT.orgContract()`, and one view
  per contract, and confirms `SkillRegistry` is the `abi.encode` version.

## 2. Contract versions in this redeploy

These ship with the redeploy. The registries live on today's chain keep their old
bytecode until the reroll replaces the chain.

- **AnchorRegistry** records one anchor per `(committer, root)`. A second committer
  of the same root is recorded under its own address instead of being refused, so
  the committer a reader sees is always the sender of that committer's own
  transaction. New reads: `getAnchorBy(committer, root)`, `isAnchoredBy(committer,
  root)`, `rootCountByCommitter`, `rootsByCommitter`. `getAnchor(root)` and
  `isAnchored(root)` keep their meaning (the first record of a root). The
  `anchor(uint8,bytes32)` selector is unchanged. Paginated reads clamp the page
  without computing `start + count`.
- **BenchmarkRegistry**: `getMetric` clamps the page the same way.
- **SkillRegistry**: `skillHash = keccak256(abi.encode(owner, name, version))`, plus a
  pure `skillHashOf(owner, name, version)` so clients can ask the contract. Names are
  still not authoritative: resolve skills by `skillHash` against a pinned owner list.

**Consumer follow-ups (other repos, before members rely on the new registries):**

1. citrate-agent-runtime `agent-learn/src/registry.rs::skill_hash` must switch to
   `abi.encode` layout (or call `skillHashOf`). Until then the publish payload's
   `expected_skill_hash` will not match what the new registry returns. Publishing is
   off by default.
2. citrate-core and citrate-agent-runtime (`agent/core/src/chain/anchor.rs`) should
   confirm their own anchors with `isAnchoredBy(self, root)` / `getAnchorBy`, and
   treat their own transaction receipt as the confirmation.
3. citrate-core `scripts/sync-addresses.py` lists only `AgentSBT` and
   `OrganizationSBT` of this set as optional pins (plus `SkillRegistry` as required).
   Add `AnchorRegistry`, `BenchmarkRegistry`, `CapsuleRegistry` and `InferenceRouter`
   to its optional list so the app picks them up.

## 3. Preconditions (all must hold)

- [ ] The reroll has landed and the new genesis block-0 hash is recorded.
- [ ] The main ceremony has run, and `contracts/addresses/40204.json` has been
      regenerated from it, with code at every ceremony-owned name in section 1.
- [ ] **ADMIN decided (owner sign-off).** Placeholder: the cit-agent 2-of-3 timelock
      (`CitAgentTimelock`, the holder of these registries on today's chain), either
      redeployed by this script from `HUP_TIMELOCK_OWNER_{0,1,2}` or passed in as
      `HUP_REGISTRY_ADMIN` if the ceremony already created it. `GOVERNANCE` is the
      alternative. Do not use an EOA.
- [ ] Deployer funded for 6 or 7 contract creations.
- [ ] Rehearsal (step 0) passes against the new chain.

## 4. Steps

All commands run from the citrate-chain root unless noted.

**Step 0. Rehearse on a local fork** (no transaction reaches 40204):

```bash
HUP_FORK_RPC=https://rpc.citrate.ai scripts/ops/hup-redeploy-dryrun.sh
scripts/ops/hup-redeploy-dryrun.sh --fresh   # empty chain, script-deployed timelock
```

The fork run deploys with an impersonated sender, mints an org and an agent through
the impersonated admin, registers a workspace capsule, anchors one root from two
committers, records a benchmark, registers a skill, checks each read-back, and runs
the book tool against a temporary copy of the book. It must end with `dryrun: PASS`.

**Step 1. Simulate against 40204** (no `--broadcast`):

```bash
cd contracts
DEPLOYER_ADDRESS=0x<deployer> \
HUP_TIMELOCK_OWNER_0=0x<owner0> HUP_TIMELOCK_OWNER_1=0x<owner1> HUP_TIMELOCK_OWNER_2=0x<owner2> \
forge script script/DeployHupRegistries.s.sol --rpc-url https://rpc.citrate.ai --sender 0x<deployer>
```

(Or `HUP_REGISTRY_ADMIN=0x<multisig>` instead of the three owners.) Record the
`BOOK PINS` block it prints.

**Step 2. Broadcast** (operator only, operator-held key):

```bash
forge script script/DeployHupRegistries.s.sol --rpc-url https://rpc.citrate.ai \
  --broadcast --slow --sender 0x<deployer> <your forge signer flags>
```

The pins must equal step 1's. If the run stops part-way, rerun the same command: it
skips what already has code.

**Step 3. Update the book** (reads the broadcast, verifies on chain, then writes):

```bash
scripts/ops/hup-book-update.py \
  --broadcast contracts/broadcast/DeployHupRegistries.s.sol/40204/run-latest.json \
  --book contracts/addresses/40204.json \
  --admin 0x<admin> --genesis 0x<new block-0 hash> --rpc https://rpc.citrate.ai --check
# then the same command without --check
```

Use `--keep-existing` only when a rerun skipped a registry that the book already
pins at the same projection. The tool refuses to write if any CREATE2 address does
not re-derive from the sent init code, a receipt failed, an address has no code, an
owner is not the admin, the admin has no code, `AgentSBT.orgContract()` is not the
OrganizationSBT, two names share an address, or the chain id / genesis differ.

**Step 4.** Commit the book (one-file PR, squash). Regenerate the provenance ledger
the same way as the reroll book (the deployer transactions now include these).

**Step 5. Consumers.** In citrate-core (after follow-up 3):

```bash
scripts/sync-addresses.py --book ../citrate-chain/contracts/addresses/40204.json \
  --genesis 0x<new block-0 hash> --rpc https://rpc.citrate.ai
```

**Step 6. After deploy (owner decisions, not part of this script):**

- Mint the parent organization and set the AgentSBT issuance path through the admin
  timelock (propose, second approval, wait `minDelay`, execute). `mintAgent` is
  admin-only today.
- Keep the anchor key unfunded until the core app's anchor follow-ups tracked for
  HUP-S7.3 are settled.
- Then flip the HUP features from "not deployed" to available by shipping the
  regenerated core book.

## 5. Verification checklist

- [ ] `forge test --match-path 'test/cit_agent/*'` green on the commit that was deployed.
- [ ] `python3 -m unittest discover -s scripts/ops/tests -p 'test_hup_*.py'` green.
- [ ] Step 0 `dryrun: PASS` against the new chain.
- [ ] Step 3 `--check` reports exactly the 6 (or 7) expected names.
- [ ] `cast call <AgentSBT> 'owner()(address)'` equals the admin, and the same for
      OrganizationSBT and CapsuleRegistry.
- [ ] `cast call <SkillRegistry> 'skillHashOf(address,string,string)(bytes32)' …`
      returns the `abi.encode` hash.

## 6. Abort

Abort and change nothing in the book if: the simulate and broadcast pins differ, the
ceremony-owned check fails, any owner is not the admin, or the book tool refuses.
The deployed contracts are inert until the book points at them.

## 7. Rule 6

No core crate (consensus, execution, storage, api, sequencer, network) changes in
this work, so the daily chain benchmark is not triggered by it.
