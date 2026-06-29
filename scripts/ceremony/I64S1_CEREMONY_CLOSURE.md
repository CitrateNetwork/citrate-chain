---
created: 2026-06-29T16:05:00Z
branch: main
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8
status: ceremony-complete
sprint: I64-S1 (re-roll ceremony closure)
---

# I64-S1 re-roll — ceremony closure (raw evidence)

The deterministic-deploy narrative lives in the sprint journal
(`.agentile/sprints/completed/2026-06/2026-06-28-I64-S1-phases-bcd-and-reroll.md`,
§ Ceremony). This file is the raw fact log captured at close.

## What landed

A genuine **i64-consensus re-roll** of chain 40204 — the first re-roll where the
node binary actually carries the i64 Q16.16 widening (Phases A–D), AND the first
where the **bootnodes sync** instead of split-braining.

## Binary

- Built **natively on boot1** (amd64 DO droplet) to sidestep the aarch64 cross
  blocker. `cargo build --release -p citrate-node`, 55m12s, 0 errors, 8G swap
  added first (peaked ~50 MiB — RAM was never the limit).
- Source = `main` (i64 Phases A–D, PRs #58–61, all merged) **plus** the sync
  liveness fix (commit `8663b78`), rsync'd in before `citrate-network`/
  `citrate-node` compiled so the single binary carries both.
- Artifact: x86-64 ELF, **md5 `017b9b92eae7`**, staged identically on all 4 nodes.
- Boot-test (throwaway data dir, non-destructive): genesis initialized clean —
  **state root `0x9cd39b4b18d16947`**, **genesis block `6b6d8b895169052c` @ height 0**,
  deployer `0x4250…00c6` funded 10M SALT.

## Node reset (order held: bootnodes first, rpc-1 last; Noise keys preserved)

| Node | Role | Archive (recoverable) | Post-reset |
|---|---|---|---|
| boot2 | bootstrap | `.citrate.preroll-20260629-153745` | active, blk 0, md5 ✓, noise.key ✓ |
| boot3 | bootstrap | `.citrate.preroll-20260629-153811` | active, blk 0, md5 ✓ |
| boot1 | bootstrap | `.citrate.preroll-20260629-153822` | active, blk 0, md5 ✓ |
| rpc-1 | **miner** (last) | `.citrate.preroll-20260629-153852` | active, mining 2s blocks |

## The headline — bootnodes sync (split-brain fixed)

The 3-bug block-sync deadlock (pending never cleared → false timeout → permanent
ban of the only block source) is fixed (`8663b78`, 2 regression tests). Verified
**live** on the rerolled chain:

```
t+20s: rpc=63  boot1=64  boot2=64  boot3=65
t+40s: rpc=76  boot1=76  boot2=77  boot3=79
t+60s: rpc=89  boot1=90  boot2=90  boot3=91
```

All four climb in lockstep; **zero** `Banned peer` / `repeated sync timeouts`
lines across all bootnodes since reset. This is the first re-roll where the
bootnodes track the producer in real time.

## Contracts — deterministic deploy

`regenesis.sh` (no `--with-aa`): **44 business contracts deployed, every one
verified `eth_getCode != 0x`** on-chain. Functional probe:
`AggregationChallenge.challengeWindow()` → `150` (EVM executing on the i64 binary).

**Determinism contract held perfectly** — all 5 federated-learning contracts
landed at their `I64S1_PROJECTION.md` projected addresses, byte-exact:

| Contract | Projected = Deployed |
|---|---|
| KYCRegistry | `0x2a82a9e18adb79e2e2306243bd5df13fbfb949fa` ✓ |
| IPFSIncentivesV2 | `0x7e3c937af313e06e648e26e98f251684c4d82b4d` ✓ |
| IPFSIncentivesV3 | `0x629f7cd4aeade49e4b27c9a39237d132f9ff39f4` ✓ |
| AggregationChallenge | `0xe7d7ebe1242feec29d514b00c9272fbffc9e69be` ✓ |
| ComputePoolPipeline | `0xc2ddf9dd186781697ed9c16af3bb36e42a79f4ad` ✓ |

## Deviations from the runbook's "additions-only" expectation (owner review)

The runbook expected `git diff 40204.json` = only new keys. Actual:

1. **11 peripheral contracts moved** vs the committed (2026-06-08) table:
   AIInferenceRouterPortable, WrappedSALT, X402Facilitator, X402Paywall,
   ComputeVerifier, ComputeMarketplace, InstitutionalVault, ClassroomClusterV1,
   BudgetAllocation, CashoutRequest, EduForwarder. **No salt changed** — these
   moved because their bytecode drifted since 2026-06-08, so CREATE2 (correctly)
   lands them at new but fully-deterministic addresses. The **core** contracts
   (ModelRegistry, LearningPool, InferenceRouter, token, ContributionAccounting,
   NematocystSlashing) HELD their committed addresses. The movers are all
   vertical/peripheral (EduStack, x402 payments, compute marketplace, wSALT
   wrapper, portable router).
2. **CitrateCooperativeFactory** still un-deployable (EIP-170: 31694 > 24576) —
   skipped by `emit-address-table.sh`. Needs library extraction (WP-B2 size bug).
3. **AA stack stale** — `regenesis.sh` ran without `--with-aa` (the
   `CITRATE_AA_*` env + EntryPoint vendoring is not on this box), so all 6
   `aaStack` entries in the regenerated table point at **codeless** addresses on
   this chain. Wallet/bundler stay down until AA is redeployed.
4. **Canonical `40204.json` left UNCOMMITTED** — the diff (item 1) plus the stale
   AA (item 3) are owner-review items; the on-chain state is the real source of
   truth and the table regenerates anytime from broadcasts. Consumer
   `sync-addresses` + any Vercel rebuild are deliberately **not** run — that is
   the app-facing surface the owner wants to gate.

## Live signals at close

| Signal | Result |
|---|---|
| rpc-1 producing | ✅ 2s blocks |
| bootnodes syncing | ✅ lockstep, zero bans |
| faucet | ✅ `{"status":"ok"}` |
| explorer | ✅ HTTP 200 |
| 44 contracts have code | ✅ |
| fed-learning at projected addrs | ✅ 5/5 byte-exact |

## Owner follow-ups (gated)

1. ✅ **DONE** — `40204.json` reviewed + committed (citrate-chain `33c8e6e`), all 7
   consumers synced/pushed; 3 `ops/post-reroll-create2-sync` branches merged to main.
2. ✅ **DONE** — AA redeployed + wallet/bundler restored + wallet creation verified
   end-to-end. See "AA stack restored + wallet creation verified" below.
3. EIP-170 fix for CitrateCooperativeFactory (library extraction) before it can
   re-enter the deterministic set. **STILL OPEN.**

## AA stack restored + wallet creation verified (2026-06-29, later session)

Deviation item 3 (AA stale) is resolved. The full `CITRATE_AA_*` env turned out to
live in `.env.testnet.bak.20260608-100123` (repo root) — the live `.env.testnet`
had none. Restored it, then ran the AA ceremony:

- **EntryPoint re-vendored** via `forge create` (nonce-CREATE, NOT salt-deterministic)
  → `0x575d0d85e272eca8784a4D11F4713C698082c807`. The pin updated in `.env.testnet`.
  - **Gotcha:** this node's `eth_estimateGas` returns 21000 (base cost) for contract
    creation, so `forge create` deployed with no gas for init code (status=0, no code)
    until given an explicit `--gas-limit 6000000`. `forge script` is immune (it derives
    gas from local simulation), which is why `DeployAndPinAA` and `regenesis` work.
- **`post-reroll-redeploy.sh`** (`DeployAndPinAA`) deployed the 6 AA contracts; all 7
  have code. New: WalletFactory `0xDd5F4f…`, Paymaster `0x7A9ADb…`, WalletImpl
  `0x21AF0f…`, GuardianRecovery `0x381B58…` (all embed EntryPoint → moved). The ECDSA
  `0xD2d354…` / WebAuthn `0x97FF6d…` validators are salt-deterministic and **held**.
  - **Secrets:** the script's final `grep '^CITRATE_AA_'` echoes the `*_KEY`/`*_MNEMONIC`
    lines — run it piped through a redactor.
- Re-emitted `40204.json` (`c772e46`, aaStack-only diff, no business contract moved) +
  re-synced all 7 consumers.

**Prod-service propagation:**
- Identity (`157.230.55.191`): patched the 5 moved AA addrs + `CITRATE_AA_KERNEL_IMPL`
  (legacy alias for `WALLET_IMPL` per compose) in `/opt/citrate-identity/.env`,
  `docker compose up -d identity` (recreate — compose does `${VAR}` substitution from
  `.env`, so `restart` alone won't reload). Healthy.
- Bundler (`159.223.174.220`): set `BUNDLER_ENTRYPOINT` to the new EntryPoint; healthy;
  `eth_supportedEntryPoints` (`/rpc`) returns `0x575d0d85…`. The bundler's real signer is
  the KEYSAFE-rotated `0x560B2a15…EAC9` (from `BUNDLER_MNEMONIC`, written into
  `mnemonic.txt` by its entrypoint at boot — a `docker compose run --entrypoint sh` probe
  bypasses that and misleadingly shows the default anvil acct). Post-reroll its balance is
  0 → bundler crash-loops `insufficient funds` deploying its EntryPoint via Arachnid;
  fixed by funding `…EAC9` from the deployer. Decode the true signer from the failing
  `eth_sendRawTransaction` raw tx, not from `mnemonic.txt`.

**Wallet creation verified end-to-end (live chain):** `CitrateWalletFactory.deployFor`
with an identity-signed permit (ECDSA root-validator Kernel `initialize`) deployed a real
smart account at the identity-predicted counterfactual address
`0xBfee76E3b5781Fe0b4e6aF6705671bdFE8A454A0` (code 0 → ERC1967 proxy). Cross-checked
against the product surface: identity `GET /aa/address` returns the same address and
`GET /aa/validators` reports `deployed: true`. Permit digest =
`keccak256(abi.encode(factory, chainid, userId, keccak256(initData), expiresAt,
deployNonce[userId]))` → `toEthSignedMessageHash`, signed by the identity signer
(== `factory.identitySigner()`). Verified via a throwaway forge script (removed after).
