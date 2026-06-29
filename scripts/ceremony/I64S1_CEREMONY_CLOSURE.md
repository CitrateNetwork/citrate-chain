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

1. Review the `40204.json` diff; decide commit + consumer `sync-addresses` for the
   11 moved peripheral contracts (core apps unaffected → Vercel likely untouched).
2. Redeploy AA (`post-reroll-redeploy.sh` / `regenesis.sh --with-aa`) with
   `CITRATE_AA_*` env to restore wallet/bundler.
3. EIP-170 fix for CitrateCooperativeFactory (library extraction) before it can
   re-enter the deterministic set.
