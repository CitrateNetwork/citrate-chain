---
created: 2026-07-30
branch: docs/money-path-handoff-2026-07-30
author: Claude (Opus 5), directed by @SaulBuilds
status: handoff — 3 of 6 PRs merged; 3 HELD behind the contract deploy (merging them breaks prod)
relates:
  - handoffs/CRITICAL_EVM_INTERNAL_VALUE_TRANSFER_2026-07-29.md
  - handoffs/DGX_RESPONSE_CONSENSUS_AND_ALF_2026-07-29.md   (#139)
  - citrate-compute-pool/TRACK_A_GRADING_2026-07-29.md
---

# Money path + Track A — state, and what must happen in which order

Chain 40204 tip at writing: **88,682**. Block time 2.000 s (43,200/day).

---

## 1. THE BLOCKER THAT IS NOT CODE

**GitHub Actions is dead org-wide.** Every run in every repo returns
`startup_failure` at 0 seconds — `citrate-chain`, `citrate-core`,
`core-membership`, `citrate-compute-pool`, on `main` and on branches, including
pushes made minutes before this was written. Broken since ~2026-07-18. It is the
free-plan billing knob and it is an **owner action**; nobody else can clear it.

Two consequences, both load-bearing:

1. **The macOS sign + notarize pipeline cannot run.** `citrate-core`'s
   `.github/workflows/release.yml` builds on `macos-14`, signs with the
   Developer ID, notarizes and staples. It is triggered by `tags: ["v*"]` or
   `workflow_dispatch`. Neither can start. **There is no notarized build until
   billing is fixed** — this is not a code problem and no amount of merging
   changes it.
2. **No CI has validated anything below.** Every green result in this document
   was produced locally. Treat it accordingly.

---

## 2. MERGED (3)

Verified green on merged `main`, locally: **579** Rust tests in
`citrate-execution`, **2,813** Foundry tests.

| repo | PR | what |
|---|---|---|
| citrate-chain | **#140** | EVM: contract-initiated value transfers were silently discarded. Fixed, gated at height **300,000**. |
| citrate-chain | **#141** | M-2: the 32k membership grant becomes a validator bond in a per-member `MemberBond` escrow. |
| citrate-compute-pool | **#8** | Worker refuses to earn real SALT on a placeholder backend. |

These three were safe to merge because **none of them deploys anything by being
merged.** #140 is gated so a node built from it behaves identically below
300,000; #141 is contracts, which deploy by hand; #8 is a pure safety addition.

---

## 3. HELD — merging these BREAKS things (3)

All three are complete and locally green. They are held on **ordering**, not
quality.

### core-membership #28 — merging auto-deploys and breaks the live money path

`core-membership`'s Vercel production branch **is `main`** (project
`prj_UG29hPP00gpvB4w4RlQMr8XIUFlG`, not paused). Vercel deploys through its own
git integration, so the dead Actions do **not** protect us here: a merge ships to
production immediately.

Production would then call `grant(address,uint256,uint256)` and read
`attributedPrincipal` / `bondOf` against the **currently deployed vault, which
has none of them**. Every grant reverts — and `vercel.json` runs
`/api/cron/reconcile-grants` **every 10 minutes**, so it would retry the failure
around the clock.

### citrate-core #114 — would break the QA build you are trying to cut

The desktop app would read `attributedPrincipal` / `bondOf` / `unlockBlock` from
a vault that does not have them. `eth_call` returns empty, the decode fails, and
S5 never settles. A QA build cut from `main` with #114 in it has a broken
membership flow.

**So the QA build should be cut from `main` WITHOUT #114** — see §5.

### citrate-identity #80 — safe to merge, but arms a trap

The droplet signer deploys by hand, so merging changes nothing today. But anyone
who redeploys the droplet from `main` afterwards points the signer at
`grant(member, amount, tokenId)` on the old vault. Held for the same reason.

---

## 4. THE DEPLOY SEQUENCE (do not reorder)

1. **Fix Actions billing.** Nothing ships without it.
2. **@rule8 audit of #141** (M-3). T1 money contracts. Scope is larger than the
   original handoff assumed: it covers the `MemberBond` clone factory and the
   clone↔registry interaction, not just the vault. One item is flagged in-code:
   `transferOwnership` is single-step on a contract whose owner is the sole
   grant *and* upgrade authority.
3. **Build + roll #140 to the fleet before height 300,000.** At 2.000 s/block
   that is ~4.8 days from tip 88,682. Build amd64 **on boot1** (the dev box is
   aarch64). Every node must run the same activation height or they fork.
4. **Deploy #141's contracts.** `DeployCoreMembership.s.sol` refuses to broadcast
   below 300,000 — deliberately: below it, `registerValidator{value:}` would
   register a validator whose bond does not exist, i.e. phantom stake in the
   consensus proposer set. Use `--legacy` + explicit `--gas-limit`; 40204 rejects
   EIP-1559.
5. **Re-pin addresses.** All four move: SBT bytecode changed, the vault is now a
   proxy, `MemberBond` is new. Projections are in #141. Then run
   `scripts/sync-addresses.py` so every consumer's generated book follows.
6. **Update the droplet env** (`MEMBERSHIP_STAKE_VAULT_ADDRESS`,
   `CITRATE_MEMBER_SBT_ADDRESS`) and recreate the container — `docker restart`
   does **not** re-read `--env-file`.
7. **Merge #80, then #28, then #114**, in that order. #28 last of the two
   services because merging it is the moment production switches over.

### Still owed: state repair

The fix does not heal state already committed. `LiquidStakingPool` reports
`totalPooled = 32,000 SALT` against an actual balance of 0, and
`ValidatorRegistry` is 300 SALT short of its obligations. Owner deferred the
choice (reroll vs. targeted migration) until #140 landed. It has landed.

⚠️ **Do not call `claimRewards` on validator `0x226d0f53…` before #140 is live.**
769,970 SALT is claimable; today the payout is silently discarded and the storage
is zeroed anyway.

---

## 5. THE MAC / QA BUILD — what to build from

**Cut from current `main`, without #114.** That combination is internally
consistent: the app's existing native-balance settle bridge (#105) matches the
droplet's current EOA bond-fund behaviour, so membership settles end to end
against the contracts that are actually deployed.

After the §4 sequence completes, cut a second build with #114 in it. Do not mix.

The only thing standing between the team and a notarized build is item 1.

---

## 6. TRACK A — the critical path, restated

`citrate-compute-pool/TRACK_A_GRADING_2026-07-29.md` has the evidence. The short
version: **no backend trains the job the chain describes.**
`load_starting_weights` returns the hash it was handed, `dataset_hash` is
consumed by nothing, and `CandleBackend` trains a locally-initialised linear
layer on synthetic input with a placeholder loss — its own doc says "the point
of this reference impl isn't ML accuracy".

`ComputePoolTraining` is live on 40204 (`0x6eb7d416…`, `nextJobId = 0`) and pays
per epoch. The protocol cannot tell a Merkle root from real training apart from
one from a harness. #8 gates that: both capability bits default to the safe
answer, so a placeholder can never reach live settlement by omission.

**The critical path is a backend that loads `model_start_hash` and trains on
`dataset_hash`.** That is S2/S3-sized in this repo's own plan. The
event→dispatch wiring everyone called "A-2" is genuinely thin and is not the
hard part.

A-3 is unblocked whenever there is real work to record (`recordContribution`
already has an `isRecorder` allowlist — no contract change needed).

---

## 7. Verified vs. assumed

**Verified:** Actions failing across four repos including `main`; Vercel
production branch = `main` and unpaused, via the Vercel API; the notarize
workflow's triggers and runner; chain tip and block time; all test counts, run
locally on the merged commits; every Track A source claim, with file and line;
`ComputePoolTraining` and `ContributionAccounting` live with sizes and
`nextJobId`.

**Assumed / not done:** no CI validation of anything (it cannot run); the @rule8
audit has not happened; nothing is deployed; the EIP-170 byte count on
`CitrateCooperativeFactory` is carried from the earlier brief unverified; I did
not attempt a macOS build (no Mac, and the pipeline is CI-only).
