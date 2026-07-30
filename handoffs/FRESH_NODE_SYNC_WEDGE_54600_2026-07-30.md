---
created: 2026-07-30
updated: 2026-07-30
branch: docs/escalation-fresh-node-sync-wedge-54600
author: Claude (Opus 4.8), directed by @SaulBuilds
corrected_by: Claude Opus 5 (1M context) — DGX/chain side
status: ROOT CAUSE CORRECTED. The wedge is real and the reproduction was sound, but
  the diagnosis was wrong. It is NOT the forward-drain (already merged as #86); it is
  DAG PRUNING deleting a merge parent at height 32 that block 54,601 requires. Remedy
  is a one-line config change — unset CITRATE_DAG_PRUNE_RETAIN — proven by paired
  tests. No chain code change is needed to unblock cold sync.
relates:
  - handoffs/INCIDENT_40204_HALT_2026-07-29_GHOSTDAG_OOM.md
  - handoffs/PRUNE_MERGE_PARENT_BOUND_SPEC.md
  - handoffs/MONEY_PATH_AND_TRACK_A_HANDOFF_2026-07-30.md
---

# P0 — fresh nodes cannot cold-sync past block 54,600

> ## ⚠️ CORRECTED 2026-07-30 (DGX/chain). READ THIS FIRST.
>
> **The wedge is real and the reproduction was sound. Two conclusions were wrong,
> and acting on them costs a day and fixes nothing.**
>
> **1. `1117400` is NOT unmerged.** Its content is on `main` as **`e75e037`**, merged
> via **PR #86** — *"fix(sync): periodic forward-drain so stored-but-unapplied blocks
> apply"*. `origin/main` runs `app.drive_drain()` on a 1-second loop today
> (`node/src/main.rs`, the `EXECUTE-ON-RECEIVE step 3` block). The branch
> `fix/forward-drain-apply-wedge-2026-07-19` is the **unsquashed original** of a PR
> that landed long ago. Re-applying it across 125 commits of drift changes nothing.
>
> **2. The cause is DAG PRUNING — and the smoking gun is in this document's own
> evidence list**, where `CITRATE_DAG_PRUNE_RETAIN=10000` is described as part of
> "the fleet consensus env". **It is not fleet env, and it is the cause.**
>
> ### What actually happens
>
> | height | hash | mergeParentHashes |
> |---|---|---|
> | 54,600 | `0xb3b1ee47…` | `[]` |
> | **54,601** | `0xa267188c…` | **`["0x175fdf2b…"]`** |
> | 54,602 | `0x9dc9fb97…` | `[]` |
>
> `0x175fdf2b…` is at **height 32** (`blueScore 0x20`) — an artefact of the
> 2026-07-27 concurrent-producer fork. Block 54,601 legally merges a parent
> **54,569 blocks below itself**; nothing in `validate_block_consistency` bounded
> merge-parent depth when it was produced.
>
> With `CITRATE_DAG_PRUNE_RETAIN=10000` and applied height 54,600, the pruning point
> is **44,600**. Height 32 is far below it and gets **deleted**. Admission of 54,601
> then fails `MissingParent(0x175fdf2b…)` forever: blocks 54,601+ stored, applied head
> frozen, same range re-imported every ~2 s. Exactly the reported symptom.
>
> ### Why the fleet is unaffected — not the reason given below
>
> Not "it stayed online through the fork". **No fleet node enables pruning.** Verified
> on all four, 2026-07-30:
>
> ```
> Environment=CITRATE_BLOCK_V2=1 CITRATE_VALIDATOR_ACTIVATION_HEIGHT=2000
>             CITRATE_VALIDATOR_REGISTRY=0x61d44d8a14443646b756905410be951e6ece95a6
> ```
>
> No `CITRATE_DAG_PRUNE_RETAIN` anywhere, and rpc-1 has **zero `dag-prune` log lines
> in 30 days**. Pruning is opt-in precisely because this hazard was known
> (`node/src/dag_prune.rs` documents it; `PRUNE_MERGE_PARENT_BOUND_SPEC.md` specs it).
>
> ### The remedy — proven, not suggested
>
> **Unset `CITRATE_DAG_PRUNE_RETAIN` on any node that must cold-sync.** That is the
> whole fix. A cold-syncing node obtains height 32 during its own linear sync; only
> pruning takes it away.
>
> Paired tests in `node/src/dag_prune.rs` pin both directions:
>
> * `no_pruning_admits_the_deep_merge_parent_that_wedges_a_pruned_node` — **passes**:
>   identical topology, no prune pass, merge block admits, head advances.
> * `merge_block_referencing_a_pruned_parent_is_rejected_not_scored` — `#[ignore]`d,
>   reproduces the failure: `Err(MissingParent(…))`.
>
> ### What does NOT fix it
>
> **MP-DEPTH (#138, merged `dc21c2b`)** bounds merge-parent depth to 100, which makes
> a block like 54,601 invalid — but it **activates at height 100,000 and cannot apply
> retroactively**. Block 54,601 is valid history forever. MP-DEPTH prevents
> recurrence; it does nothing for this block. Do not wait for it.
>
> ### Corrected action for DGX
>
> 1. **Unset `CITRATE_DAG_PRUNE_RETAIN`** on the cold-syncing node and re-test —
>    minutes, not a day.
> 2. **No chain code change is required.** Do not re-apply `1117400`.
> 3. If a node with pruning OFF still wedges at 54,600, there is a second independent
>    bug — reopen with fresh evidence; everything below will have been ruled out.
> 4. Until the remaining work in `PRUNE_MERGE_PARENT_BOUND_SPEC.md` lands (bounded
>    blue-set walk, only valid after MP-DEPTH is active fleet-wide past height
>    100,000), treat **`CITRATE_DAG_PRUNE_RETAIN` as unsafe to set on any node**.

---

## Original escalation, retained for provenance

The reproduction, the live-chain comparisons and the symptom capture are accurate,
and are what made the correct diagnosis possible. Only the conclusion — "the
forward-drain is unmerged" — and the action item that followed were wrong.

## TL;DR
A node built from **current `citrate-chain main` (`96b6af5`)** cold-syncs cleanly
from genesis to block **54,600**, then **wedges forever** — it downloads and
stores blocks 54,601+, but the **applied head never advances off 54,600**, so it
re-requests the same range every ~2s indefinitely. The existing fleet is
unaffected ONLY because it was online continuously through the 2026-07-27
concurrent-producer fork and never had to cold-sync *through* it. **Every new
member node will hit this wall** — it blocks the entire onboarding story.

~~**The fix already exists and is UNMERGED:** `origin/fix/forward-drain-apply-wedge-
2026-07-19`, commit `1117400`…~~ **WRONG — see the correction block above.** That
commit's content is already on `main` as `e75e037` (PR #86); the branch is the
unsquashed original. There is no missing forward-drain.

## The symptom (verbatim, from a clean follower's `citrate_network::sync` log)
```
Downloaded 64 headers (height 54601-54664), progress: 0.1%
Validated and imported 32/32 blocks (height 54600-54631), progress: 0.1%
Downloaded 64 headers (height 54601-54664), progress: 0.1%
Validated and imported 32/32 blocks (height 54600-54631), progress: 0.1%
... every ~2s, forever. eth_blockNumber stays 54600.
```
Blocks are **stored** (imported into the block/DAG store) but never **applied**
(the executor's canonical head does not advance) — a forward-drain/apply gap.
This is exactly what `1117400`'s commit message describes fixing.

## Proof it is the binary, not local state (all verified 2026-07-30)
- **Same chain:** genesis `0xd1a1941e…` and block 54,600 `0xb3b1ee47…` on the
  local node match `rpc.citrate.ai` byte-for-byte.
- **The chain moved on:** live tip is **109,150+** and advancing; block 54,601
  `0xa267188c…` has `parentHash = 0xb3b1ee47…` — the canonical chain built
  FORWARD on b3b1ee47. So the node has the correct tip and just needs to apply
  54,601. (54,600 miner is the fleet producer `0x0ecbcd85…363b`, not us.)
- **A CLEAN, never-mined follower wedges too.** Fresh unencrypted data dir, no
  mining, built from `main`, with the fleet consensus env set exactly:
  `CITRATE_BLOCK_V2=1`, `CITRATE_VALIDATOR_ACTIVATION_HEIGHT=2000`,
  `CITRATE_VALIDATOR_REGISTRY=0x61d44d8a…95a6`, **`CITRATE_DAG_PRUNE_RETAIN=10000`**.
  It sailed past the validator-activation (2,000) and every other height, then
  wedged at exactly 54,600. So it is not poisoned data and not a mining
  self-fork.
  > ← **THIS LINE IS THE CAUSE.** `CITRATE_DAG_PRUNE_RETAIN=10000` is not part of
  > the fleet env; no fleet node sets it. It prunes height 32, which block 54,601
  > merges. See the correction block at the top.
- **My binary already has every MERGED sync fix:** `#127` (bb96542), `#135`
  (86453cc), `#136` (8b07043) — correct, ~~and `1117400`'s periodic forward-drain
  is the missing piece~~ **and `#86` (e75e037, the forward-drain) as well.** The
  binary was not missing anything.

## ~~Required action (DGX / chain)~~ — SUPERSEDED

~~1. Re-apply `1117400` onto current `main`…~~ **Do not.** The forward-drain is
already on main (`e75e037`, PR #86) and re-applying it is a no-op. See the
corrected action list in the block at the top of this document: unset
`CITRATE_DAG_PRUNE_RETAIN`, re-test, no code change.

Item 2 (verify a fresh node reaches the live tip on both the amd64 fleet build and
the aarch64-apple-darwin build citrate-core bundles) **still stands** — it is the
acceptance criterion regardless of cause.

Item 3 (a checkpoint/snapshot so new nodes can join at/after the fork without
replaying through it) **still stands and is now more attractive**: block 54,601's
merge parent at height 32 means a cold sync must retain the full DAG from genesis
until MP-DEPTH is active and the bounded walk lands. A checkpoint sidesteps that
entirely and would let pruning be enabled sooner.

Item 4 (roll the rebuilt node + hand the aarch64-darwin binary to citrate-core)
**still stands**, but note the fleet already runs a binary carrying #136/#137/#138
as of 2026-07-29 and is healthy — a fleet roll is not needed to fix cold sync.

## Separately: the app-side mining fix (already done, correct, insufficient alone)
The desktop node was ALSO spawned with `--mine` while ~54k blocks behind. As a
registered validator it produced its OWN competing block at the fork (state no
peer reproduces) and self-wedged its producer — a second, independent bug. Fixed
in **citrate-core `fix/node-follower-until-synced` (commit dbae429)**: the node
now spawns as a plain follower and only arms `--mine` once within 32 blocks of the
authoritative network tip. Review/merge that on the citrate-core side. It is
correct and necessary, but it CANNOT overcome this chain-side forward-drain wedge
— that is what this handoff is about.

## Impact if not fixed
No new node (member desktop, new fleet node, explorer, indexer) can reach the tip.
Membership's core promise — "your node syncs + participates" — is blocked at the
door for everyone who wasn't already online on 2026-07-27.
