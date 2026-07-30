---
created: 2026-07-30
branch: docs/escalation-fresh-node-sync-wedge-54600
author: Claude (Opus 4.8), directed by @SaulBuilds
status: P0 escalation — a fresh node cannot cold-sync past block 54,600 on chain
  40204. Blocks ALL new-node / new-member onboarding. The fix EXISTS but is
  UNMERGED. Root cause proven in-repo + against live 40204. No code change here
  (docs-only handoff to DGX/chain).
relates:
  - handoffs/INCIDENT_40204_HALT_2026-07-29_GHOSTDAG_OOM.md
  - handoffs/MONEY_PATH_AND_TRACK_A_HANDOFF_2026-07-30.md
  - origin/fix/forward-drain-apply-wedge-2026-07-19 (the unmerged fix)
---

# P0 — fresh nodes cannot cold-sync past block 54,600 (forward-drain-apply wedge)

## TL;DR
A node built from **current `citrate-chain main` (`96b6af5`)** cold-syncs cleanly
from genesis to block **54,600**, then **wedges forever** — it downloads and
stores blocks 54,601+, but the **applied head never advances off 54,600**, so it
re-requests the same range every ~2s indefinitely. The existing fleet is
unaffected ONLY because it was online continuously through the 2026-07-27
concurrent-producer fork and never had to cold-sync *through* it. **Every new
member node will hit this wall** — it blocks the entire onboarding story.

**The fix already exists and is UNMERGED:** `origin/fix/forward-drain-apply-wedge-
2026-07-19`, commit **`1117400`** — *"fix(sync): periodic forward-drain so
stored-but-unapplied blocks apply"* (+71 lines: `node/src/canonical_apply.rs` +
`node/src/main.rs`). The same branch carries `97b1089 docs(handoff): fresh-node
forward-sync wedges... (P0, blocks node onboarding)`. It does NOT cherry-pick
cleanly onto current main (125 commits of drift; conflicts in both files) → it
needs a manual re-apply + test.

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
  `CITRATE_VALIDATOR_REGISTRY=0x61d44d8a…95a6`, `CITRATE_DAG_PRUNE_RETAIN=10000`.
  It sailed past the validator-activation (2,000) and every other height, then
  wedged at exactly 54,600. So it is not poisoned data and not a mining
  self-fork — it is the sync/apply path at the concurrent-producer fork.
- **My binary already has every MERGED sync fix:** `#127` (bb96542, the
  2026-07-27 concurrent-producer fork + cold-sync wedge), `#135` (86453cc),
  `#136` (8b07043) are all ancestors of the build. They are necessary but NOT
  sufficient — `1117400`'s periodic forward-drain is the missing piece.

## Required action (DGX / chain)
1. **Re-apply `1117400`** onto current `main` (resolve the `canonical_apply.rs` +
   `main.rs` conflicts — it is additive, +71 lines, a periodic drain of
   stored-but-unapplied blocks). Red-first if possible: a test that cold-syncs a
   fresh node THROUGH a stored-but-unapplied gap and asserts the applied head
   advances.
2. **Verify a fresh node cold-syncs past 54,600 to the live tip** before shipping
   (the amd64 fleet build on boot1 per the runbook, AND the aarch64-apple-darwin
   node that citrate-core bundles).
3. **Consider a checkpoint/snapshot** so new nodes can join at/after the fork
   without replaying through it (node.toml already has a `[checkpoint]` section);
   this de-risks onboarding even after the drain fix lands.
4. Roll the rebuilt node to the fleet + hand the new aarch64-darwin node binary to
   citrate-core (its bundled `binaries/citrate-*` is the member node).

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
